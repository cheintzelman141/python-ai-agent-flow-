"""Durable SQLite persistence for the Agent Flow supervisor.

The store owns transactional queue mechanics only.  It deliberately accepts and
returns plain strings and dictionaries, while retaining final authority for
lease fences, role transitions, typed handoffs, and evidence gates.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence

from pydantic import ValidationError

from agent_flow.models import (
    EvidenceRef,
    FixHandoff,
    FixOutcome,
    GateKind,
    InvestigationHandoff,
    InvestigationOutcome,
    ItemState,
    TestHandoff,
    WorkspaceKind,
    evaluate_test_handoff,
)


SCHEMA_VERSION = 7
OPEN_JOB_STATUSES = ("pending", "running")
DEFAULT_REQUIRED_GATES = ("focused_tests", "browser", "database")
DEFAULT_ROLE_LIMITS = {"investigator": 2, "fixer": 2, "tester": 2}
VALID_CAMPAIGN_STATUSES = {"active", "paused", "completed", "cancelled"}
VALID_ITEM_STATES = {
    "backlog",
    "investigating",
    "ready_for_fix",
    "fixing",
    "ready_for_test",
    "testing",
    "verified_green",
    "blocked",
}
VALID_GATES = {"focused_tests", "browser", "database", "gl", "api", "export"}
ROLE_STATES = {
    "investigator": ("backlog", "investigating"),
    "fixer": ("ready_for_fix", "fixing"),
    "tester": ("ready_for_test", "testing"),
}
CREATABLE_ITEM_STATES = {"backlog", "ready_for_fix", "ready_for_test", "blocked"}
STAGE_NEXT_STATES = {
    "investigator": {"ready_for_fix", "blocked"},
    "fixer": {"ready_for_test", "blocked"},
    "tester": {"verified_green", "ready_for_fix", "blocked"},
}
VALID_WORKSPACE_KINDS = {kind.value for kind in WorkspaceKind}
WORKTREE_RESOURCE_PREFIX = "git-worktree:"


class StorageError(RuntimeError):
    """Base storage failure."""


class NotFoundError(StorageError):
    """A requested record does not exist."""


class TransitionConflict(StorageError):
    """A compare-and-swap transition no longer matches persisted state."""


class LeaseConflict(StorageError):
    """A worker presented an absent, expired, or stale lease."""


def _id() -> str:
    return uuid.uuid4().hex


def _dump(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _load(value: Optional[str], default: Any) -> Any:
    return default if value is None else json.loads(value)


def _value(value: Any) -> str:
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


def _repository_scope(value: Mapping[str, Any]) -> set[str]:
    repositories = value.get("repository_paths", value.get("repositories", ()))
    return {str(repository) for repository in repositories or ()}


def _canonical_repository_scope(value: Mapping[str, Any]) -> set[str]:
    return {
        str(Path(repository).expanduser().resolve())
        for repository in _repository_scope(value)
    }


def _approval_covers_job(
    campaign_config: Mapping[str, Any],
    job_payload: Mapping[str, Any],
    approval_scope: Mapping[str, Any],
) -> bool:
    required_repositories = _repository_scope(campaign_config).union(
        _repository_scope(job_payload)
    )
    if not required_repositories:
        return True
    return required_repositories.issubset(_repository_scope(approval_scope))


def _approval_covers_repository(
    campaign_config: Mapping[str, Any],
    repository_path: str,
    approval_scope: Mapping[str, Any],
) -> bool:
    repository = str(Path(repository_path).expanduser().resolve())
    return (
        repository in _canonical_repository_scope(campaign_config)
        and repository in _canonical_repository_scope(approval_scope)
    )


def _handoff_evidence(handoff: Any) -> Iterator[EvidenceRef]:
    for evidence in getattr(handoff, "evidence", ()):
        yield evidence
    blocker = getattr(handoff, "blocker", None)
    if blocker is not None:
        yield from blocker.evidence
    for proof in getattr(handoff, "gate_proofs", ()):
        yield from proof.evidence


_FOCUSED_TEST_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "PYTHONHASHSEED": "0",
}
_FOCUSED_TEST_ENVIRONMENT_KEYS = frozenset(_FOCUSED_TEST_ENVIRONMENT)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_PYTHON_EXECUTABLE_PATTERN = re.compile(r"^python(?:3(?:\.\d+)?)?$", re.IGNORECASE)
_TEST_SELECTOR_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$"
)


class SQLiteStore:
    """A single SQLite connection with explicit, thread-guarded transactions."""

    _JSON_COLUMNS = {
        "config_json": "config",
        "role_limits_json": "role_limits",
        "metadata_json": "metadata",
        "required_gates_json": "required_gates",
        "payload_json": "payload",
        "result_json": "result",
        "required_resources_json": "required_resources",
        "event_data_json": "event_data",
        "scope_json": "scope",
        "source_snapshot_json": "source_snapshot",
        "expected_identity_json": "expected_identity",
        "observed_identity_json": "observed_identity",
        "command_argv_json": "command_argv",
        "environment_json": "environment",
        "workspace_manifest_json": "workspace_manifest",
        "workspace_manifest_before_json": "workspace_manifest_before",
        "workspace_manifest_after_json": "workspace_manifest_after",
        "canonical_handoff_json": "canonical_handoff",
    }

    def __init__(
        self,
        path: Path,
        *,
        timeout: float = 5.0,
        clock: Callable[[], float] = time.time,
        read_only: bool = False,
    ) -> None:
        if not isinstance(read_only, bool):
            raise ValueError("read_only must be a boolean")
        self.path = Path(path).expanduser().resolve()
        self.read_only = read_only
        if not read_only:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._lock = threading.RLock()
        database = str(self.path)
        uri = False
        if read_only:
            if not self.path.is_file():
                raise StorageError("Agent Flow database does not exist: %s" % self.path)
            database = self.path.as_uri() + "?mode=ro"
            uri = True
        self._connection = sqlite3.connect(
            database,
            timeout=timeout,
            isolation_level=None,
            check_same_thread=False,
            uri=uri,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = %d" % int(timeout * 1000))
        if read_only:
            try:
                self._connection.execute("PRAGMA query_only = ON")
                version = int(
                    self._connection.execute("PRAGMA user_version").fetchone()[0]
                )
                if version != SCHEMA_VERSION:
                    raise StorageError(
                        "database schema version %d is not supported by this read-only "
                        "command; run `agent-flow init` with this database using version %d"
                        % (version, SCHEMA_VERSION)
                    )
            except BaseException:
                self._connection.close()
                raise
        else:
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._migrate()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "SQLiteStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        if self.read_only:
            raise StorageError("write transactions are disabled for this read-only store")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Connection]:
        """Hold one short, non-blocking WAL snapshot across related reads."""

        with self._lock:
            self._connection.execute("BEGIN")
            try:
                yield self._connection
            finally:
                self._connection.rollback()

    def _migrate(self) -> None:
        with self._transaction() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise StorageError(
                    "database schema version %d is newer than supported version %d"
                    % (version, SCHEMA_VERSION)
                )
            if version == 0:
                for statement in _SCHEMA_V1:
                    connection.execute(statement)
                connection.execute("PRAGMA user_version = 1")
                version = 1
            if version == 1:
                for statement in _SCHEMA_V2:
                    connection.execute(statement)
                connection.execute("PRAGMA user_version = 2")
                version = 2
            if version == 2:
                for statement in _SCHEMA_V3:
                    connection.execute(statement)
                connection.execute("PRAGMA user_version = 3")
                version = 3
            if version == 3:
                for statement in _SCHEMA_V4:
                    connection.execute(statement)
                connection.execute("PRAGMA user_version = 4")
                version = 4
            if version == 4:
                for statement in _SCHEMA_V5:
                    connection.execute(statement)
                self._migrate_workspace_kinds(connection)
                connection.execute("PRAGMA user_version = 5")
                version = 5
            if version == 5:
                for statement in _SCHEMA_V6:
                    connection.execute(statement)
                connection.execute("PRAGMA user_version = 6")
                version = 6
            if version == 6:
                for statement in _SCHEMA_V7:
                    connection.execute(statement)
                connection.execute("PRAGMA user_version = 7")

    @staticmethod
    def _migrate_workspace_kinds(connection: sqlite3.Connection) -> None:
        campaigns = {
            str(row["id"]): _load(row["config_json"], {})
            for row in connection.execute(
                "SELECT id, config_json FROM campaigns"
            ).fetchall()
        }
        jobs = connection.execute(
            "SELECT id, campaign_id, role FROM jobs"
        ).fetchall()
        for job in jobs:
            config = campaigns.get(str(job["campaign_id"]), {})
            simulated = config.get("allow_simulated_evidence") is True
            workspace_kind = WorkspaceKind.SOURCE_READ_ONLY.value
            if job["role"] in ("fixer", "tester") and simulated:
                workspace_kind = WorkspaceKind.SIMULATED.value
            elif job["role"] == "fixer":
                workspace_kind = WorkspaceKind.MANAGED_WORKTREE.value
            connection.execute(
                "UPDATE jobs SET workspace_kind = ? WHERE id = ?",
                (workspace_kind, job["id"]),
            )

    def _row(self, row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        data: Dict[str, Any] = dict(row)
        for column, public_name in self._JSON_COLUMNS.items():
            if column in data:
                data[public_name] = _load(data.pop(column), None)
        aliases = {
            "global_limit": "global_concurrency_limit",
            "role_limits": "role_concurrency_limits",
            "work_item_id": "item_id",
            "event_kind": "event_type",
            "owner_id": "lease_owner",
            "expires_at": "lease_expires_at",
        }
        for source, destination in aliases.items():
            if source in data:
                data[destination] = data[source]
        event_data = data.get("event_data")
        if isinstance(event_data, Mapping):
            data.setdefault("from_state", event_data.get("from_state"))
            data.setdefault("to_state", event_data.get("to_state"))
        return data

    def _rows(self, rows: Sequence[sqlite3.Row]) -> List[Dict[str, Any]]:
        return [self._row(row) for row in rows]  # type: ignore[misc]

    def _append_event(
        self,
        connection: sqlite3.Connection,
        event_kind: str,
        *,
        campaign_id: Optional[str] = None,
        work_item_id: Optional[str] = None,
        job_id: Optional[str] = None,
        actor: Optional[str] = None,
        event_data: Optional[Mapping[str, Any]] = None,
        created_at: Optional[float] = None,
    ) -> str:
        event_id = _id()
        connection.execute(
            """INSERT INTO events
               (id, campaign_id, work_item_id, job_id, event_kind, actor,
                event_data_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                campaign_id,
                work_item_id,
                job_id,
                event_kind,
                actor,
                _dump(dict(event_data or {})),
                self._clock() if created_at is None else created_at,
            ),
        )
        return event_id

    def create_campaign(
        self,
        name: str,
        *,
        campaign_id: Optional[str] = None,
        status: str = "active",
        config: Optional[Mapping[str, Any]] = None,
        global_limit: int = 4,
        role_limits: Optional[Mapping[str, int]] = None,
    ) -> Dict[str, Any]:
        if not name.strip():
            raise ValueError("campaign name must be non-empty")
        if (
            not isinstance(global_limit, int)
            or isinstance(global_limit, bool)
            or global_limit < 1
        ):
            raise ValueError("global_limit must be a positive integer")
        limits = {
            _value(role).lower(): limit
            for role, limit in (role_limits or DEFAULT_ROLE_LIMITS).items()
        }
        if set(limits) != set(DEFAULT_ROLE_LIMITS):
            raise ValueError("role limits must cover investigator, fixer, and tester exactly")
        if any(
            not isinstance(limit, int) or isinstance(limit, bool) or limit < 1
            for limit in limits.values()
        ):
            raise ValueError("role limits must be positive integers")
        status = _value(status).lower()
        if status not in VALID_CAMPAIGN_STATUSES:
            raise ValueError("unsupported campaign status: %s" % status)
        campaign_id = campaign_id or _id()
        now = self._clock()
        with self._transaction() as connection:
            connection.execute(
                """INSERT INTO campaigns
                   (id, name, status, config_json, global_limit, role_limits_json,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    campaign_id,
                    name,
                    status,
                    _dump(dict(config or {})),
                    global_limit,
                    _dump(limits),
                    now,
                    now,
                ),
            )
            self._append_event(
                connection, "campaign.created", campaign_id=campaign_id,
                event_data={"status": status}, created_at=now
            )
        return self.get_campaign(campaign_id)

    def get_campaign(self, campaign_id: str) -> Dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("campaign %s not found" % campaign_id)
        return self._row(row)  # type: ignore[return-value]

    def read_campaign_status_snapshot(
        self, campaign_id: str, *, event_limit: int = 8
    ) -> Dict[str, Any]:
        """Return one transactionally consistent snapshot with bounded events."""

        if (
            not isinstance(event_limit, int)
            or isinstance(event_limit, bool)
            or event_limit < 0
        ):
            raise ValueError("event_limit must be a non-negative integer")
        with self._read_transaction():
            captured_at = self._clock()
            campaign = self.get_campaign(campaign_id)
            worktrees = self.list_managed_worktrees(campaign_id=campaign_id)
            return {
                "captured_at": captured_at,
                "campaign": campaign,
                "items": self.list_work_items(campaign_id),
                "jobs": self.list_jobs(campaign_id=campaign_id),
                "attempts": self.list_attempts(campaign_id=campaign_id),
                "resource_leases": self.list_resource_leases(
                    campaign_id=campaign_id
                ),
                "events": self.list_events(
                    campaign_id=campaign_id, limit=event_limit
                ),
                "managed_worktrees": worktrees,
                "worktree_operations": self.list_worktree_operations(
                    campaign_id=campaign_id
                ),
            }

    def read_campaign_watch_snapshot(
        self,
        campaign_id: str,
        *,
        event_limit: int = 8,
        item_limit: int = 50,
    ) -> Dict[str, Any]:
        """Return exact totals plus bounded detail for the live monitor.

        A live refresh must have work proportional to its configured detail
        ceiling, not to the lifetime size of a campaign.  Aggregate counts are
        still exact and every returned record comes from one SQLite snapshot.
        """

        if (
            not isinstance(event_limit, int)
            or isinstance(event_limit, bool)
            or event_limit < 0
        ):
            raise ValueError("event_limit must be a non-negative integer")
        if (
            not isinstance(item_limit, int)
            or isinstance(item_limit, bool)
            or item_limit < 1
            or item_limit > 200
        ):
            raise ValueError("item_limit must be an integer from 1 to 200")

        with self._read_transaction():
            captured_at = self._clock()
            campaign = self.get_campaign(campaign_id)
            count_rows = self._connection.execute(
                """SELECT state, COUNT(*) AS item_count
                   FROM work_items WHERE campaign_id = ? GROUP BY state""",
                (campaign_id,),
            ).fetchall()
            item_state_counts = {
                str(row["state"]): int(row["item_count"]) for row in count_rows
            }
            total_items = sum(item_state_counts.values())
            item_facts = """SELECT i.*,
                    (SELECT COUNT(*) FROM jobs open_job
                     WHERE open_job.work_item_id = i.id
                       AND open_job.status IN ('pending', 'leased', 'running'))
                        AS open_job_count,
                    (SELECT COUNT(*) FROM jobs expired_job
                     WHERE expired_job.work_item_id = i.id
                       AND expired_job.status IN ('leased', 'running')
                       AND expired_job.lease_expires_at IS NOT NULL
                       AND expired_job.lease_expires_at <= ?)
                        AS expired_job_count,
                    (SELECT COUNT(*) FROM jobs process_job
                     JOIN attempts process_attempt
                       ON process_attempt.job_id = process_job.id
                     JOIN external_processes process
                       ON process.attempt_id = process_attempt.id
                     WHERE process_job.work_item_id = i.id
                       AND process.state IN ('quarantined',
                                             'legacy_unverifiable'))
                        AS process_alert_count,
                    EXISTS (
                        SELECT 1 FROM managed_worktrees quarantined_worktree
                        WHERE quarantined_worktree.work_item_id = i.id
                          AND quarantined_worktree.state = 'quarantined')
                        AS worktree_alert_count,
                    EXISTS (
                        SELECT 1 FROM managed_worktrees operation_worktree
                        JOIN worktree_operations operation
                          ON operation.managed_worktree_id = operation_worktree.id
                        WHERE operation_worktree.work_item_id = i.id
                          AND operation.status = 'quarantined'
                          AND operation.operation_number = (
                              SELECT MAX(latest_operation.operation_number)
                              FROM worktree_operations latest_operation
                              WHERE latest_operation.managed_worktree_id =
                                    operation.managed_worktree_id))
                        AS operation_alert_count
                FROM work_items i WHERE i.campaign_id = ?"""
            ranked_items = """SELECT facts.*,
                    CASE
                        WHEN process_alert_count > 0
                             OR worktree_alert_count > 0
                             OR operation_alert_count > 0 THEN 0
                        WHEN expired_job_count > 0 THEN 1
                        WHEN open_job_count > 1 THEN 2
                        WHEN state = 'blocked' THEN 3
                        ELSE 4
                    END AS hazard_rank
                FROM (%s) facts""" % item_facts
            alert_item_count = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM (%s) ranked WHERE hazard_rank < 4"
                    % ranked_items,
                    (captured_at, campaign_id),
                ).fetchone()[0]
            )
            item_rows = self._connection.execute(
                """SELECT * FROM (%s) ranked
                   ORDER BY hazard_rank, priority DESC, created_at, id LIMIT ?"""
                % ranked_items,
                (captured_at, campaign_id, item_limit),
            ).fetchall()
            items = self._rows(item_rows)
            item_ids = [str(row["id"]) for row in item_rows]

            jobs: List[Dict[str, Any]] = []
            attempts: List[Dict[str, Any]] = []
            resource_leases: List[Dict[str, Any]] = []
            worktrees: List[Dict[str, Any]] = []
            operations: List[Dict[str, Any]] = []
            if item_ids:
                item_placeholders = ",".join("?" for _ in item_ids)
                job_rows = self._connection.execute(
                    """SELECT j.* FROM jobs j
                       WHERE j.work_item_id IN (%s)
                         AND j.id = (
                             SELECT lane_job.id FROM jobs lane_job
                             WHERE lane_job.work_item_id = j.work_item_id
                             ORDER BY
                                 CASE
                                     WHEN lane_job.status IN ('leased', 'running')
                                          AND lane_job.lease_expires_at IS NOT NULL
                                          AND lane_job.lease_expires_at <= ? THEN 0
                                     WHEN lane_job.status IN (
                                         'pending', 'leased', 'running') THEN 1
                                     ELSE 2
                                 END,
                                 lane_job.updated_at DESC,
                                 lane_job.created_at DESC,
                                 lane_job.id DESC
                             LIMIT 1)
                       ORDER BY j.priority DESC, j.created_at, j.id"""
                    % item_placeholders,
                    item_ids + [captured_at],
                ).fetchall()
                jobs = self._rows(job_rows)
                job_ids = [str(row["id"]) for row in job_rows]
                if job_ids:
                    job_placeholders = ",".join("?" for _ in job_ids)
                    attempt_rows = self._connection.execute(
                        """SELECT a.*,
                                  ep.provider AS external_process_provider,
                                  ep.state AS external_process_state,
                                  ep.identity_version
                                      AS external_process_identity_version,
                                  ep.owner_uid AS external_process_owner_uid,
                                  ep.start_seconds
                                      AS external_process_start_seconds,
                                  ep.start_microseconds
                                      AS external_process_start_microseconds,
                                  ep.target_executable
                                      AS external_process_target_executable,
                                  ep.outcome AS external_process_outcome,
                                  ep.last_error AS external_process_last_error,
                                  ep.stopped_at AS external_process_stopped_at
                           FROM attempts a
                           JOIN jobs attempt_job ON attempt_job.id = a.job_id
                           LEFT JOIN external_processes ep
                             ON ep.attempt_id = a.id
                           WHERE (a.job_id IN (%s)
                                  AND a.attempt_number = (
                                      SELECT MAX(a2.attempt_number)
                                      FROM attempts a2
                                      WHERE a2.job_id = a.job_id))
                              OR (attempt_job.work_item_id IN (%s)
                                  AND ep.state IN ('quarantined',
                                                   'legacy_unverifiable')
                                  AND a.id = (
                                      SELECT critical_attempt.id
                                      FROM jobs critical_job
                                      JOIN attempts critical_attempt
                                        ON critical_attempt.job_id =
                                           critical_job.id
                                      JOIN external_processes critical_process
                                        ON critical_process.attempt_id =
                                           critical_attempt.id
                                      WHERE critical_job.work_item_id =
                                            attempt_job.work_item_id
                                        AND critical_process.state IN (
                                            'quarantined',
                                            'legacy_unverifiable')
                                      ORDER BY critical_process.recorded_at DESC,
                                               critical_attempt.attempt_number DESC,
                                               critical_attempt.id DESC
                                      LIMIT 1))
                           ORDER BY a.started_at, a.attempt_number"""
                        % (job_placeholders, item_placeholders),
                        job_ids + item_ids,
                    ).fetchall()
                    attempts = self._rows(attempt_rows)
                    lease_rows = self._connection.execute(
                        """SELECT r.* FROM resource_leases r
                           WHERE r.job_id IN (%s) ORDER BY r.resource_key"""
                        % job_placeholders,
                        job_ids,
                    ).fetchall()
                    resource_leases = self._rows(lease_rows)

                worktree_rows = self._connection.execute(
                    """SELECT w.* FROM managed_worktrees w
                       WHERE w.work_item_id IN (%s)
                       ORDER BY w.created_at, w.id""" % item_placeholders,
                    item_ids,
                ).fetchall()
                worktrees = self._rows(worktree_rows)
                worktree_ids = [str(row["id"]) for row in worktree_rows]
                if worktree_ids:
                    worktree_placeholders = ",".join("?" for _ in worktree_ids)
                    operation_rows = self._connection.execute(
                        """SELECT o.* FROM worktree_operations o
                           WHERE o.managed_worktree_id IN (%s)
                             AND o.operation_number = (
                                 SELECT MAX(o2.operation_number)
                                 FROM worktree_operations o2
                                 WHERE o2.managed_worktree_id =
                                       o.managed_worktree_id)
                           ORDER BY o.started_at, o.operation_number"""
                        % worktree_placeholders,
                        worktree_ids,
                    ).fetchall()
                    operations = self._rows(operation_rows)

            worker_rows = self._connection.execute(
                """SELECT role,
                          SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END)
                              AS queued_count,
                          SUM(CASE WHEN status IN ('leased', 'running')
                                        AND (lease_expires_at IS NULL
                                             OR lease_expires_at > ?)
                                   THEN 1 ELSE 0 END) AS active_count,
                          SUM(CASE WHEN status IN ('leased', 'running')
                                        AND lease_expires_at IS NOT NULL
                                        AND lease_expires_at <= ?
                                   THEN 1 ELSE 0 END) AS expired_count
                   FROM jobs WHERE campaign_id = ? GROUP BY role""",
                (captured_at, captured_at, campaign_id),
            ).fetchall()
            worker_counts = {
                str(row["role"]): {
                    "queued": int(row["queued_count"] or 0),
                    "active": int(row["active_count"] or 0),
                    "expired": int(row["expired_count"] or 0),
                }
                for row in worker_rows
            }
            return {
                "captured_at": captured_at,
                "campaign": campaign,
                "items": items,
                "jobs": jobs,
                "attempts": attempts,
                "resource_leases": resource_leases,
                "events": self.list_events(
                    campaign_id=campaign_id, limit=event_limit
                ),
                "managed_worktrees": worktrees,
                "worktree_operations": operations,
                "item_state_counts": item_state_counts,
                "worker_counts": worker_counts,
                "total_items": total_items,
                "omitted_item_count": total_items - len(items),
                "omitted_alert_item_count": max(
                    0,
                    alert_item_count
                    - sum(
                        1
                        for item in items
                        if int(item.get("hazard_rank", 4)) < 4
                    ),
                ),
                "omitted_open_job_count": sum(
                    max(0, int(item.get("open_job_count", 0)) - 1)
                    for item in items
                ),
            }

    def list_campaigns(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM campaigns ORDER BY created_at, id"
            ).fetchall()
        return self._rows(rows)

    def create_work_item(
        self,
        campaign_id: str,
        title: str,
        *,
        work_item_id: Optional[str] = None,
        description: str,
        state: str = "backlog",
        priority: int = 0,
        required_gates: Optional[Sequence[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        initial_job: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not title.strip() or not description.strip():
            raise ValueError("work item title and description must be non-empty")
        work_item_id = work_item_id or _id()
        now = self._clock()
        state = _value(state).lower()
        if state not in VALID_ITEM_STATES:
            raise ValueError("unsupported work item state: %s" % state)
        if state not in CREATABLE_ITEM_STATES:
            raise ValueError("work items cannot be created in an active or verified state")
        gates = [_value(gate).lower() for gate in (required_gates or DEFAULT_REQUIRED_GATES)]
        if not gates or len(gates) != len(set(gates)):
            raise ValueError("required_gates must be non-empty and unique")
        if not set(gates).issubset(VALID_GATES):
            raise ValueError("required_gates contains an unsupported gate")
        with self._transaction() as connection:
            connection.execute(
                """INSERT INTO work_items
                   (id, campaign_id, title, description, state, priority,
                    required_gates_json, metadata_json, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (work_item_id, campaign_id, title, description, state, priority,
                 _dump(gates), _dump(dict(metadata or {})), now, now),
            )
            self._append_event(
                connection, "work_item.created", campaign_id=campaign_id,
                work_item_id=work_item_id, event_data={"state": state}, created_at=now
            )
            if initial_job is not None:
                self._enqueue_job(
                    connection,
                    work_item_id,
                    _value(initial_job["role"]).lower(),
                    stage=str(initial_job["stage"]),
                    queued_item_state=_value(initial_job.get("queued_item_state", state)).lower(),
                    active_item_state=_value(initial_job["active_item_state"]).lower(),
                    payload=initial_job.get("payload"),
                    required_resources=initial_job.get("required_resources"),
                    required_approval_action=initial_job.get("required_approval_action"),
                    workspace_kind=initial_job.get("workspace_kind"),
                    managed_worktree_id=initial_job.get("managed_worktree_id"),
                    priority=int(initial_job.get("priority", priority)),
                    available_at=float(initial_job.get("available_at", now)),
                    job_id=initial_job.get("job_id"),
                    now=now,
                )
        return self.get_work_item(work_item_id)

    def get_work_item(self, work_item_id: str) -> Dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM work_items WHERE id = ?", (work_item_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("work item %s not found" % work_item_id)
        return self._row(row)  # type: ignore[return-value]

    def list_work_items(
        self, campaign_id: Optional[str] = None, *, state: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        parameters: List[Any] = []
        if campaign_id is not None:
            clauses.append("campaign_id = ?")
            parameters.append(campaign_id)
        if state is not None:
            clauses.append("state = ?")
            parameters.append(_value(state).lower())
        sql = "SELECT * FROM work_items"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY priority DESC, created_at, id"
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        return self._rows(rows)

    def enqueue_job(
        self,
        work_item_id: str,
        role: str,
        *,
        stage: str,
        queued_item_state: str,
        active_item_state: str,
        payload: Optional[Mapping[str, Any]] = None,
        required_resources: Optional[Sequence[str]] = None,
        required_approval_action: Optional[str] = None,
        workspace_kind: Optional[str] = None,
        managed_worktree_id: Optional[str] = None,
        priority: int = 0,
        available_at: Optional[float] = None,
        job_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = self._clock()
        with self._transaction() as connection:
            job = self._enqueue_job(
                connection, work_item_id, _value(role).lower(), stage=stage,
                queued_item_state=_value(queued_item_state).lower(),
                active_item_state=_value(active_item_state).lower(),
                payload=payload, required_resources=required_resources,
                required_approval_action=required_approval_action, priority=priority,
                workspace_kind=workspace_kind,
                managed_worktree_id=managed_worktree_id,
                available_at=now if available_at is None else available_at,
                job_id=job_id, now=now,
            )
        return self.get_job(job["id"])

    def _enqueue_job(
        self,
        connection: sqlite3.Connection,
        work_item_id: str,
        role: str,
        *,
        stage: str,
        queued_item_state: str,
        active_item_state: str,
        payload: Optional[Mapping[str, Any]],
        required_resources: Optional[Sequence[str]],
        required_approval_action: Optional[str],
        workspace_kind: Optional[str],
        managed_worktree_id: Optional[str],
        priority: int,
        available_at: float,
        job_id: Optional[str],
        now: float,
    ) -> Dict[str, Any]:
        item = connection.execute(
            """SELECT i.campaign_id, i.state, c.config_json
               FROM work_items i JOIN campaigns c ON c.id = i.campaign_id
               WHERE i.id = ?""",
            (work_item_id,),
        ).fetchone()
        if item is None:
            raise NotFoundError("work item %s not found" % work_item_id)
        if item["state"] != queued_item_state:
            raise TransitionConflict(
                "cannot enqueue %s job while item is %s (expected %s)"
                % (role, item["state"], queued_item_state)
            )
        expected_states = ROLE_STATES.get(role)
        if expected_states is None:
            raise ValueError("unsupported worker role: %s" % role)
        if (queued_item_state, active_item_state) != expected_states:
            raise ValueError(
                "%s jobs must use %s -> %s"
                % (role, expected_states[0], expected_states[1])
            )
        if not stage.strip():
            raise ValueError("job stage must be non-empty")
        campaign_config = _load(item["config_json"], {})
        if workspace_kind is None:
            if (
                role in ("fixer", "tester")
                and campaign_config.get("allow_simulated_evidence") is True
            ):
                workspace_kind = WorkspaceKind.SIMULATED.value
            elif role == "fixer":
                workspace_kind = WorkspaceKind.MANAGED_WORKTREE.value
            else:
                workspace_kind = WorkspaceKind.SOURCE_READ_ONLY.value
        workspace_kind = _value(workspace_kind).lower()
        if workspace_kind not in VALID_WORKSPACE_KINDS:
            raise ValueError("unsupported workspace kind: %s" % workspace_kind)
        allow_simulated = campaign_config.get("allow_simulated_evidence") is True
        if workspace_kind == WorkspaceKind.SIMULATED.value and not allow_simulated:
            raise ValueError(
                "simulated workspace jobs require campaign simulation policy"
            )
        if role == "fixer" and workspace_kind not in (
            WorkspaceKind.MANAGED_WORKTREE.value,
            WorkspaceKind.SIMULATED.value,
        ):
            raise ValueError(
                "fixer jobs require a managed worktree or explicit simulation"
            )
        if managed_worktree_id is not None:
            managed_worktree_id = str(managed_worktree_id)
            if workspace_kind != WorkspaceKind.MANAGED_WORKTREE.value:
                raise ValueError(
                    "managed_worktree_id requires managed_worktree workspace kind"
                )
            managed = connection.execute(
                """SELECT * FROM managed_worktrees
                   WHERE id = ? AND campaign_id = ? AND work_item_id = ?
                     AND state = 'ready'""",
                (managed_worktree_id, item["campaign_id"], work_item_id),
            ).fetchone()
            if managed is None:
                raise TransitionConflict(
                    "managed worktree is not ready for the successor job"
                )
        elif (
            workspace_kind == WorkspaceKind.MANAGED_WORKTREE.value
            and role != "fixer"
        ):
            raise ValueError(
                "only a pending fixer may await managed worktree provisioning"
            )
        resources = set(required_resources or [])
        if any(
            str(resource).startswith(WORKTREE_RESOURCE_PREFIX)
            for resource in resources
        ):
            raise ValueError(
                "git-worktree resource keys are reserved for supervisor bindings"
            )
        if managed_worktree_id is not None:
            resources.add(WORKTREE_RESOURCE_PREFIX + managed_worktree_id)
        resources = sorted(resources)
        if any(not str(resource).strip() for resource in resources):
            raise ValueError("required resource keys must be non-empty")
        if required_approval_action is not None and not required_approval_action.strip():
            raise ValueError("required approval action must be non-empty")
        job_id = job_id or _id()
        connection.execute(
            """INSERT INTO jobs
               (id, campaign_id, work_item_id, role, stage, status, priority,
                payload_json, required_resources_json, queued_item_state,
                active_item_state, required_approval_action, workspace_kind,
                managed_worktree_id, available_at, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (job_id, item["campaign_id"], work_item_id, role, stage, priority,
             _dump(dict(payload or {})), _dump(resources), queued_item_state,
             active_item_state, required_approval_action, workspace_kind,
             managed_worktree_id, available_at, now, now),
        )
        self._append_event(
            connection, "job.enqueued", campaign_id=item["campaign_id"],
            work_item_id=work_item_id, job_id=job_id,
            event_data={"role": role, "stage": stage}, created_at=now
        )
        return {"id": job_id}

    def get_job(self, job_id: str) -> Dict[str, Any]:
        with self._lock:
            row = self._connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            raise NotFoundError("job %s not found" % job_id)
        return self._row(row)  # type: ignore[return-value]

    def list_jobs(
        self, *, campaign_id: Optional[str] = None, work_item_id: Optional[str] = None,
        role: Optional[str] = None, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        parameters: List[Any] = []
        for column, value in (("campaign_id", campaign_id), ("work_item_id", work_item_id),
                              ("role", role), ("status", status)):
            if value is not None:
                clauses.append(column + " = ?")
                parameters.append(
                    _value(value).lower() if column in ("role", "status") else value
                )
        sql = "SELECT * FROM jobs" + ((" WHERE " + " AND ".join(clauses)) if clauses else "")
        sql += " ORDER BY priority DESC, created_at, id"
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        return self._rows(rows)

    @staticmethod
    def _validate_worktree_path(label: str, value: str) -> str:
        normalized = str(Path(value).expanduser().resolve())
        if not Path(normalized).is_absolute() or len(normalized) > 4096:
            raise ValueError("%s must be an absolute path" % label)
        return normalized

    def request_managed_worktree(
        self,
        campaign_id: str,
        work_item_id: str,
        *,
        worktree_id: str,
        repository_path: str,
        source_git_common_dir: str,
        source_git_dir: str,
        source_device: int,
        source_inode: int,
        source_owner_uid: int,
        object_format: str,
        worktree_path: str,
        branch_ref: str,
        base_revision: str,
        base_tree: str,
        lock_reason: str,
        source_snapshot: Mapping[str, Any],
        owner: str,
        lease_seconds: float = 900.0,
    ) -> Dict[str, Any]:
        """Persist exact creation intent and its fence before Git can run."""

        owner = owner.strip()
        if not owner or len(owner) > 256:
            raise ValueError("worktree operation owner must contain 1 to 256 characters")
        if lease_seconds <= 0:
            raise ValueError("worktree operation lease must be positive")
        if not worktree_id.strip() or len(worktree_id) > 128:
            raise ValueError("worktree id must contain 1 to 128 characters")
        repository_path = self._validate_worktree_path(
            "repository_path", repository_path
        )
        source_git_common_dir = self._validate_worktree_path(
            "source_git_common_dir", source_git_common_dir
        )
        source_git_dir = self._validate_worktree_path(
            "source_git_dir", source_git_dir
        )
        worktree_path = self._validate_worktree_path(
            "worktree_path", worktree_path
        )
        for label, value in (
            ("source_device", source_device),
            ("source_inode", source_inode),
            ("source_owner_uid", source_owner_uid),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError("%s must be a non-negative integer" % label)
        for label, value in (
            ("object_format", object_format),
            ("branch_ref", branch_ref),
            ("base_revision", base_revision),
            ("base_tree", base_tree),
            ("lock_reason", lock_reason),
        ):
            if not value.strip() or len(value) > 4096:
                raise ValueError("%s must be non-empty" % label)
        if not branch_ref.startswith("refs/heads/"):
            raise ValueError("managed branch must be a full refs/heads ref")

        with self._transaction() as connection:
            now = self._clock()
            item = connection.execute(
                """SELECT i.*, c.config_json
                   FROM work_items i JOIN campaigns c ON c.id = i.campaign_id
                   WHERE i.id = ? AND i.campaign_id = ?""",
                (work_item_id, campaign_id),
            ).fetchone()
            if item is None:
                raise NotFoundError("work item is absent from the requested campaign")
            if item["state"] != "ready_for_fix":
                raise TransitionConflict(
                    "managed worktrees can be requested only for ready-for-fix items"
                )
            campaign_config = _load(item["config_json"], {})
            if repository_path not in _canonical_repository_scope(campaign_config):
                raise TransitionConflict(
                    "repository is outside the campaign repository scope"
                )
            approvals = connection.execute(
                """SELECT scope_json FROM approvals
                   WHERE campaign_id = ? AND action = 'local_code_changes'
                     AND status = 'approved'
                     AND (work_item_id IS NULL OR work_item_id = ?)""",
                (campaign_id, work_item_id),
            ).fetchall()
            if not any(
                _approval_covers_repository(
                    campaign_config,
                    repository_path,
                    _load(approval["scope_json"], {}),
                )
                for approval in approvals
            ):
                raise TransitionConflict(
                    "approved local-write scope does not cover the canonical repository"
                )
            fixer_job = connection.execute(
                """SELECT * FROM jobs
                   WHERE work_item_id = ? AND role = 'fixer' AND status = 'pending'
                   ORDER BY created_at, id LIMIT 1""",
                (work_item_id,),
            ).fetchone()
            if fixer_job is None:
                raise TransitionConflict(
                    "ready-for-fix item has no pending fixer job"
                )
            if (
                fixer_job["workspace_kind"]
                != WorkspaceKind.MANAGED_WORKTREE.value
                or fixer_job["managed_worktree_id"] is not None
            ):
                raise TransitionConflict(
                    "pending fixer job is not awaiting a managed worktree"
                )
            existing = connection.execute(
                "SELECT id FROM managed_worktrees WHERE work_item_id = ?",
                (work_item_id,),
            ).fetchone()
            if existing is not None:
                raise TransitionConflict(
                    "work item already has a durable managed worktree"
                )

            operation_id = _id()
            token = _id()
            expires_at = now + lease_seconds
            expected_identity = {
                "worktree_id": worktree_id,
                "generation": 1,
                "campaign_id": campaign_id,
                "work_item_id": work_item_id,
                "fixer_job_id": str(fixer_job["id"]),
                "repository_path": repository_path,
                "source_git_common_dir": source_git_common_dir,
                "source_git_dir": source_git_dir,
                "source_device": source_device,
                "source_inode": source_inode,
                "source_owner_uid": source_owner_uid,
                "object_format": object_format,
                "worktree_path": worktree_path,
                "branch_ref": branch_ref,
                "base_revision": base_revision,
                "base_tree": base_tree,
                "lock_reason": lock_reason,
                "source_snapshot": dict(source_snapshot),
            }
            connection.execute(
                """INSERT INTO managed_worktrees
                   (id, generation, campaign_id, work_item_id, fixer_job_id,
                    repository_path,
                    source_git_common_dir, source_git_dir, source_device,
                    source_inode, source_owner_uid, object_format, worktree_path,
                    branch_ref, base_revision, base_tree, lock_reason,
                    source_snapshot_json, state, created_at, updated_at)
                   VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                           'provisioning', ?, ?)""",
                (
                    worktree_id,
                    campaign_id,
                    work_item_id,
                    fixer_job["id"],
                    repository_path,
                    source_git_common_dir,
                    source_git_dir,
                    source_device,
                    source_inode,
                    source_owner_uid,
                    object_format,
                    worktree_path,
                    branch_ref,
                    base_revision,
                    base_tree,
                    lock_reason,
                    _dump(dict(source_snapshot)),
                    now,
                    now,
                ),
            )
            connection.execute(
                """INSERT INTO worktree_operations
                   (id, managed_worktree_id, operation_number, kind, status,
                    owner, fencing_token, lease_expires_at,
                    expected_identity_json, started_at, updated_at)
                   VALUES (?, ?, 1, 'create', 'running', ?, ?, ?, ?, ?, ?)""",
                (
                    operation_id,
                    worktree_id,
                    owner,
                    token,
                    expires_at,
                    _dump(expected_identity),
                    now,
                    now,
                ),
            )
            self._append_event(
                connection,
                "worktree.provisioning_started",
                campaign_id=campaign_id,
                work_item_id=work_item_id,
                actor=owner,
                event_data={
                    "worktree_id": worktree_id,
                    "operation_id": operation_id,
                    "repository_path": repository_path,
                    "worktree_path": worktree_path,
                    "branch_ref": branch_ref,
                    "base_revision": base_revision,
                },
                created_at=now,
            )
            return {
                "worktree": self._row(
                    connection.execute(
                        "SELECT * FROM managed_worktrees WHERE id = ?",
                        (worktree_id,),
                    ).fetchone()
                ),
                "operation": self._row(
                    connection.execute(
                        "SELECT * FROM worktree_operations WHERE id = ?",
                        (operation_id,),
                    ).fetchone()
                ),
            }

    def _assert_worktree_operation_fence(
        self,
        connection: sqlite3.Connection,
        operation_id: str,
        owner: str,
        token: str,
        now: float,
        *,
        reconciliation: bool = False,
    ) -> sqlite3.Row:
        operation = connection.execute(
            "SELECT * FROM worktree_operations WHERE id = ?",
            (operation_id,),
        ).fetchone()
        if operation is None:
            raise NotFoundError("worktree operation %s not found" % operation_id)
        if reconciliation:
            valid = (
                operation["reconciliation_owner"] == owner
                and operation["reconciliation_token"] == token
                and operation["reconciliation_expires_at"] is not None
                and operation["reconciliation_expires_at"] > now
            )
        else:
            valid = (
                operation["status"] == "running"
                and operation["owner"] == owner
                and operation["fencing_token"] == token
                and operation["lease_expires_at"] > now
            )
        if not valid:
            raise LeaseConflict("worktree operation fence is stale")
        return operation

    def record_worktree_operation_process(
        self,
        operation_id: str,
        owner: str,
        token: str,
        *,
        process_id: int,
        process_group_id: int,
        process_owner_uid: int,
        process_start_seconds: int,
        process_start_microseconds: int,
        process_kernel_executable: str,
        process_target_executable: str,
    ) -> Dict[str, Any]:
        if process_id <= 1 or process_group_id != process_id:
            raise ValueError("worktree operation launcher must lead its process group")
        if process_owner_uid < 0 or process_start_seconds <= 0:
            raise ValueError("worktree operation process identity is incomplete")
        if not 0 <= process_start_microseconds < 1_000_000:
            raise ValueError("worktree operation process birth microseconds are invalid")
        for executable in (
            process_kernel_executable,
            process_target_executable,
        ):
            if not Path(executable).is_absolute():
                raise ValueError("worktree operation executables must be absolute")
        with self._transaction() as connection:
            now = self._clock()
            operation = self._assert_worktree_operation_fence(
                connection, operation_id, owner, token, now
            )
            if operation["process_id"] is not None:
                raise LeaseConflict("worktree operation already has a process binding")
            changed = connection.execute(
                """UPDATE worktree_operations
                   SET process_id = ?, process_group_id = ?, process_owner_uid = ?,
                       process_start_seconds = ?, process_start_microseconds = ?,
                       process_kernel_executable = ?, process_target_executable = ?,
                       process_identity_version = 'darwin_libproc_v1',
                       process_state = 'active', updated_at = ?
                   WHERE id = ? AND process_id IS NULL""",
                (
                    process_id,
                    process_group_id,
                    process_owner_uid,
                    process_start_seconds,
                    process_start_microseconds,
                    process_kernel_executable,
                    process_target_executable,
                    now,
                    operation_id,
                ),
            ).rowcount
            if changed != 1:
                raise LeaseConflict("worktree operation process changed concurrently")
            worktree = connection.execute(
                "SELECT * FROM managed_worktrees WHERE id = ?",
                (operation["managed_worktree_id"],),
            ).fetchone()
            self._append_event(
                connection,
                "worktree.process_started",
                campaign_id=worktree["campaign_id"],
                work_item_id=worktree["work_item_id"],
                actor=owner,
                event_data={
                    "worktree_id": worktree["id"],
                    "operation_id": operation_id,
                    "process_id": process_id,
                    "process_group_id": process_group_id,
                    "target_executable": process_target_executable,
                },
                created_at=now,
            )
            return self._row(
                connection.execute(
                    "SELECT * FROM worktree_operations WHERE id = ?",
                    (operation_id,),
                ).fetchone()
            )  # type: ignore[return-value]

    def clear_worktree_operation_process(
        self,
        operation_id: str,
        owner: str,
        token: str,
        process_id: int,
        process_group_id: int,
        *,
        reconciliation: bool = False,
    ) -> Dict[str, Any]:
        with self._transaction() as connection:
            now = self._clock()
            operation = self._assert_worktree_operation_fence(
                connection,
                operation_id,
                owner,
                token,
                now,
                reconciliation=reconciliation,
            )
            changed = connection.execute(
                """UPDATE worktree_operations
                   SET process_state = 'stopped', process_stopped_at = ?,
                       updated_at = ?
                   WHERE id = ? AND process_state = 'active'
                     AND process_id = ? AND process_group_id = ?""",
                (now, now, operation_id, process_id, process_group_id),
            ).rowcount
            if changed != 1:
                raise LeaseConflict("worktree operation process is absent or changed")
            worktree = connection.execute(
                "SELECT * FROM managed_worktrees WHERE id = ?",
                (operation["managed_worktree_id"],),
            ).fetchone()
            self._append_event(
                connection,
                "worktree.process_stopped",
                campaign_id=worktree["campaign_id"],
                work_item_id=worktree["work_item_id"],
                actor=owner,
                event_data={
                    "worktree_id": worktree["id"],
                    "operation_id": operation_id,
                    "process_id": process_id,
                    "process_group_id": process_group_id,
                },
                created_at=now,
            )
            return self._row(
                connection.execute(
                    "SELECT * FROM worktree_operations WHERE id = ?",
                    (operation_id,),
                ).fetchone()
            )  # type: ignore[return-value]

    def record_worktree_operation_artifacts(
        self,
        operation_id: str,
        owner: str,
        token: str,
        *,
        stdout_path: str,
        stdout_sha256: str,
        stderr_path: str,
        stderr_sha256: str,
        reconciliation: bool = False,
    ) -> Dict[str, Any]:
        paths = (Path(stdout_path), Path(stderr_path))
        if any(
            not path.is_absolute()
            or path.is_symlink()
            or not path.is_file()
            or path.stat().st_uid != os.getuid()
            for path in paths
        ):
            raise ValueError("worktree operation artifacts must be existing absolute files")
        hashes = (stdout_sha256, stderr_sha256)
        if any(
            len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in hashes
        ):
            raise ValueError("worktree operation artifact hashes must be SHA-256 hex")
        if any(
            self._sha256_file(path) != expected
            for path, expected in zip(paths, hashes)
        ):
            raise ValueError("worktree operation artifact hash does not match its file")
        with self._transaction() as connection:
            now = self._clock()
            operation = self._assert_worktree_operation_fence(
                connection,
                operation_id,
                owner,
                token,
                now,
                reconciliation=reconciliation,
            )
            resolved = tuple(str(path.resolve()) for path in paths)
            persisted_paths = (operation["stdout_path"], operation["stderr_path"])
            if any(
                persisted is not None and persisted != requested
                for persisted, requested in zip(persisted_paths, resolved)
            ):
                raise LeaseConflict("worktree artifact path intent changed")
            connection.execute(
                """UPDATE worktree_operations
                   SET stdout_path = ?, stdout_sha256 = ?, stderr_path = ?,
                       stderr_sha256 = ?, updated_at = ? WHERE id = ?""",
                (
                    resolved[0],
                    stdout_sha256,
                    resolved[1],
                    stderr_sha256,
                    now,
                    operation_id,
                ),
            )
            return self._row(
                connection.execute(
                    "SELECT * FROM worktree_operations WHERE id = ?",
                    (operation_id,),
                ).fetchone()
            )  # type: ignore[return-value]

    def record_worktree_operation_artifact_intent(
        self,
        operation_id: str,
        owner: str,
        token: str,
        *,
        stdout_path: str,
        stderr_path: str,
    ) -> Dict[str, Any]:
        paths = (Path(stdout_path), Path(stderr_path))
        if any(not path.is_absolute() for path in paths) or paths[0] == paths[1]:
            raise ValueError("worktree artifact intent requires distinct absolute paths")
        resolved = tuple(str(path.resolve()) for path in paths)
        with self._transaction() as connection:
            now = self._clock()
            operation = self._assert_worktree_operation_fence(
                connection, operation_id, owner, token, now
            )
            existing = (operation["stdout_path"], operation["stderr_path"])
            if any(existing):
                if existing != resolved:
                    raise LeaseConflict("worktree artifact intent already changed")
                return self._row(operation)  # type: ignore[return-value]
            connection.execute(
                """UPDATE worktree_operations
                   SET stdout_path = ?, stderr_path = ?, updated_at = ?
                   WHERE id = ? AND stdout_path IS NULL AND stderr_path IS NULL""",
                (resolved[0], resolved[1], now, operation_id),
            )
            return self._row(
                connection.execute(
                    "SELECT * FROM worktree_operations WHERE id = ?",
                    (operation_id,),
                ).fetchone()
            )  # type: ignore[return-value]

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    return digest.hexdigest()
                digest.update(chunk)

    @staticmethod
    def _assert_worktree_operation_process_stopped(
        operation: sqlite3.Row,
    ) -> None:
        if operation["process_id"] is None:
            raise LeaseConflict(
                "worktree lifecycle completion requires a durable guardian identity"
            )
        if operation["process_state"] != "stopped":
            raise LeaseConflict(
                "worktree Git process must be reaped before lifecycle completion"
            )
        if any(
            operation[column] is None
            for column in (
                "stdout_path",
                "stdout_sha256",
                "stderr_path",
                "stderr_sha256",
            )
        ):
            raise LeaseConflict(
                "worktree lifecycle completion requires hashed command artifacts"
            )

    def complete_managed_worktree_creation(
        self,
        operation_id: str,
        owner: str,
        token: str,
        expected_identity: Mapping[str, Any],
        observed_identity: Mapping[str, Any],
        source_snapshot_after: Mapping[str, Any],
        *,
        reconciliation: bool = False,
    ) -> Dict[str, Any]:
        with self._transaction() as connection:
            now = self._clock()
            operation = self._assert_worktree_operation_fence(
                connection,
                operation_id,
                owner,
                token,
                now,
                reconciliation=reconciliation,
            )
            if operation["kind"] != "create" or operation["status"] != "running":
                raise TransitionConflict("worktree creation operation is not running")
            self._assert_worktree_operation_process_stopped(operation)
            if _load(operation["expected_identity_json"], {}) != dict(
                expected_identity
            ):
                raise LeaseConflict("worktree creation identity fence changed")
            worktree = connection.execute(
                "SELECT * FROM managed_worktrees WHERE id = ?",
                (operation["managed_worktree_id"],),
            ).fetchone()
            if worktree is None or worktree["state"] != "provisioning":
                raise TransitionConflict("managed worktree is not provisioning")
            if _load(worktree["source_snapshot_json"], {}) != dict(
                source_snapshot_after
            ):
                raise TransitionConflict(
                    "source checkout changed during worktree provisioning"
                )
            required_observed = {
                "worktree_id": worktree["id"],
                "repository_path": worktree["repository_path"],
                "source_git_common_dir": worktree["source_git_common_dir"],
                "worktree_path": worktree["worktree_path"],
                "branch_ref": worktree["branch_ref"],
                "base_revision": worktree["base_revision"],
                "head_revision": worktree["base_revision"],
                "head_tree": worktree["base_tree"],
                "object_format": worktree["object_format"],
                "lock_reason": worktree["lock_reason"],
            }
            if any(
                observed_identity.get(key) != value
                for key, value in required_observed.items()
            ):
                raise TransitionConflict(
                    "observed worktree identity does not match durable creation intent"
                )
            for key in (
                "worktree_git_dir",
                "worktree_device",
                "worktree_inode",
                "worktree_owner_uid",
            ):
                if observed_identity.get(key) is None:
                    raise ValueError("observed worktree identity omitted %s" % key)

            changed = connection.execute(
                """UPDATE managed_worktrees
                   SET worktree_git_dir = ?, worktree_device = ?,
                       worktree_inode = ?, worktree_owner_uid = ?,
                       head_revision = ?, state = 'ready', ready_at = ?,
                       last_error = NULL, updated_at = ?
                   WHERE id = ? AND state = 'provisioning'""",
                (
                    observed_identity["worktree_git_dir"],
                    observed_identity["worktree_device"],
                    observed_identity["worktree_inode"],
                    observed_identity["worktree_owner_uid"],
                    observed_identity["head_revision"],
                    now,
                    now,
                    worktree["id"],
                ),
            ).rowcount
            if changed != 1:
                raise TransitionConflict("managed worktree changed before readiness")
            operation_changed = connection.execute(
                """UPDATE worktree_operations
                   SET status = 'succeeded', observed_identity_json = ?,
                       error = NULL, finished_at = ?, updated_at = ?,
                       reconciliation_owner = NULL,
                       reconciliation_token = NULL,
                       reconciliation_expires_at = NULL
                   WHERE id = ? AND status = 'running'""",
                (_dump(dict(observed_identity)), now, now, operation_id),
            ).rowcount
            if operation_changed != 1:
                raise LeaseConflict("worktree creation operation changed before completion")

            fixer_job = connection.execute(
                """SELECT * FROM jobs
                   WHERE id = ? AND work_item_id = ? AND role = 'fixer'
                     AND status = 'pending'""",
                (worktree["fixer_job_id"], worktree["work_item_id"]),
            ).fetchone()
            if fixer_job is None:
                raise TransitionConflict("managed worktree has no pending fixer job")
            resources = set(_load(fixer_job["required_resources_json"], []))
            resources.add(WORKTREE_RESOURCE_PREFIX + str(worktree["id"]))
            attached = connection.execute(
                """UPDATE jobs
                   SET managed_worktree_id = ?, required_resources_json = ?,
                       updated_at = ?
                   WHERE id = ? AND status = 'pending'
                     AND workspace_kind = 'managed_worktree'
                     AND managed_worktree_id IS NULL""",
                (
                    worktree["id"],
                    _dump(sorted(resources)),
                    now,
                    fixer_job["id"],
                ),
            ).rowcount
            if attached != 1:
                raise TransitionConflict("pending fixer changed before worktree attachment")
            self._append_event(
                connection,
                "worktree.ready",
                campaign_id=worktree["campaign_id"],
                work_item_id=worktree["work_item_id"],
                job_id=fixer_job["id"],
                actor=owner,
                event_data={
                    "worktree_id": worktree["id"],
                    "operation_id": operation_id,
                    "worktree_path": worktree["worktree_path"],
                    "branch_ref": worktree["branch_ref"],
                    "base_revision": worktree["base_revision"],
                    "resource_key": WORKTREE_RESOURCE_PREFIX + str(worktree["id"]),
                },
                created_at=now,
            )
            return self._row(
                connection.execute(
                    "SELECT * FROM managed_worktrees WHERE id = ?",
                    (worktree["id"],),
                ).fetchone()
            )  # type: ignore[return-value]

    def quarantine_worktree_operation(
        self,
        operation_id: str,
        owner: str,
        token: str,
        expected_identity: Mapping[str, Any],
        reason: str,
        *,
        observed_identity: Optional[Mapping[str, Any]] = None,
        reconciliation: bool = False,
        allow_active_process: bool = False,
    ) -> Dict[str, Any]:
        reason = reason.strip()
        if not reason or len(reason) > 4096:
            raise ValueError("worktree quarantine reason must be non-empty")
        with self._transaction() as connection:
            now = self._clock()
            operation = self._assert_worktree_operation_fence(
                connection,
                operation_id,
                owner,
                token,
                now,
                reconciliation=reconciliation,
            )
            if _load(operation["expected_identity_json"], {}) != dict(
                expected_identity
            ):
                raise LeaseConflict("worktree operation identity fence changed")
            if (
                not allow_active_process
                and operation["process_state"] == "active"
            ):
                raise LeaseConflict(
                    "active worktree Git process must be reconciled before quarantine"
                )
            worktree = connection.execute(
                "SELECT * FROM managed_worktrees WHERE id = ?",
                (operation["managed_worktree_id"],),
            ).fetchone()
            connection.execute(
                """UPDATE managed_worktrees
                   SET state = 'quarantined', last_error = ?, updated_at = ?
                   WHERE id = ? AND state != 'removed'""",
                (reason, now, worktree["id"]),
            )
            connection.execute(
                """UPDATE worktree_operations
                   SET status = 'quarantined', observed_identity_json = ?,
                       error = ?, finished_at = ?, updated_at = ?,
                       reconciliation_owner = NULL,
                       reconciliation_token = NULL,
                       reconciliation_expires_at = NULL
                   WHERE id = ?""",
                (
                    _dump(dict(observed_identity or {})),
                    reason,
                    now,
                    now,
                    operation_id,
                ),
            )
            self._append_event(
                connection,
                "worktree.quarantined",
                campaign_id=worktree["campaign_id"],
                work_item_id=worktree["work_item_id"],
                actor=owner,
                event_data={
                    "worktree_id": worktree["id"],
                    "operation_id": operation_id,
                    "reason": reason,
                    "process_still_active": operation["process_state"] == "active",
                },
                created_at=now,
            )
            return self._row(
                connection.execute(
                    "SELECT * FROM managed_worktrees WHERE id = ?",
                    (worktree["id"],),
                ).fetchone()
            )  # type: ignore[return-value]

    def request_managed_worktree_cleanup(
        self,
        worktree_id: str,
        owner: str,
        *,
        lease_seconds: float = 900.0,
    ) -> Dict[str, Any]:
        owner = owner.strip()
        if not owner or lease_seconds <= 0:
            raise ValueError("cleanup owner and positive lease are required")
        with self._transaction() as connection:
            now = self._clock()
            worktree = connection.execute(
                "SELECT * FROM managed_worktrees WHERE id = ?",
                (worktree_id,),
            ).fetchone()
            if worktree is None:
                raise NotFoundError("managed worktree %s not found" % worktree_id)
            if worktree["state"] != "ready":
                raise TransitionConflict("only a ready managed worktree can be cleaned up")
            item = connection.execute(
                "SELECT state FROM work_items WHERE id = ?",
                (worktree["work_item_id"],),
            ).fetchone()
            if item["state"] not in ("verified_green", "blocked"):
                raise TransitionConflict(
                    "worktree cleanup requires a terminal item state"
                )
            open_job = connection.execute(
                """SELECT 1 FROM jobs
                   WHERE work_item_id = ? AND status IN ('pending', 'running')
                   LIMIT 1""",
                (worktree["work_item_id"],),
            ).fetchone()
            if open_job is not None:
                raise LeaseConflict("worktree still has an open job")
            resource = connection.execute(
                "SELECT 1 FROM resource_leases WHERE resource_key = ?",
                (WORKTREE_RESOURCE_PREFIX + worktree_id,),
            ).fetchone()
            if resource is not None:
                raise LeaseConflict("worktree resource is still leased")
            live_process = connection.execute(
                """SELECT 1 FROM external_processes ep
                   JOIN attempts a ON a.id = ep.attempt_id
                   WHERE a.managed_worktree_id = ? AND ep.state != 'stopped'
                   LIMIT 1""",
                (worktree_id,),
            ).fetchone()
            if live_process is not None:
                raise LeaseConflict("worktree still has an unresolved worker process")

            operation_number = int(
                connection.execute(
                    """SELECT COALESCE(MAX(operation_number), 0)
                       FROM worktree_operations WHERE managed_worktree_id = ?""",
                    (worktree_id,),
                ).fetchone()[0]
            ) + 1
            operation_id = _id()
            token = _id()
            expected_identity = {
                "worktree_id": worktree_id,
                "generation": worktree["generation"],
                "repository_path": worktree["repository_path"],
                "source_git_common_dir": worktree["source_git_common_dir"],
                "worktree_path": worktree["worktree_path"],
                "worktree_git_dir": worktree["worktree_git_dir"],
                "worktree_device": worktree["worktree_device"],
                "worktree_inode": worktree["worktree_inode"],
                "worktree_owner_uid": worktree["worktree_owner_uid"],
                "branch_ref": worktree["branch_ref"],
                "base_revision": worktree["base_revision"],
                "head_revision": worktree["head_revision"],
                "lock_reason": worktree["lock_reason"],
                "source_snapshot": _load(worktree["source_snapshot_json"], {}),
            }
            connection.execute(
                """UPDATE managed_worktrees
                   SET state = 'cleanup_pending', cleanup_started_at = ?,
                       last_error = NULL, updated_at = ?
                   WHERE id = ? AND state = 'ready'""",
                (now, now, worktree_id),
            )
            connection.execute(
                """INSERT INTO worktree_operations
                   (id, managed_worktree_id, operation_number, kind, status,
                    owner, fencing_token, lease_expires_at,
                    expected_identity_json, started_at, updated_at)
                   VALUES (?, ?, ?, 'remove', 'running', ?, ?, ?, ?, ?, ?)""",
                (
                    operation_id,
                    worktree_id,
                    operation_number,
                    owner,
                    token,
                    now + lease_seconds,
                    _dump(expected_identity),
                    now,
                    now,
                ),
            )
            self._append_event(
                connection,
                "worktree.cleanup_started",
                campaign_id=worktree["campaign_id"],
                work_item_id=worktree["work_item_id"],
                actor=owner,
                event_data={
                    "worktree_id": worktree_id,
                    "operation_id": operation_id,
                },
                created_at=now,
            )
            return {
                "worktree": self._row(
                    connection.execute(
                        "SELECT * FROM managed_worktrees WHERE id = ?",
                        (worktree_id,),
                    ).fetchone()
                ),
                "operation": self._row(
                    connection.execute(
                        "SELECT * FROM worktree_operations WHERE id = ?",
                        (operation_id,),
                    ).fetchone()
                ),
            }

    def complete_managed_worktree_removal(
        self,
        operation_id: str,
        owner: str,
        token: str,
        expected_identity: Mapping[str, Any],
        observed_identity: Mapping[str, Any],
        source_snapshot_after: Mapping[str, Any],
        *,
        reconciliation: bool = False,
    ) -> Dict[str, Any]:
        with self._transaction() as connection:
            now = self._clock()
            operation = self._assert_worktree_operation_fence(
                connection,
                operation_id,
                owner,
                token,
                now,
                reconciliation=reconciliation,
            )
            if operation["kind"] != "remove" or operation["status"] != "running":
                raise TransitionConflict("worktree removal operation is not running")
            self._assert_worktree_operation_process_stopped(operation)
            if _load(operation["expected_identity_json"], {}) != dict(
                expected_identity
            ):
                raise LeaseConflict("worktree removal identity fence changed")
            worktree = connection.execute(
                "SELECT * FROM managed_worktrees WHERE id = ?",
                (operation["managed_worktree_id"],),
            ).fetchone()
            if worktree is None or worktree["state"] != "cleanup_pending":
                raise TransitionConflict("managed worktree is not pending cleanup")
            if _load(worktree["source_snapshot_json"], {}) != dict(
                source_snapshot_after
            ):
                raise TransitionConflict("source checkout changed during worktree cleanup")
            if (
                observed_identity.get("worktree_id") != worktree["id"]
                or observed_identity.get("path_absent") is not True
                or observed_identity.get("registry_absent") is not True
                or observed_identity.get("branch_ref") != worktree["branch_ref"]
                or observed_identity.get("branch_head_revision")
                != worktree["head_revision"]
            ):
                raise TransitionConflict("worktree absence or retained branch was not proven")
            connection.execute(
                """UPDATE managed_worktrees
                   SET state = 'removed', removed_at = ?, last_error = NULL,
                       updated_at = ? WHERE id = ? AND state = 'cleanup_pending'""",
                (now, now, worktree["id"]),
            )
            connection.execute(
                """UPDATE worktree_operations
                   SET status = 'succeeded', observed_identity_json = ?,
                       finished_at = ?, updated_at = ?, error = NULL,
                       reconciliation_owner = NULL,
                       reconciliation_token = NULL,
                       reconciliation_expires_at = NULL
                   WHERE id = ? AND status = 'running'""",
                (_dump(dict(observed_identity)), now, now, operation_id),
            )
            self._append_event(
                connection,
                "worktree.removed",
                campaign_id=worktree["campaign_id"],
                work_item_id=worktree["work_item_id"],
                actor=owner,
                event_data={
                    "worktree_id": worktree["id"],
                    "operation_id": operation_id,
                    "branch_retained": worktree["branch_ref"],
                },
                created_at=now,
            )
            return self._row(
                connection.execute(
                    "SELECT * FROM managed_worktrees WHERE id = ?",
                    (worktree["id"],),
                ).fetchone()
            )  # type: ignore[return-value]

    def get_managed_worktree(self, worktree_id: str) -> Dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM managed_worktrees WHERE id = ?",
                (worktree_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("managed worktree %s not found" % worktree_id)
        return self._row(row)  # type: ignore[return-value]

    def list_managed_worktrees(
        self,
        *,
        campaign_id: Optional[str] = None,
        work_item_id: Optional[str] = None,
        state: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        parameters: List[Any] = []
        for column, value in (
            ("campaign_id", campaign_id),
            ("work_item_id", work_item_id),
            ("state", state),
        ):
            if value is not None:
                clauses.append(column + " = ?")
                parameters.append(value)
        sql = "SELECT * FROM managed_worktrees"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at, id"
        with self._lock:
            return self._rows(self._connection.execute(sql, parameters).fetchall())

    def list_worktree_operations(
        self,
        *,
        managed_worktree_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT o.* FROM worktree_operations o"
        clauses: List[str] = []
        parameters: List[Any] = []
        if campaign_id is not None:
            clauses.append(
                "o.managed_worktree_id IN "
                "(SELECT id FROM managed_worktrees WHERE campaign_id = ?)"
            )
            parameters.append(campaign_id)
        if managed_worktree_id is not None:
            clauses.append("o.managed_worktree_id = ?")
            parameters.append(managed_worktree_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY o.started_at, o.operation_number"
        with self._lock:
            return self._rows(self._connection.execute(sql, parameters).fetchall())

    def claim_expired_worktree_operations(
        self,
        owner: str,
        *,
        lease_seconds: float = 30.0,
        limit: int = 25,
    ) -> List[Dict[str, Any]]:
        """Fence expired lifecycle operations for identity-safe reconciliation."""

        owner = owner.strip()
        if not owner or len(owner) > 256:
            raise ValueError("reconciliation owner must contain 1 to 256 characters")
        if lease_seconds <= 0:
            raise ValueError("reconciliation lease must be positive")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("reconciliation limit must be a positive integer")
        with self._transaction() as connection:
            now = self._clock()
            candidates = connection.execute(
                """SELECT id FROM worktree_operations
                   WHERE status = 'running' AND lease_expires_at <= ?
                     AND (reconciliation_expires_at IS NULL
                          OR reconciliation_expires_at <= ?)
                   ORDER BY started_at, id LIMIT ?""",
                (now, now, limit),
            ).fetchall()
            claimed: List[Dict[str, Any]] = []
            for candidate in candidates:
                token = _id()
                changed = connection.execute(
                    """UPDATE worktree_operations
                       SET reconciliation_owner = ?, reconciliation_token = ?,
                           reconciliation_expires_at = ?, updated_at = ?
                       WHERE id = ? AND status = 'running'
                         AND lease_expires_at <= ?
                         AND (reconciliation_expires_at IS NULL
                              OR reconciliation_expires_at <= ?)""",
                    (
                        owner,
                        token,
                        now + lease_seconds,
                        now,
                        candidate["id"],
                        now,
                        now,
                    ),
                ).rowcount
                if changed != 1:
                    continue
                operation = connection.execute(
                    "SELECT * FROM worktree_operations WHERE id = ?",
                    (candidate["id"],),
                ).fetchone()
                worktree = connection.execute(
                    "SELECT * FROM managed_worktrees WHERE id = ?",
                    (operation["managed_worktree_id"],),
                ).fetchone()
                if worktree is None:
                    raise LeaseConflict(
                        "worktree operation lost its managed-worktree parent"
                    )
                self._append_event(
                    connection,
                    "worktree.reconciliation_claimed",
                    campaign_id=worktree["campaign_id"],
                    work_item_id=worktree["work_item_id"],
                    actor=owner,
                    event_data={
                        "worktree_id": worktree["id"],
                        "operation_id": operation["id"],
                        "operation_kind": operation["kind"],
                    },
                    created_at=now,
                )
                claimed.append(
                    {
                        "operation": self._row(operation),
                        "worktree": self._row(worktree),
                    }
                )
            return claimed

    def claim_quarantined_worktree_processes(
        self,
        owner: str,
        *,
        lease_seconds: float = 30.0,
        limit: int = 25,
    ) -> List[Dict[str, Any]]:
        """Fence quarantined lifecycle operations with durable process proof."""

        owner = owner.strip()
        if not owner or len(owner) > 256:
            raise ValueError("reconciliation owner must contain 1 to 256 characters")
        if lease_seconds <= 0:
            raise ValueError("reconciliation lease must be positive")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("reconciliation limit must be a positive integer")
        with self._transaction() as connection:
            now = self._clock()
            candidates = connection.execute(
                """SELECT id FROM worktree_operations
                   WHERE status = 'quarantined'
                     AND process_state IN ('active', 'stopped')
                     AND (reconciliation_expires_at IS NULL
                          OR reconciliation_expires_at <= ?)
                   ORDER BY started_at, id LIMIT ?""",
                (now, limit),
            ).fetchall()
            claimed: List[Dict[str, Any]] = []
            for candidate in candidates:
                token = _id()
                changed = connection.execute(
                    """UPDATE worktree_operations
                       SET reconciliation_owner = ?, reconciliation_token = ?,
                           reconciliation_expires_at = ?, updated_at = ?
                       WHERE id = ? AND status = 'quarantined'
                         AND process_state IN ('active', 'stopped')
                         AND (reconciliation_expires_at IS NULL
                              OR reconciliation_expires_at <= ?)""",
                    (
                        owner,
                        token,
                        now + lease_seconds,
                        now,
                        candidate["id"],
                        now,
                    ),
                ).rowcount
                if changed != 1:
                    continue
                operation = connection.execute(
                    "SELECT * FROM worktree_operations WHERE id = ?",
                    (candidate["id"],),
                ).fetchone()
                worktree = connection.execute(
                    "SELECT * FROM managed_worktrees WHERE id = ?",
                    (operation["managed_worktree_id"],),
                ).fetchone()
                if worktree is None:
                    raise LeaseConflict(
                        "quarantined operation lost its managed-worktree parent"
                    )
                self._append_event(
                    connection,
                    "worktree.quarantined_process_retry_claimed",
                    campaign_id=worktree["campaign_id"],
                    work_item_id=worktree["work_item_id"],
                    actor=owner,
                    event_data={
                        "worktree_id": worktree["id"],
                        "operation_id": operation["id"],
                    },
                    created_at=now,
                )
                claimed.append(
                    {
                        "operation": self._row(operation),
                        "worktree": self._row(worktree),
                    }
                )
            return claimed

    def finish_quarantined_worktree_process_retry(
        self,
        operation_id: str,
        owner: str,
        token: str,
        *,
        reason: str,
        observed_identity: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Release only the retry fence; the lifecycle remains quarantined."""

        reason = reason.strip()
        if not reason or len(reason) > 4096:
            raise ValueError("quarantined reconciliation reason must be non-empty")
        with self._transaction() as connection:
            now = self._clock()
            operation = self._assert_worktree_operation_fence(
                connection,
                operation_id,
                owner,
                token,
                now,
                reconciliation=True,
            )
            if operation["status"] != "quarantined":
                raise TransitionConflict("worktree operation is not quarantined")
            connection.execute(
                """UPDATE worktree_operations
                   SET error = ?, reconciliation_owner = NULL,
                       reconciliation_token = NULL,
                       reconciliation_expires_at = NULL, updated_at = ?
                   WHERE id = ? AND status = 'quarantined'""",
                (reason, now, operation_id),
            )
            worktree = connection.execute(
                "SELECT * FROM managed_worktrees WHERE id = ?",
                (operation["managed_worktree_id"],),
            ).fetchone()
            connection.execute(
                "UPDATE managed_worktrees SET last_error = ?, updated_at = ? WHERE id = ?",
                (reason, now, worktree["id"]),
            )
            self._append_event(
                connection,
                "worktree.quarantined_process_reconciled",
                campaign_id=worktree["campaign_id"],
                work_item_id=worktree["work_item_id"],
                actor=owner,
                event_data={
                    "worktree_id": worktree["id"],
                    "operation_id": operation_id,
                    "process_state": operation["process_state"],
                    "reason": reason,
                    "observed_identity": dict(observed_identity or {}),
                },
                created_at=now,
            )
            return self._row(
                connection.execute(
                    "SELECT * FROM worktree_operations WHERE id = ?",
                    (operation_id,),
                ).fetchone()
            )  # type: ignore[return-value]

    def resume_quarantined_worktree_operation(
        self,
        operation_id: str,
        owner: str,
        token: str,
    ) -> Dict[str, Any]:
        """Reopen a reaped lifecycle under its existing reconciliation fence."""

        with self._transaction() as connection:
            now = self._clock()
            operation = self._assert_worktree_operation_fence(
                connection,
                operation_id,
                owner,
                token,
                now,
                reconciliation=True,
            )
            if operation["status"] != "quarantined":
                raise TransitionConflict("worktree operation is not quarantined")
            if operation["process_state"] != "stopped":
                raise LeaseConflict(
                    "quarantined worktree process must be reaped before resuming"
                )
            worktree = connection.execute(
                "SELECT * FROM managed_worktrees WHERE id = ?",
                (operation["managed_worktree_id"],),
            ).fetchone()
            if worktree is None or worktree["state"] != "quarantined":
                raise TransitionConflict("managed worktree is not quarantined")
            resumed_state = {
                "create": "provisioning",
                "remove": "cleanup_pending",
            }.get(str(operation["kind"]))
            if resumed_state is None:
                raise TransitionConflict("unknown worktree operation kind")
            connection.execute(
                """UPDATE managed_worktrees
                   SET state = ?, updated_at = ? WHERE id = ?""",
                (resumed_state, now, worktree["id"]),
            )
            changed = connection.execute(
                """UPDATE worktree_operations
                   SET status = 'running', finished_at = NULL, updated_at = ?
                   WHERE id = ? AND status = 'quarantined'
                     AND process_state = 'stopped'""",
                (now, operation_id),
            ).rowcount
            if changed != 1:
                raise LeaseConflict("quarantined worktree operation changed")
            self._append_event(
                connection,
                "worktree.quarantine_reconciliation_resumed",
                campaign_id=worktree["campaign_id"],
                work_item_id=worktree["work_item_id"],
                actor=owner,
                event_data={
                    "worktree_id": worktree["id"],
                    "operation_id": operation_id,
                    "operation_kind": operation["kind"],
                },
                created_at=now,
            )
            return self._row(
                connection.execute(
                    "SELECT * FROM worktree_operations WHERE id = ?",
                    (operation_id,),
                ).fetchone()
            )  # type: ignore[return-value]

    def get_claimed_managed_worktree(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> Optional[Dict[str, Any]]:
        with self._transaction() as connection:
            now = self._clock()
            job = self._assert_live_lease(
                connection, job_id, worker_id, lease_token, now
            )
            if job["workspace_kind"] != WorkspaceKind.MANAGED_WORKTREE.value:
                return None
            self._assert_managed_worktree_binding(connection, job)
            row = connection.execute(
                "SELECT * FROM managed_worktrees WHERE id = ?",
                (job["managed_worktree_id"],),
            ).fetchone()
            return self._row(row)

    def quarantine_claimed_managed_worktree(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Fail closed when a live worker disproves its exact workspace binding."""

        if not reason or len(reason) > 4096:
            raise ValueError("managed worktree quarantine reason must be non-empty")
        with self._transaction() as connection:
            now = self._clock()
            job = self._assert_live_lease(
                connection, job_id, worker_id, lease_token, now
            )
            if job["workspace_kind"] != WorkspaceKind.MANAGED_WORKTREE.value:
                raise LeaseConflict("job has no managed worktree authority")
            self._assert_managed_worktree_binding(connection, job)
            changed = connection.execute(
                """UPDATE managed_worktrees
                   SET state = 'quarantined', last_error = ?, updated_at = ?
                   WHERE id = ? AND state = 'ready'""",
                (reason, now, job["managed_worktree_id"]),
            ).rowcount
            if changed != 1:
                raise LeaseConflict("managed worktree is no longer ready")
            self._append_event(
                connection,
                "worktree.worker_validation_quarantined",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job_id,
                actor=worker_id,
                event_data={
                    "worktree_id": job["managed_worktree_id"],
                    "reason": reason,
                },
                created_at=now,
            )
            return self._row(
                connection.execute(
                    "SELECT * FROM managed_worktrees WHERE id = ?",
                    (job["managed_worktree_id"],),
                ).fetchone()
            )  # type: ignore[return-value]

    def claim_job(
        self, role: str, worker_id: str, *, lease_seconds: float = 60.0
    ) -> Optional[Dict[str, Any]]:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        role = _value(role).lower()
        with self._transaction() as connection:
            now = self._clock()
            self._recover_expired(connection, now)
            candidates = connection.execute(
                """SELECT j.*, c.global_limit, c.role_limits_json,
                          c.config_json AS campaign_config_json
                   FROM jobs j JOIN campaigns c ON c.id = j.campaign_id
                   JOIN work_items i ON i.id = j.work_item_id
                   WHERE j.status = 'pending' AND j.role = ? AND j.available_at <= ?
                     AND c.status = 'active' AND i.state = j.queued_item_state
                   ORDER BY j.priority DESC, j.created_at, j.id""",
                (role, now),
            ).fetchall()
            for job in candidates:
                campaign_config = _load(job["campaign_config_json"], {})
                workspace_kind = str(job["workspace_kind"])
                managed_worktree: Optional[sqlite3.Row] = None
                if workspace_kind == WorkspaceKind.SIMULATED.value:
                    if campaign_config.get("allow_simulated_evidence") is not True:
                        continue
                elif workspace_kind == WorkspaceKind.MANAGED_WORKTREE.value:
                    if job["managed_worktree_id"] is None:
                        continue
                    managed_worktree = connection.execute(
                        """SELECT * FROM managed_worktrees
                           WHERE id = ? AND campaign_id = ? AND work_item_id = ?
                             AND state = 'ready'""",
                        (
                            job["managed_worktree_id"],
                            job["campaign_id"],
                            job["work_item_id"],
                        ),
                    ).fetchone()
                    if managed_worktree is None:
                        continue
                    worktree_resource = (
                        WORKTREE_RESOURCE_PREFIX + str(job["managed_worktree_id"])
                    )
                    if worktree_resource not in _load(
                        job["required_resources_json"], []
                    ):
                        continue
                elif role == "fixer":
                    continue
                required_action = job["required_approval_action"]
                if required_action is not None:
                    approvals = connection.execute(
                        """SELECT scope_json FROM approvals
                           WHERE campaign_id = ? AND action = ? AND status = 'approved'
                             AND (work_item_id IS NULL OR work_item_id = ?)
                           ORDER BY requested_at, id""",
                        (job["campaign_id"], required_action, job["work_item_id"]),
                    ).fetchall()
                    job_payload = _load(job["payload_json"], {})
                    if managed_worktree is not None:
                        approved = any(
                            _approval_covers_repository(
                                campaign_config,
                                str(managed_worktree["repository_path"]),
                                _load(approval["scope_json"], {}),
                            )
                            for approval in approvals
                        )
                    else:
                        approved = any(
                            _approval_covers_job(
                                campaign_config,
                                job_payload,
                                _load(approval["scope_json"], {}),
                            )
                            for approval in approvals
                        )
                    if not approved:
                        continue
                active = connection.execute(
                    """SELECT role, COUNT(*) AS count FROM jobs
                       WHERE campaign_id = ? AND status = 'running'
                       GROUP BY role""",
                    (job["campaign_id"],),
                ).fetchall()
                active_by_role = {row["role"]: row["count"] for row in active}
                active_total = sum(active_by_role.values())
                role_limit = _load(job["role_limits_json"], {}).get(role, job["global_limit"])
                if active_total >= job["global_limit"] or active_by_role.get(role, 0) >= role_limit:
                    continue
                resources = _load(job["required_resources_json"], [])
                if resources:
                    placeholders = ",".join("?" for _ in resources)
                    held = connection.execute(
                        "SELECT 1 FROM resource_leases WHERE resource_key IN (%s) LIMIT 1"
                        % placeholders,
                        resources,
                    ).fetchone()
                    if held is not None:
                        continue
                changed = connection.execute(
                    "UPDATE work_items SET state = ?, updated_at = ? WHERE id = ? AND state = ?",
                    (job["active_item_state"], now, job["work_item_id"], job["queued_item_state"]),
                ).rowcount
                if changed != 1:
                    continue
                attempt_number = int(job["attempt_count"]) + 1
                attempt_id = _id()
                token = _id()
                expires_at = now + lease_seconds
                changed = connection.execute(
                    """UPDATE jobs SET status = 'running', lease_owner = ?, lease_token = ?,
                       lease_expires_at = ?, heartbeat_at = ?, current_attempt_id = ?,
                       attempt_count = ?, updated_at = ? WHERE id = ? AND status = 'pending'""",
                    (worker_id, token, expires_at, now, attempt_id, attempt_number, now, job["id"]),
                ).rowcount
                if changed != 1:
                    raise TransitionConflict("job was claimed during its item transition")
                connection.execute(
                    """INSERT INTO attempts
                       (id, job_id, attempt_number, worker_id, lease_token, status,
                        managed_worktree_id, managed_worktree_generation,
                        started_at, heartbeat_at, lease_expires_at)
                       VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?, ?, ?)""",
                    (
                        attempt_id,
                        job["id"],
                        attempt_number,
                        worker_id,
                        token,
                        job["managed_worktree_id"],
                        (
                            None
                            if managed_worktree is None
                            else managed_worktree["generation"]
                        ),
                        now,
                        now,
                        expires_at,
                    ),
                )
                for resource in resources:
                    connection.execute(
                        """INSERT INTO resource_leases
                           (resource_key, owner_id, job_id, lease_token, acquired_at,
                            heartbeat_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (resource, worker_id, job["id"], token, now, now, expires_at),
                    )
                self._append_event(
                    connection, "job.claimed", campaign_id=job["campaign_id"],
                    work_item_id=job["work_item_id"], job_id=job["id"], actor=worker_id,
                    event_data={"attempt_id": attempt_id, "attempt_number": attempt_number,
                                "lease_token": token, "resources": resources,
                                "from_state": job["queued_item_state"],
                                "to_state": job["active_item_state"]}, created_at=now
                )
                claimed = connection.execute(
                    "SELECT * FROM jobs WHERE id = ?", (job["id"],)
                ).fetchone()
                result = self._row(claimed)
                result.update({"attempt_id": attempt_id, "attempt_number": attempt_number})
                resumable = connection.execute(
                    """SELECT external_provider, external_session_id
                       FROM attempts
                       WHERE job_id = ? AND attempt_number < ?
                         AND status = 'interrupted'
                         AND external_provider IS NOT NULL
                         AND external_session_id IS NOT NULL
                       ORDER BY attempt_number DESC LIMIT 1""",
                    (job["id"], attempt_number),
                ).fetchone()
                if resumable is not None:
                    result.update(
                        {
                            "resume_external_provider": resumable[
                                "external_provider"
                            ],
                            "resume_external_session_id": resumable[
                                "external_session_id"
                            ],
                        }
                    )
                return result
        return None

    def _assert_live_lease(
        self, connection: sqlite3.Connection, job_id: str, worker_id: str,
        lease_token: str, now: float
    ) -> sqlite3.Row:
        job = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if job is None:
            raise NotFoundError("job %s not found" % job_id)
        if (job["status"] != "running" or job["lease_owner"] != worker_id
                or job["lease_token"] != lease_token or job["lease_expires_at"] <= now):
            raise LeaseConflict("job lease is absent, expired, or fenced by a newer attempt")
        return job

    def heartbeat_job(
        self, job_id: str, worker_id: str, lease_token: str, *, lease_seconds: float = 60.0
    ) -> Dict[str, Any]:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        with self._transaction() as connection:
            now = self._clock()
            expires_at = now + lease_seconds
            job = self._assert_live_lease(connection, job_id, worker_id, lease_token, now)
            connection.execute(
                """UPDATE jobs
                   SET heartbeat_at = ?, lease_expires_at = ?, updated_at = ?
                   WHERE id = ?""",
                (now, expires_at, now, job_id),
            )
            connection.execute(
                """UPDATE attempts SET heartbeat_at = ?, lease_expires_at = ?
                   WHERE id = ? AND status = 'running'""",
                (now, expires_at, job["current_attempt_id"]),
            )
            expected_resources = _load(job["required_resources_json"], [])
            updated = connection.execute(
                """UPDATE resource_leases SET heartbeat_at = ?, expires_at = ?
                   WHERE job_id = ? AND owner_id = ? AND lease_token = ?""",
                (now, expires_at, job_id, worker_id, lease_token),
            ).rowcount
            if updated != len(expected_resources):
                raise LeaseConflict("one or more required resource leases were lost")
        return self.get_job(job_id)

    def record_external_session(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        provider: str,
        session_id: str,
    ) -> Dict[str, Any]:
        """Persist a provider session against the current fenced attempt."""

        provider = provider.strip().lower()
        session_id = session_id.strip()
        if not provider or len(provider) > 64:
            raise ValueError("external provider must contain 1 to 64 characters")
        if not session_id or len(session_id) > 512:
            raise ValueError("external session id must contain 1 to 512 characters")

        with self._transaction() as connection:
            now = self._clock()
            job = self._assert_live_lease(
                connection, job_id, worker_id, lease_token, now
            )
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?",
                (job["current_attempt_id"],),
            ).fetchone()
            if attempt is None or attempt["status"] != "running":
                raise LeaseConflict("current running attempt is absent")

            existing = (
                attempt["external_provider"],
                attempt["external_session_id"],
            )
            requested = (provider, session_id)
            if existing == requested:
                return self._row(attempt)  # type: ignore[return-value]
            if existing != (None, None):
                raise LeaseConflict(
                    "current attempt is already bound to another external session"
                )
            cross_job = connection.execute(
                """SELECT 1 FROM attempts
                   WHERE external_provider = ? AND external_session_id = ?
                     AND job_id != ? LIMIT 1""",
                (provider, session_id, job_id),
            ).fetchone()
            if cross_job is not None:
                raise LeaseConflict(
                    "external session is already bound to another logical job"
                )

            changed = connection.execute(
                """UPDATE attempts
                   SET external_provider = ?, external_session_id = ?
                   WHERE id = ? AND status = 'running'
                     AND external_provider IS NULL
                     AND external_session_id IS NULL""",
                (provider, session_id, job["current_attempt_id"]),
            ).rowcount
            if changed != 1:
                raise LeaseConflict("external session binding changed concurrently")
            self._append_event(
                connection,
                "worker.external_session_recorded",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job_id,
                actor=worker_id,
                event_data={"provider": provider, "session_id": session_id},
                created_at=now,
            )
            recorded = connection.execute(
                "SELECT * FROM attempts WHERE id = ?",
                (job["current_attempt_id"],),
            ).fetchone()
            return self._row(recorded)  # type: ignore[return-value]

    def record_external_process(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        provider: str,
        process_id: int,
        process_group_id: int,
        owner_uid: int,
        kernel_executable: str,
        start_seconds: int,
        start_microseconds: int,
        target_executable: str,
    ) -> Dict[str, Any]:
        """Persist a live external process before it can perform worker work."""

        provider = provider.strip().lower()
        kernel_executable = kernel_executable.strip()
        target_executable = target_executable.strip()
        if not provider or len(provider) > 64:
            raise ValueError("external provider must contain 1 to 64 characters")
        if (
            not isinstance(process_id, int)
            or isinstance(process_id, bool)
            or process_id <= 1
        ):
            raise ValueError("external process id must be a positive integer")
        if (
            not isinstance(process_group_id, int)
            or isinstance(process_group_id, bool)
            or process_group_id <= 1
        ):
            raise ValueError("external process group id must be a positive integer")
        if process_group_id != process_id:
            raise ValueError("external launcher must be its process-group leader")
        if (
            not isinstance(owner_uid, int)
            or isinstance(owner_uid, bool)
            or owner_uid < 0
        ):
            raise ValueError("external process owner UID must be a non-negative integer")
        for label, value in (
            ("kernel executable", kernel_executable),
            ("target executable", target_executable),
        ):
            if not value or len(value) > 4096:
                raise ValueError("external %s must contain 1 to 4096 characters" % label)
            if not Path(value).is_absolute():
                raise ValueError("external %s must be an absolute path" % label)
        for label, value in (
            ("start seconds", start_seconds),
            ("start microseconds", start_microseconds),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ValueError("external process %s must be a non-negative integer" % label)
        if start_seconds == 0:
            raise ValueError("external process start seconds must be positive")
        if start_microseconds >= 1_000_000:
            raise ValueError("external process start microseconds must be below 1000000")

        with self._transaction() as connection:
            now = self._clock()
            job = self._assert_live_lease(
                connection, job_id, worker_id, lease_token, now
            )
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?",
                (job["current_attempt_id"],),
            ).fetchone()
            if attempt is None or attempt["status"] != "running":
                raise LeaseConflict("current running attempt is absent")
            external = connection.execute(
                "SELECT * FROM external_processes WHERE attempt_id = ?",
                (job["current_attempt_id"],),
            ).fetchone()
            requested = (
                provider,
                process_id,
                process_group_id,
                owner_uid,
                kernel_executable,
                start_seconds,
                start_microseconds,
                target_executable,
            )
            if external is not None:
                existing = (
                    external["provider"],
                    external["process_id"],
                    external["process_group_id"],
                    external["owner_uid"],
                    external["kernel_executable"],
                    external["start_seconds"],
                    external["start_microseconds"],
                    external["target_executable"],
                )
                if existing == requested and external["state"] == "active":
                    return self._row(external)  # type: ignore[return-value]
                raise LeaseConflict(
                    "current attempt is already bound to another external process"
                )
            process_id_record = _id()
            try:
                connection.execute(
                    """INSERT INTO external_processes
                       (id, attempt_id, job_id, provider, process_id,
                        process_group_id, owner_uid, start_seconds,
                        start_microseconds, kernel_executable, target_executable,
                        identity_version, state, recorded_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                               'darwin_libproc_v1', 'active', ?, ?)""",
                    (
                        process_id_record,
                        job["current_attempt_id"],
                        job_id,
                        provider,
                        process_id,
                        process_group_id,
                        owner_uid,
                        start_seconds,
                        start_microseconds,
                        kernel_executable,
                        target_executable,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise LeaseConflict(
                    "external process identity is already bound to another attempt"
                ) from error
            changed = connection.execute(
                """UPDATE attempts
                   SET external_process_id = ?, external_process_group_id = ?,
                       external_process_executable = ?,
                       external_process_started_at = ?
                   WHERE id = ? AND status = 'running'
                     AND external_process_id IS NULL""",
                (
                    process_id,
                    process_group_id,
                    kernel_executable,
                    now,
                    job["current_attempt_id"],
                ),
            ).rowcount
            if changed != 1:
                raise LeaseConflict("external process binding changed concurrently")
            self._append_event(
                connection,
                "worker.external_process_started",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job_id,
                actor=worker_id,
                event_data={
                    "provider": provider,
                    "process_id": process_id,
                    "process_group_id": process_group_id,
                    "owner_uid": owner_uid,
                    "kernel_executable": kernel_executable,
                    "start_seconds": start_seconds,
                    "start_microseconds": start_microseconds,
                    "target_executable": target_executable,
                },
                created_at=now,
            )
            recorded = connection.execute(
                "SELECT * FROM external_processes WHERE id = ?",
                (process_id_record,),
            ).fetchone()
            return self._row(recorded)  # type: ignore[return-value]

    def clear_external_process(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        process_id: int,
        process_group_id: int,
    ) -> Dict[str, Any]:
        """Clear a process binding only after the adapter has reaped its group."""

        with self._transaction() as connection:
            now = self._clock()
            job = self._assert_live_lease(
                connection, job_id, worker_id, lease_token, now
            )
            changed = connection.execute(
                """UPDATE external_processes
                   SET state = 'stopped', stopped_at = ?, outcome = 'reaped',
                       last_error = NULL, updated_at = ?
                   WHERE attempt_id = ? AND state = 'active'
                     AND process_id = ? AND process_group_id = ?""",
                (
                    now,
                    now,
                    job["current_attempt_id"],
                    process_id,
                    process_group_id,
                ),
            ).rowcount
            if changed != 1:
                raise LeaseConflict("external process binding is absent or changed")
            self._append_event(
                connection,
                "worker.external_process_stopped",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job_id,
                actor=worker_id,
                event_data={
                    "process_id": process_id,
                    "process_group_id": process_group_id,
                },
                created_at=now,
            )
            recorded = connection.execute(
                "SELECT * FROM external_processes WHERE attempt_id = ?",
                (job["current_attempt_id"],),
            ).fetchone()
            return self._row(recorded)  # type: ignore[return-value]

    @staticmethod
    def _assert_external_process_stopped(
        connection: sqlite3.Connection, job: sqlite3.Row
    ) -> None:
        external = connection.execute(
            """SELECT state FROM external_processes
               WHERE attempt_id = ?""",
            (job["current_attempt_id"],),
        ).fetchone()
        attempt = connection.execute(
            "SELECT external_process_id FROM attempts WHERE id = ?",
            (job["current_attempt_id"],),
        ).fetchone()
        if attempt is None:
            raise LeaseConflict("current attempt is absent")
        if external is None and attempt["external_process_id"] is not None:
            raise LeaseConflict("external process identity record is missing")
        if external is not None and external["state"] != "stopped":
            raise LeaseConflict(
                "external process must be reaped before the attempt can finish"
            )

    @staticmethod
    def _assert_managed_worktree_binding(
        connection: sqlite3.Connection, job: sqlite3.Row
    ) -> None:
        if job["workspace_kind"] != WorkspaceKind.MANAGED_WORKTREE.value:
            return
        if job["managed_worktree_id"] is None:
            raise LeaseConflict("managed-worktree job has no bound worktree")
        worktree = connection.execute(
            """SELECT * FROM managed_worktrees
               WHERE id = ? AND campaign_id = ? AND work_item_id = ?
                 AND state = 'ready'""",
            (
                job["managed_worktree_id"],
                job["campaign_id"],
                job["work_item_id"],
            ),
        ).fetchone()
        attempt = connection.execute(
            """SELECT managed_worktree_id, managed_worktree_generation
               FROM attempts WHERE id = ?""",
            (job["current_attempt_id"],),
        ).fetchone()
        if worktree is None or attempt is None:
            raise LeaseConflict("managed worktree identity is absent or not ready")
        if (
            attempt["managed_worktree_id"] != worktree["id"]
            or attempt["managed_worktree_generation"] != worktree["generation"]
        ):
            raise LeaseConflict("attempt worktree identity changed before finalization")

    @staticmethod
    def _normalized_relative_test_path(value: str) -> str:
        if not isinstance(value, str) or not value or "\\" in value:
            raise ValueError("focused test_file must be a non-empty POSIX relative path")
        path = PurePosixPath(value)
        if path.is_absolute() or value != path.as_posix() or any(
            part in ("", ".", "..") for part in path.parts
        ):
            raise ValueError("focused test_file must be a normalized relative path")
        if path.parts[0] == ".git":
            raise ValueError("focused test_file cannot target Git metadata")
        return value

    @staticmethod
    def _normalize_focused_manifest(
        value: Mapping[str, Mapping[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        if not isinstance(value, Mapping) or not value:
            raise ValueError("focused workspace manifest must be a non-empty mapping")
        normalized: Dict[str, Dict[str, Any]] = {}
        for raw_path, raw_identity in value.items():
            path = SQLiteStore._normalized_relative_test_path(str(raw_path))
            if path in normalized:
                raise ValueError("focused workspace manifest paths must be unique")
            if not isinstance(raw_identity, Mapping) or set(raw_identity) != {
                "sha256",
                "mode",
            }:
                raise ValueError(
                    "focused workspace manifest entries require sha256 and mode exactly"
                )
            digest = raw_identity["sha256"]
            mode = raw_identity["mode"]
            if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
                raise ValueError("focused workspace manifest hashes must be lowercase SHA-256")
            if (
                not isinstance(mode, int)
                or isinstance(mode, bool)
                or not stat.S_ISREG(mode)
            ):
                raise ValueError("focused workspace manifest entries must be regular files")
            normalized[path] = {"sha256": digest, "mode": mode}
        return {path: normalized[path] for path in sorted(normalized)}

    @staticmethod
    def _hash_file(
        path: Path, expected: Optional[os.stat_result] = None
    ) -> str:
        digest = hashlib.sha256()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(path), flags)
        try:
            before = os.fstat(descriptor)
            if expected is not None and any(
                observed != persisted
                for observed, persisted in (
                    (before.st_dev, expected.st_dev),
                    (before.st_ino, expected.st_ino),
                    (before.st_uid, expected.st_uid),
                    (before.st_mode, expected.st_mode),
                    (before.st_nlink, expected.st_nlink),
                    (before.st_size, expected.st_size),
                )
            ):
                raise LeaseConflict("file identity changed before it was opened")
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (
                before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
            ):
                raise LeaseConflict("file identity changed while it was being hashed")
        finally:
            os.close(descriptor)
        return digest.hexdigest()

    @staticmethod
    def _focused_executable_identity(executable_path: str) -> Dict[str, Any]:
        supplied = Path(executable_path).expanduser()
        if not supplied.is_absolute():
            raise ValueError("focused Python executable must be an absolute path")
        try:
            resolved = supplied.resolve(strict=True)
        except FileNotFoundError as error:
            raise ValueError("focused Python executable does not exist") from error
        if str(supplied) != str(resolved):
            raise ValueError("focused Python executable must already be fully resolved")
        details = resolved.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink < 1:
            raise ValueError("focused Python executable must be a regular file")
        if details.st_mode & 0o022:
            raise ValueError("focused Python executable cannot be group/world writable")
        if _PYTHON_EXECUTABLE_PATTERN.fullmatch(resolved.name) is None:
            raise ValueError("focused executable must be a resolved Python interpreter")
        return {
            "path": str(resolved),
            "device": int(details.st_dev),
            "inode": int(details.st_ino),
            "owner_uid": int(details.st_uid),
            "mode": int(details.st_mode),
            "sha256": SQLiteStore._hash_file(resolved, details),
        }

    @staticmethod
    def _scan_focused_workspace(root: Path) -> Dict[str, Dict[str, Any]]:
        try:
            resolved = root.resolve(strict=True)
        except FileNotFoundError as error:
            raise LeaseConflict("focused test worktree is absent") from error
        root_details = resolved.lstat()
        if not stat.S_ISDIR(root_details.st_mode) or root_details.st_uid != os.getuid():
            raise LeaseConflict("focused test worktree must be a user-owned directory")
        manifest: Dict[str, Dict[str, Any]] = {}
        for directory, directory_names, file_names in os.walk(
            str(resolved), topdown=True, followlinks=False
        ):
            current = Path(directory)
            relative_directory = current.relative_to(resolved)
            kept_directories: List[str] = []
            for name in sorted(directory_names):
                relative = relative_directory / name
                if relative.parts and relative.parts[0] == ".git":
                    continue
                details = (current / name).lstat()
                if not stat.S_ISDIR(details.st_mode):
                    raise LeaseConflict(
                        "focused workspace contains a non-directory traversal entry: %s"
                        % relative.as_posix()
                    )
                if details.st_uid != os.getuid():
                    raise LeaseConflict(
                        "focused workspace directory is not user-owned: %s"
                        % relative.as_posix()
                    )
                kept_directories.append(name)
            directory_names[:] = kept_directories
            for name in sorted(file_names):
                relative = relative_directory / name
                if relative.parts and relative.parts[0] == ".git":
                    continue
                path = current / name
                details = path.lstat()
                if (
                    not stat.S_ISREG(details.st_mode)
                    or details.st_uid != os.getuid()
                    or details.st_nlink != 1
                ):
                    raise LeaseConflict(
                        "focused workspace file is not a user-owned, single-link regular file: %s"
                        % relative.as_posix()
                    )
                manifest[relative.as_posix()] = {
                    "sha256": SQLiteStore._hash_file(path, details),
                    "mode": int(details.st_mode),
                }
        return {path: manifest[path] for path in sorted(manifest)}

    @staticmethod
    def _paths_overlap(first: Path, second: Path) -> bool:
        try:
            first.relative_to(second)
            return True
        except ValueError:
            pass
        try:
            second.relative_to(first)
            return True
        except ValueError:
            return False

    @staticmethod
    def _assert_private_directory(path: Path) -> os.stat_result:
        details = path.lstat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid != os.getuid()
            or details.st_mode & 0o077
        ):
            raise LeaseConflict(
                "focused runtime directories must be private user-owned directories"
            )
        return details

    @staticmethod
    def _create_private_directory(path: Path, *, parents: bool = False) -> None:
        path.mkdir(mode=0o700, parents=parents, exist_ok=False)
        os.chmod(path, 0o700)
        SQLiteStore._assert_private_directory(path)

    @staticmethod
    def _focused_environment(
        value: Optional[Mapping[str, str]],
    ) -> Dict[str, str]:
        environment = dict(_FOCUSED_TEST_ENVIRONMENT if value is None else value)
        if set(environment) != _FOCUSED_TEST_ENVIRONMENT_KEYS:
            raise ValueError(
                "focused test environment must contain only LANG, LC_ALL, and PYTHONHASHSEED"
            )
        if any(
            not isinstance(entry, str) or not entry or len(entry) > 256
            for entry in environment.values()
        ):
            raise ValueError("focused test environment values must be bounded strings")
        return {key: environment[key] for key in sorted(environment)}

    def create_focused_test_plan(
        self,
        work_item_id: str,
        *,
        executable_path: str,
        test_file: str,
        selector: str,
        workspace_manifest: Mapping[str, Mapping[str, Any]],
        runtime_root: str,
        timeout_seconds: float = 120.0,
        output_limit_bytes: int = 1024 * 1024,
        environment: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        """Register one immutable revision of a supervisor-owned focused-test plan."""

        test_file = self._normalized_relative_test_path(test_file)
        if _TEST_SELECTOR_PATTERN.fullmatch(selector) is None:
            raise ValueError("focused selector must be exactly ClassName.test_method")
        manifest = self._normalize_focused_manifest(workspace_manifest)
        if test_file not in manifest:
            raise ValueError("focused test_file must be present in the workspace manifest")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0
            or timeout_seconds > 3600
        ):
            raise ValueError("focused test timeout must be in (0, 3600] seconds")
        if (
            not isinstance(output_limit_bytes, int)
            or isinstance(output_limit_bytes, bool)
            or output_limit_bytes < 1024
            or output_limit_bytes > 16 * 1024 * 1024
        ):
            raise ValueError("focused output limit must be between 1024 and 16777216 bytes")
        executable = self._focused_executable_identity(executable_path)
        base_environment = self._focused_environment(environment)
        supplied_runtime_root = Path(runtime_root).expanduser()
        if not supplied_runtime_root.is_absolute():
            raise ValueError("focused runtime_root must be an absolute path")
        normalized_runtime_root = supplied_runtime_root.resolve()
        if str(supplied_runtime_root) != str(normalized_runtime_root):
            raise ValueError("focused runtime_root must already be fully resolved")
        if normalized_runtime_root.exists():
            self._assert_private_directory(normalized_runtime_root)
        else:
            self._create_private_directory(normalized_runtime_root, parents=True)

        plan_id = _id()
        now = self._clock()
        manifest_hash = hashlib.sha256(_dump(manifest).encode("utf-8")).hexdigest()
        environment_hash = hashlib.sha256(
            _dump(base_environment).encode("utf-8")
        ).hexdigest()
        with self._transaction() as connection:
            item = connection.execute(
                """SELECT i.*, c.config_json
                   FROM work_items i JOIN campaigns c ON c.id = i.campaign_id
                   WHERE i.id = ?""",
                (work_item_id,),
            ).fetchone()
            if item is None:
                raise NotFoundError("work item %s not found" % work_item_id)
            if item["state"] != "ready_for_test":
                raise TransitionConflict(
                    "focused test plans can be created only for ready-for-test items"
                )
            if _load(item["required_gates_json"], []) != ["focused_tests"]:
                raise ValueError(
                    "the focused collector slice supports exactly the focused_tests gate"
                )
            if _load(item["config_json"], {}).get("allow_simulated_evidence") is True:
                raise ValueError("authoritative focused plans cannot be simulated")
            previous_plan = connection.execute(
                """SELECT * FROM focused_test_plans WHERE work_item_id = ?
                   ORDER BY plan_number DESC LIMIT 1""",
                (work_item_id,),
            ).fetchone()
            plan_number = 1
            if previous_plan is not None:
                plan_number = int(previous_plan["plan_number"]) + 1
                immutable_authority = {
                    "executable_path": executable["path"],
                    "executable_device": executable["device"],
                    "executable_inode": executable["inode"],
                    "executable_owner_uid": executable["owner_uid"],
                    "executable_mode": executable["mode"],
                    "executable_sha256": executable["sha256"],
                    "test_file": test_file,
                    "selector": selector,
                    "environment_json": _dump(base_environment),
                    "environment_sha256": environment_hash,
                    "runtime_root": str(normalized_runtime_root),
                    "timeout_seconds": float(timeout_seconds),
                    "output_limit_bytes": output_limit_bytes,
                }
                changed_authority = [
                    name
                    for name, value in immutable_authority.items()
                    if previous_plan[name] != value
                ]
                if changed_authority:
                    raise TransitionConflict(
                        "focused plan revisions cannot change test authority: %s"
                        % ", ".join(sorted(changed_authority))
                    )
                previous_manifest = self._normalize_focused_manifest(
                    _load(previous_plan["workspace_manifest_json"], {})
                )
                if previous_manifest[test_file] != manifest[test_file]:
                    raise TransitionConflict(
                        "focused plan revisions cannot change the trusted test file"
                    )
            connection.execute(
                """INSERT INTO focused_test_plans
                   (id, work_item_id, plan_number, executable_path, executable_device,
                    executable_inode, executable_owner_uid, executable_mode,
                    executable_sha256, test_file, selector, environment_json,
                    environment_sha256, workspace_manifest_json,
                    workspace_manifest_sha256, runtime_root, timeout_seconds,
                    output_limit_bytes, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    plan_id,
                    work_item_id,
                    plan_number,
                    executable["path"],
                    executable["device"],
                    executable["inode"],
                    executable["owner_uid"],
                    executable["mode"],
                    executable["sha256"],
                    test_file,
                    selector,
                    _dump(base_environment),
                    environment_hash,
                    _dump(manifest),
                    manifest_hash,
                    str(normalized_runtime_root),
                    float(timeout_seconds),
                    output_limit_bytes,
                    now,
                ),
            )
            self._append_event(
                connection,
                "focused_test.plan_created",
                campaign_id=item["campaign_id"],
                work_item_id=work_item_id,
                event_data={
                    "plan_id": plan_id,
                    "plan_number": plan_number,
                    "selector": selector,
                    "test_file": test_file,
                },
                created_at=now,
            )
        return self.get_focused_test_plan(plan_id)

    def get_focused_test_plan(self, plan_id: str) -> Dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM focused_test_plans WHERE id = ?", (plan_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("focused test plan %s not found" % plan_id)
        return self._row(row)  # type: ignore[return-value]

    def list_focused_test_plans(
        self, work_item_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM focused_test_plans"
        parameters: Sequence[Any] = ()
        if work_item_id is not None:
            sql += " WHERE work_item_id = ?"
            parameters = (work_item_id,)
        sql += " ORDER BY work_item_id, plan_number"
        with self._lock:
            return self._rows(self._connection.execute(sql, parameters).fetchall())

    def _focused_execution_request(self, row: sqlite3.Row) -> Dict[str, Any]:
        request = self._row(row)
        assert request is not None
        request["command"] = request["command_argv"]
        request["workspace_manifest"] = request["workspace_manifest_before"]
        return request

    def prepare_focused_test_execution(
        self, job_id: str, worker_id: str, lease_token: str
    ) -> Dict[str, Any]:
        """Fence one focused execution to the current tester attempt and worktree."""

        created_run_parent: Optional[Path] = None
        try:
            with self._transaction() as connection:
                now = self._clock()
                job = self._assert_live_lease(
                    connection, job_id, worker_id, lease_token, now
                )
                if job["role"] != "tester":
                    raise LeaseConflict("focused executions require a tester lease")
                if job["workspace_kind"] != WorkspaceKind.MANAGED_WORKTREE.value:
                    raise LeaseConflict("focused executions require a managed worktree")
                self._assert_managed_worktree_binding(connection, job)
                existing = connection.execute(
                    "SELECT * FROM focused_test_executions WHERE attempt_id = ?",
                    (job["current_attempt_id"],),
                ).fetchone()
                if existing is not None:
                    return self._focused_execution_request(existing)
                item = connection.execute(
                    "SELECT required_gates_json FROM work_items WHERE id = ?",
                    (job["work_item_id"],),
                ).fetchone()
                if item is None:
                    raise NotFoundError("work item %s not found" % job["work_item_id"])
                if _load(item["required_gates_json"], []) != ["focused_tests"]:
                    raise ValueError(
                        "the focused collector slice supports exactly the focused_tests gate"
                    )
                plan = connection.execute(
                    """SELECT * FROM focused_test_plans WHERE work_item_id = ?
                       ORDER BY plan_number DESC LIMIT 1""",
                    (job["work_item_id"],),
                ).fetchone()
                if plan is None:
                    raise LeaseConflict("current work item has no authoritative focused test plan")
                worktree = connection.execute(
                    "SELECT * FROM managed_worktrees WHERE id = ? AND state = 'ready'",
                    (job["managed_worktree_id"],),
                ).fetchone()
                if worktree is None:
                    raise LeaseConflict("managed worktree is not ready")

                cwd = Path(str(worktree["worktree_path"])).resolve(strict=True)
                cwd_details = cwd.lstat()
                if (
                    not stat.S_ISDIR(cwd_details.st_mode)
                    or int(cwd_details.st_dev) != worktree["worktree_device"]
                    or int(cwd_details.st_ino) != worktree["worktree_inode"]
                    or int(cwd_details.st_uid) != worktree["worktree_owner_uid"]
                ):
                    raise LeaseConflict("focused test cwd identity changed")
                executable = self._focused_executable_identity(str(plan["executable_path"]))
                expected_executable = {
                    "path": str(plan["executable_path"]),
                    "device": int(plan["executable_device"]),
                    "inode": int(plan["executable_inode"]),
                    "owner_uid": int(plan["executable_owner_uid"]),
                    "mode": int(plan["executable_mode"]),
                    "sha256": str(plan["executable_sha256"]),
                }
                if executable != expected_executable:
                    raise LeaseConflict("focused Python executable identity changed")
                expected_manifest = self._normalize_focused_manifest(
                    _load(plan["workspace_manifest_json"], {})
                )
                observed_manifest = self._scan_focused_workspace(cwd)
                if observed_manifest != expected_manifest:
                    raise LeaseConflict("focused workspace differs from its immutable plan")
                test_path = cwd / str(plan["test_file"])
                if test_path.resolve(strict=True) != test_path or not test_path.is_file():
                    raise LeaseConflict("focused test_file is not a contained regular file")

                runtime_root = Path(str(plan["runtime_root"])).resolve(strict=True)
                self._assert_private_directory(runtime_root)
                repository_path = Path(str(worktree["repository_path"])).resolve(strict=True)
                if self._paths_overlap(runtime_root, cwd) or self._paths_overlap(
                    runtime_root, repository_path
                ):
                    raise LeaseConflict("focused runtime root overlaps a target repository")
                item_directory = runtime_root / str(job["work_item_id"])
                if item_directory.exists():
                    self._assert_private_directory(item_directory)
                else:
                    self._create_private_directory(item_directory)
                run_parent = item_directory / str(job["current_attempt_id"])
                self._create_private_directory(run_parent)
                created_run_parent = run_parent
                environment_directory = run_parent / "environment"
                home_directory = environment_directory / "home"
                temporary_directory = environment_directory / "tmp"
                artifact_directory = run_parent / "artifacts"
                if artifact_directory.exists():
                    raise LeaseConflict("focused artifact directory already exists")

                command = [
                    executable["path"],
                    "-I",
                    "-B",
                    str(test_path),
                    str(plan["selector"]),
                    "-v",
                ]
                command_hash = hashlib.sha256(_dump(command).encode("utf-8")).hexdigest()
                base_environment = self._focused_environment(
                    _load(plan["environment_json"], {})
                )
                effective_environment = dict(base_environment)
                effective_environment.update(
                    {"HOME": str(home_directory), "TMPDIR": str(temporary_directory)}
                )
                effective_environment = {
                    key: effective_environment[key] for key in sorted(effective_environment)
                }
                environment_hash = hashlib.sha256(
                    _dump(effective_environment).encode("utf-8")
                ).hexdigest()
                execution_id = _id()
                stdout_path = artifact_directory / "stdout.log"
                stderr_path = artifact_directory / "stderr.log"
                connection.execute(
                    """INSERT INTO focused_test_executions
                       (id, plan_id, attempt_id, job_id, work_item_id,
                        managed_worktree_id, managed_worktree_generation, status,
                        executable_path, executable_device, executable_inode,
                        executable_owner_uid, executable_mode, executable_sha256,
                        test_file, selector, command_argv_json, command_argv_sha256,
                        environment_json, environment_sha256, cwd, cwd_device,
                        cwd_inode, cwd_owner_uid, cwd_mode,
                        workspace_manifest_before_json,
                        workspace_manifest_before_sha256, run_parent,
                        artifact_directory, stdout_path, stderr_path,
                        timeout_seconds, output_limit_bytes, prepared_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?, ?, ?, ?, ?,
                               ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                               ?, ?, ?, ?)""",
                    (
                        execution_id,
                        plan["id"],
                        job["current_attempt_id"],
                        job_id,
                        job["work_item_id"],
                        worktree["id"],
                        worktree["generation"],
                        executable["path"],
                        executable["device"],
                        executable["inode"],
                        executable["owner_uid"],
                        executable["mode"],
                        executable["sha256"],
                        plan["test_file"],
                        plan["selector"],
                        _dump(command),
                        command_hash,
                        _dump(effective_environment),
                        environment_hash,
                        str(cwd),
                        int(cwd_details.st_dev),
                        int(cwd_details.st_ino),
                        int(cwd_details.st_uid),
                        int(cwd_details.st_mode),
                        _dump(observed_manifest),
                        plan["workspace_manifest_sha256"],
                        str(run_parent),
                        str(artifact_directory),
                        str(stdout_path),
                        str(stderr_path),
                        plan["timeout_seconds"],
                        plan["output_limit_bytes"],
                        now,
                        now,
                    ),
                )
                self._append_event(
                    connection,
                    "focused_test.execution_prepared",
                    campaign_id=job["campaign_id"],
                    work_item_id=job["work_item_id"],
                    job_id=job_id,
                    actor=worker_id,
                    event_data={
                        "execution_id": execution_id,
                        "attempt_id": job["current_attempt_id"],
                        "plan_id": plan["id"],
                    },
                    created_at=now,
                )
                prepared = connection.execute(
                    "SELECT * FROM focused_test_executions WHERE id = ?",
                    (execution_id,),
                ).fetchone()
                assert prepared is not None
                return self._focused_execution_request(prepared)
        except BaseException:
            if created_run_parent is not None and created_run_parent.exists():
                for child in sorted(created_run_parent.rglob("*"), reverse=True):
                    if child.is_dir():
                        child.rmdir()
                    else:
                        child.unlink()
                created_run_parent.rmdir()
            raise

    @staticmethod
    def _inspect_private_output(
        path: Path, output_limit_bytes: int
    ) -> tuple[Dict[str, Any], bytes]:
        details = path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.getuid()
            or details.st_nlink != 1
            or details.st_mode & 0o077
        ):
            raise LeaseConflict(
                "focused output must be a private user-owned single-link regular file"
            )
        if details.st_size > output_limit_bytes:
            raise LeaseConflict("focused output exceeds its persisted capture limit")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(str(path), flags)
        content = bytearray()
        digest = hashlib.sha256()
        try:
            before = os.fstat(descriptor)
            if any(
                observed != persisted
                for observed, persisted in (
                    (before.st_dev, details.st_dev),
                    (before.st_ino, details.st_ino),
                    (before.st_uid, details.st_uid),
                    (before.st_mode, details.st_mode),
                    (before.st_nlink, details.st_nlink),
                    (before.st_size, details.st_size),
                )
            ):
                raise LeaseConflict("focused output changed before it was opened")
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                content.extend(chunk)
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (
                before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or len(content) != after.st_size
            ):
                raise LeaseConflict("focused output identity changed while being verified")
        finally:
            os.close(descriptor)
        return (
            {
                "device": int(before.st_dev),
                "inode": int(before.st_ino),
                "owner_uid": int(before.st_uid),
                "mode": int(before.st_mode),
                "nlink": int(before.st_nlink),
                "bytes": len(content),
                "sha256": digest.hexdigest(),
            },
            bytes(content),
        )

    @staticmethod
    def _assert_focused_runtime_layout(execution: sqlite3.Row) -> None:
        run_parent = Path(str(execution["run_parent"]))
        SQLiteStore._assert_private_directory(run_parent)
        expected_environment_root = run_parent / "environment"
        expected_home = expected_environment_root / "home"
        expected_temporary = expected_environment_root / "tmp"
        environment = _load(execution["environment_json"], {})
        if environment.get("HOME") != str(expected_home) or environment.get(
            "TMPDIR"
        ) != str(expected_temporary):
            raise LeaseConflict("focused environment paths changed after preparation")
        SQLiteStore._assert_private_directory(expected_environment_root)
        SQLiteStore._assert_private_directory(expected_home)
        SQLiteStore._assert_private_directory(expected_temporary)
        artifact_directory = Path(str(execution["artifact_directory"]))
        if artifact_directory != run_parent / "artifacts":
            raise LeaseConflict("focused artifact directory changed after preparation")
        SQLiteStore._assert_private_directory(artifact_directory)

    @staticmethod
    def _focused_semantic_outcome(
        selector: str, exit_code: int, stdout: bytes, stderr: bytes
    ) -> tuple[str, str]:
        try:
            text = (stdout + b"\n" + stderr).decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ValueError("focused unittest output must be valid UTF-8") from error
        class_name, method_name = selector.split(".", 1)
        status_pattern = re.compile(
            r"^%s \(__main__\.%s\) \.\.\. (ok|FAIL|ERROR)$"
            % (re.escape(method_name), re.escape(class_name)),
            re.MULTILINE,
        )
        statuses = status_pattern.findall(text)
        ran_lines = re.findall(r"^Ran 1 test in [0-9]+(?:\.[0-9]+)?s$", text, re.MULTILINE)
        if len(statuses) != 1 or len(ran_lines) != 1:
            raise ValueError(
                "focused unittest output does not prove exactly the persisted selector"
            )
        nonempty_lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not nonempty_lines:
            raise ValueError("focused unittest output is empty")
        final_line = nonempty_lines[-1]
        status = statuses[0]
        if exit_code == 0 and status == "ok" and final_line == "OK":
            return "pass", "exactly one persisted focused unittest selector passed"
        if (
            exit_code != 0
            and status in ("FAIL", "ERROR")
            and final_line.startswith("FAILED (")
        ):
            return "fail", "exactly one persisted focused unittest selector failed"
        raise ValueError(
            "focused unittest exit code and exact one-test summary do not agree"
        )

    @staticmethod
    def _canonical_focused_handoff(
        execution: Mapping[str, Any],
        stdout_artifact: Mapping[str, Any],
        stderr_artifact: Mapping[str, Any],
    ) -> Dict[str, Any]:
        outcome = str(execution["outcome"])
        passed = outcome == "pass"
        summary = str(execution["semantic_summary"])
        evidence = [
            {
                "id": stdout_artifact["id"],
                "kind": "test",
                "location": stdout_artifact["uri"],
                "description": "Authoritative bounded stdout for the focused unittest run.",
                "metadata": {
                    "attempt_id": execution["attempt_id"],
                    "execution_id": execution["id"],
                    "sha256": execution["stdout_sha256"],
                    "bytes": execution["stdout_bytes"],
                },
            },
            {
                "id": stderr_artifact["id"],
                "kind": "log",
                "location": stderr_artifact["uri"],
                "description": "Authoritative bounded stderr for the focused unittest run.",
                "metadata": {
                    "attempt_id": execution["attempt_id"],
                    "execution_id": execution["id"],
                    "sha256": execution["stderr_sha256"],
                    "bytes": execution["stderr_bytes"],
                },
            },
        ]
        return {
            "schema_version": 1,
            "item_id": execution["work_item_id"],
            "outcome": "pass" if passed else "red",
            "summary": summary,
            "gate_proofs": [
                {
                    "gate": "focused_tests",
                    "result": "pass" if passed else "fail",
                    "summary": summary,
                    "evidence": evidence,
                }
            ],
            "failure_summary": None if passed else summary,
            "blocker": None,
        }

    def _assert_finished_focused_execution(
        self,
        connection: sqlite3.Connection,
        job: sqlite3.Row,
        execution: sqlite3.Row,
    ) -> tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        if (
            execution["status"] != "finished"
            or execution["attempt_id"] != job["current_attempt_id"]
            or execution["job_id"] != job["id"]
            or execution["work_item_id"] != job["work_item_id"]
            or execution["managed_worktree_id"] != job["managed_worktree_id"]
        ):
            raise LeaseConflict(
                "current tester attempt has no finished authoritative focused execution"
            )
        self._assert_managed_worktree_binding(connection, job)
        attempt = connection.execute(
            "SELECT managed_worktree_generation FROM attempts WHERE id = ?",
            (job["current_attempt_id"],),
        ).fetchone()
        if (
            attempt is None
            or execution["managed_worktree_generation"]
            != attempt["managed_worktree_generation"]
        ):
            raise LeaseConflict("focused execution worktree generation changed")
        external = connection.execute(
            "SELECT * FROM external_processes WHERE attempt_id = ?",
            (job["current_attempt_id"],),
        ).fetchone()
        if (
            external is None
            or external["provider"] != "focused_test"
            or external["state"] != "stopped"
            or external["target_executable"] != execution["executable_path"]
        ):
            raise LeaseConflict(
                "focused execution requires its exact durably stopped process"
            )
        executable = self._focused_executable_identity(str(execution["executable_path"]))
        if executable != {
            "path": execution["executable_path"],
            "device": execution["executable_device"],
            "inode": execution["executable_inode"],
            "owner_uid": execution["executable_owner_uid"],
            "mode": execution["executable_mode"],
            "sha256": execution["executable_sha256"],
        }:
            raise LeaseConflict("focused execution executable changed after collection")
        cwd = Path(str(execution["cwd"]))
        cwd_details = cwd.lstat()
        if (
            not stat.S_ISDIR(cwd_details.st_mode)
            or int(cwd_details.st_dev) != execution["cwd_device"]
            or int(cwd_details.st_ino) != execution["cwd_inode"]
            or int(cwd_details.st_uid) != execution["cwd_owner_uid"]
            or int(cwd_details.st_mode) != execution["cwd_mode"]
        ):
            raise LeaseConflict("focused execution cwd changed after collection")
        manifest = self._scan_focused_workspace(cwd)
        before = self._normalize_focused_manifest(
            _load(execution["workspace_manifest_before_json"], {})
        )
        after = self._normalize_focused_manifest(
            _load(execution["workspace_manifest_after_json"], {})
        )
        if manifest != before or manifest != after:
            raise LeaseConflict("focused workspace changed after collection")
        self._assert_focused_runtime_layout(execution)
        stdout_identity, stdout = self._inspect_private_output(
            Path(str(execution["stdout_path"])), int(execution["output_limit_bytes"])
        )
        stderr_identity, stderr = self._inspect_private_output(
            Path(str(execution["stderr_path"])), int(execution["output_limit_bytes"])
        )
        for prefix, identity in (("stdout", stdout_identity), ("stderr", stderr_identity)):
            for name in ("device", "inode", "owner_uid", "mode", "nlink", "bytes", "sha256"):
                if identity[name] != execution["%s_%s" % (prefix, name)]:
                    raise LeaseConflict("focused %s artifact changed after collection" % prefix)
        outcome, semantic_summary = self._focused_semantic_outcome(
            str(execution["selector"]), int(execution["exit_code"]), stdout, stderr
        )
        if outcome != execution["outcome"] or semantic_summary != execution["semantic_summary"]:
            raise LeaseConflict("focused execution semantics changed after collection")
        artifact_rows = connection.execute(
            """SELECT * FROM artifacts
               WHERE id IN (?, ?) AND attempt_id = ? AND job_id = ?""",
            (
                execution["stdout_artifact_id"],
                execution["stderr_artifact_id"],
                job["current_attempt_id"],
                job["id"],
            ),
        ).fetchall()
        artifacts = {row["id"]: self._row(row) for row in artifact_rows}
        if set(artifacts) != {
            execution["stdout_artifact_id"],
            execution["stderr_artifact_id"],
        }:
            raise LeaseConflict("focused execution artifact bindings are incomplete")
        execution_data = self._row(execution)
        assert execution_data is not None
        stdout_artifact = artifacts[execution["stdout_artifact_id"]]
        stderr_artifact = artifacts[execution["stderr_artifact_id"]]
        assert stdout_artifact is not None and stderr_artifact is not None
        canonical = self._canonical_focused_handoff(
            execution_data, stdout_artifact, stderr_artifact
        )
        persisted_canonical = _load(execution["canonical_handoff_json"], None)
        if persisted_canonical is not None and persisted_canonical != canonical:
            raise LeaseConflict("focused canonical handoff changed after collection")
        return execution_data, stdout_artifact, stderr_artifact

    def complete_focused_test_execution(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Validate and atomically persist one current-attempt focused result."""

        if not isinstance(result, Mapping):
            raise ValueError("focused execution result must be a mapping")
        with self._transaction() as connection:
            now = self._clock()
            job = self._assert_live_lease(
                connection, job_id, worker_id, lease_token, now
            )
            if job["role"] != "tester":
                raise LeaseConflict("focused completion requires a tester lease")
            self._assert_managed_worktree_binding(connection, job)
            execution = connection.execute(
                "SELECT * FROM focused_test_executions WHERE attempt_id = ?",
                (job["current_attempt_id"],),
            ).fetchone()
            if execution is None or execution["status"] != "prepared":
                raise LeaseConflict("current tester attempt has no prepared focused execution")

            required_exact = {
                "execution_id": execution["id"],
                "command": _load(execution["command_argv_json"], []),
                "cwd": execution["cwd"],
                "artifact_directory": execution["artifact_directory"],
            }
            for name, expected in required_exact.items():
                observed = result.get(name)
                if name == "command" and not isinstance(observed, (str, bytes)):
                    observed = list(observed or [])
                if observed != expected:
                    raise LeaseConflict("focused result %s differs from its prepared value" % name)
            workspace_manifest = self._normalize_focused_manifest(
                result.get("workspace_manifest", {})  # type: ignore[arg-type]
            )
            expected_manifest = self._normalize_focused_manifest(
                _load(execution["workspace_manifest_before_json"], {})
            )
            observed_manifest = self._scan_focused_workspace(Path(str(execution["cwd"])))
            if workspace_manifest != expected_manifest or observed_manifest != expected_manifest:
                raise LeaseConflict("focused workspace changed during execution")

            for name in ("stdout_truncated", "stderr_truncated"):
                if result.get(name) is not False:
                    raise ValueError("focused truncated output cannot become evidence")
            exit_code = result.get("exit_code")
            if not isinstance(exit_code, int) or isinstance(exit_code, bool):
                raise ValueError("focused exit_code must be an integer")
            self._assert_external_process_stopped(connection, job)
            external = connection.execute(
                "SELECT * FROM external_processes WHERE attempt_id = ?",
                (job["current_attempt_id"],),
            ).fetchone()
            if (
                external is None
                or external["provider"] != "focused_test"
                or external["state"] != "stopped"
                or external["target_executable"] != execution["executable_path"]
            ):
                raise LeaseConflict(
                    "focused completion requires its exact durably stopped process"
                )

            self._assert_focused_runtime_layout(execution)
            output_limit = int(execution["output_limit_bytes"])
            outputs: Dict[str, tuple[Dict[str, Any], bytes]] = {}
            for prefix in ("stdout", "stderr"):
                expected_path = str(execution["%s_path" % prefix])
                if result.get("%s_path" % prefix) != expected_path:
                    raise LeaseConflict("focused %s path differs from its prepared value" % prefix)
                identity, content = self._inspect_private_output(
                    Path(expected_path), output_limit
                )
                for field in ("sha256", "bytes"):
                    if result.get("%s_%s" % (prefix, field)) != identity[field]:
                        raise LeaseConflict(
                            "focused %s %s differs from the verified artifact"
                            % (prefix, field)
                        )
                outputs[prefix] = (identity, content)

            executable = self._focused_executable_identity(str(execution["executable_path"]))
            for field in ("path", "device", "inode", "owner_uid", "mode", "sha256"):
                execution_field = (
                    "executable_path" if field == "path" else "executable_%s" % field
                )
                if executable[field] != execution[execution_field]:
                    raise LeaseConflict("focused executable changed during execution")
            cwd_details = Path(str(execution["cwd"])).lstat()
            if (
                int(cwd_details.st_dev) != execution["cwd_device"]
                or int(cwd_details.st_ino) != execution["cwd_inode"]
                or int(cwd_details.st_uid) != execution["cwd_owner_uid"]
                or int(cwd_details.st_mode) != execution["cwd_mode"]
            ):
                raise LeaseConflict("focused cwd changed during execution")

            outcome, semantic_summary = self._focused_semantic_outcome(
                str(execution["selector"]),
                exit_code,
                outputs["stdout"][1],
                outputs["stderr"][1],
            )
            artifact_ids: Dict[str, str] = {}
            artifact_kinds = (
                ("stdout", "focused_test_stdout"),
                ("stderr", "focused_test_stderr"),
            )
            for prefix, kind in artifact_kinds:
                identity = outputs[prefix][0]
                artifact_id = _id()
                artifact_ids[prefix] = artifact_id
                connection.execute(
                    """INSERT INTO artifacts
                       (id, work_item_id, job_id, attempt_id, kind, uri,
                        metadata_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        artifact_id,
                        job["work_item_id"],
                        job_id,
                        job["current_attempt_id"],
                        kind,
                        execution["%s_path" % prefix],
                        _dump(
                            {
                                "attempt_id": job["current_attempt_id"],
                                "execution_id": execution["id"],
                                "sha256": identity["sha256"],
                                "bytes": identity["bytes"],
                            }
                        ),
                        now,
                    ),
                )
            stdout_identity = outputs["stdout"][0]
            stderr_identity = outputs["stderr"][0]
            changed = connection.execute(
                """UPDATE focused_test_executions
                   SET status = 'finished', outcome = ?,
                       workspace_manifest_after_json = ?,
                       workspace_manifest_after_sha256 = ?,
                       stdout_device = ?, stdout_inode = ?, stdout_owner_uid = ?,
                       stdout_mode = ?, stdout_nlink = ?, stdout_bytes = ?,
                       stdout_sha256 = ?, stdout_truncated = 0,
                       stderr_device = ?, stderr_inode = ?, stderr_owner_uid = ?,
                       stderr_mode = ?, stderr_nlink = ?, stderr_bytes = ?,
                       stderr_sha256 = ?, stderr_truncated = 0,
                       stdout_artifact_id = ?, stderr_artifact_id = ?,
                       exit_code = ?, semantic_summary = ?, finished_at = ?,
                       updated_at = ?
                   WHERE id = ? AND status = 'prepared'""",
                (
                    outcome,
                    _dump(observed_manifest),
                    hashlib.sha256(_dump(observed_manifest).encode("utf-8")).hexdigest(),
                    stdout_identity["device"],
                    stdout_identity["inode"],
                    stdout_identity["owner_uid"],
                    stdout_identity["mode"],
                    stdout_identity["nlink"],
                    stdout_identity["bytes"],
                    stdout_identity["sha256"],
                    stderr_identity["device"],
                    stderr_identity["inode"],
                    stderr_identity["owner_uid"],
                    stderr_identity["mode"],
                    stderr_identity["nlink"],
                    stderr_identity["bytes"],
                    stderr_identity["sha256"],
                    artifact_ids["stdout"],
                    artifact_ids["stderr"],
                    exit_code,
                    semantic_summary,
                    now,
                    now,
                    execution["id"],
                ),
            ).rowcount
            if changed != 1:
                raise LeaseConflict("focused execution changed during completion")
            for prefix in ("stdout", "stderr"):
                self._append_event(
                    connection,
                    "artifact.added",
                    campaign_id=job["campaign_id"],
                    work_item_id=job["work_item_id"],
                    job_id=job_id,
                    actor=worker_id,
                    event_data={
                        "artifact_id": artifact_ids[prefix],
                        "attempt_id": job["current_attempt_id"],
                        "execution_id": execution["id"],
                        "kind": "focused_test_%s" % prefix,
                        "uri": execution["%s_path" % prefix],
                    },
                    created_at=now,
                )
            self._append_event(
                connection,
                "focused_test.execution_finished",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job_id,
                actor=worker_id,
                event_data={
                    "execution_id": execution["id"],
                    "attempt_id": job["current_attempt_id"],
                    "outcome": outcome,
                    "exit_code": exit_code,
                },
                created_at=now,
            )
            finished = connection.execute(
                "SELECT * FROM focused_test_executions WHERE id = ?",
                (execution["id"],),
            ).fetchone()
            assert finished is not None
            execution_data, stdout_artifact, stderr_artifact = (
                self._assert_finished_focused_execution(connection, job, finished)
            )
            response = dict(execution_data)
            canonical_handoff = self._canonical_focused_handoff(
                execution_data, stdout_artifact, stderr_artifact
            )
            connection.execute(
                """UPDATE focused_test_executions
                   SET canonical_handoff_json = ?, updated_at = ?
                   WHERE id = ? AND status = 'finished'""",
                (_dump(canonical_handoff), now, execution["id"]),
            )
            response["canonical_handoff"] = canonical_handoff
            return response

    def get_focused_test_execution(self, execution_id: str) -> Dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM focused_test_executions WHERE id = ?", (execution_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("focused test execution %s not found" % execution_id)
        return self._row(row)  # type: ignore[return-value]

    def list_focused_test_executions(
        self,
        *,
        work_item_id: Optional[str] = None,
        job_id: Optional[str] = None,
        attempt_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        parameters: List[Any] = []
        for column, value in (
            ("work_item_id", work_item_id),
            ("job_id", job_id),
            ("attempt_id", attempt_id),
        ):
            if value is not None:
                clauses.append(column + " = ?")
                parameters.append(value)
        sql = "SELECT * FROM focused_test_executions"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY prepared_at, id"
        with self._lock:
            return self._rows(self._connection.execute(sql, parameters).fetchall())

    def _finish_job(
        self, connection: sqlite3.Connection, job: sqlite3.Row, worker_id: str,
        lease_token: str, result: Mapping[str, Any], now: float
    ) -> None:
        self._assert_external_process_stopped(connection, job)
        self._assert_managed_worktree_binding(connection, job)
        expected_resources = set(_load(job["required_resources_json"], []))
        persisted_resources = connection.execute(
            """SELECT resource_key, owner_id, lease_token, expires_at
               FROM resource_leases
               WHERE job_id = ?""",
            (job["id"],),
        ).fetchall()
        actual_resources = {row["resource_key"] for row in persisted_resources}
        fences_match = all(
            row["owner_id"] == worker_id
            and row["lease_token"] == lease_token
            and row["expires_at"] > now
            for row in persisted_resources
        )
        if actual_resources != expected_resources or not fences_match:
            raise LeaseConflict("one or more required resource lease fences were lost")

        attempt_changed = connection.execute(
            """UPDATE attempts SET status = 'succeeded', result_json = ?, finished_at = ?
               WHERE id = ? AND status = 'running'""",
            (_dump(dict(result)), now, job["current_attempt_id"]),
        ).rowcount
        job_changed = connection.execute(
            """UPDATE jobs SET status = 'completed', result_json = ?, lease_owner = NULL,
               lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL,
               current_attempt_id = NULL, updated_at = ?
               WHERE id = ? AND status = 'running' AND lease_owner = ?
                 AND lease_token = ?""",
            (_dump(dict(result)), now, job["id"], worker_id, lease_token),
        ).rowcount
        if attempt_changed != 1 or job_changed != 1:
            raise LeaseConflict("job or attempt fence changed during finalization")
        released = connection.execute(
            "DELETE FROM resource_leases WHERE job_id = ? AND owner_id = ? AND lease_token = ?",
            (job["id"], worker_id, lease_token),
        ).rowcount
        if released != len(expected_resources):
            raise LeaseConflict("required resources changed during finalization")

    def _validate_stage_result(
        self,
        connection: sqlite3.Connection,
        job: sqlite3.Row,
        result: Mapping[str, Any],
        next_item_state: str,
    ) -> Dict[str, Any]:
        """Validate untrusted stage output at the durable mutation boundary."""

        role = str(job["role"])
        campaign = connection.execute(
            "SELECT config_json FROM campaigns WHERE id = ?", (job["campaign_id"],)
        ).fetchone()
        if campaign is None:
            raise NotFoundError("campaign %s not found" % job["campaign_id"])
        allow_simulated = (
            _load(campaign["config_json"], {}).get("allow_simulated_evidence") is True
        )
        try:
            if role == "investigator":
                handoff = InvestigationHandoff.model_validate(result)
                expected_next_state = (
                    ItemState.BLOCKED
                    if handoff.outcome == InvestigationOutcome.BLOCKED
                    else ItemState.READY_FOR_FIX
                )
            elif role == "fixer":
                handoff = FixHandoff.model_validate(result)
                expected_next_state = (
                    ItemState.BLOCKED
                    if handoff.outcome == FixOutcome.BLOCKED
                    else ItemState.READY_FOR_TEST
                )
            elif role == "tester":
                item = connection.execute(
                    "SELECT required_gates_json FROM work_items WHERE id = ?",
                    (job["work_item_id"],),
                ).fetchone()
                if item is None:
                    raise NotFoundError(
                        "work item %s not found" % job["work_item_id"]
                    )
                required_gates = _load(item["required_gates_json"], [])
                if not allow_simulated and "focused_tests" in required_gates:
                    if required_gates != ["focused_tests"]:
                        raise ValueError(
                            "tester handoff cannot advance: the authoritative focused "
                            "collector slice supports exactly the focused_tests gate"
                        )
                    execution = connection.execute(
                        """SELECT * FROM focused_test_executions
                           WHERE attempt_id = ? AND job_id = ?""",
                        (job["current_attempt_id"], job["id"]),
                    ).fetchone()
                    if execution is None:
                        raise ValueError(
                            "current tester attempt has no authoritative focused execution"
                        )
                    if execution["canonical_handoff_json"] is None:
                        raise ValueError(
                            "current focused execution has no persisted canonical handoff"
                        )
                    execution_data, stdout_artifact, stderr_artifact = (
                        self._assert_finished_focused_execution(
                            connection, job, execution
                        )
                    )
                    handoff = TestHandoff.model_validate(
                        self._canonical_focused_handoff(
                            execution_data, stdout_artifact, stderr_artifact
                        )
                    )
                else:
                    handoff = TestHandoff.model_validate(result)
                evaluation = evaluate_test_handoff(
                    tuple(
                        GateKind(gate)
                        for gate in required_gates
                    ),
                    handoff,
                )
                if not evaluation.can_advance or evaluation.next_state is None:
                    reasons = "; ".join(evaluation.reasons) or "evidence gate rejected"
                    raise ValueError("tester handoff cannot advance: %s" % reasons)
                expected_next_state = evaluation.next_state
            else:
                raise ValueError("unsupported worker role: %s" % role)
        except ValidationError as error:
            raise ValueError("invalid %s handoff: %s" % (role, error)) from error

        if handoff.item_id != job["work_item_id"]:
            raise ValueError("handoff item_id does not match the fenced job")
        if expected_next_state.value != next_item_state:
            raise TransitionConflict(
                "%s handoff requires %s, not %s"
                % (role, expected_next_state.value, next_item_state)
            )

        for evidence in _handoff_evidence(handoff):
            if evidence.metadata.get("simulated") is True:
                if not allow_simulated:
                    raise ValueError(
                        "simulated evidence is disabled for this campaign"
                    )
                continue
            location = Path(evidence.location).expanduser()
            if not location.is_absolute() or not location.is_file():
                raise ValueError(
                    "evidence attachment does not exist as an absolute file: %s"
                    % evidence.location
                )
        return handoff.model_dump(mode="json")

    def commit_stage_result(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        result: Mapping[str, Any],
        expected_item_state: str,
        next_item_state: str,
        event_kind: str,
        event_data: Optional[Mapping[str, Any]] = None,
        next_job: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        expected_item_state = _value(expected_item_state).lower()
        next_item_state = _value(next_item_state).lower()
        if expected_item_state not in VALID_ITEM_STATES or next_item_state not in VALID_ITEM_STATES:
            raise ValueError("stage result contains an unsupported item state")
        with self._transaction() as connection:
            now = self._clock()
            job = self._assert_live_lease(connection, job_id, worker_id, lease_token, now)
            if expected_item_state != job["active_item_state"]:
                raise TransitionConflict("expected state does not match the job active state")
            if next_item_state not in STAGE_NEXT_STATES[job["role"]]:
                raise TransitionConflict(
                    "%s stage cannot transition to %s"
                    % (job["role"], next_item_state)
                )
            validated_result = self._validate_stage_result(
                connection, job, result, next_item_state
            )
            successor_by_state = {
                "ready_for_fix": "fixer",
                "ready_for_test": "tester",
            }
            expected_successor = successor_by_state.get(next_item_state)
            actual_successor = (
                None if next_job is None else _value(next_job["role"]).lower()
            )
            if actual_successor != expected_successor:
                raise TransitionConflict(
                    "%s transition requires %s successor, not %s"
                    % (
                        next_item_state,
                        expected_successor or "no",
                        actual_successor or "no",
                    )
                )
            changed = connection.execute(
                "UPDATE work_items SET state = ?, updated_at = ? WHERE id = ? AND state = ?",
                (next_item_state, now, job["work_item_id"], expected_item_state),
            ).rowcount
            if changed != 1:
                raise TransitionConflict("work item state changed before stage commit")
            self._finish_job(
                connection, job, worker_id, lease_token, validated_result, now
            )
            data = dict(event_data or {})
            data.update({"from_state": expected_item_state, "to_state": next_item_state})
            self._append_event(
                connection, event_kind, campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"], job_id=job_id, actor=worker_id,
                event_data=data, created_at=now
            )
            next_record: Optional[Dict[str, Any]] = None
            if next_job is not None:
                successor_workspace_kind = next_job.get("workspace_kind")
                successor_worktree_id = next_job.get("managed_worktree_id")
                if (
                    job["workspace_kind"]
                    == WorkspaceKind.MANAGED_WORKTREE.value
                    and actual_successor in ("fixer", "tester")
                ):
                    successor_workspace_kind = WorkspaceKind.MANAGED_WORKTREE.value
                    successor_worktree_id = job["managed_worktree_id"]
                next_record = self._enqueue_job(
                    connection, job["work_item_id"], _value(next_job["role"]).lower(),
                    stage=str(next_job["stage"]),
                    queued_item_state=_value(
                        next_job.get("queued_item_state", next_item_state)
                    ).lower(),
                    active_item_state=_value(next_job["active_item_state"]).lower(),
                    payload=next_job.get("payload"),
                    required_resources=next_job.get("required_resources"),
                    required_approval_action=next_job.get("required_approval_action"),
                    workspace_kind=successor_workspace_kind,
                    managed_worktree_id=successor_worktree_id,
                    priority=int(next_job.get("priority", 0)),
                    available_at=float(next_job.get("available_at", now)),
                    job_id=next_job.get("job_id"), now=now,
                )
            item = connection.execute(
                "SELECT * FROM work_items WHERE id = ?", (job["work_item_id"],)
            ).fetchone()
            completed = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            response = {"job": self._row(completed), "work_item": self._row(item), "next_job": None}
            if next_record is not None:
                response["next_job"] = self._row(connection.execute(
                    "SELECT * FROM jobs WHERE id = ?", (next_record["id"],)
                ).fetchone())
            return response

    def _end_prepared_focused_execution(
        self,
        connection: sqlite3.Connection,
        job: sqlite3.Row,
        *,
        status: str,
        reason: str,
        now: float,
        actor: Optional[str] = None,
    ) -> None:
        if status not in ("abandoned", "quarantined"):
            raise ValueError("focused execution terminal status is invalid")
        changed = connection.execute(
            """UPDATE focused_test_executions
               SET status = ?, error = ?, finished_at = ?, updated_at = ?
               WHERE attempt_id = ? AND status = 'prepared'""",
            (status, reason, now, now, job["current_attempt_id"]),
        ).rowcount
        if changed:
            self._append_event(
                connection,
                "focused_test.execution_%s" % status,
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job["id"],
                actor=actor,
                event_data={
                    "attempt_id": job["current_attempt_id"],
                    "reason": reason,
                },
                created_at=now,
            )

    def fail_job(
        self, job_id: str, worker_id: str, lease_token: str, error: str, *,
        result: Optional[Mapping[str, Any]] = None, requeue: bool = True,
        available_at: Optional[float] = None, max_attempts: int = 3,
        blocked_item_state: str = "blocked",
    ) -> Dict[str, Any]:
        if (
            not isinstance(max_attempts, int)
            or isinstance(max_attempts, bool)
            or max_attempts < 1
        ):
            raise ValueError("max_attempts must be a positive integer")
        with self._transaction() as connection:
            now = self._clock()
            job = self._assert_live_lease(connection, job_id, worker_id, lease_token, now)
            self._assert_external_process_stopped(connection, job)
            self._end_prepared_focused_execution(
                connection,
                job,
                status="abandoned",
                reason=error,
                now=now,
                actor=worker_id,
            )
            attempt_status = "failed"
            connection.execute(
                """UPDATE attempts SET status = ?, result_json = ?, error = ?, finished_at = ?
                   WHERE id = ? AND status = 'running'""",
                (attempt_status, _dump(dict(result or {})), error, now, job["current_attempt_id"]),
            )
            failed_attempts = int(
                connection.execute(
                    """SELECT COUNT(*) FROM attempts
                       WHERE job_id = ? AND status = 'failed'""",
                    (job_id,),
                ).fetchone()[0]
            )
            managed_worktree_quarantined = False
            if job["managed_worktree_id"] is not None:
                worktree = connection.execute(
                    "SELECT state FROM managed_worktrees WHERE id = ?",
                    (job["managed_worktree_id"],),
                ).fetchone()
                managed_worktree_quarantined = (
                    worktree is None or worktree["state"] == "quarantined"
                )
            will_requeue = (
                requeue
                and failed_attempts < max_attempts
                and not managed_worktree_quarantined
            )
            next_item_state = (
                job["queued_item_state"]
                if will_requeue
                else _value(blocked_item_state).lower()
            )
            changed = connection.execute(
                "UPDATE work_items SET state = ?, updated_at = ? WHERE id = ? AND state = ?",
                (next_item_state, now, job["work_item_id"], job["active_item_state"]),
            ).rowcount
            if changed != 1:
                raise TransitionConflict("cannot restore or block item after failed job")
            status = "pending" if will_requeue else "failed"
            connection.execute(
                """UPDATE jobs SET status = ?, result_json = ?, last_error = ?, available_at = ?,
                   lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL,
                   heartbeat_at = NULL, current_attempt_id = NULL, updated_at = ? WHERE id = ?""",
                (status, _dump(dict(result or {})), error,
                 now if available_at is None else available_at, now, job_id),
            )
            connection.execute(
                "DELETE FROM resource_leases WHERE job_id = ? AND lease_token = ?",
                (job_id, lease_token),
            )
            self._append_event(
                connection, "job.requeued" if will_requeue else "job.failed",
                campaign_id=job["campaign_id"], work_item_id=job["work_item_id"],
                job_id=job_id,
                actor=worker_id,
                event_data={
                    "error": error,
                    "from_state": job["active_item_state"],
                    "to_state": next_item_state,
                    "attempt_number": job["attempt_count"],
                    "failed_attempts": failed_attempts,
                    "max_attempts": max_attempts,
                    "managed_worktree_quarantined": managed_worktree_quarantined,
                },
                created_at=now,
            )
        return self.get_job(job_id)

    def release_job(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        *,
        reason: str = "released",
    ) -> Dict[str, Any]:
        return self.interrupt_job(
            job_id, worker_id, lease_token, reason=reason
        )

    def interrupt_job(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        *,
        reason: str = "interrupted",
    ) -> Dict[str, Any]:
        """Record a clean interruption and requeue without treating it as a defect."""

        with self._transaction() as connection:
            now = self._clock()
            job = self._assert_live_lease(
                connection, job_id, worker_id, lease_token, now
            )
            self._assert_external_process_stopped(connection, job)
            self._end_prepared_focused_execution(
                connection,
                job,
                status="abandoned",
                reason=reason,
                now=now,
                actor=worker_id,
            )
            changed = connection.execute(
                """UPDATE work_items SET state = ?, updated_at = ?
                   WHERE id = ? AND state = ?""",
                (
                    job["queued_item_state"],
                    now,
                    job["work_item_id"],
                    job["active_item_state"],
                ),
            ).rowcount
            if changed != 1:
                raise TransitionConflict("cannot restore item state after interruption")
            connection.execute(
                """UPDATE attempts SET status = 'interrupted', error = ?, finished_at = ?
                   WHERE id = ? AND status = 'running'""",
                (reason, now, job["current_attempt_id"]),
            )
            connection.execute(
                """UPDATE jobs SET status = 'pending', last_error = ?, available_at = ?,
                   lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL,
                   heartbeat_at = NULL, current_attempt_id = NULL, updated_at = ?
                   WHERE id = ?""",
                (reason, now, now, job_id),
            )
            connection.execute(
                "DELETE FROM resource_leases WHERE job_id = ? AND lease_token = ?",
                (job_id, lease_token),
            )
            self._append_event(
                connection,
                "job.interrupted",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job_id,
                actor=worker_id,
                event_data={
                    "reason": reason,
                    "from_state": job["active_item_state"],
                    "to_state": job["queued_item_state"],
                },
                created_at=now,
            )
        return self.get_job(job_id)

    def recover_expired_leases(self) -> Dict[str, Any]:
        with self._transaction() as connection:
            now = self._clock()
            return self._recover_expired(connection, now)

    def _expire_job_after_lease(
        self,
        connection: sqlite3.Connection,
        job: sqlite3.Row,
        now: float,
        *,
        error: str,
        event_data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        expected_resources = set(_load(job["required_resources_json"], []))
        persisted_resources = connection.execute(
            """SELECT resource_key, owner_id, lease_token
               FROM resource_leases WHERE job_id = ?""",
            (job["id"],),
        ).fetchall()
        actual_resources = {row["resource_key"] for row in persisted_resources}
        if actual_resources != expected_resources or any(
            row["owner_id"] != job["lease_owner"]
            or row["lease_token"] != job["lease_token"]
            for row in persisted_resources
        ):
            raise LeaseConflict(
                "expired job resource fences changed before recovery"
            )
        changed = connection.execute(
            "UPDATE work_items SET state = ?, updated_at = ? WHERE id = ? AND state = ?",
            (
                job["queued_item_state"],
                now,
                job["work_item_id"],
                job["active_item_state"],
            ),
        ).rowcount
        if changed != 1:
            raise TransitionConflict(
                "cannot recover expired job because item state is inconsistent"
            )
        self._end_prepared_focused_execution(
            connection,
            job,
            status="abandoned",
            reason=error,
            now=now,
        )
        attempt_changed = connection.execute(
            """UPDATE attempts SET status = 'expired', finished_at = ?, error = ?
               WHERE id = ? AND status = 'running'""",
            (now, error, job["current_attempt_id"]),
        ).rowcount
        if attempt_changed != 1:
            raise LeaseConflict("expired attempt changed before recovery")
        job_changed = connection.execute(
            """UPDATE jobs SET status = 'pending', lease_owner = NULL,
               lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL,
               current_attempt_id = NULL, available_at = ?, last_error = ?,
               updated_at = ? WHERE id = ? AND status = 'running'
               AND current_attempt_id = ?""",
            (
                now,
                error,
                now,
                job["id"],
                job["current_attempt_id"],
            ),
        ).rowcount
        if job_changed != 1:
            raise LeaseConflict("expired job changed before recovery")
        released = connection.execute(
            """DELETE FROM resource_leases
               WHERE job_id = ? AND owner_id = ? AND lease_token = ?""",
            (job["id"], job["lease_owner"], job["lease_token"]),
        ).rowcount
        if released != len(expected_resources):
            raise LeaseConflict("expired resource fences changed during recovery")
        details = {
            "from_state": job["active_item_state"],
            "to_state": job["queued_item_state"],
            "attempt_id": job["current_attempt_id"],
        }
        details.update(dict(event_data or {}))
        self._append_event(
            connection,
            "job.lease_expired",
            campaign_id=job["campaign_id"],
            work_item_id=job["work_item_id"],
            job_id=job["id"],
            event_data=details,
            created_at=now,
        )

    def _recover_expired(self, connection: sqlite3.Connection, now: float) -> Dict[str, Any]:
        expired = connection.execute(
            """SELECT * FROM jobs
               WHERE status = 'running' AND lease_expires_at <= ?
               ORDER BY id""",
            (now,),
        ).fetchall()
        recovered_jobs = 0
        recovered_job_ids: List[str] = []
        quarantined_processes: List[Dict[str, Any]] = []
        for job in expired:
            external = connection.execute(
                """SELECT * FROM external_processes
                   WHERE attempt_id = ? AND state != 'stopped'""",
                (job["current_attempt_id"],),
            ).fetchone()
            if external is not None:
                quarantined_processes.append(
                    {
                        "job_id": str(job["id"]),
                        "attempt_id": str(job["current_attempt_id"]),
                        "process_id": int(external["process_id"]),
                        "process_group_id": int(external["process_group_id"]),
                        "user_id": external["owner_uid"],
                        "executable": external["kernel_executable"],
                        "start_seconds": external["start_seconds"],
                        "start_microseconds": external["start_microseconds"],
                        "target_executable": external["target_executable"],
                        "identity_version": external["identity_version"],
                        "state": external["state"],
                        "last_error": external["last_error"],
                    }
                )
                continue
            self._expire_job_after_lease(
                connection,
                job,
                now,
                error="lease expired",
            )
            recovered_jobs += 1
            recovered_job_ids.append(str(job["id"]))
        orphaned = connection.execute(
            """SELECT r.* FROM resource_leases r
               LEFT JOIN jobs j ON j.id = r.job_id
               WHERE r.expires_at <= ?
                 AND (r.job_id IS NULL OR j.status IS NULL OR j.status != 'running')""",
            (now,),
        ).fetchall()
        for lease in orphaned:
            connection.execute(
                "DELETE FROM resource_leases WHERE resource_key = ?",
                (lease["resource_key"],),
            )
            self._append_event(
                connection, "resource.lease_expired", job_id=lease["job_id"],
                actor=lease["owner_id"], event_data={"resource_key": lease["resource_key"]},
                created_at=now
            )
        result = {
            "jobs": recovered_jobs,
            "resources": len(orphaned),
            "job_ids": recovered_job_ids,
        }
        if quarantined_processes:
            result["external_processes_pending"] = quarantined_processes
        return result

    def claim_external_process_reconciliation(
        self,
        owner: str,
        *,
        lease_seconds: float = 30.0,
        include_quarantined: bool = False,
        exclude_attempt_ids: Sequence[str] = (),
    ) -> Optional[Dict[str, Any]]:
        """Fence one expired external process for out-of-transaction inspection."""

        owner = owner.strip()
        if not owner or len(owner) > 256:
            raise ValueError("reconciliation owner must contain 1 to 256 characters")
        if lease_seconds <= 0:
            raise ValueError("reconciliation lease_seconds must be positive")
        states = ["active", "legacy_unverifiable"]
        if include_quarantined:
            states.append("quarantined")
        placeholders = ",".join("?" for _ in states)
        excluded = tuple(dict.fromkeys(str(value) for value in exclude_attempt_ids))
        exclusion_sql = ""
        if excluded:
            exclusion_sql = " AND ep.attempt_id NOT IN (%s)" % ",".join(
                "?" for _ in excluded
            )
        with self._transaction() as connection:
            now = self._clock()
            candidate = connection.execute(
                """SELECT ep.*, j.campaign_id, j.work_item_id
                   FROM external_processes ep
                   JOIN jobs j ON j.id = ep.job_id
                   WHERE ep.state IN (%s)
                     %s
                     AND j.status = 'running'
                     AND j.current_attempt_id = ep.attempt_id
                     AND j.lease_expires_at <= ?
                     AND (ep.reconciliation_token IS NULL
                          OR ep.reconciliation_expires_at <= ?)
                   ORDER BY ep.recorded_at, ep.id LIMIT 1"""
                % (placeholders, exclusion_sql),
                tuple(states) + excluded + (now, now),
            ).fetchone()
            if candidate is None:
                return None
            token = _id()
            expires_at = now + lease_seconds
            changed = connection.execute(
                """UPDATE external_processes
                   SET reconciliation_owner = ?, reconciliation_token = ?,
                       reconciliation_expires_at = ?, updated_at = ?
                   WHERE id = ? AND state = ?
                     AND (reconciliation_token IS NULL
                          OR reconciliation_expires_at <= ?)""",
                (
                    owner,
                    token,
                    expires_at,
                    now,
                    candidate["id"],
                    candidate["state"],
                    now,
                ),
            ).rowcount
            if changed != 1:
                raise LeaseConflict("external process reconciliation was claimed concurrently")
            self._append_event(
                connection,
                "worker.external_process_reconciliation_claimed",
                campaign_id=candidate["campaign_id"],
                work_item_id=candidate["work_item_id"],
                job_id=candidate["job_id"],
                actor=owner,
                event_data={
                    "attempt_id": candidate["attempt_id"],
                    "process_id": candidate["process_id"],
                    "process_group_id": candidate["process_group_id"],
                    "expires_at": expires_at,
                },
                created_at=now,
            )
            claimed = connection.execute(
                """SELECT ep.*, j.campaign_id, j.work_item_id
                   FROM external_processes ep
                   JOIN jobs j ON j.id = ep.job_id
                   WHERE ep.id = ?""",
                (candidate["id"],),
            ).fetchone()
            return self._row(claimed)

    def complete_external_process_reconciliation(
        self,
        attempt_id: str,
        owner: str,
        reconciliation_token: str,
        expected_identity: Mapping[str, Any],
        status: str,
        reason: str,
        *,
        observed: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Commit a fenced OS result and release resources only when proven safe."""

        status = status.strip().lower()
        reason = reason.strip()
        if status not in ("gone", "terminated", "quarantined"):
            raise ValueError("unsupported external process reconciliation status")
        if not reason or len(reason) > 4096:
            raise ValueError("reconciliation reason must contain 1 to 4096 characters")
        with self._transaction() as connection:
            now = self._clock()
            external = connection.execute(
                "SELECT * FROM external_processes WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if external is None:
                raise NotFoundError(
                    "external process for attempt %s not found" % attempt_id
                )
            job = connection.execute(
                "SELECT * FROM jobs WHERE id = ?", (external["job_id"],)
            ).fetchone()
            if job is None:
                raise NotFoundError("job %s not found" % external["job_id"])
            if (
                external["reconciliation_owner"] != owner
                or external["reconciliation_token"] != reconciliation_token
                or external["reconciliation_expires_at"] <= now
            ):
                raise LeaseConflict("external process reconciliation fence is stale")
            if (
                job["status"] != "running"
                or job["current_attempt_id"] != attempt_id
                or job["lease_expires_at"] > now
            ):
                raise LeaseConflict("external process job is not expired and current")
            persisted_identity = {
                "process_id": external["process_id"],
                "process_group_id": external["process_group_id"],
                "user_id": external["owner_uid"],
                "executable": external["kernel_executable"],
                "start_seconds": external["start_seconds"],
                "start_microseconds": external["start_microseconds"],
                "target_executable": external["target_executable"],
                "identity_version": external["identity_version"],
            }
            if dict(expected_identity) != persisted_identity:
                raise LeaseConflict("external process identity changed before reconciliation")
            if status in ("gone", "terminated") and (
                external["identity_version"] != "darwin_libproc_v1"
                or external["owner_uid"] is None
                or external["start_seconds"] is None
                or external["start_microseconds"] is None
                or not external["kernel_executable"]
                or not external["target_executable"]
            ):
                raise LeaseConflict(
                    "unverifiable external process cannot be released automatically"
                )
            event_data = {
                "attempt_id": attempt_id,
                "process_id": external["process_id"],
                "process_group_id": external["process_group_id"],
                "status": status,
                "reason": reason,
                "observed": dict(observed or {}),
            }
            if status == "quarantined":
                self._end_prepared_focused_execution(
                    connection,
                    job,
                    status="quarantined",
                    reason=reason,
                    now=now,
                    actor=owner,
                )
                connection.execute(
                    """UPDATE external_processes
                       SET state = 'quarantined', outcome = 'quarantined',
                           last_error = ?, reconciliation_owner = NULL,
                           reconciliation_token = NULL,
                           reconciliation_expires_at = NULL, updated_at = ?
                       WHERE id = ?""",
                    (reason, now, external["id"]),
                )
                self._append_event(
                    connection,
                    "worker.external_process_reconciliation_blocked",
                    campaign_id=job["campaign_id"],
                    work_item_id=job["work_item_id"],
                    job_id=job["id"],
                    actor=owner,
                    event_data=event_data,
                    created_at=now,
                )
                return {
                    "job_id": str(job["id"]),
                    "attempt_id": attempt_id,
                    "status": status,
                    "recovered": False,
                }

            changed = connection.execute(
                """UPDATE external_processes
                   SET state = 'stopped', stopped_at = ?, outcome = ?,
                       last_error = NULL, reconciliation_owner = NULL,
                       reconciliation_token = NULL,
                       reconciliation_expires_at = NULL, updated_at = ?
                   WHERE id = ? AND state IN ('active', 'legacy_unverifiable',
                                               'quarantined')""",
                (now, status, now, external["id"]),
            ).rowcount
            if changed != 1:
                raise LeaseConflict("external process lifecycle changed before completion")
            self._append_event(
                connection,
                "worker.external_process_reconciled",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job["id"],
                actor=owner,
                event_data=event_data,
                created_at=now,
            )
            self._expire_job_after_lease(
                connection,
                job,
                now,
                error="lease expired after external process reconciliation",
                event_data={"external_process_status": status},
            )
            return {
                "job_id": str(job["id"]),
                "attempt_id": attempt_id,
                "status": status,
                "recovered": True,
            }

    def list_external_processes(
        self, *, state: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM external_processes"
        parameters: Sequence[Any] = ()
        if state is not None:
            sql += " WHERE state = ?"
            parameters = (state,)
        sql += " ORDER BY recorded_at, id"
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        return self._rows(rows)

    def list_attempts(
        self,
        job_id: Optional[str] = None,
        *,
        campaign_id: Optional[str] = None,
        work_item_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        sql = """SELECT a.*, ep.provider AS external_process_provider,
                         ep.state AS external_process_state,
                         ep.identity_version AS external_process_identity_version,
                         ep.owner_uid AS external_process_owner_uid,
                         ep.start_seconds AS external_process_start_seconds,
                         ep.start_microseconds AS external_process_start_microseconds,
                         ep.target_executable AS external_process_target_executable,
                         ep.outcome AS external_process_outcome,
                         ep.last_error AS external_process_last_error,
                         ep.stopped_at AS external_process_stopped_at
                  FROM attempts a JOIN jobs j ON j.id = a.job_id
                  LEFT JOIN external_processes ep ON ep.attempt_id = a.id"""
        clauses: List[str] = []
        parameters: List[Any] = []
        if job_id is not None:
            clauses.append("a.job_id = ?")
            parameters.append(job_id)
        if campaign_id is not None:
            clauses.append("j.campaign_id = ?")
            parameters.append(campaign_id)
        if work_item_id is not None:
            clauses.append("j.work_item_id = ?")
            parameters.append(work_item_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY a.started_at, a.attempt_number"
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        return self._rows(rows)

    def acquire_resource(
        self, resource_key: str, owner_id: str, *, lease_seconds: float = 60.0,
        job_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        if job_id is not None:
            raise ValueError("job-bound resources are acquired only through job claims")
        token = _id()
        with self._transaction() as connection:
            now = self._clock()
            existing = connection.execute(
                "SELECT * FROM resource_leases WHERE resource_key = ?", (resource_key,)
            ).fetchone()
            if existing is not None and existing["job_id"] is not None:
                return None
            if existing is not None and existing["expires_at"] > now:
                return None
            if existing is not None:
                connection.execute(
                    "DELETE FROM resource_leases WHERE resource_key = ?", (resource_key,)
                )
            connection.execute(
                """INSERT INTO resource_leases
                   (resource_key, owner_id, job_id, lease_token, acquired_at,
                    heartbeat_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (resource_key, owner_id, job_id, token, now, now, now + lease_seconds),
            )
            row = connection.execute(
                "SELECT * FROM resource_leases WHERE resource_key = ?", (resource_key,)
            ).fetchone()
            return self._row(row)

    def heartbeat_resource(
        self, resource_key: str, owner_id: str, lease_token: str, *, lease_seconds: float = 60.0
    ) -> bool:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        with self._transaction() as connection:
            now = self._clock()
            existing = connection.execute(
                "SELECT job_id FROM resource_leases WHERE resource_key = ?",
                (resource_key,),
            ).fetchone()
            if existing is not None and existing["job_id"] is not None:
                raise LeaseConflict(
                    "job-bound resources are heartbeated only through their job lease"
                )
            changed = connection.execute(
                """UPDATE resource_leases SET heartbeat_at = ?, expires_at = ?
                   WHERE resource_key = ? AND owner_id = ? AND lease_token = ?
                     AND expires_at > ?""",
                (now, now + lease_seconds, resource_key, owner_id, lease_token, now),
            ).rowcount
        return changed == 1

    def release_resource(self, resource_key: str, owner_id: str, lease_token: str) -> bool:
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT job_id FROM resource_leases WHERE resource_key = ?",
                (resource_key,),
            ).fetchone()
            if existing is not None and existing["job_id"] is not None:
                raise LeaseConflict(
                    "job-bound resources are released only through their job lease"
                )
            changed = connection.execute(
                """DELETE FROM resource_leases
                   WHERE resource_key = ? AND owner_id = ? AND lease_token = ?""",
                (resource_key, owner_id, lease_token),
            ).rowcount
        return changed == 1

    def list_resource_leases(
        self, *, campaign_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        sql = "SELECT r.* FROM resource_leases r"
        parameters: Sequence[Any] = ()
        if campaign_id is not None:
            sql += " JOIN jobs j ON j.id = r.job_id WHERE j.campaign_id = ?"
            parameters = (campaign_id,)
        sql += " ORDER BY r.resource_key"
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        return self._rows(rows)

    def add_event(
        self, event_kind: str, *, campaign_id: Optional[str] = None,
        work_item_id: Optional[str] = None, job_id: Optional[str] = None,
        actor: Optional[str] = None, event_data: Optional[Mapping[str, Any]] = None
    ) -> Dict[str, Any]:
        with self._transaction() as connection:
            event_id = self._append_event(
                connection, event_kind, campaign_id=campaign_id, work_item_id=work_item_id,
                job_id=job_id, actor=actor, event_data=event_data
            )
            row = connection.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
            return self._row(row)  # type: ignore[return-value]

    def list_events(
        self, *, campaign_id: Optional[str] = None, work_item_id: Optional[str] = None,
        job_id: Optional[str] = None, after_sequence: int = 0,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        if limit is not None and (
            not isinstance(limit, int) or isinstance(limit, bool) or limit < 0
        ):
            raise ValueError("event limit must be a non-negative integer")
        clauses: List[str] = []
        parameters: List[Any] = []
        for column, value in (
            ("campaign_id", campaign_id),
            ("work_item_id", work_item_id),
            ("job_id", job_id),
        ):
            if value is not None:
                clauses.append(column + " = ?")
                parameters.append(value)
        if after_sequence:
            clauses.append("sequence > ?")
            parameters.append(after_sequence)
        sql = "SELECT * FROM events" + ((" WHERE " + " AND ".join(clauses)) if clauses else "")
        sql += " ORDER BY sequence"
        if limit is not None:
            sql += " DESC LIMIT ?"
            parameters.append(limit)
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        if limit is not None:
            rows.reverse()
        return self._rows(rows)

    def create_approval(
        self, campaign_id: str, action: str, requested_by: str, *,
        work_item_id: Optional[str] = None, scope: Optional[Mapping[str, Any]] = None
    ) -> Dict[str, Any]:
        approval_id, now = _id(), self._clock()
        with self._transaction() as connection:
            connection.execute(
                """INSERT INTO approvals
                   (id, campaign_id, work_item_id, action, scope_json, status,
                    requested_by, requested_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)""",
                (
                    approval_id,
                    campaign_id,
                    work_item_id,
                    action,
                    _dump(dict(scope or {})),
                    requested_by,
                    now,
                ),
            )
            self._append_event(
                connection,
                "approval.requested",
                campaign_id=campaign_id,
                work_item_id=work_item_id,
                actor=requested_by,
                event_data={"approval_id": approval_id, "action": action},
                created_at=now,
            )
        return self.list_approvals(approval_id=approval_id)[0]

    def resolve_approval(self, approval_id: str, status: str, resolved_by: str) -> Dict[str, Any]:
        status = _value(status).lower()
        if status not in ("approved", "rejected"):
            raise ValueError("approval status must be approved or rejected")
        now = self._clock()
        with self._transaction() as connection:
            approval = connection.execute(
                "SELECT * FROM approvals WHERE id = ?", (approval_id,)
            ).fetchone()
            if approval is None:
                raise NotFoundError("approval %s not found" % approval_id)
            changed = connection.execute(
                """UPDATE approvals SET status = ?, resolved_by = ?, resolved_at = ?
                   WHERE id = ? AND status = 'pending'""",
                (status, resolved_by, now, approval_id),
            ).rowcount
            if changed != 1:
                raise TransitionConflict("approval is absent or already resolved")
            self._append_event(
                connection,
                "approval.resolved",
                campaign_id=approval["campaign_id"],
                work_item_id=approval["work_item_id"],
                actor=resolved_by,
                event_data={
                    "approval_id": approval_id,
                    "status": status,
                    "action": approval["action"],
                },
                created_at=now,
            )
        return self.list_approvals(approval_id=approval_id)[0]

    def list_approvals(
        self,
        *,
        approval_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        clauses, parameters = [], []
        if approval_id is not None:
            clauses.append("id = ?")
            parameters.append(approval_id)
        if campaign_id is not None:
            clauses.append("campaign_id = ?")
            parameters.append(campaign_id)
        sql = "SELECT * FROM approvals" + ((" WHERE " + " AND ".join(clauses)) if clauses else "")
        sql += " ORDER BY requested_at, id"
        with self._lock:
            return self._rows(self._connection.execute(sql, parameters).fetchall())

    def add_artifact(
        self, work_item_id: str, kind: str, uri: str, *, job_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None
    ) -> Dict[str, Any]:
        artifact_id, now = _id(), self._clock()
        with self._transaction() as connection:
            item = connection.execute(
                "SELECT campaign_id FROM work_items WHERE id = ?", (work_item_id,)
            ).fetchone()
            if item is None:
                raise NotFoundError("work item %s not found" % work_item_id)
            connection.execute(
                """INSERT INTO artifacts
                   (id, work_item_id, job_id, kind, uri, metadata_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (artifact_id, work_item_id, job_id, kind, uri, _dump(dict(metadata or {})), now),
            )
            self._append_event(
                connection,
                "artifact.added",
                campaign_id=item["campaign_id"],
                work_item_id=work_item_id,
                job_id=job_id,
                event_data={"artifact_id": artifact_id, "kind": kind, "uri": uri},
                created_at=now,
            )
            row = connection.execute(
                "SELECT * FROM artifacts WHERE id = ?", (artifact_id,)
            ).fetchone()
            return self._row(row)  # type: ignore[return-value]

    def record_attempt_artifact(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        kind: str,
        uri: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Register an existing file against the current fenced attempt."""

        kind = kind.strip().lower()
        location = Path(uri).expanduser()
        if not kind or len(kind) > 128:
            raise ValueError("artifact kind must contain 1 to 128 characters")
        if not location.is_absolute() or not location.is_file():
            raise ValueError("attempt artifact must be an existing absolute file")
        normalized_uri = str(location.resolve())

        with self._transaction() as connection:
            now = self._clock()
            job = self._assert_live_lease(
                connection, job_id, worker_id, lease_token, now
            )
            existing = connection.execute(
                """SELECT * FROM artifacts
                   WHERE job_id = ? AND attempt_id = ? AND kind = ? AND uri = ?""",
                (job_id, job["current_attempt_id"], kind, normalized_uri),
            ).fetchone()
            if existing is not None:
                return self._row(existing)  # type: ignore[return-value]
            artifact_id = _id()
            artifact_metadata = dict(metadata or {})
            artifact_metadata["attempt_id"] = job["current_attempt_id"]
            connection.execute(
                """INSERT INTO artifacts
                   (id, work_item_id, job_id, attempt_id, kind, uri,
                    metadata_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    artifact_id,
                    job["work_item_id"],
                    job_id,
                    job["current_attempt_id"],
                    kind,
                    normalized_uri,
                    _dump(artifact_metadata),
                    now,
                ),
            )
            self._append_event(
                connection,
                "artifact.added",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job_id,
                actor=worker_id,
                event_data={
                    "artifact_id": artifact_id,
                    "attempt_id": job["current_attempt_id"],
                    "kind": kind,
                    "uri": normalized_uri,
                },
                created_at=now,
            )
            row = connection.execute(
                "SELECT * FROM artifacts WHERE id = ?", (artifact_id,)
            ).fetchone()
            return self._row(row)  # type: ignore[return-value]

    def list_artifacts(self, work_item_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT * FROM artifacts
                   WHERE work_item_id = ? ORDER BY created_at, id""",
                (work_item_id,),
            ).fetchall()
        return self._rows(rows)

    def foreign_key_violations(self) -> List[Dict[str, Any]]:
        """Return SQLite foreign-key violations for explicit integrity proof."""

        with self._lock:
            rows = self._connection.execute("PRAGMA foreign_key_check").fetchall()
        return [dict(row) for row in rows]


Store = SQLiteStore


_SCHEMA_V1 = [
    """CREATE TABLE campaigns (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL,
        config_json TEXT NOT NULL, global_limit INTEGER NOT NULL CHECK (global_limit > 0),
        role_limits_json TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL)""",
    """CREATE TABLE work_items (
        id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
        title TEXT NOT NULL, description TEXT NOT NULL, state TEXT NOT NULL,
        priority INTEGER NOT NULL, required_gates_json TEXT NOT NULL,
        metadata_json TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL)""",
    """CREATE TABLE jobs (
        id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
        work_item_id TEXT NOT NULL REFERENCES work_items(id) ON DELETE CASCADE,
        role TEXT NOT NULL, stage TEXT NOT NULL, status TEXT NOT NULL,
        priority INTEGER NOT NULL, payload_json TEXT NOT NULL, result_json TEXT,
        required_resources_json TEXT NOT NULL, queued_item_state TEXT NOT NULL,
        active_item_state TEXT NOT NULL, required_approval_action TEXT,
        available_at REAL NOT NULL,
        lease_owner TEXT, lease_token TEXT, lease_expires_at REAL, heartbeat_at REAL,
        current_attempt_id TEXT, attempt_count INTEGER NOT NULL DEFAULT 0,
        last_error TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL)""",
    """CREATE UNIQUE INDEX one_open_job_per_stage
        ON jobs(work_item_id, role, stage) WHERE status IN ('pending', 'running')""",
    "CREATE INDEX jobs_claim_order ON jobs(role, status, available_at, priority DESC, created_at)",
    """CREATE TABLE attempts (
        id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        attempt_number INTEGER NOT NULL, worker_id TEXT NOT NULL, lease_token TEXT NOT NULL,
        status TEXT NOT NULL, result_json TEXT, error TEXT, started_at REAL NOT NULL,
        heartbeat_at REAL NOT NULL, lease_expires_at REAL NOT NULL, finished_at REAL,
        UNIQUE(job_id, attempt_number))""",
    """CREATE TABLE events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
        campaign_id TEXT REFERENCES campaigns(id) ON DELETE CASCADE,
        work_item_id TEXT REFERENCES work_items(id) ON DELETE CASCADE,
        job_id TEXT REFERENCES jobs(id) ON DELETE CASCADE, event_kind TEXT NOT NULL,
        actor TEXT, event_data_json TEXT NOT NULL, created_at REAL NOT NULL)""",
    "CREATE INDEX events_item_order ON events(work_item_id, sequence)",
    """CREATE TABLE approvals (
        id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
        work_item_id TEXT REFERENCES work_items(id) ON DELETE CASCADE,
        action TEXT NOT NULL, scope_json TEXT NOT NULL, status TEXT NOT NULL,
        requested_by TEXT NOT NULL, requested_at REAL NOT NULL,
        resolved_by TEXT, resolved_at REAL)""",
    """CREATE TABLE artifacts (
        id TEXT PRIMARY KEY, work_item_id TEXT NOT NULL REFERENCES work_items(id) ON DELETE CASCADE,
        job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL, kind TEXT NOT NULL, uri TEXT NOT NULL,
        metadata_json TEXT NOT NULL, created_at REAL NOT NULL)""",
    """CREATE TABLE resource_leases (
        resource_key TEXT PRIMARY KEY, owner_id TEXT NOT NULL,
        job_id TEXT REFERENCES jobs(id) ON DELETE CASCADE, lease_token TEXT NOT NULL,
        acquired_at REAL NOT NULL, heartbeat_at REAL NOT NULL, expires_at REAL NOT NULL)""",
    "CREATE INDEX resource_lease_expiry ON resource_leases(expires_at)",
]


_SCHEMA_V2 = [
    "ALTER TABLE attempts ADD COLUMN external_provider TEXT",
    "ALTER TABLE attempts ADD COLUMN external_session_id TEXT",
    """CREATE INDEX attempts_external_session
       ON attempts(external_provider, external_session_id)""",
]


_SCHEMA_V3 = [
    "ALTER TABLE attempts ADD COLUMN external_process_id INTEGER",
    "ALTER TABLE attempts ADD COLUMN external_process_group_id INTEGER",
    "ALTER TABLE attempts ADD COLUMN external_process_executable TEXT",
    "ALTER TABLE attempts ADD COLUMN external_process_started_at REAL",
]


_SCHEMA_V4 = [
    """CREATE TABLE external_processes (
        id TEXT PRIMARY KEY,
        attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(id) ON DELETE CASCADE,
        job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        process_id INTEGER NOT NULL CHECK(process_id > 1),
        process_group_id INTEGER NOT NULL CHECK(process_group_id > 1),
        owner_uid INTEGER,
        start_seconds INTEGER,
        start_microseconds INTEGER,
        kernel_executable TEXT,
        target_executable TEXT,
        identity_version TEXT NOT NULL,
        state TEXT NOT NULL,
        recorded_at REAL NOT NULL,
        stopped_at REAL,
        outcome TEXT,
        reconciliation_owner TEXT,
        reconciliation_token TEXT,
        reconciliation_expires_at REAL,
        last_error TEXT,
        updated_at REAL NOT NULL,
        CHECK(identity_version IN ('darwin_libproc_v1', 'legacy_v3')),
        CHECK(state IN ('active', 'legacy_unverifiable', 'quarantined', 'stopped')),
        CHECK(start_microseconds IS NULL
              OR (start_microseconds >= 0 AND start_microseconds < 1000000)),
        CHECK(identity_version != 'darwin_libproc_v1'
              OR (owner_uid IS NOT NULL AND owner_uid >= 0
                  AND start_seconds IS NOT NULL AND start_seconds > 0
                  AND start_microseconds IS NOT NULL
                  AND kernel_executable IS NOT NULL
                  AND target_executable IS NOT NULL)),
        CHECK((state = 'stopped' AND stopped_at IS NOT NULL)
              OR (state != 'stopped' AND stopped_at IS NULL)),
        CHECK((reconciliation_owner IS NULL AND reconciliation_token IS NULL
               AND reconciliation_expires_at IS NULL)
              OR (reconciliation_owner IS NOT NULL AND reconciliation_token IS NOT NULL
                  AND reconciliation_expires_at IS NOT NULL)))""",
    """CREATE UNIQUE INDEX one_live_external_process_identity
       ON external_processes(process_id, start_seconds, start_microseconds)
       WHERE state != 'stopped'""",
    """CREATE INDEX external_process_reconciliation_queue
       ON external_processes(state, reconciliation_expires_at, recorded_at)""",
    """INSERT INTO external_processes
       (id, attempt_id, job_id, provider, process_id, process_group_id,
        owner_uid, start_seconds, start_microseconds, kernel_executable,
        target_executable, identity_version, state, recorded_at, last_error,
        updated_at)
       SELECT lower(hex(randomblob(16))), a.id, a.job_id,
              COALESCE(a.external_provider, 'unknown'),
              a.external_process_id, a.external_process_group_id,
              NULL, NULL, NULL, a.external_process_executable,
              a.external_process_executable, 'legacy_v3',
              'legacy_unverifiable', a.external_process_started_at,
              'V3 process binding has no kernel birth identity or owner UID',
              a.external_process_started_at
       FROM attempts a
       WHERE a.external_process_id IS NOT NULL""",
]


_SCHEMA_V5 = [
    """CREATE TABLE managed_worktrees (
        id TEXT PRIMARY KEY,
        generation INTEGER NOT NULL CHECK(generation > 0),
        campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
        work_item_id TEXT NOT NULL UNIQUE REFERENCES work_items(id) ON DELETE CASCADE,
        fixer_job_id TEXT NOT NULL REFERENCES jobs(id),
        repository_path TEXT NOT NULL,
        source_git_common_dir TEXT NOT NULL,
        source_git_dir TEXT NOT NULL,
        source_device INTEGER NOT NULL CHECK(source_device >= 0),
        source_inode INTEGER NOT NULL CHECK(source_inode >= 0),
        source_owner_uid INTEGER NOT NULL CHECK(source_owner_uid >= 0),
        object_format TEXT NOT NULL,
        worktree_path TEXT NOT NULL UNIQUE,
        worktree_git_dir TEXT,
        worktree_device INTEGER CHECK(worktree_device IS NULL OR worktree_device >= 0),
        worktree_inode INTEGER CHECK(worktree_inode IS NULL OR worktree_inode >= 0),
        worktree_owner_uid INTEGER CHECK(worktree_owner_uid IS NULL OR worktree_owner_uid >= 0),
        branch_ref TEXT NOT NULL,
        base_revision TEXT NOT NULL,
        base_tree TEXT NOT NULL,
        head_revision TEXT,
        lock_reason TEXT NOT NULL,
        source_snapshot_json TEXT NOT NULL,
        state TEXT NOT NULL,
        last_error TEXT,
        created_at REAL NOT NULL,
        ready_at REAL,
        cleanup_started_at REAL,
        removed_at REAL,
        updated_at REAL NOT NULL,
        CHECK(state IN ('provisioning', 'ready', 'cleanup_pending',
                        'quarantined', 'removed')),
        CHECK((state = 'removed' AND removed_at IS NOT NULL)
              OR (state != 'removed' AND removed_at IS NULL)),
        UNIQUE(source_git_common_dir, branch_ref))""",
    """CREATE TABLE worktree_operations (
        id TEXT PRIMARY KEY,
        managed_worktree_id TEXT NOT NULL
            REFERENCES managed_worktrees(id) ON DELETE CASCADE,
        operation_number INTEGER NOT NULL CHECK(operation_number > 0),
        kind TEXT NOT NULL CHECK(kind IN ('create', 'remove')),
        status TEXT NOT NULL CHECK(status IN ('running', 'succeeded', 'quarantined')),
        owner TEXT NOT NULL,
        fencing_token TEXT NOT NULL,
        lease_expires_at REAL NOT NULL,
        expected_identity_json TEXT NOT NULL,
        observed_identity_json TEXT,
        process_id INTEGER,
        process_group_id INTEGER,
        process_owner_uid INTEGER,
        process_start_seconds INTEGER,
        process_start_microseconds INTEGER,
        process_kernel_executable TEXT,
        process_target_executable TEXT,
        process_identity_version TEXT,
        process_state TEXT,
        process_stopped_at REAL,
        stdout_path TEXT,
        stdout_sha256 TEXT,
        stderr_path TEXT,
        stderr_sha256 TEXT,
        reconciliation_owner TEXT,
        reconciliation_token TEXT,
        reconciliation_expires_at REAL,
        error TEXT,
        started_at REAL NOT NULL,
        finished_at REAL,
        updated_at REAL NOT NULL,
        UNIQUE(managed_worktree_id, operation_number),
        CHECK((process_id IS NULL AND process_group_id IS NULL
               AND process_owner_uid IS NULL AND process_start_seconds IS NULL
               AND process_start_microseconds IS NULL
               AND process_kernel_executable IS NULL
               AND process_target_executable IS NULL
               AND process_identity_version IS NULL AND process_state IS NULL)
              OR (process_id > 1 AND process_group_id = process_id
                  AND process_owner_uid >= 0 AND process_start_seconds > 0
                  AND process_start_microseconds >= 0
                  AND process_start_microseconds < 1000000
                  AND process_kernel_executable IS NOT NULL
                  AND process_target_executable IS NOT NULL
                  AND process_identity_version = 'darwin_libproc_v1'
                  AND process_state IN ('active', 'stopped'))),
        CHECK((process_state = 'stopped' AND process_stopped_at IS NOT NULL)
              OR (process_state IS NULL)
              OR (process_state = 'active' AND process_stopped_at IS NULL)),
        CHECK((reconciliation_owner IS NULL AND reconciliation_token IS NULL
               AND reconciliation_expires_at IS NULL)
              OR (reconciliation_owner IS NOT NULL AND reconciliation_token IS NOT NULL
                  AND reconciliation_expires_at IS NOT NULL)))""",
    """CREATE UNIQUE INDEX one_running_worktree_operation
       ON worktree_operations(managed_worktree_id) WHERE status = 'running'""",
    """CREATE INDEX worktree_operation_reconciliation_queue
       ON worktree_operations(status, lease_expires_at,
                              reconciliation_expires_at, started_at)""",
    """ALTER TABLE jobs ADD COLUMN workspace_kind TEXT NOT NULL
       DEFAULT 'source_read_only'
       CHECK(workspace_kind IN ('source_read_only', 'managed_worktree', 'simulated'))""",
    """ALTER TABLE jobs ADD COLUMN managed_worktree_id TEXT
       REFERENCES managed_worktrees(id)""",
    """CREATE INDEX jobs_managed_worktree
       ON jobs(managed_worktree_id, status)""",
    """ALTER TABLE attempts ADD COLUMN managed_worktree_id TEXT
       REFERENCES managed_worktrees(id)""",
    """ALTER TABLE attempts ADD COLUMN managed_worktree_generation INTEGER""",
]


_SCHEMA_V6 = [
    """ALTER TABLE artifacts ADD COLUMN attempt_id TEXT
       REFERENCES attempts(id) ON DELETE CASCADE""",
    """CREATE INDEX artifacts_attempt
       ON artifacts(attempt_id, kind, created_at)""",
    """CREATE TABLE focused_test_plans (
        id TEXT PRIMARY KEY,
        work_item_id TEXT NOT NULL
            REFERENCES work_items(id) ON DELETE CASCADE,
        plan_number INTEGER NOT NULL CHECK(plan_number > 0),
        executable_path TEXT NOT NULL,
        executable_device INTEGER NOT NULL CHECK(executable_device >= 0),
        executable_inode INTEGER NOT NULL CHECK(executable_inode >= 0),
        executable_owner_uid INTEGER NOT NULL CHECK(executable_owner_uid >= 0),
        executable_mode INTEGER NOT NULL CHECK(executable_mode > 0),
        executable_sha256 TEXT NOT NULL,
        test_file TEXT NOT NULL,
        selector TEXT NOT NULL,
        environment_json TEXT NOT NULL,
        environment_sha256 TEXT NOT NULL,
        workspace_manifest_json TEXT NOT NULL,
        workspace_manifest_sha256 TEXT NOT NULL,
        runtime_root TEXT NOT NULL,
        timeout_seconds REAL NOT NULL CHECK(timeout_seconds > 0),
        output_limit_bytes INTEGER NOT NULL CHECK(output_limit_bytes > 0),
        created_at REAL NOT NULL,
        UNIQUE(work_item_id, plan_number))""",
    """CREATE TABLE focused_test_executions (
        id TEXT PRIMARY KEY,
        plan_id TEXT NOT NULL REFERENCES focused_test_plans(id) ON DELETE CASCADE,
        attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(id) ON DELETE CASCADE,
        job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        work_item_id TEXT NOT NULL REFERENCES work_items(id) ON DELETE CASCADE,
        managed_worktree_id TEXT NOT NULL
            REFERENCES managed_worktrees(id) ON DELETE CASCADE,
        managed_worktree_generation INTEGER NOT NULL
            CHECK(managed_worktree_generation > 0),
        status TEXT NOT NULL,
        outcome TEXT,
        executable_path TEXT NOT NULL,
        executable_device INTEGER NOT NULL CHECK(executable_device >= 0),
        executable_inode INTEGER NOT NULL CHECK(executable_inode >= 0),
        executable_owner_uid INTEGER NOT NULL CHECK(executable_owner_uid >= 0),
        executable_mode INTEGER NOT NULL CHECK(executable_mode > 0),
        executable_sha256 TEXT NOT NULL,
        test_file TEXT NOT NULL,
        selector TEXT NOT NULL,
        command_argv_json TEXT NOT NULL,
        command_argv_sha256 TEXT NOT NULL,
        environment_json TEXT NOT NULL,
        environment_sha256 TEXT NOT NULL,
        cwd TEXT NOT NULL,
        cwd_device INTEGER NOT NULL CHECK(cwd_device >= 0),
        cwd_inode INTEGER NOT NULL CHECK(cwd_inode >= 0),
        cwd_owner_uid INTEGER NOT NULL CHECK(cwd_owner_uid >= 0),
        cwd_mode INTEGER NOT NULL CHECK(cwd_mode > 0),
        workspace_manifest_before_json TEXT NOT NULL,
        workspace_manifest_before_sha256 TEXT NOT NULL,
        workspace_manifest_after_json TEXT,
        workspace_manifest_after_sha256 TEXT,
        run_parent TEXT NOT NULL,
        artifact_directory TEXT NOT NULL UNIQUE,
        stdout_path TEXT NOT NULL UNIQUE,
        stderr_path TEXT NOT NULL UNIQUE,
        timeout_seconds REAL NOT NULL CHECK(timeout_seconds > 0),
        output_limit_bytes INTEGER NOT NULL CHECK(output_limit_bytes > 0),
        stdout_device INTEGER CHECK(stdout_device IS NULL OR stdout_device >= 0),
        stdout_inode INTEGER CHECK(stdout_inode IS NULL OR stdout_inode >= 0),
        stdout_owner_uid INTEGER CHECK(stdout_owner_uid IS NULL OR stdout_owner_uid >= 0),
        stdout_mode INTEGER CHECK(stdout_mode IS NULL OR stdout_mode > 0),
        stdout_nlink INTEGER CHECK(stdout_nlink IS NULL OR stdout_nlink > 0),
        stdout_bytes INTEGER CHECK(stdout_bytes IS NULL OR stdout_bytes >= 0),
        stdout_sha256 TEXT,
        stdout_truncated INTEGER NOT NULL DEFAULT 0
            CHECK(stdout_truncated IN (0, 1)),
        stderr_device INTEGER CHECK(stderr_device IS NULL OR stderr_device >= 0),
        stderr_inode INTEGER CHECK(stderr_inode IS NULL OR stderr_inode >= 0),
        stderr_owner_uid INTEGER CHECK(stderr_owner_uid IS NULL OR stderr_owner_uid >= 0),
        stderr_mode INTEGER CHECK(stderr_mode IS NULL OR stderr_mode > 0),
        stderr_nlink INTEGER CHECK(stderr_nlink IS NULL OR stderr_nlink > 0),
        stderr_bytes INTEGER CHECK(stderr_bytes IS NULL OR stderr_bytes >= 0),
        stderr_sha256 TEXT,
        stderr_truncated INTEGER NOT NULL DEFAULT 0
            CHECK(stderr_truncated IN (0, 1)),
        stdout_artifact_id TEXT REFERENCES artifacts(id),
        stderr_artifact_id TEXT REFERENCES artifacts(id),
        exit_code INTEGER,
        semantic_summary TEXT,
        canonical_handoff_json TEXT,
        error TEXT,
        prepared_at REAL NOT NULL,
        finished_at REAL,
        updated_at REAL NOT NULL,
        CHECK(status IN ('prepared', 'finished', 'abandoned', 'quarantined')),
        CHECK(outcome IS NULL OR outcome IN ('pass', 'fail')),
        CHECK((status = 'finished' AND outcome IS NOT NULL AND finished_at IS NOT NULL
               AND exit_code IS NOT NULL AND semantic_summary IS NOT NULL
               AND workspace_manifest_after_json IS NOT NULL
               AND workspace_manifest_after_sha256 IS NOT NULL
               AND stdout_artifact_id IS NOT NULL AND stderr_artifact_id IS NOT NULL)
              OR status != 'finished'),
        CHECK(stdout_path != stderr_path))""",
    """CREATE INDEX focused_test_execution_item
       ON focused_test_executions(work_item_id, prepared_at)""",
    """CREATE INDEX focused_test_execution_job
       ON focused_test_executions(job_id, prepared_at)""",
]


_SCHEMA_V7 = [
    """CREATE INDEX events_campaign_sequence
       ON events(campaign_id, sequence)""",
    """CREATE INDEX work_items_campaign_priority
       ON work_items(campaign_id, priority DESC, created_at, id)""",
    """CREATE INDEX work_items_campaign_state
       ON work_items(campaign_id, state)""",
    """CREATE INDEX jobs_item_updated
       ON jobs(work_item_id, updated_at DESC, created_at DESC, id DESC)""",
    """CREATE INDEX jobs_campaign_role_status_lease
       ON jobs(campaign_id, role, status, lease_expires_at)""",
    """CREATE INDEX resource_leases_job
       ON resource_leases(job_id, resource_key)""",
    """CREATE INDEX managed_worktrees_campaign
       ON managed_worktrees(campaign_id, created_at, id)""",
]
