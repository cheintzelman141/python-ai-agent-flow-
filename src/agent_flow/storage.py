"""Durable SQLite persistence for the Agent Flow supervisor.

The store owns transactional queue mechanics only.  It deliberately accepts and
returns plain strings and dictionaries, while retaining final authority for
lease fences, role transitions, typed handoffs, and evidence gates.
"""

from __future__ import annotations

import json
import hashlib
import math
import os
import re
import shutil
import sqlite3
import stat
import threading
import time
import unicodedata
import uuid
from contextlib import contextmanager
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence
from urllib.parse import unquote, urlsplit

from pydantic import ValidationError

from agent_flow.focused_sandbox import (
    DARWIN_SANDBOX_POLICY_VERSION,
    build_command as build_focused_sandbox_command,
    build_profile as build_focused_sandbox_profile,
    direct_python_executable,
    profile_sha256 as focused_sandbox_profile_sha256,
    python_runtime_root,
    python_runtime_sha256,
    sandbox_executable,
)
from agent_flow.models import (
    EvidenceRef,
    FixHandoff,
    FixOutcome,
    GateKind,
    InvestigationHandoff,
    InvestigationOutcome,
    ItemState,
    ResourceDefinition,
    ResourceDefinitionSpec,
    ResourceKind,
    TestHandoff,
    WorkspaceKind,
    evaluate_test_handoff,
)


SCHEMA_VERSION = 11
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
RESOURCE_DEFINITION_PREFIX = "res_"
RESOURCE_DEFINITION_ID_PATTERN = re.compile(r"^res_[0-9a-f]{32}$")
FOCUSED_TEST_ADMISSION_PREFIX = "fta_"
FOCUSED_TEST_ADMISSION_ID_PATTERN = re.compile(r"^fta_[0-9a-f]{32}$")
_OPAQUE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_COLLECTOR_SECRET_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9])"
    r"(?:api[_-]?key|client[_-]?secret|cookie|password|passwd|secret|token)"
    r"\s*(?:=|:)\s*\S"
)
_COLLECTOR_CREDENTIAL_URI_PATTERN = re.compile(
    r"[A-Za-z][A-Za-z0-9+.-]*://[^/\s]+@"
)
_READ_ONLY_SQL_PATTERN = re.compile(r"SELECT\b", re.IGNORECASE)


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


def _resource_id() -> str:
    return RESOURCE_DEFINITION_PREFIX + uuid.uuid4().hex


def _focused_test_admission_id() -> str:
    return FOCUSED_TEST_ADMISSION_PREFIX + uuid.uuid4().hex


def _operator_text(value: str, name: str, limit: int) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value) > limit
        or any(unicodedata.category(character) in ("Cc", "Cf") for character in value)
        or _COLLECTOR_SECRET_PATTERN.search(value) is not None
        or _COLLECTOR_CREDENTIAL_URI_PATTERN.search(value) is not None
    ):
        raise ValueError("operator %s is invalid or sensitive" % name)
    return value


def _dump(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _resource_identity_hash(kind: str, configuration: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        _dump(
            {
                "kind": kind,
                "configuration": configuration,
            }
        ).encode("utf-8")
    ).hexdigest()


def _resource_definition_hash(
    resource_id: str, definition: Mapping[str, Any]
) -> str:
    return hashlib.sha256(
        _dump(
            {
                "id": resource_id,
                "kind": definition["kind"],
                "label": definition["label"],
                "configuration": definition["configuration"],
                "campaign_id": definition["campaign_id"],
                "metadata": definition["metadata"],
                "policy": definition["policy"],
            }
        ).encode("utf-8")
    ).hexdigest()


def _reject_registered_resource_alias(resource_key: str) -> str:
    if not isinstance(resource_key, str):
        raise ValueError("resource key must be a string")
    if resource_key.strip().startswith(RESOURCE_DEFINITION_PREFIX):
        raise ValueError(
            "registered resources are managed only through fenced job claims"
        )
    return resource_key


def _sha256_json(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_dump(value).encode("utf-8")).hexdigest()


def _reject_unsafe_collector_text(
    value: Any, label: str, *, allow_newlines: bool = False
) -> str:
    if not isinstance(value, str) or not value or len(value) > 16_384:
        raise ValueError("%s must be a bounded non-empty string" % label)
    if value != value.strip():
        raise ValueError("%s must not contain surrounding whitespace" % label)
    if any(
        unicodedata.category(character) in {"Cc", "Cf"}
        and not (allow_newlines and character == "\n")
        for character in value
    ):
        raise ValueError("%s contains prohibited control characters" % label)
    if _COLLECTOR_SECRET_PATTERN.search(value):
        raise ValueError("%s contains an obvious credential assignment" % label)
    if _COLLECTOR_CREDENTIAL_URI_PATTERN.search(value):
        raise ValueError("%s contains a credential-bearing URI" % label)
    return value


def _private_collector_root(value: Any, label: str) -> Path:
    try:
        supplied_text = os.fspath(value)
    except TypeError as error:
        raise ValueError("%s must be an absolute path" % label) from error
    text = _reject_unsafe_collector_text(supplied_text, label)
    supplied = Path(text).expanduser()
    if not supplied.is_absolute():
        raise ValueError("%s must be an absolute path" % label)
    resolved = supplied.resolve()
    if str(supplied) != str(resolved):
        raise ValueError("%s must be a canonical path" % label)
    if not str(resolved).startswith("/private/tmp/agent-flow-"):
        raise ValueError("%s must be under /private/tmp/agent-flow-*" % label)
    try:
        details = resolved.lstat()
    except OSError as error:
        raise ValueError("%s must be an existing private directory" % label) from error
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.getuid()
        or details.st_mode & 0o077
    ):
        raise ValueError("%s must be a private user-owned directory" % label)
    return resolved


def _exact_disposable_file_route(value: Any) -> str:
    route = _reject_unsafe_collector_text(value, "browser route")
    parsed = urlsplit(route)
    if (
        parsed.scheme != "file"
        or parsed.netloc not in ("", "localhost")
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(
            "browser collector currently supports exact disposable file routes only"
        )
    route_path = Path(unquote(parsed.path)).resolve()
    if not str(route_path).startswith("/private/tmp/agent-flow-"):
        raise ValueError("browser route must be under /private/tmp/agent-flow-*")
    return route


def _read_only_statement(value: Any) -> str:
    statement = _reject_unsafe_collector_text(
        value, "database statement", allow_newlines=False
    )
    if (
        not _READ_ONLY_SQL_PATTERN.match(statement)
        or ";" in statement
        or "--" in statement
        or "/*" in statement
        or "*/" in statement
        or "#" in statement
    ):
        raise ValueError(
            "database statement must be one comment-free SELECT without a terminator"
        )
    return statement


def _bounded_query_parameters(value: Sequence[Any]) -> List[Any]:
    if isinstance(value, (str, bytes)) or len(value) > 64:
        raise ValueError("database parameters must be a bounded sequence")
    parameters: List[Any] = []
    for parameter in value:
        if parameter is not None and not isinstance(
            parameter, (str, int, float, bool)
        ):
            raise ValueError("database parameters must contain only scalar values")
        if isinstance(parameter, float) and not math.isfinite(parameter):
            raise ValueError("database parameters must contain finite numbers")
        if isinstance(parameter, str):
            _reject_unsafe_collector_text(parameter, "database parameter")
            if len(parameter) > 1_024:
                raise ValueError("database parameters must be bounded")
        parameters.append(parameter)
    return parameters


def _bounded_expected_ids(value: Sequence[Any]) -> List[Any]:
    if isinstance(value, (str, bytes)) or len(value) > 256:
        raise ValueError("expected database IDs must be a bounded sequence")
    expected: List[Any] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (str, int)):
            raise ValueError("expected database IDs must be strings or integers")
        if isinstance(item, str):
            _reject_unsafe_collector_text(item, "expected database ID")
        expected.append(item)
    if len({_dump(item) for item in expected}) != len(expected):
        raise ValueError("expected database IDs must be unique")
    return expected


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
        "configuration_json": "configuration",
        "policy_json": "policy",
        "role_limits_json": "role_limits",
        "metadata_json": "metadata",
        "required_gates_json": "required_gates",
        "payload_json": "payload",
        "result_json": "result",
        "required_resources_json": "required_resources",
        "expected_resources_json": "expected_resources",
        "event_data_json": "event_data",
        "scope_json": "scope",
        "source_snapshot_json": "source_snapshot",
        "expected_identity_json": "expected_identity",
        "observed_identity_json": "observed_identity",
        "command_argv_json": "command_argv",
        "test_command_argv_json": "test_command_argv",
        "environment_json": "environment",
        "workspace_manifest_json": "workspace_manifest",
        "workspace_manifest_before_json": "workspace_manifest_before",
        "workspace_manifest_after_json": "workspace_manifest_after",
        "canonical_handoff_json": "canonical_handoff",
        "assertions_json": "assertions",
        "parameters_json": "parameters",
        "expected_ids_json": "expected_ids",
        "observed_ids_json": "observed_ids",
        "read_only_proof_json": "read_only_proof",
        "repository_identity_json": "repository_identity",
        "worktree_identity_json": "worktree_identity",
        "resource_definition_ids_json": "resource_definition_ids",
        "resource_bindings_json": "resource_bindings",
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
                version = 7
            if version == 7:
                for statement in _SCHEMA_V8:
                    connection.execute(statement)
                connection.execute("PRAGMA user_version = 8")
                version = 8
            if version == 8:
                for statement in _SCHEMA_V9:
                    connection.execute(statement)
                self._migrate_resource_definition_integrity(connection)
                connection.execute("PRAGMA user_version = 9")
                version = 9
            if version == 9:
                for statement in _SCHEMA_V10:
                    connection.execute(statement)
                connection.execute("PRAGMA user_version = 10")
                version = 10
            if version == 10:
                for statement in _SCHEMA_V11:
                    connection.execute(statement)
                connection.execute("PRAGMA user_version = 11")

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

    def _migrate_resource_definition_integrity(
        self, connection: sqlite3.Connection
    ) -> None:
        rows = connection.execute(
            "SELECT * FROM resource_definitions ORDER BY id"
        ).fetchall()
        for row in rows:
            record = self._row(row)
            try:
                spec = ResourceDefinitionSpec.model_validate(
                    {
                        field: record[field]
                        for field in (
                            "kind",
                            "label",
                            "enabled",
                            "configuration",
                            "campaign_id",
                            "metadata",
                            "policy",
                        )
                    }
                )
            except ValidationError as error:
                raise StorageError(
                    "cannot migrate malformed resource definition %s: %s"
                    % (row["id"], self._safe_validation_summary(error))
                ) from error
            canonical = spec.model_dump(mode="json")
            for field in (
                "kind",
                "label",
                "enabled",
                "configuration",
                "campaign_id",
                "metadata",
                "policy",
            ):
                if record[field] != canonical[field]:
                    raise StorageError(
                        "cannot migrate non-canonical resource definition %s"
                        % row["id"]
                    )
            identity_hash = _resource_identity_hash(
                canonical["kind"], canonical["configuration"]
            )
            if identity_hash != record["identity_hash"]:
                raise StorageError(
                    "cannot migrate resource definition %s with identity drift"
                    % row["id"]
                )
            definition_hash = _resource_definition_hash(
                str(row["id"]), canonical
            )
            connection.execute(
                "UPDATE resource_definitions SET definition_hash = ? WHERE id = ?",
                (definition_hash, row["id"]),
            )
        connection.execute(
            """UPDATE resource_leases
               SET resource_identity_hash = (
                   SELECT identity_hash FROM resource_definitions definition
                   WHERE definition.id = resource_leases.resource_definition_id)
               WHERE resource_definition_id IS NOT NULL"""
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
        if "enabled" in data:
            data["enabled"] = bool(data["enabled"])
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

    @staticmethod
    def _exact_focused_test_admission_id(admission_id: str) -> str:
        if (
            not isinstance(admission_id, str)
            or FOCUSED_TEST_ADMISSION_ID_PATTERN.fullmatch(admission_id) is None
        ):
            raise ValueError(
                "focused-test admission mutations require an exact fta_<32 hex> ID"
            )
        return admission_id

    @staticmethod
    def _exact_record_id(value: str, label: str) -> str:
        if (
            not isinstance(value, str)
            or value != value.strip()
            or not value
            or len(value) > 128
            or any(
                unicodedata.category(character) in ("Cc", "Cf")
                for character in value
            )
        ):
            raise ValueError("%s must be one exact persisted ID" % label)
        return value

    @staticmethod
    def _focused_plan_authority(plan: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "id": str(plan["id"]),
            "work_item_id": str(plan["work_item_id"]),
            "plan_number": int(plan["plan_number"]),
            "executable_path": str(plan["executable_path"]),
            "executable_device": int(plan["executable_device"]),
            "executable_inode": int(plan["executable_inode"]),
            "executable_owner_uid": int(plan["executable_owner_uid"]),
            "executable_mode": int(plan["executable_mode"]),
            "executable_sha256": str(plan["executable_sha256"]),
            "sandbox_policy_version": str(plan["sandbox_policy_version"]),
            "sandbox_executable_path": str(plan["sandbox_executable_path"]),
            "sandbox_executable_device": int(plan["sandbox_executable_device"]),
            "sandbox_executable_inode": int(plan["sandbox_executable_inode"]),
            "sandbox_executable_owner_uid": int(
                plan["sandbox_executable_owner_uid"]
            ),
            "sandbox_executable_mode": int(plan["sandbox_executable_mode"]),
            "sandbox_executable_sha256": str(plan["sandbox_executable_sha256"]),
            "python_runtime_root": str(plan["python_runtime_root"]),
            "python_runtime_sha256": str(plan["python_runtime_sha256"]),
            "test_file": str(plan["test_file"]),
            "selector": str(plan["selector"]),
            "environment": _load(str(plan["environment_json"]), {}),
            "environment_sha256": str(plan["environment_sha256"]),
            "workspace_manifest": _load(
                str(plan["workspace_manifest_json"]), {}
            ),
            "workspace_manifest_sha256": str(
                plan["workspace_manifest_sha256"]
            ),
            "runtime_root": str(plan["runtime_root"]),
            "timeout_seconds": float(plan["timeout_seconds"]),
            "output_limit_bytes": int(plan["output_limit_bytes"]),
        }

    @staticmethod
    def _repository_admission_identity(
        worktree: Mapping[str, Any]
    ) -> Dict[str, Any]:
        return {
            "repository_path": str(worktree["repository_path"]),
            "source_git_common_dir": str(worktree["source_git_common_dir"]),
            "source_git_dir": str(worktree["source_git_dir"]),
            "source_device": int(worktree["source_device"]),
            "source_inode": int(worktree["source_inode"]),
            "source_owner_uid": int(worktree["source_owner_uid"]),
            "object_format": str(worktree["object_format"]),
            "base_revision": str(worktree["base_revision"]),
            "base_tree": str(worktree["base_tree"]),
            "source_snapshot": _load(str(worktree["source_snapshot_json"]), {}),
        }

    @staticmethod
    def _worktree_admission_identity(
        worktree: Mapping[str, Any]
    ) -> Dict[str, Any]:
        return {
            "id": str(worktree["id"]),
            "generation": int(worktree["generation"]),
            "work_item_id": str(worktree["work_item_id"]),
            "worktree_path": str(worktree["worktree_path"]),
            "worktree_git_dir": str(worktree["worktree_git_dir"]),
            "worktree_device": int(worktree["worktree_device"]),
            "worktree_inode": int(worktree["worktree_inode"]),
            "worktree_owner_uid": int(worktree["worktree_owner_uid"]),
            "branch_ref": str(worktree["branch_ref"]),
            "base_revision": str(worktree["base_revision"]),
            "base_tree": str(worktree["base_tree"]),
        }

    def _focused_test_admission_resource_bindings(
        self,
        connection: sqlite3.Connection,
        campaign_id: str,
        resource_definition_ids: Sequence[str],
        *,
        require_enabled: bool,
    ) -> List[Dict[str, Any]]:
        if (
            isinstance(resource_definition_ids, (str, bytes))
            or len(resource_definition_ids) > 128
        ):
            raise ValueError(
                "focused-test admission accepts at most 128 exact resource definition IDs"
            )
        exact_ids = [
            self._exact_resource_definition_id(resource_id)
            for resource_id in resource_definition_ids
        ]
        if len(exact_ids) != len(set(exact_ids)):
            raise ValueError(
                "focused-test admission resource definition IDs must be unique"
            )
        bindings: List[Dict[str, Any]] = []
        for resource_id in sorted(exact_ids):
            row = connection.execute(
                "SELECT * FROM resource_definitions WHERE id = ?",
                (resource_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError(
                    "resource definition %s not found" % resource_id
                )
            try:
                definition = self._validated_resource_definition_row(row)
            except StorageError as error:
                raise TransitionConflict(
                    "resource definition %s failed integrity validation"
                    % resource_id
                ) from error
            if require_enabled and not bool(definition["enabled"]):
                raise TransitionConflict(
                    "resource definition %s is disabled" % resource_id
                )
            if definition["campaign_id"] not in (None, campaign_id):
                raise TransitionConflict(
                    "resource definition %s is outside the campaign scope"
                    % resource_id
                )
            bindings.append(
                {
                    "id": resource_id,
                    "kind": str(definition["kind"]),
                    "campaign_id": definition["campaign_id"],
                    "identity_hash": str(definition["identity_hash"]),
                    "definition_hash": str(definition["definition_hash"]),
                    "policy": definition["policy"],
                }
            )
        return bindings

    @staticmethod
    def _focused_test_admission_authority(
        admission: Mapping[str, Any]
    ) -> Dict[str, Any]:
        fields = (
            "id",
            "campaign_id",
            "work_item_id",
            "tester_job_id",
            "managed_worktree_id",
            "managed_worktree_generation",
            "focused_test_plan_id",
            "focused_test_plan_sha256",
            "campaign_config_sha256",
            "job_payload_sha256",
            "required_gates_sha256",
            "repository_identity",
            "repository_identity_sha256",
            "worktree_identity",
            "worktree_identity_sha256",
            "resource_definition_ids",
            "resource_bindings",
            "resource_bindings_sha256",
            "required_resources_sha256",
            "admitted_by",
            "admission_reason",
            "admitted_at",
        )
        return {field: admission[field] for field in fields}

    def _focused_test_admission_record(
        self, row: sqlite3.Row
    ) -> Dict[str, Any]:
        try:
            record = self._row(row)
            if record is None:
                raise ValueError("admission record is absent")
            self._exact_focused_test_admission_id(str(record["id"]))
            resource_ids = record["resource_definition_ids"]
            bindings = record["resource_bindings"]
            if (
                not isinstance(resource_ids, list)
                or not isinstance(bindings, list)
                or any(not isinstance(binding, Mapping) for binding in bindings)
                or resource_ids != sorted(resource_ids)
                or len(resource_ids) != len(set(resource_ids))
                or [binding.get("id") for binding in bindings] != resource_ids
            ):
                raise ValueError("resource bindings are not canonical")
            for field in ("repository_identity", "worktree_identity"):
                if not isinstance(record[field], dict):
                    raise ValueError("admission identity is not an object")
            expected_hashes = {
                "focused_test_plan_sha256": str(
                    record["focused_test_plan_sha256"]
                ),
                "campaign_config_sha256": str(record["campaign_config_sha256"]),
                "job_payload_sha256": str(record["job_payload_sha256"]),
                "required_gates_sha256": str(record["required_gates_sha256"]),
                "repository_identity_sha256": _sha256_json(
                    record["repository_identity"]
                ),
                "worktree_identity_sha256": _sha256_json(
                    record["worktree_identity"]
                ),
                "resource_bindings_sha256": hashlib.sha256(
                    _dump(bindings).encode("utf-8")
                ).hexdigest(),
                "required_resources_sha256": str(
                    record["required_resources_sha256"]
                ),
            }
            for field, expected in expected_hashes.items():
                value = str(record[field])
                if _SHA256_PATTERN.fullmatch(value) is None or value != expected:
                    raise ValueError("%s changed" % field)
            authority_hash = _sha256_json(
                self._focused_test_admission_authority(record)
            )
            if authority_hash != record["authority_sha256"]:
                raise ValueError("authority hash changed")
        except (KeyError, TypeError, ValueError) as error:
            raise StorageError(
                "persisted focused-test admission %s is malformed or changed"
                % row["id"]
            ) from error
        return record

    @staticmethod
    def _exact_resource_definition_id(resource_id: str) -> str:
        if (
            not isinstance(resource_id, str)
            or RESOURCE_DEFINITION_ID_PATTERN.fullmatch(resource_id) is None
        ):
            raise ValueError(
                "resource definition mutations require an exact res_<32 hex> ID"
            )
        return resource_id

    @staticmethod
    def _safe_validation_summary(error: ValidationError) -> str:
        messages: List[str] = []
        for detail in error.errors(include_url=False, include_input=False):
            safe_location_parts = []
            for part in detail.get("loc", ()):
                component = str(part)
                safe_location_parts.append(
                    component
                    if re.fullmatch(r"[A-Za-z0-9_]+", component)
                    else "field"
                )
            location = ".".join(safe_location_parts)
            message = str(detail.get("msg", "validation failed"))
            messages.append(
                "%s: %s" % (location, message) if location else message
            )
        return "; ".join(messages) or "validation failed"

    def _validated_resource_definition_row(
        self, row: sqlite3.Row
    ) -> Dict[str, Any]:
        try:
            record = self._row(row)
            definition = ResourceDefinition.model_validate(record)
        except ValidationError as error:
            raise StorageError(
                "persisted resource definition %s is malformed: %s"
                % (row["id"], self._safe_validation_summary(error))
            ) from error
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise StorageError(
                "persisted resource definition %s is malformed" % row["id"]
            ) from error
        canonical = definition.model_dump(mode="json")
        for field in (
            "id",
            "kind",
            "label",
            "enabled",
            "configuration",
            "campaign_id",
            "metadata",
            "policy",
            "identity_hash",
            "definition_hash",
        ):
            if record[field] != canonical[field]:
                raise StorageError(
                    "persisted resource definition %s is not canonical"
                    % row["id"]
                )
        expected_identity_hash = _resource_identity_hash(
            str(record["kind"]), record["configuration"]
        )
        if expected_identity_hash != record["identity_hash"]:
            raise StorageError(
                "persisted resource definition %s identity hash does not match its configuration"
                % row["id"]
            )
        if _resource_definition_hash(str(row["id"]), record) != record[
            "definition_hash"
        ]:
            raise StorageError(
                "persisted resource definition %s immutable fields changed"
                % row["id"]
            )
        return record  # type: ignore[return-value]

    def define_resource(
        self,
        kind: str,
        label: str,
        configuration: Mapping[str, Any],
        *,
        actor: str,
        policy: Optional[Mapping[str, Any]] = None,
        campaign_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        enabled: bool = True,
        resource_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Persist one typed resource definition without touching its resource."""

        actor = _operator_text(actor, "resource mutation actor", 256)
        if not isinstance(enabled, bool):
            raise ValueError("resource enabled status must be a boolean")
        resource_id = (
            _resource_id()
            if resource_id is None
            else self._exact_resource_definition_id(resource_id)
        )
        try:
            spec = ResourceDefinitionSpec.model_validate(
                {
                    "kind": _value(kind).lower(),
                    "label": label,
                    "enabled": enabled,
                    "configuration": dict(configuration),
                    "campaign_id": campaign_id,
                    "metadata": dict(metadata or {}),
                    "policy": dict(
                        policy or {"mode": "exclusive", "limit": 1}
                    ),
                }
            )
        except ValidationError as error:
            raise ValueError(
                "invalid resource definition: %s"
                % self._safe_validation_summary(error)
            ) from error
        data = spec.model_dump(mode="json")
        identity_hash = _resource_identity_hash(
            data["kind"], data["configuration"]
        )
        definition_hash = _resource_definition_hash(resource_id, data)
        now = self._clock()
        with self._transaction() as connection:
            if campaign_id is not None:
                campaign = connection.execute(
                    "SELECT id FROM campaigns WHERE id = ?", (campaign_id,)
                ).fetchone()
                if campaign is None:
                    raise NotFoundError("campaign %s not found" % campaign_id)
            duplicate = connection.execute(
                """SELECT id FROM resource_definitions
                   WHERE kind = ? AND identity_hash = ?""",
                (data["kind"], identity_hash),
            ).fetchone()
            if duplicate is not None:
                raise TransitionConflict(
                    "resource identity is already registered as %s"
                    % duplicate["id"]
                )
            existing_id = connection.execute(
                "SELECT 1 FROM resource_definitions WHERE id = ?",
                (resource_id,),
            ).fetchone()
            if existing_id is not None:
                raise TransitionConflict(
                    "resource definition ID already exists: %s" % resource_id
                )
            connection.execute(
                """INSERT INTO resource_definitions
                   (id, kind, label, enabled, configuration_json, campaign_id,
                    metadata_json, policy_json, identity_hash, definition_hash,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    resource_id,
                    data["kind"],
                    data["label"],
                    1 if data["enabled"] else 0,
                    _dump(data["configuration"]),
                    data["campaign_id"],
                    _dump(data["metadata"]),
                    _dump(data["policy"]),
                    identity_hash,
                    definition_hash,
                    now,
                    now,
                ),
            )
            self._append_event(
                connection,
                "resource.defined",
                campaign_id=campaign_id,
                actor=actor,
                event_data={
                    "resource_id": resource_id,
                    "kind": data["kind"],
                    "label": data["label"],
                    "enabled": data["enabled"],
                    "policy": data["policy"],
                    "identity_hash": identity_hash,
                },
                created_at=now,
            )
        return self.get_resource_definition(resource_id)

    def get_resource_definition(self, resource_id: str) -> Dict[str, Any]:
        resource_id = self._exact_resource_definition_id(resource_id)
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM resource_definitions WHERE id = ?",
                (resource_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("resource definition %s not found" % resource_id)
        return self._validated_resource_definition_row(row)

    def list_resource_definitions(
        self,
        *,
        campaign_id: Optional[str] = None,
        kind: Optional[str] = None,
        enabled: Optional[bool] = None,
        include_global: bool = True,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        parameters: List[Any] = []
        if campaign_id is not None:
            if include_global:
                clauses.append("(campaign_id IS NULL OR campaign_id = ?)")
            else:
                clauses.append("campaign_id = ?")
            parameters.append(campaign_id)
        if kind is not None:
            try:
                normalized_kind = ResourceKind(_value(kind).lower()).value
            except ValueError as error:
                raise ValueError("unsupported resource kind: %s" % kind) from error
            clauses.append("kind = ?")
            parameters.append(normalized_kind)
        if enabled is not None:
            if not isinstance(enabled, bool):
                raise ValueError("enabled filter must be a boolean")
            clauses.append("enabled = ?")
            parameters.append(1 if enabled else 0)
        sql = "SELECT * FROM resource_definitions"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY kind, label, id"
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        return [self._validated_resource_definition_row(row) for row in rows]

    def set_resource_enabled(
        self,
        resource_id: str,
        enabled: bool,
        *,
        actor: str,
    ) -> Dict[str, Any]:
        resource_id = self._exact_resource_definition_id(resource_id)
        if not isinstance(enabled, bool):
            raise ValueError("resource enabled status must be a boolean")
        actor = _operator_text(actor, "resource mutation actor", 256)
        with self._transaction() as connection:
            now = self._clock()
            row = connection.execute(
                "SELECT * FROM resource_definitions WHERE id = ?",
                (resource_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("resource definition %s not found" % resource_id)
            definition = self._validated_resource_definition_row(row)
            if bool(definition["enabled"]) == enabled:
                return definition
            changed = connection.execute(
                """UPDATE resource_definitions SET enabled = ?, updated_at = ?
                   WHERE id = ? AND enabled = ?""",
                (1 if enabled else 0, now, resource_id, 0 if enabled else 1),
            ).rowcount
            if changed != 1:
                raise TransitionConflict("resource enabled status changed concurrently")
            self._append_event(
                connection,
                "resource.enabled" if enabled else "resource.disabled",
                campaign_id=row["campaign_id"],
                actor=actor,
                event_data={
                    "resource_id": resource_id,
                    "kind": definition["kind"],
                    "label": definition["label"],
                    "enabled": enabled,
                },
                created_at=now,
            )
        return self.get_resource_definition(resource_id)

    @staticmethod
    def _exact_collector_id(value: str, label: str) -> str:
        if not isinstance(value, str) or _OPAQUE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("%s requires an exact 32-character opaque ID" % label)
        return value

    def _collector_plan_binding(
        self,
        connection: sqlite3.Connection,
        work_item_id: str,
        resource_definition_id: str,
        *,
        resource_kind: str,
        required_gate: str,
        require_ready_for_test: bool = True,
    ) -> tuple[sqlite3.Row, Dict[str, Any]]:
        resource_definition_id = self._exact_resource_definition_id(
            resource_definition_id
        )
        item = connection.execute(
            """SELECT i.*, c.config_json AS campaign_config_json
               FROM work_items i JOIN campaigns c ON c.id = i.campaign_id
               WHERE i.id = ?""",
            (work_item_id,),
        ).fetchone()
        if item is None:
            raise NotFoundError("work item %s not found" % work_item_id)
        if required_gate not in _load(item["required_gates_json"], []):
            raise TransitionConflict(
                "%s evidence is not required by this work item" % required_gate
            )
        if require_ready_for_test and item["state"] != ItemState.READY_FOR_TEST.value:
            raise TransitionConflict(
                "collector plans require a ready_for_test work item"
            )
        if _load(item["campaign_config_json"], {}).get(
            "allow_simulated_evidence"
        ) is True:
            raise TransitionConflict(
                "authoritative collector plans cannot use simulated campaigns"
            )
        resource_row = connection.execute(
            "SELECT * FROM resource_definitions WHERE id = ?",
            (resource_definition_id,),
        ).fetchone()
        if resource_row is None:
            raise NotFoundError(
                "resource definition %s not found" % resource_definition_id
            )
        resource = self._validated_resource_definition_row(resource_row)
        if not bool(resource["enabled"]):
            raise TransitionConflict("collector resource definition is disabled")
        if resource["kind"] != resource_kind:
            raise TransitionConflict(
                "%s evidence requires a %s resource"
                % (required_gate, resource_kind)
            )
        if resource["campaign_id"] not in (None, item["campaign_id"]):
            raise TransitionConflict(
                "collector resource definition is outside the work item campaign"
            )
        return item, resource

    def _validated_browser_plan_row(
        self, connection: sqlite3.Connection, row: sqlite3.Row
    ) -> Dict[str, Any]:
        record = self._row(row)
        try:
            exact_route = _exact_disposable_file_route(record["route"])
            title = _reject_unsafe_collector_text(
                record["expected_title"], "expected title"
            )
            body = _reject_unsafe_collector_text(
                record["expected_body_text"],
                "expected body text",
                allow_newlines=True,
            )
            runtime = _private_collector_root(
                record["runtime_root"], "browser runtime root"
            )
            timeout_seconds = float(record["timeout_seconds"])
            if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 120:
                raise ValueError("browser timeout is outside the supported bounds")
            _item, resource = self._collector_plan_binding(
                connection,
                str(record["work_item_id"]),
                str(record["resource_definition_id"]),
                resource_kind=ResourceKind.CHROME_PROFILE.value,
                required_gate=GateKind.BROWSER.value,
                require_ready_for_test=False,
            )
            if resource["identity_hash"] != record["resource_identity_hash"]:
                raise ValueError("browser resource identity changed after planning")
            route_path = Path(unquote(urlsplit(exact_route).path))
            route_details = route_path.lstat()
            persisted_route = (
                int(record["route_device"]),
                int(record["route_inode"]),
                int(record["route_owner_uid"]),
                int(record["route_mode"]),
                int(record["route_nlink"]),
                int(record["route_bytes"]),
            )
            observed_route = (
                int(route_details.st_dev),
                int(route_details.st_ino),
                int(route_details.st_uid),
                int(route_details.st_mode),
                int(route_details.st_nlink),
                int(route_details.st_size),
            )
            if observed_route != persisted_route:
                raise ValueError("browser route file identity changed after planning")
            route_sha256 = self._hash_file(route_path, route_details)
            if (
                _SHA256_PATTERN.fullmatch(str(record["route_sha256"])) is None
                or route_sha256 != record["route_sha256"]
            ):
                raise ValueError("browser route file bytes changed after planning")
            payload = {
                "work_item_id": record["work_item_id"],
                "resource_definition_id": record["resource_definition_id"],
                "resource_identity_hash": record["resource_identity_hash"],
                "route": exact_route,
                "route_identity": {
                    "device": persisted_route[0],
                    "inode": persisted_route[1],
                    "owner_uid": persisted_route[2],
                    "mode": persisted_route[3],
                    "nlink": persisted_route[4],
                    "bytes": persisted_route[5],
                    "sha256": route_sha256,
                },
                "expected_title": title,
                "expected_body_text": body,
                "runtime_root": str(runtime),
                "timeout_seconds": timeout_seconds,
            }
            if (
                _SHA256_PATTERN.fullmatch(str(record["plan_sha256"])) is None
                or _sha256_json(payload) != record["plan_sha256"]
            ):
                raise ValueError("browser plan hash changed after planning")
        except (KeyError, OSError, TypeError, ValueError) as error:
            raise StorageError(
                "persisted browser evidence plan %s is invalid"
                % row["id"]
            ) from error
        return record

    def _validated_database_plan_row(
        self, connection: sqlite3.Connection, row: sqlite3.Row
    ) -> Dict[str, Any]:
        record = self._row(row)
        try:
            sql = _read_only_statement(record["statement"])
            parameters = _bounded_query_parameters(record["parameters"])
            id_column = _reject_unsafe_collector_text(
                record["id_column"], "database ID column"
            )
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", id_column) is None:
                raise ValueError("database ID column is invalid")
            expected_ids = _bounded_expected_ids(record["expected_ids"])
            expected_row_count = record["expected_row_count"]
            max_rows = int(record["max_rows"])
            max_bytes = int(record["max_bytes"])
            timeout_seconds = float(record["timeout_seconds"])
            if not 1 <= max_rows <= 1000 or not 1024 <= max_bytes <= 16 * 1024 * 1024:
                raise ValueError("database plan bounds are invalid")
            if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 60:
                raise ValueError("database timeout is invalid")
            if expected_row_count is not None and not 0 <= int(expected_row_count) <= max_rows:
                raise ValueError("expected row count exceeds the result bound")
            if len(expected_ids) > max_rows:
                raise ValueError("expected IDs exceed the result bound")
            runtime = _private_collector_root(
                record["runtime_root"], "database runtime root"
            )
            _item, resource = self._collector_plan_binding(
                connection,
                str(record["work_item_id"]),
                str(record["resource_definition_id"]),
                resource_kind=ResourceKind.TENANT_DATABASE.value,
                required_gate=GateKind.DATABASE.value,
                require_ready_for_test=False,
            )
            if resource["identity_hash"] != record["resource_identity_hash"]:
                raise ValueError("database resource identity changed after planning")
            query_sha256 = _sha256_json(
                {"statement": sql, "parameters": parameters}
            )
            if (
                _SHA256_PATTERN.fullmatch(str(record["query_sha256"])) is None
                or query_sha256 != record["query_sha256"]
            ):
                raise ValueError("database query hash changed after planning")
            payload = {
                "work_item_id": record["work_item_id"],
                "resource_definition_id": record["resource_definition_id"],
                "resource_identity_hash": record["resource_identity_hash"],
                "query_sha256": query_sha256,
                "id_column": id_column,
                "expected_ids": expected_ids,
                "expected_row_count": expected_row_count,
                "max_rows": max_rows,
                "max_bytes": max_bytes,
                "timeout_seconds": timeout_seconds,
                "runtime_root": str(runtime),
            }
            if (
                _SHA256_PATTERN.fullmatch(str(record["plan_sha256"])) is None
                or _sha256_json(payload) != record["plan_sha256"]
            ):
                raise ValueError("database plan hash changed after planning")
        except (KeyError, OSError, TypeError, ValueError) as error:
            raise StorageError(
                "persisted database query plan %s is invalid" % row["id"]
            ) from error
        return record

    def create_browser_evidence_plan(
        self,
        work_item_id: str,
        resource_definition_id: str,
        *,
        route: str,
        expected_title: str,
        expected_body_text: str,
        runtime_root: Path,
        timeout_seconds: float = 30.0,
    ) -> Dict[str, Any]:
        """Create one immutable, fixed-action visible-browser evidence plan."""

        exact_route = _exact_disposable_file_route(route)
        title = _reject_unsafe_collector_text(expected_title, "expected title")
        body = _reject_unsafe_collector_text(
            expected_body_text, "expected body text", allow_newlines=True
        )
        runtime = _private_collector_root(runtime_root, "browser runtime root")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(float(timeout_seconds))
            or timeout_seconds <= 0
            or timeout_seconds > 120
        ):
            raise ValueError("browser timeout must be between 0 and 120 seconds")
        with self._transaction() as connection:
            now = self._clock()
            item, resource = self._collector_plan_binding(
                connection,
                work_item_id,
                resource_definition_id,
                resource_kind=ResourceKind.CHROME_PROFILE.value,
                required_gate=GateKind.BROWSER.value,
            )
            user_data_dir = Path(
                str(resource["configuration"]["user_data_dir"])
            ).resolve()
            if not str(user_data_dir).startswith("/private/tmp/agent-flow-"):
                raise TransitionConflict(
                    "the fixed browser collector requires a disposable Chrome profile"
                )
            route_path = Path(unquote(urlsplit(exact_route).path))
            try:
                route_details = route_path.lstat()
            except OSError as error:
                raise ValueError(
                    "browser route must identify an existing disposable file"
                ) from error
            if (
                not stat.S_ISREG(route_details.st_mode)
                or route_details.st_uid != os.getuid()
                or route_details.st_mode & 0o077
                or route_details.st_nlink != 1
                or route_details.st_size <= 0
                or route_details.st_size > 1024 * 1024
            ):
                raise ValueError(
                    "browser route must be a bounded private user-owned regular file"
                )
            route_sha256 = self._hash_file(route_path, route_details)
            plan_payload = {
                "work_item_id": work_item_id,
                "resource_definition_id": resource_definition_id,
                "resource_identity_hash": resource["identity_hash"],
                "route": exact_route,
                "route_identity": {
                    "device": int(route_details.st_dev),
                    "inode": int(route_details.st_ino),
                    "owner_uid": int(route_details.st_uid),
                    "mode": int(route_details.st_mode),
                    "nlink": int(route_details.st_nlink),
                    "bytes": int(route_details.st_size),
                    "sha256": route_sha256,
                },
                "expected_title": title,
                "expected_body_text": body,
                "runtime_root": str(runtime),
                "timeout_seconds": float(timeout_seconds),
            }
            plan_sha256 = _sha256_json(plan_payload)
            existing = connection.execute(
                """SELECT * FROM browser_evidence_plans
                   WHERE work_item_id = ? AND plan_sha256 = ?""",
                (work_item_id, plan_sha256),
            ).fetchone()
            if existing is not None:
                return self._validated_browser_plan_row(connection, existing)
            plan_number = int(
                connection.execute(
                    """SELECT COALESCE(MAX(plan_number), 0) + 1
                       FROM browser_evidence_plans WHERE work_item_id = ?""",
                    (work_item_id,),
                ).fetchone()[0]
            )
            plan_id = _id()
            connection.execute(
                """INSERT INTO browser_evidence_plans
                   (id, work_item_id, plan_number, resource_definition_id,
                    resource_identity_hash, route, route_device, route_inode,
                    route_owner_uid, route_mode, route_nlink, route_bytes,
                    route_sha256, expected_title,
                    expected_body_text, runtime_root, timeout_seconds,
                    plan_sha256, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    plan_id,
                    work_item_id,
                    plan_number,
                    resource_definition_id,
                    resource["identity_hash"],
                    exact_route,
                    int(route_details.st_dev),
                    int(route_details.st_ino),
                    int(route_details.st_uid),
                    int(route_details.st_mode),
                    int(route_details.st_nlink),
                    int(route_details.st_size),
                    route_sha256,
                    title,
                    body,
                    str(runtime),
                    float(timeout_seconds),
                    plan_sha256,
                    now,
                ),
            )
            self._append_event(
                connection,
                "browser_evidence.plan_created",
                campaign_id=item["campaign_id"],
                work_item_id=work_item_id,
                event_data={
                    "plan_id": plan_id,
                    "plan_number": plan_number,
                    "resource_id": resource_definition_id,
                    "resource_identity_hash": resource["identity_hash"],
                    "route": exact_route,
                    "plan_sha256": plan_sha256,
                },
                created_at=now,
            )
        return self.get_browser_evidence_plan(plan_id)

    def get_browser_evidence_plan(self, plan_id: str) -> Dict[str, Any]:
        plan_id = self._exact_collector_id(plan_id, "browser plan")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM browser_evidence_plans WHERE id = ?", (plan_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("browser evidence plan %s not found" % plan_id)
        return self._validated_browser_plan_row(self._connection, row)

    def list_browser_evidence_plans(
        self, *, work_item_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM browser_evidence_plans"
        parameters: Sequence[Any] = ()
        if work_item_id is not None:
            sql += " WHERE work_item_id = ?"
            parameters = (work_item_id,)
        sql += " ORDER BY work_item_id, plan_number"
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
            return [
                self._validated_browser_plan_row(self._connection, row)
                for row in rows
            ]

    def create_database_query_plan(
        self,
        work_item_id: str,
        resource_definition_id: str,
        *,
        statement: str,
        parameters: Sequence[Any] = (),
        id_column: str = "id",
        expected_ids: Sequence[Any] = (),
        expected_row_count: Optional[int] = None,
        max_rows: int = 100,
        max_bytes: int = 1_048_576,
        timeout_seconds: float = 5.0,
        runtime_root: Path,
    ) -> Dict[str, Any]:
        """Create one immutable supervisor-owned disposable SQLite query plan."""

        sql = _read_only_statement(statement)
        bound_parameters = _bounded_query_parameters(parameters)
        exact_id_column = _reject_unsafe_collector_text(
            id_column, "database ID column"
        )
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", exact_id_column) is None:
            raise ValueError("database ID column must be a safe exact identifier")
        exact_ids = _bounded_expected_ids(expected_ids)
        if (
            expected_row_count is not None
            and (
                not isinstance(expected_row_count, int)
                or isinstance(expected_row_count, bool)
                or expected_row_count < 0
                or expected_row_count > 1000
            )
        ):
            raise ValueError("expected row count must be from 0 to 1000")
        if (
            not isinstance(max_rows, int)
            or isinstance(max_rows, bool)
            or max_rows < 1
            or max_rows > 1000
        ):
            raise ValueError("database max_rows must be from 1 to 1000")
        if (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or max_bytes < 1024
            or max_bytes > 16 * 1024 * 1024
        ):
            raise ValueError("database max_bytes is outside the supported bounds")
        if expected_row_count is not None and expected_row_count > max_rows:
            raise ValueError("expected row count cannot exceed max_rows")
        if len(exact_ids) > max_rows:
            raise ValueError("expected database IDs cannot exceed max_rows")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(float(timeout_seconds))
            or timeout_seconds <= 0
            or timeout_seconds > 60
        ):
            raise ValueError("database timeout must be between 0 and 60 seconds")
        runtime = _private_collector_root(runtime_root, "database runtime root")
        query_payload = {"statement": sql, "parameters": bound_parameters}
        query_sha256 = _sha256_json(query_payload)
        with self._transaction() as connection:
            now = self._clock()
            item, resource = self._collector_plan_binding(
                connection,
                work_item_id,
                resource_definition_id,
                resource_kind=ResourceKind.TENANT_DATABASE.value,
                required_gate=GateKind.DATABASE.value,
            )
            plan_payload = {
                "work_item_id": work_item_id,
                "resource_definition_id": resource_definition_id,
                "resource_identity_hash": resource["identity_hash"],
                "query_sha256": query_sha256,
                "id_column": exact_id_column,
                "expected_ids": exact_ids,
                "expected_row_count": expected_row_count,
                "max_rows": max_rows,
                "max_bytes": max_bytes,
                "timeout_seconds": float(timeout_seconds),
                "runtime_root": str(runtime),
            }
            plan_sha256 = _sha256_json(plan_payload)
            existing = connection.execute(
                """SELECT * FROM database_query_plans
                   WHERE work_item_id = ? AND plan_sha256 = ?""",
                (work_item_id, plan_sha256),
            ).fetchone()
            if existing is not None:
                return self._validated_database_plan_row(connection, existing)
            plan_number = int(
                connection.execute(
                    """SELECT COALESCE(MAX(plan_number), 0) + 1
                       FROM database_query_plans WHERE work_item_id = ?""",
                    (work_item_id,),
                ).fetchone()[0]
            )
            plan_id = _id()
            connection.execute(
                """INSERT INTO database_query_plans
                   (id, work_item_id, plan_number, resource_definition_id,
                    resource_identity_hash, statement, parameters_json,
                    query_sha256, id_column, expected_ids_json, expected_row_count,
                    max_rows, max_bytes, timeout_seconds, runtime_root,
                    plan_sha256, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    plan_id,
                    work_item_id,
                    plan_number,
                    resource_definition_id,
                    resource["identity_hash"],
                    sql,
                    _dump(bound_parameters),
                    query_sha256,
                    exact_id_column,
                    _dump(exact_ids),
                    expected_row_count,
                    max_rows,
                    max_bytes,
                    float(timeout_seconds),
                    str(runtime),
                    plan_sha256,
                    now,
                ),
            )
            self._append_event(
                connection,
                "database_evidence.plan_created",
                campaign_id=item["campaign_id"],
                work_item_id=work_item_id,
                event_data={
                    "plan_id": plan_id,
                    "plan_number": plan_number,
                    "resource_id": resource_definition_id,
                    "resource_identity_hash": resource["identity_hash"],
                    "query_sha256": query_sha256,
                    "plan_sha256": plan_sha256,
                },
                created_at=now,
            )
        return self.get_database_query_plan(plan_id)

    def get_database_query_plan(self, plan_id: str) -> Dict[str, Any]:
        plan_id = self._exact_collector_id(plan_id, "database plan")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM database_query_plans WHERE id = ?", (plan_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("database query plan %s not found" % plan_id)
        return self._validated_database_plan_row(self._connection, row)

    def list_database_query_plans(
        self, *, work_item_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM database_query_plans"
        parameters: Sequence[Any] = ()
        if work_item_id is not None:
            sql += " WHERE work_item_id = ?"
            parameters = (work_item_id,)
        sql += " ORDER BY work_item_id, plan_number"
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
            return [
                self._validated_database_plan_row(self._connection, row)
                for row in rows
            ]

    def _collector_live_binding(
        self,
        connection: sqlite3.Connection,
        *,
        job_id: str,
        worker_id: str,
        lease_token: str,
        work_item_id: str,
        resource_definition_id: str,
        now: float,
    ) -> tuple[sqlite3.Row, sqlite3.Row]:
        job = self._assert_live_lease(
            connection, job_id, worker_id, lease_token, now
        )
        if (
            job["role"] != "tester"
            or job["work_item_id"] != work_item_id
            or job["current_attempt_id"] is None
        ):
            raise LeaseConflict(
                "collector plan does not match the current tester job and attempt"
            )
        attempt = connection.execute(
            "SELECT * FROM attempts WHERE id = ?",
            (job["current_attempt_id"],),
        ).fetchone()
        if attempt is None or attempt["status"] != "running":
            raise LeaseConflict("current collector attempt is absent")
        lease = connection.execute(
            """SELECT 1 FROM resource_leases
               WHERE job_id = ? AND owner_id = ? AND lease_token = ?
                 AND resource_key = ? AND resource_definition_id = ?""",
            (
                job_id,
                worker_id,
                lease_token,
                resource_definition_id,
                resource_definition_id,
            ),
        ).fetchone()
        if lease is None:
            raise LeaseConflict(
                "collector attempt does not hold the exact registered resource fence"
            )
        return job, attempt

    @staticmethod
    def _assert_stopped_collector_process(
        connection: sqlite3.Connection,
        attempt_id: str,
        provider: str,
    ) -> None:
        stopped = connection.execute(
            """SELECT 1 FROM external_processes
               WHERE attempt_id = ? AND provider = ? AND state = 'stopped'
               LIMIT 1""",
            (attempt_id, provider),
        ).fetchone()
        active = connection.execute(
            """SELECT 1 FROM external_processes
               WHERE attempt_id = ? AND state != 'stopped' LIMIT 1""",
            (attempt_id,),
        ).fetchone()
        if stopped is None or active is not None:
            raise LeaseConflict(
                "%s collector lacks durable process-group reap proof" % provider
            )

    @staticmethod
    def _prepare_collector_run_parent(
        runtime_root: Path, attempt_id: str, collector: str
    ) -> Path:
        SQLiteStore._assert_private_directory(runtime_root)
        attempt_root = runtime_root / attempt_id
        if attempt_root.exists():
            SQLiteStore._assert_private_directory(attempt_root)
        else:
            SQLiteStore._create_private_directory(attempt_root)
        run_parent = attempt_root / collector
        if run_parent.exists() or run_parent.is_symlink():
            raise LeaseConflict("collector run directory already exists")
        SQLiteStore._create_private_directory(run_parent)
        return run_parent

    @contextmanager
    def _collector_prepare_transaction(
        self,
    ) -> Iterator[tuple[sqlite3.Connection, List[Path]]]:
        created_run_parents: List[Path] = []
        try:
            with self._transaction() as connection:
                yield connection, created_run_parents
        except BaseException:
            for run_parent in reversed(created_run_parents):
                try:
                    shutil.rmtree(run_parent)
                    run_parent.parent.rmdir()
                except OSError:
                    pass
            raise

    @staticmethod
    def _collector_artifact(
        supplied_path: Any,
        expected_path: Path,
        claimed_sha256: Any,
        *,
        max_bytes: int,
    ) -> tuple[os.stat_result, str, bytes]:
        if not isinstance(supplied_path, str) or supplied_path != str(expected_path):
            raise LeaseConflict("collector artifact path changed after preparation")
        if (
            not isinstance(claimed_sha256, str)
            or _SHA256_PATTERN.fullmatch(claimed_sha256) is None
        ):
            raise ValueError("collector artifact hash must be lowercase SHA-256")
        try:
            descriptor = os.open(
                str(expected_path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
        except OSError as error:
            raise LeaseConflict("collector artifact is missing") from error
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.getuid()
                or details.st_mode & 0o077
                or details.st_nlink != 1
                or details.st_size <= 0
                or details.st_size > max_bytes
            ):
                raise LeaseConflict(
                    "collector artifact must be a bounded private user-owned regular file"
                )
            chunks: List[bytes] = []
            remaining = max_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            path_details = expected_path.lstat()
            identity_fields = (
                "st_dev",
                "st_ino",
                "st_uid",
                "st_mode",
                "st_nlink",
                "st_size",
            )
            if any(
                getattr(details, field) != getattr(after, field)
                or getattr(details, field) != getattr(path_details, field)
                for field in identity_fields
            ):
                raise LeaseConflict("collector artifact changed while it was read")
        except OSError as error:
            raise LeaseConflict("collector artifact changed while it was read") from error
        finally:
            os.close(descriptor)
        if len(raw) != details.st_size or len(raw) > max_bytes:
            raise LeaseConflict("collector artifact changed while it was read")
        observed_sha256 = hashlib.sha256(raw).hexdigest()
        if observed_sha256 != claimed_sha256:
            raise LeaseConflict("collector artifact hash does not match its bytes")
        return details, observed_sha256, raw

    def prepare_browser_evidence_execution(
        self,
        plan_id: str,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> Dict[str, Any]:
        plan_id = self._exact_collector_id(plan_id, "browser plan")
        with self._collector_prepare_transaction() as (
            connection,
            created_run_parents,
        ):
            now = self._clock()
            plan_row = connection.execute(
                "SELECT * FROM browser_evidence_plans WHERE id = ?", (plan_id,)
            ).fetchone()
            if plan_row is None:
                raise NotFoundError("browser evidence plan %s not found" % plan_id)
            plan = self._validated_browser_plan_row(connection, plan_row)
            job, attempt = self._collector_live_binding(
                connection,
                job_id=job_id,
                worker_id=worker_id,
                lease_token=lease_token,
                work_item_id=str(plan["work_item_id"]),
                resource_definition_id=str(plan["resource_definition_id"]),
                now=now,
            )
            admission = self._assert_attempt_collector_admission(
                connection, job, attempt, "browser"
            )
            existing = connection.execute(
                "SELECT * FROM browser_evidence_executions WHERE attempt_id = ?",
                (attempt["id"],),
            ).fetchone()
            if existing is not None:
                if existing["plan_id"] != plan_id or existing["job_id"] != job_id:
                    raise LeaseConflict(
                        "browser execution is already bound to another plan or job"
                    )
                return self._browser_execution_contract(
                    self._row(existing), plan, connection
                )
            runtime_root = Path(str(plan["runtime_root"]))
            run_parent = self._prepare_collector_run_parent(
                runtime_root, str(attempt["id"]), "browser"
            )
            created_run_parents.append(run_parent)
            screenshot_path = run_parent / "screenshot.png"
            execution_id = _id()
            connection.execute(
                """INSERT INTO browser_evidence_executions
                   (id, plan_id, attempt_id, job_id, work_item_id,
                    resource_definition_id, resource_identity_hash, status,
                    requested_route, run_parent, screenshot_path,
                    prepared_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?, ?, ?, ?)""",
                (
                    execution_id,
                    plan_id,
                    attempt["id"],
                    job_id,
                    job["work_item_id"],
                    plan["resource_definition_id"],
                    plan["resource_identity_hash"],
                    plan["route"],
                    str(run_parent),
                    str(screenshot_path),
                    now,
                    now,
                ),
            )
            self._append_event(
                connection,
                "browser_evidence.execution_prepared",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job_id,
                actor=worker_id,
                event_data={
                    "execution_id": execution_id,
                    "plan_id": plan_id,
                    "attempt_id": attempt["id"],
                    "resource_id": plan["resource_definition_id"],
                    "resource_identity_hash": plan["resource_identity_hash"],
                    "focused_test_admission_id": admission["id"],
                    "focused_test_admission_sha256": admission["authority_sha256"],
                },
                created_at=now,
            )
            execution = self._row(
                connection.execute(
                    "SELECT * FROM browser_evidence_executions WHERE id = ?",
                    (execution_id,),
                ).fetchone()
            )
            return self._browser_execution_contract(execution, plan, connection)

    def _browser_execution_contract(
        self,
        execution: Mapping[str, Any],
        plan: Mapping[str, Any],
        connection: sqlite3.Connection,
    ) -> Dict[str, Any]:
        resource_row = connection.execute(
            "SELECT * FROM resource_definitions WHERE id = ?",
            (plan["resource_definition_id"],),
        ).fetchone()
        if resource_row is None:
            raise LeaseConflict("browser collector resource disappeared")
        resource = self._validated_resource_definition_row(resource_row)
        if resource["identity_hash"] != plan["resource_identity_hash"]:
            raise LeaseConflict("browser collector resource identity changed")
        contract = dict(execution)
        contract.update(
            {
                "route": plan["route"],
                "expected_title": plan["expected_title"],
                "expected_body_text": plan["expected_body_text"],
                "timeout_seconds": plan["timeout_seconds"],
                "chrome_configuration": dict(resource["configuration"]),
                "plan_sha256": plan["plan_sha256"],
            }
        )
        return contract

    def complete_browser_evidence_execution(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        execution_id = self._exact_collector_id(
            str(result.get("execution_id", "")), "browser execution"
        )
        observed_route = _exact_disposable_file_route(result.get("observed_route"))
        observed_title = _reject_unsafe_collector_text(
            result.get("observed_title"), "observed browser title"
        )
        observed_body = _reject_unsafe_collector_text(
            result.get("observed_body_text"),
            "observed browser body",
            allow_newlines=True,
        )
        with self._transaction() as connection:
            now = self._clock()
            execution_row = connection.execute(
                "SELECT * FROM browser_evidence_executions WHERE id = ?",
                (execution_id,),
            ).fetchone()
            if execution_row is None:
                raise NotFoundError(
                    "browser evidence execution %s not found" % execution_id
                )
            plan_row = connection.execute(
                "SELECT * FROM browser_evidence_plans WHERE id = ?",
                (execution_row["plan_id"],),
            ).fetchone()
            if plan_row is None:
                raise LeaseConflict("browser evidence plan disappeared")
            plan = self._validated_browser_plan_row(connection, plan_row)
            job, attempt = self._collector_live_binding(
                connection,
                job_id=job_id,
                worker_id=worker_id,
                lease_token=lease_token,
                work_item_id=str(plan["work_item_id"]),
                resource_definition_id=str(plan["resource_definition_id"]),
                now=now,
            )
            self._assert_attempt_collector_admission(connection, job, attempt, "browser")
            if (
                execution_row["job_id"] != job_id
                or execution_row["attempt_id"] != attempt["id"]
            ):
                raise LeaseConflict(
                    "browser execution belongs to another job or attempt"
                )
            self._assert_stopped_collector_process(
                connection, str(attempt["id"]), "browser_evidence"
            )
            screenshot_path = Path(str(execution_row["screenshot_path"]))
            details, screenshot_sha256, _screenshot_bytes = self._collector_artifact(
                result.get("screenshot_path"),
                screenshot_path,
                result.get("screenshot_sha256"),
                max_bytes=16 * 1024 * 1024,
            )
            assertions = {
                "route": observed_route == plan["route"],
                "title": observed_title == plan["expected_title"],
                "body": observed_body == plan["expected_body_text"],
            }
            observed_body_sha256 = hashlib.sha256(
                observed_body.encode("utf-8")
            ).hexdigest()
            outcome = "pass" if all(assertions.values()) else "fail"
            if execution_row["status"] == "finished":
                persisted = self._row(execution_row)
                if (
                    persisted["observed_route"] != observed_route
                    or persisted["observed_title"] != observed_title
                    or persisted["observed_body_sha256"] != observed_body_sha256
                    or persisted["assertions"] != assertions
                    or persisted["screenshot_sha256"] != screenshot_sha256
                    or persisted["outcome"] != outcome
                ):
                    raise LeaseConflict("finished browser evidence changed")
                return persisted
            if execution_row["status"] != "prepared":
                raise LeaseConflict("browser evidence execution is not completable")
            artifact_id = _id()
            connection.execute(
                """INSERT INTO artifacts
                   (id, work_item_id, job_id, attempt_id, kind, uri,
                    metadata_json, created_at)
                   VALUES (?, ?, ?, ?, 'browser_screenshot', ?, ?, ?)""",
                (
                    artifact_id,
                    job["work_item_id"],
                    job_id,
                    execution_row["attempt_id"],
                    str(screenshot_path),
                    _dump(
                        {
                            "attempt_id": execution_row["attempt_id"],
                            "execution_id": execution_id,
                            "resource_id": plan["resource_definition_id"],
                            "sha256": screenshot_sha256,
                            "bytes": int(details.st_size),
                        }
                    ),
                    now,
                ),
            )
            connection.execute(
                """UPDATE browser_evidence_executions
                   SET status = 'finished', outcome = ?, observed_route = ?,
                       observed_title = ?, observed_body_sha256 = ?,
                       assertions_json = ?,
                       screenshot_device = ?, screenshot_inode = ?,
                       screenshot_owner_uid = ?, screenshot_mode = ?,
                       screenshot_nlink = ?, screenshot_bytes = ?,
                       screenshot_sha256 = ?, artifact_id = ?, finished_at = ?,
                       updated_at = ?
                   WHERE id = ? AND status = 'prepared'""",
                (
                    outcome,
                    observed_route,
                    observed_title,
                    observed_body_sha256,
                    _dump(assertions),
                    int(details.st_dev),
                    int(details.st_ino),
                    int(details.st_uid),
                    int(details.st_mode),
                    int(details.st_nlink),
                    int(details.st_size),
                    screenshot_sha256,
                    artifact_id,
                    now,
                    now,
                    execution_id,
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
                    "attempt_id": execution_row["attempt_id"],
                    "kind": "browser_screenshot",
                    "uri": str(screenshot_path),
                },
                created_at=now,
            )
            self._append_event(
                connection,
                "browser_evidence.execution_finished",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job_id,
                actor=worker_id,
                event_data={
                    "execution_id": execution_id,
                    "plan_id": plan["id"],
                    "attempt_id": execution_row["attempt_id"],
                    "resource_id": plan["resource_definition_id"],
                    "outcome": outcome,
                    "screenshot_sha256": screenshot_sha256,
                },
                created_at=now,
            )
            finished = connection.execute(
                "SELECT * FROM browser_evidence_executions WHERE id = ?",
                (execution_id,),
            ).fetchone()
            return self._row(finished)  # type: ignore[return-value]

    def get_browser_evidence_execution(self, execution_id: str) -> Dict[str, Any]:
        execution_id = self._exact_collector_id(execution_id, "browser execution")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM browser_evidence_executions WHERE id = ?",
                (execution_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("browser evidence execution %s not found" % execution_id)
        return self._row(row)  # type: ignore[return-value]

    def list_browser_evidence_executions(
        self, *, work_item_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM browser_evidence_executions"
        parameters: Sequence[Any] = ()
        if work_item_id is not None:
            sql += " WHERE work_item_id = ?"
            parameters = (work_item_id,)
        sql += " ORDER BY work_item_id, prepared_at, id"
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        return self._rows(rows)

    def prepare_database_query_execution(
        self,
        plan_id: str,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> Dict[str, Any]:
        plan_id = self._exact_collector_id(plan_id, "database plan")
        with self._collector_prepare_transaction() as (
            connection,
            created_run_parents,
        ):
            now = self._clock()
            plan_row = connection.execute(
                "SELECT * FROM database_query_plans WHERE id = ?", (plan_id,)
            ).fetchone()
            if plan_row is None:
                raise NotFoundError("database query plan %s not found" % plan_id)
            plan = self._validated_database_plan_row(connection, plan_row)
            job, attempt = self._collector_live_binding(
                connection,
                job_id=job_id,
                worker_id=worker_id,
                lease_token=lease_token,
                work_item_id=str(plan["work_item_id"]),
                resource_definition_id=str(plan["resource_definition_id"]),
                now=now,
            )
            admission = self._assert_attempt_collector_admission(
                connection, job, attempt, "database"
            )
            existing = connection.execute(
                "SELECT * FROM database_query_executions WHERE attempt_id = ?",
                (attempt["id"],),
            ).fetchone()
            if existing is not None:
                if existing["plan_id"] != plan_id or existing["job_id"] != job_id:
                    raise LeaseConflict(
                        "database execution is already bound to another plan or job"
                    )
                return self._database_execution_contract(
                    self._row(existing), plan, connection
                )
            runtime_root = Path(str(plan["runtime_root"]))
            run_parent = self._prepare_collector_run_parent(
                runtime_root, str(attempt["id"]), "database"
            )
            created_run_parents.append(run_parent)
            result_path = run_parent / "result.json"
            execution_id = _id()
            connection.execute(
                """INSERT INTO database_query_executions
                   (id, plan_id, attempt_id, job_id, work_item_id,
                    resource_definition_id, resource_identity_hash, status,
                    query_sha256, run_parent, result_path, prepared_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?, ?, ?, ?)""",
                (
                    execution_id,
                    plan_id,
                    attempt["id"],
                    job_id,
                    job["work_item_id"],
                    plan["resource_definition_id"],
                    plan["resource_identity_hash"],
                    plan["query_sha256"],
                    str(run_parent),
                    str(result_path),
                    now,
                    now,
                ),
            )
            self._append_event(
                connection,
                "database_evidence.execution_prepared",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job_id,
                actor=worker_id,
                event_data={
                    "execution_id": execution_id,
                    "plan_id": plan_id,
                    "attempt_id": attempt["id"],
                    "resource_id": plan["resource_definition_id"],
                    "resource_identity_hash": plan["resource_identity_hash"],
                    "query_sha256": plan["query_sha256"],
                    "focused_test_admission_id": admission["id"],
                    "focused_test_admission_sha256": admission["authority_sha256"],
                },
                created_at=now,
            )
            execution = self._row(
                connection.execute(
                    "SELECT * FROM database_query_executions WHERE id = ?",
                    (execution_id,),
                ).fetchone()
            )
            return self._database_execution_contract(execution, plan, connection)

    def _database_execution_contract(
        self,
        execution: Mapping[str, Any],
        plan: Mapping[str, Any],
        connection: sqlite3.Connection,
    ) -> Dict[str, Any]:
        resource_row = connection.execute(
            "SELECT * FROM resource_definitions WHERE id = ?",
            (plan["resource_definition_id"],),
        ).fetchone()
        if resource_row is None:
            raise LeaseConflict("database collector resource disappeared")
        resource = self._validated_resource_definition_row(resource_row)
        if resource["identity_hash"] != plan["resource_identity_hash"]:
            raise LeaseConflict("database collector resource identity changed")
        contract = dict(execution)
        contract.update(
            {
                "statement": plan["statement"],
                "parameters": list(plan["parameters"]),
                "id_column": plan["id_column"],
                "expected_ids": list(plan["expected_ids"]),
                "expected_row_count": plan["expected_row_count"],
                "max_rows": plan["max_rows"],
                "max_bytes": plan["max_bytes"],
                "timeout_seconds": plan["timeout_seconds"],
                "database_configuration": dict(resource["configuration"]),
                "plan_sha256": plan["plan_sha256"],
            }
        )
        return contract

    @staticmethod
    def _validated_database_result(
        raw: bytes, max_rows: int, max_bytes: int, id_column: str
    ) -> tuple[Dict[str, Any], List[Any]]:
        if len(raw) > max_bytes:
            raise LeaseConflict("database result exceeded its byte bound")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise LeaseConflict("database result is not valid JSON") from error
        if not isinstance(payload, dict) or set(payload) != {
            "columns",
            "rows",
            "read_only_proof",
        }:
            raise LeaseConflict("database result has an unexpected structure")
        if raw != _dump(payload).encode("utf-8"):
            raise LeaseConflict("database result is not canonical JSON")
        columns = payload["columns"]
        rows = payload["rows"]
        proof = payload["read_only_proof"]
        if (
            not isinstance(columns, list)
            or not columns
            or len(columns) > 64
            or any(
                not isinstance(column, str)
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", column) is None
                for column in columns
            )
            or len(set(columns)) != len(columns)
        ):
            raise LeaseConflict("database result columns are invalid")
        if id_column not in columns:
            raise LeaseConflict("database result omitted the exact ID column")
        if not isinstance(rows, list) or len(rows) > max_rows:
            raise LeaseConflict("database result exceeded its row bound")
        id_index = columns.index(id_column)
        observed_ids: List[Any] = []
        for row in rows:
            if not isinstance(row, list) or len(row) != len(columns):
                raise LeaseConflict("database result rows do not match the columns")
            for value in row:
                if value is not None and not isinstance(
                    value, (str, int, float, bool)
                ):
                    raise LeaseConflict("database result contains a non-scalar value")
                if isinstance(value, float) and not math.isfinite(value):
                    raise LeaseConflict("database result contains a non-finite value")
                if isinstance(value, str):
                    _reject_unsafe_collector_text(
                        value, "database result value", allow_newlines=True
                    )
            observed_id = row[id_index]
            if isinstance(observed_id, bool) or not isinstance(
                observed_id, (str, int)
            ):
                raise LeaseConflict("database result ID values are invalid")
            observed_ids.append(observed_id)
        if (
            not isinstance(proof, dict)
            or set(proof) != {
                "authorizer",
                "foreign_key_violations",
                "query_only",
                "uri_mode",
            }
            or proof.get("authorizer") != "deny_non_read"
            or proof.get("query_only") is not True
            or proof.get("uri_mode") != "ro"
            or not isinstance(proof.get("foreign_key_violations"), int)
            or isinstance(proof.get("foreign_key_violations"), bool)
            or int(proof["foreign_key_violations"]) < 0
        ):
            raise LeaseConflict("database read-only proof is incomplete")
        return payload, observed_ids

    def complete_database_query_execution(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        execution_id = self._exact_collector_id(
            str(result.get("execution_id", "")), "database execution"
        )
        with self._transaction() as connection:
            now = self._clock()
            execution_row = connection.execute(
                "SELECT * FROM database_query_executions WHERE id = ?",
                (execution_id,),
            ).fetchone()
            if execution_row is None:
                raise NotFoundError(
                    "database query execution %s not found" % execution_id
                )
            plan_row = connection.execute(
                "SELECT * FROM database_query_plans WHERE id = ?",
                (execution_row["plan_id"],),
            ).fetchone()
            if plan_row is None:
                raise LeaseConflict("database query plan disappeared")
            plan = self._validated_database_plan_row(connection, plan_row)
            job, attempt = self._collector_live_binding(
                connection,
                job_id=job_id,
                worker_id=worker_id,
                lease_token=lease_token,
                work_item_id=str(plan["work_item_id"]),
                resource_definition_id=str(plan["resource_definition_id"]),
                now=now,
            )
            self._assert_attempt_collector_admission(connection, job, attempt, "database")
            if (
                execution_row["job_id"] != job_id
                or execution_row["attempt_id"] != attempt["id"]
            ):
                raise LeaseConflict(
                    "database execution belongs to another job or attempt"
                )
            result_path = Path(str(execution_row["result_path"]))
            details, result_sha256, result_bytes = self._collector_artifact(
                result.get("result_path"),
                result_path,
                result.get("result_sha256"),
                max_bytes=int(plan["max_bytes"]),
            )
            payload, observed_ids = self._validated_database_result(
                result_bytes,
                int(plan["max_rows"]),
                int(plan["max_bytes"]),
                str(plan["id_column"]),
            )
            row_count = len(payload["rows"])
            column_count = len(payload["columns"])
            row_count_matches = (
                plan["expected_row_count"] is None
                or row_count == int(plan["expected_row_count"])
            )
            ids_match = observed_ids == list(plan["expected_ids"])
            foreign_keys_clean = (
                int(payload["read_only_proof"]["foreign_key_violations"]) == 0
            )
            outcome = (
                "pass"
                if row_count_matches and ids_match and foreign_keys_clean
                else "fail"
            )
            if execution_row["status"] == "finished":
                persisted = self._row(execution_row)
                if (
                    persisted["row_count"] != row_count
                    or persisted["column_count"] != column_count
                    or persisted["observed_ids"] != observed_ids
                    or persisted["read_only_proof"] != payload["read_only_proof"]
                    or persisted["result_sha256"] != result_sha256
                    or persisted["outcome"] != outcome
                ):
                    raise LeaseConflict("finished database evidence changed")
                return persisted
            if execution_row["status"] != "prepared":
                raise LeaseConflict("database evidence execution is not completable")
            artifact_id = _id()
            connection.execute(
                """INSERT INTO artifacts
                   (id, work_item_id, job_id, attempt_id, kind, uri,
                    metadata_json, created_at)
                   VALUES (?, ?, ?, ?, 'database_result', ?, ?, ?)""",
                (
                    artifact_id,
                    job["work_item_id"],
                    job_id,
                    execution_row["attempt_id"],
                    str(result_path),
                    _dump(
                        {
                            "attempt_id": execution_row["attempt_id"],
                            "execution_id": execution_id,
                            "resource_id": plan["resource_definition_id"],
                            "query_sha256": plan["query_sha256"],
                            "sha256": result_sha256,
                            "bytes": int(details.st_size),
                            "row_count": row_count,
                        }
                    ),
                    now,
                ),
            )
            connection.execute(
                """UPDATE database_query_executions
                   SET status = 'finished', outcome = ?, row_count = ?,
                       column_count = ?, observed_ids_json = ?,
                       read_only_proof_json = ?, result_device = ?,
                       result_inode = ?, result_owner_uid = ?, result_mode = ?,
                       result_nlink = ?, result_bytes = ?, result_sha256 = ?,
                       artifact_id = ?, finished_at = ?, updated_at = ?
                   WHERE id = ? AND status = 'prepared'""",
                (
                    outcome,
                    row_count,
                    column_count,
                    _dump(observed_ids),
                    _dump(payload["read_only_proof"]),
                    int(details.st_dev),
                    int(details.st_ino),
                    int(details.st_uid),
                    int(details.st_mode),
                    int(details.st_nlink),
                    int(details.st_size),
                    result_sha256,
                    artifact_id,
                    now,
                    now,
                    execution_id,
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
                    "attempt_id": execution_row["attempt_id"],
                    "kind": "database_result",
                    "uri": str(result_path),
                },
                created_at=now,
            )
            self._append_event(
                connection,
                "database_evidence.execution_finished",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job_id,
                actor=worker_id,
                event_data={
                    "execution_id": execution_id,
                    "plan_id": plan["id"],
                    "attempt_id": execution_row["attempt_id"],
                    "resource_id": plan["resource_definition_id"],
                    "query_sha256": plan["query_sha256"],
                    "outcome": outcome,
                    "row_count": row_count,
                    "observed_ids": observed_ids,
                    "result_sha256": result_sha256,
                },
                created_at=now,
            )
            finished = connection.execute(
                "SELECT * FROM database_query_executions WHERE id = ?",
                (execution_id,),
            ).fetchone()
            return self._row(finished)  # type: ignore[return-value]

    def get_database_query_execution(self, execution_id: str) -> Dict[str, Any]:
        execution_id = self._exact_collector_id(execution_id, "database execution")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM database_query_executions WHERE id = ?",
                (execution_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("database query execution %s not found" % execution_id)
        return self._row(row)  # type: ignore[return-value]

    def list_database_query_executions(
        self, *, work_item_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM database_query_executions"
        parameters: Sequence[Any] = ()
        if work_item_id is not None:
            sql += " WHERE work_item_id = ?"
            parameters = (work_item_id,)
        sql += " ORDER BY work_item_id, prepared_at, id"
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        return self._rows(rows)

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
                             ON ep.id = (
                                 SELECT latest_process.id
                                 FROM external_processes latest_process
                                 WHERE latest_process.attempt_id = a.id
                                 ORDER BY
                                     CASE WHEN latest_process.state IN (
                                         'quarantined', 'legacy_unverifiable')
                                         THEN 0 ELSE 1 END,
                                     latest_process.recorded_at DESC,
                                     latest_process.id DESC
                                 LIMIT 1)
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
                           WHERE r.job_id IN (%s)
                           ORDER BY r.resource_key, r.lease_slot"""
                        % job_placeholders,
                        job_ids,
                    ).fetchall()
                    resource_leases = self._safe_resource_lease_records(
                        self._connection, lease_rows
                    )

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

    @staticmethod
    def _assert_admission_directory_identity(
        path_value: str,
        *,
        device: int,
        inode: int,
        owner_uid: int,
        label: str,
    ) -> None:
        path = Path(path_value)
        try:
            resolved = path.resolve(strict=True)
            details = path.lstat()
        except OSError as error:
            raise LeaseConflict("%s is absent" % label) from error
        if (
            resolved != path
            or not stat.S_ISDIR(details.st_mode)
            or int(details.st_dev) != device
            or int(details.st_ino) != inode
            or int(details.st_uid) != owner_uid
        ):
            raise LeaseConflict("%s identity changed" % label)

    def _validate_live_focused_test_admission(
        self,
        connection: sqlite3.Connection,
        admission_row: sqlite3.Row,
        job: sqlite3.Row,
    ) -> Dict[str, Any]:
        try:
            admission = self._focused_test_admission_record(admission_row)
        except StorageError as error:
            raise LeaseConflict("focused-test admission integrity changed") from error
        if admission["status"] != "active":
            raise LeaseConflict("focused-test admission is not active")
        if (
            admission["campaign_id"] != job["campaign_id"]
            or admission["work_item_id"] != job["work_item_id"]
            or admission["tester_job_id"] != job["id"]
            or job["role"] != "tester"
            or job["workspace_kind"] != WorkspaceKind.MANAGED_WORKTREE.value
            or admission["managed_worktree_id"] != job["managed_worktree_id"]
        ):
            raise LeaseConflict("focused-test admission does not match the exact tester job")

        campaign = connection.execute(
            "SELECT * FROM campaigns WHERE id = ?",
            (job["campaign_id"],),
        ).fetchone()
        item = connection.execute(
            "SELECT * FROM work_items WHERE id = ? AND campaign_id = ?",
            (job["work_item_id"], job["campaign_id"]),
        ).fetchone()
        worktree = connection.execute(
            """SELECT * FROM managed_worktrees
               WHERE id = ? AND campaign_id = ? AND work_item_id = ?""",
            (
                admission["managed_worktree_id"],
                job["campaign_id"],
                job["work_item_id"],
            ),
        ).fetchone()
        plan = connection.execute(
            """SELECT * FROM focused_test_plans
               WHERE id = ? AND work_item_id = ?""",
            (admission["focused_test_plan_id"], job["work_item_id"]),
        ).fetchone()
        latest_plan = connection.execute(
            """SELECT id FROM focused_test_plans WHERE work_item_id = ?
               ORDER BY plan_number DESC LIMIT 1""",
            (job["work_item_id"],),
        ).fetchone()
        if (
            campaign is None
            or campaign["status"] != "active"
            or campaign["execution_mode"] != "focused_test_admission"
            or item is None
            or worktree is None
            or worktree["state"] != "ready"
            or plan is None
            or latest_plan is None
            or latest_plan["id"] != plan["id"]
        ):
            raise LeaseConflict("focused-test admission authority is absent or no longer current")

        campaign_config = _load(campaign["config_json"], {})
        required_gates = _load(item["required_gates_json"], [])
        job_payload = _load(job["payload_json"], {})
        if required_gates not in (
            [GateKind.FOCUSED_TESTS.value],
            list(DEFAULT_REQUIRED_GATES),
        ):
            raise LeaseConflict(
                "focused-test admission supports only the trusted focused-test "
                "gate or fixed three-gate pipeline"
            )
        if (
            _sha256_json(campaign_config) != admission["campaign_config_sha256"]
            or hashlib.sha256(_dump(job_payload).encode("utf-8")).hexdigest()
            != admission["job_payload_sha256"]
            or hashlib.sha256(_dump(required_gates).encode("utf-8")).hexdigest()
            != admission["required_gates_sha256"]
        ):
            raise LeaseConflict("campaign, item, or tester payload authority changed")

        repository_identity = self._repository_admission_identity(worktree)
        worktree_identity = self._worktree_admission_identity(worktree)
        if (
            repository_identity != admission["repository_identity"]
            or worktree_identity != admission["worktree_identity"]
            or int(worktree["generation"])
            != int(admission["managed_worktree_generation"])
            or str(worktree["repository_path"])
            not in _canonical_repository_scope(campaign_config)
        ):
            raise LeaseConflict("campaign repository or worktree authority changed")
        self._assert_admission_directory_identity(
            str(worktree["repository_path"]),
            device=int(worktree["source_device"]),
            inode=int(worktree["source_inode"]),
            owner_uid=int(worktree["source_owner_uid"]),
            label="admitted source repository",
        )
        self._assert_admission_directory_identity(
            str(worktree["worktree_path"]),
            device=int(worktree["worktree_device"]),
            inode=int(worktree["worktree_inode"]),
            owner_uid=int(worktree["worktree_owner_uid"]),
            label="admitted managed worktree",
        )

        try:
            plan_hash = _sha256_json(self._focused_plan_authority(plan))
        except (KeyError, TypeError, ValueError) as error:
            raise LeaseConflict("focused test plan authority is incomplete") from error
        if (
            plan_hash != admission["focused_test_plan_sha256"]
            or plan["sandbox_policy_version"] != DARWIN_SANDBOX_POLICY_VERSION
        ):
            raise LeaseConflict("focused test plan authority changed")

        try:
            bindings = self._focused_test_admission_resource_bindings(
                connection,
                str(job["campaign_id"]),
                admission["resource_definition_ids"],
                require_enabled=True,
            )
        except (NotFoundError, StorageError, TransitionConflict, ValueError) as error:
            raise LeaseConflict(
                "focused-test admission resource authority is unavailable"
            ) from error
        expected_resources = sorted(
            list(admission["resource_definition_ids"])
            + [WORKTREE_RESOURCE_PREFIX + str(worktree["id"])]
        )
        if (
            bindings != admission["resource_bindings"]
            or _load(job["required_resources_json"], []) != expected_resources
            or hashlib.sha256(
                _dump(expected_resources).encode("utf-8")
            ).hexdigest()
            != admission["required_resources_sha256"]
        ):
            raise LeaseConflict("focused-test admission resource authority changed")
        return admission

    def _assert_live_focused_test_admission(
        self,
        connection: sqlite3.Connection,
        admission_row: sqlite3.Row,
        job: sqlite3.Row,
    ) -> Dict[str, Any]:
        try:
            return self._validate_live_focused_test_admission(
                connection, admission_row, job
            )
        except LeaseConflict:
            raise
        except (KeyError, OSError, TypeError, ValueError) as error:
            raise LeaseConflict(
                "focused-test admission live authority is malformed"
            ) from error

    def _assert_attempt_focused_test_admission(
        self,
        connection: sqlite3.Connection,
        job: sqlite3.Row,
    ) -> Optional[Dict[str, Any]]:
        attempt = connection.execute(
            """SELECT focused_test_admission_id FROM attempts
               WHERE id = ? AND job_id = ? AND status = 'running'""",
            (job["current_attempt_id"], job["id"]),
        ).fetchone()
        if attempt is None:
            raise LeaseConflict("current running attempt is absent")
        admission_id = attempt["focused_test_admission_id"]
        campaign = connection.execute(
            "SELECT execution_mode FROM campaigns WHERE id = ?",
            (job["campaign_id"],),
        ).fetchone()
        if campaign is None:
            raise LeaseConflict("attempt campaign disappeared")
        if admission_id is None:
            if campaign["execution_mode"] == "focused_test_admission":
                raise LeaseConflict(
                    "focused-test campaign attempt has no pinned admission"
                )
            return None
        if campaign["execution_mode"] != "focused_test_admission":
            raise LeaseConflict(
                "focused-test admission is outside its persisted campaign mode"
            )
        admission_row = connection.execute(
            "SELECT * FROM focused_test_admissions WHERE id = ?",
            (admission_id,),
        ).fetchone()
        if admission_row is None:
            raise LeaseConflict("attempt focused-test admission disappeared")
        admission = self._assert_live_focused_test_admission(
            connection, admission_row, job
        )
        if admission["id"] != admission_id:
            raise LeaseConflict("attempt focused-test admission identity changed")
        return admission

    def create_focused_test_admission(
        self,
        campaign_id: str,
        work_item_id: str,
        tester_job_id: str,
        managed_worktree_id: str,
        focused_test_plan_id: str,
        resource_definition_ids: Sequence[str],
        *,
        admitted_by: str,
        reason: str,
        admission_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Bind one internally attributed tester job to exact immutable authority.

        This precursor records an actor and reason for audit.  It is not an
        operator-approval workflow and is intentionally not exposed by the CLI.
        """

        for value, label in (
            (campaign_id, "campaign ID"),
            (work_item_id, "work item ID"),
            (tester_job_id, "tester job ID"),
            (managed_worktree_id, "managed worktree ID"),
            (focused_test_plan_id, "focused test plan ID"),
        ):
            self._exact_record_id(value, label)
        admitted_by = _operator_text(admitted_by, "focused-test admission actor", 256)
        reason = _operator_text(reason, "focused-test admission reason", 1024)
        admission_id = (
            _focused_test_admission_id()
            if admission_id is None
            else self._exact_focused_test_admission_id(admission_id)
        )
        with self._transaction() as connection:
            now = self._clock()
            campaign = connection.execute(
                "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
            ).fetchone()
            item = connection.execute(
                """SELECT * FROM work_items
                   WHERE id = ? AND campaign_id = ?""",
                (work_item_id, campaign_id),
            ).fetchone()
            job = connection.execute(
                """SELECT * FROM jobs
                   WHERE id = ? AND campaign_id = ? AND work_item_id = ?""",
                (tester_job_id, campaign_id, work_item_id),
            ).fetchone()
            worktree = connection.execute(
                """SELECT * FROM managed_worktrees
                   WHERE id = ? AND campaign_id = ? AND work_item_id = ?""",
                (managed_worktree_id, campaign_id, work_item_id),
            ).fetchone()
            plan = connection.execute(
                """SELECT * FROM focused_test_plans
                   WHERE id = ? AND work_item_id = ?""",
                (focused_test_plan_id, work_item_id),
            ).fetchone()
            latest_plan = connection.execute(
                """SELECT id FROM focused_test_plans WHERE work_item_id = ?
                   ORDER BY plan_number DESC LIMIT 1""",
                (work_item_id,),
            ).fetchone()
            if campaign is None:
                raise NotFoundError("campaign %s not found" % campaign_id)
            if item is None:
                raise NotFoundError("work item is outside the requested campaign")
            if job is None:
                raise NotFoundError("tester job is outside the requested work item")
            if worktree is None:
                raise NotFoundError("managed worktree is outside the requested work item")
            if plan is None:
                raise NotFoundError("focused test plan is outside the requested work item")
            if campaign["status"] != "active" or item["state"] != "ready_for_test":
                raise TransitionConflict(
                    "focused-test admission requires an active ready-for-test item"
                )
            if (
                job["role"] != "tester"
                or job["status"] != "pending"
                or job["queued_item_state"] != "ready_for_test"
                or job["active_item_state"] != "testing"
                or job["workspace_kind"] != WorkspaceKind.MANAGED_WORKTREE.value
                or job["managed_worktree_id"] != managed_worktree_id
            ):
                raise TransitionConflict(
                    "focused-test admission requires the exact pending managed-worktree tester job"
                )
            if (
                worktree["state"] != "ready"
                or latest_plan is None
                or latest_plan["id"] != focused_test_plan_id
                or plan["sandbox_policy_version"] != DARWIN_SANDBOX_POLICY_VERSION
            ):
                raise TransitionConflict(
                    "focused-test admission requires the latest trusted focused-test plan and ready worktree"
                )
            campaign_config = _load(campaign["config_json"], {})
            required_gates = _load(item["required_gates_json"], [])
            if required_gates not in (
                [GateKind.FOCUSED_TESTS.value],
                list(DEFAULT_REQUIRED_GATES),
            ):
                raise TransitionConflict(
                    "focused-test admission permits only the focused-test gate "
                    "or fixed three-gate pipeline"
                )
            if str(worktree["repository_path"]) not in _canonical_repository_scope(
                campaign_config
            ):
                raise TransitionConflict(
                    "managed worktree repository is outside the campaign scope"
                )
            bindings = self._focused_test_admission_resource_bindings(
                connection,
                campaign_id,
                resource_definition_ids,
                require_enabled=True,
            )
            exact_resource_ids = [binding["id"] for binding in bindings]
            repository_identity = self._repository_admission_identity(worktree)
            worktree_identity = self._worktree_admission_identity(worktree)
            focused_plan_hash = _sha256_json(
                self._focused_plan_authority(plan)
            )
            required_resources = sorted(
                exact_resource_ids
                + [WORKTREE_RESOURCE_PREFIX + managed_worktree_id]
            )
            if _load(job["required_resources_json"], []) != required_resources:
                raise TransitionConflict(
                    "tester job resources must exactly match the requested admission"
                )
            data: Dict[str, Any] = {
                "id": admission_id,
                "campaign_id": campaign_id,
                "work_item_id": work_item_id,
                "tester_job_id": tester_job_id,
                "managed_worktree_id": managed_worktree_id,
                "managed_worktree_generation": int(worktree["generation"]),
                "focused_test_plan_id": focused_test_plan_id,
                "focused_test_plan_sha256": focused_plan_hash,
                "campaign_config_sha256": _sha256_json(campaign_config),
                "job_payload_sha256": hashlib.sha256(
                    str(job["payload_json"]).encode("utf-8")
                ).hexdigest(),
                "required_gates_sha256": hashlib.sha256(
                    str(item["required_gates_json"]).encode("utf-8")
                ).hexdigest(),
                "repository_identity": repository_identity,
                "repository_identity_sha256": _sha256_json(repository_identity),
                "worktree_identity": worktree_identity,
                "worktree_identity_sha256": _sha256_json(worktree_identity),
                "resource_definition_ids": exact_resource_ids,
                "resource_bindings": bindings,
                "resource_bindings_sha256": hashlib.sha256(
                    _dump(bindings).encode("utf-8")
                ).hexdigest(),
                "required_resources_sha256": hashlib.sha256(
                    _dump(required_resources).encode("utf-8")
                ).hexdigest(),
                "admitted_by": admitted_by,
                "admission_reason": reason,
                "admitted_at": now,
            }
            data["authority_sha256"] = _sha256_json(
                self._focused_test_admission_authority(data)
            )
            changed = connection.execute(
                """UPDATE campaigns
                   SET execution_mode = 'focused_test_admission', updated_at = ?
                   WHERE id = ?
                     AND execution_mode IN ('legacy', 'focused_test_admission')""",
                (now, campaign_id),
            ).rowcount
            if changed != 1:
                raise TransitionConflict(
                    "campaign execution mode cannot accept focused admission"
                )
            try:
                connection.execute(
                    """INSERT INTO focused_test_admissions
                       (id, campaign_id, work_item_id, tester_job_id,
                        managed_worktree_id, managed_worktree_generation,
                        focused_test_plan_id, focused_test_plan_sha256,
                        campaign_config_sha256, job_payload_sha256,
                        required_gates_sha256, repository_identity_json,
                        repository_identity_sha256, worktree_identity_json,
                        worktree_identity_sha256, resource_definition_ids_json,
                        resource_bindings_json, resource_bindings_sha256,
                        required_resources_sha256,
                        authority_sha256, status, admitted_by, admission_reason,
                        admitted_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                               ?, ?, ?, ?, 'active', ?, ?, ?, ?)""",
                    (
                        admission_id,
                        campaign_id,
                        work_item_id,
                        tester_job_id,
                        managed_worktree_id,
                        int(worktree["generation"]),
                        focused_test_plan_id,
                        focused_plan_hash,
                        data["campaign_config_sha256"],
                        data["job_payload_sha256"],
                        data["required_gates_sha256"],
                        _dump(repository_identity),
                        data["repository_identity_sha256"],
                        _dump(worktree_identity),
                        data["worktree_identity_sha256"],
                        _dump(exact_resource_ids),
                        _dump(bindings),
                        data["resource_bindings_sha256"],
                        data["required_resources_sha256"],
                        data["authority_sha256"],
                        admitted_by,
                        reason,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise TransitionConflict(
                    "tester job already has an active focused-test admission"
                ) from error
            self._append_event(
                connection,
                "focused_test.admission_created",
                campaign_id=campaign_id,
                work_item_id=work_item_id,
                job_id=tester_job_id,
                actor=admitted_by,
                event_data={
                    "admission_id": admission_id,
                    "managed_worktree_id": managed_worktree_id,
                    "managed_worktree_generation": int(worktree["generation"]),
                    "focused_test_plan_id": focused_test_plan_id,
                    "resource_definition_ids": exact_resource_ids,
                    "authority_sha256": data["authority_sha256"],
                    "reason": reason,
                },
                created_at=now,
            )
            inserted = connection.execute(
                "SELECT * FROM focused_test_admissions WHERE id = ?",
                (admission_id,),
            ).fetchone()
            assert inserted is not None
            self._assert_live_focused_test_admission(
                connection, inserted, job
            )
        return self.get_focused_test_admission(admission_id)

    def get_focused_test_admission(self, admission_id: str) -> Dict[str, Any]:
        admission_id = self._exact_focused_test_admission_id(admission_id)
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM focused_test_admissions WHERE id = ?",
                (admission_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("focused-test admission %s not found" % admission_id)
        return self._focused_test_admission_record(row)

    def list_focused_test_admissions(
        self,
        *,
        campaign_id: Optional[str] = None,
        work_item_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        parameters: List[Any] = []
        for column, value in (
            ("campaign_id", campaign_id),
            ("work_item_id", work_item_id),
            ("status", status),
        ):
            if value is not None:
                clauses.append(column + " = ?")
                parameters.append(value)
        sql = "SELECT * FROM focused_test_admissions"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY admitted_at, id"
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        return [self._focused_test_admission_record(row) for row in rows]

    def revoke_focused_test_admission(
        self,
        admission_id: str,
        *,
        revoked_by: str,
        reason: str,
    ) -> Dict[str, Any]:
        admission_id = self._exact_focused_test_admission_id(admission_id)
        revoked_by = _operator_text(revoked_by, "campaign revocation actor", 256)
        reason = _operator_text(reason, "campaign revocation reason", 1024)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM focused_test_admissions WHERE id = ?",
                (admission_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("focused-test admission %s not found" % admission_id)
            admission = self._focused_test_admission_record(row)
            if admission["status"] == "revoked":
                return admission
            now = self._clock()
            changed = connection.execute(
                """UPDATE focused_test_admissions
                   SET status = 'revoked', revoked_by = ?, revocation_reason = ?,
                       revoked_at = ?, updated_at = ?
                   WHERE id = ? AND status = 'active'""",
                (revoked_by, reason, now, now, admission_id),
            ).rowcount
            if changed != 1:
                raise TransitionConflict(
                    "focused-test admission changed during revocation"
                )
            self._append_event(
                connection,
                "focused_test.admission_revoked",
                campaign_id=str(admission["campaign_id"]),
                work_item_id=str(admission["work_item_id"]),
                job_id=str(admission["tester_job_id"]),
                actor=revoked_by,
                event_data={
                    "admission_id": admission_id,
                    "reason": reason,
                },
                created_at=now,
            )
        return self.get_focused_test_admission(admission_id)

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
                """SELECT i.*, c.config_json, c.execution_mode
                   FROM work_items i JOIN campaigns c ON c.id = i.campaign_id
                   WHERE i.id = ? AND i.campaign_id = ?""",
                (work_item_id, campaign_id),
            ).fetchone()
            if item is None:
                raise NotFoundError("work item is absent from the requested campaign")
            if item["execution_mode"] == "focused_test_admission":
                raise TransitionConflict(
                    "focused-test-only campaign mode cannot provision another worktree"
                )
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

    def _resource_claim_plan(
        self,
        connection: sqlite3.Connection,
        job: sqlite3.Row,
        resources: Sequence[str],
    ) -> Optional[List[Dict[str, Any]]]:
        """Resolve exact lease slots or fail closed without mutating state."""

        plan: List[Dict[str, Any]] = []
        for value in resources:
            resource_key = str(value)
            definition: Optional[Dict[str, Any]] = None
            concurrency_limit = 1
            stripped_resource_key = resource_key.strip()
            if (
                stripped_resource_key.startswith(RESOURCE_DEFINITION_PREFIX)
                and stripped_resource_key != resource_key
            ):
                return None
            if resource_key.startswith(RESOURCE_DEFINITION_PREFIX):
                if RESOURCE_DEFINITION_ID_PATTERN.fullmatch(resource_key) is None:
                    return None
                row = connection.execute(
                    "SELECT * FROM resource_definitions WHERE id = ?",
                    (resource_key,),
                ).fetchone()
                if row is None or not bool(row["enabled"]):
                    return None
                try:
                    definition = self._validated_resource_definition_row(row)
                except StorageError:
                    return None
                if definition["campaign_id"] not in (None, job["campaign_id"]):
                    return None
                concurrency_limit = int(definition["policy"]["limit"])
            held_slots = {
                int(row["lease_slot"])
                for row in connection.execute(
                    """SELECT lease_slot FROM resource_leases
                       WHERE resource_key = ?""",
                    (resource_key,),
                ).fetchall()
            }
            lease_slot = next(
                (
                    slot
                    for slot in range(1, concurrency_limit + 1)
                    if slot not in held_slots
                ),
                None,
            )
            if lease_slot is None:
                return None
            plan.append(
                {
                    "resource_key": resource_key,
                    "lease_slot": lease_slot,
                    "resource_definition_id": (
                        None if definition is None else definition["id"]
                    ),
                    "definition": definition,
                }
            )
        return plan

    def _registered_job_resource_leases(
        self, connection: sqlite3.Connection, job_id: str
    ) -> List[sqlite3.Row]:
        return connection.execute(
            """SELECT r.* FROM resource_leases r
               WHERE r.job_id = ?
                 AND r.resource_definition_id IS NOT NULL
               ORDER BY r.resource_key, r.lease_slot""",
            (job_id,),
        ).fetchall()

    def _assert_registered_resource_fences(
        self,
        connection: sqlite3.Connection,
        job: Mapping[str, Any],
        now: float,
    ) -> None:
        rows = self._registered_job_resource_leases(
            connection, str(job["id"])
        )
        for lease in rows:
            definition_row = connection.execute(
                "SELECT * FROM resource_definitions WHERE id = ?",
                (lease["resource_definition_id"],),
            ).fetchone()
            if definition_row is None:
                raise LeaseConflict("registered resource definition disappeared")
            try:
                definition = self._validated_resource_definition_row(
                    definition_row
                )
            except StorageError as error:
                raise LeaseConflict(
                    "registered resource definition integrity changed"
                ) from error
            if (
                not bool(definition["enabled"])
                or definition["campaign_id"] not in (None, job["campaign_id"])
                or lease["resource_key"] != definition["id"]
                or lease["resource_identity_hash"] != definition["identity_hash"]
                or int(lease["lease_slot"]) > int(definition["policy"]["limit"])
                or lease["expires_at"] <= now
            ):
                raise LeaseConflict(
                    "registered resource definition or lease identity changed"
                )

    def _safe_resource_lease_records(
        self,
        connection: sqlite3.Connection,
        rows: Sequence[sqlite3.Row],
    ) -> List[Dict[str, Any]]:
        records = self._rows(rows)
        definitions: Dict[str, Optional[Dict[str, Any]]] = {}
        for record in records:
            definition_id = record.get("resource_definition_id")
            if definition_id is None:
                continue
            exact_id = str(definition_id)
            if exact_id not in definitions:
                definition_row = connection.execute(
                    "SELECT * FROM resource_definitions WHERE id = ?",
                    (exact_id,),
                ).fetchone()
                if definition_row is None:
                    definitions[exact_id] = None
                else:
                    try:
                        definitions[exact_id] = (
                            self._validated_resource_definition_row(
                                definition_row
                            )
                        )
                    except StorageError:
                        definitions[exact_id] = None
            definition = definitions[exact_id]
            record["resource_kind"] = (
                None if definition is None else definition["kind"]
            )
            record["resource_label"] = (
                None if definition is None else definition["label"]
            )
        return records

    def _append_resource_lease_events(
        self,
        connection: sqlite3.Connection,
        event_kind: str,
        leases: Sequence[Mapping[str, Any]],
        *,
        campaign_id: str,
        work_item_id: str,
        job_id: str,
        actor: Optional[str],
        created_at: float,
    ) -> None:
        for lease in leases:
            if lease["resource_definition_id"] is None:
                continue
            definition_row = connection.execute(
                "SELECT * FROM resource_definitions WHERE id = ?",
                (lease["resource_definition_id"],),
            ).fetchone()
            definition: Optional[Dict[str, Any]] = None
            if definition_row is not None:
                try:
                    definition = self._validated_resource_definition_row(
                        definition_row
                    )
                except StorageError:
                    definition = None
            event_data: Dict[str, Any] = {
                "resource_id": lease["resource_definition_id"],
                "lease_slot": lease["lease_slot"],
            }
            if definition is None:
                event_data["definition_status"] = "invalid"
            else:
                event_data.update(
                    {
                        "kind": definition["kind"],
                        "label": definition["label"],
                        "policy": definition["policy"],
                    }
                )
            self._append_event(
                connection,
                event_kind,
                campaign_id=campaign_id,
                work_item_id=work_item_id,
                job_id=job_id,
                actor=actor,
                event_data=event_data,
                created_at=created_at,
            )

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
                          c.execution_mode,
                          c.config_json AS campaign_config_json
                   FROM jobs j JOIN campaigns c ON c.id = j.campaign_id
                   JOIN work_items i ON i.id = j.work_item_id
                   WHERE j.status = 'pending' AND j.role = ? AND j.available_at <= ?
                     AND c.status = 'active' AND i.state = j.queued_item_state
                   ORDER BY j.priority DESC, j.created_at, j.id""",
                (role, now),
            ).fetchall()
            for job in candidates:
                admission_row: Optional[sqlite3.Row] = None
                if job["execution_mode"] == "focused_test_admission":
                    if role != "tester":
                        continue
                    admission_row = connection.execute(
                        """SELECT * FROM focused_test_admissions
                           WHERE tester_job_id = ? AND status = 'active'
                           ORDER BY admitted_at DESC, id DESC LIMIT 1""",
                        (job["id"],),
                    ).fetchone()
                    if admission_row is None:
                        continue
                    try:
                        self._assert_live_focused_test_admission(
                            connection, admission_row, job
                        )
                    except LeaseConflict:
                        continue
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
                resource_plan = self._resource_claim_plan(
                    connection, job, resources
                )
                if resource_plan is None:
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
                        focused_test_admission_id, started_at, heartbeat_at,
                        lease_expires_at)
                       VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?, ?, ?, ?)""",
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
                        None if admission_row is None else admission_row["id"],
                        now,
                        now,
                        expires_at,
                    ),
                )
                for resource in resource_plan:
                    connection.execute(
                        """INSERT INTO resource_leases
                           (resource_key, lease_slot, resource_definition_id,
                            resource_identity_hash, owner_id, job_id,
                            lease_token, acquired_at, heartbeat_at, expires_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            resource["resource_key"],
                            resource["lease_slot"],
                            resource["resource_definition_id"],
                            (
                                None
                                if resource["definition"] is None
                                else resource["definition"]["identity_hash"]
                            ),
                            worker_id,
                            job["id"],
                            token,
                            now,
                            now,
                            expires_at,
                        ),
                    )
                self._append_event(
                    connection, "job.claimed", campaign_id=job["campaign_id"],
                    work_item_id=job["work_item_id"], job_id=job["id"], actor=worker_id,
                    event_data={"attempt_id": attempt_id, "attempt_number": attempt_number,
                                "lease_token": token, "resources": resources,
                                "focused_test_admission_id": (
                                    None if admission_row is None else admission_row["id"]
                                ),
                                "from_state": job["queued_item_state"],
                                "to_state": job["active_item_state"]}, created_at=now
                )
                registered_leases = self._registered_job_resource_leases(
                    connection, str(job["id"])
                )
                self._append_resource_lease_events(
                    connection,
                    "resource.claimed",
                    registered_leases,
                    campaign_id=str(job["campaign_id"]),
                    work_item_id=str(job["work_item_id"]),
                    job_id=str(job["id"]),
                    actor=worker_id,
                    created_at=now,
                )
                claimed = connection.execute(
                    "SELECT * FROM jobs WHERE id = ?", (job["id"],)
                ).fetchone()
                result = self._row(claimed)
                result.update({"attempt_id": attempt_id, "attempt_number": attempt_number})
                resume_request = connection.execute(
                    """SELECT * FROM operator_controls
                       WHERE job_id = ? AND action = 'resume' AND status = 'pending'
                       ORDER BY requested_at, id LIMIT 1""",
                    (job["id"],),
                ).fetchone()
                if resume_request is not None:
                    source = connection.execute(
                        """SELECT * FROM attempts
                           WHERE id = ? AND job_id = ? AND status = 'interrupted'""",
                        (resume_request["source_attempt_id"], job["id"]),
                    ).fetchone()
                    resources_json, resources_hash = self._operator_resource_snapshot(job)
                    unresolved = connection.execute(
                        """SELECT 1 FROM external_processes
                           WHERE attempt_id = ? AND state != 'stopped' LIMIT 1""",
                        (resume_request["source_attempt_id"],),
                    ).fetchone()
                    stopped_provider_process = connection.execute(
                        """SELECT 1 FROM external_processes
                           WHERE attempt_id = ? AND state = 'stopped'
                             AND provider = ? LIMIT 1""",
                        (
                            resume_request["source_attempt_id"],
                            resume_request["expected_provider"],
                        ),
                    ).fetchone()
                    if (
                        source is None
                        or source["attempt_number"] != attempt_number - 1
                        or source["external_provider"]
                        != resume_request["expected_provider"]
                        or source["external_session_id"]
                        != resume_request["expected_session_id"]
                        or source["managed_worktree_id"]
                        != resume_request["expected_worktree_id"]
                        or source["managed_worktree_generation"]
                        != resume_request["expected_worktree_generation"]
                        or resume_request["expected_resources_json"]
                        != resources_json
                        or resume_request["expected_resources_sha256"]
                        != resources_hash
                        or unresolved is not None
                        or stopped_provider_process is None
                    ):
                        raise LeaseConflict(
                            "operator resume authorization changed before claim"
                        )
                    changed = connection.execute(
                        """UPDATE operator_controls
                           SET status = 'applied', target_attempt_id = ?, applied_at = ?
                           WHERE id = ? AND status = 'pending'""",
                        (attempt_id, now, resume_request["id"]),
                    ).rowcount
                    if changed != 1:
                        raise LeaseConflict(
                            "operator resume authorization was consumed concurrently"
                        )
                    self._append_event(
                        connection,
                        "operator.resume_applied",
                        campaign_id=job["campaign_id"],
                        work_item_id=job["work_item_id"],
                        job_id=job["id"],
                        actor=resume_request["requested_by"],
                        event_data={
                            "request_id": resume_request["id"],
                            "source_attempt_id": source["id"],
                            "target_attempt_id": attempt_id,
                            "provider": resume_request["expected_provider"],
                            "session_id": resume_request["expected_session_id"],
                        },
                        created_at=now,
                    )
                    result.update(
                        {
                            "resume_external_provider": resume_request[
                                "expected_provider"
                            ],
                            "resume_external_session_id": resume_request[
                                "expected_session_id"
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
            self._assert_attempt_focused_test_admission(connection, job)
            self._assert_registered_resource_fences(connection, job, now)
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

    @staticmethod
    def _operator_resource_snapshot(job: Mapping[str, Any]) -> tuple[str, str]:
        resources = _load(job["required_resources_json"], [])
        raw = _dump(resources)
        return raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def request_job_interrupt(
        self,
        job_id: str,
        lease_token: str,
        *,
        requested_by: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Durably request cancellation of one exact live job/process fence."""

        requested_by = _operator_text(requested_by, "identity", 256)
        reason = _operator_text(reason, "interrupt reason", 4096)
        if (
            not isinstance(job_id, str)
            or job_id != job_id.strip()
            or not job_id
            or not isinstance(lease_token, str)
            or lease_token != lease_token.strip()
            or not lease_token
        ):
            raise ValueError("operator interrupt requires exact job and lease IDs")
        with self._transaction() as connection:
            now = self._clock()
            job = connection.execute(
                "SELECT * FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if job is None:
                raise NotFoundError("job %s not found" % job_id)
            if (
                job["status"] != "running"
                or job["lease_token"] != lease_token
                or job["lease_expires_at"] <= now
                or not job["lease_owner"]
                or not job["current_attempt_id"]
            ):
                raise LeaseConflict("operator interrupt fence is absent or stale")
            existing = connection.execute(
                """SELECT * FROM operator_controls
                   WHERE job_id = ? AND action = 'interrupt' AND status = 'pending'""",
                (job_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["source_attempt_id"] == job["current_attempt_id"]
                    and existing["expected_lease_token"] == lease_token
                    and existing["requested_by"] == requested_by
                    and existing["reason"] == reason
                ):
                    return self._row(existing)  # type: ignore[return-value]
                raise LeaseConflict(
                    "another operator interrupt is already pending for this job"
                )
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ? AND status = 'running'",
                (job["current_attempt_id"],),
            ).fetchone()
            if attempt is None:
                raise LeaseConflict("operator interrupt attempt is absent or stale")
            external = connection.execute(
                """SELECT * FROM external_processes
                   WHERE attempt_id = ? AND state != 'stopped'
                   ORDER BY recorded_at DESC, id DESC LIMIT 1""",
                (attempt["id"],),
            ).fetchone()
            resources_json, resources_hash = self._operator_resource_snapshot(job)
            request_id = _id()
            connection.execute(
                """INSERT INTO operator_controls
                   (id, job_id, source_attempt_id, action, status, requested_by,
                    reason, expected_lease_owner, expected_lease_token,
                    expected_provider, expected_session_id,
                    expected_process_id, expected_process_group_id,
                    expected_process_start_seconds,
                    expected_process_start_microseconds,
                    expected_process_executable, expected_worktree_id,
                    expected_worktree_generation, expected_resources_json,
                    expected_resources_sha256, requested_at)
                   VALUES (?, ?, ?, 'interrupt', 'pending', ?, ?, ?, ?, ?, ?,
                           ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    request_id,
                    job_id,
                    attempt["id"],
                    requested_by,
                    reason,
                    job["lease_owner"],
                    lease_token,
                    attempt["external_provider"],
                    attempt["external_session_id"],
                    None if external is None else external["process_id"],
                    None if external is None else external["process_group_id"],
                    None if external is None else external["start_seconds"],
                    None if external is None else external["start_microseconds"],
                    None if external is None else external["kernel_executable"],
                    attempt["managed_worktree_id"],
                    attempt["managed_worktree_generation"],
                    resources_json,
                    resources_hash,
                    now,
                ),
            )
            self._append_event(
                connection,
                "operator.interrupt_requested",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job_id,
                actor=requested_by,
                event_data={
                    "request_id": request_id,
                    "attempt_id": attempt["id"],
                    "process_id": None if external is None else external["process_id"],
                    "process_group_id": (
                        None if external is None else external["process_group_id"]
                    ),
                    "reason": reason,
                },
                created_at=now,
            )
            row = connection.execute(
                "SELECT * FROM operator_controls WHERE id = ?", (request_id,)
            ).fetchone()
            return self._row(row)  # type: ignore[return-value]

    def _assert_operator_interrupt_request(
        self,
        connection: sqlite3.Connection,
        request_id: str,
        job: sqlite3.Row,
        worker_id: str,
        lease_token: str,
        *,
        allow_stopped_process: bool = False,
    ) -> sqlite3.Row:
        request = connection.execute(
            """SELECT * FROM operator_controls
               WHERE id = ? AND action = 'interrupt' AND status = 'pending'""",
            (request_id,),
        ).fetchone()
        if request is None:
            raise LeaseConflict("operator interrupt request is absent or stale")
        resources_json, resources_hash = self._operator_resource_snapshot(job)
        if (
            request["job_id"] != job["id"]
            or request["source_attempt_id"] != job["current_attempt_id"]
            or request["expected_lease_owner"] != worker_id
            or request["expected_lease_token"] != lease_token
            or request["expected_worktree_id"] != job["managed_worktree_id"]
            or request["expected_resources_json"] != resources_json
            or request["expected_resources_sha256"] != resources_hash
        ):
            raise LeaseConflict("operator interrupt request no longer matches its job fence")
        attempt = connection.execute(
            "SELECT * FROM attempts WHERE id = ? AND status = 'running'",
            (job["current_attempt_id"],),
        ).fetchone()
        if (
            attempt is None
            or attempt["managed_worktree_id"] != request["expected_worktree_id"]
            or attempt["managed_worktree_generation"]
            != request["expected_worktree_generation"]
            or attempt["external_provider"] != request["expected_provider"]
            or attempt["external_session_id"] != request["expected_session_id"]
        ):
            raise LeaseConflict("operator interrupt attempt identity changed")
        if allow_stopped_process and request["expected_process_id"] is not None:
            external = connection.execute(
                """SELECT * FROM external_processes
                   WHERE attempt_id = ? AND process_id = ?
                     AND process_group_id = ?
                   ORDER BY recorded_at DESC, id DESC LIMIT 1""",
                (
                    attempt["id"],
                    request["expected_process_id"],
                    request["expected_process_group_id"],
                ),
            ).fetchone()
            if external is None or external["state"] not in ("active", "stopped"):
                raise LeaseConflict(
                    "operator interrupt process identity is unresolved"
                )
            if external["state"] == "stopped":
                replacement = connection.execute(
                    """SELECT 1 FROM external_processes
                       WHERE attempt_id = ? AND state != 'stopped'
                         AND id != ? LIMIT 1""",
                    (attempt["id"], external["id"]),
                ).fetchone()
                if replacement is not None:
                    raise LeaseConflict(
                        "operator interrupt cannot cross into a replacement process"
                    )
        else:
            external = connection.execute(
                """SELECT * FROM external_processes
                   WHERE attempt_id = ? AND state != 'stopped'
                   ORDER BY recorded_at DESC, id DESC LIMIT 1""",
                (attempt["id"],),
            ).fetchone()
        expected_process = (
            request["expected_process_id"],
            request["expected_process_group_id"],
            request["expected_process_start_seconds"],
            request["expected_process_start_microseconds"],
            request["expected_process_executable"],
        )
        observed_process = (
            None,
            None,
            None,
            None,
            None,
        ) if external is None else (
            external["process_id"],
            external["process_group_id"],
            external["start_seconds"],
            external["start_microseconds"],
            external["kernel_executable"],
        )
        if expected_process != observed_process:
            raise LeaseConflict("operator interrupt process identity changed")
        return request

    def poll_operator_interrupt(
        self, job_id: str, worker_id: str, lease_token: str
    ) -> Optional[Dict[str, Any]]:
        """Return only a pending request matching the exact current fence."""

        with self._lock:
            now = self._clock()
            job = self._assert_live_lease(
                self._connection, job_id, worker_id, lease_token, now
            )
            request = self._connection.execute(
                """SELECT id FROM operator_controls
                   WHERE job_id = ? AND action = 'interrupt' AND status = 'pending'""",
                (job_id,),
            ).fetchone()
            if request is None:
                return None
            validated = self._assert_operator_interrupt_request(
                self._connection,
                str(request["id"]),
                job,
                worker_id,
                lease_token,
                allow_stopped_process=True,
            )
            return self._row(validated)

    @staticmethod
    def _assert_no_pending_operator_interrupt(
        connection: sqlite3.Connection, job_id: str
    ) -> None:
        pending = connection.execute(
            """SELECT 1 FROM operator_controls
               WHERE job_id = ? AND action = 'interrupt'
                 AND status = 'pending' LIMIT 1""",
            (job_id,),
        ).fetchone()
        if pending is not None:
            raise LeaseConflict(
                "pending operator interrupt must be resolved before this mutation"
            )

    def request_job_resume(
        self,
        job_id: str,
        source_attempt_id: str,
        provider: str,
        session_id: str,
        *,
        requested_by: str,
        reason: str = "resume exact persisted external session",
    ) -> Dict[str, Any]:
        """Authorize one exact interrupted session for the next claim only."""

        requested_by = _operator_text(requested_by, "identity", 256)
        reason = _operator_text(reason, "resume reason", 4096)
        for name, value, limit in (
            ("job id", job_id, 512),
            ("source attempt id", source_attempt_id, 512),
            ("provider", provider, 64),
            ("session id", session_id, 512),
        ):
            if (
                not isinstance(value, str)
                or value != value.strip()
                or not value
                or len(value) > limit
            ):
                raise ValueError("operator resume %s must be byte-exact" % name)
        with self._transaction() as connection:
            now = self._clock()
            job = connection.execute(
                "SELECT * FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if (
                job is None
                or job["status"] != "pending"
                or job["current_attempt_id"] is not None
            ):
                raise LeaseConflict("operator resume requires one pending logical job")
            attempt = connection.execute(
                """SELECT * FROM attempts
                   WHERE id = ? AND job_id = ? AND status = 'interrupted'""",
                (source_attempt_id, job_id),
            ).fetchone()
            if (
                attempt is None
                or attempt["attempt_number"] != job["attempt_count"]
                or attempt["external_provider"] != provider
                or attempt["external_session_id"] != session_id
            ):
                raise LeaseConflict("operator resume session identity is stale or mismatched")
            unresolved = connection.execute(
                """SELECT 1 FROM external_processes
                   WHERE attempt_id = ? AND state != 'stopped' LIMIT 1""",
                (source_attempt_id,),
            ).fetchone()
            if unresolved is not None:
                raise LeaseConflict("operator resume source process is not durably stopped")
            stopped_provider_process = connection.execute(
                """SELECT 1 FROM external_processes
                   WHERE attempt_id = ? AND state = 'stopped'
                     AND provider = ? LIMIT 1""",
                (source_attempt_id, provider),
            ).fetchone()
            if stopped_provider_process is None:
                raise LeaseConflict(
                    "operator resume source lacks exact stopped provider process proof"
                )
            resources_json, resources_hash = self._operator_resource_snapshot(job)
            request_id = _id()
            try:
                connection.execute(
                    """INSERT INTO operator_controls
                       (id, job_id, source_attempt_id, action, status,
                        requested_by, reason, expected_provider,
                        expected_session_id, expected_worktree_id,
                        expected_worktree_generation, expected_resources_json,
                        expected_resources_sha256, requested_at)
                       VALUES (?, ?, ?, 'resume', 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        request_id,
                        job_id,
                        source_attempt_id,
                        requested_by,
                        reason,
                        provider,
                        session_id,
                        attempt["managed_worktree_id"],
                        attempt["managed_worktree_generation"],
                        resources_json,
                        resources_hash,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise LeaseConflict(
                    "another operator resume is already pending for this job"
                ) from error
            self._append_event(
                connection,
                "operator.resume_requested",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job_id,
                actor=requested_by,
                event_data={
                    "request_id": request_id,
                    "source_attempt_id": source_attempt_id,
                    "provider": provider,
                    "session_id": session_id,
                    "reason": reason,
                },
                created_at=now,
            )
            row = connection.execute(
                "SELECT * FROM operator_controls WHERE id = ?", (request_id,)
            ).fetchone()
            return self._row(row)  # type: ignore[return-value]

    def list_operator_controls(
        self, *, job_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM operator_controls"
        parameters: Sequence[Any] = ()
        if job_id is not None:
            sql += " WHERE job_id = ?"
            parameters = (job_id,)
        sql += " ORDER BY requested_at, id"
        with self._lock:
            return self._rows(self._connection.execute(sql, parameters).fetchall())

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
            self._assert_attempt_focused_test_admission(connection, job)
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?",
                (job["current_attempt_id"],),
            ).fetchone()
            if attempt is None or attempt["status"] != "running":
                raise LeaseConflict("current running attempt is absent")

            resume_authorization = connection.execute(
                """SELECT source_attempt_id, expected_provider,
                          expected_session_id
                   FROM operator_controls
                   WHERE target_attempt_id = ? AND action = 'resume'
                     AND status = 'applied'""",
                (attempt["id"],),
            ).fetchone()
            if resume_authorization is not None and (
                resume_authorization["expected_provider"] != provider
                or resume_authorization["expected_session_id"] != session_id
            ):
                raise LeaseConflict(
                    "external session does not match the exact resume authorization"
                )

            prior_same_job = connection.execute(
                """SELECT 1 FROM attempts
                   WHERE external_provider = ? AND external_session_id = ?
                     AND job_id = ? AND id != ? LIMIT 1""",
                (provider, session_id, job_id, attempt["id"]),
            ).fetchone()
            if prior_same_job is not None:
                if resume_authorization is None:
                    raise LeaseConflict(
                        "reusing an external session requires exact operator resume authorization"
                    )
                authorized_source = connection.execute(
                    """SELECT 1 FROM attempts
                       WHERE id = ? AND job_id = ?
                         AND external_provider = ? AND external_session_id = ?
                       LIMIT 1""",
                    (
                        resume_authorization["source_attempt_id"],
                        job_id,
                        provider,
                        session_id,
                    ),
                ).fetchone()
                if authorized_source is None:
                    raise LeaseConflict(
                        "external session reuse does not match its authorized source"
                    )

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
            self._assert_attempt_focused_test_admission(connection, job)
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?",
                (job["current_attempt_id"],),
            ).fetchone()
            if attempt is None or attempt["status"] != "running":
                raise LeaseConflict("current running attempt is absent")
            external = connection.execute(
                """SELECT * FROM external_processes
                   WHERE attempt_id = ? AND state != 'stopped'
                   ORDER BY recorded_at DESC, id DESC LIMIT 1""",
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
                   WHERE id = ? AND status = 'running'""",
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

    def authorize_database_query_execution(
        self,
        execution_id: str,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> Dict[str, Any]:
        execution_id = self._exact_collector_id(execution_id, "database execution")
        with self._transaction() as connection:
            now = self._clock()
            execution = connection.execute(
                "SELECT * FROM database_query_executions WHERE id = ?",
                (execution_id,),
            ).fetchone()
            if execution is None or execution["status"] != "prepared":
                raise LeaseConflict("database execution is not ready for query")
            job = self._assert_live_lease(connection, job_id, worker_id, lease_token, now)
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (job["current_attempt_id"],)
            ).fetchone()
            if attempt is None or execution["attempt_id"] != attempt["id"]:
                raise LeaseConflict("database execution belongs to another attempt")
            self._assert_attempt_collector_admission(connection, job, attempt, "database")
            plan_row = connection.execute(
                "SELECT * FROM database_query_plans WHERE id = ?", (execution["plan_id"],)
            ).fetchone()
            if plan_row is None:
                raise LeaseConflict("database query plan disappeared")
            plan = self._validated_database_plan_row(connection, plan_row)
            return self._database_execution_contract(self._row(execution), plan, connection)

    @contextmanager
    def browser_guardian_release_fence(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        process_id: int,
        process_group_id: int,
        owner_uid: int,
        kernel_executable: str,
        start_seconds: int,
        start_microseconds: int,
        target_executable: str,
    ) -> Iterator[None]:
        """Serialize exact browser guardian release against admission revocation."""

        with self._transaction() as connection:
            now = self._clock()
            job = self._assert_live_lease(connection, job_id, worker_id, lease_token, now)
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (job["current_attempt_id"],)
            ).fetchone()
            if attempt is None:
                raise LeaseConflict("browser guardian release has no current attempt")
            self._assert_attempt_collector_admission(connection, job, attempt, "browser")
            execution = connection.execute(
                """SELECT * FROM browser_evidence_executions
                   WHERE attempt_id = ? AND job_id = ? AND status = 'prepared'""",
                (job["current_attempt_id"], job["id"]),
            ).fetchone()
            external = connection.execute(
                """SELECT * FROM external_processes
                   WHERE attempt_id = ? AND job_id = ? AND provider = 'browser_evidence'
                     AND state = 'active'
                   ORDER BY recorded_at DESC, id DESC LIMIT 1""",
                (job["current_attempt_id"], job["id"]),
            ).fetchone()
            if execution is None or external is None:
                raise LeaseConflict(
                    "browser guardian release lacks prepared execution and process authority"
                )
            expected_process = (
                int(process_id), int(process_group_id), int(owner_uid),
                str(kernel_executable), int(start_seconds), int(start_microseconds),
                str(target_executable),
            )
            persisted_process = (
                int(external["process_id"]), int(external["process_group_id"]),
                int(external["owner_uid"]), str(external["kernel_executable"]),
                int(external["start_seconds"]), int(external["start_microseconds"]),
                str(external["target_executable"]),
            )
            if expected_process != persisted_process or process_id != process_group_id:
                raise LeaseConflict("browser guardian release process identity changed")
            yield

    def focused_test_guardian_release_fence(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        process_id: int,
        process_group_id: int,
        owner_uid: int,
        kernel_executable: str,
        start_seconds: int,
        start_microseconds: int,
        target_executable: str,
    ) -> Iterator[None]:
        """Serialize the exact focused guardian release against revocation.

        The caller writes the guardian barrier while this transaction remains
        open. A revocation transaction therefore either commits first and
        denies release, or commits after the already-authorized release. There
        is no check-then-release interval in which revocation can be lost.
        """

        with self._transaction() as connection:
            now = self._clock()
            job = self._assert_live_lease(
                connection, job_id, worker_id, lease_token, now
            )
            admission = self._assert_attempt_focused_test_admission(
                connection, job
            )
            if admission is None:
                raise LeaseConflict(
                    "focused-test guardian release requires an exact admission"
                )
            execution = connection.execute(
                """SELECT * FROM focused_test_executions
                   WHERE attempt_id = ? AND job_id = ? AND status = 'prepared'""",
                (job["current_attempt_id"], job["id"]),
            ).fetchone()
            external = connection.execute(
                """SELECT * FROM external_processes
                   WHERE attempt_id = ? AND job_id = ? AND provider = 'focused_test'
                     AND state = 'active'
                   ORDER BY recorded_at DESC, id DESC LIMIT 1""",
                (job["current_attempt_id"], job["id"]),
            ).fetchone()
            if execution is None or external is None:
                raise LeaseConflict(
                    "focused-test guardian release lacks prepared execution and process authority"
                )
            expected_process = (
                int(process_id),
                int(process_group_id),
                int(owner_uid),
                str(kernel_executable),
                int(start_seconds),
                int(start_microseconds),
                str(target_executable),
            )
            persisted_process = (
                int(external["process_id"]),
                int(external["process_group_id"]),
                int(external["owner_uid"]),
                str(external["kernel_executable"]),
                int(external["start_seconds"]),
                int(external["start_microseconds"]),
                str(external["target_executable"]),
            )
            if (
                expected_process != persisted_process
                or process_id != process_group_id
                or target_executable != execution["sandbox_executable_path"]
            ):
                raise LeaseConflict(
                    "focused-test guardian release process identity changed"
                )
            yield

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
            matching_identities = int(
                connection.execute(
                    """SELECT COUNT(*) FROM external_processes
                       WHERE attempt_id = ? AND process_id = ?
                         AND process_group_id = ?""",
                    (
                        job["current_attempt_id"],
                        process_id,
                        process_group_id,
                    ),
                ).fetchone()[0]
            )
            if matching_identities != 1:
                raise LeaseConflict(
                    "external process PID reuse is ambiguous without exact birth identity"
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
                """SELECT * FROM external_processes
                   WHERE attempt_id = ? AND process_id = ?
                     AND process_group_id = ? AND state = 'stopped'
                   ORDER BY recorded_at DESC, id DESC LIMIT 1""",
                (job["current_attempt_id"], process_id, process_group_id),
            ).fetchone()
            return self._row(recorded)  # type: ignore[return-value]

    @staticmethod
    def _assert_external_process_stopped(
        connection: sqlite3.Connection, job: sqlite3.Row
    ) -> None:
        external = connection.execute(
            """SELECT state FROM external_processes
               WHERE attempt_id = ? AND state != 'stopped'
               ORDER BY recorded_at DESC, id DESC LIMIT 1""",
            (job["current_attempt_id"],),
        ).fetchone()
        attempt = connection.execute(
            "SELECT external_process_id FROM attempts WHERE id = ?",
            (job["current_attempt_id"],),
        ).fetchone()
        if attempt is None:
            raise LeaseConflict("current attempt is absent")
        if external is None and attempt["external_process_id"] is not None:
            latest = connection.execute(
                """SELECT state FROM external_processes
                   WHERE attempt_id = ? AND process_id = ?
                   ORDER BY recorded_at DESC, id DESC LIMIT 1""",
                (job["current_attempt_id"], attempt["external_process_id"]),
            ).fetchone()
            if latest is None:
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
            supplied_resolved = supplied.resolve(strict=True)
        except FileNotFoundError as error:
            raise ValueError("focused Python executable does not exist") from error
        if str(supplied) != str(supplied_resolved):
            raise ValueError("focused Python executable must already be fully resolved")
        resolved = direct_python_executable(supplied_resolved)
        details = resolved.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink < 1
            or not os.access(str(resolved), os.X_OK)
        ):
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
    def _focused_sandbox_executable_identity(
        executable_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        resolved = sandbox_executable()
        if executable_path is not None and executable_path != str(resolved):
            raise ValueError("focused Seatbelt executable path changed")
        details = resolved.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0
            or details.st_mode & 0o022
            or not os.access(str(resolved), os.X_OK)
        ):
            raise ValueError("focused Seatbelt executable identity is unsafe")
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
        sandbox = self._focused_sandbox_executable_identity()
        interpreter_root = python_runtime_root(Path(str(executable["path"])))
        interpreter_root_hash = python_runtime_sha256(interpreter_root)
        interpreter_root_details = interpreter_root.lstat()
        if (
            not stat.S_ISDIR(interpreter_root_details.st_mode)
            or interpreter_root_details.st_mode & 0o022
        ):
            raise ValueError(
                "focused Python runtime root cannot be group/world writable"
            )
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
            required_gates = _load(item["required_gates_json"], [])
            if required_gates not in (
                ["focused_tests"],
                list(DEFAULT_REQUIRED_GATES),
            ):
                raise ValueError(
                    "the focused collector supports only its gate or the fixed "
                    "focused/browser/database pipeline"
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
                    "sandbox_policy_version": DARWIN_SANDBOX_POLICY_VERSION,
                    "sandbox_executable_path": sandbox["path"],
                    "sandbox_executable_device": sandbox["device"],
                    "sandbox_executable_inode": sandbox["inode"],
                    "sandbox_executable_owner_uid": sandbox["owner_uid"],
                    "sandbox_executable_mode": sandbox["mode"],
                    "sandbox_executable_sha256": sandbox["sha256"],
                    "python_runtime_root": str(interpreter_root),
                    "python_runtime_sha256": interpreter_root_hash,
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
                    and not (
                        previous_plan["sandbox_policy_version"] is None
                        and (
                            name.startswith("executable_")
                            or name.startswith("sandbox_")
                            or name.startswith("python_runtime_")
                        )
                    )
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
                    executable_sha256, sandbox_policy_version,
                    sandbox_executable_path, sandbox_executable_device,
                    sandbox_executable_inode, sandbox_executable_owner_uid,
                    sandbox_executable_mode, sandbox_executable_sha256,
                    python_runtime_root, python_runtime_sha256,
                    test_file, selector, environment_json,
                    environment_sha256, workspace_manifest_json,
                    workspace_manifest_sha256, runtime_root, timeout_seconds,
                    output_limit_bytes, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                           ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                    DARWIN_SANDBOX_POLICY_VERSION,
                    sandbox["path"],
                    sandbox["device"],
                    sandbox["inode"],
                    sandbox["owner_uid"],
                    sandbox["mode"],
                    sandbox["sha256"],
                    str(interpreter_root),
                    interpreter_root_hash,
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
                    "sandbox_policy_version": DARWIN_SANDBOX_POLICY_VERSION,
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
                attempt_admission = self._assert_attempt_focused_test_admission(
                    connection, job
                )
                if attempt_admission is None:
                    raise LeaseConflict(
                        "authoritative focused execution requires an exact admission"
                    )
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
                required_gates = _load(item["required_gates_json"], [])
                if required_gates not in (
                    ["focused_tests"],
                    list(DEFAULT_REQUIRED_GATES),
                ):
                    raise ValueError(
                        "the focused collector supports only its gate or the fixed "
                        "focused/browser/database pipeline"
                    )
                plan = connection.execute(
                    """SELECT * FROM focused_test_plans
                       WHERE id = ? AND work_item_id = ?""",
                    (
                        attempt_admission["focused_test_plan_id"],
                        job["work_item_id"],
                    ),
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
                if plan["sandbox_policy_version"] != DARWIN_SANDBOX_POLICY_VERSION:
                    raise LeaseConflict(
                        "focused test plan lacks the current trusted sandbox policy"
                    )
                sandbox = self._focused_sandbox_executable_identity(
                    str(plan["sandbox_executable_path"])
                )
                expected_sandbox = {
                    "path": str(plan["sandbox_executable_path"]),
                    "device": int(plan["sandbox_executable_device"]),
                    "inode": int(plan["sandbox_executable_inode"]),
                    "owner_uid": int(plan["sandbox_executable_owner_uid"]),
                    "mode": int(plan["sandbox_executable_mode"]),
                    "sha256": str(plan["sandbox_executable_sha256"]),
                }
                if sandbox != expected_sandbox:
                    raise LeaseConflict("focused Seatbelt executable identity changed")
                interpreter_root = python_runtime_root(
                    Path(str(executable["path"]))
                )
                interpreter_root_hash = python_runtime_sha256(interpreter_root)
                if (
                    str(interpreter_root) != plan["python_runtime_root"]
                    or interpreter_root_hash != plan["python_runtime_sha256"]
                ):
                    raise LeaseConflict("focused Python runtime changed")
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
                if self._paths_overlap(interpreter_root, cwd) or self._paths_overlap(
                    interpreter_root, repository_path
                ):
                    raise LeaseConflict(
                        "focused Python runtime root overlaps a target repository"
                    )
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

                test_command = [
                    executable["path"],
                    "-I",
                    "-B",
                    str(test_path),
                    str(plan["selector"]),
                    "-v",
                ]
                sandbox_profile = build_focused_sandbox_profile(
                    test_executable=Path(str(executable["path"])),
                    runtime_read_root=interpreter_root,
                    workspace=cwd,
                    run_parent=run_parent,
                )
                command = list(
                    build_focused_sandbox_command(
                        Path(str(sandbox["path"])), sandbox_profile, test_command
                    )
                )
                command_hash = hashlib.sha256(_dump(command).encode("utf-8")).hexdigest()
                test_command_hash = hashlib.sha256(
                    _dump(test_command).encode("utf-8")
                ).hexdigest()
                sandbox_profile_hash = focused_sandbox_profile_sha256(
                    sandbox_profile
                )
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
                        sandbox_policy_version, sandbox_executable_path,
                        sandbox_executable_device, sandbox_executable_inode,
                        sandbox_executable_owner_uid, sandbox_executable_mode,
                        sandbox_executable_sha256, python_runtime_root,
                        python_runtime_sha256,
                        sandbox_profile, sandbox_profile_sha256,
                        test_file, selector, test_command_argv_json,
                        test_command_argv_sha256, command_argv_json, command_argv_sha256,
                        environment_json, environment_sha256, cwd, cwd_device,
                        cwd_inode, cwd_owner_uid, cwd_mode,
                        workspace_manifest_before_json,
                        workspace_manifest_before_sha256, run_parent,
                        artifact_directory, stdout_path, stderr_path,
                        timeout_seconds, output_limit_bytes, prepared_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?, ?, ?, ?, ?,
                               ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                               ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                        DARWIN_SANDBOX_POLICY_VERSION,
                        sandbox["path"],
                        sandbox["device"],
                        sandbox["inode"],
                        sandbox["owner_uid"],
                        sandbox["mode"],
                        sandbox["sha256"],
                        str(interpreter_root),
                        interpreter_root_hash,
                        sandbox_profile,
                        sandbox_profile_hash,
                        plan["test_file"],
                        plan["selector"],
                        _dump(test_command),
                        test_command_hash,
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
    def _assert_focused_sandbox_binding(execution: sqlite3.Row) -> None:
        if execution["sandbox_policy_version"] != DARWIN_SANDBOX_POLICY_VERSION:
            raise LeaseConflict("focused execution lacks trusted Seatbelt proof")
        sandbox = SQLiteStore._focused_sandbox_executable_identity(
            str(execution["sandbox_executable_path"])
        )
        expected_sandbox = {
            "path": execution["sandbox_executable_path"],
            "device": execution["sandbox_executable_device"],
            "inode": execution["sandbox_executable_inode"],
            "owner_uid": execution["sandbox_executable_owner_uid"],
            "mode": execution["sandbox_executable_mode"],
            "sha256": execution["sandbox_executable_sha256"],
        }
        if sandbox != expected_sandbox:
            raise LeaseConflict("focused Seatbelt executable changed after preparation")

        executable = SQLiteStore._focused_executable_identity(
            str(execution["executable_path"])
        )
        expected_executable = {
            "path": execution["executable_path"],
            "device": execution["executable_device"],
            "inode": execution["executable_inode"],
            "owner_uid": execution["executable_owner_uid"],
            "mode": execution["executable_mode"],
            "sha256": execution["executable_sha256"],
        }
        if executable != expected_executable:
            raise LeaseConflict("focused Python executable changed after preparation")
        interpreter_root = python_runtime_root(Path(str(executable["path"])))
        if (
            str(interpreter_root) != execution["python_runtime_root"]
            or python_runtime_sha256(interpreter_root)
            != execution["python_runtime_sha256"]
        ):
            raise LeaseConflict("focused Python runtime changed after preparation")

        cwd = Path(str(execution["cwd"]))
        run_parent = Path(str(execution["run_parent"]))
        expected_profile = build_focused_sandbox_profile(
            test_executable=Path(str(executable["path"])),
            runtime_read_root=interpreter_root,
            workspace=cwd,
            run_parent=run_parent,
        )
        if (
            execution["sandbox_profile"] != expected_profile
            or execution["sandbox_profile_sha256"]
            != focused_sandbox_profile_sha256(expected_profile)
        ):
            raise LeaseConflict("focused Seatbelt profile changed after preparation")
        expected_test_command = [
            executable["path"],
            "-I",
            "-B",
            str(cwd / str(execution["test_file"])),
            str(execution["selector"]),
            "-v",
        ]
        if (
            _load(execution["test_command_argv_json"], []) != expected_test_command
            or execution["test_command_argv_sha256"]
            != hashlib.sha256(_dump(expected_test_command).encode("utf-8")).hexdigest()
        ):
            raise LeaseConflict("focused sandboxed test command changed")
        expected_command = list(
            build_focused_sandbox_command(
                Path(str(sandbox["path"])), expected_profile, expected_test_command
            )
        )
        if (
            _load(execution["command_argv_json"], []) != expected_command
            or execution["command_argv_sha256"]
            != hashlib.sha256(_dump(expected_command).encode("utf-8")).hexdigest()
        ):
            raise LeaseConflict("focused Seatbelt launch command changed")

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
        *,
        block_admitted_red: bool,
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
                    "sandbox_policy_version": execution["sandbox_policy_version"],
                    "sandbox_profile_sha256": execution["sandbox_profile_sha256"],
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
                    "sandbox_policy_version": execution["sandbox_policy_version"],
                    "sandbox_profile_sha256": execution["sandbox_profile_sha256"],
                },
            },
        ]
        if not passed and block_admitted_red:
            return {
                "schema_version": 1,
                "item_id": execution["work_item_id"],
                "outcome": "blocked",
                "summary": (
                    "The admitted focused test failed; this tester-only authority "
                    "cannot launch a fixer."
                ),
                "gate_proofs": [],
                "failure_summary": None,
                "blocker": {
                    "kind": "execution",
                    "summary": (
                        "The admitted focused test failed and no authorized fixer "
                        "path exists in this campaign mode."
                    ),
                    "next_action": (
                        "Create a separately approved pre-launch campaign and "
                        "repository admission before starting a new fix cycle."
                    ),
                    "evidence": evidence,
                },
            }
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
            """SELECT managed_worktree_generation, focused_test_admission_id
               FROM attempts WHERE id = ?""",
            (job["current_attempt_id"],),
        ).fetchone()
        if (
            attempt is None
            or execution["managed_worktree_generation"]
            != attempt["managed_worktree_generation"]
        ):
            raise LeaseConflict("focused execution worktree generation changed")
        external = connection.execute(
            """SELECT * FROM external_processes
               WHERE attempt_id = ? AND provider = 'focused_test'
               ORDER BY recorded_at DESC, id DESC LIMIT 1""",
            (job["current_attempt_id"],),
        ).fetchone()
        if (
            external is None
            or external["provider"] != "focused_test"
            or external["state"] != "stopped"
            or external["target_executable"]
            != execution["sandbox_executable_path"]
        ):
            raise LeaseConflict(
                "focused execution requires its exact durably stopped process"
            )
        self._assert_focused_sandbox_binding(execution)
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
            execution_data,
            stdout_artifact,
            stderr_artifact,
            block_admitted_red=attempt["focused_test_admission_id"] is not None,
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
            attempt_admission = self._assert_attempt_focused_test_admission(
                connection, job
            )
            if attempt_admission is None:
                raise LeaseConflict(
                    "authoritative focused execution requires an exact admission"
                )
            execution = connection.execute(
                "SELECT * FROM focused_test_executions WHERE attempt_id = ?",
                (job["current_attempt_id"],),
            ).fetchone()
            if execution is None or execution["status"] != "prepared":
                raise LeaseConflict("current tester attempt has no prepared focused execution")
            self._assert_focused_sandbox_binding(execution)

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
                """SELECT * FROM external_processes
                   WHERE attempt_id = ? AND provider = 'focused_test'
                   ORDER BY recorded_at DESC, id DESC LIMIT 1""",
                (job["current_attempt_id"],),
            ).fetchone()
            if (
                external is None
                or external["provider"] != "focused_test"
                or external["state"] != "stopped"
                or external["target_executable"]
                != execution["sandbox_executable_path"]
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
                                "sandbox_policy_version": execution[
                                    "sandbox_policy_version"
                                ],
                                "sandbox_profile_sha256": execution[
                                    "sandbox_profile_sha256"
                                ],
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
                execution_data,
                stdout_artifact,
                stderr_artifact,
                block_admitted_red=True,
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
        self._assert_resume_authorization_fulfilled(connection, job)
        self._assert_managed_worktree_binding(connection, job)
        self._assert_registered_resource_fences(connection, job, now)
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
        registered_leases = self._registered_job_resource_leases(
            connection, str(job["id"])
        )

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
        self._append_resource_lease_events(
            connection,
            "resource.released",
            registered_leases,
            campaign_id=str(job["campaign_id"]),
            work_item_id=str(job["work_item_id"]),
            job_id=str(job["id"]),
            actor=worker_id,
            created_at=now,
        )

    @staticmethod
    def _assert_resume_authorization_fulfilled(
        connection: sqlite3.Connection, job: sqlite3.Row
    ) -> None:
        authorization = connection.execute(
            """SELECT expected_provider, expected_session_id
               FROM operator_controls
               WHERE target_attempt_id = ? AND action = 'resume'
                 AND status = 'applied'""",
            (job["current_attempt_id"],),
        ).fetchone()
        if authorization is None:
            return
        attempt = connection.execute(
            "SELECT external_provider, external_session_id FROM attempts WHERE id = ?",
            (job["current_attempt_id"],),
        ).fetchone()
        if (
            attempt is None
            or attempt["external_provider"] != authorization["expected_provider"]
            or attempt["external_session_id"]
            != authorization["expected_session_id"]
        ):
            raise LeaseConflict(
                "resumed attempt did not bind its exact authorized session"
            )
        stopped_process = connection.execute(
            """SELECT 1 FROM external_processes
               WHERE attempt_id = ? AND state = 'stopped' AND provider = ?
               LIMIT 1""",
            (job["current_attempt_id"], authorization["expected_provider"]),
        ).fetchone()
        if stopped_process is None:
            raise LeaseConflict(
                "resumed attempt lacks exact stopped provider process proof"
            )

    def _assert_finished_browser_execution(
        self,
        connection: sqlite3.Connection,
        job: sqlite3.Row,
    ) -> tuple[Dict[str, Any], Dict[str, Any]]:
        execution = connection.execute(
            """SELECT * FROM browser_evidence_executions
               WHERE attempt_id = ? AND job_id = ?""",
            (job["current_attempt_id"], job["id"]),
        ).fetchone()
        if (
            execution is None
            or execution["status"] != "finished"
            or execution["work_item_id"] != job["work_item_id"]
        ):
            raise LeaseConflict(
                "current tester attempt has no finished browser evidence"
            )
        self._assert_stopped_collector_process(
            connection, str(job["current_attempt_id"]), "browser_evidence"
        )
        plan_row = connection.execute(
            "SELECT * FROM browser_evidence_plans WHERE id = ?",
            (execution["plan_id"],),
        ).fetchone()
        if plan_row is None:
            raise LeaseConflict("browser evidence plan disappeared")
        plan = self._validated_browser_plan_row(connection, plan_row)
        if (
            execution["resource_definition_id"]
            != plan["resource_definition_id"]
            or execution["resource_identity_hash"]
            != plan["resource_identity_hash"]
            or execution["requested_route"] != plan["route"]
        ):
            raise LeaseConflict("browser execution authority changed")
        details, digest, _raw = self._collector_artifact(
            execution["screenshot_path"],
            Path(str(execution["screenshot_path"])),
            execution["screenshot_sha256"],
            max_bytes=16 * 1024 * 1024,
        )
        for column, observed in (
            ("screenshot_device", details.st_dev),
            ("screenshot_inode", details.st_ino),
            ("screenshot_owner_uid", details.st_uid),
            ("screenshot_mode", details.st_mode),
            ("screenshot_nlink", details.st_nlink),
            ("screenshot_bytes", details.st_size),
            ("screenshot_sha256", digest),
        ):
            if execution[column] != observed:
                raise LeaseConflict("browser screenshot identity changed")
        assertions = _load(execution["assertions_json"], {})
        expected_assertions = {
            "route": execution["observed_route"] == plan["route"],
            "title": execution["observed_title"] == plan["expected_title"],
            "body": execution["observed_body_sha256"]
            == hashlib.sha256(
                str(plan["expected_body_text"]).encode("utf-8")
            ).hexdigest(),
        }
        if (
            assertions.get("route") != expected_assertions["route"]
            or assertions.get("title") != expected_assertions["title"]
            or assertions.get("body") != expected_assertions["body"]
            or execution["outcome"]
            != ("pass" if all(assertions.values()) else "fail")
        ):
            raise LeaseConflict("browser assertion outcome changed")
        artifact = connection.execute(
            """SELECT * FROM artifacts
               WHERE id = ? AND attempt_id = ? AND job_id = ?
                 AND kind = 'browser_screenshot' AND uri = ?""",
            (
                execution["artifact_id"],
                job["current_attempt_id"],
                job["id"],
                execution["screenshot_path"],
            ),
        ).fetchone()
        if artifact is None:
            raise LeaseConflict("browser screenshot artifact binding is incomplete")
        return self._row(execution), self._row(artifact)  # type: ignore[return-value]

    def _assert_finished_database_execution(
        self,
        connection: sqlite3.Connection,
        job: sqlite3.Row,
    ) -> tuple[Dict[str, Any], Dict[str, Any]]:
        execution = connection.execute(
            """SELECT * FROM database_query_executions
               WHERE attempt_id = ? AND job_id = ?""",
            (job["current_attempt_id"], job["id"]),
        ).fetchone()
        if (
            execution is None
            or execution["status"] != "finished"
            or execution["work_item_id"] != job["work_item_id"]
        ):
            raise LeaseConflict(
                "current tester attempt has no finished database evidence"
            )
        plan_row = connection.execute(
            "SELECT * FROM database_query_plans WHERE id = ?",
            (execution["plan_id"],),
        ).fetchone()
        if plan_row is None:
            raise LeaseConflict("database query plan disappeared")
        plan = self._validated_database_plan_row(connection, plan_row)
        if (
            execution["resource_definition_id"]
            != plan["resource_definition_id"]
            or execution["resource_identity_hash"]
            != plan["resource_identity_hash"]
            or execution["query_sha256"] != plan["query_sha256"]
        ):
            raise LeaseConflict("database execution authority changed")
        details, digest, raw = self._collector_artifact(
            execution["result_path"],
            Path(str(execution["result_path"])),
            execution["result_sha256"],
            max_bytes=int(plan["max_bytes"]),
        )
        payload, observed_ids = self._validated_database_result(
            raw,
            int(plan["max_rows"]),
            int(plan["max_bytes"]),
            str(plan["id_column"]),
        )
        expected_outcome = (
            "pass"
            if (
                (
                    plan["expected_row_count"] is None
                    or len(payload["rows"]) == int(plan["expected_row_count"])
                )
                and observed_ids == list(plan["expected_ids"])
                and payload["read_only_proof"]["foreign_key_violations"] == 0
            )
            else "fail"
        )
        comparisons = {
            "result_device": details.st_dev,
            "result_inode": details.st_ino,
            "result_owner_uid": details.st_uid,
            "result_mode": details.st_mode,
            "result_nlink": details.st_nlink,
            "result_bytes": details.st_size,
            "result_sha256": digest,
            "row_count": len(payload["rows"]),
            "column_count": len(payload["columns"]),
            "outcome": expected_outcome,
        }
        if any(execution[name] != value for name, value in comparisons.items()):
            raise LeaseConflict("database result identity or outcome changed")
        if (
            _load(execution["observed_ids_json"], []) != observed_ids
            or _load(execution["read_only_proof_json"], {})
            != payload["read_only_proof"]
        ):
            raise LeaseConflict("database result semantics changed")
        artifact = connection.execute(
            """SELECT * FROM artifacts
               WHERE id = ? AND attempt_id = ? AND job_id = ?
                 AND kind = 'database_result' AND uri = ?""",
            (
                execution["artifact_id"],
                job["current_attempt_id"],
                job["id"],
                execution["result_path"],
            ),
        ).fetchone()
        if artifact is None:
            raise LeaseConflict("database result artifact binding is incomplete")
        return self._row(execution), self._row(artifact)  # type: ignore[return-value]

    @staticmethod
    def _canonical_pipeline_handoff(
        focused: Mapping[str, Any],
        browser: Optional[Mapping[str, Any]] = None,
        browser_artifact: Optional[Mapping[str, Any]] = None,
        database: Optional[Mapping[str, Any]] = None,
        database_artifact: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        canonical = dict(focused)
        if canonical["outcome"] == "blocked":
            return canonical
        proofs = list(canonical["gate_proofs"])
        failures: List[str] = []
        if canonical["outcome"] != "pass":
            failures.append(str(canonical["summary"]))
        if browser is not None and browser_artifact is not None:
            browser_passed = browser["outcome"] == "pass"
            browser_summary = (
                "exact visible route, title, and body assertions passed"
                if browser_passed
                else "one or more exact visible browser assertions failed"
            )
            proofs.append(
                {
                    "gate": "browser",
                    "result": "pass" if browser_passed else "fail",
                    "summary": browser_summary,
                    "evidence": [
                        {
                            "id": browser_artifact["id"],
                            "kind": "screenshot",
                            "location": browser_artifact["uri"],
                            "description": (
                                "Visible Chrome screenshot for the fixed route."
                            ),
                            "metadata": {
                                "attempt_id": browser["attempt_id"],
                                "execution_id": browser["id"],
                                "resource_id": browser[
                                    "resource_definition_id"
                                ],
                                "route": browser["observed_route"],
                                "sha256": browser["screenshot_sha256"],
                                "bytes": browser["screenshot_bytes"],
                            },
                        }
                    ],
                }
            )
            if not browser_passed:
                failures.append(browser_summary)
        if database is not None and database_artifact is not None:
            database_passed = database["outcome"] == "pass"
            database_summary = (
                "fixed read-only query, expected IDs, row count, and foreign keys passed"
                if database_passed
                else "one or more fixed database assertions failed"
            )
            proofs.append(
                {
                    "gate": "database",
                    "result": "pass" if database_passed else "fail",
                    "summary": database_summary,
                    "evidence": [
                        {
                            "id": database_artifact["id"],
                            "kind": "database",
                            "location": database_artifact["uri"],
                            "description": (
                                "Bounded canonical result from the fixed read-only query."
                            ),
                            "metadata": {
                                "attempt_id": database["attempt_id"],
                                "execution_id": database["id"],
                                "resource_id": database[
                                    "resource_definition_id"
                                ],
                                "query_sha256": database["query_sha256"],
                                "result_sha256": database["result_sha256"],
                                "row_count": database["row_count"],
                                "read_only_proof": database["read_only_proof"],
                            },
                        }
                    ],
                }
            )
            if not database_passed:
                failures.append(database_summary)
        canonical["gate_proofs"] = proofs
        if failures:
            canonical["outcome"] = "red"
            canonical["summary"] = "; ".join(failures)
            canonical["failure_summary"] = canonical["summary"]
        else:
            canonical["outcome"] = "pass"
            canonical["summary"] = (
                "focused test, visible browser, and read-only database collectors passed"
            )
            canonical["failure_summary"] = None
        canonical["blocker"] = None
        return canonical

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
                if not allow_simulated:
                    if required_gates not in (
                        ["focused_tests"],
                        list(DEFAULT_REQUIRED_GATES),
                    ):
                        raise ValueError(
                            "tester handoff cannot advance: non-simulated evidence "
                            "requires authoritative focused tests or the fixed "
                            "three-gate pipeline"
                        )
                    execution = connection.execute(
                        """SELECT * FROM focused_test_executions
                           WHERE attempt_id = ? AND job_id = ?""",
                        (job["current_attempt_id"], job["id"]),
                    ).fetchone()
                    if execution is None:
                        raise ValueError(
                            "tester handoff cannot advance: current attempt has no "
                            "authoritative focused execution"
                        )
                    if execution["canonical_handoff_json"] is None:
                        raise ValueError(
                            "tester handoff cannot advance: current focused execution "
                            "has no persisted canonical handoff"
                        )
                    execution_data, stdout_artifact, stderr_artifact = (
                        self._assert_finished_focused_execution(
                            connection, job, execution
                        )
                    )
                    focused_handoff = _load(
                        execution["canonical_handoff_json"], None
                    )
                    if not isinstance(focused_handoff, dict):
                        raise LeaseConflict(
                            "focused canonical handoff is malformed"
                        )
                    if required_gates == list(DEFAULT_REQUIRED_GATES):
                        browser = browser_artifact = None
                        database = database_artifact = None
                        if focused_handoff["outcome"] == "pass":
                            browser, browser_artifact = (
                                self._assert_finished_browser_execution(
                                    connection, job
                                )
                            )
                            if browser["outcome"] == "pass":
                                database, database_artifact = (
                                    self._assert_finished_database_execution(
                                        connection, job
                                    )
                                )
                        focused_handoff = self._canonical_pipeline_handoff(
                            focused_handoff,
                            browser,
                            browser_artifact,
                            database,
                            database_artifact,
                        )
                    handoff = TestHandoff.model_validate(focused_handoff)
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
            self._assert_no_pending_operator_interrupt(connection, job_id)
            self._assert_attempt_focused_test_admission(connection, job)
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

    def _end_prepared_evidence_executions(
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
            raise ValueError("collector execution terminal status is invalid")
        for table, event_prefix in (
            ("browser_evidence_executions", "browser_evidence"),
            ("database_query_executions", "database_evidence"),
        ):
            changed = connection.execute(
                """UPDATE %s SET status = ?, error = ?, finished_at = ?,
                          updated_at = ?
                   WHERE attempt_id = ? AND status = 'prepared'""" % table,
                (status, reason, now, now, job["current_attempt_id"]),
            ).rowcount
            if changed:
                self._append_event(
                    connection,
                    "%s.execution_%s" % (event_prefix, status),
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
            self._assert_no_pending_operator_interrupt(connection, job_id)
            self._assert_external_process_stopped(connection, job)
            self._end_prepared_focused_execution(
                connection,
                job,
                status="abandoned",
                reason=error,
                now=now,
                actor=worker_id,
            )
            self._end_prepared_evidence_executions(
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
            registered_leases = self._registered_job_resource_leases(
                connection, job_id
            )
            connection.execute(
                "DELETE FROM resource_leases WHERE job_id = ? AND lease_token = ?",
                (job_id, lease_token),
            )
            self._append_resource_lease_events(
                connection,
                "resource.released",
                registered_leases,
                campaign_id=str(job["campaign_id"]),
                work_item_id=str(job["work_item_id"]),
                job_id=job_id,
                actor=worker_id,
                created_at=now,
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
        operator_request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record a clean interruption and requeue without treating it as a defect."""

        with self._transaction() as connection:
            now = self._clock()
            job = self._assert_live_lease(
                connection, job_id, worker_id, lease_token, now
            )
            operator_request = None
            if operator_request_id is not None:
                operator_request = self._assert_operator_interrupt_request(
                    connection,
                    operator_request_id,
                    job,
                    worker_id,
                    lease_token,
                    allow_stopped_process=True,
                )
                if reason != operator_request["reason"]:
                    raise LeaseConflict(
                        "operator interrupt reason differs from its request"
                    )
            else:
                self._assert_no_pending_operator_interrupt(connection, job_id)
            self._assert_external_process_stopped(connection, job)
            self._end_prepared_focused_execution(
                connection,
                job,
                status="abandoned",
                reason=reason,
                now=now,
                actor=worker_id,
            )
            self._end_prepared_evidence_executions(
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
            registered_leases = self._registered_job_resource_leases(
                connection, job_id
            )
            connection.execute(
                "DELETE FROM resource_leases WHERE job_id = ? AND lease_token = ?",
                (job_id, lease_token),
            )
            self._append_resource_lease_events(
                connection,
                "resource.released",
                registered_leases,
                campaign_id=str(job["campaign_id"]),
                work_item_id=str(job["work_item_id"]),
                job_id=job_id,
                actor=worker_id,
                created_at=now,
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
                    "operator_request_id": operator_request_id,
                    "from_state": job["active_item_state"],
                    "to_state": job["queued_item_state"],
                },
                created_at=now,
            )
            if operator_request is not None:
                changed = connection.execute(
                    """UPDATE operator_controls
                       SET status = 'applied', target_attempt_id = ?, applied_at = ?
                       WHERE id = ? AND status = 'pending'""",
                    (job["current_attempt_id"], now, operator_request_id),
                ).rowcount
                if changed != 1:
                    raise LeaseConflict(
                        "operator interrupt request was consumed concurrently"
                    )
                self._append_event(
                    connection,
                    "operator.interrupt_applied",
                    campaign_id=job["campaign_id"],
                    work_item_id=job["work_item_id"],
                    job_id=job_id,
                    actor=operator_request["requested_by"],
                    event_data={
                        "request_id": operator_request_id,
                        "attempt_id": job["current_attempt_id"],
                        "reason": reason,
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
        pending_interrupt = connection.execute(
            """SELECT * FROM operator_controls
               WHERE job_id = ? AND action = 'interrupt'
                 AND status = 'pending'""",
            (job["id"],),
        ).fetchone()
        if pending_interrupt is not None:
            rejected_reason = "%s before the operator interrupt was applied" % error
            changed = connection.execute(
                """UPDATE operator_controls
                   SET status = 'rejected', last_error = ?
                   WHERE id = ? AND status = 'pending'""",
                (rejected_reason, pending_interrupt["id"]),
            ).rowcount
            if changed != 1:
                raise LeaseConflict(
                    "pending operator interrupt changed during recovery"
                )
            self._append_event(
                connection,
                "operator.interrupt_rejected",
                campaign_id=job["campaign_id"],
                work_item_id=job["work_item_id"],
                job_id=job["id"],
                actor=pending_interrupt["requested_by"],
                event_data={
                    "request_id": pending_interrupt["id"],
                    "attempt_id": job["current_attempt_id"],
                    "reason": rejected_reason,
                },
                created_at=now,
            )
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
        registered_leases = self._registered_job_resource_leases(
            connection, str(job["id"])
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
        self._end_prepared_evidence_executions(
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
        self._append_resource_lease_events(
            connection,
            "resource.recovered",
            registered_leases,
            campaign_id=str(job["campaign_id"]),
            work_item_id=str(job["work_item_id"]),
            job_id=str(job["id"]),
            actor=(None if job["lease_owner"] is None else str(job["lease_owner"])),
            created_at=now,
        )
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
            """SELECT r.*, j.campaign_id AS job_campaign_id,
                      j.work_item_id AS job_work_item_id,
                      d.kind AS resource_kind, d.label AS resource_label,
                      d.policy_json AS resource_policy_json,
                      d.campaign_id AS resource_campaign_id
               FROM resource_leases r
               LEFT JOIN jobs j ON j.id = r.job_id
               LEFT JOIN resource_definitions d
                 ON d.id = r.resource_definition_id
               WHERE r.expires_at <= ?
                 AND (r.job_id IS NULL OR j.status IS NULL OR j.status != 'running')""",
            (now,),
        ).fetchall()
        for lease in orphaned:
            connection.execute(
                """DELETE FROM resource_leases
                   WHERE resource_key = ? AND lease_slot = ?""",
                (lease["resource_key"], lease["lease_slot"]),
            )
            if lease["resource_definition_id"] is None:
                self._append_event(
                    connection, "resource.lease_expired", job_id=lease["job_id"],
                    actor=lease["owner_id"],
                    event_data={"resource_key": lease["resource_key"]},
                    created_at=now
                )
            else:
                self._append_resource_lease_events(
                    connection,
                    "resource.recovered",
                    [lease],
                    campaign_id=str(lease["job_campaign_id"]),
                    work_item_id=str(lease["job_work_item_id"]),
                    job_id=str(lease["job_id"]),
                    actor=str(lease["owner_id"]),
                    created_at=now,
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
                """SELECT * FROM external_processes
                   WHERE attempt_id = ?
                     AND reconciliation_owner = ?
                     AND reconciliation_token = ?
                   ORDER BY recorded_at DESC, id DESC LIMIT 1""",
                (attempt_id, owner, reconciliation_token),
            ).fetchone()
            if external is None:
                exists = connection.execute(
                    "SELECT 1 FROM external_processes WHERE attempt_id = ? LIMIT 1",
                    (attempt_id,),
                ).fetchone()
                if exists is None:
                    raise NotFoundError(
                        "external process for attempt %s not found" % attempt_id
                    )
                raise LeaseConflict("external process reconciliation fence is stale")
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
                self._end_prepared_evidence_executions(
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
                  LEFT JOIN external_processes ep ON ep.id = (
                      SELECT latest_process.id
                      FROM external_processes latest_process
                      WHERE latest_process.attempt_id = a.id
                      ORDER BY latest_process.recorded_at DESC,
                               latest_process.id DESC
                      LIMIT 1)"""
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
        resource_key = _reject_registered_resource_alias(resource_key)
        resource_key = _reject_unsafe_collector_text(resource_key, "resource key")
        owner_id = _operator_text(owner_id, "resource lease owner", 256)
        token = _id()
        with self._transaction() as connection:
            now = self._clock()
            existing = connection.execute(
                """SELECT * FROM resource_leases
                   WHERE resource_key = ? AND lease_slot = 1""",
                (resource_key,),
            ).fetchone()
            if existing is not None and existing["job_id"] is not None:
                return None
            if existing is not None and existing["expires_at"] > now:
                return None
            if existing is not None:
                connection.execute(
                    """DELETE FROM resource_leases
                       WHERE resource_key = ? AND lease_slot = 1""",
                    (resource_key,),
                )
                self._append_event(
                    connection,
                    "resource.lease_expired",
                    actor=owner_id,
                    event_data={"resource_key": resource_key, "lease_slot": 1},
                    created_at=now,
                )
            connection.execute(
                """INSERT INTO resource_leases
                   (resource_key, lease_slot, resource_definition_id, owner_id,
                    job_id, lease_token, acquired_at, heartbeat_at, expires_at)
                   VALUES (?, 1, NULL, ?, ?, ?, ?, ?, ?)""",
                (
                    resource_key,
                    owner_id,
                    job_id,
                    token,
                    now,
                    now,
                    now + lease_seconds,
                ),
            )
            self._append_event(
                connection,
                "resource.acquired",
                actor=owner_id,
                event_data={
                    "resource_key": resource_key,
                    "lease_slot": 1,
                    "expires_at": now + lease_seconds,
                },
                created_at=now,
            )
            row = connection.execute(
                """SELECT * FROM resource_leases
                   WHERE resource_key = ? AND lease_slot = 1""",
                (resource_key,),
            ).fetchone()
            return self._row(row)

    def heartbeat_resource(
        self, resource_key: str, owner_id: str, lease_token: str, *, lease_seconds: float = 60.0
    ) -> bool:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        resource_key = _reject_registered_resource_alias(resource_key)
        resource_key = _reject_unsafe_collector_text(resource_key, "resource key")
        owner_id = _operator_text(owner_id, "resource lease owner", 256)
        with self._transaction() as connection:
            now = self._clock()
            existing = connection.execute(
                """SELECT job_id FROM resource_leases
                   WHERE resource_key = ? AND lease_slot = 1""",
                (resource_key,),
            ).fetchone()
            if existing is not None and existing["job_id"] is not None:
                raise LeaseConflict(
                    "job-bound resources are heartbeated only through their job lease"
                )
            changed = connection.execute(
                """UPDATE resource_leases SET heartbeat_at = ?, expires_at = ?
                   WHERE resource_key = ? AND lease_slot = 1
                     AND owner_id = ? AND lease_token = ?
                     AND expires_at > ?""",
                (now, now + lease_seconds, resource_key, owner_id, lease_token, now),
            ).rowcount
            if changed == 1:
                self._append_event(
                    connection,
                    "resource.heartbeat",
                    actor=owner_id,
                    event_data={
                        "resource_key": resource_key,
                        "lease_slot": 1,
                        "expires_at": now + lease_seconds,
                    },
                    created_at=now,
                )
        return changed == 1

    def release_resource(self, resource_key: str, owner_id: str, lease_token: str) -> bool:
        resource_key = _reject_registered_resource_alias(resource_key)
        resource_key = _reject_unsafe_collector_text(resource_key, "resource key")
        owner_id = _operator_text(owner_id, "resource lease owner", 256)
        with self._transaction() as connection:
            now = self._clock()
            existing = connection.execute(
                """SELECT job_id FROM resource_leases
                   WHERE resource_key = ? AND lease_slot = 1""",
                (resource_key,),
            ).fetchone()
            if existing is not None and existing["job_id"] is not None:
                raise LeaseConflict(
                    "job-bound resources are released only through their job lease"
                )
            changed = connection.execute(
                """DELETE FROM resource_leases
                   WHERE resource_key = ? AND lease_slot = 1
                     AND owner_id = ? AND lease_token = ?""",
                (resource_key, owner_id, lease_token),
            ).rowcount
            if changed == 1:
                self._append_event(
                    connection,
                    "resource.released",
                    actor=owner_id,
                    event_data={"resource_key": resource_key, "lease_slot": 1},
                    created_at=now,
                )
        return changed == 1

    def list_resource_leases(
        self, *, campaign_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        sql = "SELECT r.* FROM resource_leases r"
        parameters: Sequence[Any] = ()
        if campaign_id is not None:
            sql += " JOIN jobs j ON j.id = r.job_id WHERE j.campaign_id = ?"
            parameters = (campaign_id,)
        sql += " ORDER BY r.resource_key, r.lease_slot"
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
            return self._safe_resource_lease_records(
                self._connection, rows
            )

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


_SCHEMA_V8 = [
    """CREATE TABLE resource_definitions (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        label TEXT NOT NULL,
        enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
        configuration_json TEXT NOT NULL,
        campaign_id TEXT REFERENCES campaigns(id) ON DELETE RESTRICT,
        metadata_json TEXT NOT NULL,
        policy_json TEXT NOT NULL,
        identity_hash TEXT NOT NULL,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        CHECK(kind IN ('chrome_profile', 'tenant_database',
                       'queue_environment', 'test_fixture')),
        CHECK(length(id) = 36 AND substr(id, 1, 4) = 'res_'
              AND substr(id, 5) NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(identity_hash) = 64
              AND identity_hash NOT GLOB '*[^0-9a-f]*'),
        UNIQUE(kind, identity_hash))""",
    """CREATE INDEX resource_definitions_campaign
       ON resource_definitions(campaign_id, enabled, kind, label, id)""",
    """CREATE TABLE resource_leases_v8 (
        resource_key TEXT NOT NULL,
        lease_slot INTEGER NOT NULL CHECK(lease_slot > 0),
        resource_definition_id TEXT
            REFERENCES resource_definitions(id) ON DELETE RESTRICT,
        owner_id TEXT NOT NULL,
        job_id TEXT REFERENCES jobs(id) ON DELETE CASCADE,
        lease_token TEXT NOT NULL,
        acquired_at REAL NOT NULL,
        heartbeat_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        PRIMARY KEY(resource_key, lease_slot),
        CHECK(resource_definition_id IS NULL
              OR resource_definition_id = resource_key),
        CHECK(resource_definition_id IS NULL OR job_id IS NOT NULL))""",
    """INSERT INTO resource_leases_v8
       (resource_key, lease_slot, resource_definition_id, owner_id, job_id,
        lease_token, acquired_at, heartbeat_at, expires_at)
       SELECT resource_key, 1, NULL, owner_id, job_id, lease_token,
              acquired_at, heartbeat_at, expires_at
       FROM resource_leases""",
    "DROP TABLE resource_leases",
    "ALTER TABLE resource_leases_v8 RENAME TO resource_leases",
    "CREATE INDEX resource_lease_expiry ON resource_leases(expires_at)",
    """CREATE INDEX resource_leases_job
       ON resource_leases(job_id, resource_key, lease_slot)""",
    """CREATE INDEX resource_leases_definition
       ON resource_leases(resource_definition_id, lease_slot)""",
]


_SCHEMA_V9 = [
    "ALTER TABLE resource_definitions ADD COLUMN definition_hash TEXT",
    "ALTER TABLE resource_leases ADD COLUMN resource_identity_hash TEXT",
    "ALTER TABLE external_processes RENAME TO external_processes_v4",
    "DROP INDEX one_live_external_process_identity",
    "DROP INDEX external_process_reconciliation_queue",
    """CREATE TABLE external_processes (
        id TEXT PRIMARY KEY,
        attempt_id TEXT NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
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
    """INSERT INTO external_processes
       SELECT * FROM external_processes_v4""",
    "DROP TABLE external_processes_v4",
    """CREATE UNIQUE INDEX one_live_external_process_identity
       ON external_processes(process_id, start_seconds, start_microseconds)
       WHERE state != 'stopped'""",
    """CREATE UNIQUE INDEX one_live_external_process_per_attempt
       ON external_processes(attempt_id) WHERE state != 'stopped'""",
    """CREATE INDEX external_process_attempt_history
       ON external_processes(attempt_id, recorded_at, id)""",
    """CREATE INDEX external_process_reconciliation_queue
       ON external_processes(state, reconciliation_expires_at, recorded_at)""",
    """CREATE UNIQUE INDEX attempts_id_job
       ON attempts(id, job_id)""",
    """CREATE UNIQUE INDEX jobs_id_item
       ON jobs(id, work_item_id)""",
    """CREATE TABLE browser_evidence_plans (
        id TEXT PRIMARY KEY,
        work_item_id TEXT NOT NULL
            REFERENCES work_items(id) ON DELETE CASCADE,
        plan_number INTEGER NOT NULL CHECK(plan_number > 0),
        resource_definition_id TEXT NOT NULL
            REFERENCES resource_definitions(id) ON DELETE RESTRICT,
        resource_identity_hash TEXT NOT NULL,
        route TEXT NOT NULL,
        route_device INTEGER NOT NULL CHECK(route_device >= 0),
        route_inode INTEGER NOT NULL CHECK(route_inode >= 0),
        route_owner_uid INTEGER NOT NULL CHECK(route_owner_uid >= 0),
        route_mode INTEGER NOT NULL CHECK(route_mode > 0),
        route_nlink INTEGER NOT NULL CHECK(route_nlink > 0),
        route_bytes INTEGER NOT NULL CHECK(route_bytes > 0),
        route_sha256 TEXT NOT NULL,
        expected_title TEXT NOT NULL,
        expected_body_text TEXT NOT NULL,
        runtime_root TEXT NOT NULL,
        timeout_seconds REAL NOT NULL CHECK(timeout_seconds > 0),
        plan_sha256 TEXT NOT NULL,
        created_at REAL NOT NULL,
        UNIQUE(work_item_id, plan_number),
        UNIQUE(work_item_id, plan_sha256),
        UNIQUE(id, work_item_id, resource_definition_id),
        CHECK(length(resource_identity_hash) = 64
              AND resource_identity_hash NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(route_sha256) = 64
              AND route_sha256 NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(plan_sha256) = 64
              AND plan_sha256 NOT GLOB '*[^0-9a-f]*'))""",
    """CREATE INDEX browser_evidence_plan_resource
       ON browser_evidence_plans(resource_definition_id, work_item_id)""",
    """CREATE TABLE browser_evidence_executions (
        id TEXT PRIMARY KEY,
        plan_id TEXT NOT NULL
            REFERENCES browser_evidence_plans(id) ON DELETE CASCADE,
        attempt_id TEXT NOT NULL UNIQUE
            REFERENCES attempts(id) ON DELETE CASCADE,
        job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        work_item_id TEXT NOT NULL REFERENCES work_items(id) ON DELETE CASCADE,
        resource_definition_id TEXT NOT NULL
            REFERENCES resource_definitions(id) ON DELETE RESTRICT,
        resource_identity_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        outcome TEXT,
        requested_route TEXT NOT NULL,
        observed_route TEXT,
        observed_title TEXT,
        observed_body_sha256 TEXT,
        assertions_json TEXT,
        run_parent TEXT NOT NULL,
        screenshot_path TEXT NOT NULL UNIQUE,
        screenshot_device INTEGER,
        screenshot_inode INTEGER,
        screenshot_owner_uid INTEGER,
        screenshot_mode INTEGER,
        screenshot_nlink INTEGER,
        screenshot_bytes INTEGER,
        screenshot_sha256 TEXT,
        artifact_id TEXT REFERENCES artifacts(id),
        error TEXT,
        prepared_at REAL NOT NULL,
        finished_at REAL,
        updated_at REAL NOT NULL,
        FOREIGN KEY(plan_id, work_item_id, resource_definition_id)
            REFERENCES browser_evidence_plans(
                id, work_item_id, resource_definition_id) ON DELETE CASCADE,
        FOREIGN KEY(attempt_id, job_id)
            REFERENCES attempts(id, job_id) ON DELETE CASCADE,
        FOREIGN KEY(job_id, work_item_id)
            REFERENCES jobs(id, work_item_id) ON DELETE CASCADE,
        CHECK(status IN ('prepared', 'finished', 'abandoned', 'quarantined')),
        CHECK(outcome IS NULL OR outcome IN ('pass', 'fail')),
        CHECK((status = 'finished' AND outcome IS NOT NULL
               AND observed_route IS NOT NULL AND observed_title IS NOT NULL
               AND observed_body_sha256 IS NOT NULL
               AND assertions_json IS NOT NULL AND screenshot_device IS NOT NULL
               AND screenshot_inode IS NOT NULL AND screenshot_owner_uid IS NOT NULL
               AND screenshot_mode IS NOT NULL AND screenshot_nlink IS NOT NULL
               AND screenshot_bytes IS NOT NULL AND screenshot_sha256 IS NOT NULL
               AND artifact_id IS NOT NULL AND finished_at IS NOT NULL)
              OR status != 'finished'),
        CHECK((status = 'prepared' AND outcome IS NULL
               AND observed_route IS NULL AND observed_title IS NULL
               AND observed_body_sha256 IS NULL AND assertions_json IS NULL
               AND screenshot_sha256 IS NULL AND artifact_id IS NULL
               AND error IS NULL AND finished_at IS NULL)
              OR status != 'prepared'),
        CHECK(length(resource_identity_hash) = 64
              AND resource_identity_hash NOT GLOB '*[^0-9a-f]*'),
        CHECK(screenshot_sha256 IS NULL OR
              (length(screenshot_sha256) = 64
               AND screenshot_sha256 NOT GLOB '*[^0-9a-f]*')),
        CHECK(observed_body_sha256 IS NULL OR
              (length(observed_body_sha256) = 64
               AND observed_body_sha256 NOT GLOB '*[^0-9a-f]*')))""",
    """CREATE INDEX browser_evidence_execution_item
       ON browser_evidence_executions(work_item_id, prepared_at)""",
    """CREATE TABLE database_query_plans (
        id TEXT PRIMARY KEY,
        work_item_id TEXT NOT NULL
            REFERENCES work_items(id) ON DELETE CASCADE,
        plan_number INTEGER NOT NULL CHECK(plan_number > 0),
        resource_definition_id TEXT NOT NULL
            REFERENCES resource_definitions(id) ON DELETE RESTRICT,
        resource_identity_hash TEXT NOT NULL,
        statement TEXT NOT NULL,
        parameters_json TEXT NOT NULL,
        query_sha256 TEXT NOT NULL,
        id_column TEXT NOT NULL,
        expected_ids_json TEXT NOT NULL,
        expected_row_count INTEGER CHECK(expected_row_count IS NULL
                                         OR expected_row_count >= 0),
        max_rows INTEGER NOT NULL CHECK(max_rows > 0),
        max_bytes INTEGER NOT NULL CHECK(max_bytes > 0),
        timeout_seconds REAL NOT NULL CHECK(timeout_seconds > 0),
        runtime_root TEXT NOT NULL,
        plan_sha256 TEXT NOT NULL,
        created_at REAL NOT NULL,
        UNIQUE(work_item_id, plan_number),
        UNIQUE(work_item_id, plan_sha256),
        UNIQUE(id, work_item_id, resource_definition_id),
        CHECK(length(resource_identity_hash) = 64
              AND resource_identity_hash NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(query_sha256) = 64
              AND query_sha256 NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(plan_sha256) = 64
              AND plan_sha256 NOT GLOB '*[^0-9a-f]*'))""",
    """CREATE INDEX database_query_plan_resource
       ON database_query_plans(resource_definition_id, work_item_id)""",
    """CREATE TABLE database_query_executions (
        id TEXT PRIMARY KEY,
        plan_id TEXT NOT NULL
            REFERENCES database_query_plans(id) ON DELETE CASCADE,
        attempt_id TEXT NOT NULL UNIQUE
            REFERENCES attempts(id) ON DELETE CASCADE,
        job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        work_item_id TEXT NOT NULL REFERENCES work_items(id) ON DELETE CASCADE,
        resource_definition_id TEXT NOT NULL
            REFERENCES resource_definitions(id) ON DELETE RESTRICT,
        resource_identity_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        outcome TEXT,
        query_sha256 TEXT NOT NULL,
        row_count INTEGER,
        column_count INTEGER,
        observed_ids_json TEXT,
        read_only_proof_json TEXT,
        run_parent TEXT NOT NULL,
        result_path TEXT NOT NULL UNIQUE,
        result_device INTEGER,
        result_inode INTEGER,
        result_owner_uid INTEGER,
        result_mode INTEGER,
        result_nlink INTEGER,
        result_bytes INTEGER,
        result_sha256 TEXT,
        artifact_id TEXT REFERENCES artifacts(id),
        error TEXT,
        prepared_at REAL NOT NULL,
        finished_at REAL,
        updated_at REAL NOT NULL,
        FOREIGN KEY(plan_id, work_item_id, resource_definition_id)
            REFERENCES database_query_plans(
                id, work_item_id, resource_definition_id) ON DELETE CASCADE,
        FOREIGN KEY(attempt_id, job_id)
            REFERENCES attempts(id, job_id) ON DELETE CASCADE,
        FOREIGN KEY(job_id, work_item_id)
            REFERENCES jobs(id, work_item_id) ON DELETE CASCADE,
        CHECK(status IN ('prepared', 'finished', 'abandoned', 'quarantined')),
        CHECK(outcome IS NULL OR outcome IN ('pass', 'fail')),
        CHECK((status = 'finished' AND outcome IS NOT NULL
               AND row_count IS NOT NULL AND column_count IS NOT NULL
               AND observed_ids_json IS NOT NULL
               AND read_only_proof_json IS NOT NULL
               AND result_sha256 IS NOT NULL AND artifact_id IS NOT NULL
               AND finished_at IS NOT NULL)
              OR status != 'finished'),
        CHECK((status = 'prepared' AND outcome IS NULL
               AND row_count IS NULL AND column_count IS NULL
               AND observed_ids_json IS NULL AND read_only_proof_json IS NULL
               AND result_sha256 IS NULL AND artifact_id IS NULL
               AND error IS NULL AND finished_at IS NULL)
              OR status != 'prepared'),
        CHECK(length(resource_identity_hash) = 64
              AND resource_identity_hash NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(query_sha256) = 64
              AND query_sha256 NOT GLOB '*[^0-9a-f]*'),
        CHECK(result_sha256 IS NULL OR
              (length(result_sha256) = 64
               AND result_sha256 NOT GLOB '*[^0-9a-f]*')))""",
    """CREATE INDEX database_query_execution_item
       ON database_query_executions(work_item_id, prepared_at)""",
    """CREATE TABLE operator_controls (
        id TEXT PRIMARY KEY,
        job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        source_attempt_id TEXT NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
        target_attempt_id TEXT REFERENCES attempts(id) ON DELETE SET NULL,
        action TEXT NOT NULL CHECK(action IN ('interrupt', 'resume')),
        status TEXT NOT NULL CHECK(status IN ('pending', 'applied', 'rejected')),
        requested_by TEXT NOT NULL,
        reason TEXT NOT NULL,
        expected_lease_owner TEXT,
        expected_lease_token TEXT,
        expected_provider TEXT,
        expected_session_id TEXT,
        expected_process_id INTEGER,
        expected_process_group_id INTEGER,
        expected_process_start_seconds INTEGER,
        expected_process_start_microseconds INTEGER,
        expected_process_executable TEXT,
        expected_worktree_id TEXT,
        expected_worktree_generation INTEGER,
        expected_resources_json TEXT NOT NULL,
        expected_resources_sha256 TEXT NOT NULL,
        requested_at REAL NOT NULL,
        applied_at REAL,
        last_error TEXT,
        CHECK(length(expected_resources_sha256) = 64
              AND expected_resources_sha256 NOT GLOB '*[^0-9a-f]*'),
        CHECK((status = 'pending' AND target_attempt_id IS NULL
               AND applied_at IS NULL AND last_error IS NULL)
              OR status != 'pending'),
        CHECK((status = 'applied' AND applied_at IS NOT NULL)
              OR status != 'applied'),
        CHECK((action = 'interrupt' AND expected_lease_owner IS NOT NULL
               AND expected_lease_token IS NOT NULL)
              OR action != 'interrupt'),
        CHECK((action = 'resume' AND expected_provider IS NOT NULL
               AND expected_session_id IS NOT NULL)
              OR action != 'resume'))""",
    """CREATE UNIQUE INDEX one_pending_operator_control
       ON operator_controls(job_id, action) WHERE status = 'pending'""",
    """CREATE INDEX operator_control_history
       ON operator_controls(job_id, requested_at, id)""",
]


_SCHEMA_V10 = [
    "ALTER TABLE focused_test_plans ADD COLUMN sandbox_policy_version TEXT",
    "ALTER TABLE focused_test_plans ADD COLUMN sandbox_executable_path TEXT",
    "ALTER TABLE focused_test_plans ADD COLUMN sandbox_executable_device INTEGER",
    "ALTER TABLE focused_test_plans ADD COLUMN sandbox_executable_inode INTEGER",
    "ALTER TABLE focused_test_plans ADD COLUMN sandbox_executable_owner_uid INTEGER",
    "ALTER TABLE focused_test_plans ADD COLUMN sandbox_executable_mode INTEGER",
    "ALTER TABLE focused_test_plans ADD COLUMN sandbox_executable_sha256 TEXT",
    "ALTER TABLE focused_test_plans ADD COLUMN python_runtime_root TEXT",
    "ALTER TABLE focused_test_plans ADD COLUMN python_runtime_sha256 TEXT",
    "ALTER TABLE focused_test_executions ADD COLUMN sandbox_policy_version TEXT",
    "ALTER TABLE focused_test_executions ADD COLUMN sandbox_executable_path TEXT",
    "ALTER TABLE focused_test_executions ADD COLUMN sandbox_executable_device INTEGER",
    "ALTER TABLE focused_test_executions ADD COLUMN sandbox_executable_inode INTEGER",
    "ALTER TABLE focused_test_executions ADD COLUMN sandbox_executable_owner_uid INTEGER",
    "ALTER TABLE focused_test_executions ADD COLUMN sandbox_executable_mode INTEGER",
    "ALTER TABLE focused_test_executions ADD COLUMN sandbox_executable_sha256 TEXT",
    "ALTER TABLE focused_test_executions ADD COLUMN python_runtime_root TEXT",
    "ALTER TABLE focused_test_executions ADD COLUMN python_runtime_sha256 TEXT",
    "ALTER TABLE focused_test_executions ADD COLUMN sandbox_profile TEXT",
    "ALTER TABLE focused_test_executions ADD COLUMN sandbox_profile_sha256 TEXT",
    "ALTER TABLE focused_test_executions ADD COLUMN test_command_argv_json TEXT",
    "ALTER TABLE focused_test_executions ADD COLUMN test_command_argv_sha256 TEXT",
]


_SCHEMA_V11 = [
    """ALTER TABLE campaigns ADD COLUMN execution_mode TEXT NOT NULL
       DEFAULT 'legacy'
       CHECK(execution_mode IN ('legacy', 'focused_test_admission'))""",
    """CREATE TABLE focused_test_admissions (
        id TEXT PRIMARY KEY,
        campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
        work_item_id TEXT NOT NULL REFERENCES work_items(id) ON DELETE CASCADE,
        tester_job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        managed_worktree_id TEXT NOT NULL
            REFERENCES managed_worktrees(id) ON DELETE RESTRICT,
        managed_worktree_generation INTEGER NOT NULL
            CHECK(managed_worktree_generation > 0),
        focused_test_plan_id TEXT NOT NULL
            REFERENCES focused_test_plans(id) ON DELETE RESTRICT,
        focused_test_plan_sha256 TEXT NOT NULL,
        campaign_config_sha256 TEXT NOT NULL,
        job_payload_sha256 TEXT NOT NULL,
        required_gates_sha256 TEXT NOT NULL,
        repository_identity_json TEXT NOT NULL,
        repository_identity_sha256 TEXT NOT NULL,
        worktree_identity_json TEXT NOT NULL,
        worktree_identity_sha256 TEXT NOT NULL,
        resource_definition_ids_json TEXT NOT NULL,
        resource_bindings_json TEXT NOT NULL,
        resource_bindings_sha256 TEXT NOT NULL,
        required_resources_sha256 TEXT NOT NULL,
        authority_sha256 TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
        admitted_by TEXT NOT NULL,
        admission_reason TEXT NOT NULL,
        admitted_at REAL NOT NULL,
        revoked_by TEXT,
        revocation_reason TEXT,
        revoked_at REAL,
        updated_at REAL NOT NULL,
        CHECK(length(id) = 36 AND substr(id, 1, 4) = 'fta_'
              AND substr(id, 5) NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(focused_test_plan_sha256) = 64
              AND focused_test_plan_sha256 NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(campaign_config_sha256) = 64
              AND campaign_config_sha256 NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(job_payload_sha256) = 64
              AND job_payload_sha256 NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(required_gates_sha256) = 64
              AND required_gates_sha256 NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(repository_identity_sha256) = 64
              AND repository_identity_sha256 NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(worktree_identity_sha256) = 64
              AND worktree_identity_sha256 NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(resource_bindings_sha256) = 64
              AND resource_bindings_sha256 NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(required_resources_sha256) = 64
              AND required_resources_sha256 NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(authority_sha256) = 64
              AND authority_sha256 NOT GLOB '*[^0-9a-f]*'),
        CHECK((status = 'active' AND revoked_by IS NULL
               AND revocation_reason IS NULL AND revoked_at IS NULL)
              OR (status = 'revoked' AND revoked_by IS NOT NULL
                  AND revocation_reason IS NOT NULL AND revoked_at IS NOT NULL)))""",
    """CREATE UNIQUE INDEX one_active_focused_test_admission_per_tester_job
       ON focused_test_admissions(tester_job_id) WHERE status = 'active'""",
    """CREATE INDEX focused_test_admissions_campaign
       ON focused_test_admissions(campaign_id, status, admitted_at, id)""",
    """CREATE INDEX focused_test_admissions_item
       ON focused_test_admissions(work_item_id, status, admitted_at, id)""",
    """ALTER TABLE attempts ADD COLUMN focused_test_admission_id TEXT
       REFERENCES focused_test_admissions(id) ON DELETE RESTRICT""",
    """CREATE INDEX attempts_focused_test_admission
       ON attempts(focused_test_admission_id, status)""",
]
