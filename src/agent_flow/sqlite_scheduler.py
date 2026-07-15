"""Typed scheduler boundary over the plain-dictionary SQLite store."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, ContextManager, Iterable, Iterator, List, Mapping, Optional, Tuple

from agent_flow.models import (
    Campaign,
    CampaignStatus,
    ItemState,
    Job,
    JobStatus,
    WorkerRole,
    WorkspaceKind,
    WorkItem,
)
from agent_flow.process_reconciler import (
    ExternalProcessBinding,
    ExternalProcessReconciler,
    ReconciliationResult,
)
from agent_flow.storage import LeaseConflict, SQLiteStore


LOCAL_WRITE_APPROVAL_ACTION = "local_code_changes"


@dataclass(frozen=True)
class LeaseRecoveryBatch:
    """Recovered jobs plus bounded external-process work examined this tick."""

    recovered_job_ids: Tuple[str, ...]
    reconciliation_count: int = 0

    def __iter__(self) -> Iterator[str]:
        return iter(self.recovered_job_ids)

_ROLE_STATES = {
    WorkerRole.INVESTIGATOR: (ItemState.BACKLOG, ItemState.INVESTIGATING),
    WorkerRole.FIXER: (ItemState.READY_FOR_FIX, ItemState.FIXING),
    WorkerRole.TESTER: (ItemState.READY_FOR_TEST, ItemState.TESTING),
}


def _datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise TypeError("expected a persisted timestamp")
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _campaign(record: Mapping[str, Any]) -> Campaign:
    config = record.get("config") or {}
    return Campaign(
        id=str(record["id"]),
        name=str(record["name"]),
        description=str(config.get("description", "")),
        status=CampaignStatus(str(record["status"])),
        repository_paths=tuple(config.get("repository_paths", ())),
        global_concurrency_limit=int(record["global_limit"]),
        role_concurrency_limits={
            WorkerRole(str(role)): int(limit)
            for role, limit in (record.get("role_limits") or {}).items()
        },
        created_at=_datetime(record["created_at"]),
        updated_at=_datetime(record["updated_at"]),
    )


def _work_item(record: Mapping[str, Any]) -> WorkItem:
    return WorkItem(
        id=str(record["id"]),
        campaign_id=str(record["campaign_id"]),
        title=str(record["title"]),
        description=str(record["description"]),
        state=ItemState(str(record["state"])),
        required_gates=tuple(record.get("required_gates") or ()),
        priority=int(record["priority"]),
        created_at=_datetime(record["created_at"]),
        updated_at=_datetime(record["updated_at"]),
    )


def _job(record: Mapping[str, Any]) -> Job:
    lease_expires_at = record.get("lease_expires_at")
    return Job(
        id=str(record["id"]),
        campaign_id=str(record["campaign_id"]),
        item_id=str(record.get("item_id") or record["work_item_id"]),
        role=WorkerRole(str(record["role"])),
        status=JobStatus(str(record["status"])),
        attempt_number=int(record.get("attempt_number") or record.get("attempt_count") or 1),
        queued_item_state=ItemState(str(record["queued_item_state"])),
        active_item_state=ItemState(str(record["active_item_state"])),
        required_resources=tuple(record.get("required_resources") or ()),
        payload=dict(record.get("payload") or {}),
        workspace_kind=WorkspaceKind(str(record["workspace_kind"])),
        managed_worktree_id=record.get("managed_worktree_id"),
        lease_token=record.get("lease_token"),
        lease_owner=record.get("lease_owner"),
        lease_expires_at=(
            _datetime(lease_expires_at) if lease_expires_at is not None else None
        ),
        current_attempt_id=record.get("current_attempt_id"),
        resume_external_provider=record.get("resume_external_provider"),
        resume_external_session_id=record.get("resume_external_session_id"),
        created_at=_datetime(record["created_at"]),
        updated_at=_datetime(record["updated_at"]),
    )


class SQLiteSchedulerStorage:
    """Adapt SQLite records and atomic operations to the scheduler protocol."""

    def __init__(
        self,
        store: SQLiteStore,
        *,
        process_reconciler: Optional[ExternalProcessReconciler] = None,
        reconciliation_owner: Optional[str] = None,
        reconciliation_lease_seconds: float = 30.0,
    ) -> None:
        if reconciliation_lease_seconds <= 0:
            raise ValueError("reconciliation_lease_seconds must be positive")
        self.store = store
        self.process_reconciler = process_reconciler or ExternalProcessReconciler()
        minimum_reconciliation_lease = (
            2 * self.process_reconciler.terminate_grace_seconds
            + self.process_reconciler.poll_interval_seconds
        )
        if reconciliation_lease_seconds <= minimum_reconciliation_lease:
            raise ValueError(
                "reconciliation lease must outlast TERM and KILL grace periods"
            )
        self.reconciliation_owner = reconciliation_owner or (
            "agent-flow-reconciler-%d-%s" % (os.getpid(), uuid.uuid4().hex)
        )
        self.reconciliation_lease_seconds = reconciliation_lease_seconds
        self.last_reconciliation_results: List[ReconciliationResult] = []

    def recover_expired_leases(self) -> LeaseRecoveryBatch:
        recovered_job_ids = tuple(
            self.reconcile_expired_processes(max_processes=1)
        )
        return LeaseRecoveryBatch(
            recovered_job_ids=recovered_job_ids,
            reconciliation_count=len(self.last_reconciliation_results),
        )

    def reconcile_expired_processes(
        self,
        *,
        max_processes: Optional[int] = None,
        retry_quarantined: bool = False,
    ) -> Iterable[str]:
        if max_processes is not None and max_processes < 1:
            raise ValueError("max_processes must be positive")
        summary = self.store.recover_expired_leases()
        recovered_job_ids = [
            str(job_id) for job_id in summary.get("job_ids", ())
        ]
        self.last_reconciliation_results = []
        processed_attempt_ids = set()
        while (
            max_processes is None
            or len(self.last_reconciliation_results) < max_processes
        ):
            claim = self.store.claim_external_process_reconciliation(
                self.reconciliation_owner,
                lease_seconds=self.reconciliation_lease_seconds,
                include_quarantined=retry_quarantined,
                exclude_attempt_ids=tuple(processed_attempt_ids),
            )
            if claim is None:
                break
            binding = ExternalProcessBinding.from_mapping(claim)
            processed_attempt_ids.add(binding.attempt_id)
            result = self.process_reconciler.reconcile(binding)
            completion = self.store.complete_external_process_reconciliation(
                binding.attempt_id,
                self.reconciliation_owner,
                str(claim["reconciliation_token"]),
                binding.persistence_identity(),
                result.status.value,
                result.reason,
                observed=result.observed,
            )
            self.last_reconciliation_results.append(result)
            if completion["recovered"]:
                recovered_job_ids.append(str(completion["job_id"]))
        return tuple(dict.fromkeys(recovered_job_ids))

    def claim_job(
        self, role: WorkerRole, worker_id: str, lease_seconds: float
    ) -> Optional[Job]:
        record = self.store.claim_job(role.value, worker_id, lease_seconds=lease_seconds)
        return None if record is None else _job(record)

    def get_campaign(self, campaign_id: str) -> Campaign:
        return _campaign(self.store.get_campaign(campaign_id))

    def get_work_item(self, item_id: str) -> WorkItem:
        return _work_item(self.store.get_work_item(item_id))

    def get_claimed_managed_worktree(
        self, job_id: str, worker_id: str, lease_token: str
    ) -> Optional[Mapping[str, Any]]:
        try:
            return self.store.get_claimed_managed_worktree(
                job_id, worker_id, lease_token
            )
        except LeaseConflict:
            return None

    def quarantine_claimed_managed_worktree(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        reason: str,
    ) -> bool:
        try:
            self.store.quarantine_claimed_managed_worktree(
                job_id,
                worker_id,
                lease_token,
                reason,
            )
        except LeaseConflict:
            return False
        return True

    def heartbeat_job(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        lease_seconds: float,
    ) -> bool:
        try:
            self.store.heartbeat_job(
                job_id,
                worker_id,
                lease_token,
                lease_seconds=lease_seconds,
            )
        except LeaseConflict:
            return False
        return True

    def poll_operator_interrupt(
        self, job_id: str, worker_id: str, lease_token: str
    ) -> Optional[Mapping[str, Any]]:
        try:
            return self.store.poll_operator_interrupt(
                job_id, worker_id, lease_token
            )
        except LeaseConflict:
            return None

    def complete_operator_interrupt(
        self,
        *,
        request_id: str,
        job_id: str,
        worker_id: str,
        lease_token: str,
        reason: str,
    ) -> bool:
        try:
            self.store.interrupt_job(
                job_id,
                worker_id,
                lease_token,
                reason=reason,
                operator_request_id=request_id,
            )
        except LeaseConflict:
            return False
        return True

    def record_external_session(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        provider: str,
        session_id: str,
    ) -> bool:
        try:
            self.store.record_external_session(
                job_id,
                worker_id,
                lease_token,
                provider,
                session_id,
            )
        except LeaseConflict:
            return False
        return True

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
    ) -> bool:
        try:
            self.store.record_external_process(
                job_id,
                worker_id,
                lease_token,
                provider,
                process_id,
                process_group_id,
                owner_uid,
                kernel_executable,
                start_seconds,
                start_microseconds,
                target_executable,
            )
        except LeaseConflict:
            return False
        return True

    def focused_test_guardian_release_fence(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        identity: "ProcessIdentity",
        target_executable: str,
    ) -> ContextManager[None]:
        return self.store.focused_test_guardian_release_fence(
            job_id,
            worker_id,
            lease_token,
            identity.process_id,
            identity.process_group_id,
            identity.user_id,
            identity.executable,
            identity.start_seconds,
            identity.start_microseconds,
            target_executable,
        )

    def clear_external_process(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        process_id: int,
        process_group_id: int,
    ) -> bool:
        try:
            self.store.clear_external_process(
                job_id,
                worker_id,
                lease_token,
                process_id,
                process_group_id,
            )
        except LeaseConflict:
            return False
        return True

    def record_attempt_artifact(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        kind: str,
        uri: str,
        metadata: Mapping[str, Any],
    ) -> bool:
        try:
            self.store.record_attempt_artifact(
                job_id,
                worker_id,
                lease_token,
                kind,
                uri,
                metadata,
            )
        except LeaseConflict:
            return False
        return True

    def prepare_focused_test_execution(
        self, job_id: str, worker_id: str, lease_token: str
    ) -> Optional[Mapping[str, Any]]:
        try:
            return self.store.prepare_focused_test_execution(
                job_id, worker_id, lease_token
            )
        except LeaseConflict:
            return None

    def complete_focused_test_execution(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        result: Mapping[str, Any],
    ) -> Optional[Mapping[str, Any]]:
        try:
            return self.store.complete_focused_test_execution(
                job_id,
                worker_id,
                lease_token,
                dict(result),
            )
        except LeaseConflict:
            return None

    def prepare_browser_evidence_execution(
        self, job_id: str, worker_id: str, lease_token: str
    ) -> Optional[Mapping[str, Any]]:
        try:
            job = self.store.get_job(job_id)
            plans = self.store.list_browser_evidence_plans(
                work_item_id=str(job["work_item_id"])
            )
            if not plans:
                return None
            return self.store.prepare_browser_evidence_execution(
                str(plans[-1]["id"]), job_id, worker_id, lease_token
            )
        except LeaseConflict:
            return None

    def complete_browser_evidence_execution(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        result: Mapping[str, Any],
    ) -> Optional[Mapping[str, Any]]:
        try:
            return self.store.complete_browser_evidence_execution(
                job_id, worker_id, lease_token, dict(result)
            )
        except LeaseConflict:
            return None

    def prepare_database_query_execution(
        self, job_id: str, worker_id: str, lease_token: str
    ) -> Optional[Mapping[str, Any]]:
        try:
            job = self.store.get_job(job_id)
            plans = self.store.list_database_query_plans(
                work_item_id=str(job["work_item_id"])
            )
            if not plans:
                return None
            return self.store.prepare_database_query_execution(
                str(plans[-1]["id"]), job_id, worker_id, lease_token
            )
        except LeaseConflict:
            return None

    def complete_database_query_execution(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        result: Mapping[str, Any],
    ) -> Optional[Mapping[str, Any]]:
        try:
            return self.store.complete_database_query_execution(
                job_id, worker_id, lease_token, dict(result)
            )
        except LeaseConflict:
            return None

    def commit_stage_result(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_token: str,
        handoff: Mapping[str, Any],
        next_item_state: ItemState,
        event_type: str,
        next_job_role: Optional[WorkerRole] = None,
        next_job_payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        current = self.store.get_job(job_id)
        next_job = None
        if next_job_role is not None:
            queued_state, active_state = _ROLE_STATES[next_job_role]
            next_job = {
                "role": next_job_role.value,
                "stage": next_job_role.value,
                "queued_item_state": queued_state.value,
                "active_item_state": active_state.value,
                "payload": dict(next_job_payload or {}),
                "required_approval_action": (
                    LOCAL_WRITE_APPROVAL_ACTION
                    if next_job_role == WorkerRole.FIXER
                    else None
                ),
            }
        try:
            self.store.commit_stage_result(
                job_id,
                worker_id,
                lease_token,
                dict(handoff),
                str(current["active_item_state"]),
                next_item_state.value,
                event_type,
                event_data={"role": current["role"]},
                next_job=next_job,
            )
        except LeaseConflict:
            return False
        return True

    def fail_job(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_token: str,
        error: str,
        max_attempts: int,
    ) -> bool:
        try:
            self.store.fail_job(
                job_id,
                worker_id,
                lease_token,
                error,
                requeue=True,
                max_attempts=max_attempts,
            )
        except LeaseConflict:
            return False
        return True

    def interrupt_job(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_token: str,
        reason: str,
    ) -> bool:
        try:
            self.store.interrupt_job(
                job_id,
                worker_id,
                lease_token,
                reason=reason,
            )
        except LeaseConflict:
            return False
        return True
