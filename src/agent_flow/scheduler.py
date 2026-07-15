"""Async worker-pool scheduling over an atomic storage boundary.

The scheduler deliberately contains no SQL and no durable workflow state.  It
only lends free local worker slots to jobs atomically claimed by ``Storage``.
All final state changes, downstream job creation, evidence persistence, and
lease release happen in one storage transaction through
``commit_stage_result``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Tuple, Type, Union

from pydantic import BaseModel, ValidationError

from agent_flow.models import (
    Campaign,
    EvidenceRef,
    FixHandoff,
    FixOutcome,
    InvestigationHandoff,
    InvestigationOutcome,
    ItemState,
    Job,
    TestHandoff,
    WorkerRole,
    WorkItem,
    evaluate_test_handoff,
)
from agent_flow.process_reconciler import ProcessIdentity
from agent_flow.workers import Worker, WorkerContext, WorkerOutput


class Storage(Protocol):
    """Atomic persistence operations required by the scheduler.

    Implementations are synchronous because the Phase 1 SQLite adapter is
    local and transaction-bounded.  In particular, ``claim_job`` must enforce
    persisted campaign limits and resource exclusion, not merely rely on the
    scheduler's process-local slot counts.
    """

    def recover_expired_leases(self) -> Iterable[str]:
        """Recover expired attempts/resources and return affected job IDs."""

    def claim_job(
        self, role: WorkerRole, worker_id: str, lease_seconds: float
    ) -> Optional[Job]:
        """Atomically claim one eligible job, skipping resource-blocked jobs."""

    def get_campaign(self, campaign_id: str) -> Union[Campaign, Mapping[str, Any]]:
        """Return the campaign for a claimed job."""

    def get_work_item(self, item_id: str) -> Union[WorkItem, Mapping[str, Any]]:
        """Return the work item for a claimed job."""

    def get_claimed_managed_worktree(
        self, job_id: str, worker_id: str, lease_token: str
    ) -> Optional[Mapping[str, Any]]:
        """Return the worktree bound to this exact live job/attempt fence."""

    def quarantine_claimed_managed_worktree(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        reason: str,
    ) -> bool:
        """Quarantine the exact managed worktree behind a live attempt fence."""

    def heartbeat_job(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        lease_seconds: float,
    ) -> bool:
        """Extend a fenced job/resource lease, or reject a stale owner."""

    def poll_operator_interrupt(
        self, job_id: str, worker_id: str, lease_token: str
    ) -> Optional[Mapping[str, Any]]:
        """Return a pending interrupt only when every persisted fence matches."""

    def complete_operator_interrupt(
        self,
        *,
        request_id: str,
        job_id: str,
        worker_id: str,
        lease_token: str,
        reason: str,
    ) -> bool:
        """Atomically apply one exact request after process-group reap."""

    def record_external_session(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        provider: str,
        session_id: str,
    ) -> bool:
        """Bind a provider session to the current fenced attempt."""

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
        """Bind a live provider process to the current fenced attempt."""

    def clear_external_process(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        process_id: int,
        process_group_id: int,
    ) -> bool:
        """Clear a provider process after its process group is reaped."""

    def record_attempt_artifact(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        kind: str,
        uri: str,
        metadata: Mapping[str, Any],
    ) -> bool:
        """Register a durable artifact against the current fenced attempt."""

    def prepare_focused_test_execution(
        self, job_id: str, worker_id: str, lease_token: str
    ) -> Optional[Mapping[str, Any]]:
        """Prepare the immutable focused-test request for this tester attempt."""

    def complete_focused_test_execution(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        result: Mapping[str, Any],
    ) -> Optional[Mapping[str, Any]]:
        """Validate and persist authoritative focused-test output."""

    def prepare_browser_evidence_execution(
        self, job_id: str, worker_id: str, lease_token: str
    ) -> Optional[Mapping[str, Any]]:
        """Prepare one fixed visible-browser request for this tester attempt."""

    def complete_browser_evidence_execution(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        result: Mapping[str, Any],
    ) -> Optional[Mapping[str, Any]]:
        """Validate and persist one fixed browser-evidence result."""

    def prepare_database_query_execution(
        self, job_id: str, worker_id: str, lease_token: str
    ) -> Optional[Mapping[str, Any]]:
        """Prepare one fixed read-only database request for this tester attempt."""

    def complete_database_query_execution(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        result: Mapping[str, Any],
    ) -> Optional[Mapping[str, Any]]:
        """Validate and persist one fixed database-evidence result."""

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
        """Atomically finalize a stage and optionally enqueue its successor."""

    def fail_job(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_token: str,
        error: str,
        max_attempts: int,
    ) -> bool:
        """Atomically fail an attempt and perform the bounded retry decision."""

    def interrupt_job(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_token: str,
        reason: str,
    ) -> bool:
        """Atomically record interruption, release resources, and requeue."""


class InvalidWorkerOutput(ValueError):
    """A worker returned output that is invalid for its claimed role."""


class LeaseLost(RuntimeError):
    """A heartbeat or recovery proved that an active claim is stale."""


class HeartbeatStorageFailure(RuntimeError):
    """Heartbeat storage remained unavailable after bounded retries."""


class OperatorInterruption(RuntimeError):
    """A durable exact-fence operator request cancelled the active worker."""

    def __init__(self, request_id: str, reason: str) -> None:
        super().__init__(reason)
        self.request_id = request_id
        self.reason = reason


@dataclass
class _WorkerSlot:
    role: WorkerRole
    worker_id: str
    worker: Worker
    task: Optional[asyncio.Task[None]] = None
    job_id: Optional[str] = None
    job: Optional[Job] = None

    @property
    def is_free(self) -> bool:
        return self.task is None


_HANDOFF_MODEL_BY_ROLE: Dict[WorkerRole, Type[BaseModel]] = {
    WorkerRole.INVESTIGATOR: InvestigationHandoff,
    WorkerRole.FIXER: FixHandoff,
    WorkerRole.TESTER: TestHandoff,
}


class Scheduler:
    """Run bounded worker pools while storage remains the workflow authority."""

    def __init__(
        self,
        storage: Storage,
        worker_pools: Mapping[WorkerRole, Sequence[Worker]],
        *,
        global_concurrency_limit: int,
        lease_seconds: float = 30.0,
        heartbeat_interval_seconds: Optional[float] = None,
        max_attempts: int = 3,
        heartbeat_error_retries: int = 3,
        worker_id_prefix: str = "agent-flow",
        allow_simulated_evidence: bool = False,
    ) -> None:
        if (
            not isinstance(global_concurrency_limit, int)
            or isinstance(global_concurrency_limit, bool)
            or global_concurrency_limit < 1
        ):
            raise ValueError("global_concurrency_limit must be a positive integer")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        if (
            not isinstance(max_attempts, int)
            or isinstance(max_attempts, bool)
            or max_attempts < 1
        ):
            raise ValueError("max_attempts must be a positive integer")
        if (
            not isinstance(heartbeat_error_retries, int)
            or isinstance(heartbeat_error_retries, bool)
            or heartbeat_error_retries < 0
        ):
            raise ValueError("heartbeat_error_retries must be a non-negative integer")

        heartbeat_interval = (
            lease_seconds / 3.0
            if heartbeat_interval_seconds is None
            else heartbeat_interval_seconds
        )
        if heartbeat_interval <= 0 or heartbeat_interval >= lease_seconds:
            raise ValueError("heartbeat interval must be positive and shorter than the lease")

        self.storage = storage
        self.global_concurrency_limit = global_concurrency_limit
        self.lease_seconds = lease_seconds
        self.heartbeat_interval_seconds = heartbeat_interval
        self.max_attempts = max_attempts
        self.heartbeat_error_retries = heartbeat_error_retries
        self.allow_simulated_evidence = allow_simulated_evidence
        self.errors: List[BaseException] = []
        self.stale_job_ids: List[str] = []
        self._role_cursor = 0
        self._last_recovery_progressed = False

        slots: List[_WorkerSlot] = []
        for role in WorkerRole:
            for index, worker in enumerate(worker_pools.get(role, ())):
                if worker.role != role:
                    raise ValueError(
                        f"{role.value} pool contains a {worker.role.value} worker"
                    )
                slots.append(
                    _WorkerSlot(
                        role=role,
                        worker_id=f"{worker_id_prefix}-{role.value}-{index + 1}",
                        worker=worker,
                    )
                )
        self._slots = slots

    @property
    def active_count(self) -> int:
        return sum(not slot.is_free for slot in self._slots)

    @property
    def active_job_ids(self) -> Tuple[str, ...]:
        return tuple(slot.job_id for slot in self._slots if slot.job_id is not None)

    async def run_once(self) -> int:
        """Recover stale claims, reap workers, and fill currently free slots.

        Jobs are never prefetched: ``claim_job`` is called only for a free
        worker slot and while a process-local global slot remains available.
        A claim miss for one role does not prevent other roles from claiming.
        """

        recovery = await asyncio.to_thread(self.storage.recover_expired_leases)
        recovered = tuple(recovery)
        self._last_recovery_progressed = bool(recovered) or bool(
            getattr(recovery, "reconciliation_count", 0)
        )
        self._cancel_recovered_jobs(recovered)
        self._reap_finished_slots()

        claims = 0
        last_claimed_role: Optional[WorkerRole] = None
        for slot in self._claim_order():
            if self.active_count >= self.global_concurrency_limit:
                break
            if not slot.is_free:
                continue

            job = self.storage.claim_job(
                slot.role,
                slot.worker_id,
                lease_seconds=self.lease_seconds,
            )
            if job is None:
                continue
            self._validate_claim(job, slot)

            slot.job_id = job.id
            slot.job = job
            slot.task = asyncio.create_task(
                self._execute_claim(slot, job),
                name=f"agent-flow:{slot.worker_id}:{job.id}",
            )
            claims += 1
            last_claimed_role = slot.role

        if last_claimed_role is not None:
            roles = tuple(WorkerRole)
            self._role_cursor = (roles.index(last_claimed_role) + 1) % len(roles)

        # Let newly created tasks start before control returns to callers.  This
        # keeps run_once useful for deterministic probes without awaiting the
        # bounded worker to completion.
        if claims:
            await asyncio.sleep(0)
        return claims

    async def run_until_quiescent(self) -> None:
        """Run until no active task can progress and no free slot can claim.

        A queue containing only resource-blocked or otherwise ineligible jobs
        produces claim misses and returns immediately instead of polling in an
        infinite loop.
        """

        while True:
            claims = await self.run_once()
            active_tasks = self._active_tasks()
            if active_tasks:
                await asyncio.wait(active_tasks, return_when=asyncio.FIRST_COMPLETED)
                continue
            if claims == 0:
                if self._last_recovery_progressed:
                    continue
                return

    async def shutdown(self) -> None:
        """Cancel local work and atomically return fenced claims to their queues."""

        active_slots = [slot for slot in self._slots if slot.task is not None]
        tasks = [slot.task for slot in active_slots if slot.task is not None]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        rejected_job_ids = []
        for slot in active_slots:
            job = slot.job
            if job is None or job.lease_token is None:
                continue
            try:
                accepted = self.storage.interrupt_job(
                    job_id=job.id,
                    worker_id=slot.worker_id,
                    lease_token=job.lease_token,
                    reason="scheduler shutdown interrupted active work",
                )
                if not accepted:
                    rejected_job_ids.append(job.id)
            except BaseException as error:
                self.errors.append(error)
                rejected_job_ids.append(job.id)
        try:
            recovered = await asyncio.to_thread(
                lambda: tuple(self.storage.recover_expired_leases())
            )
            self._record_recovered_job_ids(recovered)
        except BaseException as error:
            self.errors.append(error)
        for job_id in rejected_job_ids:
            if job_id not in self.stale_job_ids:
                self.stale_job_ids.append(job_id)
        self._reap_finished_slots()

    def _cancel_recovered_jobs(self, recovered: Optional[Iterable[Any]]) -> None:
        recovered_ids = self._record_recovered_job_ids(recovered)

        if not recovered_ids:
            return
        for slot in self._slots:
            if slot.job_id in recovered_ids and slot.task is not None:
                slot.task.cancel()

    def _record_recovered_job_ids(
        self, recovered: Optional[Iterable[Any]]
    ) -> set[str]:
        recovered_ids = set()
        for recovered_job in recovered or ():
            if isinstance(recovered_job, str):
                recovered_ids.add(recovered_job)
            else:
                job_id = getattr(recovered_job, "id", None)
                if job_id is not None:
                    recovered_ids.add(str(job_id))

        for job_id in sorted(recovered_ids):
            if job_id not in self.stale_job_ids:
                self.stale_job_ids.append(job_id)
        return recovered_ids

    def _reap_finished_slots(self) -> None:
        for slot in self._slots:
            task = slot.task
            if task is None or not task.done():
                continue
            try:
                task.result()
            except asyncio.CancelledError:
                pass
            except BaseException as error:  # preserve storage/invariant failures for the caller
                self.errors.append(error)
            slot.task = None
            slot.job_id = None
            slot.job = None

    def _active_tasks(self) -> List[asyncio.Task[None]]:
        return [slot.task for slot in self._slots if slot.task is not None]

    def _claim_order(self) -> List[_WorkerSlot]:
        """Interleave role lanes so an upstream backlog cannot starve testing."""

        roles = tuple(WorkerRole)
        ordered_roles = roles[self._role_cursor :] + roles[: self._role_cursor]
        slots_by_role = {
            role: [slot for slot in self._slots if slot.role == role]
            for role in ordered_roles
        }
        max_lanes = max((len(slots) for slots in slots_by_role.values()), default=0)
        return [
            slots_by_role[role][lane]
            for lane in range(max_lanes)
            for role in ordered_roles
            if lane < len(slots_by_role[role])
        ]

    @staticmethod
    def _validate_claim(job: Job, slot: _WorkerSlot) -> None:
        if job.role != slot.role:
            raise RuntimeError(
                f"storage returned a {job.role.value} job to a {slot.role.value} slot"
            )
        if not job.lease_token or job.lease_owner != slot.worker_id:
            raise RuntimeError("storage returned a claim without the requested lease fence")

    async def _execute_claim(self, slot: _WorkerSlot, job: Job) -> None:
        lease_token = job.lease_token
        if lease_token is None:  # guarded by _validate_claim; narrows the type
            raise RuntimeError("claimed job is missing a lease token")

        try:
            campaign_record = self.storage.get_campaign(job.campaign_id)
            item_record = self.storage.get_work_item(job.item_id)
            campaign = _as_mapping(campaign_record)
            item = _as_mapping(item_record)
            if str(item.get("id")) != job.item_id:
                raise RuntimeError("storage returned a work item that does not match the claim")
            if str(campaign.get("id")) != job.campaign_id:
                raise RuntimeError("storage returned a campaign that does not match the claim")

            def record_external_session(provider: str, session_id: str) -> None:
                self._record_external_session(
                    slot, job, provider, session_id
                )

            def record_external_process(
                provider: str,
                identity: ProcessIdentity,
                target_executable: str,
            ) -> None:
                self._record_external_process(
                    slot,
                    job,
                    provider,
                    identity,
                    target_executable,
                )

            def clear_external_process(
                process_id: int, process_group_id: int
            ) -> None:
                self._clear_external_process(
                    slot, job, process_id, process_group_id
                )

            def record_artifact(
                kind: str, uri: str, metadata: Mapping[str, Any]
            ) -> None:
                self._record_attempt_artifact(
                    slot, job, kind, uri, metadata
                )

            def require_managed_worktree() -> Optional[Mapping[str, Any]]:
                worktree = self.storage.get_claimed_managed_worktree(
                    job.id, slot.worker_id, lease_token
                )
                if worktree is None and job.managed_worktree_id is not None:
                    raise LeaseLost(
                        "managed worktree lookup rejected the stale lease fence"
                    )
                return worktree

            def quarantine_managed_worktree(reason: str) -> bool:
                return self.storage.quarantine_claimed_managed_worktree(
                    job.id,
                    slot.worker_id,
                    lease_token,
                    reason,
                )

            def prepare_focused_test_execution() -> Mapping[str, Any]:
                return self._prepare_focused_test_execution(slot, job)

            def complete_focused_test_execution(
                result: Mapping[str, Any],
            ) -> Mapping[str, Any]:
                return self._complete_focused_test_execution(slot, job, result)

            def prepare_browser_evidence_execution() -> Mapping[str, Any]:
                return self._prepare_browser_evidence_execution(slot, job)

            def complete_browser_evidence_execution(
                result: Mapping[str, Any],
            ) -> Mapping[str, Any]:
                return self._complete_browser_evidence_execution(slot, job, result)

            def prepare_database_query_execution() -> Mapping[str, Any]:
                return self._prepare_database_query_execution(slot, job)

            def complete_database_query_execution(
                result: Mapping[str, Any],
            ) -> Mapping[str, Any]:
                return self._complete_database_query_execution(slot, job, result)

            context = WorkerContext(
                campaign=campaign,
                item=item,
                job=_as_mapping(job),
                _external_session_recorder=record_external_session,
                _external_process_recorder=record_external_process,
                _external_process_clearer=clear_external_process,
                _artifact_recorder=record_artifact,
                _managed_worktree_provider=require_managed_worktree,
                _managed_worktree_quarantiner=quarantine_managed_worktree,
                _focused_test_execution_preparer=prepare_focused_test_execution,
                _focused_test_execution_completer=complete_focused_test_execution,
                _browser_evidence_execution_preparer=(
                    prepare_browser_evidence_execution
                ),
                _browser_evidence_execution_completer=(
                    complete_browser_evidence_execution
                ),
                _database_query_execution_preparer=prepare_database_query_execution,
                _database_query_execution_completer=complete_database_query_execution,
            )
            output = await self._run_worker_with_heartbeat(slot, job, context)
            pending_interrupt = self._poll_operator_interrupt(slot, job)
            if pending_interrupt is not None:
                raise pending_interrupt
            handoff = _validate_and_bind_output(job.role, job.item_id, output)
            _validate_evidence_attachments(
                handoff, allow_simulated=self.allow_simulated_evidence
            )
            self._finalize_handoff(slot, job, handoff)
        except OperatorInterruption as interruption:
            accepted = self.storage.complete_operator_interrupt(
                request_id=interruption.request_id,
                job_id=job.id,
                worker_id=slot.worker_id,
                lease_token=lease_token,
                reason=interruption.reason,
            )
            if not accepted:
                self.stale_job_ids.append(job.id)
        except LeaseLost:
            self.stale_job_ids.append(job.id)
        except HeartbeatStorageFailure as error:
            self.errors.append(error)
            try:
                accepted = self.storage.interrupt_job(
                    job_id=job.id,
                    worker_id=slot.worker_id,
                    lease_token=lease_token,
                    reason="heartbeat storage failure interrupted active work",
                )
                if not accepted:
                    recovered = await asyncio.to_thread(
                        lambda: tuple(self.storage.recover_expired_leases())
                    )
                    self._record_recovered_job_ids(recovered)
                    if job.id not in self.stale_job_ids:
                        self.stale_job_ids.append(job.id)
            except BaseException as recovery_error:
                self.errors.append(recovery_error)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            accepted = self.storage.fail_job(
                job_id=job.id,
                worker_id=slot.worker_id,
                lease_token=lease_token,
                error=f"{type(error).__name__}: {error}",
                max_attempts=self.max_attempts,
            )
            if not accepted:
                pending_interrupt = self._poll_operator_interrupt(slot, job)
                if pending_interrupt is None:
                    self.stale_job_ids.append(job.id)
                else:
                    completed = self.storage.complete_operator_interrupt(
                        request_id=pending_interrupt.request_id,
                        job_id=job.id,
                        worker_id=slot.worker_id,
                        lease_token=lease_token,
                        reason=pending_interrupt.reason,
                    )
                    if not completed:
                        self.stale_job_ids.append(job.id)

    def _record_external_session(
        self,
        slot: _WorkerSlot,
        job: Job,
        provider: str,
        session_id: str,
    ) -> None:
        lease_token = job.lease_token
        if lease_token is None:
            raise LeaseLost("claimed job has no lease token")
        accepted = self.storage.record_external_session(
            job.id,
            slot.worker_id,
            lease_token,
            provider,
            session_id,
        )
        if not accepted:
            raise LeaseLost("external session binding rejected the stale lease fence")

    def _record_external_process(
        self,
        slot: _WorkerSlot,
        job: Job,
        provider: str,
        identity: ProcessIdentity,
        target_executable: str,
    ) -> None:
        lease_token = job.lease_token
        if lease_token is None:
            raise LeaseLost("claimed job has no lease token")
        accepted = self.storage.record_external_process(
            job.id,
            slot.worker_id,
            lease_token,
            provider,
            identity.process_id,
            identity.process_group_id,
            identity.user_id,
            identity.executable,
            identity.start_seconds,
            identity.start_microseconds,
            target_executable,
        )
        if not accepted:
            raise LeaseLost("external process binding rejected the stale lease fence")

    def _clear_external_process(
        self,
        slot: _WorkerSlot,
        job: Job,
        process_id: int,
        process_group_id: int,
    ) -> None:
        lease_token = job.lease_token
        if lease_token is None:
            raise LeaseLost("claimed job has no lease token")
        accepted = self.storage.clear_external_process(
            job.id,
            slot.worker_id,
            lease_token,
            process_id,
            process_group_id,
        )
        if not accepted:
            raise LeaseLost("external process clearing rejected the stale lease fence")

    def _record_attempt_artifact(
        self,
        slot: _WorkerSlot,
        job: Job,
        kind: str,
        uri: str,
        metadata: Mapping[str, Any],
    ) -> None:
        lease_token = job.lease_token
        if lease_token is None:
            raise LeaseLost("claimed job has no lease token")
        accepted = self.storage.record_attempt_artifact(
            job.id,
            slot.worker_id,
            lease_token,
            kind,
            uri,
            metadata,
        )
        if not accepted:
            raise LeaseLost("artifact registration rejected the stale lease fence")

    def _prepare_focused_test_execution(
        self, slot: _WorkerSlot, job: Job
    ) -> Mapping[str, Any]:
        lease_token = job.lease_token
        if lease_token is None:
            raise LeaseLost("claimed job has no lease token")
        prepared = self.storage.prepare_focused_test_execution(
            job.id, slot.worker_id, lease_token
        )
        if prepared is None:
            raise LeaseLost(
                "focused-test preparation rejected the stale lease fence"
            )
        return prepared

    def _complete_focused_test_execution(
        self,
        slot: _WorkerSlot,
        job: Job,
        result: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        lease_token = job.lease_token
        if lease_token is None:
            raise LeaseLost("claimed job has no lease token")
        completed = self.storage.complete_focused_test_execution(
            job.id,
            slot.worker_id,
            lease_token,
            result,
        )
        if completed is None:
            raise LeaseLost(
                "focused-test completion rejected the stale lease fence"
            )
        return completed

    def _prepare_browser_evidence_execution(
        self, slot: _WorkerSlot, job: Job
    ) -> Mapping[str, Any]:
        lease_token = job.lease_token
        if lease_token is None:
            raise LeaseLost("claimed job has no lease token")
        prepared = self.storage.prepare_browser_evidence_execution(
            job.id, slot.worker_id, lease_token
        )
        if prepared is None:
            raise LeaseLost(
                "browser-evidence preparation rejected the stale lease fence"
            )
        return prepared

    def _complete_browser_evidence_execution(
        self,
        slot: _WorkerSlot,
        job: Job,
        result: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        lease_token = job.lease_token
        if lease_token is None:
            raise LeaseLost("claimed job has no lease token")
        completed = self.storage.complete_browser_evidence_execution(
            job.id, slot.worker_id, lease_token, result
        )
        if completed is None:
            raise LeaseLost(
                "browser-evidence completion rejected the stale lease fence"
            )
        return completed

    def _prepare_database_query_execution(
        self, slot: _WorkerSlot, job: Job
    ) -> Mapping[str, Any]:
        lease_token = job.lease_token
        if lease_token is None:
            raise LeaseLost("claimed job has no lease token")
        prepared = self.storage.prepare_database_query_execution(
            job.id, slot.worker_id, lease_token
        )
        if prepared is None:
            raise LeaseLost(
                "database-evidence preparation rejected the stale lease fence"
            )
        return prepared

    def _complete_database_query_execution(
        self,
        slot: _WorkerSlot,
        job: Job,
        result: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        lease_token = job.lease_token
        if lease_token is None:
            raise LeaseLost("claimed job has no lease token")
        completed = self.storage.complete_database_query_execution(
            job.id, slot.worker_id, lease_token, result
        )
        if completed is None:
            raise LeaseLost(
                "database-evidence completion rejected the stale lease fence"
            )
        return completed

    async def _run_worker_with_heartbeat(
        self,
        slot: _WorkerSlot,
        job: Job,
        context: WorkerContext,
    ) -> WorkerOutput:
        worker_task = asyncio.create_task(slot.worker.run(context))
        heartbeat_task = asyncio.create_task(self._heartbeat(slot, job))
        try:
            done, _ = await asyncio.wait(
                (worker_task, heartbeat_task),
                return_when=asyncio.FIRST_COMPLETED,
            )

            # A rejected/erroring heartbeat takes precedence even when the
            # worker happens to finish during the same event-loop turn.
            if heartbeat_task in done:
                try:
                    heartbeat_task.result()
                except OperatorInterruption:
                    heartbeat_task = asyncio.create_task(
                        self._heartbeat(
                            slot, job, poll_operator_interrupt=False
                        )
                    )
                    if not worker_task.done():
                        worker_task.cancel()
                    await asyncio.gather(worker_task, return_exceptions=True)
                    raise
            return worker_task.result()
        finally:
            for task in (worker_task, heartbeat_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(worker_task, heartbeat_task, return_exceptions=True)

    async def _heartbeat(
        self,
        slot: _WorkerSlot,
        job: Job,
        *,
        poll_operator_interrupt: bool = True,
    ) -> None:
        lease_token = job.lease_token
        if lease_token is None:
            raise LeaseLost("claimed job has no lease token")
        while True:
            await asyncio.sleep(self.heartbeat_interval_seconds)
            accepted = None
            for retry in range(self.heartbeat_error_retries + 1):
                try:
                    accepted = self.storage.heartbeat_job(
                        job.id,
                        slot.worker_id,
                        lease_token,
                        lease_seconds=self.lease_seconds,
                    )
                    break
                except Exception as error:
                    if retry == self.heartbeat_error_retries:
                        raise HeartbeatStorageFailure(
                            "heartbeat storage failed after %d attempt(s): %s"
                            % (retry + 1, error)
                        ) from error
                    await asyncio.sleep(
                        min(0.05, self.heartbeat_interval_seconds / 10.0)
                    )
            if not accepted:
                raise LeaseLost("heartbeat rejected the stale lease fence")
            if poll_operator_interrupt:
                interrupt = self._poll_operator_interrupt(slot, job)
                if interrupt is not None:
                    raise interrupt

    def _poll_operator_interrupt(
        self, slot: _WorkerSlot, job: Job
    ) -> Optional[OperatorInterruption]:
        lease_token = job.lease_token
        if lease_token is None:
            raise LeaseLost("claimed job has no lease token")
        poll_interrupt = getattr(self.storage, "poll_operator_interrupt", None)
        interrupt = (
            None
            if poll_interrupt is None
            else poll_interrupt(job.id, slot.worker_id, lease_token)
        )
        if interrupt is None:
            return None
        request_id = interrupt.get("id")
        reason = interrupt.get("reason")
        if not isinstance(request_id, str) or not isinstance(reason, str):
            raise HeartbeatStorageFailure(
                "operator interrupt storage returned an invalid request"
            )
        return OperatorInterruption(request_id, reason)

    def _finalize_handoff(self, slot: _WorkerSlot, job: Job, handoff: BaseModel) -> None:
        lease_token = job.lease_token
        if lease_token is None:
            raise LeaseLost("claimed job has no lease token")

        next_state: ItemState
        event_type: str
        next_role: Optional[WorkerRole] = None
        next_payload: Optional[Mapping[str, Any]] = None

        handoff_payload = handoff.model_dump(mode="json")
        if isinstance(handoff, InvestigationHandoff):
            if handoff.outcome == InvestigationOutcome.BLOCKED:
                next_state = ItemState.BLOCKED
                event_type = "investigation_blocked"
            else:
                next_state = ItemState.READY_FOR_FIX
                event_type = "investigation_completed"
                next_role = WorkerRole.FIXER
                next_payload = {"investigation_handoff": handoff_payload}
        elif isinstance(handoff, FixHandoff):
            if handoff.outcome == FixOutcome.BLOCKED:
                next_state = ItemState.BLOCKED
                event_type = "fix_blocked"
            else:
                next_state = ItemState.READY_FOR_TEST
                event_type = "fix_completed"
                next_role = WorkerRole.TESTER
                next_payload = {"fix_handoff": handoff_payload}
        elif isinstance(handoff, TestHandoff):
            item = self.storage.get_work_item(job.item_id)
            required_gates = WorkItem.model_validate(_as_mapping(item)).required_gates
            evaluation = evaluate_test_handoff(required_gates, handoff)
            if not evaluation.can_advance or evaluation.next_state is None:
                reasons = "; ".join(evaluation.reasons) or "test evidence gate rejected"
                raise InvalidWorkerOutput(reasons)

            next_state = evaluation.next_state
            if next_state == ItemState.VERIFIED_GREEN:
                event_type = "test_verified_green"
            elif next_state == ItemState.READY_FOR_FIX:
                event_type = "test_returned_to_fix"
                next_role = WorkerRole.FIXER
                next_payload = {
                    "test_failure": handoff_payload,
                    "gate_evaluation": evaluation.model_dump(mode="json"),
                }
            elif next_state == ItemState.BLOCKED:
                event_type = "test_blocked"
            else:  # deterministic evaluator must never invent another path
                raise RuntimeError(f"unsupported test gate transition: {next_state.value}")
        else:  # role validation always returns one of the concrete schemas
            raise RuntimeError(f"unsupported handoff type: {type(handoff).__name__}")

        accepted = self.storage.commit_stage_result(
            job_id=job.id,
            worker_id=slot.worker_id,
            lease_token=lease_token,
            handoff=handoff_payload,
            next_item_state=next_state,
            event_type=event_type,
            next_job_role=next_role,
            next_job_payload=next_payload,
        )
        if not accepted:
            pending_interrupt = self._poll_operator_interrupt(slot, job)
            if pending_interrupt is not None:
                raise pending_interrupt
            raise LeaseLost("stage finalization rejected the stale lease fence")


def _as_mapping(record: Union[BaseModel, Mapping[str, Any]]) -> Dict[str, Any]:
    if isinstance(record, BaseModel):
        return record.model_dump(mode="json")
    if isinstance(record, Mapping):
        return dict(record)
    raise TypeError(f"expected a model or mapping, got {type(record).__name__}")


def _validate_and_bind_output(
    role: WorkerRole,
    item_id: str,
    output: WorkerOutput,
) -> BaseModel:
    """Strictly parse role output while binding identity to the claimed item."""

    if isinstance(output, BaseModel):
        payload = output.model_dump(mode="python")
    elif isinstance(output, Mapping):
        payload = dict(output)
    else:
        raise InvalidWorkerOutput(
            f"{role.value} output must be a pydantic model or mapping"
        )

    # The worker's item_id is untrusted.  The current fenced claim is the sole
    # identity authority, so even a valid handoff cannot redirect its result.
    payload["item_id"] = item_id
    handoff_model = _HANDOFF_MODEL_BY_ROLE[role]
    try:
        return handoff_model.model_validate(payload)
    except ValidationError as error:
        raise InvalidWorkerOutput(
            f"invalid {role.value} handoff: {error}"
        ) from error


def _validate_evidence_attachments(
    handoff: BaseModel, *, allow_simulated: bool
) -> None:
    evidence_refs = list(_walk_evidence(handoff))
    for evidence in evidence_refs:
        simulated = evidence.metadata.get("simulated") is True
        if simulated:
            if not allow_simulated:
                raise InvalidWorkerOutput(
                    "simulated evidence is disabled for this scheduler run"
                )
            continue

        location = Path(evidence.location).expanduser()
        if not location.is_absolute() or not location.is_file():
            raise InvalidWorkerOutput(
                "evidence attachment does not exist as an absolute file: %s"
                % evidence.location
            )


def _walk_evidence(value: Any) -> Iterable[EvidenceRef]:
    if isinstance(value, EvidenceRef):
        yield value
        return
    if isinstance(value, BaseModel):
        for field_name in type(value).model_fields:
            yield from _walk_evidence(getattr(value, field_name))
        return
    if isinstance(value, Mapping):
        for child in value.values():
            yield from _walk_evidence(child)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_evidence(child)
