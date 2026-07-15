from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import timedelta
from threading import Event
from typing import Any, Dict, Iterable, Mapping, Optional
from uuid import uuid4

import pytest

from agent_flow import models as domain_models
from agent_flow.models import (
    Campaign,
    EvidenceKind,
    EvidenceRef,
    FixHandoff,
    GateKind,
    GateProof,
    GateResult,
    InvestigationHandoff,
    ItemState,
    Job,
    JobStatus,
    WorkerRole,
    WorkItem,
    utc_now,
)
from agent_flow.scheduler import Scheduler
from agent_flow.workers import ScriptedWorker, WorkerContext, WorkerOutput


def _evidence(kind: EvidenceKind = EvidenceKind.TEST) -> EvidenceRef:
    return EvidenceRef(
        kind=kind,
        location="/private/tmp/agent-flow-proof.txt",
        description="deterministic test evidence",
        metadata={"simulated": True},
    )


def _investigation(item_id: str) -> InvestigationHandoff:
    return InvestigationHandoff(
        item_id=item_id,
        synopsis="The defect is reproducible.",
        reproduction_steps=("Open the exact workflow.",),
        root_cause="The bounded fake dependency returns stale state.",
        proposed_fix="Update the bounded state transition.",
        acceptance_criteria=("The exact workflow returns current state.",),
        evidence=(_evidence(EvidenceKind.LOG),),
    )


def _fix(item_id: str) -> FixHandoff:
    return FixHandoff(
        item_id=item_id,
        summary="Applied the surgical state-transition fix.",
        changed_files=("src/example.py",),
        tests_run=("python3 -m pytest tests/test_example.py",),
        tester_instructions=("Exercise the exact workflow.",),
        evidence=(_evidence(),),
    )


def _passing_test(item_id: str) -> domain_models.TestHandoff:
    return domain_models.TestHandoff(
        item_id=item_id,
        outcome=domain_models.TestOutcome.PASS,
        summary="The required focused test is green.",
        gate_proofs=(
            GateProof(
                gate=GateKind.FOCUSED_TESTS,
                result=GateResult.PASS,
                summary="Focused test passed.",
                evidence=(_evidence(),),
            ),
        ),
    )


def _red_test(item_id: str) -> domain_models.TestHandoff:
    return domain_models.TestHandoff(
        item_id=item_id,
        outcome=domain_models.TestOutcome.RED,
        summary="The focused regression remains red.",
        failure_summary="Focused test still reproduces the defect.",
        gate_proofs=(
            GateProof(
                gate=GateKind.FOCUSED_TESTS,
                result=GateResult.FAIL,
                summary="Focused test failed.",
                evidence=(_evidence(),),
            ),
        ),
    )


class FakeStore:
    """In-memory storage boundary; scheduler tests intentionally exercise no SQL."""

    def __init__(self, campaign: Campaign, items: Iterable[WorkItem], jobs: Iterable[Job]):
        self.campaigns = {campaign.id: campaign}
        self.items = {item.id: item for item in items}
        self.jobs = {job.id: job for job in jobs}
        self.claim_calls: Dict[WorkerRole, int] = defaultdict(int)
        self.failures: list[Dict[str, Any]] = []
        self.interruptions: list[Dict[str, Any]] = []
        self.commits: list[Dict[str, Any]] = []
        self.events: list[Dict[str, Any]] = []
        self.recover_next: list[str] = []
        self.heartbeat_accepted = True
        self.heartbeat_calls = 0
        self.recovery_started: Optional[Event] = None
        self.recovery_release: Optional[Event] = None
        self.focused_test_preparations: list[Dict[str, Any]] = []
        self.focused_test_completions: list[Dict[str, Any]] = []

    def recover_expired_leases(self) -> Iterable[str]:
        if self.recovery_started is not None:
            self.recovery_started.set()
        if self.recovery_release is not None:
            self.recovery_release.wait(timeout=2)
        recovered = tuple(self.recover_next)
        self.recover_next.clear()
        return recovered

    def claim_job(
        self, role: WorkerRole, worker_id: str, lease_seconds: float
    ) -> Optional[Job]:
        self.claim_calls[role] += 1
        for job_id, job in tuple(self.jobs.items()):
            item = self.items[job.item_id]
            if (
                job.role != role
                or job.status != JobStatus.PENDING
                or item.state != job.queued_item_state
            ):
                continue
            token = f"fence-{uuid4()}"
            expiry = utc_now() + timedelta(seconds=lease_seconds)
            claimed = Job.model_validate(
                {
                    **job.model_dump(mode="python"),
                    "status": JobStatus.RUNNING,
                    "lease_token": token,
                    "lease_owner": worker_id,
                    "lease_expires_at": expiry,
                    "updated_at": utc_now(),
                }
            )
            self.jobs[job_id] = claimed
            self.items[item.id] = item.model_copy(
                update={"state": job.active_item_state, "updated_at": utc_now()}
            )
            self.events.append(
                {
                    "type": "job_claimed",
                    "item_id": item.id,
                    "to_state": job.active_item_state,
                }
            )
            return claimed
        return None

    def get_campaign(self, campaign_id: str) -> Campaign:
        return self.campaigns[campaign_id]

    def get_work_item(self, item_id: str) -> WorkItem:
        return self.items[item_id]

    def heartbeat_job(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        lease_seconds: float,
    ) -> bool:
        self.heartbeat_calls += 1
        job = self.jobs[job_id]
        return bool(
            self.heartbeat_accepted
            and job.lease_owner == worker_id
            and job.lease_token == lease_token
        )

    def prepare_focused_test_execution(
        self, job_id: str, worker_id: str, lease_token: str
    ) -> Optional[Mapping[str, Any]]:
        job = self.jobs[job_id]
        if job.lease_owner != worker_id or job.lease_token != lease_token:
            return None
        prepared = {
            "id": "focused-execution",
            "command": ["/usr/bin/true"],
        }
        self.focused_test_preparations.append(dict(prepared))
        return prepared

    def complete_focused_test_execution(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        result: Mapping[str, Any],
    ) -> Optional[Mapping[str, Any]]:
        job = self.jobs[job_id]
        if job.lease_owner != worker_id or job.lease_token != lease_token:
            return None
        self.focused_test_completions.append(dict(result))
        return {"canonical_handoff": _passing_test(job.item_id).model_dump(mode="json")}

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
        job = self.jobs[job_id]
        if job.lease_owner != worker_id or job.lease_token != lease_token:
            return False
        item = self.items[job.item_id]
        self.jobs[job_id] = Job.model_validate(
            {
                **job.model_dump(mode="python"),
                "status": JobStatus.COMPLETED,
                "lease_token": None,
                "lease_owner": None,
                "lease_expires_at": None,
                "updated_at": utc_now(),
            }
        )
        self.items[item.id] = item.model_copy(
            update={"state": next_item_state, "updated_at": utc_now()}
        )
        commit = {
            "job_id": job_id,
            "item_id": job.item_id,
            "handoff": dict(handoff),
            "next_item_state": next_item_state,
            "event_type": event_type,
            "next_job_role": next_job_role,
            "next_job_payload": dict(next_job_payload or {}),
        }
        self.commits.append(commit)
        self.events.append(
            {
                "type": event_type,
                "item_id": job.item_id,
                "to_state": next_item_state,
            }
        )
        if next_job_role is not None:
            next_job = Job(
                campaign_id=job.campaign_id,
                item_id=job.item_id,
                role=next_job_role,
                payload=dict(next_job_payload or {}),
            )
            self.jobs[next_job.id] = next_job
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
        job = self.jobs[job_id]
        if job.lease_owner != worker_id or job.lease_token != lease_token:
            return False
        self.failures.append({"job_id": job_id, "error": error})
        item = self.items[job.item_id]
        if job.attempt_number < max_attempts:
            status = JobStatus.PENDING
            state = job.queued_item_state
            attempt_number = job.attempt_number + 1
        else:
            status = JobStatus.FAILED
            state = ItemState.BLOCKED
            attempt_number = job.attempt_number
        self.jobs[job_id] = Job.model_validate(
            {
                **job.model_dump(mode="python"),
                "status": status,
                "attempt_number": attempt_number,
                "lease_token": None,
                "lease_owner": None,
                "lease_expires_at": None,
                "updated_at": utc_now(),
            }
        )
        self.items[item.id] = item.model_copy(update={"state": state, "updated_at": utc_now()})
        self.events.append(
            {
                "type": "job_retry_queued" if status == JobStatus.PENDING else "job_failed",
                "item_id": item.id,
                "to_state": state,
            }
        )
        return True

    def interrupt_job(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_token: str,
        reason: str,
    ) -> bool:
        job = self.jobs[job_id]
        if job.lease_owner != worker_id or job.lease_token != lease_token:
            return False
        self.interruptions.append({"job_id": job_id, "reason": reason})
        item = self.items[job.item_id]
        self.jobs[job_id] = Job.model_validate(
            {
                **job.model_dump(mode="python"),
                "status": JobStatus.PENDING,
                "lease_token": None,
                "lease_owner": None,
                "lease_expires_at": None,
                "updated_at": utc_now(),
            }
        )
        self.items[item.id] = item.model_copy(
            update={"state": job.queued_item_state, "updated_at": utc_now()}
        )
        self.events.append(
            {
                "type": "job_interrupted",
                "item_id": item.id,
                "to_state": job.queued_item_state,
            }
        )
        return True


class BlockingWorker:
    def __init__(self, role: WorkerRole, output_factory: Any):
        self.role = role
        self.output_factory = output_factory
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.calls: list[WorkerContext] = []

    async def run(self, context: WorkerContext) -> WorkerOutput:
        self.calls.append(context)
        self.started.set()
        await self.release.wait()
        return self.output_factory(context)


def _campaign() -> Campaign:
    return Campaign(name="Phase 1 scheduler proof", global_concurrency_limit=4)


def _item(campaign: Campaign, item_id: str, state: ItemState) -> WorkItem:
    return WorkItem(
        id=item_id,
        campaign_id=campaign.id,
        title=f"Item {item_id}",
        description="A deterministic scheduler test item.",
        state=state,
        required_gates=(GateKind.FOCUSED_TESTS,),
    )


def _job(campaign: Campaign, item: WorkItem, role: WorkerRole) -> Job:
    return Job(campaign_id=campaign.id, item_id=item.id, role=role)


def test_scheduler_rejects_fractional_global_concurrency_limit() -> None:
    campaign = _campaign()
    item = _item(campaign, "fractional-limit", ItemState.BACKLOG)
    store = FakeStore(
        campaign,
        (item,),
        (_job(campaign, item, WorkerRole.INVESTIGATOR),),
    )
    with pytest.raises(ValueError, match="positive integer"):
        Scheduler(
            store,
            {
                WorkerRole.INVESTIGATOR: (
                    ScriptedWorker(
                        WorkerRole.INVESTIGATOR,
                        default=lambda context: _investigation(context.item_id),
                    ),
                )
            },
            global_concurrency_limit=1.5,  # type: ignore[arg-type]
            allow_simulated_evidence=True,
        )

    with pytest.raises(ValueError, match="max_attempts must be a positive integer"):
        Scheduler(
            store,
            {},
            global_concurrency_limit=1,
            max_attempts=1.5,  # type: ignore[arg-type]
        )


def test_scheduler_never_claims_without_a_free_worker_slot() -> None:
    async def scenario() -> None:
        campaign = _campaign()
        item = _item(campaign, "one", ItemState.BACKLOG)
        waiting_item = _item(campaign, "two", ItemState.BACKLOG)
        store = FakeStore(
            campaign,
            (item, waiting_item),
            (
                _job(campaign, item, WorkerRole.INVESTIGATOR),
                _job(campaign, waiting_item, WorkerRole.INVESTIGATOR),
            ),
        )
        worker = BlockingWorker(
            WorkerRole.INVESTIGATOR,
            lambda context: _investigation(context.item_id),
        )
        scheduler = Scheduler(
            store,
            {WorkerRole.INVESTIGATOR: (worker,)},
            global_concurrency_limit=1,
            allow_simulated_evidence=True,
        )

        assert await scheduler.run_once() == 1
        await worker.started.wait()
        assert store.claim_calls[WorkerRole.INVESTIGATOR] == 1

        assert await scheduler.run_once() == 0
        assert store.claim_calls[WorkerRole.INVESTIGATOR] == 1
        assert scheduler.active_count == 1

        worker.release.set()
        await scheduler.run_until_quiescent()
        assert store.items[item.id].state == ItemState.READY_FOR_FIX
        assert store.items[waiting_item.id].state == ItemState.READY_FOR_FIX

    asyncio.run(scenario())


def test_scheduler_global_limit_reserves_only_one_cross_role_slot() -> None:
    async def scenario() -> None:
        campaign = _campaign()
        investigation_item = _item(campaign, "investigate", ItemState.BACKLOG)
        fix_item = _item(campaign, "fix", ItemState.READY_FOR_FIX)
        store = FakeStore(
            campaign,
            (investigation_item, fix_item),
            (
                _job(campaign, investigation_item, WorkerRole.INVESTIGATOR),
                _job(campaign, fix_item, WorkerRole.FIXER),
            ),
        )
        investigator = BlockingWorker(
            WorkerRole.INVESTIGATOR,
            lambda context: _investigation(context.item_id),
        )
        fixer = BlockingWorker(WorkerRole.FIXER, lambda context: _fix(context.item_id))
        scheduler = Scheduler(
            store,
            {
                WorkerRole.INVESTIGATOR: (investigator,),
                WorkerRole.FIXER: (fixer,),
            },
            global_concurrency_limit=1,
            allow_simulated_evidence=True,
        )

        assert await scheduler.run_once() == 1
        await investigator.started.wait()
        assert scheduler.active_count == 1
        assert store.claim_calls[WorkerRole.FIXER] == 0

        investigator.release.set()
        for _ in range(20):
            await scheduler.run_once()
            if fixer.started.is_set():
                break
            await asyncio.sleep(0)
        await fixer.started.wait()
        assert scheduler.active_count == 1

        fixer.release.set()
        await scheduler.run_until_quiescent()

    asyncio.run(scenario())


def test_busy_fixer_does_not_stop_an_eligible_tester() -> None:
    async def scenario() -> None:
        campaign = _campaign()
        fix_item = _item(campaign, "slow-fix", ItemState.READY_FOR_FIX)
        test_item = _item(campaign, "fast-test", ItemState.READY_FOR_TEST)
        store = FakeStore(
            campaign,
            (fix_item, test_item),
            (
                _job(campaign, fix_item, WorkerRole.FIXER),
                _job(campaign, test_item, WorkerRole.TESTER),
            ),
        )
        fixer = BlockingWorker(WorkerRole.FIXER, lambda context: _fix(context.item_id))
        tester = ScriptedWorker(
            WorkerRole.TESTER,
            default=lambda context: _passing_test(context.item_id),
        )
        scheduler = Scheduler(
            store,
            {WorkerRole.FIXER: (fixer,), WorkerRole.TESTER: (tester,)},
            global_concurrency_limit=2,
            allow_simulated_evidence=True,
        )

        assert await scheduler.run_once() == 2
        await fixer.started.wait()
        for _ in range(10):
            if store.items[test_item.id].state == ItemState.VERIFIED_GREEN:
                break
            await asyncio.sleep(0)

        assert store.items[fix_item.id].state == ItemState.FIXING
        assert store.items[test_item.id].state == ItemState.VERIFIED_GREEN

        fixer.release.set()
        await scheduler.run_until_quiescent()

    asyncio.run(scenario())


def test_round_robin_roles_prevent_upstream_backlog_from_starving_tester() -> None:
    async def scenario() -> None:
        campaign = _campaign()
        investigation_items = tuple(
            _item(campaign, f"investigation-{number}", ItemState.BACKLOG)
            for number in range(3)
        )
        tester_item = _item(campaign, "tester-ready", ItemState.READY_FOR_TEST)
        store = FakeStore(
            campaign,
            investigation_items + (tester_item,),
            tuple(
                _job(campaign, item, WorkerRole.INVESTIGATOR)
                for item in investigation_items
            )
            + (_job(campaign, tester_item, WorkerRole.TESTER),),
        )
        execution_order: list[str] = []

        def investigation_output(context: WorkerContext) -> InvestigationHandoff:
            execution_order.append(context.item_id)
            return _investigation(context.item_id)

        def tester_output(context: WorkerContext) -> domain_models.TestHandoff:
            execution_order.append(context.item_id)
            return _passing_test(context.item_id)

        scheduler = Scheduler(
            store,
            {
                WorkerRole.INVESTIGATOR: (
                    ScriptedWorker(
                        WorkerRole.INVESTIGATOR, default=investigation_output
                    ),
                ),
                WorkerRole.TESTER: (
                    ScriptedWorker(WorkerRole.TESTER, default=tester_output),
                ),
            },
            global_concurrency_limit=1,
            allow_simulated_evidence=True,
        )

        await scheduler.run_until_quiescent()

        assert execution_order[0] == investigation_items[0].id
        assert execution_order[1] == tester_item.id
        assert store.items[tester_item.id].state == ItemState.VERIFIED_GREEN

    asyncio.run(scenario())


def test_invalid_role_output_requeues_and_server_binds_the_claimed_item() -> None:
    async def scenario() -> None:
        campaign = _campaign()
        item = _item(campaign, "bound-item", ItemState.BACKLOG)
        store = FakeStore(campaign, (item,), (_job(campaign, item, WorkerRole.INVESTIGATOR),))
        wrong_role_output = _fix("attempted-redirect")
        valid_output_with_untrusted_id = _investigation("attempted-redirect")
        worker = ScriptedWorker(
            WorkerRole.INVESTIGATOR,
            outcomes={item.id: [wrong_role_output, valid_output_with_untrusted_id]},
        )
        scheduler = Scheduler(
            store,
            {WorkerRole.INVESTIGATOR: (worker,)},
            global_concurrency_limit=1,
            max_attempts=2,
            allow_simulated_evidence=True,
        )

        await scheduler.run_until_quiescent()

        assert len(worker.calls) == 2
        assert len(store.failures) == 1
        assert "invalid investigator handoff" in store.failures[0]["error"]
        assert store.items[item.id].state == ItemState.READY_FOR_FIX
        assert store.commits[-1]["handoff"]["item_id"] == item.id

    asyncio.run(scenario())


def test_test_gate_routes_green_and_red_without_worker_control_of_state() -> None:
    async def scenario() -> None:
        campaign = _campaign()
        green_item = _item(campaign, "green", ItemState.READY_FOR_TEST)
        red_item = _item(campaign, "red", ItemState.READY_FOR_TEST)
        store = FakeStore(
            campaign,
            (green_item, red_item),
            (
                _job(campaign, green_item, WorkerRole.TESTER),
                _job(campaign, red_item, WorkerRole.TESTER),
            ),
        )

        def result_for_item(context: WorkerContext) -> domain_models.TestHandoff:
            if context.item_id == green_item.id:
                return _passing_test(context.item_id)
            return _red_test(context.item_id)

        scheduler = Scheduler(
            store,
            {
                WorkerRole.TESTER: (
                    ScriptedWorker(WorkerRole.TESTER, default=result_for_item),
                    ScriptedWorker(WorkerRole.TESTER, default=result_for_item),
                )
            },
            global_concurrency_limit=2,
            allow_simulated_evidence=True,
        )

        await scheduler.run_until_quiescent()

        assert store.items[green_item.id].state == ItemState.VERIFIED_GREEN
        assert store.items[red_item.id].state == ItemState.READY_FOR_FIX
        red_commit = next(commit for commit in store.commits if commit["item_id"] == red_item.id)
        assert red_commit["event_type"] == "test_returned_to_fix"
        assert red_commit["next_job_role"] == WorkerRole.FIXER
        assert red_commit["next_job_payload"]["test_failure"]["item_id"] == red_item.id
        assert red_commit["next_job_payload"]["gate_evaluation"]["failed_gates"] == [
            GateKind.FOCUSED_TESTS.value
        ]

    asyncio.run(scenario())


def test_run_until_quiescent_returns_when_all_claims_are_blocked() -> None:
    async def scenario() -> None:
        campaign = _campaign()
        item = _item(campaign, "resource-blocked", ItemState.BACKLOG)
        store = FakeStore(campaign, (item,), (_job(campaign, item, WorkerRole.INVESTIGATOR),))
        worker = ScriptedWorker(
            WorkerRole.INVESTIGATOR,
            default=lambda context: _investigation(context.item_id),
        )

        def blocked_claim(
            role: WorkerRole, worker_id: str, lease_seconds: float
        ) -> Optional[Job]:
            store.claim_calls[role] += 1
            return None

        store.claim_job = blocked_claim  # type: ignore[method-assign]
        scheduler = Scheduler(
            store,
            {WorkerRole.INVESTIGATOR: (worker,)},
            global_concurrency_limit=1,
            allow_simulated_evidence=True,
        )

        await asyncio.wait_for(scheduler.run_until_quiescent(), timeout=0.1)
        assert store.claim_calls[WorkerRole.INVESTIGATOR] == 1

    asyncio.run(scenario())


def test_run_until_quiescent_drains_bounded_reconciliation_progress() -> None:
    class RecoveryBatch:
        def __init__(self, recovered: tuple[str, ...], count: int) -> None:
            self.recovered = recovered
            self.reconciliation_count = count

        def __iter__(self):
            return iter(self.recovered)

    async def scenario() -> None:
        campaign = _campaign()
        store = FakeStore(campaign, (), ())
        batches = [
            RecoveryBatch((), 1),
            RecoveryBatch(("recovered-after-quarantine",), 1),
            RecoveryBatch((), 0),
        ]
        recovery_calls = 0

        def recover() -> RecoveryBatch:
            nonlocal recovery_calls
            recovery_calls += 1
            return batches.pop(0)

        store.recover_expired_leases = recover  # type: ignore[method-assign]
        scheduler = Scheduler(
            store,
            {},
            global_concurrency_limit=1,
            allow_simulated_evidence=True,
        )

        await scheduler.run_until_quiescent()

        assert recovery_calls == 3
        assert batches == []
        assert scheduler.stale_job_ids == ["recovered-after-quarantine"]

    asyncio.run(scenario())


def test_recovery_cancels_stale_local_worker_before_it_can_finalize() -> None:
    async def scenario() -> None:
        campaign = _campaign()
        item = _item(campaign, "stale", ItemState.BACKLOG)
        job = _job(campaign, item, WorkerRole.INVESTIGATOR)
        store = FakeStore(campaign, (item,), (job,))
        worker = BlockingWorker(
            WorkerRole.INVESTIGATOR,
            lambda context: _investigation(context.item_id),
        )
        scheduler = Scheduler(
            store,
            {WorkerRole.INVESTIGATOR: (worker,)},
            global_concurrency_limit=1,
            allow_simulated_evidence=True,
        )

        await scheduler.run_once()
        await worker.started.wait()
        store.recover_next.append(job.id)
        await scheduler.run_once()
        await asyncio.sleep(0)
        worker.release.set()
        await scheduler.run_once()

        assert job.id in scheduler.stale_job_ids
        assert store.commits == []
        assert store.failures == []

    asyncio.run(scenario())


def test_blocking_reconciliation_does_not_starve_active_heartbeats() -> None:
    async def scenario() -> None:
        campaign = _campaign()
        item = _item(campaign, "heartbeat-during-recovery", ItemState.BACKLOG)
        job = _job(campaign, item, WorkerRole.INVESTIGATOR)
        store = FakeStore(campaign, (item,), (job,))
        worker = BlockingWorker(
            WorkerRole.INVESTIGATOR,
            lambda context: _investigation(context.item_id),
        )
        scheduler = Scheduler(
            store,
            {WorkerRole.INVESTIGATOR: (worker,)},
            global_concurrency_limit=1,
            heartbeat_interval_seconds=0.01,
            allow_simulated_evidence=True,
        )

        await scheduler.run_once()
        await worker.started.wait()
        store.recovery_started = Event()
        store.recovery_release = Event()
        recovery = asyncio.create_task(scheduler.run_once())
        assert await asyncio.to_thread(store.recovery_started.wait, 1)
        before = store.heartbeat_calls
        await asyncio.sleep(0.05)
        after = store.heartbeat_calls
        store.recovery_release.set()
        await recovery
        worker.release.set()
        await scheduler.run_until_quiescent()

        assert after > before
        assert store.commits

    asyncio.run(scenario())


def test_clean_shutdown_interrupts_and_requeues_fenced_work_immediately() -> None:
    async def scenario() -> None:
        campaign = _campaign()
        item = _item(campaign, "shutdown", ItemState.BACKLOG)
        job = _job(campaign, item, WorkerRole.INVESTIGATOR)
        store = FakeStore(campaign, (item,), (job,))
        worker = BlockingWorker(
            WorkerRole.INVESTIGATOR,
            lambda context: _investigation(context.item_id),
        )
        scheduler = Scheduler(
            store,
            {WorkerRole.INVESTIGATOR: (worker,)},
            global_concurrency_limit=1,
            allow_simulated_evidence=True,
        )

        await scheduler.run_once()
        await worker.started.wait()
        await scheduler.shutdown()

        assert scheduler.active_count == 0
        assert store.jobs[job.id].status == JobStatus.PENDING
        assert store.items[item.id].state == ItemState.BACKLOG
        assert store.interruptions == [
            {
                "job_id": job.id,
                "reason": "scheduler shutdown interrupted active work",
            }
        ]

    asyncio.run(scenario())


def test_transient_heartbeat_storage_error_retries_without_stranding_claim() -> None:
    async def scenario() -> None:
        campaign = _campaign()
        item = _item(campaign, "flaky-heartbeat", ItemState.BACKLOG)
        job = _job(campaign, item, WorkerRole.INVESTIGATOR)
        store = FakeStore(campaign, (item,), (job,))
        original_heartbeat = store.heartbeat_job
        heartbeat_calls = 0

        def flaky_heartbeat(
            job_id: str,
            worker_id: str,
            lease_token: str,
            lease_seconds: float,
        ) -> bool:
            nonlocal heartbeat_calls
            heartbeat_calls += 1
            if heartbeat_calls == 1:
                raise RuntimeError("simulated transient SQLite busy")
            return original_heartbeat(
                job_id, worker_id, lease_token, lease_seconds
            )

        store.heartbeat_job = flaky_heartbeat  # type: ignore[method-assign]
        worker = BlockingWorker(
            WorkerRole.INVESTIGATOR,
            lambda context: _investigation(context.item_id),
        )
        scheduler = Scheduler(
            store,
            {WorkerRole.INVESTIGATOR: (worker,)},
            global_concurrency_limit=1,
            lease_seconds=0.2,
            heartbeat_interval_seconds=0.02,
            allow_simulated_evidence=True,
        )

        await scheduler.run_once()
        await worker.started.wait()
        for _ in range(100):
            if heartbeat_calls >= 2:
                break
            await asyncio.sleep(0.005)
        assert heartbeat_calls >= 2
        worker.release.set()
        await scheduler.run_until_quiescent()

        assert scheduler.errors == []
        assert scheduler.stale_job_ids == []
        assert store.items[item.id].state == ItemState.READY_FOR_FIX
        assert store.commits[-1]["job_id"] == job.id
        assert store.failures == []

    asyncio.run(scenario())


def test_default_scheduler_rejects_nonexistent_evidence_attachment() -> None:
    async def scenario() -> None:
        campaign = _campaign()
        item = _item(campaign, "missing-attachment", ItemState.BACKLOG)
        store = FakeStore(campaign, (item,), (_job(campaign, item, WorkerRole.INVESTIGATOR),))
        handoff = _investigation(item.id).model_copy(
            update={
                "evidence": (
                    EvidenceRef(
                        kind=EvidenceKind.LOG,
                        location="/private/tmp/agent-flow-does-not-exist/proof.txt",
                        description="Claimed proof without a durable attachment",
                    ),
                )
            }
        )
        scheduler = Scheduler(
            store,
            {
                WorkerRole.INVESTIGATOR: (
                    ScriptedWorker(WorkerRole.INVESTIGATOR, default=handoff),
                )
            },
            global_concurrency_limit=1,
            max_attempts=1,
        )

        await scheduler.run_until_quiescent()

        assert store.commits == []
        assert store.items[item.id].state == ItemState.BLOCKED
        assert "evidence attachment does not exist" in store.failures[0]["error"]

    asyncio.run(scenario())


def test_focused_test_callbacks_remain_bound_to_the_claim_fence() -> None:
    class CallbackTester:
        role = WorkerRole.TESTER

        async def run(self, context: WorkerContext) -> WorkerOutput:
            prepared = context.prepare_focused_test_execution()
            assert prepared == {
                "id": "focused-execution",
                "command": ["/usr/bin/true"],
            }
            completed = context.complete_focused_test_execution(
                {"execution_id": prepared["id"], "exit_code": 0}
            )
            return completed["canonical_handoff"]

    async def scenario() -> None:
        campaign = _campaign()
        item = _item(campaign, "focused-callbacks", ItemState.READY_FOR_TEST)
        job = _job(campaign, item, WorkerRole.TESTER)
        store = FakeStore(campaign, (item,), (job,))
        scheduler = Scheduler(
            store,
            {WorkerRole.TESTER: (CallbackTester(),)},
            global_concurrency_limit=1,
            allow_simulated_evidence=True,
        )

        await scheduler.run_until_quiescent()

        assert scheduler.errors == []
        assert store.items[item.id].state == ItemState.VERIFIED_GREEN
        assert store.focused_test_preparations == [
            {"id": "focused-execution", "command": ["/usr/bin/true"]}
        ]
        assert store.focused_test_completions == [
            {"execution_id": "focused-execution", "exit_code": 0}
        ]

    asyncio.run(scenario())
