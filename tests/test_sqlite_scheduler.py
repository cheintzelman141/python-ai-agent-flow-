from __future__ import annotations

import asyncio
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock
from typing import Iterator, Sequence

import pytest

from agent_flow.models import (
    EvidenceKind,
    EvidenceRef,
    FixHandoff,
    GateKind,
    GateProof,
    GateResult,
    InvestigationHandoff,
    ItemState,
    TestHandoff as DomainTestHandoff,
    TestOutcome as DomainTestOutcome,
    WorkerRole,
)
from agent_flow.scheduler import Scheduler
from agent_flow.sqlite_scheduler import (
    LOCAL_WRITE_APPROVAL_ACTION,
    SQLiteSchedulerStorage,
)
from agent_flow.storage import SQLiteStore
from agent_flow.workers import ScriptedWorker


_ROLE_STATES = {
    WorkerRole.INVESTIGATOR: (ItemState.BACKLOG, ItemState.INVESTIGATING),
    WorkerRole.FIXER: (ItemState.READY_FOR_FIX, ItemState.FIXING),
    WorkerRole.TESTER: (ItemState.READY_FOR_TEST, ItemState.TESTING),
}


class ManualClock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value
        self._lock = Lock()

    def __call__(self) -> float:
        with self._lock:
            return self.value

    def advance(self, seconds: float) -> None:
        with self._lock:
            self.value += seconds


class BlockingInvestigator:
    role = WorkerRole.INVESTIGATOR

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def run(self, context):
        self.started.set()
        await self.release.wait()
        return _investigation(context.item_id)


@contextmanager
def _temporary_store() -> Iterator[SQLiteStore]:
    with TemporaryDirectory(prefix="agent-flow-sqlite-scheduler-", dir="/private/tmp") as root:
        store = SQLiteStore(Path(root) / "state.sqlite3")
        try:
            yield store
        finally:
            store.close()


def _create_campaign(store: SQLiteStore) -> dict[str, object]:
    return store.create_campaign(
        "SQLite scheduler integration proof",
        config={
            "description": "Phase 1 deterministic fake-worker pipeline.",
            "allow_simulated_evidence": True,
        },
        global_limit=3,
        role_limits={"investigator": 1, "fixer": 1, "tester": 1},
    )


def test_reconciliation_fence_outlasts_both_signal_grace_periods() -> None:
    with _temporary_store() as store:
        with pytest.raises(ValueError, match="outlast TERM and KILL"):
            SQLiteSchedulerStorage(
                store,
                reconciliation_lease_seconds=10,
            )


def test_bounded_recovery_reports_reconciliation_progress() -> None:
    with _temporary_store() as store:
        adapter = SQLiteSchedulerStorage(store)

        def reconcile_once(*, max_processes=None):
            assert max_processes == 1
            adapter.last_reconciliation_results = [object()]  # type: ignore[list-item]
            return ()

        adapter.reconcile_expired_processes = reconcile_once  # type: ignore[method-assign]

        recovery = adapter.recover_expired_leases()

        assert tuple(recovery) == ()
        assert recovery.reconciliation_count == 1


def _create_item(
    store: SQLiteStore,
    campaign_id: str,
    *,
    title: str,
    initial_role: WorkerRole = WorkerRole.INVESTIGATOR,
    required_gates: Sequence[GateKind] = (
        GateKind.FOCUSED_TESTS,
        GateKind.BROWSER,
        GateKind.DATABASE,
    ),
    required_resources: Sequence[str] = (),
) -> dict[str, object]:
    queued_state, active_state = _ROLE_STATES[initial_role]
    return store.create_work_item(
        campaign_id,
        title,
        description="Exercise the complete persisted scheduler workflow.",
        state=queued_state.value,
        required_gates=[gate.value for gate in required_gates],
        initial_job={
            "role": initial_role.value,
            "stage": initial_role.value,
            "queued_item_state": queued_state.value,
            "active_item_state": active_state.value,
            "required_resources": list(required_resources),
        },
    )


def _evidence(label: str, kind: EvidenceKind) -> EvidenceRef:
    return EvidenceRef(
        kind=kind,
        location=f"/private/tmp/agent-flow-evidence/{label}.txt",
        description=f"Simulated {label} evidence produced by a deterministic fake worker.",
        metadata={"simulated": True},
    )


def _investigation(item_id: str) -> InvestigationHandoff:
    return InvestigationHandoff(
        item_id=item_id,
        synopsis="The exact workflow reproduces a stale-state defect.",
        reproduction_steps=("Open the exact workflow and exercise the stale transition.",),
        root_cause="The bounded state transition retains the prior value.",
        proposed_fix="Update only the proven state transition.",
        acceptance_criteria=("The exact workflow returns the current persisted value.",),
        evidence=(_evidence("investigation-log", EvidenceKind.LOG),),
    )


def _fix(item_id: str, *, revision: int = 1) -> FixHandoff:
    return FixHandoff(
        item_id=item_id,
        summary=f"Applied surgical revision {revision} to the proven transition.",
        changed_files=("src/example.py",),
        tests_run=("python3 -m pytest tests/test_example.py",),
        tester_instructions=("Repeat the exact browser and database workflow.",),
        evidence=(_evidence(f"fix-{revision}-test", EvidenceKind.TEST),),
    )


def _green_test(item_id: str) -> DomainTestHandoff:
    return DomainTestHandoff(
        item_id=item_id,
        outcome=DomainTestOutcome.PASS,
        summary="Focused tests, the exact browser workflow, and database proof are green.",
        gate_proofs=(
            GateProof(
                gate=GateKind.FOCUSED_TESTS,
                result=GateResult.PASS,
                summary="Focused regression test passed.",
                evidence=(_evidence("focused-test-pass", EvidenceKind.TEST),),
            ),
            GateProof(
                gate=GateKind.BROWSER,
                result=GateResult.PASS,
                summary="Exact visible browser workflow passed.",
                evidence=(_evidence("browser-pass", EvidenceKind.SCREENSHOT),),
            ),
            GateProof(
                gate=GateKind.DATABASE,
                result=GateResult.PASS,
                summary="Targeted database checks passed.",
                evidence=(_evidence("database-pass", EvidenceKind.DATABASE),),
            ),
        ),
    )


def _red_test(item_id: str) -> DomainTestHandoff:
    return DomainTestHandoff(
        item_id=item_id,
        outcome=DomainTestOutcome.RED,
        summary="The visible workflow remains red after the first fix.",
        failure_summary="The browser still renders the stale value after persistence succeeds.",
        gate_proofs=(
            GateProof(
                gate=GateKind.FOCUSED_TESTS,
                result=GateResult.PASS,
                summary="Focused regression test passed.",
                evidence=(_evidence("red-round-focused-test-pass", EvidenceKind.TEST),),
            ),
            GateProof(
                gate=GateKind.BROWSER,
                result=GateResult.FAIL,
                summary="Exact visible browser workflow still shows stale state.",
                evidence=(_evidence("red-round-browser-fail", EvidenceKind.SCREENSHOT),),
            ),
            GateProof(
                gate=GateKind.DATABASE,
                result=GateResult.PASS,
                summary="Targeted database value is correct.",
                evidence=(_evidence("red-round-database-pass", EvidenceKind.DATABASE),),
            ),
        ),
    )


def _missing_gate_test(item_id: str) -> DomainTestHandoff:
    return DomainTestHandoff(
        item_id=item_id,
        outcome=DomainTestOutcome.PASS,
        summary="The worker incorrectly reports green without browser or database proof.",
        gate_proofs=(
            GateProof(
                gate=GateKind.FOCUSED_TESTS,
                result=GateResult.PASS,
                summary="Only the focused regression test passed.",
                evidence=(_evidence("incomplete-focused-test-pass", EvidenceKind.TEST),),
            ),
        ),
    )


def _approve_local_changes(store: SQLiteStore, campaign_id: str) -> None:
    approval = store.create_approval(
        campaign_id,
        LOCAL_WRITE_APPROVAL_ACTION,
        "phase-1-test",
        scope={"repositories": ["/private/tmp/simulated-target"]},
    )
    store.resolve_approval(str(approval["id"]), "approved", "phase-1-test")


def _scheduler(
    store: SQLiteStore,
    *,
    investigators: Sequence[ScriptedWorker] = (),
    fixers: Sequence[ScriptedWorker] = (),
    testers: Sequence[ScriptedWorker] = (),
    max_attempts: int = 3,
) -> Scheduler:
    return Scheduler(
        SQLiteSchedulerStorage(store),
        {
            WorkerRole.INVESTIGATOR: investigators,
            WorkerRole.FIXER: fixers,
            WorkerRole.TESTER: testers,
        },
        global_concurrency_limit=3,
        max_attempts=max_attempts,
        allow_simulated_evidence=True,
    )


def test_sqlite_pipeline_requires_approval_then_reaches_evidence_gated_green() -> None:
    async def scenario() -> None:
        with _temporary_store() as store:
            campaign = _create_campaign(store)
            item = _create_item(store, str(campaign["id"]), title="Approval-gated green")
            item_id = str(item["id"])
            investigator = ScriptedWorker(
                WorkerRole.INVESTIGATOR,
                default=lambda context: _investigation(context.item_id),
            )
            fixer = ScriptedWorker(
                WorkerRole.FIXER,
                default=lambda context: _fix(context.item_id),
            )
            tester = ScriptedWorker(
                WorkerRole.TESTER,
                default=lambda context: _green_test(context.item_id),
            )
            scheduler = _scheduler(
                store,
                investigators=(investigator,),
                fixers=(fixer,),
                testers=(tester,),
            )

            await scheduler.run_until_quiescent()

            assert store.get_work_item(item_id)["state"] == ItemState.READY_FOR_FIX.value
            assert len(investigator.calls) == 1
            assert fixer.calls == []
            fixer_job = store.list_jobs(work_item_id=item_id, role=WorkerRole.FIXER.value)[0]
            assert fixer_job["status"] == "pending"
            assert fixer_job["required_approval_action"] == LOCAL_WRITE_APPROVAL_ACTION

            _approve_local_changes(store, str(campaign["id"]))
            await scheduler.run_until_quiescent()

            assert scheduler.errors == []
            assert store.get_work_item(item_id)["state"] == ItemState.VERIFIED_GREEN.value
            assert len(fixer.calls) == 1
            assert len(tester.calls) == 1
            jobs = store.list_jobs(work_item_id=item_id)
            assert [job["role"] for job in jobs] == [
                WorkerRole.INVESTIGATOR.value,
                WorkerRole.FIXER.value,
                WorkerRole.TESTER.value,
            ]
            assert {job["status"] for job in jobs} == {"completed"}
            assert {attempt["status"] for attempt in store.list_attempts()} == {"succeeded"}
            assert store.list_resource_leases() == []
            assert store.foreign_key_violations() == []

            transitions = [
                (event["from_state"], event["to_state"])
                for event in store.list_events(work_item_id=item_id)
                if event["from_state"] is not None
            ]
            assert transitions == [
                (ItemState.BACKLOG.value, ItemState.INVESTIGATING.value),
                (ItemState.INVESTIGATING.value, ItemState.READY_FOR_FIX.value),
                (ItemState.READY_FOR_FIX.value, ItemState.FIXING.value),
                (ItemState.FIXING.value, ItemState.READY_FOR_TEST.value),
                (ItemState.READY_FOR_TEST.value, ItemState.TESTING.value),
                (ItemState.TESTING.value, ItemState.VERIFIED_GREEN.value),
            ]

    asyncio.run(scenario())


def test_red_test_packet_is_preserved_for_new_fixer_before_later_green() -> None:
    async def scenario() -> None:
        with _temporary_store() as store:
            campaign = _create_campaign(store)
            item = _create_item(store, str(campaign["id"]), title="Red loop to green")
            item_id = str(item["id"])
            _approve_local_changes(store, str(campaign["id"]))

            investigator = ScriptedWorker(
                WorkerRole.INVESTIGATOR,
                default=lambda context: _investigation(context.item_id),
            )
            fixer = ScriptedWorker(
                WorkerRole.FIXER,
                outcomes={item_id: [_fix(item_id, revision=1), _fix(item_id, revision=2)]},
            )
            tester = ScriptedWorker(
                WorkerRole.TESTER,
                outcomes={item_id: [_red_test(item_id), _green_test(item_id)]},
            )
            scheduler = _scheduler(
                store,
                investigators=(investigator,),
                fixers=(fixer,),
                testers=(tester,),
            )

            await scheduler.run_until_quiescent()

            assert scheduler.errors == []
            assert store.get_work_item(item_id)["state"] == ItemState.VERIFIED_GREEN.value
            assert len(fixer.calls) == 2
            assert len(tester.calls) == 2
            fixer_jobs = store.list_jobs(work_item_id=item_id, role=WorkerRole.FIXER.value)
            tester_jobs = store.list_jobs(work_item_id=item_id, role=WorkerRole.TESTER.value)
            assert len(fixer_jobs) == 2
            assert len(tester_jobs) == 2

            retry_payload = fixer_jobs[1]["payload"]
            failure_packet = retry_payload["test_failure"]
            assert failure_packet["outcome"] == DomainTestOutcome.RED.value
            assert failure_packet["failure_summary"] == (
                "The browser still renders the stale value after persistence succeeds."
            )
            assert failure_packet["gate_proofs"][1]["gate"] == GateKind.BROWSER.value
            assert failure_packet["gate_proofs"][1]["result"] == GateResult.FAIL.value
            assert failure_packet["gate_proofs"][1]["evidence"][0]["location"] == (
                "/private/tmp/agent-flow-evidence/red-round-browser-fail.txt"
            )
            assert retry_payload["gate_evaluation"]["failed_gates"] == [
                GateKind.BROWSER.value
            ]
            assert fixer.calls[1].job["payload"] == retry_payload

            event_types = [
                event["event_type"] for event in store.list_events(work_item_id=item_id)
            ]
            assert event_types.count("test_returned_to_fix") == 1
            assert event_types.count("test_verified_green") == 1
            assert store.foreign_key_violations() == []

    asyncio.run(scenario())


def test_missing_required_gate_output_retries_then_blocks_at_max_attempts() -> None:
    async def scenario() -> None:
        with _temporary_store() as store:
            campaign = _create_campaign(store)
            item = _create_item(
                store,
                str(campaign["id"]),
                title="Incomplete tester proof",
                initial_role=WorkerRole.TESTER,
            )
            item_id = str(item["id"])
            tester = ScriptedWorker(
                WorkerRole.TESTER,
                default=lambda context: _missing_gate_test(context.item_id),
            )
            scheduler = _scheduler(store, testers=(tester,), max_attempts=2)

            await scheduler.run_until_quiescent()

            assert scheduler.errors == []
            assert len(tester.calls) == 2
            assert store.get_work_item(item_id)["state"] == ItemState.BLOCKED.value
            job = store.list_jobs(work_item_id=item_id, role=WorkerRole.TESTER.value)[0]
            assert job["status"] == "failed"
            assert job["attempt_count"] == 2
            assert "missing proof for required gates: browser, database" in job["last_error"]
            attempts = store.list_attempts(str(job["id"]))
            assert [attempt["status"] for attempt in attempts] == ["failed", "failed"]
            assert all(
                "missing proof for required gates: browser, database" in attempt["error"]
                for attempt in attempts
            )

            event_types = [
                event["event_type"] for event in store.list_events(work_item_id=item_id)
            ]
            assert event_types.count("job.requeued") == 1
            assert event_types.count("job.failed") == 1
            assert "test_verified_green" not in event_types
            assert store.list_resource_leases() == []
            assert store.foreign_key_violations() == []

    asyncio.run(scenario())


def test_persisted_queue_and_handoff_survive_store_and_scheduler_reconstruction() -> None:
    async def scenario(database_path: Path) -> None:
        first_store = SQLiteStore(database_path)
        campaign = _create_campaign(first_store)
        campaign_id = str(campaign["id"])
        item = _create_item(first_store, campaign_id, title="Restart recovery")
        item_id = str(item["id"])
        first_scheduler = _scheduler(
            first_store,
            investigators=(
                ScriptedWorker(
                    WorkerRole.INVESTIGATOR,
                    default=lambda context: _investigation(context.item_id),
                ),
            ),
        )

        await first_scheduler.run_until_quiescent()
        assert first_store.get_work_item(item_id)["state"] == ItemState.READY_FOR_FIX.value
        pending_fixer = first_store.list_jobs(
            work_item_id=item_id,
            role=WorkerRole.FIXER.value,
        )[0]
        assert pending_fixer["status"] == "pending"
        persisted_investigation = pending_fixer["payload"]["investigation_handoff"]
        sequence_before_restart = first_store.list_events(work_item_id=item_id)[-1]["sequence"]
        _approve_local_changes(first_store, campaign_id)
        first_store.close()

        second_store = SQLiteStore(database_path)
        try:
            assert second_store.get_work_item(item_id)["state"] == ItemState.READY_FOR_FIX.value
            reconstructed_fixer_job = second_store.get_job(str(pending_fixer["id"]))
            assert reconstructed_fixer_job["payload"]["investigation_handoff"] == (
                persisted_investigation
            )

            fixer = ScriptedWorker(
                WorkerRole.FIXER,
                default=lambda context: _fix(context.item_id),
            )
            tester = ScriptedWorker(
                WorkerRole.TESTER,
                default=lambda context: _green_test(context.item_id),
            )
            second_scheduler = _scheduler(second_store, fixers=(fixer,), testers=(tester,))
            await second_scheduler.run_until_quiescent()

            assert second_scheduler.errors == []
            assert len(fixer.calls) == 1
            assert fixer.calls[0].job["payload"]["investigation_handoff"] == (
                persisted_investigation
            )
            assert len(tester.calls) == 1
            assert second_store.get_work_item(item_id)["state"] == (
                ItemState.VERIFIED_GREEN.value
            )
            events = second_store.list_events(work_item_id=item_id)
            assert events[-1]["sequence"] > sequence_before_restart
            assert events[-1]["event_type"] == "test_verified_green"
            assert second_store.foreign_key_violations() == []
        finally:
            second_store.close()

    with TemporaryDirectory(prefix="agent-flow-restart-", dir="/private/tmp") as root:
        asyncio.run(scenario(Path(root) / "state.sqlite3"))


def test_shutdown_recovers_claim_that_expires_before_interrupt() -> None:
    async def scenario(database_path: Path) -> None:
        clock = ManualClock()
        store = SQLiteStore(database_path, clock=clock)
        try:
            campaign = _create_campaign(store)
            item = _create_item(
                store,
                str(campaign["id"]),
                title="Expired during shutdown",
                required_resources=("chrome:shutdown-proof",),
            )
            worker = BlockingInvestigator()
            scheduler = Scheduler(
                SQLiteSchedulerStorage(store),
                {WorkerRole.INVESTIGATOR: (worker,)},
                global_concurrency_limit=1,
                lease_seconds=5,
                heartbeat_interval_seconds=1,
                allow_simulated_evidence=True,
            )

            assert await scheduler.run_once() == 1
            await worker.started.wait()
            assert store.get_work_item(str(item["id"]))["state"] == "investigating"
            assert len(store.list_resource_leases()) == 1

            clock.advance(6)
            await scheduler.shutdown()

            job = store.list_jobs(work_item_id=str(item["id"]))[0]
            assert scheduler.active_count == 0
            assert job["status"] == "pending"
            assert store.get_work_item(str(item["id"]))["state"] == "backlog"
            assert store.list_attempts(str(job["id"]))[0]["status"] == "expired"
            assert store.list_resource_leases() == []
            assert str(job["id"]) in scheduler.stale_job_ids
            assert store.foreign_key_violations() == []
        finally:
            store.close()

    with TemporaryDirectory(prefix="agent-flow-shutdown-", dir="/private/tmp") as root:
        asyncio.run(scenario(Path(root) / "state.sqlite3"))
