from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from agent_flow.models import WorkerRole
from agent_flow.scheduler import Scheduler
from agent_flow.sqlite_scheduler import SQLiteSchedulerStorage
from agent_flow.storage import LeaseConflict, SQLiteStore
from agent_flow.workers import ScriptedWorker


def _running_job(path: Path):
    store = SQLiteStore(path)
    campaign = store.create_campaign("operator controls")
    item = store.create_work_item(
        campaign["id"],
        "exact operator fence",
        description="Exercise exact interrupt and resume controls.",
        initial_job={
            "role": "investigator",
            "stage": "investigate",
            "active_item_state": "investigating",
        },
    )
    claim = store.claim_job("investigator", "worker-a", lease_seconds=60)
    assert claim is not None
    return store, campaign, item, claim


def _record_process_and_session(store: SQLiteStore, claim, session: str) -> None:
    store.record_external_process(
        claim["id"],
        "worker-a",
        claim["lease_token"],
        "codex",
        39101,
        39101,
        os.getuid(),
        "/usr/bin/python3",
        100,
        200,
        "/usr/local/bin/codex",
    )
    store.record_external_session(
        claim["id"],
        "worker-a",
        claim["lease_token"],
        "codex",
        session,
    )


def test_interrupt_is_exact_durable_reaped_and_transactionally_audited(
    tmp_path: Path,
) -> None:
    path = tmp_path / "interrupt.sqlite3"
    store, campaign, _item, claim = _running_job(path)
    _record_process_and_session(store, claim, "session-interrupt")

    with pytest.raises(LeaseConflict, match="absent or stale"):
        store.request_job_interrupt(
            claim["id"],
            "stale-token",
            requested_by="operator-a",
            reason="stop exact process",
        )
    request = store.request_job_interrupt(
        claim["id"],
        claim["lease_token"],
        requested_by="operator-a",
        reason="stop exact process",
    )
    assert request["status"] == "pending"
    assert request["expected_process_id"] == 39101
    assert store.poll_operator_interrupt(
        claim["id"], "worker-a", claim["lease_token"]
    )["id"] == request["id"]

    store.close()
    restarted = SQLiteStore(path)
    assert restarted.poll_operator_interrupt(
        claim["id"], "worker-a", claim["lease_token"]
    )["id"] == request["id"]
    with pytest.raises(LeaseConflict, match="must be reaped"):
        restarted.interrupt_job(
            claim["id"],
            "worker-a",
            claim["lease_token"],
            reason="stop exact process",
            operator_request_id=request["id"],
        )
    restarted.clear_external_process(
        claim["id"], "worker-a", claim["lease_token"], 39101, 39101
    )
    completed = restarted.interrupt_job(
        claim["id"],
        "worker-a",
        claim["lease_token"],
        reason="stop exact process",
        operator_request_id=request["id"],
    )
    assert completed["status"] == "pending"
    control = restarted.list_operator_controls(job_id=claim["id"])[0]
    assert control["status"] == "applied"
    assert control["target_attempt_id"] == claim["attempt_id"]
    kinds = [
        event["event_kind"]
        for event in restarted.list_events(campaign_id=campaign["id"])
    ]
    assert "operator.interrupt_requested" in kinds
    assert "operator.interrupt_applied" in kinds
    assert kinds.index("job.interrupted") < kinds.index("operator.interrupt_applied")


def test_resume_requires_explicit_exact_one_time_authorization(
    tmp_path: Path,
) -> None:
    store, campaign, _item, claim = _running_job(tmp_path / "resume.sqlite3")
    session = "session-resume"
    _record_process_and_session(store, claim, session)
    store.clear_external_process(
        claim["id"], "worker-a", claim["lease_token"], 39101, 39101
    )
    store.interrupt_job(
        claim["id"],
        "worker-a",
        claim["lease_token"],
        reason="clean stopped session",
    )

    with pytest.raises(LeaseConflict, match="stale or mismatched"):
        store.request_job_resume(
            claim["id"],
            claim["attempt_id"],
            "claude",
            session,
            requested_by="operator-a",
        )
    with pytest.raises(ValueError, match="byte-exact"):
        store.request_job_resume(
            " " + claim["id"],
            claim["attempt_id"],
            "codex",
            session,
            requested_by="operator-a",
        )
    request = store.request_job_resume(
        claim["id"],
        claim["attempt_id"],
        "codex",
        session,
        requested_by="operator-a",
    )
    resumed = store.claim_job("investigator", "worker-b")
    assert resumed is not None
    assert resumed["resume_external_provider"] == "codex"
    assert resumed["resume_external_session_id"] == session
    with pytest.raises(LeaseConflict, match="exact resume authorization"):
        store.record_external_session(
            claim["id"],
            "worker-b",
            resumed["lease_token"],
            "codex",
            "different-session",
        )
    recorded = store.record_external_session(
        claim["id"],
        "worker-b",
        resumed["lease_token"],
        "codex",
        session,
    )
    assert recorded["external_session_id"] == session
    control = store.list_operator_controls(job_id=claim["id"])[0]
    assert control["id"] == request["id"]
    assert control["status"] == "applied"
    assert control["target_attempt_id"] == resumed["attempt_id"]
    kinds = [
        event["event_kind"]
        for event in store.list_events(campaign_id=campaign["id"])
    ]
    assert kinds.count("operator.resume_requested") == 1
    assert kinds.count("operator.resume_applied") == 1


def test_operator_request_event_failure_rolls_back(monkeypatch, tmp_path: Path) -> None:
    store, _campaign, _item, claim = _running_job(tmp_path / "rollback.sqlite3")
    original = store._append_event

    def fail_event(connection, event_kind, **kwargs):
        if event_kind == "operator.interrupt_requested":
            raise RuntimeError("forced operator audit failure")
        return original(connection, event_kind, **kwargs)

    monkeypatch.setattr(store, "_append_event", fail_event)
    with pytest.raises(RuntimeError, match="forced operator audit failure"):
        store.request_job_interrupt(
            claim["id"],
            claim["lease_token"],
            requested_by="operator-a",
            reason="rollback request",
        )
    assert store.list_operator_controls(job_id=claim["id"]) == []
    assert store.get_job(claim["id"])["status"] == "running"
    assert store.foreign_key_violations() == []


def test_one_attempt_can_record_sequential_but_not_concurrent_processes(
    tmp_path: Path,
) -> None:
    store, _campaign, _item, claim = _running_job(tmp_path / "sequential.sqlite3")
    first = store.record_external_process(
        claim["id"], "worker-a", claim["lease_token"], "focused_test",
        39201, 39201, os.getuid(), "/usr/bin/python3", 110, 210,
        "/usr/bin/python3",
    )
    with pytest.raises(LeaseConflict, match="already bound"):
        store.record_external_process(
            claim["id"], "worker-a", claim["lease_token"], "browser_evidence",
            39202, 39202, os.getuid(), "/usr/bin/python3", 111, 211,
            "/usr/bin/python3",
        )
    store.clear_external_process(
        claim["id"], "worker-a", claim["lease_token"], 39201, 39201
    )
    second = store.record_external_process(
        claim["id"], "worker-a", claim["lease_token"], "browser_evidence",
        39202, 39202, os.getuid(), "/usr/bin/python3", 111, 211,
        "/usr/bin/python3",
    )
    store.clear_external_process(
        claim["id"], "worker-a", claim["lease_token"], 39202, 39202
    )
    processes = store.list_external_processes()
    assert [process["id"] for process in processes] == [first["id"], second["id"]]
    assert all(process["state"] == "stopped" for process in processes)
    attempts = store.list_attempts(claim["id"])
    assert len(attempts) == 1
    assert attempts[0]["external_process_provider"] == "browser_evidence"
    assert store.foreign_key_violations() == []


def test_interrupt_remains_actionable_only_between_sequential_processes(
    tmp_path: Path,
) -> None:
    store, _campaign, _item, claim = _running_job(
        tmp_path / "interrupt-between-processes.sqlite3"
    )
    _record_process_and_session(store, claim, "session-between")
    request = store.request_job_interrupt(
        claim["id"],
        claim["lease_token"],
        requested_by="operator-a",
        reason="stop between collectors",
    )
    store.clear_external_process(
        claim["id"], "worker-a", claim["lease_token"], 39101, 39101
    )
    assert store.poll_operator_interrupt(
        claim["id"], "worker-a", claim["lease_token"]
    )["id"] == request["id"]
    store.record_external_process(
        claim["id"], "worker-a", claim["lease_token"], "browser_evidence",
        39102, 39102, os.getuid(), "/usr/bin/python3", 101, 201,
        "/usr/bin/python3",
    )
    with pytest.raises(LeaseConflict, match="replacement process"):
        store.poll_operator_interrupt(
            claim["id"], "worker-a", claim["lease_token"]
        )
    store.clear_external_process(
        claim["id"], "worker-a", claim["lease_token"], 39102, 39102
    )
    assert store.poll_operator_interrupt(
        claim["id"], "worker-a", claim["lease_token"]
    )["id"] == request["id"]


def test_scheduler_consumes_durable_interrupt_and_cancels_exact_worker(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store = SQLiteStore(tmp_path / "scheduler-interrupt.sqlite3")
        campaign = store.create_campaign("scheduler operator interrupt")
        item = store.create_work_item(
            campaign["id"],
            "cancel exact worker",
            description="Scheduler polls and applies an exact operator request.",
            initial_job={
                "role": "investigator",
                "stage": "investigate",
                "active_item_state": "investigating",
            },
        )
        worker = ScriptedWorker(
            WorkerRole.INVESTIGATOR,
            default=RuntimeError("must be cancelled before output"),
            delay_seconds=30,
        )
        scheduler = Scheduler(
            SQLiteSchedulerStorage(store),
            {WorkerRole.INVESTIGATOR: (worker,)},
            global_concurrency_limit=1,
            lease_seconds=2,
            heartbeat_interval_seconds=0.05,
        )
        assert await scheduler.run_once() == 1
        job = store.list_jobs(work_item_id=item["id"])[0]
        assert job["status"] == "running"
        request = store.request_job_interrupt(
            job["id"],
            job["lease_token"],
            requested_by="operator-a",
            reason="cancel exact scheduled worker",
        )
        for _ in range(100):
            await asyncio.sleep(0.02)
            control = store.list_operator_controls(job_id=job["id"])[0]
            if control["status"] == "applied":
                break
        else:
            raise AssertionError("scheduler did not apply the operator request")
        scheduler._reap_finished_slots()
        assert scheduler.active_count == 0
        assert store.get_job(job["id"])["status"] == "pending"
        assert store.get_work_item(item["id"])["state"] == "backlog"
        assert control["id"] == request["id"]
        assert scheduler.errors == []
        assert scheduler.stale_job_ids == []
        assert store.foreign_key_violations() == []
        store.close()

    asyncio.run(scenario())


def test_same_job_session_reuse_requires_exact_resume_authorization(
    tmp_path: Path,
) -> None:
    store, _campaign, _item, first = _running_job(
        tmp_path / "same-job-session.sqlite3"
    )
    _record_process_and_session(store, first, "same-session")
    store.clear_external_process(
        first["id"], "worker-a", first["lease_token"], 39101, 39101
    )
    store.interrupt_job(
        first["id"], "worker-a", first["lease_token"], reason="clean stop"
    )
    second = store.claim_job("investigator", "worker-b")
    assert second is not None
    with pytest.raises(LeaseConflict, match="requires exact operator resume"):
        store.record_external_session(
            second["id"],
            "worker-b",
            second["lease_token"],
            "codex",
            "same-session",
        )
    assert store.list_operator_controls(job_id=second["id"]) == []


@pytest.mark.parametrize("process_provider", [None, "browser_evidence"])
def test_resume_requires_stopped_process_proof_for_the_exact_provider(
    tmp_path: Path, process_provider: str
) -> None:
    store, _campaign, _item, claim = _running_job(
        tmp_path / ("resume-proof-%s.sqlite3" % process_provider)
    )
    if process_provider is not None:
        store.record_external_process(
            claim["id"],
            "worker-a",
            claim["lease_token"],
            process_provider,
            39501,
            39501,
            os.getuid(),
            "/usr/bin/python3",
            130,
            230,
            "/usr/bin/python3",
        )
        store.clear_external_process(
            claim["id"], "worker-a", claim["lease_token"], 39501, 39501
        )
    store.record_external_session(
        claim["id"],
        "worker-a",
        claim["lease_token"],
        "codex",
        "unproven-session",
    )
    store.interrupt_job(
        claim["id"], "worker-a", claim["lease_token"], reason="clean stop"
    )
    with pytest.raises(LeaseConflict, match="stopped provider process proof"):
        store.request_job_resume(
            claim["id"],
            claim["attempt_id"],
            "codex",
            "unproven-session",
            requested_by="operator-a",
        )


def test_applied_resume_must_be_fulfilled_before_success(
    tmp_path: Path,
) -> None:
    proof = tmp_path / "resume-proof.txt"
    proof.write_text("resume proof\n", encoding="utf-8")
    store, _campaign, item, first = _running_job(
        tmp_path / "resume-fulfillment.sqlite3"
    )
    _record_process_and_session(store, first, "session-fulfillment")
    store.clear_external_process(
        first["id"], "worker-a", first["lease_token"], 39101, 39101
    )
    store.interrupt_job(
        first["id"], "worker-a", first["lease_token"], reason="clean stop"
    )
    store.request_job_resume(
        first["id"],
        first["attempt_id"],
        "codex",
        "session-fulfillment",
        requested_by="operator-a",
    )
    resumed = store.claim_job("investigator", "worker-b")
    assert resumed is not None
    with pytest.raises(LeaseConflict, match="did not bind"):
        store.commit_stage_result(
            resumed["id"],
            "worker-b",
            resumed["lease_token"],
            {
                "item_id": item["id"],
                "outcome": "ready_for_fix",
                "synopsis": "Bounded resumed investigation.",
                "reproduction_steps": ["Run the bounded fixture."],
                "root_cause": "The resume must be exact.",
                "proposed_fix": "Require the authorized session.",
                "acceptance_criteria": ["Exact resumed identity is present."],
                "evidence": [
                    {
                        "kind": "log",
                        "location": str(proof),
                        "description": "Bounded resume proof.",
                    }
                ],
            },
            "investigating",
            "ready_for_fix",
            "investigation.completed",
            next_job={
                "role": "fixer",
                "stage": "fix",
                "active_item_state": "fixing",
            },
        )
    assert store.get_job(resumed["id"])["status"] == "running"
    assert store.get_work_item(item["id"])["state"] == "investigating"


def test_stale_clear_cannot_stop_replacement_after_pid_reuse(
    tmp_path: Path,
) -> None:
    store, _campaign, _item, claim = _running_job(
        tmp_path / "pid-reuse.sqlite3"
    )
    store.record_external_process(
        claim["id"], "worker-a", claim["lease_token"], "focused_test",
        39601, 39601, os.getuid(), "/usr/bin/python3", 140, 240,
        "/usr/bin/python3",
    )
    store.clear_external_process(
        claim["id"], "worker-a", claim["lease_token"], 39601, 39601
    )
    store.record_external_process(
        claim["id"], "worker-a", claim["lease_token"], "browser_evidence",
        39601, 39601, os.getuid(), "/usr/bin/python3", 141, 241,
        "/usr/bin/python3",
    )
    with pytest.raises(LeaseConflict, match="PID reuse"):
        store.clear_external_process(
            claim["id"], "worker-a", claim["lease_token"], 39601, 39601
        )
    assert [process["state"] for process in store.list_external_processes()] == [
        "stopped",
        "active",
    ]


def test_pending_interrupt_wins_over_stage_finalization(
    tmp_path: Path,
) -> None:
    proof = tmp_path / "interrupt-proof.txt"
    proof.write_text("interrupt proof\n", encoding="utf-8")
    store, _campaign, item, claim = _running_job(
        tmp_path / "interrupt-finalization.sqlite3"
    )
    request = store.request_job_interrupt(
        claim["id"],
        claim["lease_token"],
        requested_by="operator-a",
        reason="operator request wins",
    )
    with pytest.raises(LeaseConflict, match="pending operator interrupt"):
        store.commit_stage_result(
            claim["id"],
            "worker-a",
            claim["lease_token"],
            {
                "item_id": item["id"],
                "outcome": "ready_for_fix",
                "synopsis": "Result raced an interrupt.",
                "reproduction_steps": ["Request an interrupt."],
                "root_cause": "The operator request committed first.",
                "proposed_fix": "Apply the operator request.",
                "acceptance_criteria": ["The result does not advance."],
                "evidence": [
                    {
                        "kind": "log",
                        "location": str(proof),
                        "description": "Bounded interrupt proof.",
                    }
                ],
            },
            "investigating",
            "ready_for_fix",
            "investigation.completed",
            next_job={
                "role": "fixer",
                "stage": "fix",
                "active_item_state": "fixing",
            },
        )
    store.interrupt_job(
        claim["id"],
        "worker-a",
        claim["lease_token"],
        reason="operator request wins",
        operator_request_id=request["id"],
    )
    assert store.get_work_item(item["id"])["state"] == "backlog"
    assert store.list_operator_controls(job_id=claim["id"])[0]["status"] == "applied"


def test_expired_pending_interrupt_is_rejected_before_requeue(
    tmp_path: Path,
) -> None:
    clock = [1_000.0]
    store = SQLiteStore(
        tmp_path / "interrupt-expiry.sqlite3", clock=lambda: clock[0]
    )
    campaign = store.create_campaign("interrupt recovery")
    item = store.create_work_item(
        campaign["id"],
        "interrupt recovery",
        description="Reject stale pending operator controls.",
        initial_job={
            "role": "investigator",
            "stage": "investigate",
            "active_item_state": "investigating",
        },
    )
    claim = store.claim_job("investigator", "worker-a", lease_seconds=1)
    assert claim is not None
    store.request_job_interrupt(
        claim["id"],
        claim["lease_token"],
        requested_by="operator-a",
        reason="expires before application",
    )
    clock[0] += 2
    assert store.recover_expired_leases()["jobs"] == 1
    control = store.list_operator_controls(job_id=claim["id"])[0]
    assert control["status"] == "rejected"
    assert store.get_work_item(item["id"])["state"] == "backlog"
    assert store.claim_job("investigator", "worker-b") is not None


def test_scheduler_keeps_exact_lease_alive_during_interrupt_cleanup(
    tmp_path: Path,
) -> None:
    class SlowCancellationWorker:
        role = WorkerRole.INVESTIGATOR

        async def run(self, _context):
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                await asyncio.sleep(0.35)
                raise

    async def scenario() -> None:
        store = SQLiteStore(tmp_path / "slow-interrupt-cleanup.sqlite3")
        campaign = store.create_campaign("slow interrupt cleanup")
        item = store.create_work_item(
            campaign["id"],
            "slow cleanup",
            description="Heartbeat the exact fence until cleanup finishes.",
            initial_job={
                "role": "investigator",
                "stage": "investigate",
                "active_item_state": "investigating",
            },
        )
        scheduler = Scheduler(
            SQLiteSchedulerStorage(store),
            {WorkerRole.INVESTIGATOR: (SlowCancellationWorker(),)},
            global_concurrency_limit=1,
            lease_seconds=0.2,
            heartbeat_interval_seconds=0.05,
        )
        assert await scheduler.run_once() == 1
        job = store.list_jobs(work_item_id=item["id"])[0]
        request = store.request_job_interrupt(
            job["id"],
            job["lease_token"],
            requested_by="operator-a",
            reason="bounded slow cleanup",
        )
        for _ in range(100):
            await asyncio.sleep(0.02)
            control = store.list_operator_controls(job_id=job["id"])[0]
            if control["status"] == "applied":
                break
        else:
            raise AssertionError("operator request was not applied after cleanup")
        scheduler._reap_finished_slots()
        assert control["id"] == request["id"]
        assert store.get_job(job["id"])["status"] == "pending"
        assert scheduler.stale_job_ids == []
        assert store.foreign_key_violations() == []

    asyncio.run(scenario())
