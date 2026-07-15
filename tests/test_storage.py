from concurrent.futures import ThreadPoolExecutor
from io import StringIO
import os
from pathlib import Path
import re
import sqlite3
from threading import Barrier, Event, Lock
import time

import pytest
from rich.console import Console

from agent_flow.status import build_watch_board
from agent_flow.storage import (
    SCHEMA_VERSION,
    LeaseConflict,
    SQLiteStore,
    StorageError,
    TransitionConflict,
    _SCHEMA_V1,
    _SCHEMA_V2,
    _SCHEMA_V3,
)


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


def seeded_store(path: Path, clock: ManualClock, *, global_limit: int = 4) -> tuple:
    store = SQLiteStore(path, clock=clock)
    campaign = store.create_campaign(
        "phase one",
        config={"allow_simulated_evidence": True},
        global_limit=global_limit,
        role_limits={"INVESTIGATOR": global_limit, "FIXER": global_limit, "TESTER": global_limit},
    )
    item = store.create_work_item(
        campaign["id"], "first item", description="First durable workflow item."
    )
    return store, campaign, item


def enqueue_investigation(
    store: SQLiteStore, item_id: str, *, resource: str = "chrome:one", stage: str = "investigate"
) -> dict:
    return store.enqueue_job(
        item_id,
        "INVESTIGATOR",
        stage=stage,
        queued_item_state="BACKLOG",
        active_item_state="INVESTIGATING",
        required_resources=[resource],
        payload={"item_id": item_id},
    )


def investigation_result(item_id: str) -> dict:
    return {
        "schema_version": 1,
        "item_id": item_id,
        "outcome": "ready_for_fix",
        "synopsis": "The exact workflow reproduces the defect.",
        "reproduction_steps": ["Exercise the bounded workflow."],
        "root_cause": "The persisted transition retains stale state.",
        "proposed_fix": "Update only the proven transition.",
        "acceptance_criteria": ["The bounded workflow returns current state."],
        "evidence": [
            {
                "kind": "log",
                "location": "/private/tmp/agent-flow-storage-simulated.txt",
                "description": "Deterministic simulated investigation log.",
                "metadata": {"simulated": True},
            }
        ],
    }


def test_competing_connections_cannot_claim_same_job_or_resource(tmp_path: Path) -> None:
    path = tmp_path / "flow.sqlite3"
    clock = ManualClock()
    first, _campaign, item = seeded_store(path, clock)
    job = enqueue_investigation(first, item["id"])
    second = SQLiteStore(path, clock=clock)
    barrier = Barrier(2)

    def claim(store: SQLiteStore, worker: str):
        barrier.wait()
        return store.claim_job("INVESTIGATOR", worker, lease_seconds=30)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda args: claim(*args),
                [(first, "worker-a"), (second, "worker-b")],
            )
        )

    claims = [result for result in results if result is not None]
    assert len(claims) == 1
    assert claims[0]["id"] == job["id"]
    assert claims[0]["lease_token"]
    leases = first.list_resource_leases()
    assert len(leases) == 1
    assert leases[0]["job_id"] == job["id"]
    assert leases[0]["lease_token"] == claims[0]["lease_token"]
    first.close()
    second.close()


def test_persisted_global_limit_is_atomic_across_connections(tmp_path: Path) -> None:
    path = tmp_path / "limits.sqlite3"
    clock = ManualClock()
    first, campaign, item_one = seeded_store(path, clock, global_limit=1)
    item_two = first.create_work_item(
        campaign["id"], "second item", description="Second durable workflow item."
    )
    enqueue_investigation(first, item_one["id"], resource="tenant:one", stage="investigate-one")
    enqueue_investigation(first, item_two["id"], resource="tenant:two", stage="investigate-two")
    second = SQLiteStore(path, clock=clock)
    barrier = Barrier(2)

    def claim(store: SQLiteStore, worker: str):
        barrier.wait()
        return store.claim_job("INVESTIGATOR", worker)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda args: claim(*args),
                [(first, "worker-a"), (second, "worker-b")],
            )
        )

    assert len([result for result in results if result is not None]) == 1
    assert len(first.list_jobs(status="running")) == 1
    assert len(first.list_jobs(status="pending")) == 1
    first.close()
    second.close()


def test_expired_job_recovery_restores_state_resources_and_fences_old_worker(
    tmp_path: Path,
) -> None:
    path = tmp_path / "recovery.sqlite3"
    clock = ManualClock()
    store, _campaign, item = seeded_store(path, clock)
    job = enqueue_investigation(store, item["id"])
    claim = store.claim_job("INVESTIGATOR", "old-worker", lease_seconds=5)
    assert claim is not None
    old_token = claim["lease_token"]
    store.close()  # simulate supervisor process loss

    clock.advance(6)
    restarted = SQLiteStore(path, clock=clock)
    recovery = restarted.recover_expired_leases()
    assert recovery == {"jobs": 1, "resources": 0, "job_ids": [job["id"]]}
    assert restarted.get_job(job["id"])["status"] == "pending"
    assert restarted.get_work_item(item["id"])["state"] == "backlog"
    assert restarted.list_resource_leases() == []
    assert restarted.list_attempts(job["id"])[0]["status"] == "expired"

    with pytest.raises(LeaseConflict):
        restarted.heartbeat_job(job["id"], "old-worker", old_token)

    new_claim = restarted.claim_job("INVESTIGATOR", "new-worker")
    assert new_claim is not None
    assert new_claim["lease_token"] != old_token
    assert new_claim["attempt_number"] == 2
    restarted.close()


def test_competing_resource_leases_and_expired_takeover(tmp_path: Path) -> None:
    path = tmp_path / "resources.sqlite3"
    clock = ManualClock()
    first = SQLiteStore(path, clock=clock)
    second = SQLiteStore(path, clock=clock)
    barrier = Barrier(2)

    def acquire(store: SQLiteStore, worker: str):
        barrier.wait()
        return store.acquire_resource("chrome:profile", worker, lease_seconds=5)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda args: acquire(*args),
                [(first, "worker-a"), (second, "worker-b")],
            )
        )

    winners = [result for result in results if result is not None]
    assert len(winners) == 1
    clock.advance(6)
    takeover = second.acquire_resource("chrome:profile", "worker-c", lease_seconds=5)
    assert takeover is not None
    assert takeover["owner_id"] == "worker-c"
    assert takeover["lease_token"] != winners[0]["lease_token"]
    first.close()
    second.close()


def test_stage_commit_is_atomic_and_rolls_back_on_item_cas_failure(tmp_path: Path) -> None:
    path = tmp_path / "commit.sqlite3"
    clock = ManualClock()
    store, _campaign, item = seeded_store(path, clock)
    job = enqueue_investigation(store, item["id"])
    claim = store.claim_job("INVESTIGATOR", "worker-a")
    assert claim is not None

    next_job = {
        "role": "FIXER",
        "stage": "fix-1",
        "queued_item_state": "READY_FOR_FIX",
        "active_item_state": "FIXING",
        "payload": {"root_cause": "proven"},
    }
    with pytest.raises(TransitionConflict):
        store.commit_stage_result(
            job["id"],
            "worker-a",
            claim["lease_token"],
            investigation_result(item["id"]),
            "TESTING",
            "READY_FOR_FIX",
            "investigation.completed",
            next_job=next_job,
        )

    assert store.get_job(job["id"])["status"] == "running"
    assert store.get_work_item(item["id"])["state"] == "investigating"
    assert store.list_jobs(role="FIXER") == []

    committed = store.commit_stage_result(
        job["id"],
        "worker-a",
        claim["lease_token"],
        investigation_result(item["id"]),
        "INVESTIGATING",
        "READY_FOR_FIX",
        "investigation.completed",
        next_job=next_job,
    )
    assert committed["job"]["status"] == "completed"
    assert committed["work_item"]["state"] == "ready_for_fix"
    assert committed["next_job"]["status"] == "pending"
    assert committed["next_job"]["role"] == "fixer"
    kinds = [event["event_kind"] for event in store.list_events(work_item_id=item["id"])]
    assert "investigation.completed" in kinds
    assert "job.enqueued" in kinds
    store.close()


def test_read_only_store_requires_current_schema_and_rejects_writes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "read-only.sqlite3"
    with SQLiteStore(path) as writer:
        campaign = writer.create_campaign("read-only proof")
        events_before = writer.list_events(campaign_id=campaign["id"])

    with SQLiteStore(path, read_only=True) as reader:
        assert reader.read_only is True
        assert reader._connection.execute("PRAGMA query_only").fetchone()[0] == 1
        assert reader.get_campaign(campaign["id"])["name"] == "read-only proof"
        with pytest.raises(StorageError, match="write transactions are disabled"):
            reader.create_campaign("must not be written")

    with SQLiteStore(path) as writer:
        assert writer.list_events(campaign_id=campaign["id"]) == events_before
        writer._connection.execute("PRAGMA user_version = 6")

    with pytest.raises(StorageError, match="run `agent-flow init`"):
        SQLiteStore(path, read_only=True)
    connection = sqlite3.connect(str(path))
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 6
    finally:
        connection.close()


def test_campaign_status_snapshot_is_atomic_and_recent_events_are_bounded(
    tmp_path: Path,
) -> None:
    path = tmp_path / "atomic-status.sqlite3"
    writer = SQLiteStore(path)
    campaign = writer.create_campaign("atomic watch")
    first = writer.create_work_item(
        campaign["id"],
        "first",
        description="First snapshot item.",
        initial_job={
            "role": "investigator",
            "stage": "investigate",
            "active_item_state": "investigating",
        },
    )
    reader = SQLiteStore(path, read_only=True)
    original_list_items = reader.list_work_items
    writer_committed = False

    def interleaved_list_items(*args, **kwargs):
        nonlocal writer_committed
        items = original_list_items(*args, **kwargs)
        writer.create_work_item(
            campaign["id"],
            "second",
            description="Committed while the reader snapshot is open.",
            initial_job={
                "role": "investigator",
                "stage": "investigate",
                "active_item_state": "investigating",
            },
        )
        writer_committed = True
        return items

    reader.list_work_items = interleaved_list_items  # type: ignore[method-assign]
    snapshot = reader.read_campaign_status_snapshot(campaign["id"], event_limit=2)

    assert writer_committed is True
    assert [item["id"] for item in snapshot["items"]] == [first["id"]]
    assert len(snapshot["jobs"]) == 1
    assert len(snapshot["events"]) == 2
    assert [event["sequence"] for event in snapshot["events"]] == [2, 3]
    assert len(writer.list_work_items(campaign["id"])) == 2
    assert len(writer.list_events(campaign_id=campaign["id"])) == 5
    indexes = {
        row["name"]
        for row in writer._connection.execute("PRAGMA index_list(events)").fetchall()
    }
    assert "events_campaign_sequence" in indexes
    reader.close()
    writer.close()


def test_status_snapshot_clock_is_conservative_across_concurrent_heartbeat(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status-heartbeat.sqlite3"
    clock = ManualClock()
    writer, campaign, item = seeded_store(path, clock)
    job = enqueue_investigation(writer, item["id"])
    claim = writer.claim_job("investigator", "worker-a", lease_seconds=5)
    assert claim is not None
    reader = SQLiteStore(path, clock=clock, read_only=True)
    original_get_campaign = reader.get_campaign

    def heartbeat_after_snapshot_anchor(campaign_id: str):
        persisted_campaign = original_get_campaign(campaign_id)
        clock.advance(4)
        assert writer.heartbeat_job(
            job["id"],
            "worker-a",
            claim["lease_token"],
            lease_seconds=60,
        )
        clock.advance(2)
        return persisted_campaign

    reader.get_campaign = heartbeat_after_snapshot_anchor  # type: ignore[method-assign]
    snapshot = reader.read_campaign_status_snapshot(campaign["id"])

    assert snapshot["captured_at"] == 1_000
    assert snapshot["jobs"][0]["lease_expires_at"] == 1_005
    assert snapshot["jobs"][0]["lease_expires_at"] > snapshot["captured_at"]
    assert writer.get_job(job["id"])["lease_expires_at"] == 1_064
    reader.close()
    writer.close()


def test_watch_snapshot_bounds_detail_but_keeps_exact_campaign_totals(
    tmp_path: Path,
) -> None:
    path = tmp_path / "watch-bounded.sqlite3"
    with SQLiteStore(path) as writer:
        campaign = writer.create_campaign("Bounded watch")
        for number in range(7):
            writer.create_work_item(
                campaign["id"],
                "Item %d" % number,
                description="Bounded live-monitor detail.",
                initial_job={
                    "role": "investigator",
                    "stage": "investigate",
                    "active_item_state": "investigating",
                },
            )

    with SQLiteStore(path, read_only=True) as reader:
        snapshot = reader.read_campaign_watch_snapshot(
            campaign["id"], event_limit=2, item_limit=3
        )

    assert snapshot["total_items"] == 7
    assert snapshot["item_state_counts"] == {"backlog": 7}
    assert snapshot["worker_counts"]["investigator"] == {
        "queued": 7,
        "active": 0,
        "expired": 0,
    }
    assert len(snapshot["items"]) == 3
    assert len(snapshot["jobs"]) == 3
    assert snapshot["omitted_item_count"] == 4
    assert len(snapshot["events"]) == 2


def test_watch_snapshot_rejects_unbounded_item_limits(tmp_path: Path) -> None:
    path = tmp_path / "watch-limit.sqlite3"
    with SQLiteStore(path) as writer:
        campaign = writer.create_campaign("Watch limits")
    with SQLiteStore(path, read_only=True) as reader:
        for item_limit in (0, 201, True):
            with pytest.raises(ValueError, match="item_limit"):
                reader.read_campaign_watch_snapshot(
                    campaign["id"], item_limit=item_limit
                )


def test_watch_snapshot_prioritizes_alert_rows_before_ordinary_detail(
    tmp_path: Path,
) -> None:
    path = tmp_path / "watch-alert-priority.sqlite3"
    with SQLiteStore(path) as writer:
        campaign = writer.create_campaign("Watch alert priority")
        writer.create_work_item(
            campaign["id"],
            "Ordinary high priority item",
            description="Would otherwise sort first.",
            priority=100,
        )
        blocked = writer.create_work_item(
            campaign["id"],
            "Blocked low priority item",
            description="Must remain visible to the operator.",
            state="blocked",
        )
        writer.create_work_item(
            campaign["id"],
            "Second blocked item",
            description="Must be counted even outside the detail limit.",
            state="blocked",
        )

    with SQLiteStore(path, read_only=True) as reader:
        snapshot = reader.read_campaign_watch_snapshot(
            campaign["id"], item_limit=1
        )

    assert [item["id"] for item in snapshot["items"]] == [blocked["id"]]
    assert snapshot["omitted_item_count"] == 2
    assert snapshot["omitted_alert_item_count"] == 1


def test_watch_snapshot_prioritizes_expired_worker_over_blocked_item_limit(
    tmp_path: Path,
) -> None:
    path = tmp_path / "watch-mixed-severity.sqlite3"
    clock = ManualClock()
    with SQLiteStore(path, clock=clock) as writer:
        campaign = writer.create_campaign("Watch mixed severity")
        blocked_ids = []
        for number in range(50):
            blocked = writer.create_work_item(
                campaign["id"],
                "Blocked item %02d" % number,
                description="High-priority blocked monitor row.",
                state="blocked",
                priority=100,
            )
            blocked_ids.append(blocked["id"])
        expired_item = writer.create_work_item(
            campaign["id"],
            "Expired low-priority worker",
            description="Expired execution hazards outrank blocked rows.",
            priority=0,
        )
        expired_job = enqueue_investigation(
            writer,
            expired_item["id"],
            resource="tenant:expired-watch",
            stage="expired-watch",
        )
        claim = writer.claim_job(
            "investigator", "expired-worker", lease_seconds=5
        )
        assert claim is not None
        assert claim["id"] == expired_job["id"]
        clock.advance(6)

    with SQLiteStore(path, clock=clock, read_only=True) as reader:
        snapshot = reader.read_campaign_watch_snapshot(
            campaign["id"], item_limit=50
        )

    selected_ids = [item["id"] for item in snapshot["items"]]
    assert selected_ids[0] == expired_item["id"]
    assert expired_item["id"] in selected_ids
    assert len(set(blocked_ids) & set(selected_ids)) == 49
    assert snapshot["omitted_item_count"] == 1
    assert snapshot["omitted_alert_item_count"] == 1
    assert snapshot["worker_counts"]["investigator"] == {
        "queued": 0,
        "active": 0,
        "expired": 1,
    }


def test_watch_snapshot_prioritizes_ambiguous_item_and_counts_open_jobs(
    tmp_path: Path,
) -> None:
    path = tmp_path / "watch-ambiguous-priority.sqlite3"
    with SQLiteStore(path) as writer:
        campaign = writer.create_campaign("Watch ambiguous priority")
        ordinary = writer.create_work_item(
            campaign["id"],
            "Ordinary high-priority item",
            description="Priority alone must not hide an ambiguous lane.",
            priority=100,
        )
        ambiguous = writer.create_work_item(
            campaign["id"],
            "Ambiguous low-priority item",
            description="Two distinct open stages require reconciliation.",
            priority=0,
        )
        for number in range(2):
            enqueue_investigation(
                writer,
                ambiguous["id"],
                resource="tenant:ambiguous-%d" % number,
                stage="ambiguous-stage-%d" % number,
            )

    with SQLiteStore(path, read_only=True) as reader:
        snapshot = reader.read_campaign_watch_snapshot(
            campaign["id"], item_limit=1
        )

    assert ordinary["id"] not in [item["id"] for item in snapshot["items"]]
    assert [item["id"] for item in snapshot["items"]] == [ambiguous["id"]]
    assert snapshot["items"][0]["open_job_count"] == 2
    assert len(snapshot["jobs"]) == 1
    assert snapshot["omitted_item_count"] == 1
    assert snapshot["omitted_alert_item_count"] == 0
    assert snapshot["omitted_open_job_count"] == 1


def test_watch_snapshot_bounds_more_than_one_thousand_open_job_records(
    tmp_path: Path,
) -> None:
    path = tmp_path / "watch-open-job-scale.sqlite3"
    with SQLiteStore(path) as writer:
        campaign = writer.create_campaign("Watch open-job scale")
        item = writer.create_work_item(
            campaign["id"],
            "Large ambiguous lane",
            description="One item has more jobs than SQLite's legacy bind limit.",
        )
        for number in range(1_001):
            enqueue_investigation(
                writer,
                item["id"],
                resource="tenant:scale",
                stage="scale-stage-%04d" % number,
            )

    with SQLiteStore(path, read_only=True) as reader:
        snapshot = reader.read_campaign_watch_snapshot(
            campaign["id"], event_limit=2, item_limit=1
        )

    assert snapshot["items"][0]["open_job_count"] == 1_001
    assert len(snapshot["jobs"]) == 1
    assert snapshot["worker_counts"]["investigator"]["queued"] == 1_001
    assert snapshot["omitted_open_job_count"] == 1_000
    assert snapshot["omitted_item_count"] == 0
    assert snapshot["omitted_alert_item_count"] == 0

    output = StringIO()
    console = Console(
        file=output,
        width=120,
        color_system=None,
        force_terminal=False,
    )
    console.print(
        build_watch_board(
            snapshot["campaign"],
            snapshot["items"],
            snapshot["jobs"],
            snapshot["attempts"],
            snapshot["resource_leases"],
            snapshot["events"],
            item_state_counts=snapshot["item_state_counts"],
            worker_counts=snapshot["worker_counts"],
            total_items=snapshot["total_items"],
            omitted_item_count=snapshot["omitted_item_count"],
            omitted_alert_item_count=snapshot["omitted_alert_item_count"],
            omitted_open_job_count=snapshot["omitted_open_job_count"],
        )
    )
    rendered = re.sub(r"\s+", " ", output.getvalue())
    assert "AMBIGUOUS" in rendered
    assert "1001 open jobs require storage reconciliation" in rendered
    assert (
        "1000 additional open job records are summarized by exact per-item "
        "ambiguity counts" in rendered
    )


def test_campaign_worktree_operation_query_uses_scoped_indexes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "watch-worktree-query-plan.sqlite3"
    with SQLiteStore(path) as store:
        campaign = store.create_campaign("Watch worktree query plan")
        traced_statements = []
        store._connection.set_trace_callback(traced_statements.append)
        try:
            assert store.list_worktree_operations(campaign_id=campaign["id"]) == []
        finally:
            store._connection.set_trace_callback(None)

        query = next(
            statement
            for statement in traced_statements
            if "FROM worktree_operations o" in statement
        )
        plan = [
            str(row["detail"])
            for row in store._connection.execute(
                "EXPLAIN QUERY PLAN " + query
            ).fetchall()
        ]

    assert any(
        "SEARCH managed_worktrees USING COVERING INDEX managed_worktrees_campaign"
        in detail
        for detail in plan
    )
    assert any(
        "SEARCH o USING INDEX" in detail and "managed_worktree_id=?" in detail
        for detail in plan
    )
    assert not any(
        detail.startswith("SCAN o") or "SCAN worktree_operations" in detail
        for detail in plan
    )


def test_claim_skips_resource_blocked_head_of_line_job(tmp_path: Path) -> None:
    path = tmp_path / "head-of-line.sqlite3"
    clock = ManualClock()
    store, campaign, first_item = seeded_store(path, clock)
    second_item = store.create_work_item(
        campaign["id"],
        "second eligible item",
        description="Does not require the occupied browser profile.",
    )
    blocked_job = enqueue_investigation(
        store, first_item["id"], resource="chrome:shared", stage="investigate-blocked"
    )
    eligible_job = enqueue_investigation(
        store, second_item["id"], resource="tenant:free", stage="investigate-free"
    )
    held = store.acquire_resource("chrome:shared", "external-owner", lease_seconds=30)
    assert held is not None

    claim = store.claim_job("investigator", "worker-a")

    assert claim is not None
    assert claim["id"] == eligible_job["id"]
    assert store.get_job(blocked_job["id"])["status"] == "pending"
    store.close()


def test_heartbeat_extends_all_leases_and_wrong_token_is_fenced(tmp_path: Path) -> None:
    path = tmp_path / "heartbeat.sqlite3"
    clock = ManualClock()
    store, _campaign, item = seeded_store(path, clock)
    job = enqueue_investigation(store, item["id"])
    claim = store.claim_job("investigator", "worker-a", lease_seconds=5)
    assert claim is not None

    clock.advance(4)
    heartbeat = store.heartbeat_job(job["id"], "worker-a", claim["lease_token"], lease_seconds=5)
    assert heartbeat["lease_expires_at"] == clock.value + 5
    assert store.list_resource_leases()[0]["expires_at"] == clock.value + 5

    with pytest.raises(LeaseConflict):
        store.heartbeat_job(job["id"], "worker-a", "stale-token")

    clock.advance(4)
    assert store.recover_expired_leases()["jobs"] == 0
    clock.advance(2)
    assert store.recover_expired_leases()["job_ids"] == [job["id"]]
    store.close()


def test_double_finalization_cannot_create_duplicate_downstream_job(tmp_path: Path) -> None:
    path = tmp_path / "double-finalize.sqlite3"
    clock = ManualClock()
    store, _campaign, item = seeded_store(path, clock)
    job = enqueue_investigation(store, item["id"])
    claim = store.claim_job("investigator", "worker-a")
    assert claim is not None
    next_job = {
        "role": "fixer",
        "stage": "fix",
        "queued_item_state": "ready_for_fix",
        "active_item_state": "fixing",
    }

    store.commit_stage_result(
        job["id"],
        "worker-a",
        claim["lease_token"],
        investigation_result(item["id"]),
        "investigating",
        "ready_for_fix",
        "investigation.completed",
        next_job=next_job,
    )
    with pytest.raises(LeaseConflict):
        store.commit_stage_result(
            job["id"],
            "worker-a",
            claim["lease_token"],
            investigation_result(item["id"]),
            "investigating",
            "ready_for_fix",
            "investigation.completed",
            next_job=next_job,
        )

    assert len(store.list_jobs(role="fixer")) == 1
    events = store.list_events(work_item_id=item["id"])
    assert sum(event["event_kind"] == "investigation.completed" for event in events) == 1
    store.close()


def test_execution_failures_retry_with_bound_then_block(tmp_path: Path) -> None:
    path = tmp_path / "bounded-retry.sqlite3"
    clock = ManualClock()
    store, _campaign, item = seeded_store(path, clock)
    job = enqueue_investigation(store, item["id"])

    first = store.claim_job("investigator", "worker-a")
    assert first is not None
    store.fail_job(job["id"], "worker-a", first["lease_token"], "invalid handoff", max_attempts=2)
    assert store.get_job(job["id"])["status"] == "pending"
    assert store.get_work_item(item["id"])["state"] == "backlog"

    second = store.claim_job("investigator", "worker-b")
    assert second is not None
    store.fail_job(job["id"], "worker-b", second["lease_token"], "invalid again", max_attempts=2)
    assert store.get_job(job["id"])["status"] == "failed"
    assert store.get_work_item(item["id"])["state"] == "blocked"
    assert [attempt["status"] for attempt in store.list_attempts(job["id"])] == [
        "failed",
        "failed",
    ]
    store.close()


def test_write_approval_blocks_then_unlocks_fixer_claim(tmp_path: Path) -> None:
    path = tmp_path / "approval.sqlite3"
    clock = ManualClock()
    store = SQLiteStore(path, clock=clock)
    campaign = store.create_campaign(
        "approval campaign", config={"allow_simulated_evidence": True}
    )
    item = store.create_work_item(
        campaign["id"],
        "approved fix",
        description="A local fix that requires campaign approval.",
        state="ready_for_fix",
    )
    store.enqueue_job(
        item["id"],
        "fixer",
        stage="fix",
        queued_item_state="ready_for_fix",
        active_item_state="fixing",
        required_approval_action="local_code_changes",
        workspace_kind="simulated",
    )

    assert store.claim_job("fixer", "fixer-a") is None
    approval = store.create_approval(campaign["id"], "local_code_changes", "human-owner")
    store.resolve_approval(approval["id"], "APPROVED", "human-owner")

    assert store.claim_job("fixer", "fixer-a") is not None
    event_kinds = [event["event_kind"] for event in store.list_events(campaign_id=campaign["id"])]
    assert "approval.requested" in event_kinds
    assert "approval.resolved" in event_kinds
    store.close()


def test_enqueue_rejects_unexecutable_workspace_and_reserved_resource_policies(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "workspace-policy.sqlite3") as store:
        campaign = store.create_campaign("real workspace policy")
        fix_item = store.create_work_item(
            campaign["id"],
            "real fix",
            description="Workspace policy must fail before a dead job is persisted.",
            state="ready_for_fix",
        )
        with pytest.raises(ValueError, match="managed worktree"):
            store.enqueue_job(
                fix_item["id"],
                "fixer",
                stage="source-fixer",
                queued_item_state="ready_for_fix",
                active_item_state="fixing",
                workspace_kind="source_read_only",
            )
        with pytest.raises(ValueError, match="simulation policy"):
            store.enqueue_job(
                fix_item["id"],
                "fixer",
                stage="simulated-fixer",
                queued_item_state="ready_for_fix",
                active_item_state="fixing",
                workspace_kind="simulated",
            )
        backlog_item = store.create_work_item(
            campaign["id"],
            "reserved resource",
            description="Only the supervisor may derive worktree resource keys.",
        )
        with pytest.raises(ValueError, match="reserved"):
            store.enqueue_job(
                backlog_item["id"],
                "investigator",
                stage="reserved-resource",
                queued_item_state="backlog",
                active_item_state="investigating",
                required_resources=["git-worktree:spoofed"],
            )

        assert store.list_jobs(work_item_id=fix_item["id"]) == []
        assert store.list_jobs(work_item_id=backlog_item["id"]) == []


def test_role_and_global_limits_are_both_enforced(tmp_path: Path) -> None:
    path = tmp_path / "role-limits.sqlite3"
    clock = ManualClock()
    store = SQLiteStore(path, clock=clock)
    campaign = store.create_campaign(
        "limits",
        config={"allow_simulated_evidence": True},
        global_limit=2,
        role_limits={"investigator": 1, "fixer": 1, "tester": 1},
    )
    first = store.create_work_item(
        campaign["id"], "investigation one", description="First investigation."
    )
    second = store.create_work_item(
        campaign["id"], "investigation two", description="Second investigation."
    )
    fix_item = store.create_work_item(
        campaign["id"], "fix one", description="Independent fix.", state="ready_for_fix"
    )
    enqueue_investigation(store, first["id"], resource="tenant:one", stage="investigate-one")
    enqueue_investigation(store, second["id"], resource="tenant:two", stage="investigate-two")
    store.enqueue_job(
        fix_item["id"],
        "fixer",
        stage="fix",
        queued_item_state="ready_for_fix",
        active_item_state="fixing",
        workspace_kind="simulated",
    )

    assert store.claim_job("investigator", "investigator-a") is not None
    assert store.claim_job("investigator", "investigator-b") is None
    assert store.claim_job("fixer", "fixer-a") is not None
    assert store.claim_job("tester", "tester-a") is None
    assert len(store.list_jobs(status="running")) == 2
    store.close()


def test_item_and_initial_investigation_job_are_created_atomically(tmp_path: Path) -> None:
    path = tmp_path / "initial-job.sqlite3"
    store = SQLiteStore(path)
    campaign = store.create_campaign("atomic intake")
    item = store.create_work_item(
        campaign["id"],
        "intake item",
        description="Created with its first durable stage job.",
        initial_job={
            "role": "investigator",
            "stage": "investigate",
            "active_item_state": "investigating",
        },
    )

    jobs = store.list_jobs(work_item_id=item["id"])
    assert len(jobs) == 1
    assert jobs[0]["status"] == "pending"
    assert jobs[0]["role"] == "investigator"
    assert store.foreign_key_violations() == []
    store.close()


def test_stage_commit_rolls_back_everything_when_event_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "event-rollback.sqlite3"
    clock = ManualClock()
    store, _campaign, item = seeded_store(path, clock)
    job = enqueue_investigation(store, item["id"])
    claim = store.claim_job("investigator", "worker-a")
    assert claim is not None

    def fail_event(*_args, **_kwargs):
        raise RuntimeError("forced event persistence failure")

    monkeypatch.setattr(store, "_append_event", fail_event)
    with pytest.raises(RuntimeError, match="forced event"):
        store.commit_stage_result(
            job["id"],
            "worker-a",
            claim["lease_token"],
            investigation_result(item["id"]),
            "investigating",
            "ready_for_fix",
            "investigation.completed",
            next_job={
                "role": "fixer",
                "stage": "fix",
                "active_item_state": "fixing",
            },
        )

    assert store.get_job(job["id"])["status"] == "running"
    assert store.get_work_item(item["id"])["state"] == "investigating"
    assert store.list_jobs(role="fixer") == []
    assert len(store.list_resource_leases()) == 1
    store.close()


def test_event_sequence_is_stable_resume_cursor(tmp_path: Path) -> None:
    path = tmp_path / "event-cursor.sqlite3"
    store = SQLiteStore(path)
    campaign = store.create_campaign("event cursor")
    item = store.create_work_item(
        campaign["id"], "cursor item", description="Produces ordered durable events."
    )

    all_events = store.list_events(campaign_id=campaign["id"])
    sequences = [event["sequence"] for event in all_events]
    assert sequences == sorted(sequences)
    assert len(sequences) == len(set(sequences))
    resumed = store.list_events(campaign_id=campaign["id"], after_sequence=sequences[0])
    assert [event["sequence"] for event in resumed] == sequences[1:]
    assert item["id"] == resumed[-1]["work_item_id"]
    store.close()


def test_fractional_concurrency_limits_are_rejected(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "fractional-limits.sqlite3")
    with pytest.raises(ValueError, match="positive integer"):
        store.create_campaign("fractional global", global_limit=1.5)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="positive integers"):
        store.create_campaign(
            "fractional role",
            role_limits={
                "investigator": 1.5,  # type: ignore[dict-item]
                "fixer": 1,
                "tester": 1,
            },
        )
    store.close()


def test_fractional_retry_limit_is_rejected(tmp_path: Path) -> None:
    store, _campaign, item = seeded_store(
        tmp_path / "fractional-retry-limit.sqlite3", ManualClock()
    )
    job = enqueue_investigation(store, item["id"])
    claim = store.claim_job("investigator", "worker-a")
    assert claim is not None

    with pytest.raises(ValueError, match="positive integer"):
        store.fail_job(
            job["id"],
            "worker-a",
            claim["lease_token"],
            "invalid retry policy",
            max_attempts=1.5,  # type: ignore[arg-type]
        )

    assert store.get_job(job["id"])["status"] == "running"
    store.close()


def test_schema_v1_database_migrates_external_and_worktree_fields_to_v5(
    tmp_path: Path,
) -> None:
    path = tmp_path / "schema-v1.sqlite3"
    connection = sqlite3.connect(str(path))
    try:
        for statement in _SCHEMA_V1:
            connection.execute(statement)
        connection.execute("PRAGMA user_version = 1")
        connection.commit()
    finally:
        connection.close()

    with SQLiteStore(path) as store:
        version = int(store._connection.execute("PRAGMA user_version").fetchone()[0])
        columns = {
            row["name"]
            for row in store._connection.execute("PRAGMA table_info(attempts)").fetchall()
        }

    assert version == SCHEMA_VERSION == 9
    assert {
        "external_provider",
        "external_session_id",
        "external_process_id",
        "external_process_group_id",
        "external_process_executable",
        "external_process_started_at",
        "managed_worktree_id",
        "managed_worktree_generation",
    }.issubset(columns)


def test_schema_v2_database_migrates_process_and_worktree_fields_to_v5(
    tmp_path: Path,
) -> None:
    path = tmp_path / "schema-v2.sqlite3"
    connection = sqlite3.connect(str(path))
    try:
        for statement in _SCHEMA_V1:
            connection.execute(statement)
        for statement in _SCHEMA_V2:
            connection.execute(statement)
        connection.execute("PRAGMA user_version = 2")
        connection.commit()
    finally:
        connection.close()

    with SQLiteStore(path) as store:
        version = int(store._connection.execute("PRAGMA user_version").fetchone()[0])
        columns = {
            row["name"]
            for row in store._connection.execute("PRAGMA table_info(attempts)").fetchall()
        }

    assert version == SCHEMA_VERSION == 9
    assert {
        "external_provider",
        "external_session_id",
        "external_process_id",
        "external_process_group_id",
        "external_process_executable",
        "external_process_started_at",
        "managed_worktree_id",
        "managed_worktree_generation",
    }.issubset(columns)


def test_external_session_is_fenced_resumable_and_cannot_cross_jobs(
    tmp_path: Path,
) -> None:
    store, campaign, item = seeded_store(tmp_path / "external-session.sqlite3", ManualClock())
    first_job = enqueue_investigation(store, item["id"])
    first_claim = store.claim_job("investigator", "worker-a")
    assert first_claim is not None
    session_id = "019f6677-1111-7222-8333-444444444444"

    store.record_external_process(
        first_job["id"],
        "worker-a",
        first_claim["lease_token"],
        "codex",
        32099,
        32099,
        os.getuid(),
        "/usr/bin/python3",
        29,
        39,
        "/usr/local/bin/codex",
    )
    recorded = store.record_external_session(
        first_job["id"],
        "worker-a",
        first_claim["lease_token"],
        "codex",
        session_id,
    )
    assert recorded["external_provider"] == "codex"
    assert recorded["external_session_id"] == session_id
    assert (
        store.record_external_session(
            first_job["id"],
            "worker-a",
            first_claim["lease_token"],
            "codex",
            session_id,
        )["id"]
        == recorded["id"]
    )
    with pytest.raises(LeaseConflict):
        store.record_external_session(
            first_job["id"],
            "worker-a",
            "stale-token",
            "codex",
            session_id,
        )

    store.clear_external_process(
        first_job["id"],
        "worker-a",
        first_claim["lease_token"],
        32099,
        32099,
    )

    store.interrupt_job(
        first_job["id"],
        "worker-a",
        first_claim["lease_token"],
        reason="clean stop for exact-session resume",
    )
    store.request_job_resume(
        first_job["id"],
        first_claim["attempt_id"],
        "codex",
        session_id,
        requested_by="operator-a",
    )
    resumed = store.claim_job("investigator", "worker-b")
    assert resumed is not None
    assert resumed["resume_external_provider"] == "codex"
    assert resumed["resume_external_session_id"] == session_id
    store.record_external_session(
        first_job["id"],
        "worker-b",
        resumed["lease_token"],
        "codex",
        session_id,
    )

    second_item = store.create_work_item(
        campaign["id"],
        "second external item",
        description="Must not reuse another logical job's Codex thread.",
    )
    second_job = enqueue_investigation(
        store, second_item["id"], resource="chrome:two", stage="investigate-two"
    )
    second_claim = store.claim_job("investigator", "worker-c")
    assert second_claim is not None
    with pytest.raises(LeaseConflict, match="another logical job"):
        store.record_external_session(
            second_job["id"],
            "worker-c",
            second_claim["lease_token"],
            "codex",
            session_id,
        )
    store.close()


def test_live_external_process_quarantines_expired_job_and_resource(
    tmp_path: Path,
) -> None:
    clock = ManualClock()
    store, _campaign, item = seeded_store(tmp_path / "external-process-quarantine.sqlite3", clock)
    job = enqueue_investigation(store, item["id"])
    claim = store.claim_job("investigator", "worker-a", lease_seconds=5)
    assert claim is not None
    store.record_external_process(
        job["id"],
        "worker-a",
        claim["lease_token"],
        "codex",
        43210,
        43210,
        os.getuid(),
        "/usr/bin/python3",
        10,
        20,
        "/usr/local/bin/codex",
    )

    with pytest.raises(LeaseConflict, match="must be reaped"):
        store.interrupt_job(job["id"], "worker-a", claim["lease_token"], reason="unsafe stop")
    clock.advance(6)
    recovery = store.recover_expired_leases()

    assert recovery["jobs"] == 0
    assert recovery["resources"] == 0
    assert recovery["external_processes_pending"][0]["job_id"] == job["id"]
    assert store.get_job(job["id"])["status"] == "running"
    assert store.get_work_item(item["id"])["state"] == "investigating"
    assert len(store.list_resource_leases()) == 1
    assert store.list_attempts(job["id"])[0]["status"] == "running"
    store.close()


def test_reaped_external_process_can_be_cleanly_interrupted_and_resumed(
    tmp_path: Path,
) -> None:
    store, _campaign, item = seeded_store(
        tmp_path / "external-process-clean-stop.sqlite3", ManualClock()
    )
    job = enqueue_investigation(store, item["id"])
    claim = store.claim_job("investigator", "worker-a")
    assert claim is not None
    store.record_external_process(
        job["id"],
        "worker-a",
        claim["lease_token"],
        "codex",
        32100,
        32100,
        os.getuid(),
        "/usr/bin/python3",
        30,
        40,
        "/usr/local/bin/codex",
    )
    store.record_external_session(
        job["id"],
        "worker-a",
        claim["lease_token"],
        "codex",
        "019f6677-aaaa-7bbb-8ccc-dddddddddddd",
    )
    store.clear_external_process(
        job["id"],
        "worker-a",
        claim["lease_token"],
        32100,
        32100,
    )

    interrupted = store.interrupt_job(
        job["id"],
        "worker-a",
        claim["lease_token"],
        reason="adapter reaped process group",
    )
    store.request_job_resume(
        job["id"],
        claim["attempt_id"],
        "codex",
        "019f6677-aaaa-7bbb-8ccc-dddddddddddd",
        requested_by="operator-a",
    )
    resumed = store.claim_job("investigator", "worker-b")

    assert interrupted["status"] == "pending"
    assert resumed is not None
    assert resumed["resume_external_session_id"] == ("019f6677-aaaa-7bbb-8ccc-dddddddddddd")
    events = store.list_events(work_item_id=item["id"])
    assert [event["event_kind"] for event in events].count("worker.external_process_started") == 1
    assert [event["event_kind"] for event in events].count("worker.external_process_stopped") == 1
    store.close()


def test_schema_v3_live_process_migrates_to_unverifiable_quarantine(
    tmp_path: Path,
) -> None:
    path = tmp_path / "schema-v3-live-process.sqlite3"
    connection = sqlite3.connect(str(path))
    try:
        for statement in _SCHEMA_V1:
            connection.execute(statement)
        for statement in _SCHEMA_V2:
            connection.execute(statement)
        for statement in _SCHEMA_V3:
            connection.execute(statement)
        connection.execute(
            """INSERT INTO campaigns
               (id, name, status, config_json, global_limit, role_limits_json,
                created_at, updated_at)
               VALUES ('campaign-v3', 'V3 migration', 'active', '{}', 1,
                       '{"investigator": 1}', 10, 10)"""
        )
        connection.execute(
            """INSERT INTO work_items
               (id, campaign_id, title, description, state, priority,
                required_gates_json, metadata_json, created_at, updated_at)
               VALUES ('item-v3', 'campaign-v3', 'Legacy process',
                       'Migrate a live V3 process binding.', 'investigating', 0,
                       '[]', '{}', 10, 10)"""
        )
        connection.execute(
            """INSERT INTO jobs
               (id, campaign_id, work_item_id, role, stage, status, priority,
                payload_json, required_resources_json, queued_item_state,
                active_item_state, available_at, lease_owner, lease_token,
                lease_expires_at, heartbeat_at, current_attempt_id,
                attempt_count, created_at, updated_at)
               VALUES ('job-v3', 'campaign-v3', 'item-v3', 'investigator',
                       'investigate', 'running', 0, '{}', '[]', 'backlog',
                       'investigating', 10, 'worker-v3', 'lease-v3', 20, 10,
                       'attempt-v3', 1, 10, 10)"""
        )
        connection.execute(
            """INSERT INTO attempts
               (id, job_id, attempt_number, worker_id, lease_token, status,
                started_at, heartbeat_at, lease_expires_at, external_provider,
                external_process_id, external_process_group_id,
                external_process_executable, external_process_started_at)
               VALUES ('attempt-v3', 'job-v3', 1, 'worker-v3', 'lease-v3',
                       'running', 10, 10, 20, 'codex', 43210, 43210,
                       '/usr/bin/node', 11)"""
        )
        connection.execute("PRAGMA user_version = 3")
        connection.commit()
    finally:
        connection.close()

    clock = ManualClock(30)
    with SQLiteStore(path, clock=clock) as store:
        processes = store.list_external_processes()
        assert len(processes) == 1
        process = processes[0]
        assert process["attempt_id"] == "attempt-v3"
        assert process["identity_version"] == "legacy_v3"
        assert process["state"] == "legacy_unverifiable"
        assert process["owner_uid"] is None
        assert process["start_seconds"] is None
        assert process["start_microseconds"] is None
        assert process["kernel_executable"] == "/usr/bin/node"
        assert "no kernel birth identity" in process["last_error"]

        recovery = store.recover_expired_leases()
        assert recovery["jobs"] == 0
        assert recovery["external_processes_pending"][0]["identity_version"] == ("legacy_v3")
        claim = store.claim_external_process_reconciliation("reconciler-v4")
        assert claim is not None
        expected_identity = {
            "process_id": 43210,
            "process_group_id": 43210,
            "user_id": None,
            "executable": "/usr/bin/node",
            "start_seconds": None,
            "start_microseconds": None,
            "target_executable": "/usr/bin/node",
            "identity_version": "legacy_v3",
        }
        with pytest.raises(LeaseConflict, match="unverifiable"):
            store.complete_external_process_reconciliation(
                "attempt-v3",
                "reconciler-v4",
                claim["reconciliation_token"],
                expected_identity,
                "gone",
                "Legacy PID was absent.",
            )

        assert store.get_job("job-v3")["status"] == "running"
        assert store.get_work_item("item-v3")["state"] == "investigating"
        assert store.list_attempts("job-v3")[0]["status"] == "running"
        assert store.foreign_key_violations() == []


def test_external_process_identity_is_immutable_after_reap(tmp_path: Path) -> None:
    store, _campaign, item = seeded_store(
        tmp_path / "external-process-immutable.sqlite3", ManualClock()
    )
    job = enqueue_investigation(store, item["id"])
    claim = store.claim_job("investigator", "worker-a")
    assert claim is not None
    recorded = store.record_external_process(
        job["id"],
        "worker-a",
        claim["lease_token"],
        "codex",
        32110,
        32110,
        os.getuid(),
        "/usr/bin/python3",
        123,
        456,
        "/usr/local/bin/codex",
    )

    stopped = store.clear_external_process(
        job["id"],
        "worker-a",
        claim["lease_token"],
        32110,
        32110,
    )

    identity_fields = (
        "id",
        "attempt_id",
        "job_id",
        "provider",
        "process_id",
        "process_group_id",
        "owner_uid",
        "kernel_executable",
        "start_seconds",
        "start_microseconds",
        "target_executable",
        "identity_version",
        "recorded_at",
    )
    assert {field: stopped[field] for field in identity_fields} == {
        field: recorded[field] for field in identity_fields
    }
    assert stopped["state"] == "stopped"
    assert stopped["outcome"] == "reaped"
    assert stopped["stopped_at"] is not None
    attempt = store.list_attempts(job["id"])[0]
    assert attempt["external_process_id"] == 32110
    assert attempt["external_process_group_id"] == 32110
    assert attempt["external_process_state"] == "stopped"
    assert store.foreign_key_violations() == []
    store.close()


def test_expired_job_bound_resource_cannot_be_stolen_before_recovery(
    tmp_path: Path,
) -> None:
    clock = ManualClock()
    store, _campaign, item = seeded_store(tmp_path / "expired-job-resource.sqlite3", clock)
    job = enqueue_investigation(store, item["id"], resource="chrome:exclusive")
    claim = store.claim_job("investigator", "worker-a", lease_seconds=5)
    assert claim is not None
    clock.advance(6)

    assert store.acquire_resource("chrome:exclusive", "unrelated-worker", lease_seconds=30) is None
    lease = store.list_resource_leases()[0]
    assert lease["job_id"] == job["id"]
    assert lease["owner_id"] == "worker-a"
    assert lease["lease_token"] == claim["lease_token"]

    recovery = store.recover_expired_leases()
    assert recovery["job_ids"] == [job["id"]]
    assert store.list_resource_leases() == []
    store.close()


def test_external_process_reconciliation_claim_is_fenced_and_quarantine_retains_state(
    tmp_path: Path,
) -> None:
    path = tmp_path / "external-process-reconciliation-fence.sqlite3"
    clock = ManualClock()
    first, _campaign, item = seeded_store(path, clock)
    job = enqueue_investigation(first, item["id"], resource="chrome:fenced")
    job_claim = first.claim_job("investigator", "worker-a", lease_seconds=5)
    assert job_claim is not None
    external = first.record_external_process(
        job["id"],
        "worker-a",
        job_claim["lease_token"],
        "codex",
        32120,
        32120,
        os.getuid(),
        "/usr/bin/python3",
        200,
        300,
        "/usr/local/bin/codex",
    )
    clock.advance(6)
    second = SQLiteStore(path, clock=clock)
    barrier = Barrier(2)

    def reconcile_claim(store: SQLiteStore, owner: str):
        barrier.wait()
        return store.claim_external_process_reconciliation(owner, lease_seconds=5)

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(
            pool.map(
                lambda args: reconcile_claim(*args),
                [(first, "reconciler-a"), (second, "reconciler-b")],
            )
        )

    winner = next(claim for claim in claims if claim is not None)
    winner_owner = winner["reconciliation_owner"]
    assert len([claim for claim in claims if claim is not None]) == 1
    assert first.claim_external_process_reconciliation("reconciler-c") is None
    expected_identity = {
        "process_id": external["process_id"],
        "process_group_id": external["process_group_id"],
        "user_id": external["owner_uid"],
        "executable": external["kernel_executable"],
        "start_seconds": external["start_seconds"],
        "start_microseconds": external["start_microseconds"],
        "target_executable": external["target_executable"],
        "identity_version": external["identity_version"],
    }
    with pytest.raises(LeaseConflict, match="fence is stale"):
        first.complete_external_process_reconciliation(
            external["attempt_id"],
            winner_owner,
            "not-the-current-token",
            expected_identity,
            "quarantined",
            "Rejected stale reconciliation completion.",
        )

    clock.advance(6)
    replacement = second.claim_external_process_reconciliation("reconciler-new", lease_seconds=5)
    assert replacement is not None
    with pytest.raises(LeaseConflict, match="fence is stale"):
        first.complete_external_process_reconciliation(
            external["attempt_id"],
            winner_owner,
            winner["reconciliation_token"],
            expected_identity,
            "quarantined",
            "Expired reconciliation must not commit.",
        )

    blocked = second.complete_external_process_reconciliation(
        external["attempt_id"],
        "reconciler-new",
        replacement["reconciliation_token"],
        expected_identity,
        "quarantined",
        "Kernel identity did not match the persisted binding.",
        observed={"process_id": 32120, "start_seconds": 201},
    )
    assert blocked["recovered"] is False
    assert blocked["status"] == "quarantined"
    assert first.get_job(job["id"])["status"] == "running"
    assert first.get_work_item(item["id"])["state"] == "investigating"
    assert first.list_attempts(job["id"])[0]["status"] == "running"
    assert len(first.list_resource_leases()) == 1
    process = first.list_external_processes()[0]
    assert process["state"] == "quarantined"
    assert process["reconciliation_token"] is None
    assert process["last_error"] == ("Kernel identity did not match the persisted binding.")
    event_kinds = [event["event_kind"] for event in first.list_events(work_item_id=item["id"])]
    assert event_kinds.count("worker.external_process_reconciliation_claimed") == 2
    assert "worker.external_process_reconciliation_blocked" in event_kinds
    assert first.foreign_key_violations() == []
    first.close()
    second.close()


def test_safe_external_process_reconciliation_atomically_recovers_job(
    tmp_path: Path,
) -> None:
    clock = ManualClock()
    store, _campaign, item = seeded_store(tmp_path / "safe-process-reconciliation.sqlite3", clock)
    job = enqueue_investigation(store, item["id"], resource="chrome:safe")
    job_claim = store.claim_job("investigator", "worker-a", lease_seconds=5)
    assert job_claim is not None
    external = store.record_external_process(
        job["id"],
        "worker-a",
        job_claim["lease_token"],
        "codex",
        32130,
        32130,
        os.getuid(),
        "/usr/bin/python3",
        300,
        400,
        "/usr/local/bin/codex",
    )
    clock.advance(6)
    reconciliation_claim = store.claim_external_process_reconciliation("reconciler-safe")
    assert reconciliation_claim is not None
    expected_identity = {
        "process_id": external["process_id"],
        "process_group_id": external["process_group_id"],
        "user_id": external["owner_uid"],
        "executable": external["kernel_executable"],
        "start_seconds": external["start_seconds"],
        "start_microseconds": external["start_microseconds"],
        "target_executable": external["target_executable"],
        "identity_version": external["identity_version"],
    }

    completed = store.complete_external_process_reconciliation(
        external["attempt_id"],
        "reconciler-safe",
        reconciliation_claim["reconciliation_token"],
        expected_identity,
        "gone",
        "Exact persisted process identity is absent from the OS.",
        observed={"process_id": None, "process_group_id": None},
    )

    assert completed == {
        "job_id": job["id"],
        "attempt_id": external["attempt_id"],
        "status": "gone",
        "recovered": True,
    }
    assert store.get_job(job["id"])["status"] == "pending"
    assert store.get_job(job["id"])["current_attempt_id"] is None
    assert store.get_work_item(item["id"])["state"] == "backlog"
    attempt = store.list_attempts(job["id"])[0]
    assert attempt["status"] == "expired"
    assert attempt["error"] == ("lease expired after external process reconciliation")
    assert store.list_resource_leases() == []
    process = store.list_external_processes()[0]
    assert process["state"] == "stopped"
    assert process["outcome"] == "gone"
    assert process["process_id"] == 32130
    assert process["start_seconds"] == 300
    event_kinds = [event["event_kind"] for event in store.list_events(work_item_id=item["id"])]
    assert event_kinds[-3:] == [
        "worker.external_process_reconciliation_claimed",
        "worker.external_process_reconciled",
        "job.lease_expired",
    ]
    assert store.foreign_key_violations() == []
    store.close()


def test_external_process_reconciliation_rolls_back_if_resource_fence_is_lost(
    tmp_path: Path,
) -> None:
    clock = ManualClock()
    store, _campaign, item = seeded_store(
        tmp_path / "process-reconciliation-rollback.sqlite3", clock
    )
    job = enqueue_investigation(store, item["id"], resource="chrome:lost")
    job_claim = store.claim_job("investigator", "worker-a", lease_seconds=5)
    assert job_claim is not None
    external = store.record_external_process(
        job["id"],
        "worker-a",
        job_claim["lease_token"],
        "codex",
        32140,
        32140,
        os.getuid(),
        "/usr/bin/python3",
        400,
        500,
        "/usr/local/bin/codex",
    )
    clock.advance(6)
    reconciliation_claim = store.claim_external_process_reconciliation("reconciler-rollback")
    assert reconciliation_claim is not None
    expected_identity = {
        "process_id": external["process_id"],
        "process_group_id": external["process_group_id"],
        "user_id": external["owner_uid"],
        "executable": external["kernel_executable"],
        "start_seconds": external["start_seconds"],
        "start_microseconds": external["start_microseconds"],
        "target_executable": external["target_executable"],
        "identity_version": external["identity_version"],
    }
    with store._transaction() as connection:
        connection.execute("DELETE FROM resource_leases WHERE job_id = ?", (job["id"],))

    with pytest.raises(LeaseConflict, match="resource fences changed"):
        store.complete_external_process_reconciliation(
            external["attempt_id"],
            "reconciler-rollback",
            reconciliation_claim["reconciliation_token"],
            expected_identity,
            "gone",
            "Exact persisted process identity is absent from the OS.",
        )

    assert store.get_job(job["id"])["status"] == "running"
    assert store.get_work_item(item["id"])["state"] == "investigating"
    assert store.list_attempts(job["id"])[0]["status"] == "running"
    process = store.list_external_processes()[0]
    assert process["state"] == "active"
    assert process["outcome"] is None
    event_kinds = [event["event_kind"] for event in store.list_events(work_item_id=item["id"])]
    assert "worker.external_process_reconciled" not in event_kinds
    assert "job.lease_expired" not in event_kinds
    assert store.foreign_key_violations() == []
    store.close()


def test_stage_authority_prevents_direct_or_non_tester_green(tmp_path: Path) -> None:
    store, _campaign, item = seeded_store(tmp_path / "green-authority.sqlite3", ManualClock())
    with pytest.raises(ValueError, match="active or verified"):
        store.create_work_item(
            item["campaign_id"],
            "pre-green item",
            description="Cannot bypass the tester evidence gate.",
            state="verified_green",
        )
    assert not hasattr(store, "transition_work_item")
    assert not hasattr(store, "update_work_item_state")

    job = enqueue_investigation(store, item["id"])
    claim = store.claim_job("investigator", "worker-a")
    assert claim is not None
    with pytest.raises(TransitionConflict, match="cannot transition"):
        store.commit_stage_result(
            job["id"],
            "worker-a",
            claim["lease_token"],
            {"unsupported": "green"},
            "investigating",
            "verified_green",
            "invalid-green",
        )
    assert store.get_job(job["id"])["status"] == "running"
    assert store.get_work_item(item["id"])["state"] == "investigating"
    store.close()


def test_direct_store_tester_commit_cannot_bypass_required_evidence_gates(
    tmp_path: Path,
) -> None:
    store = SQLiteStore(tmp_path / "tester-gate-authority.sqlite3")
    campaign = store.create_campaign("tester gate authority")
    item = store.create_work_item(
        campaign["id"],
        "proofless green",
        description="A direct store caller must not bypass evidence gates.",
        state="ready_for_test",
    )
    job = store.enqueue_job(
        item["id"],
        "tester",
        stage="test",
        queued_item_state="ready_for_test",
        active_item_state="testing",
    )
    claim = store.claim_job("tester", "tester-a")
    assert claim is not None
    proof = tmp_path / "focused-test-proof.txt"
    proof.write_text("focused test passed\n", encoding="utf-8")
    incomplete_handoff = {
        "schema_version": 1,
        "item_id": item["id"],
        "outcome": "pass",
        "summary": "Only the focused test has proof.",
        "gate_proofs": [
            {
                "gate": "focused_tests",
                "result": "pass",
                "summary": "Focused test passed.",
                "evidence": [
                    {
                        "kind": "test",
                        "location": str(proof),
                        "description": "Focused test output.",
                    }
                ],
            }
        ],
    }

    with pytest.raises(ValueError, match="tester handoff cannot advance"):
        store.commit_stage_result(
            job["id"],
            "tester-a",
            claim["lease_token"],
            incomplete_handoff,
            "testing",
            "verified_green",
            "test_verified_green",
        )

    assert store.get_job(job["id"])["status"] == "running"
    assert store.get_work_item(item["id"])["state"] == "testing"
    store.close()


def test_job_bound_resources_cannot_be_released_or_finalized_after_loss(
    tmp_path: Path,
) -> None:
    store, _campaign, item = seeded_store(tmp_path / "job-resource-fence.sqlite3", ManualClock())
    job = enqueue_investigation(store, item["id"])
    claim = store.claim_job("investigator", "worker-a")
    assert claim is not None
    resource = store.list_resource_leases()[0]

    with pytest.raises(LeaseConflict, match="job-bound resources are released"):
        store.release_resource(resource["resource_key"], "worker-a", claim["lease_token"])

    with store._transaction() as connection:
        connection.execute(
            "DELETE FROM resource_leases WHERE resource_key = ?",
            (resource["resource_key"],),
        )
    with pytest.raises(LeaseConflict, match="resource lease fences were lost"):
        store.commit_stage_result(
            job["id"],
            "worker-a",
            claim["lease_token"],
            investigation_result(item["id"]),
            "investigating",
            "ready_for_fix",
            "investigation.completed",
            next_job={
                "role": "fixer",
                "stage": "fix",
                "active_item_state": "fixing",
            },
        )

    assert store.get_job(job["id"])["status"] == "running"
    assert store.get_work_item(item["id"])["state"] == "investigating"
    store.close()


def test_commit_samples_clock_after_database_write_lock_is_acquired(
    tmp_path: Path,
) -> None:
    path = tmp_path / "lease-lock-contention.sqlite3"
    clock = ManualClock()
    store, _campaign, item = seeded_store(path, clock)
    job = enqueue_investigation(store, item["id"])
    claim = store.claim_job("investigator", "worker-a", lease_seconds=5)
    assert claim is not None
    blocker = SQLiteStore(path, clock=clock)
    lock_acquired = Event()
    release_lock = Event()
    commit_started = Event()

    def hold_write_lock() -> None:
        with blocker._transaction():
            lock_acquired.set()
            assert release_lock.wait(timeout=2)

    def commit_after_wait() -> dict:
        commit_started.set()
        return store.commit_stage_result(
            job["id"],
            "worker-a",
            claim["lease_token"],
            investigation_result(item["id"]),
            "investigating",
            "ready_for_fix",
            "investigation.completed",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        holder = pool.submit(hold_write_lock)
        assert lock_acquired.wait(timeout=2)
        commit = pool.submit(commit_after_wait)
        assert commit_started.wait(timeout=2)
        time.sleep(0.05)
        clock.advance(6)
        release_lock.set()
        holder.result(timeout=2)
        with pytest.raises(LeaseConflict):
            commit.result(timeout=2)

    assert store.get_job(job["id"])["status"] == "running"
    assert store.get_work_item(item["id"])["state"] == "investigating"
    blocker.close()
    store.close()


def test_approval_repository_scope_is_enforced_during_claim(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "approval-scope.sqlite3")
    campaign = store.create_campaign(
        "repository scope",
        config={
            "repository_paths": ["/private/tmp/repo-b"],
            "allow_simulated_evidence": True,
        },
    )
    item = store.create_work_item(
        campaign["id"],
        "scoped fix",
        description="Fix belongs only to repository B.",
        state="ready_for_fix",
    )
    store.enqueue_job(
        item["id"],
        "fixer",
        stage="fix",
        queued_item_state="ready_for_fix",
        active_item_state="fixing",
        required_approval_action="local_code_changes",
        workspace_kind="simulated",
    )
    wrong = store.create_approval(
        campaign["id"],
        "local_code_changes",
        "human-owner",
        scope={"repository_paths": ["/private/tmp/repo-a"]},
    )
    store.resolve_approval(wrong["id"], "approved", "human-owner")
    assert store.claim_job("fixer", "fixer-a") is None

    correct = store.create_approval(
        campaign["id"],
        "local_code_changes",
        "human-owner",
        scope={"repository_paths": ["/private/tmp/repo-b"]},
    )
    store.resolve_approval(correct["id"], "approved", "human-owner")
    assert store.claim_job("fixer", "fixer-a") is not None
    store.close()


def test_clean_interruption_requeues_and_releases_resources(tmp_path: Path) -> None:
    store, _campaign, item = seeded_store(tmp_path / "interruption.sqlite3", ManualClock())
    job = enqueue_investigation(store, item["id"])
    claim = store.claim_job("investigator", "worker-a")
    assert claim is not None

    interrupted = store.interrupt_job(
        job["id"],
        "worker-a",
        claim["lease_token"],
        reason="clean supervisor shutdown",
    )

    assert interrupted["status"] == "pending"
    assert store.get_work_item(item["id"])["state"] == "backlog"
    assert store.list_attempts(job["id"])[0]["status"] == "interrupted"
    assert store.list_resource_leases() == []
    with pytest.raises(LeaseConflict):
        store.heartbeat_job(job["id"], "worker-a", claim["lease_token"])
    store.close()


def test_clean_interruption_does_not_consume_failure_retry_budget(tmp_path: Path) -> None:
    store, _campaign, item = seeded_store(tmp_path / "interruption-budget.sqlite3", ManualClock())
    job = enqueue_investigation(store, item["id"])

    interrupted = store.claim_job("investigator", "worker-a")
    assert interrupted is not None
    store.interrupt_job(
        job["id"],
        "worker-a",
        interrupted["lease_token"],
        reason="clean restart",
    )

    first_failure = store.claim_job("investigator", "worker-b")
    assert first_failure is not None
    store.fail_job(
        job["id"],
        "worker-b",
        first_failure["lease_token"],
        "first actual defect",
        max_attempts=2,
    )
    assert store.get_job(job["id"])["status"] == "pending"
    assert store.get_work_item(item["id"])["state"] == "backlog"

    second_failure = store.claim_job("investigator", "worker-c")
    assert second_failure is not None
    store.fail_job(
        job["id"],
        "worker-c",
        second_failure["lease_token"],
        "second actual defect",
        max_attempts=2,
    )
    assert store.get_job(job["id"])["status"] == "failed"
    assert store.get_work_item(item["id"])["state"] == "blocked"
    assert [attempt["status"] for attempt in store.list_attempts(job["id"])] == [
        "interrupted",
        "failed",
        "failed",
    ]
    store.close()
