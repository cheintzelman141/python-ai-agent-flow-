from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock
from typing import Iterator, List, Optional, Tuple

import pytest

from agent_flow.process_reconciler import (
    DarwinProcessRuntime,
    ExternalProcessReconciler,
    ProcessIdentity,
    ProcessInspectionError,
    ReconciliationStatus,
)
from agent_flow.sqlite_scheduler import SQLiteSchedulerStorage
from agent_flow.storage import SQLiteStore


pytestmark = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="exact process birth identity currently requires macOS libproc",
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


class RecordingDarwinRuntime:
    """Real libproc inspection with an explicit audit trail for every signal."""

    def __init__(self) -> None:
        self.runtime = DarwinProcessRuntime()
        self.signals: List[Tuple[int, int]] = []

    def inspect(self, process_id: int) -> Optional[ProcessIdentity]:
        return self.runtime.inspect(process_id)

    def list_group(self, process_group_id: int) -> Tuple[ProcessIdentity, ...]:
        return self.runtime.list_group(process_group_id)

    def signal_group(self, process_group_id: int, signal_number: int) -> None:
        self.signals.append((process_group_id, signal_number))
        self.runtime.signal_group(process_group_id, signal_number)


@contextmanager
def _temporary_database(clock: ManualClock) -> Iterator[Tuple[Path, SQLiteStore]]:
    with TemporaryDirectory(
        prefix="agent-flow-process-reconciliation-", dir="/private/tmp"
    ) as root:
        database = Path(root) / "state.sqlite3"
        store = SQLiteStore(database, clock=clock)
        try:
            yield database, store
        finally:
            store.close()


def _create_claimed_job(store: SQLiteStore) -> Tuple[dict, dict, dict, dict]:
    campaign = store.create_campaign(
        "Disposable process reconciliation proof",
        global_limit=1,
        role_limits={"investigator": 1, "fixer": 1, "tester": 1},
    )
    item = store.create_work_item(
        campaign["id"],
        "Recover only the exact expired external process",
        description="Exercise restart reconciliation against a test-owned process group.",
        required_gates=["focused_tests"],
        initial_job={
            "role": "investigator",
            "stage": "investigator",
            "queued_item_state": "backlog",
            "active_item_state": "investigating",
            "required_resources": ["test-owned-exclusive-resource"],
        },
    )
    job = store.list_jobs(work_item_id=item["id"])[0]
    claim = store.claim_job("investigator", "disposable-worker", lease_seconds=5)
    assert claim is not None
    assert claim["id"] == job["id"]
    return campaign, item, job, claim


def _spawn_disposable_process(
    runtime: RecordingDarwinRuntime,
) -> Tuple[subprocess.Popen, ProcessIdentity]:
    reaper = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import os, sys, time\n"
                "child = os.fork()\n"
                "if child == 0:\n"
                "    os.setsid()\n"
                "    time.sleep(300)\n"
                "    raise SystemExit(0)\n"
                "print(child, flush=True)\n"
                "os.waitpid(child, 0)\n"
                "raise SystemExit(0)\n"
            ),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert reaper.stdout is not None
    process_id = int(reaper.stdout.readline().strip())
    try:
        deadline = time.monotonic() + 3.0
        identity: Optional[ProcessIdentity] = None
        stable_since: Optional[float] = None
        while time.monotonic() < deadline:
            try:
                observed = runtime.inspect(process_id)
            except ProcessInspectionError:
                identity = None
                stable_since = None
                time.sleep(0.01)
                continue
            now = time.monotonic()
            if observed is None:
                identity = None
                stable_since = None
            elif observed != identity:
                identity = observed
                stable_since = now
            elif stable_since is not None and now - stable_since >= 0.1:
                break
            time.sleep(0.01)
        assert identity is not None
        assert stable_since is not None
        assert time.monotonic() - stable_since >= 0.1
        assert identity.process_id == process_id
        assert identity.process_group_id == process_id
        assert identity.user_id == os.getuid()
        return reaper, identity
    except BaseException:
        try:
            os.killpg(process_id, signal.SIGKILL)
        except ProcessLookupError:
            pass
        reaper.wait(timeout=3.0)
        raise


def _record_process(
    store: SQLiteStore,
    job: dict,
    claim: dict,
    identity: ProcessIdentity,
    *,
    start_microseconds: Optional[int] = None,
) -> None:
    store.record_external_process(
        job["id"],
        "disposable-worker",
        claim["lease_token"],
        "test-python",
        identity.process_id,
        identity.process_group_id,
        identity.user_id,
        identity.executable,
        identity.start_seconds,
        (identity.start_microseconds if start_microseconds is None else start_microseconds),
        str(Path(sys.executable).resolve()),
    )


def _cleanup_exact_test_process(
    runtime: RecordingDarwinRuntime,
    reaper: subprocess.Popen,
    identity: ProcessIdentity,
) -> None:
    observed = runtime.inspect(identity.process_id)
    if observed == identity:
        members = runtime.list_group(identity.process_group_id)
        member_by_pid = {member.process_id: member for member in members}
        if member_by_pid.get(identity.process_id) == identity:
            os.killpg(identity.process_group_id, signal.SIGKILL)
    assert reaper.wait(timeout=3.0) == 0


def test_restart_reconciliation_terminates_exact_process_and_recovers_job() -> None:
    clock = ManualClock()
    runtime = RecordingDarwinRuntime()
    reaper: Optional[subprocess.Popen] = None
    identity: Optional[ProcessIdentity] = None

    try:
        with _temporary_database(clock) as (database, first_store):
            campaign, item, job, claim = _create_claimed_job(first_store)
            reaper, identity = _spawn_disposable_process(runtime)
            _record_process(first_store, job, claim, identity)
            clock.advance(6)
            first_store.close()

            restarted_store = SQLiteStore(database, clock=clock)
            try:
                scheduler_storage = SQLiteSchedulerStorage(
                    restarted_store,
                    process_reconciler=ExternalProcessReconciler(
                        runtime,
                        terminate_grace_seconds=0.5,
                        poll_interval_seconds=0.01,
                    ),
                    reconciliation_owner="restart-integration-test",
                    reconciliation_lease_seconds=5,
                )

                recovered_job_ids = tuple(scheduler_storage.reconcile_expired_processes())
                assert recovered_job_ids == (job["id"],), [
                    (result.status.value, result.reason, dict(result.observed))
                    for result in scheduler_storage.last_reconciliation_results
                ]
                assert reaper.wait(timeout=3.0) == 0

                assert runtime.inspect(identity.process_id) is None
                assert runtime.list_group(identity.process_group_id) == ()
                assert runtime.signals == [(identity.process_group_id, signal.SIGTERM)]
                assert len(scheduler_storage.last_reconciliation_results) == 1
                assert (
                    scheduler_storage.last_reconciliation_results[0].status
                    is ReconciliationStatus.TERMINATED
                )

                recovered_job = restarted_store.get_job(job["id"])
                assert recovered_job["status"] == "pending"
                assert recovered_job["current_attempt_id"] is None
                assert recovered_job["lease_owner"] is None
                assert recovered_job["lease_token"] is None
                assert restarted_store.get_work_item(item["id"])["state"] == "backlog"
                attempts = restarted_store.list_attempts(job["id"])
                assert len(attempts) == 1
                assert attempts[0]["status"] == "expired"
                assert restarted_store.list_resource_leases() == []
                external = restarted_store.list_external_processes()
                assert len(external) == 1
                assert external[0]["state"] == "stopped"
                assert external[0]["outcome"] == "terminated"
                event_kinds = [
                    event["event_kind"] for event in restarted_store.list_events(job_id=job["id"])
                ]
                assert event_kinds[-3:] == [
                    "worker.external_process_reconciliation_claimed",
                    "worker.external_process_reconciled",
                    "job.lease_expired",
                ]
                assert restarted_store.foreign_key_violations() == []
                assert restarted_store.get_campaign(campaign["id"])["status"] == "active"
            finally:
                restarted_store.close()
    finally:
        if reaper is not None and identity is not None:
            _cleanup_exact_test_process(runtime, reaper, identity)


def test_restart_reconciliation_quarantines_wrong_birth_without_signal() -> None:
    clock = ManualClock()
    runtime = RecordingDarwinRuntime()
    reaper: Optional[subprocess.Popen] = None
    identity: Optional[ProcessIdentity] = None

    try:
        with _temporary_database(clock) as (database, first_store):
            _campaign, item, job, claim = _create_claimed_job(first_store)
            reaper, identity = _spawn_disposable_process(runtime)
            wrong_microseconds = (identity.start_microseconds + 1) % 1_000_000
            _record_process(
                first_store,
                job,
                claim,
                identity,
                start_microseconds=wrong_microseconds,
            )
            clock.advance(6)
            first_store.close()

            restarted_store = SQLiteStore(database, clock=clock)
            try:
                scheduler_storage = SQLiteSchedulerStorage(
                    restarted_store,
                    process_reconciler=ExternalProcessReconciler(
                        runtime,
                        terminate_grace_seconds=0.2,
                        poll_interval_seconds=0.01,
                    ),
                    reconciliation_owner="wrong-birth-integration-test",
                    reconciliation_lease_seconds=5,
                )

                assert tuple(scheduler_storage.reconcile_expired_processes()) == ()

                assert runtime.signals == []
                assert reaper.poll() is None
                assert runtime.inspect(identity.process_id) == identity
                assert len(scheduler_storage.last_reconciliation_results) == 1
                result = scheduler_storage.last_reconciliation_results[0]
                assert result.status is ReconciliationStatus.QUARANTINED
                assert "identity no longer matches" in result.reason

                quarantined_job = restarted_store.get_job(job["id"])
                assert quarantined_job["status"] == "running"
                assert quarantined_job["current_attempt_id"] == claim["attempt_id"]
                assert restarted_store.get_work_item(item["id"])["state"] == "investigating"
                assert restarted_store.list_attempts(job["id"])[0]["status"] == "running"
                assert len(restarted_store.list_resource_leases()) == 1
                external = restarted_store.list_external_processes()
                assert len(external) == 1
                assert external[0]["state"] == "quarantined"
                assert external[0]["outcome"] == "quarantined"
                event_kinds = [
                    event["event_kind"] for event in restarted_store.list_events(job_id=job["id"])
                ]
                assert event_kinds[-2:] == [
                    "worker.external_process_reconciliation_claimed",
                    "worker.external_process_reconciliation_blocked",
                ]
                assert restarted_store.foreign_key_violations() == []
            finally:
                restarted_store.close()
    finally:
        if reaper is not None and identity is not None:
            _cleanup_exact_test_process(runtime, reaper, identity)
