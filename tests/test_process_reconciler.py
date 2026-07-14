from __future__ import annotations

import os
import signal
import sys
from dataclasses import replace
from pathlib import Path
from typing import List, Optional, Tuple

import pytest

from agent_flow.process_reconciler import (
    DarwinProcessRuntime,
    ExternalProcessBinding,
    ExternalProcessReconciler,
    ProcessIdentity,
    ProcessInspectionError,
    ReconciliationStatus,
)


_PROCESS_ID = max(os.getpid(), os.getpgrp(), 1) + 10_000
_PROCESS_GROUP_ID = _PROCESS_ID


class FakeClock:
    def __init__(self) -> None:
        self.current = 0.0

    def monotonic(self) -> float:
        return self.current

    def sleep(self, seconds: float) -> None:
        self.current += seconds


class FakeProcessRuntime:
    def __init__(
        self,
        *,
        group_members: Tuple[ProcessIdentity, ...],
        inspections: Optional[List[Optional[ProcessIdentity]]] = None,
        terminate_on_term: bool = True,
        terminate_on_kill: bool = True,
        group_failure_calls: Tuple[int, ...] = (),
    ) -> None:
        self.group_members = group_members
        self.inspections = list(inspections or [])
        self.terminate_on_term = terminate_on_term
        self.terminate_on_kill = terminate_on_kill
        self.group_failure_calls = group_failure_calls
        self.inspect_calls: List[int] = []
        self.group_calls: List[int] = []
        self.signals: List[Tuple[int, int]] = []

    def inspect(self, process_id: int) -> Optional[ProcessIdentity]:
        self.inspect_calls.append(process_id)
        if self.inspections:
            return self.inspections.pop(0)
        return next(
            (member for member in self.group_members if member.process_id == process_id),
            None,
        )

    def list_group(self, process_group_id: int) -> Tuple[ProcessIdentity, ...]:
        self.group_calls.append(process_group_id)
        if len(self.group_calls) in self.group_failure_calls:
            raise ProcessInspectionError("transient process-exit race")
        return tuple(
            member for member in self.group_members if member.process_group_id == process_group_id
        )

    def signal_group(self, process_group_id: int, signal_number: int) -> None:
        self.signals.append((process_group_id, signal_number))
        if (
            signal_number == signal.SIGTERM
            and self.terminate_on_term
            or signal_number == signal.SIGKILL
            and self.terminate_on_kill
        ):
            self.group_members = ()


@pytest.fixture
def identity() -> ProcessIdentity:
    return ProcessIdentity(
        process_id=_PROCESS_ID,
        process_group_id=_PROCESS_GROUP_ID,
        user_id=os.getuid(),
        executable="/usr/bin/python3",
        start_seconds=1_720_000_000,
        start_microseconds=123_456,
    )


@pytest.fixture
def binding(identity: ProcessIdentity) -> ExternalProcessBinding:
    return ExternalProcessBinding(
        job_id="job-1",
        attempt_id="attempt-1",
        process_id=identity.process_id,
        process_group_id=identity.process_group_id,
        user_id=identity.user_id,
        executable=identity.executable,
        start_seconds=identity.start_seconds,
        start_microseconds=identity.start_microseconds,
        target_executable="/opt/codex/bin/codex",
        identity_version="darwin_libproc_v1",
    )


def reconciler(
    runtime: FakeProcessRuntime, clock: Optional[FakeClock] = None
) -> ExternalProcessReconciler:
    deterministic_clock = clock or FakeClock()
    return ExternalProcessReconciler(
        runtime,
        terminate_grace_seconds=0.1,
        poll_interval_seconds=0.01,
        sleeper=deterministic_clock.sleep,
        monotonic=deterministic_clock.monotonic,
    )


def test_exact_identity_exits_after_sigterm(
    identity: ProcessIdentity, binding: ExternalProcessBinding
) -> None:
    runtime = FakeProcessRuntime(group_members=(identity,), inspections=[identity, identity])

    result = reconciler(runtime).reconcile(binding)

    assert result.status is ReconciliationStatus.TERMINATED
    assert result.can_release is True
    assert runtime.signals == [(_PROCESS_GROUP_ID, signal.SIGTERM)]
    assert runtime.group_members == ()


def test_transient_exit_inspection_race_is_retried_after_sigterm(
    identity: ProcessIdentity, binding: ExternalProcessBinding
) -> None:
    runtime = FakeProcessRuntime(
        group_members=(identity,),
        inspections=[identity, identity],
        group_failure_calls=(2,),
    )

    result = reconciler(runtime).reconcile(binding)

    assert result.status is ReconciliationStatus.TERMINATED
    assert runtime.signals == [(_PROCESS_GROUP_ID, signal.SIGTERM)]


def test_stubborn_verified_group_escalates_to_sigkill(
    identity: ProcessIdentity, binding: ExternalProcessBinding
) -> None:
    runtime = FakeProcessRuntime(
        group_members=(identity,),
        inspections=[identity, identity, identity],
        terminate_on_term=False,
    )

    result = reconciler(runtime).reconcile(binding)

    assert result.status is ReconciliationStatus.TERMINATED
    assert result.can_release is True
    assert runtime.signals == [
        (_PROCESS_GROUP_ID, signal.SIGTERM),
        (_PROCESS_GROUP_ID, signal.SIGKILL),
    ]
    assert runtime.group_members == ()


@pytest.mark.parametrize(
    ("field", "different_value"),
    [
        ("process_id", _PROCESS_ID + 1),
        ("process_group_id", _PROCESS_GROUP_ID + 1),
        ("user_id", os.getuid() + 1),
        ("executable", "/different/python"),
        ("start_seconds", 1_720_000_001),
        ("start_microseconds", 123_457),
    ],
)
def test_observed_identity_mismatch_never_signals(
    identity: ProcessIdentity,
    binding: ExternalProcessBinding,
    field: str,
    different_value: object,
) -> None:
    observed = replace(identity, **{field: different_value})
    runtime = FakeProcessRuntime(group_members=(identity,), inspections=[observed])

    result = reconciler(runtime).reconcile(binding)

    assert result.status is ReconciliationStatus.QUARANTINED
    assert result.can_release is False
    assert runtime.signals == []


def test_missing_launcher_with_populated_group_is_quarantined(
    identity: ProcessIdentity, binding: ExternalProcessBinding
) -> None:
    child = replace(identity, process_id=identity.process_id + 1)
    runtime = FakeProcessRuntime(group_members=(child,), inspections=[None])

    result = reconciler(runtime).reconcile(binding)

    assert result.status is ReconciliationStatus.QUARANTINED
    assert result.can_release is False
    assert runtime.signals == []
    assert result.observed["members"][0]["process_id"] == child.process_id


def test_incomplete_legacy_identity_is_quarantined_without_os_access(
    binding: ExternalProcessBinding,
) -> None:
    legacy_binding = replace(
        binding,
        user_id=None,
        executable=None,
        start_seconds=None,
        start_microseconds=None,
    )
    runtime = FakeProcessRuntime(group_members=())

    result = reconciler(runtime).reconcile(legacy_binding)

    assert result.status is ReconciliationStatus.QUARANTINED
    assert result.can_release is False
    assert runtime.inspect_calls == []
    assert runtime.group_calls == []
    assert runtime.signals == []


@pytest.mark.parametrize(
    ("process_id", "process_group_id"),
    [
        (1, _PROCESS_GROUP_ID),
        (_PROCESS_ID, 1),
        (os.getpid(), _PROCESS_GROUP_ID),
        (_PROCESS_ID, os.getpgrp()),
    ],
)
def test_protected_process_or_group_is_never_inspected_or_signaled(
    binding: ExternalProcessBinding,
    process_id: int,
    process_group_id: int,
) -> None:
    runtime = FakeProcessRuntime(group_members=())

    result = reconciler(runtime).reconcile(
        replace(
            binding,
            process_id=process_id,
            process_group_id=process_group_id,
        )
    )

    assert result.status is ReconciliationStatus.QUARANTINED
    assert runtime.inspect_calls == []
    assert runtime.signals == []


def test_persisted_owner_mismatch_is_never_inspected_or_signaled(
    binding: ExternalProcessBinding,
) -> None:
    runtime = FakeProcessRuntime(group_members=())

    result = reconciler(runtime).reconcile(
        replace(binding, user_id=os.getuid() + 1)
    )

    assert result.status is ReconciliationStatus.QUARANTINED
    assert runtime.inspect_calls == []
    assert runtime.signals == []


def test_identity_change_immediately_before_sigterm_prevents_signal(
    identity: ProcessIdentity, binding: ExternalProcessBinding
) -> None:
    replacement = replace(identity, start_microseconds=identity.start_microseconds + 1)
    runtime = FakeProcessRuntime(group_members=(identity,), inspections=[identity, replacement])

    result = reconciler(runtime).reconcile(binding)

    assert result.status is ReconciliationStatus.QUARANTINED
    assert result.can_release is False
    assert runtime.signals == []


def test_identity_change_immediately_before_sigkill_prevents_escalation(
    identity: ProcessIdentity, binding: ExternalProcessBinding
) -> None:
    replacement = replace(identity, start_microseconds=identity.start_microseconds + 1)
    runtime = FakeProcessRuntime(
        group_members=(identity,),
        inspections=[identity, identity, replacement],
        terminate_on_term=False,
    )

    result = reconciler(runtime).reconcile(binding)

    assert result.status is ReconciliationStatus.QUARANTINED
    assert result.can_release is False
    assert runtime.signals == [(_PROCESS_GROUP_ID, signal.SIGTERM)]


@pytest.mark.skipif(sys.platform != "darwin", reason="requires macOS libproc")
def test_darwin_runtime_reads_current_process_identity_without_signaling() -> None:
    runtime = DarwinProcessRuntime()

    identity = runtime.inspect(os.getpid())

    assert identity is not None
    assert identity.process_id == os.getpid()
    assert identity.process_group_id == os.getpgrp()
    assert identity.user_id == os.getuid()
    executable = Path(identity.executable)
    assert executable.is_absolute()
    assert executable.is_file()
    assert identity.start_seconds > 0
    assert 0 <= identity.start_microseconds < 1_000_000
    assert identity in runtime.list_group(os.getpgrp())
