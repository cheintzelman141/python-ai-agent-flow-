from __future__ import annotations

import asyncio
from contextlib import nullcontext
from dataclasses import replace
import hashlib
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

import pytest

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
from agent_flow.focused_tests import FocusedTestWorker
from agent_flow.models import (
    TestHandoff as DomainTestHandoff,
    TestOutcome as DomainTestOutcome,
    WorkerRole,
)
from agent_flow.process_reconciler import DarwinProcessRuntime, ProcessIdentity
from agent_flow.workers import WorkerContext, WorkerExecutionError
from agent_flow.worktrees import (
    GuardedCommandResult,
    GuardedGitCommandRunner,
    GitCommandError,
)


class FakeGuardedRunner:
    def __init__(
        self,
        *,
        return_code: int = 0,
        timeout_seconds: float = 5.0,
        max_output_bytes: int = 1024,
    ) -> None:
        self.return_code = return_code
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.calls: List[Dict[str, Any]] = []

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        artifact_directory: Path,
        record_process: Any,
        clear_process: Any,
        release_fence: Any,
        cancellation_event: threading.Event,
    ) -> GuardedCommandResult:
        self.calls.append(
            {
                "command": tuple(command),
                "cwd": cwd,
                "environment": dict(environment),
                "artifact_directory": artifact_directory,
                "cancellation_event": cancellation_event,
            }
        )
        identity = ProcessIdentity(
            process_id=3141,
            process_group_id=3141,
            user_id=os.getuid(),
            executable="/usr/bin/python3",
            start_seconds=10,
            start_microseconds=20,
        )
        target = str(Path(command[0]).resolve())
        record_process(identity, target)
        with release_fence(identity, target):
            pass
        artifact_directory.mkdir(mode=0o700)
        stdout_path = artifact_directory / "stdout.log"
        stderr_path = artifact_directory / "stderr.log"
        stdout_path.write_bytes(b"focused proof\n")
        stderr_path.write_bytes(b"Ran 1 test\nOK\n")
        os.chmod(stdout_path, 0o600)
        os.chmod(stderr_path, 0o600)
        clear_process(identity.process_id, identity.process_group_id)
        return GuardedCommandResult(
            command=tuple(command),
            return_code=self.return_code,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            stdout_sha256=_sha256(stdout_path),
            stderr_sha256=_sha256(stderr_path),
            stdout_truncated=False,
            stderr_truncated=False,
        )


class FailingRunner:
    timeout_seconds = 5.0
    max_output_bytes = 1024

    def run(self, *_args: Any, **_kwargs: Any) -> GuardedCommandResult:
        raise GitCommandError("simulated guarded test failure")


class CancellationRunner:
    def __init__(self) -> None:
        self.timeout_seconds = 5.0
        self.max_output_bytes = 1024
        self.started = threading.Event()
        self.stopped = threading.Event()

    def run(
        self, *_args: Any, cancellation_event: threading.Event, **_kwargs: Any
    ) -> GuardedCommandResult:
        self.started.set()
        while not cancellation_event.is_set():
            time.sleep(0.01)
        self.stopped.set()
        raise GitCommandError("cancelled guarded test")


def _context(
    tmp_path: Path,
    *,
    outcome: str = "pass",
    test_source: Optional[str] = None,
) -> tuple[WorkerContext, Dict[str, List[Any]], Dict[str, Any]]:
    workspace = tmp_path / "managed-worktree"
    workspace.mkdir(mode=0o700)
    test_file = workspace / "test_fixture.py"
    test_file.write_text(
        test_source
        or """import unittest

class FixtureTests(unittest.TestCase):
    def test_exact(self):
        self.assertEqual(2 + 3, 5)

if __name__ == "__main__":
    unittest.main()
""",
        encoding="utf-8",
    )
    run_parent = tmp_path / "runtime" / "execution-1"
    run_parent.mkdir(parents=True, mode=0o700)
    os.chmod(run_parent, 0o700)
    executable = direct_python_executable(Path(os.sys.executable))
    runtime_root = python_runtime_root(executable)
    sandbox = sandbox_executable()
    runner_command = (
        str(executable),
        "-I",
        "-B",
        str(test_file.resolve()),
        "FixtureTests.test_exact",
        "-v",
    )
    sandbox_profile = build_focused_sandbox_profile(
        test_executable=executable,
        runtime_read_root=runtime_root,
        workspace=workspace,
        run_parent=run_parent,
    )
    sandbox_command = build_focused_sandbox_command(
        sandbox,
        sandbox_profile,
        runner_command,
    )
    prepared = {
        "id": "focused-execution-1",
        "command": list(sandbox_command),
        "test_command_argv": list(runner_command),
        "executable_path": str(executable),
        "sandbox_policy_version": DARWIN_SANDBOX_POLICY_VERSION,
        "sandbox_executable_path": str(sandbox),
        "python_runtime_root": str(runtime_root),
        "python_runtime_sha256": python_runtime_sha256(runtime_root),
        "sandbox_profile": sandbox_profile,
        "sandbox_profile_sha256": focused_sandbox_profile_sha256(sandbox_profile),
        "test_file": "test_fixture.py",
        "selector": "FixtureTests.test_exact",
        "cwd": str(workspace.resolve()),
        "environment": {
            "HOME": str((run_parent / "environment" / "home").resolve()),
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONHASHSEED": "0",
            "TMPDIR": str((run_parent / "environment" / "tmp").resolve()),
        },
        "artifact_directory": str((run_parent / "artifacts").resolve()),
        "workspace_manifest": {
            "managed_worktree_id": "worktree-1",
            "generation": 2,
            "digest": "abc123",
        },
        "timeout_seconds": 5.0,
        "output_limit_bytes": 1024,
    }
    observed: Dict[str, List[Any]] = {
        "prepared": [],
        "completed": [],
        "processes": [],
        "cleared": [],
    }

    def prepare() -> Mapping[str, Any]:
        observed["prepared"].append(True)
        return prepared

    def complete(result: Mapping[str, Any]) -> Mapping[str, Any]:
        packet = dict(result)
        observed["completed"].append(packet)
        evidence = {
            "kind": "test",
            "location": packet["stderr_path"],
            "description": "Supervisor-captured focused test output.",
            "metadata": {"execution_id": packet["execution_id"]},
        }
        gate_result = "pass" if outcome == "pass" else "fail"
        handoff: Dict[str, Any] = {
            "schema_version": 1,
            "item_id": "item-focused",
            "outcome": outcome,
            "summary": "The supervisor evaluated the exact focused test.",
            "gate_proofs": [
                {
                    "gate": "focused_tests",
                    "result": gate_result,
                    "summary": "The exact focused test completed.",
                    "evidence": [evidence],
                }
            ],
        }
        if outcome == "red":
            handoff["failure_summary"] = "The exact focused test failed."
        return {"canonical_handoff": handoff}

    context = WorkerContext(
        campaign={"id": "campaign-focused"},
        item={
            "id": "item-focused",
            "title": "Focused item",
            "description": "Run the supervisor-owned focused test.",
            "required_gates": ["focused_tests"],
        },
        job={
            "id": "job-focused",
            "role": "tester",
            "payload": {
                "command": ["/usr/bin/touch", str(tmp_path / "payload-ran")],
                "cwd": "/",
            },
        },
        _external_process_recorder=lambda provider, identity, target: observed[
            "processes"
        ].append((provider, identity, target)),
        _external_process_clearer=lambda pid, pgid: observed["cleared"].append(
            (pid, pgid)
        ),
        _focused_test_guardian_release_fencer=(
            lambda _identity, _target: nullcontext()
        ),
        _focused_test_execution_preparer=prepare,
        _focused_test_execution_completer=complete,
    )
    return context, observed, prepared


@pytest.mark.parametrize(
    ("return_code", "outcome"),
    ((0, DomainTestOutcome.PASS), (1, DomainTestOutcome.RED)),
)
def test_worker_executes_only_prepared_command_and_returns_canonical_handoff(
    tmp_path: Path, return_code: int, outcome: DomainTestOutcome
) -> None:
    runner = FakeGuardedRunner(return_code=return_code)
    context, observed, prepared = _context(tmp_path, outcome=outcome.value)

    handoff = asyncio.run(FocusedTestWorker(runner).run(context))  # type: ignore[arg-type]

    assert isinstance(handoff, DomainTestHandoff)
    assert handoff.outcome == outcome
    assert FocusedTestWorker.role == WorkerRole.TESTER
    assert observed["prepared"] == [True]
    assert runner.calls[0]["command"] == tuple(prepared["command"])
    assert runner.calls[0]["cwd"] == Path(prepared["cwd"])
    assert not (tmp_path / "payload-ran").exists()
    assert set(runner.calls[0]["environment"]) == {
        "HOME",
        "LANG",
        "LC_ALL",
        "PYTHONHASHSEED",
        "TMPDIR",
    }
    assert Path(runner.calls[0]["environment"]["HOME"]).is_dir()
    assert Path(runner.calls[0]["environment"]["TMPDIR"]).is_dir()
    assert observed["processes"][0][0] == "focused_test"
    identity = observed["processes"][0][1]
    assert observed["cleared"] == [
        (identity.process_id, identity.process_group_id)
    ]
    packet = observed["completed"][0]
    assert packet["execution_id"] == prepared["id"]
    assert packet["command"] == prepared["command"]
    assert packet["cwd"] == prepared["cwd"]
    assert packet["workspace_manifest"] == prepared["workspace_manifest"]
    assert packet["exit_code"] == return_code
    assert packet["stdout_bytes"] == len(b"focused proof\n")
    assert packet["stderr_bytes"] == len(b"Ran 1 test\nOK\n")
    assert packet["stdout_truncated"] is False
    assert packet["stderr_truncated"] is False


def test_runner_error_propagates_without_fabricating_completion(
    tmp_path: Path,
) -> None:
    context, observed, _prepared = _context(tmp_path)

    with pytest.raises(GitCommandError, match="simulated guarded test failure"):
        asyncio.run(FocusedTestWorker(FailingRunner()).run(context))  # type: ignore[arg-type]

    assert observed["completed"] == []


def test_real_guardian_is_registered_and_cleared_as_focused_test(
    tmp_path: Path,
) -> None:
    context, observed, prepared = _context(tmp_path)
    prepared["timeout_seconds"] = 2.0
    runner = GuardedGitCommandRunner(
        runtime=DarwinProcessRuntime(),
        timeout_seconds=2,
        terminate_grace_seconds=1,
        max_output_bytes=1024,
    )

    handoff = asyncio.run(FocusedTestWorker(runner).run(context))

    assert isinstance(handoff, DomainTestHandoff)
    assert observed["processes"][0][0] == "focused_test"
    identity = observed["processes"][0][1]
    assert observed["cleared"] == [
        (identity.process_id, identity.process_group_id)
    ]


def test_worker_rejects_runner_command_substitution(tmp_path: Path) -> None:
    class SubstitutingRunner(FakeGuardedRunner):
        def run(self, *args: Any, **kwargs: Any) -> GuardedCommandResult:
            result = super().run(*args, **kwargs)
            return GuardedCommandResult(
                command=("/usr/bin/false",),
                return_code=result.return_code,
                stdout_path=result.stdout_path,
                stderr_path=result.stderr_path,
                stdout_sha256=result.stdout_sha256,
                stderr_sha256=result.stderr_sha256,
                stdout_truncated=False,
                stderr_truncated=False,
            )

    context, observed, _prepared = _context(tmp_path)

    with pytest.raises(WorkerExecutionError, match="different command"):
        asyncio.run(FocusedTestWorker(SubstitutingRunner()).run(context))  # type: ignore[arg-type]

    assert observed["completed"] == []


def test_worker_reconstructs_and_rejects_a_broadened_sandbox_profile(
    tmp_path: Path,
) -> None:
    context, observed, prepared = _context(tmp_path)
    broadened = prepared["sandbox_profile"] + "(allow network*)\n"
    prepared["sandbox_profile"] = broadened
    prepared["sandbox_profile_sha256"] = focused_sandbox_profile_sha256(broadened)
    prepared["command"][2] = broadened

    with pytest.raises(WorkerExecutionError, match="trusted sandbox contract"):
        asyncio.run(FocusedTestWorker(FakeGuardedRunner()).run(context))  # type: ignore[arg-type]

    assert observed["processes"] == []
    assert observed["completed"] == []


def test_worker_rejects_runner_limits_that_differ_from_durable_plan(
    tmp_path: Path,
) -> None:
    context, observed, _prepared = _context(tmp_path)
    runner = FakeGuardedRunner(timeout_seconds=30.0, max_output_bytes=4096)

    with pytest.raises(WorkerExecutionError, match="durable execution plan"):
        asyncio.run(FocusedTestWorker(runner).run(context))  # type: ignore[arg-type]

    assert runner.calls == []
    assert observed["processes"] == []
    assert observed["completed"] == []


def test_worker_requires_exact_persisted_private_environment(tmp_path: Path) -> None:
    context, observed, prepared = _context(tmp_path)
    prepared["environment"]["HOME"] = "/private/tmp/not-the-persisted-home"
    runner = FakeGuardedRunner()

    with pytest.raises(WorkerExecutionError, match="exact safe contract"):
        asyncio.run(FocusedTestWorker(runner).run(context))  # type: ignore[arg-type]

    assert runner.calls == []
    assert observed["completed"] == []


def test_worker_rejects_environment_injection_before_launch(tmp_path: Path) -> None:
    context, observed, prepared = _context(tmp_path)
    prepared["environment"]["DYLD_INSERT_LIBRARIES"] = str(
        tmp_path / "untrusted.dylib"
    )

    with pytest.raises(WorkerExecutionError, match="exact safe contract"):
        asyncio.run(FocusedTestWorker(FakeGuardedRunner()).run(context))  # type: ignore[arg-type]

    assert observed["processes"] == []
    assert observed["completed"] == []


def test_worker_accepts_only_storage_authoritative_canonical_handoff(
    tmp_path: Path,
) -> None:
    context, _observed, _prepared = _context(tmp_path)
    context = replace(
        context,
        _focused_test_execution_completer=lambda _result: {
            "handoff": {
                "schema_version": 1,
                "item_id": "item-focused",
                "outcome": "pass",
                "summary": "This noncanonical response must not be trusted.",
                "gate_proofs": [],
            }
        },
    )

    with pytest.raises(WorkerExecutionError, match="storage-authoritative"):
        asyncio.run(FocusedTestWorker(FakeGuardedRunner()).run(context))  # type: ignore[arg-type]


def test_cancellation_waits_for_guarded_runner_cleanup(tmp_path: Path) -> None:
    runner = CancellationRunner()
    context, observed, _prepared = _context(tmp_path)

    async def cancel_worker() -> None:
        task = asyncio.create_task(
            FocusedTestWorker(runner).run(context)  # type: ignore[arg-type]
        )
        started = await asyncio.to_thread(runner.started.wait, 2)
        assert started
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_worker())

    assert runner.stopped.is_set()
    assert observed["completed"] == []


def test_cancellation_before_guardian_release_never_starts_target(
    tmp_path: Path,
) -> None:
    context, observed, prepared = _context(
        tmp_path,
        test_source="""import os
from pathlib import Path
import unittest

class FixtureTests(unittest.TestCase):
    def test_exact(self):
        Path(os.environ["HOME"], "target-started").write_text("started")

if __name__ == "__main__":
    unittest.main()
""",
    )
    marker = Path(prepared["environment"]["HOME"]) / "target-started"
    process_registered = threading.Event()
    release_registration = threading.Event()

    def block_after_registration(provider: str, identity: Any, target: str) -> None:
        observed["processes"].append((provider, identity, target))
        process_registered.set()
        assert release_registration.wait(timeout=2)

    context = replace(
        context,
        _external_process_recorder=block_after_registration,
    )
    runner = GuardedGitCommandRunner(
        runtime=DarwinProcessRuntime(),
        timeout_seconds=5,
        terminate_grace_seconds=1,
        max_output_bytes=1024,
    )

    async def cancel_before_release() -> None:
        task = asyncio.create_task(FocusedTestWorker(runner).run(context))
        registered = await asyncio.to_thread(process_registered.wait, 2)
        assert registered
        task.cancel()
        await asyncio.sleep(0)
        release_registration.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_before_release())

    assert not marker.exists()
    assert len(observed["processes"]) == 1
    identity = observed["processes"][0][1]
    assert observed["cleared"] == [
        (identity.process_id, identity.process_group_id)
    ]
    assert observed["completed"] == []


def test_context_requires_both_focused_test_fences() -> None:
    context = WorkerContext(campaign={}, item={"id": "item"}, job={})

    with pytest.raises(WorkerExecutionError, match="execution authority"):
        context.prepare_focused_test_execution()
    with pytest.raises(WorkerExecutionError, match="completion authority"):
        context.complete_focused_test_execution({})


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
