"""Deterministic focused-test worker for supervisor-owned command plans.

The worker never derives a command, workspace, or environment from a job
payload.  SQLite prepares the exact execution contract and later decides what
the captured result means.  This adapter only executes that contract through
the same blocked-guardian boundary used by managed Git operations.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import stat
import threading
from pathlib import Path
from typing import Any, Dict, Mapping

from agent_flow.focused_sandbox import (
    DARWIN_SANDBOX_POLICY_VERSION,
    FocusedSandboxError,
    build_command as build_focused_sandbox_command,
    build_profile as build_focused_sandbox_profile,
    profile_sha256 as focused_sandbox_profile_sha256,
    python_runtime_root,
    python_runtime_sha256,
    sandbox_executable,
)
from agent_flow.models import TestHandoff, WorkerRole
from agent_flow.workers import WorkerContext, WorkerExecutionError, WorkerOutput
from agent_flow.worktrees import GuardedCommandResult, GuardedGitCommandRunner


class FocusedTestWorker:
    """Execute one storage-authorized focused test and return its canonical handoff."""

    role = WorkerRole.TESTER

    def __init__(self, command_runner: GuardedGitCommandRunner) -> None:
        self.command_runner = command_runner

    async def run(self, context: WorkerContext) -> WorkerOutput:
        prepared = context.prepare_focused_test_execution()
        contract = _validate_prepared_contract(prepared)
        _validate_runner_limits(contract, self.command_runner)
        environment = _private_environment(
            contract["environment"], contract["artifact_directory"]
        )
        cancellation_event = threading.Event()

        async def execute() -> GuardedCommandResult:
            return await asyncio.to_thread(
                self.command_runner.run,
                contract["command"],
                cwd=contract["cwd"],
                environment=environment,
                artifact_directory=contract["artifact_directory"],
                record_process=lambda identity, target: context.record_external_process(
                    "focused_test", identity, target
                ),
                clear_process=context.clear_external_process,
                release_fence=context.focused_test_guardian_release_fence,
                cancellation_event=cancellation_event,
            )

        runner_task = asyncio.create_task(execute())
        try:
            result = await asyncio.shield(runner_task)
        except asyncio.CancelledError:
            cancellation_event.set()
            try:
                await asyncio.shield(runner_task)
            except Exception:
                # The supervisor cancellation remains the authoritative error;
                # the guarded runner still owns bounded termination and reap.
                pass
            raise

        completion = _completion_packet(contract, result)
        canonical = context.complete_focused_test_execution(completion)
        return _canonical_handoff(canonical, context.item_id)


def _validate_prepared_contract(value: Mapping[str, Any]) -> Dict[str, Any]:
    execution_id = value.get("id")
    if not isinstance(execution_id, str) or not execution_id.strip():
        raise WorkerExecutionError(
            "focused-test preparation omitted its durable execution id"
        )

    command_value = value.get("command")
    if (
        not isinstance(command_value, (list, tuple))
        or not command_value
        or any(not isinstance(argument, str) or not argument for argument in command_value)
    ):
        raise WorkerExecutionError(
            "focused-test preparation returned an invalid direct command"
        )
    command = tuple(command_value)
    if "\x00" in "".join(command) or not Path(command[0]).is_absolute():
        raise WorkerExecutionError(
            "focused-test command requires an absolute executable and valid arguments"
        )
    cwd = _canonical_path(value.get("cwd"), "focused-test cwd")
    _require_private_directory(cwd, private=False)
    artifact_directory = _canonical_path(
        value.get("artifact_directory"), "focused-test artifact directory"
    )
    if artifact_directory.exists() or artifact_directory.is_symlink():
        raise WorkerExecutionError(
            "focused-test artifact directory must be an unallocated path"
        )
    if _is_within(artifact_directory, cwd):
        raise WorkerExecutionError(
            "focused-test runtime artifacts must remain outside the tested workspace"
        )
    _require_private_directory(artifact_directory.parent, private=True)

    sandbox_profile = value.get("sandbox_profile")
    test_command_value = value.get("test_command_argv")
    test_file = value.get("test_file")
    selector = value.get("selector")
    if (
        value.get("sandbox_policy_version") != DARWIN_SANDBOX_POLICY_VERSION
        or not isinstance(sandbox_profile, str)
        or not sandbox_profile
        or value.get("sandbox_profile_sha256")
        != focused_sandbox_profile_sha256(sandbox_profile)
        or not isinstance(test_command_value, (list, tuple))
        or not test_command_value
        or any(
            not isinstance(argument, str) or not argument
            for argument in test_command_value
        )
        or not isinstance(test_file, str)
        or not test_file
        or not isinstance(selector, str)
        or not selector
    ):
        raise WorkerExecutionError(
            "focused-test preparation omitted its trusted sandbox contract"
        )
    test_path = cwd / test_file
    try:
        resolved_test_path = test_path.resolve(strict=True)
        expected_sandbox = sandbox_executable()
        executable = Path(str(value.get("executable_path"))).resolve(strict=True)
        runtime_root = python_runtime_root(executable)
        runtime_hash = python_runtime_sha256(runtime_root)
        expected_profile = build_focused_sandbox_profile(
            test_executable=executable,
            runtime_read_root=runtime_root,
            workspace=cwd,
            run_parent=artifact_directory.parent,
        )
    except (FocusedSandboxError, OSError, RuntimeError) as error:
        raise WorkerExecutionError(
            "focused-test sandbox contract could not be reconstructed"
        ) from error
    if (
        resolved_test_path != test_path
        or not resolved_test_path.is_file()
        or not _is_within(resolved_test_path, cwd)
        or value.get("python_runtime_root") != str(runtime_root)
        or value.get("python_runtime_sha256") != runtime_hash
    ):
        raise WorkerExecutionError(
            "focused-test authority does not identify its exact trusted test"
        )
    expected_test_command = (
        str(executable),
        "-I",
        "-B",
        str(resolved_test_path),
        selector,
        "-v",
    )
    expected_command = build_focused_sandbox_command(
        expected_sandbox, expected_profile, expected_test_command
    )
    test_command = tuple(test_command_value)
    if (
        test_command != expected_test_command
        or command != expected_command
        or sandbox_profile != expected_profile
        or value.get("sandbox_executable_path") != str(expected_sandbox)
    ):
        raise WorkerExecutionError(
            "focused-test command does not match its trusted sandbox contract"
        )

    environment_value = value.get("environment")
    if not isinstance(environment_value, Mapping):
        raise WorkerExecutionError(
            "focused-test preparation returned an invalid environment"
        )
    environment: Dict[str, str] = {}
    for key, raw_value in environment_value.items():
        if (
            not isinstance(key, str)
            or not key
            or "=" in key
            or "\x00" in key
            or not isinstance(raw_value, str)
            or "\x00" in raw_value
        ):
            raise WorkerExecutionError(
                "focused-test environment keys and values must be valid strings"
            )
        environment[key] = raw_value

    workspace_manifest = value.get("workspace_manifest")
    if not isinstance(workspace_manifest, Mapping):
        raise WorkerExecutionError(
            "focused-test preparation omitted its immutable workspace manifest"
        )
    try:
        manifest = json.loads(
            json.dumps(
                dict(workspace_manifest),
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    except (TypeError, ValueError) as error:
        raise WorkerExecutionError(
            "focused-test workspace manifest is not canonical JSON"
        ) from error

    timeout_seconds = value.get("timeout_seconds")
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
        or timeout_seconds > 3600
    ):
        raise WorkerExecutionError(
            "focused-test timeout must be a bounded positive number"
        )
    output_limit_bytes = value.get("output_limit_bytes")
    if (
        not isinstance(output_limit_bytes, int)
        or isinstance(output_limit_bytes, bool)
        or output_limit_bytes < 1024
        or output_limit_bytes > 16 * 1024 * 1024
    ):
        raise WorkerExecutionError(
            "focused-test output limit is outside the supported bounds"
        )

    return {
        "id": execution_id,
        "command": command,
        "test_command": test_command,
        "sandbox_profile": sandbox_profile,
        "sandbox_policy_version": DARWIN_SANDBOX_POLICY_VERSION,
        "cwd": cwd,
        "environment": environment,
        "artifact_directory": artifact_directory,
        "workspace_manifest": manifest,
        "timeout_seconds": float(timeout_seconds),
        "output_limit_bytes": output_limit_bytes,
    }


def _validate_runner_limits(
    contract: Mapping[str, Any], command_runner: GuardedGitCommandRunner
) -> None:
    if (
        getattr(command_runner, "timeout_seconds", None)
        != contract["timeout_seconds"]
        or getattr(command_runner, "max_output_bytes", None)
        != contract["output_limit_bytes"]
    ):
        raise WorkerExecutionError(
            "focused-test runner limits do not match the durable execution plan"
        )


def _private_environment(
    base_environment: Mapping[str, str], artifact_directory: Path
) -> Dict[str, str]:
    environment_root = artifact_directory.parent / "environment"
    home = environment_root / "home"
    temporary = environment_root / "tmp"
    expected_environment = {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONHASHSEED": "0",
        "TMPDIR": str(temporary),
    }
    if dict(base_environment) != expected_environment:
        raise WorkerExecutionError(
            "focused-test environment does not match its exact safe contract"
        )
    if environment_root.exists() or environment_root.is_symlink():
        raise WorkerExecutionError(
            "focused-test private environment directory already exists"
        )
    try:
        environment_root.mkdir(mode=0o700)
        os.chmod(environment_root, 0o700)
        home.mkdir(mode=0o700)
        temporary.mkdir(mode=0o700)
        os.chmod(home, 0o700)
        os.chmod(temporary, 0o700)
    except OSError as error:
        raise WorkerExecutionError(
            "could not allocate the focused-test private environment"
        ) from error

    return dict(base_environment)


def _completion_packet(
    contract: Mapping[str, Any], result: GuardedCommandResult
) -> Dict[str, Any]:
    command = tuple(str(argument) for argument in contract["command"])
    if tuple(result.command) != command:
        raise WorkerExecutionError(
            "guarded focused-test runner returned a different command"
        )

    artifact_directory = Path(contract["artifact_directory"])
    _require_private_directory(artifact_directory, private=True)
    stdout_path = _validated_output(
        result.stdout_path, artifact_directory / "stdout.log", result.stdout_sha256
    )
    stderr_path = _validated_output(
        result.stderr_path, artifact_directory / "stderr.log", result.stderr_sha256
    )
    if result.stdout_truncated or result.stderr_truncated:
        raise WorkerExecutionError(
            "focused-test output was truncated before authoritative evaluation"
        )

    return {
        "execution_id": contract["id"],
        "command": list(command),
        "cwd": str(contract["cwd"]),
        "artifact_directory": str(artifact_directory),
        "workspace_manifest": dict(contract["workspace_manifest"]),
        "exit_code": result.return_code,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stdout_sha256": result.stdout_sha256,
        "stderr_sha256": result.stderr_sha256,
        "stdout_bytes": stdout_path.stat().st_size,
        "stderr_bytes": stderr_path.stat().st_size,
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
    }


def _canonical_handoff(value: Mapping[str, Any], item_id: str) -> TestHandoff:
    handoff_value = value.get("canonical_handoff")
    if handoff_value is None:
        raise WorkerExecutionError(
            "focused-test completion omitted its storage-authoritative handoff"
        )
    try:
        handoff = TestHandoff.model_validate(handoff_value)
    except Exception as error:
        raise WorkerExecutionError(
            "focused-test completion omitted a valid canonical handoff"
        ) from error
    if handoff.item_id != item_id:
        raise WorkerExecutionError(
            "focused-test canonical handoff belongs to a different item"
        )
    return handoff


def _canonical_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise WorkerExecutionError("%s must be an absolute path" % label)
    path = Path(value)
    if not path.is_absolute() or path != path.resolve(strict=False):
        raise WorkerExecutionError("%s must be an absolute canonical path" % label)
    return path


def _require_private_directory(path: Path, *, private: bool) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise WorkerExecutionError("required focused-test directory is absent") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise WorkerExecutionError("focused-test path is not a real directory")
    if metadata.st_uid != os.getuid():
        raise WorkerExecutionError("focused-test directory has an unexpected owner")
    if private and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise WorkerExecutionError("focused-test runtime directory is not private")


def _validated_output(path: Path, expected: Path, expected_sha256: str) -> Path:
    if path != expected or path != path.resolve(strict=False):
        raise WorkerExecutionError("focused-test runner returned an unexpected output path")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise WorkerExecutionError("focused-test runner output is absent") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise WorkerExecutionError("focused-test runner output identity is unsafe")
    if _sha256(path) != expected_sha256:
        raise WorkerExecutionError("focused-test runner output hash changed before completion")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents
