from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import os
import signal
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from agent_flow import codex_worker as codex_worker_module
from agent_flow.codex_worker import (
    _BLOCKED_LAUNCHER,
    CodexCliConfig,
    CodexCliWorker,
)
from agent_flow.models import InvestigationHandoff, WorkerRole
from agent_flow.process_reconciler import ProcessIdentity
from agent_flow.scheduler import Scheduler
from agent_flow.sqlite_scheduler import SQLiteSchedulerStorage
from agent_flow.storage import SQLiteStore
from agent_flow.worktrees import ManagedWorktreeConfig, ManagedWorktreeManager
from agent_flow.workers import WorkerContext, WorkerExecutionError


_FAKE_CODEX = r'''from __future__ import annotations
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

args = sys.argv[1:]
prompt = sys.stdin.read()
scenario = os.environ.get("FAKE_CODEX_SCENARIO", "valid")
thread_id = os.environ.get(
    "FAKE_CODEX_THREAD_ID", "019f6677-1111-7222-8333-555555555555"
)
if scenario == "resume_mismatch":
    thread_id = "019f6677-9999-7aaa-8bbb-666666666666"
log_path = os.environ.get("FAKE_CODEX_LOG")
if log_path:
    Path(log_path).write_text(
        json.dumps({"args": args, "prompt": prompt, "cwd": os.getcwd()}),
        encoding="utf-8",
    )
if scenario == "malformed":
    print("{not-json", flush=True)
    raise SystemExit(0)

print(json.dumps({"type": "thread.started", "thread_id": thread_id}), flush=True)
if scenario == "conflicting_thread":
    print(
        json.dumps(
            {
                "type": "thread.started",
                "thread_id": "019f6677-ffff-7000-8000-999999999999",
            }
        ),
        flush=True,
    )
if scenario == "hang":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(1)
if scenario == "leader_exits_with_child":
    child_code = """\
from pathlib import Path
import os
import signal
import sys
import time
Path(sys.argv[1]).write_text(str(os.getpid()), encoding="utf-8")
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(1)
"""
    subprocess.Popen(
        [sys.executable, "-c", child_code, os.environ["FAKE_CODEX_CHILD_PID"]],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )

print(
    json.dumps(
        {
            "type": "item.completed",
            "item": {"id": "item-1", "type": "agent_message", "text": "done"},
        }
    ),
    flush=True,
)
if scenario == "terminal_error":
    print(json.dumps({"type": "turn.failed", "error": "simulated"}), flush=True)
elif scenario == "missing_completion":
    pass
elif scenario == "oversized":
    print(json.dumps({"type": "future.event", "data": "x" * 4096}), flush=True)
    print(json.dumps({"type": "turn.completed", "usage": {}}), flush=True)
else:
    print(json.dumps({"type": "turn.completed", "usage": {}}), flush=True)

output_index = args.index("-o") + 1
final_payload = "{}" if scenario == "invalid_handoff" else os.environ["FAKE_CODEX_HANDOFF"]
Path(args[output_index]).write_text(final_payload, encoding="utf-8")
if scenario == "nonzero":
    print("simulated codex failure", file=sys.stderr, flush=True)
    raise SystemExit(7)
'''


def _git_repository(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    (path / "README.md").write_text("# Fake Codex repository\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "README.md"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "-c",
            "user.name=Agent Flow Tests",
            "-c",
            "user.email=agent-flow@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
        check=True,
    )
    return path


def _fake_cli(path: Path) -> Path:
    script = path / "fake_codex.py"
    script.write_text(_FAKE_CODEX, encoding="utf-8")
    return script


def _handoff(item_id: str, evidence_path: Path) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "item_id": item_id,
        "outcome": "ready_for_fix",
        "synopsis": "The fake CLI reproduced the bounded defect.",
        "reproduction_steps": ["Inspect the exact fake repository workflow."],
        "root_cause": "The deterministic fixture proves the stale transition.",
        "proposed_fix": "Update only the bounded transition.",
        "acceptance_criteria": ["The exact workflow returns current state."],
        "evidence": [
            {
                "kind": "log",
                "location": str(evidence_path),
                "description": "Existing repository evidence for the fake run.",
            }
        ],
    }


def _context(
    repository: Path,
    *,
    item_id: str = "item-codex",
    resume_session_id: str = "",
) -> Tuple[WorkerContext, Dict[str, List[Any]]]:
    recorded: Dict[str, List[Any]] = {
        "sessions": [],
        "processes": [],
        "cleared": [],
        "artifacts": [],
    }
    job: Dict[str, Any] = {
        "id": "job-codex",
        "role": "investigator",
        "attempt_number": 1,
        "current_attempt_id": "attempt-codex",
        "payload": {},
    }
    if resume_session_id:
        job.update(
            {
                "resume_external_provider": "codex",
                "resume_external_session_id": resume_session_id,
            }
        )
    context = WorkerContext(
        campaign={
            "id": "campaign-codex",
            "repository_paths": [str(repository)],
        },
        item={
            "id": item_id,
            "title": "Codex adapter item",
            "description": "Inspect $(touch /private/tmp/should-not-run) as task data.",
            "required_gates": ["focused_tests"],
        },
        job=job,
        _external_session_recorder=lambda provider, session_id: recorded[
            "sessions"
        ].append((provider, session_id)),
        _external_process_recorder=lambda provider, identity, target: recorded[
            "processes"
        ].append(
            (
                provider,
                identity.process_id,
                identity.process_group_id,
                identity.executable,
                target,
            )
        ),
        _external_process_clearer=lambda pid, pgid: recorded["cleared"].append(
            (pid, pgid)
        ),
        _artifact_recorder=lambda kind, uri, metadata: recorded[
            "artifacts"
        ].append((kind, uri, dict(metadata))),
    )
    return context, recorded


def _worker(
    tmp_path: Path,
    repository: Path,
    *,
    scenario: str = "valid",
    thread_id: str = "019f6677-1111-7222-8333-555555555555",
    timeout: float = 2.0,
    max_output_bytes: int = 10 * 1024 * 1024,
) -> Tuple[CodexCliWorker, Path]:
    script = _fake_cli(tmp_path)
    log_path = tmp_path / "fake-codex-invocation.json"
    config = CodexCliConfig(
        command_prefix=(sys.executable, str(script)),
        timeout_seconds=timeout,
        terminate_grace_seconds=0.1,
        max_output_bytes=max_output_bytes,
        runtime_root=tmp_path / "runtime",
        environment_overrides={
            "FAKE_CODEX_SCENARIO": scenario,
            "FAKE_CODEX_THREAD_ID": thread_id,
            "FAKE_CODEX_LOG": str(log_path),
            "FAKE_CODEX_CHILD_PID": str(tmp_path / "fake-codex-child.pid"),
            "FAKE_CODEX_HANDOFF": json.dumps(
                _handoff("item-codex", repository / "README.md")
            ),
        },
    )
    return CodexCliWorker(WorkerRole.INVESTIGATOR, config=config), log_path


def test_codex_worker_uses_stdin_strict_schema_and_read_only_policy(
    tmp_path: Path,
) -> None:
    repository = _git_repository(tmp_path / "repo")
    context, recorded = _context(repository)
    worker, log_path = _worker(tmp_path, repository)

    result = asyncio.run(worker.run(context))

    assert isinstance(result, InvestigationHandoff)
    invocation = worker.last_invocation
    assert invocation is not None
    assert invocation.sandbox == "read-only"
    assert invocation.command[-1] == "-"
    assert "--json" in invocation.command
    assert "--output-schema" in invocation.command
    assert "--ignore-user-config" in invocation.command
    assert "--strict-config" in invocation.command
    assert "--ignore-rules" in invocation.command
    assert "dangerously-bypass" not in " ".join(invocation.command)
    assert "--skip-git-repo-check" not in invocation.command
    assert "--last" not in invocation.command
    assert "--ephemeral" not in invocation.command
    assert 'web_search="disabled"' in invocation.command
    assert "mcp_servers={}" in invocation.command
    assert "features.hooks=false" in invocation.command
    assert "features.apps=false" in invocation.command
    assert "sandbox_workspace_write.writable_roots=[]" in invocation.command
    assert "sandbox_workspace_write.exclude_tmpdir_env_var=true" in invocation.command
    assert "sandbox_workspace_write.exclude_slash_tmp=true" in invocation.command
    logged = json.loads(log_path.read_text(encoding="utf-8"))
    assert "$(touch /private/tmp/should-not-run)" in logged["prompt"]
    assert all("should-not-run" not in argument for argument in logged["args"])
    assert logged["cwd"] == str(repository)
    assert recorded["sessions"] == [
        ("codex", "019f6677-1111-7222-8333-555555555555")
    ]
    assert len(recorded["processes"]) == 1
    assert recorded["cleared"] == [
        (recorded["processes"][0][1], recorded["processes"][0][2])
    ]
    assert invocation.events_path.is_file()
    assert invocation.stderr_path.is_file()
    assert invocation.final_path.is_file()
    assert invocation.schema_path.is_file()
    assert {artifact[0] for artifact in recorded["artifacts"]} == {
        "codex_schema",
        "codex_jsonl",
        "codex_stderr",
        "codex_final",
    }
    assert all(len(artifact[2]["sha256"]) == 64 for artifact in recorded["artifacts"])
    assert not Path("/private/tmp/should-not-run").exists()


def test_codex_worker_resolves_and_executes_target_from_exact_child_path(
    tmp_path: Path,
) -> None:
    repository = _git_repository(tmp_path / "repo")
    context, recorded = _context(repository)
    original_worker, log_path = _worker(tmp_path, repository)
    child_bin = tmp_path / "child-bin"
    child_bin.mkdir()
    launcher = child_bin / "isolated-codex"
    fake_cli = original_worker.config.command_prefix[1]
    launcher.write_text(
        '#!/bin/sh\nexec "%s" "%s" "$@"\n'
        % (sys.executable, fake_cli),
        encoding="utf-8",
    )
    launcher.chmod(0o700)
    worker = CodexCliWorker(
        WorkerRole.INVESTIGATOR,
        config=replace(
            original_worker.config,
            command_prefix=("isolated-codex",),
            environment_overrides={
                **original_worker.config.environment_overrides,
                "PATH": str(child_bin),
            },
        ),
    )

    result = asyncio.run(worker.run(context))

    assert isinstance(result, InvestigationHandoff)
    assert worker.last_invocation is not None
    assert worker.last_invocation.command[0] == str(launcher.resolve())
    assert recorded["processes"][0][4] == str(launcher.resolve())
    assert log_path.is_file()


def test_active_cleanup_identity_mismatch_sends_no_process_group_signal(
    tmp_path: Path,
) -> None:
    identity = ProcessIdentity(
        process_id=max(os.getpid(), os.getpgrp()) + 10_000,
        process_group_id=max(os.getpid(), os.getpgrp()) + 10_000,
        user_id=os.getuid(),
        executable="/usr/bin/python3",
        start_seconds=100,
        start_microseconds=200,
    )

    class MismatchedRuntime:
        def __init__(self) -> None:
            self.signals: List[Tuple[int, int]] = []

        def inspect(self, _process_id: int) -> ProcessIdentity:
            return replace(identity, start_microseconds=201)

        def list_group(self, _process_group_id: int) -> Tuple[ProcessIdentity, ...]:
            return (replace(identity, start_microseconds=201),)

        def signal_group(self, process_group_id: int, signal_number: int) -> None:
            self.signals.append((process_group_id, signal_number))

    runtime = MismatchedRuntime()
    worker = CodexCliWorker(
        WorkerRole.INVESTIGATOR,
        config=CodexCliConfig(runtime_root=tmp_path / "runtime"),
        process_runtime=runtime,
    )

    with pytest.raises(WorkerExecutionError, match="identity changed"):
        worker._signal_owned_group(identity, signal.SIGTERM)

    assert runtime.signals == []


def test_guardian_installs_termination_handler_before_child_launch() -> None:
    assert _BLOCKED_LAUNCHER.index("signal.signal(signal.SIGTERM") < (
        _BLOCKED_LAUNCHER.index("child = subprocess.Popen")
    )


def test_guardian_release_requires_final_process_group_absence(
    tmp_path: Path,
) -> None:
    class ReapedGuardian:
        pid = max(os.getpid(), os.getpgrp()) + 10_000
        returncode = 0

        async def wait(self) -> int:
            return 0

    async def scenario() -> None:
        worker = CodexCliWorker(
            WorkerRole.INVESTIGATOR,
            config=CodexCliConfig(runtime_root=tmp_path / "runtime"),
        )

        async def group_remains(_process_group_id: int, _timeout: float) -> bool:
            return False

        worker._wait_for_process_group_exit = group_remains  # type: ignore[method-assign]
        read_fd, write_fd = os.pipe()
        try:
            with pytest.raises(WorkerExecutionError, match="remained populated"):
                await worker._release_guardian(ReapedGuardian(), write_fd)  # type: ignore[arg-type]
        finally:
            os.close(read_fd)

    asyncio.run(scenario())


def test_output_schema_closes_every_object_for_codex(tmp_path: Path) -> None:
    repository = _git_repository(tmp_path / "repo")
    context, _recorded = _context(repository)
    worker = CodexCliWorker(
        WorkerRole.INVESTIGATOR,
        config=CodexCliConfig(runtime_root=tmp_path / "runtime"),
    )

    invocation = worker.prepare_invocation(context)
    schema = json.loads(invocation.schema_path.read_text(encoding="utf-8"))

    def assert_strict_objects(node: object) -> None:
        if isinstance(node, list):
            for child in node:
                assert_strict_objects(child)
            return
        if not isinstance(node, dict):
            return
        assert "default" not in node
        if node.get("type") == "object" or "properties" in node:
            assert node["additionalProperties"] is False
            assert set(node["required"]) == set(node.get("properties", {}))
        for child in node.values():
            assert_strict_objects(child)

    assert_strict_objects(schema)
    metadata = schema["$defs"]["EvidenceRef"]["properties"]["metadata"]
    assert metadata["properties"] == {}
    assert metadata["additionalProperties"] is False


def test_codex_worker_resumes_only_the_exact_persisted_thread(tmp_path: Path) -> None:
    repository = _git_repository(tmp_path / "repo")
    session_id = "019f6677-aaaa-7bbb-8ccc-777777777777"
    context, recorded = _context(repository, resume_session_id=session_id)
    worker, _log_path = _worker(tmp_path, repository, thread_id=session_id)

    result = asyncio.run(worker.run(context))

    assert isinstance(result, InvestigationHandoff)
    invocation = worker.last_invocation
    assert invocation is not None
    assert "resume" in invocation.command
    assert session_id in invocation.command
    assert "--last" not in invocation.command
    assert "--color" not in invocation.command
    assert recorded["sessions"] == [("codex", session_id)]


@pytest.mark.skipif(shutil.which("codex") is None, reason="Codex CLI is not installed")
def test_resume_arguments_parse_with_installed_codex_cli(tmp_path: Path) -> None:
    repository = _git_repository(tmp_path / "repo")
    session_id = "019f6677-aaaa-7bbb-8ccc-777777777777"
    context, _recorded = _context(repository, resume_session_id=session_id)
    worker = CodexCliWorker(
        WorkerRole.INVESTIGATOR,
        config=CodexCliConfig(runtime_root=tmp_path / "runtime"),
    )
    invocation = worker.prepare_invocation(context)
    parser_command = list(invocation.command[:-2]) + ["--help"]

    result = subprocess.run(
        parser_command,
        cwd=str(repository),
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert "Usage: codex exec resume" in result.stdout


def test_codex_worker_rejects_mismatched_resumed_thread(tmp_path: Path) -> None:
    repository = _git_repository(tmp_path / "repo")
    session_id = "019f6677-aaaa-7bbb-8ccc-888888888888"
    context, recorded = _context(repository, resume_session_id=session_id)
    worker, _log_path = _worker(
        tmp_path,
        repository,
        scenario="resume_mismatch",
        thread_id=session_id,
    )

    with pytest.raises(WorkerExecutionError, match="did not match"):
        asyncio.run(worker.run(context))

    assert recorded["sessions"] == []
    assert len(recorded["processes"]) == 1
    assert len(recorded["cleared"]) == 1


@pytest.mark.parametrize(
    ("scenario", "message"),
    [
        ("malformed", "malformed JSONL"),
        ("terminal_error", "terminal event"),
        ("nonzero", "exited with code 7"),
        ("conflicting_thread", "conflicting thread IDs"),
        ("missing_completion", "required completion events"),
        ("invalid_handoff", "did not match the role handoff schema"),
    ],
)
def test_codex_worker_fails_closed_on_invalid_execution(
    tmp_path: Path, scenario: str, message: str
) -> None:
    repository = _git_repository(tmp_path / "repo")
    context, recorded = _context(repository)
    worker, _log_path = _worker(tmp_path, repository, scenario=scenario)

    with pytest.raises(WorkerExecutionError, match=message):
        asyncio.run(worker.run(context))

    assert len(recorded["processes"]) == 1
    assert len(recorded["cleared"]) == 1


def test_codex_worker_drains_but_rejects_oversized_output(tmp_path: Path) -> None:
    repository = _git_repository(tmp_path / "repo")
    context, recorded = _context(repository)
    worker, _log_path = _worker(
        tmp_path,
        repository,
        scenario="oversized",
        max_output_bytes=1500,
    )

    with pytest.raises(WorkerExecutionError, match="exceeded"):
        asyncio.run(worker.run(context))

    invocation = worker.last_invocation
    assert invocation is not None
    assert invocation.events_path.stat().st_size == 1500
    assert len(recorded["cleared"]) == 1


def test_codex_worker_cancellation_reaps_group_and_reraises(tmp_path: Path) -> None:
    async def scenario() -> None:
        repository = _git_repository(tmp_path / "repo")
        context, recorded = _context(repository)
        worker, _log_path = _worker(
            tmp_path, repository, scenario="hang", timeout=10
        )
        task = asyncio.create_task(worker.run(context))
        for _ in range(200):
            if recorded["sessions"]:
                break
            await asyncio.sleep(0.005)
        assert recorded["sessions"]
        process = worker.process
        assert process is not None

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert process.returncode is not None
        assert len(recorded["processes"]) == 1
        assert len(recorded["cleared"]) == 1

    asyncio.run(scenario())


def test_cancellation_during_post_barrier_pre_child_window_never_launches_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        repository = _git_repository(tmp_path / "repo")
        context, recorded = _context(repository)
        worker, log_path = _worker(
            tmp_path,
            repository,
            scenario="hang",
            timeout=10,
        )
        marker = Path(str(log_path) + ".guardian-window")
        delayed_launcher = _BLOCKED_LAUNCHER.replace(
            "child = subprocess.Popen(command)",
            (
                "from pathlib import Path\n"
                "import time\n"
                "Path(os.environ['FAKE_CODEX_LOG'] + "
                "'.guardian-window').write_text('released', encoding='utf-8')\n"
                "time.sleep(10)\n"
                "child = subprocess.Popen(command)"
            ),
        )
        monkeypatch.setattr(
            codex_worker_module,
            "_BLOCKED_LAUNCHER",
            delayed_launcher,
        )

        task = asyncio.create_task(worker.run(context))
        for _ in range(400):
            if marker.exists():
                break
            await asyncio.sleep(0.005)
        assert marker.read_text(encoding="utf-8") == "released"
        process = worker.process
        assert process is not None
        process_group_id = process.pid

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)

        assert not log_path.exists()
        assert process.returncode is not None
        with pytest.raises(ProcessLookupError):
            os.killpg(process_group_id, 0)
        assert len(recorded["processes"]) == 1
        assert len(recorded["cleared"]) == 1

    asyncio.run(scenario())


def test_codex_worker_reaps_surviving_child_after_leader_exits(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        repository = _git_repository(tmp_path / "repo")
        context, recorded = _context(repository)
        worker, _log_path = _worker(
            tmp_path,
            repository,
            scenario="leader_exits_with_child",
        )

        result = await worker.run(context)

        assert isinstance(result, InvestigationHandoff)
        process_group_id = recorded["processes"][0][2]
        with pytest.raises(ProcessLookupError):
            os.killpg(process_group_id, 0)
        assert len(recorded["cleared"]) == 1

    asyncio.run(scenario())


def test_blocked_launcher_does_not_exec_codex_before_process_is_persisted(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        repository = _git_repository(tmp_path / "repo")
        context, _recorded = _context(repository)
        process_identity: List[int] = []

        def reject_process(_provider: str, identity: Any, _target: str) -> None:
            process_identity.append(identity.process_group_id)
            raise RuntimeError("simulated durable registration failure")

        context = replace(context, _external_process_recorder=reject_process)
        worker, log_path = _worker(tmp_path, repository)

        with pytest.raises(RuntimeError, match="registration failure"):
            await worker.run(context)

        assert process_identity
        assert not log_path.exists()
        with pytest.raises(ProcessLookupError):
            os.killpg(process_identity[0], 0)

    asyncio.run(scenario())


def test_fixer_rejects_source_repository_as_write_workspace(tmp_path: Path) -> None:
    repository = _git_repository(tmp_path / "repo")
    context, _recorded = _context(repository)
    fixer_context = WorkerContext(
        campaign=context.campaign,
        item=context.item,
        job={
            **context.job,
            "role": "fixer",
            "payload": {"worktree_path": str(repository)},
        },
    )
    worker = CodexCliWorker(
        WorkerRole.FIXER,
        config=CodexCliConfig(runtime_root=tmp_path / "runtime"),
    )

    with pytest.raises(WorkerExecutionError, match="supervisor-managed worktree"):
        worker.prepare_invocation(fixer_context)


def test_fixer_and_tester_use_same_fenced_worktree_and_ignore_payload_path(
    tmp_path: Path,
) -> None:
    repository = _git_repository(tmp_path / "repo")
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        campaign = store.create_campaign(
            "managed Codex roles",
            config={"repository_paths": [str(repository.resolve())]},
        )
        item = store.create_work_item(
            campaign["id"],
            "managed worker item",
            description="Prove persisted workspace authorization.",
            state="ready_for_fix",
            required_gates=["focused_tests"],
            initial_job={
                "role": "fixer",
                "stage": "fix",
                "active_item_state": "fixing",
                "required_approval_action": "local_code_changes",
            },
        )
        approval = store.create_approval(
            campaign["id"],
            "local_code_changes",
            "test-owner",
            scope={"repository_paths": [str(repository.resolve())]},
        )
        store.resolve_approval(approval["id"], "approved", "test-owner")
        manager = ManagedWorktreeManager(
            store,
            owner="codex-worker-test",
            config=ManagedWorktreeConfig(
                worktree_root=(tmp_path / "managed").resolve(),
                runtime_root=(tmp_path / "git-runtime").resolve(),
                command_timeout_seconds=5,
                terminate_grace_seconds=1,
                operation_lease_seconds=30,
            ),
        )
        worktree = manager.provision(
            campaign["id"], item["id"], repository.resolve(), "HEAD"
        )
        fixer_claim = store.claim_job("fixer", "fixer-worker")
        assert fixer_claim is not None
        fixer_context = WorkerContext(
            campaign=campaign,
            item=item,
            job={
                **fixer_claim,
                "payload": {"worktree_path": str(repository.resolve())},
            },
            _managed_worktree_provider=lambda: store.get_claimed_managed_worktree(
                fixer_claim["id"],
                "fixer-worker",
                fixer_claim["lease_token"],
            ),
        )
        fixer_worker = CodexCliWorker(
            WorkerRole.FIXER,
            config=CodexCliConfig(runtime_root=tmp_path / "codex-fixer-runtime"),
        )

        fixer_invocation = fixer_worker.prepare_invocation(fixer_context)

        assert fixer_invocation.working_directory == Path(worktree["worktree_path"])
        assert fixer_invocation.working_directory != repository.resolve()
        completed = store.commit_stage_result(
            fixer_claim["id"],
            "fixer-worker",
            fixer_claim["lease_token"],
            {
                "schema_version": 1,
                "item_id": item["id"],
                "outcome": "ready_for_test",
                "summary": "Bounded fixture fix completed.",
                "changed_files": ["README.md"],
                "tests_run": [],
                "tester_instructions": ["Run the focused fixture proof."],
                "evidence": [],
                "blocker": None,
            },
            "fixing",
            "ready_for_test",
            "fix.completed",
            next_job={
                "role": "tester",
                "stage": "test",
                "active_item_state": "testing",
            },
        )
        assert completed["next_job"]["managed_worktree_id"] == worktree["id"]
        tester_claim = store.claim_job("tester", "tester-worker")
        assert tester_claim is not None
        tester_context = WorkerContext(
            campaign=campaign,
            item=store.get_work_item(item["id"]),
            job={
                **tester_claim,
                "payload": {"working_directory": str(repository.resolve())},
            },
            _managed_worktree_provider=lambda: store.get_claimed_managed_worktree(
                tester_claim["id"],
                "tester-worker",
                tester_claim["lease_token"],
            ),
            _managed_worktree_quarantiner=lambda reason: bool(
                store.quarantine_claimed_managed_worktree(
                    tester_claim["id"],
                    "tester-worker",
                    tester_claim["lease_token"],
                    reason,
                )
            ),
        )
        tester_worker = CodexCliWorker(
            WorkerRole.TESTER,
            config=CodexCliConfig(runtime_root=tmp_path / "codex-tester-runtime"),
        )

        tester_invocation = tester_worker.prepare_invocation(tester_context)

        assert tester_invocation.working_directory == fixer_invocation.working_directory
        assert tester_invocation.managed_worktree_id == worktree["id"]
        (tester_invocation.working_directory / "tester-write.txt").write_text(
            "forbidden\n", encoding="utf-8"
        )

        with pytest.raises(WorkerExecutionError, match="changed its validated workspace"):
            tester_worker._postflight_workspace(tester_context, tester_invocation)

        assert store.get_managed_worktree(worktree["id"])["state"] == "quarantined"


def test_managed_fixer_postflight_rejects_branch_head_change(
    tmp_path: Path,
) -> None:
    repository = _git_repository(tmp_path / "repo")
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        campaign = store.create_campaign(
            "postflight identity",
            config={"repository_paths": [str(repository.resolve())]},
        )
        item = store.create_work_item(
            campaign["id"],
            "identity item",
            description="Reject commits from a bounded fixer.",
            state="ready_for_fix",
            initial_job={
                "role": "fixer",
                "stage": "fix",
                "active_item_state": "fixing",
                "required_approval_action": "local_code_changes",
            },
        )
        approval = store.create_approval(
            campaign["id"],
            "local_code_changes",
            "test-owner",
            scope={"repository_paths": [str(repository.resolve())]},
        )
        store.resolve_approval(approval["id"], "approved", "test-owner")
        manager = ManagedWorktreeManager(
            store,
            owner="postflight-test",
            config=ManagedWorktreeConfig(
                worktree_root=(tmp_path / "managed").resolve(),
                runtime_root=(tmp_path / "git-runtime").resolve(),
                command_timeout_seconds=5,
                terminate_grace_seconds=1,
                operation_lease_seconds=30,
            ),
        )
        worktree = manager.provision(
            campaign["id"], item["id"], repository.resolve(), "HEAD"
        )
        claim = store.claim_job("fixer", "fixer-worker")
        assert claim is not None
        context = WorkerContext(
            campaign=campaign,
            item=item,
            job=claim,
            _managed_worktree_provider=lambda: store.get_claimed_managed_worktree(
                claim["id"], "fixer-worker", claim["lease_token"]
            ),
            _managed_worktree_quarantiner=lambda reason: bool(
                store.quarantine_claimed_managed_worktree(
                    claim["id"],
                    "fixer-worker",
                    claim["lease_token"],
                    reason,
                )
            ),
        )
        worker = CodexCliWorker(
            WorkerRole.FIXER,
            config=CodexCliConfig(runtime_root=tmp_path / "codex-runtime"),
        )
        invocation = worker.prepare_invocation(context)
        subprocess.run(
            [
                "git",
                "-C",
                str(worktree["worktree_path"]),
                "-c",
                "user.name=Agent Flow Tests",
                "-c",
                "user.email=agent-flow@example.invalid",
                "commit",
                "--allow-empty",
                "-q",
                "-m",
                "forbidden fixer commit",
            ],
            check=True,
        )

        with pytest.raises(WorkerExecutionError, match="preflight validation"):
            worker._postflight_workspace(context, invocation)

        assert store.get_managed_worktree(worktree["id"])["state"] == "quarantined"
        store.fail_job(
            claim["id"],
            "fixer-worker",
            claim["lease_token"],
            "managed worktree identity changed",
            max_attempts=3,
        )
        assert store.get_job(claim["id"])["status"] == "failed"
        assert store.get_work_item(item["id"])["state"] == "blocked"


def test_existing_shared_codex_runtime_root_is_rejected_without_chmod(
    tmp_path: Path,
) -> None:
    repository = _git_repository(tmp_path / "repo")
    runtime_root = tmp_path / "shared-runtime"
    runtime_root.mkdir(mode=0o755)
    os.chmod(runtime_root, 0o755)
    context = WorkerContext(
        campaign={
            "id": "campaign-private-root",
            "repository_paths": [str(repository)],
        },
        item={"id": "item-private-root"},
        job={
            "id": "job-private-root",
            "role": "investigator",
            "workspace_kind": "source_read_only",
            "current_attempt_id": "attempt-private-root",
            "payload": {},
        },
    )
    worker = CodexCliWorker(
        WorkerRole.INVESTIGATOR,
        config=CodexCliConfig(runtime_root=runtime_root),
    )

    with pytest.raises(WorkerExecutionError, match="permissions are not private"):
        worker.prepare_invocation(context)

    assert stat.S_IMODE(runtime_root.stat().st_mode) == 0o755


def test_scheduler_quarantine_callback_blocks_invalid_managed_workspace(
    tmp_path: Path,
) -> None:
    class QuarantiningFixer:
        role = WorkerRole.FIXER

        async def run(self, context: WorkerContext) -> dict:
            context.require_managed_worktree()
            context.quarantine_managed_worktree(
                "exact managed workspace identity was disproved"
            )
            raise WorkerExecutionError("managed workspace identity failed")

    async def scenario() -> None:
        repository = _git_repository(tmp_path / "repo")
        with SQLiteStore(tmp_path / "flow.sqlite3") as store:
            campaign = store.create_campaign(
                "scheduler quarantine",
                config={"repository_paths": [str(repository)]},
            )
            item = store.create_work_item(
                campaign["id"],
                "invalid managed identity",
                description="The scheduler must fence and block this workspace.",
                state="ready_for_fix",
                initial_job={
                    "role": "fixer",
                    "stage": "fix",
                    "active_item_state": "fixing",
                    "required_approval_action": "local_code_changes",
                },
            )
            approval = store.create_approval(
                campaign["id"],
                "local_code_changes",
                "test-owner",
                scope={"repository_paths": [str(repository)]},
            )
            store.resolve_approval(approval["id"], "approved", "test-owner")
            manager = ManagedWorktreeManager(
                store,
                owner="scheduler-quarantine-test",
                config=ManagedWorktreeConfig(
                    worktree_root=(tmp_path / "managed").resolve(),
                    runtime_root=(tmp_path / "git-runtime").resolve(),
                    command_timeout_seconds=5,
                    terminate_grace_seconds=1,
                    operation_lease_seconds=30,
                ),
            )
            worktree = manager.provision(
                campaign["id"], item["id"], repository, "HEAD"
            )
            scheduler = Scheduler(
                SQLiteSchedulerStorage(store),
                {WorkerRole.FIXER: (QuarantiningFixer(),)},
                global_concurrency_limit=1,
            )

            await scheduler.run_until_quiescent()

            assert store.get_managed_worktree(worktree["id"])["state"] == "quarantined"
            assert store.get_work_item(item["id"])["state"] == "blocked"
            assert store.list_jobs(work_item_id=item["id"])[0]["status"] == "failed"
            assert store.foreign_key_violations() == []

    asyncio.run(scenario())


def test_fake_codex_runs_through_scheduler_and_persists_session_without_repo_changes(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        repository = _git_repository(tmp_path / "repo")
        before = subprocess.run(
            ["git", "-C", str(repository), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        store = SQLiteStore(tmp_path / "agent-flow.sqlite3")
        try:
            campaign = store.create_campaign(
                "Fake Codex scheduler integration",
                config={"repository_paths": [str(repository)]},
                global_limit=1,
                role_limits={"investigator": 1, "fixer": 1, "tester": 1},
            )
            item = store.create_work_item(
                campaign["id"],
                "Fake Codex investigation",
                description="Prove the real adapter boundary without model usage.",
                initial_job={
                    "role": "investigator",
                    "stage": "investigator",
                    "active_item_state": "investigating",
                },
            )
            worker, _log_path = _worker(tmp_path, repository)
            scheduler = Scheduler(
                SQLiteSchedulerStorage(store),
                {WorkerRole.INVESTIGATOR: (worker,)},
                global_concurrency_limit=1,
                allow_simulated_evidence=False,
            )

            await scheduler.run_until_quiescent()

            assert scheduler.errors == []
            assert store.get_work_item(item["id"])["state"] == "ready_for_fix"
            jobs = store.list_jobs(work_item_id=item["id"])
            assert [job["role"] for job in jobs] == ["investigator", "fixer"]
            assert [job["status"] for job in jobs] == ["completed", "pending"]
            attempt = store.list_attempts(str(jobs[0]["id"]))[0]
            assert attempt["status"] == "succeeded"
            assert attempt["external_provider"] == "codex"
            assert attempt["external_session_id"] == (
                "019f6677-1111-7222-8333-555555555555"
            )
            assert attempt["external_process_id"] is not None
            assert attempt["external_process_state"] == "stopped"
            assert attempt["external_process_identity_version"] == (
                "darwin_libproc_v1"
            )
            event_kinds = [
                event["event_kind"]
                for event in store.list_events(work_item_id=item["id"])
            ]
            assert "worker.external_process_started" in event_kinds
            assert "worker.external_session_recorded" in event_kinds
            assert "worker.external_process_stopped" in event_kinds
            artifacts = store.list_artifacts(item["id"])
            assert {artifact["kind"] for artifact in artifacts} == {
                "codex_schema",
                "codex_jsonl",
                "codex_stderr",
                "codex_final",
            }
            assert all(
                artifact["metadata"]["attempt_id"] == attempt["id"]
                for artifact in artifacts
            )
            assert all(
                len(artifact["metadata"]["sha256"]) == 64
                for artifact in artifacts
            )
            assert store.foreign_key_violations() == []
        finally:
            store.close()

        after = subprocess.run(
            ["git", "-C", str(repository), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        assert after == before

    asyncio.run(scenario())
