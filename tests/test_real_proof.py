from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import shlex
import stat

from typer.testing import CliRunner

from agent_flow.cli import app
from agent_flow.codex_worker import CodexCliConfig, codex_handoff_schema
from agent_flow.models import WorkerRole
from agent_flow.real_proof import PROVIDER_ARTIFACT_NAMES, RealProofRunner
from agent_flow.workers import WorkerContext


class DeterministicProofWorker:
    def __init__(self, role: WorkerRole) -> None:
        self.role = role

    async def run(self, context: WorkerContext) -> dict:
        if self.role == WorkerRole.INVESTIGATOR:
            repository = Path(str(context.campaign["repository_paths"][0]))
            return {
                "schema_version": 1,
                "item_id": context.item_id,
                "outcome": "ready_for_fix",
                "synopsis": "The focused addition test fails on subtraction.",
                "reproduction_steps": ["Run python3 -B -m unittest -v."],
                "root_cause": "calculator.add subtracts the right operand.",
                "proposed_fix": "Return left plus right in calculator.add.",
                "acceptance_criteria": ["The focused unittest passes."],
                "evidence": [self._evidence(repository / "test_calculator.py")],
                "blocker": None,
            }
        worktree = context.require_managed_worktree()
        worktree_path = Path(str(worktree["worktree_path"]))
        if self.role == WorkerRole.FIXER:
            (worktree_path / "calculator.py").write_text(
                "def add(left: int, right: int) -> int:\n"
                "    return left + right\n",
                encoding="utf-8",
            )
            return {
                "schema_version": 1,
                "item_id": context.item_id,
                "outcome": "ready_for_test",
                "summary": "Changed the bounded arithmetic operation to addition.",
                "changed_files": ["calculator.py"],
                "tests_run": ["python3 -B -m unittest -v"],
                "tester_instructions": ["Run the focused unittest."],
                "evidence": [
                    self._evidence(worktree_path / "test_calculator.py")
                ],
                "blocker": None,
            }
        return {
            "schema_version": 1,
            "item_id": context.item_id,
            "outcome": "pass",
            "summary": "The focused addition test passes.",
            "gate_proofs": [
                {
                    "gate": "focused_tests",
                    "result": "pass",
                    "summary": "The focused unittest passed.",
                    "evidence": [
                        self._evidence(worktree_path / "test_calculator.py")
                    ],
                }
            ],
            "failure_summary": None,
            "blocker": None,
        }

    @staticmethod
    def _evidence(path: Path) -> dict:
        return {
            "kind": "test",
            "location": str(path),
            "description": "Tracked focused-test fixture.",
            "metadata": {},
        }


def _worker_factory(
    role: WorkerRole, _config: CodexCliConfig
) -> DeterministicProofWorker:
    return DeterministicProofWorker(role)


def test_fixed_proof_orchestrates_managed_flow_without_provider_claims(
    tmp_path: Path,
) -> None:
    proof_root = tmp_path / "fixed-proof"
    runner = RealProofRunner(
        root=proof_root,
        worker_factory=_worker_factory,
        require_authenticated_provider=False,
    )

    result = asyncio.run(runner.run())

    assert result.verified is True
    assert result.report["final_item_state"] == "verified_green"
    assert result.report["source_unchanged"] is True
    assert result.report["exact_worktree_diff"] is True
    assert result.report["jobs_exactly_once"] is True
    assert result.report["attempts_succeeded_exactly_once"] is True
    assert result.report["same_worktree_fixer_tester"] is True
    assert result.report["provider_checks_skipped"] is True
    assert result.report["sessions_distinct_and_persisted"] is False
    assert result.report["resource_leases"] == []
    assert result.report["foreign_key_violations"] == []
    assert result.report["supervisor_focused_test"]["return_code"] == 0
    assert result.report["scheduler_error_free"] is True
    assert result.report["executable_hashes_unchanged"] is True
    assert Path(result.report["guardian_executable"]["path"]).is_absolute()
    assert Path(result.report["python_executable"]["path"]).is_absolute()
    assert result.report_path.is_file()
    assert stat.S_IMODE(result.report_path.stat().st_mode) == 0o600
    assert not any(result.root.rglob("__pycache__"))

    failed = dict(result.report)
    failed["scheduler_error_free"] = False
    assert not all(runner._core_requirements(failed, 0))

    failed_attempts = [dict(attempt) for attempt in result.report["attempts"]]
    failed_attempts[0]["status"] = "failed"
    failed_attempts[0]["error"] = "failure"
    assert runner._attempts_succeeded_exactly_once(
        result.report["jobs"], failed_attempts
    ) is False

    worktree = Path(result.report["worktree_path"])
    empty = worktree / "empty-directory"
    empty.mkdir()
    assert runner._exact_worktree_diff(worktree, dict(result.report)) is False
    empty.rmdir()

    ignored = worktree / "ignored-proof.txt"
    exclude_value = runner._git(
        "rev-parse", "--git-path", "info/exclude", cwd=worktree
    )
    exclude = Path(exclude_value)
    if not exclude.is_absolute():
        exclude = worktree / exclude
    previous_exclude = exclude.read_bytes()
    exclude.write_bytes(previous_exclude + b"\nignored-proof.txt\n")
    ignored.write_text("must be detected\n", encoding="utf-8")
    assert runner._exact_worktree_diff(worktree, dict(result.report)) is False
    ignored.unlink()
    exclude.write_bytes(previous_exclude)

    runner._git(
        "update-index", "--skip-worktree", "test_calculator.py", cwd=worktree
    )
    assert runner._exact_worktree_diff(worktree, dict(result.report)) is False
    runner._git(
        "update-index",
        "--no-skip-worktree",
        "test_calculator.py",
        cwd=worktree,
    )
    runner._git(
        "update-index", "--assume-unchanged", "calculator.py", cwd=worktree
    )
    assert runner._exact_worktree_diff(worktree, dict(result.report)) is False
    runner._git(
        "update-index",
        "--no-assume-unchanged",
        "calculator.py",
        cwd=worktree,
    )


def test_real_proof_cli_requires_explicit_live_model_acknowledgement() -> None:
    result = CliRunner().invoke(app, ["prove-real-codex"])

    assert result.exit_code != 0
    assert "--acknowledge-live-model is required" in result.output
    assert "agent-flow-real-proof-" not in result.output


def test_tester_command_proof_rejects_substrings_and_requires_test_output(
    tmp_path: Path,
) -> None:
    runner = RealProofRunner(root=tmp_path / "proof")
    jsonl = tmp_path / "tester.jsonl"
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    tester = {"id": "tester-job", "role": "tester"}
    artifacts = [
        {"job_id": "tester-job", "kind": "codex_jsonl", "uri": str(jsonl)}
    ]
    exact = runner._focused_command_text

    _write_command_event(
        jsonl,
        "/bin/zsh -lc %s" % shlex.quote("echo %s" % shlex.quote(exact)),
        _test_output(worktree),
    )
    assert runner._tester_command_proof(
        [tester], artifacts, worktree
    ) is False

    _write_command_event(
        jsonl,
        "/bin/zsh -lc %s" % shlex.quote(exact),
        _test_output(worktree),
    )
    assert runner._tester_command_proof(
        [tester], artifacts, worktree
    ) is True

    _write_command_event(
        jsonl,
        "/bin/zsh -lc %s" % shlex.quote(exact),
        _test_output(tmp_path / "other-worktree"),
    )
    assert runner._tester_command_proof(
        [tester], artifacts, worktree
    ) is False

    _write_command_event(
        jsonl,
        "/bin/zsh -lc %s" % shlex.quote(exact),
        "not a unittest result\n",
    )
    assert runner._tester_command_proof(
        [tester], artifacts, worktree
    ) is False


def test_provider_artifacts_bind_job_attempt_and_jsonl_session(
    tmp_path: Path,
) -> None:
    root = tmp_path / "proof"
    runner = RealProofRunner(root=root)
    root.mkdir(mode=0o700)
    runner.source.mkdir(mode=0o700)
    worktree = root / "worktree"
    worktree.mkdir(mode=0o700)
    artifact_root = runner._attempt_runtime_directory(
        "campaign-proof", "tester-job", "tester-attempt"
    )
    artifact_root.mkdir(mode=0o700, parents=True)
    job = {"id": "tester-job", "role": "tester"}
    attempt = {
        "id": "tester-attempt",
        "job_id": "tester-job",
        "external_session_id": "persisted-session",
        "external_process_target_executable": "/private/tmp/codex",
        "result": _tester_result(),
    }
    report = {
        "campaign_id": "campaign-proof",
        "item_id": "item-proof",
    }
    artifacts = _provider_artifacts(
        runner,
        artifact_root,
        thread_id="different-session",
    )

    assert runner._provider_artifacts_valid(
        artifacts, [attempt], [job], worktree, report
    ) is False

    artifacts = _provider_artifacts(
        runner,
        artifact_root,
        thread_id="persisted-session",
    )
    jsonl_artifact = next(
        artifact
        for artifact in artifacts
        if artifact["kind"] == "codex_jsonl"
    )
    jsonl_path = Path(str(jsonl_artifact["uri"]))
    for artifact in artifacts:
        path = Path(str(artifact["uri"]))
        if path != jsonl_path:
            path.unlink()
            os.link(jsonl_path, path)
        artifact["metadata"]["bytes"] = path.stat().st_size
        artifact["metadata"]["sha256"] = runner._sha256(path)
    assert len({Path(str(row["uri"])).stat().st_ino for row in artifacts}) == 1
    assert runner._provider_artifacts_valid(
        artifacts, [attempt], [job], worktree, report
    ) is False

    artifacts = _provider_artifacts(
        runner,
        artifact_root,
        thread_id="persisted-session",
    )
    assert runner._provider_artifacts_valid(
        artifacts, [attempt], [job], worktree, report
    ) is True

    jsonl_artifact = next(
        artifact
        for artifact in artifacts
        if artifact["kind"] == "codex_jsonl"
    )
    jsonl_path = Path(str(jsonl_artifact["uri"]))
    wrong_result = _tester_result()
    wrong_result["summary"] = "Wrong final handoff."
    jsonl_path.write_text(
        "\n".join(
            (
                json.dumps(
                    {
                        "type": "thread.started",
                        "thread_id": "persisted-session",
                    }
                ),
                json.dumps({"type": "turn.started"}),
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {
                            "type": "agent_message",
                            "text": json.dumps(wrong_result, sort_keys=True),
                        },
                    }
                ),
                json.dumps({"type": "turn.completed"}),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    jsonl_artifact["metadata"]["bytes"] = jsonl_path.stat().st_size
    jsonl_artifact["metadata"]["sha256"] = runner._sha256(jsonl_path)
    assert runner._provider_artifacts_valid(
        artifacts, [attempt], [job], worktree, report
    ) is False

    artifacts = _provider_artifacts(
        runner,
        artifact_root,
        thread_id="persisted-session",
    )

    schema = next(
        artifact
        for artifact in artifacts
        if artifact["kind"] == "codex_schema"
    )
    schema_path = Path(str(schema["uri"]))
    schema_path.write_text("{}\n", encoding="utf-8")
    schema["metadata"]["bytes"] = schema_path.stat().st_size
    schema["metadata"]["sha256"] = runner._sha256(schema_path)
    assert runner._provider_artifacts_valid(
        artifacts, [attempt], [job], worktree, report
    ) is False

    artifacts[0]["job_id"] = "other-job"
    assert runner._provider_artifacts_valid(
        artifacts, [attempt], [job], worktree, report
    ) is False

    artifacts = _provider_artifacts(
        runner,
        artifact_root,
        thread_id="persisted-session",
    )
    artifacts.append(dict(artifacts[0]))
    assert runner._provider_artifacts_valid(
        artifacts, [attempt], [job], worktree, report
    ) is False

    artifacts = _provider_artifacts(
        runner,
        artifact_root,
        thread_id="persisted-session",
    )
    aliased_path = next(
        Path(str(artifact["uri"]))
        for artifact in artifacts
        if artifact["kind"] == "codex_jsonl"
    )
    for artifact in artifacts:
        artifact["uri"] = str(aliased_path)
        artifact["metadata"]["bytes"] = aliased_path.stat().st_size
        artifact["metadata"]["sha256"] = runner._sha256(aliased_path)
    assert runner._provider_artifacts_valid(
        artifacts, [attempt], [job], worktree, report
    ) is False


def test_process_proof_rejects_incomplete_darwin_identity(tmp_path: Path) -> None:
    runner = RealProofRunner(root=tmp_path / "proof")
    complete = {
        "status": "succeeded",
        "error": None,
        "finished_at": 2.0,
        "external_process_id": 200,
        "external_process_group_id": 200,
        "external_provider": "codex",
        "external_process_identity_version": "darwin_libproc_v1",
        "external_process_owner_uid": os.getuid(),
        "external_process_start_seconds": 1,
        "external_process_start_microseconds": 1,
        "external_process_executable": str(runner.guardian_executable),
        "external_process_target_executable": "/private/tmp/codex",
        "external_process_state": "stopped",
        "external_process_outcome": "reaped",
        "external_process_stopped_at": 2.0,
        "external_process_last_error": None,
    }
    report = {
        "guardian_executable": {"path": str(runner.guardian_executable)},
        "codex_executable": {"path": "/private/tmp/codex"},
    }
    second = dict(complete)
    second.update(
        {
            "external_process_id": 201,
            "external_process_group_id": 201,
            "external_process_start_microseconds": 2,
        }
    )
    third = dict(complete)
    third.update(
        {
            "external_process_id": 202,
            "external_process_group_id": 202,
            "external_process_start_microseconds": 3,
        }
    )

    assert runner._all_processes_stopped(
        [complete, second, third], report
    ) is True

    wrong_guardian = dict(complete)
    wrong_guardian["external_process_executable"] = "/bin/ls"
    assert runner._all_processes_stopped(
        [wrong_guardian, second, third], report
    ) is False

    failed = dict(complete)
    failed["status"] = "failed"
    failed["error"] = "failure"
    assert runner._all_processes_stopped(
        [failed, second, third], report
    ) is False

    incomplete = dict(complete)
    incomplete.pop("external_process_start_seconds")

    assert runner._all_processes_stopped(
        [incomplete, second, third], report
    ) is False

    assert runner._all_processes_stopped(
        [complete, complete, complete], report
    ) is False


def test_session_events_bind_exact_attempt_identity(tmp_path: Path) -> None:
    runner = RealProofRunner(root=tmp_path / "proof")
    job = {"id": "tester-job", "role": "tester"}
    attempt = _complete_process_attempt(runner)
    attempt.update(
        {
            "job_id": "tester-job",
            "external_session_id": "session-1",
        }
    )
    events = _identity_events(attempt)

    assert runner._session_events_precede_completion(
        [job], [attempt], events
    ) is True

    events[1]["event_data"] = {
        "provider": "codex",
        "session_id": "wrong-session",
    }
    assert runner._session_events_precede_completion(
        [job], [attempt], events
    ) is False


def test_artifact_events_bind_rows_before_process_stop() -> None:
    job = {"id": "tester-job", "role": "tester"}
    artifacts = [
        {
            "id": "artifact-%d" % index,
            "job_id": "tester-job",
            "kind": kind,
            "uri": "/private/tmp/%s" % PROVIDER_ARTIFACT_NAMES[kind],
            "metadata": {"attempt_id": "tester-attempt"},
        }
        for index, kind in enumerate(sorted(PROVIDER_ARTIFACT_NAMES), start=1)
    ]
    events = [
        {
            "job_id": "tester-job",
            "event_type": "worker.external_session_recorded",
            "sequence": 1,
            "event_data": {},
        }
    ]
    events.extend(
        {
            "job_id": "tester-job",
            "event_type": "artifact.added",
            "sequence": index + 1,
            "event_data": {
                "artifact_id": artifact["id"],
                "attempt_id": "tester-attempt",
                "kind": artifact["kind"],
                "uri": artifact["uri"],
            },
        }
        for index, artifact in enumerate(artifacts, start=1)
    )
    events.append(
        {
            "job_id": "tester-job",
            "event_type": "worker.external_process_stopped",
            "sequence": 6,
            "event_data": {},
        }
    )

    assert RealProofRunner._artifact_events_valid(
        [job], artifacts, events
    ) is True

    events[1]["event_data"]["uri"] = "/private/tmp/wrong"
    assert RealProofRunner._artifact_events_valid(
        [job], artifacts, events
    ) is False

    events[1]["event_data"]["uri"] = artifacts[0]["uri"]
    events[1]["event_data"]["attempt_id"] = "wrong-attempt"
    assert RealProofRunner._artifact_events_valid(
        [job], artifacts, events
    ) is False


def test_jsonl_requires_one_ordered_completed_turn(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    final_text = json.dumps(_tester_result(), sort_keys=True)
    valid = [
        {"type": "thread.started", "thread_id": "session"},
        {"type": "turn.started"},
        {
            "type": "item.completed",
            "item": {"type": "agent_message", "text": final_text},
        },
        {"type": "turn.completed"},
    ]

    _write_jsonl_events(path, valid)
    assert RealProofRunner._jsonl_final_payload(path) == _tester_result()

    _write_jsonl_events(
        path, [event for event in valid if event["type"] != "turn.started"]
    )
    assert RealProofRunner._jsonl_final_payload(path) is None

    _write_jsonl_events(path, valid[:2] + [{"type": "turn.started"}] + valid[2:])
    assert RealProofRunner._jsonl_final_payload(path) is None

    _write_jsonl_events(path, valid[:2] + [valid[3], valid[2]])
    assert RealProofRunner._jsonl_final_payload(path) is None


def test_executable_hash_drift_fails_closed(tmp_path: Path) -> None:
    runner = RealProofRunner(
        root=tmp_path / "proof",
        require_authenticated_provider=False,
    )
    git = tmp_path / "git"
    guardian = tmp_path / "guardian"
    python = tmp_path / "python"
    git.write_bytes(b"git-before")
    guardian.write_bytes(b"guardian-before")
    python.write_bytes(b"python-before")
    report = {
        "git_executable": runner._executable_record(git),
        "guardian_executable": runner._executable_record(guardian),
        "python_executable": runner._executable_record(python),
    }

    assert runner._executable_hashes_unchanged(report) is True
    git.write_bytes(b"git-after")
    assert runner._executable_hashes_unchanged(report) is False
    assert runner.executable_baselines["git_executable"]["sha256"]
    assert runner.executable_baselines["guardian_executable"]["sha256"]
    assert runner.executable_baselines["python_executable"]["sha256"]


def _write_command_event(path: Path, command: str, output: str) -> None:
    path.write_text(
        json.dumps(
            {
                "type": "item.completed",
                "item": {
                    "type": "command_execution",
                    "command": command,
                    "aggregated_output": output,
                    "exit_code": 0,
                    "status": "completed",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _write_jsonl_events(path: Path, events: list) -> None:
    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )


def _test_output(worktree: Path) -> str:
    return (
        "test_adds_two_numbers ... ok\n"
        "AGENT_FLOW_TEST_FILE=%s\n"
        "Ran 1 test\nOK\n" % (worktree / "test_calculator.py")
    )


def _provider_artifacts(
    runner: RealProofRunner,
    artifact_root: Path,
    *,
    thread_id: str,
) -> list:
    artifacts = []
    for kind in ("codex_schema", "codex_jsonl", "codex_stderr", "codex_final"):
        path = artifact_root / PROVIDER_ARTIFACT_NAMES[kind]
        if path.exists() or path.is_symlink():
            path.unlink()
        if kind == "codex_jsonl":
            payload = "\n".join(
                (
                    json.dumps(
                        {"type": "thread.started", "thread_id": thread_id}
                    ),
                    json.dumps({"type": "turn.started"}),
                    json.dumps(
                        {
                            "type": "item.completed",
                            "item": {
                                "type": "agent_message",
                                "text": json.dumps(
                                    _tester_result(), sort_keys=True
                                ),
                            },
                        }
                    ),
                    json.dumps({"type": "turn.completed"}),
                )
            ) + "\n"
        elif kind == "codex_schema":
            payload = json.dumps(
                codex_handoff_schema(WorkerRole.TESTER), sort_keys=True
            ) + "\n"
        elif kind == "codex_final":
            payload = json.dumps(_tester_result(), sort_keys=True) + "\n"
        else:
            payload = ""
        path.write_text(payload, encoding="utf-8")
        path.chmod(0o600)
        artifacts.append(
            {
                "job_id": "tester-job",
                "item_id": "item-proof",
                "kind": kind,
                "uri": str(path),
                "metadata": {
                    "attempt_id": "tester-attempt",
                    "provider": "codex",
                    "executable": "/private/tmp/codex",
                    "sandbox": "read-only",
                    "truncated": False,
                    "resumed": False,
                    "bytes": path.stat().st_size,
                    "sha256": runner._sha256(path),
                },
            }
        )
    return artifacts


def _complete_process_attempt(runner: RealProofRunner) -> dict:
    return {
        "status": "succeeded",
        "error": None,
        "finished_at": 2.0,
        "external_process_id": 200,
        "external_process_group_id": 200,
        "external_provider": "codex",
        "external_process_identity_version": "darwin_libproc_v1",
        "external_process_owner_uid": os.getuid(),
        "external_process_start_seconds": 1,
        "external_process_start_microseconds": 1,
        "external_process_executable": str(runner.guardian_executable),
        "external_process_target_executable": "/private/tmp/codex",
        "external_process_state": "stopped",
        "external_process_outcome": "reaped",
        "external_process_stopped_at": 2.0,
        "external_process_last_error": None,
    }


def _identity_events(attempt: dict) -> list:
    return [
        {
            "job_id": "tester-job",
            "event_type": "worker.external_process_started",
            "sequence": 1,
            "event_data": {
                "provider": attempt["external_provider"],
                "process_id": attempt["external_process_id"],
                "process_group_id": attempt["external_process_group_id"],
                "owner_uid": attempt["external_process_owner_uid"],
                "kernel_executable": attempt["external_process_executable"],
                "start_seconds": attempt["external_process_start_seconds"],
                "start_microseconds": attempt[
                    "external_process_start_microseconds"
                ],
                "target_executable": attempt[
                    "external_process_target_executable"
                ],
            },
        },
        {
            "job_id": "tester-job",
            "event_type": "worker.external_session_recorded",
            "sequence": 2,
            "event_data": {
                "provider": attempt["external_provider"],
                "session_id": attempt["external_session_id"],
            },
        },
        {
            "job_id": "tester-job",
            "event_type": "worker.external_process_stopped",
            "sequence": 3,
            "event_data": {
                "process_id": attempt["external_process_id"],
                "process_group_id": attempt["external_process_group_id"],
            },
        },
        {
            "job_id": "tester-job",
            "event_type": "test_verified_green",
            "sequence": 4,
            "event_data": {},
        },
    ]


def _tester_result() -> dict:
    return {
        "schema_version": 1,
        "item_id": "item-proof",
        "outcome": "pass",
        "summary": "Focused test passed.",
        "gate_proofs": [
            {
                "gate": "focused_tests",
                "result": "pass",
                "summary": "One focused test passed.",
                "evidence": [
                    {
                        "id": "test-proof",
                        "kind": "test",
                        "location": "/private/tmp/test_calculator.py",
                        "description": "Focused test evidence.",
                        "metadata": {},
                    }
                ],
            }
        ],
        "failure_summary": None,
        "blocker": None,
    }
