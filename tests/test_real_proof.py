from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
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
            "tests_run": [],
            "tester_instructions": [
                "Use Agent Flow's immutable focused-test plan."
            ],
            "evidence": [
                self._evidence(worktree_path / "test_calculator.py")
            ],
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


def test_fixed_proof_orchestrates_managed_flow_without_provider_claims(
    tmp_path: Path,
) -> None:
    proof_root = tmp_path / "fixed-proof"
    provider_roles = []

    def worker_factory(
        role: WorkerRole, config: CodexCliConfig
    ) -> DeterministicProofWorker:
        del config
        provider_roles.append(role)
        return DeterministicProofWorker(role)

    runner = RealProofRunner(
        root=proof_root,
        worker_factory=worker_factory,
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
    assert result.report["focused_test_execution_proof"] is True
    assert provider_roles == [WorkerRole.INVESTIGATOR, WorkerRole.FIXER]
    assert len(result.report["focused_test_plans"]) == 1
    assert len(result.report["focused_test_executions"]) == 1
    assert result.report["resource_leases"] == []
    assert result.report["foreign_key_violations"] == []
    assert result.report["scheduler_error_free"] is True
    assert result.report["executable_hashes_unchanged"] is True
    assert Path(result.report["guardian_executable"]["path"]).is_absolute()
    assert Path(result.report["python_executable"]["path"]).is_absolute()
    assert result.report_path.is_file()
    assert stat.S_IMODE(result.report_path.stat().st_mode) == 0o600
    assert not any(result.root.rglob("__pycache__"))

    failed = dict(result.report)
    failed["scheduler_error_free"] = False
    assert not all(runner._core_requirements(failed))

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

    tampered_execution = dict(result.report["focused_test_executions"][0])
    tampered_execution["exit_code"] = 1
    assert runner._focused_test_execution_proof(
        result.report["focused_test_plans"],
        [tampered_execution],
        result.report["jobs"],
        result.report["attempts"],
        result.report["artifacts"],
        result.report["events"],
        worktree,
        result.report,
    ) is False


def test_real_proof_cli_requires_explicit_live_model_acknowledgement() -> None:
    result = CliRunner().invoke(app, ["prove-real-codex"])

    assert result.exit_code != 0
    assert "--acknowledge-live-model is required" in result.output
    assert "agent-flow-real-proof-" not in result.output


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
        "campaign-proof", "investigator-job", "investigator-attempt"
    )
    artifact_root.mkdir(mode=0o700, parents=True)
    job = {"id": "investigator-job", "role": "investigator"}
    attempt = {
        "id": "investigator-attempt",
        "job_id": "investigator-job",
        "external_session_id": "persisted-session",
        "external_process_target_executable": "/private/tmp/codex",
        "result": _investigator_result(),
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
    wrong_result = _investigator_result()
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
        "python_executable": {"path": str(runner.python_executable)},
    }
    jobs = [
        {"id": "investigator-job", "role": "investigator"},
        {"id": "fixer-job", "role": "fixer"},
        {"id": "tester-job", "role": "tester"},
    ]
    complete.update({"id": "investigator-attempt", "job_id": "investigator-job"})
    second = dict(complete)
    second.update(
        {
            "id": "fixer-attempt",
            "job_id": "fixer-job",
            "external_process_id": 201,
            "external_process_group_id": 201,
            "external_process_start_microseconds": 2,
        }
    )
    third = dict(complete)
    third.update(
        {
            "id": "tester-attempt",
            "job_id": "tester-job",
            "external_process_id": 202,
            "external_process_group_id": 202,
            "external_process_start_microseconds": 3,
            "external_provider": "focused_test",
            "external_process_target_executable": str(
                runner.python_executable
            ),
        }
    )
    attempts = [complete, second, third]
    processes = [_process_from_attempt(attempt) for attempt in attempts]

    assert runner._all_processes_stopped(
        jobs, attempts, processes, report
    ) is True

    wrong_guardian = dict(processes[0])
    wrong_guardian["kernel_executable"] = "/bin/ls"
    assert runner._all_processes_stopped(
        jobs, attempts, [wrong_guardian, *processes[1:]], report
    ) is False

    failed = dict(complete)
    failed["status"] = "failed"
    failed["error"] = "failure"
    assert runner._all_processes_stopped(
        jobs, [failed, second, third], processes, report
    ) is False

    incomplete = dict(processes[0])
    incomplete.pop("start_seconds")

    assert runner._all_processes_stopped(
        jobs, attempts, [incomplete, *processes[1:]], report
    ) is False

    assert runner._all_processes_stopped(
        jobs, attempts, [processes[0], processes[0], processes[0]], report
    ) is False


def test_session_events_bind_exact_attempt_identity(tmp_path: Path) -> None:
    runner = RealProofRunner(root=tmp_path / "proof")
    job = {"id": "investigator-job", "role": "investigator"}
    attempt = _complete_process_attempt(runner)
    attempt.update(
        {
            "id": "investigator-attempt",
            "job_id": "investigator-job",
            "external_session_id": "session-1",
        }
    )
    events = _identity_events(
        attempt, job_id="investigator-job", completion="investigation_completed"
    )

    assert runner._session_events_precede_completion(
        [job], [attempt], [_process_from_attempt(attempt)], events
    ) is True

    events[1]["event_data"] = {
        "provider": "codex",
        "session_id": "wrong-session",
    }
    assert runner._session_events_precede_completion(
        [job], [attempt], [_process_from_attempt(attempt)], events
    ) is False


def test_artifact_events_bind_rows_before_process_stop() -> None:
    job = {"id": "investigator-job", "role": "investigator"}
    artifacts = [
        {
            "id": "artifact-%d" % index,
            "job_id": "investigator-job",
            "kind": kind,
            "uri": "/private/tmp/%s" % PROVIDER_ARTIFACT_NAMES[kind],
            "metadata": {"attempt_id": "investigator-attempt"},
        }
        for index, kind in enumerate(sorted(PROVIDER_ARTIFACT_NAMES), start=1)
    ]
    events = [
        {
            "job_id": "investigator-job",
            "event_type": "worker.external_session_recorded",
            "sequence": 1,
            "event_data": {},
        }
    ]
    events.extend(
        {
            "job_id": "investigator-job",
            "event_type": "artifact.added",
            "sequence": index + 1,
            "event_data": {
                "artifact_id": artifact["id"],
                "attempt_id": "investigator-attempt",
                "kind": artifact["kind"],
                "uri": artifact["uri"],
            },
        }
        for index, artifact in enumerate(artifacts, start=1)
    )
    events.append(
        {
            "job_id": "investigator-job",
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


def _write_jsonl_events(path: Path, events: list) -> None:
    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
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
                                    _investigator_result(), sort_keys=True
                                ),
                            },
                        }
                    ),
                    json.dumps({"type": "turn.completed"}),
                )
            ) + "\n"
        elif kind == "codex_schema":
            payload = json.dumps(
                codex_handoff_schema(WorkerRole.INVESTIGATOR), sort_keys=True
            ) + "\n"
        elif kind == "codex_final":
            payload = json.dumps(_investigator_result(), sort_keys=True) + "\n"
        else:
            payload = ""
        path.write_text(payload, encoding="utf-8")
        path.chmod(0o600)
        artifacts.append(
            {
                "job_id": "investigator-job",
                "item_id": "item-proof",
                "kind": kind,
                "uri": str(path),
                "metadata": {
                    "attempt_id": "investigator-attempt",
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


def _process_from_attempt(attempt: dict) -> dict:
    return {
        "attempt_id": attempt["id"],
        "provider": attempt["external_provider"],
        "process_id": attempt["external_process_id"],
        "process_group_id": attempt["external_process_group_id"],
        "owner_uid": attempt["external_process_owner_uid"],
        "start_seconds": attempt["external_process_start_seconds"],
        "start_microseconds": attempt["external_process_start_microseconds"],
        "kernel_executable": attempt["external_process_executable"],
        "target_executable": attempt["external_process_target_executable"],
        "identity_version": attempt["external_process_identity_version"],
        "state": attempt["external_process_state"],
        "outcome": attempt["external_process_outcome"],
        "stopped_at": attempt["external_process_stopped_at"],
        "last_error": attempt["external_process_last_error"],
    }


def _identity_events(
    attempt: dict, *, job_id: str, completion: str
) -> list:
    return [
        {
            "job_id": job_id,
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
            "job_id": job_id,
            "event_type": "worker.external_session_recorded",
            "sequence": 2,
            "event_data": {
                "provider": attempt["external_provider"],
                "session_id": attempt["external_session_id"],
            },
        },
        {
            "job_id": job_id,
            "event_type": "worker.external_process_stopped",
            "sequence": 3,
            "event_data": {
                "process_id": attempt["external_process_id"],
                "process_group_id": attempt["external_process_group_id"],
            },
        },
        {
            "job_id": job_id,
            "event_type": completion,
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


def _investigator_result() -> dict:
    return {
        "schema_version": 1,
        "item_id": "item-proof",
        "outcome": "ready_for_fix",
        "synopsis": "The focused addition test fails on subtraction.",
        "reproduction_steps": ["Inspect the focused unittest."],
        "root_cause": "calculator.add subtracts the right operand.",
        "proposed_fix": "Return left plus right in calculator.add.",
        "acceptance_criteria": ["The focused unittest passes."],
        "evidence": [
            {
                "id": "test-proof",
                "kind": "test",
                "location": "/private/tmp/test_calculator.py",
                "description": "Focused test evidence.",
                "metadata": {},
            }
        ],
        "blocker": None,
    }
