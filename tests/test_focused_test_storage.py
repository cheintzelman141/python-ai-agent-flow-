from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from typing import Any, Dict, Mapping

import pytest

from agent_flow.focused_sandbox import (
    direct_python_executable,
    profile_sha256 as focused_sandbox_profile_sha256,
)
from agent_flow.storage import (
    LeaseConflict,
    SCHEMA_VERSION,
    SQLiteStore,
    TransitionConflict,
    _SCHEMA_V1,
    _SCHEMA_V2,
    _SCHEMA_V3,
    _SCHEMA_V4,
    _SCHEMA_V5,
    _SCHEMA_V6,
    _SCHEMA_V7,
    _SCHEMA_V8,
    _SCHEMA_V9,
)
from agent_flow.worktrees import ManagedWorktreeConfig, ManagedWorktreeManager


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repository(path: Path) -> Path:
    path.mkdir(parents=True)
    subprocess.run(("git", "init", "-q", str(path)), check=True)
    _git(path, "config", "user.name", "Agent Flow Tests")
    _git(path, "config", "user.email", "agent-flow@example.invalid")
    (path / "calculator.py").write_text(
        "def add(left, right):\n    return left + right\n", encoding="utf-8"
    )
    (path / "test_calculator.py").write_text(
        """import unittest
from calculator import add

class CalculatorTests(unittest.TestCase):
    def test_adds_two_numbers(self):
        self.assertEqual(add(2, 3), 5)

if __name__ == "__main__":
    unittest.main()
""",
        encoding="utf-8",
    )
    _git(path, "add", "calculator.py", "test_calculator.py")
    _git(path, "commit", "-q", "-m", "fixture")
    return path.resolve()


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)


def _managed_tester(
    store: SQLiteStore, tmp_path: Path
) -> tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    repository = _repository(tmp_path / "repo")
    campaign = store.create_campaign(
        "focused storage",
        config={"repository_paths": [str(repository)]},
    )
    item = store.create_work_item(
        campaign["id"],
        "focused fixture",
        description="Prove an authoritative focused unittest execution.",
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
        scope={"repository_paths": [str(repository)]},
    )
    store.resolve_approval(approval["id"], "approved", "test-owner")
    manager = ManagedWorktreeManager(
        store,
        owner="focused-storage-test",
        config=ManagedWorktreeConfig(
            worktree_root=(tmp_path / "worktrees").resolve(),
            runtime_root=(tmp_path / "git-runtime").resolve(),
            command_timeout_seconds=5,
            terminate_grace_seconds=1,
            operation_lease_seconds=30,
        ),
    )
    worktree = manager.provision(campaign["id"], item["id"], repository, "HEAD")
    fixer = store.claim_job("fixer", "fixer-worker")
    assert fixer is not None
    completed = store.commit_stage_result(
        fixer["id"],
        "fixer-worker",
        fixer["lease_token"],
        {
            "schema_version": 1,
            "item_id": item["id"],
            "outcome": "ready_for_test",
            "summary": "The fixed disposable fixture is ready for focused proof.",
            "changed_files": ["calculator.py"],
            "tests_run": [],
            "tester_instructions": ["Run the exact focused unittest selector."],
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
    manifest = store._scan_focused_workspace(Path(worktree["worktree_path"]))
    plan = store.create_focused_test_plan(
        item["id"],
        executable_path=str(Path(sys.executable).resolve()),
        test_file="test_calculator.py",
        selector="CalculatorTests.test_adds_two_numbers",
        workspace_manifest=manifest,
        runtime_root=str((tmp_path / "focused-runtime").resolve()),
        timeout_seconds=10,
        output_limit_bytes=16 * 1024,
    )
    store.create_focused_test_admission(
        campaign["id"],
        item["id"],
        completed["next_job"]["id"],
        worktree["id"],
        plan["id"],
        [],
        admitted_by="focused-storage-test",
        reason="authorize the exact focused storage fixture",
    )
    tester = store.claim_job("tester", "tester-worker")
    assert tester is not None
    assert tester["id"] == completed["next_job"]["id"]
    return item, worktree, plan, tester


def _stop_focused_process(
    store: SQLiteStore, tester: Mapping[str, Any], process_id: int = 41001
) -> None:
    executable = str(Path(sys.executable).resolve())
    execution = store.list_focused_test_executions(
        attempt_id=str(tester["attempt_id"])
    )[0]
    target = str(execution["sandbox_executable_path"])
    store.record_external_process(
        tester["id"],
        "tester-worker",
        tester["lease_token"],
        "focused_test",
        process_id,
        process_id,
        os.getuid(),
        executable,
        process_id,
        1,
        target,
    )
    store.clear_external_process(
        tester["id"],
        "tester-worker",
        tester["lease_token"],
        process_id,
        process_id,
    )


def _execution_packet(
    execution: Mapping[str, Any], *, passed: bool = True
) -> Dict[str, Any]:
    run_parent = Path(execution["run_parent"])
    environment_root = run_parent / "environment"
    _private_directory(environment_root)
    _private_directory(environment_root / "home")
    _private_directory(environment_root / "tmp")
    artifacts = Path(execution["artifact_directory"])
    _private_directory(artifacts)
    stdout = Path(execution["stdout_path"])
    stderr = Path(execution["stderr_path"])
    stdout.write_text("AGENT_FLOW_TEST_FILE=test_calculator.py\n", encoding="utf-8")
    if passed:
        stderr.write_text(
            "test_adds_two_numbers (__main__.CalculatorTests) ... ok\n\n"
            "----------------------------------------------------------------------\n"
            "Ran 1 test in 0.001s\n\nOK\n",
            encoding="utf-8",
        )
        exit_code = 0
    else:
        stderr.write_text(
            "test_adds_two_numbers (__main__.CalculatorTests) ... FAIL\n\n"
            "======================================================================\n"
            "FAIL: test_adds_two_numbers (__main__.CalculatorTests)\n"
            "----------------------------------------------------------------------\n"
            "Traceback (most recent call last):\n  assertion failed\n\n"
            "----------------------------------------------------------------------\n"
            "Ran 1 test in 0.001s\n\nFAILED (failures=1)\n",
            encoding="utf-8",
        )
        exit_code = 1
    os.chmod(stdout, 0o600)
    os.chmod(stderr, 0o600)
    return {
        "execution_id": execution["id"],
        "command": execution["command"],
        "cwd": execution["cwd"],
        "artifact_directory": execution["artifact_directory"],
        "workspace_manifest": execution["workspace_manifest"],
        "exit_code": exit_code,
        "stdout_path": str(stdout),
        "stderr_path": str(stderr),
        "stdout_sha256": hashlib.sha256(stdout.read_bytes()).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.read_bytes()).hexdigest(),
        "stdout_bytes": stdout.stat().st_size,
        "stderr_bytes": stderr.stat().st_size,
        "stdout_truncated": False,
        "stderr_truncated": False,
    }


def _complete(
    store: SQLiteStore,
    tester: Mapping[str, Any],
    execution: Mapping[str, Any],
    *,
    passed: bool = True,
    process_id: int = 41001,
) -> Dict[str, Any]:
    packet = _execution_packet(execution, passed=passed)
    _stop_focused_process(store, tester, process_id)
    return store.complete_focused_test_execution(
        tester["id"], "tester-worker", tester["lease_token"], packet
    )


def test_schema_v5_migrates_focused_tables_and_attempt_artifact_fk(
    tmp_path: Path,
) -> None:
    path = tmp_path / "schema-v5.sqlite3"
    connection = sqlite3.connect(str(path))
    try:
        for statements in (_SCHEMA_V1, _SCHEMA_V2, _SCHEMA_V3, _SCHEMA_V4, _SCHEMA_V5):
            for statement in statements:
                connection.execute(statement)
        connection.execute("PRAGMA user_version = 5")
        connection.commit()
    finally:
        connection.close()

    with SQLiteStore(path) as store:
        assert store._connection.execute("PRAGMA user_version").fetchone()[0] == 11
        tables = {
            row["name"]
            for row in store._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        artifact_columns = {
            row["name"]
            for row in store._connection.execute("PRAGMA table_info(artifacts)").fetchall()
        }
        artifact_fks = {
            (row["from"], row["table"])
            for row in store._connection.execute(
                "PRAGMA foreign_key_list(artifacts)"
            ).fetchall()
        }

    assert SCHEMA_VERSION == 11
    assert {"focused_test_plans", "focused_test_executions"}.issubset(tables)
    assert "attempt_id" in artifact_columns
    assert ("attempt_id", "attempts") in artifact_fks


def test_schema_v9_migrates_exact_sandbox_contract_columns(
    tmp_path: Path,
) -> None:
    path = tmp_path / "schema-v9.sqlite3"
    connection = sqlite3.connect(str(path))
    try:
        for statements in (
            _SCHEMA_V1,
            _SCHEMA_V2,
            _SCHEMA_V3,
            _SCHEMA_V4,
            _SCHEMA_V5,
            _SCHEMA_V6,
            _SCHEMA_V7,
            _SCHEMA_V8,
            _SCHEMA_V9,
        ):
            for statement in statements:
                connection.execute(statement)
        connection.execute("PRAGMA user_version = 9")
        connection.commit()
    finally:
        connection.close()

    with SQLiteStore(path) as store:
        version = store._connection.execute("PRAGMA user_version").fetchone()[0]
        plan_columns = {
            row["name"]
            for row in store._connection.execute(
                "PRAGMA table_info(focused_test_plans)"
            ).fetchall()
        }
        execution_columns = {
            row["name"]
            for row in store._connection.execute(
                "PRAGMA table_info(focused_test_executions)"
            ).fetchall()
        }
        foreign_key_violations = store.foreign_key_violations()

    assert version == 11
    assert {
        "sandbox_policy_version",
        "sandbox_executable_path",
        "sandbox_executable_sha256",
        "python_runtime_root",
        "python_runtime_sha256",
    }.issubset(plan_columns)
    assert {
        "sandbox_policy_version",
        "sandbox_executable_path",
        "sandbox_executable_sha256",
        "python_runtime_root",
        "python_runtime_sha256",
        "sandbox_profile",
        "sandbox_profile_sha256",
        "test_command_argv_json",
        "test_command_argv_sha256",
    }.issubset(execution_columns)
    assert foreign_key_violations == []


def test_plan_rejects_shell_module_selector_and_payload_command_authority(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        campaign = store.create_campaign("plan validation")
        item = store.create_work_item(
            campaign["id"],
            "plan",
            description="Validate the exact plan authority.",
            state="ready_for_test",
            required_gates=["focused_tests"],
        )
        test_file = tmp_path / "test_fixture.py"
        test_file.write_text("pass\n", encoding="utf-8")
        details = test_file.lstat()
        manifest = {
            "test_fixture.py": {
                "sha256": hashlib.sha256(test_file.read_bytes()).hexdigest(),
                "mode": details.st_mode,
            }
        }
        common = {
            "test_file": "test_fixture.py",
            "selector": "FixtureTests.test_exact",
            "workspace_manifest": manifest,
            "runtime_root": str((tmp_path / "runtime").resolve()),
        }

        with pytest.raises(ValueError, match="Python interpreter"):
            store.create_focused_test_plan(
                item["id"], executable_path="/bin/sh", **common
            )
        with pytest.raises(ValueError, match="ClassName.test_method"):
            store.create_focused_test_plan(
                item["id"],
                executable_path=str(Path(sys.executable).resolve()),
                **{**common, "selector": "module.FixtureTests.test_exact"},
            )

        plan = store.create_focused_test_plan(
            item["id"],
            executable_path=str(Path(sys.executable).resolve()),
            **common,
        )
        with pytest.raises(TransitionConflict, match="cannot change test authority"):
            store.create_focused_test_plan(
                item["id"],
                executable_path=str(Path(sys.executable).resolve()),
                **{**common, "selector": "FixtureTests.test_other"},
            )
        changed_manifest = {
            "test_fixture.py": {
                "sha256": "0" * 64,
                "mode": details.st_mode,
            }
        }
        with pytest.raises(TransitionConflict, match="trusted test file"):
            store.create_focused_test_plan(
                item["id"],
                executable_path=str(Path(sys.executable).resolve()),
                **{**common, "workspace_manifest": changed_manifest},
            )

    assert plan["test_file"] == "test_fixture.py"
    assert "command" not in plan
    assert plan["environment"] == {
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONHASHSEED": "0",
    }


def test_migrated_v9_plan_requires_and_accepts_one_sandboxed_revision(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        campaign = store.create_campaign("legacy focused plan")
        item = store.create_work_item(
            campaign["id"],
            "legacy plan",
            description="Replace legacy test authority before execution.",
            state="ready_for_test",
            required_gates=["focused_tests"],
        )
        test_file = tmp_path / "test_fixture.py"
        test_file.write_text("pass\n", encoding="utf-8")
        details = test_file.lstat()
        manifest = {
            "test_fixture.py": {
                "sha256": hashlib.sha256(test_file.read_bytes()).hexdigest(),
                "mode": details.st_mode,
            }
        }
        authority = {
            "executable_path": str(Path(sys.executable).resolve()),
            "test_file": "test_fixture.py",
            "selector": "FixtureTests.test_exact",
            "workspace_manifest": manifest,
            "runtime_root": str((tmp_path / "runtime").resolve()),
        }
        first = store.create_focused_test_plan(item["id"], **authority)
        store._connection.execute(
            """UPDATE focused_test_plans
               SET sandbox_policy_version = NULL,
                   sandbox_executable_path = NULL,
                   sandbox_executable_device = NULL,
                   sandbox_executable_inode = NULL,
                   sandbox_executable_owner_uid = NULL,
                   sandbox_executable_mode = NULL,
                   sandbox_executable_sha256 = NULL,
                   python_runtime_root = NULL,
                   python_runtime_sha256 = NULL
               WHERE id = ?""",
            (first["id"],),
        )

        second = store.create_focused_test_plan(item["id"], **authority)

    assert second["plan_number"] == 2
    assert second["sandbox_policy_version"] == "darwin-seatbelt-v1"
    assert second["python_runtime_sha256"] is not None


def test_current_attempt_pass_is_canonical_and_attempt_bound(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        item, _worktree, plan, tester = _managed_tester(store, tmp_path)
        execution = store.prepare_focused_test_execution(
            tester["id"], "tester-worker", tester["lease_token"]
        )
        assert execution["test_command_argv"] == [
            str(direct_python_executable(Path(sys.executable).resolve())),
            "-I",
            "-B",
            str(Path(execution["cwd"]) / "test_calculator.py"),
            "CalculatorTests.test_adds_two_numbers",
            "-v",
        ]
        assert execution["command"] == [
            plan["sandbox_executable_path"],
            "-p",
            execution["sandbox_profile"],
            *execution["test_command_argv"],
        ]
        assert not Path(execution["artifact_directory"]).exists()
        completed = _complete(store, tester, execution)
        assert completed["outcome"] == "pass"
        assert completed["canonical_handoff"]["outcome"] == "pass"
        persisted = store.list_focused_test_executions(attempt_id=tester["attempt_id"])
        assert persisted[0]["canonical_handoff"] == completed["canonical_handoff"]

        result = store.commit_stage_result(
            tester["id"],
            "tester-worker",
            tester["lease_token"],
            {
                "schema_version": 1,
                "item_id": "untrusted-item",
                "outcome": "red",
                "summary": "Untrusted and ignored.",
                "gate_proofs": [],
            },
            "testing",
            "verified_green",
            "test.verified_green",
        )
        artifacts = store.list_artifacts(item["id"])
        foreign_key_violations = store.foreign_key_violations()

    assert result["work_item"]["state"] == "verified_green"
    assert {artifact["kind"] for artifact in artifacts} == {
        "focused_test_stdout",
        "focused_test_stderr",
    }
    assert {artifact["attempt_id"] for artifact in artifacts} == {tester["attempt_id"]}
    assert foreign_key_violations == []


def test_admitted_nonzero_result_blocks_without_authorizing_a_fixer(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        item, _worktree, _plan, tester = _managed_tester(store, tmp_path)
        execution = store.prepare_focused_test_execution(
            tester["id"], "tester-worker", tester["lease_token"]
        )
        completed = _complete(store, tester, execution, passed=False)
        assert completed["canonical_handoff"]["outcome"] == "blocked"
        assert completed["canonical_handoff"]["blocker"]["kind"] == "execution"
        result = store.commit_stage_result(
            tester["id"],
            "tester-worker",
            tester["lease_token"],
            {
                "schema_version": 1,
                "item_id": item["id"],
                "outcome": "pass",
                "summary": "A forged pass must not win.",
                "gate_proofs": [],
            },
            "testing",
            "blocked",
            "test_blocked",
        )
        pending_fixers = [
            job
            for job in store.list_jobs(work_item_id=item["id"])
            if job["role"] == "fixer" and job["status"] == "pending"
        ]
        blocked_events = [
            event
            for event in store.list_events(work_item_id=item["id"])
            if event["event_type"] == "test_blocked"
        ]

    assert result["work_item"]["state"] == "blocked"
    assert result["job"]["result"]["outcome"] == "blocked"
    assert len(result["job"]["result"]["blocker"]["evidence"]) == 2
    assert pending_fixers == []
    assert len(blocked_events) == 1


def test_new_plan_revision_requires_a_new_exact_admission_before_claim(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        item, worktree, first_plan, first_tester = _managed_tester(store, tmp_path)
        store.prepare_focused_test_execution(
            first_tester["id"], "tester-worker", first_tester["lease_token"]
        )
        store.interrupt_job(
            first_tester["id"],
            "tester-worker",
            first_tester["lease_token"],
            reason="new revision requires fresh authority",
        )
        worktree_path = Path(worktree["worktree_path"])
        second_plan = store.create_focused_test_plan(
            item["id"],
            executable_path=str(Path(sys.executable).resolve()),
            test_file="test_calculator.py",
            selector="CalculatorTests.test_adds_two_numbers",
            workspace_manifest=store._scan_focused_workspace(worktree_path),
            runtime_root=str((tmp_path / "focused-runtime").resolve()),
            timeout_seconds=10,
            output_limit_bytes=16 * 1024,
        )
        second_tester = store.claim_job("tester", "tester-worker")
        plans = store.list_focused_test_plans(item["id"])

    assert [plan["plan_number"] for plan in plans] == [1, 2]
    assert first_plan["id"] != second_plan["id"]
    assert second_tester is None


def test_stale_attempt_cannot_prepare_or_reuse_prior_execution(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        _item, _worktree, _plan, first = _managed_tester(store, tmp_path)
        first_execution = store.prepare_focused_test_execution(
            first["id"], "tester-worker", first["lease_token"]
        )
        store.interrupt_job(
            first["id"], "tester-worker", first["lease_token"], reason="retry proof"
        )
        with pytest.raises(LeaseConflict):
            store.prepare_focused_test_execution(
                first["id"], "tester-worker", first["lease_token"]
            )
        second = store.claim_job("tester", "tester-worker")
        assert second is not None
        second_execution = store.prepare_focused_test_execution(
            second["id"], "tester-worker", second["lease_token"]
        )
        first_status = store.list_focused_test_executions(
            attempt_id=first["attempt_id"]
        )[0]["status"]

    assert first_execution["attempt_id"] != second_execution["attempt_id"]
    assert first_execution["id"] != second_execution["id"]
    assert first_status == "abandoned"


def test_symlink_output_and_post_completion_mutation_are_rejected(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        item, _worktree, _plan, tester = _managed_tester(store, tmp_path)
        execution = store.prepare_focused_test_execution(
            tester["id"], "tester-worker", tester["lease_token"]
        )
        packet = _execution_packet(execution)
        stdout = Path(execution["stdout_path"])
        target = stdout.with_name("outside.log")
        stdout.replace(target)
        stdout.symlink_to(target)
        _stop_focused_process(store, tester)
        with pytest.raises(LeaseConflict, match="single-link regular file"):
            store.complete_focused_test_execution(
                tester["id"], "tester-worker", tester["lease_token"], packet
            )

    with SQLiteStore(tmp_path / "second.sqlite3") as store:
        item, _worktree, _plan, tester = _managed_tester(store, tmp_path / "second")
        execution = store.prepare_focused_test_execution(
            tester["id"], "tester-worker", tester["lease_token"]
        )
        completed = _complete(store, tester, execution, process_id=41002)
        stdout = Path(completed["stdout_path"])
        stdout.write_text("mutated\n", encoding="utf-8")
        os.chmod(stdout, 0o600)
        with pytest.raises(LeaseConflict, match="artifact changed"):
            store.commit_stage_result(
                tester["id"],
                "tester-worker",
                tester["lease_token"],
                completed["canonical_handoff"],
                "testing",
                "verified_green",
                "test.verified_green",
            )
        assert store.get_work_item(item["id"])["state"] == "testing"


def test_persisted_sandbox_profile_drift_cannot_complete_or_finalize(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        item, _worktree, _plan, tester = _managed_tester(store, tmp_path)
        execution = store.prepare_focused_test_execution(
            tester["id"], "tester-worker", tester["lease_token"]
        )
        packet = _execution_packet(execution)
        _stop_focused_process(store, tester)
        broadened = execution["sandbox_profile"] + "(allow network*)\n"
        store._connection.execute(
            """UPDATE focused_test_executions
               SET sandbox_profile = ?, sandbox_profile_sha256 = ?
               WHERE id = ?""",
            (
                broadened,
                focused_sandbox_profile_sha256(broadened),
                execution["id"],
            ),
        )

        with pytest.raises(LeaseConflict, match="profile changed"):
            store.complete_focused_test_execution(
                tester["id"], "tester-worker", tester["lease_token"], packet
            )

        assert store.get_work_item(item["id"])["state"] == "testing"
        persisted = store.list_focused_test_executions(
            attempt_id=tester["attempt_id"]
        )[0]

    assert persisted["status"] == "prepared"
    assert persisted["outcome"] is None
