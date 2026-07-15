from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import uuid

import pytest

from agent_flow.evidence_pipeline import EvidencePipelineWorker
from agent_flow.models import TestHandoff as DomainTestHandoff
from agent_flow.process_reconciler import DarwinProcessRuntime, ProcessIdentity
from agent_flow.storage import SQLiteStore
from agent_flow.workers import WorkerContext
from agent_flow.worktrees import (
    GuardedGitCommandRunner,
    ManagedWorktreeConfig,
    ManagedWorktreeManager,
)


class PassingFocusedWorker:
    def __init__(self, proof: Path) -> None:
        self.proof = proof

    async def run(self, context: WorkerContext) -> DomainTestHandoff:
        return DomainTestHandoff.model_validate(
            {
                "item_id": context.item_id,
                "outcome": "pass",
                "summary": "fixed focused selector passed",
                "gate_proofs": [
                    {
                        "gate": "focused_tests",
                        "result": "pass",
                        "summary": "fixed focused selector passed",
                        "evidence": [
                            {
                                "kind": "test",
                                "location": str(self.proof),
                                "description": "Disposable focused-test proof.",
                            }
                        ],
                    }
                ],
            }
        )


@pytest.fixture
def pipeline_root():
    root = Path("/private/tmp/agent-flow-pipeline-%s" % uuid.uuid4().hex)
    root.mkdir(mode=0o700)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_fixed_pipeline_runs_guarded_visible_chrome_and_read_only_database(
    tmp_path: Path, pipeline_root: Path, monkeypatch
) -> None:
    fixture = pipeline_root / "fixture.html"
    fixture.write_text(
        "<title>Agent Flow Pipeline</title><main>pipeline-ready</main>",
        encoding="utf-8",
    )
    fixture.chmod(0o600)
    proof = pipeline_root / "focused-proof.txt"
    proof.write_text("focused selector passed\n", encoding="utf-8")
    proof.chmod(0o600)
    database_path = pipeline_root / "tenant_pipeline.sqlite3"
    with sqlite3.connect(str(database_path)) as database:
        database.execute(
            "CREATE TABLE proof_accounts (account_id TEXT PRIMARY KEY, status TEXT NOT NULL)"
        )
        database.execute(
            "INSERT INTO proof_accounts VALUES ('ACCT-PIPELINE', 'active')"
        )
    database_path.chmod(0o600)
    before_database = hashlib.sha256(database_path.read_bytes()).hexdigest()
    monkeypatch.setenv("AGENT_FLOW_PIPELINE_DATABASE", str(database_path))
    browser_runtime = pipeline_root / "browser-runtime"
    database_runtime = pipeline_root / "database-runtime"
    browser_runtime.mkdir(mode=0o700)
    database_runtime.mkdir(mode=0o700)

    with SQLiteStore(tmp_path / "pipeline.sqlite3") as store:
        campaign = store.create_campaign("fixed evidence pipeline")
        chrome = store.define_resource(
            "chrome_profile",
            "Disposable visible Chrome",
            {
                "user_data_dir": str(pipeline_root / "chrome-profile"),
                "profile_directory": "Profile 1",
            },
            actor="pipeline-test",
            campaign_id=campaign["id"],
        )
        database = store.define_resource(
            "tenant_database",
            "Disposable tenant database",
            {
                "tenant_key": "pipeline-tenant",
                "database_name": "tenant_pipeline",
                "connection_env": "AGENT_FLOW_PIPELINE_DATABASE",
            },
            actor="pipeline-test",
            campaign_id=campaign["id"],
        )
        item = store.create_work_item(
            campaign["id"],
            "fixed three-gate pipeline",
            description="Run fixed focused, browser, and database collectors.",
            state="ready_for_test",
            required_gates=["focused_tests", "browser", "database"],
            initial_job={
                "role": "tester",
                "stage": "test",
                "active_item_state": "testing",
                "required_resources": [chrome["id"], database["id"]],
            },
        )
        browser_plan = store.create_browser_evidence_plan(
            item["id"],
            chrome["id"],
            route=fixture.as_uri(),
            expected_title="Agent Flow Pipeline",
            expected_body_text="pipeline-ready",
            runtime_root=browser_runtime,
            timeout_seconds=15,
        )
        database_plan = store.create_database_query_plan(
            item["id"],
            database["id"],
            statement=(
                "SELECT account_id, status FROM proof_accounts "
                "WHERE account_id = ?"
            ),
            parameters=("ACCT-PIPELINE",),
            id_column="account_id",
            expected_ids=("ACCT-PIPELINE",),
            expected_row_count=1,
            max_rows=5,
            max_bytes=4096,
            timeout_seconds=2,
            runtime_root=database_runtime,
        )
        claim = store.claim_job("tester", "pipeline-worker", lease_seconds=60)
        assert claim is not None

        context = WorkerContext(
            campaign=campaign,
            item=item,
            job=claim,
            _external_process_recorder=lambda provider, identity, target: (
                store.record_external_process(
                    claim["id"],
                    "pipeline-worker",
                    claim["lease_token"],
                    provider,
                    identity.process_id,
                    identity.process_group_id,
                    identity.user_id,
                    identity.executable,
                    identity.start_seconds,
                    identity.start_microseconds,
                    target,
                )
            ),
            _external_process_clearer=lambda process_id, process_group_id: (
                store.clear_external_process(
                    claim["id"],
                    "pipeline-worker",
                    claim["lease_token"],
                    process_id,
                    process_group_id,
                )
            ),
            _browser_evidence_execution_preparer=lambda: (
                store.prepare_browser_evidence_execution(
                    browser_plan["id"],
                    claim["id"],
                    "pipeline-worker",
                    claim["lease_token"],
                )
            ),
            _browser_evidence_execution_completer=lambda result: (
                store.complete_browser_evidence_execution(
                    claim["id"],
                    "pipeline-worker",
                    claim["lease_token"],
                    result,
                )
            ),
            _database_query_execution_preparer=lambda: (
                store.prepare_database_query_execution(
                    database_plan["id"],
                    claim["id"],
                    "pipeline-worker",
                    claim["lease_token"],
                )
            ),
            _database_query_execution_completer=lambda result: (
                store.complete_database_query_execution(
                    claim["id"],
                    "pipeline-worker",
                    claim["lease_token"],
                    result,
                )
            ),
        )
        runner = GuardedGitCommandRunner(
            runtime=DarwinProcessRuntime(),
            timeout_seconds=20,
            terminate_grace_seconds=3,
            max_output_bytes=1024 * 1024,
        )
        worker = EvidencePipelineWorker(runner)
        worker.focused_worker = PassingFocusedWorker(proof)  # type: ignore[assignment]
        handoff = DomainTestHandoff.model_validate(asyncio.run(worker.run(context)))

        assert handoff.outcome.value == "pass"
        assert [proof.gate.value for proof in handoff.gate_proofs] == [
            "focused_tests",
            "browser",
            "database",
        ]
        browser_execution = store.list_browser_evidence_executions(
            work_item_id=item["id"]
        )[0]
        database_execution = store.list_database_query_executions(
            work_item_id=item["id"]
        )[0]
        assert browser_execution["outcome"] == "pass"
        assert Path(browser_execution["screenshot_path"]).is_file()
        assert database_execution["outcome"] == "pass"
        assert database_execution["observed_ids"] == ["ACCT-PIPELINE"]
        assert database_execution["read_only_proof"]["foreign_key_violations"] == 0
        assert hashlib.sha256(database_path.read_bytes()).hexdigest() == before_database
        processes = store.list_external_processes()
        assert len(processes) == 1
        assert processes[0]["provider"] == "browser_evidence"
        assert processes[0]["state"] == "stopped"
        assert store.foreign_key_violations() == []


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_storage_replaces_forged_handoff_with_three_canonical_gate_proofs(
    tmp_path: Path, pipeline_root: Path, monkeypatch
) -> None:
    repository = pipeline_root / "repository"
    repository.mkdir()
    subprocess.run(("git", "init", "-q", str(repository)), check=True)
    _git(repository, "config", "user.name", "Agent Flow Tests")
    _git(repository, "config", "user.email", "agent-flow@example.invalid")
    (repository / "calculator.py").write_text(
        "def add(left, right):\n    return left + right\n", encoding="utf-8"
    )
    (repository / "test_calculator.py").write_text(
        """import unittest

def add(left, right):
    return left + right

class CalculatorTests(unittest.TestCase):
    def test_adds_two_numbers(self):
        self.assertEqual(add(2, 3), 5)

if __name__ == "__main__":
    unittest.main()
""",
        encoding="utf-8",
    )
    _git(repository, "add", "calculator.py", "test_calculator.py")
    _git(repository, "commit", "-q", "-m", "fixture")
    route = pipeline_root / "canonical.html"
    route.write_text(
        "<title>Canonical Pipeline</title><main>canonical-ready</main>",
        encoding="utf-8",
    )
    route.chmod(0o600)
    database_path = pipeline_root / "tenant_canonical.sqlite3"
    with sqlite3.connect(str(database_path)) as database_connection:
        database_connection.execute(
            "CREATE TABLE proof_accounts (account_id TEXT PRIMARY KEY, status TEXT NOT NULL)"
        )
        database_connection.execute(
            "INSERT INTO proof_accounts VALUES ('ACCT-CANONICAL', 'active')"
        )
    database_path.chmod(0o600)
    monkeypatch.setenv("AGENT_FLOW_CANONICAL_DATABASE", str(database_path))
    for name in ("browser-runtime", "database-runtime"):
        (pipeline_root / name).mkdir(mode=0o700)

    with SQLiteStore(tmp_path / "canonical-pipeline.sqlite3") as store:
        campaign = store.create_campaign(
            "canonical fixed pipeline",
            config={"repository_paths": [str(repository.resolve())]},
        )
        chrome = store.define_resource(
            "chrome_profile",
            "Canonical Chrome",
            {
                "user_data_dir": str(pipeline_root / "canonical-profile"),
                "profile_directory": "Default",
            },
            actor="pipeline-test",
            campaign_id=campaign["id"],
        )
        database = store.define_resource(
            "tenant_database",
            "Canonical tenant",
            {
                "tenant_key": "canonical-tenant",
                "database_name": "tenant_canonical",
                "connection_env": "AGENT_FLOW_CANONICAL_DATABASE",
            },
            actor="pipeline-test",
            campaign_id=campaign["id"],
        )
        item = store.create_work_item(
            campaign["id"],
            "canonical gate replacement",
            description="Storage owns all three authoritative gate proofs.",
            required_gates=["focused_tests", "browser", "database"],
            initial_job={
                "role": "investigator",
                "stage": "investigate",
                "active_item_state": "investigating",
            },
        )
        approval = store.create_approval(
            campaign["id"],
            "local_code_changes",
            "pipeline-test",
            scope={"repository_paths": [str(repository.resolve())]},
        )
        store.resolve_approval(approval["id"], "approved", "pipeline-test")
        investigator = store.claim_job("investigator", "investigator-worker")
        assert investigator is not None
        investigated = store.commit_stage_result(
            investigator["id"],
            "investigator-worker",
            investigator["lease_token"],
            {
                "item_id": item["id"],
                "outcome": "ready_for_fix",
                "synopsis": "Disposable fixture is ready for the managed fix stage.",
                "reproduction_steps": ["Run the exact disposable pipeline."],
                "root_cause": "The fixture requires its bounded proof workflow.",
                "proposed_fix": "Use the managed worktree without changing fixture bytes.",
                "acceptance_criteria": ["All three fixed gates pass."],
                "evidence": [{
                    "kind": "log",
                    "location": str(route),
                    "description": "Disposable investigation fixture.",
                }],
            },
            "investigating",
            "ready_for_fix",
            "investigation.completed",
            next_job={
                "role": "fixer",
                "stage": "fix",
                "active_item_state": "fixing",
                "required_approval_action": "local_code_changes",
            },
        )
        manager = ManagedWorktreeManager(
            store,
            owner="pipeline-test",
            config=ManagedWorktreeConfig(
                worktree_root=pipeline_root / "worktrees",
                runtime_root=pipeline_root / "git-runtime",
                command_timeout_seconds=5,
                terminate_grace_seconds=1,
                operation_lease_seconds=30,
            ),
        )
        worktree = manager.provision(
            campaign["id"], item["id"], repository.resolve(), "HEAD"
        )
        fixer = store.claim_job("fixer", "fixer-worker")
        assert fixer is not None and fixer["id"] == investigated["next_job"]["id"]
        fixed = store.commit_stage_result(
            fixer["id"],
            "fixer-worker",
            fixer["lease_token"],
            {
                "item_id": item["id"],
                "outcome": "ready_for_test",
                "summary": "Disposable fixture is ready.",
                "changed_files": ["calculator.py"],
                "tester_instructions": ["Run fixed pipeline."],
            },
            "fixing",
            "ready_for_test",
            "fix.completed",
            next_job={
                "role": "tester",
                "stage": "test",
                "active_item_state": "testing",
                "required_resources": [chrome["id"], database["id"]],
            },
        )
        manifest = store._scan_focused_workspace(Path(worktree["worktree_path"]))
        focused_plan = store.create_focused_test_plan(
            item["id"],
            executable_path=str(Path(sys.executable).resolve()),
            test_file="test_calculator.py",
            selector="CalculatorTests.test_adds_two_numbers",
            workspace_manifest=manifest,
            runtime_root=str(pipeline_root / "focused-runtime"),
            timeout_seconds=10,
            output_limit_bytes=16 * 1024,
        )
        browser_plan = store.create_browser_evidence_plan(
            item["id"],
            chrome["id"],
            route=route.as_uri(),
            expected_title="Canonical Pipeline",
            expected_body_text="canonical-ready",
            runtime_root=pipeline_root / "browser-runtime",
            timeout_seconds=15,
        )
        database_plan = store.create_database_query_plan(
            item["id"],
            database["id"],
            statement="SELECT account_id, status FROM proof_accounts WHERE account_id = ?",
            parameters=("ACCT-CANONICAL",),
            id_column="account_id",
            expected_ids=("ACCT-CANONICAL",),
            expected_row_count=1,
            max_rows=5,
            max_bytes=4096,
            timeout_seconds=2,
            runtime_root=pipeline_root / "database-runtime",
        )
        store.create_focused_test_admission(
            campaign["id"],
            item["id"],
            fixed["next_job"]["id"],
            worktree["id"],
            focused_plan["id"],
            [chrome["id"], database["id"]],
            admitted_by="pipeline-test",
            reason="authorize the exact fixed three-gate fixture",
        )
        tester = store.claim_job("tester", "tester-worker", lease_seconds=60)
        assert tester is not None and tester["id"] == fixed["next_job"]["id"]
        context = WorkerContext(
            campaign=campaign,
            item=store.get_work_item(item["id"]),
            job=tester,
            _external_process_recorder=lambda provider, identity, target: (
                store.record_external_process(
                    tester["id"], "tester-worker", tester["lease_token"],
                    provider, identity.process_id, identity.process_group_id,
                    identity.user_id, identity.executable,
                    identity.start_seconds, identity.start_microseconds, target,
                )
            ),
            _external_process_clearer=lambda process_id, process_group_id: (
                store.clear_external_process(
                    tester["id"], "tester-worker", tester["lease_token"],
                    process_id, process_group_id,
                )
            ),
            _focused_test_guardian_release_fencer=(
                lambda identity, target: store.focused_test_guardian_release_fence(
                    tester["id"],
                    "tester-worker",
                    tester["lease_token"],
                    identity.process_id,
                    identity.process_group_id,
                    identity.user_id,
                    identity.executable,
                    identity.start_seconds,
                    identity.start_microseconds,
                    target,
                )
            ),
            _focused_test_execution_preparer=lambda: (
                store.prepare_focused_test_execution(
                    tester["id"], "tester-worker", tester["lease_token"]
                )
            ),
            _focused_test_execution_completer=lambda result: (
                store.complete_focused_test_execution(
                    tester["id"], "tester-worker", tester["lease_token"], result
                )
            ),
            _browser_evidence_execution_preparer=lambda: (
                store.prepare_browser_evidence_execution(
                    browser_plan["id"], tester["id"], "tester-worker",
                    tester["lease_token"],
                )
            ),
            _browser_evidence_execution_completer=lambda result: (
                store.complete_browser_evidence_execution(
                    tester["id"], "tester-worker", tester["lease_token"], result
                )
            ),
            _database_query_execution_preparer=lambda: (
                store.prepare_database_query_execution(
                    database_plan["id"], tester["id"], "tester-worker",
                    tester["lease_token"],
                )
            ),
            _database_query_execution_completer=lambda result: (
                store.complete_database_query_execution(
                    tester["id"], "tester-worker", tester["lease_token"], result
                )
            ),
        )
        focused_runner = GuardedGitCommandRunner(
            runtime=DarwinProcessRuntime(),
            timeout_seconds=10,
            terminate_grace_seconds=3,
            max_output_bytes=16 * 1024,
        )
        browser_runner = GuardedGitCommandRunner(
            runtime=DarwinProcessRuntime(),
            timeout_seconds=20,
            terminate_grace_seconds=3,
            max_output_bytes=1024 * 1024,
        )
        pipeline_handoff = DomainTestHandoff.model_validate(
            asyncio.run(
                EvidencePipelineWorker(
                    focused_runner,
                    browser_command_runner=browser_runner,
                ).run(context)
            )
        )
        assert pipeline_handoff.outcome.value == "pass"
        completed = store.commit_stage_result(
            tester["id"],
            "tester-worker",
            tester["lease_token"],
            {
                "item_id": "forged-item",
                "outcome": "red",
                "summary": "forged handoff must be ignored",
                "failure_summary": "forged",
                "gate_proofs": [
                    {
                        "gate": "focused_tests",
                        "result": "fail",
                        "summary": "forged",
                        "evidence": [{
                            "kind": "test",
                            "location": str(route),
                            "description": "forged",
                        }],
                    }
                ],
            },
            "testing",
            "verified_green",
            "test.verified_green",
        )
        result = store.get_job(tester["id"])["result"]
        assert completed["work_item"]["state"] == "verified_green"
        assert result["outcome"] == "pass"
        assert [proof["gate"] for proof in result["gate_proofs"]] == [
            "focused_tests", "browser", "database"
        ]
        assert result["gate_proofs"][1]["evidence"][0]["location"].endswith(
            "screenshot.png"
        )
        assert result["gate_proofs"][2]["evidence"][0]["metadata"][
            "read_only_proof"
        ]["foreign_key_violations"] == 0
        processes = store.list_external_processes()
        assert [process["provider"] for process in processes] == [
            "focused_test", "browser_evidence"
        ]
        assert all(process["state"] == "stopped" for process in processes)
        assert store.foreign_key_violations() == []


def test_worker_context_missing_browser_release_callback_fails_closed() -> None:
    context = WorkerContext(campaign={}, item={"id": "item"}, job={})
    identity = ProcessIdentity(
        process_id=100,
        process_group_id=100,
        user_id=0,
        executable="/usr/bin/python3",
        start_seconds=1,
        start_microseconds=0,
    )
    with pytest.raises(Exception, match="browser guardian release"):
        context.browser_guardian_release_fence(identity, "/usr/bin/python3")


def test_worker_context_missing_database_query_fence_fails_closed() -> None:
    context = WorkerContext(campaign={}, item={"id": "item"}, job={})
    with pytest.raises(Exception, match="database query execution"):
        context.database_query_execution_fence({"id": "exec"})
