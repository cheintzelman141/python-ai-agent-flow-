from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
from typing import Any, Dict, Optional, Tuple

import pytest

from agent_flow.focused_tests import FocusedTestWorker
from agent_flow.process_reconciler import DarwinProcessRuntime
from agent_flow.storage import (
    LeaseConflict,
    NotFoundError,
    SCHEMA_VERSION,
    SQLiteStore,
    StorageError,
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
    _SCHEMA_V10,
)
from agent_flow.workers import WorkerContext
from agent_flow.worktrees import (
    GitCommandError,
    GuardedGitCommandRunner,
    ManagedWorktreeConfig,
    ManagedWorktreeManager,
)


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
    _git(path, "config", "user.name", "Agent Flow Admission Tests")
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


def _ready_tester(
    store: SQLiteStore,
    tmp_path: Path,
    *,
    name: str = "admission",
    with_resource: bool = False,
) -> Tuple[Dict[str, Any], ...]:
    repository = _repository(tmp_path / (name + "-repo"))
    campaign = store.create_campaign(
        name,
        config={"repository_paths": [str(repository)]},
    )
    resource: Optional[Dict[str, Any]] = None
    if with_resource:
        resource = store.define_resource(
            "test_fixture",
            "%s fixture" % name,
            {
                "fixture_key": "%s-fixture" % name,
                "root_path": "/private/tmp/agent-flow-%s-%s-%s"
                % (os.getpid(), tmp_path.name, name),
                "disposable": True,
            },
            actor="admission-test",
            campaign_id=campaign["id"],
        )
    item = store.create_work_item(
        campaign["id"],
        "%s item" % name,
        description="Prove exact focused-test admission fencing.",
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
        "admission-test",
        scope={"repository_paths": [str(repository)]},
    )
    store.resolve_approval(approval["id"], "approved", "admission-test")
    manager = ManagedWorktreeManager(
        store,
        owner="admission-test",
        config=ManagedWorktreeConfig(
            worktree_root=(tmp_path / (name + "-worktrees")).resolve(),
            runtime_root=(tmp_path / (name + "-git-runtime")).resolve(),
            command_timeout_seconds=5,
            terminate_grace_seconds=1,
            operation_lease_seconds=30,
        ),
    )
    worktree = manager.provision(
        campaign["id"], item["id"], repository, "HEAD"
    )
    fixer = store.claim_job("fixer", "%s-fixer" % name)
    assert fixer is not None
    completed = store.commit_stage_result(
        fixer["id"],
        "%s-fixer" % name,
        fixer["lease_token"],
        {
            "schema_version": 1,
            "item_id": item["id"],
            "outcome": "ready_for_test",
            "summary": "The exact managed worktree is ready for testing.",
            "changed_files": ["calculator.py"],
            "tests_run": [],
            "tester_instructions": ["Run the immutable focused selector."],
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
            "required_resources": (
                [] if resource is None else [resource["id"]]
            ),
        },
    )
    tester = completed["next_job"]
    assert tester is not None
    plan = store.create_focused_test_plan(
        item["id"],
        executable_path=str(Path(sys.executable).resolve()),
        test_file="test_calculator.py",
        selector="CalculatorTests.test_adds_two_numbers",
        workspace_manifest=store._scan_focused_workspace(
            Path(worktree["worktree_path"])
        ),
        runtime_root=str((tmp_path / (name + "-focused-runtime")).resolve()),
        timeout_seconds=10,
        output_limit_bytes=16 * 1024,
    )
    return campaign, item, worktree, plan, tester, resource


def _admit(
    store: SQLiteStore,
    fixture: Tuple[Dict[str, Any], ...],
) -> Dict[str, Any]:
    campaign, item, worktree, plan, tester, resource = fixture
    return store.create_focused_test_admission(
        campaign["id"],
        item["id"],
        tester["id"],
        worktree["id"],
        plan["id"],
        [] if resource is None else [resource["id"]],
        admitted_by="focused-test-operator",
        reason="approve exact isolated focused-test execution",
    )


def _pending_fixer(
    store: SQLiteStore,
    tmp_path: Path,
    campaign: Dict[str, Any],
    repository: Path,
    *,
    name: str,
    priority: int,
) -> Dict[str, Any]:
    item = store.create_work_item(
        campaign["id"],
        "%s fixer" % name,
        description="Pending managed-worktree fixer claim.",
        state="ready_for_fix",
        required_gates=["focused_tests"],
        priority=priority,
        initial_job={
            "role": "fixer",
            "stage": "fix",
            "active_item_state": "fixing",
            "required_approval_action": "local_code_changes",
            "priority": priority,
        },
    )
    manager = ManagedWorktreeManager(
        store,
        owner="%s-manager" % name,
        config=ManagedWorktreeConfig(
            worktree_root=(tmp_path / (name + "-worktrees")).resolve(),
            runtime_root=(tmp_path / (name + "-runtime")).resolve(),
            command_timeout_seconds=5,
            terminate_grace_seconds=1,
            operation_lease_seconds=30,
        ),
    )
    manager.provision(campaign["id"], item["id"], repository, "HEAD")
    return store.list_jobs(work_item_id=item["id"])[0]


def test_schema_v10_migrates_to_dormant_v11_without_grandfathering(
    tmp_path: Path,
) -> None:
    database = tmp_path / "schema-v10.sqlite3"
    connection = sqlite3.connect(str(database))
    try:
        for schema in (
            _SCHEMA_V1,
            _SCHEMA_V2,
            _SCHEMA_V3,
            _SCHEMA_V4,
            _SCHEMA_V5,
            _SCHEMA_V6,
            _SCHEMA_V7,
            _SCHEMA_V8,
            _SCHEMA_V9,
            _SCHEMA_V10,
        ):
            for statement in schema:
                connection.execute(statement)
        connection.execute("PRAGMA user_version = 10")
        connection.commit()
    finally:
        connection.close()

    with SQLiteStore(database) as store:
        version = store._connection.execute("PRAGMA user_version").fetchone()[0]
        tables = {
            row["name"]
            for row in store._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        admissions = store.list_focused_test_admissions()

    assert version == SCHEMA_VERSION == 11
    assert "focused_test_admissions" in tables
    assert admissions == []


@pytest.mark.parametrize("with_resource", [False, True])
def test_exact_admission_is_audited_claimed_and_attempt_pinned(
    tmp_path: Path, with_resource: bool
) -> None:
    database = tmp_path / "flow.sqlite3"
    with SQLiteStore(database) as store:
        fixture = _ready_tester(
            store, tmp_path, with_resource=with_resource
        )
        campaign, item, _worktree, _plan, tester, resource = fixture
        admission = _admit(store, fixture)
        claimed = store.claim_job("tester", "admitted-tester")
        assert claimed is not None
        assert claimed["id"] == tester["id"]
        attempt = store.list_attempts(work_item_id=item["id"])[-1]
        events = store.list_events(campaign_id=campaign["id"])

    assert admission["status"] == "active"
    assert admission["resource_definition_ids"] == (
        [] if resource is None else [resource["id"]]
    )
    assert attempt["focused_test_admission_id"] == admission["id"]
    assert any(
        event["event_type"] == "focused_test.admission_created"
        and event["event_data"]["admission_id"] == admission["id"]
        for event in events
    )


def test_legacy_tester_cannot_prepare_authoritative_focused_execution(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        fixture = _ready_tester(store, tmp_path, name="no-admission")
        claimed = store.claim_job("tester", "legacy-real-tester")

        assert claimed is not None
        attempt = store.list_attempts(work_item_id=fixture[1]["id"])[-1]
        assert attempt["focused_test_admission_id"] is None
        with pytest.raises(LeaseConflict, match="requires an exact admission"):
            store.prepare_focused_test_execution(
                claimed["id"],
                "legacy-real-tester",
                claimed["lease_token"],
            )
        assert store.list_focused_test_executions(
            attempt_id=claimed["attempt_id"]
        ) == []
        assert store.get_campaign(fixture[0]["id"])["execution_mode"] == "legacy"


def test_revoked_admission_cannot_be_claimed_and_survives_restart(
    tmp_path: Path,
) -> None:
    database = tmp_path / "flow.sqlite3"
    with SQLiteStore(database) as store:
        fixture = _ready_tester(store, tmp_path)
        admission = _admit(store, fixture)
        store.revoke_focused_test_admission(
            admission["id"],
            revoked_by="focused-test-operator",
            reason="operator withdrew exact test authority",
        )

    with SQLiteStore(database) as store:
        assert store.claim_job("tester", "must-not-claim") is None
        assert store.get_focused_test_admission(admission["id"])["status"] == "revoked"


def test_cross_campaign_authority_rolls_back_without_audit_event(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        first = _ready_tester(store, tmp_path, name="first")
        second = _ready_tester(store, tmp_path, name="second")
        campaign, item, _worktree, _plan, tester, _resource = first
        before = len(store.list_events(campaign_id=campaign["id"]))

        with pytest.raises(NotFoundError):
            store.create_focused_test_admission(
                campaign["id"],
                item["id"],
                tester["id"],
                second[2]["id"],
                second[3]["id"],
                [],
                admitted_by="focused-test-operator",
                reason="must not cross campaign authority",
            )

        assert store.list_focused_test_admissions(campaign_id=campaign["id"]) == []
        assert len(store.list_events(campaign_id=campaign["id"])) == before
        assert store.get_campaign(campaign["id"])["execution_mode"] == "legacy"


def test_focused_mode_skips_earlier_roles_without_head_of_line_blocking(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        focused = _ready_tester(store, tmp_path, name="focused")
        focused_campaign = focused[0]
        focused_repository = Path(focused[2]["repository_path"])
        focused_fixer = _pending_fixer(
            store,
            tmp_path,
            focused_campaign,
            focused_repository,
            name="focused-pending",
            priority=100,
        )
        _admit(store, focused)
        focused_investigator_item = store.create_work_item(
            focused_campaign["id"],
            "focused pending investigator",
            description="Must not launch in focused-test-only mode.",
            priority=100,
            initial_job={
                "role": "investigator",
                "stage": "investigator",
                "active_item_state": "investigating",
                "priority": 100,
            },
        )

        legacy_repository = _repository(tmp_path / "legacy-repo")
        legacy_campaign = store.create_campaign(
            "legacy eligible",
            config={"repository_paths": [str(legacy_repository)]},
        )
        approval = store.create_approval(
            legacy_campaign["id"],
            "local_code_changes",
            "legacy-test",
            scope={"repository_paths": [str(legacy_repository)]},
        )
        store.resolve_approval(approval["id"], "approved", "legacy-test")
        legacy_fixer = _pending_fixer(
            store,
            tmp_path,
            legacy_campaign,
            legacy_repository,
            name="legacy-pending",
            priority=1,
        )
        legacy_investigator_item = store.create_work_item(
            legacy_campaign["id"],
            "legacy eligible investigator",
            description="Eligible lower-priority claim.",
            priority=1,
            initial_job={
                "role": "investigator",
                "stage": "investigator",
                "active_item_state": "investigating",
                "priority": 1,
            },
        )

        investigator = store.claim_job("investigator", "eligible-investigator")
        fixer = store.claim_job("fixer", "eligible-fixer")
        focused_fixer_after = store.get_job(focused_fixer["id"])
        focused_investigator_after = store.get_work_item(
            focused_investigator_item["id"]
        )

    assert investigator is not None
    assert investigator["work_item_id"] == legacy_investigator_item["id"]
    assert fixer is not None
    assert fixer["id"] == legacy_fixer["id"]
    assert focused_fixer_after["status"] == "pending"
    assert focused_investigator_after["state"] == "backlog"


@pytest.mark.parametrize(
    "drift",
    [
        "campaign_config",
        "required_resources",
        "repository",
        "source_snapshot",
        "generation",
    ],
)
def test_each_bound_identity_drift_fails_closed_before_claim(
    tmp_path: Path, drift: str
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        fixture = _ready_tester(store, tmp_path)
        campaign, _item, worktree, _plan, tester, _resource = fixture
        _admit(store, fixture)
        if drift == "campaign_config":
            store._connection.execute(
                "UPDATE campaigns SET config_json = ? WHERE id = ?",
                ('{"repository_paths":[],"widened":true}', campaign["id"]),
            )
        elif drift == "required_resources":
            store._connection.execute(
                "UPDATE jobs SET required_resources_json = ? WHERE id = ?",
                ('["legacy:unadmitted"]', tester["id"]),
            )
        elif drift == "repository":
            store._connection.execute(
                "UPDATE managed_worktrees SET source_inode = source_inode + 1 WHERE id = ?",
                (worktree["id"],),
            )
        elif drift == "source_snapshot":
            store._connection.execute(
                "UPDATE managed_worktrees SET source_snapshot_json = '{}' WHERE id = ?",
                (worktree["id"],),
            )
        else:
            store._connection.execute(
                "UPDATE managed_worktrees SET generation = generation + 1 WHERE id = ?",
                (worktree["id"],),
            )

        assert store.claim_job("tester", "drifted-authority") is None


@pytest.mark.parametrize("malformation", ["authority_hash", "resource_json"])
def test_malformed_admission_fails_closed_before_claim(
    tmp_path: Path, malformation: str
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        fixture = _ready_tester(store, tmp_path)
        admission = _admit(store, fixture)
        if malformation == "authority_hash":
            store._connection.execute(
                "UPDATE focused_test_admissions SET authority_sha256 = ? WHERE id = ?",
                ("0" * 64, admission["id"]),
            )
        else:
            store._connection.execute(
                "UPDATE focused_test_admissions SET resource_bindings_json = ? WHERE id = ?",
                ("{", admission["id"]),
            )

        assert store.claim_job("tester", "tampered-admission") is None
        with pytest.raises(StorageError, match="malformed or changed"):
            store.get_focused_test_admission(admission["id"])


def test_non_mapping_resource_binding_fails_closed_without_head_of_line_blocking(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        malformed_fixture = _ready_tester(store, tmp_path, name="malformed")
        malformed_admission = _admit(store, malformed_fixture)
        eligible_fixture = _ready_tester(store, tmp_path, name="eligible")
        _admit(store, eligible_fixture)
        store._connection.execute(
            """UPDATE focused_test_admissions
               SET resource_bindings_json = ? WHERE id = ?""",
            ("[1]", malformed_admission["id"]),
        )

        claimed = store.claim_job("tester", "eligible-after-malformed")

        assert claimed is not None
        assert claimed["id"] == eligible_fixture[4]["id"]
        with pytest.raises(StorageError, match="malformed or changed"):
            store.get_focused_test_admission(malformed_admission["id"])


def test_cross_campaign_and_tampered_resource_definitions_fail_closed(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        first = _ready_tester(store, tmp_path, name="resource-first")
        second = _ready_tester(
            store, tmp_path, name="resource-second", with_resource=True
        )
        foreign_resource = second[5]
        assert foreign_resource is not None

        with pytest.raises(TransitionConflict, match="outside the campaign scope"):
            store.create_focused_test_admission(
                first[0]["id"],
                first[1]["id"],
                first[4]["id"],
                first[2]["id"],
                first[3]["id"],
                [foreign_resource["id"]],
                admitted_by="focused-test-operator",
                reason="cross-campaign resource must fail",
            )

        store._connection.execute(
            "UPDATE campaigns SET status = 'paused' WHERE id = ?",
            (first[0]["id"],),
        )
        admission = _admit(store, second)
        store._connection.execute(
            "UPDATE resource_definitions SET label = ? WHERE id = ?",
            ("tampered label", foreign_resource["id"]),
        )
        assert admission["status"] == "active"
        assert store.claim_job("tester", "tampered-definition") is None


def test_payload_plan_and_definition_drift_fail_closed_before_claim(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        fixture = _ready_tester(store, tmp_path, with_resource=True)
        campaign, item, worktree, plan, tester, resource = fixture
        assert resource is not None
        _admit(store, fixture)
        original_payload_json = store._connection.execute(
            "SELECT payload_json FROM jobs WHERE id = ?", (tester["id"],)
        ).fetchone()[0]
        store._connection.execute(
            "UPDATE jobs SET payload_json = ? WHERE id = ?",
            ('{"working_directory":"/private/tmp/escape"}', tester["id"]),
        )

        assert store.claim_job("tester", "payload-bypass") is None

        store._connection.execute(
            "UPDATE jobs SET payload_json = ? WHERE id = ?",
            (original_payload_json, tester["id"]),
        )
        store.set_resource_enabled(resource["id"], False, actor="resource-owner")
        assert store.claim_job("tester", "disabled-resource") is None

        store.set_resource_enabled(resource["id"], True, actor="resource-owner")
        store.create_focused_test_plan(
            item["id"],
            executable_path=str(Path(sys.executable).resolve()),
            test_file="test_calculator.py",
            selector="CalculatorTests.test_adds_two_numbers",
            workspace_manifest=store._scan_focused_workspace(
                Path(worktree["worktree_path"])
            ),
            runtime_root=plan["runtime_root"],
            timeout_seconds=10,
            output_limit_bytes=16 * 1024,
        )
        assert store.claim_job("tester", "newer-plan") is None


def test_post_claim_revocation_blocks_launch_completion_and_finalization(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        fixture = _ready_tester(store, tmp_path)
        admission = _admit(store, fixture)
        claimed = store.claim_job("tester", "admitted-tester")
        assert claimed is not None
        execution = store.prepare_focused_test_execution(
            claimed["id"], "admitted-tester", claimed["lease_token"]
        )
        store.revoke_focused_test_admission(
            admission["id"],
            revoked_by="focused-test-operator",
            reason="stop before the guardian can release",
        )

        with pytest.raises(LeaseConflict, match="admission"):
            store.heartbeat_job(
                claimed["id"],
                "admitted-tester",
                claimed["lease_token"],
            )
        with pytest.raises(LeaseConflict, match="admission"):
            store.record_external_process(
                claimed["id"],
                "admitted-tester",
                claimed["lease_token"],
                "focused_test",
                41001,
                41001,
                os.getuid(),
                str(Path(sys.executable).resolve()),
                41001,
                1,
                execution["sandbox_executable_path"],
            )
        with pytest.raises(LeaseConflict, match="admission"):
            store.complete_focused_test_execution(
                claimed["id"],
                "admitted-tester",
                claimed["lease_token"],
                {},
            )
        with pytest.raises(LeaseConflict, match="admission"):
            store.commit_stage_result(
                claimed["id"],
                "admitted-tester",
                claimed["lease_token"],
                {},
                "testing",
                "verified_green",
                "test.verified_green",
            )

        assert [
            process
            for process in store.list_external_processes()
            if process["attempt_id"] == claimed["attempt_id"]
        ] == []
        assert store.get_work_item(fixture[1]["id"])["state"] == "testing"


def test_revocation_between_registration_and_release_never_launches_target(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        fixture = _ready_tester(store, tmp_path, name="release-race")
        admission = _admit(store, fixture)
        claimed = store.claim_job("tester", "release-race-tester")
        assert claimed is not None
        registered = threading.Event()
        revocation_finished = threading.Event()

        def record_process(provider: str, identity: Any, target: str) -> None:
            store.record_external_process(
                claimed["id"],
                "release-race-tester",
                claimed["lease_token"],
                provider,
                identity.process_id,
                identity.process_group_id,
                identity.user_id,
                identity.executable,
                identity.start_seconds,
                identity.start_microseconds,
                target,
            )
            registered.set()
            assert revocation_finished.wait(timeout=5)

        context = WorkerContext(
            campaign=fixture[0],
            item=store.get_work_item(fixture[1]["id"]),
            job=claimed,
            _external_process_recorder=record_process,
            _external_process_clearer=lambda process_id, process_group_id: (
                store.clear_external_process(
                    claimed["id"],
                    "release-race-tester",
                    claimed["lease_token"],
                    process_id,
                    process_group_id,
                )
            ),
            _focused_test_guardian_release_fencer=(
                lambda identity, target: store.focused_test_guardian_release_fence(
                    claimed["id"],
                    "release-race-tester",
                    claimed["lease_token"],
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
                    claimed["id"],
                    "release-race-tester",
                    claimed["lease_token"],
                )
            ),
            _focused_test_execution_completer=lambda result: (
                store.complete_focused_test_execution(
                    claimed["id"],
                    "release-race-tester",
                    claimed["lease_token"],
                    result,
                )
            ),
        )
        runner = GuardedGitCommandRunner(
            runtime=DarwinProcessRuntime(),
            timeout_seconds=10,
            terminate_grace_seconds=2,
            max_output_bytes=16 * 1024,
        )

        async def revoke_before_release() -> GitCommandError:
            task = asyncio.create_task(FocusedTestWorker(runner).run(context))
            assert await asyncio.to_thread(registered.wait, 5)
            store.revoke_focused_test_admission(
                admission["id"],
                revoked_by="focused-test-operator",
                reason="win the exact registration-to-release race",
            )
            revocation_finished.set()
            with pytest.raises(
                GitCommandError,
                match="could not release the durably registered Git guardian",
            ) as captured:
                await task
            return captured.value

        error = asyncio.run(revoke_before_release())
        processes = store.list_external_processes()
        execution = store.list_focused_test_executions(
            attempt_id=claimed["attempt_id"]
        )[0]

    assert error.result is not None
    assert error.result.return_code == -1
    assert Path(error.result.stdout_path).read_bytes() == b""
    assert Path(error.result.stderr_path).read_bytes() == b""
    assert len(processes) == 1
    assert processes[0]["state"] == "stopped"
    assert execution["status"] == "prepared"
    assert execution["canonical_handoff"] is None


def test_attempt_retry_reuses_only_the_same_durable_admission(
    tmp_path: Path,
) -> None:
    database = tmp_path / "flow.sqlite3"
    with SQLiteStore(database) as store:
        fixture = _ready_tester(store, tmp_path)
        admission = _admit(store, fixture)
        first = store.claim_job("tester", "retry-tester")
        assert first is not None
        store.fail_job(
            first["id"],
            "retry-tester",
            first["lease_token"],
            "bounded retry proof",
            requeue=True,
            max_attempts=2,
        )

    with SQLiteStore(database) as store:
        second = store.claim_job("tester", "retry-tester")
        assert second is not None
        attempts = store.list_attempts(work_item_id=fixture[1]["id"])

    assert len(attempts) == 3  # fixer plus two tester attempts
    assert attempts[-2]["focused_test_admission_id"] == admission["id"]
    assert attempts[-1]["focused_test_admission_id"] == admission["id"]
    assert attempts[-1]["attempt_number"] == 2
