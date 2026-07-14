from pathlib import Path
import subprocess

from typer.testing import CliRunner

from agent_flow.cli import app
from agent_flow.storage import SQLiteStore


runner = CliRunner()


def _last_line(output: str) -> str:
    return output.strip().splitlines()[-1].strip()


def test_cli_creates_campaign_item_and_reopens_read_only_status(tmp_path: Path) -> None:
    database = tmp_path / "cli.sqlite3"
    created = runner.invoke(
        app,
        [
            "campaign-create",
            "CLI proof",
            "--description",
            "Durable CLI test campaign.",
            "--database",
            str(database),
        ],
    )
    assert created.exit_code == 0, created.output
    campaign_id = _last_line(created.output)

    added = runner.invoke(
        app,
        [
            "item-add",
            campaign_id,
            "CLI item",
            "--description",
            "Created atomically with its investigation job.",
            "--database",
            str(database),
        ],
    )
    assert added.exit_code == 0, added.output

    with SQLiteStore(database) as store:
        events_before = store.list_events(campaign_id=campaign_id)
        assert len(store.list_work_items(campaign_id)) == 1
        assert len(store.list_jobs(campaign_id=campaign_id)) == 1

    first = runner.invoke(
        app, ["status", campaign_id, "--database", str(database)]
    )
    second = runner.invoke(
        app, ["status", campaign_id, "--database", str(database)]
    )
    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert first.output == second.output
    assert "CLI proof" in first.output
    assert "Backlog" in first.output
    assert "Investigator" in first.output

    with SQLiteStore(database) as store:
        assert store.list_events(campaign_id=campaign_id) == events_before


def test_cli_write_approval_is_explicit_and_idempotent(tmp_path: Path) -> None:
    database = tmp_path / "approval-cli.sqlite3"
    created = runner.invoke(
        app,
        ["campaign-create", "Approval CLI", "--database", str(database)],
    )
    assert created.exit_code == 0, created.output
    campaign_id = _last_line(created.output)

    first = runner.invoke(
        app,
        [
            "approve-writes",
            campaign_id,
            "--by",
            "human-owner",
            "--database",
            str(database),
        ],
    )
    second = runner.invoke(
        app,
        [
            "approve-writes",
            campaign_id,
            "--by",
            "human-owner",
            "--database",
            str(database),
        ],
    )
    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert "already approved" in second.output

    with SQLiteStore(database) as store:
        approvals = store.list_approvals(campaign_id=campaign_id)
        assert len(approvals) == 1
        assert approvals[0]["status"] == "approved"


def test_cli_manages_and_displays_real_worktree_lifecycle(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    subprocess.run(("git", "init", "-q", str(repository)), check=True)
    (repository / "README.md").write_text("# CLI worktree\n", encoding="utf-8")
    subprocess.run(("git", "-C", str(repository), "add", "README.md"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(repository),
            "-c",
            "user.name=Agent Flow Tests",
            "-c",
            "user.email=agent-flow@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ),
        check=True,
    )
    repository = repository.resolve()
    database = tmp_path / "worktree-cli.sqlite3"
    worktree_root = (tmp_path / "managed").resolve()
    runtime_root = (tmp_path / "runtime").resolve()
    with SQLiteStore(database) as store:
        campaign = store.create_campaign(
            "CLI worktree proof",
            config={"repository_paths": [str(repository)]},
        )
        item = store.create_work_item(
            campaign["id"],
            "CLI managed item",
            description="Exercise the lifecycle operator commands.",
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
            "cli-owner",
            scope={"repository_paths": [str(repository)]},
        )
        store.resolve_approval(approval["id"], "approved", "cli-owner")

    provisioned = runner.invoke(
        app,
        [
            "worktree-provision",
            campaign["id"],
            item["id"],
            "--repository",
            str(repository),
            "--worktree-root",
            str(worktree_root),
            "--runtime-root",
            str(runtime_root),
            "--database",
            str(database),
        ],
    )
    assert provisioned.exit_code == 0, provisioned.output
    worktree_id = _last_line(provisioned.output)

    verified = runner.invoke(
        app,
        [
            "worktree-verify",
            worktree_id,
            "--worktree-root",
            str(worktree_root),
            "--runtime-root",
            str(runtime_root),
            "--database",
            str(database),
        ],
    )
    assert verified.exit_code == 0, verified.output
    status = runner.invoke(
        app, ["status", campaign["id"], "--database", str(database)]
    )
    assert status.exit_code == 0, status.output
    assert "Managed worktrees" in status.output
    assert worktree_id[:8] in status.output
    assert "Ready" in status.output

    with SQLiteStore(database) as store:
        operation = store.list_worktree_operations(
            managed_worktree_id=worktree_id
        )[0]
        with store._transaction() as connection:
            connection.execute(
                """UPDATE worktree_operations
                   SET status = 'quarantined', error = 'operator attention required'
                   WHERE id = ?""",
                (operation["id"],),
            )
            connection.execute(
                """UPDATE managed_worktrees
                   SET state = 'quarantined', last_error = 'operator attention required'
                   WHERE id = ?""",
                (worktree_id,),
            )
    reconciliation = runner.invoke(
        app,
        [
            "worktree-reconcile",
            "--worktree-root",
            str(worktree_root),
            "--runtime-root",
            str(runtime_root),
            "--database",
            str(database),
        ],
    )
    assert reconciliation.exit_code == 1
    assert "quarantined" in reconciliation.output
    assert "operator attention required" in reconciliation.output
    assert "No expired lifecycle operation" not in reconciliation.output
    with SQLiteStore(database) as store:
        with store._transaction() as connection:
            connection.execute(
                """UPDATE worktree_operations
                   SET status = 'succeeded', error = NULL WHERE id = ?""",
                (operation["id"],),
            )
            connection.execute(
                """UPDATE managed_worktrees
                   SET state = 'ready', last_error = NULL WHERE id = ?""",
                (worktree_id,),
            )

    with SQLiteStore(database) as store:
        claim = store.claim_job("fixer", "cli-fixer")
        assert claim is not None
        store.commit_stage_result(
            claim["id"],
            "cli-fixer",
            claim["lease_token"],
            {
                "schema_version": 1,
                "item_id": item["id"],
                "outcome": "blocked",
                "summary": "Fixture stops without changing files.",
                "changed_files": [],
                "tests_run": [],
                "tester_instructions": [],
                "evidence": [],
                "blocker": {
                    "kind": "execution",
                    "summary": "Intentional terminal fixture blocker.",
                    "next_action": "Clean up the unchanged managed worktree.",
                    "evidence": [
                        {
                            "kind": "log",
                            "location": str(repository / "README.md"),
                            "description": "Committed fixture evidence.",
                            "metadata": {},
                        }
                    ],
                },
            },
            "fixing",
            "blocked",
            "fix.blocked",
        )
        branch_ref = store.get_managed_worktree(worktree_id)["branch_ref"]

    cleaned = runner.invoke(
        app,
        [
            "worktree-cleanup",
            worktree_id,
            "--worktree-root",
            str(worktree_root),
            "--runtime-root",
            str(runtime_root),
            "--database",
            str(database),
        ],
    )
    assert cleaned.exit_code == 0, cleaned.output
    assert "branch retained" in cleaned.output
    branch = subprocess.run(
        ("git", "-C", str(repository), "show-ref", "--verify", branch_ref),
        check=True,
        capture_output=True,
        text=True,
    )
    assert branch.stdout.strip()
