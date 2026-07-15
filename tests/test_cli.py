from io import BytesIO, StringIO
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pexpect
from rich.console import Console
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


def test_watch_refreshes_from_read_only_snapshots_without_writing(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "watch-cli.sqlite3"
    with SQLiteStore(database) as store:
        campaign = store.create_campaign("Live watch proof")
        store.create_work_item(
            campaign["id"],
            "First lane",
            description="Visible on the first snapshot.",
            initial_job={
                "role": "investigator",
                "stage": "investigate",
                "active_item_state": "investigating",
            },
        )

    refreshed = False

    def add_second_item(_seconds: float) -> None:
        nonlocal refreshed
        if refreshed:
            return
        with SQLiteStore(database) as writer:
            writer.create_work_item(
                campaign["id"],
                "Second lane",
                description="Committed between live snapshots.",
            )
        refreshed = True

    monkeypatch.setattr("agent_flow.cli.time.sleep", add_second_item)
    watched = runner.invoke(
        app,
        [
            "watch",
            campaign["id"],
            "--database",
            str(database),
            "--refresh",
            "0.1",
            "--refresh-count",
            "2",
        ],
    )

    assert watched.exit_code == 0, watched.output
    normalized = " ".join(watched.output.split())
    assert "READ-ONLY LIVE MONITOR" in watched.output
    assert "Pipeline lanes" in watched.output
    assert "First lane" in normalized
    assert "Second lane" in normalized
    with SQLiteStore(database) as store:
        assert len(store.list_work_items(campaign["id"])) == 2
        assert len(store.list_events(campaign_id=campaign["id"])) == 4


def test_unbounded_watch_requires_terminal_and_interrupt_is_clean(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "watch-interrupt.sqlite3"
    with SQLiteStore(database) as store:
        campaign = store.create_campaign("Watch interrupt")

    refused = runner.invoke(
        app, ["watch", campaign["id"], "--database", str(database)]
    )
    assert refused.exit_code != 0
    assert "unbounded watch requires an interactive terminal" in refused.output

    def interrupt(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("agent_flow.cli.time.sleep", interrupt)
    interrupted = runner.invoke(
        app,
        [
            "watch",
            campaign["id"],
            "--database",
            str(database),
            "--refresh-count",
            "2",
        ],
    )
    assert interrupted.exit_code == 0, interrupted.output
    assert "Watch stopped; persisted state was not changed." in interrupted.output


def test_watch_marks_a_busy_refresh_stale_and_then_recovers(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "watch-stale.sqlite3"
    with SQLiteStore(database) as store:
        campaign = store.create_campaign("Watch stale recovery")

    original_snapshot = SQLiteStore.read_campaign_watch_snapshot
    calls = 0

    def intermittently_busy(
        self,
        campaign_id: str,
        *,
        event_limit: int = 8,
        item_limit: int = 50,
    ):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise sqlite3.OperationalError("database is busy")
        return original_snapshot(
            self,
            campaign_id,
            event_limit=event_limit,
            item_limit=item_limit,
        )

    renderables = []

    class RecordingLive:
        def __init__(self, renderable, **_kwargs) -> None:
            renderables.append(renderable)

        def start(self, *, refresh: bool) -> None:
            assert refresh is True
            return None

        def stop(self) -> None:
            return None

        def update(self, renderable, *, refresh: bool) -> None:
            assert refresh is True
            renderables.append(renderable)

    monkeypatch.setattr(
        "agent_flow.cli.SQLiteStore.read_campaign_watch_snapshot",
        intermittently_busy,
    )
    monkeypatch.setattr("agent_flow.cli.Live", RecordingLive)
    monkeypatch.setattr("agent_flow.cli.time.sleep", lambda _seconds: None)
    watched = runner.invoke(
        app,
        [
            "watch",
            campaign["id"],
            "--database",
            str(database),
            "--refresh-count",
            "3",
        ],
    )

    assert watched.exit_code == 0, watched.output
    assert calls == 3
    rendered = []
    for renderable in renderables:
        output = StringIO()
        Console(file=output, width=120, color_system=None).print(renderable)
        rendered.append(output.getvalue())
    assert "READ-ONLY LIVE MONITOR" in rendered[0]
    assert "STALE - database is busy" in rendered[1]
    assert "READ-ONLY LIVE MONITOR" in rendered[2]


def test_watch_restores_cursor_when_interrupted_during_initial_terminal_draw(
    tmp_path: Path,
) -> None:
    database = tmp_path / "watch-terminal.sqlite3"
    with SQLiteStore(database) as store:
        campaign = store.create_campaign("Watch terminal restoration")
        for number in range(20):
            store.create_work_item(
                campaign["id"],
                "Terminal row %02d" % number,
                description="Ensure the initial Rich draw has enough output to interrupt.",
            )

    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    environment["TERM"] = "xterm-256color"
    output = BytesIO()
    child = pexpect.spawn(
        sys.executable,
        [
            "-m",
            "agent_flow.cli",
            "watch",
            campaign["id"],
            "--database",
            str(database),
            "--refresh",
            "60",
        ],
        env=environment,
        encoding=None,
        timeout=10,
    )
    child.logfile_read = output
    child.expect(b"Agent Flow - READ-ONLY LIVE MONITOR")
    child.sendcontrol("c")
    child.expect(pexpect.EOF)
    child.close()

    terminal_output = output.getvalue()
    hidden = terminal_output.count(b"\x1b[?25l")
    shown = terminal_output.count(b"\x1b[?25h")
    assert child.exitstatus == 0
    assert hidden >= 1
    assert shown >= hidden


def test_unbounded_watch_rejects_a_dumb_terminal(tmp_path: Path) -> None:
    database = tmp_path / "watch-dumb-terminal.sqlite3"
    with SQLiteStore(database) as store:
        campaign = store.create_campaign("Watch dumb terminal")

    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    environment["TERM"] = "dumb"
    child = pexpect.spawn(
        sys.executable,
        [
            "-m",
            "agent_flow.cli",
            "watch",
            campaign["id"],
            "--database",
            str(database),
        ],
        env=environment,
        encoding="utf-8",
        timeout=10,
    )
    child.expect(pexpect.EOF)
    child.close()

    assert child.exitstatus != 0
    assert "unbounded watch requires an interactive terminal" in child.before


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
