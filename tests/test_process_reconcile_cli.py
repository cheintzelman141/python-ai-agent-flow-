import os
from pathlib import Path

from typer.testing import CliRunner

from agent_flow.cli import app
from agent_flow.storage import SQLiteStore


runner = CliRunner()


def test_process_reconcile_cli_reports_clear_database(tmp_path: Path) -> None:
    database = tmp_path / "process-reconcile-clear.sqlite3"
    with SQLiteStore(database):
        pass

    result = runner.invoke(app, ["process-reconcile", "--database", str(database)])

    assert result.exit_code == 0, result.output
    assert "External process reconciliation" in result.output
    assert "clear" in result.output
    assert "No expired process binding" in result.output


def test_process_reconcile_cli_fails_closed_for_unverifiable_binding(
    tmp_path: Path,
) -> None:
    database = tmp_path / "process-reconcile-blocked.sqlite3"
    with SQLiteStore(database, clock=lambda: 1.0) as store:
        campaign = store.create_campaign("Blocked process reconciliation")
        item = store.create_work_item(
            campaign["id"],
            "Legacy process",
            description="An incomplete process identity must remain quarantined.",
        )
        job = store.enqueue_job(
            item["id"],
            "investigator",
            stage="investigate",
            queued_item_state="backlog",
            active_item_state="investigating",
            required_resources=["chrome:blocked"],
        )
        claim = store.claim_job("investigator", "legacy-worker", lease_seconds=5)
        assert claim is not None
        process = store.record_external_process(
            job["id"],
            "legacy-worker",
            claim["lease_token"],
            "codex",
            43210,
            43210,
            os.getuid(),
            "/usr/bin/python3",
            10,
            20,
            "/usr/local/bin/codex",
        )
        with store._transaction() as connection:
            connection.execute(
                """UPDATE external_processes
                   SET owner_uid = NULL, start_seconds = NULL,
                       start_microseconds = NULL,
                       identity_version = 'legacy_v3',
                       state = 'legacy_unverifiable',
                       last_error = 'V3 binding cannot prove process birth identity'
                   WHERE id = ?""",
                (process["id"],),
            )

    result = runner.invoke(app, ["process-reconcile", "--database", str(database)])

    assert result.exit_code == 1, result.output
    assert "quarantined" in result.output
    assert "unverifiable" in result.output
    retried = runner.invoke(
        app,
        [
            "process-reconcile",
            "--retry-quarantined",
            "--database",
            str(database),
        ],
    )
    assert retried.exit_code == 1, retried.output
    assert "quarantined" in retried.output
    with SQLiteStore(database) as store:
        assert store.get_job(job["id"])["status"] == "running"
        assert store.get_work_item(item["id"])["state"] == "investigating"
        assert store.list_attempts(job["id"])[0]["status"] == "running"
        assert len(store.list_resource_leases()) == 1
        persisted = store.list_external_processes()[0]
        assert persisted["state"] == "quarantined"
        assert persisted["reconciliation_token"] is None
        event_kinds = [event["event_kind"] for event in store.list_events()]
        assert event_kinds.count(
            "worker.external_process_reconciliation_claimed"
        ) == 2
        assert store.foreign_key_violations() == []
