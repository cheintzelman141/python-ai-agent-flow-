from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import sqlite3
import time
import uuid

import pytest

from agent_flow.database_collector import DatabaseCollectorError, DatabaseEvidenceCollector
from agent_flow.storage import SQLiteStore


@pytest.fixture
def runtime_root() -> Path:
    root = Path("/private/tmp/agent-flow-database-collector-%s" % uuid.uuid4().hex)
    root.mkdir(mode=0o700)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _prepared(store: SQLiteStore, root: Path):
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    database_path = root / "tenant_proof.sqlite3"
    connection = sqlite3.connect(str(database_path))
    try:
        connection.executescript(
            """PRAGMA foreign_keys = ON;
               CREATE TABLE proof_accounts (
                   account_id TEXT PRIMARY KEY,
                   status TEXT NOT NULL
               );
               INSERT INTO proof_accounts(account_id, status)
               VALUES ('ACCT-100', 'active');"""
        )
        connection.commit()
    finally:
        connection.close()
    database_path.chmod(0o600)
    campaign = store.create_campaign("database collector")
    resource = store.define_resource(
        "tenant_database",
        "Disposable tenant",
        {
            "tenant_key": "tenant-proof",
            "database_name": "tenant_proof",
            "connection_env": "AGENT_FLOW_TEST_DATABASE",
        },
        actor="collector-test",
        campaign_id=campaign["id"],
    )
    item = store.create_work_item(
        campaign["id"],
        "database proof",
        description="Run one exact read-only query.",
        state="ready_for_test",
        required_gates=["database"],
        initial_job={
            "role": "tester",
            "stage": "database",
            "active_item_state": "testing",
            "required_resources": [resource["id"]],
        },
    )
    plan = store.create_database_query_plan(
        item["id"],
        resource["id"],
        statement="SELECT account_id, status FROM proof_accounts WHERE account_id = ?",
        parameters=("ACCT-100",),
        id_column="account_id",
        expected_ids=("ACCT-100",),
        expected_row_count=1,
        max_rows=10,
        max_bytes=4096,
        timeout_seconds=2,
        runtime_root=runtime,
    )
    claim = store.claim_job("tester", "database-collector")
    assert claim is not None
    contract = store.prepare_database_query_execution(
        plan["id"],
        claim["id"],
        "database-collector",
        claim["lease_token"],
    )
    return campaign, item, database_path, claim, contract


def test_read_only_collector_runs_exact_plan_and_persists_proof(
    tmp_path: Path, runtime_root: Path
) -> None:
    with SQLiteStore(tmp_path / "supervisor.sqlite3") as store:
        campaign, item, database_path, claim, contract = _prepared(store, runtime_root)
        before = hashlib.sha256(database_path.read_bytes()).hexdigest()
        result = DatabaseEvidenceCollector().collect(
            contract,
            environment={"AGENT_FLOW_TEST_DATABASE": str(database_path)},
        )
        finished = store.complete_database_query_execution(
            claim["id"],
            "database-collector",
            claim["lease_token"],
            result,
        )
        after = hashlib.sha256(database_path.read_bytes()).hexdigest()
        assert finished["outcome"] == "pass"
        assert finished["observed_ids"] == ["ACCT-100"]
        assert finished["read_only_proof"] == {
            "authorizer": "deny_non_read",
            "foreign_key_violations": 0,
            "query_only": True,
            "uri_mode": "ro",
        }
        assert before == after
        with sqlite3.connect(str(database_path)) as verification:
            assert verification.execute(
                "SELECT account_id, status FROM proof_accounts"
            ).fetchall() == [("ACCT-100", "active")]
        assert store.foreign_key_violations() == []
        assert any(
            event["event_kind"] == "database_evidence.execution_finished"
            for event in store.list_events(campaign_id=campaign["id"])
        )
        artifact = store.list_artifacts(item["id"])[0]
        assert artifact["metadata"]["query_sha256"] == contract["query_sha256"]


def test_collector_rejects_mutated_statement_and_sanitizes_connection_failure(
    tmp_path: Path, runtime_root: Path
) -> None:
    with SQLiteStore(tmp_path / "supervisor.sqlite3") as store:
        _campaign, _item, database_path, _claim, contract = _prepared(store, runtime_root)
        changed = dict(contract)
        changed["statement"] = "DELETE FROM proof_accounts"
        with pytest.raises(DatabaseCollectorError, match="direct SELECT"):
            DatabaseEvidenceCollector().collect(
                changed,
                environment={"AGENT_FLOW_TEST_DATABASE": str(database_path)},
            )
        with sqlite3.connect(str(database_path)) as verification:
            assert verification.execute("SELECT COUNT(*) FROM proof_accounts").fetchone()[0] == 1

        secret_path = str(runtime_root / "password=hunter2.sqlite3")
        with pytest.raises(DatabaseCollectorError) as captured:
            DatabaseEvidenceCollector().collect(
                contract,
                environment={"AGENT_FLOW_TEST_DATABASE": secret_path},
            )
        assert "hunter2" not in str(captured.value)


def test_foreign_key_scan_obeys_timeout_and_does_not_materialize_all_violations(
    tmp_path: Path, runtime_root: Path
) -> None:
    with SQLiteStore(tmp_path / "supervisor.sqlite3") as store:
        _campaign, _item, database_path, _claim, contract = _prepared(
            store, runtime_root
        )
        with sqlite3.connect(str(database_path)) as database:
            database.executescript(
                """PRAGMA foreign_keys = OFF;
                   CREATE TABLE parents (id INTEGER PRIMARY KEY);
                   CREATE TABLE children (
                       id INTEGER PRIMARY KEY,
                       parent_id INTEGER NOT NULL REFERENCES parents(id)
                   );
                   WITH RECURSIVE numbers(value) AS (
                       SELECT 1 UNION ALL SELECT value + 1 FROM numbers
                       WHERE value < 100000
                   )
                   INSERT INTO parents(id)
                   SELECT value FROM numbers;
                   WITH RECURSIVE numbers(value) AS (
                       SELECT 1 UNION ALL SELECT value + 1 FROM numbers
                       WHERE value < 100000
                   )
                   INSERT INTO children(id, parent_id)
                   SELECT value, value FROM numbers;"""
            )
        database_path.chmod(0o600)
        changed = dict(contract)
        changed["timeout_seconds"] = 0.001
        started = time.monotonic()
        with pytest.raises(DatabaseCollectorError, match="query was rejected"):
            DatabaseEvidenceCollector().collect(
                changed,
                environment={"AGENT_FLOW_TEST_DATABASE": str(database_path)},
            )
        assert time.monotonic() - started < 1.0


def test_collector_requires_private_database_permissions(
    tmp_path: Path, runtime_root: Path
) -> None:
    with SQLiteStore(tmp_path / "supervisor.sqlite3") as store:
        _campaign, _item, database_path, _claim, contract = _prepared(
            store, runtime_root
        )
        database_path.chmod(0o644)
        with pytest.raises(DatabaseCollectorError, match="identity"):
            DatabaseEvidenceCollector().collect(
                contract,
                environment={"AGENT_FLOW_TEST_DATABASE": str(database_path)},
            )
