from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import uuid

import pytest

from agent_flow.storage import (
    LeaseConflict,
    SCHEMA_VERSION,
    SQLiteStore,
    StorageError,
    TransitionConflict,
)


class ManualClock:
    def __init__(self) -> None:
        self.value = 1_000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture
def runtime_root() -> Path:
    root = Path("/private/tmp/agent-flow-evidence-plans-%s" % uuid.uuid4().hex)
    root.mkdir(mode=0o700)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _fixture(store: SQLiteStore, runtime_root: Path):
    fixture = runtime_root / "fixture.html"
    if not fixture.exists():
        fixture.write_text(
            "<title>Agent Flow Browser Proof</title><main>collector-ready</main>",
            encoding="utf-8",
        )
        fixture.chmod(0o600)
    for name in ("browser-runtime", "database-runtime"):
        directory = runtime_root / name
        if not directory.exists():
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
    campaign = store.create_campaign("collector plans")
    chrome = store.define_resource(
        "chrome_profile",
        "Disposable Chrome",
        {
            "user_data_dir": str(runtime_root / "chrome-user-data"),
            "profile_directory": "Profile 1",
        },
        actor="plan-test",
        campaign_id=campaign["id"],
    )
    database = store.define_resource(
        "tenant_database",
        "Disposable tenant",
        {
            "tenant_key": "tenant-proof",
            "database_name": "tenant_proof",
            "connection_env": "AGENT_FLOW_TEST_DATABASE",
        },
        actor="plan-test",
        campaign_id=campaign["id"],
    )
    item = store.create_work_item(
        campaign["id"],
        "fixed collector fixture",
        description="Run supervisor-owned fixed evidence collectors.",
        state="ready_for_test",
        required_gates=["focused_tests", "browser", "database"],
        initial_job={
            "role": "tester",
            "stage": "test",
            "active_item_state": "testing",
            "required_resources": [chrome["id"], database["id"]],
        },
    )
    return campaign, item, chrome, database


def test_schema_v9_and_immutable_collector_plans(
    tmp_path: Path, runtime_root: Path
) -> None:
    with SQLiteStore(tmp_path / "plans.sqlite3") as store:
        _campaign, item, chrome, database = _fixture(store, runtime_root)
        browser = store.create_browser_evidence_plan(
            item["id"],
            chrome["id"],
            route=(runtime_root / "fixture.html").as_uri(),
            expected_title="Agent Flow Browser Proof",
            expected_body_text="collector-ready",
            runtime_root=runtime_root / "browser-runtime",
        )
        repeated = store.create_browser_evidence_plan(
            item["id"],
            chrome["id"],
            route=(runtime_root / "fixture.html").as_uri(),
            expected_title="Agent Flow Browser Proof",
            expected_body_text="collector-ready",
            runtime_root=runtime_root / "browser-runtime",
        )
        revised = store.create_browser_evidence_plan(
            item["id"],
            chrome["id"],
            route=(runtime_root / "fixture.html").as_uri(),
            expected_title="Agent Flow Browser Proof v2",
            expected_body_text="collector-ready",
            runtime_root=runtime_root / "browser-runtime",
        )
        query = store.create_database_query_plan(
            item["id"],
            database["id"],
            statement="SELECT account_id, status FROM proof_accounts WHERE account_id = ?",
            parameters=("ACCT-100",),
            id_column="account_id",
            expected_ids=("ACCT-100",),
            expected_row_count=1,
            max_rows=10,
            max_bytes=4096,
            runtime_root=runtime_root / "database-runtime",
        )

        version = store._connection.execute("PRAGMA user_version").fetchone()[0]
        tables = {
            row["name"]
            for row in store._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert store.foreign_key_violations() == []

    assert version == SCHEMA_VERSION == 9
    assert {
        "browser_evidence_plans",
        "browser_evidence_executions",
        "database_query_plans",
        "database_query_executions",
    }.issubset(tables)
    assert repeated["id"] == browser["id"]
    assert revised["plan_number"] == 2
    assert browser["resource_identity_hash"] == chrome["identity_hash"]
    assert len(browser["plan_sha256"]) == 64
    assert query["parameters"] == ["ACCT-100"]
    assert query["expected_ids"] == ["ACCT-100"]
    assert len(query["query_sha256"]) == 64
    assert len(query["plan_sha256"]) == 64


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE proof_accounts SET status = 'active'",
        "SELECT 1; SELECT 2",
        "SELECT 1 -- bypass",
        "SELECT 1 /* bypass */",
        "PRAGMA query_only",
        "WITH changed AS (DELETE FROM proof_accounts RETURNING *) SELECT * FROM changed",
    ],
)
def test_database_plan_rejects_non_read_or_ambiguous_sql(
    tmp_path: Path, runtime_root: Path, statement: str
) -> None:
    with SQLiteStore(tmp_path / "unsafe-query.sqlite3") as store:
        _campaign, item, _chrome, database = _fixture(store, runtime_root)
        with pytest.raises(ValueError, match="comment-free SELECT"):
            store.create_database_query_plan(
                item["id"],
                database["id"],
                statement=statement,
                runtime_root=runtime_root / "database-runtime",
            )
        assert store.list_database_query_plans() == []


def test_collector_plan_scope_kind_disposable_and_identity_fail_closed(
    tmp_path: Path, runtime_root: Path
) -> None:
    with SQLiteStore(tmp_path / "plan-boundaries.sqlite3") as store:
        campaign, item, chrome, database = _fixture(store, runtime_root)
        with pytest.raises(TransitionConflict, match="chrome_profile"):
            store.create_browser_evidence_plan(
                item["id"],
                database["id"],
                route=(runtime_root / "fixture.html").as_uri(),
                expected_title="Proof",
                expected_body_text="ready",
                runtime_root=runtime_root / "browser-runtime",
            )
        unsafe_chrome = store.define_resource(
            "chrome_profile",
            "Non-disposable Chrome",
            {
                "user_data_dir": "/Users/example/Library/Application Support/Google/Chrome",
                "profile_directory": "Default",
            },
            actor="plan-test",
            campaign_id=campaign["id"],
        )
        with pytest.raises(TransitionConflict, match="disposable Chrome profile"):
            store.create_browser_evidence_plan(
                item["id"],
                unsafe_chrome["id"],
                route=(runtime_root / "fixture.html").as_uri(),
                expected_title="Proof",
                expected_body_text="ready",
                runtime_root=runtime_root / "browser-runtime",
            )
        store._connection.execute(
            "UPDATE resource_definitions SET configuration_json = ? WHERE id = ?",
            (
                json.dumps(
                    {
                        "user_data_dir": str(runtime_root / "other-profile"),
                        "profile_directory": "Default",
                    }
                ),
                chrome["id"],
            ),
        )
        with pytest.raises(StorageError, match="identity hash"):
            store.create_browser_evidence_plan(
                item["id"],
                chrome["id"],
                route=(runtime_root / "fixture.html").as_uri(),
                expected_title="Proof",
                expected_body_text="ready",
                runtime_root=runtime_root / "browser-runtime",
            )


def test_collector_plan_event_failure_rolls_back_and_secrets_are_not_echoed(
    tmp_path: Path, runtime_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "plan-events.sqlite3") as store:
        _campaign, item, chrome, database = _fixture(store, runtime_root)
        original_append = store._append_event

        def fail_event(*_args, **_kwargs):
            raise RuntimeError("forced collector plan event failure")

        monkeypatch.setattr(store, "_append_event", fail_event)
        with pytest.raises(RuntimeError, match="forced collector plan event"):
            store.create_browser_evidence_plan(
                item["id"],
                chrome["id"],
                route=(runtime_root / "fixture.html").as_uri(),
                expected_title="Proof",
                expected_body_text="ready",
                runtime_root=runtime_root / "browser-runtime",
            )
        assert store.list_browser_evidence_plans() == []
        monkeypatch.setattr(store, "_append_event", original_append)

        with pytest.raises(ValueError, match="credential assignment") as captured:
            store.create_database_query_plan(
                item["id"],
                database["id"],
                statement="SELECT account_id FROM proof_accounts WHERE note = ?",
                parameters=("password=hunter2",),
                runtime_root=runtime_root / "database-runtime",
            )
        assert "hunter2" not in str(captured.value)
        assert store.list_database_query_plans() == []


def test_fenced_browser_and_database_executions_persist_authoritative_artifacts(
    tmp_path: Path, runtime_root: Path
) -> None:
    database_path = tmp_path / "collector-executions.sqlite3"
    with SQLiteStore(database_path) as store:
        campaign, item, chrome, database = _fixture(store, runtime_root)
        browser_plan = store.create_browser_evidence_plan(
            item["id"],
            chrome["id"],
            route=(runtime_root / "fixture.html").as_uri(),
            expected_title="Agent Flow Browser Proof",
            expected_body_text="collector-ready",
            runtime_root=runtime_root / "browser-runtime",
        )
        database_plan = store.create_database_query_plan(
            item["id"],
            database["id"],
            statement="SELECT account_id, status FROM proof_accounts WHERE account_id = ?",
            parameters=("ACCT-100",),
            id_column="account_id",
            expected_ids=("ACCT-100",),
            expected_row_count=1,
            max_rows=10,
            max_bytes=4096,
            runtime_root=runtime_root / "database-runtime",
        )
        claim = store.claim_job("tester", "collector-worker")
        assert claim is not None
        with pytest.raises(LeaseConflict):
            store.prepare_browser_evidence_execution(
                browser_plan["id"], claim["id"], "collector-worker", "stale-token"
            )

        browser_execution = store.prepare_browser_evidence_execution(
            browser_plan["id"],
            claim["id"],
            "collector-worker",
            claim["lease_token"],
        )
        repeated_browser = store.prepare_browser_evidence_execution(
            browser_plan["id"],
            claim["id"],
            "collector-worker",
            claim["lease_token"],
        )
        assert repeated_browser["id"] == browser_execution["id"]
        assert browser_execution["chrome_configuration"]["profile_directory"] == "Profile 1"
        screenshot = Path(browser_execution["screenshot_path"])
        screenshot.write_bytes(b"\x89PNG\r\n\x1a\nfixed-disposable-proof")
        screenshot.chmod(0o600)
        screenshot_sha256 = hashlib.sha256(screenshot.read_bytes()).hexdigest()
        with pytest.raises(LeaseConflict, match="process-group reap proof"):
            store.complete_browser_evidence_execution(
                claim["id"],
                "collector-worker",
                claim["lease_token"],
                {
                    "execution_id": browser_execution["id"],
                    "observed_route": browser_plan["route"],
                    "observed_title": "Agent Flow Browser Proof",
                    "observed_body_text": "collector-ready",
                    "screenshot_path": str(screenshot),
                    "screenshot_sha256": screenshot_sha256,
                },
            )
        store.record_external_process(
            claim["id"],
            "collector-worker",
            claim["lease_token"],
            "browser_evidence",
            39401,
            39401,
            os.getuid(),
            "/usr/bin/python3",
            120,
            220,
            "/usr/bin/python3",
        )
        store.clear_external_process(
            claim["id"],
            "collector-worker",
            claim["lease_token"],
            39401,
            39401,
        )
        browser_finished = store.complete_browser_evidence_execution(
            claim["id"],
            "collector-worker",
            claim["lease_token"],
            {
                "execution_id": browser_execution["id"],
                "observed_route": browser_plan["route"],
                "observed_title": "Agent Flow Browser Proof",
                "observed_body_text": "collector-ready",
                "screenshot_path": str(screenshot),
                "screenshot_sha256": screenshot_sha256,
            },
        )
        assert browser_finished["outcome"] == "pass"
        assert browser_finished["assertions"] == {
            "body": True,
            "route": True,
            "title": True,
        }

        database_execution = store.prepare_database_query_execution(
            database_plan["id"],
            claim["id"],
            "collector-worker",
            claim["lease_token"],
        )
        assert database_execution["database_configuration"]["connection_env"] == (
            "AGENT_FLOW_TEST_DATABASE"
        )
        result_path = Path(database_execution["result_path"])
        payload = {
            "columns": ["account_id", "status"],
            "read_only_proof": {
                "authorizer": "deny_non_read",
                "foreign_key_violations": 0,
                "query_only": True,
                "uri_mode": "ro",
            },
            "rows": [["ACCT-100", "active"]],
        }
        result_path.write_text(
            json.dumps(payload, separators=(",", ":"), sort_keys=True),
            encoding="utf-8",
        )
        result_path.chmod(0o600)
        result_sha256 = hashlib.sha256(result_path.read_bytes()).hexdigest()
        database_finished = store.complete_database_query_execution(
            claim["id"],
            "collector-worker",
            claim["lease_token"],
            {
                "execution_id": database_execution["id"],
                "result_path": str(result_path),
                "result_sha256": result_sha256,
            },
        )
        assert database_finished["outcome"] == "pass"
        assert database_finished["row_count"] == 1
        assert database_finished["observed_ids"] == ["ACCT-100"]
        assert database_finished["read_only_proof"] == payload["read_only_proof"]
        artifacts = store.list_artifacts(item["id"])
        assert {artifact["kind"] for artifact in artifacts} == {
            "browser_screenshot",
            "database_result",
        }
        assert all(
            artifact["attempt_id"] == claim["attempt_id"] for artifact in artifacts
        )
        assert store.foreign_key_violations() == []
        event_kinds = {
            event["event_kind"]
            for event in store.list_events(campaign_id=campaign["id"])
        }
        assert {
            "browser_evidence.execution_prepared",
            "browser_evidence.execution_finished",
            "database_evidence.execution_prepared",
            "database_evidence.execution_finished",
        }.issubset(event_kinds)


def test_execution_schema_rejects_cross_plan_resource_and_invalid_lifecycle(
    tmp_path: Path, runtime_root: Path
) -> None:
    with SQLiteStore(tmp_path / "collector-relations.sqlite3") as store:
        _campaign, item, chrome, database = _fixture(store, runtime_root)
        browser_plan = store.create_browser_evidence_plan(
            item["id"],
            chrome["id"],
            route=(runtime_root / "fixture.html").as_uri(),
            expected_title="Agent Flow Browser Proof",
            expected_body_text="collector-ready",
            runtime_root=runtime_root / "browser-runtime",
        )
        claim = store.claim_job("tester", "collector-worker")
        assert claim is not None
        values = (
            uuid.uuid4().hex,
            browser_plan["id"],
            claim["attempt_id"],
            claim["id"],
            item["id"],
            database["id"],
            database["identity_hash"],
            browser_plan["route"],
            str(runtime_root / "cross-run"),
            str(runtime_root / "cross-run" / "screenshot.png"),
            1.0,
            1.0,
        )
        with pytest.raises(sqlite3.IntegrityError):
            store._connection.execute(
                """INSERT INTO browser_evidence_executions
                   (id, plan_id, attempt_id, job_id, work_item_id,
                    resource_definition_id, resource_identity_hash, status,
                    requested_route, run_parent, screenshot_path,
                    prepared_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?, ?, ?, ?)""",
                values,
            )
        with pytest.raises(sqlite3.IntegrityError):
            store._connection.execute(
                """INSERT INTO browser_evidence_executions
                   (id, plan_id, attempt_id, job_id, work_item_id,
                    resource_definition_id, resource_identity_hash, status,
                    outcome, requested_route, run_parent, screenshot_path,
                    prepared_at, finished_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'prepared', 'pass', ?, ?, ?, ?, ?, ?)""",
                (
                    uuid.uuid4().hex,
                    browser_plan["id"],
                    claim["attempt_id"],
                    claim["id"],
                    item["id"],
                    chrome["id"],
                    chrome["identity_hash"],
                    browser_plan["route"],
                    str(runtime_root / "bad-run"),
                    str(runtime_root / "bad-run" / "screenshot.png"),
                    1.0,
                    1.0,
                    1.0,
                ),
            )


def test_prepare_event_failure_cleans_filesystem_and_exact_retry_succeeds(
    tmp_path: Path, runtime_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "prepare-rollback.sqlite3") as store:
        _campaign, item, chrome, database = _fixture(store, runtime_root)
        browser_plan = store.create_browser_evidence_plan(
            item["id"],
            chrome["id"],
            route=(runtime_root / "fixture.html").as_uri(),
            expected_title="Agent Flow Browser Proof",
            expected_body_text="collector-ready",
            runtime_root=runtime_root / "browser-runtime",
        )
        database_plan = store.create_database_query_plan(
            item["id"],
            database["id"],
            statement="SELECT account_id FROM proof_accounts",
            id_column="account_id",
            runtime_root=runtime_root / "database-runtime",
        )
        claim = store.claim_job("tester", "collector-worker")
        assert claim is not None
        original_append = store._append_event

        def fail_prepared(_connection, event_kind, **_kwargs):
            if event_kind.endswith("execution_prepared"):
                raise RuntimeError("forced prepare event failure")
            return original_append(_connection, event_kind, **_kwargs)

        monkeypatch.setattr(store, "_append_event", fail_prepared)
        with pytest.raises(RuntimeError, match="forced prepare event"):
            store.prepare_browser_evidence_execution(
                browser_plan["id"],
                claim["id"],
                "collector-worker",
                claim["lease_token"],
            )
        with pytest.raises(RuntimeError, match="forced prepare event"):
            store.prepare_database_query_execution(
                database_plan["id"],
                claim["id"],
                "collector-worker",
                claim["lease_token"],
            )
        assert store.list_browser_evidence_executions() == []
        assert store.list_database_query_executions() == []
        assert not (runtime_root / "browser-runtime" / claim["attempt_id"]).exists()
        assert not (runtime_root / "database-runtime" / claim["attempt_id"]).exists()

        monkeypatch.setattr(store, "_append_event", original_append)
        browser = store.prepare_browser_evidence_execution(
            browser_plan["id"],
            claim["id"],
            "collector-worker",
            claim["lease_token"],
        )
        database_execution = store.prepare_database_query_execution(
            database_plan["id"],
            claim["id"],
            "collector-worker",
            claim["lease_token"],
        )
        assert browser["status"] == database_execution["status"] == "prepared"


def test_new_attempt_cannot_complete_stale_collector_executions(
    tmp_path: Path, runtime_root: Path
) -> None:
    clock = ManualClock()
    with SQLiteStore(tmp_path / "stale-execution.sqlite3", clock=clock) as store:
        _campaign, item, chrome, database = _fixture(store, runtime_root)
        browser_plan = store.create_browser_evidence_plan(
            item["id"],
            chrome["id"],
            route=(runtime_root / "fixture.html").as_uri(),
            expected_title="Agent Flow Browser Proof",
            expected_body_text="collector-ready",
            runtime_root=runtime_root / "browser-runtime",
        )
        database_plan = store.create_database_query_plan(
            item["id"],
            database["id"],
            statement="SELECT account_id FROM proof_accounts",
            id_column="account_id",
            runtime_root=runtime_root / "database-runtime",
        )
        first = store.claim_job("tester", "worker-1", lease_seconds=5)
        assert first is not None
        browser = store.prepare_browser_evidence_execution(
            browser_plan["id"], first["id"], "worker-1", first["lease_token"]
        )
        database_execution = store.prepare_database_query_execution(
            database_plan["id"], first["id"], "worker-1", first["lease_token"]
        )
        clock.advance(6)
        assert store.recover_expired_leases()["jobs"] == 1
        second = store.claim_job("tester", "worker-2", lease_seconds=5)
        assert second is not None and second["attempt_id"] != first["attempt_id"]

        with pytest.raises(LeaseConflict, match="another job or attempt"):
            store.complete_browser_evidence_execution(
                second["id"],
                "worker-2",
                second["lease_token"],
                {
                    "execution_id": browser["id"],
                    "observed_route": browser_plan["route"],
                    "observed_title": "Agent Flow Browser Proof",
                    "observed_body_text": "collector-ready",
                    "screenshot_path": browser["screenshot_path"],
                    "screenshot_sha256": "a" * 64,
                },
            )
        with pytest.raises(LeaseConflict, match="another job or attempt"):
            store.complete_database_query_execution(
                second["id"],
                "worker-2",
                second["lease_token"],
                {
                    "execution_id": database_execution["id"],
                    "result_path": database_execution["result_path"],
                    "result_sha256": "a" * 64,
                },
            )
        assert store.list_artifacts(item["id"]) == []


@pytest.mark.parametrize(
    "required_gates",
    [["browser"], ["database"], ["browser", "database"]],
)
def test_non_simulated_partial_gate_sets_cannot_bypass_authoritative_collectors(
    tmp_path: Path, required_gates: list[str]
) -> None:
    proof = tmp_path / "worker-authored-proof.txt"
    proof.write_text("not authoritative collector output\n", encoding="utf-8")
    with SQLiteStore(tmp_path / "partial-gates.sqlite3") as store:
        campaign = store.create_campaign("partial fixed gates")
        item = store.create_work_item(
            campaign["id"],
            "partial fixed gates",
            description="Worker-authored attachments cannot become canonical.",
            state="ready_for_test",
            required_gates=required_gates,
            initial_job={
                "role": "tester",
                "stage": "test",
                "active_item_state": "testing",
            },
        )
        claim = store.claim_job("tester", "untrusted-tester")
        assert claim is not None
        handoff = {
            "item_id": item["id"],
            "outcome": "pass",
            "summary": "Worker claims partial gates passed.",
            "gate_proofs": [
                {
                    "gate": gate,
                    "result": "pass",
                    "summary": "Worker-authored proof.",
                    "evidence": [
                        {
                            "kind": "screenshot" if gate == "browser" else "database",
                            "location": str(proof),
                            "description": "Not storage-canonical evidence.",
                        }
                    ],
                }
                for gate in required_gates
            ],
        }
        with pytest.raises(ValueError, match="requires authoritative"):
            store.commit_stage_result(
                claim["id"],
                "untrusted-tester",
                claim["lease_token"],
                handoff,
                "testing",
                "verified_green",
                "test.verified_green",
            )
        assert store.get_work_item(item["id"])["state"] == "testing"
        assert store.list_browser_evidence_executions() == []
        assert store.list_database_query_executions() == []
