from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
from threading import Lock
from typing import Any, Dict, Optional

import pytest
from typer.testing import CliRunner

from agent_flow.cli import app
from agent_flow.storage import (
    LeaseConflict,
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
    _resource_identity_hash,
)


runner = CliRunner()


class ManualClock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value
        self._lock = Lock()

    def __call__(self) -> float:
        with self._lock:
            return self.value

    def advance(self, seconds: float) -> None:
        with self._lock:
            self.value += seconds


def _campaign(store: SQLiteStore, name: str = "resource campaign") -> dict:
    return store.create_campaign(
        name,
        global_limit=8,
        role_limits={"investigator": 8, "fixer": 8, "tester": 8},
    )


def _job(
    store: SQLiteStore,
    campaign_id: str,
    title: str,
    resource_id: str,
    *,
    priority: int = 0,
) -> dict:
    item = store.create_work_item(
        campaign_id,
        title,
        description="Resource-definition claim fixture.",
        priority=priority,
    )
    return store.enqueue_job(
        item["id"],
        "investigator",
        stage="resource-%s" % title,
        queued_item_state="backlog",
        active_item_state="investigating",
        required_resources=[resource_id],
        priority=priority,
    )


def _chrome(
    store: SQLiteStore,
    label: str = "Visible QA Chrome",
    *,
    campaign_id: Optional[str] = None,
    enabled: bool = True,
    policy: Optional[Dict[str, Any]] = None,
) -> dict:
    return store.define_resource(
        "chrome_profile",
        label,
        {
            "user_data_dir": "/private/tmp/agent-flow-chrome-profile",
            "profile_directory": "Default",
        },
        actor="resource-test",
        campaign_id=campaign_id,
        enabled=enabled,
        policy=policy,
        metadata={"environment": "qa"},
    )


def test_schema_v7_migrates_resource_definitions_and_preserves_legacy_lease(
    tmp_path: Path,
) -> None:
    path = tmp_path / "schema-v7.sqlite3"
    connection = sqlite3.connect(str(path))
    try:
        for schema in (
            _SCHEMA_V1,
            _SCHEMA_V2,
            _SCHEMA_V3,
            _SCHEMA_V4,
            _SCHEMA_V5,
            _SCHEMA_V6,
            _SCHEMA_V7,
        ):
            for statement in schema:
                connection.execute(statement)
        connection.execute(
            """INSERT INTO campaigns
               (id, name, status, config_json, global_limit, role_limits_json,
                created_at, updated_at)
               VALUES ('campaign-v7', 'V7', 'active', '{}', 4,
                       '{"investigator":2,"fixer":2,"tester":2}', 1, 1)"""
        )
        connection.execute(
            """INSERT INTO work_items
               (id, campaign_id, title, description, state, priority,
                required_gates_json, metadata_json, created_at, updated_at)
               VALUES ('item-v7', 'campaign-v7', 'Legacy item', 'Migration',
                       'investigating', 0, '["focused_tests"]', '{}', 1, 1)"""
        )
        connection.execute(
            """INSERT INTO jobs
               (id, campaign_id, work_item_id, role, stage, status, priority,
                payload_json, required_resources_json, queued_item_state,
                active_item_state, available_at, lease_owner, lease_token,
                lease_expires_at, heartbeat_at, created_at, updated_at)
               VALUES ('job-v7', 'campaign-v7', 'item-v7', 'investigator',
                       'legacy', 'running', 0, '{}', '["legacy:resource"]',
                       'backlog', 'investigating', 1, 'worker-v7', 'token-v7',
                       100, 1, 1, 1)"""
        )
        connection.execute(
            """INSERT INTO resource_leases
               (resource_key, owner_id, job_id, lease_token, acquired_at,
                heartbeat_at, expires_at)
               VALUES ('legacy:resource', 'worker-v7', 'job-v7', 'token-v7',
                       1, 1, 100)"""
        )
        connection.execute("PRAGMA user_version = 7")
        connection.commit()
    finally:
        connection.close()

    with SQLiteStore(path) as store:
        version = store._connection.execute("PRAGMA user_version").fetchone()[0]
        tables = {
            row["name"]
            for row in store._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        lease = store.list_resource_leases()[0]
        lease_columns = {
            row["name"]
            for row in store._connection.execute(
                "PRAGMA table_info(resource_leases)"
            ).fetchall()
        }
        assert store.foreign_key_violations() == []

    assert version == SCHEMA_VERSION == 9
    assert "resource_definitions" in tables
    assert {"lease_slot", "resource_definition_id"}.issubset(lease_columns)
    assert lease["resource_key"] == "legacy:resource"
    assert lease["lease_slot"] == 1
    assert lease["resource_definition_id"] is None


def test_schema_v8_migrates_definition_and_lease_integrity_hashes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "schema-v8.sqlite3"
    resource_id = "res_" + ("a" * 32)
    configuration = {
        "tenant_key": "tenant-v8",
        "database_name": "tenant_v8",
        "connection_env": "TENANT_V8_DATABASE",
    }
    identity_hash = _resource_identity_hash("tenant_database", configuration)
    connection = sqlite3.connect(str(path))
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
        ):
            for statement in schema:
                connection.execute(statement)
        connection.execute(
            """INSERT INTO resource_definitions
               (id, kind, label, enabled, configuration_json, campaign_id,
                metadata_json, policy_json, identity_hash, created_at, updated_at)
               VALUES (?, 'tenant_database', 'V8 tenant', 1, ?, NULL,
                       '{}', '{"limit":1,"mode":"exclusive"}', ?, 1, 1)""",
            (
                resource_id,
                json.dumps(configuration, separators=(",", ":"), sort_keys=True),
                identity_hash,
            ),
        )
        connection.execute("PRAGMA user_version = 8")
        connection.commit()
    finally:
        connection.close()

    with SQLiteStore(path) as store:
        resource = store.get_resource_definition(resource_id)
        version = store._connection.execute("PRAGMA user_version").fetchone()[0]
        lease_columns = {
            row["name"]
            for row in store._connection.execute(
                "PRAGMA table_info(resource_leases)"
            ).fetchall()
        }
        assert store.foreign_key_violations() == []

    assert version == SCHEMA_VERSION == 9
    assert resource["identity_hash"] == identity_hash
    assert len(resource["definition_hash"]) == 64
    assert "resource_identity_hash" in lease_columns


@pytest.mark.parametrize(
    ("kind", "configuration", "expected"),
    [
        (
            "chrome_profile",
            {
                "user_data_dir": "/private/tmp/agent-flow-chrome",
                "profile_directory": "Profile-1",
            },
            ("profile_directory", "Profile-1"),
        ),
        (
            "tenant_database",
            {
                "tenant_key": "tenant-qa",
                "database_name": "tenant_qa",
                "connection_env": "TENANT_QA_DATABASE",
            },
            ("connection_env", "TENANT_QA_DATABASE"),
        ),
        (
            "queue_environment",
            {
                "environment_key": "qa",
                "queue_names": ["default", "billing"],
                "connection_env": "QUEUE_QA_CONFIG",
            },
            ("queue_names", ["default", "billing"]),
        ),
        (
            "test_fixture",
            {
                "fixture_key": "disposable-proof",
                "root_path": "/private/tmp/agent-flow-disposable-proof",
                "disposable": True,
            },
            ("disposable", True),
        ),
    ],
)
def test_all_resource_kinds_are_typed_and_validated(
    tmp_path: Path,
    kind: str,
    configuration: dict,
    expected: tuple,
) -> None:
    with SQLiteStore(tmp_path / (kind + ".sqlite3")) as store:
        resource = store.define_resource(
            kind,
            "%s label" % kind,
            configuration,
            actor="resource-test",
            metadata={"purpose": "display-safe"},
        )

    assert resource["id"].startswith("res_")
    assert len(resource["id"]) == 36
    assert resource["kind"] == kind
    assert resource["configuration"][expected[0]] == expected[1]
    assert resource["metadata"] == {"purpose": "display-safe"}
    assert resource["policy"] == {"limit": 1, "mode": "exclusive"}
    assert len(resource["definition_hash"]) == 64


@pytest.mark.parametrize(
    "profile_directory",
    ["Default", "Profile 1", "System Profile"],
)
def test_chrome_profile_accepts_real_directory_names(
    tmp_path: Path, profile_directory: str
) -> None:
    with SQLiteStore(tmp_path / (profile_directory.replace(" ", "-") + ".sqlite3")) as store:
        resource = store.define_resource(
            "chrome_profile",
            "Real Chrome profile",
            {
                "user_data_dir": "/private/tmp/agent-flow-real-chrome-profile",
                "profile_directory": profile_directory,
            },
            actor="resource-test",
        )

    assert resource["configuration"]["profile_directory"] == profile_directory


@pytest.mark.parametrize(
    "profile_directory",
    [".", "..", "../Default", "Profile/1", "Profile\\1", " Profile 1", "Profile 1 "],
)
def test_chrome_profile_rejects_traversal_separators_and_ambiguous_whitespace(
    tmp_path: Path, profile_directory: str
) -> None:
    with SQLiteStore(tmp_path / "unsafe-chrome-profile.sqlite3") as store:
        with pytest.raises(ValueError, match="profile_directory"):
            store.define_resource(
                "chrome_profile",
                "Unsafe Chrome profile",
                {
                    "user_data_dir": "/private/tmp/agent-flow-unsafe-chrome-profile",
                    "profile_directory": profile_directory,
                },
                actor="resource-test",
            )
        assert store.list_resource_definitions() == []


@pytest.mark.parametrize(
    ("label", "metadata", "user_data_dir"),
    [
        (
            "Safe label",
            {"environment": "password=hunter2"},
            "/private/tmp/agent-flow-secret-chrome",
        ),
        (
            "Password=hunter2",
            {"environment": "qa"},
            "/private/tmp/agent-flow-secret-chrome",
        ),
        (
            "Safe label",
            {"environment": "qa"},
            "/private/tmp/agent-flow-password=hunter2/chrome",
        ),
    ],
)
def test_embedded_credential_assignments_are_rejected_without_echoing_secrets(
    tmp_path: Path, label: str, metadata: dict, user_data_dir: str
) -> None:
    with SQLiteStore(tmp_path / "embedded-secret.sqlite3") as store:
        with pytest.raises(ValueError, match="credential assignment") as captured:
            store.define_resource(
                "chrome_profile",
                label,
                {
                    "user_data_dir": user_data_dir,
                    "profile_directory": "Default",
                },
                actor="resource-test",
                metadata=metadata,
            )
        assert "hunter2" not in str(captured.value)
        assert store.list_resource_definitions() == []
        assert store.list_events() == []


@pytest.mark.parametrize(
    ("label", "metadata"),
    [
        ("QA \x1b[31mChrome", {"environment": "qa"}),
        ("QA \u202eChrome", {"environment": "qa"}),
        ("Safe label", {"environment": "qa\x1b[0m"}),
        ("Safe label", {"environment": "qa\u200b"}),
    ],
)
def test_labels_and_metadata_strings_reject_control_and_format_characters(
    tmp_path: Path, label: str, metadata: dict
) -> None:
    with SQLiteStore(tmp_path / "unsafe-display.sqlite3") as store:
        with pytest.raises(ValueError, match="control or format"):
            store.define_resource(
                "chrome_profile",
                label,
                {
                    "user_data_dir": "/private/tmp/agent-flow-display-chrome",
                    "profile_directory": "Default",
                },
                actor="resource-test",
                metadata=metadata,
            )
        assert store.list_resource_definitions() == []


@pytest.mark.parametrize(
    "configuration",
    [
        {
            "tenant_key": "tenant-qa",
            "database_name": "tenant_qa",
            "connection_env": "TENANT_QA_DATABASE",
            "password": "must-not-persist",
        },
        {
            "tenant_key": "tenant-qa",
            "database_name": "mysql://user:password@db/tenant_qa",
            "connection_env": "TENANT_QA_DATABASE",
        },
        {
            "tenant_key": "tenant-qa",
            "database_name": "tenant_qa",
            "dsn": "mysql://user:password@db/tenant_qa",
            "connection_env": "TENANT_QA_DATABASE",
        },
        {
            "tenant_key": "tenant-qa",
            "database_name": "tenant_qa",
            "connection_env": "TENANT_QA_DATABASE",
            "apiKey": "must-not-persist",
        },
    ],
)
def test_secrets_and_credential_bearing_dsns_are_rejected(
    tmp_path: Path, configuration: dict
) -> None:
    with SQLiteStore(tmp_path / "resource-secrets.sqlite3") as store:
        with pytest.raises(ValueError, match="sensitive|credential-bearing"):
            store.define_resource(
                "tenant_database",
                "Unsafe database",
                configuration,
                actor="resource-test",
            )
        with pytest.raises(ValueError, match="sensitive"):
            store.define_resource(
                "tenant_database",
                "Unsafe metadata",
                {
                    "tenant_key": "tenant-qa",
                    "database_name": "tenant_qa",
                    "connection_env": "TENANT_QA_DATABASE",
                },
                actor="resource-test",
                metadata={"access_token": "must-not-persist"},
            )
        assert store.list_resource_definitions() == []


def test_duplicate_resource_identity_is_rejected_deterministically(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "resource-identity.sqlite3") as store:
        first = _chrome(store, "First label")
        with pytest.raises(
            TransitionConflict,
            match="already registered as %s" % first["id"],
        ):
            _chrome(
                store,
                "Different display label",
                policy={"mode": "shared", "limit": 2},
            )
        assert [
            resource["id"] for resource in store.list_resource_definitions()
        ] == [first["id"]]


def test_resource_definition_ids_are_byte_exact_for_reads_and_mutations(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "exact-resource-id.sqlite3") as store:
        resource = _chrome(store)
        for obscured_id in (" " + resource["id"], resource["id"] + " ", "\t" + resource["id"]):
            with pytest.raises(ValueError, match="exact res_<32 hex>"):
                store.get_resource_definition(obscured_id)
            with pytest.raises(ValueError, match="exact res_<32 hex>"):
                store.set_resource_enabled(
                    obscured_id, False, actor="resource-test"
                )
            with pytest.raises(ValueError, match="exact res_<32 hex>"):
                store.define_resource(
                    "chrome_profile",
                    "Obscured custom ID",
                    {
                        "user_data_dir": "/private/tmp/agent-flow-obscured-id",
                        "profile_directory": "Default",
                    },
                    actor="resource-test",
                    resource_id=obscured_id,
                )
        assert store.get_resource_definition(resource["id"])["enabled"] is True


def test_whitespace_obscured_definition_id_cannot_bypass_into_raw_resource_keys(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "obscured-required-resource.sqlite3") as store:
        campaign = _campaign(store)
        resource = _chrome(store)
        blocked = _job(
            store,
            campaign["id"],
            "obscured-high",
            " " + resource["id"] + " ",
            priority=100,
        )
        eligible = _job(
            store,
            campaign["id"],
            "raw-low",
            "internal:narrow-resource",
            priority=1,
        )

        claim = store.claim_job("investigator", "worker")

        assert claim is not None and claim["id"] == eligible["id"]
        assert store.get_job(blocked["id"])["status"] == "pending"
        lease = store.list_resource_leases()[0]
        assert lease["resource_key"] == "internal:narrow-resource"
        assert lease["resource_definition_id"] is None


def test_valid_looking_identity_drift_fails_reads_and_skips_blocked_job(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "resource-identity-drift.sqlite3") as store:
        campaign = _campaign(store)
        drifted = _chrome(store, "Drifted Chrome")
        eligible_resource = store.define_resource(
            "queue_environment",
            "Eligible queues",
            {
                "environment_key": "qa",
                "queue_names": ["default"],
                "connection_env": "QUEUE_QA_CONFIG",
            },
            actor="resource-test",
        )
        blocked = _job(
            store, campaign["id"], "drifted-high", drifted["id"], priority=100
        )
        eligible = _job(
            store,
            campaign["id"],
            "eligible-low",
            eligible_resource["id"],
            priority=1,
        )
        store._connection.execute(
            "UPDATE resource_definitions SET configuration_json = ? WHERE id = ?",
            (
                json.dumps(
                    {
                        "user_data_dir": "/private/tmp/agent-flow-chrome-profile",
                        "profile_directory": "Profile-2",
                    }
                ),
                drifted["id"],
            ),
        )

        with pytest.raises(StorageError, match="identity hash"):
            store.get_resource_definition(drifted["id"])
        with pytest.raises(StorageError, match="identity hash"):
            store.list_resource_definitions()

        claim = store.claim_job("investigator", "worker")

        assert claim is not None and claim["id"] == eligible["id"]
        assert store.get_job(blocked["id"])["status"] == "pending"
        assert all(
            lease["resource_definition_id"] != drifted["id"]
            for lease in store.list_resource_leases()
        )


def test_canonicalization_cannot_hide_configuration_drift(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "canonical-drift.sqlite3") as store:
        campaign = _campaign(store)
        resource = store.define_resource(
            "tenant_database",
            "Canonical tenant",
            {
                "tenant_key": "tenant-qa",
                "database_name": "tenant_qa",
                "connection_env": "TENANT_QA_DATABASE",
            },
            actor="resource-test",
        )
        job = _job(store, campaign["id"], "canonical-drift", resource["id"])
        store._connection.execute(
            "UPDATE resource_definitions SET configuration_json = ? WHERE id = ?",
            (
                json.dumps(
                    {
                        "tenant_key": " tenant-qa ",
                        "database_name": "tenant_qa",
                        "connection_env": "TENANT_QA_DATABASE",
                    }
                ),
                resource["id"],
            ),
        )

        with pytest.raises(StorageError, match="not canonical"):
            store.get_resource_definition(resource["id"])
        assert store.claim_job("investigator", "worker") is None
        assert store.get_job(job["id"])["status"] == "pending"


def test_post_claim_definition_drift_cannot_finalize_success(
    tmp_path: Path,
) -> None:
    proof = tmp_path / "investigation-proof.txt"
    proof.write_text("bounded proof\n", encoding="utf-8")
    with SQLiteStore(tmp_path / "post-claim-drift.sqlite3") as store:
        campaign = _campaign(store)
        resource = _chrome(store)
        job = _job(store, campaign["id"], "post-claim-drift", resource["id"])
        claim = store.claim_job("investigator", "worker")
        assert claim is not None
        store._connection.execute(
            "UPDATE resource_definitions SET configuration_json = ? WHERE id = ?",
            (
                json.dumps(
                    {
                        "user_data_dir": "/private/tmp/agent-flow-other-profile",
                        "profile_directory": "Default",
                    }
                ),
                resource["id"],
            ),
        )
        with pytest.raises(LeaseConflict, match="definition integrity"):
            store.commit_stage_result(
                job["id"],
                "worker",
                claim["lease_token"],
                {
                    "item_id": store.get_job(job["id"])["work_item_id"],
                    "outcome": "ready_for_fix",
                    "synopsis": "Bounded investigation completed.",
                    "reproduction_steps": ["Run the bounded fixture."],
                    "root_cause": "The fixture proves the resource fence.",
                    "proposed_fix": "Keep the resource identity exact.",
                    "acceptance_criteria": ["The exact resource remains bound."],
                    "evidence": [
                        {
                            "kind": "log",
                            "location": str(proof),
                            "description": "Bounded fixture proof.",
                        }
                    ],
                },
                "investigating",
                "ready_for_fix",
                "investigation.completed",
                next_job={
                    "role": "fixer",
                    "stage": "fix",
                    "active_item_state": "fixing",
                },
            )
        assert store.get_job(job["id"])["status"] == "running"
        assert store.get_work_item(store.get_job(job["id"])["work_item_id"])[
            "state"
        ] == "investigating"


def test_policy_drift_cannot_widen_claimed_capacity(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "policy-drift.sqlite3") as store:
        campaign = _campaign(store)
        resource = _chrome(store)
        first = _job(store, campaign["id"], "policy-first", resource["id"])
        second = _job(store, campaign["id"], "policy-second", resource["id"])
        store._connection.execute(
            "UPDATE resource_definitions SET policy_json = ? WHERE id = ?",
            ('{"limit":128,"mode":"shared"}', resource["id"]),
        )
        with pytest.raises(StorageError, match="immutable fields"):
            store.get_resource_definition(resource["id"])
        assert store.claim_job("investigator", "worker-1") is None
        assert store.get_job(first["id"])["status"] == "pending"
        assert store.get_job(second["id"])["status"] == "pending"


def test_legacy_resource_api_rejects_whitespace_obscured_registered_ids(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "raw-resource-alias.sqlite3") as store:
        resource = _chrome(store)
        for obscured in (
            resource["id"],
            " " + resource["id"],
            resource["id"] + " ",
        ):
            with pytest.raises(ValueError, match="fenced job claims"):
                store.acquire_resource(obscured, "owner")
            with pytest.raises(ValueError, match="fenced job claims"):
                store.heartbeat_resource(obscured, "owner", "token")
            with pytest.raises(ValueError, match="fenced job claims"):
                store.release_resource(obscured, "owner", "token")
        assert store.list_resource_leases() == []


def test_legacy_resource_mutations_are_audited_and_event_failure_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "legacy-resource-audit.sqlite3") as store:
        lease = store.acquire_resource(
            "internal:audited-resource", "resource-owner", lease_seconds=30
        )
        assert lease is not None
        assert store.heartbeat_resource(
            lease["resource_key"],
            "resource-owner",
            lease["lease_token"],
            lease_seconds=30,
        )
        assert store.release_resource(
            lease["resource_key"], "resource-owner", lease["lease_token"]
        )
        assert [event["event_kind"] for event in store.list_events()] == [
            "resource.acquired",
            "resource.heartbeat",
            "resource.released",
        ]

        events_before = store.list_events()
        original_append = store._append_event

        def fail_acquire(connection, event_kind, **kwargs):
            if event_kind == "resource.acquired":
                raise RuntimeError("forced raw resource audit failure")
            return original_append(connection, event_kind, **kwargs)

        monkeypatch.setattr(store, "_append_event", fail_acquire)
        with pytest.raises(RuntimeError, match="forced raw resource audit"):
            store.acquire_resource("internal:rolled-back", "resource-owner")
        assert store.list_resource_leases() == []
        assert store.list_events() == events_before


def test_resource_mutation_actor_rejects_secrets_controls_and_rolls_back(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "resource-actor.sqlite3") as store:
        with pytest.raises(ValueError) as captured:
            store.define_resource(
                "chrome_profile",
                "Safe label",
                {
                    "user_data_dir": "/private/tmp/agent-flow-safe-actor",
                    "profile_directory": "Default",
                },
                actor="password=hunter2\x1b[31m",
            )
        assert "hunter2" not in str(captured.value)
        assert store.list_resource_definitions() == []
        assert store.list_events() == []

        resource = _chrome(store)
        events = store.list_events()
        with pytest.raises(ValueError) as captured:
            store.set_resource_enabled(
                resource["id"], False, actor="token=topsecret\u200b"
            )
        assert "topsecret" not in str(captured.value)
        assert store.get_resource_definition(resource["id"])["enabled"] is True
        assert store.list_events() == events


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_resource_metadata_rejects_non_finite_numbers(
    tmp_path: Path, value: float
) -> None:
    with SQLiteStore(tmp_path / "non-finite-metadata.sqlite3") as store:
        with pytest.raises(ValueError, match="finite"):
            store.define_resource(
                "chrome_profile",
                "Safe label",
                {
                    "user_data_dir": "/private/tmp/agent-flow-finite-metadata",
                    "profile_directory": "Default",
                },
                actor="resource-test",
                metadata={"ratio": value},
            )
        assert store.list_resource_definitions() == []


@pytest.mark.parametrize("blocked_kind", ["missing", "malformed", "disabled", "scope"])
def test_missing_disabled_malformed_and_out_of_scope_resources_fail_closed(
    tmp_path: Path, blocked_kind: str
) -> None:
    with SQLiteStore(tmp_path / (blocked_kind + ".sqlite3")) as store:
        target = _campaign(store, "target campaign")
        if blocked_kind == "missing":
            resource_id = "res_" + ("a" * 32)
        elif blocked_kind == "malformed":
            resource_id = "res_not-an-exact-id"
        elif blocked_kind == "disabled":
            resource_id = _chrome(store, enabled=False)["id"]
        else:
            other = _campaign(store, "other campaign")
            resource_id = _chrome(store, campaign_id=other["id"])["id"]
        job = _job(store, target["id"], blocked_kind, resource_id)

        assert store.claim_job("investigator", "worker") is None
        assert store.get_job(job["id"])["status"] == "pending"
        assert store.list_resource_leases() == []


def test_exclusive_definition_allows_only_one_concurrent_job(
    tmp_path: Path,
) -> None:
    path = tmp_path / "exclusive.sqlite3"
    with SQLiteStore(path) as store:
        campaign = _campaign(store)
        resource = _chrome(store)
        first = _job(store, campaign["id"], "first", resource["id"])
        second = _job(store, campaign["id"], "second", resource["id"])

    def claim(worker_id: str) -> Optional[dict]:
        with SQLiteStore(path) as competing_store:
            return competing_store.claim_job("investigator", worker_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(claim, ("worker-1", "worker-2")))

    claimed = [claim for claim in claims if claim is not None]
    assert len(claimed) == 1
    assert claimed[0]["id"] == first["id"]
    with SQLiteStore(path) as store:
        assert store.get_job(second["id"])["status"] == "pending"
        leases = store.list_resource_leases()
        assert [(lease["resource_definition_id"], lease["lease_slot"]) for lease in leases] == [
            (resource["id"], 1)
        ]


def test_malformed_persisted_definition_is_skipped_without_head_of_line_blocking(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "malformed-persisted.sqlite3") as store:
        campaign = _campaign(store)
        malformed = _chrome(store, "Malformed persisted resource")
        eligible = store.define_resource(
            "queue_environment",
            "Eligible resource",
            {
                "environment_key": "qa",
                "queue_names": ["default"],
                "connection_env": "QUEUE_QA_CONFIG",
            },
            actor="resource-test",
        )
        blocked_job = _job(
            store, campaign["id"], "malformed-high", malformed["id"], priority=100
        )
        eligible_job = _job(
            store, campaign["id"], "eligible-low", eligible["id"], priority=1
        )
        store._connection.execute(
            "UPDATE resource_definitions SET configuration_json = ? WHERE id = ?",
            ("{not-json", malformed["id"]),
        )

        claim = store.claim_job("investigator", "worker")

        assert claim is not None
        assert claim["id"] == eligible_job["id"]
        assert store.get_job(blocked_job["id"])["status"] == "pending"


def test_shared_definition_enforces_limit_and_reuses_released_slot(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "shared.sqlite3") as store:
        campaign = _campaign(store)
        resource = _chrome(
            store,
            policy={"mode": "shared", "limit": 2},
        )
        jobs = [
            _job(store, campaign["id"], "shared-%d" % number, resource["id"])
            for number in range(3)
        ]

        first = store.claim_job("investigator", "worker-1")
        second = store.claim_job("investigator", "worker-2")
        assert first is not None and second is not None
        assert store.claim_job("investigator", "worker-3") is None
        assert [lease["lease_slot"] for lease in store.list_resource_leases()] == [1, 2]

        store.fail_job(
            first["id"],
            "worker-1",
            first["lease_token"],
            "shared slot release fixture",
            requeue=False,
        )
        third = store.claim_job("investigator", "worker-3")
        assert third is not None
        assert third["id"] == jobs[2]["id"]
        assert [lease["lease_slot"] for lease in store.list_resource_leases()] == [1, 2]


def test_resource_blocked_job_is_not_a_head_of_line_blocker(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "resource-head-of-line.sqlite3") as store:
        campaign = _campaign(store)
        blocked = _chrome(store, "Disabled Chrome", enabled=False)
        eligible = store.define_resource(
            "queue_environment",
            "QA queues",
            {
                "environment_key": "qa",
                "queue_names": ["default"],
                "connection_env": "QUEUE_QA_CONFIG",
            },
            actor="resource-test",
        )
        blocked_job = _job(
            store, campaign["id"], "blocked", blocked["id"], priority=100
        )
        eligible_job = _job(
            store, campaign["id"], "eligible", eligible["id"], priority=1
        )

        claim = store.claim_job("investigator", "worker")

        assert claim is not None
        assert claim["id"] == eligible_job["id"]
        assert store.get_job(blocked_job["id"])["status"] == "pending"


def test_definition_mutations_and_lease_lifecycle_are_audited_and_atomic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "resource-events.sqlite3"
    clock = ManualClock()
    with SQLiteStore(path, clock=clock) as store:
        original_append = store._append_event

        def fail_define(*_args, **_kwargs):
            raise RuntimeError("forced resource event failure")

        monkeypatch.setattr(store, "_append_event", fail_define)
        with pytest.raises(RuntimeError, match="forced resource event"):
            _chrome(store, "Rolled back")
        assert store.list_resource_definitions() == []
        monkeypatch.setattr(store, "_append_event", original_append)

        campaign = _campaign(store)
        resource = _chrome(store, campaign_id=campaign["id"])

        def fail_disable(*_args, **_kwargs):
            raise RuntimeError("forced disable event failure")

        monkeypatch.setattr(store, "_append_event", fail_disable)
        with pytest.raises(RuntimeError, match="forced disable event"):
            store.set_resource_enabled(resource["id"], False, actor="operator")
        monkeypatch.setattr(store, "_append_event", original_append)
        assert store.get_resource_definition(resource["id"])["enabled"] is True

        store.set_resource_enabled(resource["id"], False, actor="operator")
        store.set_resource_enabled(resource["id"], True, actor="operator")
        job = _job(store, campaign["id"], "audited", resource["id"])
        first = store.claim_job("investigator", "worker-1", lease_seconds=5)
        assert first is not None
        store.interrupt_job(job["id"], "worker-1", first["lease_token"])
        second = store.claim_job("investigator", "worker-2", lease_seconds=5)
        assert second is not None
        clock.advance(6)

    with SQLiteStore(path, clock=clock) as restarted:
        recovery = restarted.recover_expired_leases()
        events = restarted.list_events(campaign_id=campaign["id"])
        event_kinds = [event["event_kind"] for event in events]
        assert recovery == {"jobs": 1, "resources": 0, "job_ids": [job["id"]]}
        assert restarted.list_resource_leases() == []
        assert restarted.get_job(job["id"])["status"] == "pending"
        assert restarted.foreign_key_violations() == []

    for event_kind in (
        "resource.defined",
        "resource.disabled",
        "resource.enabled",
        "resource.claimed",
        "resource.released",
        "resource.recovered",
    ):
        assert event_kind in event_kinds


@pytest.mark.parametrize(
    ("failed_event", "operation"),
    [
        ("resource.claimed", "claim"),
        ("resource.released", "release"),
        ("resource.recovered", "recover"),
    ],
)
def test_resource_lifecycle_event_failures_roll_back_associated_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_event: str,
    operation: str,
) -> None:
    clock = ManualClock()
    with SQLiteStore(tmp_path / (operation + "-event-rollback.sqlite3"), clock=clock) as store:
        campaign = _campaign(store)
        resource = _chrome(store, campaign_id=campaign["id"])
        job = _job(store, campaign["id"], operation, resource["id"])
        claim = None
        if operation != "claim":
            claim = store.claim_job(
                "investigator", "worker", lease_seconds=5
            )
            assert claim is not None
            if operation == "recover":
                clock.advance(6)

        events_before = store.list_events(campaign_id=campaign["id"])
        original_append = store._append_event

        def fail_selected_event(connection, event_kind, **kwargs):
            if event_kind == failed_event:
                raise RuntimeError("forced %s failure" % failed_event)
            return original_append(connection, event_kind, **kwargs)

        monkeypatch.setattr(store, "_append_event", fail_selected_event)
        with pytest.raises(RuntimeError, match="forced %s failure" % failed_event):
            if operation == "claim":
                store.claim_job("investigator", "worker", lease_seconds=5)
            elif operation == "release":
                assert claim is not None
                store.interrupt_job(job["id"], "worker", claim["lease_token"])
            else:
                store.recover_expired_leases()

        persisted_job = store.get_job(job["id"])
        if operation == "claim":
            assert persisted_job["status"] == "pending"
            assert store.list_attempts(job_id=job["id"]) == []
            assert store.list_resource_leases() == []
        else:
            assert persisted_job["status"] == "running"
            assert store.list_attempts(job_id=job["id"])[0]["status"] == "running"
            assert len(store.list_resource_leases()) == 1
        assert store.list_events(campaign_id=campaign["id"]) == events_before


def test_tampered_definition_never_leaks_secrets_or_controls_to_read_surfaces_or_events(
    tmp_path: Path,
) -> None:
    database = tmp_path / "tampered-display.sqlite3"
    dangerous_label = "password=hunter2\x1b[31m"
    dangerous_metadata = {"environment": "token=topsecret\u200b"}
    with SQLiteStore(database) as store:
        campaign = _campaign(store, "Tampered display")
        resource = _chrome(store, "Original safe Chrome", campaign_id=campaign["id"])
        job = _job(store, campaign["id"], "tampered", resource["id"])
        claim = store.claim_job("investigator", "worker")
        assert claim is not None
        store._connection.execute(
            """UPDATE resource_definitions
               SET label = ?, metadata_json = ? WHERE id = ?""",
            (dangerous_label, json.dumps(dangerous_metadata), resource["id"]),
        )

        with pytest.raises(StorageError):
            store.get_resource_definition(resource["id"])
        with pytest.raises(StorageError):
            store.list_resource_definitions()

        leases = store.list_resource_leases(campaign_id=campaign["id"])
        status_snapshot = store.read_campaign_status_snapshot(campaign["id"])
        watch_snapshot = store.read_campaign_watch_snapshot(campaign["id"])
        for value in (leases, status_snapshot, watch_snapshot):
            serialized = repr(value)
            assert "hunter2" not in serialized
            assert "topsecret" not in serialized
            assert "\x1b" not in serialized
            assert "\u200b" not in serialized
        assert leases[0]["resource_key"] == resource["id"]
        assert leases[0]["resource_label"] is None
        assert leases[0]["resource_kind"] is None

    for command in (
        ["resource-list", "--database", str(database)],
        ["resource-show", resource["id"], "--database", str(database)],
        ["status", campaign["id"], "--database", str(database)],
        [
            "watch",
            campaign["id"],
            "--refresh-count",
            "1",
            "--database",
            str(database),
        ],
    ):
        result = runner.invoke(app, command)
        assert "hunter2" not in result.output
        assert "topsecret" not in result.output
        assert "\x1b" not in result.output
        assert "\u200b" not in result.output

    with SQLiteStore(database) as store:
        store.fail_job(
            job["id"],
            "worker",
            claim["lease_token"],
            "safe cleanup",
            requeue=False,
        )
        serialized_events = repr(store.list_events(campaign_id=campaign["id"]))
        assert "hunter2" not in serialized_events
        assert "topsecret" not in serialized_events
        assert "\x1b" not in serialized_events
        assert "\u200b" not in serialized_events


def test_cli_requires_exact_ids_and_read_only_status_surfaces_safe_identity(
    tmp_path: Path,
) -> None:
    database = tmp_path / "resource-cli.sqlite3"
    with SQLiteStore(database) as store:
        campaign = _campaign(store, "CLI resources")

    defined = runner.invoke(
        app,
        [
            "resource-define",
            "chrome_profile",
            "CLI Chrome",
            "--configuration",
            json.dumps(
                {
                    "user_data_dir": "/private/tmp/agent-flow-cli-chrome",
                    "profile_directory": "Default",
                }
            ),
            "--campaign",
            campaign["id"],
            "--metadata",
            '{"environment":"qa"}',
            "--by",
            "cli-operator",
            "--database",
            str(database),
        ],
    )
    assert defined.exit_code == 0, defined.output
    resource_id = defined.output.strip().splitlines()[-1]
    assert resource_id.startswith("res_")

    refused = runner.invoke(
        app,
        [
            "resource-disable",
            "CLI Chrome",
            "--by",
            "cli-operator",
            "--database",
            str(database),
        ],
    )
    assert refused.exit_code != 0
    assert "resource definition mutations require an exact res_<32 hex>" in (
        " ".join(refused.output.split())
    )

    disabled = runner.invoke(
        app,
        [
            "resource-disable",
            resource_id,
            "--by",
            "cli-operator",
            "--database",
            str(database),
        ],
    )
    enabled = runner.invoke(
        app,
        [
            "resource-enable",
            resource_id,
            "--by",
            "cli-operator",
            "--database",
            str(database),
        ],
    )
    assert disabled.exit_code == 0, disabled.output
    assert enabled.exit_code == 0, enabled.output

    listed = runner.invoke(
        app,
        ["resource-list", "--database", str(database)],
    )
    shown = runner.invoke(
        app,
        ["resource-show", resource_id, "--database", str(database)],
    )
    assert listed.exit_code == 0, listed.output
    assert shown.exit_code == 0, shown.output
    assert resource_id in listed.output
    assert "CLI Chrome" in listed.output
    assert "user_data_dir" not in listed.output
    assert "user_data_dir" in shown.output
    assert "profile_directory" in shown.output

    with SQLiteStore(database) as store:
        job = _job(store, campaign["id"], "visible", resource_id)
        claim = store.claim_job("investigator", "visible-worker")
        assert claim is not None and claim["id"] == job["id"]
        events_before = store.list_events(campaign_id=campaign["id"])

    status = runner.invoke(
        app,
        ["status", campaign["id"], "--database", str(database)],
    )
    watch = runner.invoke(
        app,
        [
            "watch",
            campaign["id"],
            "--refresh-count",
            "1",
            "--database",
            str(database),
        ],
    )
    assert status.exit_code == 0, status.output
    assert watch.exit_code == 0, watch.output
    for output in (status.output, watch.output):
        normalized = " ".join(output.split())
        assert "CLI Chrome" in normalized
        assert "Chrome Profile" in normalized
        assert "user_data_dir" not in normalized
        assert "profile_directory" not in normalized

    with SQLiteStore(database) as store:
        assert store.list_events(campaign_id=campaign["id"]) == events_before
        assert store.foreign_key_violations() == []
