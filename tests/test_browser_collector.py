from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
import uuid

import pytest

from agent_flow.browser_collector import BrowserCollectorError, BrowserEvidenceCollector
from agent_flow.storage import SQLiteStore


@pytest.fixture
def runtime_root() -> Path:
    root = Path("/private/tmp/agent-flow-browser-collector-%s" % uuid.uuid4().hex)
    root.mkdir(mode=0o700)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _prepared(store: SQLiteStore, root: Path):
    fixture = root / "fixture.html"
    fixture.write_text(
        "<!doctype html><html><head><title>Agent Flow Browser Proof</title></head>"
        "<body><main>collector-ready</main></body></html>",
        encoding="utf-8",
    )
    fixture.chmod(0o600)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    campaign = store.create_campaign("browser collector")
    resource = store.define_resource(
        "chrome_profile",
        "Disposable visible Chrome",
        {
            "user_data_dir": str(root / "chrome-user-data"),
            "profile_directory": "Profile 1",
        },
        actor="collector-test",
        campaign_id=campaign["id"],
    )
    item = store.create_work_item(
        campaign["id"],
        "visible browser proof",
        description="Navigate the exact disposable fixture and capture it.",
        state="ready_for_test",
        required_gates=["browser"],
        initial_job={
            "role": "tester",
            "stage": "browser",
            "active_item_state": "testing",
            "required_resources": [resource["id"]],
        },
    )
    plan = store.create_browser_evidence_plan(
        item["id"],
        resource["id"],
        route=fixture.as_uri(),
        expected_title="Agent Flow Browser Proof",
        expected_body_text="collector-ready",
        runtime_root=runtime,
        timeout_seconds=15,
    )
    claim = store.claim_job("tester", "browser-collector")
    assert claim is not None
    contract = store.prepare_browser_evidence_execution(
        plan["id"],
        claim["id"],
        "browser-collector",
        claim["lease_token"],
    )
    return campaign, item, plan, claim, contract


def _chrome_processes(profile_root: Path) -> list[str]:
    result = subprocess.run(
        ("pgrep", "-af", str(profile_root)),
        capture_output=True,
        text=True,
        check=False,
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def test_visible_chrome_collector_captures_exact_disposable_route(
    tmp_path: Path, runtime_root: Path
) -> None:
    with SQLiteStore(tmp_path / "supervisor.sqlite3") as store:
        _campaign, _item, plan, _claim, contract = _prepared(store, runtime_root)
        profile_root = Path(contract["chrome_configuration"]["user_data_dir"])
        assert _chrome_processes(profile_root) == []
        result = BrowserEvidenceCollector().collect(contract)
        deadline = time.monotonic() + 3
        while _chrome_processes(profile_root) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _chrome_processes(profile_root) == []
        screenshot = Path(result["screenshot_path"])
        assert screenshot.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        assert hashlib.sha256(screenshot.read_bytes()).hexdigest() == result[
            "screenshot_sha256"
        ]
        assert result["observed_route"] == plan["route"]
        assert result["observed_title"] == "Agent Flow Browser Proof"
        assert result["observed_body_text"] == "collector-ready"
        assert store.foreign_key_violations() == []
        assert store.list_external_processes() == []


def test_browser_collector_rejects_worker_mutated_route_without_launch(
    tmp_path: Path, runtime_root: Path
) -> None:
    with SQLiteStore(tmp_path / "supervisor.sqlite3") as store:
        _campaign, _item, _plan, _claim, contract = _prepared(store, runtime_root)
        changed = dict(contract)
        changed["route"] = "https://example.invalid/"
        with pytest.raises(BrowserCollectorError, match="contract|fixture"):
            BrowserEvidenceCollector().collect(changed)
        assert _chrome_processes(
            Path(contract["chrome_configuration"]["user_data_dir"])
        ) == []


def test_browser_collector_refuses_an_existing_profile_session(
    tmp_path: Path, runtime_root: Path
) -> None:
    with SQLiteStore(tmp_path / "supervisor.sqlite3") as store:
        _campaign, _item, plan, _claim, contract = _prepared(store, runtime_root)
        collector = BrowserEvidenceCollector()
        profile_root = Path(contract["chrome_configuration"]["user_data_dir"])
        profile_root.mkdir(mode=0o700)
        process = subprocess.Popen(
            (
                str(collector.chrome_executable),
                "--user-data-dir=%s" % profile_root,
                "--profile-directory=Profile 1",
                "--remote-debugging-port=0",
                "--no-first-run",
                "--no-default-browser-check",
                plan["route"],
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 10
            while (
                not (profile_root / "DevToolsActivePort").exists()
                and time.monotonic() < deadline
            ):
                time.sleep(0.05)
            assert process.poll() is None
            assert (profile_root / "DevToolsActivePort").is_file()
            with pytest.raises(BrowserCollectorError, match="existing session state"):
                collector.collect(contract)
            assert process.poll() is None
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)
