from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

import pytest

from agent_flow.storage import LeaseConflict, SQLiteStore
from agent_flow.process_reconciler import DarwinProcessRuntime
from agent_flow.worktrees import (
    _CaptureThread,
    GuardedGitCommandRunner,
    GitCommandError,
    ManagedWorktreeConfig,
    ManagedWorktreeError,
    ManagedWorktreeManager,
)


class ManualClock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repository(path: Path) -> Path:
    path.mkdir()
    subprocess.run(("git", "init", "-q", str(path)), check=True)
    _git(path, "config", "user.name", "Agent Flow Tests")
    _git(path, "config", "user.email", "agent-flow@example.invalid")
    (path / "tracked.txt").write_text("base\n", encoding="utf-8")
    _git(path, "add", "tracked.txt")
    _git(path, "commit", "-q", "-m", "base")
    return path.resolve()


def _manager(
    store: SQLiteStore, tmp_path: Path, *, owner: str = "worktree-test"
) -> ManagedWorktreeManager:
    return ManagedWorktreeManager(
        store,
        owner=owner,
        config=ManagedWorktreeConfig(
            worktree_root=(tmp_path / "managed").resolve(),
            runtime_root=(tmp_path / "runtime").resolve(),
            command_timeout_seconds=5,
            terminate_grace_seconds=1,
            operation_lease_seconds=30,
        ),
    )


def _pending_fixer(
    store: SQLiteStore, repository: Path
) -> tuple[dict, dict, dict]:
    campaign = store.create_campaign(
        "real managed worktree",
        config={"repository_paths": [str(repository)]},
    )
    item = store.create_work_item(
        campaign["id"],
        "managed fix",
        description="Prove exact managed-worktree lifecycle behavior.",
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
    job = store.list_jobs(work_item_id=item["id"])[0]
    return campaign, item, job


def _finish_green(
    store: SQLiteStore, item: dict, evidence_path: Path
) -> None:
    fixer = store.claim_job("fixer", "fixer-test")
    assert fixer is not None
    fixed = store.commit_stage_result(
        fixer["id"],
        "fixer-test",
        fixer["lease_token"],
        {
            "schema_version": 1,
            "item_id": item["id"],
            "outcome": "ready_for_test",
            "summary": "The bounded fix is ready for focused verification.",
            "changed_files": ["tracked.txt"],
            "tests_run": ["focused lifecycle fixture"],
            "tester_instructions": ["Run the focused lifecycle proof."],
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
    tester_job = fixed["next_job"]
    assert tester_job["managed_worktree_id"] == fixer["managed_worktree_id"]
    tester = store.claim_job("tester", "tester-test")
    assert tester is not None
    assert tester["managed_worktree_id"] == fixer["managed_worktree_id"]
    store.commit_stage_result(
        tester["id"],
        "tester-test",
        tester["lease_token"],
        {
            "schema_version": 1,
            "item_id": item["id"],
            "outcome": "pass",
            "summary": "The focused managed-worktree proof passed.",
            "gate_proofs": [
                {
                    "gate": "focused_tests",
                    "result": "pass",
                    "summary": "Focused proof passed.",
                    "evidence": [
                        {
                            "kind": "test",
                            "location": str(evidence_path),
                            "description": "Committed repository fixture evidence.",
                            "metadata": {},
                        }
                    ],
                }
            ],
            "failure_summary": None,
            "blocker": None,
        },
        "testing",
        "verified_green",
        "test.verified_green",
    )


def test_real_worktree_creation_binds_fixer_and_preserves_dirty_source(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    (repository / "source-only.txt").write_text("untracked\n", encoding="utf-8")
    (repository / "tracked.txt").unlink()
    before = _git(repository, "status", "--porcelain=v2", "--untracked-files=all")
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        campaign, item, pending = _pending_fixer(store, repository)
        assert pending["workspace_kind"] == "managed_worktree"
        assert pending["managed_worktree_id"] is None
        assert store.claim_job("fixer", "too-early") is None

        manager = _manager(store, tmp_path)
        worktree = manager.provision(
            campaign["id"], item["id"], repository, "HEAD"
        )

        assert worktree["state"] == "ready"
        assert Path(worktree["worktree_path"]).is_dir()
        assert manager.verify(worktree["id"])["head_revision"] == _git(
            repository, "rev-parse", "HEAD"
        )
        claim = store.claim_job("fixer", "fixer-test")
        assert claim is not None
        assert claim["managed_worktree_id"] == worktree["id"]
        assert "git-worktree:%s" % worktree["id"] in claim["required_resources"]
        binding = store.get_claimed_managed_worktree(
            claim["id"], "fixer-test", claim["lease_token"]
        )
        assert binding is not None
        assert binding["id"] == worktree["id"]
        assert store.foreign_key_violations() == []

    after = _git(repository, "status", "--porcelain=v2", "--untracked-files=all")
    assert after == before


def test_creation_attaches_only_the_fixer_job_fenced_at_request_time(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        campaign, item, original_job = _pending_fixer(store, repository)
        manager = _manager(store, tmp_path)
        request = store.request_managed_worktree

        def add_competing_fixer(*args: object, **kwargs: object) -> dict:
            result = request(*args, **kwargs)
            store.enqueue_job(
                item["id"],
                "fixer",
                stage="alternate-fix",
                queued_item_state="ready_for_fix",
                active_item_state="fixing",
            )
            return result

        store.request_managed_worktree = add_competing_fixer  # type: ignore[method-assign]
        worktree = manager.provision(
            campaign["id"], item["id"], repository, "HEAD"
        )

        jobs = {job["id"]: job for job in store.list_jobs(work_item_id=item["id"])}
        alternate = next(job for job in jobs.values() if job["stage"] == "alternate-fix")
        assert jobs[original_job["id"]]["managed_worktree_id"] == worktree["id"]
        assert alternate["managed_worktree_id"] is None
        assert worktree["fixer_job_id"] == original_job["id"]


def test_creation_completion_requires_guardian_and_artifact_proof(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        campaign, item, _pending = _pending_fixer(store, repository)
        manager = _manager(store, tmp_path)
        manager.command_runner.run = (  # type: ignore[method-assign]
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError("stop before guardian registration")
            )
        )
        manager._quarantine_if_fenced = (  # type: ignore[method-assign]
            lambda *_args, **_kwargs: None
        )
        with pytest.raises(RuntimeError, match="before guardian"):
            manager.provision(campaign["id"], item["id"], repository, "HEAD")

        operation = store.list_worktree_operations()[0]
        worktree = store.list_managed_worktrees()[0]
        with pytest.raises(LeaseConflict, match="guardian identity"):
            store.complete_managed_worktree_creation(
                operation["id"],
                operation["owner"],
                operation["fencing_token"],
                operation["expected_identity"],
                {},
                worktree["source_snapshot"],
            )


def test_existing_shared_worktree_root_is_rejected_without_chmod(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    shared_root = tmp_path / "managed"
    shared_root.mkdir(mode=0o755)
    os.chmod(shared_root, 0o755)
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        campaign, item, _pending = _pending_fixer(store, repository)
        manager = _manager(store, tmp_path)

        with pytest.raises(ManagedWorktreeError, match="permissions are not private"):
            manager.provision(campaign["id"], item["id"], repository, "HEAD")

    assert stat.S_IMODE(shared_root.stat().st_mode) == 0o755


def test_clean_terminal_worktree_is_removed_but_branch_is_retained(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        campaign, item, _pending = _pending_fixer(store, repository)
        manager = _manager(store, tmp_path)
        worktree = manager.provision(
            campaign["id"], item["id"], repository, "HEAD"
        )
        worktree_path = Path(worktree["worktree_path"])
        branch_ref = str(worktree["branch_ref"])
        _finish_green(store, item, repository / "tracked.txt")

        removed = manager.cleanup(worktree["id"])

        assert removed["state"] == "removed"
        assert not worktree_path.exists()
        assert _git(repository, "show-ref", "--hash", branch_ref) == worktree[
            "head_revision"
        ]
        assert store.foreign_key_violations() == []


def test_cleanup_refuses_assume_unchanged_content_loss(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        campaign, item, _pending = _pending_fixer(store, repository)
        manager = _manager(store, tmp_path)
        worktree = manager.provision(
            campaign["id"], item["id"], repository, "HEAD"
        )
        path = Path(worktree["worktree_path"])
        _finish_green(store, item, repository / "tracked.txt")
        _git(path, "update-index", "--assume-unchanged", "tracked.txt")
        (path / "tracked.txt").write_text("hidden change\n", encoding="utf-8")
        assert _git(path, "status", "--porcelain") == ""

        with pytest.raises(ManagedWorktreeError, match="dirty"):
            manager.cleanup(worktree["id"])

        assert path.is_dir()
        assert store.get_managed_worktree(worktree["id"])["state"] == "quarantined"


def test_bad_base_filter_is_rejected_before_checkout_execution(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repo")
    safe = _git(repository, "rev-parse", "HEAD")
    (repository / ".gitattributes").write_text(
        "victim.txt filter=pwn\n", encoding="utf-8"
    )
    (repository / "victim.txt").write_text("victim\n", encoding="utf-8")
    _git(repository, "add", ".gitattributes", "victim.txt")
    _git(repository, "commit", "-q", "-m", "bad filter base")
    bad = _git(repository, "rev-parse", "HEAD")
    _git(repository, "reset", "--hard", safe)
    marker = tmp_path / "filter-ran"
    _git(
        repository,
        "config",
        "filter.pwn.smudge",
        "sh -c 'touch %s; cat'" % marker,
    )

    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        campaign, item, _pending = _pending_fixer(store, repository)
        manager = _manager(store, tmp_path)
        with pytest.raises(ManagedWorktreeError, match="filter attributes"):
            manager.provision(campaign["id"], item["id"], repository, bad)

        assert not marker.exists()
        assert store.list_managed_worktrees() == []


def test_working_tree_filter_is_rejected_without_running_filter(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repo")
    marker = tmp_path / "working-filter-ran"
    (repository / ".gitattributes").write_text(
        "tracked.txt filter=pwn\n", encoding="utf-8"
    )
    _git(
        repository,
        "config",
        "filter.pwn.smudge",
        "sh -c 'touch %s; cat'" % marker,
    )

    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        campaign, item, _pending = _pending_fixer(store, repository)
        manager = _manager(store, tmp_path)
        with pytest.raises(ManagedWorktreeError, match="working-tree filter"):
            manager.provision(campaign["id"], item["id"], repository, "HEAD")

        assert not marker.exists()
        assert store.list_managed_worktrees() == []


def test_persisted_command_artifact_digest_matches_retained_bytes(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "artifact.log"
    capture = _CaptureThread(io.BytesIO(b"x" * 2048), artifact, 1024)
    capture.start()
    capture.join(1)

    assert capture.truncated is True
    assert artifact.stat().st_size == 1024
    assert capture.digest.hexdigest() == hashlib.sha256(
        artifact.read_bytes()
    ).hexdigest()


def test_restart_reconciliation_adopts_exact_completed_creation(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    clock = ManualClock()
    with SQLiteStore(tmp_path / "flow.sqlite3", clock=clock) as store:
        campaign, item, _pending = _pending_fixer(store, repository)
        manager = _manager(store, tmp_path, owner="crashed-owner")
        original_complete = store.complete_managed_worktree_creation

        def crash_before_commit(*_args: object, **_kwargs: object) -> dict:
            raise RuntimeError("simulated supervisor loss after Git completed")

        store.complete_managed_worktree_creation = (  # type: ignore[method-assign]
            crash_before_commit
        )
        manager._quarantine_if_fenced = (  # type: ignore[method-assign]
            lambda *_args, **_kwargs: None
        )
        with pytest.raises(RuntimeError, match="simulated supervisor loss"):
            manager.provision(campaign["id"], item["id"], repository, "HEAD")
        store.complete_managed_worktree_creation = original_complete  # type: ignore[method-assign]

        operation = store.list_worktree_operations()[0]
        assert operation["status"] == "running"
        assert operation["process_state"] == "stopped"
        clock.advance(31)

        results = _manager(
            store, tmp_path, owner="restart-reconciler"
        ).reconcile_expired()

        assert len(results) == 1
        worktree = store.list_managed_worktrees()[0]
        assert worktree["state"] == "ready"
        assert store.list_jobs(work_item_id=item["id"])[0][
            "managed_worktree_id"
        ] == worktree["id"]
        assert store.list_worktree_operations()[0]["status"] == "succeeded"
        assert store.foreign_key_violations() == []


def test_guardian_release_failure_reaps_and_clears_durable_process(
    tmp_path: Path,
) -> None:
    runtime = DarwinProcessRuntime()
    runner = GuardedGitCommandRunner(
        runtime=runtime,
        timeout_seconds=2,
        terminate_grace_seconds=1,
        max_output_bytes=1024,
    )
    recorded: list[tuple[int, int]] = []
    cleared: list[tuple[int, int]] = []

    def terminate_after_record(identity: object, _target: str) -> None:
        process_id = int(getattr(identity, "process_id"))
        process_group_id = int(getattr(identity, "process_group_id"))
        recorded.append((process_id, process_group_id))
        os.killpg(process_group_id, signal.SIGKILL)
        time.sleep(0.05)

    with pytest.raises(GitCommandError, match="release"):
        runner.run(
            ("/usr/bin/true",),
            cwd=tmp_path,
            environment={"PATH": os.environ.get("PATH", "")},
            artifact_directory=tmp_path / "guardian-artifacts",
            record_process=terminate_after_record,  # type: ignore[arg-type]
            clear_process=lambda pid, pgid: cleared.append((pid, pgid)),
        )

    assert recorded
    assert cleared == recorded
    with pytest.raises(ProcessLookupError):
        os.killpg(recorded[0][1], 0)


def test_restart_reconciliation_quarantines_create_without_process_proof(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    clock = ManualClock()
    with SQLiteStore(tmp_path / "flow.sqlite3", clock=clock) as store:
        campaign, item, _pending = _pending_fixer(store, repository)
        manager = _manager(store, tmp_path, owner="crashed-owner")
        manager.command_runner.run = (  # type: ignore[method-assign]
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError("simulated loss before guardian launch")
            )
        )
        manager._quarantine_if_fenced = (  # type: ignore[method-assign]
            lambda *_args, **_kwargs: None
        )
        with pytest.raises(RuntimeError, match="before guardian launch"):
            manager.provision(campaign["id"], item["id"], repository, "HEAD")
        clock.advance(31)

        results = _manager(
            store, tmp_path, owner="restart-reconciler"
        ).reconcile_expired()

        assert len(results) == 1
        assert results[0].status.value == "quarantined"
        assert store.list_managed_worktrees()[0]["state"] == "quarantined"
        assert store.list_worktree_operations()[0]["status"] == "quarantined"


def test_quarantined_active_guardian_can_be_reinspected_and_cleared(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    with SQLiteStore(tmp_path / "flow.sqlite3") as store:
        campaign, item, _pending = _pending_fixer(store, repository)
        manager = _manager(store, tmp_path)
        worktree = manager.provision(
            campaign["id"], item["id"], repository, "HEAD"
        )
        operation = store.list_worktree_operations()[0]
        assert operation["process_state"] == "stopped"
        with store._transaction() as connection:
            connection.execute(
                """UPDATE managed_worktrees
                   SET state = 'quarantined', last_error = 'transient inspection failure'
                   WHERE id = ?""",
                (worktree["id"],),
            )
            connection.execute(
                """UPDATE jobs SET managed_worktree_id = NULL,
                       required_resources_json = '[]'
                   WHERE id = ?""",
                (worktree["fixer_job_id"],),
            )
            connection.execute(
                """UPDATE worktree_operations
                   SET status = 'quarantined', process_state = 'active',
                       process_stopped_at = NULL,
                       error = 'transient inspection failure'
                   WHERE id = ?""",
                (operation["id"],),
            )

        results = manager.retry_quarantined_processes()

        assert len(results) == 1
        assert results[0].can_release is True
        retried = store.list_worktree_operations()[0]
        assert retried["status"] == "succeeded"
        assert retried["process_state"] == "stopped"
        assert retried["reconciliation_owner"] is None
        recovered = store.get_managed_worktree(worktree["id"])
        assert recovered["state"] == "ready"
        assert store.get_job(worktree["fixer_job_id"])[
            "managed_worktree_id"
        ] == worktree["id"]


def test_removal_reconciliation_rejects_broken_symlink_replacement(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    clock = ManualClock()
    with SQLiteStore(tmp_path / "flow.sqlite3", clock=clock) as store:
        campaign, item, _pending = _pending_fixer(store, repository)
        manager = _manager(store, tmp_path, owner="cleanup-owner")
        worktree = manager.provision(
            campaign["id"], item["id"], repository, "HEAD"
        )
        _finish_green(store, item, repository / "tracked.txt")
        original_complete = store.complete_managed_worktree_removal

        def crash_before_commit(*_args: object, **_kwargs: object) -> dict:
            raise RuntimeError("simulated loss after worktree removal")

        store.complete_managed_worktree_removal = crash_before_commit  # type: ignore[method-assign]
        manager._quarantine_if_fenced = (  # type: ignore[method-assign]
            lambda *_args, **_kwargs: None
        )
        with pytest.raises(RuntimeError, match="after worktree removal"):
            manager.cleanup(worktree["id"])
        store.complete_managed_worktree_removal = original_complete  # type: ignore[method-assign]
        path = Path(worktree["worktree_path"])
        path.symlink_to(tmp_path / "missing-target")
        assert path.is_symlink() and not path.exists()
        clock.advance(31)

        results = _manager(
            store, tmp_path, owner="restart-reconciler"
        ).reconcile_expired()

        assert results[0].status.value == "quarantined"
        assert path.is_symlink()
        assert store.get_managed_worktree(worktree["id"])["state"] == "quarantined"
