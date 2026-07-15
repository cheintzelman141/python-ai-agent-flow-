"""Opt-in authenticated proof for the real managed Codex production line.

The proof owns a fixed disposable repository and accepts no target repository
or command input.  It is intentionally narrower than a general real-campaign
runner: the result must independently reconcile provider, Git, filesystem,
test, and SQLite evidence before it can report verified.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple
import uuid

from pydantic import ValidationError

from agent_flow.codex_worker import (
    CodexCliConfig,
    CodexCliWorker,
    codex_handoff_schema,
)
from agent_flow.models import (
    FixHandoff,
    InvestigationHandoff,
    TestHandoff,
    WorkerRole,
)
from agent_flow.process_reconciler import (
    ProcessInspectionError,
    local_process_runtime,
)
from agent_flow.scheduler import Scheduler
from agent_flow.sqlite_scheduler import (
    LOCAL_WRITE_APPROVAL_ACTION,
    SQLiteSchedulerStorage,
)
from agent_flow.storage import SQLiteStore
from agent_flow.workers import Worker
from agent_flow.worktrees import (
    GitInspector,
    ManagedWorktreeConfig,
    ManagedWorktreeManager,
)


FOCUSED_TEST_ARGUMENTS = ("-B", "-m", "unittest", "-v")
PROVIDER_ARTIFACT_KINDS = {
    "codex_schema",
    "codex_jsonl",
    "codex_stderr",
    "codex_final",
}
PROVIDER_ARTIFACT_NAMES = {
    "codex_schema": "handoff-schema.json",
    "codex_jsonl": "events.jsonl",
    "codex_stderr": "stderr.log",
    "codex_final": "final.json",
}
_COMPLETION_EVENT_BY_ROLE = {
    "investigator": "investigation_completed",
    "fixer": "fix_completed",
    "tester": "test_verified_green",
}
_HANDOFF_BY_ROLE = {
    WorkerRole.INVESTIGATOR: InvestigationHandoff,
    WorkerRole.FIXER: FixHandoff,
    WorkerRole.TESTER: TestHandoff,
}


class RealProofError(RuntimeError):
    """The fixed authenticated proof could not satisfy its contract."""


WorkerFactory = Callable[[WorkerRole, CodexCliConfig], Worker]


@dataclass(frozen=True)
class RealProofResult:
    root: Path
    report_path: Path
    verified: bool
    report: Mapping[str, Any]


class RealProofRunner:
    """Run and independently assess one fixed disposable Codex pipeline."""

    def __init__(
        self,
        *,
        root: Optional[Path] = None,
        worker_factory: Optional[WorkerFactory] = None,
        require_authenticated_provider: bool = True,
    ) -> None:
        generated = Path("/private/tmp") / (
            "agent-flow-real-proof-%s" % uuid.uuid4().hex
        )
        self.root = (root or generated).expanduser().resolve()
        self.source = self.root / "source"
        self.database = self.root / "agent-flow.sqlite3"
        self.worktree_root = self.root / "worktrees"
        self.lifecycle_runtime = self.root / "lifecycle-runtime"
        self.codex_runtime = self.root / "codex-runtime"
        self.report_path = self.root / "proof-report.json"
        self.focused_test_log = self.root / "supervisor-focused-test.log"
        self.worker_factory = worker_factory or self._codex_worker
        self.require_authenticated_provider = require_authenticated_provider
        self.inspector = GitInspector.controlled()
        self.git_executable = self.inspector.git_executable
        self.python_executable = Path(sys.executable).resolve()
        if not self.python_executable.is_file():
            raise RealProofError("current Python executable is not an existing file")
        try:
            supervisor_identity = local_process_runtime().inspect(os.getpid())
        except (OSError, ProcessInspectionError, ValueError) as error:
            raise RealProofError(
                "cannot inspect the proof supervisor executable"
            ) from error
        if supervisor_identity is None:
            raise RealProofError("proof supervisor process identity is absent")
        self.guardian_executable = Path(supervisor_identity.executable)
        self.executable_baselines = {
            "git_executable": self._executable_record(self.git_executable),
            "guardian_executable": self._executable_record(
                self.guardian_executable
            ),
            "python_executable": self._executable_record(
                self.python_executable
            ),
        }

    async def run(self) -> RealProofResult:
        report: Dict[str, Any] = {
            "root": str(self.root),
            "authenticated_provider_required": self.require_authenticated_provider,
            "verified": False,
        }
        try:
            report.update(self.executable_baselines)
            self._create_fixture()
            report["source_before"] = self._source_snapshot()
            await self._run_pipeline(report)
            self._assess(report)
        except BaseException as error:
            report["error"] = "%s: %s" % (type(error).__name__, error)
            report["verified"] = False
        self._write_report(report)
        return RealProofResult(
            root=self.root,
            report_path=self.report_path,
            verified=report["verified"] is True,
            report=report,
        )

    def _create_fixture(self) -> None:
        if self.root.exists() or self.root.is_symlink():
            raise RealProofError("proof root already exists")
        self.root.mkdir(mode=0o700)
        if self.root.stat().st_uid != os.getuid():
            raise RealProofError("proof root is not user-owned")
        if self.root.stat().st_mode & 0o077:
            raise RealProofError("proof root permissions are not private")
        self.source.mkdir(mode=0o700)
        self._git("init", "-q", "-b", "main")
        (self.source / "calculator.py").write_text(
            "def add(left: int, right: int) -> int:\n"
            "    return left - right\n",
            encoding="utf-8",
        )
        (self.source / "test_calculator.py").write_text(
            "from pathlib import Path\n"
            "import unittest\n\n"
            "from calculator import add\n\n\n"
            "class CalculatorTests(unittest.TestCase):\n"
            "    def test_adds_two_numbers(self) -> None:\n"
            "        test_file = Path(__file__).resolve()\n"
            "        print('AGENT_FLOW_TEST_FILE=%s' % test_file)\n"
            "        self.assertEqual(Path.cwd().resolve(), test_file.parent)\n"
            "        self.assertEqual(add(2, 3), 5)\n\n\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n",
            encoding="utf-8",
        )
        focused_command = self._focused_command_text
        (self.source / "AGENTS.md").write_text(
            "# Disposable Agent Flow proof fixture\n\n"
            "This repository exists only for the bounded Agent Flow proof.\n\n"
            "- Investigator: run `%s` as a standalone command, identify the "
            "arithmetic defect, and cite the absolute tracked "
            "`test_calculator.py` path as test evidence.\n"
            "- Fixer: change only `calculator.py` so `add(2, 3)` returns `5`; "
            "run `%s` as a standalone command; do not commit; cite the absolute "
            "tracked `test_calculator.py` path as evidence.\n"
            "- Tester: run `%s` as a standalone command with no chaining or "
            "shell compound; return one passing "
            "`focused_tests` gate proof citing the absolute tracked test file.\n"
            "- Do not create files, use the network, change Git state, or touch "
            "any other path.\n"
            % (focused_command, focused_command, focused_command),
            encoding="utf-8",
        )
        self._git("add", "AGENTS.md", "calculator.py", "test_calculator.py")
        self._run(
            (
                str(self.git_executable),
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "user.name=Agent Flow Proof",
                "-c",
                "user.email=agent-flow-proof@example.invalid",
                "commit",
                "-q",
                "-m",
                "Create disposable failing fixture",
            ),
            cwd=self.source,
        )

    async def _run_pipeline(self, report: Dict[str, Any]) -> None:
        command_prefix: Tuple[str, ...] = ("codex",)
        if self.require_authenticated_provider:
            codex = shutil.which("codex", path=os.environ.get("PATH"))
            if codex is None:
                raise RealProofError("codex was not found on the operator PATH")
            codex_executable = Path(codex).resolve()
            if not codex_executable.is_file():
                raise RealProofError("resolved Codex executable is not a file")
            report["codex_executable"] = self._executable_record(
                codex_executable
            )
            command_prefix = (str(codex_executable),)
        config = CodexCliConfig(
            command_prefix=command_prefix,
            timeout_seconds=300,
            terminate_grace_seconds=5,
            runtime_root=self.codex_runtime,
        )
        with SQLiteStore(self.database) as store:
            campaign = store.create_campaign(
                "Authenticated disposable managed Codex proof",
                config={
                    "description": (
                        "Real provider proof against a disposable Git fixture."
                    ),
                    "repository_paths": [str(self.source)],
                },
                global_limit=2,
                role_limits={"investigator": 1, "fixer": 1, "tester": 1},
            )
            item = store.create_work_item(
                campaign["id"],
                "Repair the disposable calculator addition defect",
                description=(
                    "Run %s as a standalone command. Investigate the failing "
                    "add(2, 3) behavior, change only calculator.py from "
                    "subtraction to addition, and prove the focused unittest "
                    "passes. Use the absolute tracked test_calculator.py file "
                    "as evidence; do not create evidence files."
                    % self._focused_command_text
                ),
                required_gates=["focused_tests"],
                initial_job={
                    "role": "investigator",
                    "stage": "investigator",
                    "active_item_state": "investigating",
                },
            )
            investigator_scheduler = await self._run_scheduler(
                store,
                {
                    WorkerRole.INVESTIGATOR: (
                        self.worker_factory(WorkerRole.INVESTIGATOR, config),
                    )
                },
            )
            report["investigator_scheduler_errors"] = [
                repr(error) for error in investigator_scheduler.errors
            ]
            if store.get_work_item(item["id"])["state"] != "ready_for_fix":
                self._capture_store(report, store, campaign["id"], item["id"])
                raise RealProofError("investigator did not reach ready_for_fix")

            approval = store.create_approval(
                campaign["id"],
                LOCAL_WRITE_APPROVAL_ACTION,
                "explicit-disposable-proof",
                work_item_id=item["id"],
                scope={
                    "mode": "local_code_changes",
                    "repository_paths": [str(self.source)],
                    "push": False,
                    "merge": False,
                    "deploy": False,
                },
            )
            store.resolve_approval(
                approval["id"], "approved", "explicit-disposable-proof"
            )
            manager = ManagedWorktreeManager(
                store,
                owner="real-proof-worktree-manager",
                config=ManagedWorktreeConfig(
                    worktree_root=self.worktree_root,
                    runtime_root=self.lifecycle_runtime,
                    command_timeout_seconds=30,
                    terminate_grace_seconds=2,
                    operation_lease_seconds=60,
                ),
            )
            worktree = manager.provision(
                campaign["id"], item["id"], self.source, "HEAD"
            )
            worker_scheduler = await self._run_scheduler(
                store,
                {
                    WorkerRole.FIXER: (
                        self.worker_factory(WorkerRole.FIXER, config),
                    ),
                    WorkerRole.TESTER: (
                        self.worker_factory(WorkerRole.TESTER, config),
                    ),
                },
            )
            report["worker_scheduler_errors"] = [
                repr(error) for error in worker_scheduler.errors
            ]
            report["campaign_id"] = campaign["id"]
            report["item_id"] = item["id"]
            report["worktree_id"] = worktree["id"]
            report["worktree_path"] = worktree["worktree_path"]
            self._capture_store(report, store, campaign["id"], item["id"])

    async def _run_scheduler(
        self,
        store: SQLiteStore,
        worker_pools: Mapping[WorkerRole, Sequence[Worker]],
    ) -> Scheduler:
        scheduler = Scheduler(
            SQLiteSchedulerStorage(store),
            worker_pools,
            global_concurrency_limit=2,
            lease_seconds=60,
            heartbeat_interval_seconds=10,
            max_attempts=1,
            allow_simulated_evidence=False,
            worker_id_prefix="real-proof",
        )
        await scheduler.run_until_quiescent()
        return scheduler

    @staticmethod
    def _capture_store(
        report: Dict[str, Any],
        store: SQLiteStore,
        campaign_id: str,
        item_id: str,
    ) -> None:
        report["final_item_state"] = store.get_work_item(item_id)["state"]
        report["jobs"] = store.list_jobs(work_item_id=item_id)
        report["attempts"] = store.list_attempts(campaign_id=campaign_id)
        report["artifacts"] = store.list_artifacts(item_id)
        report["events"] = store.list_events(work_item_id=item_id)
        report["resource_leases"] = store.list_resource_leases(
            campaign_id=campaign_id
        )
        report["foreign_key_violations"] = store.foreign_key_violations()
        worktrees = store.list_managed_worktrees(campaign_id=campaign_id)
        report["managed_worktrees"] = worktrees
        if worktrees:
            report["managed_worktree"] = worktrees[0]

    def _assess(self, report: Dict[str, Any]) -> None:
        report["source_after"] = self._source_snapshot()
        report["source_unchanged"] = (
            report["source_before"] == report["source_after"]
        )
        worktree_path = Path(str(report.get("worktree_path") or ""))
        if not worktree_path.is_dir():
            raise RealProofError("managed proof worktree is absent")
        test = self._run(
            self.focused_test_command, cwd=worktree_path, check=False
        )
        self.focused_test_log.write_text(
            test.stdout + test.stderr, encoding="utf-8"
        )
        report["supervisor_focused_test"] = {
            "command": list(self.focused_test_command),
            "return_code": test.returncode,
            "log": str(self.focused_test_log),
            "log_sha256": self._sha256(self.focused_test_log),
        }
        report["exact_worktree_diff"] = self._exact_worktree_diff(
            worktree_path, report
        )
        jobs = list(report.get("jobs") or [])
        attempts = list(report.get("attempts") or [])
        artifacts = list(report.get("artifacts") or [])
        events = list(report.get("events") or [])
        report["jobs_exactly_once"] = self._jobs_exactly_once(jobs)
        report["attempts_succeeded_exactly_once"] = (
            self._attempts_succeeded_exactly_once(jobs, attempts)
        )
        report["same_worktree_fixer_tester"] = self._same_worktree(
            jobs, attempts, report
        )
        report["provider_artifacts_valid"] = self._provider_artifacts_valid(
            artifacts, attempts, jobs, worktree_path, report
        )
        report["sessions_distinct_and_persisted"] = (
            self._sessions_distinct(attempts)
        )
        report["all_processes_stopped"] = self._all_processes_stopped(
            attempts, report
        )
        report["session_events_precede_completion"] = (
            self._session_events_precede_completion(
                jobs, attempts, events
            )
        )
        report["artifact_events_valid"] = self._artifact_events_valid(
            jobs, artifacts, events
        )
        report["tester_command_proof"] = self._tester_command_proof(
            jobs, artifacts, worktree_path
        )
        report["executable_hashes_unchanged"] = (
            self._executable_hashes_unchanged(report)
        )
        provider_checks = (
            report["provider_artifacts_valid"],
            report["sessions_distinct_and_persisted"],
            report["all_processes_stopped"],
            report["session_events_precede_completion"],
            report["artifact_events_valid"],
            report["tester_command_proof"],
            report["executable_hashes_unchanged"],
        )
        report["provider_checks_skipped"] = (
            not self.require_authenticated_provider
        )
        report["scheduler_error_free"] = not (
            report.get("investigator_scheduler_errors")
            or report.get("worker_scheduler_errors")
        )
        required = self._core_requirements(report, test.returncode)
        if self.require_authenticated_provider:
            required += provider_checks
        report["verified"] = all(required)

    def _exact_worktree_diff(
        self, worktree_path: Path, report: Dict[str, Any]
    ) -> bool:
        status = self._git(
            "status",
            "--porcelain=v2",
            "--untracked-files=all",
            cwd=worktree_path,
        )
        report["worktree_status"] = status
        lines = status.splitlines()
        managed = report.get("managed_worktree") or {}
        expected_paths = {"AGENTS.md", "calculator.py", "test_calculator.py"}
        filesystem_paths = {
            entry.name for entry in worktree_path.iterdir()
        }
        tagged_records = [
            record
            for record in self._git(
                "ls-files", "-v", "-z", cwd=worktree_path
            ).split("\0")
            if record
        ]
        tagged_paths = {
            record[2:]
            for record in tagged_records
            if len(record) > 2 and record[1] == " "
        }
        index_entries = self._index_entries(worktree_path)
        head_entries = self._head_entries(worktree_path)
        object_format = self._git(
            "rev-parse", "--show-object-format", cwd=worktree_path
        )
        worktree_entries: Dict[str, Tuple[str, str]] = {}
        for relative in expected_paths:
            path = worktree_path / relative
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                return False
            if not path.is_file() or path.is_symlink():
                return False
            mode = "100755" if metadata.st_mode & 0o111 else "100644"
            worktree_entries[relative] = (
                mode,
                self._git_blob_oid(path.read_bytes(), object_format),
            )
        expected_calculator = (
            b"def add(left: int, right: int) -> int:\n"
            b"    return left + right\n"
        )
        calculator = worktree_path / "calculator.py"
        return (
            len(lines) == 1
            and lines[0].startswith("1 .M ")
            and lines[0].endswith(" calculator.py")
            and self._git(
                "ls-files",
                "-z",
                "--others",
                "--exclude-standard",
                cwd=worktree_path,
            )
            == ""
            and self._git(
                "ls-files",
                "-z",
                "--others",
                "--ignored",
                "--exclude-standard",
                cwd=worktree_path,
            )
            == ""
            and len(tagged_records) == len(expected_paths)
            and tagged_paths == expected_paths
            and all(record.startswith("H ") for record in tagged_records)
            and filesystem_paths == expected_paths | {".git"}
            and index_entries is not None
            and index_entries == head_entries
            and set(head_entries or {}) == expected_paths
            and set(worktree_entries) == expected_paths
            and all(
                worktree_entries[path][0] == head_entries[path][0]
                for path in expected_paths
            )
            and worktree_entries["AGENTS.md"] == head_entries["AGENTS.md"]
            and worktree_entries["test_calculator.py"]
            == head_entries["test_calculator.py"]
            and worktree_entries["calculator.py"]
            != head_entries["calculator.py"]
            and self._git("diff", "--name-only", cwd=worktree_path)
            == "calculator.py"
            and self._git("diff", "--cached", "--name-only", cwd=worktree_path)
            == ""
            and self._git("rev-parse", "HEAD", cwd=worktree_path)
            == managed.get("head_revision")
            and self._git("symbolic-ref", "-q", "HEAD", cwd=worktree_path)
            == managed.get("branch_ref")
            and calculator.read_bytes() == expected_calculator
            and (worktree_path / "AGENTS.md").read_bytes()
            == (self.source / "AGENTS.md").read_bytes()
            and (worktree_path / "test_calculator.py").read_bytes()
            == (self.source / "test_calculator.py").read_bytes()
        )

    def _index_entries(
        self, repository: Path
    ) -> Optional[Dict[str, Tuple[str, str]]]:
        entries: Dict[str, Tuple[str, str]] = {}
        output = self._git("ls-files", "--stage", "-z", cwd=repository)
        for record in (value for value in output.split("\0") if value):
            metadata, separator, relative = record.partition("\t")
            fields = metadata.split(" ")
            if (
                not separator
                or len(fields) != 3
                or fields[2] != "0"
                or relative in entries
            ):
                return None
            entries[relative] = (fields[0], fields[1])
        return entries

    def _head_entries(
        self, repository: Path
    ) -> Optional[Dict[str, Tuple[str, str]]]:
        entries: Dict[str, Tuple[str, str]] = {}
        output = self._git(
            "ls-tree", "-r", "-z", "--full-tree", "HEAD", cwd=repository
        )
        for record in (value for value in output.split("\0") if value):
            metadata, separator, relative = record.partition("\t")
            fields = metadata.split(" ")
            if (
                not separator
                or len(fields) != 3
                or fields[1] != "blob"
                or relative in entries
            ):
                return None
            entries[relative] = (fields[0], fields[2])
        return entries

    @staticmethod
    def _git_blob_oid(content: bytes, object_format: str) -> str:
        if object_format == "sha1":
            digest = hashlib.sha1()
        elif object_format == "sha256":
            digest = hashlib.sha256()
        else:
            raise RealProofError("unsupported Git object format")
        digest.update(("blob %d\0" % len(content)).encode("ascii"))
        digest.update(content)
        return digest.hexdigest()

    @staticmethod
    def _jobs_exactly_once(jobs: Sequence[Mapping[str, Any]]) -> bool:
        roles = [str(job.get("role")) for job in jobs]
        return (
            roles == ["investigator", "fixer", "tester"]
            and all(job.get("status") == "completed" for job in jobs)
            and all(job.get("attempt_count") == 1 for job in jobs)
        )

    @staticmethod
    def _same_worktree(
        jobs: Sequence[Mapping[str, Any]],
        attempts: Sequence[Mapping[str, Any]],
        report: Mapping[str, Any],
    ) -> bool:
        jobs_by_role = {str(job.get("role")): job for job in jobs}
        attempts_by_job = {
            str(attempt.get("job_id")): attempt for attempt in attempts
        }
        fixer = jobs_by_role.get("fixer", {})
        tester = jobs_by_role.get("tester", {})
        fixer_attempt = attempts_by_job.get(str(fixer.get("id")), {})
        tester_attempt = attempts_by_job.get(str(tester.get("id")), {})
        worktree_id = report.get("worktree_id")
        return (
            worktree_id is not None
            and fixer.get("managed_worktree_id") == worktree_id
            and tester.get("managed_worktree_id") == worktree_id
            and fixer_attempt.get("managed_worktree_id") == worktree_id
            and tester_attempt.get("managed_worktree_id") == worktree_id
            and fixer_attempt.get("managed_worktree_generation") == 1
            and tester_attempt.get("managed_worktree_generation") == 1
        )

    @staticmethod
    def _attempts_succeeded_exactly_once(
        jobs: Sequence[Mapping[str, Any]],
        attempts: Sequence[Mapping[str, Any]],
    ) -> bool:
        job_ids = {str(job.get("id")) for job in jobs}
        attempts_by_job: Dict[str, list] = {}
        for attempt in attempts:
            attempts_by_job.setdefault(
                str(attempt.get("job_id")), []
            ).append(attempt)
        if set(attempts_by_job) != job_ids or any(
            len(bound) != 1 for bound in attempts_by_job.values()
        ):
            return False
        for bound in attempts_by_job.values():
            attempt = bound[0]
            started_at = attempt.get("started_at")
            finished_at = attempt.get("finished_at")
            if (
                attempt.get("attempt_number") != 1
                or attempt.get("status") != "succeeded"
                or attempt.get("error") is not None
                or not isinstance(started_at, (int, float))
                or not isinstance(finished_at, (int, float))
                or finished_at < started_at
            ):
                return False
        return bool(job_ids)

    def _provider_artifacts_valid(
        self,
        artifacts: Sequence[Mapping[str, Any]],
        attempts: Sequence[Mapping[str, Any]],
        jobs: Sequence[Mapping[str, Any]],
        worktree_path: Path,
        report: Mapping[str, Any],
    ) -> bool:
        job_by_id = {str(job.get("id")): job for job in jobs}
        attempt_by_id = {
            str(attempt.get("id")): attempt for attempt in attempts
        }
        expected_attempts = set(attempt_by_id)
        kinds_by_attempt: Dict[str, set] = {
            attempt_id: set() for attempt_id in expected_attempts
        }
        paths_by_attempt: Dict[str, set] = {
            attempt_id: set() for attempt_id in expected_attempts
        }
        files_by_attempt: Dict[str, set] = {
            attempt_id: set() for attempt_id in expected_attempts
        }
        parents_by_attempt: Dict[str, set] = {
            attempt_id: set() for attempt_id in expected_attempts
        }
        jsonl_by_attempt: Dict[str, Path] = {}
        jsonl_payload_by_attempt: Dict[str, Mapping[str, Any]] = {}
        for artifact in artifacts:
            path = Path(str(artifact.get("uri") or ""))
            metadata = artifact.get("metadata") or {}
            attempt_id = str(metadata.get("attempt_id") or "")
            kind = str(artifact.get("kind") or "")
            attempt = attempt_by_id.get(attempt_id, {})
            job_id = str(attempt.get("job_id") or "")
            job = job_by_id.get(job_id, {})
            expected_sandbox = {
                "investigator": "read-only",
                "fixer": "workspace-write",
                "tester": "read-only",
            }.get(str(job.get("role")))
            expected_directory = self._attempt_runtime_directory(
                str(report.get("campaign_id") or ""),
                job_id,
                attempt_id,
            )
            if not path.is_file() or path.is_symlink():
                return False
            resolved_path = path.resolve()
            artifact_stat = path.stat()
            if (
                attempt_id not in kinds_by_attempt
                or kind not in PROVIDER_ARTIFACT_KINDS
                or kind in kinds_by_attempt[attempt_id]
                or path.name != PROVIDER_ARTIFACT_NAMES.get(kind)
                or resolved_path.parent != expected_directory
                or resolved_path in paths_by_attempt[attempt_id]
                or (artifact_stat.st_dev, artifact_stat.st_ino)
                in files_by_attempt[attempt_id]
                or artifact.get("job_id") != job_id
                or artifact.get("item_id") != report.get("item_id")
                or metadata.get("provider") != "codex"
                or metadata.get("executable")
                != attempt.get("external_process_target_executable")
                or metadata.get("sandbox") != expected_sandbox
                or metadata.get("truncated") is not False
                or metadata.get("resumed") is not False
                or metadata.get("bytes") != artifact_stat.st_size
                or artifact_stat.st_uid != os.getuid()
                or artifact_stat.st_nlink != 1
                or artifact_stat.st_mode & 0o077
                or not self._is_within(resolved_path, self.codex_runtime)
                or self._is_within(resolved_path, self.source)
                or self._is_within(resolved_path, worktree_path)
                or metadata.get("sha256") != self._sha256(path)
            ):
                return False
            kinds_by_attempt[attempt_id].add(kind)
            paths_by_attempt[attempt_id].add(resolved_path)
            files_by_attempt[attempt_id].add(
                (artifact_stat.st_dev, artifact_stat.st_ino)
            )
            parents_by_attempt[attempt_id].add(resolved_path.parent)
            if kind == "codex_jsonl":
                jsonl_by_attempt[attempt_id] = path
                jsonl_payload = self._jsonl_final_payload(path)
                if jsonl_payload is None:
                    return False
                jsonl_payload_by_attempt[attempt_id] = jsonl_payload
            elif kind == "codex_schema":
                if self._load_json_object(path) != codex_handoff_schema(
                    WorkerRole(str(job.get("role")))
                ):
                    return False
            elif kind == "codex_final":
                payload = self._load_json_object(path)
                try:
                    validated = _HANDOFF_BY_ROLE[
                        WorkerRole(str(job.get("role")))
                    ].model_validate(payload)
                except (KeyError, TypeError, ValidationError, ValueError):
                    return False
                if (
                    payload != attempt.get("result")
                    or validated.model_dump(mode="json") != payload
                ):
                    return False
            elif kind == "codex_stderr" and artifact_stat.st_size != 0:
                return False
        if not kinds_by_attempt or not all(
            kinds == PROVIDER_ARTIFACT_KINDS
            for kinds in kinds_by_attempt.values()
        ):
            return False
        if not all(
            len(paths_by_attempt[attempt_id]) == len(PROVIDER_ARTIFACT_KINDS)
            and len(files_by_attempt[attempt_id])
            == len(PROVIDER_ARTIFACT_KINDS)
            and len(parents_by_attempt[attempt_id]) == 1
            for attempt_id in expected_attempts
        ):
            return False
        if len(
            {
                next(iter(parents_by_attempt[attempt_id]))
                for attempt_id in expected_attempts
            }
        ) != len(expected_attempts):
            return False
        for attempt_id, attempt in attempt_by_id.items():
            jsonl = jsonl_by_attempt.get(attempt_id)
            if (
                jsonl is None
                or self._jsonl_thread_id(jsonl)
                != attempt.get("external_session_id")
                or jsonl_payload_by_attempt.get(attempt_id)
                != attempt.get("result")
            ):
                return False
        return True

    @staticmethod
    def _sessions_distinct(attempts: Sequence[Mapping[str, Any]]) -> bool:
        sessions = [attempt.get("external_session_id") for attempt in attempts]
        return len(sessions) == 3 and all(sessions) and len(set(sessions)) == 3

    def _all_processes_stopped(
        self,
        attempts: Sequence[Mapping[str, Any]],
        report: Mapping[str, Any],
    ) -> bool:
        codex = report.get("codex_executable") or {}
        guardian = report.get("guardian_executable") or {}
        expected_target = codex.get("path")
        expected_guardian = guardian.get("path")
        if len(attempts) != 3 or not all(
            attempt.get("status") == "succeeded"
            and attempt.get("error") is None
            and attempt.get("finished_at") is not None
            and attempt.get("external_process_id") is not None
            and int(attempt.get("external_process_id")) > 1
            and attempt.get("external_process_group_id")
            == attempt.get("external_process_id")
            and attempt.get("external_provider") == "codex"
            and attempt.get("external_process_identity_version")
            == "darwin_libproc_v1"
            and attempt.get("external_process_owner_uid") == os.getuid()
            and int(attempt.get("external_process_start_seconds") or 0) > 0
            and 0
            <= int(attempt.get("external_process_start_microseconds") or -1)
            < 1_000_000
            and attempt.get("external_process_executable")
            == expected_guardian
            and self._existing_absolute_file(expected_guardian)
            and attempt.get("external_process_target_executable")
            == expected_target
            and attempt.get("external_process_state") == "stopped"
            and attempt.get("external_process_outcome") == "reaped"
            and attempt.get("external_process_stopped_at") is not None
            and attempt.get("external_process_last_error") is None
            for attempt in attempts
        ):
            return False
        identities = {
            (
                attempt.get("external_process_id"),
                attempt.get("external_process_start_seconds"),
                attempt.get("external_process_start_microseconds"),
            )
            for attempt in attempts
        }
        return len(identities) == 3

    @staticmethod
    def _session_events_precede_completion(
        jobs: Sequence[Mapping[str, Any]],
        attempts: Sequence[Mapping[str, Any]],
        events: Sequence[Mapping[str, Any]],
    ) -> bool:
        attempts_by_job: Dict[str, list] = {}
        for attempt in attempts:
            attempts_by_job.setdefault(
                str(attempt.get("job_id")), []
            ).append(attempt)
        for job in jobs:
            role = str(job.get("role"))
            job_id = str(job.get("id"))
            bound_attempts = attempts_by_job.get(job_id, [])
            if len(bound_attempts) != 1:
                return False
            attempt = bound_attempts[0]
            by_type: Dict[str, list] = {}
            for event in events:
                if event.get("job_id") == job_id:
                    by_type.setdefault(
                        str(event.get("event_type")), []
                    ).append(event)
            started_events = by_type.get(
                "worker.external_process_started", []
            )
            session_events = by_type.get(
                "worker.external_session_recorded", []
            )
            stopped_events = by_type.get(
                "worker.external_process_stopped", []
            )
            completion_events = by_type.get(
                str(_COMPLETION_EVENT_BY_ROLE.get(role)), []
            )
            if not (
                len(started_events) == 1
                and len(session_events) == 1
                and len(stopped_events) == 1
                and len(completion_events) == 1
            ):
                return False
            started_data = started_events[0].get("event_data") or {}
            session_data = session_events[0].get("event_data") or {}
            stopped_data = stopped_events[0].get("event_data") or {}
            if started_data != {
                "provider": attempt.get("external_provider"),
                "process_id": attempt.get("external_process_id"),
                "process_group_id": attempt.get(
                    "external_process_group_id"
                ),
                "owner_uid": attempt.get("external_process_owner_uid"),
                "kernel_executable": attempt.get(
                    "external_process_executable"
                ),
                "start_seconds": attempt.get(
                    "external_process_start_seconds"
                ),
                "start_microseconds": attempt.get(
                    "external_process_start_microseconds"
                ),
                "target_executable": attempt.get(
                    "external_process_target_executable"
                ),
            }:
                return False
            if session_data != {
                "provider": attempt.get("external_provider"),
                "session_id": attempt.get("external_session_id"),
            }:
                return False
            if stopped_data != {
                "process_id": attempt.get("external_process_id"),
                "process_group_id": attempt.get(
                    "external_process_group_id"
                ),
            }:
                return False
            sequences = (
                int(started_events[0]["sequence"]),
                int(session_events[0]["sequence"]),
                int(stopped_events[0]["sequence"]),
                int(completion_events[0]["sequence"]),
            )
            if not (
                sequences[0]
                < sequences[1]
                < sequences[2]
                < sequences[3]
            ):
                return False
        return bool(jobs)

    def _tester_command_proof(
        self,
        jobs: Sequence[Mapping[str, Any]],
        artifacts: Sequence[Mapping[str, Any]],
        worktree_path: Path,
    ) -> bool:
        tester = next(
            (job for job in jobs if job.get("role") == "tester"), None
        )
        if tester is None:
            return False
        jsonl = next(
            (
                Path(str(artifact["uri"]))
                for artifact in artifacts
                if artifact.get("job_id") == tester.get("id")
                and artifact.get("kind") == "codex_jsonl"
            ),
            None,
        )
        if jsonl is None or not jsonl.is_file():
            return False
        exact_command = self._focused_command_text
        expected_test_marker = "AGENT_FLOW_TEST_FILE=%s" % (
            worktree_path / "test_calculator.py"
        )
        found = False
        for line in jsonl.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                return False
            item = event.get("item") or {}
            command = str(item.get("command") or "")
            try:
                command_parts = shlex.split(command)
            except ValueError:
                return False
            exact_execution = command_parts == list(self.focused_test_command)
            if (
                len(command_parts) == 3
                and command_parts[0] in ("/bin/zsh", "/bin/bash", "/bin/sh")
                and command_parts[1] == "-lc"
                and command_parts[2] == exact_command
            ):
                exact_execution = True
            output = str(item.get("aggregated_output") or "")
            if (
                event.get("type") == "item.completed"
                and item.get("type") == "command_execution"
                and exact_execution
                and item.get("status") == "completed"
                and item.get("exit_code") == 0
                and "test_adds_two_numbers" in output
                and expected_test_marker in output
                and "Ran 1 test" in output
                and "OK" in output
                and "FAILED" not in output
                and "ERROR" not in output
            ):
                found = True
        return found

    @staticmethod
    def _artifact_events_valid(
        jobs: Sequence[Mapping[str, Any]],
        artifacts: Sequence[Mapping[str, Any]],
        events: Sequence[Mapping[str, Any]],
    ) -> bool:
        for job in jobs:
            job_id = str(job.get("id"))
            job_artifacts = [
                artifact
                for artifact in artifacts
                if str(artifact.get("job_id")) == job_id
            ]
            artifact_events = [
                event
                for event in events
                if str(event.get("job_id")) == job_id
                and event.get("event_type") == "artifact.added"
            ]
            session_events = [
                event
                for event in events
                if str(event.get("job_id")) == job_id
                and event.get("event_type")
                == "worker.external_session_recorded"
            ]
            stopped_events = [
                event
                for event in events
                if str(event.get("job_id")) == job_id
                and event.get("event_type")
                == "worker.external_process_stopped"
            ]
            expected = {
                (
                    artifact.get("id"),
                    (artifact.get("metadata") or {}).get("attempt_id"),
                    artifact.get("kind"),
                    artifact.get("uri"),
                )
                for artifact in job_artifacts
            }
            observed = {
                (
                    (event.get("event_data") or {}).get("artifact_id"),
                    (event.get("event_data") or {}).get("attempt_id"),
                    (event.get("event_data") or {}).get("kind"),
                    (event.get("event_data") or {}).get("uri"),
                )
                for event in artifact_events
            }
            if (
                len(job_artifacts) != len(PROVIDER_ARTIFACT_KINDS)
                or len(expected) != len(PROVIDER_ARTIFACT_KINDS)
                or len(artifact_events) != len(PROVIDER_ARTIFACT_KINDS)
                or observed != expected
                or len(session_events) != 1
                or len(stopped_events) != 1
                or not all(
                    int(session_events[0]["sequence"])
                    < int(event["sequence"])
                    < int(stopped_events[0]["sequence"])
                    for event in artifact_events
                )
            ):
                return False
        return bool(jobs)

    def _source_snapshot(self) -> Mapping[str, Any]:
        snapshot = dict(self.inspector.snapshot(self.source))
        files = {}
        for relative in self._git("ls-files", "-z").split("\0"):
            if relative:
                files[relative] = self._sha256(self.source / relative)
        snapshot["tracked_file_hashes"] = files
        return snapshot

    def _git(self, *arguments: str, cwd: Optional[Path] = None) -> str:
        command = (
            str(self.git_executable),
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            *arguments,
        )
        return self._run(command, cwd=cwd or self.source).stdout.strip()

    @staticmethod
    def _run(
        command: Sequence[str],
        *,
        cwd: Path,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": os.environ.get("HOME", str(Path.home())),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        return subprocess.run(
            tuple(command),
            cwd=str(cwd),
            check=check,
            capture_output=True,
            text=True,
            timeout=60,
            env=environment,
        )

    def _write_report(self, report: Mapping[str, Any]) -> None:
        self.report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        os.chmod(self.report_path, 0o600)

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    return digest.hexdigest()
                digest.update(chunk)

    @staticmethod
    def _is_within(path: Path, parent: Path) -> bool:
        try:
            path.relative_to(parent)
        except ValueError:
            return False
        return True

    @property
    def focused_test_command(self) -> Tuple[str, ...]:
        return (str(self.python_executable),) + FOCUSED_TEST_ARGUMENTS

    @property
    def _focused_command_text(self) -> str:
        return shlex.join(self.focused_test_command)

    def _executable_record(self, path: Path) -> Mapping[str, Any]:
        resolved = path.resolve()
        if not resolved.is_absolute() or not resolved.is_file():
            raise RealProofError("proof executable is absent: %s" % resolved)
        return {"path": str(resolved), "sha256": self._sha256(resolved)}

    def _executable_hashes_unchanged(
        self, report: Mapping[str, Any]
    ) -> bool:
        labels = [
            "git_executable",
            "guardian_executable",
            "python_executable",
        ]
        if self.require_authenticated_provider:
            labels.append("codex_executable")
        for label in labels:
            record = report.get(label) or {}
            path = Path(str(record.get("path") or ""))
            if (
                not path.is_absolute()
                or not path.is_file()
                or record.get("sha256") != self._sha256(path)
            ):
                return False
        return True

    @staticmethod
    def _existing_absolute_file(value: Any) -> bool:
        if not value:
            return False
        path = Path(str(value))
        return path.is_absolute() and path.is_file()

    @staticmethod
    def _jsonl_thread_id(path: Path) -> Optional[str]:
        thread_ids = []
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                return None
            if event.get("type") == "thread.started":
                thread_id = event.get("thread_id")
                if not isinstance(thread_id, str) or not thread_id:
                    return None
                thread_ids.append(thread_id)
        return thread_ids[0] if len(thread_ids) == 1 else None

    @staticmethod
    def _jsonl_final_payload(
        path: Path,
    ) -> Optional[Mapping[str, Any]]:
        turn_started = []
        turn_completed = []
        agent_messages = []
        for index, line in enumerate(
            path.read_text(encoding="utf-8").splitlines()
        ):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                return False
            event_type = event.get("type")
            if event_type in ("error", "turn.failed"):
                return None
            if event_type == "turn.started":
                turn_started.append(index)
            elif event_type == "turn.completed":
                turn_completed.append(index)
            item = event.get("item") or {}
            if (
                event_type == "item.completed"
                and item.get("type") == "agent_message"
            ):
                text = item.get("text")
                if not isinstance(text, str):
                    return None
                agent_messages.append((index, text))
        if (
            len(turn_started) != 1
            or len(turn_completed) != 1
            or not agent_messages
            or not (
                turn_started[0]
                < agent_messages[-1][0]
                < turn_completed[0]
            )
        ):
            return None
        try:
            payload = json.loads(agent_messages[-1][1])
        except json.JSONDecodeError:
            return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _load_json_object(path: Path) -> Optional[Mapping[str, Any]]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def _attempt_runtime_directory(
        self, campaign_id: str, job_id: str, attempt_id: str
    ) -> Path:
        if not campaign_id or not job_id or not attempt_id:
            return Path("/")
        return self.codex_runtime.joinpath(
            self._hash_part(campaign_id),
            self._hash_part(job_id),
            self._hash_part(attempt_id),
        )

    @staticmethod
    def _hash_part(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]

    @staticmethod
    def _core_requirements(
        report: Mapping[str, Any], test_return_code: int
    ) -> Tuple[bool, ...]:
        return (
            report.get("final_item_state") == "verified_green",
            report.get("source_unchanged") is True,
            report.get("exact_worktree_diff") is True,
            report.get("jobs_exactly_once") is True,
            report.get("attempts_succeeded_exactly_once") is True,
            report.get("same_worktree_fixer_tester") is True,
            report.get("scheduler_error_free") is True,
            test_return_code == 0,
            not report.get("resource_leases"),
            report.get("foreign_key_violations") == [],
        )

    @staticmethod
    def _codex_worker(role: WorkerRole, config: CodexCliConfig) -> Worker:
        return CodexCliWorker(role, config=config)


async def run_authenticated_disposable_proof() -> RealProofResult:
    """Run the fixed live-provider proof used by the opt-in CLI."""

    return await RealProofRunner().run()


def run_authenticated_disposable_proof_sync() -> RealProofResult:
    """Synchronous wrapper for operator and CLI use."""

    return asyncio.run(run_authenticated_disposable_proof())
