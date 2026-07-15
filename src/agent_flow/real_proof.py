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
from agent_flow.focused_tests import FocusedTestWorker
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
    GuardedGitCommandRunner,
    ManagedWorktreeConfig,
    ManagedWorktreeManager,
)


FOCUSED_TEST_FILE = "test_calculator.py"
FOCUSED_TEST_SELECTOR = "CalculatorTests.test_adds_two_numbers"
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
        self.focused_test_runtime = self.root / "focused-test-runtime"
        self.report_path = self.root / "proof-report.json"
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
            "import importlib.util\n"
            "import unittest\n\n"
            "calculator_file = Path(__file__).with_name('calculator.py').resolve()\n"
            "calculator_spec = importlib.util.spec_from_file_location(\n"
            "    'agent_flow_fixture_calculator', calculator_file\n"
            ")\n"
            "if calculator_spec is None or calculator_spec.loader is None:\n"
            "    raise RuntimeError('calculator fixture cannot be loaded')\n"
            "calculator = importlib.util.module_from_spec(calculator_spec)\n"
            "calculator_spec.loader.exec_module(calculator)\n\n\n"
            "class CalculatorTests(unittest.TestCase):\n"
            "    def test_adds_two_numbers(self) -> None:\n"
            "        test_file = Path(__file__).resolve()\n"
            "        print('AGENT_FLOW_TEST_FILE=%s' % test_file)\n"
            "        self.assertEqual(Path.cwd().resolve(), test_file.parent)\n"
            "        self.assertEqual(calculator.add(2, 3), 5)\n\n\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n",
            encoding="utf-8",
        )
        (self.source / "AGENTS.md").write_text(
            "# Disposable Agent Flow proof fixture\n\n"
            "This repository exists only for the bounded Agent Flow proof.\n\n"
            "- Investigator: inspect the focused unittest, identify the "
            "arithmetic defect, and cite the absolute tracked "
            "`test_calculator.py` path as test evidence.\n"
            "- Fixer: change only `calculator.py` so `add(2, 3)` returns `5`; "
            "do not run tests or commit; cite the absolute "
            "tracked `test_calculator.py` path as evidence.\n"
            "- Testing is owned by Agent Flow's deterministic focused-test "
            "collector; no model may supply or alter its command.\n"
            "- Do not create files, use the network, change Git state, or touch "
            "any other path.\n",
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
                    "Investigate the failing add(2, 3) behavior and change only "
                    "calculator.py from subtraction to addition. Agent Flow "
                    "will run its immutable focused-test plan. Use the absolute "
                    "tracked test_calculator.py file as evidence; do not create "
                    "evidence files."
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
            report["campaign_id"] = campaign["id"]
            report["item_id"] = item["id"]
            report["worktree_id"] = worktree["id"]
            report["worktree_path"] = worktree["worktree_path"]
            report["managed_worktree"] = worktree
            fixer_scheduler = await self._run_scheduler(
                store,
                {
                    WorkerRole.FIXER: (
                        self.worker_factory(WorkerRole.FIXER, config),
                    ),
                },
            )
            report["fixer_scheduler_errors"] = [
                repr(error) for error in fixer_scheduler.errors
            ]
            if store.get_work_item(item["id"])["state"] != "ready_for_test":
                self._capture_store(report, store, campaign["id"], item["id"])
                raise RealProofError("fixer did not reach ready_for_test")
            worktree_path = Path(str(worktree["worktree_path"]))
            if not self._exact_worktree_diff(worktree_path, report):
                self._capture_store(report, store, campaign["id"], item["id"])
                raise RealProofError(
                    "fixer output did not match the exact disposable diff"
                )
            plan = store.create_focused_test_plan(
                item["id"],
                executable_path=str(self.python_executable),
                test_file=FOCUSED_TEST_FILE,
                selector=FOCUSED_TEST_SELECTOR,
                workspace_manifest=self._workspace_manifest(worktree_path),
                runtime_root=str(self.focused_test_runtime),
                timeout_seconds=60.0,
                output_limit_bytes=1024 * 1024,
            )
            report["focused_test_plan_id"] = plan["id"]
            focused_worker = FocusedTestWorker(
                GuardedGitCommandRunner(
                    runtime=local_process_runtime(),
                    timeout_seconds=60.0,
                    terminate_grace_seconds=5.0,
                    max_output_bytes=1024 * 1024,
                )
            )
            tester_scheduler = await self._run_scheduler(
                store,
                {WorkerRole.TESTER: (focused_worker,)},
            )
            report["tester_scheduler_errors"] = [
                repr(error) for error in tester_scheduler.errors
            ]
            report["worker_scheduler_errors"] = (
                report["fixer_scheduler_errors"]
                + report["tester_scheduler_errors"]
            )
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
        report["external_processes"] = store.list_external_processes()
        report["artifacts"] = store.list_artifacts(item_id)
        report["focused_test_plans"] = store.list_focused_test_plans(
            work_item_id=item_id
        )
        report["focused_test_executions"] = (
            store.list_focused_test_executions(work_item_id=item_id)
        )
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
            jobs,
            attempts,
            list(report.get("external_processes") or []),
            report,
        )
        report["session_events_precede_completion"] = (
            self._session_events_precede_completion(
                jobs,
                attempts,
                list(report.get("external_processes") or []),
                events,
            )
        )
        report["artifact_events_valid"] = self._artifact_events_valid(
            jobs, artifacts, events
        )
        report["focused_test_execution_proof"] = (
            self._focused_test_execution_proof(
                list(report.get("focused_test_plans") or []),
                list(report.get("focused_test_executions") or []),
                jobs,
                attempts,
                artifacts,
                events,
                worktree_path,
                report,
            )
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
            report["focused_test_execution_proof"],
            report["executable_hashes_unchanged"],
        )
        report["provider_checks_skipped"] = (
            not self.require_authenticated_provider
        )
        report["scheduler_error_free"] = not (
            report.get("investigator_scheduler_errors")
            or report.get("worker_scheduler_errors")
        )
        required = self._core_requirements(report)
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
        codex_job_ids = {
            str(job.get("id"))
            for job in jobs
            if str(job.get("role")) in ("investigator", "fixer")
        }
        attempt_by_id = {
            str(attempt.get("id")): attempt
            for attempt in attempts
            if str(attempt.get("job_id")) in codex_job_ids
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
        for artifact in (
            row
            for row in artifacts
            if str(row.get("kind")) in PROVIDER_ARTIFACT_KINDS
        ):
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
        sessions = [
            attempt.get("external_session_id")
            for attempt in attempts
            if attempt.get("external_session_id") is not None
        ]
        return (
            len(attempts) == 3
            and len(sessions) == 2
            and all(sessions)
            and len(set(sessions)) == 2
            and sum(
                attempt.get("external_session_id") is None
                for attempt in attempts
            ) == 1
        )

    def _all_processes_stopped(
        self,
        jobs: Sequence[Mapping[str, Any]],
        attempts: Sequence[Mapping[str, Any]],
        processes: Sequence[Mapping[str, Any]],
        report: Mapping[str, Any],
    ) -> bool:
        codex = report.get("codex_executable") or {}
        guardian = report.get("guardian_executable") or {}
        expected_guardian = guardian.get("path")
        jobs_by_id = {str(job.get("id")): job for job in jobs}
        attempts_by_id = {
            str(attempt.get("id")): attempt for attempt in attempts
        }
        expected_target_by_provider = {
            "codex": codex.get("path"),
            "focused_test": (report.get("python_executable") or {}).get("path"),
        }
        if (
            len(attempts) != 3
            or len(processes) != 3
            or not all(
            attempt.get("status") == "succeeded"
            and attempt.get("error") is None
            and attempt.get("finished_at") is not None
            for attempt in attempts
            )
            or not all(
                process.get("attempt_id") in attempts_by_id
                and int(process.get("process_id") or 0) > 1
                and process.get("process_group_id") == process.get("process_id")
                and process.get("provider") in expected_target_by_provider
                and process.get("identity_version") == "darwin_libproc_v1"
                and process.get("owner_uid") == os.getuid()
                and int(process.get("start_seconds") or 0) > 0
                and 0 <= int(process.get("start_microseconds") or -1) < 1_000_000
                and process.get("kernel_executable") == expected_guardian
                and self._existing_absolute_file(expected_guardian)
                and process.get("target_executable")
                == expected_target_by_provider.get(str(process.get("provider")))
                and process.get("state") == "stopped"
                and process.get("outcome") == "reaped"
                and process.get("stopped_at") is not None
                and process.get("last_error") is None
                for process in processes
            )
        ):
            return False
        providers_by_role = {
            str(
                jobs_by_id.get(
                    str(attempts_by_id[str(process.get("attempt_id"))].get("job_id")),
                    {},
                ).get("role")
            ): process.get("provider")
            for process in processes
        }
        if providers_by_role != {
            "investigator": "codex",
            "fixer": "codex",
            "tester": "focused_test",
        }:
            return False
        identities = {
            (
                process.get("process_id"),
                process.get("start_seconds"),
                process.get("start_microseconds"),
            )
            for process in processes
        }
        return len(identities) == 3

    @staticmethod
    def _session_events_precede_completion(
        jobs: Sequence[Mapping[str, Any]],
        attempts: Sequence[Mapping[str, Any]],
        processes: Sequence[Mapping[str, Any]],
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
            bound_processes = [
                process
                for process in processes
                if process.get("attempt_id") == attempt.get("id")
            ]
            if len(bound_processes) != 1:
                return False
            process = bound_processes[0]
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
            session_required = process.get("provider") == "codex"
            if not (
                len(started_events) == 1
                and len(session_events) == (1 if session_required else 0)
                and len(stopped_events) == 1
                and len(completion_events) == 1
            ):
                return False
            started_data = started_events[0].get("event_data") or {}
            stopped_data = stopped_events[0].get("event_data") or {}
            if started_data != {
                "provider": process.get("provider"),
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
            if session_required and (
                session_events[0].get("event_data") or {}
            ) != {
                "provider": process.get("provider"),
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
            sequences = [int(started_events[0]["sequence"])]
            if session_required:
                sequences.append(int(session_events[0]["sequence"]))
            sequences.extend(
                (
                    int(stopped_events[0]["sequence"]),
                    int(completion_events[0]["sequence"]),
                )
            )
            if sequences != sorted(set(sequences)):
                return False
        return bool(jobs)

    def _focused_test_execution_proof(
        self,
        plans: Sequence[Mapping[str, Any]],
        executions: Sequence[Mapping[str, Any]],
        jobs: Sequence[Mapping[str, Any]],
        attempts: Sequence[Mapping[str, Any]],
        artifacts: Sequence[Mapping[str, Any]],
        events: Sequence[Mapping[str, Any]],
        worktree_path: Path,
        report: Mapping[str, Any],
    ) -> bool:
        testers = [job for job in jobs if job.get("role") == "tester"]
        if len(testers) != 1 or len(plans) != 1 or len(executions) != 1:
            return False
        tester = testers[0]
        tester_attempts = [
            attempt
            for attempt in attempts
            if attempt.get("job_id") == tester.get("id")
        ]
        if len(tester_attempts) != 1:
            return False
        attempt = tester_attempts[0]
        plan = plans[0]
        execution = executions[0]
        expected_manifest = self._workspace_manifest(worktree_path)
        expected_command = [
            str(self.python_executable),
            "-I",
            "-B",
            str(worktree_path / FOCUSED_TEST_FILE),
            FOCUSED_TEST_SELECTOR,
            "-v",
        ]
        command = execution.get("command_argv", execution.get("command"))
        if (
            plan.get("id") != report.get("focused_test_plan_id")
            or plan.get("work_item_id") != report.get("item_id")
            or plan.get("executable_path") != str(self.python_executable)
            or plan.get("test_file") != FOCUSED_TEST_FILE
            or plan.get("selector") != FOCUSED_TEST_SELECTOR
            or plan.get("workspace_manifest") != expected_manifest
            or execution.get("plan_id") != plan.get("id")
            or execution.get("attempt_id") != attempt.get("id")
            or execution.get("job_id") != tester.get("id")
            or execution.get("work_item_id") != report.get("item_id")
            or execution.get("managed_worktree_id")
            != report.get("worktree_id")
            or execution.get("managed_worktree_generation") != 1
            or command != expected_command
            or execution.get("cwd") != str(worktree_path)
            or execution.get("status") != "finished"
            or execution.get("exit_code") != 0
            or execution.get("outcome") != "pass"
            or execution.get("semantic_summary")
            != "exactly one persisted focused unittest selector passed"
            or execution.get("stdout_truncated") not in (False, 0)
            or execution.get("stderr_truncated") not in (False, 0)
            or execution.get("workspace_manifest_before") != expected_manifest
            or execution.get("workspace_manifest_after") != expected_manifest
            or attempt.get("external_session_id") is not None
        ):
            return False

        focused_artifacts = [
            artifact
            for artifact in artifacts
            if artifact.get("job_id") == tester.get("id")
        ]
        if {
            str(artifact.get("kind")) for artifact in focused_artifacts
        } != {"focused_test_stdout", "focused_test_stderr"}:
            return False
        output_by_kind: Dict[str, str] = {}
        for artifact in focused_artifacts:
            kind = str(artifact.get("kind"))
            metadata = artifact.get("metadata") or {}
            path = Path(str(artifact.get("uri") or ""))
            prefix = "stdout" if kind.endswith("stdout") else "stderr"
            try:
                file_metadata = path.lstat()
            except OSError:
                return False
            if (
                not path.is_file()
                or path.is_symlink()
                or file_metadata.st_uid != os.getuid()
                or file_metadata.st_nlink != 1
                or file_metadata.st_mode & 0o077
                or not self._is_within(path.resolve(), self.focused_test_runtime)
                or self._is_within(path.resolve(), self.source)
                or self._is_within(path.resolve(), worktree_path)
                or metadata.get("attempt_id") != attempt.get("id")
                or metadata.get("execution_id") != execution.get("id")
                or metadata.get("sha256") != self._sha256(path)
                or metadata.get("bytes") != file_metadata.st_size
                or execution.get(prefix + "_path") != str(path.resolve())
                or execution.get(prefix + "_sha256") != self._sha256(path)
                or execution.get(prefix + "_bytes") != file_metadata.st_size
            ):
                return False
            try:
                output_by_kind[prefix] = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                return False
        combined_output = output_by_kind.get("stdout", "") + output_by_kind.get(
            "stderr", ""
        )
        expected_marker = "AGENT_FLOW_TEST_FILE=%s" % (
            worktree_path / FOCUSED_TEST_FILE
        )
        if not (
            "test_adds_two_numbers" in combined_output
            and expected_marker in combined_output
            and "Ran 1 test" in combined_output
            and "OK" in combined_output
            and "FAILED" not in combined_output
            and "ERROR" not in combined_output
        ):
            return False

        artifact_by_kind = {
            str(artifact.get("kind")): artifact
            for artifact in focused_artifacts
        }
        summary = str(execution.get("semantic_summary"))
        expected_handoff = {
            "schema_version": 1,
            "item_id": report.get("item_id"),
            "outcome": "pass",
            "summary": summary,
            "gate_proofs": [
                {
                    "gate": "focused_tests",
                    "result": "pass",
                    "summary": summary,
                    "evidence": [
                        {
                            "id": artifact_by_kind["focused_test_stdout"].get("id"),
                            "kind": "test",
                            "location": artifact_by_kind["focused_test_stdout"].get("uri"),
                            "description": (
                                "Authoritative bounded stdout for the focused "
                                "unittest run."
                            ),
                            "metadata": artifact_by_kind[
                                "focused_test_stdout"
                            ].get("metadata"),
                        },
                        {
                            "id": artifact_by_kind["focused_test_stderr"].get("id"),
                            "kind": "log",
                            "location": artifact_by_kind["focused_test_stderr"].get("uri"),
                            "description": (
                                "Authoritative bounded stderr for the focused "
                                "unittest run."
                            ),
                            "metadata": artifact_by_kind[
                                "focused_test_stderr"
                            ].get("metadata"),
                        },
                    ],
                }
            ],
            "failure_summary": None,
            "blocker": None,
        }
        if (
            attempt.get("result") != expected_handoff
            or execution.get("canonical_handoff") != expected_handoff
        ):
            return False

        plan_events = [
            event
            for event in events
            if event.get("event_type") == "focused_test.plan_created"
        ]
        prepared_events = [
            event
            for event in events
            if event.get("event_type") == "focused_test.execution_prepared"
        ]
        finished_events = [
            event
            for event in events
            if event.get("event_type") == "focused_test.execution_finished"
        ]
        tester_started = [
            event
            for event in events
            if event.get("job_id") == tester.get("id")
            and event.get("event_type") == "worker.external_process_started"
        ]
        tester_stopped = [
            event
            for event in events
            if event.get("job_id") == tester.get("id")
            and event.get("event_type") == "worker.external_process_stopped"
        ]
        tester_completed = [
            event
            for event in events
            if event.get("job_id") == tester.get("id")
            and event.get("event_type") == "test_verified_green"
        ]
        if not (
            len(plan_events) == 1
            and len(prepared_events) == 1
            and len(finished_events) == 1
            and len(tester_started) == 1
            and len(tester_stopped) == 1
            and len(tester_completed) == 1
            and (plan_events[0].get("event_data") or {}).get("plan_id")
            == plan.get("id")
            and (prepared_events[0].get("event_data") or {}).get("execution_id")
            == execution.get("id")
            and (finished_events[0].get("event_data") or {}).get("execution_id")
            == execution.get("id")
            and int(plan_events[0]["sequence"])
            < int(prepared_events[0]["sequence"])
            < int(tester_started[0]["sequence"])
            < int(tester_stopped[0]["sequence"])
            < int(finished_events[0]["sequence"])
            < int(tester_completed[0]["sequence"])
        ):
            return False
        return True

    @staticmethod
    def _artifact_events_valid(
        jobs: Sequence[Mapping[str, Any]],
        artifacts: Sequence[Mapping[str, Any]],
        events: Sequence[Mapping[str, Any]],
    ) -> bool:
        expected_kinds_by_role = {
            "investigator": PROVIDER_ARTIFACT_KINDS,
            "fixer": PROVIDER_ARTIFACT_KINDS,
            "tester": {"focused_test_stdout", "focused_test_stderr"},
        }
        for job in jobs:
            job_id = str(job.get("id"))
            role = str(job.get("role"))
            expected_kinds = expected_kinds_by_role.get(role)
            if expected_kinds is None:
                return False
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
                {str(artifact.get("kind")) for artifact in job_artifacts}
                != expected_kinds
                or len(job_artifacts) != len(expected_kinds)
                or len(expected) != len(expected_kinds)
                or len(artifact_events) != len(expected_kinds)
                or observed != expected
                or len(stopped_events) != 1
            ):
                return False
            if role in ("investigator", "fixer"):
                if len(session_events) != 1 or not all(
                        int(session_events[0]["sequence"])
                        < int(event["sequence"])
                        < int(stopped_events[0]["sequence"])
                        for event in artifact_events
                    ):
                    return False
            else:
                prepared = [
                    event
                    for event in events
                    if str(event.get("job_id")) == job_id
                    and event.get("event_type")
                    == "focused_test.execution_prepared"
                ]
                finished = [
                    event
                    for event in events
                    if str(event.get("job_id")) == job_id
                    and event.get("event_type")
                    == "focused_test.execution_finished"
                ]
                if (
                    session_events
                    or len(prepared) != 1
                    or len(finished) != 1
                    or not all(
                        int(stopped_events[0]["sequence"])
                        < int(event["sequence"])
                        < int(finished[0]["sequence"])
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

    def _workspace_manifest(
        self, worktree_path: Path
    ) -> Mapping[str, Mapping[str, Any]]:
        expected = {"AGENTS.md", "calculator.py", FOCUSED_TEST_FILE}
        observed = {
            entry.name for entry in worktree_path.iterdir() if entry.name != ".git"
        }
        if observed != expected:
            raise RealProofError(
                "focused-test workspace does not contain the exact fixed fixture"
            )
        manifest: Dict[str, Mapping[str, Any]] = {}
        for relative in sorted(expected):
            path = worktree_path / relative
            metadata = path.lstat()
            if path.is_symlink() or not path.is_file():
                raise RealProofError(
                    "focused-test workspace contains a non-regular fixture file"
                )
            manifest[relative] = {
                "sha256": self._sha256(path),
                "mode": metadata.st_mode,
            }
        return manifest

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
        report: Mapping[str, Any]
    ) -> Tuple[bool, ...]:
        return (
            report.get("final_item_state") == "verified_green",
            report.get("source_unchanged") is True,
            report.get("exact_worktree_diff") is True,
            report.get("jobs_exactly_once") is True,
            report.get("attempts_succeeded_exactly_once") is True,
            report.get("same_worktree_fixer_tester") is True,
            report.get("scheduler_error_free") is True,
            report.get("focused_test_execution_proof") is True,
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
