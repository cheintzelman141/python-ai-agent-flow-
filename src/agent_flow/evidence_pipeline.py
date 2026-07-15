"""Supervisor-owned focused-test, browser, and database evidence pipeline."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import threading
from typing import Any, Dict, List, Mapping, Optional

from agent_flow.database_collector import DatabaseEvidenceCollector
from agent_flow.focused_tests import FocusedTestWorker
from agent_flow.models import TestHandoff, WorkerRole
from agent_flow.workers import WorkerContext, WorkerExecutionError, WorkerOutput
from agent_flow.worktrees import GuardedGitCommandRunner


class EvidencePipelineWorker:
    """Run only the three fixed, storage-prepared authoritative collectors."""

    role = WorkerRole.TESTER

    def __init__(
        self,
        command_runner: GuardedGitCommandRunner,
        *,
        browser_command_runner: Optional[GuardedGitCommandRunner] = None,
        database_collector: Optional[DatabaseEvidenceCollector] = None,
    ) -> None:
        self.command_runner = command_runner
        self.browser_command_runner = browser_command_runner or command_runner
        self.focused_worker = FocusedTestWorker(command_runner)
        self.database_collector = database_collector or DatabaseEvidenceCollector()

    async def run(self, context: WorkerContext) -> WorkerOutput:
        focused = TestHandoff.model_validate(
            await self.focused_worker.run(context)
        )
        proofs: List[Dict[str, Any]] = [
            proof.model_dump(mode="json") for proof in focused.gate_proofs
        ]
        if focused.outcome.value != "pass":
            return focused

        browser_contract = dict(context.prepare_browser_evidence_execution())
        browser_result = await self._run_guarded_browser(context, browser_contract)
        browser = dict(context.complete_browser_evidence_execution(browser_result))
        proofs.append(self._browser_proof(browser))
        if browser.get("outcome") != "pass":
            return self._handoff(
                context.item_id,
                proofs,
                "visible browser assertions failed",
            )

        database_contract = dict(context.prepare_database_query_execution())
        with context.database_query_execution_fence(database_contract) as authorized_contract:
            database_contract = dict(authorized_contract)
            database_task = asyncio.create_task(
                asyncio.to_thread(
                    self.database_collector.collect,
                    database_contract,
                )
            )
            try:
                database_result = await asyncio.shield(database_task)
            except asyncio.CancelledError:
                # The query is read-only and bounded.  Do not release its resource
                # fence while a background thread can still be using it.
                try:
                    await asyncio.shield(database_task)
                except Exception:
                    pass
                raise
        database = dict(
            context.complete_database_query_execution(database_result)
        )
        proofs.append(self._database_proof(database))
        if database.get("outcome") != "pass":
            return self._handoff(
                context.item_id,
                proofs,
                "read-only database assertions failed",
            )
        return TestHandoff.model_validate(
            {
                "schema_version": 1,
                "item_id": context.item_id,
                "outcome": "pass",
                "summary": (
                    "focused test, visible browser, and read-only database "
                    "collectors passed"
                ),
                "gate_proofs": proofs,
                "failure_summary": None,
                "blocker": None,
            }
        )

    async def _run_guarded_browser(
        self,
        context: WorkerContext,
        contract: Mapping[str, Any],
    ) -> Dict[str, str]:
        run_parent = Path(str(contract.get("run_parent", "")))
        if (
            not run_parent.is_absolute()
            or str(run_parent) != str(run_parent.resolve())
            or not str(run_parent).startswith("/private/tmp/agent-flow-")
            or not run_parent.is_dir()
        ):
            raise WorkerExecutionError(
                "browser preparation returned an invalid runtime directory"
            )
        contract_path = run_parent / "contract.json"
        process_artifacts = run_parent / "guarded-process"
        with contract_path.open("x", encoding="utf-8") as stream:
            os.chmod(contract_path, 0o600)
            json.dump(
                dict(contract),
                stream,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            stream.flush()
            os.fsync(stream.fileno())
        helper = Path(__file__).with_name("browser_runtime.py").resolve(strict=True)
        source_root = helper.parent.parent
        command = (sys.executable, str(helper), str(contract_path))
        environment = {
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONHASHSEED": "0",
            "PYTHONPATH": str(source_root),
        }
        cancellation_event = threading.Event()

        async def execute():
            return await asyncio.to_thread(
                self.browser_command_runner.run,
                command,
                cwd=run_parent,
                environment=environment,
                artifact_directory=process_artifacts,
                record_process=lambda identity, target: context.record_external_process(
                    "browser_evidence", identity, target
                ),
                clear_process=context.clear_external_process,
                release_fence=context.browser_guardian_release_fence,
                cancellation_event=cancellation_event,
            )

        runner_task = asyncio.create_task(execute())
        try:
            result = await asyncio.shield(runner_task)
        except asyncio.CancelledError:
            cancellation_event.set()
            try:
                await asyncio.shield(runner_task)
            except Exception:
                pass
            raise
        if result.return_code != 0 or result.stdout_truncated or result.stderr_truncated:
            raise WorkerExecutionError("guarded visible browser collector failed")
        try:
            raw = result.stdout_path.read_bytes()
            if len(raw) > 1024 * 1024:
                raise ValueError
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise WorkerExecutionError(
                "guarded visible browser collector returned invalid output"
            ) from error
        if not isinstance(value, dict):
            raise WorkerExecutionError(
                "guarded visible browser collector returned invalid output"
            )
        return {str(key): str(entry) for key, entry in value.items()}

    @staticmethod
    def _browser_proof(execution: Mapping[str, Any]) -> Dict[str, Any]:
        passed = execution.get("outcome") == "pass"
        return {
            "gate": "browser",
            "result": "pass" if passed else "fail",
            "summary": (
                "exact visible route, title, and body assertions passed"
                if passed
                else "one or more exact visible browser assertions failed"
            ),
            "evidence": [
                {
                    "id": execution["artifact_id"],
                    "kind": "screenshot",
                    "location": execution["screenshot_path"],
                    "description": "Visible Chrome screenshot for the fixed route.",
                    "metadata": {
                        "attempt_id": execution["attempt_id"],
                        "execution_id": execution["id"],
                        "resource_id": execution["resource_definition_id"],
                        "route": execution["observed_route"],
                        "sha256": execution["screenshot_sha256"],
                        "bytes": execution["screenshot_bytes"],
                    },
                }
            ],
        }

    @staticmethod
    def _database_proof(execution: Mapping[str, Any]) -> Dict[str, Any]:
        passed = execution.get("outcome") == "pass"
        proof = execution.get("read_only_proof")
        return {
            "gate": "database",
            "result": "pass" if passed else "fail",
            "summary": (
                "fixed read-only query, expected IDs, row count, and foreign keys passed"
                if passed
                else "one or more fixed database assertions failed"
            ),
            "evidence": [
                {
                    "id": execution["artifact_id"],
                    "kind": "database",
                    "location": execution["result_path"],
                    "description": "Bounded canonical result from the fixed read-only query.",
                    "metadata": {
                        "attempt_id": execution["attempt_id"],
                        "execution_id": execution["id"],
                        "resource_id": execution["resource_definition_id"],
                        "query_sha256": execution["query_sha256"],
                        "result_sha256": execution["result_sha256"],
                        "row_count": execution["row_count"],
                        "read_only_proof": proof,
                    },
                }
            ],
        }

    @staticmethod
    def _handoff(
        item_id: str,
        proofs: List[Dict[str, Any]],
        failure: str,
    ) -> TestHandoff:
        return TestHandoff.model_validate(
            {
                "schema_version": 1,
                "item_id": item_id,
                "outcome": "red",
                "summary": failure,
                "gate_proofs": proofs,
                "failure_summary": failure,
                "blocker": None,
            }
        )
