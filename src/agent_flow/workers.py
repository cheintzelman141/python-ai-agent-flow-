from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, Mapping, Optional, Protocol, Union

from pydantic import BaseModel

from agent_flow.models import WorkerRole
from agent_flow.process_reconciler import ProcessIdentity


@dataclass(frozen=True)
class WorkerContext:
    """Persisted records supplied to a worker for one bounded stage attempt."""

    campaign: Mapping[str, Any]
    item: Mapping[str, Any]
    job: Mapping[str, Any]
    _external_session_recorder: Optional[Callable[[str, str], None]] = field(
        default=None, repr=False, compare=False
    )
    _external_process_recorder: Optional[
        Callable[[str, ProcessIdentity, str], None]
    ] = field(default=None, repr=False, compare=False)
    _external_process_clearer: Optional[Callable[[int, int], None]] = field(
        default=None, repr=False, compare=False
    )
    _artifact_recorder: Optional[
        Callable[[str, str, Mapping[str, Any]], None]
    ] = field(default=None, repr=False, compare=False)
    _managed_worktree_provider: Optional[
        Callable[[], Optional[Mapping[str, Any]]]
    ] = field(default=None, repr=False, compare=False)
    _managed_worktree_quarantiner: Optional[Callable[[str], bool]] = field(
        default=None, repr=False, compare=False
    )
    _focused_test_execution_preparer: Optional[
        Callable[[], Mapping[str, Any]]
    ] = field(default=None, repr=False, compare=False)
    _focused_test_execution_completer: Optional[
        Callable[[Mapping[str, Any]], Mapping[str, Any]]
    ] = field(default=None, repr=False, compare=False)
    _browser_evidence_execution_preparer: Optional[
        Callable[[], Mapping[str, Any]]
    ] = field(default=None, repr=False, compare=False)
    _browser_evidence_execution_completer: Optional[
        Callable[[Mapping[str, Any]], Mapping[str, Any]]
    ] = field(default=None, repr=False, compare=False)
    _database_query_execution_preparer: Optional[
        Callable[[], Mapping[str, Any]]
    ] = field(default=None, repr=False, compare=False)
    _database_query_execution_completer: Optional[
        Callable[[Mapping[str, Any]], Mapping[str, Any]]
    ] = field(default=None, repr=False, compare=False)

    @property
    def item_id(self) -> str:
        return str(self.item["id"])

    def record_external_session(self, provider: str, session_id: str) -> None:
        """Durably bind an external worker session to this fenced attempt."""

        if self._external_session_recorder is None:
            raise WorkerExecutionError(
                "this worker context cannot persist an external session"
            )
        self._external_session_recorder(provider, session_id)

    def record_external_process(
        self,
        provider: str,
        identity: ProcessIdentity,
        target_executable: str,
    ) -> None:
        """Durably bind a live external process to this fenced attempt."""

        if self._external_process_recorder is None:
            raise WorkerExecutionError(
                "this worker context cannot persist an external process"
            )
        self._external_process_recorder(
            provider, identity, target_executable
        )

    def clear_external_process(
        self, process_id: int, process_group_id: int
    ) -> None:
        """Clear the process binding after the adapter has reaped the group."""

        if self._external_process_clearer is None:
            raise WorkerExecutionError(
                "this worker context cannot clear an external process"
            )
        self._external_process_clearer(process_id, process_group_id)

    def record_artifact(
        self, kind: str, uri: str, metadata: Mapping[str, Any]
    ) -> None:
        """Persist a fenced execution artifact for the current attempt."""

        if self._artifact_recorder is None:
            raise WorkerExecutionError("this worker context cannot persist artifacts")
        self._artifact_recorder(kind, uri, metadata)

    def require_managed_worktree(self) -> Mapping[str, Any]:
        """Return the worktree bound to this exact live job/attempt fence."""

        if self._managed_worktree_provider is None:
            raise WorkerExecutionError(
                "this worker context has no managed-worktree authority"
            )
        worktree = self._managed_worktree_provider()
        if worktree is None:
            raise WorkerExecutionError(
                "the managed worktree binding is absent, stale, or not ready"
            )
        return worktree

    def quarantine_managed_worktree(self, reason: str) -> None:
        """Durably fence a managed workspace that failed exact validation."""

        if self._managed_worktree_quarantiner is None:
            raise WorkerExecutionError(
                "this worker context has no managed-worktree quarantine authority"
            )
        if not self._managed_worktree_quarantiner(reason):
            raise WorkerExecutionError(
                "managed worktree quarantine rejected the stale lease fence"
            )

    def prepare_focused_test_execution(self) -> Mapping[str, Any]:
        """Request the supervisor-owned command for this exact attempt."""

        if self._focused_test_execution_preparer is None:
            raise WorkerExecutionError(
                "this worker context has no focused-test execution authority"
            )
        prepared = self._focused_test_execution_preparer()
        if not isinstance(prepared, Mapping):
            raise WorkerExecutionError(
                "focused-test preparation returned an invalid command contract"
            )
        return prepared

    def complete_focused_test_execution(
        self, result: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Submit captured process evidence through the current attempt fence."""

        if self._focused_test_execution_completer is None:
            raise WorkerExecutionError(
                "this worker context has no focused-test completion authority"
            )
        completed = self._focused_test_execution_completer(result)
        if not isinstance(completed, Mapping):
            raise WorkerExecutionError(
                "focused-test completion returned an invalid canonical result"
            )
        return completed

    def prepare_browser_evidence_execution(self) -> Mapping[str, Any]:
        """Request the fixed visible-browser contract for this attempt."""

        if self._browser_evidence_execution_preparer is None:
            raise WorkerExecutionError(
                "this worker context has no browser-evidence authority"
            )
        prepared = self._browser_evidence_execution_preparer()
        if not isinstance(prepared, Mapping):
            raise WorkerExecutionError(
                "browser-evidence preparation returned an invalid contract"
            )
        return prepared

    def complete_browser_evidence_execution(
        self, result: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Submit a fixed browser result through the current attempt fence."""

        if self._browser_evidence_execution_completer is None:
            raise WorkerExecutionError(
                "this worker context has no browser-evidence completion authority"
            )
        completed = self._browser_evidence_execution_completer(result)
        if not isinstance(completed, Mapping):
            raise WorkerExecutionError(
                "browser-evidence completion returned an invalid result"
            )
        return completed

    def prepare_database_query_execution(self) -> Mapping[str, Any]:
        """Request the fixed read-only database contract for this attempt."""

        if self._database_query_execution_preparer is None:
            raise WorkerExecutionError(
                "this worker context has no database-evidence authority"
            )
        prepared = self._database_query_execution_preparer()
        if not isinstance(prepared, Mapping):
            raise WorkerExecutionError(
                "database-evidence preparation returned an invalid contract"
            )
        return prepared

    def complete_database_query_execution(
        self, result: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Submit a fixed database result through the current attempt fence."""

        if self._database_query_execution_completer is None:
            raise WorkerExecutionError(
                "this worker context has no database-evidence completion authority"
            )
        completed = self._database_query_execution_completer(result)
        if not isinstance(completed, Mapping):
            raise WorkerExecutionError(
                "database-evidence completion returned an invalid result"
            )
        return completed


WorkerOutput = Union[BaseModel, Mapping[str, Any]]
OutputFactory = Callable[[WorkerContext], WorkerOutput]
ScriptedOutcome = Union[WorkerOutput, OutputFactory, Exception]


class Worker(Protocol):
    role: WorkerRole

    async def run(self, context: WorkerContext) -> WorkerOutput:
        """Run one job and return a structured handoff."""


class WorkerExecutionError(RuntimeError):
    """A bounded worker failed before producing a valid handoff."""


class ConcurrencyProbe:
    """Deterministic instrumentation used to prove scheduler limits in tests."""

    def __init__(self) -> None:
        self.active_total = 0
        self.max_active_total = 0
        self.active_by_role: Dict[WorkerRole, int] = defaultdict(int)
        self.max_active_by_role: Dict[WorkerRole, int] = defaultdict(int)

    def started(self, role: WorkerRole) -> None:
        self.active_total += 1
        self.active_by_role[role] += 1
        self.max_active_total = max(self.max_active_total, self.active_total)
        self.max_active_by_role[role] = max(
            self.max_active_by_role[role], self.active_by_role[role]
        )

    def finished(self, role: WorkerRole) -> None:
        self.active_total -= 1
        self.active_by_role[role] -= 1


class ScriptedWorker:
    """Fake worker with per-item outcome queues for end-to-end scheduler tests."""

    def __init__(
        self,
        role: WorkerRole,
        outcomes: Optional[Mapping[str, list[ScriptedOutcome]]] = None,
        *,
        default: Optional[ScriptedOutcome] = None,
        delay_seconds: float = 0.0,
        probe: Optional[ConcurrencyProbe] = None,
    ) -> None:
        self.role = role
        self.delay_seconds = delay_seconds
        self.default = default
        self.probe = probe
        self._outcomes: Dict[str, Deque[ScriptedOutcome]] = {
            item_id: deque(item_outcomes) for item_id, item_outcomes in (outcomes or {}).items()
        }
        self.calls: list[WorkerContext] = []

    async def run(self, context: WorkerContext) -> WorkerOutput:
        self.calls.append(context)
        if self.probe is not None:
            self.probe.started(self.role)

        try:
            if self.delay_seconds:
                await asyncio.sleep(self.delay_seconds)

            item_outcomes = self._outcomes.get(context.item_id)
            if item_outcomes:
                outcome = item_outcomes.popleft()
            elif self.default is not None:
                outcome = self.default
            else:
                raise WorkerExecutionError(
                    f"No scripted {self.role.value} outcome for item {context.item_id}"
                )

            if isinstance(outcome, Exception):
                raise outcome
            if callable(outcome):
                return outcome(context)
            return outcome
        finally:
            if self.probe is not None:
                self.probe.finished(self.role)
