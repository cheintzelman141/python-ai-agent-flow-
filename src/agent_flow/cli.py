from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from agent_flow.models import (
    EvidenceKind,
    EvidenceRef,
    FixHandoff,
    GateKind,
    GateProof,
    GateResult,
    InvestigationHandoff,
    TestHandoff as TesterHandoff,
    TestOutcome,
    WorkerRole,
)
from agent_flow.scheduler import Scheduler
from agent_flow.sqlite_scheduler import LOCAL_WRITE_APPROVAL_ACTION, SQLiteSchedulerStorage
from agent_flow.status import render_status
from agent_flow.storage import NotFoundError, SQLiteStore, StorageError
from agent_flow.worktrees import (
    ManagedWorktreeConfig,
    ManagedWorktreeError,
    ManagedWorktreeManager,
)
from agent_flow.workers import ScriptedWorker, WorkerContext


app = typer.Typer(
    no_args_is_help=True,
    help="Durable, evidence-gated worker production-line supervisor.",
)
console = Console()


def default_database_path() -> Path:
    configured = os.environ.get("AGENT_FLOW_DB")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".agent-flow" / "agent-flow.sqlite3"


def _database_path(database: Optional[Path]) -> Path:
    return (database or default_database_path()).expanduser().resolve()


def _open_existing(database: Optional[Path]) -> SQLiteStore:
    path = _database_path(database)
    if not path.exists():
        raise typer.BadParameter("Agent Flow database does not exist: %s" % path)
    return SQLiteStore(path)


def _worktree_manager(
    store: SQLiteStore,
    *,
    worktree_root: Optional[Path],
    runtime_root: Optional[Path],
) -> ManagedWorktreeManager:
    defaults = ManagedWorktreeConfig()
    return ManagedWorktreeManager(
        store,
        config=ManagedWorktreeConfig(
            worktree_root=(
                defaults.worktree_root
                if worktree_root is None
                else worktree_root.expanduser().resolve()
            ),
            runtime_root=(
                defaults.runtime_root
                if runtime_root is None
                else runtime_root.expanduser().resolve()
            ),
        ),
    )


@app.command("init")
def initialize(
    database: Optional[Path] = typer.Option(None, "--database", "-d"),
) -> None:
    """Initialize or migrate an Agent Flow database."""

    path = _database_path(database)
    with SQLiteStore(path):
        pass
    console.print("Initialized Agent Flow database: %s" % path)


@app.command("campaign-create")
def campaign_create(
    name: str = typer.Argument(...),
    description: str = typer.Option("", "--description"),
    repository: Optional[List[str]] = typer.Option(None, "--repository"),
    global_limit: int = typer.Option(4, "--global-limit", min=1),
    investigators: int = typer.Option(2, "--investigators", min=1),
    fixers: int = typer.Option(2, "--fixers", min=1),
    testers: int = typer.Option(2, "--testers", min=1),
    database: Optional[Path] = typer.Option(None, "--database", "-d"),
) -> None:
    """Create a durable campaign with persisted concurrency limits."""

    with SQLiteStore(_database_path(database)) as store:
        campaign = store.create_campaign(
            name,
            config={
                "description": description,
                "repository_paths": repository or [],
            },
            global_limit=global_limit,
            role_limits={
                WorkerRole.INVESTIGATOR.value: investigators,
                WorkerRole.FIXER.value: fixers,
                WorkerRole.TESTER.value: testers,
            },
        )
    console.print(campaign["id"])


@app.command("item-add")
def item_add(
    campaign_id: str = typer.Argument(...),
    title: str = typer.Argument(...),
    description: str = typer.Option(..., "--description"),
    gate: Optional[List[GateKind]] = typer.Option(None, "--gate"),
    resource: Optional[List[str]] = typer.Option(None, "--resource"),
    priority: int = typer.Option(0, "--priority", min=0),
    database: Optional[Path] = typer.Option(None, "--database", "-d"),
) -> None:
    """Create an item and its initial investigation job atomically."""

    with SQLiteStore(_database_path(database)) as store:
        item = store.create_work_item(
            campaign_id,
            title,
            description=description,
            priority=priority,
            required_gates=[required_gate.value for required_gate in gate] if gate else None,
            initial_job={
                "role": WorkerRole.INVESTIGATOR.value,
                "stage": WorkerRole.INVESTIGATOR.value,
                "active_item_state": "investigating",
                "required_resources": resource or [],
                "priority": priority,
            },
        )
    console.print(item["id"])


@app.command("approve-writes")
def approve_writes(
    campaign_id: str = typer.Argument(...),
    approved_by: str = typer.Option(..., "--by"),
    database: Optional[Path] = typer.Option(None, "--database", "-d"),
) -> None:
    """Explicitly approve scoped local fixer writes for one campaign."""

    with _open_existing(database) as store:
        campaign = store.get_campaign(campaign_id)
        campaign_config = campaign.get("config") or {}
        existing = [
            approval
            for approval in store.list_approvals(campaign_id=campaign_id)
            if approval["action"] == LOCAL_WRITE_APPROVAL_ACTION
            and approval["status"] == "approved"
        ]
        if existing:
            console.print("Local writes are already approved: %s" % existing[-1]["id"])
            return
        approval = store.create_approval(
            campaign_id,
            LOCAL_WRITE_APPROVAL_ACTION,
            approved_by,
            scope={
                "mode": "local_code_changes",
                "repository_paths": campaign_config.get("repository_paths", []),
                "push": False,
                "merge": False,
                "deploy": False,
            },
        )
        resolved = store.resolve_approval(
            approval["id"], "approved", approved_by
        )
    console.print(resolved["id"])


@app.command("status")
def status(
    campaign_id: str = typer.Argument(...),
    database: Optional[Path] = typer.Option(None, "--database", "-d"),
    event_limit: int = typer.Option(8, "--event-limit", min=0),
) -> None:
    """Render persisted campaign state without changing it."""

    try:
        with _open_existing(database) as store:
            campaign = store.get_campaign(campaign_id)
            worktrees = store.list_managed_worktrees(campaign_id=campaign_id)
            worktree_ids = {str(worktree["id"]) for worktree in worktrees}
            render_status(
                campaign,
                store.list_work_items(campaign_id),
                store.list_jobs(campaign_id=campaign_id),
                store.list_attempts(campaign_id=campaign_id),
                store.list_resource_leases(campaign_id=campaign_id),
                store.list_events(campaign_id=campaign_id),
                managed_worktrees=worktrees,
                worktree_operations=[
                    operation
                    for operation in store.list_worktree_operations()
                    if str(operation["managed_worktree_id"]) in worktree_ids
                ],
                console=console,
                event_limit=event_limit,
            )
    except NotFoundError as error:
        raise typer.BadParameter(str(error)) from error


@app.command("worktree-provision")
def worktree_provision(
    campaign_id: str = typer.Argument(...),
    item_id: str = typer.Argument(...),
    repository: Path = typer.Option(..., "--repository"),
    base: str = typer.Option("HEAD", "--base"),
    worktree_root: Optional[Path] = typer.Option(None, "--worktree-root"),
    runtime_root: Optional[Path] = typer.Option(None, "--runtime-root"),
    database: Optional[Path] = typer.Option(None, "--database", "-d"),
) -> None:
    """Provision and durably bind one exact managed Git worktree."""

    try:
        with _open_existing(database) as store:
            manager = _worktree_manager(
                store,
                worktree_root=worktree_root,
                runtime_root=runtime_root,
            )
            worktree = manager.provision(
                campaign_id, item_id, repository, base
            )
    except (ManagedWorktreeError, StorageError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    console.print(worktree["id"])


@app.command("worktree-verify")
def worktree_verify(
    worktree_id: str = typer.Argument(...),
    worktree_root: Optional[Path] = typer.Option(None, "--worktree-root"),
    runtime_root: Optional[Path] = typer.Option(None, "--runtime-root"),
    database: Optional[Path] = typer.Option(None, "--database", "-d"),
) -> None:
    """Revalidate the exact persisted source and worktree identity."""

    try:
        with _open_existing(database) as store:
            manager = _worktree_manager(
                store,
                worktree_root=worktree_root,
                runtime_root=runtime_root,
            )
            observed = manager.verify(worktree_id)
    except (ManagedWorktreeError, StorageError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    console.print("Verified managed worktree: %s" % observed["worktree_id"])


@app.command("worktree-cleanup")
def worktree_cleanup(
    worktree_id: str = typer.Argument(...),
    worktree_root: Optional[Path] = typer.Option(None, "--worktree-root"),
    runtime_root: Optional[Path] = typer.Option(None, "--runtime-root"),
    database: Optional[Path] = typer.Option(None, "--database", "-d"),
) -> None:
    """Remove a clean terminal worktree while retaining its managed branch."""

    try:
        with _open_existing(database) as store:
            manager = _worktree_manager(
                store,
                worktree_root=worktree_root,
                runtime_root=runtime_root,
            )
            worktree = manager.cleanup(worktree_id)
    except (ManagedWorktreeError, StorageError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    console.print("Removed managed worktree; branch retained: %s" % worktree["branch_ref"])


@app.command("worktree-reconcile")
def worktree_reconcile(
    retry_quarantined: bool = typer.Option(
        False,
        "--retry-quarantined",
        help="Retry quarantined lifecycle operations without bypassing identity proof.",
    ),
    worktree_root: Optional[Path] = typer.Option(None, "--worktree-root"),
    runtime_root: Optional[Path] = typer.Option(None, "--runtime-root"),
    database: Optional[Path] = typer.Option(None, "--database", "-d"),
) -> None:
    """Identity-safely reconcile expired worktree lifecycle operations."""

    with _open_existing(database) as store:
        manager = _worktree_manager(
            store,
            worktree_root=worktree_root,
            runtime_root=runtime_root,
        )
        results = list(manager.reconcile_expired())
        if retry_quarantined:
            results.extend(manager.retry_quarantined_processes())
        operations = store.list_worktree_operations()
        violations = store.foreign_key_violations()

    unresolved = [
        operation
        for operation in operations
        if operation["status"] in ("running", "quarantined")
    ]

    table = Table(title="Worktree lifecycle reconciliation")
    table.add_column("Operation")
    table.add_column("Outcome")
    table.add_column("Evidence / blocker")
    for result in results:
        table.add_row(
            result.binding.attempt_id,
            result.status.value,
            result.reason,
        )
    for operation in unresolved:
        table.add_row(
            str(operation["id"]),
            str(operation["status"]),
            str(operation.get("error") or "Lifecycle operation remains unresolved"),
        )
    if not results and not unresolved:
        table.add_row("None", "clear", "No expired lifecycle operation")
    if violations:
        table.add_row(
            "SQLite",
            "foreign-key violation",
            "%d violation(s) require repair" % len(violations),
        )
    console.print(table)
    if unresolved or violations or any(
        result.status.value == "quarantined" for result in results
    ):
        raise typer.Exit(code=1)


@app.command("process-reconcile")
def process_reconcile(
    database: Optional[Path] = typer.Option(None, "--database", "-d"),
    retry_quarantined: bool = typer.Option(
        False,
        "--retry-quarantined",
        help="Retry previously quarantined identities without bypassing proof.",
    ),
) -> None:
    """Reconcile expired supervisor-owned process groups before new work."""

    with _open_existing(database) as store:
        adapter = SQLiteSchedulerStorage(store)
        recovered_job_ids = tuple(
            adapter.reconcile_expired_processes(
                retry_quarantined=retry_quarantined
            )
        )
        pending = store.recover_expired_leases().get(
            "external_processes_pending", ()
        )
        violations = store.foreign_key_violations()

    table = Table(title="External process reconciliation")
    table.add_column("Attempt")
    table.add_column("PID", justify="right")
    table.add_column("PGID", justify="right")
    table.add_column("Outcome")
    table.add_column("Evidence / blocker")
    for result in adapter.last_reconciliation_results:
        table.add_row(
            result.binding.attempt_id,
            str(result.binding.process_id),
            str(result.binding.process_group_id),
            result.status.value,
            result.reason,
        )
    reconciled_attempts = {
        result.binding.attempt_id for result in adapter.last_reconciliation_results
    }
    for process in pending:
        if str(process["attempt_id"]) in reconciled_attempts:
            continue
        table.add_row(
            str(process["attempt_id"]),
            str(process["process_id"]),
            str(process["process_group_id"]),
            str(process["state"]),
            str(process.get("last_error") or "awaiting safe reconciliation"),
        )
    if not adapter.last_reconciliation_results and not pending:
        table.add_row("None", "-", "-", "clear", "No expired process binding")
    console.print(table)
    if recovered_job_ids:
        console.print("Recovered jobs: %s" % ", ".join(recovered_job_ids))
    if violations:
        console.print("Foreign-key violations: %d" % len(violations))
    if pending or violations:
        raise typer.Exit(code=1)


def _demo_evidence(kind: EvidenceKind, item_id: str, label: str) -> EvidenceRef:
    return EvidenceRef(
        kind=kind,
        location="/private/tmp/agent-flow-simulated/%s-%s.txt" % (item_id, label),
        description="Simulated Phase 1 %s evidence" % label,
        metadata={"simulated": True},
    )


def _demo_investigation(context: WorkerContext) -> InvestigationHandoff:
    return InvestigationHandoff(
        item_id=context.item_id,
        synopsis="Simulated defect reproduced and traced.",
        reproduction_steps=("Run the bounded Phase 1 fake workflow.",),
        root_cause="Simulated stale state in the bounded fixture.",
        proposed_fix="Apply the simulated surgical state correction.",
        acceptance_criteria=("All configured simulated gates pass.",),
        evidence=(_demo_evidence(EvidenceKind.LOG, context.item_id, "investigation"),),
    )


def _demo_fix(context: WorkerContext) -> FixHandoff:
    return FixHandoff(
        item_id=context.item_id,
        summary="Simulated surgical change prepared.",
        changed_files=("SIMULATED/worktree/change.py",),
        tests_run=("SIMULATED focused test",),
        tester_instructions=("Run all configured simulated gates.",),
        evidence=(_demo_evidence(EvidenceKind.TEST, context.item_id, "fix"),),
    )


def _demo_test(context: WorkerContext) -> TesterHandoff:
    gate_kind_to_evidence = {
        GateKind.FOCUSED_TESTS: EvidenceKind.TEST,
        GateKind.BROWSER: EvidenceKind.SCREENSHOT,
        GateKind.DATABASE: EvidenceKind.DATABASE,
        GateKind.GL: EvidenceKind.GL,
        GateKind.API: EvidenceKind.API,
        GateKind.EXPORT: EvidenceKind.EXPORT,
    }
    proofs = tuple(
        GateProof(
            gate=GateKind(gate),
            result=GateResult.PASS,
            summary="Simulated %s gate passed." % gate,
            evidence=(
                _demo_evidence(
                    gate_kind_to_evidence[GateKind(gate)],
                    context.item_id,
                    gate,
                ),
            ),
        )
        for gate in context.item["required_gates"]
    )
    return TesterHandoff(
        item_id=context.item_id,
        outcome=TestOutcome.PASS,
        summary="All configured simulated gates passed.",
        gate_proofs=proofs,
    )


@app.command("simulate")
def simulate(
    items: int = typer.Option(3, "--items", min=1, max=50),
    database: Optional[Path] = typer.Option(None, "--database", "-d"),
) -> None:
    """Run a clearly labeled fake production line through the real queue engine."""

    with SQLiteStore(_database_path(database)) as store:
        campaign = store.create_campaign(
            "Phase 1 simulated production line",
            config={
                "description": "No real agents, repositories, browser, or database writes.",
                "allow_simulated_evidence": True,
            },
            global_limit=4,
            role_limits={"investigator": 2, "fixer": 2, "tester": 2},
        )
        approval = store.create_approval(
            campaign["id"],
            LOCAL_WRITE_APPROVAL_ACTION,
            "phase1-simulator",
            scope={"simulated": True},
        )
        store.resolve_approval(approval["id"], "approved", "phase1-simulator")
        for number in range(1, items + 1):
            store.create_work_item(
                campaign["id"],
                "Simulated item %d" % number,
                description="Bounded fake item for scheduler validation.",
                initial_job={
                    "role": "investigator",
                    "stage": "investigator",
                    "active_item_state": "investigating",
                },
            )

        adapter = SQLiteSchedulerStorage(store)
        scheduler = Scheduler(
            adapter,
            {
                WorkerRole.INVESTIGATOR: (
                    ScriptedWorker(WorkerRole.INVESTIGATOR, default=_demo_investigation),
                    ScriptedWorker(WorkerRole.INVESTIGATOR, default=_demo_investigation),
                ),
                WorkerRole.FIXER: (
                    ScriptedWorker(WorkerRole.FIXER, default=_demo_fix),
                    ScriptedWorker(WorkerRole.FIXER, default=_demo_fix),
                ),
                WorkerRole.TESTER: (
                    ScriptedWorker(WorkerRole.TESTER, default=_demo_test),
                    ScriptedWorker(WorkerRole.TESTER, default=_demo_test),
                ),
            },
            global_concurrency_limit=4,
            allow_simulated_evidence=True,
        )
        asyncio.run(scheduler.run_until_quiescent())
        if scheduler.errors:
            raise typer.Exit(code=1)
        render_status(
            store.get_campaign(campaign["id"]),
            store.list_work_items(campaign["id"]),
            store.list_jobs(campaign_id=campaign["id"]),
            store.list_attempts(campaign_id=campaign["id"]),
            store.list_resource_leases(campaign_id=campaign["id"]),
            store.list_events(campaign_id=campaign["id"]),
            console=console,
        )
        console.print("Simulation campaign: %s" % campaign["id"])


def main() -> None:
    app()


if __name__ == "__main__":
    main()
