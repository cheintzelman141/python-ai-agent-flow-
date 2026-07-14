"""Read-only Rich status rendering for persisted Agent Flow snapshots.

This module deliberately knows nothing about SQLite or Typer.  Callers supply
plain persisted dictionaries, making the status board usable by the CLI,
tests, or a future UI adapter without giving presentation code access to the
workflow engine.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Optional, Sequence, Tuple

from rich import box
from rich.console import Console, Group
from rich.table import Table
from rich.text import Text


Record = Mapping[str, Any]

_ITEM_STATE_ORDER = (
    "backlog",
    "investigating",
    "ready_for_fix",
    "fixing",
    "ready_for_test",
    "testing",
    "verified_green",
    "blocked",
)
_ROLE_ORDER = ("investigator", "fixer", "tester")
_ACTIVE_JOB_STATUSES = frozenset(("leased", "running"))
_ATTEMPT_STATUS_ORDER = (
    "running",
    "expired_unrecovered",
    "succeeded",
    "failed",
    "expired",
    "interrupted",
)
_WORKTREE_STATE_ORDER = (
    "provisioning",
    "ready",
    "cleanup_pending",
    "quarantined",
    "removed",
)


def _value(record: Record, key: str, default: Any = "") -> Any:
    value = record.get(key, default)
    if isinstance(value, Enum):
        return value.value
    return value


def _string_value(record: Record, key: str, default: str = "") -> str:
    value = _value(record, key, default)
    return default if value is None else str(value)


def _label(value: str) -> str:
    return value.replace("_", " ").title()


def _ordered_values(counter: Counter[str], preferred: Tuple[str, ...]) -> Tuple[str, ...]:
    extras = tuple(sorted(value for value in counter if value not in preferred))
    return preferred + extras


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _timestamp_label(value: Any) -> str:
    parsed = _parse_timestamp(value)
    if parsed is None:
        return "-" if value is None else str(value)
    return parsed.isoformat(timespec="seconds")


def _campaign_table(campaign: Record) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column()
    table.add_row("Campaign", _string_value(campaign, "name", "Unnamed campaign"))
    table.add_row("ID", _string_value(campaign, "id", "-"))
    table.add_row("Status", _label(_string_value(campaign, "status", "unknown")))
    table.add_row(
        "Global concurrency",
        _string_value(campaign, "global_concurrency_limit", "-"),
    )
    return table


def _item_state_table(items: Sequence[Record]) -> Table:
    counts = Counter(_string_value(item, "state", "unknown") for item in items)
    table = Table(title="Item states", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("State")
    table.add_column("Count", justify="right")
    for state in _ordered_values(counts, _ITEM_STATE_ORDER):
        table.add_row(_label(state), str(counts[state]))
    table.add_section()
    table.add_row("Total", str(len(items)), style="bold")
    return table


def _worker_table(campaign: Record, jobs: Sequence[Record], as_of: datetime) -> Table:
    queued: Counter[str] = Counter()
    active: Counter[str] = Counter()
    expired: Counter[str] = Counter()
    for job in jobs:
        role = _string_value(job, "role", "unknown")
        status = _string_value(job, "status", "unknown")
        if status == "pending":
            queued[role] += 1
        elif status in _ACTIVE_JOB_STATUSES:
            lease_expiry = _parse_timestamp(
                _value(job, "lease_expires_at", None)
            )
            if lease_expiry is not None and lease_expiry <= as_of:
                expired[role] += 1
            else:
                active[role] += 1

    configured_limits = _value(campaign, "role_concurrency_limits", {})
    normalized_limits = {}
    if isinstance(configured_limits, Mapping):
        normalized_limits = {
            (key.value if isinstance(key, Enum) else str(key)): value
            for key, value in configured_limits.items()
        }

    all_roles = Counter({**queued, **active, **expired})
    table = Table(title="Worker queues", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Role")
    table.add_column("Queued", justify="right")
    table.add_column("Active", justify="right")
    table.add_column("Expired", justify="right")
    table.add_column("Limit", justify="right")
    for role in _ordered_values(all_roles, _ROLE_ORDER):
        limit = normalized_limits.get(role, "-")
        table.add_row(
            _label(role),
            str(queued[role]),
            str(active[role]),
            str(expired[role]),
            str(limit),
        )
    table.add_section()
    table.add_row(
        "Total",
        str(sum(queued.values())),
        str(sum(active.values())),
        str(sum(expired.values())),
        "",
        style="bold",
    )
    return table


def _attempt_table(attempts: Sequence[Record], as_of: datetime) -> Table:
    counts: Counter[str] = Counter()
    for attempt in attempts:
        status = _string_value(attempt, "status", "unknown")
        lease_expiry = _parse_timestamp(
            _value(attempt, "lease_expires_at", None)
        )
        if status == "running" and lease_expiry is not None and lease_expiry <= as_of:
            status = "expired_unrecovered"
        counts[status] += 1
    table = Table(title="Attempts", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Status")
    table.add_column("Count", justify="right")
    for status in _ordered_values(counts, _ATTEMPT_STATUS_ORDER):
        table.add_row(_label(status), str(counts[status]))
    table.add_section()
    table.add_row("Total", str(len(attempts)), style="bold")
    return table


def _external_session_table(attempts: Sequence[Record], as_of: datetime) -> Table:
    external_attempts = [
        attempt
        for attempt in attempts
        if _value(attempt, "external_session_id", None) is not None
        or _value(attempt, "external_process_id", None) is not None
    ]
    table = Table(title="External worker sessions", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Attempt")
    table.add_column("Provider")
    table.add_column("Session")
    table.add_column("PID / PGID", justify="right")
    table.add_column("Lifecycle")
    for attempt in external_attempts:
        attempt_state = _string_value(attempt, "status", "unknown")
        lease_expiry = _parse_timestamp(
            _value(attempt, "lease_expires_at", None)
        )
        if (
            attempt_state == "running"
            and lease_expiry is not None
            and lease_expiry <= as_of
        ):
            attempt_state = "expired_unrecovered"
        process_state = _string_value(
            attempt, "external_process_state", "unknown"
        )
        table.add_row(
            _string_value(attempt, "id", "-"),
            _string_value(attempt, "external_provider", "-"),
            _string_value(attempt, "external_session_id", "-"),
            "%s / %s"
            % (
                _string_value(attempt, "external_process_id", "-"),
                _string_value(attempt, "external_process_group_id", "-"),
            ),
            "%s / %s" % (_label(attempt_state), _label(process_state)),
        )
    if not external_attempts:
        table.add_row("None", "-", "-", "-", "-")
    return table


def _active_resource_table(resource_leases: Sequence[Record], as_of: datetime) -> Table:
    ordered_leases = list(resource_leases)
    ordered_leases.sort(
        key=lambda lease: (
            _string_value(lease, "resource_key"),
            _string_value(lease, "job_id"),
        )
    )

    table = Table(title="Resource leases", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Resource")
    table.add_column("Owner")
    table.add_column("Job")
    table.add_column("State")
    table.add_column("Expires")
    for lease in ordered_leases:
        expires_at = _parse_timestamp(_value(lease, "lease_expires_at", None))
        expired = expires_at is not None and expires_at <= as_of
        state = "Active"
        if expired and _value(lease, "job_id", None) is not None:
            state = "Expired - held"
        elif expired:
            state = "Expired"
        table.add_row(
            _string_value(lease, "resource_key", "-"),
            _string_value(lease, "lease_owner", "-"),
            _string_value(lease, "job_id", "-"),
            state,
            _timestamp_label(_value(lease, "lease_expires_at", None)),
        )
    if not ordered_leases:
        table.add_row("None", "-", "-", "-", "-")
    return table


def _managed_worktree_table(worktrees: Sequence[Record]) -> Table:
    ordered = sorted(
        worktrees,
        key=lambda worktree: (
            _WORKTREE_STATE_ORDER.index(_string_value(worktree, "state"))
            if _string_value(worktree, "state") in _WORKTREE_STATE_ORDER
            else len(_WORKTREE_STATE_ORDER),
            _string_value(worktree, "item_id"),
            _string_value(worktree, "id"),
        ),
    )
    table = Table(title="Managed worktrees", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Worktree")
    table.add_column("Item")
    table.add_column("State")
    table.add_column("Branch / base")
    table.add_column("Path")
    table.add_column("Blocker")
    for worktree in ordered:
        branch = _string_value(worktree, "branch_ref", "-")
        if branch.startswith("refs/heads/"):
            branch = branch[len("refs/heads/") :]
        base = _string_value(worktree, "base_revision", "-")
        table.add_row(
            _string_value(worktree, "id", "-"),
            _string_value(worktree, "item_id", "-"),
            _label(_string_value(worktree, "state", "unknown")),
            "%s / %s" % (branch, base[:12]),
            _string_value(worktree, "worktree_path", "-"),
            _string_value(worktree, "last_error", "-"),
        )
    if not ordered:
        table.add_row("None", "-", "-", "-", "-", "-")
    return table


def _worktree_operation_table(operations: Sequence[Record]) -> Table:
    ordered = sorted(
        operations,
        key=lambda operation: (
            _string_value(operation, "started_at"),
            int(_value(operation, "operation_number", 0) or 0),
            _string_value(operation, "id"),
        ),
    )
    table = Table(
        title="Worktree lifecycle operations", box=box.SIMPLE_HEAVY, expand=True
    )
    table.add_column("Operation")
    table.add_column("Worktree")
    table.add_column("Kind")
    table.add_column("Status")
    table.add_column("Process")
    table.add_column("Reconciliation")
    table.add_column("Evidence / blocker")
    for operation in ordered:
        process = "-"
        if _value(operation, "process_id", None) is not None:
            process = "%s / %s" % (
                _string_value(operation, "process_id", "-"),
                _label(_string_value(operation, "process_state", "unknown")),
            )
        reconciliation = _string_value(
            operation, "reconciliation_owner", "-"
        )
        evidence = _string_value(operation, "error", "-")
        if evidence == "-" and _value(operation, "stdout_sha256", None) is not None:
            evidence = "stdout %s; stderr %s" % (
                _string_value(operation, "stdout_sha256")[:12],
                _string_value(operation, "stderr_sha256")[:12],
            )
        table.add_row(
            _string_value(operation, "id", "-"),
            _string_value(operation, "managed_worktree_id", "-"),
            _label(_string_value(operation, "kind", "unknown")),
            _label(_string_value(operation, "status", "unknown")),
            process,
            reconciliation,
            evidence,
        )
    if not ordered:
        table.add_row("None", "-", "-", "-", "-", "-", "-")
    return table


def _event_table(events: Sequence[Record], event_limit: int) -> Table:
    ordered = sorted(
        events,
        key=lambda event: (
            int(_value(event, "sequence", 0) or 0),
            _string_value(event, "created_at"),
            _string_value(event, "id"),
        ),
        reverse=True,
    )[:event_limit]
    table = Table(title="Recent events", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Time")
    table.add_column("Item")
    table.add_column("Event")
    table.add_column("Transition")
    for event in ordered:
        from_state = _string_value(event, "from_state")
        to_state = _string_value(event, "to_state")
        transition = "-"
        if from_state or to_state:
            transition = f"{from_state or '-'} -> {to_state or '-'}"
        table.add_row(
            _timestamp_label(_value(event, "created_at", None)),
            _string_value(event, "item_id", "-"),
            _string_value(event, "event_type", "-"),
            transition,
        )
    if not ordered:
        table.add_row("-", "-", "No events", "-")
    return table


def build_status_board(
    campaign: Record,
    items: Sequence[Record],
    jobs: Sequence[Record],
    attempts: Sequence[Record],
    resource_leases: Sequence[Record],
    events: Sequence[Record],
    *,
    managed_worktrees: Sequence[Record] = (),
    worktree_operations: Sequence[Record] = (),
    as_of: Optional[datetime] = None,
    event_limit: int = 5,
) -> Group:
    """Build a Rich renderable from immutable-style persisted snapshots.

    The function only reads its arguments.  ``as_of`` controls resource-expiry
    filtering and can be injected by callers that require deterministic output.
    """

    if event_limit < 0:
        raise ValueError("event_limit must be non-negative")
    reference_time = as_of or datetime.now(timezone.utc)
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=timezone.utc)
    else:
        reference_time = reference_time.astimezone(timezone.utc)

    heading = Text("Agent Flow status", style="bold")
    return Group(
        heading,
        _campaign_table(campaign),
        _item_state_table(items),
        _worker_table(campaign, jobs, reference_time),
        _attempt_table(attempts, reference_time),
        _external_session_table(attempts, reference_time),
        _managed_worktree_table(managed_worktrees),
        _worktree_operation_table(worktree_operations),
        _active_resource_table(resource_leases, reference_time),
        _event_table(events, event_limit),
    )


def render_status(
    campaign: Record,
    items: Sequence[Record],
    jobs: Sequence[Record],
    attempts: Sequence[Record],
    resource_leases: Sequence[Record],
    events: Sequence[Record],
    *,
    managed_worktrees: Sequence[Record] = (),
    worktree_operations: Sequence[Record] = (),
    console: Optional[Console] = None,
    as_of: Optional[datetime] = None,
    event_limit: int = 5,
) -> None:
    """Print :func:`build_status_board` to a supplied or default Rich console."""

    target = console or Console()
    target.print(
        build_status_board(
            campaign,
            items,
            jobs,
            attempts,
            resource_leases,
            events,
            managed_worktrees=managed_worktrees,
            worktree_operations=worktree_operations,
            as_of=as_of,
            event_limit=event_limit,
        )
    )
