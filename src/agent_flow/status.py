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
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

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


def _timestamp_number(value: Any) -> float:
    parsed = _parse_timestamp(value)
    return 0.0 if parsed is None else parsed.timestamp()


def _short_id_map(values: Sequence[str], minimum: int = 8) -> Dict[str, str]:
    unique = sorted({value for value in values if value})
    labels: Dict[str, str] = {}
    for index, value in enumerate(unique):
        previous = unique[index - 1] if index else ""
        following = unique[index + 1] if index + 1 < len(unique) else ""
        shared = max(
            _common_prefix_length(value, previous),
            _common_prefix_length(value, following),
        )
        length = min(len(value), max(minimum, shared + 1))
        labels[value] = value[:length]
    return labels


def _common_prefix_length(left: str, right: str) -> int:
    length = 0
    for left_character, right_character in zip(left, right):
        if left_character != right_character:
            break
        length += 1
    return length


def _lease_label(value: Any, as_of: datetime) -> str:
    expiry = _parse_timestamp(value)
    if expiry is None:
        return "-"
    seconds = int((expiry - as_of).total_seconds())
    if seconds <= 0:
        return "Expired"
    return "%ds" % seconds


def _job_result_blocker(job: Optional[Record]) -> str:
    if job is None:
        return "-"
    result = _value(job, "result", None)
    if isinstance(result, Mapping):
        blocker = result.get("blocker")
        if isinstance(blocker, Mapping):
            summary = blocker.get("summary")
            if isinstance(summary, str) and summary.strip():
                return summary.strip()
    if _string_value(job, "status") == "completed":
        return "-"
    error = _string_value(job, "last_error", "-")
    if error != "-":
        return error
    return "-"


def _item_lane_table(
    items: Sequence[Record],
    jobs: Sequence[Record],
    attempts: Sequence[Record],
    worktrees: Sequence[Record],
    as_of: datetime,
    *,
    compact: bool = False,
) -> Table:
    item_ids = [_string_value(item, "id") for item in items]
    item_labels = _short_id_map(item_ids)
    attempt_labels = _short_id_map(
        [_string_value(attempt, "id") for attempt in attempts]
    )
    worktree_labels = _short_id_map(
        [_string_value(worktree, "id") for worktree in worktrees]
    )
    jobs_by_item: Dict[str, List[Record]] = {}
    for job in jobs:
        jobs_by_item.setdefault(_string_value(job, "item_id"), []).append(job)
    attempts_by_job: Dict[str, List[Record]] = {}
    for attempt in attempts:
        attempts_by_job.setdefault(_string_value(attempt, "job_id"), []).append(attempt)
    worktrees_by_item: Dict[str, List[Record]] = {}
    for worktree in worktrees:
        worktrees_by_item.setdefault(_string_value(worktree, "item_id"), []).append(
            worktree
        )

    table = Table(title="Pipeline lanes", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Item", no_wrap=True)
    table.add_column(
        "Title",
        no_wrap=True,
        overflow="ellipsis",
        max_width=24 if compact else 30,
    )
    table.add_column("State", no_wrap=compact, max_width=14 if compact else None)
    if compact:
        table.add_column("Lane\nstatus", no_wrap=True, max_width=14)
        table.add_column("Owner\nlease", no_wrap=True, max_width=16)
        table.add_column("Context")
    else:
        table.add_column("Lane")
        table.add_column("Queue / run")
        table.add_column("Lease")
        table.add_column("Worker / attempt")
        table.add_column("Worktree")
        table.add_column("Blocker")
    for item in items:
        item_id = _string_value(item, "id")
        item_jobs = jobs_by_item.get(item_id, [])
        open_jobs = [
            job
            for job in item_jobs
            if _string_value(job, "status") in ("pending", "leased", "running")
        ]
        open_job_count = int(_value(item, "open_job_count", len(open_jobs)) or 0)
        ambiguous = open_job_count > 1
        job: Optional[Record] = None
        if len(open_jobs) == 1:
            job = open_jobs[0]
        elif not ambiguous and item_jobs:
            job = max(
                item_jobs,
                key=lambda candidate: (
                    _timestamp_number(_value(candidate, "updated_at", None)),
                    _timestamp_number(_value(candidate, "created_at", None)),
                    _string_value(candidate, "id"),
                ),
            )

        attempt: Optional[Record] = None
        if job is not None:
            current_attempt_id = _string_value(job, "current_attempt_id")
            candidates = attempts_by_job.get(_string_value(job, "id"), [])
            attempt = next(
                (
                    candidate
                    for candidate in candidates
                    if _string_value(candidate, "id") == current_attempt_id
                ),
                None,
            )
            if attempt is None and candidates:
                attempt = max(
                    candidates,
                    key=lambda candidate: (
                        int(_value(candidate, "attempt_number", 0) or 0),
                        _timestamp_number(_value(candidate, "started_at", None)),
                    ),
                )

        item_worktrees = worktrees_by_item.get(item_id, [])
        worktree = None
        if item_worktrees:
            worktree = max(
                item_worktrees,
                key=lambda candidate: (
                    int(_value(candidate, "generation", 0) or 0),
                    _timestamp_number(_value(candidate, "created_at", None)),
                ),
            )

        lane = "-" if job is None else _label(_string_value(job, "role", "unknown"))
        activity = "-" if job is None else _label(_string_value(job, "status", "unknown"))
        lease = "-"
        worker = "-"
        attempt_label = "-"
        worker_attempt = "-"
        blocker = _job_result_blocker(job)
        if ambiguous:
            lane = "AMBIGUOUS"
            activity = "AMBIGUOUS"
            blocker = "%d open jobs require storage reconciliation" % open_job_count
        elif job is not None:
            job_status = _string_value(job, "status")
            if job_status == "pending":
                activity = "Queued"
            elif job_status in ("leased", "running"):
                activity = "Active"
                lease = _lease_label(_value(job, "lease_expires_at", None), as_of)
                if lease == "Expired":
                    activity = "Expired"
            worker = _string_value(job, "lease_owner", "-")
            if worker == "-" and attempt is not None:
                worker = _string_value(attempt, "worker_id", "-")
            if attempt is not None:
                attempt_id = _string_value(attempt, "id")
                attempt_label = attempt_labels.get(attempt_id, attempt_id)
            worker_attempt = "%s / %s" % (worker, attempt_label)

        worktree_label = "-"
        if worktree is not None:
            worktree_id = _string_value(worktree, "id")
            worktree_label = "%s / %s" % (
                worktree_labels.get(worktree_id, worktree_id),
                _label(_string_value(worktree, "state", "unknown")),
            )
            if blocker == "-":
                blocker = _string_value(worktree, "last_error", "-")
        common = (
            item_labels.get(item_id, item_id or "-"),
            _string_value(item, "title", "-"),
            _label(_string_value(item, "state", "unknown")),
        )
        if compact:
            context = []
            if attempt_label != "-":
                context.append("attempt %s" % attempt_label)
            if worktree_label != "-":
                context.append("worktree %s" % worktree_label)
            if blocker != "-":
                context.append(blocker)
            table.add_row(
                *common,
                "%s\n%s" % (lane, activity),
                "%s\n%s" % (worker, lease),
                "; ".join(context) or "-",
            )
        else:
            table.add_row(
                *common,
                lane,
                activity,
                lease,
                worker_attempt,
                worktree_label,
                blocker,
            )
    if not items:
        empty_columns = 6 if compact else 9
        table.add_row("None", *("-" for _column in range(empty_columns - 1)))
    return table


def _alert_table(
    items: Sequence[Record],
    jobs: Sequence[Record],
    attempts: Sequence[Record],
    worktrees: Sequence[Record],
    operations: Sequence[Record],
    as_of: datetime,
    *,
    limit: int = 10,
    omitted_item_count: int = 0,
    omitted_alert_item_count: int = 0,
    omitted_open_job_count: int = 0,
) -> Table:
    jobs_by_item: Dict[str, List[Record]] = {}
    for job in jobs:
        jobs_by_item.setdefault(_string_value(job, "item_id"), []).append(job)
    alerts: List[Tuple[int, str, str]] = []
    for item in items:
        item_id = _string_value(item, "id")
        item_jobs = jobs_by_item.get(item_id, [])
        visible_open_job_count = sum(
            1
            for job in item_jobs
            if _string_value(job, "status") in ("pending", "leased", "running")
        )
        open_job_count = int(
            _value(item, "open_job_count", visible_open_job_count) or 0
        )
        if open_job_count > 1:
            alerts.append(
                (
                    2,
                    item_id,
                    "%d open jobs require storage reconciliation"
                    % open_job_count,
                )
            )
        process_alert_count = int(
            _value(item, "process_alert_count", 0) or 0
        )
        if process_alert_count > 1:
            alerts.append(
                (
                    0,
                    item_id,
                    "%d external process identity alerts; one representative "
                    "process is shown" % process_alert_count,
                )
            )
        if _string_value(item, "state") == "blocked":
            job = None
            if item_jobs:
                job = max(
                    item_jobs,
                    key=lambda candidate: (
                        _timestamp_number(_value(candidate, "updated_at", None)),
                        _timestamp_number(_value(candidate, "created_at", None)),
                        _string_value(candidate, "id"),
                    ),
                )
            reason = _job_result_blocker(job)
            message = "Persisted item state is Blocked"
            if reason != "-":
                message += ": %s" % reason
            alerts.append((3, item_id, message))
    for job in jobs:
        if _string_value(job, "status") in ("leased", "running") and _lease_label(
            _value(job, "lease_expires_at", None), as_of
        ) == "Expired":
            alerts.append(
                (
                    1,
                    _string_value(job, "id"),
                    "%s job lease expired and remains unrecovered"
                    % _label(_string_value(job, "role", "unknown")),
                )
            )
    for attempt in attempts:
        process_state = _string_value(attempt, "external_process_state")
        if process_state in ("quarantined", "legacy_unverifiable"):
            alerts.append(
                (
                    0,
                    _string_value(attempt, "id"),
                    "External process is %s: %s"
                    % (
                        _label(process_state),
                        _string_value(attempt, "external_process_last_error", "-"),
                    ),
                )
            )
    for worktree in worktrees:
        if _string_value(worktree, "state") == "quarantined":
            alerts.append(
                (
                    0,
                    _string_value(worktree, "id"),
                    "Worktree is quarantined: %s"
                    % _string_value(worktree, "last_error", "reason unavailable"),
                )
            )
    for operation in operations:
        if _string_value(operation, "status") == "quarantined":
            alerts.append(
                (
                    0,
                    _string_value(operation, "id"),
                    "Worktree operation is quarantined: %s"
                    % _string_value(operation, "error", "reason unavailable"),
                )
            )

    table = Table(title="Operator alerts", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Record", no_wrap=True)
    table.add_column("Alert")
    if omitted_item_count:
        alert_notice = ""
        if omitted_alert_item_count:
            alert_notice = (
                " %d omitted item rows have persisted alerts."
                % omitted_alert_item_count
            )
        else:
            alert_notice = " All persisted alert-bearing item rows are included."
        table.add_row(
            "DETAIL LIMIT",
            "%d item rows are omitted; aggregate totals remain exact. "
            "Increase --item-limit to inspect additional rows.%s"
            % (omitted_item_count, alert_notice),
        )
    if omitted_open_job_count:
        table.add_row(
            "RECORD LIMIT",
            "%d additional open job records are summarized by exact "
            "per-item ambiguity counts." % omitted_open_job_count,
        )
    alerts.sort(key=lambda alert: (alert[0], alert[1], alert[2]))
    record_labels = _short_id_map(
        [record for _severity, record, _message in alerts]
    )
    for _severity, record, message in alerts[:limit]:
        table.add_row(record_labels.get(record, record) or "-", message)
    if len(alerts) > limit:
        table.add_row("...", "%d additional alerts" % (len(alerts) - limit))
    if not alerts and not omitted_item_count:
        table.add_row("None", "No persisted blockers or expired leases")
    return table


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


def _item_state_summary(
    items: Sequence[Record],
    *,
    exact_counts: Optional[Mapping[str, int]] = None,
    total_items: Optional[int] = None,
) -> Table:
    counts = Counter(_string_value(item, "state", "unknown") for item in items)
    if exact_counts is not None:
        counts = Counter(
            {str(state): int(count) for state, count in exact_counts.items()}
        )
    total = len(items) if total_items is None else total_items
    cells = [
        "%s %d" % (_label(state), counts[state])
        for state in _ITEM_STATE_ORDER
    ]
    table = Table(
        title="Pipeline totals (%d %s)"
        % (total, "item" if total == 1 else "items"),
        box=box.SIMPLE,
        expand=True,
        show_header=False,
    )
    for _column in range(4):
        table.add_column()
    table.add_row(*cells[:4])
    table.add_row(*cells[4:])
    return table


def _worker_table(
    campaign: Record,
    jobs: Sequence[Record],
    as_of: datetime,
    *,
    exact_counts: Optional[Mapping[str, Mapping[str, int]]] = None,
) -> Table:
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
    if exact_counts is not None:
        queued = Counter(
            {
                str(role): int(counts.get("queued", 0))
                for role, counts in exact_counts.items()
            }
        )
        active = Counter(
            {
                str(role): int(counts.get("active", 0))
                for role, counts in exact_counts.items()
            }
        )
        expired = Counter(
            {
                str(role): int(counts.get("expired", 0))
                for role, counts in exact_counts.items()
            }
        )

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
        provider = _value(attempt, "external_provider", None) or _value(
            attempt, "external_process_provider", "-"
        )
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
            str(provider),
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


def build_watch_board(
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
    refresh_seconds: float = 1.0,
    stale_error: Optional[str] = None,
    compact: bool = False,
    item_state_counts: Optional[Mapping[str, int]] = None,
    worker_counts: Optional[Mapping[str, Mapping[str, int]]] = None,
    total_items: Optional[int] = None,
    omitted_item_count: int = 0,
    omitted_alert_item_count: int = 0,
    omitted_open_job_count: int = 0,
) -> Group:
    """Build the compact, read-only live monitor from one persisted snapshot."""

    if event_limit < 0:
        raise ValueError("event_limit must be non-negative")
    if refresh_seconds <= 0:
        raise ValueError("refresh_seconds must be positive")
    reference_time = as_of or datetime.now(timezone.utc)
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=timezone.utc)
    else:
        reference_time = reference_time.astimezone(timezone.utc)
    state = "STALE - %s" % stale_error if stale_error else "READ-ONLY LIVE MONITOR"
    state_style = "bold red" if stale_error else "bold cyan"
    heading = Text("Agent Flow - %s" % state, style=state_style)
    footer = Text(
        "Updated %s UTC | refresh %.1fs | Ctrl+C to stop"
        % (reference_time.strftime("%H:%M:%S"), refresh_seconds),
        style="dim",
    )
    return Group(
        heading,
        _campaign_table(campaign),
        _item_state_summary(
            items,
            exact_counts=item_state_counts,
            total_items=total_items,
        ),
        _worker_table(
            campaign,
            jobs,
            reference_time,
            exact_counts=worker_counts,
        ),
        _item_lane_table(
            items,
            jobs,
            attempts,
            managed_worktrees,
            reference_time,
            compact=compact,
        ),
        _alert_table(
            items,
            jobs,
            attempts,
            managed_worktrees,
            worktree_operations,
            reference_time,
            omitted_item_count=omitted_item_count,
            omitted_alert_item_count=omitted_alert_item_count,
            omitted_open_job_count=omitted_open_job_count,
        ),
        _external_session_table(attempts, reference_time),
        _active_resource_table(resource_leases, reference_time),
        _event_table(events, event_limit),
        footer,
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
