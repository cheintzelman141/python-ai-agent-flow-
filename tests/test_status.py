import re
from copy import deepcopy
from datetime import datetime, timezone
from io import StringIO

from rich.console import Console

from agent_flow.status import _short_id_map, build_watch_board, render_status


AS_OF = datetime(2026, 7, 14, 16, 0, tzinfo=timezone.utc)


def snapshots():
    campaign = {
        "id": "campaign-1",
        "name": "Phase 1",
        "status": "active",
        "global_concurrency_limit": 4,
        "role_concurrency_limits": {"investigator": 2, "fixer": 2, "tester": 1},
    }
    items = [
        {"id": "item-1", "state": "backlog"},
        {"id": "item-2", "state": "fixing"},
        {"id": "item-3", "state": "testing"},
        {"id": "item-4", "state": "verified_green"},
    ]
    jobs = [
        {"id": "job-1", "role": "investigator", "status": "pending"},
        {"id": "job-2", "role": "fixer", "status": "running"},
        {"id": "job-3", "role": "fixer", "status": "pending"},
        {"id": "job-4", "role": "tester", "status": "leased"},
        {"id": "job-5", "role": "tester", "status": "completed"},
    ]
    attempts = [
        {"id": "attempt-1", "status": "running"},
        {"id": "attempt-2", "status": "succeeded"},
        {"id": "attempt-3", "status": "failed"},
    ]
    leases = [
        {
            "resource_key": "chrome:profile-1",
            "job_id": "job-4",
            "lease_owner": "tester-1",
            "lease_expires_at": "2026-07-14T16:05:00+00:00",
        },
        {
            "resource_key": "tenant:expired",
            "job_id": "job-old",
            "lease_owner": "tester-old",
            "lease_expires_at": "2026-07-14T15:55:00+00:00",
        },
    ]
    events = [
        {
            "id": "event-1",
            "item_id": "item-2",
            "event_type": "job_claimed",
            "from_state": "ready_for_fix",
            "to_state": "fixing",
            "created_at": "2026-07-14T15:59:00+00:00",
        }
    ]
    return campaign, items, jobs, attempts, leases, events


def render(snapshots_value) -> str:
    output = StringIO()
    console = Console(
        file=output,
        width=120,
        color_system=None,
        force_terminal=False,
    )
    render_status(*snapshots_value, console=console, as_of=AS_OF)
    return output.getvalue()


def render_watch(
    snapshots_value,
    *,
    width: int = 120,
    worktrees=(),
    operations=(),
    stale_error=None,
) -> str:
    output = StringIO()
    console = Console(
        file=output,
        width=width,
        color_system=None,
        force_terminal=False,
    )
    console.print(
        build_watch_board(
            *snapshots_value[:6],
            managed_worktrees=worktrees,
            worktree_operations=operations,
            as_of=AS_OF,
            event_limit=8,
            refresh_seconds=1.0,
            stale_error=stale_error,
            compact=width < 110,
        )
    )
    return output.getvalue()


def test_status_renders_campaign_counts_attempts_resources_and_events() -> None:
    text = render(snapshots())
    item_section = text[text.index("Item states") : text.index("Worker queues")]
    attempt_section = text[
        text.index("Attempts") : text.index("External worker sessions")
    ]

    assert "Agent Flow status" in text
    assert "Phase 1" in text
    assert "campaign-1" in text
    assert "Global concurrency" in text
    assert re.search(r"Backlog\s+1", item_section)
    assert re.search(r"Fixing\s+1", item_section)
    assert re.search(r"Testing\s+1", item_section)
    assert re.search(r"Verified Green\s+1", item_section)
    assert re.search(r"Total\s+4", item_section)
    assert "Worker queues" in text
    assert "Investigator" in text
    assert "Fixer" in text
    assert "Tester" in text
    assert re.search(r"Running\s+1", attempt_section)
    assert re.search(r"Succeeded\s+1", attempt_section)
    assert re.search(r"Failed\s+1", attempt_section)
    assert re.search(r"Total\s+3", attempt_section)
    assert "Resource leases" in text
    assert "chrome:profile-1" in text
    assert "tenant:expired" in text
    assert "Expired - held" in text
    assert "Recent events" in text
    assert "job_claimed" in text
    assert "ready_for_fix -> fixing" in text


def test_status_reports_per_role_queued_and_active_counts() -> None:
    text = render(snapshots())
    worker_section = text[text.index("Worker queues") : text.index("Attempts")]

    assert re.search(r"Investigator\s+1\s+0\s+0\s+2", worker_section)
    assert re.search(r"Fixer\s+1\s+1\s+0\s+2", worker_section)
    assert re.search(r"Tester\s+0\s+1\s+0\s+1", worker_section)
    assert re.search(r"Total\s+2\s+2\s+0", worker_section)


def test_status_does_not_report_expired_unrecovered_work_as_active() -> None:
    data = list(snapshots())
    data[2].append(
        {
            "id": "job-expired",
            "role": "investigator",
            "status": "running",
            "lease_expires_at": "2026-07-14T15:59:00+00:00",
        }
    )
    data[3].append(
        {
            "id": "attempt-expired",
            "status": "running",
            "lease_expires_at": "2026-07-14T15:59:00+00:00",
        }
    )

    text = render(tuple(data))
    worker_section = text[text.index("Worker queues") : text.index("Attempts")]
    attempt_section = text[
        text.index("Attempts") : text.index("External worker sessions")
    ]

    assert re.search(r"Investigator\s+1\s+0\s+1\s+2", worker_section)
    assert re.search(r"Expired Unrecovered\s+1", attempt_section)


def test_status_displays_external_session_and_quarantined_process() -> None:
    data = list(snapshots())
    data[3].append(
        {
            "id": "attempt-codex",
            "status": "running",
            "lease_expires_at": "2026-07-14T15:59:00+00:00",
            "external_provider": "codex",
            "external_session_id": "019f6677-aaaa-7bbb-8ccc-999999999999",
            "external_process_id": 43210,
            "external_process_group_id": 43210,
            "external_process_state": "quarantined",
        }
    )

    text = render(tuple(data))
    section = text[
        text.index("External worker sessions") : text.index("Resource leases")
    ]

    assert "attempt-codex" in section
    assert "codex" in section
    assert "019f6677-aaaa-7bbb-8ccc-999999999999" in section
    assert "43210" in section
    assert "Expired Unrecovered" in section
    assert "Quarantined" in section


def test_status_uses_process_provider_when_worker_has_no_session() -> None:
    data = list(snapshots())
    data[3].append(
        {
            "id": "attempt-focused-test",
            "status": "succeeded",
            "external_process_provider": "focused_test",
            "external_process_id": 43211,
            "external_process_group_id": 43211,
            "external_process_state": "stopped",
        }
    )

    text = render(tuple(data))
    section = text[
        text.index("External worker sessions") : text.index("Resource leases")
    ]

    assert "attempt-focused-test" in section
    assert "focused_test" in section
    assert "43211" in section


def test_watch_board_renders_live_lanes_alerts_and_collision_safe_ids() -> None:
    campaign, _items, _jobs, _attempts, leases, events = snapshots()
    items = [
        {
            "id": "12345678aaaa",
            "title": "Queued fix",
            "state": "ready_for_fix",
        },
        {
            "id": "12345678bbbb",
            "title": "Active test",
            "state": "testing",
        },
        {"id": "blocked-item", "title": "Blocked item", "state": "blocked"},
    ]
    jobs = [
        {
            "id": "fix-job",
            "item_id": "12345678aaaa",
            "role": "fixer",
            "status": "pending",
            "created_at": 1,
            "updated_at": 1,
        },
        {
            "id": "test-job",
            "item_id": "12345678bbbb",
            "role": "tester",
            "status": "running",
            "lease_owner": "tester-1",
            "lease_expires_at": "2026-07-14T16:00:42+00:00",
            "current_attempt_id": "attempt-running",
            "created_at": 2,
            "updated_at": 2,
        },
        {
            "id": "blocked-job",
            "item_id": "blocked-item",
            "role": "investigator",
            "status": "completed",
            "result": {"blocker": {"summary": "Product decision required."}},
            "created_at": 3,
            "updated_at": 3,
        },
    ]
    attempts = [
        {
            "id": "attempt-running",
            "job_id": "test-job",
            "attempt_number": 1,
            "worker_id": "tester-1",
            "status": "running",
        }
    ]
    worktrees = [
        {
            "id": "worktree-one",
            "item_id": "12345678aaaa",
            "state": "ready",
            "generation": 1,
        }
    ]
    operations = [
        {
            "id": "operation-quarantined",
            "status": "quarantined",
            "error": "identity mismatch",
        }
    ]
    data = (campaign, items, jobs, attempts, leases, events)
    before = deepcopy(data)

    text = render_watch(data, worktrees=worktrees, operations=operations)
    narrow = render_watch(data, width=80, worktrees=worktrees, operations=operations)
    normalized = re.sub(r"\s+", " ", text)

    assert "READ-ONLY LIVE MONITOR" in text
    assert "Pipeline lanes" in text
    assert "12345678a" in text
    assert "12345678b" in text
    assert "Queued" in text
    assert "tester-1" in text
    assert "42s" in text
    assert "Product decision required." in normalized
    assert "Worktree operation is quarantined: identity mismatch" in normalized
    assert "Ctrl+C to stop" in text
    assert "Pipeline" in narrow
    assert data == before


def test_watch_board_fails_closed_on_ambiguous_open_jobs_and_marks_stale() -> None:
    campaign, _items, _jobs, attempts, leases, events = snapshots()
    items = [{"id": "item-ambiguous", "title": "Ambiguous", "state": "testing"}]
    jobs = [
        {
            "id": "job-a",
            "item_id": "item-ambiguous",
            "role": "fixer",
            "status": "pending",
        },
        {
            "id": "job-b",
            "item_id": "item-ambiguous",
            "role": "tester",
            "status": "running",
        },
    ]

    text = render_watch(
        (campaign, items, jobs, attempts, leases, events),
        stale_error="database is busy",
    )
    normalized = re.sub(r"\s+", " ", text)

    assert "STALE - database is busy" in text
    assert "AMBIGUOUS" in text
    assert "2 open jobs require storage reconciliation" in normalized


def test_watch_board_does_not_render_stale_retry_errors_as_current_blockers() -> None:
    campaign, _items, _jobs, attempts, leases, events = snapshots()
    items = [
        {
            "id": "item-blocked",
            "title": "Current blocker",
            "state": "blocked",
        },
        {
            "id": "item-ready",
            "title": "Successful retry",
            "state": "ready_for_fix",
        },
    ]
    jobs = [
        {
            "id": "job-blocked",
            "item_id": "item-blocked",
            "role": "investigator",
            "status": "completed",
            "last_error": "stale blocked retry error",
            "result": {
                "blocker": {"summary": "Current product decision blocker."}
            },
        },
        {
            "id": "job-ready",
            "item_id": "item-ready",
            "role": "investigator",
            "status": "completed",
            "last_error": "stale successful retry error",
            "result": {"outcome": "ready_for_fix"},
        },
    ]

    text = render_watch((campaign, items, jobs, attempts, leases, events))
    normalized = re.sub(r"\s+", " ", text)

    assert "Current product decision blocker." in normalized
    assert "stale blocked retry error" not in normalized
    assert "stale successful retry error" not in normalized


def test_watch_board_prioritizes_quarantine_over_many_blocked_items() -> None:
    campaign, _items, _jobs, _attempts, leases, events = snapshots()
    items = [
        {
            "id": "blocked-%02d" % number,
            "title": "Blocked %02d" % number,
            "state": "blocked",
        }
        for number in range(12)
    ]
    attempts = [
        {
            "id": "attempt-quarantined",
            "status": "running",
            "external_process_state": "quarantined",
            "external_process_last_error": "kernel identity mismatch",
        }
    ]

    text = render_watch((campaign, items, [], attempts, leases, events))
    normalized = re.sub(r"\s+", " ", text)

    assert "External process is Quarantined: kernel identity mismatch" in normalized
    assert "3 additional alerts" in normalized


def test_watch_board_uses_exact_totals_and_discloses_bounded_detail() -> None:
    campaign, _items, _jobs, attempts, leases, events = snapshots()
    items = [{"id": "shown", "title": "Shown", "state": "backlog"}]
    output = StringIO()
    console = Console(
        file=output,
        width=120,
        color_system=None,
        force_terminal=False,
    )
    console.print(
        build_watch_board(
            campaign,
            items,
            [],
            attempts,
            leases,
            events,
            as_of=AS_OF,
            item_state_counts={"backlog": 9, "testing": 3},
            worker_counts={
                "investigator": {"queued": 8, "active": 1, "expired": 0},
                "tester": {"queued": 2, "active": 1, "expired": 1},
            },
            total_items=12,
            omitted_item_count=11,
        )
    )
    text = re.sub(r"\s+", " ", output.getvalue())

    assert "Pipeline totals (12 items)" in text
    assert "Backlog 9" in text
    assert "Testing 3" in text
    assert re.search(r"Investigator\s+8\s+1\s+0\s+2", text)
    assert "11 item rows are omitted; aggregate totals remain exact" in text


def test_collision_safe_short_ids_scale_to_large_campaigns() -> None:
    identifiers = ["shared-prefix-%05d" % number for number in range(10_000)]

    labels = _short_id_map(identifiers)

    assert len(labels) == len(identifiers)
    assert len(set(labels.values())) == len(identifiers)


def test_repeated_rendering_is_deterministic_and_does_not_mutate_snapshots() -> None:
    data = snapshots()
    before = deepcopy(data)

    first = render(data)
    second = render(data)

    assert first == second
    assert data == before
