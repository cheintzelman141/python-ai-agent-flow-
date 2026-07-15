import re
from copy import deepcopy
from datetime import datetime, timezone
from io import StringIO

from rich.console import Console

from agent_flow.status import render_status


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


def test_repeated_rendering_is_deterministic_and_does_not_mutate_snapshots() -> None:
    data = snapshots()
    before = deepcopy(data)

    first = render(data)
    second = render(data)

    assert first == second
    assert data == before
