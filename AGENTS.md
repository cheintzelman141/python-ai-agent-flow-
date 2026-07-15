# AGENTS.md - Agent Flow Engineering Contract

## Mission

Build a durable local production-line supervisor for multiple AI workers. The
supervisor owns queues, state transitions, evidence gates, resource leases,
interrupts, retries, and recovery. AI workers perform bounded investigation,
fixing, and testing tasks; their output is untrusted until structurally
validated.

## Phase 1 Scope

Phase 1 must provide:

- a Python 3.9-compatible, CLI-first runtime;
- SQLite-backed campaigns, work items, jobs, attempts, events, approvals, and
  resource leases;
- atomic worker claims with expiring leases and heartbeat/recovery support;
- configurable investigator, fixer, and tester pools with a global concurrency
  ceiling;
- typed investigation, fix, and test handoffs;
- deterministic state transitions and evidence-gate evaluation;
- fake workers that prove concurrent flow without invoking external AI tools;
- a readable CLI status board;
- focused tests for concurrency, red-to-fix loops, incomplete-proof rejection,
  resource exclusion, and restart recovery.

Phase 1 must not:

- modify target repositories;
- launch real Codex, Claude, or Gemini workers;
- automate Chrome or database mutations;
- create real Git worktrees;
- push, merge, deploy, send, post, rebill, or perform destructive actions;
- build the desktop UI.

## Phase 2 Current Slice

The current Phase 2 vertical slice adds a real Codex CLI worker boundary and
managed Git-worktree lifecycle while keeping Phase 1 storage authoritative. It
includes:

- strict investigator, fixer, and tester output schemas;
- read-only investigator/tester execution and workspace-write fixer execution
  only inside a validated distinct Git worktree;
- prompt delivery through stdin with no shell and an allowlisted environment;
- a stable blocked guardian that cannot start Codex until exact PID, PGID,
  UID, kernel birth, and executable registration is durable;
- untrusted-project execution with ambient hooks, MCP, apps, remote tools,
  network access, extra write roots, and temporary-directory writes disabled;
- exact external session persistence and exact-ID resume;
- persisted PID, process-group, UID, kernel birth, guardian executable, and
  target executable identity;
- bounded JSONL/stderr capture plus hashed attempt artifacts outside target
  repositories;
- process-group termination and reap on timeout, failure, or cancellation;
- fail-closed lease recovery that quarantines an attempt while a recorded
  external process still needs reconciliation;
- separately fenced restart reconciliation that revalidates exact Darwin
  process identity before TERM/KILL and atomically recovers only after group
  absence is proven; and
- status visibility for external sessions and processes;
- durable creation, verification, cleanup, quarantine retry, and restart
  reconciliation for exact locked managed worktrees;
- scheduler-fenced fixer authorization and same-worktree tester inheritance;
- payload-independent workspace selection with exact pre/postflight Git and
  filesystem identity validation; and
- an opt-in `prove-real-codex --acknowledge-live-model` command that accepts no
  target paths and proves the authenticated investigator -> managed fixer ->
  same-worktree tester boundary against a fixed disposable fixture.

This slice does not yet provide durable browser/database evidence collectors or
general real-repository campaign execution. The current evidence attachment
gate proves file existence but not the semantics of arbitrary test, browser, or
database commands. Keep general real campaigns disabled until those collectors
exist and are proven against disposable fixtures.

## Architecture Rules

- The scheduler and storage layer, not an LLM, own state transitions.
- A worker cannot mark an item green. It can only submit evidence. The
  deterministic gate evaluator decides whether the item qualifies.
- Use SQLite transactions for claims and leases. Do not coordinate concurrent
  workers through unguarded JSON files.
- A claim must atomically enforce persisted role/global limits, acquire every
  required resource, create an immutable attempt, transition the item, and
  append its event. Resource-blocked jobs must be skipped, not head-of-line
  blockers.
- Every claim uses an opaque fencing token. Heartbeats and finalization must
  match the current job, owner, and token so expired workers cannot submit
  stale output after recovery.
- Keep durable work items, logical stage jobs, and immutable execution attempts
  separate. Retries never overwrite attempt history.
- Stage finalization must atomically store the handoff, finish the attempt/job,
  release resources, transition the item, enqueue the next stage, and append
  its event.
- Keep worker adapters behind a small protocol so fake and real workers use the
  same scheduler path.
- Every state change must append an event suitable for audit and UI streaming.
- Jobs and leases must be recoverable after supervisor process failure.
- Keep changes surgical, explicit, typed, and Python 3.9-compatible.
- Do not introduce Redis, Celery, Temporal, a web framework, or a service
  dependency in Phase 1.
- Store runtime state outside target repositories. Tests must use temporary
  directories.

## Shared Module Boundaries

- `models.py`: enums, records, handoff schemas, and deterministic gate checks.
- `storage.py`: SQLite schema, transactions, persistence, claims, events, and
  leases. It must not run workers.
- `scheduler.py`: worker-pool scheduling and workflow transitions. It must use
  the storage API rather than issuing SQL directly.
- `workers.py`: worker protocol and deterministic fake workers only.
- `codex_worker.py`: the least-privilege Codex subprocess, structured-output,
  process-reaping, session, and runtime-artifact boundary.
- `cli.py`: user-facing commands and status rendering. It must not duplicate
  workflow rules.

## Workflow

```text
BACKLOG -> INVESTIGATING -> READY_FOR_FIX -> FIXING
       -> READY_FOR_TEST -> TESTING -> VERIFIED_GREEN
                                  -> READY_FOR_FIX on a proven red result
                                  -> BLOCKED on a concrete execution/product blocker
```

Invalid or incomplete handoffs never advance the item. Missing test proof must
not become green.

## Verification Standard

Before Phase 1 is complete, prove:

1. A busy fixer or tester does not stop other eligible items from progressing.
2. Pool and global concurrency limits are enforced.
3. Two jobs cannot simultaneously lease the same exclusive resource.
4. Expired job and resource leases recover after restart.
5. A red test packet creates a new fixer attempt with the failure evidence.
6. Green requires all item-specific gates and attached evidence.
7. Every transition is represented in the event history.
8. The CLI accurately reflects persisted state.

For each real worker adapter added in Phase 2, also prove with an authenticated
disposable sandbox that:

1. the exact provider session is persisted before final output;
2. the provider process and its group are cleared only after reap;
3. failure cannot advance the item;
4. runtime artifacts are outside the target repository and integrity hashed;
5. the target repository status and file hashes are unchanged for read-only
   roles; and
6. the database has no foreign-key violations.

Use:

```bash
python3 -m pytest -o cache_dir=/private/tmp/agent-flow-pytest-cache
python3 -X pycache_prefix=/private/tmp/agent-flow-pycache -m compileall -q src tests
```

## Artifact Rules

- Do not place screenshots, exports, debug dumps, or runtime databases in the
  repository.
- Use `/private/tmp/agent-flow-*` for temporary verification artifacts.
- Never commit generated runtime state.
