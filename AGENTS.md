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
- read-only investigator execution and workspace-write fixer execution only
  inside a validated distinct Git worktree;
- prompt delivery through stdin with no shell and an allowlisted environment;
- a stable blocked guardian that cannot start Codex until exact PID, PGID,
  UID, kernel birth, and executable registration is durable;
- untrusted-project execution with ambient hooks, MCP, apps, remote tools,
  network access, extra write roots, and temporary-directory writes disabled;
- exact external session persistence plus explicit, one-time exact-ID resume
  authorization;
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
- immutable, revisioned supervisor-owned focused `unittest` plan snapshots for
  the fixed disposable fixture, with each retest preserving the executable,
  trusted test bytes, selector, environment, and limits while approving only a
  new workspace manifest; an attempt/worktree-generation-bound deterministic
  tester, bounded private output, semantic PASS/RED evaluation, and storage-side
  canonical handoff replacement; and
- schema-v10 immutable macOS Seatbelt execution contracts for those focused
  plans. Storage binds the root-owned sandbox executable, direct Python
  interpreter and byte-hashed root-owned runtime, byte-exact deny-default
  profile, logical test command, wrapped command, and hashes; the worker
  reconstructs the policy
  before launch. The policy permits the exact worktree and private scratch,
  while denying worktree writes, outside same-user file contents and directory
  listings, networking, forks, other executables, and detached children; and
- schema-v11 internal focused-test admission precursors for exact pending tester
  jobs. A durable `fta_...` record binds the campaign configuration, item gates,
  tester payload, source repository identity and snapshot, managed worktree and
  generation, every schema-v10 focused-plan authority field, the complete
  resource set, and exact registered definition hashes. The campaign enters an
  irreversible focused-test-only mode; storage skips investigator and fixer
  claims, pins the admission to each tester attempt, and revalidates it at
  heartbeat, session/process registration, collection, completion, and stage
  finalization. The exact guardian barrier release occurs while the admission
  transaction remains open, serializing it against revocation. Revocation or
  drift fails closed while process clearing remains available for reap. An
  admitted RED becomes a durable execution blocker because this tester-only
  mode cannot authorize a fixer. This internal attributed record is not an
  operator approval workflow and has no public CLI; and
- an opt-in `prove-real-codex --acknowledge-live-model` command that accepts no
  target paths and proves the authenticated investigator -> managed fixer ->
  authoritative same-worktree focused tester boundary against a fixed
  disposable fixture; and
- a compact `watch` terminal monitor backed by strict read-only SQLite opens,
  transactionally consistent snapshots with exact aggregate totals, bounded
  item detail and recent events, alert-prioritized per-item lanes, clean
  interruption, and no workflow-control authority; and
- schema-v9 durable resource definitions for exact visible Chrome profiles,
  tenant databases, queue environments, and disposable test fixtures. Typed,
  secret-rejecting configuration, stable opaque IDs, optional campaign scope,
  display-safe metadata, enablement state, and exclusive/shared capacity policy
  remain separate from active fenced leases. Claims fail closed for missing,
  disabled, malformed, or out-of-scope definitions while skipping blocked jobs;
  definition and lease lifecycle mutations append durable audit events; and
- immutable supervisor-owned visible-Chrome and read-only SQLite query plans,
  attempt/job/resource-fenced execution rows, bounded hashed artifacts, and
  storage-canonical focused/browser/database gate replacement. Visible Chrome
  runs only a fixed file-route/title/body/screenshot contract inside a durable
  blocked process-group guardian. SQLite runs only a comment-free direct
  `SELECT` with URI read-only mode, `query_only`, a deny-non-read authorizer,
  row/byte/time bounds, exact expected IDs, and foreign-key proof; and
- transactional `operator-interrupt` and `operator-resume` controls. Interrupt
  requests bind the current lease, attempt, process birth identity, session,
  worktree generation, and resource set; resume authorization is explicit,
  one-time, same-job, and exact-session. Sequential collector processes retain
  immutable history while only one process may be active per attempt.

This slice still does not provide general real-repository campaign execution.
The three collectors are authoritative only for their supervisor-prepared,
disposable fixed contracts; arbitrary worker-supplied commands, routes, browser
actions, SQL, credentials, and target paths remain unauthorized. The focused
collector is an authorization boundary only for its immutable supervisor-owned
macOS `unittest` plan; it does not authorize worker-supplied commands or paths,
and its exact-selector semantic transcript evaluator is not a general test
framework. Keep general real campaigns disabled until a separately approved
admission path binds exact repositories, worktrees, test plans, and registered
resources without delegating authority to worker output. Resource registration
alone still does not authorize launching Chrome, reading an existing browser
profile, connecting to an application database, starting queues/workers, or
mutating a target.
The schema-v11 focused-test precursor is intentionally created only after the
investigator, managed-worktree provisioning, and fixer stages have already
finished. It therefore does not authorize those earlier launches and must not
be represented as general campaign admission. A separate pre-launch,
approval-consuming campaign/repository contract remains required before any
general real-worker command can be exposed.
Schema-v11 legacy campaigns cannot prepare an authoritative focused execution
without an exact admission. Simulation-only Phase 1 campaigns remain available
under their explicit `allow_simulated_evidence` contract.

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
- Registered resource identity uses its exact opaque definition ID. Labels are
  display-only and must never select a mutation target. Definition records and
  active lease fences remain separate; do not create a second lease system.
- Persist credential references or environment-key names only. Never store
  passwords, tokens, cookies, credential-bearing DSNs, or browser session
  contents in definitions, metadata, events, or status output.
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

- `models.py`: enums, typed resource definitions, records, handoff schemas, and
  deterministic gate checks.
- `storage.py`: SQLite schema, transactions, persistence, claims, events, and
  leases. It must not run workers.
- `scheduler.py`: worker-pool scheduling and workflow transitions. It must use
  the storage API rather than issuing SQL directly.
- `workers.py`: worker protocol and deterministic fake workers only.
- `codex_worker.py`: the least-privilege Codex subprocess, structured-output,
  process-reaping, session, and runtime-artifact boundary.
- `focused_tests.py`: deterministic execution of storage-prepared focused-test
  plans. It must not derive commands, paths, or environment from worker data.
- `focused_sandbox.py`: deterministic construction and validation of the exact
  macOS Seatbelt policy for a storage-prepared focused-test execution.
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
