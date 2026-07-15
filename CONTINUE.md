# Continue - Agent Flow

## Start here

```bash
cd /Users/cheintzelman/code/agent-flow
python3 -m pytest -o cache_dir=/private/tmp/agent-flow-pytest-cache
python3 -X pycache_prefix=/private/tmp/agent-flow-pycache -m compileall -q src tests
PYTHONPATH=src python3 -m agent_flow.cli --help
```

Read `AGENTS.md` completely before changing the runtime.

## Current state

Phase 1 is implemented, and the first Phase 2 vertical slice is implemented:

- typed and versioned handoffs;
- deterministic evidence-gate evaluation;
- SQLite WAL persistence and schema versioning;
- atomic fenced claims, attempts, resources, transitions, next jobs, and
  events;
- persisted concurrency limits and fair role scheduling;
- bounded execution and heartbeat retries, clean interruption, and
  shutdown/restart expired-lease recovery;
- storage-authoritative handoff, evidence, successor, and resource-fence
  validation;
- repository-scoped fixer approval;
- read-only status rendering and CLI commands;
- end-to-end fake-worker integration through the real SQLite adapter;
- a real Codex CLI adapter with explicit role sandboxing, stdin-only prompts,
  ambient-config isolation, bounded JSONL/stderr capture, and strict output;
- stable, crash-safe blocked guardian launch before provider startup and
  complete process-group reap, including cancellation before child launch;
- schema-v5 durable external session, process, managed-worktree, and lifecycle
  operation identity;
- explicit one-time exact-session resume authorization for cleanly interrupted
  attempts;
- fenced, hashed Codex artifacts outside the target repository;
- cancellation/timeout process-group reap;
- fenced restart-time Darwin process reconciliation with exact PID, PGID, UID,
  birth-time, executable, and identity-version checks;
- atomic safe recovery and fail-closed legacy, mismatched, or ambiguous process
  quarantine;
- explicit `process-reconcile` CLI reporting, nonzero blocked status, and
  gated retry of previously quarantined identities;
- external worker and managed-worktree lifecycle visibility in the status board;
- durable one-worktree-per-fix-item creation, exact source/base/branch/path/Git
  identity, locked worktrees, and same-worktree fixer/tester propagation;
- payload-independent Codex fixer authorization plus managed tester binding;
- exact pre/postflight source and worktree validation off the event loop;
- checkout refusal for exact-base filters, submodules, missing/promisor objects,
  runtime overlap, transport, and lazy-fetch behavior;
- byte-level cleanup proof that catches ignored and hidden index flags, refuses
  dirty removal, and retains the managed branch;
- blocked-guardian lifecycle Git commands with hashed artifacts and separately
  fenced restart adoption/quarantine; and
- explicit `worktree-provision`, `worktree-verify`, `worktree-cleanup`, and
  `worktree-reconcile` commands, including exact-state retry of quarantined
  lifecycle guardians; and
- fake-CLI integration plus an authenticated, disposable, read-only Codex
  smoke run through Scheduler -> SQLite; and
- a green opt-in fixed-fixture `prove-real-codex` acceptance command covering
  authenticated investigator -> managed fixer -> deterministic same-worktree
  focused tester with exact session, process, artifact, source, diff, test,
  lease, and SQLite proof; and
- a strict read-only `watch` terminal monitor with transactionally consistent,
  bounded-detail campaign snapshots, exact aggregate totals, alert-prioritized
  per-item lanes, worker/session/resource state, persisted alerts, non-TTY
  protection, and clean `Ctrl+C` handling; and
- schema-v9 durable definitions for `chrome_profile`, `tenant_database`,
  `queue_environment`, and `test_fixture`, with opaque exact IDs, typed and
  secret-rejecting configuration, optional campaign scope, display-safe
  metadata, enable/disable audit history, and explicit exclusive or bounded
  shared capacity. Definitions remain separate from active leases; storage
  resolves definition IDs during claims, skips unavailable-resource jobs, and
  preserves fencing, release, and restart recovery events; and
- fixed supervisor-owned visible-Chrome and read-only SQLite evidence plans,
  attempt/job/resource-bound executions, hashed screenshot/query artifacts,
  and storage-canonical three-gate handoff replacement; and
- durable `operator-interrupt` and `operator-resume` controls with exact lease,
  attempt, session/process, worktree-generation, resource-set, audit, process
  reap, restart, and one-time resume fences. Sequential collector process
  records retain history while permitting only one active group per attempt;
  and
- schema-v10 immutable macOS Seatbelt contracts for the focused `unittest`
  collector. Storage persists the exact root-owned sandbox executable,
  direct Python interpreter and byte-hashed root-owned runtime, byte-stable
  deny-default profile, logical test command, wrapped command, and hashes. The
  worker independently
  reconstructs the profile before launch. Real negative controls prove denial
  of outside same-user reads, writes, and directory listings; worktree writes;
  loopback networking; fork; other executables; subprocesses; and detached
  children while the exact selector and private HOME/TMPDIR remain usable; and
- schema-v11 internal focused-test admissions. One exact `fta_...` record binds
  a pending tester job to its campaign/configuration, item gates, payload,
  source snapshot, managed worktree generation, complete schema-v10 plan,
  complete resource set, and registered-definition hashes. The persisted
  focused-test-only campaign mode blocks investigator/fixer claims and new
  worktree requests. Attempts pin the record, and heartbeat, guardian
  registration, preparation, completion, and finalization all revalidate it.
  The admission transaction remains open through the exact guardian barrier
  release, so revocation and release have one serialized order. Revocation or
  drift fails closed without blocking process reap. An admitted RED is stored
  as a concrete BLOCKED handoff with its evidence and no impossible fixer
  successor. This internal attributed precursor has no CLI and does not consume
  or replace an operator approval.

Migrated schema-v9 plans may receive a new schema-v10 revision. Already
prepared legacy executions are intentionally not grandfathered into the new
sandbox proof and cannot complete as authoritative evidence.
Schema-v10 campaigns migrate to schema v11 in legacy mode with no admission;
nothing is grandfathered into focused-test authority, and a legacy tester
cannot prepare a real focused execution. Explicit Phase 1 simulation remains
available only through `allow_simulated_evidence`.

Resource commands still register and inspect definitions only. The fixed
collectors are separate and accept only supervisor-prepared disposable
contracts: one exact visible `file://` route/title/body/screenshot workflow and
one exact bounded SQLite `SELECT` under URI/read-only/authorizer enforcement.
They do not authorize existing browser sessions, general application databases,
worker-supplied actions/SQL, queues, or target mutations. General real-worker
campaign execution remains intentionally disabled because this sandbox
authorizes only the immutable supervisor-owned macOS `unittest` contract; no
general campaign admission path yet binds user-approved repositories,
worktrees, test plans, and resource definitions without accepting
worker-selected authority.
The v11 precursor is created only after investigator, worktree, and fixer work,
so it does not authorize those earlier real launches. General execution stays
disabled until a pre-launch, approval-consuming campaign/repository contract is
proven before any investigator or guarded Git process can start.


## Phase 2 admission-bound collector correction

The current schema-v11 focused-test admission is also revalidated by the
supervisor-owned browser and database collectors before they execute or
canonicalize evidence. Browser guardian release now uses the same transactional
release fence pattern as focused tests, so revocation and target launch have one
durable ordering. The SQLite database collector is revalidated immediately
before the bounded read and again before completion. Revocation remains allowed
to clear, terminate, and reap already-recorded process groups; it does not
authorize new browser launches or database reads.

Schema-v12 extends the internal focused-test admission record for the fixed
three-gate disposable pipeline by pinning the exact browser and database plan
IDs and plan hashes. Revocation is serialized with browser release and database
reads, and collector completion revalidates the same attempt-pinned authority.

This correction does not expose general real-campaign execution. The missing
pre-launch campaign/repository admission remains a separate future approval
contract and must still consume an explicit operator approval before any general
investigator, managed-worktree, fixer, tester, browser, or database boundary can
run against a non-disposable target.

## Phase 2 pickup point

Continue the real worker and environment adapters without weakening Phase 1's
storage boundary:

1. Design and prove the missing pre-launch admission scope. It must consume a
   separately resolved operator approval and bind the exact campaign and source
   repository before investigator claim or managed-worktree provisioning, then
   carry exact worktree, plan, and resource authority through fixer and tester.
   Keep worker-supplied commands, paths, routes, SQL, credentials, and target
   selection unauthorized.
2. Add a non-disposable application-database backend only after its credential,
   read-only session, query-authority, and isolation boundaries are separately
   specified and proven; keep the current implementation SQLite-only.
3. Add GL and any further evidence collectors behind the same immutable-plan,
   exact-resource, bounded-artifact, and storage-canonical pattern.
4. Build the native macOS worker-lane dashboard only after the CLI/runtime path
   remains green.

Do not add auto-push, auto-merge, auto-deploy, customer sends, production sync,
rebilling, posting, or destructive behavior.
