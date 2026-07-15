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
- exact-session resume for cleanly interrupted attempts;
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
  protection, and clean `Ctrl+C` handling.

Visible Chrome and application database adapters do not exist yet. General
real-worker campaign execution remains intentionally disabled because generic
evidence attachments prove file existence, not the semantics of arbitrary
commands, browser flows, or database queries.

## Phase 2 pickup point

Continue the real worker and environment adapters without weakening Phase 1's
storage boundary:

1. Add resource definitions for visible Chrome profiles, tenants, databases,
   queues, and fixtures.
2. Add real evidence collectors that register screenshots, browser routes, SQL
   results, IDs, and hashes as durable artifacts.
3. Add explicit operator interruption/resume CLI commands; use only the exact
   external session ID already bound to the same logical job.
4. Add an OS sandbox or trusted harness before allowing arbitrary repository
   test code through the focused-test collector.
5. Validate visible browser and application-database adapters in disposable
   fixtures before enabling any production repository.
6. Build the native macOS worker-lane dashboard only after the CLI/runtime path
   remains green.

Do not add auto-push, auto-merge, auto-deploy, customer sends, production sync,
rebilling, posting, or destructive behavior.
