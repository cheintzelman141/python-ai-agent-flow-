# Agent Flow

Agent Flow is a local, durable production-line supervisor for bounded AI
workers. It routes multiple work items through investigation, fixing, and
evidence-gated testing without requiring a human to relay every handoff.

```text
BACKLOG -> INVESTIGATING -> READY_FOR_FIX -> FIXING
        -> READY_FOR_TEST -> TESTING -> VERIFIED_GREEN
                                   -> READY_FOR_FIX on proven red evidence
                                   -> BLOCKED on a concrete blocker
```

The scheduler does not trust a worker to select workflow state. Workers submit
strict, versioned handoffs; deterministic code evaluates the handoff, and the
SQLite store independently revalidates it before committing the result, next
job, resource release, and audit event in one transaction.

## Phase 1

Phase 1 provides:

- SQLite-backed campaigns, work items, logical jobs, immutable attempts,
  approvals, artifacts, events, and resource leases;
- database-enforced per-role and global concurrency limits;
- role-fair investigator, fixer, and tester pools;
- atomic claims that acquire all exclusive resources or claim nothing;
- expiring leases, bounded heartbeat retries, fencing tokens, interruption,
  shutdown recovery, and restart recovery;
- explicit, repository-scoped approval before fixer jobs can be claimed;
- strict investigation, fix, and test handoff schemas;
- focused-test, browser, database, and optional GL/API/export gate policies;
- real attachment checks by default and an explicit simulated-evidence mode;
- deterministic red-to-fixer routing with the complete failure packet;
- a read-only Rich CLI status board and a bounded fake-worker simulation.

Phase 1 does **not** launch real Codex/Claude/Gemini workers, modify target
repositories, control Chrome, query application
databases, push, merge, deploy, or send customer-facing communications.

`VERIFIED_GREEN` in the `simulate` command proves the queue, transition, and
evidence-contract machinery only. It is clearly labeled simulated and is not a
claim that a real browser or database was exercised.

## Phase 2 status

Phase 2 has started with a real, least-privilege Codex CLI vertical slice:

- investigators and testers are forced into read-only sandboxes;
- real fixers require a scheduler-fenced managed-worktree ID; payload paths
  cannot authorize writes;
- the tester successor inherits and validates the same exact managed worktree;
- prompts go through stdin without a shell, and ambient Codex configuration
  cannot widen the supervisor's sandbox or approval policy;
- a stable blocked guardian persists PID, PGID, UID, kernel birth time,
  guardian executable, and target executable before Codex can start;
- hooks, MCP/apps, remote tools, network access, extra writable roots, and
  temporary-directory writes are explicitly disabled at the provider boundary;
- Codex JSONL, structured final output, exact thread IDs, process identity,
  and hashed artifacts are bound to the fenced SQLite attempt;
- only a proven child-completion status can release the guardian, while
  cancellation, timeout, and error paths terminate and reap the exact process
  group even before the child starts;
- restart recovery uses a separately fenced Darwin `libproc` reconciler that
  revalidates the complete immutable identity before TERM and KILL;
- safe reconciliation atomically preserves process history, expires the old
  attempt, requeues its job, and releases its exact resource fences; and
- ambiguous, legacy, changed, or still-populated process groups remain
  quarantined instead of being signaled or silently reissued;
- schema-v5 managed worktrees persist source repository identity, exact base
  commit/tree/object format, branch, path, Git directory, device, inode, owner,
  lock reason, generation, state, and lifecycle history;
- creation and removal run behind the same durable blocked-guardian boundary,
  with separately fenced restart reconciliation that adopts only exact
  completed Git state and otherwise quarantines;
- quarantined lifecycle guardians can be explicitly re-inspected and, after
  exact reap proof, the same fenced operation is adopted only if Git state and
  hashed artifacts still match;
- checkout preflight rejects submodules, active filter attributes at the exact
  requested base, missing/promisor objects, source/runtime overlap, and
  untrusted Git transport or lazy-fetch behavior;
- cleanup is terminal-item-only, refuses staged, untracked, ignored,
  assume-unchanged, skip-worktree, or byte-level tracked changes, and retains
  the managed branch; and
- the status board and explicit lifecycle CLI expose worktrees, operations,
  process state, artifact hashes, and blockers.

The real adapter is intentionally not exposed as a general campaign CLI yet.
The managed-worktree lifecycle is available to operators, but an authenticated
disposable fixer -> tester Codex run is still required before enabling general
real-worker execution. Visible Chrome, application database, and GL proof
adapters remain unimplemented, so this project does not yet claim end-to-end
production-line green.

## Development

The project supports Python 3.9 and later.

```bash
cd /Users/cheintzelman/code/agent-flow
python3 -m pytest -o cache_dir=/private/tmp/agent-flow-pytest-cache
python3 -X pycache_prefix=/private/tmp/agent-flow-pycache -m compileall -q src tests
```

Run the CLI without installing it:

```bash
PYTHONPATH=src python3 -m agent_flow.cli --help
```

## CLI workflow

Initialize the default database under `~/.agent-flow`:

```bash
PYTHONPATH=src python3 -m agent_flow.cli init
```

Create a campaign:

```bash
PYTHONPATH=src python3 -m agent_flow.cli campaign-create "QA production line" \
  --repository /absolute/path/to/repository
```

Create an item and its investigation job atomically:

```bash
PYTHONPATH=src python3 -m agent_flow.cli item-add CAMPAIGN_ID "QA item" \
  --description "Exact requirement and expected behavior"
```

Explicitly approve local fixer changes for the campaign's configured
repositories:

```bash
PYTHONPATH=src python3 -m agent_flow.cli approve-writes CAMPAIGN_ID --by USERNAME
```

View persisted state without changing it:

```bash
PYTHONPATH=src python3 -m agent_flow.cli status CAMPAIGN_ID
```

Explicitly reconcile expired supervisor-owned external processes before
starting new real work. This command exits nonzero if any identity remains
ambiguous or quarantined:

```bash
PYTHONPATH=src python3 -m agent_flow.cli process-reconcile
```

Previously quarantined identities can be re-inspected after a transient OS
failure without weakening any identity gate:

```bash
PYTHONPATH=src python3 -m agent_flow.cli process-reconcile --retry-quarantined
```

Provision the exact worktree for an approved ready-for-fix item, verify it,
and inspect it on the campaign status board:

```bash
PYTHONPATH=src python3 -m agent_flow.cli worktree-provision \
  CAMPAIGN_ID ITEM_ID --repository /absolute/path/to/repository --base HEAD
PYTHONPATH=src python3 -m agent_flow.cli worktree-verify WORKTREE_ID
PYTHONPATH=src python3 -m agent_flow.cli status CAMPAIGN_ID
```

Reconcile expired lifecycle operations after a restart. This exits nonzero for
running or quarantined operations:

```bash
PYTHONPATH=src python3 -m agent_flow.cli worktree-reconcile
PYTHONPATH=src python3 -m agent_flow.cli worktree-reconcile --retry-quarantined
```

After the item is terminal and the worktree is independently proven clean,
remove the worktree while retaining its branch:

```bash
PYTHONPATH=src python3 -m agent_flow.cli worktree-cleanup WORKTREE_ID
```

Run the Phase 1 fake production line through the real SQLite scheduler:

```bash
PYTHONPATH=src python3 -m agent_flow.cli simulate \
  --database /private/tmp/agent-flow-simulation.sqlite3 \
  --items 3
```

## Persistence and safety

- Runtime state defaults to `~/.agent-flow/agent-flow.sqlite3`.
- Tests and temporary demonstrations use `/private/tmp`.
- Target repositories never receive Agent Flow runtime databases or evidence
  files.
- Lifecycle command output defaults under `/private/tmp`; managed worktrees
  default under `~/.agent-flow/worktrees` and never overlap the source checkout.
- Managed worktree cleanup never force-removes, deletes its branch, or discards
  unproven file content.
- No public storage API can directly set an item to `VERIFIED_GREEN`.
- Only a fenced tester-stage completion accepted by the gate evaluator may
  enter `VERIFIED_GREEN`.
- Job finalization proves that every required resource still has the same live
  owner and fencing token.
- Local write approval never implies permission to push, merge, deploy, send,
  post, rebill, or run destructive operations.

See `AGENTS.md` for the complete engineering contract and `CONTINUE.md` for the
next Phase 2 pickup point.
