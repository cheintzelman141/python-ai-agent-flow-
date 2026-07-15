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

Phase 2 has started with real, least-privilege Codex workers and a deterministic
focused-test collector:

- investigators are forced into read-only sandboxes;
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
  process state, artifact hashes, and blockers; and
- `watch` provides a compact live terminal monitor with per-item lanes,
  persisted alerts, worker leases, sessions, resources, and recent events.
  Status and watch use strict read-only SQLite connections, require the current
  schema, never migrate, and read each screen from one transactionally
  consistent snapshot with a bounded recent-event window; and
- schema-v9 resource definitions register visible Chrome profiles, application
  tenants/databases, queue environments, and disposable test fixtures by
  opaque exact ID. Definitions are typed, campaign-scoped or global,
  enabled/disabled, display-safe, and separate from their active leases.
  Claims resolve registered IDs in storage, fail closed on missing, disabled,
  malformed, or out-of-scope definitions, and enforce exclusive or bounded
  shared capacity through the existing fenced lease lifecycle;
- supervisor-owned browser and database plans bind an exact resource identity,
  attempt, job, and immutable contract. The browser collector can only open a
  disposable `file://` fixture in visible Chrome, assert its exact route/title/
  body, and capture a bounded hashed PNG. It runs inside the same durable
  process-group guardian and restart-reconciliation boundary as focused tests;
- the first database collector is deliberately SQLite-only. It resolves an
  environment-key reference from the registered disposable tenant, opens URI
  `mode=ro`, enables `query_only`, denies every non-read authorizer action, and
  persists bounded exact IDs, row counts, query/result hashes, and foreign-key
  results; and
- `operator-interrupt` records an exact current lease/attempt/process/session/
  worktree/resource request for scheduler-owned cancellation and reap.
  `operator-resume` replaces automatic resume with one explicit, one-time,
  same-job authorization for the exact stopped external session; and
- schema-v10 focused executions persist and independently reconstruct an exact
  macOS Seatbelt profile before launch. The fixed `unittest` selector can read
  only its managed worktree, a root-owned byte-hashed Python runtime, the
  required system libraries, and its private scratch tree; worktree writes,
  other same-user file contents and directory listings, networking, forks,
  other executables, and detached children are denied by the OS policy; and
- schema-v11 adds an internal focused-test admission precursor. It binds one
  exact pending tester job to the campaign/configuration hash, item gates,
  payload, source and worktree identities, worktree generation, immutable
  schema-v10 plan, complete resource set, and exact registered-definition
  hashes. The `fta_...` identity is pinned to every admitted attempt and
  revalidated through heartbeat, guardian registration, collection, completion,
  and finalization. Guardian release is serialized against revocation by
  holding the admission transaction through the exact barrier write.
  Revocation and authority drift fail closed. This is an attributed internal
  contract, not an operator approval or public CLI.

Schema migration does not retroactively trust an already prepared focused
execution. A schema-v9 plan can receive one new schema-v10 revision, but legacy
prepared executions remain fail-closed and must be replaced by a fresh fenced
attempt with an exact schema-v11 admission before they can produce canonical
evidence. Explicit Phase 1 simulation remains compatible only when
`allow_simulated_evidence` is enabled; it is not authoritative focused proof.

The fixed authenticated acceptance command creates its own private disposable
repository, runs a source-only Codex investigator and an approved managed-
worktree Codex fixer, then gives testing to a deterministic focused-test worker.
The supervisor, not an LLM, owns that test command and persists its immutable,
revisioned plan snapshot, managed-worktree generation, process identity,
bounded stdout/stderr, hashes, semantic result, and canonical test handoff
before the item can become green. The command creates and later proves one exact
schema-v11 admission for its pending tester. A RED result becomes BLOCKED with
the captured test evidence because this post-fix precursor has no authority to
launch another fixer; a new fix cycle requires the separately approved
pre-launch admission described below.
The final assessment reconciles the exact one-file diff, two distinct Codex
sessions, all three reaped process groups, authoritative test execution,
artifact hashes, released leases, unchanged source, and SQLite foreign-key
integrity.

The real adapter is intentionally not exposed as a general campaign CLI yet.
The managed-worktree lifecycle, fixed proof command, and fixed disposable
three-gate pipeline are available, but they do not authorize arbitrary
repository test code, browser actions, SQL, credentials, or target paths. The
schema-v10 focused collector closes the same-user file-content/directory-list,
network, fork, other-executable, and detached-child boundary only for its exact
supervisor-owned macOS `unittest` plan. It is not authority for worker-supplied
commands or paths, and its exact-selector transcript evaluator is not a general
test framework. Existing browser profiles and application databases are not
authorized by resource registration alone; the current collectors accept only
supervisor-prepared disposable contracts, and the database implementation is
SQLite-only. GL collection remains unimplemented. General real-worker campaign
execution stays disabled until a separately approved campaign-admission path
binds exact repositories, worktrees, test plans, and resource definitions
without accepting worker-selected authority.

The schema-v11 precursor is intentionally narrower than that missing general
admission path: it can be created only after investigation, worktree
provisioning, and fixing have already completed. Its persisted campaign mode
blocks any later investigator/fixer claim or new worktree request, but it does
not retroactively authorize those earlier launches. General real campaigns
therefore remain disabled until a separately resolved pre-launch approval binds
the exact campaign and source repository before investigator or Git execution,
then carries that authority through fixer and tester admission. Existing
schema-v10 campaigns receive no automatic admission during migration.

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

Register durable environment resources without touching the external systems:

```bash
PYTHONPATH=src python3 -m agent_flow.cli resource-define chrome_profile \
  "QA Chrome" --campaign CAMPAIGN_ID --by USERNAME \
  --configuration \
  '{"user_data_dir":"/absolute/chrome-user-data","profile_directory":"Default"}'

PYTHONPATH=src python3 -m agent_flow.cli resource-define tenant_database \
  "QA tenant" --campaign CAMPAIGN_ID --by USERNAME \
  --configuration \
  '{"tenant_key":"tenant-qa","database_name":"tenant_qa","connection_env":"TENANT_QA_DATABASE"}'

PYTHONPATH=src python3 -m agent_flow.cli resource-define queue_environment \
  "QA queues" --campaign CAMPAIGN_ID --by USERNAME \
  --policy shared --concurrency-limit 2 --configuration \
  '{"environment_key":"qa","queue_names":["default"],"connection_env":"QUEUE_QA_CONFIG"}'

PYTHONPATH=src python3 -m agent_flow.cli resource-define test_fixture \
  "Disposable proof" --campaign CAMPAIGN_ID --by USERNAME \
  --configuration \
  '{"fixture_key":"proof","root_path":"/private/tmp/agent-flow-proof","disposable":true}'
```

Definitions default to an exclusive capacity of one. Shared definitions require
an explicit limit of at least two. Configuration accepts environment-key
references, never secret values: passwords, tokens, cookies, sensitive fields,
and credential-bearing URLs are rejected before persistence.

List or inspect definitions read-only, then use the returned exact `res_...` ID
for job references and mutations. Labels are display text and are never
mutation identifiers:

```bash
PYTHONPATH=src python3 -m agent_flow.cli resource-list --campaign CAMPAIGN_ID
PYTHONPATH=src python3 -m agent_flow.cli resource-show RESOURCE_DEFINITION_ID
PYTHONPATH=src python3 -m agent_flow.cli resource-disable \
  RESOURCE_DEFINITION_ID --by USERNAME
PYTHONPATH=src python3 -m agent_flow.cli resource-enable \
  RESOURCE_DEFINITION_ID --by USERNAME
```

View persisted state without changing it:

```bash
PYTHONPATH=src python3 -m agent_flow.cli status CAMPAIGN_ID
```

Watch the production line in an interactive terminal until `Ctrl+C`:

```bash
PYTHONPATH=src python3 -m agent_flow.cli watch CAMPAIGN_ID --refresh 1.0
```

Live refreshes show exact campaign and worker totals while bounding detailed
item rows to 50 by default. Use `--item-limit 100` when more detail is needed;
the monitor visibly reports any omitted rows and prioritizes persisted alert
rows inside the limit.

For a bounded non-interactive capture, set an explicit snapshot count:

```bash
PYTHONPATH=src python3 -m agent_flow.cli watch CAMPAIGN_ID \
  --refresh 1.0 --refresh-count 2
```

The monitor is read-only. It cannot start, interrupt, approve, retry, or mutate
a campaign. Run `init` separately if the database needs a schema migration.

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

Request scheduler-owned cancellation by the exact current lease fence, then
authorize the exact persisted session only if an operator chooses to resume it:

```bash
PYTHONPATH=src python3 -m agent_flow.cli operator-interrupt JOB_ID \
  --lease-token EXACT_TOKEN --by OPERATOR --reason "bounded stop"
PYTHONPATH=src python3 -m agent_flow.cli operator-resume JOB_ID ATTEMPT_ID \
  --provider codex --session-id EXACT_SESSION --by OPERATOR
```

The CLI records requests; it never directly signals a PID. The running
scheduler cancels its own worker, the adapter reaps the exact process group,
and storage applies the interrupt transaction only after reap proof.

Run the live-provider acceptance proof only with explicit acknowledgement. It
accepts no repository, database, worktree, or command paths, invokes Codex only
for investigation and fixing, and retains its private
`/private/tmp/agent-flow-real-proof-*` report for audit:

```bash
PYTHONPATH=src python3 -m agent_flow.cli prove-real-codex \
  --acknowledge-live-model
```

Run the Phase 1 fake production line through the real SQLite scheduler:

```bash
PYTHONPATH=src python3 -m agent_flow.cli simulate \
  --database /private/tmp/agent-flow-simulation.sqlite3 \
  --items 3
```

## Persistence and safety

- Runtime state defaults to `~/.agent-flow/agent-flow.sqlite3`.
- `status` and `watch` open existing state in SQLite `mode=ro` with
  `query_only=ON`; they fail closed on an outdated schema instead of migrating.
- Registered resource definitions contain typed identity/configuration,
  display-safe metadata, scope, and capacity policy; live owner/token/expiry
  fences remain in the separate resource-lease table.
- Resource lifecycle events disclose IDs, labels, kinds, policy, and lease
  slots, but never persisted configuration or browser/database credentials.
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
# python-ai-agent-flow-
