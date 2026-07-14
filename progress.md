# Agent Flow Progress

## Completed

- Phase 1 architecture and repository engineering contract
- Python 3.9 project scaffold and CLI entry point
- Durable SQLite domain store
- Atomic resource-aware claims with lease fencing
- Immutable execution attempts and stable event cursors
- Persisted role/global concurrency policy
- Round-robin role-fair scheduler
- Investigation, fix, test, red-loop, blocked, and green paths
- Explicit repository-scoped local-write approvals
- Attachment-aware evidence validation with isolated simulation mode
- Store-authoritative green gates and successor validation
- Resource-fenced finalization and lock-safe lease timing
- Transient heartbeat retry plus clean shutdown/restart recovery
- Rich read-only status board
- Real SQLite fake-worker pipeline and regression suite
- SQLite schema v5 external session/process/worktree persistence and exact-session resume
- Least-privilege real Codex CLI worker adapter
- Strict provider-compatible structured handoff schemas
- Bounded, hashed Codex JSONL/stderr/final/schema artifacts
- Process-group timeout/cancellation cleanup and fail-closed process quarantine
- Crash-safe blocked launch before durable process registration
- Ambient project-config, hook, MCP/app, network, and write-root isolation
- External session/process status visibility
- Fake Codex Scheduler -> SQLite integration coverage
- Authenticated disposable read-only Codex smoke proof
- Immutable Darwin PID/PGID/UID/birth/executable process identity
- Stable guardian launch boundary with separate target-executable audit identity
- Exact child-PATH resolution and guardian-anchored live process cleanup
- Status-proven guardian release with pre-child cancellation race protection
- Fenced restart-time external-process claim, inspection, and reconciliation
- Off-event-loop, bounded scheduler reconciliation with live heartbeats
- TERM/KILL identity revalidation with protected supervisor PID/PGID checks
- Atomic reconciled-attempt expiry, job requeue, and exact resource release
- Fail-closed V3 process migration and identity-mismatch quarantine
- Explicit nonzero-on-blocked `process-reconcile` CLI proof surface
- Explicit fail-closed retry for previously quarantined identities
- Disposable real-process reconciliation and wrong-birth no-signal coverage
- Durable managed-worktree and lifecycle-operation schema with typed job/attempt binding
- Exact source checkout, base commit/tree, branch, Git dir, inode/device/UID, and lock proof
- Scheduler-fenced payload-independent fixer authorization and same-worktree tester propagation
- Exact pre/postflight Codex workspace validation with read-only content snapshots
- Exact-base filter/submodule/promisor rejection with lazy fetch and Git transport disabled
- Blocked-guardian Git creation/removal with bounded hashed artifacts
- Separately fenced lifecycle restart reconciliation with exact-state adoption or quarantine
- Exact-state retry and recovery for quarantined lifecycle guardians
- Byte-level cleanup proof including ignored, assume-unchanged, and skip-worktree protection
- Clean non-force removal with managed branch retention
- Managed-worktree and lifecycle-operation status visibility
- Explicit provision, verify, cleanup, and reconcile CLI commands
- Disposable real-Git creation, hidden-change refusal, filter-execution prevention,
  branch-retention, and crash-reconciliation coverage

## Phase 2 next

- Authenticated disposable managed fixer -> same-worktree tester Codex proof
- General real-worker CLI enablement after the disposable proof
- Visible Chrome control and browser evidence collection
- Application database/tenant/fixture adapters
- Real focused-test, browser, database, GL, export, and API artifact collectors
- Native macOS production-line dashboard
- Human-approved integration, push, merge, or deployment workflows
