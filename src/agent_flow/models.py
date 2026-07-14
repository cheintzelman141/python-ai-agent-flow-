"""Typed domain records and deterministic evidence-gate evaluation.

Workers produce handoffs; they do not control workflow state.  In particular,
``TestHandoff`` deliberately has no ``VERIFIED_GREEN`` outcome.  Only
``evaluate_test_handoff`` can return that decision after checking the item's
required gates and attached evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, Literal, Optional, Tuple
from uuid import uuid4

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)
from typing_extensions import Annotated


NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


def utc_now() -> datetime:
    """Return an aware UTC timestamp suitable for persisted records."""

    return datetime.now(timezone.utc)


class DomainModel(BaseModel):
    """Common validation policy for persisted records and worker handoffs."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, validate_assignment=True)


class CampaignStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class ItemState(str, Enum):
    BACKLOG = "backlog"
    INVESTIGATING = "investigating"
    READY_FOR_FIX = "ready_for_fix"
    FIXING = "fixing"
    READY_FOR_TEST = "ready_for_test"
    TESTING = "testing"
    VERIFIED_GREEN = "verified_green"
    BLOCKED = "blocked"


class WorkerRole(str, Enum):
    INVESTIGATOR = "investigator"
    FIXER = "fixer"
    TESTER = "tester"


class JobStatus(str, Enum):
    PENDING = "pending"
    LEASED = "leased"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AttemptStatus(str, Enum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    EXPIRED = "expired"
    INTERRUPTED = "interrupted"


class WorkspaceKind(str, Enum):
    SOURCE_READ_ONLY = "source_read_only"
    MANAGED_WORKTREE = "managed_worktree"
    SIMULATED = "simulated"


class ManagedWorktreeState(str, Enum):
    PROVISIONING = "provisioning"
    READY = "ready"
    CLEANUP_PENDING = "cleanup_pending"
    QUARANTINED = "quarantined"
    REMOVED = "removed"


class WorktreeOperationKind(str, Enum):
    CREATE = "create"
    REMOVE = "remove"


class WorktreeOperationStatus(str, Enum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    QUARANTINED = "quarantined"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class EvidenceKind(str, Enum):
    BROWSER = "browser"
    SCREENSHOT = "screenshot"
    DATABASE = "database"
    TEST = "test"
    GL = "gl"
    API = "api"
    LOG = "log"
    EXPORT = "export"
    DOCUMENT = "document"
    OTHER = "other"


class GateKind(str, Enum):
    FOCUSED_TESTS = "focused_tests"
    BROWSER = "browser"
    DATABASE = "database"
    GL = "gl"
    API = "api"
    EXPORT = "export"


class GateResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"


class InvestigationOutcome(str, Enum):
    READY_FOR_FIX = "ready_for_fix"
    BLOCKED = "blocked"


class FixOutcome(str, Enum):
    READY_FOR_TEST = "ready_for_test"
    BLOCKED = "blocked"


class TestOutcome(str, Enum):
    """A worker observation, intentionally distinct from a green decision."""

    PASS = "pass"
    RED = "red"
    BLOCKED = "blocked"


class BlockerKind(str, Enum):
    EXECUTION = "execution"
    PRODUCT_DECISION = "product_decision"


class GateDecision(str, Enum):
    VERIFIED_GREEN = "verified_green"
    RETURN_TO_FIX = "return_to_fix"
    BLOCKED = "blocked"
    REJECTED = "rejected"


class Campaign(DomainModel):
    id: NonEmptyString = Field(default_factory=lambda: str(uuid4()))
    name: NonEmptyString
    description: str = ""
    status: CampaignStatus = CampaignStatus.ACTIVE
    repository_paths: Tuple[NonEmptyString, ...] = ()
    global_concurrency_limit: int = Field(default=4, ge=1)
    role_concurrency_limits: Dict[WorkerRole, int] = Field(
        default_factory=lambda: {
            WorkerRole.INVESTIGATOR: 2,
            WorkerRole.FIXER: 2,
            WorkerRole.TESTER: 2,
        }
    )
    created_at: AwareDatetime = Field(default_factory=utc_now)
    updated_at: AwareDatetime = Field(default_factory=utc_now)

    @field_validator("role_concurrency_limits")
    @classmethod
    def validate_role_concurrency_limits(
        cls, value: Dict[WorkerRole, int]
    ) -> Dict[WorkerRole, int]:
        expected_roles = set(WorkerRole)
        if set(value) != expected_roles:
            missing = expected_roles.difference(value)
            extra = set(value).difference(expected_roles)
            details = []
            if missing:
                details.append("missing " + ", ".join(sorted(role.value for role in missing)))
            if extra:
                details.append("unexpected " + ", ".join(sorted(str(role) for role in extra)))
            raise ValueError(
                "role concurrency limits must cover every worker role: " + "; ".join(details)
            )
        if any(isinstance(limit, bool) or limit < 1 for limit in value.values()):
            raise ValueError("role concurrency limits must be positive integers")
        return value


class WorkItem(DomainModel):
    id: NonEmptyString = Field(default_factory=lambda: str(uuid4()))
    campaign_id: NonEmptyString
    title: NonEmptyString
    description: NonEmptyString
    state: ItemState = ItemState.BACKLOG
    required_gates: Tuple[GateKind, ...] = (
        GateKind.FOCUSED_TESTS,
        GateKind.BROWSER,
        GateKind.DATABASE,
    )
    priority: int = Field(default=0, ge=0)
    created_at: AwareDatetime = Field(default_factory=utc_now)
    updated_at: AwareDatetime = Field(default_factory=utc_now)

    @field_validator("required_gates")
    @classmethod
    def required_gates_must_be_unique_and_nonempty(
        cls, value: Tuple[GateKind, ...]
    ) -> Tuple[GateKind, ...]:
        if not value:
            raise ValueError("an item must require at least one evidence gate")
        if len(set(value)) != len(value):
            raise ValueError("required gates must be unique")
        return value


_ROLE_STATE_PAIRS = {
    WorkerRole.INVESTIGATOR: (ItemState.BACKLOG, ItemState.INVESTIGATING),
    WorkerRole.FIXER: (ItemState.READY_FOR_FIX, ItemState.FIXING),
    WorkerRole.TESTER: (ItemState.READY_FOR_TEST, ItemState.TESTING),
}


class Job(DomainModel):
    id: NonEmptyString = Field(default_factory=lambda: str(uuid4()))
    campaign_id: NonEmptyString
    item_id: NonEmptyString
    role: WorkerRole
    status: JobStatus = JobStatus.PENDING
    attempt_number: int = Field(default=1, ge=1)
    queued_item_state: Optional[ItemState] = None
    active_item_state: Optional[ItemState] = None
    required_resources: Tuple[NonEmptyString, ...] = ()
    payload: Dict[str, Any] = Field(default_factory=dict)
    workspace_kind: WorkspaceKind = WorkspaceKind.SOURCE_READ_ONLY
    managed_worktree_id: Optional[NonEmptyString] = None
    lease_token: Optional[NonEmptyString] = None
    lease_owner: Optional[NonEmptyString] = None
    lease_expires_at: Optional[AwareDatetime] = None
    current_attempt_id: Optional[NonEmptyString] = None
    resume_external_provider: Optional[NonEmptyString] = None
    resume_external_session_id: Optional[NonEmptyString] = None
    created_at: AwareDatetime = Field(default_factory=utc_now)
    updated_at: AwareDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_role_states_and_lease(self) -> Job:
        queued_state, active_state = _ROLE_STATE_PAIRS[self.role]
        if self.queued_item_state is None:
            object.__setattr__(self, "queued_item_state", queued_state)
        elif self.queued_item_state != queued_state:
            raise ValueError(f"{self.role.value} jobs must queue from {queued_state.value}")

        if self.active_item_state is None:
            object.__setattr__(self, "active_item_state", active_state)
        elif self.active_item_state != active_state:
            raise ValueError(f"{self.role.value} jobs must activate as {active_state.value}")

        lease_fields = (self.lease_token, self.lease_owner, self.lease_expires_at)
        if any(value is not None for value in lease_fields) and not all(
            value is not None for value in lease_fields
        ):
            raise ValueError("job lease token, owner, and expiry must be set together")
        if self.status in (JobStatus.LEASED, JobStatus.RUNNING) and not all(
            value is not None for value in lease_fields
        ):
            raise ValueError("leased or running jobs require a complete lease fence")
        resume_fields = (
            self.resume_external_provider,
            self.resume_external_session_id,
        )
        if any(value is not None for value in resume_fields) and not all(
            value is not None for value in resume_fields
        ):
            raise ValueError(
                "resume external provider and session id must be set together"
            )
        if (
            self.managed_worktree_id is not None
            and self.workspace_kind != WorkspaceKind.MANAGED_WORKTREE
        ):
            raise ValueError(
                "managed_worktree_id requires managed_worktree workspace_kind"
            )
        if (
            self.workspace_kind == WorkspaceKind.MANAGED_WORKTREE
            and self.role == WorkerRole.INVESTIGATOR
        ):
            raise ValueError("investigator jobs cannot use a managed worktree")
        return self


class Attempt(DomainModel):
    id: NonEmptyString = Field(default_factory=lambda: str(uuid4()))
    job_id: NonEmptyString
    item_id: NonEmptyString
    role: WorkerRole
    number: int = Field(ge=1)
    status: AttemptStatus = AttemptStatus.RUNNING
    lease_token: NonEmptyString
    lease_owner: NonEmptyString
    lease_expires_at: AwareDatetime
    started_at: AwareDatetime = Field(default_factory=utc_now)
    completed_at: Optional[AwareDatetime] = None
    error: Optional[str] = None


class Event(DomainModel):
    id: NonEmptyString = Field(default_factory=lambda: str(uuid4()))
    campaign_id: NonEmptyString
    item_id: Optional[NonEmptyString] = None
    job_id: Optional[NonEmptyString] = None
    event_type: NonEmptyString
    from_state: Optional[ItemState] = None
    to_state: Optional[ItemState] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: AwareDatetime = Field(default_factory=utc_now)


class Approval(DomainModel):
    id: NonEmptyString = Field(default_factory=lambda: str(uuid4()))
    campaign_id: NonEmptyString
    action: NonEmptyString
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: AwareDatetime = Field(default_factory=utc_now)
    decided_at: Optional[AwareDatetime] = None
    decided_by: Optional[NonEmptyString] = None


class ResourceLease(DomainModel):
    resource_key: NonEmptyString
    job_id: NonEmptyString
    lease_token: NonEmptyString
    lease_owner: NonEmptyString
    acquired_at: AwareDatetime = Field(default_factory=utc_now)
    heartbeat_at: AwareDatetime = Field(default_factory=utc_now)
    lease_expires_at: AwareDatetime


class ManagedWorktree(DomainModel):
    id: NonEmptyString
    generation: int = Field(ge=1)
    campaign_id: NonEmptyString
    item_id: NonEmptyString
    repository_path: NonEmptyString
    source_git_common_dir: NonEmptyString
    source_git_dir: NonEmptyString
    source_device: int = Field(ge=0)
    source_inode: int = Field(ge=0)
    source_owner_uid: int = Field(ge=0)
    object_format: NonEmptyString
    worktree_path: NonEmptyString
    worktree_git_dir: Optional[NonEmptyString] = None
    worktree_device: Optional[int] = Field(default=None, ge=0)
    worktree_inode: Optional[int] = Field(default=None, ge=0)
    worktree_owner_uid: Optional[int] = Field(default=None, ge=0)
    branch_ref: NonEmptyString
    base_revision: NonEmptyString
    base_tree: NonEmptyString
    head_revision: Optional[NonEmptyString] = None
    lock_reason: NonEmptyString
    source_snapshot: Dict[str, Any]
    state: ManagedWorktreeState
    last_error: Optional[str] = None
    created_at: AwareDatetime
    ready_at: Optional[AwareDatetime] = None
    cleanup_started_at: Optional[AwareDatetime] = None
    removed_at: Optional[AwareDatetime] = None
    updated_at: AwareDatetime


class EvidenceRef(DomainModel):
    id: NonEmptyString = Field(default_factory=lambda: str(uuid4()))
    kind: EvidenceKind
    location: NonEmptyString
    description: NonEmptyString
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Blocker(DomainModel):
    kind: BlockerKind
    summary: NonEmptyString
    next_action: NonEmptyString
    evidence: Tuple[EvidenceRef, ...] = Field(min_length=1)


class InvestigationHandoff(DomainModel):
    schema_version: Literal[1] = 1
    item_id: NonEmptyString
    outcome: InvestigationOutcome = InvestigationOutcome.READY_FOR_FIX
    synopsis: NonEmptyString
    reproduction_steps: Tuple[NonEmptyString, ...] = Field(min_length=1)
    root_cause: NonEmptyString
    proposed_fix: NonEmptyString
    acceptance_criteria: Tuple[NonEmptyString, ...] = Field(min_length=1)
    evidence: Tuple[EvidenceRef, ...] = Field(min_length=1)
    blocker: Optional[Blocker] = None

    @model_validator(mode="after")
    def validate_outcome(self) -> InvestigationHandoff:
        if self.outcome == InvestigationOutcome.BLOCKED and self.blocker is None:
            raise ValueError("a blocked investigation requires a concrete blocker")
        if self.outcome == InvestigationOutcome.READY_FOR_FIX and self.blocker is not None:
            raise ValueError("a ready-for-fix investigation cannot include a blocker")
        return self


class FixHandoff(DomainModel):
    schema_version: Literal[1] = 1
    item_id: NonEmptyString
    outcome: FixOutcome = FixOutcome.READY_FOR_TEST
    summary: NonEmptyString
    changed_files: Tuple[NonEmptyString, ...] = ()
    tests_run: Tuple[NonEmptyString, ...] = ()
    tester_instructions: Tuple[NonEmptyString, ...] = ()
    evidence: Tuple[EvidenceRef, ...] = ()
    blocker: Optional[Blocker] = None

    @model_validator(mode="after")
    def validate_outcome(self) -> FixHandoff:
        if self.outcome == FixOutcome.BLOCKED:
            if self.blocker is None:
                raise ValueError("a blocked fix requires a concrete blocker")
            return self
        if self.blocker is not None:
            raise ValueError("a ready-for-test fix cannot include a blocker")
        if not self.changed_files:
            raise ValueError("a ready-for-test fix must identify changed files")
        if not self.tester_instructions:
            raise ValueError("a ready-for-test fix must include tester instructions")
        return self


_GATE_EVIDENCE_KINDS = {
    GateKind.FOCUSED_TESTS: {EvidenceKind.TEST, EvidenceKind.LOG},
    GateKind.BROWSER: {EvidenceKind.BROWSER, EvidenceKind.SCREENSHOT},
    GateKind.DATABASE: {EvidenceKind.DATABASE},
    GateKind.GL: {EvidenceKind.GL, EvidenceKind.DATABASE},
    GateKind.API: {EvidenceKind.API, EvidenceKind.LOG},
    GateKind.EXPORT: {EvidenceKind.EXPORT, EvidenceKind.DOCUMENT},
}


class GateProof(DomainModel):
    gate: GateKind
    result: GateResult
    summary: NonEmptyString
    evidence: Tuple[EvidenceRef, ...] = ()

    @model_validator(mode="after")
    def require_evidence_for_observed_results(self) -> GateProof:
        if self.result in (GateResult.PASS, GateResult.FAIL) and not self.evidence:
            raise ValueError("passing and failing gate proofs require attached evidence")
        allowed_kinds = _GATE_EVIDENCE_KINDS[self.gate]
        incompatible = [
            evidence.kind for evidence in self.evidence if evidence.kind not in allowed_kinds
        ]
        if incompatible:
            raise ValueError(
                "%s gate proof contains incompatible evidence kinds: %s"
                % (
                    self.gate.value,
                    ", ".join(sorted(kind.value for kind in set(incompatible))),
                )
            )
        return self


class TestHandoff(DomainModel):
    schema_version: Literal[1] = 1
    item_id: NonEmptyString
    outcome: TestOutcome
    summary: NonEmptyString
    gate_proofs: Tuple[GateProof, ...] = ()
    failure_summary: Optional[NonEmptyString] = None
    blocker: Optional[Blocker] = None

    @model_validator(mode="after")
    def validate_outcome(self) -> TestHandoff:
        proof_gates = [proof.gate for proof in self.gate_proofs]
        if len(set(proof_gates)) != len(proof_gates):
            raise ValueError("a test handoff may include only one proof per gate")

        failed_proofs = [proof for proof in self.gate_proofs if proof.result == GateResult.FAIL]
        if self.outcome == TestOutcome.PASS:
            if not self.gate_proofs:
                raise ValueError("a passing test handoff requires gate proofs")
            if failed_proofs:
                raise ValueError("a passing test handoff cannot contain failed gates")
            if self.failure_summary is not None or self.blocker is not None:
                raise ValueError("a passing test handoff cannot contain failure or blocker data")
        elif self.outcome == TestOutcome.RED:
            if not failed_proofs:
                raise ValueError("a red test handoff requires at least one failed gate proof")
            if self.failure_summary is None:
                raise ValueError("a red test handoff requires a failure summary")
            if self.blocker is not None:
                raise ValueError("a red test handoff cannot also be blocked")
        elif self.outcome == TestOutcome.BLOCKED:
            if self.blocker is None:
                raise ValueError("a blocked test handoff requires a concrete blocker")
            if failed_proofs or self.failure_summary is not None:
                raise ValueError("a blocked test handoff cannot also report a red result")
        return self


class GateEvaluation(DomainModel):
    decision: GateDecision
    next_state: Optional[ItemState]
    missing_gates: Tuple[GateKind, ...] = ()
    failed_gates: Tuple[GateKind, ...] = ()
    inapplicable_required_gates: Tuple[GateKind, ...] = ()
    reasons: Tuple[NonEmptyString, ...] = ()

    @property
    def can_advance(self) -> bool:
        return self.next_state is not None


def evaluate_test_handoff(
    required_gates: Iterable[GateKind], handoff: TestHandoff
) -> GateEvaluation:
    """Evaluate untrusted tester output without mutating persisted state.

    ``PASS`` means only that the tester believes the item passed.  Green is
    emitted here only when every item-specific required gate has a passing
    proof.  ``GateProof`` separately guarantees that every pass/fail has at
    least one evidence reference.
    """

    required = tuple(required_gates)
    if not required:
        return GateEvaluation(
            decision=GateDecision.REJECTED,
            next_state=None,
            reasons=("an item must define at least one required evidence gate",),
        )
    if len(set(required)) != len(required):
        return GateEvaluation(
            decision=GateDecision.REJECTED,
            next_state=None,
            reasons=("required evidence gates must be unique",),
        )

    if handoff.outcome == TestOutcome.BLOCKED:
        return GateEvaluation(
            decision=GateDecision.BLOCKED,
            next_state=ItemState.BLOCKED,
            reasons=(handoff.blocker.summary,),  # type: ignore[union-attr]
        )

    proof_by_gate = {proof.gate: proof for proof in handoff.gate_proofs}
    failed = tuple(proof.gate for proof in handoff.gate_proofs if proof.result == GateResult.FAIL)

    if handoff.outcome == TestOutcome.RED:
        failed_required = tuple(gate for gate in required if gate in failed)
        if not failed_required:
            return GateEvaluation(
                decision=GateDecision.REJECTED,
                next_state=None,
                failed_gates=failed,
                reasons=("a red result must fail at least one item-required gate",),
            )
        return GateEvaluation(
            decision=GateDecision.RETURN_TO_FIX,
            next_state=ItemState.READY_FOR_FIX,
            failed_gates=failed_required,
            reasons=(handoff.failure_summary,),  # type: ignore[arg-type]
        )

    missing = tuple(gate for gate in required if gate not in proof_by_gate)
    inapplicable = tuple(
        gate
        for gate in required
        if gate in proof_by_gate and proof_by_gate[gate].result == GateResult.NOT_APPLICABLE
    )
    failed_required = tuple(
        gate
        for gate in required
        if gate in proof_by_gate and proof_by_gate[gate].result == GateResult.FAIL
    )

    if missing or inapplicable or failed_required:
        reasons = []
        if missing:
            reasons.append(
                "missing proof for required gates: " + ", ".join(g.value for g in missing)
            )
        if inapplicable:
            reasons.append(
                "required gates cannot be marked not applicable: "
                + ", ".join(g.value for g in inapplicable)
            )
        if failed_required:
            reasons.append("required gates failed: " + ", ".join(g.value for g in failed_required))
        return GateEvaluation(
            decision=GateDecision.REJECTED,
            next_state=None,
            missing_gates=missing,
            failed_gates=failed_required,
            inapplicable_required_gates=inapplicable,
            reasons=tuple(reasons),
        )

    return GateEvaluation(
        decision=GateDecision.VERIFIED_GREEN,
        next_state=ItemState.VERIFIED_GREEN,
        reasons=("all required evidence gates passed with attached evidence",),
    )
