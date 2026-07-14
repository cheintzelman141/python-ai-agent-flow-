from datetime import timedelta

import pytest
from pydantic import ValidationError

from agent_flow.models import (
    Blocker,
    BlockerKind,
    Campaign,
    EvidenceKind,
    EvidenceRef,
    GateDecision,
    GateKind,
    GateProof,
    GateResult,
    ItemState,
    Job,
    JobStatus,
    TestHandoff as ValidatedHandoff,
    TestOutcome as RunOutcome,
    WorkerRole,
    evaluate_test_handoff,
    utc_now,
)


def evidence(kind: EvidenceKind, label: str) -> EvidenceRef:
    return EvidenceRef(
        kind=kind,
        location=f"/private/tmp/agent-flow-tests/{label}.txt",
        description=f"Evidence for {label}",
    )


def proof(gate: GateKind, kind: EvidenceKind) -> GateProof:
    return GateProof(
        gate=gate,
        result=GateResult.PASS,
        summary=f"{gate.value} passed",
        evidence=(evidence(kind, gate.value),),
    )


def test_evaluator_is_the_only_component_that_declares_verified_green() -> None:
    handoff = ValidatedHandoff(
        item_id="item-1",
        outcome=RunOutcome.PASS,
        summary="Tester observed all required workflows passing",
        gate_proofs=(
            proof(GateKind.FOCUSED_TESTS, EvidenceKind.TEST),
            proof(GateKind.BROWSER, EvidenceKind.SCREENSHOT),
            proof(GateKind.DATABASE, EvidenceKind.DATABASE),
        ),
    )

    assert "verified_green" not in {outcome.value for outcome in RunOutcome}
    result = evaluate_test_handoff(
        (GateKind.FOCUSED_TESTS, GateKind.BROWSER, GateKind.DATABASE), handoff
    )

    assert result.decision == GateDecision.VERIFIED_GREEN
    assert result.next_state == ItemState.VERIFIED_GREEN
    assert result.can_advance is True


def test_handoff_schema_version_rejects_unknown_contracts() -> None:
    with pytest.raises(ValidationError):
        ValidatedHandoff(
            schema_version=2,
            item_id="item-1",
            outcome=RunOutcome.PASS,
            summary="Unsupported future handoff",
            gate_proofs=(proof(GateKind.FOCUSED_TESTS, EvidenceKind.TEST),),
        )


def test_campaign_persists_validated_global_and_role_concurrency_policy() -> None:
    campaign = Campaign(name="Phase 1")

    assert campaign.global_concurrency_limit == 4
    assert campaign.role_concurrency_limits == {
        WorkerRole.INVESTIGATOR: 2,
        WorkerRole.FIXER: 2,
        WorkerRole.TESTER: 2,
    }

    with pytest.raises(ValidationError, match="positive"):
        Campaign(
            name="Invalid limits",
            role_concurrency_limits={
                WorkerRole.INVESTIGATOR: 2,
                WorkerRole.FIXER: 0,
                WorkerRole.TESTER: 2,
            },
        )


def test_missing_required_proof_is_rejected_without_advancing() -> None:
    handoff = ValidatedHandoff(
        item_id="item-1",
        outcome=RunOutcome.PASS,
        summary="Only tests were checked",
        gate_proofs=(proof(GateKind.FOCUSED_TESTS, EvidenceKind.TEST),),
    )

    result = evaluate_test_handoff(
        (GateKind.FOCUSED_TESTS, GateKind.BROWSER, GateKind.DATABASE), handoff
    )

    assert result.decision == GateDecision.REJECTED
    assert result.next_state is None
    assert result.missing_gates == (GateKind.BROWSER, GateKind.DATABASE)


def test_red_result_returns_item_to_fix_with_failure_evidence() -> None:
    handoff = ValidatedHandoff(
        item_id="item-1",
        outcome=RunOutcome.RED,
        summary="Exact browser workflow still fails",
        failure_summary="Save action leaves stale UI state",
        gate_proofs=(
            GateProof(
                gate=GateKind.BROWSER,
                result=GateResult.FAIL,
                summary="UI did not refresh after save",
                evidence=(evidence(EvidenceKind.SCREENSHOT, "browser-red"),),
            ),
        ),
    )

    result = evaluate_test_handoff((GateKind.BROWSER,), handoff)

    assert result.decision == GateDecision.RETURN_TO_FIX
    assert result.next_state == ItemState.READY_FOR_FIX
    assert result.failed_gates == (GateKind.BROWSER,)
    assert result.reasons == ("Save action leaves stale UI state",)


def test_optional_failed_gate_cannot_force_required_fix_loop() -> None:
    handoff = ValidatedHandoff(
        item_id="item-1",
        outcome=RunOutcome.RED,
        summary="An out-of-scope API check failed",
        failure_summary="Optional API endpoint returned an error",
        gate_proofs=(
            GateProof(
                gate=GateKind.API,
                result=GateResult.FAIL,
                summary="Optional API probe failed",
                evidence=(evidence(EvidenceKind.API, "optional-api-red"),),
            ),
        ),
    )

    result = evaluate_test_handoff((GateKind.BROWSER,), handoff)

    assert result.decision == GateDecision.REJECTED
    assert result.next_state is None
    assert result.failed_gates == (GateKind.API,)


def test_non_required_gate_can_be_not_applicable_without_blocking_green() -> None:
    handoff = ValidatedHandoff(
        item_id="item-1",
        outcome=RunOutcome.PASS,
        summary="Required gates passed; this item has no GL behavior",
        gate_proofs=(
            proof(GateKind.FOCUSED_TESTS, EvidenceKind.TEST),
            GateProof(
                gate=GateKind.GL,
                result=GateResult.NOT_APPLICABLE,
                summary="No financial or posting behavior is in scope",
            ),
        ),
    )

    result = evaluate_test_handoff((GateKind.FOCUSED_TESTS,), handoff)

    assert result.decision == GateDecision.VERIFIED_GREEN
    assert result.next_state == ItemState.VERIFIED_GREEN


def test_required_gate_cannot_be_not_applicable() -> None:
    handoff = ValidatedHandoff(
        item_id="item-1",
        outcome=RunOutcome.PASS,
        summary="Database proof was incorrectly treated as optional",
        gate_proofs=(
            proof(GateKind.FOCUSED_TESTS, EvidenceKind.TEST),
            GateProof(
                gate=GateKind.DATABASE,
                result=GateResult.NOT_APPLICABLE,
                summary="Database check was skipped",
            ),
        ),
    )

    result = evaluate_test_handoff((GateKind.FOCUSED_TESTS, GateKind.DATABASE), handoff)

    assert result.decision == GateDecision.REJECTED
    assert result.next_state is None
    assert result.inapplicable_required_gates == (GateKind.DATABASE,)


def test_blocked_result_requires_concrete_evidence_and_moves_to_blocked() -> None:
    handoff = ValidatedHandoff(
        item_id="item-1",
        outcome=RunOutcome.BLOCKED,
        summary="Fixture is absent",
        blocker=Blocker(
            kind=BlockerKind.EXECUTION,
            summary="Required tenant fixture does not exist",
            next_action="Provision the named fixture and rerun this tester attempt",
            evidence=(evidence(EvidenceKind.DATABASE, "missing-fixture"),),
        ),
    )

    result = evaluate_test_handoff((GateKind.DATABASE,), handoff)

    assert result.decision == GateDecision.BLOCKED
    assert result.next_state == ItemState.BLOCKED


@pytest.mark.parametrize(
    "handoff_data",
    [
        {
            "item_id": "item-1",
            "outcome": RunOutcome.PASS,
            "summary": "Claims pass without proof",
            "gate_proofs": (),
        },
        {
            "item_id": "item-1",
            "outcome": RunOutcome.RED,
            "summary": "Claims red without a failed gate",
            "failure_summary": "Failure claimed",
            "gate_proofs": (),
        },
        {
            "item_id": "item-1",
            "outcome": RunOutcome.BLOCKED,
            "summary": "Claims blocked without a concrete blocker",
            "gate_proofs": (),
        },
    ],
)
def test_inconsistent_test_handoffs_are_invalid(handoff_data: object) -> None:
    with pytest.raises(ValidationError):
        ValidatedHandoff.model_validate(handoff_data)


def test_gate_pass_or_failure_without_evidence_is_invalid() -> None:
    with pytest.raises(ValidationError, match="require attached evidence"):
        GateProof(
            gate=GateKind.BROWSER,
            result=GateResult.PASS,
            summary="Unsupported claim",
        )


def test_gate_proof_rejects_incompatible_generic_evidence() -> None:
    with pytest.raises(ValidationError, match="incompatible evidence kinds"):
        GateProof(
            gate=GateKind.BROWSER,
            result=GateResult.PASS,
            summary="A generic reference cannot prove visible browser behavior",
            evidence=(evidence(EvidenceKind.OTHER, "not-browser-proof"),),
        )


def test_job_claims_have_role_states_and_complete_lease_fences() -> None:
    expiry = utc_now() + timedelta(seconds=30)
    job = Job(
        campaign_id="campaign-1",
        item_id="item-1",
        role=WorkerRole.FIXER,
        status=JobStatus.LEASED,
        lease_token="claim-generation-2",
        lease_owner="fixer-2",
        lease_expires_at=expiry,
    )

    assert job.queued_item_state == ItemState.READY_FOR_FIX
    assert job.active_item_state == ItemState.FIXING

    with pytest.raises(ValidationError, match="complete lease fence"):
        Job(
            campaign_id="campaign-1",
            item_id="item-1",
            role=WorkerRole.FIXER,
            status=JobStatus.RUNNING,
        )
