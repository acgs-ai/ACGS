"""Security semantics for non-executable tri-state conformance."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from agent_bus_analyzer.process_mining._canonical import sha256_canonical
from agent_bus_analyzer.process_mining.integrations.gove_zone import (
    VerificationStatus,
    attach_receipt_verification,
    build_production_conformance_provider,
    build_public_receipt_verifier,
    load_public_decision_receipt,
    verify_with_public_receipt_verifier,
)
from agent_bus_analyzer.process_mining.miners.conformance import (
    CaptureState,
    ConformanceAttestation,
    ConformanceEvidence,
    ConformanceOutcome,
    ConformanceReason,
    CorrelationState,
    EvidenceReference,
    EvidenceReferenceType,
    EvidenceState,
    ProofStatus,
    ReproducibilityStatus,
    SideEffectState,
    VerificationCheck,
    VerificationComponent,
    attest_conformance,
    evaluate_conformance,
    hash_only_evidence_from_event,
)
from agent_bus_analyzer.process_mining.schemas.process_event import (
    GovernanceContext,
    GovernanceDecision,
    ProcessEvent,
    ProcessEventKind,
    build_process_event,
)
from tests.test_process_discovery_support import (
    HASH_A,
    HASH_B,
    HASH_C,
    HASH_D,
    governance_complete,
    make_event,
)


def _evidence(**updates: object) -> ConformanceEvidence:
    data: dict[str, object] = {
        "tenant_id": "tenant-A",
        "case_id": "case-1",
        "event_id": "event-1",
        "event_normalization_hash": HASH_A,
        "observed_action": "runtime.file.write",
        "observed_argument_hash": HASH_B,
        "observed_audit_hash": HASH_C,
        "observed_actor": "agent-1",
        "observed_execution_boundary": "local-sandbox",
        "observed_policy_bundle_id": "policy-bundle",
        "observed_policy_hash": HASH_D,
        "side_effect_state": SideEffectState.EXECUTED,
        "capture_state": CaptureState.COMPLETE,
        "correlation_state": CorrelationState.EXACT,
        "governance_decision": GovernanceDecision.ALLOW,
        "receipt": EvidenceState.VERIFIED,
        "policy": EvidenceState.VERIFIED,
        "audit": EvidenceState.VERIFIED,
        "authority": EvidenceState.VERIFIED,
        "signature": EvidenceState.VERIFIED,
        "source_chain": EvidenceState.VERIFIED,
        "replay": EvidenceState.VERIFIED,
        "evidence_bundle": EvidenceState.VERIFIED,
        "authoritative_verification": True,
        "verifier_name": "gove_zone.ReceiptVerifier",
        "verifier_signature_required": True,
        "verifier_expiry_required": True,
        "production_profile_verified": True,
        "evidence_references": ("audit-1", "receipt-1"),
    }
    data.update(updates)
    if (
        data["authoritative_verification"] is False
        or data["signature"] is not EvidenceState.VERIFIED
        or data["verifier_expiry_required"] is False
    ):
        data["production_profile_verified"] = False
    return ConformanceEvidence.model_validate(data)


def _production_receipt_material(
    governance_decision: GovernanceDecision = GovernanceDecision.ALLOW,
) -> tuple[object, object, dict[str, object]]:
    gove_zone = pytest.importorskip("gove_zone")
    args: dict[str, object] = {"path": "safe.txt"}
    try:
        signer = gove_zone.Ed25519Signer.from_private_bytes(
            hashlib.sha256(b"gove-zone fixture corpus v1 :: trusted").digest(),
            key_id="fixture-key-1",
        )
    except gove_zone.SigningError as exc:
        if "crypto" in str(exc):
            pytest.skip("requires the optional gove-zone[crypto] verification extra")
        raise
    record = gove_zone.DecisionRecord(
        decision=getattr(gove_zone.Decision, governance_decision.name),
        tool="runtime.file.write",
        argument_hash=gove_zone.sha256_json(args),
        policy_version="v1",
        event_id="receipt-production-1",
        actor="agent-1",
        timestamp_iso="2026-01-01T00:00:00+00:00",
    )
    receipt = gove_zone.DecisionReceipt.from_record(
        record=record,
        audit_hash=HASH_C,
        previous_audit_hash=HASH_B,
        tenant_id="tenant-A",
        execution_boundary="local-sandbox",
        policy_bundle_id="policy-bundle",
        policy_hash=HASH_D,
        request_id="request-production-1",
        validator=gove_zone.Validator("constitutional-council"),
        authority="tenant-A/write-grant",
        expires_at="2030-01-01T00:00:00+00:00",
        signer=signer,
    )
    verifier = build_public_receipt_verifier(
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_actor="agent-1",
        expected_policy_bundle_id="policy-bundle",
        expected_policy_hash=HASH_D,
        verifier=signer,
        require_signature=True,
        require_expiry=True,
    )
    return receipt, verifier, args


def _production_verified_evidence() -> ConformanceEvidence:
    receipt, verifier, args = _production_receipt_material()
    verification = verify_with_public_receipt_verifier(
        verifier,
        receipt,
        expected_action="runtime.file.write",
        expected_args=args,
        expected_audit_hash=HASH_C,
        expected_actor="agent-1",
        event_normalization_hash=HASH_A,
        now_iso="2026-01-02T00:00:00+00:00",
    )
    return attach_receipt_verification(
        _evidence(
            receipt=EvidenceState.HASH_ONLY,
            signature=EvidenceState.UNAVAILABLE,
            authoritative_verification=False,
            observed_argument_hash=receipt.argument_hash,
        ),
        verification,
    )


def _production_attestation() -> ConformanceAttestation:
    return attest_conformance(_production_verified_evidence())


def _production_event_material(
    governance_decision: GovernanceDecision = GovernanceDecision.ALLOW,
) -> tuple[
    ProcessEvent,
    ConformanceEvidence,
    object,
    object,
    dict[str, object],
]:
    receipt, verifier, args = _production_receipt_material(governance_decision)
    governance = GovernanceContext(
        is_side_effect=True,
        actor_authority_id=receipt.authority,
        tool_name=receipt.proposed_action,
        argument_hash=receipt.argument_hash,
        decision=governance_decision,
        policy_id="policy-1",
        policy_bundle_id=receipt.policy_bundle_id,
        policy_version=receipt.policy_version,
        policy_hash=receipt.policy_hash,
        execution_boundary=receipt.execution_boundary,
        decision_receipt_id=receipt.receipt_id,
        decision_receipt_hash=receipt.receipt_hash,
        evidence_bundle_ids=("evidence-1",),
        audit_event_id="audit-1",
        audit_event_hash=receipt.audit_event_hash,
        replay_verified=True,
    )
    event = make_event(
        event_id="event-production-1",
        case_id="case-production-1",
        sequence=0,
        minute=0,
        activity="Execute governed write",
        kind=ProcessEventKind.TOOL_RESULT,
        governance=governance,
    )
    evidence_payload = hash_only_evidence_from_event(
        event,
        side_effect_state=SideEffectState.EXECUTED,
    ).model_dump(mode="python")
    evidence_payload.update(
        {
            "policy": EvidenceState.VERIFIED,
            "audit": EvidenceState.VERIFIED,
            "authority": EvidenceState.VERIFIED,
            "evidence_bundle": EvidenceState.VERIFIED,
        }
    )
    evidence = ConformanceEvidence.model_validate(evidence_payload)
    return event, evidence, receipt, verifier, args


def _supplemental_proof_checks(
    event: ProcessEvent,
    _evidence: ConformanceEvidence,
    verification: object,
) -> tuple[VerificationCheck, ...]:
    if not getattr(verification, "verified", False):
        return ()
    if event.governance.replay_verified is not True:
        return ()
    if not event.governance.evidence_bundle_ids:
        return ()
    return (
        VerificationCheck(
            component=VerificationComponent.EVIDENCE_BUNDLE,
            check_name="test.evidence_bundle.complete",
            verifier_name="test.EvidenceBundleVerifier",
            verifier_version="1.0",
            evidence_hash=sha256_canonical(event.governance.evidence_bundle_ids),
        ),
        VerificationCheck(
            component=VerificationComponent.REPLAY,
            check_name="test.replay_store.verify",
            verifier_name="test.ReplayVerifier",
            verifier_version="1.0",
            evidence_hash=sha256_canonical({"event_id": event.event_id, "replay_verified": True}),
        ),
    )


def test_caller_asserted_complete_evidence_remains_non_authoritative() -> None:
    finding = evaluate_conformance(_evidence())
    assert finding.outcome is ConformanceOutcome.INVESTIGATE
    assert finding.proof_status is ProofStatus.ASSERTED
    assert finding.reproducibility is ReproducibilityStatus.UNKNOWN
    assert finding.receipt_verifier_succeeded is False
    assert finding.production_profile_verified is False
    assert finding.analytical_only is True
    assert finding.executable_authority is False
    assert finding.model_dump(mode="json")["outcome"] == "INVESTIGATE"


def test_plain_caller_claims_cannot_forge_production_allow() -> None:
    """Regression: caller-controlled VERIFIED booleans are assertions, not proof."""
    evidence = _evidence()

    finding = evaluate_conformance(evidence)
    attestation = attest_conformance(evidence)

    assert finding.outcome is ConformanceOutcome.INVESTIGATE
    assert finding.proof_status is ProofStatus.ASSERTED
    assert finding.receipt_verifier_succeeded is False
    assert finding.production_profile_verified is False
    assert finding.reasons == (ConformanceReason.ASSERTED_EVIDENCE_UNVERIFIED,)
    assert attestation.finding == finding
    assert attestation.verification_checks == ()
    assert attestation.seal is None


def test_unsigned_dev_assertion_is_investigate_not_production_proof() -> None:
    finding = evaluate_conformance(
        _evidence(
            signature=EvidenceState.NOT_REQUIRED,
            signature_required=False,
            verifier_signature_required=False,
            verifier_expiry_required=False,
        )
    )
    assert finding.outcome is ConformanceOutcome.INVESTIGATE
    assert finding.proof_status is ProofStatus.ASSERTED
    assert finding.production_profile_verified is False
    assert finding.reasons == (ConformanceReason.ASSERTED_EVIDENCE_UNVERIFIED,)


@pytest.mark.parametrize(
    "component",
    ["receipt", "policy", "audit", "authority", "source_chain"],
)
def test_always_required_components_reject_not_required(component: str) -> None:
    with pytest.raises(ValueError, match="always required"):
        _evidence(
            **{
                component: EvidenceState.NOT_REQUIRED,
                "authoritative_verification": False,
            }
        )


@pytest.mark.parametrize(
    ("field", "state", "reason"),
    [
        ("receipt", EvidenceState.MISSING, ConformanceReason.RECEIPT_MISSING),
        ("receipt", EvidenceState.INVALID, ConformanceReason.RECEIPT_INVALID),
        ("policy", EvidenceState.MISSING, ConformanceReason.POLICY_MISSING),
        ("policy", EvidenceState.INVALID, ConformanceReason.POLICY_INVALID),
        ("audit", EvidenceState.MISSING, ConformanceReason.AUDIT_MISSING),
        ("audit", EvidenceState.INVALID, ConformanceReason.AUDIT_INVALID),
        ("authority", EvidenceState.MISSING, ConformanceReason.AUTHORITY_MISSING),
        ("authority", EvidenceState.INVALID, ConformanceReason.AUTHORITY_INVALID),
        ("signature", EvidenceState.MISSING, ConformanceReason.SIGNATURE_MISSING),
        ("signature", EvidenceState.INVALID, ConformanceReason.SIGNATURE_INVALID),
        ("source_chain", EvidenceState.MISSING, ConformanceReason.SOURCE_CHAIN_MISSING),
        ("source_chain", EvidenceState.INVALID, ConformanceReason.SOURCE_CHAIN_INVALID),
        ("replay", EvidenceState.MISSING, ConformanceReason.REPLAY_MISSING),
        ("replay", EvidenceState.INVALID, ConformanceReason.REPLAY_INVALID),
        (
            "evidence_bundle",
            EvidenceState.MISSING,
            ConformanceReason.EVIDENCE_BUNDLE_MISSING,
        ),
        (
            "evidence_bundle",
            EvidenceState.INVALID,
            ConformanceReason.EVIDENCE_BUNDLE_INVALID,
        ),
    ],
)
def test_confirmed_side_effect_with_complete_capture_and_bad_proof_denies(
    field: str,
    state: EvidenceState,
    reason: ConformanceReason,
) -> None:
    updates: dict[str, object] = {field: state}
    if field == "receipt":
        updates["authoritative_verification"] = False
    finding = evaluate_conformance(_evidence(**updates))
    assert finding.outcome is ConformanceOutcome.DENY
    assert reason in finding.reasons


@pytest.mark.parametrize(
    "updates",
    [
        {"capture_state": CaptureState.INCOMPLETE},
        {"capture_state": CaptureState.INGEST_GAP},
        {"correlation_state": CorrelationState.AMBIGUOUS},
        {"receipt": EvidenceState.HASH_ONLY, "authoritative_verification": False},
        {"signature": EvidenceState.UNAVAILABLE},
        {"side_effect_state": SideEffectState.UNKNOWN},
    ],
)
def test_uncertain_or_hash_only_evidence_investigates(updates: dict[str, object]) -> None:
    assert evaluate_conformance(_evidence(**updates)).outcome is ConformanceOutcome.INVESTIGATE


def test_explicit_invalid_binding_is_not_masked_by_an_unavailable_check() -> None:
    finding = evaluate_conformance(
        _evidence(policy=EvidenceState.INVALID, signature=EvidenceState.UNAVAILABLE)
    )
    assert finding.outcome is ConformanceOutcome.DENY
    assert finding.reasons == (ConformanceReason.POLICY_INVALID,)


def test_missing_receipt_is_not_masked_by_unavailable_signature_check() -> None:
    finding = evaluate_conformance(
        _evidence(
            receipt=EvidenceState.MISSING,
            signature=EvidenceState.UNAVAILABLE,
            authoritative_verification=False,
        )
    )
    assert finding.outcome is ConformanceOutcome.DENY
    assert finding.reasons == (ConformanceReason.RECEIPT_MISSING,)


def test_hash_only_receipt_with_unavailable_signature_remains_investigate() -> None:
    finding = evaluate_conformance(
        _evidence(
            receipt=EvidenceState.HASH_ONLY,
            signature=EvidenceState.UNAVAILABLE,
            authoritative_verification=False,
        )
    )
    assert finding.outcome is ConformanceOutcome.INVESTIGATE
    assert ConformanceReason.HASH_ONLY_EVIDENCE in finding.reasons


@pytest.mark.parametrize(
    "decision",
    [GovernanceDecision.DENY, GovernanceDecision.ESCALATE],
)
def test_blocked_deny_or_escalate_is_a_compliant_control_outcome(
    decision: GovernanceDecision,
) -> None:
    evidence = _evidence(
        side_effect_state=SideEffectState.BLOCKED,
        governance_decision=decision,
        receipt=EvidenceState.MISSING,
        signature=EvidenceState.MISSING,
        replay=EvidenceState.NOT_REQUIRED,
        evidence_bundle=EvidenceState.NOT_REQUIRED,
        replay_required=False,
        evidence_bundle_required=False,
        authoritative_verification=False,
    )
    finding = evaluate_conformance(evidence)
    assert finding.outcome is ConformanceOutcome.ALLOW
    assert finding.reasons == (ConformanceReason.CONTROL_EFFECTIVE,)
    assert finding.receipt_verifier_succeeded is False


@pytest.mark.parametrize(
    ("decision", "reason"),
    [
        (GovernanceDecision.DENY, ConformanceReason.DENIED_ACTION_EXECUTED),
        (GovernanceDecision.ESCALATE, ConformanceReason.ESCALATED_ACTION_EXECUTED),
    ],
)
def test_executed_deny_or_escalate_is_nonconformant(
    decision: GovernanceDecision,
    reason: ConformanceReason,
) -> None:
    finding = evaluate_conformance(
        _evidence(
            governance_decision=decision,
            receipt=EvidenceState.INVALID,
            authoritative_verification=False,
        )
    )
    assert finding.outcome is ConformanceOutcome.DENY
    assert finding.reasons == (reason,)


def test_event_identifiers_are_only_hash_references_not_authoritative_proof() -> None:
    event = make_event(
        event_id="event-hash-only",
        case_id="case-1",
        sequence=0,
        minute=0,
        activity="Write",
        governance=governance_complete(),
    )
    evidence = hash_only_evidence_from_event(
        event,
        side_effect_state=SideEffectState.EXECUTED,
    )
    finding = evaluate_conformance(evidence)
    assert finding.outcome is ConformanceOutcome.INVESTIGATE
    assert finding.proof_status is ProofStatus.HASH_ONLY
    assert finding.receipt_verifier_succeeded is False


def test_evidence_references_preserve_shared_receipt_and_audit_event_id() -> None:
    shared_id = "ev_shared_receipt_audit_binding"
    governance = governance_complete().model_copy(
        update={
            "decision_receipt_id": shared_id,
            "audit_event_id": shared_id,
        }
    )
    event = make_event(
        event_id="event-shared-governance-id",
        case_id="case-1",
        sequence=0,
        minute=0,
        activity="Write",
        governance=governance,
    )

    evidence = hash_only_evidence_from_event(
        event,
        side_effect_state=SideEffectState.EXECUTED,
    )

    assert all(
        isinstance(reference, EvidenceReference) for reference in evidence.evidence_references
    )
    assert (
        EvidenceReference(
            reference_type=EvidenceReferenceType.RECEIPT_ID,
            reference_id=shared_id,
        )
        in evidence.evidence_references
    )
    assert (
        EvidenceReference(
            reference_type=EvidenceReferenceType.AUDIT_EVENT_ID,
            reference_id=shared_id,
        )
        in evidence.evidence_references
    )


def test_attestation_binds_event_identity_and_deterministic_finding() -> None:
    attestation = _production_attestation()
    assert attestation.finding.event_normalization_hash == HASH_A
    assert attestation.finding == evaluate_conformance(attestation.evidence)
    forged = attestation.finding.model_copy(update={"event_normalization_hash": HASH_B})
    with pytest.raises(ValueError, match="identity do not match"):
        ConformanceAttestation(evidence=attestation.evidence, finding=forged)
    altered = attestation.finding.model_copy(update={"outcome": ConformanceOutcome.DENY})
    with pytest.raises(ValueError, match="deterministic evidence result"):
        ConformanceAttestation(evidence=attestation.evidence, finding=altered)


def test_public_gove_zone_adapter_preserves_real_machine_reason_code() -> None:
    pytest.importorskip("gove_zone")
    fixture = (
        Path(__file__).resolve().parents[2]
        / "gove-zone/tests/fixtures/receipts/valid-allow-unsigned-dev/receipt.json"
    )
    receipt = load_public_decision_receipt(fixture.read_text(encoding="utf-8"))
    verifier = build_public_receipt_verifier(
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_actor="agent-1",
        require_signature=False,
    )
    rejected = verify_with_public_receipt_verifier(
        verifier,
        receipt,
        expected_action="runtime.file.write",
        expected_args={"path": "safe.txt"},
        expected_audit_hash="audit_hash",
        expected_actor="intruder",
        event_normalization_hash=HASH_A,
    )
    assert rejected.status is VerificationStatus.INVALID
    assert rejected.reason_code == "ACTOR_MISMATCH"

    attached = attach_receipt_verification(
        _evidence(
            receipt=EvidenceState.HASH_ONLY,
            authoritative_verification=False,
        ),
        rejected,
    )
    assert attached.receipt is EvidenceState.INVALID
    assert attached.verifier_reason_codes == ("ACTOR_MISMATCH",)
    assert evaluate_conformance(attached).outcome is ConformanceOutcome.DENY


@pytest.mark.parametrize(
    ("omitted", "reason_code"),
    [
        ("expected_action", "EXPECTED_ACTION_REQUIRED"),
        ("expected_args", "EXPECTED_ARGUMENTS_REQUIRED"),
        ("expected_audit_hash", "EXPECTED_AUDIT_HASH_REQUIRED"),
        ("expected_actor", "EXPECTED_ACTOR_REQUIRED"),
        ("event_normalization_hash", "EVENT_NORMALIZATION_HASH_REQUIRED"),
    ],
)
def test_public_verifier_never_verifies_with_an_omitted_binding(
    omitted: str,
    reason_code: str,
) -> None:
    pytest.importorskip("gove_zone")
    fixture = (
        Path(__file__).resolve().parents[2]
        / "gove-zone/tests/fixtures/receipts/valid-allow-unsigned-dev/receipt.json"
    )
    receipt = load_public_decision_receipt(fixture.read_text(encoding="utf-8"))
    verifier = build_public_receipt_verifier(
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_actor="agent-1",
        require_signature=False,
    )
    bindings: dict[str, object] = {
        "expected_action": "runtime.file.write",
        "expected_args": {"path": "safe.txt"},
        "expected_audit_hash": "audit_hash",
        "expected_actor": "agent-1",
        "event_normalization_hash": HASH_A,
    }
    del bindings[omitted]
    result = verify_with_public_receipt_verifier(verifier, receipt, **bindings)
    assert result.status is VerificationStatus.UNAVAILABLE
    assert result.reason_code == reason_code


def test_empty_expected_arguments_are_supplied_not_treated_as_omitted() -> None:
    receipt, verifier, _args = _production_receipt_material()
    result = verify_with_public_receipt_verifier(
        verifier,
        receipt,
        expected_action="runtime.file.write",
        expected_args={},
        expected_audit_hash=HASH_C,
        expected_actor="agent-1",
        event_normalization_hash=HASH_A,
        now_iso="2026-01-02T00:00:00+00:00",
    )
    assert result.status is VerificationStatus.INVALID
    assert result.reason_code == "ARGUMENT_MISMATCH"


@pytest.mark.parametrize(
    ("overrides", "reason_code"),
    [
        ({"event_normalization_hash": HASH_B}, "EVENT_NORMALIZATION_HASH_MISMATCH"),
        ({"tenant_id": "tenant-B"}, "TENANT_MISMATCH"),
        ({"observed_execution_boundary": "other"}, "EXECUTION_BOUNDARY_MISMATCH"),
        ({"observed_policy_bundle_id": "other"}, "POLICY_BUNDLE_MISMATCH"),
        ({"observed_policy_hash": HASH_B}, "POLICY_HASH_MISMATCH"),
        ({"observed_action": "runtime.file.delete"}, "ACTION_MISMATCH"),
        ({"observed_argument_hash": HASH_B}, "ARGUMENT_HASH_MISMATCH"),
        ({"observed_audit_hash": HASH_B}, "AUDIT_HASH_MISMATCH"),
        ({"observed_actor": "intruder"}, "ACTOR_MISMATCH"),
    ],
)
def test_verified_receipt_cannot_attach_to_detached_event_bindings(
    overrides: dict[str, object],
    reason_code: str,
) -> None:
    receipt, verifier, args = _production_receipt_material()
    verification = verify_with_public_receipt_verifier(
        verifier,
        receipt,
        expected_action="runtime.file.write",
        expected_args=args,
        expected_audit_hash=HASH_C,
        expected_actor="agent-1",
        event_normalization_hash=HASH_A,
        now_iso="2026-01-02T00:00:00+00:00",
    )
    evidence_updates: dict[str, object] = {
        "receipt": EvidenceState.HASH_ONLY,
        "signature": EvidenceState.UNAVAILABLE,
        "authoritative_verification": False,
        "observed_argument_hash": receipt.argument_hash,
    }
    evidence_updates.update(overrides)
    attached = attach_receipt_verification(_evidence(**evidence_updates), verification)
    assert attached.authoritative_verification is False
    assert attached.receipt is EvidenceState.INVALID
    assert reason_code in attached.verifier_reason_codes
    assert evaluate_conformance(attached).outcome is ConformanceOutcome.DENY


def test_production_profile_requires_signature_and_expiry() -> None:
    attestation = _production_attestation()
    assert attestation.finding.outcome is ConformanceOutcome.INVESTIGATE
    assert attestation.finding.proof_status is ProofStatus.ASSERTED
    assert attestation.finding.production_profile_verified is False

    pytest.importorskip("gove_zone")
    unsigned_fixture = (
        Path(__file__).resolve().parents[2]
        / "gove-zone/tests/fixtures/receipts/valid-allow-unsigned-dev/receipt.json"
    )
    receipt = load_public_decision_receipt(unsigned_fixture.read_text(encoding="utf-8"))
    dev_verifier = build_public_receipt_verifier(
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_actor="agent-1",
        require_signature=False,
        require_expiry=False,
    )
    dev_result = verify_with_public_receipt_verifier(
        dev_verifier,
        receipt,
        expected_action="runtime.file.write",
        expected_args={"path": "safe.txt"},
        expected_audit_hash="audit_hash",
        expected_actor="agent-1",
        event_normalization_hash=HASH_A,
    )
    assert dev_result.status is VerificationStatus.VERIFIED
    assert dev_result.signature_verified is False
    assert dev_result.production_profile_verified is False

    signed_fixture = (
        Path(__file__).resolve().parents[2]
        / "gove-zone/tests/fixtures/receipts/valid-allow-signed/receipt.json"
    )
    signed_receipt = load_public_decision_receipt(signed_fixture.read_text(encoding="utf-8"))
    gove_zone = pytest.importorskip("gove_zone")
    signer = gove_zone.Ed25519Signer.from_private_bytes(
        hashlib.sha256(b"gove-zone fixture corpus v1 :: trusted").digest(),
        key_id="fixture-key-1",
    )
    signed_nonexpiring_verifier = build_public_receipt_verifier(
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_actor="agent-1",
        verifier=signer,
        require_signature=True,
        require_expiry=False,
    )
    signed_nonexpiring = verify_with_public_receipt_verifier(
        signed_nonexpiring_verifier,
        signed_receipt,
        expected_action="runtime.file.write",
        expected_args={"path": "safe.txt"},
        expected_audit_hash="audit_hash",
        expected_actor="agent-1",
        event_normalization_hash=HASH_A,
    )
    assert signed_nonexpiring.status is VerificationStatus.VERIFIED
    assert signed_nonexpiring.signature_verified is True
    assert signed_nonexpiring.production_profile_verified is False

    strict_verifier = build_public_receipt_verifier(
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_actor="agent-1",
        verifier=signer,
        require_signature=True,
        require_expiry=True,
    )
    rejected_nonexpiring = verify_with_public_receipt_verifier(
        strict_verifier,
        signed_receipt,
        expected_action="runtime.file.write",
        expected_args={"path": "safe.txt"},
        expected_audit_hash="audit_hash",
        expected_actor="agent-1",
        event_normalization_hash=HASH_A,
    )
    assert rejected_nonexpiring.status is VerificationStatus.INVALID
    assert rejected_nonexpiring.reason_code == "EXPIRY_REQUIRED"


def test_production_provider_refuses_missing_or_nonproduction_verifier() -> None:
    pytest.importorskip("gove_zone")

    def resolver(_event: ProcessEvent) -> None:
        return None

    def evidence_resolver(_event: ProcessEvent) -> ConformanceEvidence:
        return _evidence(
            authoritative_verification=False,
            receipt=EvidenceState.MISSING,
        )

    with pytest.raises(TypeError, match=r"gove_zone\.ReceiptVerifier"):
        build_production_conformance_provider(
            verifier=object(),
            receipt_resolver=resolver,
            arguments_resolver=resolver,
            evidence_resolver=evidence_resolver,
        )

    dev_verifier = build_public_receipt_verifier(
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_actor="agent-1",
        expected_policy_bundle_id="policy-bundle",
        expected_policy_hash=HASH_D,
        require_signature=False,
        require_expiry=False,
    )
    with pytest.raises(ValueError, match="signature verification"):
        build_production_conformance_provider(
            verifier=dev_verifier,
            receipt_resolver=resolver,
            arguments_resolver=resolver,
            evidence_resolver=evidence_resolver,
        )


def test_production_provider_is_event_bound_and_runtime_fail_closed() -> None:
    event, evidence, receipt, verifier, args = _production_event_material()
    provider = build_production_conformance_provider(
        verifier=verifier,
        receipt_resolver=lambda _event: receipt,
        arguments_resolver=lambda _event: args,
        evidence_resolver=lambda _event: evidence,
        supplemental_check_resolver=_supplemental_proof_checks,
        attestation_secret=b"A" * 32,
        attestation_key_id="test-attestation-key",
        now_iso="2026-01-02T00:00:00+00:00",
    )
    attestation = provider(event)
    assert attestation.finding.outcome is ConformanceOutcome.ALLOW
    assert attestation.finding.production_profile_verified is True
    verification = provider.attestation_verifier(attestation)
    assert verification.verified is True
    assert verification.production_profile_verified is True

    tampered_checks = list(attestation.verification_checks)
    tampered_checks[0] = tampered_checks[0].model_copy(update={"evidence_hash": HASH_B})
    tampered = attestation.model_copy(update={"verification_checks": tuple(tampered_checks)})
    assert provider.attestation_verifier(tampered).verified is False

    assert attestation.seal is not None
    bad_seal = attestation.seal.model_copy(update={"digest": HASH_B})
    sealed_tamper = attestation.model_copy(update={"seal": bad_seal})
    assert provider.attestation_verifier(sealed_tamper).verified is False

    other_provider = build_production_conformance_provider(
        verifier=verifier,
        receipt_resolver=lambda _event: receipt,
        arguments_resolver=lambda _event: args,
        evidence_resolver=lambda _event: evidence,
        supplemental_check_resolver=_supplemental_proof_checks,
        attestation_secret=b"B" * 32,
        attestation_key_id="other-attestation-key",
        now_iso="2026-01-02T00:00:00+00:00",
    )
    assert other_provider.attestation_verifier(attestation).verified is False

    missing_supplemental = build_production_conformance_provider(
        verifier=verifier,
        receipt_resolver=lambda _event: receipt,
        arguments_resolver=lambda _event: args,
        evidence_resolver=lambda _event: evidence,
        attestation_secret=b"C" * 32,
        attestation_key_id="missing-proof-key",
        now_iso="2026-01-02T00:00:00+00:00",
    )(event)
    assert missing_supplemental.finding.outcome is ConformanceOutcome.INVESTIGATE
    assert missing_supplemental.finding.reasons == (ConformanceReason.VERIFICATION_CHECK_MISSING,)

    missing_args = build_production_conformance_provider(
        verifier=verifier,
        receipt_resolver=lambda _event: receipt,
        arguments_resolver=lambda _event: None,
        evidence_resolver=lambda _event: evidence,
        now_iso="2026-01-02T00:00:00+00:00",
    )(event)
    assert missing_args.finding.outcome is ConformanceOutcome.INVESTIGATE
    assert missing_args.finding.production_profile_verified is False

    detached = evidence.model_copy(update={"event_normalization_hash": HASH_B})
    detached_provider = build_production_conformance_provider(
        verifier=verifier,
        receipt_resolver=lambda _event: receipt,
        arguments_resolver=lambda _event: args,
        evidence_resolver=lambda _event: detached,
    )
    with pytest.raises(ValueError, match="detached from the normalized event"):
        detached_provider(event)


def test_sealed_deny_has_verified_proof_posture_but_never_authority() -> None:
    event, evidence, receipt, verifier, args = _production_event_material(GovernanceDecision.DENY)
    provider = build_production_conformance_provider(
        verifier=verifier,
        receipt_resolver=lambda _event: receipt,
        arguments_resolver=lambda _event: args,
        evidence_resolver=lambda _event: evidence,
        supplemental_check_resolver=_supplemental_proof_checks,
        attestation_secret=b"D" * 32,
        attestation_key_id="deny-attestation-key",
        now_iso="2026-01-02T00:00:00+00:00",
    )

    attestation = provider(event)
    verification = provider.attestation_verifier(attestation)

    assert attestation.finding.outcome is ConformanceOutcome.DENY
    assert attestation.finding.proof_status is ProofStatus.FAILED
    assert attestation.finding.production_profile_verified is False
    assert attestation.finding.executable_authority is False
    assert verification.verified is True
    assert verification.production_profile_verified is True

    tool_call_payload = event.model_dump(
        mode="python",
        exclude={"normalization_hash", "completeness"},
    )
    tool_call_payload["kind"] = ProcessEventKind.TOOL_CALL
    tool_call = build_process_event(tool_call_payload)
    tool_call_evidence = evidence.model_copy(
        update={
            "event_normalization_hash": tool_call.normalization_hash,
            "side_effect_state": SideEffectState.UNKNOWN,
        }
    )
    tool_call_provider = build_production_conformance_provider(
        verifier=verifier,
        receipt_resolver=lambda _event: receipt,
        arguments_resolver=lambda _event: args,
        evidence_resolver=lambda _event: tool_call_evidence,
        supplemental_check_resolver=_supplemental_proof_checks,
        attestation_secret=b"E" * 32,
        attestation_key_id="deny-tool-call-key",
        now_iso="2026-01-02T00:00:00+00:00",
    )
    tool_call_attestation = tool_call_provider(tool_call)
    assert tool_call_attestation.finding.outcome is ConformanceOutcome.DENY
    assert (
        tool_call_provider.attestation_verifier(tool_call_attestation).production_profile_verified
        is True
    )
