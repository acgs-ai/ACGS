"""Fail-closed analytical conformance semantics.

These verdicts describe observed evidence only.  They are intentionally
incapable of authorizing a side effect and are not accepted by gove-zone's
executor gate as receipts.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_bus_analyzer.process_mining._canonical import sha256_canonical
from agent_bus_analyzer.process_mining.schemas.process_event import (
    GovernanceDecision,
    ProcessEvent,
    SourceChainStatus,
)

CONFORMANCE_ALGORITHM_VERSION: Literal["conformance-1.0"] = "conformance-1.0"
PUBLIC_RECEIPT_VERIFIER_NAME: Literal["gove_zone.ReceiptVerifier"] = "gove_zone.ReceiptVerifier"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_ALWAYS_REQUIRED_COMPONENTS: tuple[str, ...] = (
    "receipt",
    "policy",
    "audit",
    "authority",
    "source_chain",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ConformanceOutcome(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    INVESTIGATE = "INVESTIGATE"


class SideEffectState(StrEnum):
    EXECUTED = "executed"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class CaptureState(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    INGEST_GAP = "ingest_gap"


class CorrelationState(StrEnum):
    EXACT = "exact"
    AMBIGUOUS = "ambiguous"
    UNASSIGNED = "unassigned"


class EvidenceState(StrEnum):
    VERIFIED = "verified"
    INVALID = "invalid"
    MISSING = "missing"
    UNAVAILABLE = "unavailable"
    AMBIGUOUS = "ambiguous"
    HASH_ONLY = "hash_only"
    NOT_REQUIRED = "not_required"


class ConformanceReason(StrEnum):
    AUTHORITATIVE_EVIDENCE_VERIFIED = "authoritative_evidence_verified"
    AUTHORITATIVE_EVIDENCE_VERIFIED_NON_PRODUCTION = (
        "authoritative_evidence_verified_non_production"
    )
    CONTROL_EFFECTIVE = "control_effective"
    SIDE_EFFECT_STATUS_UNKNOWN = "side_effect_status_unknown"
    CAPTURE_INCOMPLETE = "capture_incomplete"
    INGEST_GAP = "ingest_gap"
    CORRELATION_AMBIGUOUS = "correlation_ambiguous"
    CORRELATION_UNASSIGNED = "correlation_unassigned"
    HASH_ONLY_EVIDENCE = "hash_only_evidence"
    VERIFIER_UNAVAILABLE = "verifier_unavailable"
    AUTHORITATIVE_VERIFICATION_MISSING = "authoritative_verification_missing"
    ASSERTED_EVIDENCE_UNVERIFIED = "asserted_evidence_unverified"
    VERIFICATION_CHECK_MISSING = "verification_check_missing"
    RECEIPT_MISSING = "receipt_missing"
    RECEIPT_INVALID = "receipt_invalid"
    POLICY_MISSING = "policy_missing"
    POLICY_INVALID = "policy_invalid"
    AUDIT_MISSING = "audit_missing"
    AUDIT_INVALID = "audit_invalid"
    AUTHORITY_MISSING = "authority_missing"
    AUTHORITY_INVALID = "authority_invalid"
    SIGNATURE_MISSING = "signature_missing"
    SIGNATURE_INVALID = "signature_invalid"
    SOURCE_CHAIN_MISSING = "source_chain_missing"
    SOURCE_CHAIN_INVALID = "source_chain_invalid"
    REPLAY_MISSING = "replay_missing"
    REPLAY_INVALID = "replay_invalid"
    EVIDENCE_BUNDLE_MISSING = "evidence_bundle_missing"
    EVIDENCE_BUNDLE_INVALID = "evidence_bundle_invalid"
    POLICY_DECISION_MISSING = "policy_decision_missing"
    DENIED_ACTION_EXECUTED = "denied_action_executed"
    ESCALATED_ACTION_EXECUTED = "escalated_action_executed"
    BLOCKED_CONTROL_UNVERIFIABLE = "blocked_control_unverifiable"


class ProofStatus(StrEnum):
    VERIFIED = "verified"
    NON_PRODUCTION = "non_production"
    ASSERTED = "asserted"
    FAILED = "failed"
    INCOMPLETE = "incomplete"
    UNAVAILABLE = "unavailable"
    HASH_ONLY = "hash_only"


class ReproducibilityStatus(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    UNKNOWN = "unknown"
    NOT_REQUIRED = "not_required"


class VerificationComponent(StrEnum):
    """Evidence components that must have an explicit named verification check."""

    EVENT_BINDING = "event_binding"
    RECEIPT = "receipt"
    POLICY = "policy"
    AUDIT = "audit"
    AUTHORITY = "authority"
    SIGNATURE = "signature"
    EXPIRY = "expiry"
    SOURCE_CHAIN = "source_chain"
    REPLAY = "replay"
    EVIDENCE_BUNDLE = "evidence_bundle"


class EvidenceReferenceType(StrEnum):
    """Semantic type of an authentic governance evidence identifier."""

    RECEIPT_ID = "receipt_id"
    RECEIPT_HASH = "receipt_hash"
    AUDIT_EVENT_ID = "audit_event_id"
    AUDIT_EVENT_HASH = "audit_event_hash"
    EVIDENCE_BUNDLE_ID = "evidence_bundle_id"


class EvidenceReference(_StrictModel):
    """Typed evidence binding; distinct semantics may share an authentic ID."""

    reference_type: EvidenceReferenceType
    reference_id: str = Field(min_length=1, max_length=512)


EvidenceReferenceValue = EvidenceReference | str


class VerificationCheck(_StrictModel):
    """Immutable provenance for one successful evidence verification."""

    component: VerificationComponent
    check_name: str = Field(min_length=1, max_length=256)
    verifier_name: str = Field(min_length=1, max_length=256)
    verifier_version: str = Field(min_length=1, max_length=128)
    evidence_hash: str = Field(pattern=_SHA256_PATTERN)


class AttestationSeal(_StrictModel):
    """Key-scoped integrity seal; validity is established only by its verifier."""

    algorithm: Literal["HMAC-SHA256"] = "HMAC-SHA256"
    issuer_id: str = Field(min_length=1, max_length=256)
    verifier_version: str = Field(min_length=1, max_length=128)
    key_id_hash: str = Field(pattern=_SHA256_PATTERN)
    digest: str = Field(pattern=_SHA256_PATTERN)


class AttestationVerificationResult(_StrictModel):
    """Result of independently verifying one canonical attestation body."""

    verified: bool
    production_profile_verified: bool
    verifier_name: str = Field(min_length=1, max_length=256)
    verifier_version: str = Field(min_length=1, max_length=128)
    attestation_hash: str = Field(pattern=_SHA256_PATTERN)
    key_id_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    reason_codes: tuple[str, ...] = ()

    @field_validator("reason_codes")
    @classmethod
    def require_stable_reasons(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("attestation verifier reasons must be sorted and unique")
        return value

    @model_validator(mode="after")
    def validate_success_posture(self) -> Self:
        if self.production_profile_verified and not self.verified:
            raise ValueError("production profile cannot be asserted by a failed verifier")
        if self.verified and self.reason_codes:
            raise ValueError("successful attestation verification cannot carry failure reasons")
        return self


class AttestationVerifier(Protocol):
    def __call__(
        self,
        attestation: ConformanceAttestation,
    ) -> AttestationVerificationResult: ...


class ConformanceEvidence(_StrictModel):
    """Strict evidence inputs kept separate from normalized event references."""

    tenant_id: str = Field(min_length=1, max_length=128)
    case_id: str = Field(min_length=1, max_length=512)
    event_id: str = Field(min_length=1, max_length=512)
    event_normalization_hash: str = Field(pattern=_SHA256_PATTERN)
    observed_action: str | None = Field(default=None, min_length=1, max_length=512)
    observed_argument_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    observed_audit_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    observed_actor: str | None = Field(default=None, min_length=1, max_length=512)
    observed_execution_boundary: str | None = Field(default=None, min_length=1, max_length=512)
    observed_policy_bundle_id: str | None = Field(default=None, min_length=1, max_length=512)
    observed_policy_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    side_effect_state: SideEffectState
    capture_state: CaptureState
    correlation_state: CorrelationState
    governance_decision: GovernanceDecision | None = None
    receipt: EvidenceState
    policy: EvidenceState
    audit: EvidenceState
    authority: EvidenceState
    signature: EvidenceState
    source_chain: EvidenceState
    replay: EvidenceState
    evidence_bundle: EvidenceState
    signature_required: bool = True
    replay_required: bool = True
    evidence_bundle_required: bool = True
    authoritative_verification: bool = False
    verifier_name: str | None = None
    verifier_signature_required: bool = False
    verifier_expiry_required: bool = False
    production_profile_verified: bool = False
    verifier_reason_codes: tuple[str, ...] = ()
    evidence_references: tuple[EvidenceReferenceValue, ...] = ()

    @field_validator("verifier_reason_codes")
    @classmethod
    def require_sorted_unique_reason_codes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or value != tuple(sorted(value)):
            raise ValueError("verifier reason codes must be sorted and unique")
        return value

    @field_validator("evidence_references")
    @classmethod
    def require_sorted_unique_evidence_references(
        cls,
        value: tuple[EvidenceReferenceValue, ...],
    ) -> tuple[EvidenceReferenceValue, ...]:
        keys = tuple(
            ("legacy", reference)
            if isinstance(reference, str)
            else (reference.reference_type.value, reference.reference_id)
            for reference in value
        )
        if len(keys) != len(set(keys)) or keys != tuple(sorted(keys)):
            raise ValueError("evidence references must be sorted and unique by type and identifier")
        return value

    @model_validator(mode="after")
    def validate_authoritative_claim(self) -> Self:
        for component in _ALWAYS_REQUIRED_COMPONENTS:
            if getattr(self, component) is EvidenceState.NOT_REQUIRED:
                raise ValueError(f"{component} is always required for conformance evidence")
        if self.authoritative_verification and self.receipt is not EvidenceState.VERIFIED:
            raise ValueError("authoritative verification requires a verified receipt")
        if self.authoritative_verification and self.verifier_name != PUBLIC_RECEIPT_VERIFIER_NAME:
            raise ValueError("authoritative verification requires gove_zone.ReceiptVerifier")
        if self.authoritative_verification and self.verifier_reason_codes:
            raise ValueError("successful authoritative verification cannot carry rejection codes")
        if self.authoritative_verification:
            observed_bindings = (
                self.observed_action,
                self.observed_argument_hash,
                self.observed_audit_hash,
                self.observed_actor,
                self.observed_execution_boundary,
                self.observed_policy_bundle_id,
                self.observed_policy_hash,
            )
            if any(value is None for value in observed_bindings):
                raise ValueError(
                    "authoritative verification requires complete observed event bindings"
                )
            if self.signature_required != self.verifier_signature_required:
                raise ValueError("signature requirement must match the public verifier posture")
        if self.production_profile_verified and not (
            self.authoritative_verification
            and self.verifier_signature_required
            and self.verifier_expiry_required
            and self.signature is EvidenceState.VERIFIED
        ):
            raise ValueError(
                "production profile proof requires signature, expiry, and public verification"
            )
        if not self.signature_required and self.signature is EvidenceState.MISSING:
            raise ValueError("an optional signature must be represented as not_required")
        if not self.replay_required and self.replay is EvidenceState.MISSING:
            raise ValueError("optional replay must be represented as not_required")
        if not self.evidence_bundle_required and self.evidence_bundle is EvidenceState.MISSING:
            raise ValueError("optional evidence bundle must be represented as not_required")
        return self


class ConformanceFinding(_StrictModel):
    tenant_id: str
    case_id: str
    event_id: str
    event_normalization_hash: str = Field(pattern=_SHA256_PATTERN)
    outcome: ConformanceOutcome
    proof_status: ProofStatus
    reproducibility: ReproducibilityStatus
    receipt_verifier_succeeded: bool
    verifier_name: str | None
    verifier_signature_required: bool
    verifier_expiry_required: bool
    production_profile_verified: bool
    reasons: tuple[ConformanceReason, ...]
    verifier_reason_codes: tuple[str, ...]
    evidence_references: tuple[EvidenceReferenceValue, ...]
    algorithm_version: Literal["conformance-1.0"] = CONFORMANCE_ALGORITHM_VERSION
    analytical_only: Literal[True] = True
    executable_authority: Literal[False] = False


_REQUIRED_COMPONENTS: tuple[tuple[str, ConformanceReason, ConformanceReason], ...] = (
    ("receipt", ConformanceReason.RECEIPT_MISSING, ConformanceReason.RECEIPT_INVALID),
    ("policy", ConformanceReason.POLICY_MISSING, ConformanceReason.POLICY_INVALID),
    ("audit", ConformanceReason.AUDIT_MISSING, ConformanceReason.AUDIT_INVALID),
    ("authority", ConformanceReason.AUTHORITY_MISSING, ConformanceReason.AUTHORITY_INVALID),
    (
        "source_chain",
        ConformanceReason.SOURCE_CHAIN_MISSING,
        ConformanceReason.SOURCE_CHAIN_INVALID,
    ),
)


def _finding(
    evidence: ConformanceEvidence,
    outcome: ConformanceOutcome,
    reasons: tuple[ConformanceReason, ...],
    *,
    verified_attestation: bool = False,
) -> ConformanceFinding:
    proof_status = _proof_status(evidence, verified_attestation=verified_attestation)
    if verified_attestation and evidence.replay is EvidenceState.VERIFIED:
        reproducibility = ReproducibilityStatus.VERIFIED
    elif evidence.replay is EvidenceState.INVALID:
        reproducibility = ReproducibilityStatus.FAILED
    elif evidence.replay is EvidenceState.NOT_REQUIRED:
        reproducibility = ReproducibilityStatus.NOT_REQUIRED
    else:
        reproducibility = ReproducibilityStatus.UNKNOWN
    return ConformanceFinding(
        tenant_id=evidence.tenant_id,
        case_id=evidence.case_id,
        event_id=evidence.event_id,
        event_normalization_hash=evidence.event_normalization_hash,
        outcome=outcome,
        proof_status=proof_status,
        reproducibility=reproducibility,
        receipt_verifier_succeeded=(verified_attestation and evidence.authoritative_verification),
        verifier_name=evidence.verifier_name if verified_attestation else None,
        verifier_signature_required=(verified_attestation and evidence.verifier_signature_required),
        verifier_expiry_required=(verified_attestation and evidence.verifier_expiry_required),
        production_profile_verified=(verified_attestation and evidence.production_profile_verified),
        reasons=reasons,
        verifier_reason_codes=evidence.verifier_reason_codes,
        evidence_references=evidence.evidence_references,
    )


def _proof_status(
    evidence: ConformanceEvidence,
    *,
    verified_attestation: bool = False,
) -> ProofStatus:
    states = (
        evidence.receipt,
        evidence.policy,
        evidence.audit,
        evidence.authority,
        evidence.signature,
        evidence.source_chain,
        evidence.replay,
        evidence.evidence_bundle,
    )
    if EvidenceState.INVALID in states:
        return ProofStatus.FAILED
    if EvidenceState.HASH_ONLY in states:
        return ProofStatus.HASH_ONLY
    if any(state in {EvidenceState.UNAVAILABLE, EvidenceState.AMBIGUOUS} for state in states):
        return ProofStatus.UNAVAILABLE
    if EvidenceState.MISSING in states:
        return ProofStatus.INCOMPLETE
    if verified_attestation and evidence.authoritative_verification:
        return (
            ProofStatus.VERIFIED
            if evidence.production_profile_verified
            else ProofStatus.NON_PRODUCTION
        )
    if all(state in {EvidenceState.VERIFIED, EvidenceState.NOT_REQUIRED} for state in states):
        return ProofStatus.ASSERTED
    return ProofStatus.INCOMPLETE


def _uncertainty_reasons(evidence: ConformanceEvidence) -> tuple[ConformanceReason, ...]:
    states = (
        evidence.receipt,
        evidence.policy,
        evidence.audit,
        evidence.authority,
        evidence.signature,
        evidence.source_chain,
        evidence.replay,
        evidence.evidence_bundle,
    )
    reasons: list[ConformanceReason] = []
    if EvidenceState.HASH_ONLY in states:
        reasons.append(ConformanceReason.HASH_ONLY_EVIDENCE)
    if any(state in {EvidenceState.UNAVAILABLE, EvidenceState.AMBIGUOUS} for state in states):
        reasons.append(ConformanceReason.VERIFIER_UNAVAILABLE)
    return tuple(reasons)


def evaluate_conformance(evidence: ConformanceEvidence) -> ConformanceFinding:
    """Evaluate one observed action conservatively and without granting authority."""
    if evidence.side_effect_state is SideEffectState.UNKNOWN:
        return _finding(
            evidence,
            ConformanceOutcome.INVESTIGATE,
            (ConformanceReason.SIDE_EFFECT_STATUS_UNKNOWN,),
        )
    if evidence.capture_state is CaptureState.INGEST_GAP:
        return _finding(
            evidence,
            ConformanceOutcome.INVESTIGATE,
            (ConformanceReason.INGEST_GAP,),
        )
    if evidence.capture_state is CaptureState.INCOMPLETE:
        return _finding(
            evidence,
            ConformanceOutcome.INVESTIGATE,
            (ConformanceReason.CAPTURE_INCOMPLETE,),
        )
    if evidence.correlation_state is CorrelationState.AMBIGUOUS:
        return _finding(
            evidence,
            ConformanceOutcome.INVESTIGATE,
            (ConformanceReason.CORRELATION_AMBIGUOUS,),
        )
    if evidence.correlation_state is CorrelationState.UNASSIGNED:
        return _finding(
            evidence,
            ConformanceOutcome.INVESTIGATE,
            (ConformanceReason.CORRELATION_UNASSIGNED,),
        )

    if evidence.side_effect_state is SideEffectState.BLOCKED:
        control_states = (evidence.policy, evidence.audit, evidence.source_chain)
        if evidence.governance_decision in {
            GovernanceDecision.DENY,
            GovernanceDecision.ESCALATE,
        } and all(state is EvidenceState.VERIFIED for state in control_states):
            return _finding(
                evidence,
                ConformanceOutcome.ALLOW,
                (ConformanceReason.CONTROL_EFFECTIVE,),
            )
        return _finding(
            evidence,
            ConformanceOutcome.INVESTIGATE,
            (ConformanceReason.BLOCKED_CONTROL_UNVERIFIABLE,),
        )

    verified_control = all(
        state is EvidenceState.VERIFIED
        for state in (evidence.policy, evidence.audit, evidence.source_chain)
    )
    if evidence.governance_decision is GovernanceDecision.DENY and verified_control:
        return _finding(
            evidence,
            ConformanceOutcome.DENY,
            (ConformanceReason.DENIED_ACTION_EXECUTED,),
        )
    if evidence.governance_decision is GovernanceDecision.ESCALATE and verified_control:
        return _finding(
            evidence,
            ConformanceOutcome.DENY,
            (ConformanceReason.ESCALATED_ACTION_EXECUTED,),
        )

    invalid_failures: list[ConformanceReason] = []
    for name, _missing_reason, invalid_reason in _REQUIRED_COMPONENTS:
        state = getattr(evidence, name)
        if state is EvidenceState.INVALID:
            invalid_failures.append(invalid_reason)

    optional_components = (
        (
            evidence.signature,
            evidence.signature_required,
            ConformanceReason.SIGNATURE_MISSING,
            ConformanceReason.SIGNATURE_INVALID,
        ),
        (
            evidence.replay,
            evidence.replay_required,
            ConformanceReason.REPLAY_MISSING,
            ConformanceReason.REPLAY_INVALID,
        ),
        (
            evidence.evidence_bundle,
            evidence.evidence_bundle_required,
            ConformanceReason.EVIDENCE_BUNDLE_MISSING,
            ConformanceReason.EVIDENCE_BUNDLE_INVALID,
        ),
    )
    for state, required, _missing_reason, invalid_reason in optional_components:
        if required and state is EvidenceState.INVALID:
            invalid_failures.append(invalid_reason)
    if invalid_failures:
        return _finding(evidence, ConformanceOutcome.DENY, tuple(invalid_failures))

    failures: list[ConformanceReason] = []
    for name, missing_reason, _ in _REQUIRED_COMPONENTS:
        if getattr(evidence, name) is EvidenceState.MISSING:
            failures.append(missing_reason)
    for state, required, missing_reason, _ in optional_components:
        if required and state is EvidenceState.MISSING:
            failures.append(missing_reason)
    if failures:
        return _finding(evidence, ConformanceOutcome.DENY, tuple(failures))

    uncertainty = _uncertainty_reasons(evidence)
    if uncertainty:
        return _finding(evidence, ConformanceOutcome.INVESTIGATE, uncertainty)

    if evidence.governance_decision not in {
        GovernanceDecision.ALLOW,
        GovernanceDecision.TRANSFORM,
    }:
        failures.append(ConformanceReason.POLICY_DECISION_MISSING)
    if failures:
        return _finding(evidence, ConformanceOutcome.DENY, tuple(failures))
    required_components_verified = all(
        getattr(evidence, component) is EvidenceState.VERIFIED
        for component in _ALWAYS_REQUIRED_COMPONENTS
    )
    if (
        not required_components_verified
        or not evidence.authoritative_verification
        or evidence.verifier_name != PUBLIC_RECEIPT_VERIFIER_NAME
    ):
        return _finding(
            evidence,
            ConformanceOutcome.INVESTIGATE,
            (ConformanceReason.AUTHORITATIVE_VERIFICATION_MISSING,),
        )
    # These fields are an analytical assertion supplied by the caller.  They
    # are deliberately insufficient to establish production trust.  Only a
    # cryptographically sealed attestation checked by an independent verifier
    # may promote the same evidence to a verified finding.
    return _finding(
        evidence,
        ConformanceOutcome.INVESTIGATE,
        (ConformanceReason.ASSERTED_EVIDENCE_UNVERIFIED,),
    )


_CHECK_COMPONENT_BY_EVIDENCE_FIELD: dict[str, VerificationComponent] = {
    "receipt": VerificationComponent.RECEIPT,
    "policy": VerificationComponent.POLICY,
    "audit": VerificationComponent.AUDIT,
    "authority": VerificationComponent.AUTHORITY,
    "signature": VerificationComponent.SIGNATURE,
    "source_chain": VerificationComponent.SOURCE_CHAIN,
    "replay": VerificationComponent.REPLAY,
    "evidence_bundle": VerificationComponent.EVIDENCE_BUNDLE,
}


def _required_verification_components(
    evidence: ConformanceEvidence,
) -> frozenset[VerificationComponent]:
    components = {
        VerificationComponent.EVENT_BINDING,
        VerificationComponent.RECEIPT,
        VerificationComponent.POLICY,
        VerificationComponent.AUDIT,
        VerificationComponent.AUTHORITY,
        VerificationComponent.SOURCE_CHAIN,
    }
    if evidence.signature_required:
        components.add(VerificationComponent.SIGNATURE)
        components.add(VerificationComponent.EXPIRY)
    if evidence.replay_required:
        components.add(VerificationComponent.REPLAY)
    if evidence.evidence_bundle_required:
        components.add(VerificationComponent.EVIDENCE_BUNDLE)
    return frozenset(components)


def _evaluate_checked_conformance(
    evidence: ConformanceEvidence,
    verification_checks: tuple[VerificationCheck, ...],
) -> ConformanceFinding:
    """Evaluate evidence whose successful checks will be authenticated by a seal."""
    checked_receipt_rejection = any(
        check.component is VerificationComponent.RECEIPT
        and check.check_name == "receipt.public_contract_rejection"
        for check in verification_checks
    )
    if (
        checked_receipt_rejection
        and evidence.governance_decision is GovernanceDecision.DENY
        and evidence.receipt is EvidenceState.INVALID
    ):
        return _finding(
            evidence,
            ConformanceOutcome.DENY,
            (ConformanceReason.RECEIPT_INVALID,),
            verified_attestation=True,
        )
    analytical = evaluate_conformance(evidence)
    if analytical.outcome is ConformanceOutcome.DENY:
        return _finding(
            evidence,
            ConformanceOutcome.DENY,
            analytical.reasons,
            verified_attestation=True,
        )
    components = frozenset(check.component for check in verification_checks)
    missing = _required_verification_components(evidence) - components
    inconsistent = {
        component
        for field, component in _CHECK_COMPONENT_BY_EVIDENCE_FIELD.items()
        if component in components and getattr(evidence, field) is not EvidenceState.VERIFIED
    }
    if missing or inconsistent:
        return _finding(
            evidence,
            ConformanceOutcome.INVESTIGATE,
            (ConformanceReason.VERIFICATION_CHECK_MISSING,),
        )

    # Reuse fail-closed analytical branches, but explicitly promote only the
    # one complete authoritative success branch after check coverage is known.
    if evidence.side_effect_state is not SideEffectState.EXECUTED:
        return _finding(
            evidence,
            analytical.outcome,
            analytical.reasons,
            verified_attestation=True,
        )
    if evidence.governance_decision not in {
        GovernanceDecision.ALLOW,
        GovernanceDecision.TRANSFORM,
    }:
        return _finding(
            evidence,
            analytical.outcome,
            analytical.reasons,
            verified_attestation=True,
        )
    if not evidence.authoritative_verification:
        return _finding(
            evidence,
            ConformanceOutcome.INVESTIGATE,
            (ConformanceReason.AUTHORITATIVE_VERIFICATION_MISSING,),
            verified_attestation=True,
        )
    reason = (
        ConformanceReason.AUTHORITATIVE_EVIDENCE_VERIFIED
        if evidence.production_profile_verified
        else ConformanceReason.AUTHORITATIVE_EVIDENCE_VERIFIED_NON_PRODUCTION
    )
    return _finding(
        evidence,
        ConformanceOutcome.ALLOW,
        (reason,),
        verified_attestation=True,
    )


class ConformanceAttestation(_StrictModel):
    """Identity-bound evidence plus its deterministic analytical finding."""

    evidence: ConformanceEvidence
    finding: ConformanceFinding
    verification_checks: tuple[VerificationCheck, ...] = ()
    seal: AttestationSeal | None = None

    @model_validator(mode="after")
    def validate_identity_and_finding(self) -> Self:
        evidence_identity = (
            self.evidence.tenant_id,
            self.evidence.case_id,
            self.evidence.event_id,
            self.evidence.event_normalization_hash,
        )
        finding_identity = (
            self.finding.tenant_id,
            self.finding.case_id,
            self.finding.event_id,
            self.finding.event_normalization_hash,
        )
        if evidence_identity != finding_identity:
            raise ValueError("conformance evidence and finding identity do not match")
        check_keys = tuple(
            (check.component.value, check.check_name, check.verifier_name, check.verifier_version)
            for check in self.verification_checks
        )
        if check_keys != tuple(sorted(set(check_keys))):
            raise ValueError("verification checks must be sorted and unique")
        expected_finding = (
            _evaluate_checked_conformance(self.evidence, self.verification_checks)
            if self.verification_checks
            else evaluate_conformance(self.evidence)
        )
        if self.finding != expected_finding:
            raise ValueError("conformance finding is not the deterministic evidence result")
        if self.seal is not None and not self.verification_checks:
            raise ValueError("sealed attestation requires named verification checks")
        return self


def attest_conformance(evidence: ConformanceEvidence) -> ConformanceAttestation:
    """Evaluate and bind one immutable conformance evidence record."""
    return ConformanceAttestation(
        evidence=evidence,
        finding=evaluate_conformance(evidence),
    )


def checked_conformance_attestation(
    evidence: ConformanceEvidence,
    verification_checks: tuple[VerificationCheck, ...],
    *,
    seal: AttestationSeal | None = None,
) -> ConformanceAttestation:
    """Bind named checks for sealing; consumers must still invoke a verifier."""
    return ConformanceAttestation(
        evidence=evidence,
        finding=_evaluate_checked_conformance(evidence, verification_checks),
        verification_checks=verification_checks,
        seal=seal,
    )


def canonical_attestation_hash(attestation: ConformanceAttestation) -> str:
    """Digest the unsigned canonical attestation body authenticated by a seal."""
    return sha256_canonical(attestation.model_dump(mode="python", exclude={"seal"}))


def hash_only_evidence_from_event(
    event: ProcessEvent,
    *,
    side_effect_state: SideEffectState,
    capture_state: CaptureState = CaptureState.COMPLETE,
    correlation_state: CorrelationState = CorrelationState.EXACT,
) -> ConformanceEvidence:
    """Project event references without falsely upgrading hashes to verification."""
    governance = event.governance
    references = tuple(
        sorted(
            (
                *(
                    (
                        EvidenceReference(
                            reference_type=EvidenceReferenceType.RECEIPT_ID,
                            reference_id=governance.decision_receipt_id,
                        ),
                    )
                    if governance.decision_receipt_id is not None
                    else ()
                ),
                *(
                    (
                        EvidenceReference(
                            reference_type=EvidenceReferenceType.RECEIPT_HASH,
                            reference_id=governance.decision_receipt_hash,
                        ),
                    )
                    if governance.decision_receipt_hash is not None
                    else ()
                ),
                *(
                    (
                        EvidenceReference(
                            reference_type=EvidenceReferenceType.AUDIT_EVENT_ID,
                            reference_id=governance.audit_event_id,
                        ),
                    )
                    if governance.audit_event_id is not None
                    else ()
                ),
                *(
                    (
                        EvidenceReference(
                            reference_type=EvidenceReferenceType.AUDIT_EVENT_HASH,
                            reference_id=governance.audit_event_hash,
                        ),
                    )
                    if governance.audit_event_hash is not None
                    else ()
                ),
                *(
                    EvidenceReference(
                        reference_type=EvidenceReferenceType.EVIDENCE_BUNDLE_ID,
                        reference_id=bundle_id,
                    )
                    for bundle_id in governance.evidence_bundle_ids
                ),
            ),
            key=lambda reference: (
                reference.reference_type.value,
                reference.reference_id,
            ),
        )
    )
    receipt_state = (
        EvidenceState.HASH_ONLY
        if governance.decision_receipt_id or governance.decision_receipt_hash
        else EvidenceState.MISSING
    )
    return ConformanceEvidence(
        tenant_id=event.tenant_id,
        case_id=event.case_id,
        event_id=event.event_id,
        event_normalization_hash=event.normalization_hash,
        observed_action=governance.tool_name,
        observed_argument_hash=governance.argument_hash,
        observed_audit_hash=governance.audit_event_hash,
        observed_actor=event.actor_id,
        observed_execution_boundary=governance.execution_boundary,
        observed_policy_bundle_id=governance.policy_bundle_id,
        observed_policy_hash=governance.policy_hash,
        side_effect_state=side_effect_state,
        capture_state=capture_state,
        correlation_state=correlation_state,
        governance_decision=governance.decision,
        receipt=receipt_state,
        policy=(
            EvidenceState.HASH_ONLY
            if governance.policy_id or governance.policy_version
            else EvidenceState.MISSING
        ),
        audit=(
            EvidenceState.HASH_ONLY
            if governance.audit_event_id or governance.audit_event_hash
            else EvidenceState.MISSING
        ),
        authority=(
            EvidenceState.HASH_ONLY if governance.actor_authority_id else EvidenceState.MISSING
        ),
        signature=EvidenceState.UNAVAILABLE,
        source_chain=(
            EvidenceState.VERIFIED
            if event.integrity.chain_status is SourceChainStatus.VERIFIED
            else EvidenceState.UNAVAILABLE
        ),
        replay=(
            EvidenceState.VERIFIED
            if governance.replay_verified is True
            else EvidenceState.INVALID
            if governance.replay_verified is False
            else EvidenceState.MISSING
        ),
        evidence_bundle=(
            EvidenceState.HASH_ONLY if governance.evidence_bundle_ids else EvidenceState.MISSING
        ),
        authoritative_verification=False,
        evidence_references=references,
    )
