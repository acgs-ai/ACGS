"""Optional adapter around the public gove-zone receipt contracts.

No verification logic is copied here.  When gove-zone is installed the adapter
loads its public ``DecisionReceipt`` and ``ReceiptVerifier`` exports and invokes
the verifier.  Otherwise it returns an explicit unavailable result.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from enum import Enum, StrEnum
from typing import Protocol, cast

from agent_bus_analyzer.process_mining._canonical import canonical_json, sha256_canonical
from agent_bus_analyzer.process_mining.miners.conformance import (
    PUBLIC_RECEIPT_VERIFIER_NAME,
    AttestationSeal,
    AttestationVerificationResult,
    ConformanceAttestation,
    ConformanceEvidence,
    ConformanceOutcome,
    EvidenceState,
    ProofStatus,
    VerificationCheck,
    VerificationComponent,
    canonical_attestation_hash,
    checked_conformance_attestation,
)
from agent_bus_analyzer.process_mining.schemas.process_event import (
    ProcessEvent,
    SourceChainStatus,
    validated_event_snapshot,
)

PRODUCTION_ATTESTATION_VERIFIER_NAME = "agent-bus-analyzer.production-conformance"
PRODUCTION_ATTESTATION_VERIFIER_VERSION = "hmac-attestation-1.0"


class VerificationStatus(StrEnum):
    VERIFIED = "verified"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class AuthoritativeReceiptVerification:
    status: VerificationStatus
    verifier_name: str
    reason_code: str | None = None
    bound_event_normalization_hash: str | None = None
    bound_tenant_id: str | None = None
    bound_execution_boundary: str | None = None
    bound_policy_bundle_id: str | None = None
    bound_policy_hash: str | None = None
    bound_action: str | None = None
    bound_argument_hash: str | None = None
    bound_audit_hash: str | None = None
    bound_actor: str | None = None
    bound_governance_decision: str | None = None
    signature_required: bool = False
    expiry_required: bool = False
    signature_verified: bool = False
    production_profile_verified: bool = False

    def __post_init__(self) -> None:
        if self.status is VerificationStatus.VERIFIED:
            bindings = (
                self.bound_event_normalization_hash,
                self.bound_tenant_id,
                self.bound_execution_boundary,
                self.bound_policy_bundle_id,
                self.bound_policy_hash,
                self.bound_action,
                self.bound_argument_hash,
                self.bound_audit_hash,
                self.bound_actor,
                self.bound_governance_decision,
            )
            if any(value is None for value in bindings):
                raise ValueError("verified receipt result requires complete binding values")
            if self.reason_code is not None:
                raise ValueError("verified receipt result cannot carry a rejection code")
        if self.production_profile_verified != (
            self.status is VerificationStatus.VERIFIED
            and self.signature_required
            and self.expiry_required
            and self.signature_verified
        ):
            raise ValueError("production profile result is inconsistent with verifier posture")

    @property
    def verified(self) -> bool:
        return self.status is VerificationStatus.VERIFIED


class _ReceiptFactory(Protocol):
    @classmethod
    def from_json(cls, payload: str) -> object: ...


class _VerifierMethod(Protocol):
    def __call__(
        self,
        receipt: object | None,
        *,
        expected_action: str | None = None,
        expected_args: dict[str, object] | None = None,
        expected_audit_hash: str | None = None,
        expected_actor: str | None = None,
        now_iso: str | None = None,
    ) -> None: ...


class _VerifierObject(Protocol):
    verify: _VerifierMethod


ReceiptResolver = Callable[[ProcessEvent], object | None]
ArgumentsResolver = Callable[[ProcessEvent], Mapping[str, object] | None]
EvidenceResolver = Callable[[ProcessEvent], ConformanceEvidence]
SupplementalCheckResolver = Callable[
    [ProcessEvent, ConformanceEvidence, AuthoritativeReceiptVerification],
    tuple[VerificationCheck, ...],
]


@dataclass(frozen=True, slots=True)
class HmacAttestationVerifier:
    """Verify provider-issued attestations without trusting serialized flags."""

    secret: bytes
    issuer_id: str
    key_id_hash: str
    verifier_version: str = PRODUCTION_ATTESTATION_VERIFIER_VERSION

    def __call__(
        self,
        attestation: ConformanceAttestation,
    ) -> AttestationVerificationResult:
        # Revalidate serialized fields so ``model_construct`` cannot bypass the
        # strict model invariants at this trust boundary.
        try:
            validated = ConformanceAttestation.model_validate_json(attestation.model_dump_json())
        except Exception:
            return self._failure(attestation, "ATTESTATION_SCHEMA_INVALID")
        attestation_hash = canonical_attestation_hash(validated)
        seal = validated.seal
        if seal is None:
            return self._failure(validated, "ATTESTATION_SEAL_MISSING")
        if (
            seal.algorithm != "HMAC-SHA256"
            or seal.issuer_id != self.issuer_id
            or seal.verifier_version != self.verifier_version
            or seal.key_id_hash != self.key_id_hash
        ):
            return self._failure(validated, "ATTESTATION_SEAL_IDENTITY_MISMATCH")
        expected = _attestation_digest(self.secret, validated)
        if not hmac.compare_digest(seal.digest, expected):
            return self._failure(validated, "ATTESTATION_SEAL_INVALID")
        allow_proof_verified = (
            validated.finding.proof_status is ProofStatus.VERIFIED
            and validated.finding.receipt_verifier_succeeded
            and validated.finding.production_profile_verified
            and validated.evidence.production_profile_verified
            and bool(validated.verification_checks)
        )
        checked_rejection = any(
            check.component is VerificationComponent.RECEIPT
            and check.check_name == "receipt.public_contract_rejection"
            for check in validated.verification_checks
        )
        deny_proof_verified = (
            validated.finding.outcome is ConformanceOutcome.DENY
            and validated.finding.proof_status is ProofStatus.FAILED
            and validated.evidence.verifier_signature_required
            and validated.evidence.verifier_expiry_required
            and checked_rejection
        )
        return AttestationVerificationResult(
            verified=True,
            production_profile_verified=allow_proof_verified or deny_proof_verified,
            verifier_name=self.issuer_id,
            verifier_version=self.verifier_version,
            attestation_hash=attestation_hash,
            key_id_hash=self.key_id_hash,
        )

    def _failure(
        self,
        attestation: ConformanceAttestation,
        reason: str,
    ) -> AttestationVerificationResult:
        try:
            attestation_hash = canonical_attestation_hash(attestation)
        except Exception:
            attestation_hash = "0" * 64
        return AttestationVerificationResult(
            verified=False,
            production_profile_verified=False,
            verifier_name=self.issuer_id,
            verifier_version=self.verifier_version,
            attestation_hash=attestation_hash,
            key_id_hash=self.key_id_hash,
            reason_codes=(reason,),
        )


@dataclass(frozen=True, slots=True)
class ProductionConformanceProvider:
    """Event-bound provider that can only use the public production verifier."""

    verifier: object
    receipt_resolver: ReceiptResolver
    arguments_resolver: ArgumentsResolver
    evidence_resolver: EvidenceResolver
    attestation_verifier: HmacAttestationVerifier
    supplemental_check_resolver: SupplementalCheckResolver | None = None
    now_iso: str | None = None

    def __call__(self, event: ProcessEvent) -> ConformanceAttestation:
        event = validated_event_snapshot(event)
        asserted_evidence = self.evidence_resolver(event)
        _assert_evidence_bound_to_event(asserted_evidence, event)
        verification = verify_with_public_receipt_verifier(
            self.verifier,
            self.receipt_resolver(event),
            expected_action=event.governance.tool_name,
            expected_args=self.arguments_resolver(event),
            expected_audit_hash=event.governance.audit_event_hash,
            expected_actor=event.actor_id,
            event_normalization_hash=event.normalization_hash,
            now_iso=self.now_iso,
        )
        evidence, checks = _derive_verified_evidence(
            event,
            asserted_evidence,
            verification,
            supplemental_check_resolver=self.supplemental_check_resolver,
        )
        unsigned = checked_conformance_attestation(evidence, checks)
        seal = AttestationSeal(
            issuer_id=self.attestation_verifier.issuer_id,
            verifier_version=self.attestation_verifier.verifier_version,
            key_id_hash=self.attestation_verifier.key_id_hash,
            digest=_attestation_digest(self.attestation_verifier.secret, unsigned),
        )
        return checked_conformance_attestation(evidence, checks, seal=seal)


def _attestation_digest(secret: bytes, attestation: ConformanceAttestation) -> str:
    payload = attestation.model_dump(mode="python", exclude={"seal"})
    return hmac.new(
        secret,
        canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _check(
    component: VerificationComponent,
    check_name: str,
    evidence_material: object,
    *,
    verifier_name: str = PUBLIC_RECEIPT_VERIFIER_NAME,
    verifier_version: str = "public-contract-1.0",
) -> VerificationCheck:
    return VerificationCheck(
        component=component,
        check_name=check_name,
        verifier_name=verifier_name,
        verifier_version=verifier_version,
        evidence_hash=sha256_canonical(evidence_material),
    )


def _derive_verified_evidence(
    event: ProcessEvent,
    asserted: ConformanceEvidence,
    verification: AuthoritativeReceiptVerification,
    *,
    supplemental_check_resolver: SupplementalCheckResolver | None,
) -> tuple[ConformanceEvidence, tuple[VerificationCheck, ...]]:
    """Derive states solely from named checks, never from asserted proof flags."""
    payload = asserted.model_dump(mode="python")
    payload.update(
        {
            "receipt": EvidenceState.UNAVAILABLE,
            "policy": EvidenceState.UNAVAILABLE,
            "audit": EvidenceState.UNAVAILABLE,
            "authority": EvidenceState.UNAVAILABLE,
            "signature": EvidenceState.UNAVAILABLE,
            "source_chain": EvidenceState.UNAVAILABLE,
            "replay": (
                EvidenceState.UNAVAILABLE
                if asserted.replay_required
                else EvidenceState.NOT_REQUIRED
            ),
            "evidence_bundle": (
                EvidenceState.UNAVAILABLE
                if asserted.evidence_bundle_required
                else EvidenceState.NOT_REQUIRED
            ),
            "authoritative_verification": False,
            "verifier_name": verification.verifier_name,
            "verifier_signature_required": verification.signature_required,
            "verifier_expiry_required": verification.expiry_required,
            "production_profile_verified": False,
            "verifier_reason_codes": (
                (verification.reason_code,) if verification.reason_code is not None else ()
            ),
        }
    )
    attached = attach_receipt_verification(
        ConformanceEvidence.model_validate(payload),
        verification,
    )
    payload = attached.model_dump(mode="python")
    checks: list[VerificationCheck] = [
        _check(
            VerificationComponent.EVENT_BINDING,
            "normalized_event.identity_binding",
            {
                "tenant_id": event.tenant_id,
                "case_id": event.case_id,
                "event_id": event.event_id,
                "normalization_hash": event.normalization_hash,
                "action": event.governance.tool_name,
                "argument_hash": event.governance.argument_hash,
                "audit_hash": event.governance.audit_event_hash,
                "actor": event.actor_id,
                "execution_boundary": event.governance.execution_boundary,
                "policy_bundle_id": event.governance.policy_bundle_id,
                "policy_hash": event.governance.policy_hash,
            },
            verifier_name="agent-bus-analyzer.ProcessEvent",
            verifier_version="process-event-1.0",
        )
    ]
    if verification.status is VerificationStatus.VERIFIED:
        payload.update(
            {
                "policy": EvidenceState.VERIFIED,
                "audit": EvidenceState.VERIFIED,
                "authority": EvidenceState.VERIFIED,
            }
        )
        checks.extend(
            (
                _check(
                    VerificationComponent.RECEIPT,
                    "receipt.public_contract",
                    asdict(verification),
                ),
                _check(
                    VerificationComponent.POLICY,
                    "receipt.policy_binding",
                    {
                        "policy_bundle_id": verification.bound_policy_bundle_id,
                        "policy_hash": verification.bound_policy_hash,
                    },
                ),
                _check(
                    VerificationComponent.AUDIT,
                    "receipt.audit_binding",
                    verification.bound_audit_hash,
                ),
                _check(
                    VerificationComponent.AUTHORITY,
                    "receipt.actor_authority_binding",
                    {
                        "tenant_id": verification.bound_tenant_id,
                        "actor": verification.bound_actor,
                        "execution_boundary": verification.bound_execution_boundary,
                    },
                ),
            )
        )
        if verification.signature_required and verification.signature_verified:
            checks.append(
                _check(
                    VerificationComponent.SIGNATURE,
                    "receipt.signature_verification",
                    asdict(verification),
                )
            )
        if verification.expiry_required:
            checks.append(
                _check(
                    VerificationComponent.EXPIRY,
                    "receipt.expiry_verification",
                    {"verified_at": "configured-now"},
                )
            )
        if event.integrity.chain_status is SourceChainStatus.VERIFIED:
            payload["source_chain"] = EvidenceState.VERIFIED
            checks.append(
                _check(
                    VerificationComponent.SOURCE_CHAIN,
                    "normalized_event.source_chain_binding",
                    {
                        "source_event_hash": event.integrity.source_event_hash,
                        "source_previous_hash": event.integrity.source_previous_hash,
                        "normalization_hash": event.normalization_hash,
                    },
                    verifier_name="agent-bus-analyzer.ProcessEvent",
                    verifier_version="process-event-1.0",
                )
            )
    elif verification.status is VerificationStatus.INVALID:
        checks.append(
            _check(
                VerificationComponent.RECEIPT,
                "receipt.public_contract_rejection",
                {
                    "event_normalization_hash": event.normalization_hash,
                    "reason_code": verification.reason_code,
                    "signature_required": verification.signature_required,
                    "expiry_required": verification.expiry_required,
                },
            )
        )
    evidence = ConformanceEvidence.model_validate(payload)
    if supplemental_check_resolver is not None:
        supplemental = supplemental_check_resolver(event, evidence, verification)
        allowed = {
            VerificationComponent.REPLAY,
            VerificationComponent.EVIDENCE_BUNDLE,
        }
        if any(check.component not in allowed for check in supplemental):
            raise ValueError("supplemental verifier may only prove replay or evidence_bundle")
        components = {check.component for check in supplemental}
        payload = evidence.model_dump(mode="python")
        if VerificationComponent.REPLAY in components:
            payload["replay"] = EvidenceState.VERIFIED
        if VerificationComponent.EVIDENCE_BUNDLE in components:
            payload["evidence_bundle"] = EvidenceState.VERIFIED
        evidence = ConformanceEvidence.model_validate(payload)
        checks.extend(supplemental)
    ordered = tuple(
        sorted(
            checks,
            key=lambda item: (
                item.component.value,
                item.check_name,
                item.verifier_name,
                item.verifier_version,
            ),
        )
    )
    return evidence, ordered


def _assert_evidence_bound_to_event(
    evidence: ConformanceEvidence,
    event: ProcessEvent,
) -> None:
    expected = (
        event.tenant_id,
        event.case_id,
        event.event_id,
        event.normalization_hash,
        event.governance.tool_name,
        event.governance.argument_hash,
        event.governance.audit_event_hash,
        event.actor_id,
        event.governance.execution_boundary,
        event.governance.policy_bundle_id,
        event.governance.policy_hash,
        event.governance.decision,
    )
    observed = (
        evidence.tenant_id,
        evidence.case_id,
        evidence.event_id,
        evidence.event_normalization_hash,
        evidence.observed_action,
        evidence.observed_argument_hash,
        evidence.observed_audit_hash,
        evidence.observed_actor,
        evidence.observed_execution_boundary,
        evidence.observed_policy_bundle_id,
        evidence.observed_policy_hash,
        evidence.governance_decision,
    )
    if observed != expected:
        raise ValueError("conformance evidence is detached from the normalized event")


def build_production_conformance_provider(
    *,
    verifier: object,
    receipt_resolver: ReceiptResolver,
    arguments_resolver: ArgumentsResolver,
    evidence_resolver: EvidenceResolver,
    supplemental_check_resolver: SupplementalCheckResolver | None = None,
    attestation_secret: bytes | None = None,
    attestation_issuer_id: str = PRODUCTION_ATTESTATION_VERIFIER_NAME,
    attestation_key_id: str | None = None,
    now_iso: str | None = None,
) -> ProductionConformanceProvider:
    """Build a provider or fail startup when production verifier posture is absent."""
    try:
        module = importlib.import_module("gove_zone")
        verifier_type = module.ReceiptVerifier
    except (AttributeError, ImportError) as exc:
        raise RuntimeError("gove-zone public ReceiptVerifier is unavailable") from exc
    if not isinstance(verifier, verifier_type):
        raise TypeError("production conformance requires gove_zone.ReceiptVerifier")
    if getattr(verifier, "require_signature", None) is not True:
        raise ValueError("production conformance requires signature verification")
    if getattr(verifier, "require_expiry", None) is not True:
        raise ValueError("production conformance requires expiry verification")
    for field in (
        "expected_tenant_id",
        "expected_execution_boundary",
        "expected_actor",
        "expected_policy_bundle_id",
        "expected_policy_hash",
    ):
        value = getattr(verifier, field, None)
        if not isinstance(value, str) or not value:
            raise ValueError(f"production conformance verifier requires {field}")
    secret = attestation_secret if attestation_secret is not None else secrets.token_bytes(32)
    if len(secret) < 32:
        raise ValueError("production attestation secret must contain at least 32 bytes")
    if not attestation_issuer_id:
        raise ValueError("production attestation issuer id is required")
    key_id = attestation_key_id or secrets.token_hex(16)
    attestation_verifier = HmacAttestationVerifier(
        secret=secret,
        issuer_id=attestation_issuer_id,
        key_id_hash=hashlib.sha256(key_id.encode("utf-8")).hexdigest(),
    )
    return ProductionConformanceProvider(
        verifier=verifier,
        receipt_resolver=receipt_resolver,
        arguments_resolver=arguments_resolver,
        evidence_resolver=evidence_resolver,
        attestation_verifier=attestation_verifier,
        supplemental_check_resolver=supplemental_check_resolver,
        now_iso=now_iso,
    )


def load_public_decision_receipt(payload: str) -> object:
    """Parse JSON through gove-zone's public ``DecisionReceipt`` contract."""
    module = importlib.import_module("gove_zone")
    receipt_type = cast(_ReceiptFactory, module.DecisionReceipt)
    return receipt_type.from_json(payload)


def build_public_receipt_verifier(**configuration: object) -> object:
    """Construct gove-zone's public ``ReceiptVerifier`` without a hard dependency."""
    module = importlib.import_module("gove_zone")
    verifier_type = cast(type[object], module.ReceiptVerifier)
    return verifier_type(**configuration)


def verify_with_public_receipt_verifier(
    verifier: object,
    receipt: object | None,
    *,
    expected_action: str | None = None,
    expected_args: Mapping[str, object] | None = None,
    expected_audit_hash: str | None = None,
    expected_actor: str | None = None,
    event_normalization_hash: str | None = None,
    now_iso: str | None = None,
) -> AuthoritativeReceiptVerification:
    """Invoke the public verifier and preserve its machine-readable reason code."""
    if receipt is None:
        return AuthoritativeReceiptVerification(
            status=VerificationStatus.INVALID,
            verifier_name=PUBLIC_RECEIPT_VERIFIER_NAME,
            reason_code="MISSING_RECEIPT",
        )
    required_bindings = (
        ("EXPECTED_ACTION_REQUIRED", expected_action),
        ("EXPECTED_ARGUMENTS_REQUIRED", expected_args),
        ("EXPECTED_AUDIT_HASH_REQUIRED", expected_audit_hash),
        ("EXPECTED_ACTOR_REQUIRED", expected_actor),
        ("EVENT_NORMALIZATION_HASH_REQUIRED", event_normalization_hash),
    )
    for reason_code, value in required_bindings:
        if value is None:
            return AuthoritativeReceiptVerification(
                status=VerificationStatus.UNAVAILABLE,
                verifier_name=PUBLIC_RECEIPT_VERIFIER_NAME,
                reason_code=reason_code,
            )
    assert event_normalization_hash is not None
    if re.fullmatch(r"[a-f0-9]{64}", event_normalization_hash) is None:
        return AuthoritativeReceiptVerification(
            status=VerificationStatus.UNAVAILABLE,
            verifier_name=PUBLIC_RECEIPT_VERIFIER_NAME,
            reason_code="EVENT_NORMALIZATION_HASH_INVALID",
        )
    try:
        module = importlib.import_module("gove_zone")
        receipt_type = module.DecisionReceipt
        verifier_type = module.ReceiptVerifier
    except (AttributeError, ImportError):
        return AuthoritativeReceiptVerification(
            status=VerificationStatus.UNAVAILABLE,
            verifier_name=PUBLIC_RECEIPT_VERIFIER_NAME,
            reason_code="VERIFIER_UNAVAILABLE",
        )
    if not isinstance(receipt, receipt_type) or not isinstance(verifier, verifier_type):
        return AuthoritativeReceiptVerification(
            status=VerificationStatus.UNAVAILABLE,
            verifier_name=PUBLIC_RECEIPT_VERIFIER_NAME,
            reason_code="PUBLIC_CONTRACT_REQUIRED",
        )
    signature_required = getattr(verifier, "require_signature", None)
    expiry_required = getattr(verifier, "require_expiry", None)
    if not isinstance(signature_required, bool) or not isinstance(expiry_required, bool):
        return AuthoritativeReceiptVerification(
            status=VerificationStatus.UNAVAILABLE,
            verifier_name=PUBLIC_RECEIPT_VERIFIER_NAME,
            reason_code="VERIFIER_POSTURE_UNAVAILABLE",
        )
    try:
        verify_method = cast(_VerifierObject, verifier).verify
    except (AttributeError, TypeError):
        return AuthoritativeReceiptVerification(
            status=VerificationStatus.UNAVAILABLE,
            verifier_name=PUBLIC_RECEIPT_VERIFIER_NAME,
            reason_code="VERIFIER_UNAVAILABLE",
            signature_required=signature_required,
            expiry_required=expiry_required,
        )
    try:
        verify_method(
            receipt,
            expected_action=expected_action,
            expected_args=dict(expected_args) if expected_args is not None else None,
            expected_audit_hash=expected_audit_hash,
            expected_actor=expected_actor,
            now_iso=now_iso,
        )
    except Exception as exc:
        reason = getattr(exc, "reason_code", None)
        if isinstance(reason, Enum):
            reason_text = str(reason.value)
        elif reason is not None:
            reason_text = str(reason)
        else:
            reason_text = None
        module_name = type(exc).__module__
        if module_name.startswith("gove_zone") or reason_text is not None:
            return AuthoritativeReceiptVerification(
                status=VerificationStatus.INVALID,
                verifier_name=PUBLIC_RECEIPT_VERIFIER_NAME,
                reason_code=reason_text or type(exc).__name__,
                signature_required=signature_required,
                expiry_required=expiry_required,
            )
        return AuthoritativeReceiptVerification(
            status=VerificationStatus.UNAVAILABLE,
            verifier_name=PUBLIC_RECEIPT_VERIFIER_NAME,
            reason_code="VERIFIER_UNAVAILABLE",
            signature_required=signature_required,
            expiry_required=expiry_required,
        )
    receipt_bindings: dict[str, str] = {}
    for result_name, receipt_name in (
        ("bound_tenant_id", "tenant_id"),
        ("bound_execution_boundary", "execution_boundary"),
        ("bound_policy_bundle_id", "policy_bundle_id"),
        ("bound_policy_hash", "policy_hash"),
        ("bound_action", "proposed_action"),
        ("bound_argument_hash", "argument_hash"),
        ("bound_audit_hash", "audit_event_hash"),
        ("bound_actor", "actor"),
    ):
        value = getattr(receipt, receipt_name, None)
        if not isinstance(value, str) or not value:
            return AuthoritativeReceiptVerification(
                status=VerificationStatus.UNAVAILABLE,
                verifier_name=PUBLIC_RECEIPT_VERIFIER_NAME,
                reason_code="VERIFIED_BINDING_UNAVAILABLE",
                signature_required=signature_required,
                expiry_required=expiry_required,
            )
        receipt_bindings[result_name] = value
    decision = getattr(receipt, "decision", None)
    decision_value = decision.value if isinstance(decision, Enum) else decision
    if not isinstance(decision_value, str) or not decision_value:
        return AuthoritativeReceiptVerification(
            status=VerificationStatus.UNAVAILABLE,
            verifier_name=PUBLIC_RECEIPT_VERIFIER_NAME,
            reason_code="VERIFIED_DECISION_UNAVAILABLE",
            signature_required=signature_required,
            expiry_required=expiry_required,
        )
    signature_algorithm = getattr(receipt, "signature_algorithm", None)
    if not isinstance(signature_algorithm, str) or not signature_algorithm:
        return AuthoritativeReceiptVerification(
            status=VerificationStatus.UNAVAILABLE,
            verifier_name=PUBLIC_RECEIPT_VERIFIER_NAME,
            reason_code="SIGNATURE_POSTURE_UNAVAILABLE",
            signature_required=signature_required,
            expiry_required=expiry_required,
        )
    signature_verified = signature_algorithm != "none"
    production_profile_verified = signature_required and expiry_required and signature_verified
    return AuthoritativeReceiptVerification(
        status=VerificationStatus.VERIFIED,
        verifier_name=PUBLIC_RECEIPT_VERIFIER_NAME,
        bound_event_normalization_hash=event_normalization_hash,
        bound_tenant_id=receipt_bindings["bound_tenant_id"],
        bound_execution_boundary=receipt_bindings["bound_execution_boundary"],
        bound_policy_bundle_id=receipt_bindings["bound_policy_bundle_id"],
        bound_policy_hash=receipt_bindings["bound_policy_hash"],
        bound_action=receipt_bindings["bound_action"],
        bound_argument_hash=receipt_bindings["bound_argument_hash"],
        bound_audit_hash=receipt_bindings["bound_audit_hash"],
        bound_actor=receipt_bindings["bound_actor"],
        bound_governance_decision=decision_value,
        signature_required=signature_required,
        expiry_required=expiry_required,
        signature_verified=signature_verified,
        production_profile_verified=production_profile_verified,
    )


def attach_receipt_verification(
    evidence: ConformanceEvidence,
    verification: AuthoritativeReceiptVerification,
) -> ConformanceEvidence:
    """Attach only what the public receipt-verifier result actually proves."""
    payload = evidence.model_dump(mode="python")
    if verification.status is VerificationStatus.VERIFIED:
        binding_pairs = (
            (
                "EVENT_NORMALIZATION_HASH_MISMATCH",
                evidence.event_normalization_hash,
                verification.bound_event_normalization_hash,
            ),
            ("TENANT_MISMATCH", evidence.tenant_id, verification.bound_tenant_id),
            (
                "EXECUTION_BOUNDARY_MISMATCH",
                evidence.observed_execution_boundary,
                verification.bound_execution_boundary,
            ),
            (
                "POLICY_BUNDLE_MISMATCH",
                evidence.observed_policy_bundle_id,
                verification.bound_policy_bundle_id,
            ),
            (
                "POLICY_HASH_MISMATCH",
                evidence.observed_policy_hash,
                verification.bound_policy_hash,
            ),
            ("ACTION_MISMATCH", evidence.observed_action, verification.bound_action),
            (
                "ARGUMENT_HASH_MISMATCH",
                evidence.observed_argument_hash,
                verification.bound_argument_hash,
            ),
            (
                "AUDIT_HASH_MISMATCH",
                evidence.observed_audit_hash,
                verification.bound_audit_hash,
            ),
            ("ACTOR_MISMATCH", evidence.observed_actor, verification.bound_actor),
            (
                "GOVERNANCE_DECISION_MISMATCH",
                (
                    evidence.governance_decision.value
                    if evidence.governance_decision is not None
                    else None
                ),
                verification.bound_governance_decision,
            ),
        )
        mismatches = tuple(
            sorted(reason for reason, observed, verified in binding_pairs if observed != verified)
        )
        if mismatches:
            payload.update(
                {
                    "receipt": EvidenceState.INVALID,
                    "authoritative_verification": False,
                    "verifier_name": verification.verifier_name,
                    "verifier_signature_required": verification.signature_required,
                    "verifier_expiry_required": verification.expiry_required,
                    "production_profile_verified": False,
                    "verifier_reason_codes": mismatches,
                }
            )
            return ConformanceEvidence.model_validate(payload)
        payload.update(
            {
                "receipt": EvidenceState.VERIFIED,
                "signature": (
                    EvidenceState.VERIFIED
                    if verification.signature_verified
                    else EvidenceState.NOT_REQUIRED
                ),
                "signature_required": verification.signature_required,
                "authoritative_verification": True,
                "verifier_name": verification.verifier_name,
                "verifier_signature_required": verification.signature_required,
                "verifier_expiry_required": verification.expiry_required,
                "production_profile_verified": verification.production_profile_verified,
                "verifier_reason_codes": (),
            }
        )
        return ConformanceEvidence.model_validate(payload)
    reason_codes = (verification.reason_code,) if verification.reason_code is not None else ()
    payload.update(
        {
            "receipt": (
                EvidenceState.INVALID
                if verification.status is VerificationStatus.INVALID
                else EvidenceState.UNAVAILABLE
            ),
            "authoritative_verification": False,
            "verifier_name": verification.verifier_name,
            "verifier_signature_required": verification.signature_required,
            "verifier_expiry_required": verification.expiry_required,
            "production_profile_verified": False,
            "verifier_reason_codes": reason_codes,
        }
    )
    return ConformanceEvidence.model_validate(payload)
