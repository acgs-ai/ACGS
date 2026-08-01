"""Strict workload-signed observed evidence for gateway dispatcher wiring.

The workload signature is self-attestation by the enrolled runtime key.  It is
not independent evidence, authorization, or a native/federated assurance
upgrade.  Only an embedded Decision Receipt may carry native assurance.
"""

from __future__ import annotations

import dataclasses
import importlib.metadata
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, NoReturn, Protocol, Self

from gove_zone.consumption import ReceiptConsumptionLedger
from gove_zone.decision import canonical_json, sha256_json
from gove_zone.errors import (
    ReceiptAlreadyUsedError,
    ReceiptRejectionReason,
    ReceiptValidationError,
)
from gove_zone.executor import execute_with_receipt
from gove_zone.gateway import BypassAttemptError, UniversalGateway
from gove_zone.policy_sync import (
    ManagedPolicyProvenance,
    PolicySyncScope,
    SyncedRuleSetPolicy,
)
from gove_zone.receipt import DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS, DecisionReceipt
from gove_zone.runtime_identity import (
    GateScope,
    RuntimeIdentityDescriptor,
    WorkloadKeyProvider,
    b64url_decode,
    public_key_thumbprint,
    verify_ed25519,
)
from gove_zone.tool import ToolCall
from gove_zone.trust import ReceiptTrustRegistry

WIRING_ATTESTATION_SCHEMA = "acgs.in-process-public-surface-conformance/v1"
WIRING_ATTESTATION_PURPOSE = "acgs.in-process-public-surface-conformance/v1"
WIRING_SUITE_ID = "acgs.gove-zone.in-process-public-surfaces/v1"
_ASSURANCE_CLASS = "observed"
_EVIDENCE_KIND = "in_process_public_surface_conformance"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_ATTESTATION_TTL_SECONDS = 900


class WiringAttestationError(ValueError):
    """Reason-coded fail-closed wiring-attestation rejection."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(f"{reason_code}: {message}")
        self.reason_code = reason_code


class AttestationReplayGuard(Protocol):
    """Atomic verifier-owned nonce/sequence acceptance boundary.

    Durable implementations belong to the consuming control plane.  Returning
    ``False`` means the candidate was replayed or did not advance high water.
    """

    def consume(self, *, namespace_digest: str, nonce: str, sequence: int) -> bool: ...


_TOOLS = {
    "allow": "acgs.conformance.invoke_allow",
    "mcp": "acgs.conformance.mcp_deny",
    "openai": "acgs.conformance.openai_escalate",
    "langgraph": "acgs.conformance.langgraph_deny",
    "rest": "acgs.conformance.rest_deny",
    "claude": "acgs.conformance.claude_deny",
    "bypass": "acgs.conformance.raw_bypass",
}
_CLAUDE_PROBE_ARGUMENTS = {
    "action_kind": "PreToolUse",
    "summary": {
        "probe": {
            "type": "str",
            "len": 6,
            "sha256": "389432cbf83f3d1b64029a75864ec96f8fd06451b4c99d7b28385d395d480bfa",
        }
    },
}


@dataclass(frozen=True, slots=True)
class WiringCaseSpec:
    case_id: str
    dispatcher: str
    classification: str
    expected_outcome: str
    expected_side_effect_count: int
    tool: str
    argument_hash: str
    expected_audit_reason: str
    expected_decision: str
    expected_actor_kind: str
    expected_policy_binding: bool
    expected_matched_rules: tuple[str, ...]
    expected_executor_verified: bool
    expected_receipt_evidence: bool
    expected_consumption_evidence: bool
    expected_event_id_kind: str
    expected_rejection_code: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


WIRING_SUITE_SPEC = (
    WiringCaseSpec(
        "invoke.allow_once",
        "UniversalGateway.invoke",
        "native_executor",
        "allow",
        1,
        _TOOLS["allow"],
        sha256_json({"probe": "allow"}),
        "no rules matched",
        "allow",
        "authenticated_runtime",
        True,
        (),
        True,
        True,
        True,
        "managed_event_id",
    ),
    WiringCaseSpec(
        "mcp.deny_zero",
        "UniversalGateway.handle_mcp_call",
        "public_dispatcher",
        "deny",
        0,
        _TOOLS["mcp"],
        sha256_json({"probe": "mcp"}),
        "matched rule deny-conformance",
        "deny",
        "authenticated_runtime",
        True,
        ("deny-conformance",),
        False,
        False,
        False,
        "managed_event_id",
    ),
    WiringCaseSpec(
        "openai.escalate_zero",
        "UniversalGateway.handle_openai_tool_call",
        "public_dispatcher",
        "escalate",
        0,
        _TOOLS["openai"],
        sha256_json({"probe": "openai"}),
        "matched rule escalate-conformance",
        "escalate",
        "authenticated_runtime",
        True,
        ("escalate-conformance",),
        False,
        False,
        False,
        "managed_event_id",
    ),
    WiringCaseSpec(
        "langgraph.deny_zero",
        "UniversalGateway.langgraph_tools",
        "public_dispatcher",
        "deny",
        0,
        _TOOLS["langgraph"],
        sha256_json({"probe": "langgraph"}),
        "matched rule deny-conformance",
        "deny",
        "authenticated_runtime",
        True,
        ("deny-conformance",),
        False,
        False,
        False,
        "managed_event_id",
    ),
    WiringCaseSpec(
        "rest.deny_zero",
        "UniversalGateway.handle_rest_call",
        "public_dispatcher",
        "deny",
        0,
        _TOOLS["rest"],
        sha256_json({"probe": "rest"}),
        "matched rule deny-conformance",
        "deny",
        "authenticated_runtime",
        True,
        ("deny-conformance",),
        False,
        False,
        False,
        "managed_event_id",
    ),
    WiringCaseSpec(
        "claude_hook.deny_decision_only",
        "UniversalGateway.handle_claude_hook",
        "decision_only",
        "deny",
        0,
        f"runtime.{_TOOLS['claude']}",
        sha256_json(_CLAUDE_PROBE_ARGUMENTS),
        "matched rule deny-conformance",
        "deny",
        "authenticated_runtime",
        True,
        ("deny-conformance",),
        False,
        False,
        False,
        "managed_event_id",
    ),
    WiringCaseSpec(
        "executor.tampered_receipt_zero",
        "execute_with_receipt",
        "executor_conformance",
        "rejected",
        0,
        _TOOLS["allow"],
        sha256_json({"probe": "allow"}),
        "no rules matched",
        "allow",
        "authenticated_runtime",
        True,
        (),
        True,
        False,
        False,
        "managed_event_id",
        ReceiptRejectionReason.RECEIPT_HASH_MISMATCH.value,
    ),
    WiringCaseSpec(
        "sealed_handle.raw_bypass_zero",
        "UniversalGateway.register_tool/SealedTool",
        "sealed_handle_conformance",
        "rejected",
        0,
        _TOOLS["bypass"],
        sha256_json({"probe": "bypass"}),
        "sealed tool 'acgs.conformance.raw_bypass' invoked outside the "
        "receipt-gated execution path",
        "deny",
        "structural_bypass_sentinel",
        False,
        ("BYPASS_ATTEMPT",),
        False,
        False,
        False,
        "uuid_hex",
    ),
)
WIRING_SUITE_HASH = sha256_json([case.to_dict() for case in WIRING_SUITE_SPEC])


@dataclass(frozen=True, slots=True)
class RuntimeWiringBinding:
    runtime_identity_id: str
    credential_id: str
    credential_generation: int
    workload_key_id: str
    public_key_thumbprint: str

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        _exact_keys(
            payload,
            "runtime",
            {
                "runtime_identity_id",
                "credential_id",
                "credential_generation",
                "workload_key_id",
                "public_key_thumbprint",
            },
        )
        return cls(
            runtime_identity_id=_string(payload, "runtime_identity_id", "runtime"),
            credential_id=_string(payload, "credential_id", "runtime"),
            credential_generation=_positive_int(payload, "credential_generation", "runtime"),
            workload_key_id=_string(payload, "workload_key_id", "runtime"),
            public_key_thumbprint=_digest(payload, "public_key_thumbprint", "runtime"),
        )

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True, slots=True)
class PackageWiringBinding:
    name: str
    version: str
    runtime_build_digest: str
    configuration_digest: str

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        _exact_keys(
            payload,
            "package",
            {"name", "version", "runtime_build_digest", "configuration_digest"},
        )
        name = _string(payload, "name", "package")
        if name != "gove-zone":
            _reject("package_mismatch", "package.name must be gove-zone")
        return cls(
            name=name,
            version=_string(payload, "version", "package"),
            runtime_build_digest=_digest(payload, "runtime_build_digest", "package"),
            configuration_digest=_digest(payload, "configuration_digest", "package"),
        )

    def to_dict(self) -> dict[str, str]:
        return dataclasses.asdict(self)


@dataclass(frozen=True, slots=True)
class ObservedWiringCase:
    case_id: str
    dispatcher: str
    classification: str
    outcome: str
    side_effect_count: int
    executor_verified: bool
    receipt_id: str
    receipt_hash: str
    receipt_signature_algorithm: str
    receipt_signing_key_id: str
    audit_hash: str
    previous_audit_hash: str
    action_hash: str
    argument_hash: str
    actor: str
    receipt_expires_at: str
    receipt_rejection_code: str
    policy_hash: str
    policy_version_id: str
    policy_provenance_hash: str
    consumption_commitment: str
    receipt: Mapping[str, Any]
    audit_event: Mapping[str, Any]
    consumption_entry: Mapping[str, Any]

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        _validate_ijson(payload, "wiring attestation")
        fields = {field.name for field in dataclasses.fields(cls)}
        _exact_keys(payload, "case result", fields)
        result = cls(
            case_id=_string(payload, "case_id", "case result"),
            dispatcher=_string(payload, "dispatcher", "case result"),
            classification=_string(payload, "classification", "case result"),
            outcome=_string(payload, "outcome", "case result"),
            side_effect_count=_nonnegative_int(payload, "side_effect_count", "case result"),
            executor_verified=_bool(payload, "executor_verified", "case result"),
            receipt_id=_string(payload, "receipt_id", "case result", allow_empty=True),
            receipt_hash=_optional_digest(payload, "receipt_hash", "case result"),
            receipt_signature_algorithm=_string(
                payload, "receipt_signature_algorithm", "case result", allow_empty=True
            ),
            receipt_signing_key_id=_string(
                payload, "receipt_signing_key_id", "case result", allow_empty=True
            ),
            audit_hash=_digest(payload, "audit_hash", "case result"),
            previous_audit_hash=_digest(payload, "previous_audit_hash", "case result"),
            action_hash=_digest(payload, "action_hash", "case result"),
            argument_hash=_digest(payload, "argument_hash", "case result"),
            actor=_string(payload, "actor", "case result"),
            receipt_expires_at=_string(
                payload, "receipt_expires_at", "case result", allow_empty=True
            ),
            receipt_rejection_code=_string(
                payload, "receipt_rejection_code", "case result", allow_empty=True
            ),
            policy_hash=_optional_digest(payload, "policy_hash", "case result"),
            policy_version_id=_string(
                payload, "policy_version_id", "case result", allow_empty=True
            ),
            policy_provenance_hash=_optional_digest(
                payload, "policy_provenance_hash", "case result"
            ),
            consumption_commitment=_optional_digest(
                payload, "consumption_commitment", "case result"
            ),
            receipt=dict(_mapping(payload.get("receipt"), "case result.receipt")),
            audit_event=dict(_mapping(payload.get("audit_event"), "case result.audit_event")),
            consumption_entry=dict(
                _mapping(payload.get("consumption_entry"), "case result.consumption_entry")
            ),
        )
        return result

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True, slots=True)
class ExpectedWiringContext:
    scope: GateScope
    runtime_identity_descriptor: RuntimeIdentityDescriptor
    runtime_identity_issuer_public_key: bytes
    runtime_identity_audience: str
    receipt_trust_registry: ReceiptTrustRegistry
    receipt_trust_purpose: str
    workload_key_id: str
    execution_boundary: str
    runtime_build_digest: str
    configuration_digest: str
    policy_head: Mapping[str, Any]
    policy_provenance_hash: str
    policy_issued_at: str
    policy_fresh_until: str
    policy_expires_at: str
    policy_mode: str
    expected_nonce: str
    minimum_sequence: int
    now: datetime
    replay_guard: AttestationReplayGuard

    def __post_init__(self) -> None:
        if self.minimum_sequence < 0:
            _reject("sequence_invalid", "minimum_sequence must be non-negative")
        if self.now.tzinfo is None:
            _reject("clock_invalid", "verification clock must be timezone-aware")
        _require_hex(self.runtime_build_digest, "runtime_build_digest")
        _require_hex(self.configuration_digest, "configuration_digest")
        _require_hex(self.policy_provenance_hash, "policy_provenance_hash")
        if not self.runtime_identity_issuer_public_key or not self.runtime_identity_audience:
            _reject("descriptor_trust_missing", "descriptor issuer key and audience are required")
        if not self.receipt_trust_purpose:
            _reject("receipt_trust_missing", "receipt trust registry and purpose are required")


@dataclass(frozen=True, slots=True)
class WiringAttestation:
    schema: str
    purpose: str
    assurance_class: str
    evidence_kind: str
    scope: GateScope
    runtime: RuntimeWiringBinding
    execution_boundary: str
    package: PackageWiringBinding
    policy_head: ManagedPolicyProvenance
    policy_provenance_hash: str
    policy_issued_at: str
    policy_fresh_until: str
    policy_expires_at: str
    policy_mode: str
    suite_id: str
    suite_hash: str
    results: tuple[ObservedWiringCase, ...]
    sequence: int
    nonce: str
    issued_at: str
    expires_at: str
    signature_algorithm: str
    signing_key_id: str
    attestation_hash: str
    signature: str

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Self:
        _validate_ijson(payload, "wiring attestation")
        fields = {field.name for field in dataclasses.fields(cls)}
        _exact_keys(payload, "wiring attestation", fields)
        results_raw = _sequence(payload.get("results"), "results")
        results = tuple(
            ObservedWiringCase.from_dict(_mapping(item, "case result")) for item in results_raw
        )
        expected_ids = tuple(case.case_id for case in WIRING_SUITE_SPEC)
        if tuple(result.case_id for result in results) != expected_ids:
            _reject("case_manifest_mismatch", "case results must be complete and in exact order")
        for result, spec in zip(results, WIRING_SUITE_SPEC, strict=True):
            if (
                result.dispatcher != spec.dispatcher
                or result.classification != spec.classification
                or result.outcome != spec.expected_outcome
                or result.side_effect_count != spec.expected_side_effect_count
                or result.argument_hash != spec.argument_hash
                or result.action_hash
                != sha256_json({"tool": spec.tool, "argument_hash": spec.argument_hash})
                or result.executor_verified != spec.expected_executor_verified
                or result.receipt_rejection_code != spec.expected_rejection_code
            ):
                _reject("case_manifest_mismatch", f"case {result.case_id} contradicts fixed suite")
        if results[0].receipt_signature_algorithm != "ed25519" or not results[0].executor_verified:
            _reject(
                "native_receipt_required", "ALLOW case requires executor-verified Ed25519 receipt"
            )
        if results[5].executor_verified:
            _reject("hook_assurance_invalid", "Claude hook must remain decision_only")
        return cls(
            schema=_literal(payload, "schema", WIRING_ATTESTATION_SCHEMA),
            purpose=_literal(payload, "purpose", WIRING_ATTESTATION_PURPOSE),
            assurance_class=_literal(payload, "assurance_class", _ASSURANCE_CLASS),
            evidence_kind=_literal(payload, "evidence_kind", _EVIDENCE_KIND),
            scope=GateScope.from_dict(_mapping(payload.get("scope"), "scope")),
            runtime=RuntimeWiringBinding.from_dict(_mapping(payload.get("runtime"), "runtime")),
            execution_boundary=_string(payload, "execution_boundary", "wiring attestation"),
            package=PackageWiringBinding.from_dict(_mapping(payload.get("package"), "package")),
            policy_head=_provenance_from_dict(_mapping(payload.get("policy_head"), "policy_head")),
            policy_provenance_hash=_digest(payload, "policy_provenance_hash", "wiring attestation"),
            policy_issued_at=_timestamp_string(payload, "policy_issued_at", "wiring attestation"),
            policy_fresh_until=_timestamp_string(
                payload, "policy_fresh_until", "wiring attestation"
            ),
            policy_expires_at=_timestamp_string(payload, "policy_expires_at", "wiring attestation"),
            policy_mode=_literal(payload, "policy_mode", "fresh"),
            suite_id=_literal(payload, "suite_id", WIRING_SUITE_ID),
            suite_hash=_digest(payload, "suite_hash", "wiring attestation"),
            results=results,
            sequence=_positive_int(payload, "sequence", "wiring attestation"),
            nonce=_string(payload, "nonce", "wiring attestation"),
            issued_at=_timestamp_string(payload, "issued_at", "wiring attestation"),
            expires_at=_timestamp_string(payload, "expires_at", "wiring attestation"),
            signature_algorithm=_literal(payload, "signature_algorithm", "ed25519"),
            signing_key_id=_string(payload, "signing_key_id", "wiring attestation"),
            attestation_hash=_digest(payload, "attestation_hash", "wiring attestation"),
            signature=_signature(payload, "signature", "wiring attestation"),
        )

    def unsigned_payload(self) -> dict[str, Any]:
        payload = self.to_dict()
        payload.pop("attestation_hash")
        payload.pop("signature")
        return payload

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "purpose": self.purpose,
            "assurance_class": self.assurance_class,
            "evidence_kind": self.evidence_kind,
            "scope": self.scope.to_dict(),
            "runtime": self.runtime.to_dict(),
            "execution_boundary": self.execution_boundary,
            "package": self.package.to_dict(),
            "policy_head": self.policy_head.to_dict(),
            "policy_provenance_hash": self.policy_provenance_hash,
            "policy_issued_at": self.policy_issued_at,
            "policy_fresh_until": self.policy_fresh_until,
            "policy_expires_at": self.policy_expires_at,
            "policy_mode": self.policy_mode,
            "suite_id": self.suite_id,
            "suite_hash": self.suite_hash,
            "results": [result.to_dict() for result in self.results],
            "sequence": self.sequence,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature_algorithm": self.signature_algorithm,
            "signing_key_id": self.signing_key_id,
            "attestation_hash": self.attestation_hash,
            "signature": self.signature,
        }


def verify_wiring_attestation(
    artifact: WiringAttestation, *, expected: ExpectedWiringContext
) -> WiringAttestation:
    """Verify in-process public-method observations, never deployed ingress wiring."""
    if type(artifact) is not WiringAttestation:
        _reject("artifact_type_invalid", "artifact must be WiringAttestation")
    artifact = WiringAttestation.from_dict(artifact.to_dict())
    if artifact.suite_hash != WIRING_SUITE_HASH:
        _reject("suite_hash_mismatch", "suite hash mismatch")
    if artifact.policy_head.compute_hash() != artifact.policy_provenance_hash:
        _reject("policy_provenance_mismatch", "policy provenance hash mismatch")
    unsigned = artifact.unsigned_payload()
    if sha256_json(unsigned) != artifact.attestation_hash:
        _reject("attestation_hash_mismatch", "attestation hash mismatch")

    descriptor = expected.runtime_identity_descriptor
    try:
        descriptor.verify(
            expected.runtime_identity_issuer_public_key,
            expected_scope=expected.scope,
            expected_audience=expected.runtime_identity_audience,
            now=expected.now,
        )
    except ValueError as exc:
        raise WiringAttestationError(
            "descriptor_invalid", "runtime identity descriptor verification failed"
        ) from exc
    if descriptor.scope != expected.scope or artifact.scope != expected.scope:
        _reject("scope_mismatch", "scope mismatch")
    if artifact.execution_boundary != expected.execution_boundary:
        _reject("boundary_mismatch", "execution boundary mismatch")
    if descriptor.runtime_identity_id != artifact.runtime.runtime_identity_id:
        _reject("runtime_identity_mismatch", "runtime identity mismatch")
    if descriptor.credential_id != artifact.runtime.credential_id:
        _reject("credential_mismatch", "credential mismatch")
    if descriptor.credential_generation != artifact.runtime.credential_generation:
        _reject("credential_generation_mismatch", "credential_generation mismatch")
    if artifact.runtime.workload_key_id != expected.workload_key_id:
        _reject("workload_key_mismatch", "workload key mismatch")
    if artifact.signing_key_id != artifact.runtime.workload_key_id:
        _reject("workload_key_mismatch", "workload key signing id mismatch")
    if descriptor.public_key_thumbprint != artifact.runtime.public_key_thumbprint:
        _reject("workload_key_mismatch", "workload key thumbprint mismatch")
    if artifact.package.runtime_build_digest != expected.runtime_build_digest:
        _reject("runtime_build_mismatch", "runtime build digest mismatch")
    if artifact.package.configuration_digest != expected.configuration_digest:
        _reject("configuration_mismatch", "configuration digest mismatch")
    if canonical_json(artifact.policy_head.to_dict()) != canonical_json(dict(expected.policy_head)):
        _reject("policy_head_mismatch", "current policy head mismatch")
    if artifact.policy_provenance_hash != expected.policy_provenance_hash:
        _reject("policy_provenance_mismatch", "policy provenance mismatch")
    if (
        artifact.policy_issued_at != expected.policy_issued_at
        or artifact.policy_fresh_until != expected.policy_fresh_until
        or artifact.policy_expires_at != expected.policy_expires_at
        or artifact.policy_mode != expected.policy_mode
    ):
        _reject("policy_currentness_mismatch", "policy currentness mismatch")
    if any(
        result.policy_hash != artifact.policy_head.content_hash
        or result.policy_version_id != artifact.policy_head.policy_version_id
        or result.policy_provenance_hash != artifact.policy_provenance_hash
        for result in artifact.results[:-1]
    ) or any(
        value
        for result in artifact.results[-1:]
        for value in (result.policy_hash, result.policy_version_id, result.policy_provenance_hash)
    ):
        _reject("case_policy_mismatch", "case policy binding mismatch")

    now = expected.now.astimezone(UTC)
    policy_issued = _parse_timestamp(artifact.policy_issued_at, "policy_issued_at")
    policy_fresh_until = _parse_timestamp(artifact.policy_fresh_until, "policy_fresh_until")
    policy_expires_at = _parse_timestamp(artifact.policy_expires_at, "policy_expires_at")
    if not policy_issued <= now < policy_fresh_until < policy_expires_at:
        _reject("policy_time_order_invalid", "policy issued/fresh/expiry ordering is invalid")
    if artifact.policy_mode != "fresh" or now >= _parse_timestamp(
        artifact.policy_fresh_until, "policy_fresh_until"
    ):
        _reject("policy_not_fresh", "policy snapshot is not fresh at verification")
    descriptor_expiry = _parse_timestamp(descriptor.expires_at, "descriptor.expires_at")
    if now >= descriptor_expiry:
        _reject("descriptor_expired", "runtime identity descriptor expired")
    issued = _parse_timestamp(artifact.issued_at, "issued_at")
    expires = _parse_timestamp(artifact.expires_at, "expires_at")
    if issued > now:
        _reject("issued_at_future", "attestation issued_at is in the future")
    if now >= expires:
        _reject("attestation_expired", "attestation expired")
    if expires <= issued or (expires - issued).total_seconds() > _MAX_ATTESTATION_TTL_SECONDS:
        _reject("attestation_ttl_invalid", "attestation TTL is invalid")
    if artifact.nonce != expected.expected_nonce:
        _reject("nonce_mismatch", "verifier nonce mismatch")
    if artifact.sequence <= expected.minimum_sequence:
        _reject("sequence_replay", "sequence did not advance high water")
    if not verify_ed25519(
        descriptor.public_key_bytes, canonical_json(unsigned).encode("utf-8"), artifact.signature
    ):
        _reject("signature_invalid", "workload signature invalid")
    for result, spec in zip(artifact.results, WIRING_SUITE_SPEC, strict=True):
        _verify_case_evidence_presence(result, spec)
    for result, spec in zip(artifact.results, WIRING_SUITE_SPEC, strict=True):
        _verify_audit_evidence(result, spec, artifact, expected=expected)
    _verify_audit_chain(artifact.results)
    _verify_native_allow_evidence(artifact.results[0], artifact, expected)
    if not expected.replay_guard.consume(
        namespace_digest=_replay_namespace_digest(artifact),
        nonce=artifact.nonce,
        sequence=artifact.sequence,
    ):
        _reject("replay_rejected", "atomic replay guard rejected attestation")
    return artifact


def _verify_case_evidence_presence(result: ObservedWiringCase, spec: WiringCaseSpec) -> None:
    receipt_labels = (
        result.receipt_id,
        result.receipt_hash,
        result.receipt_signature_algorithm,
        result.receipt_signing_key_id,
        result.receipt_expires_at,
    )
    if spec.expected_receipt_evidence:
        valid_receipt_shape = all(receipt_labels) and bool(result.receipt)
    else:
        valid_receipt_shape = not any(receipt_labels) and result.receipt == {}
    if spec.expected_consumption_evidence:
        valid_consumption_shape = bool(result.consumption_commitment) and bool(
            result.consumption_entry
        )
    else:
        valid_consumption_shape = (
            result.consumption_commitment == "" and result.consumption_entry == {}
        )
    if not valid_receipt_shape or not valid_consumption_shape or not result.audit_event:
        _reject("evidence_presence_invalid", f"{result.case_id} evidence presence mismatch")


def _verify_native_allow_evidence(
    result: ObservedWiringCase,
    artifact: WiringAttestation,
    expected: ExpectedWiringContext,
) -> None:
    raw_receipt = dict(result.receipt)
    audit_event = dict(result.audit_event)
    expected_audit_keys = {
        "actor",
        "argument_hash",
        "decision",
        "decision_request_hash",
        "event_hash",
        "event_id",
        "goal",
        "matched_rules",
        "path",
        "policy_provenance_hash",
        "policy_version",
        "previous_hash",
        "reason",
        "state_hash",
        "timestamp_iso",
        "tool",
        "transformed_args",
    }
    _exact_keys(audit_event, "ALLOW audit event", expected_audit_keys)
    for field in (
        "receipt_id",
        "request_id",
        "actor",
        "proposed_action",
        "argument_hash",
        "policy_version",
        "policy_hash",
        "policy_bundle_id",
        "decision",
        "timestamp",
        "previous_audit_hash",
        "audit_event_hash",
    ):
        _string(raw_receipt, field, "ALLOW receipt")
    _string(raw_receipt, "declared_goal", "ALLOW receipt", allow_empty=True)
    if not isinstance(raw_receipt.get("matched_rules"), list) or not isinstance(
        audit_event.get("matched_rules"), list
    ):
        _reject("audit_evidence_type_invalid", "matched_rules must be JSON lists")
    if any(type(rule) is not str for rule in raw_receipt["matched_rules"]) or any(
        type(rule) is not str for rule in audit_event["matched_rules"]
    ):
        _reject("audit_evidence_type_invalid", "matched_rules entries must be strings")
    if not isinstance(raw_receipt.get("transformations"), list):
        _reject("audit_evidence_type_invalid", "receipt transformations must be a JSON list")
    transformed_args = audit_event.get("transformed_args")
    if transformed_args is not None and not isinstance(transformed_args, Mapping):
        _reject(
            "audit_evidence_type_invalid",
            "audit transformed_args must be an object or null",
        )
    try:
        receipt = DecisionReceipt.from_dict(raw_receipt)
    except (KeyError, TypeError, ValueError) as exc:
        raise WiringAttestationError("receipt_invalid", "ALLOW receipt is malformed") from exc
    if set(result.receipt) != set(receipt.to_dict()):
        _reject("receipt_shape_invalid", "ALLOW receipt contains missing or unknown fields")
    constraints = {
        "schema": "acgs.managed-policy-execution/v1",
        "policy_provenance": artifact.policy_head.to_dict(),
        "policy_provenance_hash": artifact.policy_provenance_hash,
    }
    try:
        receipt.verify(
            expected_tenant_id=artifact.scope.org_id,
            expected_project_id=artifact.scope.project_id,
            expected_environment_id=artifact.scope.environment,
            expected_execution_boundary=artifact.scope.gate_id,
            expected_audit_hash=result.audit_hash,
            expected_args={"probe": "allow"},
            expected_action=_TOOLS["allow"],
            expected_actor=expected.runtime_identity_descriptor.runtime_identity_id,
            expected_policy_hash=artifact.policy_head.content_hash,
            expected_policy_bundle_id=artifact.policy_head.policy_version_id,
            expected_constraints=constraints,
            trust_registry=expected.receipt_trust_registry,
            trust_purpose=expected.receipt_trust_purpose,
            require_signature=True,
            require_expiry=True,
            now_iso=expected.now.astimezone(UTC).isoformat(),
        )
    except ReceiptValidationError as exc:
        raise WiringAttestationError(
            "receipt_invalid", "ALLOW receipt verification failed"
        ) from exc
    if (
        result.receipt_hash != receipt.receipt_hash
        or result.receipt_id != receipt.receipt_id
        or result.receipt_signature_algorithm != receipt.signature_algorithm
        or result.receipt_signing_key_id != receipt.signing_key_id
        or result.receipt_expires_at != receipt.expires_at
    ):
        _reject("receipt_binding_mismatch", "ALLOW receipt labels contradict signed receipt")

    event_hash = _string(audit_event, "event_hash", "ALLOW audit event")
    unsigned_event = dict(audit_event)
    unsigned_event.pop("event_hash")
    if sha256_json(unsigned_event) != event_hash or event_hash != receipt.audit_event_hash:
        _reject("audit_evidence_invalid", "ALLOW audit event hash or receipt anchor mismatch")
    expected_transformations = (
        []
        if transformed_args is None
        else [{"field": key, "value": value} for key, value in transformed_args.items()]
    )
    if (
        receipt.receipt_id != _string(audit_event, "event_id", "ALLOW audit event")
        or receipt.request_id != _string(audit_event, "decision_request_hash", "ALLOW audit event")
        or receipt.actor != _string(audit_event, "actor", "ALLOW audit event")
        or receipt.actor != expected.runtime_identity_descriptor.runtime_identity_id
        or receipt.proposed_action != _string(audit_event, "tool", "ALLOW audit event")
        or receipt.argument_hash != _string(audit_event, "argument_hash", "ALLOW audit event")
        or receipt.declared_goal
        != _string(audit_event, "goal", "ALLOW audit event", allow_empty=True)
        or receipt.policy_version != _string(audit_event, "policy_version", "ALLOW audit event")
        or receipt.policy_version != artifact.policy_head.version
        or receipt.policy_hash != artifact.policy_head.content_hash
        or receipt.policy_bundle_id != artifact.policy_head.policy_version_id
        or receipt.decision != _string(audit_event, "decision", "ALLOW audit event")
        or receipt.decision != "allow"
        or receipt.matched_rules != audit_event["matched_rules"]
        or raw_receipt["transformations"] != expected_transformations
        or receipt.timestamp != _string(audit_event, "timestamp_iso", "ALLOW audit event")
        or receipt.previous_audit_hash != _string(audit_event, "previous_hash", "ALLOW audit event")
        or receipt.audit_event_hash != event_hash
        or audit_event["policy_provenance_hash"] != artifact.policy_provenance_hash
        or receipt.constraints.get("policy_provenance_hash") != artifact.policy_provenance_hash
        or receipt.constraints.get("policy_provenance") != artifact.policy_head.to_dict()
    ):
        _reject("audit_evidence_invalid", "ALLOW audit event contradicts signed receipt")

    entry = dict(result.consumption_entry)
    _exact_keys(
        entry,
        "ALLOW consumption entry",
        {
            "actor",
            "consumed_at",
            "consumed_key",
            "entry_hash",
            "expires_at",
            "previous_hash",
            "proposed_action",
            "receipt_hash",
            "request_id",
            "tenant_id",
        },
    )
    entry_hash = _string(entry, "entry_hash", "ALLOW consumption entry")
    for digest_field in ("consumed_key", "entry_hash", "previous_hash", "receipt_hash"):
        _require_hex(_string(entry, digest_field, "ALLOW consumption entry"), digest_field)
    consumed_at = _parse_timestamp(
        _string(entry, "consumed_at", "ALLOW consumption entry"), "consumed_at"
    )
    receipt_issued_at = _parse_timestamp(receipt.timestamp, "receipt.timestamp")
    audit_issued_at = _parse_timestamp(
        _string(audit_event, "timestamp_iso", "ALLOW audit event"), "audit.timestamp_iso"
    )
    ledger_expires_at = _parse_timestamp(
        _string(entry, "expires_at", "ALLOW consumption entry"), "ledger.expires_at"
    )
    verifier_upper_bound = expected.now.astimezone(UTC) + timedelta(
        seconds=DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS
    )
    unsigned_entry = dict(entry)
    unsigned_entry.pop("entry_hash")
    if sha256_json(unsigned_entry) != entry_hash:
        _reject("consumption_evidence_invalid", "consumption entry hash mismatch")
    if (
        entry["consumed_key"] != receipt.audit_event_hash
        or entry["receipt_hash"] != receipt.receipt_hash
        or entry["actor"] != receipt.actor
        or entry["actor"] != expected.runtime_identity_descriptor.runtime_identity_id
        or entry["proposed_action"] != receipt.proposed_action
        or entry["tenant_id"] != receipt.tenant_id
        or entry["request_id"] != receipt.request_id
        or entry["expires_at"] != receipt.expires_at
        or not receipt_issued_at <= consumed_at
        or not audit_issued_at <= consumed_at
        or not _parse_timestamp(artifact.issued_at, "issued_at")
        <= consumed_at
        <= verifier_upper_bound
        or consumed_at >= _parse_timestamp(artifact.expires_at, "expires_at")
        or consumed_at >= ledger_expires_at
        or result.consumption_commitment
        != sha256_json({"previous_hash": entry["previous_hash"], "entry_hash": entry_hash})
    ):
        _reject("consumption_evidence_invalid", "consumption entry contradicts receipt")


def _verify_audit_evidence(
    result: ObservedWiringCase,
    spec: WiringCaseSpec,
    artifact: WiringAttestation,
    *,
    expected: ExpectedWiringContext,
) -> None:
    policy_bound = spec.expected_policy_binding
    event = dict(result.audit_event)
    expected_keys = {
        "actor",
        "argument_hash",
        "decision",
        "decision_request_hash",
        "event_hash",
        "event_id",
        "goal",
        "matched_rules",
        "path",
        "policy_version",
        "previous_hash",
        "reason",
        "state_hash",
        "timestamp_iso",
        "tool",
        "transformed_args",
    }
    if policy_bound:
        expected_keys.add("policy_provenance_hash")
    _exact_keys(
        event,
        f"{result.case_id} audit event",
        expected_keys,
    )
    if not isinstance(event.get("matched_rules"), list):
        _reject(
            "audit_evidence_type_invalid",
            f"{result.case_id} matched_rules must be a JSON list",
        )
    event_hash = _string(event, "event_hash", f"{result.case_id} audit event")
    unsigned = dict(event)
    unsigned.pop("event_hash")
    if sha256_json(unsigned) != event_hash or event_hash != result.audit_hash:
        _reject("audit_evidence_invalid", f"{result.case_id} audit event hash mismatch")
    if (
        event["tool"] != spec.tool
        or event["argument_hash"] != spec.argument_hash
        or event["actor"] != result.actor
        or event["previous_hash"] != result.previous_audit_hash
        or event["reason"] != spec.expected_audit_reason
    ):
        _reject(
            "audit_evidence_invalid",
            f"{result.case_id} audit event or fixed non-sensitive probe reason mismatch",
        )
    expected_actor = (
        expected.runtime_identity_descriptor.runtime_identity_id
        if spec.expected_actor_kind == "authenticated_runtime"
        else "<unattributed>"
    )
    expected_policy_version = (
        artifact.policy_head.version if policy_bound else "gateway/synthesized/v1"
    )
    expected_request_hash = ToolCall(
        spec.tool,
        _safe_probe_arguments(spec.case_id),
        actor=expected_actor,
    ).decision_request_hash()
    event_id_pattern = (
        r"ev_[0-9a-f]{16}" if spec.expected_event_id_kind == "managed_event_id" else r"[0-9a-f]{32}"
    )
    if (
        event["decision"] != spec.expected_decision
        or event["actor"] != expected_actor
        or event["policy_version"] != expected_policy_version
        or tuple(event["matched_rules"]) != spec.expected_matched_rules
        or event["goal"] != ""
        or event["path"] != []
        or event["state_hash"] is not None
        or event["transformed_args"] is not None
        or event["decision_request_hash"] != expected_request_hash
        or re.fullmatch(event_id_pattern, str(event["event_id"])) is None
    ):
        _reject("audit_semantics_invalid", f"{result.case_id} audit semantics mismatch")
    event_time = _parse_timestamp(str(event["timestamp_iso"]), f"{result.case_id}.timestamp_iso")
    if not (
        _parse_timestamp(artifact.issued_at, "issued_at")
        <= event_time
        < _parse_timestamp(artifact.expires_at, "expires_at")
    ):
        _reject("audit_semantics_invalid", f"{result.case_id} audit time is out of window")
    provenance_hash = event.get("policy_provenance_hash") or ""
    if policy_bound and provenance_hash != artifact.policy_provenance_hash:
        _reject("audit_evidence_invalid", f"{result.case_id} policy binding mismatch")
    if not policy_bound and provenance_hash:
        _reject("audit_evidence_invalid", "structural bypass must be explicitly non-policy-bound")


def _verify_audit_chain(results: tuple[ObservedWiringCase, ...]) -> None:
    ordered = (*results[:6], results[7])
    for previous, current in zip(ordered, ordered[1:], strict=False):
        if current.previous_audit_hash != previous.audit_hash:
            _reject("audit_chain_invalid", "case audit chain continuity mismatch")
    if results[6].audit_event != results[0].audit_event:
        _reject("audit_chain_invalid", "tamper case must reuse the exact native ALLOW anchor")


def _safe_probe_arguments(case_id: str) -> Mapping[str, Any]:
    if case_id == "claude_hook.deny_decision_only":
        return _CLAUDE_PROBE_ARGUMENTS
    probe = {
        "invoke.allow_once": "allow",
        "mcp.deny_zero": "mcp",
        "openai.escalate_zero": "openai",
        "langgraph.deny_zero": "langgraph",
        "rest.deny_zero": "rest",
        "executor.tampered_receipt_zero": "allow",
        "sealed_handle.raw_bypass_zero": "bypass",
    }.get(case_id)
    if probe is None:
        _reject("case_manifest_mismatch", "unknown fixed conformance case")
    return {"probe": probe}


def _produce_wiring_attestation(
    *,
    gateway: UniversalGateway,
    runtime_identity_descriptor: RuntimeIdentityDescriptor,
    runtime_identity_issuer_public_key: bytes,
    runtime_identity_audience: str,
    workload_key_provider: WorkloadKeyProvider,
    receipt_consumption_ledger: ReceiptConsumptionLedger,
    authenticated_actor: str,
    nonce: str,
    sequence: int,
    runtime_build_digest: str,
    configuration_digest: str,
    issued_at: str,
    expires_at: str,
    now: datetime,
    probe_registrations: dict[str, tuple[Any, Any]],
) -> WiringAttestation:
    """Run the fixed public-dispatcher suite and sign observed evidence.

    The caller supplies the gateway's shared consumption ledger explicitly so
    exact native-receipt replay can be exercised through the public executor
    gate.  The returned statement remains workload self-attestation.
    """
    _validate_producer_inputs(
        gateway=gateway,
        descriptor=runtime_identity_descriptor,
        runtime_identity_issuer_public_key=runtime_identity_issuer_public_key,
        runtime_identity_audience=runtime_identity_audience,
        workload_key_provider=workload_key_provider,
        actor=authenticated_actor,
        nonce=nonce,
        sequence=sequence,
        runtime_build_digest=runtime_build_digest,
        configuration_digest=configuration_digest,
        issued_at=issued_at,
        expires_at=expires_at,
        now=now,
    )
    if not isinstance(gateway.policy, SyncedRuleSetPolicy):
        _reject("managed_policy_required", "producer requires SyncedRuleSetPolicy")
    with gateway.policy.receipt_binding_scope() as preflight_provenance:
        _validate_producer_provenance(gateway, runtime_identity_descriptor, preflight_provenance)
        _validate_policy_currentness(gateway.policy.current_snapshot_currentness(), now=now)
    collisions = sorted(set(gateway.tool_names()) & set(_TOOLS.values()))
    if collisions:
        _reject("reserved_tool_collision", f"reserved conformance tool exists: {collisions[0]}")

    counters = {name: 0 for name in _TOOLS}

    def probe(counter: str, value: str) -> Any:
        def run(**_: Any) -> str:
            counters[counter] += 1
            return value

        return run

    managed_policy = gateway.policy

    def register_probe(name: str, fn: Any) -> Any:
        sealed = gateway.register_tool(name, fn)
        probe_registrations[name] = (sealed, gateway._openai_specs[name])
        return sealed

    with managed_policy.receipt_binding_scope() as provenance:
        _validate_producer_provenance(gateway, runtime_identity_descriptor, provenance)
        policy_currentness = managed_policy.current_snapshot_currentness()
        _validate_policy_currentness(policy_currentness, now=now)
        allow_handle = register_probe(_TOOLS["allow"], probe("allow", "allow-ok"))
        del allow_handle
        register_probe(_TOOLS["mcp"], probe("mcp", "forbidden"))
        register_probe(_TOOLS["openai"], probe("openai", "forbidden"))
        register_probe(_TOOLS["rest"], probe("rest", "forbidden"))
        register_probe(_TOOLS["claude"], probe("claude", "forbidden"))
        bypass_handle = register_probe(_TOOLS["bypass"], probe("bypass", "forbidden"))

        allow_args = {"probe": "allow"}
        allowed = gateway.invoke(authenticated_actor, _TOOLS["allow"], allow_args)
        if not allowed.executed or allowed.receipt is None or counters["allow"] != 1:
            _reject("allow_probe_failed", "native ALLOW did not execute exactly once")
        receipt = allowed.receipt
        if allowed.assurance_class != "native" or receipt.signature_algorithm != "ed25519":
            _reject("native_receipt_required", "ALLOW did not produce a native Ed25519 receipt")
        constraints = receipt.constraints
        if constraints.get("schema") != "acgs.managed-policy-execution/v1":
            _reject("policy_binding_missing", "ALLOW receipt lacks managed constraints")
        if constraints.get("policy_provenance") != provenance.to_dict():
            _reject("policy_head_mismatch", "ALLOW receipt provenance mismatch")
        if constraints.get("policy_provenance_hash") != provenance.compute_hash():
            _reject("policy_provenance_mismatch", "ALLOW receipt provenance hash mismatch")

        mcp_args = {"probe": "mcp"}
        mcp = gateway.handle_mcp_call(
            {"method": "tools/call", "params": {"name": _TOOLS["mcp"], "arguments": mcp_args}},
            actor=authenticated_actor,
        )
        mcp_meta = _mapping(
            _mapping(mcp.get("_meta"), "mcp._meta").get("gove_zone"), "mcp.gove_zone"
        )
        if mcp_meta.get("decision") != "denied" or counters["mcp"] != 0:
            _reject("mcp_probe_failed", "MCP DENY outcome mismatch")
        mcp_envelope = _mapping(mcp_meta.get("envelope"), "mcp.envelope")

        openai_args = {"probe": "openai"}
        openai = gateway.handle_openai_tool_call(
            {
                "id": "acgs-conformance-openai",
                "type": "function",
                "function": {"name": _TOOLS["openai"], "arguments": canonical_json(openai_args)},
            },
            actor=authenticated_actor,
        )
        openai_body = _json_object(openai.get("content"), "openai.content")
        if openai_body.get("status") != "escalated" or counters["openai"] != 0:
            _reject("openai_probe_failed", "OpenAI ESCALATE outcome mismatch")
        openai_envelope = _mapping(openai_body.get("envelope"), "openai.envelope")

        try:
            from langchain_core.tools import StructuredTool
        except ImportError as exc:
            raise WiringAttestationError(
                "optional_surface_missing", "langchain-core is required for fixed suite"
            ) from exc
        langgraph_args = {"probe": "langgraph"}

        def langgraph_probe(probe: str) -> str:
            counters["langgraph"] += 1
            return f"forbidden:{probe}"

        langgraph_tool = StructuredTool.from_function(
            func=langgraph_probe,
            name=_TOOLS["langgraph"],
            description="Reserved gove-zone wiring conformance probe.",
        )
        (governed_tool,) = gateway.langgraph_tools([langgraph_tool], actor=authenticated_actor)
        probe_registrations[_TOOLS["langgraph"]] = (
            gateway._tools[_TOOLS["langgraph"]],
            gateway._openai_specs[_TOOLS["langgraph"]],
        )
        langgraph_body = _json_object(governed_tool.invoke(langgraph_args), "langgraph.result")
        if langgraph_body.get("status") != "denied" or counters["langgraph"] != 0:
            _reject("langgraph_probe_failed", "LangGraph DENY outcome mismatch")
        langgraph_envelope = _mapping(langgraph_body.get("envelope"), "langgraph.envelope")

        rest_args = {"probe": "rest"}
        rest = gateway.handle_rest_call(
            {
                "tool": _TOOLS["rest"],
                "args": rest_args,
                "actor": "body-spoof-must-not-win",
            },
            actor=authenticated_actor,
        )
        rest_body = _mapping(rest.get("body"), "rest.body")
        if (
            rest.get("status") != 403
            or rest_body.get("actor") != authenticated_actor
            or counters["rest"] != 0
        ):
            _reject("rest_probe_failed", "REST DENY or actor binding mismatch")
        rest_envelope = _mapping(rest_body.get("envelope"), "rest.envelope")

        claude_args = {"probe": "claude"}
        claude = gateway.handle_claude_hook(
            {"tool_name": _TOOLS["claude"], "tool_input": claude_args},
            actor=authenticated_actor,
        )
        hook_output = _mapping(claude.get("hookSpecificOutput"), "claude.hookSpecificOutput")
        hook_evidence = _mapping(claude.get("gove_zone"), "claude.gove_zone")
        decisions = _sequence(hook_evidence.get("decisions"), "claude.decisions")
        if (
            hook_output.get("permissionDecision") != "deny"
            or hook_evidence.get("execution_classification") != "decision_only"
            or len(decisions) != 1
            or counters["claude"] != 0
            or "receipts" in hook_evidence
        ):
            _reject("claude_probe_failed", "Claude decision-only DENY mismatch")
        claude_commitment = _mapping(decisions[0], "claude.decision")

        tampered_count = 0

        def tampered_spy(**_: Any) -> None:
            nonlocal tampered_count
            tampered_count += 1

        tampered = dataclasses.replace(receipt, argument_hash="0" * 64)
        tamper_ledger = ReceiptConsumptionLedger(
            receipt_consumption_ledger.path.with_name(
                receipt_consumption_ledger.path.name + ".attestation-tamper"
            )
        )
        tamper_rejection_code = ""
        try:
            _replay_receipt(
                gateway,
                tamper_ledger,
                tampered,
                tampered_spy,
                allow_args,
                authenticated_actor,
                provenance,
            )
        except ReceiptValidationError as exc:
            tamper_rejection_code = exc.reason_code.value if exc.reason_code is not None else ""
            if tamper_rejection_code != WIRING_SUITE_SPEC[6].expected_rejection_code:
                _reject(
                    "tampered_receipt_wrong_rejection",
                    "fixed argument-hash mutation was rejected for an unexpected reason",
                )
        else:
            _reject("tampered_receipt_accepted", "tampered receipt reached side effect")
        if tampered_count != 0:
            _reject("tampered_receipt_executed", "tampered receipt executed a side effect")
        if tamper_ledger.is_consumed(receipt.audit_event_hash):
            _reject("tampered_receipt_burned", "invalid receipt verification burned approval")

        replay_count = 0

        def replay_spy(**_: Any) -> None:
            nonlocal replay_count
            replay_count += 1

        try:
            _replay_receipt(
                gateway,
                receipt_consumption_ledger,
                receipt,
                replay_spy,
                allow_args,
                authenticated_actor,
                provenance,
            )
        except ReceiptAlreadyUsedError:
            pass
        else:
            _reject("receipt_replay_accepted", "consumed receipt replay was accepted")
        if replay_count != 0:
            _reject("receipt_replay_executed", "receipt replay executed a side effect")

        try:
            bypass_handle(probe="bypass")
        except BypassAttemptError:
            pass
        else:
            _reject("raw_bypass_accepted", "sealed handle bypass was accepted")
        if counters["bypass"] != 0:
            _reject("raw_bypass_executed", "sealed handle bypass executed")
        bypass = gateway.bypass_attempts()[-1]

        if any(counters[name] != 0 for name in counters if name != "allow"):
            _reject("forbidden_effect", "a forbidden conformance probe executed")
        ledger_report = receipt_consumption_ledger.verify_ledger()
        if not ledger_report.get("valid") or not ledger_report.get("last_hash"):
            _reject("consumption_unverified", "receipt consumption commitment unavailable")
        if not receipt_consumption_ledger.is_consumed(receipt.audit_event_hash):
            _reject("consumption_unverified", "native receipt was not consumed")
        consumption_entry = receipt_consumption_ledger.entry_for(receipt.audit_event_hash)
        if consumption_entry is None:
            _reject("consumption_unverified", "native receipt consumption entry is missing")
        audit_event = _audit_event_for(gateway, receipt.audit_event_hash)

        common = {
            "actor": authenticated_actor,
            "policy_hash": provenance.content_hash,
            "policy_version_id": provenance.policy_version_id,
            "policy_provenance_hash": provenance.compute_hash(),
            "policy_issued_at": policy_currentness["issued_at"],
        }
        results = (
            _observed_case(
                WIRING_SUITE_SPEC[0],
                _TOOLS["allow"],
                allow_args,
                allowed.audit_hash,
                receipt.previous_audit_hash,
                1,
                True,
                common,
                receipt=receipt,
                consumption_commitment=sha256_json(
                    {
                        "previous_hash": consumption_entry["previous_hash"],
                        "entry_hash": consumption_entry["entry_hash"],
                    }
                ),
                receipt_evidence=receipt.to_dict(),
                audit_event=audit_event,
                consumption_entry=consumption_entry,
            ),
            _observed_case(
                WIRING_SUITE_SPEC[1],
                _TOOLS["mcp"],
                mcp_args,
                str(mcp_envelope["audit_hash"]),
                "",
                0,
                False,
                common,
                audit_event=_audit_event_for(gateway, str(mcp_envelope["audit_hash"])),
            ),
            _observed_case(
                WIRING_SUITE_SPEC[2],
                _TOOLS["openai"],
                openai_args,
                str(openai_envelope["audit_hash"]),
                "",
                0,
                False,
                common,
                audit_event=_audit_event_for(gateway, str(openai_envelope["audit_hash"])),
            ),
            _observed_case(
                WIRING_SUITE_SPEC[3],
                _TOOLS["langgraph"],
                langgraph_args,
                str(langgraph_envelope["audit_hash"]),
                "",
                0,
                False,
                common,
                audit_event=_audit_event_for(gateway, str(langgraph_envelope["audit_hash"])),
            ),
            _observed_case(
                WIRING_SUITE_SPEC[4],
                _TOOLS["rest"],
                rest_args,
                str(rest_envelope["audit_hash"]),
                "",
                0,
                False,
                common,
                audit_event=_audit_event_for(gateway, str(rest_envelope["audit_hash"])),
            ),
            _observed_case(
                WIRING_SUITE_SPEC[5],
                f"runtime.{_TOOLS['claude']}",
                claude_args,
                str(claude_commitment["audit_hash"]),
                "",
                0,
                False,
                common,
                audit_event=_audit_event_for(gateway, str(claude_commitment["audit_hash"])),
            ),
            _observed_case(
                WIRING_SUITE_SPEC[6],
                _TOOLS["allow"],
                allow_args,
                receipt.audit_event_hash,
                receipt.previous_audit_hash,
                0,
                True,
                common,
                receipt_rejection_code=tamper_rejection_code,
                audit_event=audit_event,
            ),
            _observed_case(
                WIRING_SUITE_SPEC[7],
                _TOOLS["bypass"],
                {"probe": "bypass"},
                str(bypass["audit_hash"]),
                "",
                0,
                False,
                {
                    "actor": "<unattributed>",
                    "policy_hash": "",
                    "policy_version_id": "",
                    "policy_provenance_hash": "",
                },
                audit_event=_audit_event_for(gateway, str(bypass["audit_hash"])),
            ),
        )

        unsigned = {
            "schema": WIRING_ATTESTATION_SCHEMA,
            "purpose": WIRING_ATTESTATION_PURPOSE,
            "assurance_class": _ASSURANCE_CLASS,
            "evidence_kind": _EVIDENCE_KIND,
            "scope": runtime_identity_descriptor.scope.to_dict(),
            "runtime": {
                "runtime_identity_id": runtime_identity_descriptor.runtime_identity_id,
                "credential_id": runtime_identity_descriptor.credential_id,
                "credential_generation": runtime_identity_descriptor.credential_generation,
                "workload_key_id": workload_key_provider.key_id,
                "public_key_thumbprint": runtime_identity_descriptor.public_key_thumbprint,
            },
            "execution_boundary": gateway.execution_boundary,
            "package": {
                "name": "gove-zone",
                "version": _package_version(),
                "runtime_build_digest": runtime_build_digest,
                "configuration_digest": configuration_digest,
            },
            "policy_head": provenance.to_dict(),
            "policy_provenance_hash": provenance.compute_hash(),
            "policy_issued_at": policy_currentness["issued_at"],
            "policy_fresh_until": policy_currentness["fresh_until"],
            "policy_expires_at": policy_currentness["expires_at"],
            "policy_mode": policy_currentness["mode"],
            "suite_id": WIRING_SUITE_ID,
            "suite_hash": WIRING_SUITE_HASH,
            "results": [result.to_dict() for result in results],
            "sequence": sequence,
            "nonce": nonce,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "signature_algorithm": "ed25519",
            "signing_key_id": workload_key_provider.key_id,
        }
        artifact = WiringAttestation.from_dict(
            {
                **unsigned,
                "attestation_hash": sha256_json(unsigned),
                "signature": workload_key_provider.sign(canonical_json(unsigned).encode("utf-8")),
            }
        )

    self_guard = _SingleAcceptance()
    scoped_config = gateway.scoped_receipt_config
    assert scoped_config is not None
    verify_wiring_attestation(
        artifact,
        expected=ExpectedWiringContext(
            scope=runtime_identity_descriptor.scope,
            runtime_identity_descriptor=runtime_identity_descriptor,
            runtime_identity_issuer_public_key=runtime_identity_issuer_public_key,
            runtime_identity_audience=runtime_identity_audience,
            receipt_trust_registry=scoped_config.trust_registry,
            receipt_trust_purpose=scoped_config.trust_purpose,
            workload_key_id=workload_key_provider.key_id,
            execution_boundary=gateway.execution_boundary,
            runtime_build_digest=runtime_build_digest,
            configuration_digest=configuration_digest,
            policy_head=artifact.policy_head.to_dict(),
            policy_provenance_hash=artifact.policy_provenance_hash,
            policy_issued_at=artifact.policy_issued_at,
            policy_fresh_until=artifact.policy_fresh_until,
            policy_expires_at=artifact.policy_expires_at,
            policy_mode=artifact.policy_mode,
            expected_nonce=nonce,
            minimum_sequence=sequence - 1,
            now=now,
            replay_guard=self_guard,
        ),
    )
    return artifact


def produce_wiring_attestation(
    *,
    gateway: UniversalGateway,
    runtime_identity_descriptor: RuntimeIdentityDescriptor,
    runtime_identity_issuer_public_key: bytes,
    runtime_identity_audience: str,
    workload_key_provider: WorkloadKeyProvider,
    receipt_consumption_ledger: ReceiptConsumptionLedger,
    authenticated_actor: str,
    nonce: str,
    sequence: int,
    runtime_build_digest: str,
    configuration_digest: str,
    issued_at: str,
    expires_at: str,
    now: datetime,
) -> WiringAttestation:
    """Observe fixed in-process public methods; this does not prove deployed ingress wiring."""
    probe_registrations: dict[str, tuple[Any, Any]] = {}
    try:
        return _produce_wiring_attestation(
            gateway=gateway,
            runtime_identity_descriptor=runtime_identity_descriptor,
            runtime_identity_issuer_public_key=runtime_identity_issuer_public_key,
            runtime_identity_audience=runtime_identity_audience,
            workload_key_provider=workload_key_provider,
            receipt_consumption_ledger=receipt_consumption_ledger,
            authenticated_actor=authenticated_actor,
            nonce=nonce,
            sequence=sequence,
            runtime_build_digest=runtime_build_digest,
            configuration_digest=configuration_digest,
            issued_at=issued_at,
            expires_at=expires_at,
            now=now,
            probe_registrations=probe_registrations,
        )
    finally:
        for name, (sealed, spec) in probe_registrations.items():
            if gateway._tools.get(name) is sealed:
                gateway._tools.pop(name)
            if gateway._openai_specs.get(name) is spec:
                gateway._openai_specs.pop(name)


class _SingleAcceptance:
    def __init__(self) -> None:
        self._used = False

    def consume(self, *, namespace_digest: str, nonce: str, sequence: int) -> bool:
        del namespace_digest, nonce, sequence
        if self._used:
            return False
        self._used = True
        return True


def _replay_namespace_digest(artifact: WiringAttestation) -> str:
    return sha256_json(
        {
            "scope": artifact.scope.to_dict(),
            "runtime_identity_id": artifact.runtime.runtime_identity_id,
            "credential_id": artifact.runtime.credential_id,
            "credential_generation": artifact.runtime.credential_generation,
            "workload_key_id": artifact.runtime.workload_key_id,
            "public_key_thumbprint": artifact.runtime.public_key_thumbprint,
        }
    )


def _validate_producer_inputs(
    *,
    gateway: UniversalGateway,
    descriptor: RuntimeIdentityDescriptor,
    runtime_identity_issuer_public_key: bytes,
    runtime_identity_audience: str,
    workload_key_provider: WorkloadKeyProvider,
    actor: str,
    nonce: str,
    sequence: int,
    runtime_build_digest: str,
    configuration_digest: str,
    issued_at: str,
    expires_at: str,
    now: datetime,
) -> None:
    try:
        descriptor.verify(
            runtime_identity_issuer_public_key,
            expected_scope=descriptor.scope,
            expected_audience=runtime_identity_audience,
            now=now,
        )
    except ValueError as exc:
        raise WiringAttestationError(
            "descriptor_invalid", "runtime identity descriptor authentication failed"
        ) from exc
    if not actor or actor != descriptor.runtime_identity_id:
        _reject("actor_mismatch", "authenticated actor must match runtime identity")
    if not nonce or len(nonce) < 16:
        _reject("nonce_invalid", "verifier nonce must be unpredictable and non-empty")
    if type(sequence) is not int or sequence <= 0:
        _reject("sequence_invalid", "sequence must be positive")
    _require_hex(runtime_build_digest, "runtime_build_digest")
    _require_hex(configuration_digest, "configuration_digest")
    if now.tzinfo is None:
        _reject("clock_invalid", "producer clock must be timezone-aware")
    issued = _parse_timestamp(issued_at, "issued_at")
    expires = _parse_timestamp(expires_at, "expires_at")
    if issued > now.astimezone(UTC) or now.astimezone(UTC) >= expires:
        _reject("freshness_invalid", "attestation issuance window is not current")
    if expires <= issued or (expires - issued).total_seconds() > _MAX_ATTESTATION_TTL_SECONDS:
        _reject("attestation_ttl_invalid", "attestation TTL is invalid")
    if now.astimezone(UTC) >= _parse_timestamp(descriptor.expires_at, "descriptor.expires_at"):
        _reject("descriptor_expired", "runtime identity descriptor expired")
    provider_public = workload_key_provider.public_key_bytes()
    if provider_public != descriptor.public_key_bytes:
        _reject("workload_key_mismatch", "workload provider key does not match descriptor")
    if public_key_thumbprint(provider_public) != descriptor.public_key_thumbprint:
        _reject("workload_key_mismatch", "workload provider thumbprint mismatch")
    if (
        gateway.tenant_id != descriptor.scope.org_id
        or gateway.execution_boundary != descriptor.scope.gate_id
    ):
        _reject("scope_mismatch", "gateway scope does not match runtime descriptor")
    config = gateway.scoped_receipt_config
    if config is None:
        _reject("scope_mismatch", "managed gateway scope configuration missing")
    if (
        config.project_id != descriptor.scope.project_id
        or config.environment_id != descriptor.scope.environment
        or config.gate_id != descriptor.scope.gate_id
    ):
        _reject("scope_mismatch", "gateway configuration does not match runtime descriptor")


def _validate_producer_provenance(
    gateway: UniversalGateway,
    descriptor: RuntimeIdentityDescriptor,
    provenance: ManagedPolicyProvenance,
) -> None:
    config = gateway.scoped_receipt_config
    if config is None:
        _reject("scope_mismatch", "managed gateway scope configuration missing")
    if (
        provenance.runtime_identity_id != descriptor.runtime_identity_id
        or provenance.credential_id != descriptor.credential_id
        or provenance.credential_generation != descriptor.credential_generation
        or provenance.scope.org_id != descriptor.scope.org_id
        or provenance.scope.project_id != config.project_id
        or provenance.scope.environment_id != config.environment_id
        or provenance.scope.gate_id != gateway.execution_boundary
    ):
        _reject("policy_scope_mismatch", "managed policy provenance does not match runtime")


def _validate_policy_currentness(currentness: Mapping[str, str], *, now: datetime) -> None:
    policy_issued = _parse_timestamp(currentness["issued_at"], "policy_issued_at")
    policy_fresh = _parse_timestamp(currentness["fresh_until"], "policy_fresh_until")
    policy_expires = _parse_timestamp(currentness["expires_at"], "policy_expires_at")
    if (
        currentness["mode"] != "fresh"
        or not policy_issued <= now.astimezone(UTC) < policy_fresh < policy_expires
    ):
        _reject("policy_not_fresh", "producer requires a fresh signed policy snapshot")


def _replay_receipt(
    gateway: UniversalGateway,
    ledger: ReceiptConsumptionLedger,
    receipt: Any,
    tool_fn: Any,
    args: dict[str, Any],
    actor: str,
    provenance: ManagedPolicyProvenance,
) -> Any:
    config = gateway.scoped_receipt_config
    assert config is not None
    gate_kwargs = gateway.profile.as_gate_kwargs()
    gate_kwargs["consumption_ledger"] = ledger
    return execute_with_receipt(
        tool_fn=tool_fn,
        args=args,
        receipt=receipt,
        expected_tenant_id=gateway.tenant_id,
        expected_execution_boundary=gateway.execution_boundary,
        expected_action=_TOOLS["allow"],
        expected_actor=actor,
        expected_audit_hash=receipt.audit_event_hash,
        expected_policy_hash=provenance.content_hash,
        expected_policy_bundle_id=provenance.policy_version_id,
        expected_constraints={
            "schema": "acgs.managed-policy-execution/v1",
            "policy_provenance": provenance.to_dict(),
            "policy_provenance_hash": provenance.compute_hash(),
        },
        expected_project_id=config.project_id,
        expected_environment_id=config.environment_id,
        trust_registry=config.trust_registry,
        trust_purpose=config.trust_purpose,
        **gate_kwargs,
    )


def _observed_case(
    spec: WiringCaseSpec,
    tool: str,
    args: Mapping[str, Any],
    audit_hash: str,
    previous_audit_hash: str,
    side_effect_count: int,
    executor_verified: bool,
    common: Mapping[str, str],
    *,
    receipt: Any | None = None,
    receipt_rejection_code: str = "",
    consumption_commitment: str = "",
    receipt_evidence: Mapping[str, Any] | None = None,
    audit_event: Mapping[str, Any] | None = None,
    consumption_entry: Mapping[str, Any] | None = None,
) -> ObservedWiringCase:
    exact_audit_event = dict(audit_event or {})
    argument_hash = ToolCall(tool, dict(args), actor=common["actor"]).argument_hash()
    observed_previous_hash = previous_audit_hash
    if exact_audit_event:
        argument_hash = _digest(exact_audit_event, "argument_hash", f"{spec.case_id} audit event")
        observed_previous_hash = _digest(
            exact_audit_event, "previous_hash", f"{spec.case_id} audit event"
        )
    return ObservedWiringCase(
        case_id=spec.case_id,
        dispatcher=spec.dispatcher,
        classification=spec.classification,
        outcome=spec.expected_outcome,
        side_effect_count=side_effect_count,
        executor_verified=executor_verified,
        receipt_id=receipt.receipt_id if receipt is not None else "",
        receipt_hash=receipt.receipt_hash if receipt is not None else "",
        receipt_signature_algorithm=(receipt.signature_algorithm if receipt is not None else ""),
        receipt_signing_key_id=receipt.signing_key_id if receipt is not None else "",
        audit_hash=audit_hash,
        previous_audit_hash=observed_previous_hash or "0" * 64,
        action_hash=sha256_json({"tool": tool, "argument_hash": argument_hash}),
        argument_hash=argument_hash,
        actor=common["actor"],
        receipt_expires_at=receipt.expires_at if receipt is not None else "",
        receipt_rejection_code=receipt_rejection_code,
        policy_hash=common["policy_hash"],
        policy_version_id=common["policy_version_id"],
        policy_provenance_hash=common["policy_provenance_hash"],
        consumption_commitment=consumption_commitment,
        receipt=dict(receipt_evidence or {}),
        audit_event=exact_audit_event,
        consumption_entry=dict(consumption_entry or {}),
    )


def _json_object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, str):
        _reject("surface_shape_invalid", f"{label} must be JSON text")
    try:
        parsed = json.loads(value)
    except ValueError as exc:
        raise WiringAttestationError("surface_shape_invalid", f"{label} is invalid JSON") from exc
    return _mapping(parsed, label)


def _audit_event_for(gateway: UniversalGateway, event_hash: str) -> Mapping[str, Any]:
    matches = [
        event for event in gateway._audit.iter_events() if event.get("event_hash") == event_hash
    ]
    if len(matches) != 1:
        _reject("audit_evidence_missing", "exact native ALLOW audit event is unavailable")
    return matches[0]


def _package_version() -> str:
    try:
        return importlib.metadata.version("gove-zone")
    except importlib.metadata.PackageNotFoundError:
        return "1.0.0rc1"


def _provenance_from_dict(payload: Mapping[str, Any]) -> ManagedPolicyProvenance:
    names = {field.name for field in dataclasses.fields(ManagedPolicyProvenance)}
    _exact_keys(payload, "policy_head", names)
    values: dict[str, Any] = {}
    for field in dataclasses.fields(ManagedPolicyProvenance):
        name = field.name
        if name == "scope":
            values[name] = PolicySyncScope.from_dict(
                _mapping(payload.get(name), "policy_head.scope")
            )
        elif name in {
            "credential_generation",
            "head_generation",
            "policy_trust_epoch",
            "attestation_trust_epoch",
        }:
            values[name] = _positive_int(payload, name, "policy_head")
        elif name.endswith("hash") or name.endswith("fingerprint"):
            values[name] = _digest(payload, name, "policy_head")
        else:
            values[name] = _string(payload, name, "policy_head")
    return ManagedPolicyProvenance(**values)


def _exact_keys(payload: Mapping[str, Any], label: str, expected: set[str]) -> None:
    actual = set(payload)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        _reject("shape_missing", f"{label} missing keys: {', '.join(missing)}")
    if unknown:
        _reject("shape_unknown", f"{label} unknown keys: {', '.join(unknown)}")


def _validate_ijson(value: Any, label: str) -> None:
    """Reject values that cannot be represented unambiguously as I-JSON."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                _reject("ijson_invalid", f"{label} contains a non-string object key")
            _validate_ijson(key, f"{label}.<key>")
            _validate_ijson(item, f"{label}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_ijson(item, f"{label}[{index}]")
        return
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise WiringAttestationError(
                "ijson_invalid", f"{label} contains invalid Unicode"
            ) from exc
        return
    if type(value) is int:
        if not -(2**53 - 1) <= value <= 2**53 - 1:
            _reject("ijson_invalid", f"{label} contains an unsafe-range integer")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _reject("ijson_invalid", f"{label} contains a non-finite number")
        return
    _reject("ijson_invalid", f"{label} contains a non-JSON value")


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _reject("type_invalid", f"{label} must be an object")
    return value


def _sequence(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        _reject("type_invalid", f"{label} must be a list")
    return value


def _string(
    payload: Mapping[str, Any], field: str, label: str, *, allow_empty: bool = False
) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        _reject("type_invalid", f"{label}.{field} must be a string")
    return value


def _literal(payload: Mapping[str, Any], field: str, expected: str) -> str:
    value = _string(payload, field, "wiring attestation")
    if value != expected:
        _reject("literal_mismatch", f"{field} must be {expected}")
    return value


def _positive_int(payload: Mapping[str, Any], field: str, label: str) -> int:
    value = payload.get(field)
    if type(value) is not int or value <= 0:
        _reject("type_invalid", f"{label}.{field} must be a positive integer")
    return value


def _nonnegative_int(payload: Mapping[str, Any], field: str, label: str) -> int:
    value = payload.get(field)
    if type(value) is not int or value < 0:
        _reject("type_invalid", f"{label}.{field} must be a non-negative integer")
    return value


def _bool(payload: Mapping[str, Any], field: str, label: str) -> bool:
    value = payload.get(field)
    if type(value) is not bool:
        _reject("type_invalid", f"{label}.{field} must be boolean")
    return value


def _require_hex(value: str, field: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        _reject("digest_invalid", f"{field} must be lowercase SHA-256")
    return value


def _digest(payload: Mapping[str, Any], field: str, label: str) -> str:
    return _require_hex(_string(payload, field, label), f"{label}.{field}")


def _optional_digest(payload: Mapping[str, Any], field: str, label: str) -> str:
    value = _string(payload, field, label, allow_empty=True)
    return value if not value else _require_hex(value, f"{label}.{field}")


def _timestamp_string(payload: Mapping[str, Any], field: str, label: str) -> str:
    value = _string(payload, field, label)
    _parse_timestamp(value, f"{label}.{field}")
    return value


def _parse_timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _reject("timestamp_invalid", f"{field} must be ISO-8601")
    if parsed.tzinfo is None:
        _reject("timestamp_invalid", f"{field} must be timezone-aware")
    return parsed.astimezone(UTC)


def _signature(payload: Mapping[str, Any], field: str, label: str) -> str:
    value = _string(payload, field, label)
    try:
        b64url_decode(value, expected_len=64)
    except ValueError as exc:
        raise WiringAttestationError("signature_invalid", "signature is not Ed25519") from exc
    return value


def _reject(reason_code: str, message: str) -> NoReturn:
    raise WiringAttestationError(reason_code, message)
