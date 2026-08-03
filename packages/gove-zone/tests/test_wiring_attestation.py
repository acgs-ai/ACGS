from __future__ import annotations

import copy
import dataclasses
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import gove_zone.wiring_attestation as wiring_attestation_module
from gove_zone.consumption import ReceiptConsumptionLedger
from gove_zone.decision import canonical_json, sha256_json
from gove_zone.errors import ReceiptRejectionReason, ReceiptValidationError
from gove_zone.gateway import ScopedDecisionReceiptConfig, UniversalGateway
from gove_zone.policy import RuleSetPolicy
from gove_zone.policy_sync import (
    POLICY_ENVELOPE_PURPOSE,
    POLICY_SYNC_ATTESTATION_PURPOSE,
    AtomicJsonPolicyCache,
    PolicySyncSnapshot,
    SyncedRuleSetPolicy,
)
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.runtime_identity import (
    GateScope,
    InMemoryEd25519WorkloadKeyProvider,
    RuntimeIdentityDescriptor,
    b64url_encode,
    public_key_thumbprint,
)
from gove_zone.signing import Ed25519Signer
from gove_zone.trust import (
    DECISION_RECEIPT_PURPOSE,
    ReceiptTrustScope,
    StaticReceiptTrustRegistry,
    TrustedReceiptKey,
)
from gove_zone.wiring_attestation import (
    WIRING_SUITE_HASH,
    WIRING_SUITE_ID,
    WIRING_SUITE_SPEC,
    AttestationReplayGuard,
    ExpectedWiringContext,
    WiringAttestation,
    WiringAttestationError,
    produce_wiring_attestation,
    verify_wiring_attestation,
)

NOW = datetime.now(UTC)


def _iso(offset: timedelta) -> str:
    return (NOW + offset).isoformat().replace("+00:00", "Z")


ISSUED = _iso(timedelta(seconds=-10))
FUTURE = _iso(timedelta(minutes=1))
ATTESTATION_EXPIRES = _iso(timedelta(minutes=5))
POLICY_FRESH_UNTIL = _iso(timedelta(minutes=2))
POLICY_EXPIRES_AT = _iso(timedelta(minutes=4))
SCOPE = GateScope("org-1", "project-1", "production", "gate-1")
ATTESTATION_SIGNER = Ed25519Signer.generate(key_id="attestation-key")
IDENTITY_ISSUER = InMemoryEd25519WorkloadKeyProvider(key_id="identity-issuer")
RESERVED_ALLOW_TOOL = "acgs.conformance.invoke_allow"


def _trusted_key(signer: Ed25519Signer, purpose: str) -> TrustedReceiptKey:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public = Ed25519PublicKey.from_public_bytes(signer.public_bytes())
    return TrustedReceiptKey(
        scope=ReceiptTrustScope("org-1", "project-1", "production", purpose),
        key_id=signer.key_id,
        algorithm=signer.algorithm,
        public_key_spki_der=public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        activated_epoch=1,
        not_after="2027-01-01T00:00:00+00:00",
        status="active",
    )


def _managed_registry(
    policy_signer: Ed25519Signer, receipt_signer: Ed25519Signer
) -> StaticReceiptTrustRegistry:
    return StaticReceiptTrustRegistry(
        [
            _trusted_key(policy_signer, POLICY_ENVELOPE_PURPOSE),
            _trusted_key(ATTESTATION_SIGNER, POLICY_SYNC_ATTESTATION_PURPOSE),
            _trusted_key(receipt_signer, DECISION_RECEIPT_PURPOSE),
        ]
    )


def _snapshot(
    policy_signer: Ed25519Signer,
    *,
    workload: InMemoryEd25519WorkloadKeyProvider,
) -> PolicySyncSnapshot:
    rules = [
        {
            "id": "deny-conformance",
            "effect": "deny",
            "tools": [
                "acgs.conformance.mcp_deny",
                "acgs.conformance.langgraph_deny",
                "acgs.conformance.rest_deny",
                "runtime.acgs.conformance.claude_deny",
            ],
        },
        {
            "id": "escalate-conformance",
            "effect": "escalate",
            "tools": ["acgs.conformance.openai_escalate"],
        },
    ]
    policy = RuleSetPolicy.from_dict({"id": "policy-1", "rules": rules})
    document = {"id": policy.policy_id, "version": policy.version, "rules": rules}
    content_hash = sha256_json(document)
    envelope_body = {
        "schema": "acgs.policy-registry.envelope/v1",
        "scope": {
            "org_id": "org-1",
            "project_id": "project-1",
            "environment_id": "production",
        },
        "policy_id": policy.policy_id,
        "version": policy.version,
        "content_hash": content_hash,
        "document": document,
        "rules": rules,
        "key_id": policy_signer.key_id,
        "signature_algorithm": policy_signer.algorithm,
        "trust_epoch": 1,
        "purpose": POLICY_ENVELOPE_PURPOSE,
    }
    envelope = {
        **envelope_body,
        "signature": policy_signer.sign(canonical_json(envelope_body).encode()),
    }
    body: dict[str, Any] = {
        "schema": "acgs.policy-sync.snapshot/v2",
        "purpose": "acgs.policy-sync/v2",
        "scope": {
            "org_id": "org-1",
            "project_id": "project-1",
            "environment_id": "production",
            "gate_id": "gate-1",
        },
        "runtime_identity_id": "runtime-1",
        "credential_id": "credential-1",
        "credential_generation": 3,
        "cursor": "psync_" + "A" * 43,
        "head_generation": 7,
        "head_updated_at": ISSUED,
        "policy_version_id": "policy-version-7",
        "policy_id": policy.policy_id,
        "version": policy.version,
        "content_hash": content_hash,
        "activation_receipt_id": "activation-receipt-1",
        "activation_receipt_hash": "2" * 64,
        "activation_event_hash": "3" * 64,
        "policy_envelope": envelope,
        "attestation_purpose": POLICY_SYNC_ATTESTATION_PURPOSE,
        "attestation_trust_epoch": 1,
        "attestation_key_id": ATTESTATION_SIGNER.key_id,
        "attestation_signature_algorithm": ATTESTATION_SIGNER.algorithm,
        "issued_at": ISSUED,
        "revocation_checked_at": ISSUED,
        "fresh_until": POLICY_FRESH_UNTIL,
        "expires_at": POLICY_EXPIRES_AT,
    }
    cursor_binding = {
        "schema": "acgs.policy-sync.binding/v2",
        "scope": body["scope"],
        "runtime_identity_id": body["runtime_identity_id"],
        "credential_id": body["credential_id"],
        "credential_generation": body["credential_generation"],
        "head_generation": body["head_generation"],
        "head_updated_at": body["head_updated_at"],
        "policy_version_id": body["policy_version_id"],
        "policy_id": body["policy_id"],
        "version": body["version"],
        "content_hash": body["content_hash"],
        "policy_envelope_trust_epoch": envelope["trust_epoch"],
        "policy_envelope_key_id": envelope["key_id"],
        "policy_envelope_signature_algorithm": envelope["signature_algorithm"],
        "policy_envelope_signature": envelope["signature"],
        "activation_receipt_id": body["activation_receipt_id"],
        "activation_receipt_hash": body["activation_receipt_hash"],
        "activation_event_hash": body["activation_event_hash"],
        "attestation_purpose": body["attestation_purpose"],
        "attestation_trust_epoch": body["attestation_trust_epoch"],
        "attestation_key_id": body["attestation_key_id"],
        "attestation_signature_algorithm": body["attestation_signature_algorithm"],
    }
    digest = hashlib.sha256(canonical_json(cursor_binding).encode()).digest()
    body["cursor"] = "psync_" + b64url_encode(digest)
    body["attestation_signature"] = ATTESTATION_SIGNER.sign(canonical_json(body).encode())
    return PolicySyncSnapshot.from_dict(body)


def _managed_gateway(
    tmp_path: Path,
    workload: InMemoryEd25519WorkloadKeyProvider,
    *,
    receipt_trust_epoch: int = 1,
) -> tuple[UniversalGateway, RuntimeIdentityDescriptor, ReceiptConsumptionLedger]:
    policy_signer = Ed25519Signer.generate(key_id="policy-key")
    receipt_signer = Ed25519Signer.generate(key_id="receipt-key")
    registry = _managed_registry(policy_signer, receipt_signer)
    descriptor = _descriptor(workload)
    cache = AtomicJsonPolicyCache(
        tmp_path / "policy.json", descriptor=descriptor, trust_registry=registry
    )
    cache.install(_snapshot(policy_signer, workload=workload), now=NOW)
    ledger = ReceiptConsumptionLedger(tmp_path / "ledger.jsonl")
    gateway = UniversalGateway(
        tenant_id="org-1",
        execution_boundary="gate-1",
        policy=SyncedRuleSetPolicy(cache, clock=lambda: NOW),
        profile=GovernanceProfile.production(signer=receipt_signer),
        validator=Validator("validator-1"),
        authority="wiring-test",
        receipt_ttl_seconds=60,
        scoped_receipt_config=ScopedDecisionReceiptConfig(
            "project-1", "production", "gate-1", receipt_trust_epoch, registry
        ),
        audit_path=tmp_path / "audit.jsonl",
        ledger=ledger,
    )
    return gateway, descriptor, ledger


class _ReplayGuard(AttestationReplayGuard):
    def __init__(self) -> None:
        self.accepted: dict[str, tuple[set[str], int]] = {}

    def consume(self, *, namespace_digest: str, nonce: str, sequence: int) -> bool:
        nonces, high_water = self.accepted.setdefault(namespace_digest, (set(), -1))
        if nonce in nonces or sequence <= high_water:
            return False
        nonces.add(nonce)
        self.accepted[namespace_digest] = (nonces, sequence)
        return True


def _descriptor(workload: InMemoryEd25519WorkloadKeyProvider) -> RuntimeIdentityDescriptor:
    return RuntimeIdentityDescriptor.issue(
        scope=SCOPE,
        runtime_identity_id="runtime-1",
        credential_id="credential-1",
        credential_generation=3,
        workload_public_key=workload.public_key_bytes(),
        issuer="control-plane",
        audience="control-plane",
        issued_at=_iso(timedelta(days=-1)),
        expires_at=_iso(timedelta(days=30)),
        signer=IDENTITY_ISSUER,
    )


def _policy_head() -> dict[str, Any]:
    return {
        "scope": {
            "org_id": "org-1",
            "project_id": "project-1",
            "environment_id": "production",
            "gate_id": "gate-1",
        },
        "runtime_identity_id": "runtime-1",
        "credential_id": "credential-1",
        "credential_generation": 3,
        "cursor": "psync_" + "A" * 43,
        "head_generation": 7,
        "head_updated_at": ISSUED,
        "policy_version_id": "policy-version-7",
        "policy_id": "policy-1",
        "version": "ruleset/policy-1/0123456789abcdef",
        "content_hash": "1" * 64,
        "activation_receipt_id": "activation-receipt-1",
        "activation_receipt_hash": "2" * 64,
        "activation_event_hash": "3" * 64,
        "policy_sync_schema": "acgs.policy-sync.snapshot/v2",
        "policy_sync_purpose": "acgs.policy-sync/v2",
        "policy_trust_purpose": "acgs.policy-envelope/v1",
        "policy_trust_epoch": 4,
        "policy_key_id": "policy-key",
        "policy_signature_algorithm": "ed25519",
        "policy_key_fingerprint": "4" * 64,
        "attestation_purpose": "acgs.policy-sync-attestation/v1",
        "attestation_trust_epoch": 5,
        "attestation_key_id": "attestation-key",
        "attestation_signature_algorithm": "ed25519",
        "attestation_key_fingerprint": "5" * 64,
        "signed_snapshot_hash": "6" * 64,
    }


def _case_result(case_id: str, index: int) -> dict[str, Any]:
    is_allow = case_id == "invoke.allow_once"
    dispatchers = {
        "invoke.allow_once": "UniversalGateway.invoke",
        "mcp.deny_zero": "UniversalGateway.handle_mcp_call",
        "openai.escalate_zero": "UniversalGateway.handle_openai_tool_call",
        "langgraph.deny_zero": "UniversalGateway.langgraph_tools",
        "rest.deny_zero": "UniversalGateway.handle_rest_call",
        "claude_hook.deny_decision_only": "UniversalGateway.handle_claude_hook",
        "executor.tampered_receipt_zero": "execute_with_receipt",
        "sealed_handle.raw_bypass_zero": "UniversalGateway.register_tool/SealedTool",
    }
    classifications = {
        "invoke.allow_once": "native_executor",
        "mcp.deny_zero": "public_dispatcher",
        "openai.escalate_zero": "public_dispatcher",
        "langgraph.deny_zero": "public_dispatcher",
        "rest.deny_zero": "public_dispatcher",
        "claude_hook.deny_decision_only": "decision_only",
        "executor.tampered_receipt_zero": "executor_conformance",
        "sealed_handle.raw_bypass_zero": "sealed_handle_conformance",
    }
    outcomes = {
        "invoke.allow_once": "allow",
        "mcp.deny_zero": "deny",
        "openai.escalate_zero": "escalate",
        "langgraph.deny_zero": "deny",
        "rest.deny_zero": "deny",
        "claude_hook.deny_decision_only": "deny",
        "executor.tampered_receipt_zero": "rejected",
        "sealed_handle.raw_bypass_zero": "rejected",
    }
    tools = {
        "invoke.allow_once": "acgs.conformance.invoke_allow",
        "mcp.deny_zero": "acgs.conformance.mcp_deny",
        "openai.escalate_zero": "acgs.conformance.openai_escalate",
        "langgraph.deny_zero": "acgs.conformance.langgraph_deny",
        "rest.deny_zero": "acgs.conformance.rest_deny",
        "claude_hook.deny_decision_only": "runtime.acgs.conformance.claude_deny",
        "executor.tampered_receipt_zero": "acgs.conformance.invoke_allow",
        "sealed_handle.raw_bypass_zero": "acgs.conformance.raw_bypass",
    }
    probes = {
        "invoke.allow_once": "allow",
        "mcp.deny_zero": "mcp",
        "openai.escalate_zero": "openai",
        "langgraph.deny_zero": "langgraph",
        "rest.deny_zero": "rest",
        "claude_hook.deny_decision_only": "claude",
        "executor.tampered_receipt_zero": "allow",
        "sealed_handle.raw_bypass_zero": "bypass",
    }
    arguments: dict[str, Any] = {"probe": probes[case_id]}
    if case_id == "claude_hook.deny_decision_only":
        arguments = {
            "action_kind": "PreToolUse",
            "summary": {
                "probe": {
                    "type": "str",
                    "len": 6,
                    "sha256": "389432cbf83f3d1b64029a75864ec96f8fd06451b4c99d7b28385d395d480bfa",
                }
            },
        }
    argument_hash = sha256_json(arguments)
    return {
        "case_id": case_id,
        "dispatcher": dispatchers[case_id],
        "classification": classifications[case_id],
        "outcome": outcomes[case_id],
        "side_effect_count": 1 if is_allow else 0,
        "executor_verified": is_allow or case_id.startswith("executor."),
        "receipt_id": "receipt-allow-1" if is_allow else "",
        "receipt_hash": "7" * 64 if is_allow else "",
        "receipt_signature_algorithm": "ed25519" if is_allow else "",
        "receipt_signing_key_id": "receipt-key" if is_allow else "",
        "audit_hash": f"{index + 8:064x}",
        "previous_audit_hash": f"{index + 32:064x}",
        "action_hash": sha256_json({"tool": tools[case_id], "argument_hash": argument_hash}),
        "argument_hash": argument_hash,
        "actor": "runtime-1",
        "receipt_expires_at": POLICY_EXPIRES_AT if is_allow else "",
        "receipt_rejection_code": (
            ReceiptRejectionReason.RECEIPT_HASH_MISMATCH.value
            if case_id == "executor.tampered_receipt_zero"
            else ""
        ),
        "policy_hash": "" if case_id == "sealed_handle.raw_bypass_zero" else "1" * 64,
        "policy_version_id": ""
        if case_id == "sealed_handle.raw_bypass_zero"
        else "policy-version-7",
        "policy_provenance_hash": (
            "" if case_id == "sealed_handle.raw_bypass_zero" else sha256_json(_policy_head())
        ),
        "consumption_commitment": "b" * 64 if is_allow else "",
        "receipt": {},
        "audit_event": {},
        "consumption_entry": {},
    }


def _unsigned_payload(workload: InMemoryEd25519WorkloadKeyProvider) -> dict[str, Any]:
    case_ids = (
        "invoke.allow_once",
        "mcp.deny_zero",
        "openai.escalate_zero",
        "langgraph.deny_zero",
        "rest.deny_zero",
        "claude_hook.deny_decision_only",
        "executor.tampered_receipt_zero",
        "sealed_handle.raw_bypass_zero",
    )
    return {
        "schema": "acgs.in-process-public-surface-conformance/v1",
        "purpose": "acgs.in-process-public-surface-conformance/v1",
        "assurance_class": "observed",
        "evidence_kind": "in_process_public_surface_conformance",
        "scope": SCOPE.to_dict(),
        "runtime": {
            "runtime_identity_id": "runtime-1",
            "credential_id": "credential-1",
            "credential_generation": 3,
            "workload_key_id": workload.key_id,
            "public_key_thumbprint": public_key_thumbprint(workload.public_key_bytes()),
        },
        "execution_boundary": "gate-1",
        "package": {
            "name": "gove-zone",
            "version": "1.0.0rc1",
            "runtime_build_digest": "c" * 64,
            "configuration_digest": "d" * 64,
        },
        "policy_head": _policy_head(),
        "policy_provenance_hash": sha256_json(_policy_head()),
        "policy_issued_at": ISSUED,
        "policy_fresh_until": POLICY_FRESH_UNTIL,
        "policy_expires_at": POLICY_EXPIRES_AT,
        "policy_mode": "fresh",
        "suite_id": WIRING_SUITE_ID,
        "suite_hash": WIRING_SUITE_HASH,
        "results": [_case_result(case_id, index) for index, case_id in enumerate(case_ids)],
        "sequence": 11,
        "nonce": "verifier-nonce-0123456789abcdef",
        "issued_at": ISSUED,
        "expires_at": ATTESTATION_EXPIRES,
        "signature_algorithm": "ed25519",
        "signing_key_id": workload.key_id,
    }


def _signed_payload(
    workload: InMemoryEd25519WorkloadKeyProvider,
) -> dict[str, Any]:
    unsigned = _unsigned_payload(workload)
    return {
        **unsigned,
        "attestation_hash": sha256_json(unsigned),
        "signature": workload.sign(canonical_json(unsigned).encode("utf-8")),
    }


def _resign_payload(payload: dict[str, Any], workload: InMemoryEd25519WorkloadKeyProvider) -> None:
    unsigned = dict(payload)
    unsigned.pop("attestation_hash", None)
    unsigned.pop("signature", None)
    payload["attestation_hash"] = sha256_json(unsigned)
    payload["signature"] = workload.sign(canonical_json(unsigned).encode("utf-8"))


def _context(
    workload: InMemoryEd25519WorkloadKeyProvider,
    guard: AttestationReplayGuard | None = None,
) -> ExpectedWiringContext:
    return ExpectedWiringContext(
        scope=SCOPE,
        runtime_identity_descriptor=_descriptor(workload),
        runtime_identity_issuer_public_key=IDENTITY_ISSUER.public_key_bytes(),
        runtime_identity_audience="control-plane",
        receipt_trust_registry=StaticReceiptTrustRegistry([]),
        receipt_trust_purpose=DECISION_RECEIPT_PURPOSE,
        workload_key_id=workload.key_id,
        execution_boundary="gate-1",
        runtime_build_digest="c" * 64,
        configuration_digest="d" * 64,
        policy_head=_policy_head(),
        policy_provenance_hash=sha256_json(_policy_head()),
        policy_issued_at=ISSUED,
        policy_fresh_until=POLICY_FRESH_UNTIL,
        policy_expires_at=POLICY_EXPIRES_AT,
        policy_mode="fresh",
        expected_nonce="verifier-nonce-0123456789abcdef",
        minimum_sequence=10,
        now=NOW,
        replay_guard=guard or _ReplayGuard(),
    )


def _managed_wiring_artifact(
    tmp_path: Path, *, receipt_trust_epoch: int = 1
) -> tuple[WiringAttestation, ExpectedWiringContext, TrustedReceiptKey]:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    gateway, descriptor, ledger = _managed_gateway(
        tmp_path,
        workload,
        receipt_trust_epoch=receipt_trust_epoch,
    )
    artifact = produce_wiring_attestation(
        gateway=gateway,
        runtime_identity_descriptor=descriptor,
        runtime_identity_issuer_public_key=IDENTITY_ISSUER.public_key_bytes(),
        runtime_identity_audience="control-plane",
        workload_key_provider=workload,
        receipt_consumption_ledger=ledger,
        authenticated_actor="runtime-1",
        nonce="verifier-nonce-0123456789abcdef",
        sequence=11,
        runtime_build_digest="c" * 64,
        configuration_digest="d" * 64,
        issued_at=ISSUED,
        expires_at=ATTESTATION_EXPIRES,
        now=NOW,
    )
    signer = gateway.profile.signer
    assert isinstance(signer, Ed25519Signer)
    expected = ExpectedWiringContext(
        scope=SCOPE,
        runtime_identity_descriptor=descriptor,
        runtime_identity_issuer_public_key=IDENTITY_ISSUER.public_key_bytes(),
        runtime_identity_audience="control-plane",
        receipt_trust_registry=gateway.scoped_receipt_config.trust_registry,
        receipt_trust_purpose=DECISION_RECEIPT_PURPOSE,
        workload_key_id=workload.key_id,
        execution_boundary="gate-1",
        runtime_build_digest="c" * 64,
        configuration_digest="d" * 64,
        policy_head=artifact.policy_head.to_dict(),
        policy_provenance_hash=artifact.policy_provenance_hash,
        policy_issued_at=artifact.policy_issued_at,
        policy_fresh_until=artifact.policy_fresh_until,
        policy_expires_at=artifact.policy_expires_at,
        policy_mode=artifact.policy_mode,
        expected_nonce=artifact.nonce,
        minimum_sequence=10,
        now=NOW,
        replay_guard=_ReplayGuard(),
    )
    return artifact, expected, _trusted_key(signer, DECISION_RECEIPT_PURPOSE)


@pytest.fixture
def managed_wiring_artifact(
    tmp_path: Path,
) -> tuple[WiringAttestation, ExpectedWiringContext, TrustedReceiptKey]:
    return _managed_wiring_artifact(tmp_path)


def test_default_execution_verification_rejects_retired_receipt_key(
    managed_wiring_artifact: tuple[WiringAttestation, ExpectedWiringContext, TrustedReceiptKey],
) -> None:
    artifact, expected, active_key = managed_wiring_artifact
    retired_key = dataclasses.replace(active_key, status="retired", retired_epoch=2)

    with pytest.raises(WiringAttestationError) as caught:
        verify_wiring_attestation(
            artifact,
            expected=dataclasses.replace(
                expected,
                receipt_trust_registry=StaticReceiptTrustRegistry([retired_key]),
            ),
        )

    assert caught.value.reason_code == "receipt_invalid"


def test_explicit_historical_verification_accepts_correctly_retired_receipt_key(
    managed_wiring_artifact: tuple[WiringAttestation, ExpectedWiringContext, TrustedReceiptKey],
) -> None:
    artifact, expected, active_key = managed_wiring_artifact
    retired_key = dataclasses.replace(active_key, status="retired", retired_epoch=2)

    verified = verify_wiring_attestation(
        artifact,
        expected=dataclasses.replace(
            expected,
            receipt_trust_registry=StaticReceiptTrustRegistry([retired_key]),
            historical_trust_verification=True,
        ),
    )

    assert verified == artifact


def test_explicit_historical_verification_rejects_receipt_at_retirement_epoch(
    tmp_path: Path,
) -> None:
    artifact, expected, active_key = _managed_wiring_artifact(tmp_path, receipt_trust_epoch=2)
    receipt_trust_epoch = artifact.results[0].receipt["trust_epoch"]
    retired_key = dataclasses.replace(
        active_key,
        status="retired",
        retired_epoch=receipt_trust_epoch,
    )

    with pytest.raises(WiringAttestationError) as caught:
        verify_wiring_attestation(
            artifact,
            expected=dataclasses.replace(
                expected,
                receipt_trust_registry=StaticReceiptTrustRegistry([retired_key]),
                historical_trust_verification=True,
            ),
        )

    assert caught.value.reason_code == "receipt_invalid"


def test_explicit_historical_verification_still_rejects_revoked_receipt_key(
    managed_wiring_artifact: tuple[WiringAttestation, ExpectedWiringContext, TrustedReceiptKey],
) -> None:
    artifact, expected, active_key = managed_wiring_artifact
    revoked_key = dataclasses.replace(active_key, status="revoked")

    with pytest.raises(WiringAttestationError) as caught:
        verify_wiring_attestation(
            artifact,
            expected=dataclasses.replace(
                expected,
                receipt_trust_registry=StaticReceiptTrustRegistry([revoked_key]),
                historical_trust_verification=True,
            ),
        )

    assert caught.value.reason_code == "receipt_invalid"


def test_strict_parser_preserves_every_outer_binding() -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    artifact = WiringAttestation.from_dict(_signed_payload(workload))

    assert artifact.attestation_hash == _signed_payload(workload)["attestation_hash"]
    assert artifact.assurance_class == "observed"
    assert artifact.evidence_kind == "in_process_public_surface_conformance"
    assert artifact.sequence == 11


def test_verifier_reparses_direct_dataclass_instances_fail_closed() -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    artifact = WiringAttestation.from_dict(_signed_payload(workload))
    forged = dataclasses.replace(artifact, purpose="acgs.deployed-wiring/v1")

    with pytest.raises(WiringAttestationError, match="purpose"):
        verify_wiring_attestation(forged, expected=_context(workload))


def test_attestation_hash_and_signature_are_over_canonical_unsigned_payload() -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    payload = _signed_payload(workload)
    artifact = WiringAttestation.from_dict(payload)

    assert artifact.unsigned_payload() == _unsigned_payload(workload)
    assert artifact.attestation_hash == sha256_json(_unsigned_payload(workload))
    assert b64url_encode(workload.public_key_bytes()) not in canonical_json(payload)


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda payload: payload.update({"unknown": True}), "unknown"),
        (lambda payload: payload.pop("purpose"), "missing"),
        (lambda payload: payload.update({"sequence": True}), "sequence"),
        (
            lambda payload: payload["results"][0].update({"side_effect_count": float("nan")}),
            "side_effect_count",
        ),
        (lambda payload: payload["runtime"].update({"secret": "no"}), "unknown"),
        (lambda payload: payload["results"][0].pop("audit_hash"), "missing"),
    ],
)
def test_parser_rejects_unknown_missing_or_wrong_typed_fields(mutation: Any, match: str) -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    payload = _signed_payload(workload)
    mutation(payload)

    with pytest.raises(WiringAttestationError, match=match):
        WiringAttestation.from_dict(payload)


def test_parser_rejects_nested_non_finite_ijson_numbers() -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    for value in (float("nan"), float("inf"), float("-inf")):
        payload = _signed_payload(workload)
        payload["results"][0]["receipt"] = {"nested": {"value": value}}
        with pytest.raises(WiringAttestationError, match="ijson"):
            WiringAttestation.from_dict(payload)


@pytest.mark.parametrize(
    "value",
    [b"not-json", object(), 2**53, -(2**53), "\ud800"],
)
def test_parser_rejects_nested_non_ijson_values(value: Any) -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    payload = _signed_payload(workload)
    payload["package"]["nested_invalid"] = {"items": [value]}
    with pytest.raises(WiringAttestationError, match="ijson"):
        WiringAttestation.from_dict(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("signature_algorithm", "none"),
        ("signature", "unsigned_local"),
        ("assurance_class", "native"),
        ("evidence_kind", "authorization"),
    ],
)
def test_unsigned_non_ed25519_or_outer_assurance_upgrade_is_rejected(
    field: str, value: str
) -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    payload = _signed_payload(workload)
    payload[field] = value

    with pytest.raises(WiringAttestationError):
        artifact = WiringAttestation.from_dict(payload)
        verify_wiring_attestation(artifact, expected=_context(workload))


def test_wrong_workload_key_or_descriptor_generation_is_rejected() -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    payload = _signed_payload(workload)
    wrong = copy.deepcopy(payload)
    wrong["runtime"]["credential_generation"] = 2
    _resign_payload(wrong, workload)

    with pytest.raises(WiringAttestationError, match="credential_generation"):
        verify_wiring_attestation(WiringAttestation.from_dict(wrong), expected=_context(workload))

    other_workload = InMemoryEd25519WorkloadKeyProvider(key_id="other-workload-key")
    with pytest.raises(WiringAttestationError, match="workload key"):
        verify_wiring_attestation(
            WiringAttestation.from_dict(payload), expected=_context(other_workload)
        )


@pytest.mark.parametrize(
    ("path", "value", "match"),
    [
        (("scope", "project_id"), "project-2", "scope"),
        (("execution_boundary",), "gate-2", "boundary"),
        (("package", "runtime_build_digest"), "e" * 64, "build"),
        (("package", "configuration_digest"), "e" * 64, "configuration"),
        (("policy_head", "policy_version_id"), "policy-version-8", "policy"),
        (("policy_provenance_hash",), "e" * 64, "provenance"),
    ],
)
def test_wrong_scope_policy_runtime_or_boundary_is_rejected(
    path: tuple[str, ...], value: Any, match: str
) -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    payload = _signed_payload(workload)
    target = payload
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    _resign_payload(payload, workload)

    with pytest.raises(WiringAttestationError, match=match):
        verify_wiring_attestation(WiringAttestation.from_dict(payload), expected=_context(workload))


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("issued_at", FUTURE, "future"),
        ("expires_at", NOW.isoformat(), "expired"),
        ("nonce", "wrong-verifier-nonce", "nonce"),
        ("sequence", 10, "sequence"),
    ],
)
def test_stale_future_expired_wrong_nonce_or_non_monotonic_sequence_is_rejected(
    field: str, value: Any, match: str
) -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    payload = _signed_payload(workload)
    payload[field] = value
    _resign_payload(payload, workload)

    with pytest.raises(WiringAttestationError, match=match):
        verify_wiring_attestation(WiringAttestation.from_dict(payload), expected=_context(workload))


def test_policy_freshness_order_has_exact_fail_closed_reason() -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    payload = _signed_payload(workload)
    payload["policy_issued_at"] = POLICY_FRESH_UNTIL
    _resign_payload(payload, workload)
    expected = dataclasses.replace(_context(workload), policy_issued_at=POLICY_FRESH_UNTIL)

    with pytest.raises(WiringAttestationError) as caught:
        verify_wiring_attestation(WiringAttestation.from_dict(payload), expected=expected)
    assert caught.value.reason_code == "policy_time_order_invalid"


def test_replay_guard_atomically_rejects_second_acceptance() -> None:
    guard = _ReplayGuard()
    assert guard.consume(namespace_digest="a" * 64, nonce="nonce-0123456789", sequence=11)
    assert not guard.consume(namespace_digest="a" * 64, nonce="nonce-0123456789", sequence=11)
    assert not guard.consume(namespace_digest="a" * 64, nonce="new-nonce", sequence=10)
    assert guard.consume(namespace_digest="b" * 64, nonce="nonce-0123456789", sequence=11)


def test_reordered_omitted_or_duplicated_cases_are_rejected() -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    for mutate in (
        lambda results: results.reverse(),
        lambda results: results.pop(),
        lambda results: results.__setitem__(1, copy.deepcopy(results[0])),
    ):
        payload = _signed_payload(workload)
        mutate(payload["results"])
        with pytest.raises(WiringAttestationError, match="case"):
            WiringAttestation.from_dict(payload)


def test_tampering_any_bound_attestation_field_invalidates_verification() -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    payload = _signed_payload(workload)
    payload["results"][0]["receipt_hash"] = "f" * 64

    with pytest.raises(WiringAttestationError, match="hash"):
        verify_wiring_attestation(WiringAttestation.from_dict(payload), expected=_context(workload))


def test_producer_drives_fixed_public_dispatcher_suite_and_signs_results(
    tmp_path: Path,
) -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    gateway, descriptor, ledger = _managed_gateway(tmp_path, workload)
    existing = gateway.register_tool("customer.existing", lambda: "existing")

    artifact = produce_wiring_attestation(
        gateway=gateway,
        runtime_identity_descriptor=descriptor,
        runtime_identity_issuer_public_key=IDENTITY_ISSUER.public_key_bytes(),
        runtime_identity_audience="control-plane",
        workload_key_provider=workload,
        receipt_consumption_ledger=ledger,
        authenticated_actor="runtime-1",
        nonce="verifier-nonce-0123456789abcdef",
        sequence=11,
        runtime_build_digest="c" * 64,
        configuration_digest="d" * 64,
        issued_at=ISSUED,
        expires_at=ATTESTATION_EXPIRES,
        now=NOW,
    )

    assert [result.case_id for result in artifact.results] == [
        case.case_id for case in WIRING_SUITE_SPEC
    ]
    assert [result.side_effect_count for result in artifact.results] == [1, 0, 0, 0, 0, 0, 0, 0]
    assert artifact.results[0].receipt_signature_algorithm == "ed25519"
    assert artifact.results[0].consumption_commitment
    assert artifact.results[5].classification == "decision_only"
    assert artifact.results[5].executor_verified is False
    assert all(result.audit_hash for result in artifact.results)
    assert "verifier-nonce" not in canonical_json(artifact.results[0].to_dict())
    assert [result.audit_event["reason"] for result in artifact.results] == [
        case.expected_audit_reason for case in WIRING_SUITE_SPEC
    ]
    assert artifact.assurance_class == "observed"
    assert artifact.evidence_kind == "in_process_public_surface_conformance"
    assert "deployed" not in artifact.assurance_class
    assert "proven" not in artifact.evidence_kind

    replay_guard = _ReplayGuard()
    expected = ExpectedWiringContext(
        scope=SCOPE,
        runtime_identity_descriptor=descriptor,
        runtime_identity_issuer_public_key=IDENTITY_ISSUER.public_key_bytes(),
        runtime_identity_audience="control-plane",
        receipt_trust_registry=gateway.scoped_receipt_config.trust_registry,
        receipt_trust_purpose=gateway.scoped_receipt_config.trust_purpose,
        workload_key_id=workload.key_id,
        execution_boundary="gate-1",
        runtime_build_digest="c" * 64,
        configuration_digest="d" * 64,
        policy_head=artifact.policy_head.to_dict(),
        policy_provenance_hash=artifact.policy_provenance_hash,
        policy_issued_at=artifact.policy_issued_at,
        policy_fresh_until=artifact.policy_fresh_until,
        policy_expires_at=artifact.policy_expires_at,
        policy_mode=artifact.policy_mode,
        expected_nonce=artifact.nonce,
        minimum_sequence=10,
        now=NOW,
        replay_guard=replay_guard,
    )

    forbidden_labels = {
        "receipt_id": "forbidden-receipt",
        "receipt_hash": "f" * 64,
        "receipt_signature_algorithm": "ed25519",
        "receipt_signing_key_id": "forbidden-key",
        "receipt_expires_at": ATTESTATION_EXPIRES,
        "consumption_commitment": "f" * 64,
    }
    for result_index in range(1, len(artifact.results)):
        for label, value in forbidden_labels.items():
            forbidden = artifact.to_dict()
            forbidden["results"][result_index][label] = value
            _resign_payload(forbidden, workload)
            with pytest.raises(WiringAttestationError) as caught:
                verify_wiring_attestation(
                    WiringAttestation.from_dict(forbidden),
                    expected=dataclasses.replace(expected, replay_guard=_ReplayGuard()),
                )
            assert caught.value.reason_code == "evidence_presence_invalid"
        for nested_label in ("receipt", "consumption_entry"):
            forbidden = artifact.to_dict()
            forbidden["results"][result_index][nested_label] = {"forbidden": "evidence"}
            _resign_payload(forbidden, workload)
            with pytest.raises(WiringAttestationError) as caught:
                verify_wiring_attestation(
                    WiringAttestation.from_dict(forbidden),
                    expected=dataclasses.replace(expected, replay_guard=_ReplayGuard()),
                )
            assert caught.value.reason_code == "evidence_presence_invalid"

    for field, value in (
        ("decision", "allow"),
        ("actor", "other-runtime"),
        ("policy_version", "secret-policy"),
        ("matched_rules", ["secret-rule"]),
        ("goal", "secret-goal"),
        ("path", ["secret-path"]),
        ("state_hash", "f" * 64),
        ("decision_request_hash", "f" * 64),
        ("transformed_args", {"secret": "value"}),
    ):
        mutation = artifact.to_dict()
        event = mutation["results"][1]["audit_event"]
        event[field] = value
        unsigned_event = dict(event)
        unsigned_event.pop("event_hash")
        event["event_hash"] = sha256_json(unsigned_event)
        mutation["results"][1]["audit_hash"] = event["event_hash"]
        _resign_payload(mutation, workload)
        with pytest.raises(WiringAttestationError, match="audit"):
            verify_wiring_attestation(
                WiringAttestation.from_dict(mutation),
                expected=dataclasses.replace(expected, replay_guard=_ReplayGuard()),
            )

    wrong_presence = artifact.to_dict()
    wrong_presence["results"][1]["receipt"] = {"secret": "must-not-pass"}
    _resign_payload(wrong_presence, workload)
    with pytest.raises(WiringAttestationError, match="presence"):
        verify_wiring_attestation(
            WiringAttestation.from_dict(wrong_presence),
            expected=dataclasses.replace(expected, replay_guard=_ReplayGuard()),
        )

    broken_chain = artifact.to_dict()
    event = broken_chain["results"][2]["audit_event"]
    event["previous_hash"] = "f" * 64
    broken_chain["results"][2]["previous_audit_hash"] = "f" * 64
    unsigned_event = dict(event)
    unsigned_event.pop("event_hash")
    event["event_hash"] = sha256_json(unsigned_event)
    broken_chain["results"][2]["audit_hash"] = event["event_hash"]
    _resign_payload(broken_chain, workload)
    with pytest.raises(WiringAttestationError, match="chain"):
        verify_wiring_attestation(
            WiringAttestation.from_dict(broken_chain),
            expected=dataclasses.replace(expected, replay_guard=_ReplayGuard()),
        )

    for field, value in (("argument_hash", "f" * 64), ("actor", "runtime-2")):
        tampered_receipt = artifact.to_dict()
        tampered_receipt["results"][0]["receipt"][field] = value
        _resign_payload(tampered_receipt, workload)
        with pytest.raises(WiringAttestationError, match="receipt"):
            verify_wiring_attestation(
                WiringAttestation.from_dict(tampered_receipt),
                expected=dataclasses.replace(expected, replay_guard=_ReplayGuard()),
            )

    contradictory_request = artifact.to_dict()
    raw_receipt = contradictory_request["results"][0]["receipt"]
    raw_receipt["request_id"] = "f" * 64
    raw_receipt["receipt_hash"] = ""
    raw_receipt["signature"] = "unsigned_local"
    replacement = DecisionReceipt.from_dict(raw_receipt)
    replacement_hash = replacement.compute_hash()
    signer = gateway.profile.signer
    assert signer is not None
    raw_receipt["receipt_hash"] = replacement_hash
    raw_receipt["signature"] = signer.sign(replacement_hash.encode("utf-8"))
    contradictory_request["results"][0]["receipt_hash"] = replacement_hash
    entry = contradictory_request["results"][0]["consumption_entry"]
    entry["request_id"] = raw_receipt["request_id"]
    entry["receipt_hash"] = replacement_hash
    unsigned_entry = dict(entry)
    unsigned_entry.pop("entry_hash")
    entry["entry_hash"] = sha256_json(unsigned_entry)
    contradictory_request["results"][0]["consumption_commitment"] = sha256_json(
        {"previous_hash": entry["previous_hash"], "entry_hash": entry["entry_hash"]}
    )
    _resign_payload(contradictory_request, workload)
    with pytest.raises(WiringAttestationError) as caught:
        verify_wiring_attestation(
            WiringAttestation.from_dict(contradictory_request),
            expected=dataclasses.replace(expected, replay_guard=_ReplayGuard()),
        )
    assert caught.value.reason_code == "audit_evidence_invalid"

    for location in ("receipt", "audit_event"):
        wrong_type = artifact.to_dict()
        wrong_type["results"][0][location]["matched_rules"] = "not-a-list"
        if location == "audit_event":
            event = wrong_type["results"][0]["audit_event"]
            unsigned_event = dict(event)
            unsigned_event.pop("event_hash")
            event["event_hash"] = sha256_json(unsigned_event)
            wrong_type["results"][0]["audit_hash"] = event["event_hash"]
        _resign_payload(wrong_type, workload)
        with pytest.raises(WiringAttestationError) as caught:
            verify_wiring_attestation(
                WiringAttestation.from_dict(wrong_type),
                expected=dataclasses.replace(expected, replay_guard=_ReplayGuard()),
            )
        assert caught.value.reason_code == "audit_evidence_type_invalid"

    for label in ("receipt_signing_key_id", "receipt_expires_at", "receipt_hash"):
        contradictory_label = artifact.to_dict()
        contradictory_label["results"][0][label] = (
            "f" * 64 if label == "receipt_hash" else "contradictory"
        )
        _resign_payload(contradictory_label, workload)
        with pytest.raises(WiringAttestationError, match="receipt"):
            verify_wiring_attestation(
                WiringAttestation.from_dict(contradictory_label),
                expected=dataclasses.replace(expected, replay_guard=_ReplayGuard()),
            )

    freeform_reason = artifact.to_dict()
    event = freeform_reason["results"][1]["audit_event"]
    event["reason"] = "caller-controlled secret"
    unsigned_event = dict(event)
    unsigned_event.pop("event_hash")
    event["event_hash"] = sha256_json(unsigned_event)
    freeform_reason["results"][1]["audit_hash"] = event["event_hash"]
    _resign_payload(freeform_reason, workload)
    with pytest.raises(WiringAttestationError, match="reason"):
        verify_wiring_attestation(
            WiringAttestation.from_dict(freeform_reason),
            expected=dataclasses.replace(expected, replay_guard=_ReplayGuard()),
        )

    tampered_consumption = artifact.to_dict()
    entry = tampered_consumption["results"][0]["consumption_entry"]
    entry["actor"] = "other-runtime"
    unsigned_entry = dict(entry)
    unsigned_entry.pop("entry_hash")
    entry["entry_hash"] = sha256_json(unsigned_entry)
    tampered_consumption["results"][0]["consumption_commitment"] = entry["entry_hash"]
    _resign_payload(tampered_consumption, workload)
    with pytest.raises(WiringAttestationError, match="consumption"):
        verify_wiring_attestation(
            WiringAttestation.from_dict(tampered_consumption),
            expected=dataclasses.replace(expected, replay_guard=_ReplayGuard()),
        )

    receipt_timestamp = datetime.fromisoformat(
        artifact.results[0].receipt["timestamp"].replace("Z", "+00:00")
    )
    for invalid_consumed_at in (
        receipt_timestamp - timedelta(microseconds=1),
        datetime.fromisoformat(artifact.expires_at.replace("Z", "+00:00")),
    ):
        invalid_time = artifact.to_dict()
        entry = invalid_time["results"][0]["consumption_entry"]
        entry["consumed_at"] = invalid_consumed_at.isoformat()
        unsigned_entry = dict(entry)
        unsigned_entry.pop("entry_hash")
        entry["entry_hash"] = sha256_json(unsigned_entry)
        invalid_time["results"][0]["consumption_commitment"] = sha256_json(
            {"previous_hash": entry["previous_hash"], "entry_hash": entry["entry_hash"]}
        )
        _resign_payload(invalid_time, workload)
        with pytest.raises(WiringAttestationError) as caught:
            verify_wiring_attestation(
                WiringAttestation.from_dict(invalid_time),
                expected=dataclasses.replace(expected, replay_guard=_ReplayGuard()),
            )
        assert caught.value.reason_code == "consumption_evidence_invalid"

    assert verify_wiring_attestation(artifact, expected=expected) == artifact
    with pytest.raises(WiringAttestationError, match="replay"):
        verify_wiring_attestation(artifact, expected=expected)
    assert gateway._tools["customer.existing"] is existing
    assert set(gateway.tool_names()) == {"customer.existing"}

    second = produce_wiring_attestation(
        gateway=gateway,
        runtime_identity_descriptor=descriptor,
        runtime_identity_issuer_public_key=IDENTITY_ISSUER.public_key_bytes(),
        runtime_identity_audience="control-plane",
        workload_key_provider=workload,
        receipt_consumption_ledger=ledger,
        authenticated_actor="runtime-1",
        nonce="second-verifier-nonce-0123456789",
        sequence=12,
        runtime_build_digest="c" * 64,
        configuration_digest="d" * 64,
        issued_at=ISSUED,
        expires_at=ATTESTATION_EXPIRES,
        now=NOW,
    )
    assert second.sequence == 12
    assert gateway._tools["customer.existing"] is existing
    assert set(gateway.tool_names()) == {"customer.existing"}


def test_tamper_probe_rejects_wrong_failure_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    gateway, descriptor, ledger = _managed_gateway(tmp_path, workload)

    def wrong_rejection(*_args: Any, **_kwargs: Any) -> None:
        raise ReceiptValidationError(
            "forced expiry",
            reason_code=ReceiptRejectionReason.RECEIPT_EXPIRED,
        )

    monkeypatch.setattr(wiring_attestation_module, "_replay_receipt", wrong_rejection)
    with pytest.raises(WiringAttestationError) as caught:
        produce_wiring_attestation(
            gateway=gateway,
            runtime_identity_descriptor=descriptor,
            runtime_identity_issuer_public_key=IDENTITY_ISSUER.public_key_bytes(),
            runtime_identity_audience="control-plane",
            workload_key_provider=workload,
            receipt_consumption_ledger=ledger,
            authenticated_actor="runtime-1",
            nonce="verifier-nonce-0123456789abcdef",
            sequence=11,
            runtime_build_digest="c" * 64,
            configuration_digest="d" * 64,
            issued_at=ISSUED,
            expires_at=ATTESTATION_EXPIRES,
            now=NOW,
        )
    assert caught.value.reason_code == "tampered_receipt_wrong_rejection"


def test_probe_registry_restores_exact_objects_when_surface_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    gateway, descriptor, ledger = _managed_gateway(tmp_path, workload)
    existing = gateway.register_tool("customer.existing", lambda: "existing")
    interleaved: Any | None = None

    def fail_mcp(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal interleaved
        interleaved = gateway.register_tool("customer.interleaved", lambda: "interleaved")
        raise RuntimeError("surface failure")

    monkeypatch.setattr(gateway, "handle_mcp_call", fail_mcp)
    with pytest.raises(RuntimeError, match="surface failure"):
        produce_wiring_attestation(
            gateway=gateway,
            runtime_identity_descriptor=descriptor,
            runtime_identity_issuer_public_key=IDENTITY_ISSUER.public_key_bytes(),
            runtime_identity_audience="control-plane",
            workload_key_provider=workload,
            receipt_consumption_ledger=ledger,
            authenticated_actor="runtime-1",
            nonce="verifier-nonce-0123456789abcdef",
            sequence=11,
            runtime_build_digest="c" * 64,
            configuration_digest="d" * 64,
            issued_at=ISSUED,
            expires_at=ATTESTATION_EXPIRES,
            now=NOW,
        )

    assert gateway._tools["customer.existing"] is existing
    assert gateway._tools["customer.interleaved"] is interleaved
    assert set(gateway.tool_names()) == {"customer.existing", "customer.interleaved"}


def test_probe_cleanup_preserves_interleaved_registration_on_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    gateway, descriptor, ledger = _managed_gateway(tmp_path, workload)
    existing = gateway.register_tool("customer.existing", lambda: "existing")
    original = gateway.handle_mcp_call
    interleaved: Any | None = None

    def register_during_probe(*args: Any, **kwargs: Any) -> Any:
        nonlocal interleaved
        interleaved = gateway.register_tool("customer.interleaved", lambda: "interleaved")
        return original(*args, **kwargs)

    monkeypatch.setattr(gateway, "handle_mcp_call", register_during_probe)
    produce_wiring_attestation(
        gateway=gateway,
        runtime_identity_descriptor=descriptor,
        runtime_identity_issuer_public_key=IDENTITY_ISSUER.public_key_bytes(),
        runtime_identity_audience="control-plane",
        workload_key_provider=workload,
        receipt_consumption_ledger=ledger,
        authenticated_actor="runtime-1",
        nonce="verifier-nonce-0123456789abcdef",
        sequence=11,
        runtime_build_digest="c" * 64,
        configuration_digest="d" * 64,
        issued_at=ISSUED,
        expires_at=ATTESTATION_EXPIRES,
        now=NOW,
    )

    assert gateway._tools["customer.existing"] is existing
    assert gateway._tools["customer.interleaved"] is interleaved
    assert set(gateway.tool_names()) == {"customer.existing", "customer.interleaved"}


def test_reserved_tool_collision_fails_before_any_probe_executes(tmp_path: Path) -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    gateway, descriptor, ledger = _managed_gateway(tmp_path, workload)
    effects: list[str] = []
    gateway.register_tool(RESERVED_ALLOW_TOOL, lambda: effects.append("customer"))

    with pytest.raises(WiringAttestationError, match="reserved"):
        produce_wiring_attestation(
            gateway=gateway,
            runtime_identity_descriptor=descriptor,
            runtime_identity_issuer_public_key=IDENTITY_ISSUER.public_key_bytes(),
            runtime_identity_audience="control-plane",
            workload_key_provider=workload,
            receipt_consumption_ledger=ledger,
            authenticated_actor="runtime-1",
            nonce="verifier-nonce-0123456789abcdef",
            sequence=11,
            runtime_build_digest="c" * 64,
            configuration_digest="d" * 64,
            issued_at=ISSUED,
            expires_at=ATTESTATION_EXPIRES,
            now=NOW,
        )

    assert effects == []


def test_scope_mismatch_fails_before_probe_registration_or_audit(tmp_path: Path) -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    gateway, _descriptor_value, ledger = _managed_gateway(tmp_path, workload)
    wrong_scope = GateScope("org-1", "project-2", "production", "gate-1")
    descriptor = RuntimeIdentityDescriptor.issue(
        scope=wrong_scope,
        runtime_identity_id="runtime-1",
        credential_id="credential-1",
        credential_generation=3,
        workload_public_key=workload.public_key_bytes(),
        issuer="control-plane",
        audience="control-plane",
        issued_at=_iso(timedelta(days=-1)),
        expires_at=_iso(timedelta(days=30)),
        signer=IDENTITY_ISSUER,
    )

    with pytest.raises(WiringAttestationError, match="scope"):
        produce_wiring_attestation(
            gateway=gateway,
            runtime_identity_descriptor=descriptor,
            runtime_identity_issuer_public_key=IDENTITY_ISSUER.public_key_bytes(),
            runtime_identity_audience="control-plane",
            workload_key_provider=workload,
            receipt_consumption_ledger=ledger,
            authenticated_actor="runtime-1",
            nonce="verifier-nonce-0123456789abcdef",
            sequence=11,
            runtime_build_digest="c" * 64,
            configuration_digest="d" * 64,
            issued_at=ISSUED,
            expires_at=ATTESTATION_EXPIRES,
            now=NOW,
        )

    assert gateway.tool_names() == ()
    assert tuple(gateway._audit.iter_events()) == ()


@pytest.mark.parametrize("failure", ["signature", "audience", "scope", "generation"])
def test_descriptor_authentication_fails_before_every_side_effect(
    tmp_path: Path, failure: str
) -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    gateway, descriptor, ledger = _managed_gateway(tmp_path, workload)
    existing = gateway.register_tool("customer.existing", lambda: "existing")
    audience = "control-plane"
    if failure == "signature":
        descriptor = dataclasses.replace(descriptor, signature="A" * 86)
    elif failure == "audience":
        audience = "other-audience"
    else:
        scope = (
            SCOPE
            if failure == "generation"
            else GateScope("org-1", "project-2", "production", "gate-1")
        )
        descriptor = RuntimeIdentityDescriptor.issue(
            scope=scope,
            runtime_identity_id="runtime-1",
            credential_id="credential-1",
            credential_generation=4 if failure == "generation" else 3,
            workload_public_key=workload.public_key_bytes(),
            issuer="control-plane",
            audience="control-plane",
            issued_at=_iso(timedelta(days=-1)),
            expires_at=_iso(timedelta(days=30)),
            signer=IDENTITY_ISSUER,
        )

    with pytest.raises(WiringAttestationError):
        produce_wiring_attestation(
            gateway=gateway,
            runtime_identity_descriptor=descriptor,
            runtime_identity_issuer_public_key=IDENTITY_ISSUER.public_key_bytes(),
            runtime_identity_audience=audience,
            workload_key_provider=workload,
            receipt_consumption_ledger=ledger,
            authenticated_actor="runtime-1",
            nonce="verifier-nonce-0123456789abcdef",
            sequence=11,
            runtime_build_digest="c" * 64,
            configuration_digest="d" * 64,
            issued_at=ISSUED,
            expires_at=ATTESTATION_EXPIRES,
            now=NOW,
        )

    assert gateway._tools == {"customer.existing": existing}
    assert tuple(gateway._audit.iter_events()) == ()
    assert not ledger.path.exists() or ledger.path.read_text(encoding="utf-8") == ""


def test_managed_claude_hook_decision_uses_verified_policy_binding(tmp_path: Path) -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    gateway, _descriptor_value, _ledger = _managed_gateway(tmp_path, workload)
    effects: list[str] = []
    gateway.register_tool("acgs.conformance.claude_deny", lambda: effects.append("forbidden"))

    response = gateway.handle_claude_hook(
        {
            "tool_name": "acgs.conformance.claude_deny",
            "tool_input": {"probe": "claude"},
        },
        actor="runtime-1",
    )

    with gateway.policy.receipt_binding_scope() as provenance:
        expected_hash = provenance.compute_hash()
    (commitment,) = response["gove_zone"]["decisions"]
    assert commitment["policy_provenance_hash"] == expected_hash
    assert effects == []


def test_managed_claude_allow_remains_decision_only_and_executes_nothing(tmp_path: Path) -> None:
    workload = InMemoryEd25519WorkloadKeyProvider(key_id="workload-key")
    gateway, _descriptor_value, _ledger = _managed_gateway(tmp_path, workload)
    effects: list[str] = []
    gateway.register_tool("customer.safe", lambda: effects.append("ran"))

    response = gateway.handle_claude_hook(
        {"tool_name": "customer.safe", "tool_input": {}}, actor="runtime-1"
    )

    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert response["gove_zone"]["execution_classification"] == "decision_only"
    assert response["gove_zone"]["decisions"][0]["decision"] == "allow"
    assert "receipts" not in response["gove_zone"]
    assert effects == []
