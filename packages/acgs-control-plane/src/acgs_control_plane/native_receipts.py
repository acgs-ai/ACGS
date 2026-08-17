"""Transactional persistence for signed native Decision Receipts.

This module is deliberately not connected to the legacy HTTP routes. Its
providers use a caller-owned :class:`sqlalchemy.orm.Session`: they flush so
database constraints are observed, but never commit or roll back. The caller
must place receipt persistence, the consumption burn, and the protected SQL
effect in one transaction. A rollback therefore removes all three; a commit
makes the authorization an at-most-once committed database effect.

External/non-transactional effects are outside this slice: they require a
separate durable execution protocol and must not use rollback as an "unburn".
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from gove_zone.audit import GENESIS_HASH
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import (
    ProductionProfileError,
    ReceiptAlreadyUsedError,
    ReceiptValidationError,
)
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.revocation import RevocationList
from gove_zone.signing import ReceiptSigner
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from acgs_control_plane.models import (
    GovernanceEvent,
    GovernanceEventCutover,
    GovernanceEventHead,
    NativeDecisionReceiptRow,
    NativeReceiptConsumption,
    Organization,
    ReceiptRow,
)

_LEDGER_NAME = "database:native_receipt_consumptions"
NATIVE_ASSURANCE_CLASS = "native"
NATIVE_SOURCE_SYSTEM = "gove-zone"
NATIVE_PROJECTION_SCHEMA = "acgs.native-receipt-projection.v1"
NATIVE_EVIDENCE_PROFILE = "managed-safe-native-v1"
CONSUMPTION_ATTESTATION_SCHEMA = "acgs.native-consumption-attestation.v1"
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9._:/@=-]{1,200}\Z")
_CUTOVER_READY_STATE = "native_artifacts_ready"
_PSEUDONYM_DOMAIN = "acgs-control-plane.native-receipt.pseudonym.v1"
_PSEUDONYM_PREFIX = "acgs-pseudo-v1:"
_REFERENCE_DOMAIN = "acgs-control-plane.native-receipt.reference.v1"
_REFERENCE_PREFIX = "acgs-ref-v1:"
_TENANT_SEGMENT = r"[A-Za-z0-9._-]{1,64}"
_TENANT_BOUND_PSEUDONYM_PATTERN = re.compile(
    rf"{re.escape(_PSEUDONYM_PREFIX)}(?P<tenant>{_TENANT_SEGMENT}):[0-9a-f]{{64}}\Z"
)
_TENANT_BOUND_REFERENCE_PATTERN = re.compile(
    rf"{re.escape(_REFERENCE_PREFIX)}(?P<tenant>{_TENANT_SEGMENT}):[0-9a-f]{{64}}\Z"
)
_SECRET_LIKE = re.compile(
    r"(?:sk_live|sk_test|sk-proj|ghp_|github_pat_|xox[baprs]-|AKIA|ASIA)[A-Za-z0-9_=-]*"
)
_READABLE_ACTIONS = frozenset({"database.agent.create"})
_READABLE_BOUNDARIES = frozenset({"control-plane/sql-transaction"})


def _parse_utc(value: str, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ReceiptValidationError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ReceiptValidationError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _as_utc(value: datetime) -> datetime:
    """Normalize SQLite's naive round-trip and PostgreSQL's aware value."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _require_hash_identifier(value: object, *, field: str) -> None:
    if not isinstance(value, str) or _HEX_SHA256.fullmatch(value) is None:
        raise ReceiptValidationError(f"native receipt artifact rejects unsafe {field}")


@dataclass(frozen=True, slots=True)
class TenantPrivacyProvider:
    """Tenant-bound HMAC helper for privacy-safe persisted references."""

    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) < 32:
            raise ValueError("tenant privacy provider requires at least 32 bytes of key material")

    def pseudonym(self, *, tenant_id: str, field: str, value: str) -> str:
        return self._digest(
            prefix=_PSEUDONYM_PREFIX,
            domain=_PSEUDONYM_DOMAIN,
            tenant_id=tenant_id,
            field=field,
            value=value,
        )

    def reference(self, *, tenant_id: str, field: str, value: str) -> str:
        return self._digest(
            prefix=_REFERENCE_PREFIX,
            domain=_REFERENCE_DOMAIN,
            tenant_id=tenant_id,
            field=field,
            value=value,
        )

    def _digest(self, *, prefix: str, domain: str, tenant_id: str, field: str, value: str) -> str:
        if not tenant_id or not field or not value:
            raise ValueError("tenant-bound privacy references require tenant, field, and value")
        if _SAFE_IDENTIFIER.fullmatch(tenant_id) is None:
            raise ValueError("tenant-bound privacy reference requires a safe tenant id")
        message = sha256_json(
            {"domain": domain, "tenant_id": tenant_id, "field": field, "value": value}
        ).encode()
        digest = hmac.new(self.key, message, hashlib.sha256).hexdigest()
        return f"{prefix}{tenant_id}:{digest}"


def native_receipt_pseudonym(
    field: str, value: str, *, tenant_id: str, privacy: TenantPrivacyProvider
) -> str:
    """Return a keyed tenant-bound pseudonym for persisted receipt identities."""
    return privacy.pseudonym(tenant_id=tenant_id, field=field, value=value)


def native_receipt_reference(
    field: str, value: str, *, tenant_id: str, privacy: TenantPrivacyProvider
) -> str:
    """Return a keyed tenant-bound reference for persisted caller-controlled IDs."""
    return privacy.reference(tenant_id=tenant_id, field=field, value=value)


def _require_pseudonym(value: object, *, field: str, tenant_id: str) -> None:
    if not isinstance(value, str):
        raise ReceiptValidationError(f"native receipt artifact rejects unsafe {field}")
    match = _TENANT_BOUND_PSEUDONYM_PATTERN.fullmatch(value)
    if match is None or match.group("tenant") != tenant_id:
        raise ReceiptValidationError(f"native receipt artifact rejects unsafe {field}")


def _require_reference(value: object, *, field: str, tenant_id: str) -> None:
    if not isinstance(value, str):
        raise ReceiptValidationError(f"native receipt artifact rejects unsafe {field}")
    match = _TENANT_BOUND_REFERENCE_PATTERN.fullmatch(value)
    if match is None or match.group("tenant") != tenant_id:
        raise ReceiptValidationError(f"native receipt artifact rejects unsafe {field}")


def _require_safe_identifier(value: object, *, field: str, allow_empty: bool = False) -> None:
    if allow_empty and value == "":
        return
    if not isinstance(value, str) or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ReceiptValidationError(f"native receipt artifact rejects unsafe {field}")
    if _SECRET_LIKE.search(value):
        raise ReceiptValidationError(f"native receipt artifact rejects unsafe {field}")


def _require_readable_value(value: object, *, field: str, allowed: frozenset[str]) -> None:
    _require_safe_identifier(value, field=field)
    if value not in allowed:
        raise ReceiptValidationError(f"native receipt artifact rejects unsafe {field}")


def _ed25519_public_fingerprint(signer: ReceiptSigner, *, field: str) -> str:
    if signer.algorithm != "ed25519":
        raise ReceiptValidationError(f"native receipt artifact rejects non-Ed25519 {field}")
    public_bytes = getattr(signer, "public_bytes", None)
    if not callable(public_bytes):
        raise ReceiptValidationError(f"native receipt artifact cannot fingerprint {field}")
    try:
        raw = public_bytes()
    except Exception as exc:
        raise ReceiptValidationError(f"native receipt artifact cannot fingerprint {field}") from exc
    if not isinstance(raw, bytes) or len(raw) != 32:
        raise ReceiptValidationError(f"native receipt artifact rejects unsafe {field}")
    return hashlib.sha256(raw).hexdigest()


def _require_distinct_attestor_key_material(
    *,
    receipt: DecisionReceipt,
    issuer_verifier: ReceiptSigner | None,
    attestor_key_id: str,
    attestor_verifier: ReceiptSigner | None,
) -> None:
    if issuer_verifier is None:
        raise ReceiptValidationError("native receipt issuer signer is untrusted")
    if attestor_verifier is None:
        raise ReceiptValidationError("native consumption attestation signer is untrusted")
    _require_safe_identifier(receipt.signing_key_id, field="receipt_signing_key_id")
    _require_safe_identifier(attestor_key_id, field="attestor_key_id")
    if attestor_key_id == receipt.signing_key_id:
        raise ReceiptValidationError(
            "native consumption attestor must be distinct from receipt issuer"
        )
    issuer_fingerprint = _ed25519_public_fingerprint(issuer_verifier, field="receipt_signing_key")
    attestor_fingerprint = _ed25519_public_fingerprint(attestor_verifier, field="attestor_key")
    if issuer_fingerprint == attestor_fingerprint:
        raise ReceiptValidationError(
            "native consumption attestor must use distinct key material from receipt issuer"
        )


def _validate_receipt_safe_bindings(receipt: DecisionReceipt) -> None:
    _require_safe_identifier(receipt.tenant_id, field="tenant_id")
    _require_pseudonym(receipt.actor, field="actor", tenant_id=receipt.tenant_id)
    _require_readable_value(
        receipt.proposed_action, field="proposed_action", allowed=_READABLE_ACTIONS
    )
    _require_readable_value(
        receipt.execution_boundary, field="execution_boundary", allowed=_READABLE_BOUNDARIES
    )
    _require_reference(
        receipt.policy_bundle_id, field="policy_bundle_id", tenant_id=receipt.tenant_id
    )
    _require_pseudonym(receipt.authority, field="authority", tenant_id=receipt.tenant_id)
    _require_pseudonym(receipt.validator_id, field="validator_id", tenant_id=receipt.tenant_id)
    _require_pseudonym(receipt.validator_role, field="validator_role", tenant_id=receipt.tenant_id)


def _safe_projection(receipt: DecisionReceipt) -> dict[str, Any]:
    """Return a deterministic projection that cannot retain freeform values.

    This SQL-only foundation accepts managed native ALLOW, DENY, and ESCALATE
    receipts with no subject, declared goal, constraints, or transformations.
    The approval summary must be exactly the canonical proposer/validator
    linkage added by ``DecisionReceipt.from_record``. Request IDs and
    matched-rule identifiers are retained only as hashes.
    """
    if receipt.decision not in {"allow", "deny", "escalate"}:
        raise ReceiptValidationError("native SQL receipt persistence rejects unsupported decision")
    _validate_receipt_safe_bindings(receipt)
    if receipt.subject or receipt.declared_goal:
        raise ReceiptValidationError(
            "native SQL receipt persistence rejects freeform subject or goal metadata"
        )
    if receipt.constraints or receipt.transformations:
        raise ReceiptValidationError(
            "native SQL receipt persistence rejects constraints or transformations"
        )
    expected_approval = {
        "proposer": receipt.actor,
        "validator_id": receipt.validator_id,
        "validator_role": receipt.validator_role,
        "authority": receipt.authority,
    }
    if receipt.approval_chain_summary != expected_approval:
        raise ReceiptValidationError(
            "native SQL receipt persistence rejects noncanonical approval metadata"
        )
    return {
        "schema": NATIVE_PROJECTION_SCHEMA,
        "receipt_id": receipt.receipt_id,
        "request_id_hash": sha256_json(receipt.request_id),
        "tenant_id": receipt.tenant_id,
        "actor": receipt.actor,
        "proposed_action": receipt.proposed_action,
        "execution_boundary": receipt.execution_boundary,
        "policy_bundle_id": receipt.policy_bundle_id,
        "policy_version": receipt.policy_version,
        "policy_hash": receipt.policy_hash,
        "decision": receipt.decision,
        "matched_rules_hash": sha256_json(receipt.matched_rules),
        "timestamp": receipt.timestamp,
        "expires_at": receipt.expires_at,
        "authority": receipt.authority,
        "validator_id": receipt.validator_id,
        "validator_role": receipt.validator_role,
        "argument_hash": receipt.argument_hash,
        "previous_audit_hash": receipt.previous_audit_hash,
        "audit_event_hash": receipt.audit_event_hash,
        "receipt_hash": receipt.receipt_hash,
        "signature_algorithm": receipt.signature_algorithm,
        "signing_key_id": receipt.signing_key_id,
        "signature": receipt.signature,
    }


def _safe_receipt_artifact(receipt: DecisionReceipt) -> tuple[dict[str, Any], str]:
    """Return reconstructible canonical receipt evidence for the managed-safe profile."""
    _safe_projection(receipt)
    _require_hash_identifier(receipt.request_id, field="request_id")
    for index, matched_rule in enumerate(receipt.matched_rules):
        _require_hash_identifier(matched_rule, field=f"matched_rules[{index}]")
    _require_safe_identifier(receipt.receipt_id, field="receipt_id")
    _require_safe_identifier(receipt.policy_version, field="policy_version")
    _require_hash_identifier(receipt.policy_hash, field="policy_hash")
    _require_hash_identifier(receipt.argument_hash, field="argument_hash")
    _require_hash_identifier(receipt.previous_audit_hash, field="previous_audit_hash")
    _require_hash_identifier(receipt.audit_event_hash, field="audit_event_hash")
    _require_safe_identifier(receipt.signing_key_id, field="signing_key_id")
    _require_safe_identifier(receipt.signature_algorithm, field="signature_algorithm")
    artifact = receipt.to_dict()
    reconstructed = _receipt_from_artifact(artifact)
    if reconstructed.to_dict() != artifact or reconstructed.compute_hash() != receipt.receipt_hash:
        raise ReceiptValidationError("native receipt artifact is not reconstructible")
    return artifact, sha256_json(artifact)


def _receipt_from_artifact(artifact: Mapping[str, Any]) -> DecisionReceipt:
    try:
        return DecisionReceipt.from_dict(dict(artifact))
    except (KeyError, TypeError, ValueError) as exc:
        raise ReceiptValidationError("native receipt artifact is malformed") from exc


def _row_matches_receipt(
    row: NativeDecisionReceiptRow, receipt: DecisionReceipt, projection: dict[str, Any]
) -> bool:
    return (
        row.receipt_id == receipt.receipt_id
        and row.receipt_hash == receipt.receipt_hash
        and row.audit_event_hash == receipt.audit_event_hash
        and row.assurance_class == NATIVE_ASSURANCE_CLASS
        and row.source_system == NATIVE_SOURCE_SYSTEM
        and row.decision == receipt.decision
        and row.actor == receipt.actor
        and row.execution_boundary == receipt.execution_boundary
        and row.proposed_action == receipt.proposed_action
        and row.policy_bundle_id == receipt.policy_bundle_id
        and row.policy_version == receipt.policy_version
        and row.policy_hash == receipt.policy_hash
        and _as_utc(row.issued_at) == _parse_utc(receipt.timestamp, field="timestamp")
        and _as_utc(row.expires_at) == _parse_utc(receipt.expires_at, field="expires_at")
        and row.signing_key_id == receipt.signing_key_id
        and row.signature_algorithm == receipt.signature_algorithm
        and row.projection == projection
    )


def _row_matches_verifiable_receipt(
    row: NativeDecisionReceiptRow,
    receipt: DecisionReceipt,
    projection: dict[str, Any],
    artifact: dict[str, Any],
    artifact_hash: str,
) -> bool:
    return (
        _row_matches_receipt(row, receipt, projection)
        and row.evidence_profile == NATIVE_EVIDENCE_PROFILE
        and row.receipt_artifact == artifact
        and row.receipt_artifact_hash == artifact_hash
    )


@dataclass(frozen=True, slots=True)
class NativeReceiptContext:
    """Authenticated expectations that an agent-controlled body cannot set."""

    org_id: str
    execution_boundary: str
    actor: str
    action: str
    policy_bundle_id: str
    policy_hash: str
    audit_hash: str | None = None
    args: dict[str, Any] | None = None
    validator_role: str | None = None
    authority: str | None = None

    def __post_init__(self) -> None:
        required = {
            "org_id": self.org_id,
            "execution_boundary": self.execution_boundary,
            "actor": self.actor,
            "action": self.action,
            "policy_bundle_id": self.policy_bundle_id,
            "policy_hash": self.policy_hash,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(f"native receipt context requires {', '.join(sorted(missing))}")


class ManagedNativeReceiptTrust:
    """Fail-loud signing and verification seam for managed native receipts.

    No signer or verifier is generated implicitly. Operators must inject a
    durable signer and a trust map containing its non-revoked key ID.
    """

    def __init__(
        self,
        *,
        signer: ReceiptSigner | None,
        verifiers: Mapping[str, ReceiptSigner] | None,
        revoked_keys: RevocationList | None = None,
        max_lifetime: timedelta = timedelta(minutes=5),
    ) -> None:
        if max_lifetime <= timedelta(0):
            raise ValueError("max_lifetime must be positive")
        self.signer = signer
        self.verifiers = dict(verifiers or {})
        self.revoked_keys = revoked_keys or RevocationList()
        self.max_lifetime = max_lifetime

    def assert_ready(self) -> None:
        signer = self.signer
        if signer is None or signer.algorithm != "ed25519" or not signer.key_id:
            raise ProductionProfileError(
                "managed native receipt issuance requires an explicitly configured Ed25519 signer"
            )
        _require_safe_identifier(signer.key_id, field="receipt_signing_key_id")
        self._assert_verifier_map_ready()
        verifier = self.verifiers.get(signer.key_id)
        if verifier is None:
            raise ProductionProfileError(
                f"managed native receipt signer key {signer.key_id!r} is absent from trust"
            )
        if self.revoked_keys.is_revoked(signer.key_id):
            raise ProductionProfileError(
                f"managed native receipt signer key {signer.key_id!r} is revoked"
            )
        if verifier.algorithm != "ed25519" or verifier.key_id != signer.key_id:
            raise ProductionProfileError("managed signer and verifier identity do not match")
        probe = b"acgs-control-plane-managed-native-receipt-readiness-v1"
        try:
            signature = signer.sign(probe)
            verified = verifier.verify(probe, signature)
        except Exception as exc:
            raise ProductionProfileError("managed signer/verifier readiness probe failed") from exc
        if not verified:
            raise ProductionProfileError("managed signer/verifier readiness probe failed")

    def mint(
        self,
        record: DecisionRecord,
        *,
        audit_hash: str,
        previous_audit_hash: str,
        tenant_id: str,
        execution_boundary: str,
        policy_bundle_id: str,
        policy_hash: str,
        request_id: str,
        validator: Validator,
        authority: str,
        expires_at: str,
        subject: str = "",
        constraints: dict[str, Any] | None = None,
        approval_chain_summary: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> DecisionReceipt:
        self.assert_ready()
        assert self.signer is not None
        receipt = DecisionReceipt.from_record(
            record,
            audit_hash,
            previous_audit_hash,
            tenant_id,
            execution_boundary,
            policy_bundle_id,
            policy_hash,
            request_id,
            validator=validator,
            authority=authority,
            subject=subject,
            constraints=constraints,
            approval_chain_summary=approval_chain_summary,
            expires_at=expires_at,
            signer=self.signer,
        )
        self._verify_lifetime(receipt, now=now)
        return receipt

    def verify(
        self,
        receipt: DecisionReceipt,
        context: NativeReceiptContext,
        *,
        now: datetime | None = None,
    ) -> None:
        self._assert_verifier_map_ready()
        self._verify_lifetime(receipt, now=now)
        receipt.verify(
            expected_tenant_id=context.org_id,
            expected_execution_boundary=context.execution_boundary,
            expected_audit_hash=context.audit_hash,
            expected_args=context.args,
            expected_action=context.action,
            expected_policy_hash=context.policy_hash,
            expected_policy_bundle_id=context.policy_bundle_id,
            expected_validator_role=context.validator_role,
            expected_authority=context.authority,
            expected_actor=context.actor,
            verifier=self.verifiers,
            require_signature=True,
            require_expiry=True,
            revoked_keys=self.revoked_keys,
            now_iso=(now or datetime.now(UTC)).isoformat(),
        )

    def verify_historical(self, receipt: DecisionReceipt, context: NativeReceiptContext) -> None:
        """Verify durable evidence at issuance time, not at the wall clock now."""
        self._assert_verifier_map_ready()
        issued = self._verify_recorded_lifetime(receipt)
        required_fields = [
            "receipt_id",
            "request_id",
            "tenant_id",
            "actor",
            "proposed_action",
            "execution_boundary",
            "policy_bundle_id",
            "policy_version",
            "policy_hash",
            "decision",
            "timestamp",
            "previous_audit_hash",
            "audit_event_hash",
            "validator_id",
            "validator_role",
            "authority",
            "argument_hash",
            "receipt_hash",
            "signature_algorithm",
            "signing_key_id",
            "signature",
        ]
        for field_name in required_fields:
            if getattr(receipt, field_name) in (None, ""):
                raise ReceiptValidationError(f"native receipt missing {field_name}")
        if receipt.compute_hash() != receipt.receipt_hash:
            raise ReceiptValidationError("native receipt hash recomputation failed")
        if receipt.signature_algorithm == "none":
            raise ReceiptValidationError("managed native receipt requires signature")
        if self.revoked_keys is not None and self.revoked_keys.is_revoked(receipt.signing_key_id):
            raise ReceiptValidationError("native receipt signing key is revoked")
        verifier = self.verifiers.get(receipt.signing_key_id)
        if verifier is None:
            raise ReceiptValidationError("native receipt signing key is untrusted")
        if verifier.algorithm != receipt.signature_algorithm:
            raise ReceiptValidationError("native receipt signature algorithm mismatch")
        if not verifier.verify(receipt.receipt_hash.encode("utf-8"), receipt.signature):
            raise ReceiptValidationError("native receipt signature is invalid")
        try:
            Decision(receipt.decision)
        except ValueError as exc:
            raise ReceiptValidationError("native receipt decision is unknown") from exc
        if receipt.tenant_id != context.org_id:
            raise ReceiptValidationError("native receipt tenant mismatch")
        if receipt.execution_boundary != context.execution_boundary:
            raise ReceiptValidationError("native receipt execution boundary mismatch")
        if receipt.proposed_action != context.action:
            raise ReceiptValidationError("native receipt action mismatch")
        if receipt.audit_event_hash != context.audit_hash:
            raise ReceiptValidationError("native receipt audit hash mismatch")
        if receipt.policy_hash != context.policy_hash:
            raise ReceiptValidationError("native receipt policy hash mismatch")
        if receipt.policy_bundle_id != context.policy_bundle_id:
            raise ReceiptValidationError("native receipt policy bundle mismatch")
        if receipt.validator_role != context.validator_role:
            raise ReceiptValidationError("native receipt validator role mismatch")
        if receipt.authority != context.authority:
            raise ReceiptValidationError("native receipt authority mismatch")
        if receipt.actor != context.actor:
            raise ReceiptValidationError("native receipt actor mismatch")
        if receipt.validator_id == receipt.actor:
            raise ReceiptValidationError("native receipt self-validation")
        if context.args is not None and receipt.argument_hash != sha256_json(dict(context.args)):
            raise ReceiptValidationError("native receipt argument hash mismatch")
        now_iso = issued.isoformat()
        try:
            current_dt = datetime.fromisoformat(now_iso)
            expires_dt = datetime.fromisoformat(receipt.expires_at)
        except (ValueError, TypeError) as exc:
            raise ReceiptValidationError("native receipt expiry is malformed") from exc
        if current_dt.tzinfo is None or expires_dt.tzinfo is None or current_dt > expires_dt:
            raise ReceiptValidationError("native receipt expiry is invalid")

    def _assert_verifier_map_ready(self) -> None:
        if not self.verifiers:
            raise ProductionProfileError(
                "managed native receipt verification requires an explicit trust map"
            )
        for mapping_key, verifier_candidate in self.verifiers.items():
            _require_safe_identifier(mapping_key, field="receipt_trust_key_id")
            if (
                verifier_candidate.key_id != mapping_key
                or verifier_candidate.algorithm != "ed25519"
            ):
                raise ProductionProfileError("managed native receipt trust map key mismatch")

    def _verify_lifetime(
        self, receipt: DecisionReceipt, *, now: datetime | None = None
    ) -> datetime:
        if not receipt.expires_at:
            raise ReceiptValidationError("managed native receipts require bounded expiry")
        issued = _parse_utc(receipt.timestamp, field="timestamp")
        expires = _parse_utc(receipt.expires_at, field="expires_at")
        if expires <= issued or expires - issued > self.max_lifetime:
            raise ReceiptValidationError(
                "managed native receipt lifetime exceeds the configured bound"
            )
        if expires <= (now or datetime.now(UTC)).astimezone(UTC):
            raise ReceiptValidationError("managed native receipt is expired")
        return expires

    def _verify_recorded_lifetime(self, receipt: DecisionReceipt) -> datetime:
        if not receipt.expires_at:
            raise ReceiptValidationError("managed native receipts require bounded expiry")
        issued = _parse_utc(receipt.timestamp, field="timestamp")
        expires = _parse_utc(receipt.expires_at, field="expires_at")
        if expires <= issued or expires - issued > self.max_lifetime:
            raise ReceiptValidationError(
                "managed native receipt lifetime exceeds the configured bound"
            )
        return issued


class ManagedConsumptionAttestationTrust:
    """Fail-loud signer/verifier for executor consumption attestations."""

    def __init__(
        self,
        *,
        signer: ReceiptSigner | None,
        verifiers: Mapping[str, ReceiptSigner] | None,
        revoked_keys: RevocationList | None = None,
    ) -> None:
        self.signer = signer
        self.verifiers = dict(verifiers or {})
        self.revoked_keys = revoked_keys or RevocationList()

    def assert_ready(self) -> None:
        signer = self.signer
        if signer is None or signer.algorithm != "ed25519" or not signer.key_id:
            raise ProductionProfileError(
                "native receipt consumption requires an explicitly configured Ed25519 attestor"
            )
        _require_safe_identifier(signer.key_id, field="attestor_key_id")
        for mapping_key, verifier_candidate in self.verifiers.items():
            _require_safe_identifier(mapping_key, field="attestor_trust_key_id")
            if (
                verifier_candidate.key_id != mapping_key
                or verifier_candidate.algorithm != "ed25519"
            ):
                raise ProductionProfileError(
                    "native receipt consumption attestor trust map key mismatch"
                )
        verifier = self.verifiers.get(signer.key_id)
        if verifier is None:
            raise ProductionProfileError(
                f"native receipt consumption attestor key {signer.key_id!r} is absent from trust"
            )
        if self.revoked_keys.is_revoked(signer.key_id):
            raise ProductionProfileError(
                f"native receipt consumption attestor key {signer.key_id!r} is revoked"
            )
        if verifier.algorithm != "ed25519" or verifier.key_id != signer.key_id:
            raise ProductionProfileError("native receipt consumption attestor trust mismatch")
        probe = b"acgs-control-plane-native-consumption-attestor-readiness-v1"
        try:
            signature = signer.sign(probe)
            verified = verifier.verify(probe, signature)
        except Exception as exc:
            raise ProductionProfileError(
                "native receipt consumption attestor readiness probe failed"
            ) from exc
        if not verified:
            raise ProductionProfileError(
                "native receipt consumption attestor readiness probe failed"
            )

    def sign(self, artifact: Mapping[str, Any]) -> tuple[str, str, str, str]:
        self.assert_ready()
        assert self.signer is not None
        artifact_hash = sha256_json(dict(artifact))
        signature = self.signer.sign(artifact_hash.encode())
        return artifact_hash, self.signer.algorithm, self.signer.key_id, signature

    def verify(
        self,
        artifact: Mapping[str, Any],
        *,
        artifact_hash: str,
        algorithm: str,
        key_id: str,
        signature: str,
    ) -> None:
        if not self.verifiers:
            raise ProductionProfileError(
                "native receipt consumption verification requires explicit attestor trust"
            )
        if artifact_hash != sha256_json(dict(artifact)):
            raise ReceiptValidationError("native consumption attestation hash mismatch")
        if algorithm != "ed25519":
            raise ReceiptValidationError("native consumption attestation algorithm mismatch")
        _require_safe_identifier(key_id, field="attestor_key_id")
        verifier = self.verifiers.get(key_id)
        if verifier is None:
            raise ReceiptValidationError("native consumption attestation signer is untrusted")
        if self.revoked_keys.is_revoked(key_id):
            raise ReceiptValidationError("native consumption attestation signer is revoked")
        if verifier.key_id != key_id:
            raise ReceiptValidationError("native consumption attestation signer identity mismatch")
        if verifier.algorithm != "ed25519":
            raise ReceiptValidationError("native consumption attestation algorithm mismatch")
        if not verifier.verify(artifact_hash.encode(), signature):
            raise ReceiptValidationError("native consumption attestation signature mismatch")


class DatabaseNativeReceiptStore:
    """Persist verified native receipts without owning transaction outcome."""

    def __init__(self, session: Session, *, trust: ManagedNativeReceiptTrust) -> None:
        self.session = session
        self.trust = trust

    def persist(
        self,
        receipt: DecisionReceipt,
        context: NativeReceiptContext,
        *,
        now: datetime | None = None,
    ) -> NativeDecisionReceiptRow:
        projection = _safe_projection(receipt)
        self.trust.assert_ready()
        self.trust._verify_lifetime(receipt, now=now)
        self.trust.verify_historical(receipt, context)
        existing = self.session.scalar(
            select(NativeDecisionReceiptRow).where(
                NativeDecisionReceiptRow.org_id == context.org_id,
                NativeDecisionReceiptRow.receipt_id == receipt.receipt_id,
            )
        )
        if existing is not None:
            if _row_matches_receipt(existing, receipt, projection):
                return existing
            raise ReceiptValidationError(
                "receipt_id conflicts with different persisted native receipt evidence"
            )

        row = NativeDecisionReceiptRow(
            org_id=context.org_id,
            receipt_id=receipt.receipt_id,
            receipt_hash=receipt.receipt_hash,
            audit_event_hash=receipt.audit_event_hash,
            assurance_class=NATIVE_ASSURANCE_CLASS,
            source_system=NATIVE_SOURCE_SYSTEM,
            decision=receipt.decision,
            actor=receipt.actor,
            execution_boundary=receipt.execution_boundary,
            proposed_action=receipt.proposed_action,
            policy_bundle_id=receipt.policy_bundle_id,
            policy_version=receipt.policy_version,
            policy_hash=receipt.policy_hash,
            issued_at=_parse_utc(receipt.timestamp, field="timestamp"),
            expires_at=_parse_utc(receipt.expires_at, field="expires_at"),
            signing_key_id=receipt.signing_key_id,
            signature_algorithm=receipt.signature_algorithm,
            projection=projection,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def persist_verifiable(
        self,
        receipt: DecisionReceipt,
        context: NativeReceiptContext,
        *,
        now: datetime | None = None,
    ) -> NativeDecisionReceiptRow:
        projection = _safe_projection(receipt)
        artifact, artifact_hash = _safe_receipt_artifact(receipt)
        self.trust.assert_ready()
        self.trust._verify_lifetime(receipt, now=now)
        self.trust.verify_historical(receipt, context)
        existing = self.session.scalar(
            select(NativeDecisionReceiptRow).where(
                NativeDecisionReceiptRow.org_id == context.org_id,
                NativeDecisionReceiptRow.receipt_id == receipt.receipt_id,
            )
        )
        if existing is not None:
            if _row_matches_verifiable_receipt(
                existing, receipt, projection, artifact, artifact_hash
            ):
                return existing
            raise ReceiptValidationError(
                "receipt_id conflicts with different persisted verifiable native evidence"
            )

        row = NativeDecisionReceiptRow(
            org_id=context.org_id,
            receipt_id=receipt.receipt_id,
            receipt_hash=receipt.receipt_hash,
            audit_event_hash=receipt.audit_event_hash,
            assurance_class=NATIVE_ASSURANCE_CLASS,
            source_system=NATIVE_SOURCE_SYSTEM,
            decision=receipt.decision,
            actor=receipt.actor,
            execution_boundary=receipt.execution_boundary,
            proposed_action=receipt.proposed_action,
            policy_bundle_id=receipt.policy_bundle_id,
            policy_version=receipt.policy_version,
            policy_hash=receipt.policy_hash,
            issued_at=_parse_utc(receipt.timestamp, field="timestamp"),
            expires_at=_parse_utc(receipt.expires_at, field="expires_at"),
            signing_key_id=receipt.signing_key_id,
            signature_algorithm=receipt.signature_algorithm,
            projection=projection,
            receipt_artifact=artifact,
            receipt_artifact_hash=artifact_hash,
            evidence_profile=NATIVE_EVIDENCE_PROFILE,
        )
        self.session.add(row)
        self.session.flush()
        return row


def _consumption_attestation_artifact(
    *,
    row: NativeDecisionReceiptRow,
    receipt: DecisionReceipt,
    context: NativeReceiptContext,
    consumed_at: datetime,
    attestor_algorithm: str,
    attestor_key_id: str,
) -> dict[str, Any]:
    issued = _parse_utc(receipt.timestamp, field="timestamp")
    expires = _parse_utc(receipt.expires_at, field="expires_at")
    consumed = _as_utc(consumed_at)
    if consumed < issued:
        raise ReceiptValidationError("native consumption predates receipt issuance")
    if consumed >= expires:
        raise ReceiptValidationError("native consumption is outside receipt lifetime")
    if attestor_algorithm != "ed25519":
        raise ReceiptValidationError("native consumption attestation requires Ed25519")
    _require_safe_identifier(attestor_key_id, field="attestor_key_id")
    return {
        "schema": CONSUMPTION_ATTESTATION_SCHEMA,
        "org_id": context.org_id,
        "native_receipt_id": row.id,
        "receipt_id": receipt.receipt_id,
        "receipt_hash": receipt.receipt_hash,
        "audit_event_hash": receipt.audit_event_hash,
        "execution_boundary": context.execution_boundary,
        "actor": context.actor,
        "proposed_action": context.action,
        "policy_bundle_id": context.policy_bundle_id,
        "policy_hash": context.policy_hash,
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "consumed_at": consumed.isoformat(),
        "receipt_signing_key_id": receipt.signing_key_id,
        "receipt_signature_algorithm": receipt.signature_algorithm,
        "attestor_key_id": attestor_key_id,
        "attestor_algorithm": attestor_algorithm,
    }


class DatabaseReceiptConsumptionLedger:
    """Duck-typed gove-zone consumption ledger backed by the caller's DB tx."""

    def __init__(
        self,
        session: Session,
        *,
        trust: ManagedNativeReceiptTrust,
        consumption_trust: ManagedConsumptionAttestationTrust,
        context: NativeReceiptContext,
    ) -> None:
        self.session = session
        self.trust = trust
        self.consumption_trust = consumption_trust
        self.context = context

    def consume(self, receipt: DecisionReceipt) -> dict[str, Any]:
        projection = _safe_projection(receipt)
        consumed_at = datetime.now(UTC)
        self.trust.verify(receipt, self.context, now=consumed_at)
        persisted = self.session.scalar(
            select(NativeDecisionReceiptRow)
            .where(
                NativeDecisionReceiptRow.org_id == self.context.org_id,
                NativeDecisionReceiptRow.receipt_id == receipt.receipt_id,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if persisted is None:
            raise ReceiptValidationError("native receipt must be persisted before consumption")
        if not _row_matches_receipt(persisted, receipt, projection):
            raise ReceiptValidationError("persisted native receipt evidence does not match input")

        existing = self.session.scalar(
            select(NativeReceiptConsumption.id).where(
                NativeReceiptConsumption.org_id == self.context.org_id,
                NativeReceiptConsumption.native_receipt_id == persisted.id,
            )
        )
        if existing is not None:
            raise ReceiptAlreadyUsedError(receipt.audit_event_hash, _LEDGER_NAME)

        self.consumption_trust.assert_ready()
        assert self.consumption_trust.signer is not None
        _require_distinct_attestor_key_material(
            receipt=receipt,
            issuer_verifier=self.trust.verifiers.get(receipt.signing_key_id),
            attestor_key_id=self.consumption_trust.signer.key_id,
            attestor_verifier=self.consumption_trust.signer,
        )
        artifact = _consumption_attestation_artifact(
            row=persisted,
            receipt=receipt,
            context=self.context,
            consumed_at=consumed_at,
            attestor_algorithm=self.consumption_trust.signer.algorithm,
            attestor_key_id=self.consumption_trust.signer.key_id,
        )
        artifact_hash, algorithm, key_id, signature = self.consumption_trust.sign(artifact)
        consumption = NativeReceiptConsumption(
            org_id=self.context.org_id,
            native_receipt_id=persisted.id,
            receipt_hash=receipt.receipt_hash,
            audit_event_hash=receipt.audit_event_hash,
            consumed_at=consumed_at,
            attestation_artifact=artifact,
            attestation_artifact_hash=artifact_hash,
            attestation_signature_algorithm=algorithm,
            attestation_signing_key_id=key_id,
            attestation_signature=signature,
        )
        self.session.add(consumption)
        self.session.flush()
        return {
            "org_id": self.context.org_id,
            "receipt_id": receipt.receipt_id,
            "receipt_hash": receipt.receipt_hash,
            "audit_event_hash": receipt.audit_event_hash,
        }


@dataclass(frozen=True, slots=True)
class NativeEvidenceVerificationResult:
    """Result of a complete tenant-native evidence verification pass."""

    org_id: str
    receipt_count: int
    event_count: int
    last_event_hash: str


@dataclass(frozen=True, slots=True)
class NativeCutoverReadiness:
    """Monotonic readiness report; ``ready=False`` is a fail-closed state."""

    org_id: str
    ready: bool
    reason: str
    receipt_count: int = 0
    event_count: int = 0
    last_event_hash: str = GENESIS_HASH


def verify_native_evidence_chain(
    session: Session,
    org_id: str,
    *,
    trust: ManagedNativeReceiptTrust,
    consumption_trust: ManagedConsumptionAttestationTrust,
    now: datetime | None = None,
) -> NativeEvidenceVerificationResult:
    """Verify native receipt artifacts and the full tenant governance chain."""
    rows = list(
        session.scalars(
            select(NativeDecisionReceiptRow)
            .where(NativeDecisionReceiptRow.org_id == org_id)
            .order_by(NativeDecisionReceiptRow.created_at, NativeDecisionReceiptRow.id)
        )
    )
    if not rows:
        raise ReceiptValidationError("native evidence verification found no receipts")
    events = list(
        session.scalars(
            select(GovernanceEvent)
            .where(GovernanceEvent.org_id == org_id)
            .order_by(GovernanceEvent.sequence)
        )
    )
    head = session.get(GovernanceEventHead, org_id)
    if head is None:
        raise ReceiptValidationError("native evidence verification found no governance head")

    event_by_hash = _verify_governance_events(org_id, events, head)
    consumptions = list(
        session.scalars(
            select(NativeReceiptConsumption).where(NativeReceiptConsumption.org_id == org_id)
        )
    )
    native_event_hashes = {
        event.event_hash for event in events if _is_native_managed_receipt_event(org_id, event)
    }
    row_hashes = [row.audit_event_hash for row in rows]
    if len(row_hashes) != len(set(row_hashes)):
        raise ReceiptValidationError("native evidence contains duplicate receipt event bindings")
    artifact_hashes = [row.receipt_artifact_hash for row in rows if row.receipt_artifact_hash]
    if len(artifact_hashes) != len(set(artifact_hashes)):
        raise ReceiptValidationError("native evidence contains duplicate receipt artifacts")
    missing = native_event_hashes - set(row_hashes)
    extra = set(row_hashes) - native_event_hashes
    if missing:
        raise ReceiptValidationError("native evidence missing governance receipt artifact")
    if extra:
        raise ReceiptValidationError(
            "native evidence has receipt artifact without managed governance event"
        )
    for row in rows:
        _verify_native_row(
            row,
            trust=trust,
            consumption_trust=consumption_trust,
            event_by_hash=event_by_hash,
            consumptions=consumptions,
            now=now,
        )

    return NativeEvidenceVerificationResult(
        org_id=org_id,
        receipt_count=len(rows),
        event_count=len(events),
        last_event_hash=head.last_event_hash,
    )


def assess_native_cutover_readiness(
    session: Session,
    org_id: str,
    *,
    trust: ManagedNativeReceiptTrust,
    consumption_trust: ManagedConsumptionAttestationTrust,
    legacy_write_paths_active: bool,
    now: datetime | None = None,
) -> NativeCutoverReadiness:
    """Return an assessment only; activation must recheck in the same serialized tx."""
    org = session.scalar(
        select(Organization)
        .where(Organization.id == org_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if org is None:
        return NativeCutoverReadiness(org_id=org_id, ready=False, reason="organization is missing")
    marker = session.get(GovernanceEventCutover, org_id)
    receipt_count = (
        session.scalar(
            select(func.count())
            .select_from(NativeDecisionReceiptRow)
            .where(NativeDecisionReceiptRow.org_id == org_id)
        )
        or 0
    )
    if marker is None:
        reason = "native cutover marker is missing" if receipt_count else "no native evidence"
        return NativeCutoverReadiness(org_id=org_id, ready=False, reason=reason)
    if marker.state != _CUTOVER_READY_STATE or marker.cutover_at is None:
        return NativeCutoverReadiness(
            org_id=org_id, ready=False, reason="cutover marker is not ready"
        )
    clock = (now or datetime.now(UTC)).astimezone(UTC)
    cutover_at = _as_utc(marker.cutover_at)
    if cutover_at > clock:
        return NativeCutoverReadiness(
            org_id=org_id,
            ready=False,
            reason="cutover marker is in the future",
        )
    if marker.native_event_count is None or marker.native_event_head_hash is None:
        return NativeCutoverReadiness(
            org_id=org_id,
            ready=False,
            reason="cutover marker lacks native chain anchors",
        )
    legacy_anchor_error = _legacy_cutover_anchor_error(session, org, marker, cutover_at)
    if legacy_anchor_error is not None:
        return NativeCutoverReadiness(
            org_id=org_id,
            ready=False,
            reason=legacy_anchor_error,
        )
    if legacy_write_paths_active or _canonical_route_contracts_have_legacy_writers():
        return NativeCutoverReadiness(
            org_id=org_id,
            ready=False,
            reason="legacy write path remains active",
        )
    legacy_after_boundary = (
        session.scalar(
            select(func.count())
            .select_from(ReceiptRow)
            .where(
                ReceiptRow.org_id == org_id,
                ReceiptRow.created_at > cutover_at,
            )
        )
        or 0
    )
    if legacy_after_boundary:
        return NativeCutoverReadiness(
            org_id=org_id,
            ready=False,
            reason="legacy receipts exist beyond cutover boundary",
        )
    try:
        verified = verify_native_evidence_chain(
            session,
            org_id,
            trust=trust,
            consumption_trust=consumption_trust,
            now=now,
        )
    except (ReceiptValidationError, ProductionProfileError) as exc:
        return NativeCutoverReadiness(org_id=org_id, ready=False, reason=str(exc))
    if marker.native_event_count != verified.event_count:
        return NativeCutoverReadiness(
            org_id=org_id,
            ready=False,
            reason="cutover marker native event count mismatch",
        )
    if marker.native_event_head_hash != verified.last_event_hash:
        return NativeCutoverReadiness(
            org_id=org_id,
            ready=False,
            reason="cutover marker native head hash mismatch",
        )
    return NativeCutoverReadiness(
        org_id=org_id,
        ready=True,
        reason="native artifacts and governance chain verified",
        receipt_count=verified.receipt_count,
        event_count=verified.event_count,
        last_event_hash=verified.last_event_hash,
    )


def _verify_governance_events(
    org_id: str, events: list[GovernanceEvent], head: GovernanceEventHead
) -> dict[str, GovernanceEvent]:
    if head.last_sequence != len(events):
        raise ReceiptValidationError("governance event head sequence does not match events")
    previous = GENESIS_HASH
    by_hash: dict[str, GovernanceEvent] = {}
    for expected_sequence, event in enumerate(events, start=1):
        if event.org_id != org_id:
            raise ReceiptValidationError("cross-tenant governance event in native chain")
        if event.sequence != expected_sequence:
            raise ReceiptValidationError("governance event sequence is not contiguous")
        if event.previous_hash != previous:
            raise ReceiptValidationError("governance event previous hash mismatch")
        if event.payload.get("previous_hash") != previous:
            raise ReceiptValidationError("governance event payload previous hash mismatch")
        if event.payload.get("decision") != event.decision:
            raise ReceiptValidationError("governance event decision field mismatch")
        payload = dict(event.payload)
        claimed = payload.pop("event_hash", None)
        if claimed != event.event_hash:
            raise ReceiptValidationError("governance event payload hash mismatch")
        if event.event_hash != sha256_json(payload):
            raise ReceiptValidationError("governance event hash recomputation failed")
        if event.event_hash in by_hash:
            raise ReceiptValidationError("duplicate governance event hash")
        by_hash[event.event_hash] = event
        previous = event.event_hash
    if head.last_event_hash != previous:
        raise ReceiptValidationError("governance event head hash does not match chain")
    return by_hash


def _canonical_route_contracts_have_legacy_writers() -> bool:
    from acgs_control_plane.governance import ROUTE_CONTRACTS, ExecutionClass

    return any(
        getattr(contract, "execution_class", None) is ExecutionClass.LEGACY_UNSIGNED_WRITE
        for contract in ROUTE_CONTRACTS
    )


def _legacy_cutover_anchor_error(
    session: Session,
    org: Organization,
    marker: GovernanceEventCutover,
    cutover_at: datetime,
) -> str | None:
    org_id = org.id
    if marker.legacy_audit_anchor_count < 0 or org.audit_anchor_count < 0:
        return "cutover marker legacy anchor count mismatch"
    if marker.legacy_audit_anchor_count != org.audit_anchor_count:
        return "cutover marker legacy anchor count mismatch"
    if marker.legacy_audit_anchor_hash != org.audit_anchor_hash:
        return "cutover marker legacy anchor hash mismatch"
    if org.audit_anchor_count > 0:
        if _HEX_SHA256.fullmatch(org.audit_anchor_hash) is None:
            return "cutover marker legacy anchor hash is unsafe"
        return "verified legacy chain snapshot required"
    if marker.legacy_audit_anchor_count != 0 or marker.legacy_audit_anchor_hash != "":
        return "cutover marker legacy anchor hash mismatch"
    if org.audit_anchor_hash != "":
        return "cutover marker legacy anchor hash mismatch"
    legacy_rows = list(
        session.scalars(
            select(ReceiptRow)
            .where(
                ReceiptRow.org_id == org_id,
                ReceiptRow.created_at <= cutover_at,
            )
            .order_by(ReceiptRow.created_at, ReceiptRow.id)
        )
    )
    if legacy_rows:
        return "cutover marker legacy anchor count mismatch"
    return None


def _is_executable_native_allow_event(org_id: str, event: GovernanceEvent) -> bool:
    return (
        event.org_id == org_id
        and event.decision == "allow"
        and event.payload.get("decision") == "allow"
    )


def _is_native_managed_receipt_event(org_id: str, event: GovernanceEvent) -> bool:
    return (
        event.org_id == org_id
        and event.tool == "database.agent.create"
        and event.payload.get("tool") == "database.agent.create"
        and event.decision in {"allow", "deny", "escalate"}
        and event.payload.get("decision") == event.decision
    )


def _verify_native_row(
    row: NativeDecisionReceiptRow,
    *,
    trust: ManagedNativeReceiptTrust,
    consumption_trust: ManagedConsumptionAttestationTrust,
    event_by_hash: Mapping[str, GovernanceEvent],
    consumptions: list[NativeReceiptConsumption],
    now: datetime | None,
) -> None:
    if row.assurance_class != NATIVE_ASSURANCE_CLASS or row.source_system != NATIVE_SOURCE_SYSTEM:
        raise ReceiptValidationError("native evidence row has wrong assurance source")
    if row.evidence_profile != NATIVE_EVIDENCE_PROFILE:
        raise ReceiptValidationError("native evidence row is missing managed-safe profile")
    if row.receipt_artifact is None or row.receipt_artifact_hash is None:
        raise ReceiptValidationError("native evidence row is missing receipt artifact")
    artifact = row.receipt_artifact
    if not isinstance(artifact, dict) or row.receipt_artifact_hash != sha256_json(artifact):
        raise ReceiptValidationError("native receipt artifact hash mismatch")
    receipt = _receipt_from_artifact(artifact)
    projection = _safe_projection(receipt)
    safe_artifact, artifact_hash = _safe_receipt_artifact(receipt)
    if artifact != safe_artifact or row.receipt_artifact_hash != artifact_hash:
        raise ReceiptValidationError("native receipt artifact is not canonical")
    if not _row_matches_verifiable_receipt(row, receipt, projection, safe_artifact, artifact_hash):
        raise ReceiptValidationError("native receipt row does not match artifact")
    context = NativeReceiptContext(
        org_id=row.org_id,
        execution_boundary=row.execution_boundary,
        actor=row.actor,
        action=row.proposed_action,
        policy_bundle_id=row.policy_bundle_id,
        policy_hash=row.policy_hash,
        audit_hash=row.audit_event_hash,
        args=None,
        validator_role=receipt.validator_role,
        authority=receipt.authority,
    )
    trust.verify_historical(receipt, context)
    event = event_by_hash.get(row.audit_event_hash)
    if event is None:
        raise ReceiptValidationError("native receipt audit event is missing from governance chain")
    _verify_receipt_event_equivalence(receipt, event)
    if _is_executable_native_allow_event(row.org_id, event):
        _verify_consumption(
            row,
            receipt,
            consumptions,
            trust=trust,
            consumption_trust=consumption_trust,
        )
    elif _linked_consumptions(row, consumptions):
        raise ReceiptValidationError("blocked native receipt has consumption evidence")


def _verify_receipt_event_equivalence(receipt: DecisionReceipt, event: GovernanceEvent) -> None:
    payload = event.payload
    expected = {
        "decision": receipt.decision,
        "tool": receipt.proposed_action,
        "argument_hash": receipt.argument_hash,
        "policy_version": receipt.policy_version,
        "event_id": receipt.receipt_id,
        "matched_rules": list(receipt.matched_rules),
        "timestamp_iso": receipt.timestamp,
        "actor": receipt.actor,
    }
    for field, expected_value in expected.items():
        if payload.get(field) != expected_value:
            raise ReceiptValidationError(f"native receipt audit event {field} mismatch")
    if receipt.previous_audit_hash != event.previous_hash:
        raise ReceiptValidationError("native receipt previous audit hash mismatch")
    if event.event_id != receipt.receipt_id:
        raise ReceiptValidationError("native receipt audit event id mismatch")
    if event.decision != receipt.decision or event.tool != receipt.proposed_action:
        raise ReceiptValidationError("native receipt audit event scalar mismatch")
    if event.actor != receipt.actor or event.policy_version != receipt.policy_version:
        raise ReceiptValidationError("native receipt audit event binding mismatch")


def _verify_consumption(
    row: NativeDecisionReceiptRow,
    receipt: DecisionReceipt,
    consumptions: list[NativeReceiptConsumption],
    *,
    trust: ManagedNativeReceiptTrust,
    consumption_trust: ManagedConsumptionAttestationTrust,
) -> None:
    consumption_rows = _linked_consumptions(row, consumptions)
    if len(consumption_rows) != 1:
        raise ReceiptValidationError("native receipt lacks exact consumption evidence")
    consumption = consumption_rows[0]
    if (
        consumption.receipt_hash != receipt.receipt_hash
        or consumption.audit_event_hash != receipt.audit_event_hash
    ):
        raise ReceiptValidationError("native consumption scalar binding mismatch")
    artifact = consumption.attestation_artifact
    artifact_hash = consumption.attestation_artifact_hash
    algorithm = consumption.attestation_signature_algorithm
    key_id = consumption.attestation_signing_key_id
    signature = consumption.attestation_signature
    if (
        not isinstance(artifact, dict)
        or not isinstance(artifact_hash, str)
        or not isinstance(algorithm, str)
        or not isinstance(key_id, str)
        or not isinstance(signature, str)
    ):
        raise ReceiptValidationError("native receipt lacks signed consumption attestation")
    context = NativeReceiptContext(
        org_id=row.org_id,
        execution_boundary=row.execution_boundary,
        actor=row.actor,
        action=row.proposed_action,
        policy_bundle_id=row.policy_bundle_id,
        policy_hash=row.policy_hash,
        audit_hash=row.audit_event_hash,
        args=None,
        validator_role=receipt.validator_role,
        authority=receipt.authority,
    )
    expected = _consumption_attestation_artifact(
        row=row,
        receipt=receipt,
        context=context,
        consumed_at=_as_utc(consumption.consumed_at),
        attestor_algorithm=algorithm,
        attestor_key_id=key_id,
    )
    if artifact != expected:
        raise ReceiptValidationError("native consumption attestation binding mismatch")
    consumption_trust.verify(
        artifact,
        artifact_hash=artifact_hash,
        algorithm=algorithm,
        key_id=key_id,
        signature=signature,
    )
    _require_distinct_attestor_key_material(
        receipt=receipt,
        issuer_verifier=trust.verifiers.get(receipt.signing_key_id),
        attestor_key_id=key_id,
        attestor_verifier=consumption_trust.verifiers.get(key_id),
    )


def _linked_consumptions(
    row: NativeDecisionReceiptRow,
    consumptions: list[NativeReceiptConsumption],
) -> list[NativeReceiptConsumption]:
    return [
        consumption
        for consumption in consumptions
        if consumption.org_id == row.org_id and consumption.native_receipt_id == row.id
    ]
