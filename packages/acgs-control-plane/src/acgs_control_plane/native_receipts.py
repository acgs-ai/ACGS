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

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from gove_zone.decision import DecisionRecord, sha256_json
from gove_zone.errors import (
    ProductionProfileError,
    ReceiptAlreadyUsedError,
    ReceiptValidationError,
)
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.revocation import RevocationList
from gove_zone.signing import ReceiptSigner
from sqlalchemy import select
from sqlalchemy.orm import Session

from acgs_control_plane.models import NativeDecisionReceiptRow, NativeReceiptConsumption

_LEDGER_NAME = "database:native_receipt_consumptions"
NATIVE_ASSURANCE_CLASS = "native"
NATIVE_SOURCE_SYSTEM = "gove-zone"
NATIVE_PROJECTION_SCHEMA = "acgs.native-receipt-projection.v1"


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


def _safe_projection(receipt: DecisionReceipt) -> dict[str, Any]:
    """Return a deterministic projection that cannot retain freeform values.

    This SQL-only foundation accepts native ALLOW receipts with no subject,
    declared goal, constraints, or transformations. The approval summary must
    be exactly the canonical proposer/validator linkage added by
    ``DecisionReceipt.from_record``. Request IDs and matched-rule identifiers
    are retained only as hashes.
    """
    if receipt.decision != "allow":
        raise ReceiptValidationError("native SQL receipt persistence accepts ALLOW only")
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
        if signer is None or signer.algorithm == "none" or not signer.key_id:
            raise ProductionProfileError(
                "managed native receipt issuance requires an explicitly configured signer"
            )
        verifier = self.verifiers.get(signer.key_id)
        if verifier is None:
            raise ProductionProfileError(
                f"managed native receipt signer key {signer.key_id!r} is absent from trust"
            )
        if self.revoked_keys.is_revoked(signer.key_id):
            raise ProductionProfileError(
                f"managed native receipt signer key {signer.key_id!r} is revoked"
            )
        if verifier.algorithm != signer.algorithm or verifier.key_id != signer.key_id:
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
        if not self.verifiers:
            raise ProductionProfileError(
                "managed native receipt verification requires an explicit trust map"
            )
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
        self.trust.verify(receipt, context, now=now)
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


class DatabaseReceiptConsumptionLedger:
    """Duck-typed gove-zone consumption ledger backed by the caller's DB tx."""

    def __init__(
        self,
        session: Session,
        *,
        trust: ManagedNativeReceiptTrust,
        context: NativeReceiptContext,
    ) -> None:
        self.session = session
        self.trust = trust
        self.context = context

    def consume(self, receipt: DecisionReceipt) -> dict[str, Any]:
        projection = _safe_projection(receipt)
        self.trust.verify(receipt, self.context)
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

        consumption = NativeReceiptConsumption(
            org_id=self.context.org_id,
            native_receipt_id=persisted.id,
            receipt_hash=receipt.receipt_hash,
            audit_event_hash=receipt.audit_event_hash,
        )
        self.session.add(consumption)
        self.session.flush()
        return {
            "org_id": self.context.org_id,
            "receipt_id": receipt.receipt_id,
            "receipt_hash": receipt.receipt_hash,
            "audit_event_hash": receipt.audit_event_hash,
        }
