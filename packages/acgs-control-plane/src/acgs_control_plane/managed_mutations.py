"""SQL-owned governed mutation unit of work.

This module is intentionally route-inaccessible.  It gives future management
mutations one transaction boundary that persists the native DecisionReceipt
projection, burns single-use receipt consumption, runs the operation-specific
SQL mutation, emits a governed event, and queues an outbox row atomically.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

import sqlalchemy as sa
from gove_zone.decision import Decision, sha256_json
from gove_zone.errors import ConsumptionLedgerError, ReceiptAlreadyUsedError, ReceiptValidationError
from gove_zone.executor import execute_with_receipt
from gove_zone.receipt import DecisionReceipt, safe_result_hash
from gove_zone.revocation import RevocationList
from gove_zone.signing import ReceiptSigner
from gove_zone.trust import RECEIPT_V2
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from acgs_control_plane.models import (
    AgentRecord,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedGovernanceEventHead,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    new_id,
    utcnow,
)
from acgs_control_plane.trust import SqlReceiptTrustRegistry

_GENESIS_HASH = "0" * 64
ASSURANCE_CLASS_NATIVE = "native"
CONTROL_PLANE_AGENT_CREATE_ACTION = "control-plane.agent.create"
_BOUNDARY_SCHEMA = "acgs-control-plane:managed-mutation-uow/v1"


@dataclass(frozen=True)
class ManagedMutationContext:
    """Authenticated execution context bound outside the agent-controlled body."""

    org_id: str
    project_id: str
    environment_id: str
    actor: str
    action: str
    execution_boundary: str
    policy_bundle_id: str
    policy_hash: str
    validator_role: str
    authority: str
    expected_audit_hash: str | None = None


class ReceiptArtifactSealer(Protocol):
    """Provider boundary for sealing receipt artifacts before durable persistence."""

    def seal(self, plaintext: bytes, *, associated_data: bytes) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class AesGcmReceiptArtifactSealer:
    """Local AES-GCM sealer provider used by tests and local deployments."""

    key_id: str
    key: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.key_id:
            raise ValueError("receipt artifact sealer key_id is required")
        if len(self.key) != 32:
            raise ValueError("AES-GCM receipt artifact sealer requires a 32-byte key")

    def seal(self, plaintext: bytes, *, associated_data: bytes) -> Mapping[str, Any]:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = os.urandom(12)
        ciphertext = AESGCM(self.key).encrypt(nonce, plaintext, associated_data)
        return {
            "schema": "managed-receipt-artifact-seal/v1",
            "algorithm": "AES-256-GCM",
            "key_id": self.key_id,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
            "associated_data_sha256": hashlib.sha256(associated_data).hexdigest(),
        }

    def unseal(self, envelope: Mapping[str, Any], *, associated_data: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        expected_keys = {
            "schema",
            "algorithm",
            "key_id",
            "nonce",
            "ciphertext",
            "plaintext_sha256",
            "associated_data_sha256",
        }
        if set(envelope) != expected_keys:
            raise ValueError("receipt artifact envelope has unexpected metadata")
        if envelope.get("schema") != "managed-receipt-artifact-seal/v1":
            raise ValueError("unsupported receipt artifact sealing schema")
        if envelope.get("algorithm") != "AES-256-GCM":
            raise ValueError("unsupported receipt artifact sealing algorithm")
        if envelope.get("key_id") != self.key_id:
            raise ValueError("receipt artifact sealing key mismatch")
        expected_aad_digest = hashlib.sha256(associated_data).hexdigest()
        if envelope.get("associated_data_sha256") != expected_aad_digest:
            raise ValueError("receipt artifact associated data digest mismatch")
        nonce = _decode_canonical_base64(envelope["nonce"], field_name="nonce")
        if len(nonce) != 12:
            raise ValueError("receipt artifact nonce must be 12 bytes")
        ciphertext = _decode_canonical_base64(envelope["ciphertext"], field_name="ciphertext")
        if len(ciphertext) < 16:
            raise ValueError("receipt artifact ciphertext is shorter than the authentication tag")
        try:
            plaintext = AESGCM(self.key).decrypt(nonce, ciphertext, associated_data)
        except Exception as exc:
            raise ValueError("receipt artifact authentication failed") from exc
        if hashlib.sha256(plaintext).hexdigest() != envelope.get("plaintext_sha256"):
            raise ValueError("receipt artifact digest mismatch")
        return plaintext


@dataclass(frozen=True)
class ManagedMutationResult:
    """Committed row identifiers for one governed SQL mutation."""

    receipt_row_id: str
    consumption_row_id: str
    event_row_id: str
    outbox_row_id: str
    event_hash: str
    result_hash: str
    result: Any


def managed_mutation_execution_boundary(
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    action: str,
) -> str:
    """Return the server-owned execution boundary for a managed mutation."""

    scope_hash = sha256_json(
        {
            "schema": "managed-mutation-boundary/v1",
            "org_id": org_id,
            "project_id": project_id,
            "environment_id": environment_id,
            "action": action,
        }
    )
    return f"{_BOUNDARY_SCHEMA}:{scope_hash}"


class ManagedMutationUnitOfWork:
    """Execute one governed SQL mutation through the canonical receipt gate."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
        receipt_sealer: ReceiptArtifactSealer | None = None,
        require_signature: bool = True,
        require_expiry: bool = True,
        revoked_keys: RevocationList | None = None,
    ) -> None:
        if not require_signature:
            raise ValueError(
                "managed mutation UoW is signed-only; unsigned dev posture is disabled"
            )
        if not require_expiry:
            raise ValueError(
                "managed mutation UoW requires bounded expiry; unbounded posture is disabled"
            )
        if receipt_sealer is None:
            raise ValueError("managed mutation UoW requires a receipt artifact sealer")
        self._session_factory = session_factory
        if verifier is not None:
            raise ValueError("managed mutation UoW v2 uses SQL trust registry, not verifier maps")
        self._verifier = verifier
        self._receipt_sealer = receipt_sealer
        self._require_signature = require_signature
        self._require_expiry = require_expiry
        self._revoked_keys = revoked_keys

    def execute(
        self,
        *,
        context: ManagedMutationContext,
        receipt: DecisionReceipt | None,
        args: Mapping[str, Any],
    ) -> ManagedMutationResult:
        canonical_boundary = _validated_execution_boundary(context)
        if receipt is None:
            raise ReceiptValidationError("managed mutation requires a DecisionReceipt")
        assurance_class = self._assurance_class(receipt)
        execution_args = _validated_operation_args(context.action, args)
        self._prevalidate_native_allow_receipt(
            context=context,
            receipt=receipt,
            execution_args=execution_args,
            execution_boundary=canonical_boundary,
        )
        attempt_id = _reserve_mutation_attempt(
            self._session_factory,
            context=context,
            receipt=receipt,
        )
        try:
            return self._execute_reserved_attempt(
                attempt_id=attempt_id,
                context=context,
                receipt=receipt,
                execution_args=execution_args,
                execution_boundary=canonical_boundary,
                assurance_class=assurance_class,
            )
        except Exception as exc:
            _mark_mutation_attempt_failed(
                self._session_factory,
                attempt_id=attempt_id,
                exc=exc,
            )
            raise

    def _execute_reserved_attempt(
        self,
        *,
        attempt_id: str,
        context: ManagedMutationContext,
        receipt: DecisionReceipt,
        execution_args: Mapping[str, Any],
        execution_boundary: str,
        assurance_class: str,
    ) -> ManagedMutationResult:
        with self._session_factory() as session:
            with session.begin():
                attempt = _locked_in_progress_attempt(session, attempt_id)
                ledger = _SqlReceiptConsumptionLedger(
                    session,
                    context=context,
                    execution_boundary=execution_boundary,
                    assurance_class=assurance_class,
                    receipt_sealer=self._receipt_sealer,
                )

                def protected_effect(**verified_args: Any) -> Any:
                    if verified_args != execution_args:
                        raise ReceiptValidationError(
                            "managed mutation arguments changed before SQL execution"
                        )
                    return _execute_verified_operation(session, context, verified_args)

                result = execute_with_receipt(
                    protected_effect,
                    execution_args,
                    receipt,
                    expected_tenant_id=context.org_id,
                    expected_execution_boundary=execution_boundary,
                    expected_action=context.action,
                    expected_actor=context.actor,
                    expected_audit_hash=context.expected_audit_hash,
                    expected_policy_hash=context.policy_hash,
                    expected_policy_bundle_id=context.policy_bundle_id,
                    expected_project_id=context.project_id,
                    expected_environment_id=context.environment_id,
                    expected_validator_role=context.validator_role,
                    expected_authority=context.authority,
                    verifier=None,
                    require_signature=self._require_signature,
                    require_expiry=self._require_expiry,
                    revoked_keys=self._revoked_keys,
                    trust_registry=SqlReceiptTrustRegistry(session, lock_rows=True),
                    consumption_ledger=ledger,
                )

                result_hash = safe_result_hash(result)
                receipt_row = ledger.receipt_row
                event = _append_governance_event(
                    session,
                    context=context,
                    receipt_row=receipt_row,
                    receipt=receipt,
                    result_hash=result_hash,
                    execution_boundary=execution_boundary,
                    assurance_class=assurance_class,
                )
                outbox = _enqueue_outbox(
                    session,
                    context=context,
                    receipt_row=receipt_row,
                    event=event,
                    result_hash=result_hash,
                    assurance_class=assurance_class,
                )
                attempt.status = "succeeded"
                attempt.updated_at = utcnow()
                session.flush()
                return ManagedMutationResult(
                    receipt_row_id=receipt_row.id,
                    consumption_row_id=ledger.consumption_id,
                    event_row_id=event.id,
                    outbox_row_id=outbox.id,
                    event_hash=event.event_hash,
                    result_hash=result_hash,
                    result=result,
                )

    def _assurance_class(self, receipt: DecisionReceipt | None) -> str:
        if receipt is None:
            raise ReceiptValidationError("managed mutation requires a DecisionReceipt")
        if (
            receipt.receipt_schema_version == RECEIPT_V2
            and receipt.signature_algorithm != "none"
            and receipt.signing_key_id
        ):
            return ASSURANCE_CLASS_NATIVE
        raise ReceiptValidationError(
            "managed mutation native assurance requires a signed receipt-v2 and SQL trust"
        )

    def _prevalidate_native_allow_receipt(
        self,
        *,
        context: ManagedMutationContext,
        receipt: DecisionReceipt,
        execution_args: Mapping[str, Any],
        execution_boundary: str,
    ) -> None:
        if receipt.decision != Decision.ALLOW.value:
            raise ReceiptValidationError("managed mutation requires an ALLOW receipt")
        if receipt.receipt_schema_version != RECEIPT_V2:
            raise ReceiptValidationError("managed mutation canonical path requires receipt-v2")
        if (
            receipt.project_id != context.project_id
            or receipt.environment_id != context.environment_id
        ):
            raise ReceiptValidationError("managed mutation receipt scope does not match context")
        if receipt.receipt_hash != receipt.compute_hash():
            raise ReceiptValidationError("managed mutation receipt hash mismatch")
        if receipt.argument_hash != sha256_json(dict(execution_args)):
            raise ReceiptValidationError("managed mutation receipt arguments do not match")
        if receipt.tenant_id != context.org_id:
            raise ReceiptValidationError("managed mutation receipt tenant does not match context")
        if receipt.execution_boundary != execution_boundary:
            raise ReceiptValidationError("managed mutation receipt boundary does not match context")
        if receipt.proposed_action != context.action:
            raise ReceiptValidationError("managed mutation receipt action does not match context")
        if receipt.actor != context.actor:
            raise ReceiptValidationError("managed mutation receipt actor does not match context")
        if receipt.policy_hash != context.policy_hash:
            raise ReceiptValidationError("managed mutation receipt policy hash does not match")
        if receipt.policy_bundle_id != context.policy_bundle_id:
            raise ReceiptValidationError("managed mutation receipt policy bundle does not match")
        if (
            receipt.validator_role != context.validator_role
            or receipt.authority != context.authority
        ):
            raise ReceiptValidationError("managed mutation receipt authority does not match")
        if (
            context.expected_audit_hash is not None
            and receipt.audit_event_hash != context.expected_audit_hash
        ):
            raise ReceiptValidationError("managed mutation receipt audit hash does not match")
        if self._revoked_keys is not None and self._revoked_keys.is_revoked(receipt.signing_key_id):
            raise ReceiptValidationError("managed mutation signing key revoked")
        if not receipt.expires_at:
            raise ReceiptValidationError("managed mutation receipt-v2 requires expiry")
        with self._session_factory() as session:
            with session.begin():
                receipt.verify(
                    expected_tenant_id=context.org_id,
                    expected_execution_boundary=execution_boundary,
                    expected_action=context.action,
                    expected_actor=context.actor,
                    expected_audit_hash=context.expected_audit_hash,
                    expected_args=dict(execution_args),
                    expected_policy_hash=context.policy_hash,
                    expected_policy_bundle_id=context.policy_bundle_id,
                    expected_project_id=context.project_id,
                    expected_environment_id=context.environment_id,
                    expected_validator_role=context.validator_role,
                    expected_authority=context.authority,
                    verifier=None,
                    require_signature=self._require_signature,
                    require_expiry=self._require_expiry,
                    revoked_keys=self._revoked_keys,
                    trust_registry=SqlReceiptTrustRegistry(session),
                )


def _reserve_mutation_attempt(
    session_factory: sessionmaker[Session],
    *,
    context: ManagedMutationContext,
    receipt: DecisionReceipt,
) -> str:
    try:
        with session_factory() as session:
            with session.begin():
                existing = _existing_mutation_attempt(session, context=context, receipt=receipt)
                if existing is not None:
                    raise ReceiptAlreadyUsedError(
                        receipt.audit_event_hash,
                        "managed-mutation-attempt",
                    )

                attempt = ManagedMutationAttempt(
                    id=new_id(),
                    org_id=context.org_id,
                    project_id=context.project_id,
                    environment_id=context.environment_id,
                    receipt_hash=receipt.receipt_hash,
                    audit_event_hash=receipt.audit_event_hash,
                    action=receipt.proposed_action,
                    actor_hash=sha256_json(receipt.actor),
                    argument_hash=receipt.argument_hash,
                    status="in_progress",
                    failure_class_hash=None,
                    failure_digest=None,
                    created_at=utcnow(),
                    updated_at=utcnow(),
                )
                session.add(attempt)
                session.flush()
                return attempt.id
    except IntegrityError as exc:
        if _mutation_attempt_exists(session_factory, context=context, receipt=receipt):
            raise ReceiptAlreadyUsedError(
                receipt.audit_event_hash,
                "managed-mutation-attempt",
            ) from exc
        raise


def _existing_mutation_attempt(
    session: Session,
    *,
    context: ManagedMutationContext,
    receipt: DecisionReceipt,
) -> ManagedMutationAttempt | None:
    return session.scalars(
        sa.select(ManagedMutationAttempt)
        .where(
            ManagedMutationAttempt.org_id == context.org_id,
            sa.or_(
                ManagedMutationAttempt.receipt_hash == receipt.receipt_hash,
                ManagedMutationAttempt.audit_event_hash == receipt.audit_event_hash,
            ),
        )
        .with_for_update()
    ).first()


def _mutation_attempt_exists(
    session_factory: sessionmaker[Session],
    *,
    context: ManagedMutationContext,
    receipt: DecisionReceipt,
) -> bool:
    with session_factory() as session:
        return _existing_mutation_attempt(session, context=context, receipt=receipt) is not None


def _locked_in_progress_attempt(session: Session, attempt_id: str) -> ManagedMutationAttempt:
    attempt = session.get(ManagedMutationAttempt, attempt_id, with_for_update=True)
    if attempt is None or attempt.status != "in_progress":
        raise ReceiptAlreadyUsedError(attempt_id, "managed-mutation-attempt")
    return attempt


def _mark_mutation_attempt_failed(
    session_factory: sessionmaker[Session],
    *,
    attempt_id: str,
    exc: Exception,
) -> None:
    exc_class = f"{type(exc).__module__}.{type(exc).__name__}"
    message_hash = hashlib.sha256(str(exc).encode("utf-8", "replace")).hexdigest()
    now = utcnow()
    with session_factory() as session:
        with session.begin():
            attempt = session.get(ManagedMutationAttempt, attempt_id, with_for_update=True)
            if attempt is None or attempt.status != "in_progress":
                return
            attempt.status = "failed"
            attempt.failure_class_hash = sha256_json(exc_class)
            attempt.failure_digest = sha256_json(
                {
                    "class_hash": attempt.failure_class_hash,
                    "message_hash": message_hash,
                }
            )
            attempt.updated_at = now


class _SqlReceiptConsumptionLedger:
    """ReceiptConsumptionLedger-compatible adapter backed by the caller transaction."""

    def __init__(
        self,
        session: Session,
        *,
        context: ManagedMutationContext,
        execution_boundary: str,
        assurance_class: str,
        receipt_sealer: ReceiptArtifactSealer,
    ) -> None:
        self._session = session
        self._context = context
        self._execution_boundary = execution_boundary
        self._assurance_class = assurance_class
        self._receipt_sealer = receipt_sealer
        self._receipt_row: ManagedDecisionReceipt | None = None
        self.consumption_id = ""

    @property
    def receipt_row(self) -> ManagedDecisionReceipt:
        if self._receipt_row is None:
            raise ConsumptionLedgerError("receipt was not consumed before managed mutation event")
        return self._receipt_row

    def consume(self, receipt: DecisionReceipt) -> dict[str, Any]:
        receipt_row = _persist_receipt_projection(
            self._session,
            context=self._context,
            receipt=receipt,
            execution_boundary=self._execution_boundary,
            assurance_class=self._assurance_class,
            receipt_sealer=self._receipt_sealer,
        )
        self._receipt_row = receipt_row

        existing = self._session.scalars(
            sa.select(ManagedReceiptConsumption)
            .where(
                ManagedReceiptConsumption.org_id == self._context.org_id,
                ManagedReceiptConsumption.project_id == self._context.project_id,
                ManagedReceiptConsumption.environment_id == self._context.environment_id,
                ManagedReceiptConsumption.audit_event_hash == receipt.audit_event_hash,
            )
            .with_for_update()
        ).first()
        if existing is not None:
            raise ReceiptAlreadyUsedError(receipt.audit_event_hash, "managed-sql-ledger")

        consumption = ManagedReceiptConsumption(
            id=new_id(),
            org_id=self._context.org_id,
            project_id=self._context.project_id,
            environment_id=self._context.environment_id,
            managed_receipt_id=receipt_row.id,
            receipt_hash=receipt.receipt_hash,
            audit_event_hash=receipt.audit_event_hash,
            consumed_at=utcnow(),
        )
        self._session.add(consumption)
        try:
            self._session.flush()
        except IntegrityError as exc:
            raise ReceiptAlreadyUsedError(receipt.audit_event_hash, "managed-sql-ledger") from exc
        self.consumption_id = consumption.id
        return {
            "consumed_key": receipt.audit_event_hash,
            "receipt_hash": receipt.receipt_hash,
            "tenant_id": receipt.tenant_id,
            "actor": receipt.actor,
            "proposed_action": receipt.proposed_action,
        }


def _persist_receipt_projection(
    session: Session,
    *,
    context: ManagedMutationContext,
    receipt: DecisionReceipt,
    execution_boundary: str,
    assurance_class: str,
    receipt_sealer: ReceiptArtifactSealer,
) -> ManagedDecisionReceipt:
    existing_for_environment = session.scalars(
        sa.select(ManagedDecisionReceipt)
        .where(
            ManagedDecisionReceipt.org_id == context.org_id,
            ManagedDecisionReceipt.project_id == context.project_id,
            ManagedDecisionReceipt.environment_id == context.environment_id,
            ManagedDecisionReceipt.audit_event_hash == receipt.audit_event_hash,
        )
        .with_for_update()
    ).first()
    if existing_for_environment is not None:
        _assert_receipt_projection_matches(existing_for_environment, receipt)
        return existing_for_environment

    existing_for_org = session.scalars(
        sa.select(ManagedDecisionReceipt)
        .where(
            ManagedDecisionReceipt.org_id == context.org_id,
            sa.or_(
                ManagedDecisionReceipt.receipt_hash == receipt.receipt_hash,
                ManagedDecisionReceipt.audit_event_hash == receipt.audit_event_hash,
            ),
        )
        .with_for_update()
    ).first()
    if existing_for_org is not None:
        raise ReceiptAlreadyUsedError(receipt.audit_event_hash, "managed-sql-ledger")

    receipt_payload = receipt.to_dict()
    sealed_receipt = receipt_sealer.seal(
        _canonical_json_bytes(receipt_payload),
        associated_data=managed_receipt_artifact_aad(
            org_id=context.org_id,
            project_id=context.project_id,
            environment_id=context.environment_id,
            receipt_hash=receipt.receipt_hash,
        ),
    )
    projection = {
        "schema": "managed-mutation-uow/v1",
        "assurance_class": assurance_class,
        "source_system": "gove-zone",
        "sealed_receipt": dict(sealed_receipt),
        "receipt_id_hash": sha256_json(receipt.receipt_id),
        "request_id_hash": sha256_json(receipt.request_id),
        "matched_rules_hash": sha256_json(receipt.matched_rules),
        "constraints_hash": sha256_json(receipt.constraints),
        "approval_chain_hash": sha256_json(receipt.approval_chain_summary),
        "argument_hash": receipt.argument_hash,
        "receipt_schema_version": receipt.receipt_schema_version,
        "project_id": receipt.project_id,
        "environment_id": receipt.environment_id,
        "trust_epoch": receipt.trust_epoch,
    }
    receipt_row = ManagedDecisionReceipt(
        id=new_id(),
        org_id=context.org_id,
        project_id=context.project_id,
        environment_id=context.environment_id,
        receipt_id=receipt.receipt_id,
        receipt_hash=receipt.receipt_hash,
        audit_event_hash=receipt.audit_event_hash,
        decision=receipt.decision,
        actor=receipt.actor,
        proposed_action=receipt.proposed_action,
        execution_boundary=execution_boundary,
        policy_bundle_id=receipt.policy_bundle_id,
        policy_version=receipt.policy_version,
        policy_hash=receipt.policy_hash,
        argument_hash=receipt.argument_hash,
        signing_key_id=receipt.signing_key_id,
        signature_algorithm=receipt.signature_algorithm,
        receipt_schema_version=receipt.receipt_schema_version,
        trust_epoch=receipt.trust_epoch,
        assurance_class=assurance_class,
        source_system="gove-zone",
        issued_at=_parse_receipt_timestamp(receipt.timestamp, field_name="timestamp"),
        expires_at=_parse_receipt_timestamp(receipt.expires_at, field_name="expires_at"),
        projection=projection,
        created_at=utcnow(),
    )
    session.add(receipt_row)
    session.flush()
    return receipt_row


def _assert_receipt_projection_matches(
    receipt_row: ManagedDecisionReceipt,
    receipt: DecisionReceipt,
) -> None:
    if (
        receipt_row.receipt_id != receipt.receipt_id
        or receipt_row.receipt_hash != receipt.receipt_hash
        or receipt_row.decision != receipt.decision
        or receipt_row.argument_hash != receipt.argument_hash
    ):
        raise ConsumptionLedgerError("managed receipt projection conflicts with presented receipt")


def _append_governance_event(
    session: Session,
    *,
    context: ManagedMutationContext,
    receipt_row: ManagedDecisionReceipt,
    receipt: DecisionReceipt,
    result_hash: str,
    execution_boundary: str,
    assurance_class: str,
) -> ManagedGovernanceEvent:
    head = session.get(
        ManagedGovernanceEventHead,
        (context.org_id, context.project_id, context.environment_id),
        with_for_update=True,
    )
    now = utcnow()
    if head is None:
        head = ManagedGovernanceEventHead(
            org_id=context.org_id,
            project_id=context.project_id,
            environment_id=context.environment_id,
            last_sequence=0,
            last_event_hash=_GENESIS_HASH,
            updated_at=now,
        )
        session.add(head)
        session.flush()

    sequence = head.last_sequence + 1
    previous_hash = head.last_event_hash
    payload = {
        "schema": "managed-mutation-uow/v1",
        "assurance_class": assurance_class,
        "source_system": "gove-zone",
        "receipt_hash": receipt.receipt_hash,
        "audit_event_hash": receipt.audit_event_hash,
        "argument_hash": receipt.argument_hash,
        "result_hash": result_hash,
        "decision": receipt.decision,
        "actor_hash": sha256_json(receipt.actor),
        "action": receipt.proposed_action,
        "policy_bundle_id": receipt.policy_bundle_id,
        "policy_hash": receipt.policy_hash,
        "receipt_schema_version": receipt.receipt_schema_version,
        "trust_epoch": receipt.trust_epoch,
        "scope": {
            "org_id": context.org_id,
            "project_id": context.project_id,
            "environment_id": context.environment_id,
            "execution_boundary": execution_boundary,
        },
    }
    payload_digest = sha256_json(payload)
    event_hash = sha256_json(
        {
            "schema": "managed-mutation-event-chain/v1",
            "sequence": sequence,
            "previous_hash": previous_hash,
            "payload_digest": payload_digest,
        }
    )
    event = ManagedGovernanceEvent(
        id=new_id(),
        org_id=context.org_id,
        project_id=context.project_id,
        environment_id=context.environment_id,
        managed_receipt_id=receipt_row.id,
        sequence=sequence,
        previous_hash=previous_hash,
        event_hash=event_hash,
        decision=receipt.decision,
        actor=receipt.actor,
        proposed_action=receipt.proposed_action,
        policy_version=receipt.policy_version,
        payload_digest=payload_digest,
        payload=payload,
        created_at=now,
    )
    session.add(event)
    head.last_sequence = sequence
    head.last_event_hash = event_hash
    head.updated_at = now
    session.flush()
    return event


def _enqueue_outbox(
    session: Session,
    *,
    context: ManagedMutationContext,
    receipt_row: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
    result_hash: str,
    assurance_class: str,
) -> ManagedOutboxMessage:
    payload = {
        "schema": "managed-mutation-uow-outbox/v1",
        "event_hash": event.event_hash,
        "payload_digest": event.payload_digest,
        "receipt_hash": receipt_row.receipt_hash,
        "audit_event_hash": receipt_row.audit_event_hash,
        "result_hash": result_hash,
        "assurance_class": assurance_class,
        "source_system": "gove-zone",
    }
    payload_digest = sha256_json(payload)
    outbox = ManagedOutboxMessage(
        id=new_id(),
        org_id=context.org_id,
        project_id=context.project_id,
        environment_id=context.environment_id,
        managed_receipt_id=receipt_row.id,
        managed_event_id=event.id,
        delivery_key=f"managed-mutation-uow/v1:{event.event_hash}",
        payload_digest=payload_digest,
        payload=payload,
        status="pending",
        attempts=0,
        created_at=utcnow(),
        available_at=utcnow(),
        delivered_at=None,
    )
    session.add(outbox)
    session.flush()
    return outbox


def _validated_execution_boundary(context: ManagedMutationContext) -> str:
    canonical_boundary = managed_mutation_execution_boundary(
        org_id=context.org_id,
        project_id=context.project_id,
        environment_id=context.environment_id,
        action=context.action,
    )
    if context.execution_boundary != canonical_boundary:
        raise ReceiptValidationError("managed mutation execution boundary is not canonical")
    return canonical_boundary


def managed_receipt_artifact_aad(
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    receipt_hash: str,
) -> bytes:
    return _canonical_json_bytes(
        {
            "schema": "managed-receipt-artifact-aad/v1",
            "org_id": org_id,
            "project_id": project_id,
            "environment_id": environment_id,
            "receipt_hash": receipt_hash,
        }
    )


def _validated_operation_args(action: str, args: Mapping[str, Any]) -> dict[str, Any]:
    if action != CONTROL_PLANE_AGENT_CREATE_ACTION:
        raise ReceiptValidationError(f"unsupported managed mutation action: {action}")
    allowed_fields = {"name"}
    actual_fields = set(args)
    if actual_fields != allowed_fields:
        raise ReceiptValidationError("agent.create requires exactly the name argument")
    name = args.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ReceiptValidationError("agent.create name must be a non-empty string")
    return {"name": name}


def _execute_verified_operation(
    session: Session,
    context: ManagedMutationContext,
    verified_args: Mapping[str, Any],
) -> dict[str, str]:
    if context.action != CONTROL_PLANE_AGENT_CREATE_ACTION:
        raise ReceiptValidationError(f"unsupported managed mutation action: {context.action}")
    name = str(verified_args["name"])
    agent = AgentRecord(
        id=new_id(),
        org_id=context.org_id,
        name=name,
        description="",
        trust_tier="managed",
        allowed_tools=[],
        status="active",
    )
    session.add(agent)
    session.flush()
    return {
        "agent_id_hash": sha256_json(agent.id),
        "agent_name_hash": sha256_json(agent.name),
    }


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode_canonical_base64(value: Any, *, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"receipt artifact {field_name} must be base64 text")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError(f"receipt artifact {field_name} is not strict base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"receipt artifact {field_name} is not canonical base64")
    return decoded


def _parse_receipt_timestamp(value: str, *, field_name: str) -> datetime:
    if not value:
        raise ValueError(f"managed mutation receipts require {field_name}")
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
