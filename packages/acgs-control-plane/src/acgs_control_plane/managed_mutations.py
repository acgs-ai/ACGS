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
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

import sqlalchemy as sa
from gove_zone.decision import Decision, sha256_json
from gove_zone.errors import (
    ConsumptionLedgerError,
    ReceiptAlreadyUsedError,
    ReceiptRejectionReason,
    ReceiptValidationError,
)
from gove_zone.executor import execute_with_receipt
from gove_zone.receipt import (
    DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS,
    DecisionReceipt,
    safe_result_hash,
)
from gove_zone.revocation import RevocationList
from gove_zone.signing import ReceiptSigner
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, RECEIPT_V2, ReceiptTrustRegistry
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
CONTROL_PLANE_APPROVAL_VOTE_ACTION = "control-plane.approval.vote"
CONTROL_PLANE_POLICY_PUBLISH_ACTION = "control-plane.policy.publish"
CONTROL_PLANE_POLICY_ACTIVATE_ACTION = "control-plane.policy.activate"
CONTROL_PLANE_RUNTIME_BOOTSTRAP_ISSUE_ACTION = "control-plane.runtime-bootstrap.issue"
CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION = "control-plane.runtime-identity.enroll"
CONTROL_PLANE_RUNTIME_IDENTITY_RENEW_ACTION = "control-plane.runtime-identity.renew"
CONTROL_PLANE_RUNTIME_IDENTITY_REVOKE_ACTION = "control-plane.runtime-identity.revoke"
TENANT_BOOTSTRAP_ACTION = "tenant.bootstrap"
TENANT_BOOTSTRAP_EXECUTION_BOUNDARY = "control-plane:tenant.bootstrap/v1"
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
    expected_policy_head_generation: int | None = None


class ReceiptArtifactSealer(Protocol):
    """Provider boundary for sealing receipt artifacts before durable persistence."""

    def seal(self, plaintext: bytes, *, associated_data: bytes) -> Mapping[str, Any]: ...

    def unseal(self, envelope: Mapping[str, Any], *, associated_data: bytes) -> bytes: ...


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


@dataclass(frozen=True)
class ManagedMutationReplayResult:
    """Terminal replay returned before a new managed mutation attempt is reserved."""

    result: Any


@dataclass(frozen=True)
class ManagedNonExecutableEvidenceResult:
    """Committed row identifiers for one signed DENY/ESCALATE decision."""

    receipt_row_id: str
    event_row_id: str
    outbox_row_id: str
    event_hash: str
    result_hash: str
    decision: str


class ManagedReplayArtifactValidationError(RuntimeError):
    """Stored managed replay artifacts failed integrity validation."""


@dataclass(frozen=True)
class ManagedReplayArtifacts:
    """Validated durable artifacts for a managed replay."""

    sealed_receipt: DecisionReceipt
    event: ManagedGovernanceEvent
    outbox: ManagedOutboxMessage


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
        before_execute: Callable[[Session], None] | None = None,
        before_attempt_reservation: Callable[[Session], ManagedMutationReplayResult | None]
        | None = None,
        after_success: Callable[
            [
                Session,
                ManagedDecisionReceipt,
                ManagedGovernanceEvent,
                ManagedOutboxMessage,
                ManagedMutationResult,
            ],
            None,
        ]
        | None = None,
        operation_effect: Callable[[Session, dict[str, Any]], Any] | None = None,
        trust_registry: ReceiptTrustRegistry | None = None,
        before_consume: Callable[[Session], None] | None = None,
        revoked_keys: RevocationList | None = None,
        trust_purpose: str = DECISION_RECEIPT_PURPOSE,
    ) -> ManagedMutationResult | ManagedMutationReplayResult:
        canonical_boundary = _validated_execution_boundary(context)
        if receipt is None:
            raise ReceiptValidationError("managed mutation requires a DecisionReceipt")
        assurance_class = self._assurance_class(receipt)
        execution_args = _validated_operation_args(context.action, args)
        if context.action != TENANT_BOOTSTRAP_ACTION and _mutation_attempt_exists(
            self._session_factory,
            context=context,
            receipt=receipt,
        ):
            raise ReceiptAlreadyUsedError(receipt.audit_event_hash, "managed-mutation-attempt")
        self._prevalidate_native_receipt(
            context=context,
            receipt=receipt,
            execution_args=execution_args,
            execution_boundary=canonical_boundary,
            allowed_decisions=frozenset({Decision.ALLOW.value}),
            trust_registry=trust_registry,
            revoked_keys=revoked_keys,
            trust_purpose=trust_purpose,
        )
        if context.action == TENANT_BOOTSTRAP_ACTION or before_attempt_reservation is not None:
            attempt_id = ""
        else:
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
                before_execute=before_execute,
                before_attempt_reservation=before_attempt_reservation,
                after_success=after_success,
                operation_effect=operation_effect,
                trust_registry=trust_registry,
                before_consume=before_consume,
                revoked_keys=revoked_keys,
                trust_purpose=trust_purpose,
            )
        except Exception as exc:
            if attempt_id:
                _mark_mutation_attempt_failed(
                    self._session_factory,
                    attempt_id=attempt_id,
                    exc=exc,
                )
            raise

    def record_non_executable_evidence(
        self,
        *,
        context: ManagedMutationContext,
        receipt: DecisionReceipt | None,
        args: Mapping[str, Any],
        before_record: Callable[[Session], None] | None = None,
        after_record: Callable[
            [
                Session,
                ManagedDecisionReceipt,
                ManagedGovernanceEvent,
                ManagedOutboxMessage,
                ManagedNonExecutableEvidenceResult,
            ],
            None,
        ]
        | None = None,
        trust_registry: ReceiptTrustRegistry | None = None,
        revoked_keys: RevocationList | None = None,
        trust_purpose: str = DECISION_RECEIPT_PURPOSE,
    ) -> ManagedNonExecutableEvidenceResult:
        canonical_boundary = _validated_execution_boundary(context)
        if receipt is None:
            raise ReceiptValidationError("managed mutation requires a DecisionReceipt")
        assurance_class = self._assurance_class(receipt)
        execution_args = _validated_operation_args(context.action, args)
        if _receipt_projection_exists(
            self._session_factory,
            context=context,
            receipt=receipt,
        ):
            raise ReceiptAlreadyUsedError(receipt.audit_event_hash, "managed-receipt-evidence")
        self._prevalidate_native_receipt(
            context=context,
            receipt=receipt,
            execution_args=execution_args,
            execution_boundary=canonical_boundary,
            allowed_decisions=frozenset({Decision.DENY.value, Decision.ESCALATE.value}),
            trust_registry=trust_registry,
            revoked_keys=revoked_keys,
            trust_purpose=trust_purpose,
        )
        with self._session_factory() as session:
            with session.begin():
                if session.bind is not None and session.bind.dialect.name == "postgresql":
                    session.execute(sa.text("SET CONSTRAINTS ALL DEFERRED"))
                if before_record is not None:
                    before_record(session)
                receipt_row = _persist_receipt_projection(
                    session,
                    context=context,
                    receipt=receipt,
                    execution_boundary=canonical_boundary,
                    assurance_class=assurance_class,
                    receipt_sealer=self._receipt_sealer,
                    allow_existing_projection=False,
                )
                result_hash = safe_result_hash(
                    {"status": "non_executable", "decision": receipt.decision}
                )
                event = _append_governance_event(
                    session,
                    context=context,
                    receipt_row=receipt_row,
                    receipt=receipt,
                    result_hash=result_hash,
                    execution_boundary=canonical_boundary,
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
                evidence_result = ManagedNonExecutableEvidenceResult(
                    receipt_row_id=receipt_row.id,
                    event_row_id=event.id,
                    outbox_row_id=outbox.id,
                    event_hash=event.event_hash,
                    result_hash=result_hash,
                    decision=receipt.decision,
                )
                if after_record is not None:
                    after_record(session, receipt_row, event, outbox, evidence_result)
                session.flush()
                return evidence_result

    def _execute_reserved_attempt(
        self,
        *,
        attempt_id: str,
        context: ManagedMutationContext,
        receipt: DecisionReceipt,
        execution_args: Mapping[str, Any],
        execution_boundary: str,
        assurance_class: str,
        before_execute: Callable[[Session], None] | None,
        before_attempt_reservation: Callable[[Session], ManagedMutationReplayResult | None] | None,
        after_success: Callable[
            [
                Session,
                ManagedDecisionReceipt,
                ManagedGovernanceEvent,
                ManagedOutboxMessage,
                ManagedMutationResult,
            ],
            None,
        ]
        | None,
        operation_effect: Callable[[Session, dict[str, Any]], Any] | None,
        trust_registry: ReceiptTrustRegistry | None,
        before_consume: Callable[[Session], None] | None,
        revoked_keys: RevocationList | None,
        trust_purpose: str,
    ) -> ManagedMutationResult | ManagedMutationReplayResult:
        deferred_exception: Exception | None = None
        with self._session_factory() as session:
            with session.begin():
                if session.bind is not None and session.bind.dialect.name == "postgresql":
                    session.execute(sa.text("SET CONSTRAINTS ALL DEFERRED"))
                if before_attempt_reservation is not None:
                    replay = before_attempt_reservation(session)
                    if replay is not None:
                        return replay
                attempt: ManagedMutationAttempt | None = None
                if attempt_id:
                    attempt = _locked_in_progress_attempt(session, attempt_id)
                elif context.action != TENANT_BOOTSTRAP_ACTION:
                    attempt = _reserve_mutation_attempt_row(
                        session,
                        context=context,
                        receipt=receipt,
                    )

                def run_attempt_body() -> ManagedMutationResult:
                    nonlocal attempt
                    if before_execute is not None:
                        before_execute(session)
                    ledger = _SqlReceiptConsumptionLedger(
                        session,
                        context=context,
                        execution_boundary=execution_boundary,
                        assurance_class=assurance_class,
                        receipt_sealer=self._receipt_sealer,
                        before_persist_receipt=before_consume,
                    )

                    def protected_effect(**verified_args: Any) -> Any:
                        if verified_args != execution_args:
                            raise ReceiptValidationError(
                                "managed mutation arguments changed before SQL execution"
                            )
                        if operation_effect is not None:
                            return operation_effect(session, dict(verified_args))
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
                        revoked_keys=revoked_keys
                        if revoked_keys is not None
                        else self._revoked_keys,
                        trust_registry=trust_registry
                        if trust_registry is not None
                        else SqlReceiptTrustRegistry(session, lock_rows=True),
                        trust_purpose=trust_purpose,
                        max_clock_skew_seconds=DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS,
                        consumption_ledger=ledger,
                    )

                    result_hash = safe_result_hash(result)
                    receipt_row = ledger.receipt_row
                    if attempt is None:
                        attempt = _reserve_mutation_attempt_row(
                            session,
                            context=context,
                            receipt=receipt,
                        )
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
                    mutation_result = ManagedMutationResult(
                        receipt_row_id=receipt_row.id,
                        consumption_row_id=ledger.consumption_id,
                        event_row_id=event.id,
                        outbox_row_id=outbox.id,
                        event_hash=event.event_hash,
                        result_hash=result_hash,
                        result=result,
                    )
                    if after_success is not None:
                        after_success(session, receipt_row, event, outbox, mutation_result)
                    session.flush()
                    return mutation_result

                if before_attempt_reservation is not None and attempt is not None:
                    try:
                        with session.begin_nested():
                            return run_attempt_body()
                    except Exception as exc:
                        _mark_mutation_attempt_row_failed(attempt, exc)
                        session.flush()
                        deferred_exception = exc
                else:
                    return run_attempt_body()
        if deferred_exception is not None:
            raise deferred_exception
        raise RuntimeError("managed mutation attempt exited without result")

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

    def _prevalidate_native_receipt(
        self,
        *,
        context: ManagedMutationContext,
        receipt: DecisionReceipt,
        execution_args: Mapping[str, Any],
        execution_boundary: str,
        allowed_decisions: frozenset[str],
        trust_registry: ReceiptTrustRegistry | None,
        revoked_keys: RevocationList | None,
        trust_purpose: str,
    ) -> None:
        if receipt.decision not in allowed_decisions:
            raise ReceiptValidationError(
                "managed mutation receipt decision is not allowed for this path",
                reason_code=ReceiptRejectionReason.DENIED_RECEIPT,
            )
        if receipt.receipt_schema_version != RECEIPT_V2:
            raise ReceiptValidationError(
                "managed mutation canonical path requires receipt-v2",
                reason_code=ReceiptRejectionReason.RECEIPT_SCHEMA_MISMATCH,
            )
        if receipt.project_id != context.project_id:
            raise ReceiptValidationError(
                "managed mutation receipt project does not match context",
                reason_code=ReceiptRejectionReason.SCOPED_TRUST_MISMATCH,
            )
        if receipt.environment_id != context.environment_id:
            raise ReceiptValidationError(
                "managed mutation receipt environment does not match context",
                reason_code=ReceiptRejectionReason.SCOPED_TRUST_MISMATCH,
            )
        if receipt.receipt_hash != receipt.compute_hash():
            raise ReceiptValidationError(
                "managed mutation receipt hash mismatch",
                reason_code=ReceiptRejectionReason.RECEIPT_HASH_MISMATCH,
            )
        if receipt.argument_hash != sha256_json(dict(execution_args)):
            raise ReceiptValidationError(
                "managed mutation receipt arguments do not match",
                reason_code=ReceiptRejectionReason.ARGUMENT_MISMATCH,
            )
        if receipt.tenant_id != context.org_id:
            raise ReceiptValidationError(
                "managed mutation receipt tenant does not match context",
                reason_code=ReceiptRejectionReason.TENANT_MISMATCH,
            )
        if receipt.execution_boundary != execution_boundary:
            raise ReceiptValidationError(
                "managed mutation receipt boundary does not match context",
                reason_code=ReceiptRejectionReason.EXECUTION_BOUNDARY_MISMATCH,
            )
        if receipt.proposed_action != context.action:
            raise ReceiptValidationError(
                "managed mutation receipt action does not match context",
                reason_code=ReceiptRejectionReason.ACTION_MISMATCH,
            )
        if receipt.actor != context.actor:
            raise ReceiptValidationError(
                "managed mutation receipt actor does not match context",
                reason_code=ReceiptRejectionReason.ACTOR_MISMATCH,
            )
        if receipt.policy_hash != context.policy_hash:
            raise ReceiptValidationError(
                "managed mutation receipt policy hash does not match",
                reason_code=ReceiptRejectionReason.POLICY_HASH_MISMATCH,
            )
        if receipt.policy_bundle_id != context.policy_bundle_id:
            raise ReceiptValidationError(
                "managed mutation receipt policy bundle does not match",
                reason_code=ReceiptRejectionReason.POLICY_BUNDLE_MISMATCH,
            )
        if (
            receipt.validator_role != context.validator_role
            or receipt.authority != context.authority
        ):
            reason = (
                ReceiptRejectionReason.VALIDATOR_ROLE_MISMATCH
                if receipt.validator_role != context.validator_role
                else ReceiptRejectionReason.AUTHORITY_MISMATCH
            )
            raise ReceiptValidationError(
                "managed mutation receipt authority does not match",
                reason_code=reason,
            )
        if (
            context.expected_audit_hash is not None
            and receipt.audit_event_hash != context.expected_audit_hash
        ):
            raise ReceiptValidationError(
                "managed mutation receipt audit hash does not match",
                reason_code=ReceiptRejectionReason.AUDIT_HASH_MISMATCH,
            )
        effective_revoked_keys = revoked_keys if revoked_keys is not None else self._revoked_keys
        if effective_revoked_keys is not None and effective_revoked_keys.is_revoked(
            receipt.signing_key_id
        ):
            raise ReceiptValidationError(
                "managed mutation signing key revoked",
                reason_code=ReceiptRejectionReason.SIGNING_KEY_REVOKED,
            )
        if not receipt.expires_at:
            raise ReceiptValidationError(
                "managed mutation receipt-v2 requires expiry",
                reason_code=ReceiptRejectionReason.EXPIRY_REQUIRED,
            )
        terminal_non_executable_reasons = {
            Decision.DENY.value: ReceiptRejectionReason.DENIED_RECEIPT,
            Decision.ESCALATE.value: ReceiptRejectionReason.ESCALATED_RECEIPT,
        }

        def verify_bindings(*, trust_registry: ReceiptTrustRegistry | None) -> None:
            try:
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
                    revoked_keys=effective_revoked_keys,
                    trust_registry=trust_registry,
                    trust_purpose=trust_purpose,
                    max_clock_skew_seconds=DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS,
                )
            except ReceiptValidationError as exc:
                if (
                    receipt.decision in terminal_non_executable_reasons
                    and exc.reason_code == terminal_non_executable_reasons[receipt.decision]
                ):
                    return
                raise

        if context.action == TENANT_BOOTSTRAP_ACTION:
            verify_bindings(trust_registry=trust_registry)
            return
        with self._session_factory() as session:
            with session.begin():
                verify_bindings(trust_registry=SqlReceiptTrustRegistry(session))


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


def _reserve_mutation_attempt_row(
    session: Session,
    *,
    context: ManagedMutationContext,
    receipt: DecisionReceipt,
) -> ManagedMutationAttempt:
    existing = _existing_mutation_attempt(session, context=context, receipt=receipt)
    if existing is not None:
        raise ReceiptAlreadyUsedError(receipt.audit_event_hash, "managed-mutation-attempt")

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
    try:
        session.flush()
    except IntegrityError as exc:
        raise ReceiptAlreadyUsedError(
            receipt.audit_event_hash,
            "managed-mutation-attempt",
        ) from exc
    return attempt


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


def _receipt_projection_exists(
    session_factory: sessionmaker[Session],
    *,
    context: ManagedMutationContext,
    receipt: DecisionReceipt,
) -> bool:
    with session_factory() as session:
        return (
            session.scalars(
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
            is not None
        )


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
    with session_factory() as session:
        with session.begin():
            attempt = session.get(ManagedMutationAttempt, attempt_id, with_for_update=True)
            if attempt is None or attempt.status != "in_progress":
                return
            _mark_mutation_attempt_row_failed(attempt, exc)


def _mark_mutation_attempt_row_failed(
    attempt: ManagedMutationAttempt,
    exc: Exception,
) -> None:
    failure_class_hash, failure_digest = _mutation_attempt_failure_hashes(exc)
    attempt.status = "failed"
    attempt.failure_class_hash = failure_class_hash
    attempt.failure_digest = failure_digest
    attempt.updated_at = utcnow()


def _mutation_attempt_failure_hashes(exc: Exception) -> tuple[str, str]:
    exc_class = f"{type(exc).__module__}.{type(exc).__name__}"
    message_hash = hashlib.sha256(str(exc).encode("utf-8", "replace")).hexdigest()
    failure_class_hash = sha256_json(exc_class)
    return (
        failure_class_hash,
        sha256_json(
            {
                "class_hash": failure_class_hash,
                "message_hash": message_hash,
            }
        ),
    )


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
        before_persist_receipt: Callable[[Session], None] | None = None,
    ) -> None:
        self._session = session
        self._context = context
        self._execution_boundary = execution_boundary
        self._assurance_class = assurance_class
        self._receipt_sealer = receipt_sealer
        self._before_persist_receipt = before_persist_receipt
        self._receipt_row: ManagedDecisionReceipt | None = None
        self.consumption_id = ""

    @property
    def receipt_row(self) -> ManagedDecisionReceipt:
        if self._receipt_row is None:
            raise ConsumptionLedgerError("receipt was not consumed before managed mutation event")
        return self._receipt_row

    def consume(self, receipt: DecisionReceipt) -> dict[str, Any]:
        if self._before_persist_receipt is not None:
            self._before_persist_receipt(self._session)
            self._before_persist_receipt = None
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
    allow_existing_projection: bool = True,
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
        if not allow_existing_projection:
            raise ReceiptAlreadyUsedError(receipt.audit_event_hash, "managed-receipt-evidence")
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
        "authority": receipt.authority,
        "validator_role": receipt.validator_role,
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


def validate_managed_replay_artifacts(
    session: Session,
    receipt: ManagedDecisionReceipt | None,
    *,
    expected_action: str,
    expected_actor: str,
    expected_decision: str,
    expected_args: Mapping[str, Any],
    expected_result_hash: str,
    receipt_sealer: ReceiptArtifactSealer,
    trust_purpose: str = DECISION_RECEIPT_PURPOSE,
) -> ManagedReplayArtifacts:
    if receipt is None:
        raise ManagedReplayArtifactValidationError("managed replay receipt is missing")
    expected_decision_normalized = expected_decision.lower()
    if expected_decision_normalized not in {
        Decision.ALLOW.value,
        Decision.DENY.value,
        Decision.ESCALATE.value,
    }:
        raise ManagedReplayArtifactValidationError("managed replay decision is invalid")
    if (
        receipt.proposed_action != expected_action
        or receipt.actor != expected_actor
        or receipt.decision != expected_decision_normalized
        or receipt.argument_hash != sha256_json(dict(expected_args))
        or receipt.projection.get("argument_hash") != receipt.argument_hash
    ):
        raise ManagedReplayArtifactValidationError("managed replay receipt binding is invalid")
    sealed_receipt = _validated_replay_sealed_receipt(
        session,
        receipt,
        expected_action=expected_action,
        expected_actor=expected_actor,
        expected_args=expected_args,
        receipt_sealer=receipt_sealer,
        trust_purpose=trust_purpose,
    )
    event = _validated_replay_event(
        session,
        receipt,
        expected_args=expected_args,
        expected_actor=expected_actor,
        expected_action=expected_action,
        expected_result_hash=expected_result_hash,
    )
    outbox = _validated_replay_outbox(session, receipt, event)
    if expected_decision_normalized == Decision.ALLOW.value:
        _validated_replay_allow_consumption(session, receipt)
        _validated_replay_allow_attempt(
            session,
            receipt,
            expected_actor=expected_actor,
            expected_action=expected_action,
            expected_args=expected_args,
        )
    else:
        _validate_no_allow_consumption(session, receipt)
        _validate_no_mutation_attempt(session, receipt)
    return ManagedReplayArtifacts(sealed_receipt=sealed_receipt, event=event, outbox=outbox)


def _validated_replay_sealed_receipt(
    session: Session,
    receipt: ManagedDecisionReceipt,
    *,
    expected_action: str,
    expected_actor: str,
    expected_args: Mapping[str, Any],
    receipt_sealer: ReceiptArtifactSealer,
    trust_purpose: str,
) -> DecisionReceipt:
    try:
        sealed_receipt = receipt.projection.get("sealed_receipt")
        if not isinstance(sealed_receipt, Mapping):
            raise ValueError("sealed receipt projection missing")
        plaintext = receipt_sealer.unseal(
            sealed_receipt,
            associated_data=managed_receipt_artifact_aad(
                org_id=receipt.org_id,
                project_id=receipt.project_id,
                environment_id=receipt.environment_id,
                receipt_hash=receipt.receipt_hash,
            ),
        )
        payload = json.loads(plaintext.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("sealed receipt payload must be an object")
        sealed = DecisionReceipt.from_dict(payload)
        _assert_receipt_row_matches_artifact(receipt, sealed)
        if sealed.receipt_hash != sealed.compute_hash():
            raise ReceiptValidationError("managed replay receipt hash mismatch")
        try:
            sealed.verify(
                expected_tenant_id=receipt.org_id,
                expected_execution_boundary=receipt.execution_boundary,
                expected_action=expected_action,
                expected_actor=expected_actor,
                expected_audit_hash=receipt.audit_event_hash,
                expected_args=dict(expected_args),
                expected_policy_hash=receipt.policy_hash,
                expected_policy_bundle_id=receipt.policy_bundle_id,
                expected_project_id=receipt.project_id,
                expected_environment_id=receipt.environment_id,
                expected_validator_role=receipt.projection.get("validator_role"),
                expected_authority=receipt.projection.get("authority"),
                verifier=None,
                require_signature=True,
                require_expiry=False,
                trust_registry=SqlReceiptTrustRegistry(session, lock_rows=True),
                historical_trust_verification=True,
                trust_purpose=trust_purpose,
                now_iso=sealed.timestamp,
                max_clock_skew_seconds=DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS,
            )
        except ReceiptValidationError as exc:
            terminal_non_executable_reasons = {
                Decision.DENY.value: ReceiptRejectionReason.DENIED_RECEIPT,
                Decision.ESCALATE.value: ReceiptRejectionReason.ESCALATED_RECEIPT,
            }
            if exc.reason_code == terminal_non_executable_reasons.get(sealed.decision):
                return sealed
            raise
        return sealed
    except (ReceiptValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ManagedReplayArtifactValidationError(
            "managed replay sealed receipt is invalid"
        ) from exc


def _assert_receipt_row_matches_artifact(
    receipt_row: ManagedDecisionReceipt,
    receipt: DecisionReceipt,
) -> None:
    if (
        receipt_row.receipt_id != receipt.receipt_id
        or receipt_row.receipt_hash != receipt.receipt_hash
        or receipt_row.audit_event_hash != receipt.audit_event_hash
        or receipt_row.decision != receipt.decision
        or receipt_row.actor != receipt.actor
        or receipt_row.proposed_action != receipt.proposed_action
        or receipt_row.execution_boundary != receipt.execution_boundary
        or receipt_row.policy_bundle_id != receipt.policy_bundle_id
        or receipt_row.policy_version != receipt.policy_version
        or receipt_row.policy_hash != receipt.policy_hash
        or receipt_row.argument_hash != receipt.argument_hash
        or receipt_row.signing_key_id != receipt.signing_key_id
        or receipt_row.signature_algorithm != receipt.signature_algorithm
        or receipt_row.receipt_schema_version != receipt.receipt_schema_version
        or receipt_row.trust_epoch != receipt.trust_epoch
        or receipt_row.project_id != receipt.project_id
        or receipt_row.environment_id != receipt.environment_id
    ):
        raise ReceiptValidationError("managed replay receipt row does not match artifact")


def _validated_replay_event(
    session: Session,
    receipt: ManagedDecisionReceipt,
    *,
    expected_args: Mapping[str, Any],
    expected_actor: str,
    expected_action: str,
    expected_result_hash: str,
) -> ManagedGovernanceEvent:
    events = list(
        session.scalars(
            sa.select(ManagedGovernanceEvent)
            .where(
                ManagedGovernanceEvent.org_id == receipt.org_id,
                ManagedGovernanceEvent.project_id == receipt.project_id,
                ManagedGovernanceEvent.environment_id == receipt.environment_id,
                ManagedGovernanceEvent.managed_receipt_id == receipt.id,
            )
            .with_for_update()
        )
    )
    if len(events) != 1:
        raise ManagedReplayArtifactValidationError("managed replay event is missing")
    event = events[0]
    event_payload = event.payload if isinstance(event.payload, Mapping) else {}
    if (
        event.decision != receipt.decision
        or event.actor != receipt.actor
        or event.proposed_action != receipt.proposed_action
        or event.policy_version != receipt.policy_version
        or event_payload.get("receipt_hash") != receipt.receipt_hash
        or event_payload.get("audit_event_hash") != receipt.audit_event_hash
        or event_payload.get("argument_hash") != sha256_json(dict(expected_args))
        or event_payload.get("result_hash") != expected_result_hash
        or event_payload.get("decision") != receipt.decision
        or event_payload.get("actor_hash") != sha256_json(expected_actor)
        or event_payload.get("action") != expected_action
        or event_payload.get("policy_bundle_id") != receipt.policy_bundle_id
        or event_payload.get("policy_hash") != receipt.policy_hash
    ):
        raise ManagedReplayArtifactValidationError("managed replay event binding is invalid")
    scope = event_payload.get("scope")
    if not isinstance(scope, Mapping) or (
        scope.get("org_id") != receipt.org_id
        or scope.get("project_id") != receipt.project_id
        or scope.get("environment_id") != receipt.environment_id
        or scope.get("execution_boundary") != receipt.execution_boundary
    ):
        raise ManagedReplayArtifactValidationError("managed replay event scope is invalid")
    if event.payload_digest != sha256_json(event.payload):
        raise ManagedReplayArtifactValidationError("managed replay event digest is invalid")
    _validate_replay_event_chain(session, event)
    return event


def _validate_replay_event_chain(session: Session, event: ManagedGovernanceEvent) -> None:
    expected_event_hash = sha256_json(
        {
            "schema": "managed-mutation-event-chain/v1",
            "sequence": event.sequence,
            "previous_hash": event.previous_hash,
            "payload_digest": event.payload_digest,
        }
    )
    if event.event_hash != expected_event_hash:
        raise ManagedReplayArtifactValidationError("managed replay event hash is invalid")
    head = session.get(
        ManagedGovernanceEventHead,
        (event.org_id, event.project_id, event.environment_id),
        with_for_update=True,
    )
    if head is None or event.sequence < 1 or event.sequence > head.last_sequence:
        raise ManagedReplayArtifactValidationError("managed replay event head is invalid")
    if event.sequence == 1:
        if event.previous_hash != _GENESIS_HASH:
            raise ManagedReplayArtifactValidationError("managed replay genesis link is invalid")
    else:
        previous_event = _event_at_sequence(session, event, sequence=event.sequence - 1)
        if previous_event is None or previous_event.event_hash != event.previous_hash:
            raise ManagedReplayArtifactValidationError("managed replay previous link is invalid")
    previous_hash = event.event_hash
    for sequence in range(event.sequence + 1, head.last_sequence + 1):
        next_event = _event_at_sequence(session, event, sequence=sequence)
        if next_event is None or next_event.previous_hash != previous_hash:
            raise ManagedReplayArtifactValidationError("managed replay next link is invalid")
        expected_next_hash = sha256_json(
            {
                "schema": "managed-mutation-event-chain/v1",
                "sequence": next_event.sequence,
                "previous_hash": next_event.previous_hash,
                "payload_digest": next_event.payload_digest,
            }
        )
        if next_event.event_hash != expected_next_hash:
            raise ManagedReplayArtifactValidationError(
                "managed replay successor event hash is invalid"
            )
        previous_hash = next_event.event_hash
    if head.last_event_hash != previous_hash:
        raise ManagedReplayArtifactValidationError("managed replay chain head is invalid")


def _event_at_sequence(
    session: Session,
    event: ManagedGovernanceEvent,
    *,
    sequence: int,
) -> ManagedGovernanceEvent | None:
    return session.scalars(
        sa.select(ManagedGovernanceEvent)
        .where(
            ManagedGovernanceEvent.org_id == event.org_id,
            ManagedGovernanceEvent.project_id == event.project_id,
            ManagedGovernanceEvent.environment_id == event.environment_id,
            ManagedGovernanceEvent.sequence == sequence,
        )
        .with_for_update()
    ).one_or_none()


def _validated_replay_outbox(
    session: Session,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
) -> ManagedOutboxMessage:
    outbox_rows = list(
        session.scalars(
            sa.select(ManagedOutboxMessage)
            .where(
                ManagedOutboxMessage.org_id == receipt.org_id,
                ManagedOutboxMessage.project_id == receipt.project_id,
                ManagedOutboxMessage.environment_id == receipt.environment_id,
                ManagedOutboxMessage.managed_receipt_id == receipt.id,
                ManagedOutboxMessage.managed_event_id == event.id,
            )
            .with_for_update()
        )
    )
    if len(outbox_rows) != 1:
        raise ManagedReplayArtifactValidationError("managed replay outbox is missing")
    outbox = outbox_rows[0]
    outbox_payload = outbox.payload if isinstance(outbox.payload, Mapping) else {}
    if (
        outbox_payload.get("event_hash") != event.event_hash
        or outbox_payload.get("payload_digest") != event.payload_digest
        or outbox_payload.get("receipt_hash") != receipt.receipt_hash
        or outbox_payload.get("audit_event_hash") != receipt.audit_event_hash
        or outbox_payload.get("result_hash") != event.payload.get("result_hash")
        or outbox_payload.get("assurance_class") != receipt.assurance_class
        or outbox.delivery_key != f"managed-mutation-uow/v1:{event.event_hash}"
        or outbox.payload_digest != sha256_json(outbox.payload)
    ):
        raise ManagedReplayArtifactValidationError("managed replay outbox binding is invalid")
    return outbox


def _validated_replay_allow_consumption(
    session: Session,
    receipt: ManagedDecisionReceipt,
) -> None:
    consumptions = list(
        session.scalars(
            sa.select(ManagedReceiptConsumption)
            .where(
                ManagedReceiptConsumption.org_id == receipt.org_id,
                ManagedReceiptConsumption.project_id == receipt.project_id,
                ManagedReceiptConsumption.environment_id == receipt.environment_id,
                ManagedReceiptConsumption.managed_receipt_id == receipt.id,
            )
            .with_for_update()
        )
    )
    if len(consumptions) != 1:
        raise ManagedReplayArtifactValidationError("managed replay consumption is missing")
    consumption = consumptions[0]
    if (
        consumption.receipt_hash != receipt.receipt_hash
        or consumption.audit_event_hash != receipt.audit_event_hash
    ):
        raise ManagedReplayArtifactValidationError("managed replay consumption is invalid")


def _validated_replay_allow_attempt(
    session: Session,
    receipt: ManagedDecisionReceipt,
    *,
    expected_actor: str,
    expected_action: str,
    expected_args: Mapping[str, Any],
) -> None:
    attempts = list(
        session.scalars(
            sa.select(ManagedMutationAttempt)
            .where(
                ManagedMutationAttempt.org_id == receipt.org_id,
                ManagedMutationAttempt.project_id == receipt.project_id,
                ManagedMutationAttempt.environment_id == receipt.environment_id,
                ManagedMutationAttempt.receipt_hash == receipt.receipt_hash,
            )
            .with_for_update()
        )
    )
    if len(attempts) != 1:
        raise ManagedReplayArtifactValidationError("managed replay attempt is missing")
    attempt = attempts[0]
    if (
        attempt.audit_event_hash != receipt.audit_event_hash
        or attempt.action != expected_action
        or attempt.actor_hash != sha256_json(expected_actor)
        or attempt.argument_hash != sha256_json(dict(expected_args))
        or attempt.status != "succeeded"
    ):
        raise ManagedReplayArtifactValidationError("managed replay attempt is invalid")


def _validate_no_allow_consumption(
    session: Session,
    receipt: ManagedDecisionReceipt,
) -> None:
    if (
        session.scalars(
            sa.select(ManagedReceiptConsumption)
            .where(
                ManagedReceiptConsumption.org_id == receipt.org_id,
                ManagedReceiptConsumption.project_id == receipt.project_id,
                ManagedReceiptConsumption.environment_id == receipt.environment_id,
                ManagedReceiptConsumption.managed_receipt_id == receipt.id,
            )
            .with_for_update()
        ).first()
        is not None
    ):
        raise ManagedReplayArtifactValidationError(
            "managed replay non-executable receipt has consumption"
        )


def _validate_no_mutation_attempt(
    session: Session,
    receipt: ManagedDecisionReceipt,
) -> None:
    if (
        session.scalars(
            sa.select(ManagedMutationAttempt)
            .where(
                ManagedMutationAttempt.org_id == receipt.org_id,
                ManagedMutationAttempt.project_id == receipt.project_id,
                ManagedMutationAttempt.environment_id == receipt.environment_id,
                ManagedMutationAttempt.receipt_hash == receipt.receipt_hash,
            )
            .with_for_update()
        ).first()
        is not None
    ):
        raise ManagedReplayArtifactValidationError(
            "managed replay non-executable receipt has attempt"
        )


def _validated_execution_boundary(context: ManagedMutationContext) -> str:
    if context.action == TENANT_BOOTSTRAP_ACTION:
        if context.execution_boundary != TENANT_BOOTSTRAP_EXECUTION_BOUNDARY:
            raise ReceiptValidationError("tenant.bootstrap execution boundary is not canonical")
        return TENANT_BOOTSTRAP_EXECUTION_BOUNDARY
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
    if action == TENANT_BOOTSTRAP_ACTION:
        return _validated_tenant_bootstrap_args(args)
    if action == CONTROL_PLANE_POLICY_PUBLISH_ACTION:
        return _validated_policy_publish_args(args)
    if action == CONTROL_PLANE_POLICY_ACTIVATE_ACTION:
        return _validated_policy_activate_args(args)
    if action == CONTROL_PLANE_APPROVAL_VOTE_ACTION:
        return _validated_approval_vote_args(args)
    if action == CONTROL_PLANE_RUNTIME_BOOTSTRAP_ISSUE_ACTION:
        return _validated_runtime_bootstrap_issue_args(args)
    if action == CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION:
        return _validated_runtime_identity_enroll_args(args)
    if action == CONTROL_PLANE_RUNTIME_IDENTITY_RENEW_ACTION:
        return _validated_runtime_identity_renew_args(args)
    if action == CONTROL_PLANE_RUNTIME_IDENTITY_REVOKE_ACTION:
        return _validated_runtime_identity_revoke_args(args)
    if action != CONTROL_PLANE_AGENT_CREATE_ACTION:
        raise ReceiptValidationError(f"unsupported managed mutation action: {action}")
    allowed_fields = {"name", "description", "trust_tier", "allowed_tools"}
    actual_fields = set(args)
    if actual_fields != allowed_fields:
        raise ReceiptValidationError(
            "agent.create requires exactly the canonical agent registration arguments"
        )
    name = args.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ReceiptValidationError("agent.create name must be a non-empty string")
    description = args.get("description")
    if not isinstance(description, str):
        raise ReceiptValidationError("agent.create description must be text")
    trust_tier = args.get("trust_tier")
    if not isinstance(trust_tier, str) or not trust_tier.strip():
        raise ReceiptValidationError("agent.create trust_tier must be non-empty text")
    allowed_tools = args.get("allowed_tools")
    if not isinstance(allowed_tools, list) or not all(
        isinstance(tool, str) and tool.strip() for tool in allowed_tools
    ):
        raise ReceiptValidationError("agent.create allowed_tools must be a text list")
    return {
        "name": name,
        "description": description,
        "trust_tier": trust_tier,
        "allowed_tools": list(allowed_tools),
    }


def _validated_runtime_bootstrap_issue_args(args: Mapping[str, Any]) -> dict[str, Any]:
    allowed_fields = {
        "ttl_seconds",
        "runtime_identity_id",
        "audience",
        "workload_key_id",
        "public_key_thumbprint",
    }
    if set(args) != allowed_fields:
        raise ReceiptValidationError("runtime bootstrap issue arguments are not canonical")
    ttl_seconds = args.get("ttl_seconds")
    if not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 900:
        raise ReceiptValidationError("runtime bootstrap ttl_seconds is invalid")
    normalized: dict[str, Any] = {"ttl_seconds": ttl_seconds}
    for field_name in allowed_fields - {"ttl_seconds"}:
        value = args.get(field_name)
        if not isinstance(value, str) or not value:
            raise ReceiptValidationError(f"runtime bootstrap {field_name} is invalid")
        normalized[field_name] = value
    return normalized


def _validated_runtime_identity_enroll_args(args: Mapping[str, Any]) -> dict[str, Any]:
    allowed_fields = {
        "bootstrap_id",
        "runtime_identity_id",
        "public_key_thumbprint",
        "workload_key_id",
    }
    if set(args) != allowed_fields:
        raise ReceiptValidationError("runtime identity enroll arguments are not canonical")
    normalized: dict[str, Any] = {}
    for field_name in allowed_fields:
        value = args.get(field_name)
        if not isinstance(value, str) or not value:
            raise ReceiptValidationError(f"runtime identity enroll {field_name} is invalid")
        normalized[field_name] = value
    return normalized


def _validated_runtime_identity_renew_args(args: Mapping[str, Any]) -> dict[str, Any]:
    if set(args) != {
        "identity_id",
        "nonce",
        "credential_id",
        "credential_generation",
        "generation",
    }:
        raise ReceiptValidationError("runtime identity renew arguments are not canonical")
    identity_id = args.get("identity_id")
    nonce = args.get("nonce")
    credential_id = args.get("credential_id")
    credential_generation = args.get("credential_generation")
    generation = args.get("generation")
    if not isinstance(identity_id, str) or not identity_id:
        raise ReceiptValidationError("runtime identity renew identity_id is invalid")
    if not isinstance(nonce, str) or not nonce:
        raise ReceiptValidationError("runtime identity renew nonce is invalid")
    if not isinstance(credential_id, str) or not credential_id:
        raise ReceiptValidationError("runtime identity renew credential_id is invalid")
    if not isinstance(credential_generation, int) or credential_generation < 1:
        raise ReceiptValidationError("runtime identity renew credential_generation is invalid")
    if not isinstance(generation, int) or generation < 2:
        raise ReceiptValidationError("runtime identity renew generation is invalid")
    return {
        "identity_id": identity_id,
        "nonce": nonce,
        "credential_id": credential_id,
        "credential_generation": credential_generation,
        "generation": generation,
    }


def _validated_runtime_identity_revoke_args(args: Mapping[str, Any]) -> dict[str, Any]:
    if set(args) != {"identity_id", "expected_credential_generation"}:
        raise ReceiptValidationError("runtime identity revoke arguments are not canonical")
    identity_id = args.get("identity_id")
    expected_credential_generation = args.get("expected_credential_generation")
    if not isinstance(identity_id, str) or not identity_id:
        raise ReceiptValidationError("runtime identity revoke identity_id is invalid")
    if not isinstance(expected_credential_generation, int) or expected_credential_generation < 1:
        raise ReceiptValidationError(
            "runtime identity revoke expected_credential_generation is invalid"
        )
    return {
        "identity_id": identity_id,
        "expected_credential_generation": expected_credential_generation,
    }


def _validated_tenant_bootstrap_args(args: Mapping[str, Any]) -> dict[str, Any]:
    allowed_fields = {
        "display_name",
        "admin_name",
        "admin_email_hash",
        "org_id",
        "project_id",
        "environment_id",
        "owner_user_id",
        "owner_membership_id",
        "idempotency_key_hash",
        "invitation_id_hash",
    }
    actual_fields = set(args)
    if actual_fields != allowed_fields:
        raise ReceiptValidationError("tenant.bootstrap requires exactly the canonical arguments")
    normalized: dict[str, Any] = {}
    for field_name in allowed_fields:
        value = args.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise ReceiptValidationError(f"tenant.bootstrap {field_name} must be non-empty text")
        normalized[field_name] = value
    return normalized


def _validated_policy_publish_args(args: Mapping[str, Any]) -> dict[str, Any]:
    allowed_fields = {"policy_id", "version", "content_hash", "canonical_envelope"}
    if set(args) != allowed_fields:
        raise ReceiptValidationError("policy.publish requires exactly the canonical arguments")
    policy_id = args.get("policy_id")
    version = args.get("version")
    content_hash = args.get("content_hash")
    envelope = args.get("canonical_envelope")
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise ReceiptValidationError("policy.publish policy_id must be non-empty text")
    if not isinstance(version, str) or not version.strip():
        raise ReceiptValidationError("policy.publish version must be non-empty text")
    if not isinstance(content_hash, str) or len(content_hash) != 64:
        raise ReceiptValidationError("policy.publish content_hash must be sha256 hex")
    if not isinstance(envelope, dict):
        raise ReceiptValidationError("policy.publish canonical_envelope must be an object")
    return {
        "policy_id": policy_id,
        "version": version,
        "content_hash": content_hash,
        "canonical_envelope": dict(envelope),
    }


def _validated_policy_activate_args(args: Mapping[str, Any]) -> dict[str, Any]:
    allowed_fields = {"policy_version_id", "expected_generation"}
    if set(args) != allowed_fields:
        raise ReceiptValidationError("policy.activate requires exactly the canonical arguments")
    policy_version_id = args.get("policy_version_id")
    expected_generation = args.get("expected_generation")
    if not isinstance(policy_version_id, str) or not policy_version_id.strip():
        raise ReceiptValidationError("policy.activate policy_version_id must be non-empty text")
    if type(expected_generation) is not int or expected_generation < 0:
        raise ReceiptValidationError("policy.activate expected_generation must be nonnegative int")
    return {
        "policy_version_id": policy_version_id,
        "expected_generation": expected_generation,
    }


def _validated_approval_vote_args(args: Mapping[str, Any]) -> dict[str, Any]:
    allowed_fields = {
        "approval_request_id",
        "decision",
        "request_hash",
        "approver_credential_hash",
    }
    if set(args) != allowed_fields:
        raise ReceiptValidationError("approval.vote requires exactly the canonical arguments")
    approval_request_id = args.get("approval_request_id")
    decision = args.get("decision")
    request_hash = args.get("request_hash")
    approver_credential_hash = args.get("approver_credential_hash")
    if not isinstance(approval_request_id, str) or not approval_request_id.strip():
        raise ReceiptValidationError("approval.vote approval_request_id must be non-empty text")
    if decision not in {"approve", "reject"}:
        raise ReceiptValidationError("approval.vote decision must be approve or reject")
    if not isinstance(request_hash, str) or len(request_hash) != 64:
        raise ReceiptValidationError("approval.vote request_hash must be sha256 hex")
    if not isinstance(approver_credential_hash, str) or len(approver_credential_hash) != 64:
        raise ReceiptValidationError("approval.vote approver_credential_hash must be sha256 hex")
    return {
        "approval_request_id": approval_request_id,
        "decision": decision,
        "request_hash": request_hash,
        "approver_credential_hash": approver_credential_hash,
    }


def _execute_verified_operation(
    session: Session,
    context: ManagedMutationContext,
    verified_args: Mapping[str, Any],
) -> dict[str, str]:
    if context.action == TENANT_BOOTSTRAP_ACTION:
        return {
            "org_id_hash": sha256_json(context.org_id),
            "project_id_hash": sha256_json(context.project_id),
            "environment_id_hash": sha256_json(context.environment_id),
            "owner_user_id_hash": sha256_json(verified_args["owner_user_id"]),
            "owner_membership_id_hash": sha256_json(verified_args["owner_membership_id"]),
        }
    if context.action in {
        CONTROL_PLANE_POLICY_PUBLISH_ACTION,
        CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
        CONTROL_PLANE_APPROVAL_VOTE_ACTION,
    }:
        return {
            "policy_effect_hash": sha256_json(
                {
                    "action": context.action,
                    "org_id": context.org_id,
                    "project_id": context.project_id,
                    "environment_id": context.environment_id,
                    "args": dict(verified_args),
                }
            )
        }
    if context.action != CONTROL_PLANE_AGENT_CREATE_ACTION:
        raise ReceiptValidationError(f"unsupported managed mutation action: {context.action}")
    name = str(verified_args["name"])
    agent = AgentRecord(
        id=new_id(),
        org_id=context.org_id,
        project_id=context.project_id,
        environment_id=context.environment_id,
        name=name,
        description=str(verified_args["description"]),
        trust_tier=str(verified_args["trust_tier"]),
        allowed_tools=list(verified_args["allowed_tools"]),
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
