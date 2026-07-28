"""Generic managed-approval substrate for parked ESCALATE decisions."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import sqlalchemy as sa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import ReceiptAlreadyUsedError, ReceiptRejectionReason, ReceiptValidationError
from gove_zone.executor import execute_with_receipt
from gove_zone.policy import RuleSetPolicy
from gove_zone.receipt import DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS, DecisionReceipt, safe_result_hash
from gove_zone.tool import ToolCall
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope, TrustConfigurationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from acgs_control_plane.auth import Principal
from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_AGENT_CREATE_ACTION,
    CONTROL_PLANE_APPROVAL_VOTE_ACTION,
    AesGcmReceiptArtifactSealer,
    ManagedMutationContext,
    ManagedMutationResult,
    ManagedMutationUnitOfWork,
    _append_governance_event,
    _enqueue_outbox,
    _reserve_mutation_attempt_row,
    _SqlReceiptConsumptionLedger,
    _validated_execution_boundary,
    managed_mutation_execution_boundary,
    managed_receipt_artifact_aad,
)
from acgs_control_plane.models import (
    AgentRecord,
    ApprovalOutcome,
    ApprovalRequest,
    ApprovalResumeAuthorization,
    ApprovalVote,
    EnvironmentPolicyHead,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedGovernanceEventHead,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    PolicyVersion,
    User,
    new_id,
    utcnow,
)
from acgs_control_plane.policy_registry import _verify_envelope
from acgs_control_plane.rbac import Permission, Role, role_allows
from acgs_control_plane.trust import (
    ManagedPlatformIssuer,
    ManagedTrustError,
    SqlReceiptTrustRegistry,
    active_trust_epoch_for_scope,
    mint_managed_decision_receipt_v2,
)

APPROVAL_AUTHORITY = "control-plane.approvals/v1"
APPROVAL_VALIDATOR_ROLE = "control-plane.approval-policy/v1"
_GENESIS_AUDIT_HASH = "0" * 64
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9._:/-]{8,200}$")


@dataclass
class ApprovalHttpError(RuntimeError):
    status_code: int
    code: str
    status: str
    detail: str
    stage: str = "policy"


@dataclass(frozen=True)
class ApprovalVoteResult:
    approval_request_id: str
    decision: str
    outcome: str | None
    vote_hash: str
    receipt_id: str


@dataclass(frozen=True)
class ApprovalResumeResult:
    approval_request_id: str
    agent_id: str
    org_id: str
    name: str
    description: str
    trust_tier: str
    allowed_tools: list[str]
    status: str
    created_at: Any
    receipt_id: str


@dataclass(frozen=True)
class ApprovalAuthorizationState:
    outcome: ApprovalOutcome
    votes: tuple[ApprovalVote, ...]
    summary: dict[str, Any]


@dataclass(frozen=True)
class _VoteEvidence:
    receipt: ManagedDecisionReceipt
    sealed_receipt: DecisionReceipt
    event: ManagedGovernanceEvent
    outbox: ManagedOutboxMessage
    result_hash: str


@dataclass(frozen=True)
class ApprovalProviders:
    issuer: ManagedPlatformIssuer
    receipt_sealer: AesGcmReceiptArtifactSealer
    payload_sealer: ApprovalPayloadSealer


class ApprovalService:
    """Govern approval votes and one-time resume of parked ESCALATE requests."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        issuer: ManagedPlatformIssuer,
        receipt_sealer: AesGcmReceiptArtifactSealer,
        payload_sealer: ApprovalPayloadSealer,
    ) -> None:
        self._session_factory = session_factory
        self._providers = ApprovalProviders(
            issuer=issuer,
            receipt_sealer=receipt_sealer,
            payload_sealer=payload_sealer,
        )

    def vote(
        self,
        *,
        org_id: str,
        approval_request_id: str,
        principal: Principal,
        decision: str,
        idempotency_key: str | None,
    ) -> ApprovalVoteResult:
        idempotency_key = _normalize_idempotency_key(idempotency_key, operation="approval vote")
        if decision not in {"approve", "reject"}:
            raise ApprovalHttpError(422, "APPROVAL_DECISION_INVALID", "invalid", "invalid vote")
        with self._session_factory() as session:
            request = _locked_approval_request_binding(session, org_id, approval_request_id)
            current_principal = _locked_current_principal(
                session,
                org_id=org_id,
                principal=principal,
                permission=Permission.APPROVAL_VOTE,
                operation="vote",
            )
            _require_approver(request, current_principal)
            credential_hash = _current_principal_credential_hash(current_principal)
            args = {
                "approval_request_id": request.id,
                "decision": decision,
                "request_hash": request.request_hash,
                "approver_credential_hash": credential_hash,
            }
            idempotency_hash = _idempotency_storage_key(
                org_id=org_id,
                approval_request_id=request.id,
                key=idempotency_key,
            )
            existing = _lookup_vote(session, request, idempotency_hash)
            if existing is not None:
                _assert_same_vote(existing, request=request, principal=current_principal, args=args)
                return _vote_result_from_row(
                    session,
                    request,
                    existing,
                    receipt_sealer=self._providers.receipt_sealer,
                    payload_sealer=self._providers.payload_sealer,
                    expected_idempotency_key_hash=idempotency_hash,
                    expected_actor_hash=sha256_json(current_principal.actor_id),
                    expected_credential_hash=credential_hash,
                    expected_role=current_principal.role.value,
                )
            existing_refusal = _lookup_vote_refusal(session, request, idempotency_key, args)
            if existing_refusal is not None:
                _validate_approval_vote_refusal_evidence(
                    session,
                    request=request,
                    receipt=existing_refusal,
                    idempotency_key=idempotency_key,
                    args=args,
                    expected_actor=current_principal.actor_id,
                    receipt_sealer=self._providers.receipt_sealer,
                    historical_idempotency_replay=True,
                )
                raise _approval_error_for_decision(existing_refusal.decision)
            _require_approval_request_not_expired(request)
            policy, policy_bundle_id, policy_hash = _active_policy_context(session, request)
            context = ManagedMutationContext(
                org_id=org_id,
                project_id=request.project_id,
                environment_id=request.environment_id,
                actor=current_principal.actor_id,
                action=CONTROL_PLANE_APPROVAL_VOTE_ACTION,
                execution_boundary=managed_mutation_execution_boundary(
                    org_id=org_id,
                    project_id=request.project_id,
                    environment_id=request.environment_id,
                    action=CONTROL_PLANE_APPROVAL_VOTE_ACTION,
                ),
                policy_bundle_id=policy_bundle_id,
                policy_hash=policy_hash,
                validator_role=APPROVAL_VALIDATOR_ROLE,
                authority=APPROVAL_AUTHORITY,
            )
            record = _evaluate_policy_record(
                policy,
                context=context,
                args=args,
                goal="record approval vote",
                path=("control-plane", "approvals", "vote"),
            )
            audit_hash = _decision_audit_hash(record)
            context = replace(context, expected_audit_hash=audit_hash)
            trust_epoch = active_trust_epoch_for_scope(
                session,
                ReceiptTrustScope(
                    org_id,
                    request.project_id,
                    request.environment_id,
                    DECISION_RECEIPT_PURPOSE,
                ),
            )
            receipt = _issue_receipt(
                issuer=self._providers.issuer,
                context=context,
                record=record,
                audit_hash=audit_hash,
                request_id=idempotency_key,
                trust_epoch=trust_epoch,
                approval_chain_summary={},
            )

        if record.decision in {Decision.DENY, Decision.ESCALATE}:

            def before_record(tx_session: Session) -> None:
                tx_request = _locked_approval_request_binding(
                    tx_session, org_id, approval_request_id
                )
                tx_principal = _locked_current_principal(
                    tx_session,
                    org_id=org_id,
                    principal=principal,
                    permission=Permission.APPROVAL_VOTE,
                    operation="vote",
                )
                _require_approver(tx_request, tx_principal)
                existing = _lookup_vote(tx_session, tx_request, idempotency_hash)
                if existing is not None:
                    _assert_same_vote(
                        existing,
                        request=tx_request,
                        principal=tx_principal,
                        args=args,
                    )
                    raise _CommittedApprovalVoteRace()
                existing_refusal = _lookup_vote_refusal(
                    tx_session,
                    tx_request,
                    idempotency_key,
                    args,
                )
                if existing_refusal is not None:
                    _validate_approval_vote_refusal_evidence(
                        tx_session,
                        request=tx_request,
                        receipt=existing_refusal,
                        idempotency_key=idempotency_key,
                        args=args,
                        expected_actor=tx_principal.actor_id,
                        receipt_sealer=self._providers.receipt_sealer,
                        historical_idempotency_replay=True,
                    )
                    raise _CommittedApprovalVoteRefusalRace(existing_refusal.decision)
                _require_approval_request_not_expired(tx_request)

            try:
                ManagedMutationUnitOfWork(
                    self._session_factory,
                    receipt_sealer=self._providers.receipt_sealer,
                ).record_non_executable_evidence(
                    context=context,
                    receipt=receipt,
                    args=args,
                    before_record=before_record,
                )
            except _CommittedApprovalVoteRefusalRace as exc:
                raise _approval_error_for_decision(exc.decision) from None
            except _CommittedApprovalVoteRace:
                with self._session_factory() as session:
                    request = _locked_approval_request(session, org_id, approval_request_id)
                    current_principal = _locked_current_principal(
                        session,
                        org_id=org_id,
                        principal=principal,
                        permission=Permission.APPROVAL_VOTE,
                        operation="vote",
                    )
                    _require_approver(request, current_principal)
                    existing = _lookup_vote(session, request, idempotency_hash)
                    if existing is not None:
                        return _vote_result_from_row(
                            session,
                            request,
                            existing,
                            receipt_sealer=self._providers.receipt_sealer,
                            payload_sealer=self._providers.payload_sealer,
                            expected_idempotency_key_hash=idempotency_hash,
                            expected_actor_hash=sha256_json(current_principal.actor_id),
                            expected_credential_hash=_current_principal_credential_hash(
                                current_principal
                            ),
                            expected_role=current_principal.role.value,
                        )
                raise ApprovalHttpError(
                    503, "TX_ABORTED", "tx_aborted", "approval vote not observable"
                ) from None
            except ReceiptAlreadyUsedError as exc:
                with self._session_factory() as replay_session:
                    request = _locked_approval_request(
                        replay_session,
                        org_id,
                        approval_request_id,
                    )
                    current_principal = _locked_current_principal(
                        replay_session,
                        org_id=org_id,
                        principal=principal,
                        permission=Permission.APPROVAL_VOTE,
                        operation="vote",
                    )
                    _require_approver(request, current_principal)
                    existing_refusal = _lookup_vote_refusal(
                        replay_session,
                        request,
                        idempotency_key,
                        args,
                    )
                    if existing_refusal is None:
                        raise ApprovalHttpError(
                            503,
                            "TX_ABORTED",
                            "tx_aborted",
                            "approval vote refusal receipt was consumed but not observable",
                        ) from exc
                    _validate_approval_vote_refusal_evidence(
                        replay_session,
                        request=request,
                        receipt=existing_refusal,
                        idempotency_key=idempotency_key,
                        args=args,
                        expected_actor=current_principal.actor_id,
                        receipt_sealer=self._providers.receipt_sealer,
                        historical_idempotency_replay=True,
                    )
                    raise _approval_error_for_decision(existing_refusal.decision) from None
            except (ReceiptValidationError, TrustConfigurationError, ManagedTrustError) as exc:
                raise ApprovalHttpError(
                    503, "RECEIPT_REFUSED", "receipt_refused", "approval vote receipt refused"
                ) from exc
            except (IntegrityError, SQLAlchemyError, RuntimeError) as exc:
                raise ApprovalHttpError(
                    503, "TX_ABORTED", "tx_aborted", "approval vote refusal evidence aborted"
                ) from exc
            raise _approval_error_for_decision(record.decision.value)

        holder: dict[str, ApprovalVoteResult] = {}

        def operation_effect(session: Session, verified_args: dict[str, Any]) -> dict[str, Any]:
            request = _locked_approval_request(session, org_id, approval_request_id)
            current_principal = _locked_current_principal(
                session,
                org_id=org_id,
                principal=principal,
                permission=Permission.APPROVAL_VOTE,
                operation="vote",
            )
            _require_approver(request, current_principal)
            existing = _lookup_vote(session, request, idempotency_hash)
            if existing is not None:
                _assert_same_vote(
                    existing,
                    request=request,
                    principal=current_principal,
                    args=verified_args,
                )
                raise _CommittedApprovalVoteRace()
            if _lookup_outcome(session, request) is not None:
                raise ApprovalHttpError(
                    409,
                    "APPROVAL_TERMINAL",
                    "conflict",
                    "approval request already has a terminal outcome",
                    stage="tx",
                )
            vote_hash = _vote_hash(
                request=request,
                principal=current_principal,
                args=verified_args,
            )
            vote = ApprovalVote(
                id=new_id(),
                org_id=request.org_id,
                project_id=request.project_id,
                environment_id=request.environment_id,
                approval_request_id=request.id,
                approver_actor_hash=sha256_json(current_principal.actor_id),
                approver_credential_hash=_current_principal_credential_hash(current_principal),
                approver_role=current_principal.role.value,
                decision=str(verified_args["decision"]),
                idempotency_key_hash=idempotency_hash,
                vote_receipt_id=None,
                vote_receipt_hash=None,
                vote_audit_event_hash=None,
                vote_hash=vote_hash,
                vote_replay_seal={},
            )
            session.add(vote)
            session.flush()
            outcome = _maybe_record_outcome(session, request)
            return {
                "vote_id": vote.id,
                "vote_hash": vote.vote_hash,
                "outcome": outcome.outcome if outcome is not None else "",
            }

        def after_success(
            session: Session,
            receipt_row: ManagedDecisionReceipt,
            _event: ManagedGovernanceEvent,
            _outbox: ManagedOutboxMessage,
            result: ManagedMutationResult,
        ) -> None:
            request = _locked_approval_request(session, org_id, approval_request_id)
            vote = session.get(ApprovalVote, result.result["vote_id"])
            if vote is None:
                raise RuntimeError("approval vote committed without vote row")
            vote.vote_receipt_id = receipt_row.receipt_id
            vote.vote_receipt_hash = receipt_row.receipt_hash
            vote.vote_audit_event_hash = receipt_row.audit_event_hash
            response_payload = _vote_response_payload(
                approval_request_id=request.id,
                decision=vote.decision,
                outcome=result.result["outcome"] or None,
                vote_hash=vote.vote_hash,
                receipt_id=receipt_row.receipt_id,
            )
            vote.vote_replay_seal = _seal_vote_replay_artifact(
                payload_sealer=self._providers.payload_sealer,
                request=request,
                vote=vote,
                receipt=receipt_row,
                event=_event,
                outbox=_outbox,
                result_hash=result.result_hash,
                result_payload=dict(result.result),
                response_payload=response_payload,
            )
            session.flush()
            holder["response"] = _vote_result_from_response_payload(response_payload)

        try:

            def before_execute(tx_session: Session) -> None:
                tx_request = _locked_approval_request_binding(
                    tx_session, org_id, approval_request_id
                )
                existing_refusal = _lookup_vote_refusal(
                    tx_session,
                    tx_request,
                    idempotency_key,
                    args,
                )
                if existing_refusal is not None:
                    _validate_approval_vote_refusal_evidence(
                        tx_session,
                        request=tx_request,
                        receipt=existing_refusal,
                        idempotency_key=idempotency_key,
                        args=args,
                        expected_actor=current_principal.actor_id,
                        receipt_sealer=self._providers.receipt_sealer,
                        historical_idempotency_replay=True,
                    )
                    raise _CommittedApprovalVoteRefusalRace(existing_refusal.decision)
                _require_approval_request_not_expired(tx_request)
                _verify_frozen_policy_locked(tx_session, tx_request)

            ManagedMutationUnitOfWork(
                self._session_factory,
                receipt_sealer=self._providers.receipt_sealer,
            ).execute(
                context=context,
                receipt=receipt,
                args=args,
                before_execute=before_execute,
                operation_effect=operation_effect,
                after_success=after_success,
            )
        except _CommittedApprovalVoteRefusalRace as exc:
            raise _approval_error_for_decision(exc.decision) from None
        except _CommittedApprovalVoteRace:
            with self._session_factory() as session:
                request = _locked_approval_request_binding(session, org_id, approval_request_id)
                current_principal = _locked_current_principal(
                    session,
                    org_id=org_id,
                    principal=principal,
                    permission=Permission.APPROVAL_VOTE,
                    operation="vote",
                )
                _require_approver(request, current_principal)
                existing = _lookup_vote(session, request, idempotency_hash)
                if existing is not None:
                    return _vote_result_from_row(
                        session,
                        request,
                        existing,
                        receipt_sealer=self._providers.receipt_sealer,
                        payload_sealer=self._providers.payload_sealer,
                        expected_idempotency_key_hash=idempotency_hash,
                        expected_actor_hash=sha256_json(current_principal.actor_id),
                        expected_credential_hash=_current_principal_credential_hash(
                            current_principal
                        ),
                        expected_role=current_principal.role.value,
                    )
            raise ApprovalHttpError(
                503, "TX_ABORTED", "tx_aborted", "approval vote not observable"
            ) from None
        except (ReceiptValidationError, TrustConfigurationError, ManagedTrustError) as exc:
            raise ApprovalHttpError(
                503, "RECEIPT_REFUSED", "receipt_refused", "approval vote receipt refused"
            ) from exc
        except ApprovalHttpError:
            raise
        except (IntegrityError, SQLAlchemyError, RuntimeError) as exc:
            raise ApprovalHttpError(
                503, "TX_ABORTED", "tx_aborted", "approval vote transaction aborted"
            ) from exc
        if "response" not in holder:
            raise ApprovalHttpError(503, "TX_ABORTED", "tx_aborted", "approval vote missing")
        return holder["response"]

    def resume(
        self,
        *,
        org_id: str,
        approval_request_id: str,
        principal: Principal,
        idempotency_key: str | None,
    ) -> ApprovalResumeResult:
        idempotency_key = _normalize_idempotency_key(idempotency_key, operation="approval resume")
        try:
            return _execute_resume_under_locks(
                self._session_factory,
                issuer=self._providers.issuer,
                receipt_sealer=self._providers.receipt_sealer,
                payload_sealer=self._providers.payload_sealer,
                org_id=org_id,
                approval_request_id=approval_request_id,
                principal=principal,
                idempotency_key=idempotency_key,
            )
        except _CommittedApprovalResumeRace:
            with self._session_factory() as session:
                request = _locked_approval_request_binding(session, org_id, approval_request_id)
                current_principal = _locked_current_principal(
                    session,
                    org_id=org_id,
                    principal=principal,
                    permission=Permission.APPROVAL_RESUME,
                    operation="resume",
                )
                _require_approver(request, current_principal)
                idempotency_hash = _idempotency_storage_key(
                    org_id=org_id,
                    approval_request_id=request.id,
                    key=idempotency_key,
                )
                existing = _lookup_resume(session, request, idempotency_hash)
                if existing is not None:
                    return _resume_result_from_row(
                        session,
                        existing,
                        receipt_sealer=self._providers.receipt_sealer,
                        payload_sealer=self._providers.payload_sealer,
                        expected_idempotency_key_hash=idempotency_hash,
                        expected_resumer_actor_hash=sha256_json(current_principal.actor_id),
                        expected_resumer_credential_hash=_current_principal_credential_hash(
                            current_principal
                        ),
                        expected_resumer_role=current_principal.role.value,
                    )
            raise ApprovalHttpError(
                503, "TX_ABORTED", "tx_aborted", "approval resume not observable"
            ) from None
        except ReceiptAlreadyUsedError as exc:
            raise ApprovalHttpError(
                409,
                "RECEIPT_ALREADY_USED",
                "receipt_replayed",
                "approval resume receipt was already used",
                stage="executor",
            ) from exc
        except (ReceiptValidationError, TrustConfigurationError, ManagedTrustError) as exc:
            raise ApprovalHttpError(
                503, "RECEIPT_REFUSED", "receipt_refused", "approval resume receipt refused"
            ) from exc
        except ApprovalHttpError:
            raise
        except (IntegrityError, SQLAlchemyError, RuntimeError) as exc:
            raise ApprovalHttpError(
                503, "TX_ABORTED", "tx_aborted", "approval resume transaction aborted"
            ) from exc


class ApprovalSealingError(RuntimeError):
    """Raised when approval payload custody cannot authenticate or decrypt data."""


@dataclass(frozen=True)
class ApprovalPayloadSealer:
    """Narrow AES-GCM provider for local/test approval payload custody."""

    key_id: str
    key: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.key_id:
            raise ValueError("approval payload sealer key_id is required")
        if len(self.key) != 32:
            raise ValueError("approval payload sealer requires a 32-byte AES-GCM key")

    def seal(self, plaintext: bytes, *, associated_data: bytes) -> Mapping[str, Any]:
        nonce = os.urandom(12)
        ciphertext = AESGCM(self.key).encrypt(nonce, plaintext, associated_data)
        return {
            "schema": "managed-approval-payload-seal/v1",
            "algorithm": "AES-256-GCM",
            "key_id": self.key_id,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
            "associated_data_sha256": hashlib.sha256(associated_data).hexdigest(),
        }

    def unseal(self, envelope: Mapping[str, Any], *, associated_data: bytes) -> bytes:
        if envelope.get("schema") != "managed-approval-payload-seal/v1":
            raise ApprovalSealingError("approval payload seal schema mismatch")
        if envelope.get("algorithm") != "AES-256-GCM":
            raise ApprovalSealingError("approval payload seal algorithm mismatch")
        if envelope.get("key_id") != self.key_id:
            raise ApprovalSealingError("approval payload seal key mismatch")
        if envelope.get("associated_data_sha256") != hashlib.sha256(associated_data).hexdigest():
            raise ApprovalSealingError("approval payload associated data mismatch")
        try:
            nonce = base64.b64decode(str(envelope["nonce"]), validate=True)
            ciphertext = base64.b64decode(str(envelope["ciphertext"]), validate=True)
            plaintext = AESGCM(self.key).decrypt(nonce, ciphertext, associated_data)
        except Exception as exc:
            raise ApprovalSealingError("approval payload authentication failed") from exc
        if hashlib.sha256(plaintext).hexdigest() != envelope.get("plaintext_sha256"):
            raise ApprovalSealingError("approval payload digest mismatch")
        return plaintext


def local_approval_payload_sealer() -> ApprovalPayloadSealer:
    """Deterministic local/test sealer; production must inject real custody."""

    return ApprovalPayloadSealer(
        key_id="local-control-plane-approval-payload-sealer",
        key=hashlib.sha256(b"acgs-control-plane-local-approval-payload-sealer").digest(),
    )


def approval_payload_aad(*, approval_request_id: str, binding: Mapping[str, Any]) -> bytes:
    return _canonical_json_bytes(
        {
            "schema": "managed-approval-payload-aad/v1",
            "approval_request_id": approval_request_id,
            "binding_hash": sha256_json(dict(binding)),
        }
    )


def create_agent_registration_approval_request(
    session: Session,
    *,
    context: ManagedMutationContext,
    args: Mapping[str, Any],
    receipt_row: ManagedDecisionReceipt,
    receipt_id: str,
    policy_version: str,
    policy_head_generation: int,
    trust_epoch: int,
    sealer: ApprovalPayloadSealer,
) -> ApprovalRequest:
    """Persist one immutable request for an ESCALATEd agent registration."""

    if receipt_row.decision != "escalate":
        raise ValueError("approval request can only be created for ESCALATE evidence")
    approval_id = new_id()
    now = utcnow()
    expires_at = _to_aware_utc(receipt_row.expires_at)
    argument_hash = sha256_json(dict(args))
    binding = {
        "schema": "managed-approval-binding/v1",
        "org_id": context.org_id,
        "project_id": context.project_id,
        "environment_id": context.environment_id,
        "approval_request_id": approval_id,
        "requester_actor": context.actor,
        "requester_actor_hash": sha256_json(context.actor),
        "validator_role": context.validator_role,
        "authority": context.authority,
        "approver_role": "org_admin",
        "action": context.action,
        "argument_hash": argument_hash,
        "policy_bundle_id": context.policy_bundle_id,
        "policy_version": policy_version,
        "policy_hash": context.policy_hash,
        "policy_head_generation": policy_head_generation,
        "trust_epoch": trust_epoch,
        "execution_boundary": context.execution_boundary,
        "escalate_receipt_id": receipt_id,
        "escalate_receipt_hash": receipt_row.receipt_hash,
        "escalate_audit_event_hash": receipt_row.audit_event_hash,
        "quorum_threshold": 1,
        "status": "pending",
        "created_at": _canonical_timestamp(now),
        "expires_at": _canonical_timestamp(expires_at),
    }
    sealed_args = sealer.seal(
        _canonical_json_bytes({"schema": "agent-registration-args/v1", "args": dict(args)}),
        associated_data=approval_payload_aad(approval_request_id=approval_id, binding=binding),
    )
    request_hash = sha256_json(binding)
    approval = ApprovalRequest(
        id=approval_id,
        org_id=context.org_id,
        project_id=context.project_id,
        environment_id=context.environment_id,
        action=context.action,
        requester_actor_hash=sha256_json(context.actor),
        validator_role=context.validator_role,
        authority=context.authority,
        approver_role="org_admin",
        argument_hash=argument_hash,
        request_hash=request_hash,
        policy_bundle_id=context.policy_bundle_id,
        policy_version=policy_version,
        policy_hash=context.policy_hash,
        policy_head_generation=policy_head_generation,
        trust_epoch=trust_epoch,
        execution_boundary=context.execution_boundary,
        escalate_receipt_id=receipt_id,
        escalate_receipt_hash=receipt_row.receipt_hash,
        escalate_audit_event_hash=receipt_row.audit_event_hash,
        quorum_threshold=1,
        sealed_arguments=dict(sealed_args),
        aad=binding,
        status="pending",
        created_at=now,
        expires_at=expires_at,
    )
    session.add(approval)
    session.flush()
    return approval


class _CommittedApprovalVoteRace(RuntimeError):
    pass


class _CommittedApprovalVoteRefusalRace(RuntimeError):
    def __init__(self, decision: str) -> None:
        super().__init__(decision)
        self.decision = decision


class _CommittedApprovalResumeRace(RuntimeError):
    pass


def _normalize_idempotency_key(idempotency_key: str | None, *, operation: str) -> str:
    if idempotency_key is None:
        raise ApprovalHttpError(
            400,
            "IDEMPOTENCY_KEY_REQUIRED",
            "idempotency_key_required",
            f"idempotency key is required for {operation}",
        )
    if not _IDEMPOTENCY_RE.fullmatch(idempotency_key):
        raise ApprovalHttpError(
            400,
            "IDEMPOTENCY_KEY_INVALID",
            "idempotency_key_invalid",
            "idempotency key must be 8-200 safe characters",
        )
    return idempotency_key


def _idempotency_storage_key(
    *,
    org_id: str,
    approval_request_id: str,
    key: str,
) -> str:
    return sha256_json(
        {
            "schema": "approval-idempotency/v1",
            "org_id": org_id,
            "approval_request_id": approval_request_id,
            "key": key,
        }
    )


def _locked_approval_request(
    session: Session,
    org_id: str,
    approval_request_id: str,
) -> ApprovalRequest:
    request = _locked_approval_request_binding(session, org_id, approval_request_id)
    _require_approval_request_not_expired(request)
    return request


def _require_approval_request_not_expired(request: ApprovalRequest) -> None:
    if _to_aware_utc(request.expires_at) <= utcnow():
        raise ApprovalHttpError(409, "APPROVAL_EXPIRED", "expired", "approval request expired")


def _locked_approval_request_binding(
    session: Session,
    org_id: str,
    approval_request_id: str,
) -> ApprovalRequest:
    request = session.scalars(
        sa.select(ApprovalRequest)
        .where(ApprovalRequest.org_id == org_id, ApprovalRequest.id == approval_request_id)
        .with_for_update()
    ).one_or_none()
    if request is None:
        raise ApprovalHttpError(404, "APPROVAL_NOT_FOUND", "not_found", "approval not found")
    _verify_approval_request_binding(request)
    return request


def _verify_approval_request_binding(request: ApprovalRequest) -> dict[str, Any]:
    binding = _canonical_approval_binding(request)
    if request.aad != binding:
        raise ApprovalHttpError(
            503,
            "APPROVAL_BINDING_INVALID",
            "tx_aborted",
            "approval request binding does not match locked columns",
        )
    if request.request_hash != sha256_json(binding):
        raise ApprovalHttpError(
            503,
            "APPROVAL_BINDING_INVALID",
            "tx_aborted",
            "approval request hash does not match locked columns",
        )
    expected_aad_digest = hashlib.sha256(
        approval_payload_aad(approval_request_id=request.id, binding=binding)
    ).hexdigest()
    if request.sealed_arguments.get("associated_data_sha256") != expected_aad_digest:
        raise ApprovalHttpError(
            503,
            "APPROVAL_BINDING_INVALID",
            "tx_aborted",
            "approval sealed payload is not bound to the request",
        )
    return binding


def _canonical_approval_binding(request: ApprovalRequest) -> dict[str, Any]:
    if not isinstance(request.aad, dict):
        raise ApprovalHttpError(
            503, "APPROVAL_BINDING_INVALID", "tx_aborted", "approval binding is invalid"
        )
    requester_actor = request.aad.get("requester_actor")
    if not isinstance(requester_actor, str) or sha256_json(requester_actor) != (
        request.requester_actor_hash
    ):
        raise ApprovalHttpError(
            503,
            "APPROVAL_BINDING_INVALID",
            "tx_aborted",
            "approval requester binding is invalid",
        )
    return {
        "schema": "managed-approval-binding/v1",
        "org_id": request.org_id,
        "project_id": request.project_id,
        "environment_id": request.environment_id,
        "approval_request_id": request.id,
        "requester_actor": requester_actor,
        "requester_actor_hash": request.requester_actor_hash,
        "validator_role": request.validator_role,
        "authority": request.authority,
        "approver_role": request.approver_role,
        "action": request.action,
        "argument_hash": request.argument_hash,
        "policy_bundle_id": request.policy_bundle_id,
        "policy_version": request.policy_version,
        "policy_hash": request.policy_hash,
        "policy_head_generation": request.policy_head_generation,
        "trust_epoch": request.trust_epoch,
        "execution_boundary": request.execution_boundary,
        "escalate_receipt_id": request.escalate_receipt_id,
        "escalate_receipt_hash": request.escalate_receipt_hash,
        "escalate_audit_event_hash": request.escalate_audit_event_hash,
        "quorum_threshold": request.quorum_threshold,
        "status": request.status,
        "created_at": _canonical_timestamp(request.created_at),
        "expires_at": _canonical_timestamp(request.expires_at),
    }


def _verify_frozen_policy_locked(session: Session, request: ApprovalRequest) -> PolicyVersion:
    head = session.scalars(
        sa.select(EnvironmentPolicyHead)
        .where(
            EnvironmentPolicyHead.org_id == request.org_id,
            EnvironmentPolicyHead.project_id == request.project_id,
            EnvironmentPolicyHead.environment_id == request.environment_id,
            EnvironmentPolicyHead.status == "active",
        )
        .with_for_update()
    ).one_or_none()
    if (
        head is None
        or head.generation != request.policy_head_generation
        or head.active_policy_version_id != request.policy_bundle_id
    ):
        raise ApprovalHttpError(
            409,
            "APPROVAL_POLICY_STALE",
            "conflict",
            "approval request policy is no longer current",
        )
    version = session.get(PolicyVersion, head.active_policy_version_id, with_for_update=True)
    if (
        version is None
        or version.version != request.policy_version
        or version.content_hash != request.policy_hash
    ):
        raise ApprovalHttpError(
            409,
            "APPROVAL_POLICY_STALE",
            "conflict",
            "approval request policy version is no longer current",
        )
    _verify_envelope(
        session,
        version.canonical_envelope,
        expected_org_id=request.org_id,
        expected_project_id=request.project_id,
        expected_environment_id=request.environment_id,
        expected_policy_id=version.policy_id,
        expected_version=version.version,
        expected_document=version.document,
    )
    return version


def _requester_actor_from_binding(request: ApprovalRequest) -> str:
    return str(_verify_approval_request_binding(request)["requester_actor"])


def _require_active_requester(session: Session, request: ApprovalRequest) -> str:
    actor = _requester_actor_from_binding(request)
    if not actor.startswith("user:"):
        raise ApprovalHttpError(
            409,
            "APPROVAL_REQUESTER_INACTIVE",
            "conflict",
            "approval requester is no longer active",
        )
    user_id = actor.removeprefix("user:")
    user = session.scalars(
        sa.select(User).where(User.org_id == request.org_id, User.id == user_id).with_for_update()
    ).one_or_none()
    if user is None or not user.active:
        raise ApprovalHttpError(
            409,
            "APPROVAL_REQUESTER_INACTIVE",
            "conflict",
            "approval requester is no longer active",
        )
    try:
        role = Role(user.role)
    except ValueError as exc:
        raise ApprovalHttpError(
            409,
            "APPROVAL_REQUESTER_UNAUTHORIZED",
            "conflict",
            "approval requester role is no longer authorized",
        ) from exc
    if not role_allows(role, Permission.AGENT_REGISTER):
        raise ApprovalHttpError(
            409,
            "APPROVAL_REQUESTER_UNAUTHORIZED",
            "conflict",
            "approval requester can no longer register agents",
        )
    return actor


def _verify_resume_preconditions(session: Session, request: ApprovalRequest) -> str:
    if _to_aware_utc(request.expires_at) <= utcnow():
        raise ApprovalHttpError(409, "APPROVAL_EXPIRED", "expired", "approval request expired")
    _verify_frozen_policy_locked(session, request)
    try:
        active_epoch = active_trust_epoch_for_scope(
            session,
            ReceiptTrustScope(
                request.org_id,
                request.project_id,
                request.environment_id,
                DECISION_RECEIPT_PURPOSE,
            ),
        )
    except ManagedTrustError as exc:
        raise ApprovalHttpError(
            409,
            "APPROVAL_TRUST_STALE",
            "conflict",
            "approval request trust root is no longer active",
        ) from exc
    if active_epoch != request.trust_epoch:
        raise ApprovalHttpError(
            409,
            "APPROVAL_TRUST_STALE",
            "conflict",
            "approval request trust epoch is no longer current",
        )
    return _require_active_requester(session, request)


def _require_approver(request: ApprovalRequest, principal: Principal) -> None:
    if principal.role.value != request.approver_role:
        raise ApprovalHttpError(
            403,
            "APPROVAL_ROLE_DENIED",
            "forbidden",
            "principal lacks the required approver role",
        )
    if sha256_json(principal.actor_id) == request.requester_actor_hash:
        raise ApprovalHttpError(
            403,
            "APPROVAL_SELF_APPROVAL_DENIED",
            "forbidden",
            "requester cannot approve or resume their own request",
        )


def _locked_current_principal(
    session: Session,
    *,
    org_id: str,
    principal: Principal,
    permission: Permission,
    operation: str,
) -> Principal:
    user = session.scalars(
        sa.select(User).where(User.org_id == org_id, User.id == principal.user_id).with_for_update()
    ).one_or_none()
    if user is None or not user.active:
        raise ApprovalHttpError(
            409,
            "APPROVAL_CALLER_STALE",
            "conflict",
            f"approval {operation} caller is no longer active",
        )
    if principal.api_key_hash is None or user.api_key_hash != principal.api_key_hash:
        raise ApprovalHttpError(
            409,
            "APPROVAL_CREDENTIAL_STALE",
            "conflict",
            f"approval {operation} credential is no longer current",
        )
    try:
        current_role = Role(user.role)
    except ValueError as exc:
        raise ApprovalHttpError(
            403,
            "APPROVAL_ROLE_DENIED",
            "forbidden",
            f"approval {operation} caller role is no longer authorized",
        ) from exc
    if current_role != principal.role or not role_allows(current_role, permission):
        raise ApprovalHttpError(
            403,
            "APPROVAL_ROLE_DENIED",
            "forbidden",
            f"approval {operation} caller role is no longer authorized",
        )
    return Principal(
        user_id=user.id,
        org_id=user.org_id,
        name=user.name,
        role=current_role,
        api_key_hash=user.api_key_hash,
    )


def _current_principal_credential_hash(principal: Principal) -> str:
    if principal.api_key_hash is None:
        raise ApprovalHttpError(
            409,
            "APPROVAL_CREDENTIAL_STALE",
            "conflict",
            "approval credential is no longer current",
        )
    return principal.api_key_hash


def _verify_vote_preconditions_locked(
    session: Session,
    *,
    org_id: str,
    approval_request_id: str,
) -> None:
    request = _locked_approval_request(session, org_id, approval_request_id)
    _verify_frozen_policy_locked(session, request)


def _lookup_vote(
    session: Session,
    request: ApprovalRequest,
    idempotency_hash: str,
) -> ApprovalVote | None:
    return session.scalars(
        sa.select(ApprovalVote)
        .where(
            ApprovalVote.org_id == request.org_id,
            ApprovalVote.approval_request_id == request.id,
            ApprovalVote.idempotency_key_hash == idempotency_hash,
        )
        .with_for_update()
    ).one_or_none()


def _lookup_vote_refusal(
    session: Session,
    request: ApprovalRequest,
    idempotency_key: str,
    args: Mapping[str, Any],
) -> ManagedDecisionReceipt | None:
    rows = list(
        session.scalars(
            sa.select(ManagedDecisionReceipt)
            .where(
                ManagedDecisionReceipt.org_id == request.org_id,
                ManagedDecisionReceipt.project_id == request.project_id,
                ManagedDecisionReceipt.environment_id == request.environment_id,
                ManagedDecisionReceipt.proposed_action == CONTROL_PLANE_APPROVAL_VOTE_ACTION,
                ManagedDecisionReceipt.decision.in_(("deny", "escalate")),
                ManagedDecisionReceipt.projection["request_id_hash"].as_string()
                == sha256_json(idempotency_key),
            )
            .order_by(ManagedDecisionReceipt.created_at.asc())
            .with_for_update()
        )
    )
    if not rows:
        return None
    argument_hash = sha256_json(dict(args))
    for row in rows:
        if row.argument_hash == argument_hash:
            return row
    raise ApprovalHttpError(
        409,
        "IDEMPOTENCY_CONFLICT",
        "conflict",
        "idempotency key was already used for a different approval vote",
    )


def _approval_error_for_decision(decision: str) -> ApprovalHttpError:
    if decision == Decision.ESCALATE.value:
        return ApprovalHttpError(
            202,
            "ESCALATE_PENDING",
            "pending_approval",
            "approval vote requires additional approval",
        )
    return ApprovalHttpError(403, "POLICY_DENIED", "denied", "approval vote denied by policy")


def _lookup_outcome(session: Session, request: ApprovalRequest) -> ApprovalOutcome | None:
    return session.scalars(
        sa.select(ApprovalOutcome)
        .where(
            ApprovalOutcome.org_id == request.org_id,
            ApprovalOutcome.project_id == request.project_id,
            ApprovalOutcome.environment_id == request.environment_id,
            ApprovalOutcome.approval_request_id == request.id,
        )
        .with_for_update()
    ).one_or_none()


def _lookup_resume(
    session: Session,
    request: ApprovalRequest,
    idempotency_hash: str,
) -> ApprovalResumeAuthorization | None:
    return session.scalars(
        sa.select(ApprovalResumeAuthorization)
        .where(
            ApprovalResumeAuthorization.org_id == request.org_id,
            ApprovalResumeAuthorization.approval_request_id == request.id,
            ApprovalResumeAuthorization.idempotency_key_hash == idempotency_hash,
        )
        .with_for_update()
    ).one_or_none()


def _lookup_any_resume(
    session: Session,
    request: ApprovalRequest,
) -> ApprovalResumeAuthorization | None:
    return session.scalars(
        sa.select(ApprovalResumeAuthorization)
        .where(
            ApprovalResumeAuthorization.org_id == request.org_id,
            ApprovalResumeAuthorization.project_id == request.project_id,
            ApprovalResumeAuthorization.environment_id == request.environment_id,
            ApprovalResumeAuthorization.approval_request_id == request.id,
        )
        .with_for_update()
    ).one_or_none()


def _vote_hash(
    *,
    request: ApprovalRequest,
    principal: Principal,
    args: Mapping[str, Any],
) -> str:
    return _vote_hash_from_parts(
        approval_request_id=request.id,
        request_hash=request.request_hash,
        approver_actor_hash=sha256_json(principal.actor_id),
        approver_credential_hash=_current_principal_credential_hash(principal),
        decision=str(args["decision"]),
    )


def _vote_hash_from_parts(
    *,
    approval_request_id: str,
    request_hash: str,
    approver_actor_hash: str,
    approver_credential_hash: str,
    decision: str,
) -> str:
    return sha256_json(
        {
            "schema": "approval-vote/v1",
            "approval_request_id": approval_request_id,
            "request_hash": request_hash,
            "approver_actor_hash": approver_actor_hash,
            "approver_credential_hash": approver_credential_hash,
            "decision": decision,
        }
    )


def _assert_same_vote(
    vote: ApprovalVote,
    *,
    request: ApprovalRequest,
    principal: Principal,
    args: Mapping[str, Any],
) -> None:
    if vote.vote_hash != _vote_hash(request=request, principal=principal, args=args):
        raise ApprovalHttpError(
            409,
            "IDEMPOTENCY_CONFLICT",
            "conflict",
            "idempotency key was already used for a different approval vote",
        )


def _maybe_record_outcome(session: Session, request: ApprovalRequest) -> ApprovalOutcome | None:
    existing = _lookup_outcome(session, request)
    if existing is not None:
        return existing
    votes = list(
        session.scalars(
            sa.select(ApprovalVote)
            .where(
                ApprovalVote.org_id == request.org_id,
                ApprovalVote.project_id == request.project_id,
                ApprovalVote.environment_id == request.environment_id,
                ApprovalVote.approval_request_id == request.id,
            )
            .order_by(ApprovalVote.created_at.asc())
            .with_for_update()
        )
    )
    if any(vote.decision == "reject" for vote in votes):
        outcome_value = "rejected"
    elif len([vote for vote in votes if vote.decision == "approve"]) >= request.quorum_threshold:
        outcome_value = "approved"
    else:
        return None
    approver_hashes = sorted(vote.approver_actor_hash for vote in votes)
    outcome = ApprovalOutcome(
        id=new_id(),
        org_id=request.org_id,
        project_id=request.project_id,
        environment_id=request.environment_id,
        approval_request_id=request.id,
        outcome=outcome_value,
        quorum_digest=sha256_json(
            {
                "schema": "approval-quorum/v1",
                "threshold": request.quorum_threshold,
                "votes": [vote.vote_hash for vote in votes],
            }
        ),
        approver_set_hash=sha256_json(approver_hashes),
    )
    session.add(outcome)
    session.flush()
    return outcome


def _vote_result_from_row(
    session: Session,
    request: ApprovalRequest,
    vote: ApprovalVote,
    *,
    receipt_sealer: AesGcmReceiptArtifactSealer,
    payload_sealer: ApprovalPayloadSealer,
    expected_idempotency_key_hash: str,
    expected_actor_hash: str,
    expected_credential_hash: str,
    expected_role: str,
) -> ApprovalVoteResult:
    if (
        vote.idempotency_key_hash != expected_idempotency_key_hash
        or vote.approver_actor_hash != expected_actor_hash
        or vote.approver_credential_hash != expected_credential_hash
        or vote.approver_role != expected_role
    ):
        raise _resume_replay_integrity_error("approval vote replay caller mismatch")
    evidence = _validate_approval_vote_evidence(
        session,
        request=request,
        vote=vote,
        receipt_sealer=receipt_sealer,
        historical_idempotency_replay=True,
    )
    if (
        evidence.sealed_receipt.request_id is None
        or _idempotency_storage_key(
            org_id=request.org_id,
            approval_request_id=request.id,
            key=evidence.sealed_receipt.request_id,
        )
        != expected_idempotency_key_hash
    ):
        raise _resume_replay_integrity_error("approval vote sealed request id mismatch")
    artifact = _validated_vote_replay_artifact(
        payload_sealer=payload_sealer,
        request=request,
        vote=vote,
        evidence=evidence,
    )
    return _vote_result_from_response_payload(
        _artifact_mapping(artifact, "response", detail="approval vote replay response invalid")
    )


def _vote_response_payload(
    *,
    approval_request_id: str,
    decision: str,
    outcome: str | None,
    vote_hash: str,
    receipt_id: str,
) -> dict[str, Any]:
    return {
        "schema": "approval-vote-response/v1",
        "approval_request_id": approval_request_id,
        "decision": decision,
        "outcome": outcome,
        "vote_hash": vote_hash,
        "receipt_id": receipt_id,
    }


def _vote_result_from_response_payload(payload: Mapping[str, Any]) -> ApprovalVoteResult:
    expected_keys = {
        "schema",
        "approval_request_id",
        "decision",
        "outcome",
        "vote_hash",
        "receipt_id",
    }
    if set(payload) != expected_keys or payload.get("schema") != "approval-vote-response/v1":
        raise _resume_replay_integrity_error("approval vote stored response invalid")
    outcome = payload["outcome"]
    if outcome is not None and not isinstance(outcome, str):
        raise _resume_replay_integrity_error("approval vote stored outcome invalid")
    return ApprovalVoteResult(
        approval_request_id=str(payload["approval_request_id"]),
        decision=str(payload["decision"]),
        outcome=outcome,
        vote_hash=str(payload["vote_hash"]),
        receipt_id=str(payload["receipt_id"]),
    )


def _execute_resume_under_locks(
    session_factory: sessionmaker[Session],
    *,
    issuer: ManagedPlatformIssuer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
    payload_sealer: ApprovalPayloadSealer,
    org_id: str,
    approval_request_id: str,
    principal: Principal,
    idempotency_key: str,
) -> ApprovalResumeResult:
    with session_factory() as session:
        with session.begin():
            if session.bind is not None and session.bind.dialect.name == "postgresql":
                session.execute(sa.text("SET CONSTRAINTS ALL DEFERRED"))
            request = _locked_approval_request_binding(session, org_id, approval_request_id)
            current_principal = _locked_current_principal(
                session,
                org_id=org_id,
                principal=principal,
                permission=Permission.APPROVAL_RESUME,
                operation="resume",
            )
            _require_approver(request, current_principal)
            idempotency_hash = _idempotency_storage_key(
                org_id=org_id,
                approval_request_id=request.id,
                key=idempotency_key,
            )
            existing = _lookup_resume(session, request, idempotency_hash)
            if existing is not None:
                return _resume_result_from_row(
                    session,
                    existing,
                    receipt_sealer=receipt_sealer,
                    payload_sealer=payload_sealer,
                    expected_idempotency_key_hash=idempotency_hash,
                    expected_resumer_actor_hash=sha256_json(current_principal.actor_id),
                    expected_resumer_credential_hash=_current_principal_credential_hash(
                        current_principal
                    ),
                    expected_resumer_role=current_principal.role.value,
                )
            if _lookup_any_resume(session, request) is not None:
                raise ApprovalHttpError(
                    409,
                    "APPROVAL_ALREADY_RESUMED",
                    "conflict",
                    "approval request was already resumed",
                    stage="tx",
                )
            requester_actor = _verify_resume_preconditions(session, request)
            args = _unseal_agent_args(request, payload_sealer)
            _validate_source_escalate_evidence(
                session,
                request=request,
                args=args,
                receipt_sealer=receipt_sealer,
            )
            authorization = _recompute_approval_authorization(
                session,
                request=request,
                receipt_sealer=receipt_sealer,
            )
            context = ManagedMutationContext(
                org_id=request.org_id,
                project_id=request.project_id,
                environment_id=request.environment_id,
                actor=requester_actor,
                action=CONTROL_PLANE_AGENT_CREATE_ACTION,
                execution_boundary=request.execution_boundary,
                policy_bundle_id=request.policy_bundle_id,
                policy_hash=request.policy_hash,
                validator_role=request.validator_role,
                authority=request.authority,
            )
            record = DecisionRecord(
                decision=Decision.ALLOW,
                tool=context.action,
                actor=context.actor,
                goal="resume approved agent registration",
                reason="approval quorum authorized parked agent registration",
                matched_rules=("approval-resume",),
                policy_version=request.policy_version,
                event_id=new_id(),
                argument_hash=sha256_json(args),
                path=("control-plane", "approvals", "resume"),
                transformed_args=dict(args),
                state_hash=sha256_json({"approval_request_hash": request.request_hash}),
            )
            audit_hash = _decision_audit_hash(record)
            context = replace(context, expected_audit_hash=audit_hash)
            receipt = _issue_receipt(
                issuer=issuer,
                context=context,
                record=record,
                audit_hash=audit_hash,
                request_id=idempotency_key,
                trust_epoch=request.trust_epoch,
                approval_chain_summary=authorization.summary,
            )
            canonical_boundary = _validated_execution_boundary(cast(Any, context))
            attempt = _reserve_mutation_attempt_row(session, context=context, receipt=receipt)
            ledger = _SqlReceiptConsumptionLedger(
                session,
                context=context,
                execution_boundary=canonical_boundary,
                assurance_class="native",
                receipt_sealer=receipt_sealer,
            )

            def protected_effect(**verified_args: Any) -> dict[str, Any]:
                if verified_args != args:
                    raise ReceiptValidationError(
                        "approval resume arguments changed before SQL execution"
                    )
                agent = AgentRecord(
                    id=new_id(),
                    org_id=request.org_id,
                    project_id=request.project_id,
                    environment_id=request.environment_id,
                    name=str(verified_args["name"]),
                    description=str(verified_args["description"]),
                    trust_tier=str(verified_args["trust_tier"]),
                    allowed_tools=list(verified_args["allowed_tools"]),
                    status="active",
                )
                session.add(agent)
                session.flush()
                return {
                    "agent_id": agent.id,
                    "org_id": agent.org_id,
                    "project_id_hash": sha256_json(agent.project_id or ""),
                    "environment_id_hash": sha256_json(agent.environment_id or ""),
                    "name_hash": sha256_json(agent.name),
                    "status": agent.status,
                    "created_at": agent.created_at.isoformat(),
                }

            result = execute_with_receipt(
                protected_effect,
                args,
                receipt,
                expected_tenant_id=context.org_id,
                expected_execution_boundary=canonical_boundary,
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
                require_signature=True,
                require_expiry=True,
                trust_registry=SqlReceiptTrustRegistry(session, lock_rows=True),
                trust_purpose=DECISION_RECEIPT_PURPOSE,
                max_clock_skew_seconds=DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS,
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
                execution_boundary=canonical_boundary,
                assurance_class="native",
            )
            _enqueue_outbox(
                session,
                context=context,
                receipt_row=receipt_row,
                event=event,
                result_hash=result_hash,
                assurance_class="native",
            )
            attempt.status = "succeeded"
            attempt.updated_at = utcnow()
            agent = session.get(AgentRecord, result["agent_id"], with_for_update=True)
            if agent is None:
                raise RuntimeError("approval resume committed without agent row")
            response_payload = _resume_response_payload(
                approval_request_id=request.id,
                agent=agent,
                receipt_id=receipt_row.receipt_id,
            )
            result_payload = dict(result)
            resume = ApprovalResumeAuthorization(
                id=new_id(),
                org_id=request.org_id,
                project_id=request.project_id,
                environment_id=request.environment_id,
                approval_request_id=request.id,
                resumed_agent_id=agent.id,
                resumer_actor_hash=sha256_json(current_principal.actor_id),
                resumer_credential_hash=_current_principal_credential_hash(current_principal),
                resumer_role=current_principal.role.value,
                idempotency_key_hash=idempotency_hash,
                resume_receipt_id=receipt_row.receipt_id,
                resume_receipt_hash=receipt_row.receipt_hash,
                resume_audit_event_hash=event.event_hash,
                approval_chain_hash=sha256_json(receipt.approval_chain_summary),
                resume_argument_hash=sha256_json(args),
                resume_result_hash=result_hash,
                resume_result=result_payload,
                resume_response_hash=sha256_json(response_payload),
                resume_response=response_payload,
                resume_replay_seal={},
            )
            resume.resume_replay_seal = _seal_resume_replay_artifact(
                payload_sealer=payload_sealer,
                request=request,
                row=resume,
                receipt=receipt_row,
                event=event,
                outbox=_single_outbox_for_event(session, receipt=receipt_row, event=event),
                mutation_attempt=attempt,
                args=args,
                result_payload=result_payload,
                response_payload=response_payload,
            )
            session.add(resume)
            return _resume_result_from_response_payload(response_payload)


def _recompute_approval_authorization(
    session: Session,
    *,
    request: ApprovalRequest,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> ApprovalAuthorizationState:
    outcome = _lookup_outcome(session, request)
    votes = tuple(
        session.scalars(
            sa.select(ApprovalVote)
            .where(
                ApprovalVote.org_id == request.org_id,
                ApprovalVote.project_id == request.project_id,
                ApprovalVote.environment_id == request.environment_id,
                ApprovalVote.approval_request_id == request.id,
            )
            .order_by(ApprovalVote.created_at.asc())
            .with_for_update()
        )
    )
    if outcome is None:
        raise ApprovalHttpError(
            409,
            "APPROVAL_NOT_APPROVED",
            "conflict",
            "approval request is not approved",
        )
    if not votes:
        raise _resume_replay_integrity_error("approval votes missing")
    for vote in votes:
        _validate_approval_vote_evidence(
            session,
            request=request,
            vote=vote,
            receipt_sealer=receipt_sealer,
            historical_idempotency_replay=False,
        )
    recomputed_vote_hashes = [vote.vote_hash for vote in votes]
    approver_hashes = sorted(vote.approver_actor_hash for vote in votes)
    if len(set(approver_hashes)) != len(approver_hashes):
        raise _resume_replay_integrity_error("approval duplicate approver")
    quorum_digest = sha256_json(
        {
            "schema": "approval-quorum/v1",
            "threshold": request.quorum_threshold,
            "votes": recomputed_vote_hashes,
        }
    )
    approver_set_hash = sha256_json(approver_hashes)
    if any(vote.decision == "reject" for vote in votes):
        recomputed_outcome = "rejected"
    elif len([vote for vote in votes if vote.decision == "approve"]) >= request.quorum_threshold:
        recomputed_outcome = "approved"
    else:
        recomputed_outcome = ""
    if (
        recomputed_outcome != "approved"
        or outcome.outcome != "approved"
        or outcome.quorum_digest != quorum_digest
        or outcome.approver_set_hash != approver_set_hash
    ):
        raise _resume_replay_integrity_error("approval outcome does not match recomputed votes")
    summary = _approval_chain_summary(
        request=request,
        outcome=outcome,
        proposer=_requester_actor_from_binding(request),
        validator_id=APPROVAL_AUTHORITY,
    )
    if summary["quorum_digest"] != quorum_digest or summary["approver_set_hash"] != (
        approver_set_hash
    ):
        raise _resume_replay_integrity_error("approval summary does not match recomputed quorum")
    return ApprovalAuthorizationState(outcome=outcome, votes=votes, summary=summary)


def _validate_approval_vote_evidence(
    session: Session,
    *,
    request: ApprovalRequest,
    vote: ApprovalVote,
    receipt_sealer: AesGcmReceiptArtifactSealer,
    historical_idempotency_replay: bool,
) -> _VoteEvidence:
    args = {
        "approval_request_id": request.id,
        "decision": vote.decision,
        "request_hash": request.request_hash,
        "approver_credential_hash": vote.approver_credential_hash,
    }
    if vote.approver_role != request.approver_role or vote.vote_hash != _vote_hash_from_parts(
        approval_request_id=request.id,
        request_hash=request.request_hash,
        approver_actor_hash=vote.approver_actor_hash,
        approver_credential_hash=vote.approver_credential_hash,
        decision=vote.decision,
    ):
        raise _resume_replay_integrity_error("approval vote row does not match request")
    receipt = _bound_vote_receipt(session, request=request, vote=vote)
    if (
        receipt.proposed_action != CONTROL_PLANE_APPROVAL_VOTE_ACTION
        or receipt.argument_hash != sha256_json(args)
        or receipt.decision != Decision.ALLOW.value
        or sha256_json(receipt.actor) != vote.approver_actor_hash
    ):
        raise _resume_replay_integrity_error("approval vote receipt does not match vote")
    _require_current_vote_approver(
        session,
        request=request,
        vote=vote,
        voter_actor=receipt.actor,
    )
    _validate_managed_execution_evidence(
        session,
        org_id=request.org_id,
        project_id=request.project_id,
        environment_id=request.environment_id,
        receipt=receipt,
        missing_consumption_detail="approval vote consumption missing",
        invalid_attempt_detail="approval vote mutation attempt invalid",
    )
    context = ManagedMutationContext(
        org_id=request.org_id,
        project_id=request.project_id,
        environment_id=request.environment_id,
        actor=receipt.actor,
        action=CONTROL_PLANE_APPROVAL_VOTE_ACTION,
        execution_boundary=managed_mutation_execution_boundary(
            org_id=request.org_id,
            project_id=request.project_id,
            environment_id=request.environment_id,
            action=CONTROL_PLANE_APPROVAL_VOTE_ACTION,
        ),
        policy_bundle_id=receipt.policy_bundle_id,
        policy_hash=receipt.policy_hash,
        validator_role=APPROVAL_VALIDATOR_ROLE,
        authority=APPROVAL_AUTHORITY,
        expected_audit_hash=receipt.audit_event_hash,
    )
    sealed_receipt = _validate_managed_receipt_artifact(
        session,
        receipt_row=receipt,
        context=context,
        args=args,
        allowed_decisions=frozenset({Decision.ALLOW.value}),
        receipt_sealer=receipt_sealer,
        failure_detail="approval vote receipt invalid",
        historical_idempotency_replay=historical_idempotency_replay,
    )
    event = _single_event_for_receipt(session, receipt)
    result_hash = event.payload.get("result_hash")
    if not isinstance(result_hash, str):
        raise _resume_replay_integrity_error("approval vote event result hash missing")
    _verify_managed_event_projection(
        session,
        receipt=receipt,
        event=event,
        expected_result_hash=result_hash,
        execution_boundary=context.execution_boundary,
        receipt_sealer=receipt_sealer,
    )
    outbox = _single_outbox_for_event(session, receipt=receipt, event=event)
    _verify_managed_outbox_projection(
        receipt=receipt,
        event=event,
        outbox=outbox,
        expected_result_hash=result_hash,
    )
    return _VoteEvidence(
        receipt=receipt,
        sealed_receipt=sealed_receipt,
        event=event,
        outbox=outbox,
        result_hash=result_hash,
    )


def _validate_approval_vote_refusal_evidence(
    session: Session,
    *,
    request: ApprovalRequest,
    receipt: ManagedDecisionReceipt,
    idempotency_key: str,
    args: Mapping[str, Any],
    expected_actor: str,
    receipt_sealer: AesGcmReceiptArtifactSealer,
    historical_idempotency_replay: bool,
) -> None:
    if (
        receipt.proposed_action != CONTROL_PLANE_APPROVAL_VOTE_ACTION
        or receipt.argument_hash != sha256_json(dict(args))
        or receipt.actor != expected_actor
        or receipt.decision not in {Decision.DENY.value, Decision.ESCALATE.value}
        or receipt.projection.get("request_id_hash") != sha256_json(idempotency_key)
    ):
        raise _resume_replay_integrity_error("approval vote refusal receipt does not match replay")
    context = ManagedMutationContext(
        org_id=request.org_id,
        project_id=request.project_id,
        environment_id=request.environment_id,
        actor=receipt.actor,
        action=CONTROL_PLANE_APPROVAL_VOTE_ACTION,
        execution_boundary=managed_mutation_execution_boundary(
            org_id=request.org_id,
            project_id=request.project_id,
            environment_id=request.environment_id,
            action=CONTROL_PLANE_APPROVAL_VOTE_ACTION,
        ),
        policy_bundle_id=receipt.policy_bundle_id,
        policy_hash=receipt.policy_hash,
        validator_role=APPROVAL_VALIDATOR_ROLE,
        authority=APPROVAL_AUTHORITY,
        expected_audit_hash=receipt.audit_event_hash,
    )
    _validate_managed_receipt_artifact(
        session,
        receipt_row=receipt,
        context=context,
        args=args,
        allowed_decisions=frozenset({Decision.DENY.value, Decision.ESCALATE.value}),
        receipt_sealer=receipt_sealer,
        failure_detail="approval vote refusal receipt invalid",
        historical_idempotency_replay=historical_idempotency_replay,
    )
    _validate_vote_refusal_zero_execution_evidence(session, request=request, receipt=receipt)
    expected_result_hash = safe_result_hash(
        {"status": "non_executable", "decision": receipt.decision}
    )
    event = _single_event_for_receipt(session, receipt)
    _verify_managed_event_projection(
        session,
        receipt=receipt,
        event=event,
        expected_result_hash=expected_result_hash,
        execution_boundary=context.execution_boundary,
        receipt_sealer=receipt_sealer,
    )
    outbox = _single_outbox_for_event(session, receipt=receipt, event=event)
    _verify_managed_outbox_projection(
        receipt=receipt,
        event=event,
        outbox=outbox,
        expected_result_hash=expected_result_hash,
    )


def _validate_vote_refusal_zero_execution_evidence(
    session: Session,
    *,
    request: ApprovalRequest,
    receipt: ManagedDecisionReceipt,
) -> None:
    if receipt.org_id != request.org_id:
        raise _resume_replay_integrity_error("approval vote refusal receipt scope mismatch")
    if (
        session.scalars(
            sa.select(ManagedReceiptConsumption.id).where(
                ManagedReceiptConsumption.org_id == receipt.org_id,
                sa.or_(
                    ManagedReceiptConsumption.managed_receipt_id == receipt.id,
                    ManagedReceiptConsumption.receipt_hash == receipt.receipt_hash,
                    ManagedReceiptConsumption.audit_event_hash == receipt.audit_event_hash,
                ),
            )
        ).first()
        is not None
    ):
        raise _resume_replay_integrity_error("approval vote refusal receipt was consumed")
    if (
        session.scalars(
            sa.select(ManagedMutationAttempt.id).where(
                ManagedMutationAttempt.org_id == receipt.org_id,
                sa.or_(
                    ManagedMutationAttempt.receipt_hash == receipt.receipt_hash,
                    ManagedMutationAttempt.audit_event_hash == receipt.audit_event_hash,
                ),
            )
        ).first()
        is not None
    ):
        raise _resume_replay_integrity_error("approval vote refusal has mutation attempt")


def _bound_vote_receipt(
    session: Session,
    *,
    request: ApprovalRequest,
    vote: ApprovalVote,
) -> ManagedDecisionReceipt:
    if not vote.vote_receipt_id or not vote.vote_receipt_hash or not vote.vote_audit_event_hash:
        raise _resume_replay_integrity_error("approval vote receipt binding missing")
    receipt = session.scalars(
        sa.select(ManagedDecisionReceipt)
        .where(
            ManagedDecisionReceipt.org_id == request.org_id,
            ManagedDecisionReceipt.project_id == request.project_id,
            ManagedDecisionReceipt.environment_id == request.environment_id,
            ManagedDecisionReceipt.receipt_id == vote.vote_receipt_id,
            ManagedDecisionReceipt.receipt_hash == vote.vote_receipt_hash,
            ManagedDecisionReceipt.audit_event_hash == vote.vote_audit_event_hash,
        )
        .with_for_update()
    ).one_or_none()
    if receipt is None:
        raise _resume_replay_integrity_error("approval vote receipt missing")
    return receipt


def _validate_managed_execution_evidence(
    session: Session,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    receipt: ManagedDecisionReceipt,
    missing_consumption_detail: str,
    invalid_attempt_detail: str,
) -> None:
    consumptions = list(
        session.scalars(
            sa.select(ManagedReceiptConsumption)
            .where(
                ManagedReceiptConsumption.org_id == org_id,
                ManagedReceiptConsumption.project_id == project_id,
                ManagedReceiptConsumption.environment_id == environment_id,
                ManagedReceiptConsumption.managed_receipt_id == receipt.id,
                ManagedReceiptConsumption.receipt_hash == receipt.receipt_hash,
                ManagedReceiptConsumption.audit_event_hash == receipt.audit_event_hash,
            )
            .with_for_update()
        )
    )
    if len(consumptions) != 1:
        raise _resume_replay_integrity_error(missing_consumption_detail)
    attempts = list(
        session.scalars(
            sa.select(ManagedMutationAttempt)
            .where(
                ManagedMutationAttempt.org_id == org_id,
                ManagedMutationAttempt.project_id == project_id,
                ManagedMutationAttempt.environment_id == environment_id,
                ManagedMutationAttempt.receipt_hash == receipt.receipt_hash,
                ManagedMutationAttempt.audit_event_hash == receipt.audit_event_hash,
                ManagedMutationAttempt.action == receipt.proposed_action,
                ManagedMutationAttempt.actor_hash == sha256_json(receipt.actor),
                ManagedMutationAttempt.argument_hash == receipt.argument_hash,
            )
            .with_for_update()
        )
    )
    if len(attempts) != 1:
        raise _resume_replay_integrity_error(invalid_attempt_detail)
    attempt = attempts[0]
    if (
        attempt.status != "succeeded"
        or attempt.failure_class_hash is not None
        or attempt.failure_digest is not None
    ):
        raise _resume_replay_integrity_error(invalid_attempt_detail)


def _require_current_vote_approver(
    session: Session,
    *,
    request: ApprovalRequest,
    vote: ApprovalVote,
    voter_actor: str,
) -> None:
    if not voter_actor.startswith("user:"):
        raise _approver_stale_error("approval voter actor is not a user")
    if sha256_json(voter_actor) == request.requester_actor_hash:
        raise _approver_stale_error("approval voter is the requester")
    if voter_actor == APPROVAL_AUTHORITY or voter_actor == request.validator_role:
        raise _approver_stale_error("approval voter cannot be the validator")
    user_id = voter_actor.removeprefix("user:")
    user = session.scalars(
        sa.select(User).where(User.org_id == request.org_id, User.id == user_id).with_for_update()
    ).one_or_none()
    if user is None or not user.active:
        raise _approver_stale_error("approval voter is no longer active")
    if user.api_key_hash != vote.approver_credential_hash:
        raise _approver_stale_error("approval voter credential changed")
    if user.role != vote.approver_role or user.role != request.approver_role:
        raise _approver_stale_error("approval voter role changed")
    try:
        role = Role(user.role)
    except ValueError as exc:
        raise _approver_stale_error("approval voter role is invalid") from exc
    if not role_allows(role, Permission.APPROVAL_VOTE):
        raise _approver_stale_error("approval voter no longer has approval permission")


def _approver_stale_error(detail: str) -> ApprovalHttpError:
    return ApprovalHttpError(
        409,
        "APPROVAL_APPROVER_STALE",
        "conflict",
        detail,
    )


def _validate_source_escalate_evidence(
    session: Session,
    *,
    request: ApprovalRequest,
    args: Mapping[str, Any],
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    receipt = session.scalars(
        sa.select(ManagedDecisionReceipt)
        .where(
            ManagedDecisionReceipt.org_id == request.org_id,
            ManagedDecisionReceipt.project_id == request.project_id,
            ManagedDecisionReceipt.environment_id == request.environment_id,
            ManagedDecisionReceipt.receipt_id == request.escalate_receipt_id,
            ManagedDecisionReceipt.receipt_hash == request.escalate_receipt_hash,
            ManagedDecisionReceipt.audit_event_hash == request.escalate_audit_event_hash,
            ManagedDecisionReceipt.proposed_action == request.action,
            ManagedDecisionReceipt.decision == Decision.ESCALATE.value,
        )
        .with_for_update()
    ).one_or_none()
    if receipt is None:
        raise _resume_replay_integrity_error("source escalate receipt missing")
    context = ManagedMutationContext(
        org_id=request.org_id,
        project_id=request.project_id,
        environment_id=request.environment_id,
        actor=_requester_actor_from_binding(request),
        action=request.action,
        execution_boundary=request.execution_boundary,
        policy_bundle_id=request.policy_bundle_id,
        policy_hash=request.policy_hash,
        validator_role=request.validator_role,
        authority=request.authority,
        expected_audit_hash=request.escalate_audit_event_hash,
    )
    source_receipt = _validate_managed_receipt_artifact(
        session,
        receipt_row=receipt,
        context=context,
        args=args,
        allowed_decisions=frozenset({Decision.ESCALATE.value}),
        receipt_sealer=receipt_sealer,
        failure_detail="source escalate receipt invalid",
        historical_idempotency_replay=False,
    )
    if _to_aware_utc(receipt.expires_at) != _parse_receipt_expiry(source_receipt):
        raise _resume_replay_integrity_error("source escalate receipt expiry mismatch")
    if _to_aware_utc(request.expires_at) != _to_aware_utc(receipt.expires_at):
        raise _resume_replay_integrity_error("approval expiry exceeds source receipt expiry")
    if (
        session.scalars(
            sa.select(ManagedReceiptConsumption).where(
                ManagedReceiptConsumption.org_id == request.org_id,
                ManagedReceiptConsumption.project_id == request.project_id,
                ManagedReceiptConsumption.environment_id == request.environment_id,
                ManagedReceiptConsumption.receipt_hash == request.escalate_receipt_hash,
            )
        ).first()
        is not None
    ):
        raise _resume_replay_integrity_error("source escalate receipt was consumed")
    if (
        session.scalars(
            sa.select(ManagedMutationAttempt).where(
                ManagedMutationAttempt.org_id == request.org_id,
                ManagedMutationAttempt.project_id == request.project_id,
                ManagedMutationAttempt.environment_id == request.environment_id,
                ManagedMutationAttempt.receipt_hash == request.escalate_receipt_hash,
            )
        ).first()
        is not None
    ):
        raise _resume_replay_integrity_error("source escalate receipt has mutation attempt")
    event = _single_event_for_receipt(session, receipt)
    result_hash = safe_result_hash(
        {"status": "non_executable", "decision": Decision.ESCALATE.value}
    )
    _verify_managed_event_projection(
        session,
        receipt=receipt,
        event=event,
        expected_result_hash=result_hash,
        execution_boundary=request.execution_boundary,
        receipt_sealer=receipt_sealer,
    )
    outbox = _single_outbox_for_event(session, receipt=receipt, event=event)
    _verify_managed_outbox_projection(
        receipt=receipt,
        event=event,
        outbox=outbox,
        expected_result_hash=result_hash,
    )


def _validate_managed_receipt_artifact(
    session: Session,
    *,
    receipt_row: ManagedDecisionReceipt,
    context: ManagedMutationContext,
    args: Mapping[str, Any],
    allowed_decisions: frozenset[str],
    receipt_sealer: AesGcmReceiptArtifactSealer,
    failure_detail: str,
    historical_idempotency_replay: bool,
) -> DecisionReceipt:
    try:
        sealed_receipt = receipt_row.projection.get("sealed_receipt")
        if not isinstance(sealed_receipt, dict):
            raise ValueError("sealed receipt projection missing")
        plaintext = receipt_sealer.unseal(
            sealed_receipt,
            associated_data=managed_receipt_artifact_aad(
                org_id=receipt_row.org_id,
                project_id=receipt_row.project_id,
                environment_id=receipt_row.environment_id,
                receipt_hash=receipt_row.receipt_hash,
            ),
        )
        payload = json.loads(plaintext.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("sealed receipt payload must be an object")
        receipt = DecisionReceipt.from_dict(payload)
        _assert_receipt_row_matches_artifact(receipt_row, receipt)
        if receipt.decision not in allowed_decisions:
            raise ReceiptValidationError("managed receipt decision is not allowed")
        if receipt.receipt_hash != receipt.compute_hash():
            raise ReceiptValidationError("managed receipt hash mismatch")
        terminal_non_executable_reasons = {
            Decision.DENY.value: ReceiptRejectionReason.DENIED_RECEIPT,
            Decision.ESCALATE.value: ReceiptRejectionReason.ESCALATED_RECEIPT,
        }
        try:
            receipt.verify(
                expected_tenant_id=context.org_id,
                expected_execution_boundary=context.execution_boundary,
                expected_action=context.action,
                expected_actor=context.actor,
                expected_audit_hash=context.expected_audit_hash,
                expected_args=dict(args),
                expected_policy_hash=context.policy_hash,
                expected_policy_bundle_id=context.policy_bundle_id,
                expected_project_id=context.project_id,
                expected_environment_id=context.environment_id,
                expected_validator_role=context.validator_role,
                expected_authority=context.authority,
                verifier=None,
                require_signature=True,
                require_expiry=not historical_idempotency_replay,
                trust_registry=SqlReceiptTrustRegistry(session, lock_rows=True),
                historical_trust_verification=historical_idempotency_replay,
                trust_purpose=DECISION_RECEIPT_PURPOSE,
                now_iso=receipt.timestamp if historical_idempotency_replay else None,
                max_clock_skew_seconds=DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS,
            )
        except ReceiptValidationError as exc:
            if (
                receipt.decision in terminal_non_executable_reasons
                and exc.reason_code == terminal_non_executable_reasons[receipt.decision]
            ):
                return receipt
            raise
    except (ReceiptValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise _resume_replay_integrity_error(failure_detail) from exc
    return receipt


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
        or _to_aware_utc(receipt_row.expires_at) != _parse_receipt_expiry(receipt)
    ):
        raise ReceiptValidationError("managed receipt projection does not match sealed artifact")


def _single_event_for_receipt(
    session: Session,
    receipt: ManagedDecisionReceipt,
) -> ManagedGovernanceEvent:
    event = session.scalars(
        sa.select(ManagedGovernanceEvent)
        .where(
            ManagedGovernanceEvent.org_id == receipt.org_id,
            ManagedGovernanceEvent.project_id == receipt.project_id,
            ManagedGovernanceEvent.environment_id == receipt.environment_id,
            ManagedGovernanceEvent.managed_receipt_id == receipt.id,
        )
        .with_for_update()
    ).one_or_none()
    if event is None:
        raise _resume_replay_integrity_error("managed governance event missing")
    return event


def _single_outbox_for_event(
    session: Session,
    *,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
) -> ManagedOutboxMessage:
    outbox = session.scalars(
        sa.select(ManagedOutboxMessage)
        .where(
            ManagedOutboxMessage.org_id == receipt.org_id,
            ManagedOutboxMessage.project_id == receipt.project_id,
            ManagedOutboxMessage.environment_id == receipt.environment_id,
            ManagedOutboxMessage.managed_receipt_id == receipt.id,
            ManagedOutboxMessage.managed_event_id == event.id,
        )
        .with_for_update()
    ).one_or_none()
    if outbox is None:
        raise _resume_replay_integrity_error("managed outbox missing")
    return outbox


def _verify_managed_event_projection(
    session: Session,
    *,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
    expected_result_hash: str,
    execution_boundary: str,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    expected_payload = _expected_event_payload(
        receipt=receipt,
        expected_result_hash=expected_result_hash,
        execution_boundary=execution_boundary,
    )
    if event.payload != expected_payload:
        raise _resume_replay_integrity_error("managed event payload mismatch")
    expected_payload_digest = sha256_json(expected_payload)
    if event.payload_digest != expected_payload_digest:
        raise _resume_replay_integrity_error("managed event payload digest mismatch")
    expected_event_hash = sha256_json(
        {
            "schema": "managed-mutation-event-chain/v1",
            "sequence": event.sequence,
            "previous_hash": event.previous_hash,
            "payload_digest": expected_payload_digest,
        }
    )
    if event.event_hash != expected_event_hash:
        raise _resume_replay_integrity_error("managed event hash mismatch")
    if (
        event.decision != receipt.decision
        or event.actor != receipt.actor
        or event.proposed_action != receipt.proposed_action
        or event.policy_version != receipt.policy_version
    ):
        raise _resume_replay_integrity_error("managed event projection mismatch")
    _verify_managed_event_chain_position(
        session,
        receipt=receipt,
        event=event,
        receipt_sealer=receipt_sealer,
    )


def _verify_managed_event_chain_position(
    session: Session,
    *,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    events = _verify_scoped_governance_event_chain(
        session,
        org_id=event.org_id,
        project_id=event.project_id,
        environment_id=event.environment_id,
        receipt_sealer=receipt_sealer,
    )
    if event.id not in {row.id for row in events}:
        raise _resume_replay_integrity_error("managed event missing from scoped chain")
    if (
        event.managed_receipt_id != receipt.id
        or event.org_id != receipt.org_id
        or event.project_id != receipt.project_id
        or event.environment_id != receipt.environment_id
    ):
        raise _resume_replay_integrity_error("managed event receipt scope mismatch")


def _verify_scoped_governance_event_chain(
    session: Session,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> tuple[ManagedGovernanceEvent, ...]:
    """Verify the full scoped chain; intentionally O(n) for the beta correctness gate."""

    head = session.get(
        ManagedGovernanceEventHead,
        (org_id, project_id, environment_id),
        with_for_update=True,
    )
    if head is None:
        raise _resume_replay_integrity_error("managed event chain head missing")
    events = tuple(
        session.scalars(
            sa.select(ManagedGovernanceEvent)
            .where(
                ManagedGovernanceEvent.org_id == org_id,
                ManagedGovernanceEvent.project_id == project_id,
                ManagedGovernanceEvent.environment_id == environment_id,
            )
            .order_by(ManagedGovernanceEvent.sequence.asc())
            .with_for_update()
        )
    )
    if len(events) != head.last_sequence:
        raise _resume_replay_integrity_error("managed event chain sequence count mismatch")
    previous_hash = _GENESIS_AUDIT_HASH
    for expected_sequence, chain_event in enumerate(events, start=1):
        if chain_event.sequence != expected_sequence:
            raise _resume_replay_integrity_error("managed event chain sequence gap")
        if chain_event.previous_hash != previous_hash:
            raise _resume_replay_integrity_error("managed event predecessor link mismatch")
        expected_payload_digest = sha256_json(chain_event.payload)
        if chain_event.payload_digest != expected_payload_digest:
            raise _resume_replay_integrity_error("managed event payload digest mismatch")
        expected_event_hash = sha256_json(
            {
                "schema": "managed-mutation-event-chain/v1",
                "sequence": chain_event.sequence,
                "previous_hash": chain_event.previous_hash,
                "payload_digest": expected_payload_digest,
            }
        )
        if chain_event.event_hash != expected_event_hash:
            raise _resume_replay_integrity_error("managed event hash mismatch")
        _verify_scoped_event_outbox(session, event=chain_event, receipt_sealer=receipt_sealer)
        previous_hash = chain_event.event_hash
    if head.last_sequence == 0:
        if head.last_event_hash != _GENESIS_AUDIT_HASH:
            raise _resume_replay_integrity_error("managed event empty head hash mismatch")
    elif head.last_event_hash != previous_hash:
        raise _resume_replay_integrity_error("managed event head hash mismatch")
    return events


def _verify_scoped_event_outbox(
    session: Session,
    *,
    event: ManagedGovernanceEvent,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    receipt = session.get(ManagedDecisionReceipt, event.managed_receipt_id, with_for_update=True)
    if receipt is None:
        raise _resume_replay_integrity_error("managed event receipt missing")
    if (
        receipt.org_id != event.org_id
        or receipt.project_id != event.project_id
        or receipt.environment_id != event.environment_id
    ):
        raise _resume_replay_integrity_error("managed event receipt scope mismatch")
    sealed_receipt = _validate_historical_chain_receipt_artifact(
        session,
        receipt_row=receipt,
        receipt_sealer=receipt_sealer,
        failure_detail="managed event receipt invalid",
    )
    result_hash = event.payload.get("result_hash")
    if not isinstance(result_hash, str):
        raise _resume_replay_integrity_error("managed event result hash missing")
    expected_payload = _expected_event_payload(
        receipt=receipt,
        expected_result_hash=result_hash,
        execution_boundary=receipt.execution_boundary,
    )
    if event.payload != expected_payload:
        raise _resume_replay_integrity_error("managed event payload mismatch")
    if (
        event.decision != sealed_receipt.decision
        or event.actor != sealed_receipt.actor
        or event.proposed_action != sealed_receipt.proposed_action
        or event.policy_version != sealed_receipt.policy_version
    ):
        raise _resume_replay_integrity_error("managed event projection mismatch")
    outbox = _single_outbox_for_event(session, receipt=receipt, event=event)
    _verify_managed_outbox_projection(
        receipt=receipt,
        event=event,
        outbox=outbox,
        expected_result_hash=result_hash,
    )


def _validate_historical_chain_receipt_artifact(
    session: Session,
    *,
    receipt_row: ManagedDecisionReceipt,
    receipt_sealer: AesGcmReceiptArtifactSealer,
    failure_detail: str,
) -> DecisionReceipt:
    try:
        sealed_receipt = receipt_row.projection.get("sealed_receipt")
        if not isinstance(sealed_receipt, dict):
            raise ValueError("sealed receipt projection missing")
        plaintext = receipt_sealer.unseal(
            sealed_receipt,
            associated_data=managed_receipt_artifact_aad(
                org_id=receipt_row.org_id,
                project_id=receipt_row.project_id,
                environment_id=receipt_row.environment_id,
                receipt_hash=receipt_row.receipt_hash,
            ),
        )
        payload = json.loads(plaintext.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("sealed receipt payload must be an object")
        receipt = DecisionReceipt.from_dict(payload)
        _assert_receipt_row_matches_artifact(receipt_row, receipt)
        if receipt.receipt_hash != receipt.compute_hash():
            raise ReceiptValidationError("managed receipt hash mismatch")
        terminal_non_executable_reasons = {
            Decision.DENY.value: ReceiptRejectionReason.DENIED_RECEIPT,
            Decision.ESCALATE.value: ReceiptRejectionReason.ESCALATED_RECEIPT,
        }
        try:
            receipt.verify(
                expected_tenant_id=receipt_row.org_id,
                expected_execution_boundary=receipt_row.execution_boundary,
                expected_audit_hash=receipt_row.audit_event_hash,
                expected_action=receipt_row.proposed_action,
                expected_policy_hash=receipt_row.policy_hash,
                expected_policy_bundle_id=receipt_row.policy_bundle_id,
                expected_project_id=receipt_row.project_id,
                expected_environment_id=receipt_row.environment_id,
                expected_validator_role=receipt_row.projection.get("validator_role"),
                expected_authority=receipt_row.projection.get("authority"),
                expected_actor=receipt_row.actor,
                verifier=None,
                require_signature=True,
                require_expiry=False,
                trust_registry=SqlReceiptTrustRegistry(session, lock_rows=True),
                historical_trust_verification=True,
                trust_purpose=DECISION_RECEIPT_PURPOSE,
                now_iso=receipt.timestamp,
                max_clock_skew_seconds=DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS,
            )
        except ReceiptValidationError as exc:
            if exc.reason_code == terminal_non_executable_reasons.get(receipt.decision):
                return receipt
            raise
    except (ReceiptValidationError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise _resume_replay_integrity_error(failure_detail) from exc
    return receipt


def _verify_managed_outbox_projection(
    *,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
    outbox: ManagedOutboxMessage,
    expected_result_hash: str,
) -> None:
    expected_payload = {
        "schema": "managed-mutation-uow-outbox/v1",
        "event_hash": event.event_hash,
        "payload_digest": event.payload_digest,
        "receipt_hash": receipt.receipt_hash,
        "audit_event_hash": receipt.audit_event_hash,
        "result_hash": expected_result_hash,
        "assurance_class": receipt.assurance_class,
        "source_system": receipt.source_system,
    }
    if outbox.payload != expected_payload:
        raise _resume_replay_integrity_error("managed outbox payload mismatch")
    if outbox.payload_digest != sha256_json(expected_payload):
        raise _resume_replay_integrity_error("managed outbox payload digest mismatch")
    if outbox.delivery_key != f"managed-mutation-uow/v1:{event.event_hash}":
        raise _resume_replay_integrity_error("managed outbox delivery key mismatch")


def _expected_event_payload(
    *,
    receipt: ManagedDecisionReceipt,
    expected_result_hash: str,
    execution_boundary: str,
) -> dict[str, Any]:
    return {
        "schema": "managed-mutation-uow/v1",
        "assurance_class": receipt.assurance_class,
        "source_system": receipt.source_system,
        "receipt_hash": receipt.receipt_hash,
        "audit_event_hash": receipt.audit_event_hash,
        "argument_hash": receipt.argument_hash,
        "result_hash": expected_result_hash,
        "decision": receipt.decision,
        "actor_hash": sha256_json(receipt.actor),
        "action": receipt.proposed_action,
        "policy_bundle_id": receipt.policy_bundle_id,
        "policy_hash": receipt.policy_hash,
        "receipt_schema_version": receipt.receipt_schema_version,
        "trust_epoch": receipt.trust_epoch,
        "scope": {
            "org_id": receipt.org_id,
            "project_id": receipt.project_id,
            "environment_id": receipt.environment_id,
            "execution_boundary": execution_boundary,
        },
    }


def _resume_response_payload(
    *,
    approval_request_id: str,
    agent: AgentRecord,
    receipt_id: str,
) -> dict[str, Any]:
    return {
        "schema": "approval-resume-response/v1",
        "http_status": 201,
        "approval_request_id": approval_request_id,
        "agent_id": agent.id,
        "org_id": agent.org_id,
        "project_id": agent.project_id,
        "environment_id": agent.environment_id,
        "name": agent.name,
        "description": agent.description,
        "trust_tier": agent.trust_tier,
        "allowed_tools": list(agent.allowed_tools or []),
        "status": agent.status,
        "created_at": _canonical_timestamp(agent.created_at),
        "receipt_id": receipt_id,
    }


def _approval_replay_seal_aad(*, schema: str, binding: Mapping[str, Any]) -> bytes:
    return _canonical_json_bytes(
        {
            "schema": schema,
            "binding_hash": sha256_json(dict(binding)),
        }
    )


def _approval_replay_envelope(envelope: Any, *, detail: str) -> Mapping[str, Any]:
    if not isinstance(envelope, Mapping):
        raise _resume_replay_integrity_error(detail)
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
        raise _resume_replay_integrity_error(detail)
    return envelope


def _approval_replay_artifact(
    *,
    payload_sealer: ApprovalPayloadSealer,
    envelope: Any,
    aad: bytes,
    expected_schema: str,
    expected_keys: set[str],
    detail: str,
) -> Mapping[str, Any]:
    try:
        plaintext = payload_sealer.unseal(
            _approval_replay_envelope(envelope, detail=detail),
            associated_data=aad,
        )
        artifact = json.loads(plaintext.decode("utf-8"))
    except (ApprovalSealingError, UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise _resume_replay_integrity_error(detail) from exc
    if (
        not isinstance(artifact, Mapping)
        or set(artifact) != expected_keys
        or artifact.get("schema") != expected_schema
    ):
        raise _resume_replay_integrity_error(detail)
    return artifact


def _artifact_mapping(artifact: Mapping[str, Any], key: str, *, detail: str) -> Mapping[str, Any]:
    value = artifact.get(key)
    if not isinstance(value, Mapping):
        raise _resume_replay_integrity_error(detail)
    return value


def _vote_replay_binding(
    *,
    request: ApprovalRequest,
    vote: ApprovalVote,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
    outbox: ManagedOutboxMessage,
    result_hash: str,
) -> dict[str, Any]:
    return {
        "schema": "approval-vote-replay-binding/v1",
        "org_id": request.org_id,
        "project_id": request.project_id,
        "environment_id": request.environment_id,
        "approval_request_id": request.id,
        "request_hash": request.request_hash,
        "vote_id": vote.id,
        "idempotency_key_hash": vote.idempotency_key_hash,
        "approver_actor_hash": vote.approver_actor_hash,
        "approver_credential_hash": vote.approver_credential_hash,
        "approver_role": vote.approver_role,
        "decision": vote.decision,
        "vote_hash": vote.vote_hash,
        "vote_receipt_id": receipt.receipt_id,
        "vote_receipt_hash": receipt.receipt_hash,
        "vote_audit_event_hash": receipt.audit_event_hash,
        "event_id": event.id,
        "event_hash": event.event_hash,
        "outbox_id": outbox.id,
        "outbox_delivery_key": outbox.delivery_key,
        "result_hash": result_hash,
    }


def _vote_replay_aad(
    *,
    request: ApprovalRequest,
    vote: ApprovalVote,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
    outbox: ManagedOutboxMessage,
    result_hash: str,
) -> bytes:
    return _approval_replay_seal_aad(
        schema="approval-vote-replay-aad/v1",
        binding=_vote_replay_binding(
            request=request,
            vote=vote,
            receipt=receipt,
            event=event,
            outbox=outbox,
            result_hash=result_hash,
        ),
    )


def _seal_vote_replay_artifact(
    *,
    payload_sealer: ApprovalPayloadSealer,
    request: ApprovalRequest,
    vote: ApprovalVote,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
    outbox: ManagedOutboxMessage,
    result_hash: str,
    result_payload: Mapping[str, Any],
    response_payload: Mapping[str, Any],
) -> dict[str, Any]:
    artifact = {
        "schema": "approval-vote-replay-artifact/v1",
        "binding": _vote_replay_binding(
            request=request,
            vote=vote,
            receipt=receipt,
            event=event,
            outbox=outbox,
            result_hash=result_hash,
        ),
        "result_hash": result_hash,
        "result": dict(result_payload),
        "response_hash": sha256_json(dict(response_payload)),
        "response": dict(response_payload),
    }
    return dict(
        payload_sealer.seal(
            _canonical_json_bytes(artifact),
            associated_data=_vote_replay_aad(
                request=request,
                vote=vote,
                receipt=receipt,
                event=event,
                outbox=outbox,
                result_hash=result_hash,
            ),
        )
    )


def _validated_vote_replay_artifact(
    *,
    payload_sealer: ApprovalPayloadSealer,
    request: ApprovalRequest,
    vote: ApprovalVote,
    evidence: _VoteEvidence,
) -> Mapping[str, Any]:
    artifact = _approval_replay_artifact(
        payload_sealer=payload_sealer,
        envelope=vote.vote_replay_seal,
        aad=_vote_replay_aad(
            request=request,
            vote=vote,
            receipt=evidence.receipt,
            event=evidence.event,
            outbox=evidence.outbox,
            result_hash=evidence.result_hash,
        ),
        expected_schema="approval-vote-replay-artifact/v1",
        expected_keys={"schema", "binding", "result_hash", "result", "response_hash", "response"},
        detail="approval vote replay seal invalid",
    )
    expected_binding = _vote_replay_binding(
        request=request,
        vote=vote,
        receipt=evidence.receipt,
        event=evidence.event,
        outbox=evidence.outbox,
        result_hash=evidence.result_hash,
    )
    if artifact.get("binding") != expected_binding or artifact.get("result_hash") != (
        evidence.result_hash
    ):
        raise _resume_replay_integrity_error("approval vote replay artifact binding mismatch")
    result_payload = _artifact_mapping(
        artifact, "result", detail="approval vote replay result invalid"
    )
    response_payload = _artifact_mapping(
        artifact, "response", detail="approval vote replay response invalid"
    )
    if safe_result_hash(dict(result_payload)) != evidence.result_hash:
        raise _resume_replay_integrity_error("approval vote replay result hash mismatch")
    if artifact.get("response_hash") != sha256_json(dict(response_payload)):
        raise _resume_replay_integrity_error("approval vote replay response hash mismatch")
    expected_response = _vote_response_payload(
        approval_request_id=request.id,
        decision=vote.decision,
        outcome=result_payload.get("outcome") or None,
        vote_hash=vote.vote_hash,
        receipt_id=evidence.receipt.receipt_id,
    )
    if dict(response_payload) != expected_response:
        raise _resume_replay_integrity_error("approval vote replay response mismatch")
    return artifact


def _resume_result_from_response_payload(payload: Mapping[str, Any]) -> ApprovalResumeResult:
    try:
        created_at = _to_aware_utc(datetime.fromisoformat(str(payload["created_at"])))
        allowed_tools = payload["allowed_tools"]
        if not isinstance(allowed_tools, list) or not all(
            isinstance(item, str) for item in allowed_tools
        ):
            raise ValueError("allowed_tools must be a string list")
        return ApprovalResumeResult(
            approval_request_id=str(payload["approval_request_id"]),
            agent_id=str(payload["agent_id"]),
            org_id=str(payload["org_id"]),
            name=str(payload["name"]),
            description=str(payload["description"]),
            trust_tier=str(payload["trust_tier"]),
            allowed_tools=list(allowed_tools),
            status=str(payload["status"]),
            created_at=created_at,
            receipt_id=str(payload["receipt_id"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise _resume_replay_integrity_error("approval resume stored response invalid") from exc


def _validated_resume_response_payload(row: ApprovalResumeAuthorization) -> dict[str, Any]:
    payload = row.resume_response
    if not isinstance(payload, dict):
        raise _resume_replay_integrity_error("approval resume stored response missing")
    if sha256_json(payload) != row.resume_response_hash:
        raise _resume_replay_integrity_error("approval resume stored response hash mismatch")
    expected_static = {
        "schema": "approval-resume-response/v1",
        "http_status": 201,
        "approval_request_id": row.approval_request_id,
        "agent_id": row.resumed_agent_id,
        "org_id": row.org_id,
        "project_id": row.project_id,
        "environment_id": row.environment_id,
        "receipt_id": row.resume_receipt_id,
    }
    if any(payload.get(key) != value for key, value in expected_static.items()):
        raise _resume_replay_integrity_error("approval resume stored response binding mismatch")
    _resume_result_from_response_payload(payload)
    return payload


def _resume_args_from_response_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    allowed_tools = payload.get("allowed_tools")
    if not isinstance(allowed_tools, list) or not all(
        isinstance(item, str) for item in allowed_tools
    ):
        raise _resume_replay_integrity_error("approval resume stored response args invalid")
    return {
        "name": str(payload["name"]),
        "description": str(payload["description"]),
        "trust_tier": str(payload["trust_tier"]),
        "allowed_tools": list(allowed_tools),
    }


def _validated_resume_result_payload(
    row: ApprovalResumeAuthorization,
    *,
    response_payload: Mapping[str, Any],
) -> dict[str, Any]:
    payload = row.resume_result
    if not isinstance(payload, dict):
        raise _resume_replay_integrity_error("approval resume stored result missing")
    if safe_result_hash(payload) != row.resume_result_hash:
        raise _resume_replay_integrity_error("approval resume stored result hash mismatch")
    expected_result = {
        "agent_id": row.resumed_agent_id,
        "org_id": row.org_id,
        "project_id_hash": sha256_json(row.project_id),
        "environment_id_hash": sha256_json(row.environment_id),
        "name_hash": sha256_json(str(response_payload["name"])),
        "status": str(response_payload["status"]),
        "created_at": str(response_payload["created_at"]),
    }
    if payload != expected_result:
        raise _resume_replay_integrity_error("approval resume stored result binding mismatch")
    return payload


def _resume_replay_binding(
    *,
    request: ApprovalRequest,
    row: ApprovalResumeAuthorization,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
    outbox: ManagedOutboxMessage,
    mutation_attempt: ManagedMutationAttempt | None,
    args_hash: str,
    result_hash: str,
    response_hash: str,
) -> dict[str, Any]:
    return {
        "schema": "approval-resume-replay-binding/v1",
        "org_id": request.org_id,
        "project_id": request.project_id,
        "environment_id": request.environment_id,
        "approval_request_id": request.id,
        "request_hash": request.request_hash,
        "resume_authorization_id": row.id,
        "idempotency_key_hash": row.idempotency_key_hash,
        "resumer_actor_hash": row.resumer_actor_hash,
        "resumer_credential_hash": row.resumer_credential_hash,
        "resumer_role": row.resumer_role,
        "resumed_agent_id": row.resumed_agent_id,
        "resume_receipt_id": receipt.receipt_id,
        "resume_receipt_hash": receipt.receipt_hash,
        "resume_audit_event_hash": receipt.audit_event_hash,
        "approval_chain_hash": row.approval_chain_hash,
        "argument_hash": args_hash,
        "result_hash": result_hash,
        "response_hash": response_hash,
        "event_id": event.id,
        "event_hash": event.event_hash,
        "outbox_id": outbox.id,
        "outbox_delivery_key": outbox.delivery_key,
        "mutation_attempt_id": mutation_attempt.id if mutation_attempt is not None else None,
    }


def _resume_replay_aad(
    *,
    request: ApprovalRequest,
    row: ApprovalResumeAuthorization,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
    outbox: ManagedOutboxMessage,
    mutation_attempt: ManagedMutationAttempt | None,
    args_hash: str,
    result_hash: str,
    response_hash: str,
) -> bytes:
    return _approval_replay_seal_aad(
        schema="approval-resume-replay-aad/v1",
        binding=_resume_replay_binding(
            request=request,
            row=row,
            receipt=receipt,
            event=event,
            outbox=outbox,
            mutation_attempt=mutation_attempt,
            args_hash=args_hash,
            result_hash=result_hash,
            response_hash=response_hash,
        ),
    )


def _seal_resume_replay_artifact(
    *,
    payload_sealer: ApprovalPayloadSealer,
    request: ApprovalRequest,
    row: ApprovalResumeAuthorization,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
    outbox: ManagedOutboxMessage,
    mutation_attempt: ManagedMutationAttempt,
    args: Mapping[str, Any],
    result_payload: Mapping[str, Any],
    response_payload: Mapping[str, Any],
) -> dict[str, Any]:
    result_hash = safe_result_hash(dict(result_payload))
    response_hash = sha256_json(dict(response_payload))
    artifact = {
        "schema": "approval-resume-replay-artifact/v1",
        "binding": _resume_replay_binding(
            request=request,
            row=row,
            receipt=receipt,
            event=event,
            outbox=outbox,
            mutation_attempt=mutation_attempt,
            args_hash=sha256_json(dict(args)),
            result_hash=result_hash,
            response_hash=response_hash,
        ),
        "arguments_hash": sha256_json(dict(args)),
        "arguments": dict(args),
        "result_hash": result_hash,
        "result": dict(result_payload),
        "response_hash": response_hash,
        "response": dict(response_payload),
    }
    return dict(
        payload_sealer.seal(
            _canonical_json_bytes(artifact),
            associated_data=_resume_replay_aad(
                request=request,
                row=row,
                receipt=receipt,
                event=event,
                outbox=outbox,
                mutation_attempt=mutation_attempt,
                args_hash=sha256_json(dict(args)),
                result_hash=result_hash,
                response_hash=response_hash,
            ),
        )
    )


def _validated_resume_replay_artifact(
    *,
    payload_sealer: ApprovalPayloadSealer,
    request: ApprovalRequest,
    row: ApprovalResumeAuthorization,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
    outbox: ManagedOutboxMessage,
    mutation_attempt: ManagedMutationAttempt,
) -> Mapping[str, Any]:
    artifact = _approval_replay_artifact(
        payload_sealer=payload_sealer,
        envelope=row.resume_replay_seal,
        aad=_resume_replay_aad(
            request=request,
            row=row,
            receipt=receipt,
            event=event,
            outbox=outbox,
            mutation_attempt=mutation_attempt,
            args_hash=row.resume_argument_hash,
            result_hash=row.resume_result_hash,
            response_hash=row.resume_response_hash,
        ),
        expected_schema="approval-resume-replay-artifact/v1",
        expected_keys={
            "schema",
            "binding",
            "arguments_hash",
            "arguments",
            "result_hash",
            "result",
            "response_hash",
            "response",
        },
        detail="approval resume replay seal invalid",
    )
    expected_binding = _resume_replay_binding(
        request=request,
        row=row,
        receipt=receipt,
        event=event,
        outbox=outbox,
        mutation_attempt=mutation_attempt,
        args_hash=row.resume_argument_hash,
        result_hash=row.resume_result_hash,
        response_hash=row.resume_response_hash,
    )
    if artifact.get("binding") != expected_binding:
        raise _resume_replay_integrity_error("approval resume replay artifact binding mismatch")
    args_payload = _artifact_mapping(
        artifact, "arguments", detail="approval resume replay arguments invalid"
    )
    result_payload = _artifact_mapping(
        artifact, "result", detail="approval resume replay result invalid"
    )
    response_payload = _artifact_mapping(
        artifact, "response", detail="approval resume replay response invalid"
    )
    if (
        artifact.get("arguments_hash") != row.resume_argument_hash
        or sha256_json(dict(args_payload)) != row.resume_argument_hash
        or artifact.get("result_hash") != row.resume_result_hash
        or safe_result_hash(dict(result_payload)) != row.resume_result_hash
        or artifact.get("response_hash") != row.resume_response_hash
        or sha256_json(dict(response_payload)) != row.resume_response_hash
    ):
        raise _resume_replay_integrity_error("approval resume replay artifact hash mismatch")
    if dict(args_payload) != _resume_args_from_response_payload(response_payload):
        raise _resume_replay_integrity_error("approval resume replay argument mismatch")
    _resume_result_from_response_payload(response_payload)
    return artifact


def _resume_result_from_row(
    session: Session,
    row: ApprovalResumeAuthorization,
    *,
    receipt_sealer: AesGcmReceiptArtifactSealer,
    payload_sealer: ApprovalPayloadSealer,
    expected_idempotency_key_hash: str,
    expected_resumer_actor_hash: str,
    expected_resumer_credential_hash: str,
    expected_resumer_role: str,
) -> ApprovalResumeResult:
    request = session.scalars(
        sa.select(ApprovalRequest).where(
            ApprovalRequest.org_id == row.org_id,
            ApprovalRequest.project_id == row.project_id,
            ApprovalRequest.environment_id == row.environment_id,
            ApprovalRequest.id == row.approval_request_id,
        )
    ).one_or_none()
    if request is None:
        raise _resume_replay_integrity_error("approval request missing")
    if row.idempotency_key_hash != expected_idempotency_key_hash:
        raise _resume_replay_integrity_error("approval resume replay key mismatch")
    if (
        row.resumer_actor_hash != expected_resumer_actor_hash
        or row.resumer_credential_hash != expected_resumer_credential_hash
        or row.resumer_role != expected_resumer_role
    ):
        raise ApprovalHttpError(
            403,
            "APPROVAL_REPLAY_FORBIDDEN",
            "forbidden",
            "approval resume replay caller mismatch",
        )
    response_payload = _validated_resume_response_payload(row)
    replay_args = _resume_args_from_response_payload(response_payload)
    if sha256_json(replay_args) != row.resume_argument_hash:
        raise _resume_replay_integrity_error("approval resume stored argument hash mismatch")
    result_payload = _validated_resume_result_payload(row, response_payload=response_payload)
    agent = session.scalars(
        sa.select(AgentRecord).where(
            AgentRecord.org_id == row.org_id,
            AgentRecord.project_id == row.project_id,
            AgentRecord.environment_id == row.environment_id,
            AgentRecord.id == row.resumed_agent_id,
        )
    ).one_or_none()
    if agent is None:
        raise _resume_replay_integrity_error("approval resume agent missing")
    if agent.id != str(response_payload["agent_id"]) or agent.id != str(result_payload["agent_id"]):
        raise _resume_replay_integrity_error("approval resume agent binding mismatch")
    receipt = session.scalars(
        sa.select(ManagedDecisionReceipt).where(
            ManagedDecisionReceipt.org_id == row.org_id,
            ManagedDecisionReceipt.project_id == row.project_id,
            ManagedDecisionReceipt.environment_id == row.environment_id,
            ManagedDecisionReceipt.receipt_id == row.resume_receipt_id,
            ManagedDecisionReceipt.receipt_hash == row.resume_receipt_hash,
            ManagedDecisionReceipt.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION,
            ManagedDecisionReceipt.decision == Decision.ALLOW.value,
        )
    ).one_or_none()
    if receipt is None:
        raise _resume_replay_integrity_error("approval resume receipt missing")
    if receipt.projection.get("approval_chain_hash") != row.approval_chain_hash:
        raise _resume_replay_integrity_error("approval resume receipt chain mismatch")
    if receipt.argument_hash != row.resume_argument_hash:
        raise _resume_replay_integrity_error("approval resume receipt argument mismatch")
    context = ManagedMutationContext(
        org_id=row.org_id,
        project_id=row.project_id,
        environment_id=row.environment_id,
        actor=receipt.actor,
        action=CONTROL_PLANE_AGENT_CREATE_ACTION,
        execution_boundary=request.execution_boundary,
        policy_bundle_id=request.policy_bundle_id,
        policy_hash=request.policy_hash,
        validator_role=request.validator_role,
        authority=request.authority,
        expected_audit_hash=receipt.audit_event_hash,
    )
    sealed_receipt = _validate_historical_chain_receipt_artifact(
        session,
        receipt_row=receipt,
        receipt_sealer=receipt_sealer,
        failure_detail="approval resume receipt invalid",
    )
    if (
        sealed_receipt.decision != Decision.ALLOW.value
        or sealed_receipt.argument_hash != sha256_json(replay_args)
        or sealed_receipt.argument_hash != row.resume_argument_hash
        or sealed_receipt.audit_event_hash != context.expected_audit_hash
        or sealed_receipt.proposed_action != context.action
        or sealed_receipt.actor != context.actor
        or sealed_receipt.policy_hash != context.policy_hash
        or sealed_receipt.policy_bundle_id != context.policy_bundle_id
        or sealed_receipt.project_id != context.project_id
        or sealed_receipt.environment_id != context.environment_id
        or sealed_receipt.validator_role != context.validator_role
        or sealed_receipt.authority != context.authority
    ):
        raise _resume_replay_integrity_error("approval resume sealed receipt mismatch")
    if (
        sealed_receipt.request_id is None
        or _idempotency_storage_key(
            org_id=row.org_id,
            approval_request_id=request.id,
            key=sealed_receipt.request_id,
        )
        != expected_idempotency_key_hash
    ):
        raise _resume_replay_integrity_error("approval resume sealed request id mismatch")
    if sha256_json(sealed_receipt.approval_chain_summary) != row.approval_chain_hash:
        raise _resume_replay_integrity_error("approval resume sealed chain mismatch")
    _validate_managed_execution_evidence(
        session,
        org_id=row.org_id,
        project_id=row.project_id,
        environment_id=row.environment_id,
        receipt=receipt,
        missing_consumption_detail="approval resume consumption missing",
        invalid_attempt_detail="approval resume mutation attempt invalid",
    )
    mutation_attempt = session.scalars(
        sa.select(ManagedMutationAttempt).where(
            ManagedMutationAttempt.org_id == row.org_id,
            ManagedMutationAttempt.project_id == row.project_id,
            ManagedMutationAttempt.environment_id == row.environment_id,
            ManagedMutationAttempt.receipt_hash == receipt.receipt_hash,
            ManagedMutationAttempt.audit_event_hash == receipt.audit_event_hash,
            ManagedMutationAttempt.action == receipt.proposed_action,
            ManagedMutationAttempt.actor_hash == sha256_json(receipt.actor),
            ManagedMutationAttempt.argument_hash == receipt.argument_hash,
            ManagedMutationAttempt.status == "succeeded",
        )
    ).one_or_none()
    if mutation_attempt is None:
        raise _resume_replay_integrity_error("approval resume mutation attempt missing")
    event = session.scalars(
        sa.select(ManagedGovernanceEvent).where(
            ManagedGovernanceEvent.org_id == row.org_id,
            ManagedGovernanceEvent.project_id == row.project_id,
            ManagedGovernanceEvent.environment_id == row.environment_id,
            ManagedGovernanceEvent.managed_receipt_id == receipt.id,
            ManagedGovernanceEvent.event_hash == row.resume_audit_event_hash,
        )
    ).one_or_none()
    if event is None:
        raise _resume_replay_integrity_error("approval resume event missing")
    expected_result_hash = row.resume_result_hash
    _verify_managed_event_projection(
        session,
        receipt=receipt,
        event=event,
        expected_result_hash=expected_result_hash,
        execution_boundary=request.execution_boundary,
        receipt_sealer=receipt_sealer,
    )
    if event.event_hash != row.resume_audit_event_hash:
        raise _resume_replay_integrity_error("approval resume event hash mismatch")
    outbox = _single_outbox_for_event(session, receipt=receipt, event=event)
    _verify_managed_outbox_projection(
        receipt=receipt,
        event=event,
        outbox=outbox,
        expected_result_hash=expected_result_hash,
    )
    artifact = _validated_resume_replay_artifact(
        payload_sealer=payload_sealer,
        request=request,
        row=row,
        receipt=receipt,
        event=event,
        outbox=outbox,
        mutation_attempt=mutation_attempt,
    )
    return _resume_result_from_response_payload(
        _artifact_mapping(artifact, "response", detail="approval resume replay response invalid")
    )


def _resume_replay_integrity_error(detail: str) -> ApprovalHttpError:
    return ApprovalHttpError(
        503,
        "IDEMPOTENCY_RECORD_INVALID",
        "idempotency_record_invalid",
        detail,
    )


def _verify_resume_event_projection(
    *,
    row: ApprovalResumeAuthorization,
    request: ApprovalRequest,
    agent: AgentRecord,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
    expected_result_hash: str,
) -> None:
    del agent
    expected_payload = {
        "schema": "managed-mutation-uow/v1",
        "assurance_class": receipt.assurance_class,
        "source_system": receipt.source_system,
        "receipt_hash": row.resume_receipt_hash,
        "audit_event_hash": receipt.audit_event_hash,
        "argument_hash": receipt.argument_hash,
        "result_hash": expected_result_hash,
        "decision": Decision.ALLOW.value,
        "actor_hash": sha256_json(receipt.actor),
        "action": CONTROL_PLANE_AGENT_CREATE_ACTION,
        "policy_bundle_id": request.policy_bundle_id,
        "policy_hash": request.policy_hash,
        "receipt_schema_version": receipt.receipt_schema_version,
        "trust_epoch": request.trust_epoch,
        "scope": {
            "org_id": row.org_id,
            "project_id": row.project_id,
            "environment_id": row.environment_id,
            "execution_boundary": request.execution_boundary,
        },
    }
    if event.payload != expected_payload:
        raise _resume_replay_integrity_error("approval resume event payload mismatch")
    expected_payload_digest = sha256_json(expected_payload)
    if event.payload_digest != expected_payload_digest:
        raise _resume_replay_integrity_error("approval resume event payload digest mismatch")
    expected_event_hash = sha256_json(
        {
            "schema": "managed-mutation-event-chain/v1",
            "sequence": event.sequence,
            "previous_hash": event.previous_hash,
            "payload_digest": expected_payload_digest,
        }
    )
    if event.event_hash != row.resume_audit_event_hash or event.event_hash != expected_event_hash:
        raise _resume_replay_integrity_error("approval resume event hash mismatch")
    if (
        event.decision != Decision.ALLOW.value
        or event.actor != receipt.actor
        or event.proposed_action != CONTROL_PLANE_AGENT_CREATE_ACTION
        or event.policy_version != receipt.policy_version
    ):
        raise _resume_replay_integrity_error("approval resume event projection mismatch")


def _verify_resume_outbox_projection(
    *,
    row: ApprovalResumeAuthorization,
    request: ApprovalRequest,
    receipt: ManagedDecisionReceipt,
    event: ManagedGovernanceEvent,
    outbox: ManagedOutboxMessage,
    expected_result_hash: str,
) -> None:
    del request
    expected_payload = {
        "schema": "managed-mutation-uow-outbox/v1",
        "event_hash": row.resume_audit_event_hash,
        "payload_digest": event.payload_digest,
        "receipt_hash": row.resume_receipt_hash,
        "audit_event_hash": receipt.audit_event_hash,
        "result_hash": expected_result_hash,
        "assurance_class": receipt.assurance_class,
        "source_system": receipt.source_system,
    }
    if outbox.payload != expected_payload:
        raise _resume_replay_integrity_error("approval resume outbox payload mismatch")
    if outbox.payload_digest != sha256_json(expected_payload):
        raise _resume_replay_integrity_error("approval resume outbox payload digest mismatch")
    if outbox.delivery_key != f"managed-mutation-uow/v1:{row.resume_audit_event_hash}":
        raise _resume_replay_integrity_error("approval resume outbox delivery key mismatch")


def _active_policy_context(
    session: Session,
    request: ApprovalRequest,
) -> tuple[RuleSetPolicy, str, str]:
    head = session.scalars(
        sa.select(EnvironmentPolicyHead)
        .where(
            EnvironmentPolicyHead.org_id == request.org_id,
            EnvironmentPolicyHead.project_id == request.project_id,
            EnvironmentPolicyHead.environment_id == request.environment_id,
            EnvironmentPolicyHead.status == "active",
        )
        .with_for_update()
    ).one_or_none()
    if head is None:
        raise ApprovalHttpError(409, "POLICY_NOT_READY", "policy_not_ready", "policy not active")
    version = session.get(PolicyVersion, head.active_policy_version_id, with_for_update=True)
    if version is None:
        raise ApprovalHttpError(409, "POLICY_NOT_READY", "policy_not_ready", "policy not active")
    _verify_envelope(
        session,
        version.canonical_envelope,
        expected_org_id=request.org_id,
        expected_project_id=request.project_id,
        expected_environment_id=request.environment_id,
        expected_policy_id=version.policy_id,
        expected_version=version.version,
        expected_document=version.document,
    )
    try:
        policy = RuleSetPolicy.from_dict(version.document)
    except (TypeError, ValueError) as exc:
        raise ApprovalHttpError(
            409,
            "POLICY_NOT_READY",
            "policy_not_ready",
            "active policy document is invalid",
        ) from exc
    return policy, version.id, version.content_hash


def _evaluate_policy_record(
    policy: RuleSetPolicy,
    *,
    context: ManagedMutationContext,
    args: Mapping[str, Any],
    goal: str,
    path: tuple[str, ...],
) -> DecisionRecord:
    record = policy.evaluate(
        ToolCall(
            name=context.action,
            args=dict(args),
            actor=context.actor,
            goal=goal,
            path=path,
        )
    )
    record = DecisionRecord(
        decision=record.decision,
        tool=context.action,
        actor=context.actor,
        goal=goal,
        reason=record.reason,
        matched_rules=tuple(record.matched_rules),
        policy_version=record.policy_version,
        event_id=new_id(),
        argument_hash=sha256_json(dict(args)),
        path=path,
        transformed_args=dict(args) if record.transformed_args is not None else None,
        state_hash=sha256_json({}),
    )
    return record


def _issue_receipt(
    *,
    issuer: ManagedPlatformIssuer,
    context: ManagedMutationContext,
    record: DecisionRecord,
    audit_hash: str,
    request_id: str,
    trust_epoch: int,
    approval_chain_summary: dict[str, Any],
) -> DecisionReceipt:
    try:
        return mint_managed_decision_receipt_v2(
            issuer=issuer,
            context=cast(Any, context),
            record=record,
            audit_hash=audit_hash,
            previous_audit_hash=_GENESIS_AUDIT_HASH,
            trust_epoch=trust_epoch,
            request_id=request_id,
            expires_at=(utcnow() + timedelta(minutes=10)).isoformat(),
            purpose=DECISION_RECEIPT_PURPOSE,
            constraints={"schema": "approval-operation-constraints/v1"},
            approval_chain_summary=approval_chain_summary,
        )
    except (ReceiptValidationError, ManagedTrustError, TrustConfigurationError):
        raise


def _unseal_agent_args(
    request: ApprovalRequest,
    sealer: ApprovalPayloadSealer,
) -> dict[str, Any]:
    binding = _verify_approval_request_binding(request)
    try:
        plaintext = sealer.unseal(
            request.sealed_arguments,
            associated_data=approval_payload_aad(approval_request_id=request.id, binding=binding),
        )
    except ApprovalSealingError as exc:
        raise ApprovalHttpError(
            503, "APPROVAL_PAYLOAD_INVALID", "tx_aborted", "approval payload invalid"
        ) from exc
    payload = json.loads(plaintext.decode("utf-8"))
    if payload.get("schema") != "agent-registration-args/v1" or not isinstance(
        payload.get("args"), dict
    ):
        raise ApprovalHttpError(
            503, "APPROVAL_PAYLOAD_INVALID", "tx_aborted", "approval payload invalid"
        )
    args = dict(payload["args"])
    if sha256_json(args) != request.argument_hash:
        raise ApprovalHttpError(
            503, "APPROVAL_PAYLOAD_INVALID", "tx_aborted", "approval payload hash mismatch"
        )
    return args


def _approval_chain_summary(
    *,
    request: ApprovalRequest,
    outcome: ApprovalOutcome,
    proposer: str,
    validator_id: str,
) -> dict[str, Any]:
    return {
        "schema": "managed-approval-chain/v1",
        "proposer": proposer,
        "validator_id": validator_id,
        "approval_request_id": request.id,
        "approval_request_hash": request.request_hash,
        "escalate_receipt_hash": request.escalate_receipt_hash,
        "outcome": outcome.outcome,
        "quorum_digest": outcome.quorum_digest,
        "approver_set_hash": outcome.approver_set_hash,
    }


def _decision_audit_hash(record: DecisionRecord) -> str:
    return sha256_json(
        {
            "schema": "managed-approval-decision-audit/v1",
            "record": record.to_dict(),
        }
    )


def _to_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _canonical_timestamp(value: datetime) -> str:
    return _to_aware_utc(value).isoformat()


def _parse_receipt_expiry(receipt: DecisionReceipt) -> datetime:
    if not receipt.expires_at:
        raise ReceiptValidationError("receipt expiry is required")
    return _to_aware_utc(datetime.fromisoformat(receipt.expires_at))


def _canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
