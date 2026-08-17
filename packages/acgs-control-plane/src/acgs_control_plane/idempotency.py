"""Durable terminal idempotency helpers for managed mutations."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC
from typing import Any

from fastapi import HTTPException
from gove_zone.decision import sha256_json
from gove_zone.errors import ProductionProfileError, ReceiptValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from acgs_control_plane.models import (
    AgentRecord,
    GovernanceEvent,
    ManagedIdempotencyResult,
    NativeDecisionReceiptRow,
)
from acgs_control_plane.native_receipts import (
    ManagedConsumptionAttestationTrust,
    ManagedNativeReceiptTrust,
    verify_native_evidence_chain,
)
from acgs_control_plane.schemas import AgentResponse

IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"
AGENT_CREATE_ACTION = "database.agent.create"
AGENT_CREATE_CANONICALIZER_VERSION = "acgs.agent-create-request.canon.v1"
AGENT_CREATE_REQUEST_DIGEST_VERSION = "sha256:" + AGENT_CREATE_CANONICALIZER_VERSION
RESULT_ARTIFACT_SCHEMA = "acgs.managed-idempotency-result.v1"
_KEY_RE = re.compile(r"[\x21-\x7e]{1,255}\Z")
_DECISION_TO_STATUS = {"allow": 201, "deny": 403, "escalate": 202}


def require_idempotency_key(values: list[str]) -> str:
    """Validate exact-one bounded transport key without returning it to storage."""
    if not values:
        raise HTTPException(status_code=428, detail="idempotency key required")
    if len(values) != 1:
        raise HTTPException(status_code=400, detail="ambiguous idempotency key")
    value = values[0]
    if _KEY_RE.fullmatch(value) is None:
        raise HTTPException(status_code=400, detail="invalid idempotency key")
    return value


def idempotency_key_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_agent_create_digest(body: dict[str, Any]) -> str:
    return sha256_json(
        {
            "canonicalizer_version": AGENT_CREATE_CANONICALIZER_VERSION,
            "canonical_action": AGENT_CREATE_ACTION,
            "body": body,
        }
    )


def sign_result_artifact(
    *,
    row: ManagedIdempotencyResult,
    consumption_trust: ManagedConsumptionAttestationTrust,
) -> None:
    artifact = {
        "schema": RESULT_ARTIFACT_SCHEMA,
        "org_id": row.org_id,
        "environment_id": row.environment_id,
        "principal_id": row.principal_id,
        "canonical_action": row.canonical_action,
        "key_digest": row.key_digest,
        "request_digest_version": row.request_digest_version,
        "request_digest": row.request_digest,
        "canonicalizer_version": row.canonicalizer_version,
        "terminal_decision": row.terminal_decision,
        "response_status": row.response_status,
        "response_body_hash": row.response_body_hash,
        "native_receipt_row_id": row.native_receipt_row_id,
        "receipt_id": row.receipt_id,
        "governance_event_id": row.governance_event_id,
        "governance_event_hash": row.governance_event_hash,
        "agent_id": row.agent_id,
    }
    artifact_hash, algorithm, key_id, signature = consumption_trust.sign(artifact)
    row.result_artifact = artifact
    row.result_artifact_hash = artifact_hash
    row.result_signature_algorithm = algorithm
    row.result_signing_key_id = key_id
    row.result_signature = signature


def verify_replay_result(
    session: Session,
    row: ManagedIdempotencyResult,
    *,
    receipt_trust: ManagedNativeReceiptTrust,
    consumption_trust: ManagedConsumptionAttestationTrust,
) -> dict[str, Any]:
    """Fail closed unless signed evidence reconstructs the stored semantic result."""
    if row.result_artifact_hash != sha256_json(dict(row.result_artifact)):
        raise ReceiptValidationError("idempotency result artifact hash mismatch")
    consumption_trust.verify(
        row.result_artifact,
        artifact_hash=row.result_artifact_hash,
        algorithm=row.result_signature_algorithm,
        key_id=row.result_signing_key_id,
        signature=row.result_signature,
    )
    expected = {
        "schema": RESULT_ARTIFACT_SCHEMA,
        "org_id": row.org_id,
        "environment_id": row.environment_id,
        "principal_id": row.principal_id,
        "canonical_action": row.canonical_action,
        "key_digest": row.key_digest,
        "request_digest_version": row.request_digest_version,
        "request_digest": row.request_digest,
        "canonicalizer_version": row.canonicalizer_version,
        "terminal_decision": row.terminal_decision,
        "response_status": row.response_status,
        "response_body_hash": row.response_body_hash,
        "native_receipt_row_id": row.native_receipt_row_id,
        "receipt_id": row.receipt_id,
        "governance_event_id": row.governance_event_id,
        "governance_event_hash": row.governance_event_hash,
        "agent_id": row.agent_id,
    }
    if dict(row.result_artifact) != expected:
        raise ReceiptValidationError("idempotency result artifact does not match row")
    if row.terminal_decision not in _DECISION_TO_STATUS:
        raise ReceiptValidationError("idempotency result decision is unknown")
    if row.response_status != _DECISION_TO_STATUS[row.terminal_decision]:
        raise ReceiptValidationError("idempotency result status mismatch")
    native = session.get(NativeDecisionReceiptRow, row.native_receipt_row_id)
    if (
        native is None
        or native.org_id != row.org_id
        or native.receipt_id != row.receipt_id
        or native.decision != row.terminal_decision
    ):
        raise ReceiptValidationError("idempotency result references missing native receipt")
    event = session.get(GovernanceEvent, row.governance_event_id)
    if (
        event is None
        or event.org_id != row.org_id
        or event.event_hash != row.governance_event_hash
        or event.decision != row.terminal_decision
        or native.audit_event_hash != event.event_hash
    ):
        raise ReceiptValidationError("idempotency result references missing governance event")
    event_payload = event.payload if isinstance(event.payload, dict) else {}
    if event_payload.get("decision") != row.terminal_decision:
        raise ReceiptValidationError("idempotency result event payload decision mismatch")
    if row.terminal_decision == "allow":
        if row.agent_id is None:
            raise ReceiptValidationError("idempotency allow result missing agent reference")
        agent = session.scalar(
            select(AgentRecord).where(
                AgentRecord.org_id == row.org_id,
                AgentRecord.id == row.agent_id,
                AgentRecord.environment_id == row.environment_id,
            )
        )
        if agent is None:
            raise ReceiptValidationError("idempotency result references missing agent")
        created_at = agent.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        semantic_response: dict[str, Any] = AgentResponse(
            agent_id=agent.id,
            org_id=agent.org_id,
            name=agent.name,
            description=agent.description,
            trust_tier=agent.trust_tier,
            allowed_tools=list(agent.allowed_tools),
            status=agent.status,
            created_at=created_at,
            receipt_id=row.receipt_id,
        ).model_dump(mode="json")
    else:
        if row.agent_id is not None:
            raise ReceiptValidationError("blocked idempotency result references an agent")
        reason = event_payload.get("reason")
        if not isinstance(reason, str) or not reason:
            raise ReceiptValidationError("blocked idempotency event missing reason")
        if row.terminal_decision == "deny":
            semantic_response = {
                "status": "denied",
                "reason": reason,
                "receipt_id": native.receipt_id,
                "decision": row.terminal_decision,
            }
        else:
            semantic_response = {
                "status": "pending_approval",
                "reason": reason,
                "receipt_id": native.receipt_id,
                "decision": row.terminal_decision,
            }
    if row.response_body_hash != sha256_json(semantic_response):
        raise ReceiptValidationError("idempotency reconstructed response hash mismatch")
    try:
        verify_native_evidence_chain(
            session,
            row.org_id,
            trust=receipt_trust,
            consumption_trust=consumption_trust,
        )
    except ProductionProfileError as exc:
        raise ReceiptValidationError("idempotency replay trust is unavailable") from exc
    return semantic_response
