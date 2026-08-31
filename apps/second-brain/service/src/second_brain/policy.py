from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol, runtime_checkable
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

PolicyAction = Literal[
    "capture_source",
    "generate_answer",
    "approve_memory",
    "purge_source",
    "purge_memory",
]
ResourceType = Literal["source", "answer", "memory", "workspace"]
NativeChecks = Literal["pass", "fail"]
Decision = Literal["pass", "veto", "unavailable"]

_ACTIONS = {
    "capture_source",
    "generate_answer",
    "approve_memory",
    "purge_source",
    "purge_memory",
}
_RESOURCE_TYPES = {"source", "answer", "memory", "workspace"}
_SOURCE_TYPES = {"note", "markdown", "txt", "pdf", "docx", "url"}
_MEMORY_CATEGORIES = {
    "preference",
    "commitment",
    "project_fact",
    "person_fact",
    "reference",
    "other",
}
_DECISIONS = {"pass", "veto", "unavailable"}
_SUPPORTED_OBLIGATIONS = {"record_audit", "require_explicit_user_action"}


class PolicyDenied(RuntimeError):
    """A native check or policy veto denied the protected operation."""


class PolicyUnavailable(RuntimeError):
    """An enabled policy adapter could not return a valid decision."""


def _aware_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")


def _bounded_token(value: str | None, field: str, *, required: bool = False) -> None:
    if value is None:
        if required:
            raise ValueError(f"{field} is required")
        return
    if not value or len(value) > 128 or any(character.isspace() for character in value):
        raise ValueError(f"{field} must be a bounded token")


@dataclass(frozen=True)
class PolicyContext:
    request_id: UUID
    action: PolicyAction
    actor_id: UUID
    workspace_id: UUID
    resource_type: ResourceType
    native_checks: NativeChecks
    occurred_at: datetime
    resource_id: UUID | None = None
    source_type: str | None = None
    mime_type: str | None = None
    byte_count: int | None = None
    chunk_count: int | None = None
    retrieval_result_count: int | None = None
    citation_count: int | None = None
    memory_category: str | None = None

    def __post_init__(self) -> None:
        if self.action not in _ACTIONS:
            raise ValueError("unknown policy action")
        if self.resource_type not in _RESOURCE_TYPES:
            raise ValueError("unknown policy resource type")
        if self.native_checks not in {"pass", "fail"}:
            raise ValueError("unknown native check state")
        if self.source_type is not None and self.source_type not in _SOURCE_TYPES:
            raise ValueError("unknown source type")
        if self.memory_category is not None and self.memory_category not in _MEMORY_CATEGORIES:
            raise ValueError("unknown memory category")
        if self.mime_type is not None and (not self.mime_type or len(self.mime_type) > 255):
            raise ValueError("mime_type must be bounded")
        for field in (
            "byte_count",
            "chunk_count",
            "retrieval_result_count",
            "citation_count",
        ):
            value = getattr(self, field)
            if value is not None and (isinstance(value, bool) or value < 0):
                raise ValueError(f"{field} must be non-negative")
        _aware_utc(self.occurred_at, "occurred_at")


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    reason_code: str
    evaluated_at: datetime
    policy_id: str | None = None
    policy_version: str | None = None
    audit_id: str | None = None
    obligations: tuple[str, ...] = ()


@runtime_checkable
class PolicyDecisionPort(Protocol):
    def evaluate(self, context: PolicyContext) -> object: ...


def _validate_result(result: object) -> PolicyDecision:
    if not isinstance(result, PolicyDecision):
        raise PolicyUnavailable("policy adapter unavailable")
    try:
        if result.decision not in _DECISIONS:
            raise ValueError("unknown policy decision")
        _bounded_token(result.reason_code, "reason_code", required=True)
        _bounded_token(result.policy_id, "policy_id", required=True)
        _bounded_token(result.policy_version, "policy_version", required=True)
        _bounded_token(result.audit_id, "audit_id", required=True)
        _aware_utc(result.evaluated_at, "evaluated_at")
        if len(result.obligations) > 8 or any(
            obligation not in _SUPPORTED_OBLIGATIONS for obligation in result.obligations
        ):
            raise ValueError("unsupported policy obligation")
    except (TypeError, ValueError) as exc:
        raise PolicyUnavailable("policy adapter unavailable") from exc
    return result


def evaluate_policy(
    port: PolicyDecisionPort | None,
    context: PolicyContext,
    *,
    enabled: bool,
) -> PolicyDecision:
    """Apply an optional veto; native checks always remain authoritative."""
    if context.native_checks != "pass":
        raise PolicyDenied("native_checks_failed")
    if not enabled:
        return PolicyDecision(
            decision="pass",
            reason_code="policy.disabled",
            evaluated_at=datetime.now(UTC),
        )
    unavailable = PolicyDecision(
        decision="unavailable",
        reason_code="policy.adapter_unavailable",
        policy_id="local-policy-adapter",
        policy_version="unavailable",
        audit_id=f"unavailable-{context.request_id}",
        evaluated_at=datetime.now(UTC),
    )
    if port is None:
        return unavailable
    try:
        result = _validate_result(port.evaluate(context))
    except Exception:
        return unavailable
    return result


def record_policy_decision(
    session: Session, context: PolicyContext, result: PolicyDecision
) -> UUID:
    """Append one validated, metadata-only decision in the active database scope."""
    validated = _validate_result(result)
    decision_id = uuid4()
    session.execute(
        text(
            "INSERT INTO policy_decisions "
            "(id,owner_id,workspace_id,request_id,action,actor_id,resource_type,resource_id,"
            "source_type,mime_type,byte_count,chunk_count,retrieval_result_count,citation_count,"
            "memory_category,native_checks,decision,reason_code,policy_id,policy_version,audit_id,"
            "obligations,evaluated_at) VALUES "
            "(:id,:owner_id,:workspace_id,:request_id,:action,:actor_id,:resource_type,"
            ":resource_id,:source_type,:mime_type,:byte_count,:chunk_count,"
            ":retrieval_result_count,:citation_count,:memory_category,:native_checks,:decision,"
            ":reason_code,:policy_id,:policy_version,:audit_id,:obligations,:evaluated_at)"
        ),
        {
            "id": decision_id,
            "owner_id": context.actor_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "action": context.action,
            "actor_id": context.actor_id,
            "resource_type": context.resource_type,
            "resource_id": context.resource_id,
            "source_type": context.source_type,
            "mime_type": context.mime_type,
            "byte_count": context.byte_count,
            "chunk_count": context.chunk_count,
            "retrieval_result_count": context.retrieval_result_count,
            "citation_count": context.citation_count,
            "memory_category": context.memory_category,
            "native_checks": context.native_checks,
            "decision": validated.decision,
            "reason_code": validated.reason_code,
            "policy_id": validated.policy_id,
            "policy_version": validated.policy_version,
            "audit_id": validated.audit_id,
            "obligations": list(validated.obligations),
            "evaluated_at": validated.evaluated_at,
        },
    )
    return decision_id
