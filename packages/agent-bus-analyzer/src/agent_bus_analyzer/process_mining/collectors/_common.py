"""Shared read-only collector validation and field extraction."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from agent_bus_analyzer.process_mining._canonical import json_compatible, sha256_canonical
from agent_bus_analyzer.process_mining.errors import SourceIntegrityError, TenantIsolationError
from agent_bus_analyzer.process_mining.schemas.process_event import (
    CaseIdSource,
    CorrelationConfidence,
    EventLifecycle,
    EventOutcome,
    GovernanceContext,
    GovernanceDecision,
    ProcessEventKind,
    SourceChainStatus,
)

GENESIS_HASH = "0" * 64


def snapshot_mapping(record: Mapping[str, object]) -> dict[str, Any]:
    """Make a canonical deep copy, rejecting values with unstable encodings."""
    normalized = json_compatible(record)
    if not isinstance(normalized, dict):  # defensive: Mapping always normalizes to dict
        raise TypeError("source record must normalize to an object")
    return normalized


def text(record: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def required_text(record: Mapping[str, Any], *keys: str) -> str:
    value = text(record, *keys)
    if value is None:
        raise ValueError(f"source record requires one of: {', '.join(keys)}")
    return value


def parse_timestamp(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        candidate = value.strip().replace("Z", "+00:00")
        if not candidate:
            raise ValueError("timestamp cannot be blank")
        parsed = datetime.fromisoformat(candidate)
    else:
        raise TypeError("timestamp must be an ISO-8601 string or datetime")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed


def assert_tenant(tenant_id: str, record: Mapping[str, Any]) -> None:
    source_tenant = text(record, "tenant_id", "tenant")
    if source_tenant is not None and source_tenant != tenant_id:
        raise TenantIsolationError(
            f"source tenant {source_tenant!r} does not match requested tenant {tenant_id!r}"
        )


def select_case_id(
    record: Mapping[str, Any],
    *,
    fallback_event_id: str | None = None,
    fallback_content_hash: str | None = None,
) -> tuple[str, CaseIdSource, CorrelationConfidence]:
    """Choose only explicit correlation keys; never infer from time proximity."""
    candidates = (
        ("case_id", CaseIdSource.EXPLICIT_CASE_ID, CorrelationConfidence.HIGH),
        ("correlation_id", CaseIdSource.CORRELATION_ID, CorrelationConfidence.HIGH),
        ("conversation_id", CaseIdSource.CONVERSATION_ID, CorrelationConfidence.HIGH),
        ("session_id", CaseIdSource.SESSION_ID, CorrelationConfidence.HIGH),
        ("trajectory_id", CaseIdSource.TRAJECTORY_ID, CorrelationConfidence.HIGH),
        (
            "decision_request_hash",
            CaseIdSource.DECISION_REQUEST_HASH,
            CorrelationConfidence.MEDIUM,
        ),
    )
    for key, source, confidence in candidates:
        value = text(record, key)
        if value is not None:
            return value, source, confidence
    if fallback_event_id is not None:
        return fallback_event_id, CaseIdSource.SOURCE_EVENT_ID, CorrelationConfidence.LOW
    if fallback_content_hash is not None:
        return fallback_content_hash, CaseIdSource.CONTENT_HASH, CorrelationConfidence.LOW
    raise ValueError("source record has no explicit case correlation key")


_FORBIDDEN_ATTRIBUTE_FRAGMENTS = (
    "arg",
    "content",
    "credential",
    "input",
    "key",
    "password",
    "prompt",
    "secret",
    "token",
)


def allowlisted_attributes(
    record: Mapping[str, Any],
    *,
    keys: tuple[str, ...],
) -> dict[str, Any]:
    """Copy only scalar, non-secret metadata approved by a collector."""
    attributes: dict[str, Any] = {}
    for key in keys:
        lowered = key.lower()
        if any(fragment in lowered for fragment in _FORBIDDEN_ATTRIBUTE_FRAGMENTS):
            continue
        value = record.get(key)
        if key in record and isinstance(value, (str, bool, int, float)):
            attributes[key] = value
    return attributes


def sha_value(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SourceIntegrityError("declared hash must be a string")
    candidate = value.removeprefix("sha256:").strip().lower()
    if len(candidate) != 64 or any(char not in "0123456789abcdef" for char in candidate):
        raise SourceIntegrityError("declared hash must be 64 lower-case hexadecimal characters")
    return candidate


def verify_optional_source_chain(
    record: Mapping[str, Any],
    *,
    event_hash_key: str = "event_hash",
    previous_hash_key: str = "previous_hash",
    expected_previous_hash: str | None = None,
) -> tuple[SourceChainStatus, str | None, str | None]:
    """Verify a canonical source record hash and, when available, its link."""
    claimed = sha_value(record.get(event_hash_key))
    previous = sha_value(record.get(previous_hash_key))
    if claimed is None:
        if previous is not None or expected_previous_hash is not None:
            raise SourceIntegrityError("source chain link exists without an event hash")
        return SourceChainStatus.NOT_APPLICABLE, None, None

    payload = dict(record)
    payload.pop(event_hash_key, None)
    recomputed = sha256_canonical(payload)
    if claimed != recomputed:
        raise SourceIntegrityError(
            f"source event hash mismatch: claimed={claimed}, recomputed={recomputed}"
        )
    if previous is None:
        raise SourceIntegrityError("hashed source record is missing previous_hash")

    if expected_previous_hash is not None:
        expected = sha_value(expected_previous_hash)
        if previous != expected:
            raise SourceIntegrityError(
                f"source predecessor mismatch: expected={expected}, actual={previous}"
            )
        status = SourceChainStatus.VERIFIED
    elif previous == GENESIS_HASH:
        status = SourceChainStatus.VERIFIED
    else:
        status = SourceChainStatus.UNVERIFIED
    return status, claimed, previous


_KIND_ALIASES: dict[str, ProcessEventKind] = {
    "human": ProcessEventKind.HUMAN,
    "user": ProcessEventKind.HUMAN,
    "agent": ProcessEventKind.AGENT,
    "assistant": ProcessEventKind.AGENT,
    "tool": ProcessEventKind.TOOL_CALL,
    "tool_call": ProcessEventKind.TOOL_CALL,
    "tool_use": ProcessEventKind.TOOL_CALL,
    "tool_result": ProcessEventKind.TOOL_RESULT,
    "tool_response": ProcessEventKind.TOOL_RESULT,
    "policy": ProcessEventKind.POLICY_EVALUATION,
    "policy_evaluation": ProcessEventKind.POLICY_EVALUATION,
    "receipt": ProcessEventKind.DECISION_RECEIPT,
    "decision": ProcessEventKind.DECISION_RECEIPT,
    "decision_receipt": ProcessEventKind.DECISION_RECEIPT,
    "evidence": ProcessEventKind.EVIDENCE_BUNDLE,
    "evidence_bundle": ProcessEventKind.EVIDENCE_BUNDLE,
    "audit": ProcessEventKind.AUDIT,
    "failure": ProcessEventKind.FAILURE,
    "error": ProcessEventKind.FAILURE,
    "exception": ProcessEventKind.EXCEPTION,
    "approval": ProcessEventKind.APPROVAL,
    "approved": ProcessEventKind.APPROVAL,
    "denial": ProcessEventKind.DENIAL,
    "denied": ProcessEventKind.DENIAL,
}


def parse_kind(value: object) -> ProcessEventKind:
    if isinstance(value, ProcessEventKind):
        return value
    if not isinstance(value, str):
        raise TypeError("process event kind must be a string")
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    try:
        return _KIND_ALIASES[normalized]
    except KeyError as exc:
        raise ValueError(f"unsupported process event kind: {value!r}") from exc


def parse_decision(value: object) -> GovernanceDecision | None:
    if value is None or value == "":
        return None
    if isinstance(value, GovernanceDecision):
        return value
    if not isinstance(value, str):
        raise TypeError("governance decision must be a string")
    return GovernanceDecision(value.strip().lower())


def parse_lifecycle(value: object) -> EventLifecycle:
    if value is None or value == "":
        return EventLifecycle.COMPLETED
    if isinstance(value, EventLifecycle):
        return value
    if not isinstance(value, str):
        raise TypeError("event lifecycle must be a string")
    return EventLifecycle(value.strip().lower().replace("-", "_"))


def parse_outcome(value: object) -> EventOutcome:
    if value is None or value == "":
        return EventOutcome.UNKNOWN
    if isinstance(value, EventOutcome):
        return value
    if not isinstance(value, str):
        raise TypeError("event outcome must be a string")
    normalized = value.strip().lower().replace("-", "_")
    aliases = {"allow": "approved", "deny": "denied", "error": "failure"}
    return EventOutcome(aliases.get(normalized, normalized))


def evidence_ids(record: Mapping[str, Any]) -> tuple[str, ...]:
    raw = record.get("evidence_bundle_ids", record.get("evidence_ids", ()))
    values: tuple[str, ...]
    if isinstance(raw, str):
        values = (raw,)
    elif isinstance(raw, list | tuple):
        if not all(isinstance(item, str) and item.strip() for item in raw):
            raise ValueError("evidence bundle ids must be non-empty strings")
        values = tuple(item.strip() for item in raw)
    elif raw is None:
        values = ()
    else:
        raise TypeError("evidence bundle ids must be a string or sequence")
    return tuple(sorted(set(values)))


def permission_ids(record: Mapping[str, Any]) -> tuple[str, ...]:
    """Extract only explicit permission/scope identifiers, never credentials."""
    raw = record.get("permission_ids", record.get("permissions", record.get("scopes", ())))
    if isinstance(raw, str):
        values = tuple(part for part in raw.split() if part)
    elif isinstance(raw, list | tuple):
        if not all(isinstance(item, str) and item.strip() for item in raw):
            raise ValueError("permission identifiers must be non-empty strings")
        values = tuple(item.strip() for item in raw)
    elif raw is None:
        values = ()
    else:
        raise TypeError("permission identifiers must be a string or sequence")
    return tuple(sorted(set(values)))


def governance_from_mapping(
    record: Mapping[str, Any],
    *,
    default_side_effect: bool = False,
) -> GovernanceContext:
    nested_raw = record.get("governance")
    nested = nested_raw if isinstance(nested_raw, dict) else {}

    def pick(*keys: str) -> Any:
        for key in keys:
            if key in nested:
                return nested[key]
            if key in record:
                return record[key]
        return None

    raw_side_effect = pick("is_side_effect", "side_effect")
    if raw_side_effect is None:
        is_side_effect = default_side_effect
    elif isinstance(raw_side_effect, bool):
        is_side_effect = raw_side_effect
    else:
        raise TypeError("side_effect must be boolean")

    evidence_record: dict[str, Any] = {**record, **nested}
    return GovernanceContext(
        is_side_effect=is_side_effect,
        actor_authority_id=pick("actor_authority_id", "authority_id"),
        tool_name=pick("tool_name", "tool", "action"),
        argument_hash=sha_value(pick("argument_hash", "args_hash")),
        decision=parse_decision(pick("decision", "verdict")),
        policy_id=pick("policy_id", "policy"),
        policy_version=pick("policy_version"),
        policy_bundle_id=pick("policy_bundle_id"),
        policy_hash=sha_value(pick("policy_hash")),
        execution_boundary=pick("execution_boundary"),
        decision_receipt_id=pick("decision_receipt_id", "receipt_id"),
        decision_receipt_hash=sha_value(pick("decision_receipt_hash", "receipt_hash")),
        evidence_bundle_ids=evidence_ids(evidence_record),
        audit_event_id=pick("audit_event_id"),
        audit_event_hash=sha_value(pick("audit_event_hash", "audit_hash")),
        replay_verified=pick("replay_verified"),
    )
