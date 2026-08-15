"""Shared deterministic fixtures for process-intelligence algorithm tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from agent_bus_analyzer.process_mining.schemas.process_event import (
    ActorKind,
    CaseIdSource,
    CorrelationConfidence,
    GovernanceContext,
    GovernanceDecision,
    ProcessEvent,
    ProcessEventKind,
    SourceChainStatus,
    SourceKind,
    build_process_event,
)

BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64


def governance_complete(
    *,
    tool_name: str = "runtime.file.write",
    decision: GovernanceDecision = GovernanceDecision.ALLOW,
    replay_verified: bool | None = True,
) -> GovernanceContext:
    return GovernanceContext.model_validate(
        {
            "is_side_effect": True,
            "actor_authority_id": "authority-1",
            "tool_name": tool_name,
            "argument_hash": HASH_A,
            "decision": decision,
            "policy_id": "policy-1",
            "policy_bundle_id": "policy-bundle",
            "policy_version": "v1",
            "policy_hash": HASH_D,
            "execution_boundary": "local-sandbox",
            "decision_receipt_id": "receipt-1",
            "decision_receipt_hash": HASH_B,
            "evidence_bundle_ids": ("evidence-1",),
            "audit_event_id": "audit-1",
            "audit_event_hash": HASH_C,
            "replay_verified": replay_verified,
        }
    )


def make_event(
    *,
    event_id: str,
    case_id: str,
    sequence: int | None,
    minute: int,
    activity: str,
    tenant_id: str = "tenant-A",
    kind: ProcessEventKind = ProcessEventKind.AGENT,
    governance: GovernanceContext | None = None,
    attributes: dict[str, object] | None = None,
    permission_ids: tuple[str, ...] = (),
    chain_status: SourceChainStatus = SourceChainStatus.VERIFIED,
    actor_id: str | None = "agent-1",
) -> ProcessEvent:
    integrity: dict[str, object] = {"chain_status": chain_status}
    if chain_status is SourceChainStatus.VERIFIED:
        integrity["source_event_hash"] = HASH_D
    return build_process_event(
        {
            "event_id": event_id,
            "tenant_id": tenant_id,
            "case_id": case_id,
            "case_id_source": CaseIdSource.EXPLICIT_CASE_ID,
            "correlation_confidence": CorrelationConfidence.HIGH,
            "process_id": "process-1",
            "process_name": "Process 1",
            "sequence": sequence,
            "kind": kind,
            "activity": activity,
            "occurred_at": BASE_TIME + timedelta(minutes=minute),
            "ingested_at": BASE_TIME + timedelta(minutes=minute, seconds=1),
            "actor_id": actor_id,
            "actor_kind": ActorKind.AGENT,
            "permission_ids": permission_ids,
            "provenance": {
                "source_kind": SourceKind.API_EVENT,
                "source_system": "test-fixture",
                "source_record_id": event_id,
                "source_schema_version": "1",
                "raw_record_hash": HASH_A,
            },
            "integrity": integrity,
            "governance": governance or GovernanceContext(),
            "attributes": attributes or {},
        }
    )
