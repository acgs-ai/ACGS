"""Read-only normalization of raw gove-zone audit-chain records."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from agent_bus_analyzer.process_mining._canonical import sha256_canonical
from agent_bus_analyzer.process_mining.collectors._common import (
    GENESIS_HASH,
    assert_tenant,
    evidence_ids,
    parse_decision,
    parse_timestamp,
    required_text,
    select_case_id,
    sha_value,
    snapshot_mapping,
    text,
    verify_optional_source_chain,
)
from agent_bus_analyzer.process_mining.schemas.process_event import (
    ActorKind,
    CaseIdSource,
    CorrelationConfidence,
    EventLifecycle,
    EventOutcome,
    EventProvenance,
    GovernanceContext,
    ProcessEvent,
    ProcessEventKind,
    SourceIntegrity,
    SourceKind,
    build_process_event,
)


class AuditCollector:
    """Validate source hashes before emitting normalized governance events."""

    def collect(
        self,
        record: Mapping[str, object],
        *,
        tenant_id: str,
        case_id: str | None = None,
        expected_previous_hash: str | None = None,
    ) -> ProcessEvent:
        snapshot = snapshot_mapping(record)
        assert_tenant(tenant_id, snapshot)
        status, event_hash, previous_hash = verify_optional_source_chain(
            snapshot,
            expected_previous_hash=expected_previous_hash,
        )
        if event_hash is None or previous_hash is None:
            raise ValueError("gove-zone audit record requires event_hash and previous_hash")

        event_id = required_text(snapshot, "event_id")
        tool_name = required_text(snapshot, "tool", "tool_name")
        argument_hash = sha_value(snapshot.get("argument_hash"))
        decision = parse_decision(snapshot.get("decision"))
        receipt_id = text(snapshot, "decision_receipt_id", "receipt_id")
        receipt_hash = sha_value(
            snapshot.get("decision_receipt_hash", snapshot.get("receipt_hash"))
        )
        audit_id = text(snapshot, "audit_event_id") or event_id
        governance = GovernanceContext(
            is_side_effect=False,
            actor_authority_id=text(snapshot, "actor_authority_id", "authority_id"),
            tool_name=tool_name,
            argument_hash=argument_hash,
            decision=decision,
            policy_id=text(snapshot, "policy_id"),
            policy_version=text(snapshot, "policy_version"),
            policy_bundle_id=text(snapshot, "policy_bundle_id"),
            policy_hash=sha_value(snapshot.get("policy_hash")),
            execution_boundary=text(snapshot, "execution_boundary"),
            decision_receipt_id=receipt_id,
            decision_receipt_hash=receipt_hash,
            evidence_bundle_ids=evidence_ids(snapshot),
            audit_event_id=audit_id,
            audit_event_hash=event_hash,
            replay_verified=snapshot.get("replay_verified"),
        )
        if case_id is not None:
            normalized_case_id = case_id
            case_source = CaseIdSource.EXPLICIT_CASE_ID
            confidence = CorrelationConfidence.HIGH
        else:
            normalized_case_id, case_source, confidence = select_case_id(
                snapshot,
                fallback_event_id=event_id,
            )
        decision_value = decision.value if decision is not None else None
        if decision_value == "deny":
            outcome = EventOutcome.DENIED
        elif decision_value in {"allow", "transform"}:
            outcome = EventOutcome.APPROVED
        elif decision_value == "escalate":
            outcome = EventOutcome.ESCALATED
        else:
            outcome = EventOutcome.UNKNOWN
        correlations = tuple(
            sorted(
                {
                    value
                    for value in (
                        text(snapshot, "conversation_id"),
                        text(snapshot, "decision_request_hash"),
                    )
                    if value is not None
                }
            )
        )
        return build_process_event(
            {
                "event_id": event_id,
                "tenant_id": tenant_id,
                "case_id": normalized_case_id,
                "case_id_source": case_source,
                "correlation_confidence": confidence,
                "process_id": text(snapshot, "process_id"),
                "process_name": text(snapshot, "process_name"),
                "parent_event_id": text(snapshot, "parent_event_id"),
                "correlation_references": correlations,
                "kind": ProcessEventKind.AUDIT,
                "activity": tool_name,
                "occurred_at": parse_timestamp(snapshot.get("timestamp_iso")),
                "lifecycle": EventLifecycle.COMPLETED,
                "outcome": outcome,
                "actor_id": text(snapshot, "actor"),
                "actor_kind": ActorKind.AGENT,
                "agent_id": text(snapshot, "actor"),
                "tool_id": tool_name,
                "organization_id": text(snapshot, "organization_id"),
                "provenance": EventProvenance(
                    source_kind=SourceKind.GOVE_ZONE_AUDIT,
                    source_system="gove-zone",
                    source_record_id=event_id,
                    source_schema_version=text(snapshot, "schema_version"),
                    raw_record_hash=sha256_canonical(snapshot),
                ),
                "integrity": SourceIntegrity(
                    chain_status=status,
                    source_event_hash=event_hash,
                    source_previous_hash=previous_hash,
                ),
                "governance": governance,
                "attributes": {
                    "reason_hash": sha256_canonical(text(snapshot, "reason") or ""),
                    "matched_rule_count": len(snapshot.get("matched_rules", [])),
                },
            }
        )

    def collect_many(
        self,
        records: Iterable[Mapping[str, object]],
        *,
        tenant_id: str,
        initial_previous_hash: str = GENESIS_HASH,
    ) -> tuple[ProcessEvent, ...]:
        """Normalize a contiguous chain, stopping before any invalid record."""
        expected = initial_previous_hash
        collected: list[ProcessEvent] = []
        for record in records:
            event = self.collect(
                record,
                tenant_id=tenant_id,
                expected_previous_hash=expected,
            )
            collected.append(event)
            if event.integrity.source_event_hash is None:  # guarded by collect
                raise AssertionError("audit collector produced a hash-less event")
            expected = event.integrity.source_event_hash
        return tuple(collected)
