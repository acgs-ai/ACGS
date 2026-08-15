"""Read-only collector for explicit enterprise API process events."""

from __future__ import annotations

from collections.abc import Mapping

from agent_bus_analyzer.process_mining._canonical import sha256_canonical
from agent_bus_analyzer.process_mining.collectors._common import (
    allowlisted_attributes,
    assert_tenant,
    governance_from_mapping,
    parse_kind,
    parse_lifecycle,
    parse_outcome,
    parse_timestamp,
    permission_ids,
    required_text,
    select_case_id,
    snapshot_mapping,
    text,
    verify_optional_source_chain,
)
from agent_bus_analyzer.process_mining.schemas.process_event import (
    ActorKind,
    EventProvenance,
    ProcessEvent,
    SourceIntegrity,
    SourceKind,
    build_process_event,
)


class APIEventCollector:
    """Normalize a generic API envelope with no source-side mutation."""

    def collect(
        self,
        record: Mapping[str, object],
        *,
        tenant_id: str,
        source_system: str = "api",
        expected_previous_hash: str | None = None,
    ) -> ProcessEvent:
        snapshot = snapshot_mapping(record)
        assert_tenant(tenant_id, snapshot)
        chain_status, event_hash, previous_hash = verify_optional_source_chain(
            snapshot,
            expected_previous_hash=expected_previous_hash,
        )
        event_id = required_text(snapshot, "event_id", "id")
        case_id, case_source, confidence = select_case_id(snapshot)
        kind = parse_kind(snapshot.get("kind", snapshot.get("event_type", snapshot.get("type"))))
        governance = governance_from_mapping(
            snapshot,
            default_side_effect=kind.value == "tool_call" and snapshot.get("side_effect") is True,
        )
        actor_kind_raw = text(snapshot, "actor_kind") or "unknown"
        return build_process_event(
            {
                "event_id": event_id,
                "tenant_id": tenant_id,
                "case_id": case_id,
                "case_id_source": case_source,
                "correlation_confidence": confidence,
                "process_id": text(snapshot, "process_id"),
                "process_name": text(snapshot, "process_name"),
                "sequence": snapshot.get("sequence"),
                "parent_event_id": text(snapshot, "parent_event_id"),
                "correlation_references": tuple(
                    sorted(
                        {
                            value
                            for value in (
                                text(snapshot, "correlation_id"),
                                text(snapshot, "conversation_id"),
                                text(snapshot, "session_id"),
                            )
                            if value is not None
                        }
                    )
                ),
                "kind": kind,
                "activity": required_text(snapshot, "activity", "action", "name"),
                "occurred_at": parse_timestamp(
                    snapshot.get(
                        "occurred_at", snapshot.get("timestamp", snapshot.get("created_at"))
                    )
                ),
                "lifecycle": parse_lifecycle(snapshot.get("lifecycle")),
                "outcome": parse_outcome(snapshot.get("outcome")),
                "actor_id": text(snapshot, "actor_id", "actor", "user_id", "agent_id"),
                "actor_kind": ActorKind(actor_kind_raw),
                "agent_id": text(snapshot, "agent_id"),
                "tool_id": text(snapshot, "tool_id", "tool_name", "tool"),
                "api_id": text(snapshot, "api_id", "api_name"),
                "permission_ids": permission_ids(snapshot),
                "organization_id": text(snapshot, "organization_id"),
                "provenance": EventProvenance(
                    source_kind=SourceKind.API_EVENT,
                    source_system=source_system,
                    source_record_id=event_id,
                    source_schema_version=text(snapshot, "source_schema_version", "schema_version"),
                    raw_record_hash=sha256_canonical(snapshot),
                ),
                "integrity": SourceIntegrity(
                    chain_status=chain_status,
                    source_event_hash=event_hash,
                    source_previous_hash=previous_hash,
                ),
                "governance": governance,
                "attributes": allowlisted_attributes(
                    snapshot,
                    keys=("status", "duration_ms", "http_status", "retry_count"),
                ),
            }
        )
