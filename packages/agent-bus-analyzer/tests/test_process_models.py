"""Contract tests for strict normalized process events and cases."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from agent_bus_analyzer.process_mining.collectors.api_collector import APIEventCollector
from agent_bus_analyzer.process_mining.schemas.generate_schema import main as generate_schema
from agent_bus_analyzer.process_mining.schemas.process_case import build_process_case
from agent_bus_analyzer.process_mining.schemas.process_event import (
    CaseIdSource,
    CorrelationConfidence,
    GovernanceContext,
    GovernanceReference,
    ProcessEvent,
    ProcessEventKind,
    SideEffectClassification,
    build_process_event,
    validated_event_snapshot,
)


def _api_record(event_id: str = "evt-1", *, sequence: int = 0) -> dict[str, object]:
    return {
        "event_id": event_id,
        "tenant_id": "tenant-a",
        "case_id": "case-1",
        "process_id": "loan-v1",
        "process_name": "Loan Approval",
        "sequence": sequence,
        "kind": "tool_call",
        "activity": "payment.execute",
        "occurred_at": "2026-07-09T15:00:00Z",
        "actor_id": "agent-7",
        "actor_kind": "agent",
        "agent_id": "agent-7",
        "tool_id": "payment.execute",
        "api_id": "payments-v2",
        "organization_id": "org-1",
        "lifecycle": "completed",
        "outcome": "success",
        "side_effect": True,
        "governance": {
            "actor_authority_id": "authority-7",
            "tool_name": "payment.execute",
            "argument_hash": "a" * 64,
            "decision": "allow",
            "policy_id": "payment-policy",
            "policy_version": "2026-07",
            "policy_bundle_id": "payments-bundle-2026-07",
            "policy_hash": "d" * 64,
            "execution_boundary": "payments-production",
            "decision_receipt_id": "receipt-1",
            "decision_receipt_hash": "b" * 64,
            "evidence_bundle_ids": ["evidence-1"],
            "audit_event_id": "audit-1",
            "audit_event_hash": "c" * 64,
            "replay_verified": True,
        },
    }


def test_process_event_is_strict_versioned_and_self_verifying() -> None:
    event = APIEventCollector().collect(_api_record(), tenant_id="tenant-a")

    assert event.schema_version == "1.0"
    assert event.kind is ProcessEventKind.TOOL_CALL
    assert event.case_id_source is CaseIdSource.EXPLICIT_CASE_ID
    assert event.correlation_confidence is CorrelationConfidence.HIGH
    assert event.completeness.status.value == "complete"
    assert event.completeness.evidence_coverage == 1.0
    assert len(event.normalization_hash) == 64

    tampered = event.model_dump(mode="python")
    tampered["activity"] = "payment.redirect"
    with pytest.raises(ValidationError, match="normalization_hash"):
        ProcessEvent.model_validate(tampered)

    unknown = event.model_dump(mode="python")
    unknown["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        ProcessEvent.model_validate(unknown)


def test_normalization_hash_excludes_ingestion_clock() -> None:
    collector = APIEventCollector()
    first = collector.collect(_api_record(), tenant_id="tenant-a")
    second = collector.collect(_api_record(), tenant_id="tenant-a")

    assert first.normalization_hash == second.normalization_hash
    assert first.provenance.raw_record_hash == second.provenance.raw_record_hash


def test_serialized_event_snapshot_rejects_nested_post_hash_mutation() -> None:
    event = APIEventCollector().collect(_api_record(), tenant_id="tenant-a")
    payload = event.model_dump(mode="python", exclude={"normalization_hash"})
    payload["attributes"] = {"nested": {"state": "original"}}
    mutable_event = build_process_event(payload)
    snapshot = validated_event_snapshot(mutable_event)

    assert snapshot is not mutable_event
    assert snapshot.attributes is not mutable_event.attributes
    nested = cast(dict[str, object], mutable_event.attributes["nested"])
    nested["state"] = "tampered"
    snapshot_nested = cast(dict[str, object], snapshot.attributes["nested"])
    assert snapshot_nested["state"] == "original"

    with pytest.raises(ValidationError, match="normalization_hash"):
        validated_event_snapshot(mutable_event)
    with pytest.raises(ValidationError, match="normalization_hash"):
        build_process_case([mutable_event])


def test_low_quality_case_fallback_cannot_claim_high_confidence() -> None:
    event = APIEventCollector().collect(_api_record(), tenant_id="tenant-a")
    payload = event.model_dump(mode="python")
    payload["case_id_source"] = CaseIdSource.CONTENT_HASH
    payload["correlation_confidence"] = CorrelationConfidence.HIGH
    payload["normalization_hash"] = "0" * 64

    with pytest.raises(ValidationError, match="must have low confidence"):
        ProcessEvent.model_validate(payload)


def test_permission_ids_are_strict_sorted_identifiers() -> None:
    event = APIEventCollector().collect(_api_record(), tenant_id="tenant-a")
    payload = event.model_dump(mode="python")
    payload["permission_ids"] = ("z.write", "a.read")
    payload["normalization_hash"] = "0" * 64

    with pytest.raises(ValidationError, match="deterministic sorted order"):
        ProcessEvent.model_validate(payload)


def test_side_effect_completeness_requires_authority_and_policy_bindings() -> None:
    record = _api_record()
    governance = dict(record["governance"])  # type: ignore[arg-type]
    required_bindings = {
        GovernanceReference.ACTOR_AUTHORITY_ID,
        GovernanceReference.POLICY_ID,
        GovernanceReference.POLICY_BUNDLE_ID,
        GovernanceReference.POLICY_HASH,
        GovernanceReference.EXECUTION_BOUNDARY,
    }
    for reference in required_bindings:
        governance.pop(reference.value)
    record["governance"] = governance

    event = APIEventCollector().collect(record, tenant_id="tenant-a")

    assert event.completeness.status.value == "incomplete"
    assert required_bindings <= set(event.completeness.missing_governance_references)


def test_side_effect_classification_preserves_legacy_true_without_trusting_false() -> None:
    legacy_side_effect = GovernanceContext(is_side_effect=True)
    legacy_false = GovernanceContext(is_side_effect=False)

    assert (
        legacy_side_effect.side_effect_classification
        is SideEffectClassification.CONFIRMED_SIDE_EFFECT
    )
    assert legacy_side_effect.is_side_effect is True
    assert legacy_false.side_effect_classification is SideEffectClassification.UNKNOWN
    assert legacy_false.is_side_effect is False


def test_explicit_side_effect_classification_derives_consistent_legacy_projection() -> None:
    read_only = GovernanceContext(
        side_effect_classification=SideEffectClassification.CONFIRMED_READ_ONLY
    )
    side_effect = GovernanceContext(
        side_effect_classification=SideEffectClassification.CONFIRMED_SIDE_EFFECT
    )

    assert read_only.is_side_effect is False
    assert side_effect.is_side_effect is True
    with pytest.raises(ValidationError, match="is_side_effect must match"):
        GovernanceContext(
            is_side_effect=False,
            side_effect_classification=SideEffectClassification.CONFIRMED_SIDE_EFFECT,
        )
    with pytest.raises(ValidationError, match="is_side_effect must match"):
        GovernanceContext(
            is_side_effect=True,
            side_effect_classification=SideEffectClassification.CONFIRMED_READ_ONLY,
        )


def test_process_case_uses_explicit_sequence_before_timestamp() -> None:
    later_but_first = _api_record("evt-seq-0", sequence=0)
    later_but_first["occurred_at"] = "2026-07-09T16:00:00Z"
    earlier_but_second = _api_record("evt-seq-1", sequence=1)
    earlier_but_second["occurred_at"] = "2026-07-09T14:00:00Z"
    collector = APIEventCollector()
    case = build_process_case(
        [
            collector.collect(earlier_but_second, tenant_id="tenant-a"),
            collector.collect(later_but_first, tenant_id="tenant-a"),
        ],
        process_id="loan-v1",
        process_name="Loan Approval",
    )

    assert case.event_ids == ("evt-seq-0", "evt-seq-1")
    assert case.process_name == "Loan Approval"
    assert case.event_count == 2


def test_case_evidence_coverage_counts_only_side_effect_events() -> None:
    collector = APIEventCollector()
    events = []
    for index in range(99):
        record: dict[str, object] = {
            "event_id": f"observation-{index}",
            "tenant_id": "tenant-a",
            "case_id": "case-1",
            "sequence": index,
            "kind": "agent",
            "activity": "analyze",
            "occurred_at": "2026-07-09T15:00:00Z",
            "actor_kind": "agent",
            "agent_id": "agent-7",
        }
        events.append(collector.collect(record, tenant_id="tenant-a"))
    incomplete_side_effect: dict[str, object] = {
        "event_id": "side-effect-99",
        "tenant_id": "tenant-a",
        "case_id": "case-1",
        "sequence": 99,
        "kind": "tool_call",
        "activity": "payment.execute",
        "occurred_at": "2026-07-09T15:01:00Z",
        "actor_kind": "agent",
        "side_effect": True,
        "tool_name": "payment.execute",
    }
    side_effect = collector.collect(incomplete_side_effect, tenant_id="tenant-a")
    events.append(side_effect)

    case = build_process_case(events)

    assert case.evidence_coverage == side_effect.completeness.evidence_coverage
    assert case.evidence_coverage < 0.5


def test_generated_process_event_schema_is_current_and_valid() -> None:
    contract = Path(__file__).parents[1] / "contracts" / "process-event.schema.json"

    assert generate_schema(["--check", "--output", str(contract)]) == 0
    document = json.loads(contract.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(document)
    assert document["$id"].endswith("process-event/v1.0.json")
    taxonomy = document["$defs"]["ProcessEventKind"]["enum"]
    assert set(taxonomy) == {kind.value for kind in ProcessEventKind}
    classification = document["$defs"]["SideEffectClassification"]["enum"]
    assert set(classification) == {kind.value for kind in SideEffectClassification}
