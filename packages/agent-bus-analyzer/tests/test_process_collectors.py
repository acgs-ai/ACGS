"""Read-only and fail-closed collector tests — audit-only slice."""

from __future__ import annotations

import copy
import json

import pytest

from agent_bus_analyzer.process_mining._canonical import sha256_canonical
from agent_bus_analyzer.process_mining.collectors.audit_collector import AuditCollector
from agent_bus_analyzer.process_mining.errors import SourceIntegrityError
from agent_bus_analyzer.process_mining.miners.conformance import (
    ConformanceOutcome,
    SideEffectState,
    evaluate_conformance,
    hash_only_evidence_from_event,
)
from agent_bus_analyzer.process_mining.schemas.process_event import ProcessEventKind


def _audit_record(event_id: str, previous_hash: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "tenant_id": "tenant-a",
        "decision": "allow",
        "tool": "runtime.Write",
        "argument_hash": "a" * 64,
        "actor_authority_id": "authority-1",
        "policy_id": "policy-1",
        "policy_version": "policy-v1",
        "policy_bundle_id": "policy-bundle-v1",
        "policy_hash": "b" * 64,
        "execution_boundary": "runtime-production",
        "event_id": event_id,
        "timestamp_iso": "2026-07-09T15:00:00+00:00",
        "actor": "agent-1",
        "decision_request_hash": "d" * 64,
        "evidence_bundle_ids": ["bundle-1"],
        "previous_hash": previous_hash,
        "raw_args": {"password": "do-not-persist"},
        "prompt": "private prompt text",
    }
    payload["event_hash"] = sha256_canonical(payload)
    return payload


def test_audit_collector_verifies_contiguous_chain_without_mutation_or_secret_copy() -> None:
    first = _audit_record("audit-1", "0" * 64)
    second = _audit_record("audit-2", str(first["event_hash"]))
    before = copy.deepcopy([first, second])
    before_bytes = json.dumps(before, sort_keys=True).encode()

    events = AuditCollector().collect_many([first, second], tenant_id="tenant-a")

    assert [first, second] == before
    assert json.dumps([first, second], sort_keys=True).encode() == before_bytes
    assert all(event.integrity.chain_status.value == "verified" for event in events)
    assert all(event.kind is ProcessEventKind.AUDIT for event in events)
    assert all(event.governance.is_side_effect is False for event in events)
    assert all(event.governance.decision_receipt_id is None for event in events)
    assert all(event.governance.decision_receipt_hash is None for event in events)
    assert all(event.governance.policy_bundle_id == "policy-bundle-v1" for event in events)
    assert all(event.governance.policy_hash == "b" * 64 for event in events)
    assert all(event.governance.execution_boundary == "runtime-production" for event in events)
    assert all(event.completeness.status.value == "not_applicable" for event in events)
    serialized = json.dumps([event.model_dump(mode="json") for event in events])
    assert "do-not-persist" not in serialized
    assert "private prompt text" not in serialized
    assert "raw_args" not in serialized
    assert '"prompt"' not in serialized
    unknown = hash_only_evidence_from_event(events[0], side_effect_state=SideEffectState.UNKNOWN)
    executed = hash_only_evidence_from_event(events[0], side_effect_state=SideEffectState.EXECUTED)
    assert evaluate_conformance(unknown).outcome is ConformanceOutcome.INVESTIGATE
    assert evaluate_conformance(executed).outcome is not ConformanceOutcome.ALLOW


def test_audit_collector_rejects_tamper_and_wrong_predecessor() -> None:
    record = _audit_record("audit-1", "0" * 64)
    record["tool"] = "runtime.Delete"
    with pytest.raises(SourceIntegrityError, match="event hash mismatch"):
        AuditCollector().collect(record, tenant_id="tenant-a")

    intact = _audit_record("audit-2", "f" * 64)
    with pytest.raises(SourceIntegrityError, match="predecessor mismatch"):
        AuditCollector().collect(
            intact,
            tenant_id="tenant-a",
            expected_previous_hash="e" * 64,
        )
