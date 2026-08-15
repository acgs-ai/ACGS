"""Security and contract tests for the Process Intelligence query API."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from agent_bus_analyzer.api import create_app
from agent_bus_analyzer.auth import AuthenticatedPrincipal, set_validator
from agent_bus_analyzer.process_mining._canonical import sha256_canonical
from agent_bus_analyzer.process_mining.collectors.api_collector import APIEventCollector
from agent_bus_analyzer.process_mining.miners.conformance import (
    ConformanceAttestation,
    ConformanceEvidence,
    EvidenceState,
    SideEffectState,
    attest_conformance,
    hash_only_evidence_from_event,
)
from agent_bus_analyzer.process_mining.schemas.process_event import (
    ProcessEvent,
    SideEffectClassification,
    build_process_event,
)
from agent_bus_analyzer.process_mining.service import ProcessIntelligenceService
from agent_bus_analyzer.process_mining.storage.event_store import EventStore
from agent_bus_analyzer.store import TraceStore


def _principal(
    tenant_id: str,
    *,
    roles: frozenset[str] = frozenset({"governance-reviewer"}),
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(subject="reviewer-1", tenant_id=tenant_id, roles=roles)


def _event(
    event_id: str,
    *,
    tenant_id: str = "tenant-a",
    process_id: str = "loan-v1",
    case_id: str = "case-1",
    kind: str = "agent",
    side_effect: bool = False,
    sequence: int = 0,
    activity: str | None = None,
    outcome: str = "success",
    decision: str | None = None,
    complete_governance: bool = False,
) -> ProcessEvent:
    record: dict[str, object] = {
        "event_id": event_id,
        "tenant_id": tenant_id,
        "case_id": case_id,
        "process_id": process_id,
        "process_name": "Observed Workflow",
        "sequence": sequence,
        "kind": kind,
        "activity": activity or ("payment.execute" if side_effect else "analyze"),
        "occurred_at": (
            datetime(2026, 7, 9, 15, tzinfo=UTC) + timedelta(seconds=sequence)
        ).isoformat(),
        "actor_id": "agent-7",
        "actor_kind": "agent",
        "agent_id": "agent-7",
        "side_effect": side_effect,
        "outcome": outcome,
        "previous_hash": "0" * 64,
    }
    if side_effect:
        record["tool_name"] = activity or "payment.execute"
    if decision is not None:
        record["decision"] = decision
    if complete_governance:
        record["governance"] = {
            "is_side_effect": True,
            "actor_authority_id": "authority-1",
            "tool_name": activity or "payment.execute",
            "argument_hash": "a" * 64,
            "decision": "allow",
            "policy_id": "policy-1",
            "policy_version": "v1",
            "policy_bundle_id": "policy-bundle-1",
            "policy_hash": "d" * 64,
            "execution_boundary": "executor-gate-1",
            "decision_receipt_id": "receipt-1",
            "decision_receipt_hash": "b" * 64,
            "evidence_bundle_ids": ["evidence-1"],
            "audit_event_id": "audit-1",
            "audit_event_hash": "c" * 64,
            "replay_verified": True,
        }
    # The source-chain verifier hashes the source envelope without event_hash.
    record["event_hash"] = sha256_canonical(record)
    return APIEventCollector().collect(record, tenant_id=tenant_id)


def _with_execution_observed(event: ProcessEvent) -> ProcessEvent:
    payload = event.model_dump(
        mode="python",
        exclude={"normalization_hash", "completeness"},
    )
    payload["attributes"] = {**event.attributes, "execution_observed": True}
    return build_process_event(payload)


def _confirmed_read_only(event: ProcessEvent) -> ProcessEvent:
    payload = event.model_dump(
        mode="python",
        exclude={"normalization_hash", "completeness"},
    )
    payload["governance"] = event.governance.model_copy(
        update={
            "is_side_effect": False,
            "side_effect_classification": SideEffectClassification.CONFIRMED_READ_ONLY,
        }
    )
    return build_process_event(payload)


def _authoritative_attestation(
    event: ProcessEvent,
    *,
    event_id: str | None = None,
) -> ConformanceAttestation:
    payload = hash_only_evidence_from_event(
        event,
        side_effect_state=SideEffectState.EXECUTED,
    ).model_dump(mode="python")
    payload.update(
        {
            "event_id": event_id or event.event_id,
            "receipt": EvidenceState.VERIFIED,
            "policy": EvidenceState.VERIFIED,
            "audit": EvidenceState.VERIFIED,
            "authority": EvidenceState.VERIFIED,
            "signature": EvidenceState.VERIFIED,
            "source_chain": EvidenceState.VERIFIED,
            "replay": EvidenceState.VERIFIED,
            "evidence_bundle": EvidenceState.VERIFIED,
            "authoritative_verification": True,
            "verifier_name": "gove_zone.ReceiptVerifier",
            "verifier_signature_required": True,
            "verifier_expiry_required": True,
            "production_profile_verified": True,
        }
    )
    return attest_conformance(ConformanceEvidence.model_validate(payload))


@pytest.fixture(autouse=True)
def _reset_validator() -> None:
    set_validator(lambda _token: None)


def _authorized_client(engine: ProcessIntelligenceService, tenant_id: str) -> TestClient:
    set_validator(lambda token: _principal(tenant_id) if token == "valid" else None)
    return TestClient(create_app(process_engine=engine))


def test_exact_enterprise_routes_and_versioned_aliases_are_query_only() -> None:
    engine = ProcessIntelligenceService([_event("event-1")])
    client = _authorized_client(engine, "tenant-a")
    headers = {"Authorization": "Bearer valid"}

    required = {
        "/processes",
        "/processes/{process_id}",
        "/processes/{process_id}/variants",
        "/processes/{process_id}/compliance",
    }
    excluded = {"/risks", "/recommendations"}
    paths = client.get("/api/bus/_openapi.json").json()["paths"]
    assert required <= set(paths)
    assert excluded.isdisjoint(paths)
    for path in required:
        assert set(paths[path]) == {"get"}
        assert f"/api/process-intelligence/v1{path}" in paths
    assert all(f"/api/process-intelligence/v1{path}" not in paths for path in excluded)

    assert client.get("/processes", headers=headers).status_code == 200
    assert client.get("/api/process-intelligence/v1/processes", headers=headers).status_code == 200


def test_process_auth_fails_closed_before_engine_lookup() -> None:
    client = TestClient(create_app())
    assert client.get("/processes").status_code == 401

    set_validator(lambda _token: frozenset({"governance-reviewer"}))
    assert (
        client.get("/processes", headers={"Authorization": "Bearer role-only"}).status_code == 403
    )

    set_validator(lambda _token: _principal("tenant-a", roles=frozenset({"reader"})))
    assert (
        client.get("/processes", headers={"Authorization": "Bearer wrong-role"}).status_code == 403
    )

    set_validator(lambda _token: _principal("tenant-a"))
    assert client.get("/processes", headers={"Authorization": "Bearer valid"}).status_code == 503


def test_trusted_principal_is_only_tenant_source_and_store_hydrates_lazily(
    tmp_path: Path,
) -> None:
    store = EventStore(tmp_path / "events")
    store.append(_event("public-a", tenant_id="tenant-a", process_id="public-a"))
    store.append(_event("private-b", tenant_id="tenant-b", process_id="private-b"))
    engine = ProcessIntelligenceService(event_store=store)
    client = _authorized_client(engine, "tenant-a")
    headers = {
        "Authorization": "Bearer valid",
        "X-Tenant-ID": "tenant-b",
        "X-Organization-ID": "tenant-b",
    }

    response = client.get("/processes?tenant_id=tenant-b", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["tenant_id"] == "tenant-a"
    assert body["items"][0]["process_id"] == "public-a"

    # The service must not freeze its first tenant snapshot forever. A direct
    # observer append becomes visible on the next verified refresh.
    store.append(
        _event(
            "public-a-second",
            tenant_id="tenant-a",
            process_id="public-a",
            sequence=1,
        )
    )
    refreshed = client.get("/processes/public-a", headers=headers)
    assert refreshed.status_code == 200
    assert refreshed.json()["summary"]["event_count"] == 2

    cross_tenant = client.get("/processes/private-b", headers=headers)
    unknown = client.get("/processes/not-present", headers=headers)
    assert cross_tenant.status_code == unknown.status_code == 404
    assert cross_tenant.json() == unknown.json()


def test_confirmed_side_effect_without_receipt_denies_but_tool_call_investigates() -> None:
    events = (
        _event(
            "executed-without-receipt",
            process_id="executed",
            kind="tool_result",
            side_effect=True,
        ),
        _event(
            "call-with-unknown-result",
            process_id="attempted",
            kind="tool_call",
            side_effect=True,
        ),
    )
    client = _authorized_client(ProcessIntelligenceService(events), "tenant-a")
    headers = {"Authorization": "Bearer valid"}

    executed = client.get("/processes/executed/compliance", headers=headers)
    attempted = client.get("/processes/attempted/compliance", headers=headers)

    assert executed.status_code == attempted.status_code == 200
    assert executed.json()["deny_count"] == 1
    assert executed.json()["compliance_score"] == 0.0
    assert executed.json()["findings"][0]["outcome"] == "DENY"
    assert "receipt_missing" in executed.json()["findings"][0]["reasons"]
    assert attempted.json()["investigate_count"] == 1
    assert attempted.json()["compliance_score"] is None
    assert attempted.json()["findings"][0]["outcome"] == "INVESTIGATE"
    assert attempted.json()["findings"][0]["reasons"] == ["side_effect_status_unknown"]


def test_tool_result_denial_is_not_misclassified_as_a_compliant_block() -> None:
    executed = _event(
        "executed-after-denial",
        process_id="deny-violation",
        kind="tool_result",
        side_effect=True,
        outcome="denied",
        decision="deny",
    )
    report = ProcessIntelligenceService((executed,)).get_compliance(
        tenant_id="tenant-a",
        process_id="deny-violation",
    )
    assert report is not None
    assert report.allow_count == 0
    assert all("control_effective" not in finding.reasons for finding in report.findings)

    policy_denial = _event(
        "blocked-policy-decision",
        process_id="blocked",
        kind="denial",
        outcome="denied",
        decision="deny",
    )
    risks = ProcessIntelligenceService((policy_denial,)).list_risks(
        tenant_id="tenant-a",
        process_id="blocked",
    )
    assert risks.total == 0


def test_risks_preserve_typed_shared_receipt_and_audit_identifiers() -> None:
    shared_id = "ev_shared_receipt_audit_binding"
    source = _event(
        "shared-governance-id",
        process_id="shared-identifiers",
        kind="tool_result",
        side_effect=True,
        complete_governance=True,
    )
    payload = source.model_dump(
        mode="python",
        exclude={"normalization_hash", "completeness"},
    )
    payload["governance"] = source.governance.model_copy(
        update={
            "decision_receipt_id": shared_id,
            "audit_event_id": shared_id,
        }
    )
    event = build_process_event(payload)

    risks = ProcessIntelligenceService((event,)).list_risks(
        tenant_id="tenant-a",
        process_id="shared-identifiers",
    )

    assert risks.total == 1
    assert "receipt_id:ev_shared_receipt_audit_binding" in (risks.items[0].evidence_references)
    assert "audit_event_id:ev_shared_receipt_audit_binding" in (risks.items[0].evidence_references)


def test_service_revalidates_event_hashes_and_never_aliases_mutable_attributes() -> None:
    source = _event("immutable-source", process_id="integrity-v1")
    source.attributes["caller_mutation"] = "after-construction"
    with pytest.raises(ValidationError, match="normalization_hash"):
        ProcessIntelligenceService((source,))

    clean = _event("clean-source", process_id="integrity-v1")
    service = ProcessIntelligenceService((clean,))
    clean.attributes["caller_mutation"] = "after-registration"
    stored = service.events_for_process(tenant_id="tenant-a", process_id="integrity-v1")
    assert stored is not None
    assert "caller_mutation" not in stored[0].attributes

    stored[0].attributes["returned_copy_mutation"] = True
    reread = service.events_for_process(tenant_id="tenant-a", process_id="integrity-v1")
    assert reread is not None
    assert "returned_copy_mutation" not in reread[0].attributes


def test_compliance_score_counts_determinate_denies_and_rejects_mismatched_findings() -> None:
    allowed = _event(
        "allowed",
        process_id="scored",
        kind="tool_result",
        side_effect=True,
        complete_governance=True,
    )
    denied = _event(
        "denied",
        process_id="scored",
        case_id="case-2",
        kind="tool_result",
        side_effect=True,
        sequence=1,
    )

    def provider(event: ProcessEvent) -> ConformanceAttestation:
        if event.event_id == "allowed":
            return _authoritative_attestation(event)
        missing_payload = hash_only_evidence_from_event(
            event,
            side_effect_state=SideEffectState.EXECUTED,
        ).model_dump(mode="python")
        missing_payload.update(
            {
                "receipt": EvidenceState.MISSING,
                "policy": EvidenceState.MISSING,
                "audit": EvidenceState.MISSING,
                "authority": EvidenceState.MISSING,
                "signature": EvidenceState.MISSING,
                "source_chain": EvidenceState.VERIFIED,
                "replay": EvidenceState.MISSING,
                "evidence_bundle": EvidenceState.MISSING,
            }
        )
        return attest_conformance(ConformanceEvidence.model_validate(missing_payload))

    service = ProcessIntelligenceService(
        (allowed, denied),
        conformance_provider=provider,
    )
    report = service.get_compliance(tenant_id="tenant-a", process_id="scored")
    assert report is not None
    assert report.allow_count == 0
    assert report.deny_count == 1
    assert report.investigate_count == 1
    assert report.compliance_score is None
    assert report.verification_posture == "non_authoritative"

    mismatched = ProcessIntelligenceService(
        (allowed,),
        conformance_provider=lambda event: _authoritative_attestation(
            event,
            event_id="different-event",
        ),
    )
    with pytest.raises(ValueError, match="identity does not match"):
        mismatched.get_compliance(tenant_id="tenant-a", process_id="scored")


def test_configured_baseline_adds_behavior_risks_but_absent_baseline_makes_no_claim() -> None:
    baseline = (
        _confirmed_read_only(
            _event(
                "baseline-1",
                process_id="behavior-v1",
                case_id="baseline-case-1",
                kind="tool_call",
                activity="search",
            )
        ),
        _confirmed_read_only(
            _event(
                "baseline-2",
                process_id="behavior-v1",
                case_id="baseline-case-2",
                kind="tool_call",
                activity="search",
                sequence=1,
            )
        ),
    )
    current = (
        _confirmed_read_only(
            _event(
                "current-1",
                process_id="behavior-v1",
                case_id="current-case-1",
                kind="tool_call",
                activity="export.data",
            )
        ),
        _confirmed_read_only(
            _event(
                "current-2",
                process_id="behavior-v1",
                case_id="current-case-2",
                kind="tool_call",
                activity="export.data",
                sequence=1,
            )
        ),
    )

    no_baseline = ProcessIntelligenceService(current).list_risks(
        tenant_id="tenant-a",
        process_id="behavior-v1",
    )
    assert no_baseline.total == 0

    with_baseline = ProcessIntelligenceService(
        current,
        baseline_events=baseline,
    ).list_risks(tenant_id="tenant-a", process_id="behavior-v1")
    assert with_baseline.total > 0
    assert "new_tool" in {risk.category for risk in with_baseline.items}
    assert "behavior_drift" in {risk.category for risk in with_baseline.items}


def test_concrete_policy_gap_proposals_are_merged_as_inactive_only() -> None:
    event = _with_execution_observed(
        _event(
            "policy-gap",
            process_id="gap-v1",
            kind="tool_result",
            side_effect=True,
        )
    )
    recommendations = ProcessIntelligenceService((event,)).list_recommendations(
        tenant_id="tenant-a",
        process_id="gap-v1",
        limit=200,
    )

    concrete = [
        item for item in recommendations.items if item.algorithm_version == "policy-gap-1.0"
    ]
    assert len(concrete) == 1
    assert concrete[0].lifecycle_state == "inactive"
    assert concrete[0].status == "proposal_only"
    assert concrete[0].activation_available is False


def test_recommendation_pagination_counts_beyond_first_two_hundred() -> None:
    events = tuple(
        _event(
            f"effect-{index:03d}",
            process_id="large-process",
            case_id=f"case-{index:03d}",
            kind="failure",
            sequence=index,
        )
        for index in range(201)
    )
    service = ProcessIntelligenceService(events)
    first = service.list_recommendations(
        tenant_id="tenant-a",
        process_id="large-process",
        offset=0,
        limit=200,
    )
    second = service.list_recommendations(
        tenant_id="tenant-a",
        process_id="large-process",
        offset=200,
        limit=200,
    )

    assert first.total == second.total == 201
    assert len(first.items) == 200
    assert len(second.items) == 1
    assert all(item.status == "proposal_only" for item in first.items)
    assert all(item.activation_available is False for item in first.items)


def test_process_auth_rejections_preserve_audit_side_chain(tmp_path: Path) -> None:
    set_validator(lambda _token: None)
    trace_store = TraceStore(tmp_path / "traces")
    try:
        client = TestClient(
            create_app(
                store=trace_store,
                process_engine=ProcessIntelligenceService([_event("event-1")]),
            )
        )
        assert client.get("/processes").status_code == 401

        traces = trace_store.list_traces().items
        assert traces
        trace = trace_store.get_trace(traces[0].correlation_id)
        assert trace is not None
        assert trace.events[0].decision == "deny"
        assert trace.events[0].flagged_rule == "rbac.missing_bearer"
    finally:
        trace_store.close()
