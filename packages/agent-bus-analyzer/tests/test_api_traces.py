"""T020 + T070 — query API endpoint integration tests.

Boots the app with a real TraceStore, seeds traces, asserts the endpoints
return shapes that validate against `trace-query.schema.json`. Auth is
exercised via the RBAC dependency.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema
from fastapi.testclient import TestClient
from referencing import Registry, Resource

from agent_bus_analyzer.api import create_app
from agent_bus_analyzer.auth import set_validator
from agent_bus_analyzer.store import TraceStore

CONTRACTS_DIR = Path(__file__).resolve().parents[1] / "contracts"


def _query_schema() -> dict[str, Any]:
    return json.loads((CONTRACTS_DIR / "trace-query.schema.json").read_text())


def _registry() -> Registry:
    event_schema = json.loads((CONTRACTS_DIR / "trace-event.schema.json").read_text())
    return Registry().with_resource(
        "trace-event.schema.json",
        Resource.from_contents(event_schema),
    )


def _seed_event(cid: str, idx: int) -> dict[str, Any]:
    return {
        "event_id": f"00000000-0000-0000-0000-0000000000{idx:>02}",
        "correlation_id": cid,
        "recorded_at": datetime.now(UTC).isoformat(),
        "source_agent": "claude:worker-03",
        "target_handler_declared": "policy.evaluate",
        "target_handler_resolved": None,
        "payload_ref": f"sha256:{idx:0>64}",
        "kind": "dispatch",
        "decision": None,
        "flagged_rule": None,
        "audit_receipt_hash": None,
        "constitutional_hash": "608508a9bd224290",
        "status": "completed",
    }


def _client(tmp_path: Path) -> TestClient:
    store = TraceStore(tmp_path / "store")
    for i in range(3):
        store.append(_seed_event("trace-a", i))
    set_validator(lambda _t: frozenset({"governance-reviewer"}))
    return TestClient(create_app(store=store))


def test_list_traces_requires_auth(tmp_path: Path) -> None:
    set_validator(lambda _t: None)
    client = TestClient(create_app(store=TraceStore(tmp_path / "s")))
    assert client.get("/api/bus/traces").status_code == 401


def test_list_traces_returns_schema_conforming_response(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/bus/traces", headers={"Authorization": "Bearer x"})
    assert response.status_code == 200, response.text
    jsonschema.Draft202012Validator(_query_schema(), registry=_registry()).validate(response.json())


def test_get_trace_returns_schema_conforming_response(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get(
        "/api/bus/traces/trace-a",
        headers={"Authorization": "Bearer x"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    jsonschema.Draft202012Validator(_query_schema(), registry=_registry()).validate(body)
    assert body["kind"] == "single-trace"
    assert body["integrity_status"] == "intact"
    assert len(body["events"]) == 3


def test_get_receipt_proof_returns_counter_signed_packet(tmp_path: Path) -> None:
    receipt_id = "00000000-0000-0000-0000-000000000099"
    phoenix_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    phoenix_span_id = "53995c3f42cd8ad8"
    phoenix_parent_span_id = "00f067aa0ba902b7"
    store = TraceStore(tmp_path / "store")
    store.append(
        {
            **_seed_event("trace-receipt", 0),
            "phoenix_trace_id": phoenix_trace_id,
            "phoenix_span_id": "1111111111111111",
        }
    )
    decision = {
        **_seed_event("trace-receipt", 1),
        "event_id": receipt_id,
        "kind": "decision",
        "decision": "deny",
        "flagged_rule": "P-1207",
        "target_handler_declared": "matter.fetch",
        "target_handler_resolved": "matter.fetch",
        "audit_receipt_hash": "sha256:8b38f0a1c2",
        "status": "policy-violation",
        "phoenix_trace_id": phoenix_trace_id,
        "phoenix_span_id": phoenix_span_id,
        "phoenix_parent_span_id": phoenix_parent_span_id,
    }
    store.append(decision)
    set_validator(lambda _t: frozenset({"governance-reviewer"}))
    client = TestClient(create_app(store=store))

    response = client.get(
        f"/api/bus/receipts/{receipt_id}",
        headers={"Authorization": "Bearer x"},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    jsonschema.Draft202012Validator(_query_schema(), registry=_registry()).validate(body)
    assert body["kind"] == "receipt-proof"
    assert body["receipt_id"] == receipt_id
    assert body["receipt_hash"] == "sha256:8b38f0a1c2"
    assert body["correlation_id"] == "trace-receipt"
    assert body["hash_chain_verified"] is True
    assert body["policy_path"] == ["matter.fetch", "P-1207"]
    assert body["phoenix_trace_id"] == phoenix_trace_id
    assert body["phoenix_span_id"] == "1111111111111111"
    assert body["phoenix_parent_span_id"] == phoenix_parent_span_id
    assert body["trace"]["phoenix_trace_id"] == phoenix_trace_id
    assert body["events"][1]["phoenix_span_id"] == phoenix_span_id
    packet = json.loads(body["signed_evidence_packet"])
    assert packet["counter_signature"].startswith("agent-bus-analyzer:")
    assert packet["phoenix_trace_id"] == phoenix_trace_id
    assert packet["phoenix_span_id"] == "1111111111111111"
    assert packet["phoenix_parent_span_id"] == phoenix_parent_span_id


def test_get_trace_unknown_yields_404(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get(
        "/api/bus/traces/unknown",
        headers={"Authorization": "Bearer x"},
    )
    assert response.status_code == 404


def test_get_receipt_proof_unknown_yields_404(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get(
        "/api/bus/receipts/unknown-receipt",
        headers={"Authorization": "Bearer x"},
    )
    assert response.status_code == 404


def test_traces_endpoint_503_when_store_not_configured() -> None:
    set_validator(lambda _t: frozenset({"governance-reviewer"}))
    client = TestClient(create_app())  # no store
    response = client.get("/api/bus/traces", headers={"Authorization": "Bearer x"})
    assert response.status_code == 503
