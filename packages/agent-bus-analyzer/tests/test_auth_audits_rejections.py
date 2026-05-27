"""FR-011 — unauthorized reads MUST themselves be recorded as audit events.

Architect blocker / Security HIGH#2 / Code-reviewer cross-reference: the
rejection audit was previously only a log line; this test asserts it now
lands in the TraceStore as a synthetic deny-decision event.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from agent_bus_analyzer.api import create_app
from agent_bus_analyzer.auth import set_validator
from agent_bus_analyzer.store import TraceStore


def test_missing_bearer_appends_audit_event(tmp_path: Path) -> None:
    set_validator(lambda _t: None)
    store = TraceStore(tmp_path)
    client = TestClient(create_app(store=store))

    response = client.get("/api/bus/traces")
    assert response.status_code == 401

    listed = store.list_traces().items
    assert listed, "no audit trace recorded on 401"
    cid = listed[0].correlation_id
    assert cid.startswith("rbac-")
    trace = store.get_trace(cid)
    assert trace is not None
    assert trace.events[0].kind == "decision"
    assert trace.events[0].decision == "deny"
    assert trace.events[0].source_agent == "api:query"
    assert trace.events[0].flagged_rule == "rbac.missing_bearer"


def test_unauthorized_role_appends_audit_event(tmp_path: Path) -> None:
    set_validator(lambda _t: frozenset({"random-role"}))
    store = TraceStore(tmp_path)
    client = TestClient(create_app(store=store))

    response = client.get("/api/bus/traces", headers={"Authorization": "Bearer x"})
    assert response.status_code == 403

    listed = store.list_traces().items
    assert listed
    trace = store.get_trace(listed[0].correlation_id)
    assert trace is not None
    assert trace.events[0].flagged_rule == "rbac.insufficient_role"


def test_no_audit_emitted_when_store_not_configured() -> None:
    """Tests that don't wire a store still get clean 401s (no crash)."""
    set_validator(lambda _t: None)
    client = TestClient(create_app(store=None))
    assert client.get("/api/bus/traces").status_code == 401
