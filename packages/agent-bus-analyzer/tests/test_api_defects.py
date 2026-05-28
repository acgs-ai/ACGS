"""GET /api/bus/defects integration tests (T043).

Uses the FastAPI TestClient. Auth is wired via set_validator so we can
exercise both the 401 path and the happy path.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_bus_analyzer.api import create_app
from agent_bus_analyzer.auth import set_validator
from agent_bus_analyzer.store import TraceStore

# ---- auth helpers ----------------------------------------------------------


def _allow_all(token: str) -> frozenset[str]:
    return frozenset({"governance-reviewer"})


def _deny_all(_token: str) -> frozenset[str] | None:
    return None


# ---- fixtures --------------------------------------------------------------


@pytest.fixture()
def store(tmp_path: Path) -> TraceStore:
    return TraceStore(tmp_path / "store")


@pytest.fixture()
def authed_client(store: TraceStore) -> TestClient:
    set_validator(_allow_all)
    app = create_app(store=store)
    return TestClient(app)


# ---- tests -----------------------------------------------------------------


def test_defects_requires_auth() -> None:
    """No bearer token → 401."""
    set_validator(_deny_all)
    client = TestClient(create_app())
    response = client.get("/api/bus/defects")
    assert response.status_code == 401


def test_defects_requires_store() -> None:
    """Valid auth but no store → 503."""
    set_validator(_allow_all)
    client = TestClient(create_app(store=None))
    response = client.get(
        "/api/bus/defects",
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 503


def test_defects_returns_wiring_defect_summary(authed_client: TestClient) -> None:
    """Happy path: returns a WiringDefectSummary with correct kind."""
    response = authed_client.get(
        "/api/bus/defects",
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["kind"] == "wiring-defect-summary"
    assert "findings" in data
    assert "refreshed_at" in data


def test_defects_cache_control_header(authed_client: TestClient) -> None:
    """Cache-Control: max-age=60 on the default window."""
    response = authed_client.get(
        "/api/bus/defects",
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    cc = response.headers.get("cache-control", "")
    assert "max-age=60" in cc


def test_defects_custom_window_seconds(authed_client: TestClient) -> None:
    """window_seconds query param is honoured in Cache-Control."""
    response = authed_client.get(
        "/api/bus/defects?window_seconds=120",
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    cc = response.headers.get("cache-control", "")
    assert "max-age=120" in cc


def test_defects_empty_store_no_findings(authed_client: TestClient) -> None:
    """No events in store → empty findings list."""
    response = authed_client.get(
        "/api/bus/defects",
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    assert response.json()["findings"] == []


def test_defects_findings_appear_after_event(store: TraceStore) -> None:
    """After persisting a dispatch to an unknown handler, defects surface."""
    set_validator(_allow_all)

    # Append a dispatch event directly into the store (bypassing bus).
    now = datetime.now(UTC)
    event: dict = {
        "event_id": str(uuid.uuid4()),
        "correlation_id": "corr-defect-test",
        "recorded_at": now.isoformat(),
        "source_agent": "test-agent",
        "target_handler_declared": "not.registered",
        "target_handler_resolved": None,
        "payload_ref": "sha256:" + "a" * 64,
        "kind": "dispatch",
        "decision": None,
        "flagged_rule": None,
        "audit_receipt_hash": None,
        "constitutional_hash": "608508a9bd224290",
        "status": "completed",
    }
    store.append(event)

    app = create_app(store=store)
    client = TestClient(app)
    response = client.get(
        "/api/bus/defects",
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    findings = response.json()["findings"]
    unwired = [f for f in findings if f["kind"] == "unwired_dispatch"]
    # The registry is empty (no bus wired), so dispatch goes unwired.
    assert any(f["handler_name"] == "not.registered" for f in unwired)
