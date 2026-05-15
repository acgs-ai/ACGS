"""Smoke tests for the FastAPI app skeleton (T069)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from agent_bus_analyzer.api import create_app


def test_healthz_returns_ok() -> None:
    client = TestClient(create_app())
    response = client.get("/api/bus/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_factory_returns_fresh_app_each_call() -> None:
    a = create_app()
    b = create_app()
    assert a is not b


def test_openapi_doc_advertises_title() -> None:
    client = TestClient(create_app())
    response = client.get("/api/bus/_openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"] == "agent-bus-analyzer"


def test_no_business_endpoints_yet() -> None:
    client = TestClient(create_app())
    # US1/US2 endpoints land later; Foundational scope is healthz + openapi only.
    assert client.get("/api/bus/traces").status_code == 404
    assert client.get("/api/bus/defects").status_code == 404
