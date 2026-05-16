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


def test_traces_endpoint_requires_store_or_auth() -> None:
    # US1 mounted the traces endpoint with RBAC. Without a token, 401.
    # The Foundational invariant kept here: the app still boots without a store.
    client = TestClient(create_app())
    response = client.get("/api/bus/traces")
    assert response.status_code == 401
