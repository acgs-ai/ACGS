from __future__ import annotations

import importlib

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("ACGS_API_TOKEN", "acme:secret-test-token")
    import governance.service.api as api_module

    api_module = importlib.reload(api_module)
    with TestClient(api_module.app) as test_client:
        yield test_client


def _validate_payload(actor_tenant: str = "acme", cross_tenant: bool = False) -> dict:
    metadata: dict = {"policy_citations": ["CONTRACT-AUTHORITY-001"]}
    if cross_tenant:
        metadata["cross_tenant_delegation"] = True
    return {
        "actor": {"id": "agent-legal-1", "role": "LegalOps", "tenant": actor_tenant},
        "intent": "Redline supplier agreement",
        "action_type": "contract.redline",
        "resource": "contracts/supplier-123",
        "inputs_hash": "sha256:test",
        "metadata": metadata,
    }


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_api_auth_bypass",
    coverage_angle="validate_no_token_401",
)
def test_validate_without_token_returns_401(client):
    response = client.post("/govern/validate", json=_validate_payload())
    assert response.status_code == 401


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_api_auth_bypass",
    coverage_angle="validate_invalid_token_401",
)
def test_validate_with_invalid_token_returns_401(client):
    response = client.post(
        "/govern/validate",
        json=_validate_payload(),
        headers={"Authorization": "Bearer wrong"},
    )
    assert response.status_code == 401


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_api_auth_bypass",
    coverage_angle="validate_tenant_mismatch_403",
)
def test_validate_with_tenant_mismatch_returns_403(client):
    response = client.post(
        "/govern/validate",
        json=_validate_payload(actor_tenant="globex"),
        headers={"Authorization": "Bearer acme:secret-test-token"},
    )
    assert response.status_code == 403


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_api_auth_bypass",
    coverage_angle="validate_matched_tenant_200",
)
def test_validate_with_matched_tenant_returns_200(client):
    response = client.post(
        "/govern/validate",
        json=_validate_payload(actor_tenant="acme"),
        headers={"Authorization": "Bearer acme:secret-test-token"},
    )
    assert response.status_code == 200
    body = response.json()
    assert "allow" in body
    assert "event_id" in body


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_api_auth_bypass",
    coverage_angle="audit_query_no_token_401",
)
def test_audit_query_without_token_returns_401(client):
    response = client.get("/audit/query")
    assert response.status_code == 401
