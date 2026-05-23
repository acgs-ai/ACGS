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


@pytest.fixture()
def empty_tenant_client(monkeypatch):
    """Client whose configured API token has an empty tenant prefix (':secret').
    The auth layer must reject this as malformed — empty tenant must not be
    treated as a wildcard match-all."""
    monkeypatch.setenv("ACGS_API_TOKEN", ":secret-test-token")
    import governance.service.api as api_module
    api_module = importlib.reload(api_module)
    with TestClient(api_module.app) as test_client:
        yield test_client


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_api_auth_bypass",
    coverage_angle="validate_with_expired_token_returns_401",
)
def test_validate_with_expired_token_returns_401(client, monkeypatch):
    """Simulate token expiry via rotation: the original token is now stale once
    the server-side expected value has been rotated. The stale token must 401."""
    stale_token = "acme:secret-test-token"
    # Rotate the server-side expected token to invalidate the previously valid one.
    monkeypatch.setenv("ACGS_API_TOKEN", "acme:rotated-token-v2")
    response = client.post(
        "/govern/validate",
        json=_validate_payload(),
        headers={"Authorization": f"Bearer {stale_token}"},
    )
    assert response.status_code == 401, (
        f"stale (rotated/expired) token must be rejected; got {response.status_code}"
    )


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_api_auth_bypass",
    coverage_angle="validate_with_malformed_bearer_prefix_returns_401",
)
def test_validate_with_malformed_bearer_prefix_returns_401(client):
    """Authorization headers that do not use the exact 'Bearer ' scheme must be
    rejected per RFC 6750; loose-prefix parsing is a known bypass class."""
    valid_token = "acme:secret-test-token"
    malformed_headers = [
        {"Authorization": f"Token {valid_token}"},
        {"Authorization": f"Basic {valid_token}"},
        {"Authorization": f"BearerX {valid_token}"},
        {"Authorization": valid_token},  # no scheme at all
    ]
    for headers in malformed_headers:
        response = client.post(
            "/govern/validate",
            json=_validate_payload(),
            headers=headers,
        )
        assert response.status_code == 401, (
            f"malformed auth header must be 401: headers={headers} got {response.status_code}"
        )


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_api_auth_bypass",
    coverage_angle="audit_query_with_wrong_token_returns_401",
)
def test_audit_query_with_wrong_token_returns_401(client):
    """The audit-query endpoint must enforce bearer-token auth: a token that
    does not match the configured value yields 401. Pairs with the seed
    audit_query_no_token_401 case (different angle: wrong token vs no token)."""
    response = client.get(
        "/audit/query",
        headers={"Authorization": "Bearer not-the-real-token"},
    )
    assert response.status_code == 401


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_api_auth_bypass",
    coverage_angle="validate_rejects_token_with_empty_tenant_claim",
)
def test_validate_rejects_token_with_empty_tenant_claim(empty_tenant_client):
    """A configured API token with an empty tenant prefix (':secret-token') is
    structurally invalid: the empty tenant must not be treated as a wildcard
    match-all. Any /govern/validate call must fail closed with 401."""
    response = empty_tenant_client.post(
        "/govern/validate",
        json=_validate_payload(),
        headers={"Authorization": "Bearer :secret-test-token"},
    )
    assert response.status_code == 401, (
        f"empty tenant in token must be rejected; got {response.status_code}"
    )
    assert response.status_code != 200, "empty tenant must not act as wildcard"
