from __future__ import annotations

import importlib
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402 — importorskip gates this

PACKAGE_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ACGS_API_TOKEN", "acme:secret-test-token")
    monkeypatch.delenv("ACGS_ADMIN_TENANTS", raising=False)
    monkeypatch.setenv("ACGS_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("ACGS_ROLES_PATH", str(PACKAGE_ROOT / "governance" / "roles.json"))
    monkeypatch.setenv("ACGS_POLICY_DIR", str(PACKAGE_ROOT / "governance" / "policies" / "2026-05"))
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


GOVE_ZONE_REPORT: dict = {
    "dataset": "agentdojo-mini",
    "policy_version": "ruleset/workspace-agent-risk/v1/abc123",
    "scenario_count": 1,
    "passed": 1,
    "failed": 0,
    "attack_success_rate": 0.0,
    "utility_retention_rate": None,
    "p95_latency_ms": 0.5,
    "results": [
        {
            "id": "attack-secret-read",
            "category": "attack",
            "expected_decision": "deny",
            "actual_decision": "deny",
            "passed": True,
            "matched_rules": ["BLOCK_SECRET_EXFIL"],
            "reason": "secret paths require explicit security review",
            "latency_ms": 0.5,
            "tags": ["indirect-prompt-injection"],
        }
    ],
}


def test_ingest_evaluation_report_endpoint_requires_auth(client):
    response = client.post("/evidence/evaluation-report", json={"report": GOVE_ZONE_REPORT})
    assert response.status_code == 401


def test_ingest_evaluation_report_endpoint_records_claim_safe_evidence(client):
    response = client.post(
        "/evidence/evaluation-report",
        json={"tenant": "acme", "actor_id": "console-eval-runner", "report": GOVE_ZONE_REPORT},
        headers={"Authorization": "Bearer acme:secret-test-token"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "passed"
    assert body["source"] == "gove-zone"
    assert body["normalized_report"]["results"][0]["matched_rules"] == ["BLOCK_SECRET_EXFIL"]
    assert body["report_hash"]

    audit_response = client.get(
        "/audit/query?risk_tag=evaluation:gove-zone",
        headers={"Authorization": "Bearer acme:secret-test-token"},
    )
    assert audit_response.status_code == 200
    audit_events = audit_response.json()
    assert len(audit_events) == 1
    assert audit_events[0]["request"]["metadata"]["evaluation_evidence"]["report_hash"] == body["report_hash"]

    evidence_response = client.get(
        "/evidence/evaluation-reports?status=passed",
        headers={"Authorization": "Bearer acme:secret-test-token"},
    )
    assert evidence_response.status_code == 200
    evidence_items = evidence_response.json()
    assert [item["report_hash"] for item in evidence_items] == [body["report_hash"]]
    assert evidence_items[0]["event_hash"] == body["event_hash"]
    assert evidence_items[0]["claim_safe"] is True


def test_ingest_evaluation_report_endpoint_rejects_cross_tenant_without_admin(client):
    response = client.post(
        "/evidence/evaluation-report",
        json={"tenant": "globex", "report": GOVE_ZONE_REPORT},
        headers={"Authorization": "Bearer acme:secret-test-token"},
    )

    assert response.status_code == 403
