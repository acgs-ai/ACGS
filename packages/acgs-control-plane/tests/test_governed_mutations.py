"""The core invariant: no valid Decision Receipt, no side effect.

Every mutation is receipted; a policy DENY leaves a deny receipt and NO
database row; ESCALATE leaves an escalate receipt and NO database row.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient


def test_agent_register_produces_receipt(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    resp = client.post(
        f"/orgs/{org_id}/agents",
        json={
            "name": "deploy-bot",
            "description": "governed deployer",
            "trust_tier": "internal",
            "allowed_tools": ["deploy.staging"],
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    agent = resp.json()
    assert agent["receipt_id"]

    receipt = client.get(
        f"/orgs/{org_id}/receipts/{agent['receipt_id']}", headers=admin_headers
    ).json()
    assert receipt["tool"] == "agent.register"
    assert receipt["decision"] == "allow"
    assert receipt["payload"]["result_hash"] is not None
    assert receipt["audit_hash"]


def test_policy_deny_blocks_side_effect_and_persists_receipt(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    publish_and_activate: Any,
) -> None:
    org_id = org["org_id"]
    publish_and_activate(
        org_id,
        admin_headers,
        rules=[
            {
                "id": "no-untrusted-agents",
                "effect": "deny",
                "tools": ["agent.register"],
                "state_equals": {"trust_tier": "untrusted"},
                "reason": "untrusted agents are not allowed in this org",
            }
        ],
    )
    resp = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "sketchy-bot", "trust_tier": "untrusted"},
        headers=admin_headers,
    )
    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body["status"] == "denied"
    assert body["decision"] == "deny"
    assert "untrusted" in body["reason"]

    # Deny receipt is persisted and queryable.
    receipt = client.get(
        f"/orgs/{org_id}/receipts/{body['receipt_id']}", headers=admin_headers
    ).json()
    assert receipt["decision"] == "deny"
    assert receipt["tool"] == "agent.register"

    # THE invariant: no side effect happened.
    agents = client.get(f"/orgs/{org_id}/agents", headers=admin_headers).json()
    assert all(a["name"] != "sketchy-bot" for a in agents)

    # A trusted registration still passes under the same policy.
    ok = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "trusted-bot", "trust_tier": "internal"},
        headers=admin_headers,
    )
    assert ok.status_code == 201


def test_policy_escalate_returns_202_and_no_side_effect(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    publish_and_activate: Any,
) -> None:
    org_id = org["org_id"]
    publish_and_activate(
        org_id,
        admin_headers,
        rules=[
            {
                "id": "exports-need-approval",
                "effect": "escalate",
                "tools": ["export.generate"],
                "reason": "compliance exports require human approval in this org",
            }
        ],
    )
    resp = client.post(f"/orgs/{org_id}/exports", json={"note": "q3"}, headers=admin_headers)
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "pending_approval"
    assert body["decision"] == "escalate"

    assert client.get(f"/orgs/{org_id}/exports", headers=admin_headers).json() == []
    receipt = client.get(
        f"/orgs/{org_id}/receipts/{body['receipt_id']}", headers=admin_headers
    ).json()
    assert receipt["decision"] == "escalate"


def test_policy_change_control_governs_activation(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    publish_and_activate: Any,
) -> None:
    """Once an active policy escalates policy.activate, further activations are held."""
    org_id = org["org_id"]
    publish_and_activate(
        org_id,
        admin_headers,
        rules=[
            {
                "id": "change-control",
                "effect": "escalate",
                "tools": ["policy.activate"],
                "reason": "policy changes require approval",
            }
        ],
        policy_id="change-control",
    )
    pub = client.post(
        f"/orgs/{org_id}/policies",
        json={"policy_id": "next", "rules": [{"id": "r", "effect": "deny", "tools": ["x"]}]},
        headers=admin_headers,
    )
    assert pub.status_code == 201
    resp = client.post(
        f"/orgs/{org_id}/policies/{pub.json()['bundle_id']}/activate", headers=admin_headers
    )
    assert resp.status_code == 202
    # The change-control bundle is still the active one.
    policies = client.get(f"/orgs/{org_id}/policies", headers=admin_headers).json()
    active = [p for p in policies if p["status"] == "active"]
    assert len(active) == 1
    assert active[0]["policy_id"] == "change-control"


def test_invalid_policy_bundle_is_422(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    resp = client.post(
        f"/orgs/{org['org_id']}/policies",
        json={"policy_id": "bad", "rules": [{"effect": "deny"}]},  # missing rule id
        headers=admin_headers,
    )
    assert resp.status_code == 422


def test_simulate_previews_without_receipt(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    publish_and_activate: Any,
) -> None:
    org_id = org["org_id"]
    publish_and_activate(
        org_id,
        admin_headers,
        rules=[
            {
                "id": "no-prod-deploys",
                "effect": "deny",
                "tools": ["deploy.production"],
                "reason": "production deploys are governed",
            }
        ],
    )
    before = client.get(f"/orgs/{org_id}/receipts", headers=admin_headers).json()["total"]
    resp = client.post(
        f"/orgs/{org_id}/policies/simulate",
        json={"tool": "deploy.production", "args": {"service": "api"}},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "deny"
    assert resp.json()["matched_rules"] == ["no-prod-deploys"]
    after = client.get(f"/orgs/{org_id}/receipts", headers=admin_headers).json()["total"]
    assert after == before  # simulation is pure: no receipt, no audit event


def test_agent_lifecycle_status_change_is_governed(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    agent = client.post(
        f"/orgs/{org_id}/agents", json={"name": "bot"}, headers=admin_headers
    ).json()
    resp = client.patch(
        f"/orgs/{org_id}/agents/{agent['agent_id']}/status",
        json={"status": "suspended"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "suspended"
    assert resp.json()["receipt_id"]
