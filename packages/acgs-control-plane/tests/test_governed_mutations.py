"""The core invariant: no valid Decision Receipt, no side effect.

Every mutation is receipted; a policy DENY leaves a deny receipt and NO
database row; ESCALATE leaves an escalate receipt and NO database row.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import sqlalchemy as sa
from fastapi.testclient import TestClient

from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import AgentRecord

BOOTSTRAP_TOKEN = "test-bootstrap-token"


def _agent_count(client: TestClient, org_id: str) -> int:
    with client.app.state.session_factory() as session:
        count = session.scalar(
            sa.text("SELECT COUNT(*) FROM agents WHERE org_id = :org_id"),
            {"org_id": org_id},
        )
    assert isinstance(count, int)
    return count


def _migrated_client(tmp_path: Path, audit_dir: Path) -> TestClient:
    database_url = f"sqlite:///{tmp_path / 'managed-control-plane.sqlite3'}"
    upgrade_database(database_url)
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=audit_dir,
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )
    return TestClient(app, raise_server_exceptions=False)


def _bootstrap_org(client: TestClient) -> dict[str, Any]:
    resp = client.post(
        "/orgs",
        json={
            "name": "Acme AI",
            "admin_name": "Root Admin",
            "admin_email": "root@acme.example.com",
        },
        headers={"X-Bootstrap-Token": BOOTSTRAP_TOKEN},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_agent_register_without_default_scope_fails_closed_before_receipt(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    before = _agent_count(client, org["org_id"])
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
    assert resp.status_code == 409, resp.text
    assert resp.json()["code"] == "SCOPE_NOT_READY"
    assert _agent_count(client, org_id) == before


def test_agent_register_rbac_denial_has_no_governed_side_effect(
    client: TestClient,
    org: dict[str, Any],
    make_user: Any,
) -> None:
    org_id = org["org_id"]
    before = _agent_count(client, org_id)
    viewer_headers = make_user("viewer")
    resp = client.post(
        f"/orgs/{org_id}/agents",
        json={"name": "sketchy-bot", "trust_tier": "internal"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403, resp.text

    # THE invariant: no side effect happened.
    assert _agent_count(client, org_id) == before


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


def test_agent_lifecycle_status_change_is_governed(tmp_path: Path, audit_dir: Path) -> None:
    client = _migrated_client(tmp_path, audit_dir)
    org = _bootstrap_org(client)
    org_id = org["org_id"]
    admin_headers = {"X-API-Key": org["admin_api_key"]}
    with client.app.state.session_factory.begin() as session:
        agent = AgentRecord(org_id=org_id, name="bot")
        session.add(agent)
        session.flush()
        agent_id = agent.id
    resp = client.patch(
        f"/orgs/{org_id}/agents/{agent_id}/status",
        json={"status": "suspended"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "suspended"
    assert resp.json()["receipt_id"]
