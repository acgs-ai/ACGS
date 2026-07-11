"""Bootstrap, authentication, tenant isolation, and RBAC behavior."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from acgs_control_plane.app import create_app
from acgs_control_plane.config import Settings


def test_bootstrap_requires_token(client: TestClient) -> None:
    body = {"name": "NoToken Inc", "admin_name": "A", "admin_email": "a@x.example.com"}
    assert client.post("/orgs", json=body).status_code == 401
    assert (
        client.post("/orgs", json=body, headers={"X-Bootstrap-Token": "wrong"}).status_code == 401
    )


def test_bootstrap_disabled_when_no_token_configured(tmp_path: Any) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'x.sqlite3'}",
        audit_dir=tmp_path / "audit",
        bootstrap_token=None,
    )
    client = TestClient(create_app(settings))
    resp = client.post(
        "/orgs",
        json={"name": "X", "admin_name": "A", "admin_email": "a@x.example.com"},
        headers={"X-Bootstrap-Token": "anything"},
    )
    assert resp.status_code == 503


def test_org_creation_emits_genesis_receipt(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    resp = client.get(f"/orgs/{org['org_id']}/receipts", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["tool"] == "org.create"
    assert data["items"][0]["decision"] == "allow"


def test_missing_and_invalid_api_key(client: TestClient, org: dict[str, Any]) -> None:
    url = f"/orgs/{org['org_id']}/agents"
    assert client.get(url).status_code == 401
    assert client.get(url, headers={"X-API-Key": "acp_bogus"}).status_code == 401


def test_cross_tenant_access_is_404(
    client: TestClient, org: dict[str, Any], bootstrap_headers: dict[str, str]
) -> None:
    other = client.post(
        "/orgs",
        json={"name": "Other Org", "admin_name": "B", "admin_email": "b@other.example.com"},
        headers=bootstrap_headers,
    ).json()
    # Org A's admin key against org B's resources: 404, not 403.
    headers = {"X-API-Key": org["admin_api_key"]}
    assert client.get(f"/orgs/{other['org_id']}/receipts", headers=headers).status_code == 404
    assert client.get(f"/orgs/{other['org_id']}/agents", headers=headers).status_code == 404
    assert client.get(f"/orgs/{other['org_id']}/dashboard", headers=headers).status_code == 404


def test_rbac_matrix(client: TestClient, org: dict[str, Any], make_user: Any) -> None:
    org_id = org["org_id"]
    viewer = make_user("viewer")
    auditor = make_user("auditor")
    author = make_user("policy_author")

    # Viewer: read yes, mutate no.
    assert client.get(f"/orgs/{org_id}/receipts", headers=viewer).status_code == 200
    assert (
        client.post(f"/orgs/{org_id}/agents", json={"name": "a1"}, headers=viewer).status_code
        == 403
    )
    # Auditor can create exports; viewer cannot.
    assert (
        client.post(f"/orgs/{org_id}/exports", json={"note": ""}, headers=viewer).status_code == 403
    )
    assert (
        client.post(f"/orgs/{org_id}/exports", json={"note": ""}, headers=auditor).status_code
        == 201
    )
    # Policy author can publish but not activate.
    rules = [{"id": "r1", "effect": "deny", "tools": ["nothing.here"]}]
    pub = client.post(
        f"/orgs/{org_id}/policies",
        json={"policy_id": "p", "rules": rules},
        headers=author,
    )
    assert pub.status_code == 201
    assert (
        client.post(
            f"/orgs/{org_id}/policies/{pub.json()['bundle_id']}/activate", headers=author
        ).status_code
        == 403
    )


def test_rbac_denial_produces_no_receipt(
    client: TestClient, org: dict[str, Any], make_user: Any, admin_headers: dict[str, str]
) -> None:
    """RBAC rejections happen before the membrane: nothing attempted, nothing receipted."""
    org_id = org["org_id"]
    viewer = make_user("viewer")
    before = client.get(f"/orgs/{org_id}/receipts", headers=admin_headers).json()["total"]
    assert (
        client.post(f"/orgs/{org_id}/agents", json={"name": "x"}, headers=viewer).status_code == 403
    )
    after = client.get(f"/orgs/{org_id}/receipts", headers=admin_headers).json()["total"]
    assert after == before
