"""Compliance export: hash manifest, recomputation, tamper evidence."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from acgs_control_plane.exports import verify_export_bundle
from acgs_control_plane.models import AgentRecord


def test_export_bundle_is_verifiable_and_complete(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    with client.app.state.session_factory.begin() as session:
        session.add(AgentRecord(org_id=org_id, name="bot-a"))
    user = client.post(
        f"/orgs/{org_id}/users",
        json={
            "name": "Export Reviewer",
            "email": "export-reviewer@acme.example.com",
            "role": "auditor",
        },
        headers=admin_headers,
    )
    assert user.status_code == 201, user.text
    client.post(
        f"/orgs/{org_id}/policies",
        json={"policy_id": "p1", "rules": [{"id": "r1", "effect": "deny", "tools": ["x"]}]},
        headers=admin_headers,
    )

    created = client.post(
        f"/orgs/{org_id}/exports", json={"note": "annual audit"}, headers=admin_headers
    )
    assert created.status_code == 201, created.text
    summary = created.json()
    assert summary["receipt_id"]  # the export itself was a governed action
    assert summary["receipt_count"] == 3  # org.create + user.create + policy.publish

    detail = client.get(
        f"/orgs/{org_id}/exports/{summary['export_id']}", headers=admin_headers
    ).json()
    bundle = detail["bundle"]
    assert bundle["schema"] == "acgs-control-plane/export/v1"
    assert bundle["note"] == "annual audit"
    sections = bundle["sections"]
    assert len(sections["receipts"]) == 3
    assert len(sections["agents"]) == 1
    assert len(sections["policies"]) == 1
    assert sections["audit_chain"]["event_count"] == len(sections["audit_chain"]["events"])

    # Manifest recomputes cleanly with gove-zone's canonical hashing.
    check = verify_export_bundle(bundle)
    assert check == {"valid": True, "section_mismatches": [], "bundle_hash_ok": True}


def test_export_tamper_is_detected(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    summary = client.post(
        f"/orgs/{org_id}/exports", json={"note": ""}, headers=admin_headers
    ).json()
    bundle = client.get(
        f"/orgs/{org_id}/exports/{summary['export_id']}", headers=admin_headers
    ).json()["bundle"]

    bundle["sections"]["receipts"][0]["decision"] = "allow-forged"
    check = verify_export_bundle(bundle)
    assert check["valid"] is False
    assert "receipts" in check["section_mismatches"]


def test_export_receipt_recorded_after_bundle(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    """The export's own receipt postdates the bundle, so it appears in the
    NEXT export — evidence chains forward, never self-references."""
    org_id = org["org_id"]
    first = client.post(
        f"/orgs/{org_id}/exports", json={"note": "first"}, headers=admin_headers
    ).json()
    second = client.post(
        f"/orgs/{org_id}/exports", json={"note": "second"}, headers=admin_headers
    ).json()
    bundle = client.get(
        f"/orgs/{org_id}/exports/{second['export_id']}", headers=admin_headers
    ).json()["bundle"]
    receipt_ids = {r["event_id"] for r in bundle["sections"]["receipts"]}
    assert first["receipt_id"] in receipt_ids
