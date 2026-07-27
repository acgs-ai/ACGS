"""Receipt explorer, chain verification (tamper + truncation), dashboard."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient


def _seed_activity(client: TestClient, org_id: str, headers: dict[str, str]) -> None:
    for i in range(3):
        assert (
            client.post(
                f"/orgs/{org_id}/agents",
                json={"name": f"bot-{i}"},
                headers={**headers, "Idempotency-Key": f"receipt-dashboard-bot-{i}"},
            ).status_code
            == 201
        )
        assert (
            client.post(
                f"/orgs/{org_id}/users",
                json={
                    "name": f"Receipt User {i}",
                    "email": f"receipt-user-{i}@example.com",
                    "role": "viewer",
                },
                headers=headers,
            ).status_code
            == 201
        )


def test_receipt_list_filters_and_pagination(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    _seed_activity(client, org_id, admin_headers)
    all_receipts = client.get(f"/orgs/{org_id}/receipts", headers=admin_headers).json()
    assert all_receipts["total"] == 7
    native_items = [item for item in all_receipts["items"] if item["assurance_class"] == "native"]
    assert len(native_items) == 3
    assert {item["source_system"] for item in native_items} == {"gove-zone"}

    filtered = client.get(
        f"/orgs/{org_id}/receipts",
        params={"tool": "user.create"},
        headers=admin_headers,
    ).json()
    assert filtered["total"] == 3
    native_filtered = client.get(
        f"/orgs/{org_id}/receipts",
        params={"tool": "database.agent.create"},
        headers=admin_headers,
    ).json()
    assert native_filtered["total"] == 3
    assert {item["assurance_class"] for item in native_filtered["items"]} == {"native"}

    page = client.get(
        f"/orgs/{org_id}/receipts",
        params={"limit": 2, "offset": 0},
        headers=admin_headers,
    ).json()
    assert len(page["items"]) == 2
    assert page["total"] == 7


def test_receipt_verify_clean_chain(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    _seed_activity(client, org_id, admin_headers)
    receipts = client.get(f"/orgs/{org_id}/receipts", headers=admin_headers).json()["items"]
    rid = receipts[0]["receipt_id"]
    result = client.post(f"/orgs/{org_id}/receipts/{rid}/verify", headers=admin_headers).json()
    assert result["receipt_in_chain"] is True
    assert result["chain_valid"] is True
    assert result["anchor_matched"] is True
    assert result["failures"] == []
    assert result["chain_checked"] >= 4


def test_receipt_verify_detects_tamper(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str], audit_dir: Path
) -> None:
    org_id = org["org_id"]
    _seed_activity(client, org_id, admin_headers)
    chain_file = audit_dir / f"{org_id}.audit.jsonl"
    lines = chain_file.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[1])
    event["actor"] = "attacker:rewrote-history"
    lines[1] = json.dumps(event, sort_keys=True)
    chain_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    receipts = client.get(f"/orgs/{org_id}/receipts", headers=admin_headers).json()["items"]
    result = client.post(
        f"/orgs/{org_id}/receipts/{receipts[0]['receipt_id']}/verify", headers=admin_headers
    ).json()
    assert result["chain_valid"] is False
    assert any(f["type"] == "event_hash_mismatch" for f in result["failures"])


def test_receipt_verify_detects_truncation_via_db_anchor(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str], audit_dir: Path
) -> None:
    """Deleting trailing events yields an internally-consistent chain; the
    anchor persisted in PostgreSQL catches it."""
    org_id = org["org_id"]
    _seed_activity(client, org_id, admin_headers)
    chain_file = audit_dir / f"{org_id}.audit.jsonl"
    lines = chain_file.read_text(encoding="utf-8").splitlines()
    chain_file.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    receipts = client.get(f"/orgs/{org_id}/receipts", headers=admin_headers).json()["items"]
    result = client.post(
        f"/orgs/{org_id}/receipts/{receipts[-1]['receipt_id']}/verify", headers=admin_headers
    ).json()
    assert result["anchor_matched"] is False
    assert result["chain_valid"] is False
    failure_types = {f["type"] for f in result["failures"]}
    assert "length_mismatch" in failure_types
    assert "last_hash_mismatch" in failure_types


def test_dashboard_aggregates(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    org_id = org["org_id"]
    _seed_activity(client, org_id, admin_headers)
    # One suspended agent for the gauge.
    agents = client.get(f"/orgs/{org_id}/agents", headers=admin_headers).json()
    client.patch(
        f"/orgs/{org_id}/agents/{agents[0]['agent_id']}/status",
        json={"status": "suspended"},
        headers=admin_headers,
    )
    dash = client.get(f"/orgs/{org_id}/dashboard", headers=admin_headers).json()
    assert dash["total_receipts"] == 8
    assert dash["decisions"]["allow"] == 8
    assert dash["agents_total"] == 3
    assert dash["agents_suspended"] == 1
    assert dash["chain_valid"] is True
    tools = {t["tool"]: t["count"] for t in dash["top_tools"]}
    assert tools["user.create"] == 3
    assert tools["database.agent.create"] == 3
    assert dash["active_policy_version"] is None
