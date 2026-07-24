"""Real-router contract tests for the additive /v1 control-plane surface."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from gove_zone.signing import Ed25519Signer
from sqlalchemy import select

from acgs_control_plane.api_contract import REQUEST_ID_RE
from acgs_control_plane.app import NativeAgentTransactionProviders, create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.governance import (
    ROUTE_CONTRACTS,
    ExecutionClass,
)
from acgs_control_plane.models import AgentRecord, ComplianceExport, Organization, ReceiptRow
from acgs_control_plane.native_receipts import (
    ManagedConsumptionAttestationTrust,
    ManagedNativeReceiptTrust,
    TenantPrivacyProvider,
)

BOOTSTRAP_TOKEN = "test-bootstrap-token"
_ISSUER_PRIVATE = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
_ATTESTOR_PRIVATE = bytes.fromhex(
    "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
)


def _providers() -> NativeAgentTransactionProviders:
    issuer = Ed25519Signer.from_private_bytes(_ISSUER_PRIVATE, key_id="v1-native-agent-issuer")
    attestor = Ed25519Signer.from_private_bytes(
        _ATTESTOR_PRIVATE,
        key_id="v1-native-agent-attestor",
    )
    return NativeAgentTransactionProviders(
        receipt_trust=ManagedNativeReceiptTrust(
            signer=issuer,
            verifiers={issuer.key_id: issuer},
        ),
        consumption_trust=ManagedConsumptionAttestationTrust(
            signer=attestor,
            verifiers={attestor.key_id: attestor},
        ),
        privacy=TenantPrivacyProvider(b"v1-native-agent-route-privacy-32b"),
    )


def _client(tmp_path: Path, audit_dir: Path, *, limit: int = 1024) -> TestClient:
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'v1.sqlite3'}",
            audit_dir=audit_dir,
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
            max_request_body_bytes=limit,
        ),
        native_agent_transaction=_providers(),
    )
    return TestClient(app, raise_server_exceptions=False)


def _app(client: TestClient) -> FastAPI:
    return cast(FastAPI, client.app)


def _bootstrap(client: TestClient, name: str) -> dict[str, Any]:
    response = client.post(
        "/v1/orgs",
        json={
            "name": name,
            "admin_name": "Root Admin",
            "admin_email": f"root-{name.lower().replace(' ', '-')}@example.com",
        },
        headers={"X-Bootstrap-Token": BOOTSTRAP_TOKEN},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _headers(org: dict[str, Any]) -> dict[str, str]:
    return {"X-API-Key": org["admin_api_key"]}


def _audit_bytes(audit_dir: Path) -> bytes:
    if not audit_dir.exists():
        return b""
    payload = bytearray()
    for path in sorted(p for p in audit_dir.rglob("*") if p.is_file()):
        payload.extend(path.relative_to(audit_dir).as_posix().encode("utf-8"))
        payload.extend(b"\0")
        payload.extend(path.read_bytes())
    return bytes(payload)


def _snapshot(client: TestClient, audit_dir: Path, org_id: str) -> dict[str, Any]:
    with _app(client).state.session_factory() as session:
        org = session.get(Organization, org_id)
        assert org is not None
        return {
            "agents": session.execute(
                select(AgentRecord.id, AgentRecord.name).where(AgentRecord.org_id == org_id)
            ).all(),
            "exports": session.execute(
                select(ComplianceExport.id).where(ComplianceExport.org_id == org_id)
            ).all(),
            "receipts": session.execute(
                select(ReceiptRow.id, ReceiptRow.tool, ReceiptRow.decision).where(
                    ReceiptRow.org_id == org_id
                )
            ).all(),
            "anchor_count": org.audit_anchor_count,
            "anchor_hash": org.audit_anchor_hash,
            "audit_bytes": _audit_bytes(audit_dir),
        }


def _publish_and_activate(
    client: TestClient,
    org_id: str,
    headers: dict[str, str],
    *,
    policy_id: str,
    rules: list[dict[str, Any]],
    prefix: str = "/v1",
) -> None:
    published = client.post(
        f"{prefix}/orgs/{org_id}/policies",
        json={"policy_id": policy_id, "rules": rules},
        headers=headers,
    )
    assert published.status_code == 201, published.text
    activated = client.post(
        f"{prefix}/orgs/{org_id}/policies/{published.json()['bundle_id']}/activate",
        headers=headers,
    )
    assert activated.status_code == 200, activated.text


def _assert_error_request_id(response: Any) -> None:
    body = response.json()
    assert REQUEST_ID_RE.fullmatch(response.headers["x-request-id"])
    assert body["request_id"] == response.headers["x-request-id"]
    assert body["request_id"] != "attacker-controlled"


def test_v1_org_aliases_share_v0_endpoints_with_stable_operation_ids(tmp_path: Path) -> None:
    client = _client(tmp_path, tmp_path / "audit")
    try:
        routes = {
            (method, route.path): route
            for route in _app(client).routes
            if isinstance(route, APIRoute)
            for method in route.methods or ()
        }
        assert client.get("/v1").json() == {
            "api_version": "v1",
            "status": "local-dev-legacy-alias",
            "aliased_from": "/orgs",
        }
        for (method, path), route in routes.items():
            if path == "/orgs" or path.startswith("/orgs/"):
                alias = routes[(method, f"/v1{path}")]
                assert alias.endpoint is route.endpoint
                assert alias.response_model == route.response_model
                assert alias.status_code == route.status_code
                assert alias.dependencies == route.dependencies
                assert alias.operation_id == f"v1_{route.unique_id}"
                assert route.operation_id is None
        assert all(path not in {"/v1/healthz", "/v1/readyz"} for _, path in routes)
    finally:
        _app(client).state.engine.dispose()


def test_v1_positive_write_and_read_paths_preserve_v0_behavior(
    tmp_path: Path,
) -> None:
    audit_dir = tmp_path / "audit"
    client = _client(tmp_path, audit_dir)
    try:
        org = _bootstrap(client, "V1 Positive Org")
        org_id = org["org_id"]
        headers = _headers(org)

        assert (
            client.get(f"/v1/orgs/{org_id}", headers=headers).json()
            == client.get(f"/orgs/{org_id}", headers=headers).json()
        )

        created = client.post(
            f"/v1/orgs/{org_id}/agents",
            json={"name": "dispatcher", "allowed_tools": ["ticket.create"]},
            headers=headers,
        )
        assert created.status_code == 201, created.text
        assert created.json()["receipt_id"]

        assert (
            client.get(f"/v1/orgs/{org_id}/agents", headers=headers).json()
            == client.get(f"/orgs/{org_id}/agents", headers=headers).json()
        )
        receipt_tools = [
            item["tool"]
            for item in client.get(f"/v1/orgs/{org_id}/receipts", headers=headers).json()["items"]
        ]
        assert receipt_tools == ["database.agent.create", "org.create"]
    finally:
        _app(client).state.engine.dispose()


def test_v1_unauthenticated_and_cross_tenant_refusals_are_redacted_and_unreceipted(
    tmp_path: Path,
) -> None:
    audit_dir = tmp_path / "audit"
    client = _client(tmp_path, audit_dir)
    try:
        org = _bootstrap(client, "V1 Tenant A")
        other = _bootstrap(client, "V1 Tenant B")
        before = _snapshot(client, audit_dir, org["org_id"])

        unauth = client.get(f"/v1/orgs/{org['org_id']}/agents")
        cross_tenant = client.get(
            f"/v1/orgs/{other['org_id']}/agents",
            headers=_headers(org),
        )

        assert unauth.status_code == 401
        assert cross_tenant.status_code == 404
        for response in (unauth, cross_tenant):
            assert response.json()["status"] == "error"
            _assert_error_request_id(response)
            assert "receipt" not in response.text
            assert "organization" not in response.text
            assert other["org_id"] not in response.text
        assert _snapshot(client, audit_dir, org["org_id"]) == before
    finally:
        _app(client).state.engine.dispose()


def test_v1_malformed_and_oversized_writes_are_rejected_before_side_effects(
    tmp_path: Path,
) -> None:
    audit_dir = tmp_path / "audit"
    client = _client(tmp_path, audit_dir, limit=512)
    try:
        org = _bootstrap(client, "V1 Admission Org")
        org_id = org["org_id"]
        before = _snapshot(client, audit_dir, org_id)
        secret = "sk_live_V1_SENTINEL"

        malformed = client.post(
            f"/v1/orgs/{org_id}/agents",
            content=f'{{"name":"{secret}",'.encode(),
            headers={"Content-Type": "application/json", **_headers(org)},
        )
        oversized = client.post(
            f"/v1/orgs/{org_id}/agents",
            json={"name": "x" * 800},
            headers=_headers(org),
        )

        assert malformed.status_code == 400
        assert malformed.json()["code"] == "malformed_json"
        assert secret not in malformed.text
        assert oversized.status_code == 413
        assert oversized.json()["code"] == "request_body_too_large"
        for response in (malformed, oversized):
            _assert_error_request_id(response)
            assert "receipt" not in response.text
        assert _snapshot(client, audit_dir, org_id) == before
    finally:
        _app(client).state.engine.dispose()


def test_v1_policy_deny_matches_v0_error_semantics_and_blocks_side_effect(
    tmp_path: Path,
) -> None:
    audit_dir = tmp_path / "audit"
    client = _client(tmp_path, audit_dir)
    try:
        v1_org = _bootstrap(client, "V1 Deny Org")
        v0_org = client.post(
            "/orgs",
            json={
                "name": "V0 Deny Org",
                "admin_name": "Root Admin",
                "admin_email": "root-v0-deny@example.com",
            },
            headers={"X-Bootstrap-Token": BOOTSTRAP_TOKEN},
        ).json()
        rule = {
            "id": "no-untrusted-agents",
            "effect": "deny",
            "tools": ["database.agent.create"],
            "state_equals": {"trust_tier": "untrusted"},
            "reason": "untrusted agents are not allowed in this org",
        }
        _publish_and_activate(
            client,
            v1_org["org_id"],
            _headers(v1_org),
            policy_id="v1-deny",
            rules=[rule],
        )
        _publish_and_activate(
            client,
            v0_org["org_id"],
            _headers(v0_org),
            policy_id="v0-deny",
            rules=[rule],
            prefix="",
        )
        v1_before = _snapshot(client, audit_dir, v1_org["org_id"])
        v0_before = _snapshot(client, audit_dir, v0_org["org_id"])

        v1_denied = client.post(
            f"/v1/orgs/{v1_org['org_id']}/agents",
            json={"name": "sketchy-v1", "trust_tier": "untrusted"},
            headers={**_headers(v1_org), "X-Request-ID": "attacker-controlled"},
        )
        v0_denied = client.post(
            f"/orgs/{v0_org['org_id']}/agents",
            json={"name": "sketchy-v0", "trust_tier": "untrusted"},
            headers={**_headers(v0_org), "X-Request-ID": "attacker-controlled"},
        )

        assert v1_denied.status_code == 403
        assert v0_denied.status_code == 403
        assert (
            set(v1_denied.json())
            == set(v0_denied.json())
            == {
                "status",
                "reason",
                "decision",
                "receipt_id",
                "request_id",
            }
        )
        assert v1_denied.json()["status"] == v0_denied.json()["status"] == "denied"
        assert v1_denied.json()["decision"] == v0_denied.json()["decision"] == "deny"
        assert "untrusted" in v1_denied.json()["reason"]
        _assert_error_request_id(v1_denied)
        _assert_error_request_id(v0_denied)

        v1_after = _snapshot(client, audit_dir, v1_org["org_id"])
        v0_after = _snapshot(client, audit_dir, v0_org["org_id"])
        assert v1_after["agents"] == v1_before["agents"]
        assert v0_after["agents"] == v0_before["agents"]
        assert len(v1_after["receipts"]) == len(v1_before["receipts"])
        assert len(v0_after["receipts"]) == len(v0_before["receipts"])
    finally:
        _app(client).state.engine.dispose()


def test_v1_policy_escalate_matches_v0_error_semantics_and_blocks_side_effect(
    tmp_path: Path,
) -> None:
    audit_dir = tmp_path / "audit"
    client = _client(tmp_path, audit_dir)
    try:
        v1_org = _bootstrap(client, "V1 Escalate Org")
        v0_org = client.post(
            "/orgs",
            json={
                "name": "V0 Escalate Org",
                "admin_name": "Root Admin",
                "admin_email": "root-v0-escalate@example.com",
            },
            headers={"X-Bootstrap-Token": BOOTSTRAP_TOKEN},
        ).json()
        rule = {
            "id": "exports-need-approval",
            "effect": "escalate",
            "tools": ["export.generate"],
            "reason": "compliance exports require human approval in this org",
        }
        _publish_and_activate(
            client,
            v1_org["org_id"],
            _headers(v1_org),
            policy_id="v1-escalate",
            rules=[rule],
        )
        _publish_and_activate(
            client,
            v0_org["org_id"],
            _headers(v0_org),
            policy_id="v0-escalate",
            rules=[rule],
            prefix="",
        )
        v1_before = _snapshot(client, audit_dir, v1_org["org_id"])
        v0_before = _snapshot(client, audit_dir, v0_org["org_id"])

        v1_escalated = client.post(
            f"/v1/orgs/{v1_org['org_id']}/exports",
            json={"note": "q3"},
            headers={**_headers(v1_org), "X-Request-ID": "attacker-controlled"},
        )
        v0_escalated = client.post(
            f"/orgs/{v0_org['org_id']}/exports",
            json={"note": "q3"},
            headers={**_headers(v0_org), "X-Request-ID": "attacker-controlled"},
        )

        assert v1_escalated.status_code == 202
        assert v0_escalated.status_code == 202
        assert (
            set(v1_escalated.json())
            == set(v0_escalated.json())
            == {
                "status",
                "reason",
                "receipt_id",
                "decision",
                "request_id",
            }
        )
        assert v1_escalated.json()["status"] == v0_escalated.json()["status"] == "pending_approval"
        assert v1_escalated.json()["decision"] == v0_escalated.json()["decision"] == "escalate"
        _assert_error_request_id(v1_escalated)
        _assert_error_request_id(v0_escalated)

        v1_after = _snapshot(client, audit_dir, v1_org["org_id"])
        v0_after = _snapshot(client, audit_dir, v0_org["org_id"])
        assert v1_after["exports"] == v1_before["exports"]
        assert v0_after["exports"] == v0_before["exports"]
        assert len(v1_after["receipts"]) == len(v1_before["receipts"]) + 1
        assert len(v0_after["receipts"]) == len(v0_before["receipts"]) + 1
        receipt = client.get(
            f"/v1/orgs/{v1_org['org_id']}/receipts/{v1_escalated.json()['receipt_id']}",
            headers=_headers(v1_org),
        )
        assert receipt.status_code == 200
        assert receipt.json()["tool"] == "export.generate"
        assert receipt.json()["decision"] == "escalate"
    finally:
        _app(client).state.engine.dispose()


def test_v1_contract_is_alias_only_not_beta_feature_completion() -> None:
    contracts = {(contract.method, contract.path): contract for contract in ROUTE_CONTRACTS}
    v1_writes = [
        contract
        for contract in contracts.values()
        if contract.path == "/v1/orgs" or contract.path.startswith("/v1/orgs/")
        if contract.execution_class is ExecutionClass.LEGACY_UNSIGNED_WRITE
    ]
    assert len(v1_writes) == 6
    assert all(contract.permits_persistent_effect for contract in v1_writes)
    assert (
        contracts[("POST", "/v1/orgs/{org_id}/agents")].execution_class
        is ExecutionClass.CANONICAL_MANAGED_WRITE
    )
    assert ("GET", "/v1") in contracts
    assert contracts[("GET", "/v1")].execution_class is ExecutionClass.PROTOCOL_OPERATION

    serialized = "\n".join(sorted(path for _, path in contracts))
    assert "Idempotency-Key" not in serialized
    assert "/jobs" not in serialized
    assert "/v1/projects" not in serialized
    assert "/v1/environments" not in serialized
