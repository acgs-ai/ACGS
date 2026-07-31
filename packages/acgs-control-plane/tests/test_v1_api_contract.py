"""Real-router contract tests for the additive /v1 control-plane surface."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from gove_zone.decision import sha256_json
from gove_zone.policy import RuleSetPolicy
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope
from sqlalchemy import select

from acgs_control_plane.api_contract import REQUEST_ID_RE
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.governance import (
    ROUTE_CONTRACTS,
    ExecutionClass,
)
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import (
    AgentRecord,
    ComplianceExport,
    Environment,
    EnvironmentPolicyHead,
    ManagedDecisionReceipt,
    Organization,
    PolicyVersion,
    Project,
    ReceiptRow,
    new_id,
    utcnow,
)
from acgs_control_plane.policy_registry import (
    POLICY_ENVELOPE_PURPOSE,
    _signed_envelope,
    local_policy_registry_issuer,
)
from acgs_control_plane.tenant_bootstrap import BOOTSTRAP_IDEMPOTENCY_HEADER
from acgs_control_plane.trust import (
    ManagedTrustLifecycleService,
    public_spki_der_from_signer,
)

BOOTSTRAP_TOKEN = "test-bootstrap-token"


def _client(tmp_path: Path, audit_dir: Path, *, limit: int = 1024) -> TestClient:
    # Migrate rather than create_tables=True: the latter builds only the frozen
    # v0 surface, which has no projects/environments tables, so agent
    # registration cannot resolve its scope. The /v1 alias is served from a
    # migrated schema in every deployment.
    database_url = f"sqlite:///{tmp_path / 'v1.sqlite3'}"
    upgrade_database(database_url)
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=audit_dir,
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
            max_request_body_bytes=limit,
        )
    )
    return TestClient(app, raise_server_exceptions=False)


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
    org = response.json()
    _seed_agent_registration_prerequisites(client, org)
    return org


def _seed_agent_registration_prerequisites(client: TestClient, org: dict[str, Any]) -> None:
    """Satisfy the governed preconditions for ``POST /orgs/{org}/agents``.

    Agent registration is a canonical managed mutation: it resolves the org's
    default project/environment scope, mints a receipt-v2 under a trusted key
    for that scope, and requires an active policy bundle. Mirrors
    test_agent_registration_managed_route.py.

    The permissive bundle seeded here denies only an unrelated tool. Callers
    that need their own rules publish and activate over the top; activation
    retires the currently active bundle, so the two never collide.
    """
    org_id = org["org_id"]
    app = client.app
    project_id = f"project-{new_id()}"
    environment_id = f"environment-{new_id()}"
    with app.state.session_factory.begin() as session:
        session.add_all(
            [
                Project(id=project_id, org_id=org_id, slug="default", name="Default"),
                Environment(
                    id=environment_id,
                    org_id=org_id,
                    project_id=project_id,
                    slug="production",
                    name="Production",
                ),
            ]
        )
        session.flush()
        scope = ReceiptTrustScope(org_id, project_id, environment_id, DECISION_RECEIPT_PURPOSE)
        signer = app.state.agent_registration_service.issuer.signer_for_scope(scope, trust_epoch=1)
        ManagedTrustLifecycleService(session).bootstrap(
            scope=scope,
            key_id=signer.key_id,
            algorithm=signer.algorithm,
            public_key_spki_der=public_spki_der_from_signer(signer),
            not_after=utcnow() + timedelta(days=1),
        )
        policy_scope = ReceiptTrustScope(
            org_id, project_id, environment_id, POLICY_ENVELOPE_PURPOSE
        )
        policy_signer = local_policy_registry_issuer().signer_for_scope(policy_scope, trust_epoch=1)
        ManagedTrustLifecycleService(session).bootstrap(
            scope=policy_scope,
            key_id=policy_signer.key_id,
            algorithm=policy_signer.algorithm,
            public_key_spki_der=public_spki_der_from_signer(policy_signer),
            not_after=utcnow() + timedelta(days=1),
        )
    _activate_managed_policy(
        client,
        org_id,
        rules=[
            {
                "id": "deny-unrelated",
                "effect": "deny",
                "tools": ["unrelated.tool"],
                "reason": "unrelated tools disabled",
            }
        ],
    )
    _publish_and_activate(
        client,
        org_id,
        _headers(org),
        policy_id=f"policy-{new_id()}",
        rules=[
            {
                "id": "deny-unrelated",
                "effect": "deny",
                "tools": ["unrelated.tool"],
                "reason": "unrelated tools disabled",
            }
        ],
    )


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
    with client.app.state.session_factory() as session:
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


def _activate_managed_policy(
    client: TestClient, org_id: str, *, rules: list[dict[str, Any]]
) -> None:
    """Seed the signed environment policy head that governs agent registration.

    Agent registration fails closed without an active, signature-verifiable
    ``EnvironmentPolicyHead``. Mirrors test_agent_registration_managed_route.py:
    the version and head are seeded directly because the managed policy routes
    mint decision receipts under the policy-registry issuer, while these tests
    bootstrap the scope's decision-receipt trust with the agent-registration
    issuer key.
    """
    policy_id = f"managed-policy-{new_id()}"
    parsed = RuleSetPolicy.from_dict({"id": policy_id, "rules": rules})
    document = {"id": parsed.policy_id, "version": parsed.version, "rules": list(rules)}
    with client.app.state.session_factory.begin() as session:
        environment = session.scalars(
            select(Environment)
            .where(Environment.org_id == org_id)
            .order_by(Environment.created_at.desc())
        ).first()
        assert environment is not None
        envelope = _signed_envelope(
            issuer=local_policy_registry_issuer(),
            org_id=org_id,
            project_id=environment.project_id,
            environment_id=environment.id,
            policy_id=policy_id,
            document=document,
            trust_epoch=1,
        )
        version = PolicyVersion(
            id=new_id(),
            org_id=org_id,
            project_id=environment.project_id,
            environment_id=environment.id,
            policy_id=policy_id,
            version=document["version"],
            content_hash=envelope["content_hash"],
            document=document,
            rules=list(document["rules"]),
            canonical_envelope=envelope,
            purpose=envelope["purpose"],
            key_id=envelope["key_id"],
            signature_algorithm=envelope["signature_algorithm"],
            signature=envelope["signature"],
            trust_epoch=envelope["trust_epoch"],
            receipt_id=f"test-policy-receipt-{new_id()}",
        )
        session.add(version)
        session.flush()
        head_receipt_id = _seed_policy_head_receipt(
            session,
            org_id=org_id,
            project_id=environment.project_id,
            environment_id=environment.id,
        )
        existing_head = session.scalars(
            select(EnvironmentPolicyHead).where(
                EnvironmentPolicyHead.org_id == org_id,
                EnvironmentPolicyHead.project_id == environment.project_id,
                EnvironmentPolicyHead.environment_id == environment.id,
            )
        ).one_or_none()
        if existing_head is None:
            session.add(
                EnvironmentPolicyHead(
                    id=new_id(),
                    org_id=org_id,
                    project_id=environment.project_id,
                    environment_id=environment.id,
                    active_policy_version_id=version.id,
                    generation=1,
                    status="active",
                    receipt_id=head_receipt_id,
                    created_at=utcnow(),
                    updated_at=utcnow(),
                )
            )
        else:
            existing_head.active_policy_version_id = version.id
            existing_head.generation += 1
            existing_head.receipt_id = head_receipt_id
            existing_head.updated_at = utcnow()


def _seed_policy_head_receipt(
    session: Any,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
) -> str:
    receipt_id = f"test-policy-head-receipt-{new_id()}"
    receipt_hash = sha256_json({"schema": "test-policy-head-receipt/v1", "receipt_id": receipt_id})
    audit_hash = sha256_json({"schema": "test-policy-head-audit/v1", "receipt_id": receipt_id})
    now = utcnow()
    session.add(
        ManagedDecisionReceipt(
            id=f"test-policy-head-{new_id()}",
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            receipt_id=receipt_id,
            receipt_hash=receipt_hash,
            audit_event_hash=audit_hash,
            decision="ALLOW",
            actor="test-policy-fixture",
            proposed_action="control-plane.policy.activate",
            execution_boundary="test-policy-fixture-boundary",
            policy_bundle_id="test-policy-fixture",
            policy_version="test-policy-fixture/v1",
            policy_hash=sha256_json({"schema": "test-policy-fixture/v1"}),
            argument_hash=sha256_json({"receipt_id": receipt_id}),
            signing_key_id="test-policy-fixture-key",
            signature_algorithm="ed25519",
            receipt_schema_version="receipt/v2",
            trust_epoch=1,
            assurance_class="native",
            source_system="gove-zone",
            issued_at=now,
            expires_at=now + timedelta(minutes=10),
            projection={"schema": "test-policy-head-receipt/v1"},
            created_at=now,
        )
    )
    return receipt_id


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
            for route in client.app.routes
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
                if route.operation_id in {
                    "approval.vote",
                    "approval.resume",
                    "runtime-enrollment-bootstrap.issue",
                    "runtime-identity.revoke",
                }:
                    assert alias.operation_id == f"v1_{route.operation_id}"
                else:
                    assert route.operation_id is None
        assert all(path not in {"/v1/healthz", "/v1/readyz"} for _, path in routes)
    finally:
        client.app.state.engine.dispose()


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
            headers={**headers, BOOTSTRAP_IDEMPOTENCY_HEADER: "v1-positive-agent-0001"},
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
        # Newest first. The seeded policy bundle sits between the org
        # creation and this write, so assert the registration is the most
        # recent receipt and the org creation is still on the chain, rather
        # than pinning two adjacent positions.
        assert receipt_tools[0] == "agent.register"
        assert "org.create" in receipt_tools
    finally:
        client.app.state.engine.dispose()


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
        client.app.state.engine.dispose()


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
        client.app.state.engine.dispose()


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
        # Created without _bootstrap, so it still needs the governed scope and
        # trust that agent registration resolves.
        _seed_agent_registration_prerequisites(client, v0_org)
        rule = {
            "id": "no-untrusted-agents",
            "effect": "deny",
            "tools": ["agent.register"],
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
        # Agent registration is decided by the active environment policy head,
        # so the deny rule must also land there.
        _activate_managed_policy(client, v1_org["org_id"], rules=[rule])
        _activate_managed_policy(client, v0_org["org_id"], rules=[rule])
        v1_before = _snapshot(client, audit_dir, v1_org["org_id"])
        v0_before = _snapshot(client, audit_dir, v0_org["org_id"])

        v1_denied = client.post(
            f"/v1/orgs/{v1_org['org_id']}/agents",
            json={"name": "sketchy-v1", "trust_tier": "untrusted"},
            headers={
                **_headers(v1_org),
                "X-Request-ID": "attacker-controlled",
                BOOTSTRAP_IDEMPOTENCY_HEADER: "v1-deny-agent-0001",
            },
        )
        v0_denied = client.post(
            f"/orgs/{v0_org['org_id']}/agents",
            json={"name": "sketchy-v0", "trust_tier": "untrusted"},
            headers={
                **_headers(v0_org),
                "X-Request-ID": "attacker-controlled",
                BOOTSTRAP_IDEMPOTENCY_HEADER: "v0-deny-agent-0001",
            },
        )

        assert v1_denied.status_code == 403
        assert v0_denied.status_code == 403
        assert (
            set(v1_denied.json())
            == set(v0_denied.json())
            == {
                "status",
                "reason",
                "receipt_id",
                "decision",
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
        assert len(v1_after["receipts"]) == len(v1_before["receipts"]) + 1
        assert len(v0_after["receipts"]) == len(v0_before["receipts"]) + 1
        receipt = client.get(
            f"/v1/orgs/{v1_org['org_id']}/receipts/{v1_denied.json()['receipt_id']}",
            headers=_headers(v1_org),
        )
        assert receipt.status_code == 200
        assert receipt.json()["tool"] == "agent.register"
        assert receipt.json()["decision"] == "deny"
    finally:
        client.app.state.engine.dispose()


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
        client.app.state.engine.dispose()


def test_v1_contract_is_alias_only_not_beta_feature_completion() -> None:
    contracts = {(contract.method, contract.path): contract for contract in ROUTE_CONTRACTS}
    v1_writes = [
        contract
        for contract in contracts.values()
        if contract.path == "/v1/orgs" or contract.path.startswith("/v1/orgs/")
        if contract.execution_class is ExecutionClass.LEGACY_UNSIGNED_WRITE
    ]
    # 6, not 7: agent registration is now governed with receipt v2, so
    # POST /v1/orgs/{org_id}/agents is a CANONICAL_MANAGED_WRITE rather than a
    # legacy unsigned one. The alias itself is still alias-only.
    assert len(v1_writes) == 6
    assert all(contract.permits_persistent_effect for contract in v1_writes)
    assert ("GET", "/v1") in contracts
    assert contracts[("GET", "/v1")].execution_class is ExecutionClass.PROTOCOL_OPERATION

    serialized = "\n".join(sorted(path for _, path in contracts))
    assert "Idempotency-Key" not in serialized
    assert "/jobs" not in serialized
    assert "/v1/projects" not in serialized
    assert "/v1/environments" not in serialized
