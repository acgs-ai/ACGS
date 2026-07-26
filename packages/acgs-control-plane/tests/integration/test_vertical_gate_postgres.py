"""Joint PostgreSQL vertical gate for tenant bootstrap and agent registration."""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope

from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.governance import ROUTE_CONTRACTS, ExecutionClass, ProductionPostureBlocked
from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_AGENT_CREATE_ACTION,
    CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
    TENANT_BOOTSTRAP_ACTION,
)
from acgs_control_plane.migrations import DatabaseSchemaState, upgrade_database
from acgs_control_plane.models import (
    AgentRecord,
    AgentRegistrationIdempotency,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    ManagedTrustKey,
    TenantBootstrapIdempotency,
    User,
    utcnow,
)
from acgs_control_plane.policy_registry import (
    POLICY_ENVELOPE_PURPOSE,
    local_policy_registry_issuer,
)
from acgs_control_plane.tenant_bootstrap import BOOTSTRAP_IDEMPOTENCY_HEADER
from acgs_control_plane.trust import ManagedTrustLifecycleService, public_spki_der_from_signer
from tests.integration.test_agent_registration_postgres import (
    EXPECTED_DATABASE,
    _reset_postgres_schema,
)
from tests.integration.test_tenant_bootstrap_vertical import (
    BODY,
    HEADERS,
    _seed_invitation,
    _token,
)
from tests.test_agent_registration_managed_route import (
    _admin_headers,
    _count,
    _count_agents,
    _count_legacy_agent_receipts,
    _publish_and_activate,
    _publish_and_activate_allow_agent_create,
    _rules_for_policy,
)

DENIED_BODY = {
    **BODY,
    "display_name": "Denied Governed",
    "admin_name": "Dana Denied",
    "admin_email": "dana.denied@example.com",
}


def test_real_postgres_tenant_bootstrap_then_customer_agent_register(
    tmp_path: Path,
) -> None:
    app, client, database_url = _vertical_app(tmp_path)
    try:
        tenant = _bootstrap_tenant(client, app, token=_token("verticalallow"), key="vertical-key-1")
        org = {"org_id": tenant["org_id"], "admin_api_key": tenant["owner_api_key"]}
        _bootstrap_registration_trust_for_tenant(app, tenant)
        _publish_and_activate_allow_agent_create(client, org)

        register = client.post(
            f"/orgs/{tenant['org_id']}/agents",
            json={
                "name": "vertical-dispatcher",
                "description": "dispatcher registered after tenant bootstrap",
                "trust_tier": "internal",
                "allowed_tools": ["deploy.production"],
            },
            headers={**_admin_headers(org), BOOTSTRAP_IDEMPOTENCY_HEADER: "vertical-agent-1"},
        )

        assert register.status_code == 201, register.text
        registration = register.json()
        assert registration["org_id"] == tenant["org_id"]
        with app.state.session_factory() as session:
            user = session.get(User, tenant["owner_user_id"])
            assert user is not None
            assert user.api_key_hash is not None
            agent = session.scalars(sa.select(AgentRecord)).one()
            assert agent.id == registration["agent_id"]
            assert agent.org_id == tenant["org_id"]
            assert agent.project_id == tenant["project_id"]
            assert agent.environment_id == tenant["environment_id"]
            assert agent.name == "vertical-dispatcher"
            assert _count(session, TenantBootstrapIdempotency) == 1
            assert _count(session, AgentRegistrationIdempotency) == 1
            assert _count(session, ManagedReceiptConsumption) == 2
            assert _count(session, ManagedGovernanceEvent) == 2
            assert _count(session, ManagedOutboxMessage) == 2
            assert _count(session, ManagedMutationAttempt) == 2
            assert _count_legacy_agent_receipts(session, tenant["org_id"]) == 0
            receipts = list(
                session.scalars(
                    sa.select(ManagedDecisionReceipt).order_by(ManagedDecisionReceipt.created_at)
                )
            )
            actions = {row.proposed_action for row in receipts}
            # Setup seeds exactly one policy-head fixture receipt per activated environment.
            assert actions == {
                TENANT_BOOTSTRAP_ACTION,
                CONTROL_PLANE_AGENT_CREATE_ACTION,
                CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
            }
            assert len(receipts) == 3
            minted = [
                receipt
                for receipt in receipts
                if receipt.proposed_action != CONTROL_PLANE_POLICY_ACTIVATE_ACTION
            ]
            assert len(minted) == 2
            for receipt in minted:
                assert receipt.decision == "allow"
                assert receipt.assurance_class == "native"
                assert receipt.source_system == "gove-zone"
                assert receipt.receipt_schema_version == "gove-zone/decision-receipt/v2"
                assert receipt.signature_algorithm == "ed25519"
            for receipt in receipts:
                assert tenant["owner_api_key"] not in str(receipt.projection)
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_real_postgres_vertical_negative_oracles_and_production_legacy_reachability(
    tmp_path: Path,
) -> None:
    app, client, database_url = _vertical_app(tmp_path)
    try:
        allowed = _bootstrap_tenant(client, app, token=_token("verticaldeny"), key="vertical-key-2")
        denied = _bootstrap_tenant(
            client,
            app,
            token=_token("verticaldeny2"),
            key="vertical-key-3",
            body=DENIED_BODY,
        )
        allowed_org = {"org_id": allowed["org_id"], "admin_api_key": allowed["owner_api_key"]}
        denied_org = {"org_id": denied["org_id"], "admin_api_key": denied["owner_api_key"]}
        _bootstrap_registration_trust_for_tenant(app, allowed)
        _bootstrap_registration_trust_for_tenant(app, denied)
        _publish_and_activate_allow_agent_create(client, allowed_org)
        _publish_and_activate(client, denied_org, rules=_rules_for_policy("deny"))

        cross_tenant = client.post(
            f"/orgs/{denied['org_id']}/agents",
            json={"name": "wrong-tenant-agent", "trust_tier": "internal"},
            headers={
                "X-API-Key": allowed["owner_api_key"],
                BOOTSTRAP_IDEMPOTENCY_HEADER: "vertical-cross-tenant-1",
            },
        )
        assert cross_tenant.status_code == 404, cross_tenant.text

        denied_register = client.post(
            f"/orgs/{denied['org_id']}/agents",
            json={"name": "denied-agent", "trust_tier": "internal"},
            headers={
                "X-API-Key": denied["owner_api_key"],
                BOOTSTRAP_IDEMPOTENCY_HEADER: "vertical-denied-agent-1",
            },
        )
        assert denied_register.status_code == 403, denied_register.text
        assert denied_register.json()["code"] == "POLICY_DENIED"

        with app.state.session_factory() as session:
            assert _count_agents(session, denied["org_id"], "wrong-tenant-agent") == 0
            assert _count_agents(session, denied["org_id"], "denied-agent") == 0
            assert _count(session, TenantBootstrapIdempotency) == 2
            assert _count(session, AgentRegistrationIdempotency) == 1
            assert _count(session, ManagedReceiptConsumption) == 2
            # 2 tenant bootstraps + 1 denied agent-create + 2 seeded policy-head fixtures.
            assert _count(session, ManagedDecisionReceipt) == 5
            denied_receipt = session.scalars(
                sa.select(ManagedDecisionReceipt).where(
                    ManagedDecisionReceipt.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION
                )
            ).one()
            assert denied_receipt.decision == "deny"
            assert denied_receipt.assurance_class == "native"
            assert _count(session, AgentRecord) == 0

        legacy_contracts = [
            contract
            for contract in ROUTE_CONTRACTS
            if contract.execution_class is ExecutionClass.LEGACY_UNSIGNED_WRITE
        ]
        assert len(legacy_contracts) == 6
        with pytest.raises(ProductionPostureBlocked) as blocked:
            create_app(
                Settings(
                    database_url=database_url,
                    audit_dir=tmp_path / "production-audit",
                    create_tables=False,
                    runtime_posture=RuntimePosture.PRODUCTION,
                ),
                production_providers=(),
            )
        assert len([b for b in blocked.value.blockers if b.code == "LEGACY_UNSIGNED_WRITE"]) == 6
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def _vertical_app(tmp_path: Path) -> tuple[Any, TestClient, str]:
    if (
        os.environ.get("ACP_TEST_POSTGRES_GATE_ACTIVE") != "1"
        or os.environ.get("ACP_TEST_POSTGRES_SELECTOR_MODE") != "p2-vertical-gate"
    ):
        pytest.skip("vertical gate requires the exact P2 vertical PostgreSQL selector")
    database_url = os.environ.get("ACP_TEST_POSTGRES_URL")
    if not database_url:
        pytest.fail("ACP_TEST_POSTGRES_URL is required by the P2 vertical PostgreSQL gate")

    _reset_postgres_schema(database_url)
    result = upgrade_database(database_url, expected_database=EXPECTED_DATABASE)
    assert result.after.state is DatabaseSchemaState.VERSION_0008
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "audit",
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )
    return app, TestClient(app, raise_server_exceptions=False), database_url


def _bootstrap_tenant(
    client: TestClient,
    app: Any,
    *,
    token: str,
    key: str,
    body: dict[str, object] | None = None,
) -> dict[str, Any]:
    request_body = BODY if body is None else body
    with app.state.session_factory.begin() as session:
        _seed_invitation(session, token=token, outcome="allow")
    response = client.post(
        "/v1/tenant-bootstrap",
        json=request_body,
        headers={
            **HEADERS,
            "X-Bootstrap-Invitation": token,
            BOOTSTRAP_IDEMPOTENCY_HEADER: key,
        },
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["owner_api_key"].startswith("acp_")
    retry = client.post(
        "/v1/tenant-bootstrap",
        json=request_body,
        headers={
            **HEADERS,
            "X-Bootstrap-Invitation": token,
            BOOTSTRAP_IDEMPOTENCY_HEADER: key,
        },
    )
    assert retry.status_code == 201, retry.text
    assert retry.json() == {**payload, "owner_api_key": None}
    return payload


def _bootstrap_registration_trust_for_tenant(app: Any, tenant: dict[str, Any]) -> None:
    with app.state.session_factory.begin() as session:
        scope = ReceiptTrustScope(
            tenant_id=tenant["org_id"],
            project_id=tenant["project_id"],
            environment_id=tenant["environment_id"],
            purpose=DECISION_RECEIPT_PURPOSE,
        )
        signer = app.state.agent_registration_service.issuer.signer_for_scope(
            scope,
            trust_epoch=1,
        )
        ManagedTrustLifecycleService(session).bootstrap(
            scope=scope,
            key_id=signer.key_id,
            algorithm=signer.algorithm,
            public_key_spki_der=public_spki_der_from_signer(signer),
            not_after=utcnow() + timedelta(days=1),
        )
        policy_scope = ReceiptTrustScope(
            tenant_id=tenant["org_id"],
            project_id=tenant["project_id"],
            environment_id=tenant["environment_id"],
            purpose=POLICY_ENVELOPE_PURPOSE,
        )
        policy_signer = local_policy_registry_issuer().signer_for_scope(
            policy_scope,
            trust_epoch=1,
        )
        ManagedTrustLifecycleService(session).bootstrap(
            scope=policy_scope,
            key_id=policy_signer.key_id,
            algorithm=policy_signer.algorithm,
            public_key_spki_der=public_spki_der_from_signer(policy_signer),
            not_after=utcnow() + timedelta(days=1),
        )
        for purpose in (DECISION_RECEIPT_PURPOSE, POLICY_ENVELOPE_PURPOSE):
            assert (
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(ManagedTrustKey)
                    .where(
                        ManagedTrustKey.org_id == tenant["org_id"],
                        ManagedTrustKey.project_id == tenant["project_id"],
                        ManagedTrustKey.environment_id == tenant["environment_id"],
                        ManagedTrustKey.purpose == purpose,
                    )
                )
                == 1
            )
