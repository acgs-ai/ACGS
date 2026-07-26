"""Live-PostgreSQL proof for managed mutation inventory drift refusal."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from gove_zone.trust import RECEIPT_V2

from acgs_control_plane.agent_registration import local_agent_registration_issuer
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.governance import ROUTE_CONTRACTS, ExecutionClass
from acgs_control_plane.managed_mutations import CONTROL_PLANE_AGENT_CREATE_ACTION
from acgs_control_plane.migrations import DatabaseSchemaState, upgrade_database
from acgs_control_plane.models import (
    AgentRecord,
    AgentRegistrationIdempotency,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    ReceiptRow,
)
from acgs_control_plane.tenant_bootstrap import BOOTSTRAP_IDEMPOTENCY_HEADER
from tests.test_agent_registration_managed_route import (
    BOOTSTRAP_TOKEN,
    _admin_headers,
    _bootstrap_org,
    _publish_and_activate_allow_agent_create,
    _seed_default_scope_and_trust,
)

EXPECTED_DATABASE = "acgs_control_plane_test"


def test_pg_agent_register_commits_one_sql_atomic_managed_mutation(
    tmp_path: Path,
) -> None:
    app, client, org, database_url = _postgres_mutation_inventory_app(tmp_path)
    try:
        body = {
            "name": "pg-inventory-allow-bot",
            "description": "postgres mutation inventory proof",
            "trust_tier": "internal",
            "allowed_tools": ["deploy.production"],
        }
        headers = _idempotent_admin_headers(org, "pg-mutation-inventory-allow-0001")
        before = _agent_registration_counts(app, org["org_id"], "pg-inventory-allow-bot")

        response = client.post(
            f"/orgs/{org['org_id']}/agents",
            json=body,
            headers=headers,
        )

        assert response.status_code == 201, response.text
        payload = response.json()
        assert payload["receipt_id"]
        after = _agent_registration_counts(app, org["org_id"], "pg-inventory-allow-bot")
        assert after == {
            **before,
            "agents_named": before["agents_named"] + 1,
            "agent_idempotency": before["agent_idempotency"] + 1,
            "agent_receipts": before["agent_receipts"] + 1,
            "agent_consumptions": before["agent_consumptions"] + 1,
            "agent_events": before["agent_events"] + 1,
            "agent_outbox": before["agent_outbox"] + 1,
            "agent_attempts": before["agent_attempts"] + 1,
            "all_agents": before["all_agents"] + 1,
            "all_managed_receipts": before["all_managed_receipts"] + 1,
            "all_managed_consumptions": before["all_managed_consumptions"] + 1,
            "all_managed_events": before["all_managed_events"] + 1,
            "all_managed_outbox": before["all_managed_outbox"] + 1,
            "all_managed_attempts": before["all_managed_attempts"] + 1,
            "all_agent_idempotency": before["all_agent_idempotency"] + 1,
            "all_legacy_receipts": before["all_legacy_receipts"] + 1,
            "legacy_agent_receipts": before["legacy_agent_receipts"] + 1,
        }
        with app.state.session_factory() as session:
            agent = session.scalars(
                sa.select(AgentRecord).where(
                    AgentRecord.org_id == org["org_id"],
                    AgentRecord.name == "pg-inventory-allow-bot",
                )
            ).one()
            receipt = session.scalars(_agent_registration_receipt_select()).one()
            event = session.scalars(_agent_registration_event_select()).one()
            outbox = session.scalars(_agent_registration_outbox_select()).one()

            assert agent.id == payload["agent_id"]
            assert receipt.receipt_id == payload["receipt_id"]
            assert receipt.decision == "allow"
            assert receipt.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION
            assert receipt.projection["assurance_class"] == "native"
            assert receipt.assurance_class == "native"
            assert receipt.source_system == "gove-zone"
            assert receipt.receipt_schema_version == RECEIPT_V2
            assert receipt.signature_algorithm == "ed25519"
            assert receipt.signing_key_id
            assert receipt.trust_epoch == 1
            assert receipt.projection["receipt_schema_version"] == RECEIPT_V2
            assert receipt.projection["trust_epoch"] == 1
            assert event.managed_receipt_id == receipt.id
            assert event.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION
            assert outbox.managed_receipt_id == receipt.id
            assert _count_legacy_agent_receipts(session, org["org_id"]) == 1

        replay = client.post(
            f"/orgs/{org['org_id']}/agents",
            json=body,
            headers=headers,
        )

        assert replay.status_code == 201, replay.text
        assert replay.json() == payload
        assert _agent_registration_counts(app, org["org_id"], "pg-inventory-allow-bot") == after
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_route_app_drift_refuses_before_replacement_and_preserves_sql_counts(
    tmp_path: Path,
) -> None:
    app, client, org, database_url = _postgres_mutation_inventory_app(tmp_path)
    try:
        route = _api_route(client, "POST", "/orgs/{org_id}/agents")
        before = _agent_registration_counts(app, org["org_id"], "pg-route-app-drift-bot")
        reached = {"route_app": False}

        async def replacement_route_app(_scope: Any, _receive: Any, _send: Any) -> None:
            reached["route_app"] = True

        route.app = replacement_route_app

        response = client.post(
            f"/orgs/{org['org_id']}/agents",
            json={
                "name": "pg-route-app-drift-bot",
                "description": "route app drift must not persist",
                "trust_tier": "internal",
            },
            headers=_idempotent_admin_headers(org, "pg-mutation-inventory-route-app-0001"),
        )

        assert response.status_code == 503
        assert response.json()["code"] == "MUTATION_INVENTORY_DRIFT"
        assert reached == {"route_app": False}
        assert "pg-route-app-drift-bot" not in response.text
        assert _agent_registration_counts(app, org["org_id"], "pg-route-app-drift-bot") == before
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_service_binding_drift_preserves_sql_counts_and_legacy_blockers(
    tmp_path: Path,
) -> None:
    app, client, org, database_url = _postgres_mutation_inventory_app(tmp_path)
    try:
        before = _agent_registration_counts(app, org["org_id"], "pg-service-drift-bot")
        reached = {"service": False}

        class ReplacementAgentRegistrationService:
            def register(self, *_args: Any, **_kwargs: Any) -> dict[str, bool]:
                reached["service"] = True
                return {"mutated": True}

        app.state.agent_registration_service = ReplacementAgentRegistrationService()

        response = client.post(
            f"/orgs/{org['org_id']}/agents",
            json={
                "name": "pg-service-drift-bot",
                "description": "service binding drift must not persist",
                "trust_tier": "internal",
            },
            headers=_idempotent_admin_headers(org, "pg-mutation-inventory-service-0001"),
        )

        assert response.status_code == 503
        payload = response.json()
        assert payload["code"] == "MUTATION_INVENTORY_DRIFT"
        assert {
            detail["code"]
            for detail in payload["details"]
            if detail["operation_id"] == "agent.register"
        } >= {"SERVICE_BINDING_DRIFT", "MANAGED_ROUTE_BINDING_DRIFT"}
        assert reached == {"service": False}
        assert "pg-service-drift-bot" not in response.text
        assert _agent_registration_counts(app, org["org_id"], "pg-service-drift-bot") == before
        assert _legacy_blocker_count(app) == 12
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_legacy_regex_precedence_drift_preserves_sql_counts_before_bootstrap(
    tmp_path: Path,
) -> None:
    app, client, org, database_url = _postgres_mutation_inventory_app(tmp_path)
    try:
        del org
        legacy_route = _api_route(client, "POST", "/orgs")
        canonical_route = _api_route(client, "POST", "/v1/tenant-bootstrap")
        before = _relevant_sql_counts(app)
        reached = {"legacy": False}

        async def legacy_route_app(_scope: Any, _receive: Any, _send: Any) -> None:
            reached["legacy"] = True

        legacy_route.app = legacy_route_app
        legacy_route.path_regex = re.compile("^/v1/tenant-bootstrap$")
        routes = list(app.router.routes)
        routes.remove(legacy_route)
        canonical_index = routes.index(canonical_route)
        routes.insert(canonical_index, legacy_route)
        app.router.routes[:] = routes

        response = client.post("/v1/tenant-bootstrap", json={"display_name": "PG Regex Drift"})

        assert response.status_code == 503
        assert response.json()["code"] == "MUTATION_INVENTORY_DRIFT"
        assert reached == {"legacy": False}
        assert "PG Regex Drift" not in response.text
        assert _relevant_sql_counts(app) == before
        assert _legacy_blocker_count(app) == 12
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def _postgres_mutation_inventory_app(
    tmp_path: Path,
) -> tuple[Any, TestClient, dict[str, Any], str]:
    if (
        os.environ.get("ACP_TEST_POSTGRES_GATE_ACTIVE") != "1"
        or os.environ.get("ACP_TEST_POSTGRES_SELECTOR_MODE") != "p3-mutations"
    ):
        pytest.skip("mutation inventory PostgreSQL gate requires the exact P3 mutations selector")
    database_url = os.environ.get("ACP_TEST_POSTGRES_URL")
    if not database_url:
        pytest.fail("ACP_TEST_POSTGRES_URL is required by the P3 mutations PostgreSQL gate")

    _reset_postgres_schema(database_url)
    result = upgrade_database(database_url, expected_database=EXPECTED_DATABASE)
    assert result.after.state is DatabaseSchemaState.VERSION_0009

    issuer = local_agent_registration_issuer()
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "audit",
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        ),
        agent_registration_issuer=issuer,
    )
    client = TestClient(app, raise_server_exceptions=False)
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate_allow_agent_create(client, org)
    assert _legacy_blocker_count(app) == 12
    return app, client, org, database_url


def _reset_postgres_schema(database_url: str) -> None:
    if os.environ.get("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE") != "1":
        pytest.fail("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1 is required")
    url = sa.engine.make_url(database_url)
    if url.get_backend_name() != "postgresql" or url.database != EXPECTED_DATABASE:
        pytest.fail("P3 mutations gate must target the exact disposable database")
    engine = sa.create_engine(
        url.update_query_dict({"options": "-csearch_path=pg_catalog,public"}),
        future=True,
    )
    try:
        with engine.begin() as connection:
            assert connection.scalar(sa.text("SELECT pg_catalog.current_database()")) == (
                EXPECTED_DATABASE
            )
            connection.execute(sa.text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(sa.text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


def _idempotent_admin_headers(org: dict[str, Any], key: str) -> dict[str, str]:
    return {
        **_admin_headers(org),
        BOOTSTRAP_IDEMPOTENCY_HEADER: key,
    }


def _api_route(client: TestClient, method: str, path: str) -> APIRoute:
    app = cast(FastAPI, client.app)
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path == path and method in (route.methods or ()):
            return route
    raise AssertionError(f"missing route {method} {path}")


def _legacy_blocker_count(app: Any) -> int:
    assert (
        len(
            [
                contract
                for contract in ROUTE_CONTRACTS
                if contract.execution_class is ExecutionClass.LEGACY_UNSIGNED_WRITE
            ]
        )
        == 12
    )
    return len(
        [
            blocker
            for blocker in app.state.readiness_blockers
            if blocker.code == "LEGACY_UNSIGNED_WRITE"
        ]
    )


def _agent_registration_counts(app: Any, org_id: str, agent_name: str) -> dict[str, int]:
    with app.state.session_factory() as session:
        receipt_ids = _agent_registration_receipt_ids()
        return {
            "agents_named": _count_agents(session, org_id, agent_name),
            "agent_idempotency": _count(session, AgentRegistrationIdempotency),
            "agent_receipts": _count_agent_receipts(session),
            "agent_consumptions": _count_agent_consumptions(session, receipt_ids),
            "agent_events": _count_agent_events(session, receipt_ids),
            "agent_outbox": _count_agent_outbox(session, receipt_ids),
            "agent_attempts": _count_agent_attempts(session),
            **_relevant_sql_counts_for_session(session, org_id),
        }


def _relevant_sql_counts(app: Any, org_id: str | None = None) -> dict[str, int]:
    with app.state.session_factory() as session:
        return _relevant_sql_counts_for_session(session, org_id)


def _relevant_sql_counts_for_session(session: Any, org_id: str | None = None) -> dict[str, int]:
    counts = {
        "all_agents": _count(session, AgentRecord),
        "all_agent_idempotency": _count(session, AgentRegistrationIdempotency),
        "all_managed_receipts": _count(session, ManagedDecisionReceipt),
        "all_managed_consumptions": _count(session, ManagedReceiptConsumption),
        "all_managed_events": _count(session, ManagedGovernanceEvent),
        "all_managed_outbox": _count(session, ManagedOutboxMessage),
        "all_managed_attempts": _count(session, ManagedMutationAttempt),
        "all_legacy_receipts": _count(session, ReceiptRow),
    }
    if org_id is not None:
        counts["legacy_agent_receipts"] = _count_legacy_agent_receipts(session, org_id)
    return counts


def _agent_registration_receipt_select() -> Any:
    return sa.select(ManagedDecisionReceipt).where(
        ManagedDecisionReceipt.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION
    )


def _agent_registration_receipt_ids() -> Any:
    return (
        sa.select(ManagedDecisionReceipt.id)
        .where(ManagedDecisionReceipt.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION)
        .scalar_subquery()
    )


def _agent_registration_event_select() -> Any:
    return sa.select(ManagedGovernanceEvent).where(
        ManagedGovernanceEvent.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION,
        ManagedGovernanceEvent.managed_receipt_id.in_(_agent_registration_receipt_ids()),
    )


def _agent_registration_outbox_select() -> Any:
    return sa.select(ManagedOutboxMessage).where(
        ManagedOutboxMessage.managed_receipt_id.in_(_agent_registration_receipt_ids())
    )


def _count_agent_receipts(session: Any) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count()).select_from(_agent_registration_receipt_select().subquery())
        )
        or 0
    )


def _count_agent_consumptions(session: Any, receipt_ids: Any) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(ManagedReceiptConsumption)
            .where(ManagedReceiptConsumption.managed_receipt_id.in_(receipt_ids))
        )
        or 0
    )


def _count_agent_events(session: Any, receipt_ids: Any) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(ManagedGovernanceEvent)
            .where(
                ManagedGovernanceEvent.proposed_action == CONTROL_PLANE_AGENT_CREATE_ACTION,
                ManagedGovernanceEvent.managed_receipt_id.in_(receipt_ids),
            )
        )
        or 0
    )


def _count_agent_outbox(session: Any, receipt_ids: Any) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(ManagedOutboxMessage)
            .where(ManagedOutboxMessage.managed_receipt_id.in_(receipt_ids))
        )
        or 0
    )


def _count_agent_attempts(session: Any) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(ManagedMutationAttempt)
            .where(ManagedMutationAttempt.action == CONTROL_PLANE_AGENT_CREATE_ACTION)
        )
        or 0
    )


def _count(session: Any, model: type[Any]) -> int:
    return int(session.scalar(sa.select(sa.func.count()).select_from(model)) or 0)


def _count_agents(session: Any, org_id: str, name: str) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(AgentRecord)
            .where(AgentRecord.org_id == org_id, AgentRecord.name == name)
        )
        or 0
    )


def _count_legacy_agent_receipts(session: Any, org_id: str) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(ReceiptRow)
            .where(ReceiptRow.org_id == org_id, ReceiptRow.tool == "agent.register")
        )
        or 0
    )
