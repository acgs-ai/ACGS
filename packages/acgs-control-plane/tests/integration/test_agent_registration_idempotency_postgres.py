"""Live-PostgreSQL idempotency gates for managed agent registration."""

from __future__ import annotations

import multiprocessing as mp
import os
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from acgs_control_plane.agent_registration import (
    DefaultAgentRegistrationReceiptIssuer,
    local_agent_registration_issuer,
)
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.migrations import DatabaseSchemaState, upgrade_database
from acgs_control_plane.models import (
    AgentRecord,
    AgentRegistrationIdempotency,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    new_id,
)
from acgs_control_plane.tenant_bootstrap import BOOTSTRAP_IDEMPOTENCY_HEADER
from tests.integration.test_agent_registration_postgres import (
    EXPECTED_DATABASE,
    _reset_postgres_schema,
)
from tests.test_agent_registration_managed_route import (
    BOOTSTRAP_TOKEN,
    _admin_headers,
    _bootstrap_org,
    _MutatingReceiptIssuer,
    _publish_and_activate_allow_agent_create,
    _seed_default_scope_and_trust,
)


def test_identical_key_and_canonical_request_converges_to_one_terminal_result(
    tmp_path: Path,
) -> None:
    app, client, org, database_url = _postgres_agent_registration_app(tmp_path)
    try:
        body = _agent_body("idempotent-bot")
        headers = _idempotent_admin_headers(org, "agent-register-key-0001")

        first = client.post(f"/orgs/{org['org_id']}/agents", json=body, headers=headers)
        second = client.post(f"/orgs/{org['org_id']}/agents", json=body, headers=headers)

        assert first.status_code == 201, first.text
        assert second.status_code == 201, second.text
        assert second.json() == first.json()
        _assert_single_agent_registration_effect(app, org["org_id"], "idempotent-bot")
        _assert_idempotency_scope_foreign_keys_are_database_enforced(app, client, org)
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_same_key_different_canonical_request_conflicts_without_additional_side_effects(
    tmp_path: Path,
) -> None:
    app, client, org, database_url = _postgres_agent_registration_app(tmp_path)
    try:
        headers = _idempotent_admin_headers(org, "agent-register-key-0002")
        first = client.post(
            f"/orgs/{org['org_id']}/agents",
            json=_agent_body("first-conflict-bot"),
            headers=headers,
        )
        conflict = client.post(
            f"/orgs/{org['org_id']}/agents",
            json=_agent_body("second-conflict-bot"),
            headers=headers,
        )

        assert first.status_code == 201, first.text
        assert conflict.status_code == 409, conflict.text
        assert conflict.json()["code"] == "IDEMPOTENCY_CONFLICT"
        with app.state.session_factory() as session:
            assert _count_agents(session, org["org_id"], "first-conflict-bot") == 1
            assert _count_agents(session, org["org_id"], "second-conflict-bot") == 0
            _assert_registration_counts(session, agents=1)
        with app.state.session_factory.begin() as session:
            row = session.scalars(sa.select(AgentRegistrationIdempotency)).one()
            row.response = {**row.response, "agent_id": "tampered-agent"}
        corrupt_replay = client.post(
            f"/orgs/{org['org_id']}/agents",
            json=_agent_body("first-conflict-bot"),
            headers=headers,
        )
        assert corrupt_replay.status_code == 503, corrupt_replay.text
        assert corrupt_replay.json()["code"] == "IDEMPOTENCY_RECORD_INVALID"
        with app.state.session_factory() as session:
            assert _count_agents(session, org["org_id"], "first-conflict-bot") == 1
            assert _count_agents(session, org["org_id"], "second-conflict-bot") == 0
            _assert_registration_counts(session, agents=1)
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_exact_receipt_replay_is_typed_and_nonduplicating(tmp_path: Path) -> None:
    app, client, org, database_url = _postgres_agent_registration_app(
        tmp_path,
        receipt_mode="fixed",
    )
    try:
        body = _agent_body("receipt-replay-bot")
        first = client.post(
            f"/orgs/{org['org_id']}/agents",
            json=body,
            headers=_idempotent_admin_headers(org, "agent-register-key-0003"),
        )
        replay = client.post(
            f"/orgs/{org['org_id']}/agents",
            json=body,
            headers=_idempotent_admin_headers(org, "agent-register-key-0004"),
        )

        assert first.status_code == 201, first.text
        assert replay.status_code == 409, replay.text
        assert replay.json()["code"] == "RECEIPT_ALREADY_USED"
        _assert_single_agent_registration_effect(app, org["org_id"], "receipt-replay-bot")
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_100_request_multiprocess_has_at_most_one_authorized_execution(
    tmp_path: Path,
) -> None:
    app, _client, org, database_url = _postgres_agent_registration_app(tmp_path)
    try:
        audit_dir = str(tmp_path / "multiprocess-audit")
        worker_args = (
            database_url,
            audit_dir,
            org,
            "agent-register-key-0100",
            _agent_body("multiprocess-idempotent-bot"),
        )
        with ProcessPoolExecutor(
            max_workers=16,
            mp_context=mp.get_context("fork"),
        ) as executor:
            results = list(executor.map(_post_agent_registration, [worker_args] * 100))

        assert {status for status, _code, _agent_id in results} == {201}
        agent_ids = {agent_id for _status, _code, agent_id in results}
        assert len(agent_ids) == 1
        with app.state.session_factory() as session:
            assert _count_agents(session, org["org_id"], "multiprocess-idempotent-bot") == 1
            _assert_registration_counts(session, agents=1)

        # One registration, one event on the org's tamper-evident chain. The
        # mirror's `store.append` writes a JSONL line that no transaction
        # rollback undoes, so a loser that mirrored before it had exclusively
        # claimed the idempotency key would leave the chain attesting to a
        # registration that never committed -- the failure this package exists
        # to prevent, and one no in-database assertion above can detect.
        chain = list(Path(audit_dir).glob("*.jsonl"))
        assert len(chain) == 1, chain
        assert sum(1 for _ in chain[0].open(encoding="utf-8")) == 1
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def _postgres_agent_registration_app(
    tmp_path: Path,
    *,
    receipt_mode: str | None = None,
) -> tuple[Any, TestClient, dict[str, Any], str]:
    if (
        os.environ.get("ACP_TEST_POSTGRES_GATE_ACTIVE") != "1"
        or os.environ.get("ACP_TEST_POSTGRES_SELECTOR_MODE") != "p2-idempotency"
    ):
        pytest.skip(
            "agent registration idempotency gate requires the exact P2 idempotency selector"
        )
    database_url = os.environ.get("ACP_TEST_POSTGRES_URL")
    if not database_url:
        pytest.fail("ACP_TEST_POSTGRES_URL is required by the P2 idempotency PostgreSQL gate")

    _reset_postgres_schema(database_url)
    result = upgrade_database(database_url, expected_database=EXPECTED_DATABASE)
    assert result.after.state is DatabaseSchemaState.VERSION_0008

    issuer = local_agent_registration_issuer()
    receipt_issuer = (
        _MutatingReceiptIssuer(
            DefaultAgentRegistrationReceiptIssuer(issuer),
            receipt_mode,
        )
        if receipt_mode is not None
        else None
    )
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "audit",
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        ),
        agent_registration_issuer=issuer,
        agent_registration_receipt_issuer=receipt_issuer,
    )
    client = TestClient(app, raise_server_exceptions=False)
    org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, org["org_id"])
    _publish_and_activate_allow_agent_create(client, org)
    return app, client, org, database_url


def _post_agent_registration(
    args: tuple[str, str, dict[str, Any], str, dict[str, Any]],
) -> tuple[
    int,
    str | None,
    str | None,
]:
    database_url, audit_dir, org, key, body = args
    issuer = local_agent_registration_issuer()
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=Path(audit_dir),
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        ),
        agent_registration_issuer=issuer,
    )
    client = TestClient(app, raise_server_exceptions=False)
    try:
        response = client.post(
            f"/orgs/{org['org_id']}/agents",
            json=body,
            headers=_idempotent_admin_headers(org, key),
        )
        payload = (
            response.json()
            if response.headers.get("content-type", "").startswith("application/json")
            else {}
        )
        return response.status_code, payload.get("code"), payload.get("agent_id")
    finally:
        app.state.engine.dispose()


def _agent_body(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": "registered through idempotent route",
        "trust_tier": "internal",
        "allowed_tools": ["deploy.production"],
    }


def _idempotent_admin_headers(org: dict[str, Any], key: str) -> dict[str, str]:
    return {
        **_admin_headers(org),
        BOOTSTRAP_IDEMPOTENCY_HEADER: key,
    }


def _assert_single_agent_registration_effect(app: Any, org_id: str, name: str) -> None:
    with app.state.session_factory() as session:
        assert _count_agents(session, org_id, name) == 1
        _assert_registration_counts(session, agents=1)


def _assert_idempotency_scope_foreign_keys_are_database_enforced(
    app: Any,
    client: TestClient,
    org: dict[str, Any],
) -> None:
    second_org = _bootstrap_org(client)
    _seed_default_scope_and_trust(app, second_org["org_id"])
    _publish_and_activate_allow_agent_create(client, second_org)
    second = client.post(
        f"/orgs/{second_org['org_id']}/agents",
        json=_agent_body("foreign-scope-bot"),
        headers=_idempotent_admin_headers(second_org, "agent-register-key-fk-second"),
    )
    assert second.status_code == 201, second.text

    with app.state.session_factory() as session:
        primary_row = session.scalars(
            sa.select(AgentRegistrationIdempotency).where(
                AgentRegistrationIdempotency.org_id == org["org_id"]
            )
        ).one()
        secondary_row = session.scalars(
            sa.select(AgentRegistrationIdempotency).where(
                AgentRegistrationIdempotency.org_id == second_org["org_id"]
            )
        ).one()
        secondary_agent = session.scalars(
            sa.select(AgentRecord).where(AgentRecord.org_id == second_org["org_id"])
        ).one()

    _assert_invalid_idempotency_row_rejected(
        app,
        primary_row,
        agent_id=secondary_agent.id,
        receipt_id=primary_row.receipt_id,
        key_suffix="cross-agent",
    )
    _assert_invalid_idempotency_row_rejected(
        app,
        primary_row,
        agent_id=None,
        receipt_id="missing-receipt",
        key_suffix="missing-receipt",
    )
    _assert_invalid_idempotency_row_rejected(
        app,
        primary_row,
        agent_id=None,
        receipt_id=secondary_row.receipt_id,
        key_suffix="cross-receipt",
    )


def _assert_invalid_idempotency_row_rejected(
    app: Any,
    template: AgentRegistrationIdempotency,
    *,
    agent_id: str | None,
    receipt_id: str,
    key_suffix: str,
) -> None:
    session = app.state.session_factory()
    try:
        session.add(
            AgentRegistrationIdempotency(
                id=new_id(),
                idempotency_key_hash=f"{key_suffix}-{new_id()}"[:64],
                actor_hash=template.actor_hash,
                request_hash=template.request_hash,
                org_id=template.org_id,
                project_id=template.project_id,
                environment_id=template.environment_id,
                agent_id=agent_id,
                receipt_id=receipt_id,
                response={
                    **template.response,
                    "agent_id": agent_id,
                    "receipt_id": receipt_id,
                },
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.rollback()
        session.close()


def _assert_registration_counts(session: Any, *, agents: int) -> None:
    assert _count(session, AgentRecord) == agents
    assert _count(session, AgentRegistrationIdempotency) == agents
    assert _count(session, ManagedDecisionReceipt) == agents
    assert _count(session, ManagedReceiptConsumption) == agents
    assert _count(session, ManagedGovernanceEvent) == agents
    assert _count(session, ManagedOutboxMessage) == agents


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
