"""Live-PostgreSQL gates for the managed agent-registration slice."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from acgs_control_plane.agent_registration import local_agent_registration_issuer
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.migrations import HEAD_REVISION, DatabaseSchemaState, upgrade_database
from acgs_control_plane.models import PolicyBundle, new_id
from tests.test_agent_registration_managed_route import (
    BOOTSTRAP_TOKEN,
    _admin_headers,
    _bootstrap_org,
    _publish_and_activate_allow_agent_create,
    _seed_default_scope_and_trust,
)

EXPECTED_DATABASE = "acgs_control_plane_test"


def test_real_postgres_concurrent_policy_activation_preserves_single_active(
    tmp_path: Path,
) -> None:
    if (
        os.environ.get("ACP_TEST_POSTGRES_GATE_ACTIVE") != "1"
        or os.environ.get("ACP_TEST_POSTGRES_SELECTOR_MODE") != "p2-register"
    ):
        pytest.skip("agent registration PostgreSQL gate requires the exact P2 register selector")
    database_url = os.environ.get("ACP_TEST_POSTGRES_URL")
    if not database_url:
        pytest.fail("ACP_TEST_POSTGRES_URL is required by the P2 register PostgreSQL gate")

    _reset_postgres_schema(database_url)
    result = upgrade_database(database_url, expected_database=EXPECTED_DATABASE)
    assert result.after.state is DatabaseSchemaState(f"version_{HEAD_REVISION}")

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
    try:
        org = _bootstrap_org(client)
        _seed_default_scope_and_trust(app, org["org_id"])
        _publish_and_activate_allow_agent_create(client, org)
        candidate_ids = tuple(_publish_candidate_policy(client, org) for _ in range(2))

        def activate(bundle_id: str) -> int:
            with TestClient(app, raise_server_exceptions=False) as worker_client:
                response = worker_client.post(
                    f"/orgs/{org['org_id']}/policies/{bundle_id}/activate",
                    headers=_admin_headers(org),
                )
                return response.status_code

        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = tuple(executor.map(activate, candidate_ids))

        assert statuses == (200, 200)
        with app.state.session_factory() as session:
            active = list(
                session.scalars(
                    sa.select(PolicyBundle)
                    .where(PolicyBundle.org_id == org["org_id"], PolicyBundle.status == "active")
                    .order_by(PolicyBundle.id.asc())
                )
            )
            candidates = list(
                session.scalars(
                    sa.select(PolicyBundle)
                    .where(PolicyBundle.id.in_(candidate_ids))
                    .order_by(PolicyBundle.id.asc())
                )
            )

        assert len(active) == 1
        assert active[0].id in candidate_ids
        assert {candidate.status for candidate in candidates} <= {"active", "retired"}
        assert sum(1 for candidate in candidates if candidate.status == "active") == 1
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def _publish_candidate_policy(client: TestClient, org: dict[str, Any]) -> str:
    response = client.post(
        f"/orgs/{org['org_id']}/policies",
        json={
            "policy_id": f"race-policy-{new_id()}",
            "rules": [
                {
                    "id": f"deny-unrelated-{new_id()}",
                    "effect": "deny",
                    "tools": [f"unrelated.{new_id()}"],
                    "reason": "unrelated tools disabled",
                }
            ],
        },
        headers=_admin_headers(org),
    )
    assert response.status_code == 201, response.text
    return str(response.json()["bundle_id"])


def _reset_postgres_schema(database_url: str) -> None:
    if os.environ.get("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE") != "1":
        pytest.fail("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1 is required")
    url = sa.engine.make_url(database_url)
    if url.get_backend_name() != "postgresql" or url.database != EXPECTED_DATABASE:
        pytest.fail("P2 register gate must target the exact disposable database")
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
