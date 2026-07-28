"""Live-PostgreSQL lifecycle selectors for managed environment policies."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.migrations import DatabaseSchemaState, upgrade_database
from acgs_control_plane.models import (
    EnvironmentPolicyHead,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    ManagedTrustKey,
    PolicyRegistryIdempotency,
    PolicyVersion,
)
from acgs_control_plane.policy_registry import POLICY_ENVELOPE_PURPOSE
from acgs_control_plane.tenant_bootstrap import BOOTSTRAP_IDEMPOTENCY_HEADER
from tests.integration.test_agent_registration_postgres import (
    EXPECTED_DATABASE,
    _reset_postgres_schema,
)
from tests.test_agent_registration_managed_route import BOOTSTRAP_TOKEN, _bootstrap_org
from tests.test_policy_registry_managed import _publish, _seed_scope


def test_pg_publish_immutable_version_without_head(tmp_path: Path) -> None:
    app, client, org, database_url = _postgres_policy_app(tmp_path)
    try:
        project_id, environment_id = _seed_scope(client, org["org_id"])
        response = _publish(client, org["org_id"], project_id, environment_id, _admin_headers(org))

        assert response.status_code == 201, response.text
        assert response.json()["generation"] is None
        assert _counts(app) == _expected_counts(versions=1, heads=0, receipts=1)
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_activate_advances_exactly_one_head(tmp_path: Path) -> None:
    app, client, org, database_url = _postgres_policy_app(tmp_path)
    try:
        project_id, environment_id = _seed_scope(client, org["org_id"])
        published = _publish(
            client, org["org_id"], project_id, environment_id, _admin_headers(org)
        ).json()

        active = _activate(
            client,
            org["org_id"],
            project_id,
            environment_id,
            published["bundle_id"],
            _admin_headers(org),
            key="pg-policy-activate-0001",
            expected_generation=0,
        )

        assert active.status_code == 200, active.text
        assert active.json()["generation"] == 1
        assert _counts(app) == _expected_counts(versions=1, heads=1, receipts=2)
        with app.state.session_factory() as session:
            head = session.scalars(sa.select(EnvironmentPolicyHead)).one()
            assert head.active_policy_version_id == published["bundle_id"]
            assert head.generation == 1
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_concurrent_candidates_have_one_generation_winner(tmp_path: Path) -> None:
    app, client, org, database_url = _postgres_policy_app(tmp_path)
    try:
        project_id, environment_id = _seed_scope(client, org["org_id"])
        first = _publish(
            client,
            org["org_id"],
            project_id,
            environment_id,
            _admin_headers(org),
            key="pg-policy-publish-race-0001",
            policy_id="candidate-one",
        ).json()
        second = _publish(
            client,
            org["org_id"],
            project_id,
            environment_id,
            _admin_headers(org),
            key="pg-policy-publish-race-0002",
            policy_id="candidate-two",
        ).json()

        def activate(bundle_id: str) -> tuple[int, str | None]:
            with TestClient(app, raise_server_exceptions=False) as worker_client:
                response = _activate(
                    worker_client,
                    org["org_id"],
                    project_id,
                    environment_id,
                    bundle_id,
                    _admin_headers(org),
                    key=f"pg-policy-race-{bundle_id}",
                    expected_generation=0,
                )
                return response.status_code, response.json().get("code")

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(activate, (first["bundle_id"], second["bundle_id"])))

        assert sorted(results) == [(200, None), (409, "POLICY_GENERATION_STALE")]
        with app.state.session_factory() as session:
            head = session.scalars(sa.select(EnvironmentPolicyHead)).one()
            assert head.active_policy_version_id in {first["bundle_id"], second["bundle_id"]}
            assert head.generation == 1
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_publish_idempotent_replay_is_one_terminal_effect(tmp_path: Path) -> None:
    app, client, org, database_url = _postgres_policy_app(tmp_path)
    try:
        project_id, environment_id = _seed_scope(client, org["org_id"])
        first = _publish(
            client,
            org["org_id"],
            project_id,
            environment_id,
            _admin_headers(org),
            key="pg-policy-publish-replay",
        )
        before_replay = _counts(app)
        replay = _publish(
            client,
            org["org_id"],
            project_id,
            environment_id,
            _admin_headers(org),
            key="pg-policy-publish-replay",
        )

        assert first.status_code == 201, first.text
        assert replay.status_code == 201, replay.text
        assert replay.json() == first.json()
        assert _counts(app) == before_replay
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_idempotency_conflict_has_zero_delta(tmp_path: Path) -> None:
    app, client, org, database_url = _postgres_policy_app(tmp_path)
    try:
        project_id, environment_id = _seed_scope(client, org["org_id"])
        first = _publish(
            client,
            org["org_id"],
            project_id,
            environment_id,
            _admin_headers(org),
            key="pg-policy-publish-conflict",
            policy_id="first-policy",
        )
        before_conflict = _counts(app)
        conflict = _publish(
            client,
            org["org_id"],
            project_id,
            environment_id,
            _admin_headers(org),
            key="pg-policy-publish-conflict",
            policy_id="second-policy",
        )

        assert first.status_code == 201, first.text
        assert conflict.status_code == 409, conflict.text
        assert conflict.json()["code"] == "IDEMPOTENCY_CONFLICT"
        assert _counts(app) == before_conflict
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_pg_activation_revalidates_trust_and_rolls_back_before_effect(tmp_path: Path) -> None:
    app, client, org, database_url = _postgres_policy_app(tmp_path)
    try:
        project_id, environment_id = _seed_scope(client, org["org_id"])
        published = _publish(
            client, org["org_id"], project_id, environment_id, _admin_headers(org)
        ).json()
        with app.state.session_factory.begin() as session:
            key = session.scalars(
                sa.select(ManagedTrustKey).where(
                    ManagedTrustKey.org_id == org["org_id"],
                    ManagedTrustKey.project_id == project_id,
                    ManagedTrustKey.environment_id == environment_id,
                    ManagedTrustKey.purpose == POLICY_ENVELOPE_PURPOSE,
                )
            ).one()
            key.status = "revoked"
        before_activate = _counts(app)

        response = _activate(
            client,
            org["org_id"],
            project_id,
            environment_id,
            published["bundle_id"],
            _admin_headers(org),
            key="pg-policy-activate-revoked",
            expected_generation=0,
        )

        assert response.status_code == 503, response.text
        assert response.json()["code"] == "POLICY_SIGNATURE_REFUSED"
        assert _counts(app) == before_activate
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def _postgres_policy_app(tmp_path: Path) -> tuple[Any, TestClient, dict[str, Any], str]:
    if (
        os.environ.get("ACP_TEST_POSTGRES_GATE_ACTIVE") != "1"
        or os.environ.get("ACP_TEST_POSTGRES_SELECTOR_MODE") != "p3-policy"
    ):
        pytest.skip("managed policy lifecycle gate requires the exact P3 policy selector")
    database_url = os.environ.get("ACP_TEST_POSTGRES_URL")
    if not database_url:
        pytest.fail("ACP_TEST_POSTGRES_URL is required by the P3 policy PostgreSQL gate")

    _reset_postgres_schema(database_url)
    result = upgrade_database(database_url, expected_database=EXPECTED_DATABASE)
    assert result.after.state is DatabaseSchemaState.VERSION_0010

    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "audit",
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )
    client = TestClient(app, raise_server_exceptions=False)
    org = _bootstrap_org(client)
    return app, client, org, database_url


def _admin_headers(org: dict[str, Any]) -> dict[str, str]:
    return {"X-API-Key": org["admin_api_key"]}


def _activate(
    client: TestClient,
    org_id: str,
    project_id: str,
    environment_id: str,
    bundle_id: str,
    headers: dict[str, str],
    *,
    key: str,
    expected_generation: int,
) -> Any:
    return client.post(
        f"/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies/{bundle_id}/activate",
        json={"expected_generation": expected_generation},
        headers={**headers, BOOTSTRAP_IDEMPOTENCY_HEADER: key},
    )


def _counts(app: Any) -> dict[str, int]:
    tables = {
        "versions": PolicyVersion,
        "heads": EnvironmentPolicyHead,
        "receipts": ManagedDecisionReceipt,
        "consumptions": ManagedReceiptConsumption,
        "events": ManagedGovernanceEvent,
        "outbox": ManagedOutboxMessage,
        "attempts": ManagedMutationAttempt,
        "idempotency": PolicyRegistryIdempotency,
    }
    with app.state.session_factory() as session:
        return {
            name: int(session.scalar(sa.select(sa.func.count()).select_from(model)) or 0)
            for name, model in tables.items()
        }


def _expected_counts(*, versions: int, heads: int, receipts: int) -> dict[str, int]:
    return {
        "versions": versions,
        "heads": heads,
        "receipts": receipts,
        "consumptions": receipts,
        "events": receipts,
        "outbox": receipts,
        "attempts": receipts,
        "idempotency": receipts,
    }
