"""Live-PostgreSQL gates for runtime enrollment and authenticated reports."""

from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import os
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from gove_zone.decision import Decision, canonical_json, sha256_json
from gove_zone.runtime_identity import (
    GateScope,
    InMemoryEd25519WorkloadKeyProvider,
    RuntimeEnrollmentClient,
    RuntimeHttpRequest,
    RuntimeHttpResponse,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

import acgs_control_plane.runtime_enrollment as runtime_enrollment_module
import acgs_control_plane.runtime_reports as runtime_reports_module
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.db import make_engine
from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_RUNTIME_BOOTSTRAP_ISSUE_ACTION,
    CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION,
    CONTROL_PLANE_RUNTIME_IDENTITY_RENEW_ACTION,
    CONTROL_PLANE_RUNTIME_IDENTITY_REVOKE_ACTION,
)
from acgs_control_plane.migrations import (
    DatabaseSchemaState,
    StartupSchemaPreflightError,
    assert_current_startup_schema,
    inspect_connection,
    upgrade_database,
)
from acgs_control_plane.models import (
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    RuntimeCredentialGeneration,
    RuntimeEnrollmentBootstrap,
    RuntimeEnrollmentIdempotency,
    RuntimeIdentity,
    RuntimeIdentityGate,
    RuntimeOperationIdempotency,
    RuntimeReport,
    RuntimeReportHead,
    RuntimeRequestNonce,
    RuntimeWiringAttestation,
    RuntimeWiringChallengeConsumption,
    new_id,
    utcnow,
)
from acgs_control_plane.runtime_enrollment import RuntimeEnrollmentProviderUnavailable
from acgs_control_plane.runtime_lineage_schema import (
    POSTGRES_RUNTIME_LINEAGE_FUNCTIONS,
    POSTGRES_RUNTIME_LINEAGE_TRIGGERS,
)
from tests.integration.test_agent_registration_postgres import (
    EXPECTED_DATABASE,
    _reset_postgres_schema,
)
from tests.integration.test_migrations_postgres import _controlled_upgrade_to_revision
from tests.test_agent_registration_managed_route import (
    BOOTSTRAP_TOKEN,
    _admin_headers,
    _bootstrap_org,
)
from tests.test_runtime_enrollment_routes import (
    _issue_bootstrap,
    _runtime_timestamp,
    _runtime_transport,
    _seed_scope_trust_and_policy,
)
from tests.test_runtime_reports import (
    _produce_genuine_wiring_artifact,
    _report_attempt_count,
    _report_path_counts,
    _seed_report_scope,
    _signed_challenge_request,
    _signed_status_request,
    _status_payload,
    _submit_wiring_report,
)

_RUNTIME_WORKLOAD_SEED = bytes.fromhex(
    "2e445e0c8f52dc3db9101438f1d0de70d023271108a9bf4d7f8c7e48f9fdf001"
)
_RUNTIME_DESCRIPTOR_SIGNER_SEED = bytes.fromhex(
    "a6c2388894866a773f7db3551c851d738c7cd9c06c5e6a99309b2bff18db2202"
)
_AUDIENCE = "control-plane.runtime-enrollment:v1"
_SELECTOR = "p4-runtime-enrollment"

_POSTGRES_RUNTIME_LINEAGE_TRIGGER_TARGETS = {
    "runtime_reports_immutable_update": ("UPDATE", "runtime_reports"),
    "runtime_reports_immutable_delete": ("DELETE", "runtime_reports"),
    "runtime_wiring_attestations_immutable_update": (
        "UPDATE",
        "runtime_wiring_attestations",
    ),
    "runtime_wiring_attestations_immutable_delete": (
        "DELETE",
        "runtime_wiring_attestations",
    ),
    "runtime_report_heads_monotonic_update": ("UPDATE", "runtime_report_heads"),
    "runtime_report_heads_monotonic_delete": ("DELETE", "runtime_report_heads"),
}


def test_populated_runtime_enrollment_0011_upgrades_to_0012_postgresql() -> None:
    if (
        os.environ.get("ACP_TEST_POSTGRES_GATE_ACTIVE") != "1"
        or os.environ.get("ACP_TEST_POSTGRES_SELECTOR_MODE") != _SELECTOR
    ):
        pytest.skip("runtime enrollment PostgreSQL gate requires the exact P4 selector")
    database_url = os.environ.get("ACP_TEST_POSTGRES_URL")
    if not database_url:
        pytest.fail("ACP_TEST_POSTGRES_URL is required by the P4 runtime enrollment gate")
    _reset_postgres_schema(database_url)
    try:
        _controlled_upgrade_to_revision(database_url, "0011")
        engine = make_engine(database_url)
        try:
            with engine.begin() as connection:
                assert inspect_connection(connection).state is DatabaseSchemaState.VERSION_0011
                connection.execute(
                    sa.text(
                        "INSERT INTO organizations "
                        "(id, name, created_at, audit_anchor_count, audit_anchor_hash) "
                        "VALUES ('org-0011', 'Org 0011', now(), 0, '')"
                    )
                )
                connection.execute(
                    sa.text(
                        "INSERT INTO projects (id, org_id, slug, name, created_at) "
                        "VALUES ('project-0011', 'org-0011', 'project', 'Project', now())"
                    )
                )
                connection.execute(
                    sa.text(
                        "INSERT INTO environments "
                        "(id, org_id, project_id, slug, name, created_at) "
                        "VALUES ('env-0011', 'org-0011', 'project-0011', 'env', 'Env', now())"
                    )
                )
                connection.execute(
                    sa.text(
                        "INSERT INTO runtime_identity_gates "
                        "(id, org_id, project_id, environment_id, status, created_at, updated_at) "
                        "VALUES ('gate-0011', 'org-0011', 'project-0011', 'env-0011', "
                        "'active', now(), now())"
                    )
                )
                descriptor = {
                    "schema": "runtime-identity/v1",
                    "runtime_identity_id": "identity-0011",
                    "credential_id": "credential-0011",
                    "credential_generation": 1,
                    "binding": "preserve-exactly",
                }
                connection.execute(
                    sa.text(
                        "INSERT INTO runtime_identities "
                        "(id, org_id, project_id, environment_id, gate_id, name, actor, "
                        "workload_key_id, public_key, public_key_thumbprint, descriptor, status, "
                        "current_generation, created_at, updated_at, revoked_at) VALUES "
                        "('identity-0011', 'org-0011', 'project-0011', 'env-0011', "
                        "'gate-0011', 'Runtime 0011', 'runtime:identity-0011', "
                        "'workload-key-0011', 'public-key-0011', :thumbprint, "
                        "CAST(:descriptor AS jsonb), 'active', 1, :created_at, :updated_at, NULL)"
                    ),
                    {
                        "thumbprint": "a" * 64,
                        "descriptor": json.dumps(descriptor, sort_keys=True),
                        "created_at": "2026-08-01T00:01:00+00:00",
                        "updated_at": "2026-08-01T00:02:00+00:00",
                    },
                )
                connection.execute(
                    sa.text(
                        "INSERT INTO runtime_credential_generations "
                        "(id, org_id, project_id, environment_id, identity_id, generation, "
                        "workload_key_id, public_key_thumbprint, not_before, not_after, status, "
                        "descriptor, created_at, superseded_at, revoked_at) VALUES "
                        "('credential-0011', 'org-0011', 'project-0011', 'env-0011', "
                        "'identity-0011', 1, 'workload-key-0011', :thumbprint, :not_before, "
                        ":not_after, 'active', CAST(:descriptor AS jsonb), :created_at, NULL, NULL)"
                    ),
                    {
                        "thumbprint": "a" * 64,
                        "not_before": "2026-08-01T00:00:00+00:00",
                        "not_after": "2026-08-02T00:00:00+00:00",
                        "descriptor": json.dumps(descriptor, sort_keys=True),
                        "created_at": "2026-08-01T00:03:00+00:00",
                    },
                )
        finally:
            engine.dispose()

        result = upgrade_database(database_url, expected_database=EXPECTED_DATABASE)
        assert result.before.state is DatabaseSchemaState.VERSION_0011
        assert result.after.state is DatabaseSchemaState.VERSION_0012
        engine = make_engine(database_url)
        try:
            with engine.connect() as connection:
                assert (
                    connection.scalar(
                        sa.text("SELECT status FROM runtime_identity_gates WHERE id = 'gate-0011'")
                    )
                    == "active"
                )
                identity = (
                    connection.execute(
                        sa.text(
                            "SELECT org_id, project_id, environment_id, gate_id, status, "
                            "current_generation, workload_key_id, public_key, "
                            "public_key_thumbprint, descriptor, created_at, updated_at "
                            "FROM runtime_identities "
                            "WHERE id = 'identity-0011'"
                        )
                    )
                    .mappings()
                    .one()
                )
                credential = (
                    connection.execute(
                        sa.text(
                            "SELECT org_id, project_id, environment_id, identity_id, generation, "
                            "status, workload_key_id, public_key_thumbprint, descriptor, "
                            "not_before, not_after, created_at "
                            "FROM runtime_credential_generations "
                            "WHERE id = 'credential-0011'"
                        )
                    )
                    .mappings()
                    .one()
                )
                assert dict(identity) == {
                    "org_id": "org-0011",
                    "project_id": "project-0011",
                    "environment_id": "env-0011",
                    "gate_id": "gate-0011",
                    "status": "active",
                    "current_generation": 1,
                    "workload_key_id": "workload-key-0011",
                    "public_key": "public-key-0011",
                    "public_key_thumbprint": "a" * 64,
                    "descriptor": descriptor,
                    "created_at": datetime.fromisoformat("2026-08-01T00:01:00+00:00"),
                    "updated_at": datetime.fromisoformat("2026-08-01T00:02:00+00:00"),
                }
                assert dict(credential) == {
                    "org_id": "org-0011",
                    "project_id": "project-0011",
                    "environment_id": "env-0011",
                    "identity_id": "identity-0011",
                    "generation": 1,
                    "status": "active",
                    "workload_key_id": "workload-key-0011",
                    "public_key_thumbprint": "a" * 64,
                    "descriptor": descriptor,
                    "not_before": datetime.fromisoformat("2026-08-01T00:00:00+00:00"),
                    "not_after": datetime.fromisoformat("2026-08-02T00:00:00+00:00"),
                    "created_at": datetime.fromisoformat("2026-08-01T00:03:00+00:00"),
                }
                enabled_states = dict(
                    connection.execute(
                        sa.text(
                            "SELECT tgname, tgenabled FROM pg_catalog.pg_trigger "
                            "WHERE NOT tgisinternal AND tgname IN :names"
                        ).bindparams(
                            sa.bindparam(
                                "names",
                                expanding=True,
                                value=tuple(POSTGRES_RUNTIME_LINEAGE_TRIGGERS),
                            )
                        )
                    ).all()
                )
                assert enabled_states == {name: "O" for name in POSTGRES_RUNTIME_LINEAGE_TRIGGERS}
        finally:
            engine.dispose()
    finally:
        _reset_postgres_schema(database_url)


def test_runtime_lineage_schema_objects_are_required_postgresql(tmp_path: Path) -> None:
    app, _client, _org, _project_id, _environment_id, database_url = _postgres_runtime_app(tmp_path)
    try:
        with app.state.engine.connect() as connection:
            assert inspect_connection(connection).state is DatabaseSchemaState.VERSION_0012
            enabled_states = dict(
                connection.execute(
                    sa.text(
                        "SELECT tgname, tgenabled FROM pg_catalog.pg_trigger "
                        "WHERE NOT tgisinternal AND tgname IN :names"
                    ).bindparams(
                        sa.bindparam(
                            "names",
                            expanding=True,
                            value=tuple(POSTGRES_RUNTIME_LINEAGE_TRIGGERS),
                        )
                    )
                ).all()
            )
            assert enabled_states == {name: "O" for name in POSTGRES_RUNTIME_LINEAGE_TRIGGERS}

        with app.state.engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    sa.text(
                        "ALTER TABLE runtime_report_heads ALTER CONSTRAINT "
                        "fk_runtime_report_heads_identity_scope NOT DEFERRABLE"
                    )
                )
                drifted = inspect_connection(connection)
                assert drifted.state is DatabaseSchemaState.UNKNOWN
                assert "foreign-key options outside the frozen schema" in drifted.detail
            finally:
                transaction.rollback()
        with app.state.engine.connect() as connection:
            assert inspect_connection(connection).state is DatabaseSchemaState.VERSION_0012

        for object_name in POSTGRES_RUNTIME_LINEAGE_TRIGGERS:
            event, table_name = _POSTGRES_RUNTIME_LINEAGE_TRIGGER_TARGETS[object_name]
            for mutation in ("drop", "replace"):
                with app.state.engine.connect() as connection:
                    transaction = connection.begin()
                    try:
                        connection.execute(
                            sa.text(f'DROP TRIGGER "{object_name}" ON "{table_name}"')
                        )
                        if mutation == "replace":
                            replacement_function = (
                                "acgs_runtime_report_heads_monotonic"
                                if table_name == "runtime_reports"
                                else "acgs_runtime_reports_immutable"
                            )
                            connection.execute(
                                sa.text(
                                    f'CREATE TRIGGER "{object_name}" BEFORE {event} '
                                    f'ON "{table_name}" FOR EACH ROW EXECUTE FUNCTION '
                                    f'"{replacement_function}"()'
                                )
                            )
                        preflight = inspect_connection(connection)
                        assert preflight.state is DatabaseSchemaState.UNKNOWN
                        assert "runtime lineage" in preflight.detail
                        with pytest.raises(StartupSchemaPreflightError):
                            assert_current_startup_schema(connection)
                    finally:
                        transaction.rollback()

            for enabled_mutation in ("DISABLE", "ENABLE REPLICA", "ENABLE ALWAYS"):
                with app.state.engine.connect() as connection:
                    transaction = connection.begin()
                    try:
                        connection.execute(
                            sa.text(
                                f'ALTER TABLE "{table_name}" {enabled_mutation} '
                                f'TRIGGER "{object_name}"'
                            )
                        )
                        preflight = inspect_connection(connection)
                        assert preflight.state is DatabaseSchemaState.UNKNOWN
                        assert "runtime lineage" in preflight.detail
                        with pytest.raises(StartupSchemaPreflightError):
                            assert_current_startup_schema(connection)
                    finally:
                        transaction.rollback()

        for object_name in POSTGRES_RUNTIME_LINEAGE_FUNCTIONS:
            for mutation in ("drop", "replace"):
                with app.state.engine.connect() as connection:
                    transaction = connection.begin()
                    try:
                        if mutation == "drop":
                            connection.execute(sa.text(f'DROP FUNCTION "{object_name}"() CASCADE'))
                        else:
                            connection.execute(
                                sa.text(
                                    f'CREATE OR REPLACE FUNCTION "{object_name}"() '
                                    "RETURNS trigger LANGUAGE plpgsql AS $$ "
                                    "BEGIN RETURN NEW; END; $$"
                                )
                            )
                        preflight = inspect_connection(connection)
                        assert preflight.state is DatabaseSchemaState.UNKNOWN
                        assert "runtime lineage" in preflight.detail
                        with pytest.raises(StartupSchemaPreflightError):
                            assert_current_startup_schema(connection)
                    finally:
                        transaction.rollback()
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


@pytest.mark.parametrize("provider_error", [RuntimeError, ValueError, OSError])
def test_runtime_report_provider_outages_are_redacted_and_atomic_postgresql(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider_error: type[Exception],
) -> None:
    app, client, org, _project_id, _environment_id, database_url = _postgres_runtime_app(tmp_path)
    try:
        descriptor_signer = app.state.runtime_report_service._descriptor_signer
        provider_tag = {
            RuntimeError: "rt",
            ValueError: "ve",
            OSError: "os",
        }[provider_error]
        seeded = _seed_report_scope(
            client,
            org,
            descriptor_signer,
            scope_suffix=f"p-{provider_tag}-a",
        )
        challenge_path, challenge_headers = _signed_challenge_request(
            seeded,
            snapshot=seeded["policy_snapshot"],
            runtime_build_digest="b" * 64,
            configuration_digest="c" * 64,
        )
        before = _report_path_counts(app, seeded["org_id"])
        before_attempts = _report_attempt_count(app, seeded["org_id"])
        original_private_key = descriptor_signer._private_key

        class FailingPrivateKey:
            def sign(self, _payload: bytes) -> bytes:
                raise provider_error("secret postgres signer endpoint kms://challenge-key")

        monkeypatch.setattr(descriptor_signer, "_private_key", FailingPrivateKey())
        challenge = client.get(challenge_path, headers=challenge_headers)
        monkeypatch.setattr(descriptor_signer, "_private_key", original_private_key)

        assert challenge.status_code == 503, challenge.text
        assert challenge.json() == {
            "code": "RUNTIME_REPORT_PROVIDER_UNAVAILABLE",
            "status": "service_unavailable",
            "detail": "runtime report cryptographic provider is unavailable",
        }
        assert "challenge-key" not in challenge.text
        assert _report_path_counts(app, seeded["org_id"]) == before
        assert _report_attempt_count(app, seeded["org_id"]) == before_attempts

        report_path, raw_body, report_headers = _signed_status_request(seeded)

        def unavailable_terminal_sealer(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            try:
                raise provider_error("secret postgres sealer endpoint kms://terminal-key")
            except Exception as exc:
                raise RuntimeEnrollmentProviderUnavailable from exc

        monkeypatch.setattr(
            runtime_reports_module,
            "_sealed_terminal_response_payload",
            unavailable_terminal_sealer,
        )
        report = client.post(report_path, content=raw_body, headers=report_headers)

        assert report.status_code == 503, report.text
        assert report.json() == {
            "code": "RUNTIME_REPORT_PROVIDER_UNAVAILABLE",
            "status": "service_unavailable",
            "detail": "runtime report cryptographic provider is unavailable",
        }
        assert "terminal-key" not in report.text
        assert _report_path_counts(app, seeded["org_id"]) == before
        assert _report_attempt_count(app, seeded["org_id"]) == before_attempts + 1
        with app.state.session_factory() as session:
            attempts = session.scalars(
                sa.select(ManagedMutationAttempt).where(
                    ManagedMutationAttempt.org_id == seeded["org_id"],
                    ManagedMutationAttempt.action
                    == runtime_reports_module.CONTROL_PLANE_RUNTIME_REPORT_ACCEPT_ACTION,
                )
            ).all()
        assert len(attempts) == 1
        assert attempts[0].status == "failed"
        assert attempts[0].failure_class_hash is not None
        assert len(attempts[0].failure_class_hash) == 64
        assert attempts[0].failure_digest is not None
        assert len(attempts[0].failure_digest) == 64
        assert "terminal-key" not in attempts[0].failure_digest

        monkeypatch.setattr(
            runtime_enrollment_module,
            "_sealed_terminal_response_payload",
            unavailable_terminal_sealer,
        )
        for decision in (Decision.DENY, Decision.ESCALATE):
            decision_tag = {
                Decision.DENY: "d",
                Decision.ESCALATE: "e",
            }[decision]
            refusal_seeded = _seed_report_scope(
                client,
                org,
                descriptor_signer,
                report_decision=decision,
                scope_suffix=f"p-{provider_tag}-{decision_tag}",
            )
            refusal_path, refusal_body, refusal_headers = _signed_status_request(refusal_seeded)
            before_refusal = _report_path_counts(app, refusal_seeded["org_id"])
            before_refusal_attempts = _report_attempt_count(app, refusal_seeded["org_id"])

            refusal = client.post(
                refusal_path,
                content=refusal_body,
                headers=refusal_headers,
            )

            assert refusal.status_code == 503, refusal.text
            assert refusal.json() == {
                "code": "RUNTIME_REPORT_PROVIDER_UNAVAILABLE",
                "status": "service_unavailable",
                "detail": "runtime report cryptographic provider is unavailable",
            }
            assert "terminal-key" not in refusal.text
            assert _report_path_counts(app, refusal_seeded["org_id"]) == before_refusal
            assert _report_attempt_count(app, refusal_seeded["org_id"]) == before_refusal_attempts
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_identical_runtime_reports_converge_on_postgresql(tmp_path: Path) -> None:
    app, client, org, _project_id, _environment_id, database_url = _postgres_runtime_app(tmp_path)
    try:
        seeded = _seed_report_scope(client, org, _runtime_descriptor_signer())
        path, raw_body, headers = _signed_status_request(seeded)
        before = _report_path_counts(app, seeded["org_id"])
        before_attempts = _report_attempt_count(app, seeded["org_id"])
        worker_args = (
            database_url,
            str(tmp_path / "report-workers"),
            {"method": "POST", "path": path, "query": "", "headers": headers, "body": raw_body},
        )
        with ProcessPoolExecutor(max_workers=2, mp_context=mp.get_context("fork")) as executor:
            responses = list(executor.map(_post_runtime_request, [worker_args] * 8))

        assert {status for status, _code, _body in responses} == {201}
        assert len({body for _status, _code, body in responses}) == 1
        after = _report_path_counts(app, seeded["org_id"])
        for name in (
            "receipts",
            "consumptions",
            "events",
            "outbox",
            "idempotency",
            "reports",
            "nonces",
            "heads",
        ):
            assert after[name] == before[name] + 1
        assert after["attestations"] == before["attestations"]
        assert after["challenges"] == before["challenges"]
        assert _report_attempt_count(app, seeded["org_id"]) == before_attempts + 1
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_identical_concurrent_wiring_reports_replay_without_debris_postgresql(
    tmp_path: Path,
) -> None:
    app, client, org, _project_id, _environment_id, database_url = _postgres_runtime_app(tmp_path)
    try:
        seeded = _seed_report_scope(client, org, _runtime_descriptor_signer())
        snapshot = seeded["policy_snapshot"]
        build_digest = "b" * 64
        config_digest = "c" * 64
        challenge_path, challenge_headers = _signed_challenge_request(
            seeded,
            snapshot=snapshot,
            runtime_build_digest=build_digest,
            configuration_digest=config_digest,
        )
        challenge = client.get(challenge_path, headers=challenge_headers)
        assert challenge.status_code == 200, challenge.text
        artifact = _produce_genuine_wiring_artifact(
            app,
            seeded=seeded,
            snapshot=snapshot,
            challenge_nonce=challenge.json()["nonce"],
            runtime_build_digest=build_digest,
            configuration_digest=config_digest,
            tmp_path=tmp_path / "wiring-first",
            sequence=1,
        )
        path, raw_body, headers = _signed_status_request(
            seeded,
            payload={
                "kind": "wiring",
                "sequence": 1,
                "expires_at": (utcnow() + timedelta(minutes=5)).isoformat(),
                "policy_version_id": seeded["policy_version_id"],
                "policy_head_generation": seeded["policy_head_generation"],
                "policy_content_hash": seeded["policy_content_hash"],
                "runtime_build_digest": build_digest,
                "configuration_digest": config_digest,
                "policy_snapshot": snapshot,
                "challenge_token": challenge.json()["token"],
                "artifact": artifact,
            },
            idempotency_key="runtime-wiring-postgres-converge",
        )
        before = _report_path_counts(app, seeded["org_id"])
        before_attempts = _report_attempt_count(app, seeded["org_id"])
        worker_args = (
            database_url,
            str(tmp_path / "wiring-workers"),
            {"method": "POST", "path": path, "query": "", "headers": headers, "body": raw_body},
        )
        with ProcessPoolExecutor(max_workers=2, mp_context=mp.get_context("fork")) as executor:
            responses = list(executor.map(_post_runtime_request, [worker_args] * 8))

        assert {status for status, _code, _body in responses} == {201}
        assert len({body for _status, _code, body in responses}) == 1
        after = _report_path_counts(app, seeded["org_id"])
        for name in (
            "receipts",
            "consumptions",
            "events",
            "outbox",
            "idempotency",
            "reports",
            "nonces",
            "heads",
            "attestations",
            "challenges",
        ):
            assert after[name] == before[name] + 1
        assert _report_attempt_count(app, seeded["org_id"]) == before_attempts + 1
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_concurrent_different_runtime_report_body_conflicts_without_debris(
    tmp_path: Path,
) -> None:
    app, client, org, _project_id, _environment_id, database_url = _postgres_runtime_app(tmp_path)
    try:
        seeded = _seed_report_scope(client, org, _runtime_descriptor_signer())
        snapshot = seeded["policy_snapshot"]
        build_digest = "b" * 64
        config_digest = "c" * 64
        idempotency_key = "runtime-report-postgres-different-body"
        requests: list[tuple[str, bytes, dict[str, str]]] = []
        challenge_responses: list[dict[str, Any]] = []
        for index in range(2):
            challenge_path, challenge_headers = _signed_challenge_request(
                seeded,
                snapshot=snapshot,
                runtime_build_digest=build_digest,
                configuration_digest=config_digest,
            )
            challenge = client.get(challenge_path, headers=challenge_headers)
            assert challenge.status_code == 200, challenge.text
            challenge_body = challenge.json()
            assert challenge_body["expected_sequence"] == 1
            artifact = _produce_genuine_wiring_artifact(
                app,
                seeded=seeded,
                snapshot=snapshot,
                challenge_nonce=challenge_body["nonce"],
                runtime_build_digest=build_digest,
                configuration_digest=config_digest,
                tmp_path=tmp_path / f"different-wiring-{index}",
                sequence=1,
            )
            requests.append(
                _signed_status_request(
                    seeded,
                    payload={
                        "kind": "wiring",
                        "sequence": 1,
                        "expires_at": (utcnow() + timedelta(minutes=5)).isoformat(),
                        "policy_version_id": seeded["policy_version_id"],
                        "policy_head_generation": seeded["policy_head_generation"],
                        "policy_content_hash": seeded["policy_content_hash"],
                        "runtime_build_digest": build_digest,
                        "configuration_digest": config_digest,
                        "policy_snapshot": snapshot,
                        "challenge_token": challenge_body["token"],
                        "artifact": artifact,
                    },
                    idempotency_key=idempotency_key,
                )
            )
            challenge_responses.append(challenge_body)
        before = _report_path_counts(app, seeded["org_id"])
        before_attempts = _report_attempt_count(app, seeded["org_id"])

        worker_requests = tuple(
            (
                database_url,
                str(tmp_path / "report-workers"),
                {
                    "method": "POST",
                    "path": path,
                    "query": "",
                    "headers": headers,
                    "body": body,
                },
            )
            for path, body, headers in requests
        )
        with ProcessPoolExecutor(max_workers=2, mp_context=mp.get_context("fork")) as executor:
            responses = list(executor.map(_post_runtime_request, worker_requests))

        assert sorted(status for status, _code, _body in responses) == [201, 409]
        assert next(code for status, code, _body in responses if status == 409) == (
            "IDEMPOTENCY_CONFLICT"
        )
        after = _report_path_counts(app, seeded["org_id"])
        for name in (
            "receipts",
            "consumptions",
            "events",
            "outbox",
            "idempotency",
            "reports",
            "nonces",
            "heads",
            "attestations",
            "challenges",
        ):
            assert after[name] == before[name] + 1
        assert _report_attempt_count(app, seeded["org_id"]) == before_attempts + 1

        reused_challenge = challenge_responses[0]
        reused_artifact = _produce_genuine_wiring_artifact(
            app,
            seeded=seeded,
            snapshot=snapshot,
            challenge_nonce=reused_challenge["nonce"],
            runtime_build_digest=build_digest,
            configuration_digest=config_digest,
            tmp_path=tmp_path / "reused-wiring",
            sequence=1,
        )
        reuse_path, reuse_body, reuse_headers = _signed_status_request(
            seeded,
            payload={
                "kind": "wiring",
                "sequence": 1,
                "expires_at": (utcnow() + timedelta(minutes=5)).isoformat(),
                "policy_version_id": seeded["policy_version_id"],
                "policy_head_generation": seeded["policy_head_generation"],
                "policy_content_hash": seeded["policy_content_hash"],
                "runtime_build_digest": build_digest,
                "configuration_digest": config_digest,
                "policy_snapshot": snapshot,
                "challenge_token": reused_challenge["token"],
                "artifact": reused_artifact,
            },
        )
        before_reuse = _report_path_counts(app, seeded["org_id"])
        before_reuse_attempts = _report_attempt_count(app, seeded["org_id"])
        reuse = client.post(reuse_path, content=reuse_body, headers=reuse_headers)
        assert reuse.status_code == 409, reuse.text
        assert reuse.json()["code"] == "REPORT_REJECTED"
        assert _report_path_counts(app, seeded["org_id"]) == before_reuse
        assert _report_attempt_count(app, seeded["org_id"]) == before_reuse_attempts
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_runtime_wiring_challenge_is_invalidated_by_intervening_report_postgresql(
    tmp_path: Path,
) -> None:
    app, client, org, _project_id, _environment_id, database_url = _postgres_runtime_app(tmp_path)
    try:
        seeded = _seed_report_scope(client, org, _runtime_descriptor_signer())
        snapshot = seeded["policy_snapshot"]
        build_digest = "b" * 64
        config_digest = "c" * 64
        challenge_path, challenge_headers = _signed_challenge_request(
            seeded,
            snapshot=snapshot,
            runtime_build_digest=build_digest,
            configuration_digest=config_digest,
        )
        old_challenge = client.get(challenge_path, headers=challenge_headers)
        assert old_challenge.status_code == 200, old_challenge.text
        assert old_challenge.json()["expected_sequence"] == 1
        old_artifact = _produce_genuine_wiring_artifact(
            app,
            seeded=seeded,
            snapshot=snapshot,
            challenge_nonce=old_challenge.json()["nonce"],
            runtime_build_digest=build_digest,
            configuration_digest=config_digest,
            tmp_path=tmp_path / "old",
            sequence=2,
        )
        status_path, status_body, status_headers = _signed_status_request(
            seeded, payload=_status_payload(seeded, sequence=1)
        )
        status = client.post(status_path, content=status_body, headers=status_headers)
        assert status.status_code == 201, status.text

        before = _report_path_counts(app, seeded["org_id"])
        before_attempts = _report_attempt_count(app, seeded["org_id"])
        stale_path, stale_body, stale_headers = _signed_status_request(
            seeded,
            payload={
                "kind": "wiring",
                "sequence": 2,
                "expires_at": (utcnow() + timedelta(minutes=5)).isoformat(),
                "policy_version_id": seeded["policy_version_id"],
                "policy_head_generation": seeded["policy_head_generation"],
                "policy_content_hash": seeded["policy_content_hash"],
                "runtime_build_digest": build_digest,
                "configuration_digest": config_digest,
                "policy_snapshot": snapshot,
                "challenge_token": old_challenge.json()["token"],
                "artifact": old_artifact,
            },
        )
        stale = client.post(stale_path, content=stale_body, headers=stale_headers)
        assert stale.status_code == 409, stale.text
        assert stale.json()["code"] == "REPORT_REJECTED"
        assert _report_path_counts(app, seeded["org_id"]) == before
        assert _report_attempt_count(app, seeded["org_id"]) == before_attempts

        current_path, current_headers = _signed_challenge_request(
            seeded,
            snapshot=snapshot,
            runtime_build_digest=build_digest,
            configuration_digest=config_digest,
        )
        current_challenge = client.get(current_path, headers=current_headers)
        assert current_challenge.status_code == 200, current_challenge.text
        assert current_challenge.json()["expected_sequence"] == 2
        current_artifact = _produce_genuine_wiring_artifact(
            app,
            seeded=seeded,
            snapshot=snapshot,
            challenge_nonce=current_challenge.json()["nonce"],
            runtime_build_digest=build_digest,
            configuration_digest=config_digest,
            tmp_path=tmp_path / "current",
            sequence=2,
        )
        current_report_path, current_body, current_report_headers = _signed_status_request(
            seeded,
            payload={
                "kind": "wiring",
                "sequence": 2,
                "expires_at": (utcnow() + timedelta(minutes=5)).isoformat(),
                "policy_version_id": seeded["policy_version_id"],
                "policy_head_generation": seeded["policy_head_generation"],
                "policy_content_hash": seeded["policy_content_hash"],
                "runtime_build_digest": build_digest,
                "configuration_digest": config_digest,
                "policy_snapshot": snapshot,
                "challenge_token": current_challenge.json()["token"],
                "artifact": current_artifact,
            },
        )
        accepted = client.post(
            current_report_path, content=current_body, headers=current_report_headers
        )
        assert accepted.status_code == 201, accepted.text
        with app.state.session_factory() as session:
            report = session.get(RuntimeReport, accepted.json()["report_id"])
            challenge = session.scalars(
                sa.select(RuntimeWiringChallengeConsumption).where(
                    RuntimeWiringChallengeConsumption.report_id == accepted.json()["report_id"]
                )
            ).one()
            assert report is not None
            assert report.request_projection["challenge_expected_sequence"] == 2
            assert challenge.expected_sequence == challenge.sequence == 2
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_runtime_report_post_persistence_failure_rolls_back_postgresql(
    tmp_path: Path,
) -> None:
    app, client, org, _project_id, _environment_id, database_url = _postgres_runtime_app(tmp_path)
    try:
        seeded = _seed_report_scope(client, org, _runtime_descriptor_signer())
        path, raw_body, headers = _signed_status_request(seeded)
        before = _report_path_counts(app, seeded["org_id"])

        def fail_idempotency_insert(
            _mapper: Any, _connection: Any, target: RuntimeOperationIdempotency
        ) -> None:
            if target.operation == "report":
                raise SQLAlchemyError("forced PostgreSQL report rollback")

        sa.event.listen(RuntimeOperationIdempotency, "before_insert", fail_idempotency_insert)
        try:
            failed = client.post(path, content=raw_body, headers=headers)
        finally:
            sa.event.remove(RuntimeOperationIdempotency, "before_insert", fail_idempotency_insert)
        assert failed.status_code == 503, failed.text
        assert failed.json()["code"] == "DATABASE_UNAVAILABLE"
        assert _report_path_counts(app, seeded["org_id"]) == before
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_runtime_report_head_composite_anchor_is_enforced_postgresql(
    tmp_path: Path,
) -> None:
    app, client, org, _project_id, _environment_id, database_url = _postgres_runtime_app(tmp_path)
    try:
        seeded = _seed_report_scope(client, org, _runtime_descriptor_signer())
        path, raw_body, headers = _signed_status_request(seeded)
        accepted = client.post(path, content=raw_body, headers=headers)
        assert accepted.status_code == 201, accepted.text

        with pytest.raises(SQLAlchemyError):
            with app.state.session_factory.begin() as session:
                head = session.get(RuntimeReportHead, seeded["identity_id"])
                assert head is not None
                head.latest_report_id = new_id()
        with pytest.raises(SQLAlchemyError):
            with app.state.session_factory.begin() as session:
                session.execute(
                    sa.update(RuntimeReport)
                    .where(RuntimeReport.id == accepted.json()["report_id"])
                    .values(report_hash="0" * 64)
                )
        with pytest.raises(SQLAlchemyError):
            with app.state.session_factory.begin() as session:
                session.execute(
                    sa.delete(RuntimeReport).where(RuntimeReport.id == accepted.json()["report_id"])
                )
        with pytest.raises(SQLAlchemyError):
            with app.state.session_factory.begin() as session:
                session.execute(
                    sa.delete(RuntimeReportHead).where(
                        RuntimeReportHead.identity_id == seeded["identity_id"]
                    )
                )
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_runtime_wiring_historical_replay_and_projection_binding_postgresql(
    tmp_path: Path,
) -> None:
    app, client, org, _project_id, _environment_id, database_url = _postgres_runtime_app(tmp_path)
    try:
        seeded = _seed_report_scope(client, org, _runtime_descriptor_signer())
        first, first_request = _submit_wiring_report(
            client, app=app, seeded=seeded, tmp_path=tmp_path / "first", sequence=1
        )
        second, second_request = _submit_wiring_report(
            client, app=app, seeded=seeded, tmp_path=tmp_path / "second", sequence=2
        )
        assert first.status_code == second.status_code == 201
        before = _report_path_counts(app, seeded["org_id"])
        before_attempts = _report_attempt_count(app, seeded["org_id"])
        path, body, headers = first_request
        replay = client.post(path, content=body, headers=headers)
        assert replay.status_code == 201, replay.text
        assert replay.json() == first.json()
        assert _report_path_counts(app, seeded["org_id"]) == before
        assert _report_attempt_count(app, seeded["org_id"]) == before_attempts
        with pytest.raises(SQLAlchemyError):
            with app.state.session_factory.begin() as session:
                session.execute(
                    sa.update(RuntimeWiringAttestation)
                    .where(RuntimeWiringAttestation.report_id == second.json()["report_id"])
                    .values(suite_hash="0" * 64)
                )
        with app.state.engine.begin() as connection:
            connection.execute(
                sa.text(
                    "DROP TRIGGER runtime_wiring_attestations_immutable_update "
                    "ON runtime_wiring_attestations"
                )
            )
            connection.execute(
                sa.update(RuntimeWiringAttestation)
                .where(RuntimeWiringAttestation.report_id == second.json()["report_id"])
                .values(suite_hash="0" * 64)
            )
            connection.execute(
                sa.text(
                    POSTGRES_RUNTIME_LINEAGE_TRIGGERS[
                        "runtime_wiring_attestations_immutable_update"
                    ]
                )
            )
        second_path, second_body, second_headers = second_request
        tampered = client.post(second_path, content=second_body, headers=second_headers)
        assert tampered.status_code == 503, tampered.text
        fleet = client.get(
            (
                f"/orgs/{seeded['org_id']}/projects/{seeded['project_id']}"
                f"/environments/{seeded['environment_id']}/fleet"
            ),
            headers=_admin_headers(org),
        ).json()["runtimes"][0]
        assert fleet["proven_wired"]["available"] is False
        assert fleet["proven_wired"]["reason"] == "wiring_attestation_lineage_invalid"
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_runtime_wiring_attestations_are_immutable_postgresql(tmp_path: Path) -> None:
    app, client, org, _project_id, _environment_id, database_url = _postgres_runtime_app(tmp_path)
    try:
        seeded = _seed_report_scope(client, org, _runtime_descriptor_signer())
        accepted, _request = _submit_wiring_report(
            client, app=app, seeded=seeded, tmp_path=tmp_path, sequence=1
        )
        report_id = accepted.json()["report_id"]
        with pytest.raises(SQLAlchemyError):
            with app.state.session_factory.begin() as session:
                session.execute(
                    sa.update(RuntimeWiringAttestation)
                    .where(RuntimeWiringAttestation.report_id == report_id)
                    .values(suite_hash="0" * 64)
                )
        with pytest.raises(SQLAlchemyError):
            with app.state.session_factory.begin() as session:
                session.execute(
                    sa.delete(RuntimeWiringAttestation).where(
                        RuntimeWiringAttestation.report_id == report_id
                    )
                )
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_runtime_report_bigint_schema_and_current_binding_postgresql(tmp_path: Path) -> None:
    app, client, org, _project_id, _environment_id, database_url = _postgres_runtime_app(tmp_path)
    try:
        seeded = _seed_report_scope(client, org, _runtime_descriptor_signer())
        with app.state.engine.connect() as connection:
            column_types = dict(
                connection.execute(
                    sa.text(
                        "SELECT table_name || '.' || column_name, data_type "
                        "FROM information_schema.columns "
                        "WHERE table_schema = 'public' "
                        "AND (table_name, column_name) IN "
                        "(('runtime_reports', 'sequence'), "
                        "('runtime_report_heads', 'last_sequence'), "
                        "('runtime_report_heads', 'latest_wiring_sequence'))"
                    )
                ).all()
            )
        assert column_types == {
            "runtime_report_heads.last_sequence": "bigint",
            "runtime_report_heads.latest_wiring_sequence": "bigint",
            "runtime_reports.sequence": "bigint",
        }
        wiring, _request = _submit_wiring_report(
            client, app=app, seeded=seeded, tmp_path=tmp_path / "wiring", sequence=1
        )
        assert wiring.status_code == 201, wiring.text
        status_path, status_body, status_headers = _signed_status_request(
            seeded, payload=_status_payload(seeded, sequence=2)
        )
        status = client.post(status_path, content=status_body, headers=status_headers)
        assert status.status_code == 201, status.text
        with app.state.session_factory() as session:
            head = session.get(RuntimeReportHead, seeded["identity_id"])
            assert head is not None
            assert head.last_sequence == 2
            assert head.latest_wiring_sequence == 1
            assert head.latest_wiring_report_id == wiring.json()["report_id"]

        with pytest.raises(SQLAlchemyError):
            with app.state.session_factory.begin() as session:
                session.execute(
                    sa.update(RuntimeReportHead)
                    .where(RuntimeReportHead.identity_id == seeded["identity_id"])
                    .values(latest_wiring_sequence=2)
                )
        with pytest.raises(SQLAlchemyError):
            with app.state.session_factory.begin() as session:
                session.execute(
                    sa.update(RuntimeWiringChallengeConsumption)
                    .where(
                        RuntimeWiringChallengeConsumption.report_id == wiring.json()["report_id"]
                    )
                    .values(sequence=2)
                )

        for out_of_bounds in (0, 9_007_199_254_740_992):
            with pytest.raises(SQLAlchemyError):
                with app.state.session_factory.begin() as session:
                    original = (
                        session.execute(
                            sa.select(RuntimeReport.__table__).where(
                                RuntimeReport.id == wiring.json()["report_id"]
                            )
                        )
                        .mappings()
                        .one()
                    )
                    clone = dict(original)
                    clone.update(
                        id=new_id(),
                        sequence=out_of_bounds,
                        nonce=f"postgres-out-of-bounds-{out_of_bounds}",
                        receipt_id=f"postgres-out-of-bounds-receipt-{out_of_bounds}",
                    )
                    session.execute(sa.insert(RuntimeReport).values(**clone))
            with pytest.raises(SQLAlchemyError):
                with app.state.session_factory.begin() as session:
                    session.execute(
                        sa.update(RuntimeReportHead)
                        .where(RuntimeReportHead.identity_id == seeded["identity_id"])
                        .values(last_sequence=out_of_bounds)
                    )
            with pytest.raises(SQLAlchemyError):
                with app.state.session_factory.begin() as session:
                    session.execute(
                        sa.update(RuntimeReportHead)
                        .where(RuntimeReportHead.identity_id == seeded["identity_id"])
                        .values(latest_wiring_sequence=out_of_bounds)
                    )
            with pytest.raises(SQLAlchemyError):
                with app.state.session_factory.begin() as session:
                    session.execute(
                        sa.update(RuntimeWiringChallengeConsumption)
                        .where(
                            RuntimeWiringChallengeConsumption.report_id
                            == wiring.json()["report_id"]
                        )
                        .values(sequence=out_of_bounds)
                    )

        path, raw_body, headers = _signed_status_request(seeded)
        before = _report_path_counts(app, seeded["org_id"])
        with app.state.session_factory.begin() as session:
            identity = session.get(RuntimeIdentity, seeded["identity_id"])
            assert identity is not None
            identity.public_key_thumbprint = "0" * 64
        rejected = client.post(path, content=raw_body, headers=headers)
        assert rejected.status_code == 401, rejected.text
        assert _report_path_counts(app, seeded["org_id"]) == before
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_100_identical_runtime_enrollments_converge_to_one_identity(tmp_path: Path) -> None:
    app, client, org, project_id, environment_id, database_url = _postgres_runtime_app(tmp_path)
    try:
        key_provider = _runtime_key_provider("runtime-postgres-converge-key")
        bootstrap = _issue_bootstrap(
            client,
            org["org_id"],
            project_id,
            environment_id,
            _admin_headers(org),
            key_provider=key_provider,
        )
        request = _captured_enrollment_request(
            scope=GateScope(
                org_id=org["org_id"],
                project_id=project_id,
                environment=environment_id,
                gate_id=bootstrap["gate_id"],
            ),
            bootstrap=bootstrap,
            key_provider=key_provider,
            idempotency_key="runtime-enroll-postgres-0100",
        )
        worker_args = (
            database_url,
            str(tmp_path / "multiprocess-audit"),
            _serialize_request(request),
        )

        with ProcessPoolExecutor(max_workers=16, mp_context=mp.get_context("fork")) as executor:
            results = list(executor.map(_post_runtime_request, [worker_args] * 100))

        assert {status for status, _code, _body in results} == {201}
        verifier = RuntimeEnrollmentClient(
            key_provider=key_provider,
            transport=_unused_transport,
            audience=_AUDIENCE,
        )
        verified = [
            verifier.accept_enrollment_response(
                RuntimeHttpResponse(status_code=status, body=body, headers={}),
                issuer_public_key=_runtime_descriptor_signer().public_key_bytes(),
                expected_scope=GateScope(
                    org_id=org["org_id"],
                    project_id=project_id,
                    environment=environment_id,
                    gate_id=bootstrap["gate_id"],
                ),
                expected_runtime_identity_id=bootstrap["runtime_identity_id"],
            )
            for status, _code, body in results
        ]
        assert {descriptor.runtime_identity_id for descriptor in verified} == {
            bootstrap["runtime_identity_id"]
        }
        assert {descriptor.credential_generation for descriptor in verified} == {1}
        _assert_runtime_counts(
            app,
            org["org_id"],
            project_id,
            environment_id,
            identities=1,
            credentials=1,
            active_credentials=1,
            bootstraps=1,
            consumed_bootstraps=1,
            enrollment_idempotency=1,
            operation_idempotency=0,
            nonces=0,
            bootstrap_receipts=1,
            enroll_receipts=1,
            renew_receipts=0,
            revoke_receipts=0,
        )
        chain_files = list((tmp_path / "multiprocess-audit").glob("*.jsonl"))
        assert chain_files == []
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_runtime_enrollment_conflict_and_cross_scope_idempotency_are_isolated(
    tmp_path: Path,
) -> None:
    app, client, org, project_id, environment_id, database_url = _postgres_runtime_app(tmp_path)
    try:
        key_provider = _runtime_key_provider("runtime-postgres-conflict-key")
        bootstrap = _issue_bootstrap(
            client,
            org["org_id"],
            project_id,
            environment_id,
            _admin_headers(org),
            key_provider=key_provider,
        )
        scope = GateScope(
            org_id=org["org_id"],
            project_id=project_id,
            environment=environment_id,
            gate_id=bootstrap["gate_id"],
        )
        idempotency_key = "runtime-enroll-postgres-conflict"
        second_org = _bootstrap_org(client)
        second_project_id, second_environment_id = _seed_scope_trust_and_policy(
            app, second_org["org_id"]
        )
        second_key = _runtime_key_provider("runtime-postgres-cross-scope-key")
        second_bootstrap = _issue_bootstrap(
            client,
            second_org["org_id"],
            second_project_id,
            second_environment_id,
            _admin_headers(second_org),
            key_provider=second_key,
        )
        first_request = _captured_enrollment_request(
            scope=scope,
            bootstrap=bootstrap,
            key_provider=key_provider,
            idempotency_key=idempotency_key,
            client_nonce="client-first",
        )
        second_scope = GateScope(
            org_id=second_org["org_id"],
            project_id=second_project_id,
            environment=second_environment_id,
            gate_id=second_bootstrap["gate_id"],
        )
        before_first_tamper = _runtime_counts(app, org["org_id"], project_id, environment_id)
        before_second_tamper = _runtime_counts(
            app, second_org["org_id"], second_project_id, second_environment_id
        )
        tampered = _tamper_enrollment_request_to_scope(
            first_request,
            scope=second_scope,
        )
        tamper_response = _send_runtime_request(client, tampered)
        assert tamper_response.status_code == 401, tamper_response.text
        assert tamper_response.json()["code"] == "BOOTSTRAP_SCOPE_MISMATCH"
        assert (
            _runtime_counts(app, org["org_id"], project_id, environment_id) == before_first_tamper
        )
        assert (
            _runtime_counts(app, second_org["org_id"], second_project_id, second_environment_id)
            == before_second_tamper
        )

        first = _send_runtime_request(client, first_request)
        conflict = _send_runtime_request(
            client,
            _captured_enrollment_request(
                scope=scope,
                bootstrap=bootstrap,
                key_provider=key_provider,
                idempotency_key=idempotency_key,
                client_nonce="client-conflict",
            ),
        )
        assert first.status_code == 201, first.text
        assert conflict.status_code == 409, conflict.text
        assert conflict.json()["code"] == "IDEMPOTENCY_CONFLICT"

        second_response = _send_runtime_request(
            client,
            _captured_enrollment_request(
                scope=second_scope,
                bootstrap=second_bootstrap,
                key_provider=second_key,
                idempotency_key=idempotency_key,
            ),
        )
        assert second_response.status_code == 201, second_response.text

        _assert_runtime_counts(
            app,
            org["org_id"],
            project_id,
            environment_id,
            identities=1,
            credentials=1,
            active_credentials=1,
            bootstraps=1,
            consumed_bootstraps=1,
            enrollment_idempotency=1,
            operation_idempotency=0,
            nonces=0,
            bootstrap_receipts=1,
            enroll_receipts=1,
            renew_receipts=0,
            revoke_receipts=0,
        )
        _assert_runtime_counts(
            app,
            second_org["org_id"],
            second_project_id,
            second_environment_id,
            identities=1,
            credentials=1,
            active_credentials=1,
            bootstraps=1,
            consumed_bootstraps=1,
            enrollment_idempotency=1,
            operation_idempotency=0,
            nonces=0,
            bootstrap_receipts=1,
            enroll_receipts=1,
            renew_receipts=0,
            revoke_receipts=0,
        )
        _assert_runtime_database_uniqueness(app, org["org_id"], project_id, environment_id)
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def test_runtime_renew_replay_revoke_and_expired_paths_are_nonduplicating(
    tmp_path: Path,
) -> None:
    app, client, org, project_id, environment_id, database_url = _postgres_runtime_app(tmp_path)
    try:
        key_provider = _runtime_key_provider("runtime-postgres-renew-key")
        bootstrap = _issue_bootstrap(
            client,
            org["org_id"],
            project_id,
            environment_id,
            _admin_headers(org),
            key_provider=key_provider,
        )
        scope = GateScope(
            org_id=org["org_id"],
            project_id=project_id,
            environment=environment_id,
            gate_id=bootstrap["gate_id"],
        )
        runtime_client = RuntimeEnrollmentClient(
            key_provider=key_provider,
            transport=_runtime_transport(client=client),
            audience=_AUDIENCE,
        )
        enrollment = runtime_client.exchange_bootstrap(
            scope=scope,
            bootstrap_id=bootstrap["bootstrap_id"],
            bootstrap_token=bootstrap["bootstrap_token"],
            runtime_identity_id=bootstrap["runtime_identity_id"],
            idempotency_key="runtime-enroll-postgres-renew",
            server_challenge=bootstrap["server_challenge"],
            client_nonce="client-renew",
            timestamp=_runtime_timestamp(),
        )
        descriptor = runtime_client.accept_enrollment_response(
            enrollment,
            issuer_public_key=_runtime_descriptor_signer().public_key_bytes(),
            expected_scope=scope,
            expected_runtime_identity_id=bootstrap["runtime_identity_id"],
        )
        renew_idempotency_key = "runtime-renew-postgres-0001"
        renew_nonce = "runtime-renew-nonce-0001"
        renew_timestamp = _runtime_timestamp()
        renewed = runtime_client.renew(
            descriptor=descriptor,
            idempotency_key=renew_idempotency_key,
            timestamp=renew_timestamp,
            nonce=renew_nonce,
        )
        assert renewed.status_code == 200, renewed.body.decode()
        replay = runtime_client.renew(
            descriptor=descriptor,
            idempotency_key=renew_idempotency_key,
            timestamp=renew_timestamp,
            nonce=renew_nonce,
        )
        assert replay.status_code == 200, replay.body.decode()
        assert replay.body == renewed.body
        _assert_runtime_counts(
            app,
            org["org_id"],
            project_id,
            environment_id,
            identities=1,
            credentials=2,
            active_credentials=1,
            bootstraps=1,
            consumed_bootstraps=1,
            enrollment_idempotency=1,
            operation_idempotency=1,
            nonces=1,
            bootstrap_receipts=1,
            enroll_receipts=1,
            renew_receipts=1,
            revoke_receipts=0,
        )
        renewed_descriptor = runtime_client.accept_enrollment_response(
            renewed,
            issuer_public_key=_runtime_descriptor_signer().public_key_bytes(),
            expected_scope=scope,
            expected_runtime_identity_id=bootstrap["runtime_identity_id"],
        )
        stale_revoke_body = _admin_revoke_body(
            expected_credential_generation=descriptor.credential_generation,
        )
        before_stale_revoke = _runtime_counts(app, org["org_id"], project_id, environment_id)
        stale_revoke = _post_admin_revoke(
            client,
            org=org,
            project_id=project_id,
            environment_id=environment_id,
            identity_id=bootstrap["runtime_identity_id"],
            body=stale_revoke_body,
            idempotency_key="runtime-revoke-stale",
        )
        assert stale_revoke.status_code == 409, stale_revoke.text
        assert stale_revoke.json()["code"] == "CREDENTIAL_GENERATION_MISMATCH"
        assert (
            _runtime_counts(app, org["org_id"], project_id, environment_id) == before_stale_revoke
        )

        wrong_generation_body = _admin_revoke_body(
            expected_credential_generation=renewed_descriptor.credential_generation + 1,
        )
        wrong_generation = _post_admin_revoke(
            client,
            org=org,
            project_id=project_id,
            environment_id=environment_id,
            identity_id=bootstrap["runtime_identity_id"],
            body=wrong_generation_body,
            idempotency_key="runtime-revoke-wrong-generation",
        )
        assert wrong_generation.status_code == 409, wrong_generation.text
        assert wrong_generation.json()["code"] == "CREDENTIAL_GENERATION_MISMATCH"
        assert (
            _runtime_counts(app, org["org_id"], project_id, environment_id) == before_stale_revoke
        )

        revoke_body = _admin_revoke_body(
            expected_credential_generation=renewed_descriptor.credential_generation,
        )
        revoke = _post_admin_revoke(
            client,
            org=org,
            project_id=project_id,
            environment_id=environment_id,
            identity_id=bootstrap["runtime_identity_id"],
            body=revoke_body,
            idempotency_key="runtime-revoke-postgres-0001",
        )
        assert revoke.status_code == 200, revoke.text
        replay_revoke = _post_admin_revoke(
            client,
            org=org,
            project_id=project_id,
            environment_id=environment_id,
            identity_id=bootstrap["runtime_identity_id"],
            body=revoke_body,
            idempotency_key="runtime-revoke-postgres-0001",
        )
        assert replay_revoke.status_code == 200, replay_revoke.text
        assert replay_revoke.json() == revoke.json()
        conflict_revoke_body = {
            **revoke_body,
            "expected_credential_generation": renewed_descriptor.credential_generation + 1,
        }
        before_revoke_conflict = _runtime_counts(app, org["org_id"], project_id, environment_id)
        conflict_revoke = _post_admin_revoke(
            client,
            org=org,
            project_id=project_id,
            environment_id=environment_id,
            identity_id=bootstrap["runtime_identity_id"],
            body=conflict_revoke_body,
            idempotency_key="runtime-revoke-postgres-0001",
        )
        assert conflict_revoke.status_code == 409, conflict_revoke.text
        assert conflict_revoke.json()["code"] == "IDEMPOTENCY_CONFLICT"
        assert (
            _runtime_counts(app, org["org_id"], project_id, environment_id)
            == before_revoke_conflict
        )

        second_org = _bootstrap_org(client)
        second_project_id, second_environment_id = _seed_scope_trust_and_policy(
            app, second_org["org_id"]
        )
        second_key = _runtime_key_provider("runtime-postgres-revoke-cross-scope-key")
        second_bootstrap = _issue_bootstrap(
            client,
            second_org["org_id"],
            second_project_id,
            second_environment_id,
            _admin_headers(second_org),
            key_provider=second_key,
        )
        second_scope = GateScope(
            org_id=second_org["org_id"],
            project_id=second_project_id,
            environment=second_environment_id,
            gate_id=second_bootstrap["gate_id"],
        )
        second_runtime_client = RuntimeEnrollmentClient(
            key_provider=second_key,
            transport=_runtime_transport(client=client),
            audience=_AUDIENCE,
        )
        second_enrollment = second_runtime_client.exchange_bootstrap(
            scope=second_scope,
            bootstrap_id=second_bootstrap["bootstrap_id"],
            bootstrap_token=second_bootstrap["bootstrap_token"],
            runtime_identity_id=second_bootstrap["runtime_identity_id"],
            idempotency_key="runtime-enroll-postgres-revoke-cross-scope",
            server_challenge=second_bootstrap["server_challenge"],
            client_nonce="client-revoke-cross-scope",
            timestamp=_runtime_timestamp(),
        )
        second_descriptor = second_runtime_client.accept_enrollment_response(
            second_enrollment,
            issuer_public_key=_runtime_descriptor_signer().public_key_bytes(),
            expected_scope=second_scope,
            expected_runtime_identity_id=second_bootstrap["runtime_identity_id"],
        )
        cross_scope_revoke = _post_admin_revoke(
            client,
            org=second_org,
            project_id=second_project_id,
            environment_id=second_environment_id,
            identity_id=second_bootstrap["runtime_identity_id"],
            body=_admin_revoke_body(
                expected_credential_generation=second_descriptor.credential_generation,
            ),
            idempotency_key="runtime-revoke-postgres-0001",
        )
        assert cross_scope_revoke.status_code == 200, cross_scope_revoke.text
        _assert_runtime_counts(
            app,
            second_org["org_id"],
            second_project_id,
            second_environment_id,
            identities=1,
            credentials=1,
            active_credentials=0,
            bootstraps=1,
            consumed_bootstraps=1,
            enrollment_idempotency=1,
            operation_idempotency=1,
            nonces=0,
            bootstrap_receipts=1,
            enroll_receipts=1,
            renew_receipts=0,
            revoke_receipts=1,
        )

        before_revoked_retry = _runtime_counts(app, org["org_id"], project_id, environment_id)
        revoked_retry = runtime_client.renew(
            descriptor=renewed_descriptor,
            idempotency_key="runtime-renew-after-revoke",
            timestamp=_runtime_timestamp(),
            nonce="runtime-renew-after-revoke",
        )
        assert revoked_retry.status_code == 401, revoked_retry.body.decode()
        assert (
            _runtime_counts(app, org["org_id"], project_id, environment_id) == before_revoked_retry
        )

        second_bootstrap = _issue_bootstrap(
            client,
            org["org_id"],
            project_id,
            environment_id,
            _admin_headers(org),
            key_provider=_runtime_key_provider("runtime-postgres-expired-key"),
        )
        expired_runtime_client = RuntimeEnrollmentClient(
            key_provider=_runtime_key_provider("runtime-postgres-expired-key"),
            transport=_runtime_transport(client=client),
            audience=_AUDIENCE,
        )
        expired_scope = GateScope(
            org_id=org["org_id"],
            project_id=project_id,
            environment=environment_id,
            gate_id=second_bootstrap["gate_id"],
        )
        expired_enrollment = expired_runtime_client.exchange_bootstrap(
            scope=expired_scope,
            bootstrap_id=second_bootstrap["bootstrap_id"],
            bootstrap_token=second_bootstrap["bootstrap_token"],
            runtime_identity_id=second_bootstrap["runtime_identity_id"],
            idempotency_key="runtime-enroll-postgres-expired",
            server_challenge=second_bootstrap["server_challenge"],
            client_nonce="client-expired",
            timestamp=_runtime_timestamp(),
        )
        expired_descriptor = expired_runtime_client.accept_enrollment_response(
            expired_enrollment,
            issuer_public_key=_runtime_descriptor_signer().public_key_bytes(),
            expected_scope=expired_scope,
            expected_runtime_identity_id=second_bootstrap["runtime_identity_id"],
        )
        with app.state.session_factory.begin() as session:
            credential = session.scalars(
                sa.select(RuntimeCredentialGeneration).where(
                    RuntimeCredentialGeneration.identity_id
                    == second_bootstrap["runtime_identity_id"],
                    RuntimeCredentialGeneration.status == "active",
                )
            ).one()
            credential.not_after = utcnow() - timedelta(seconds=1)
        before_expired = _runtime_counts(app, org["org_id"], project_id, environment_id)
        expired = RuntimeEnrollmentClient(
            key_provider=_runtime_key_provider("runtime-postgres-expired-key"),
            transport=_runtime_transport(client=client),
            audience=_AUDIENCE,
        ).renew(
            descriptor=expired_descriptor,
            idempotency_key="runtime-renew-expired",
            timestamp=_runtime_timestamp(),
            nonce="runtime-renew-expired",
        )
        assert expired.status_code == 401, expired.body.decode()
        assert _runtime_counts(app, org["org_id"], project_id, environment_id) == before_expired
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url)


def _postgres_runtime_app(
    tmp_path: Path,
) -> tuple[Any, TestClient, dict[str, Any], str, str, str]:
    if (
        os.environ.get("ACP_TEST_POSTGRES_GATE_ACTIVE") != "1"
        or os.environ.get("ACP_TEST_POSTGRES_SELECTOR_MODE") != _SELECTOR
    ):
        pytest.skip("runtime enrollment PostgreSQL gate requires the exact P4 selector")
    database_url = os.environ.get("ACP_TEST_POSTGRES_URL")
    if not database_url:
        pytest.fail("ACP_TEST_POSTGRES_URL is required by the P4 runtime enrollment gate")

    _reset_postgres_schema(database_url)
    result = upgrade_database(database_url, expected_database=EXPECTED_DATABASE)
    assert result.after.state is DatabaseSchemaState.VERSION_0012
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "audit",
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        ),
        runtime_descriptor_signer=_runtime_descriptor_signer(),
    )
    client = TestClient(app, raise_server_exceptions=False)
    org = _bootstrap_org(client)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    return app, client, org, project_id, environment_id, database_url


def _post_runtime_request(
    args: tuple[str, str, dict[str, Any]],
) -> tuple[int, str | None, bytes]:
    database_url, audit_dir, request = args
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=Path(audit_dir),
            bootstrap_token=BOOTSTRAP_TOKEN,
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        ),
        runtime_descriptor_signer=_runtime_descriptor_signer(),
    )
    client = TestClient(app, raise_server_exceptions=False)
    try:
        response = _send_serialized_runtime_request(client, request)
        payload = (
            response.json()
            if response.headers.get("content-type", "").startswith("application/json")
            else {}
        )
        return response.status_code, payload.get("code"), response.content
    finally:
        app.state.engine.dispose()


def _captured_enrollment_request(
    *,
    scope: GateScope,
    bootstrap: dict[str, Any],
    key_provider: InMemoryEd25519WorkloadKeyProvider,
    idempotency_key: str,
    client_nonce: str = "client-0100",
) -> RuntimeHttpRequest:
    captured: list[RuntimeHttpRequest] = []

    def capture(request: RuntimeHttpRequest) -> RuntimeHttpResponse:
        captured.append(request)
        return RuntimeHttpResponse(status_code=599, body=b"{}", headers={})

    RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=capture,
        audience=_AUDIENCE,
    ).exchange_bootstrap(
        scope=scope,
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=bootstrap["runtime_identity_id"],
        idempotency_key=idempotency_key,
        server_challenge=bootstrap["server_challenge"],
        client_nonce=client_nonce,
        timestamp=_runtime_timestamp(),
    )
    assert len(captured) == 1
    return captured[0]


def _send_runtime_request(client: TestClient, request: RuntimeHttpRequest) -> Any:
    return _send_serialized_runtime_request(client, _serialize_request(request))


def _unused_transport(_request: RuntimeHttpRequest) -> RuntimeHttpResponse:
    raise AssertionError("strict response verification must not use transport")


def _tamper_enrollment_request_to_scope(
    request: RuntimeHttpRequest,
    *,
    scope: GateScope,
) -> RuntimeHttpRequest:
    payload = json.loads(request.body.decode("utf-8"))
    payload.update(
        {
            "gate_id": scope.gate_id,
            "org_id": scope.org_id,
            "project_id": scope.project_id,
            "environment": scope.environment,
        }
    )
    return RuntimeHttpRequest(
        method=request.method,
        path=request.path,
        query=request.query,
        headers=dict(request.headers),
        body=canonical_json(payload).encode("utf-8"),
    )


def _serialize_request(request: RuntimeHttpRequest) -> dict[str, Any]:
    return {
        "method": request.method,
        "path": request.path,
        "query": request.query,
        "headers": dict(request.headers),
        "body": request.body,
    }


def _send_serialized_runtime_request(client: TestClient, request: dict[str, Any]) -> Any:
    query = request.get("query") or ""
    return client.request(
        request["method"],
        request["path"] + (f"?{query}" if query else ""),
        headers=dict(request["headers"]),
        content=request["body"],
    )


def _runtime_key_provider(key_id: str) -> InMemoryEd25519WorkloadKeyProvider:
    private_seed = hashlib.sha256(_RUNTIME_WORKLOAD_SEED + key_id.encode("utf-8")).digest()
    return InMemoryEd25519WorkloadKeyProvider(
        key_id=key_id,
        private_key=ed25519.Ed25519PrivateKey.from_private_bytes(private_seed),
    )


def _runtime_descriptor_signer() -> InMemoryEd25519WorkloadKeyProvider:
    return InMemoryEd25519WorkloadKeyProvider(
        key_id="postgres-runtime-descriptor",
        private_key=ed25519.Ed25519PrivateKey.from_private_bytes(_RUNTIME_DESCRIPTOR_SIGNER_SEED),
    )


def _admin_revoke_body(
    *,
    expected_credential_generation: int,
) -> dict[str, Any]:
    return {"expected_credential_generation": expected_credential_generation}


def _post_admin_revoke(
    client: TestClient,
    *,
    org: dict[str, Any],
    project_id: str,
    environment_id: str,
    identity_id: str,
    body: dict[str, Any],
    idempotency_key: str,
) -> Any:
    return client.post(
        f"/orgs/{org['org_id']}/projects/{project_id}/environments/{environment_id}"
        f"/runtime-identities/{identity_id}/revoke",
        json=body,
        headers={**_admin_headers(org), "Idempotency-Key": idempotency_key},
    )


def _assert_runtime_database_uniqueness(
    app: Any,
    org_id: str,
    project_id: str,
    environment_id: str,
) -> None:
    session = app.state.session_factory()
    try:
        gate = session.scalars(
            sa.select(RuntimeIdentityGate).where(
                RuntimeIdentityGate.org_id == org_id,
                RuntimeIdentityGate.project_id == project_id,
                RuntimeIdentityGate.environment_id == environment_id,
            )
        ).one()
        identity = session.scalars(
            sa.select(RuntimeIdentity).where(
                RuntimeIdentity.org_id == org_id,
                RuntimeIdentity.project_id == project_id,
                RuntimeIdentity.environment_id == environment_id,
            )
        ).one()
        credential = session.scalars(
            sa.select(RuntimeCredentialGeneration).where(
                RuntimeCredentialGeneration.org_id == org_id,
                RuntimeCredentialGeneration.project_id == project_id,
                RuntimeCredentialGeneration.environment_id == environment_id,
                RuntimeCredentialGeneration.identity_id == identity.id,
                RuntimeCredentialGeneration.status == "active",
            )
        ).one()
        now = utcnow()
        before_bootstraps = int(
            session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeEnrollmentBootstrap)
                .where(
                    RuntimeEnrollmentBootstrap.org_id == org_id,
                    RuntimeEnrollmentBootstrap.project_id == project_id,
                    RuntimeEnrollmentBootstrap.environment_id == environment_id,
                )
            )
        )
        before_active_bootstraps = int(
            session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeEnrollmentBootstrap)
                .where(
                    RuntimeEnrollmentBootstrap.org_id == org_id,
                    RuntimeEnrollmentBootstrap.project_id == project_id,
                    RuntimeEnrollmentBootstrap.environment_id == environment_id,
                    RuntimeEnrollmentBootstrap.status == "active",
                )
            )
        )
        duplicate_bootstraps = [
            RuntimeEnrollmentBootstrap(
                id=new_id(),
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                gate_id=gate.id,
                bootstrap_digest=sha256_json(
                    {"case": "duplicate-active-bootstrap", "index": index}
                ),
                bootstrap_locator=f"locator-{new_id()}",
                pepper_key_id="test-pepper",
                server_challenge=f"challenge-{new_id()}",
                runtime_identity_id=f"runtime-{new_id()}",
                audience=_AUDIENCE,
                workload_key_id=f"duplicate-key-{index}",
                public_key_thumbprint=thumbprint,
                status="active",
                created_by_actor="test",
                policy_head_generation=1,
                expires_at=now + timedelta(minutes=5),
            )
            for index, thumbprint in enumerate(("a" * 64, "b" * 64), start=1)
        ]
        session.add_all(duplicate_bootstraps)
        with pytest.raises(IntegrityError) as bootstrap_error:
            session.commit()
        session.rollback()
        assert getattr(bootstrap_error.value.orig, "sqlstate", None) == "23505"
        assert (
            getattr(getattr(bootstrap_error.value.orig, "diag", None), "constraint_name", None)
            == "uq_runtime_enrollment_active_bootstrap_scope"
        )
        assert (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeEnrollmentBootstrap)
                .where(
                    RuntimeEnrollmentBootstrap.org_id == org_id,
                    RuntimeEnrollmentBootstrap.project_id == project_id,
                    RuntimeEnrollmentBootstrap.environment_id == environment_id,
                )
            )
            == before_bootstraps
        )
        assert (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeEnrollmentBootstrap)
                .where(
                    RuntimeEnrollmentBootstrap.org_id == org_id,
                    RuntimeEnrollmentBootstrap.project_id == project_id,
                    RuntimeEnrollmentBootstrap.environment_id == environment_id,
                    RuntimeEnrollmentBootstrap.status == "active",
                )
            )
            == before_active_bootstraps
        )
        before_credentials = _count_scoped(
            session, RuntimeCredentialGeneration, org_id, project_id, environment_id
        )
        before_active_credentials = int(
            session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeCredentialGeneration)
                .where(
                    RuntimeCredentialGeneration.org_id == org_id,
                    RuntimeCredentialGeneration.project_id == project_id,
                    RuntimeCredentialGeneration.environment_id == environment_id,
                    RuntimeCredentialGeneration.status == "active",
                )
            )
        )
        session.add(
            RuntimeCredentialGeneration(
                id=new_id(),
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                identity_id=identity.id,
                generation=credential.generation + 1,
                workload_key_id=credential.workload_key_id,
                public_key_thumbprint=credential.public_key_thumbprint,
                not_before=now,
                not_after=now + timedelta(minutes=5),
                status="active",
                descriptor=dict(credential.descriptor),
            )
        )
        with pytest.raises(IntegrityError) as credential_error:
            session.commit()
        session.rollback()
        assert getattr(credential_error.value.orig, "sqlstate", None) == "23505"
        assert (
            getattr(getattr(credential_error.value.orig, "diag", None), "constraint_name", None)
            == "uq_runtime_credential_active_identity"
        )
        assert (
            _count_scoped(session, RuntimeCredentialGeneration, org_id, project_id, environment_id)
            == before_credentials
        )
        assert (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeCredentialGeneration)
                .where(
                    RuntimeCredentialGeneration.org_id == org_id,
                    RuntimeCredentialGeneration.project_id == project_id,
                    RuntimeCredentialGeneration.environment_id == environment_id,
                    RuntimeCredentialGeneration.status == "active",
                )
            )
            == before_active_credentials
        )
    finally:
        session.rollback()
        session.close()


def _assert_runtime_counts(
    app: Any,
    org_id: str,
    project_id: str,
    environment_id: str,
    **expected: int,
) -> None:
    assert _runtime_counts(app, org_id, project_id, environment_id) == expected


def _runtime_counts(
    app: Any,
    org_id: str,
    project_id: str,
    environment_id: str,
) -> dict[str, int]:
    with app.state.session_factory() as session:
        return {
            "identities": _count_scoped(
                session, RuntimeIdentity, org_id, project_id, environment_id
            ),
            "credentials": _count_scoped(
                session, RuntimeCredentialGeneration, org_id, project_id, environment_id
            ),
            "active_credentials": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(RuntimeCredentialGeneration)
                    .where(
                        RuntimeCredentialGeneration.org_id == org_id,
                        RuntimeCredentialGeneration.project_id == project_id,
                        RuntimeCredentialGeneration.environment_id == environment_id,
                        RuntimeCredentialGeneration.status == "active",
                    )
                )
            ),
            "bootstraps": _count_scoped(
                session, RuntimeEnrollmentBootstrap, org_id, project_id, environment_id
            ),
            "consumed_bootstraps": int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(RuntimeEnrollmentBootstrap)
                    .where(
                        RuntimeEnrollmentBootstrap.org_id == org_id,
                        RuntimeEnrollmentBootstrap.project_id == project_id,
                        RuntimeEnrollmentBootstrap.environment_id == environment_id,
                        RuntimeEnrollmentBootstrap.status == "consumed",
                    )
                )
            ),
            "enrollment_idempotency": _count_scoped(
                session, RuntimeEnrollmentIdempotency, org_id, project_id, environment_id
            ),
            "operation_idempotency": _count_scoped(
                session, RuntimeOperationIdempotency, org_id, project_id, environment_id
            ),
            "nonces": _count_scoped(
                session, RuntimeRequestNonce, org_id, project_id, environment_id
            ),
            "bootstrap_receipts": _action_count(
                session,
                CONTROL_PLANE_RUNTIME_BOOTSTRAP_ISSUE_ACTION,
                org_id,
                project_id,
                environment_id,
            ),
            "enroll_receipts": _action_count(
                session,
                CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION,
                org_id,
                project_id,
                environment_id,
            ),
            "renew_receipts": _action_count(
                session,
                CONTROL_PLANE_RUNTIME_IDENTITY_RENEW_ACTION,
                org_id,
                project_id,
                environment_id,
            ),
            "revoke_receipts": _action_count(
                session,
                CONTROL_PLANE_RUNTIME_IDENTITY_REVOKE_ACTION,
                org_id,
                project_id,
                environment_id,
            ),
        }


def _count_scoped(
    session: Any,
    model: Any,
    org_id: str,
    project_id: str,
    environment_id: str,
) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(model)
            .where(
                model.org_id == org_id,
                model.project_id == project_id,
                model.environment_id == environment_id,
            )
        )
    )


def _action_count(
    session: Any,
    action: str,
    org_id: str,
    project_id: str,
    environment_id: str,
) -> int:
    receipt_ids = (
        sa.select(ManagedDecisionReceipt.id)
        .where(
            ManagedDecisionReceipt.org_id == org_id,
            ManagedDecisionReceipt.project_id == project_id,
            ManagedDecisionReceipt.environment_id == environment_id,
            ManagedDecisionReceipt.proposed_action == action,
        )
        .scalar_subquery()
    )
    receipt_count = int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(ManagedDecisionReceipt)
            .where(ManagedDecisionReceipt.id.in_(receipt_ids))
        )
    )
    assert _count_action_child(session, ManagedReceiptConsumption, receipt_ids) == receipt_count
    assert _count_action_child(session, ManagedGovernanceEvent, receipt_ids) == receipt_count
    assert _count_action_child(session, ManagedOutboxMessage, receipt_ids) == receipt_count
    assert (
        _count_action_attempts(session, action, org_id, project_id, environment_id) == receipt_count
    )
    return receipt_count


def _count_action_child(session: Any, model: Any, receipt_ids: Any) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(model)
            .where(model.managed_receipt_id.in_(receipt_ids))
        )
    )


def _count_action_attempts(
    session: Any,
    action: str,
    org_id: str,
    project_id: str,
    environment_id: str,
) -> int:
    return int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(ManagedMutationAttempt)
            .where(
                ManagedMutationAttempt.org_id == org_id,
                ManagedMutationAttempt.project_id == project_id,
                ManagedMutationAttempt.environment_id == environment_id,
                ManagedMutationAttempt.action == action,
            )
        )
    )
