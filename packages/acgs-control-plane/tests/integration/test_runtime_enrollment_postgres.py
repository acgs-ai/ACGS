"""Live-PostgreSQL gates for runtime identity enrollment."""

from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import os
from concurrent.futures import ProcessPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from gove_zone.decision import canonical_json, sha256_json
from gove_zone.runtime_identity import (
    AtomicJsonRuntimeIdentityStore,
    GateScope,
    InMemoryEd25519WorkloadKeyProvider,
    RuntimeEnrollmentClient,
    RuntimeHttpRequest,
    RuntimeHttpResponse,
)
from sqlalchemy.exc import IntegrityError

from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_RUNTIME_BOOTSTRAP_ISSUE_ACTION,
    CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION,
    CONTROL_PLANE_RUNTIME_IDENTITY_RENEW_ACTION,
    CONTROL_PLANE_RUNTIME_IDENTITY_REVOKE_ACTION,
)
from acgs_control_plane.migrations import DatabaseSchemaState, upgrade_database
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
    RuntimeRequestNonce,
    new_id,
    utcnow,
)
from tests.integration.test_agent_registration_postgres import (
    EXPECTED_DATABASE,
    _reset_postgres_schema,
)
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

_RUNTIME_WORKLOAD_SEED = bytes.fromhex(
    "2e445e0c8f52dc3db9101438f1d0de70d023271108a9bf4d7f8c7e48f9fdf001"
)
_RUNTIME_DESCRIPTOR_SIGNER_SEED = bytes.fromhex(
    "a6c2388894866a773f7db3551c851d738c7cd9c06c5e6a99309b2bff18db2202"
)
_AUDIENCE = "control-plane.runtime-enrollment:v1"
_SELECTOR = "p4-runtime-enrollment"


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
        descriptor = runtime_client.exchange_and_store(
            store=AtomicJsonRuntimeIdentityStore(tmp_path / "runtime-renew-identity.json"),
            issuer_public_key=_runtime_descriptor_signer().public_key_bytes(),
            scope=scope,
            bootstrap_id=bootstrap["bootstrap_id"],
            bootstrap_token=bootstrap["bootstrap_token"],
            runtime_identity_id=bootstrap["runtime_identity_id"],
            idempotency_key="runtime-enroll-postgres-renew",
            server_challenge=bootstrap["server_challenge"],
            client_nonce="client-renew",
            timestamp=_runtime_timestamp(),
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
        second_descriptor = RuntimeEnrollmentClient(
            key_provider=second_key,
            transport=_runtime_transport(client=client),
            audience=_AUDIENCE,
        ).exchange_and_store(
            store=AtomicJsonRuntimeIdentityStore(tmp_path / "runtime-revoke-second.json"),
            issuer_public_key=_runtime_descriptor_signer().public_key_bytes(),
            scope=second_scope,
            bootstrap_id=second_bootstrap["bootstrap_id"],
            bootstrap_token=second_bootstrap["bootstrap_token"],
            runtime_identity_id=second_bootstrap["runtime_identity_id"],
            idempotency_key="runtime-enroll-postgres-revoke-cross-scope",
            server_challenge=second_bootstrap["server_challenge"],
            client_nonce="client-revoke-cross-scope",
            timestamp=_runtime_timestamp(),
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
        expired_descriptor = RuntimeEnrollmentClient(
            key_provider=_runtime_key_provider("runtime-postgres-expired-key"),
            transport=_runtime_transport(client=client),
            audience=_AUDIENCE,
        ).exchange_and_store(
            store=AtomicJsonRuntimeIdentityStore(tmp_path / "runtime-expired-identity.json"),
            issuer_public_key=_runtime_descriptor_signer().public_key_bytes(),
            scope=GateScope(
                org_id=org["org_id"],
                project_id=project_id,
                environment=environment_id,
                gate_id=second_bootstrap["gate_id"],
            ),
            bootstrap_id=second_bootstrap["bootstrap_id"],
            bootstrap_token=second_bootstrap["bootstrap_token"],
            runtime_identity_id=second_bootstrap["runtime_identity_id"],
            idempotency_key="runtime-enroll-postgres-expired",
            server_challenge=second_bootstrap["server_challenge"],
            client_nonce="client-expired",
            timestamp=_runtime_timestamp(),
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
    assert result.after.state is DatabaseSchemaState.VERSION_0011
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
