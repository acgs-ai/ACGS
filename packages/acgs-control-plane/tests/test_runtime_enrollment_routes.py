"""Route-level tests for runtime identity enrollment."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from gove_zone.decision import sha256_json
from gove_zone.policy import RuleSetPolicy
from gove_zone.receipt import safe_result_hash
from gove_zone.runtime_identity import (
    AtomicJsonRuntimeIdentityStore,
    GateScope,
    InMemoryEd25519WorkloadKeyProvider,
    RuntimeEnrollmentClient,
    RuntimeHttpRequest,
    RuntimeHttpResponse,
    public_key_thumbprint,
)
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope

from acgs_control_plane import runtime_enrollment as runtime_enrollment_module
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.managed_mutations import CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import (
    Environment,
    EnvironmentPolicyHead,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    PolicyVersion,
    Project,
    RuntimeCredentialGeneration,
    RuntimeEnrollmentBootstrap,
    RuntimeEnrollmentIdempotency,
    RuntimeIdentity,
    RuntimeOperationIdempotency,
    RuntimeRequestNonce,
    new_id,
    utcnow,
)
from acgs_control_plane.policy_registry import (
    POLICY_ENVELOPE_PURPOSE,
    _signed_envelope,
    local_policy_registry_issuer,
)
from acgs_control_plane.schemas import RuntimeEnrollmentBootstrapCreateResponse
from acgs_control_plane.trust import ManagedTrustLifecycleService, public_spki_der_from_signer


def test_runtime_issue_enroll_renew_revoke_and_bad_pop_zero_delta(
    client: TestClient,
    monkeypatch: Any,
    tmp_path: Path,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])

    audience = "control-plane.runtime-enrollment:v1"
    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-test-key")
    bootstrap = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=key_provider,
    )
    assert bootstrap["audience"] == audience
    assert bootstrap["gate_id"]
    assert bootstrap["_headers"]["cache-control"] == "no-store"
    assert bootstrap["_headers"]["pragma"] == "no-cache"
    identity_id = bootstrap["runtime_identity_id"]
    idempotency_key = f"idem-secret-{new_id()}"
    timestamp = _runtime_timestamp()
    enrollment_requests: list[RuntimeHttpRequest] = []

    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client, captured=enrollment_requests),
        audience=audience,
    )
    scope = GateScope(
        org_id=org["org_id"],
        project_id=project_id,
        environment=environment_id,
        gate_id=bootstrap["gate_id"],
    )
    descriptor = runtime_client.exchange_and_store(
        store=AtomicJsonRuntimeIdentityStore(tmp_path / "runtime-identity.json"),
        issuer_public_key=runtime_descriptor_signer.public_key_bytes(),
        scope=scope,
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=identity_id,
        idempotency_key=idempotency_key,
        server_challenge=bootstrap["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=timestamp,
    )
    assert descriptor.runtime_identity_id == identity_id
    assert descriptor.credential_generation == 1
    _assert_runtime_managed_payloads_do_not_contain(app, org["org_id"], idempotency_key)
    original_enrollment = enrollment_requests[0]
    original_runtime_now = runtime_enrollment_module.utcnow
    before_exact_enrollment_replay_counts = _runtime_mutation_counts(app, org["org_id"])
    monkeypatch.setattr(
        runtime_enrollment_module,
        "utcnow",
        lambda: original_runtime_now() + timedelta(minutes=15),
    )
    exact_enrollment_replay = client.request(
        original_enrollment.method,
        original_enrollment.path,
        content=original_enrollment.body,
        headers=dict(original_enrollment.headers),
    )
    assert exact_enrollment_replay.status_code == 201, exact_enrollment_replay.text
    assert exact_enrollment_replay.json()["identity_id"] == identity_id
    assert exact_enrollment_replay.json()["generation"] == 1
    assert _runtime_mutation_counts(app, org["org_id"]) == before_exact_enrollment_replay_counts
    monkeypatch.setattr(runtime_enrollment_module, "utcnow", original_runtime_now)
    before_bad_replay_counts = _runtime_mutation_counts(app, org["org_id"])
    bad_replay_headers = dict(original_enrollment.headers)
    bad_replay_headers["x-acgs-runtime-pop-signature"] = "invalid-pop-signature"
    bad_replay = client.request(
        original_enrollment.method,
        original_enrollment.path,
        content=original_enrollment.body,
        headers=bad_replay_headers,
    )
    assert bad_replay.status_code == 401, bad_replay.text
    assert bad_replay.json()["code"] == "POP_SIGNATURE_INVALID"
    assert bad_replay.headers["cache-control"] == "no-store"
    assert _runtime_mutation_counts(app, org["org_id"]) == before_bad_replay_counts
    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client),
        audience=audience,
    )

    renew_nonce = f"renew-{new_id()}"
    renew_timestamp = _runtime_timestamp()
    renew_idempotency_key = f"renew-idem-{new_id()}"
    renewed = runtime_client.renew(
        descriptor=descriptor,
        idempotency_key=renew_idempotency_key,
        timestamp=renew_timestamp,
        nonce=renew_nonce,
    )
    assert renewed.status_code == 200, renewed.body.decode()
    renewed_payload = json.loads(renewed.body)
    assert renewed_payload["generation"] == 2

    monkeypatch.setattr(
        runtime_enrollment_module,
        "utcnow",
        lambda: original_runtime_now() + timedelta(minutes=5),
    )
    replay = runtime_client.renew(
        descriptor=descriptor,
        idempotency_key=renew_idempotency_key,
        timestamp=renew_timestamp,
        nonce=renew_nonce,
    )
    assert replay.status_code == 200, replay.body.decode()
    assert json.loads(replay.body) == renewed_payload
    monkeypatch.setattr(runtime_enrollment_module, "utcnow", original_runtime_now)

    second_key = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-second-key")
    second = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=second_key,
    )
    second_identity_id = second["runtime_identity_id"]
    bad_key = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-bad-key")
    bad_client = RuntimeEnrollmentClient(
        key_provider=bad_key,
        transport=_runtime_transport(client=client),
        audience=audience,
    )
    before = _identity_count(app, second_identity_id)
    denied = bad_client.exchange_bootstrap(
        scope=GateScope(
            org_id=org["org_id"],
            project_id=project_id,
            environment=environment_id,
            gate_id=second["gate_id"],
        ),
        bootstrap_id=second["bootstrap_id"],
        bootstrap_token=second["bootstrap_token"],
        runtime_identity_id=second_identity_id,
        idempotency_key=f"idem-{new_id()}",
        server_challenge=second["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=_runtime_timestamp(),
    )
    assert denied.status_code == 401, denied.body.decode()
    assert denied.headers["cache-control"] == "no-store"
    assert denied.headers["pragma"] == "no-cache"
    assert _identity_count(app, second_identity_id) == before

    revoke_idempotency_key = f"revoke-idem-{new_id()}"
    revoke = client.post(
        f"/orgs/{org['org_id']}/projects/{project_id}/environments/{environment_id}"
        f"/runtime-identities/{identity_id}/revoke",
        json={"expected_credential_generation": renewed_payload["generation"]},
        headers={**admin_headers, "Idempotency-Key": revoke_idempotency_key},
    )
    assert revoke.status_code == 200, revoke.text
    assert revoke.json()["identity_id"] == identity_id

    before_retry_counts = _runtime_mutation_counts(app, org["org_id"])
    retry = client.post(
        f"/orgs/{org['org_id']}/projects/{project_id}/environments/{environment_id}"
        f"/runtime-identities/{identity_id}/revoke",
        json={"expected_credential_generation": renewed_payload["generation"]},
        headers={**admin_headers, "Idempotency-Key": revoke_idempotency_key},
    )
    assert retry.status_code == 200, retry.text
    assert retry.json() == revoke.json()
    assert _runtime_mutation_counts(app, org["org_id"]) == before_retry_counts


def test_runtime_enrollment_replay_after_renew_and_revoke_is_historic_terminal(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-historic-enroll-key")
    bootstrap = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=key_provider,
    )
    captured: list[RuntimeHttpRequest] = []
    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client, captured=captured),
        audience="control-plane.runtime-enrollment:v1",
    )
    scope = GateScope(
        org_id=org["org_id"],
        project_id=project_id,
        environment=environment_id,
        gate_id=bootstrap["gate_id"],
    )
    enrollment = runtime_client.exchange_bootstrap(
        scope=scope,
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=bootstrap["runtime_identity_id"],
        idempotency_key=f"idem-secret-{new_id()}",
        server_challenge=bootstrap["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=_runtime_timestamp(),
    )
    assert enrollment.status_code == 201, enrollment.body.decode()
    enrollment_payload = json.loads(enrollment.body)
    descriptor = runtime_client.accept_enrollment_response(
        enrollment,
        issuer_public_key=runtime_descriptor_signer.public_key_bytes(),
        expected_scope=scope,
        expected_runtime_identity_id=bootstrap["runtime_identity_id"],
    )
    original_enrollment_request = captured[0]
    renew = runtime_client.renew(
        descriptor=descriptor,
        idempotency_key=f"renew-idem-{new_id()}",
        timestamp=_runtime_timestamp(),
        nonce=f"renew-{new_id()}",
    )
    assert renew.status_code == 200, renew.body.decode()
    revoke = client.post(
        f"/orgs/{org['org_id']}/projects/{project_id}/environments/{environment_id}"
        f"/runtime-identities/{bootstrap['runtime_identity_id']}/revoke",
        json={"expected_credential_generation": 2},
        headers={**admin_headers, "Idempotency-Key": f"revoke-idem-{new_id()}"},
    )
    assert revoke.status_code == 200, revoke.text
    before_replay_counts = _runtime_replay_counts(app, org["org_id"])

    replay = client.request(
        original_enrollment_request.method,
        original_enrollment_request.path,
        content=original_enrollment_request.body,
        headers=dict(original_enrollment_request.headers),
    )

    assert replay.status_code == 201, replay.text
    assert replay.json() == enrollment_payload
    assert _runtime_replay_counts(app, org["org_id"]) == before_replay_counts
    _assert_identity_and_credentials(
        app,
        identity_id=bootstrap["runtime_identity_id"],
        expected_identity_status="revoked",
        expected_current_generation=2,
        expected_credential_statuses={1: "superseded", 2: "revoked"},
    )


def test_runtime_enrollment_forced_outer_miss_replays_under_uow_lock_without_new_attempt(
    client: TestClient,
    monkeypatch: Any,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-forced-miss-key")
    bootstrap = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=key_provider,
    )
    captured: list[RuntimeHttpRequest] = []
    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client, captured=captured),
        audience="control-plane.runtime-enrollment:v1",
    )
    scope = GateScope(
        org_id=org["org_id"],
        project_id=project_id,
        environment=environment_id,
        gate_id=bootstrap["gate_id"],
    )
    enrollment = runtime_client.exchange_bootstrap(
        scope=scope,
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=bootstrap["runtime_identity_id"],
        idempotency_key=f"idem-secret-{new_id()}",
        server_challenge=bootstrap["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=_runtime_timestamp(),
    )
    assert enrollment.status_code == 201, enrollment.body.decode()
    enrollment_payload = json.loads(enrollment.body)
    runtime_client.accept_enrollment_response(
        enrollment,
        issuer_public_key=runtime_descriptor_signer.public_key_bytes(),
        expected_scope=scope,
        expected_runtime_identity_id=bootstrap["runtime_identity_id"],
    )
    before_replay_counts = _runtime_replay_counts(app, org["org_id"])
    before_attempts = _runtime_attempt_count(app, org["org_id"])
    original_lookup = runtime_enrollment_module._lookup_enrollment_idempotency
    observed_locks: list[bool] = []

    def forced_outer_miss(*args: Any, **kwargs: Any) -> Any:
        lock = bool(kwargs["lock"])
        observed_locks.append(lock)
        if not lock:
            return None
        return original_lookup(*args, **kwargs)

    monkeypatch.setattr(
        runtime_enrollment_module,
        "_lookup_enrollment_idempotency",
        forced_outer_miss,
    )
    original_enrollment_request = captured[0]

    replay = client.request(
        original_enrollment_request.method,
        original_enrollment_request.path,
        content=original_enrollment_request.body,
        headers=dict(original_enrollment_request.headers),
    )

    assert replay.status_code == 201, replay.text
    assert replay.json() == enrollment_payload
    assert observed_locks == [False, True]
    assert _runtime_replay_counts(app, org["org_id"]) == before_replay_counts
    assert _runtime_attempt_count(app, org["org_id"]) == before_attempts


def test_runtime_renew_and_revoke_forced_outer_miss_replay_under_uow_lock_zero_delta(
    client: TestClient,
    monkeypatch: Any,
    tmp_path: Path,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-operation-forced-miss-key")
    bootstrap = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=key_provider,
    )
    captured: list[RuntimeHttpRequest] = []
    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client, captured=captured),
        audience="control-plane.runtime-enrollment:v1",
    )
    descriptor = runtime_client.exchange_and_store(
        store=AtomicJsonRuntimeIdentityStore(tmp_path / "runtime-forced-operation.json"),
        issuer_public_key=runtime_descriptor_signer.public_key_bytes(),
        scope=GateScope(
            org_id=org["org_id"],
            project_id=project_id,
            environment=environment_id,
            gate_id=bootstrap["gate_id"],
        ),
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=bootstrap["runtime_identity_id"],
        idempotency_key=f"idem-secret-{new_id()}",
        server_challenge=bootstrap["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=_runtime_timestamp(),
    )
    renew_idempotency_key = f"renew-idem-{new_id()}"
    renew = runtime_client.renew(
        descriptor=descriptor,
        idempotency_key=renew_idempotency_key,
        timestamp=_runtime_timestamp(),
        nonce=f"renew-{new_id()}",
    )
    assert renew.status_code == 200, renew.body.decode()
    renew_payload = json.loads(renew.body)
    original_renew_request = captured[1]
    original_operation_lookup = runtime_enrollment_module._lookup_runtime_operation_idempotency
    observed_renew_locks: list[bool] = []

    def forced_operation_outer_miss(*args: Any, **kwargs: Any) -> Any:
        lock = bool(kwargs["lock"])
        observed_renew_locks.append(lock)
        if not lock:
            return None
        return original_operation_lookup(*args, **kwargs)

    def forced_authenticate(
        self: Any,
        *,
        identity_id: str,
        body: Any,
        **_kwargs: Any,
    ) -> Any:
        with self._session_factory() as session:
            identity = session.get(RuntimeIdentity, identity_id)
            credential = session.get(RuntimeCredentialGeneration, body.credential_id)
            assert identity is not None
            assert credential is not None
            return (
                runtime_enrollment_module._detach_identity(identity),
                runtime_enrollment_module._detach_credential(credential),
            )

    monkeypatch.setattr(
        runtime_enrollment_module,
        "_lookup_runtime_operation_idempotency",
        forced_operation_outer_miss,
    )
    monkeypatch.setattr(
        runtime_enrollment_module.RuntimeEnrollmentService,
        "_authenticate_signed_runtime_request",
        forced_authenticate,
    )
    before_renew_counts = _runtime_replay_counts(app, org["org_id"])
    before_renew_attempts = _runtime_attempt_count(app, org["org_id"])
    renew_replay = client.request(
        original_renew_request.method,
        original_renew_request.path,
        content=original_renew_request.body,
        headers=dict(original_renew_request.headers),
    )
    assert renew_replay.status_code == 200, renew_replay.text
    assert renew_replay.json() == renew_payload
    assert observed_renew_locks == [False, True]
    assert _runtime_replay_counts(app, org["org_id"]) == before_renew_counts
    assert _runtime_attempt_count(app, org["org_id"]) == before_renew_attempts

    monkeypatch.setattr(
        runtime_enrollment_module,
        "_lookup_runtime_operation_idempotency",
        original_operation_lookup,
    )
    revoke_idempotency_key = f"revoke-idem-{new_id()}"
    revoke_url = (
        f"/orgs/{org['org_id']}/projects/{project_id}/environments/{environment_id}"
        f"/runtime-identities/{descriptor.runtime_identity_id}/revoke"
    )
    revoke = client.post(
        revoke_url,
        json={"expected_credential_generation": renew_payload["generation"]},
        headers={**admin_headers, "Idempotency-Key": revoke_idempotency_key},
    )
    assert revoke.status_code == 200, revoke.text
    revoke_payload = revoke.json()
    observed_revoke_locks: list[bool] = []

    def forced_revoke_outer_miss(*args: Any, **kwargs: Any) -> Any:
        lock = bool(kwargs["lock"])
        observed_revoke_locks.append(lock)
        if not lock:
            return None
        return original_operation_lookup(*args, **kwargs)

    monkeypatch.setattr(
        runtime_enrollment_module,
        "_lookup_runtime_operation_idempotency",
        forced_revoke_outer_miss,
    )
    before_revoke_counts = _runtime_replay_counts(app, org["org_id"])
    before_revoke_attempts = _runtime_attempt_count(app, org["org_id"])
    revoke_replay = client.post(
        revoke_url,
        json={"expected_credential_generation": renew_payload["generation"]},
        headers={**admin_headers, "Idempotency-Key": revoke_idempotency_key},
    )
    assert revoke_replay.status_code == 200, revoke_replay.text
    assert revoke_replay.json() == revoke_payload
    assert observed_revoke_locks == [False, False, True]
    assert _runtime_replay_counts(app, org["org_id"]) == before_revoke_counts
    assert _runtime_attempt_count(app, org["org_id"]) == before_revoke_attempts


def test_runtime_renew_replay_after_descriptor_expiry_is_historic_terminal(
    client: TestClient,
    monkeypatch: Any,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-historic-renew-key")
    bootstrap = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=key_provider,
    )
    captured: list[RuntimeHttpRequest] = []
    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client, captured=captured),
        audience="control-plane.runtime-enrollment:v1",
    )
    scope = GateScope(
        org_id=org["org_id"],
        project_id=project_id,
        environment=environment_id,
        gate_id=bootstrap["gate_id"],
    )
    enrollment = runtime_client.exchange_bootstrap(
        scope=scope,
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=bootstrap["runtime_identity_id"],
        idempotency_key=f"idem-secret-{new_id()}",
        server_challenge=bootstrap["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=_runtime_timestamp(),
    )
    assert enrollment.status_code == 201, enrollment.body.decode()
    descriptor = runtime_client.accept_enrollment_response(
        enrollment,
        issuer_public_key=runtime_descriptor_signer.public_key_bytes(),
        expected_scope=scope,
        expected_runtime_identity_id=bootstrap["runtime_identity_id"],
    )
    renew = runtime_client.renew(
        descriptor=descriptor,
        idempotency_key=f"renew-idem-{new_id()}",
        timestamp=_runtime_timestamp(),
        nonce=f"renew-{new_id()}",
    )
    assert renew.status_code == 200, renew.body.decode()
    renew_payload = json.loads(renew.body)
    original_renew_request = captured[-1]
    before_replay_counts = _runtime_replay_counts(app, org["org_id"])
    original_runtime_now = runtime_enrollment_module.utcnow
    monkeypatch.setattr(
        runtime_enrollment_module,
        "utcnow",
        lambda: original_runtime_now() + timedelta(days=2),
    )

    replay = client.request(
        original_renew_request.method,
        original_renew_request.path,
        content=original_renew_request.body,
        headers=dict(original_renew_request.headers),
    )

    assert replay.status_code == 200, replay.text
    assert replay.json() == renew_payload
    assert _runtime_replay_counts(app, org["org_id"]) == before_replay_counts
    _assert_identity_and_credentials(
        app,
        identity_id=bootstrap["runtime_identity_id"],
        expected_identity_status="active",
        expected_current_generation=2,
        expected_credential_statuses={1: "superseded", 2: "active"},
    )


def test_runtime_revoke_requires_org_admin_and_has_no_rbac_side_effect(
    client: TestClient,
    tmp_path: Path,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    make_user: Any,
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-rbac-key")
    bootstrap = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=key_provider,
    )
    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client),
        audience="control-plane.runtime-enrollment:v1",
    )
    descriptor = runtime_client.exchange_and_store(
        store=AtomicJsonRuntimeIdentityStore(tmp_path / "runtime-rbac-identity.json"),
        issuer_public_key=runtime_descriptor_signer.public_key_bytes(),
        scope=GateScope(
            org_id=org["org_id"],
            project_id=project_id,
            environment=environment_id,
            gate_id=bootstrap["gate_id"],
        ),
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=bootstrap["runtime_identity_id"],
        idempotency_key=f"idem-secret-{new_id()}",
        server_challenge=bootstrap["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=_runtime_timestamp(),
    )
    before_counts = _runtime_mutation_counts(app, org["org_id"])
    revoke_url = (
        f"/orgs/{org['org_id']}/projects/{project_id}/environments/{environment_id}"
        f"/runtime-identities/{descriptor.runtime_identity_id}/revoke"
    )

    for role in ("agent_operator", "viewer"):
        denied = client.post(
            revoke_url,
            json={"expected_credential_generation": descriptor.credential_generation},
            headers={**make_user(role), "Idempotency-Key": f"revoke-{role}-{new_id()}"},
        )
        assert denied.status_code == 403, denied.text
        assert _runtime_mutation_counts(app, org["org_id"]) == before_counts
        with app.state.session_factory() as session:
            identity = session.get(RuntimeIdentity, descriptor.runtime_identity_id)
            assert identity is not None
            assert identity.status == "active"


def test_runtime_bootstrap_response_repr_redacts_secret_fields() -> None:
    payload = RuntimeEnrollmentBootstrapCreateResponse(
        bootstrap_id="bootstrap-test",
        org_id="org-test",
        project_id="project-test",
        environment_id="environment-test",
        gate_id="gate-test",
        runtime_identity_id="runtime-test",
        audience="control-plane.runtime-enrollment:v1",
        workload_key_id="runtime-key",
        public_key_thumbprint="a" * 64,
        bootstrap_token="acgs_gbt_locator.SECRET",
        server_challenge="challenge-SECRET",
        expires_at=utcnow(),
        receipt_id="receipt-test",
    )

    rendered = repr(payload)
    assert "acgs_gbt_locator.SECRET" not in rendered
    assert "challenge-SECRET" not in rendered
    assert payload.model_dump()["bootstrap_token"] == "acgs_gbt_locator.SECRET"
    assert payload.model_dump()["server_challenge"] == "challenge-SECRET"


def test_runtime_bootstrap_active_retry_is_not_replayable_and_has_no_side_effect(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    first_key = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-active-key")
    _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=first_key,
    )
    before_counts = _runtime_mutation_counts(app, org["org_id"])
    second_key = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-active-retry-key")
    response = client.post(
        f"/orgs/{org['org_id']}/projects/{project_id}/environments/{environment_id}"
        "/runtime-enrollment-bootstraps",
        json={
            "ttl_seconds": 600,
            "workload_key_id": second_key.key_id,
            "public_key_thumbprint": public_key_thumbprint(second_key.public_key_bytes()),
        },
        headers=admin_headers,
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "BOOTSTRAP_TOKEN_NOT_REPLAYABLE"
    assert response.headers["cache-control"] == "no-store"
    assert _runtime_mutation_counts(app, org["org_id"]) == before_counts


def test_runtime_bootstrap_expiry_uses_in_uow_clock_after_locks(
    client: TestClient,
    monkeypatch: Any,
    org: dict[str, Any],
    admin_headers: dict[str, str],
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    base = utcnow()
    in_uow_now = base + timedelta(seconds=2)
    clock_values = iter((base, in_uow_now))

    def advancing_clock() -> Any:
        return next(clock_values, in_uow_now)

    monkeypatch.setattr(runtime_enrollment_module, "utcnow", advancing_clock)
    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-fresh-expiry-key")
    response = client.post(
        f"/orgs/{org['org_id']}/projects/{project_id}/environments/{environment_id}"
        "/runtime-enrollment-bootstraps",
        json={
            "ttl_seconds": 1,
            "workload_key_id": key_provider.key_id,
            "public_key_thumbprint": public_key_thumbprint(key_provider.public_key_bytes()),
        },
        headers=admin_headers,
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    response_expires_at = runtime_enrollment_module._parse_runtime_timestamp(payload["expires_at"])
    assert response_expires_at > in_uow_now

    with app.state.session_factory() as session:
        row = session.get(RuntimeEnrollmentBootstrap, payload["bootstrap_id"])
        assert row is not None
        assert row.status == "active"
        assert runtime_enrollment_module._to_utc(row.expires_at) == response_expires_at
        invalid_active_count = session.scalar(
            sa.select(sa.func.count())
            .select_from(RuntimeEnrollmentBootstrap)
            .where(
                RuntimeEnrollmentBootstrap.org_id == org["org_id"],
                RuntimeEnrollmentBootstrap.project_id == project_id,
                RuntimeEnrollmentBootstrap.environment_id == environment_id,
                RuntimeEnrollmentBootstrap.status == "active",
                RuntimeEnrollmentBootstrap.expires_at <= in_uow_now,
            )
        )
    assert invalid_active_count == 0


def test_denied_runtime_enrollment_replays_terminal_refusal_without_duplicate_evidence(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(
        app,
        org["org_id"],
        rules=[
            {
                "id": "deny-runtime-enroll",
                "effect": "deny",
                "tools": [CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION],
            }
        ],
    )

    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-denied-key")
    bootstrap = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=key_provider,
    )
    captured: list[RuntimeHttpRequest] = []
    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client, captured=captured),
        audience="control-plane.runtime-enrollment:v1",
    )
    first = runtime_client.exchange_bootstrap(
        scope=GateScope(
            org_id=org["org_id"],
            project_id=project_id,
            environment=environment_id,
            gate_id=bootstrap["gate_id"],
        ),
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=bootstrap["runtime_identity_id"],
        idempotency_key=f"idem-secret-{new_id()}",
        server_challenge=bootstrap["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=_runtime_timestamp(),
    )
    assert first.status_code == 403, first.body.decode()
    first_payload = json.loads(first.body)
    assert first_payload["decision"] == "DENY"
    assert _identity_count(app, bootstrap["runtime_identity_id"]) == 0

    before_retry_counts = _runtime_mutation_counts(app, org["org_id"])
    original = captured[0]
    replay = client.request(
        original.method,
        original.path,
        content=original.body,
        headers=dict(original.headers),
    )
    assert replay.status_code == 403, replay.text
    assert replay.json()["decision"] == "DENY"
    assert replay.json()["receipt_id"] == first_payload["receipt_id"]
    assert _runtime_mutation_counts(app, org["org_id"]) == before_retry_counts
    assert _identity_count(app, bootstrap["runtime_identity_id"]) == 0

    with app.state.session_factory.begin() as session:
        row = session.scalars(
            sa.select(RuntimeOperationIdempotency).where(
                RuntimeOperationIdempotency.org_id == org["org_id"],
                RuntimeOperationIdempotency.project_id == project_id,
                RuntimeOperationIdempotency.environment_id == environment_id,
                RuntimeOperationIdempotency.identity_id == bootstrap["runtime_identity_id"],
                RuntimeOperationIdempotency.operation == "enroll",
            )
        ).one()
        response = dict(row.response)
        response["receipt_id"] = "ev_tampered"
        row.response = response

    tampered_replay = client.request(
        original.method,
        original.path,
        content=original.body,
        headers=dict(original.headers),
    )
    assert tampered_replay.status_code == 503, tampered_replay.text
    assert tampered_replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"
    assert _runtime_mutation_counts(app, org["org_id"]) == before_retry_counts
    assert _identity_count(app, bootstrap["runtime_identity_id"]) == 0


def test_escalated_runtime_enrollment_replays_terminal_refusal_without_duplicate_evidence(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(
        app,
        org["org_id"],
        rules=[
            {
                "id": "escalate-runtime-enroll",
                "effect": "escalate",
                "tools": [CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION],
            }
        ],
    )

    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-escalated-key")
    bootstrap = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=key_provider,
    )
    captured: list[RuntimeHttpRequest] = []
    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client, captured=captured),
        audience="control-plane.runtime-enrollment:v1",
    )
    first = runtime_client.exchange_bootstrap(
        scope=GateScope(
            org_id=org["org_id"],
            project_id=project_id,
            environment=environment_id,
            gate_id=bootstrap["gate_id"],
        ),
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=bootstrap["runtime_identity_id"],
        idempotency_key=f"idem-secret-{new_id()}",
        server_challenge=bootstrap["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=_runtime_timestamp(),
    )
    assert first.status_code == 202, first.body.decode()
    first_payload = json.loads(first.body)
    assert first_payload["decision"] == "ESCALATE"
    assert _identity_count(app, bootstrap["runtime_identity_id"]) == 0

    before_retry_counts = _runtime_mutation_counts(app, org["org_id"])
    original = captured[0]
    replay = client.request(
        original.method,
        original.path,
        content=original.body,
        headers=dict(original.headers),
    )
    assert replay.status_code == 202, replay.text
    assert replay.json()["decision"] == "ESCALATE"
    assert replay.json()["receipt_id"] == first_payload["receipt_id"]
    assert _runtime_mutation_counts(app, org["org_id"]) == before_retry_counts
    assert _identity_count(app, bootstrap["runtime_identity_id"]) == 0

    with app.state.session_factory.begin() as session:
        row = session.scalars(
            sa.select(RuntimeOperationIdempotency).where(
                RuntimeOperationIdempotency.org_id == org["org_id"],
                RuntimeOperationIdempotency.project_id == project_id,
                RuntimeOperationIdempotency.environment_id == environment_id,
                RuntimeOperationIdempotency.identity_id == bootstrap["runtime_identity_id"],
                RuntimeOperationIdempotency.operation == "enroll",
            )
        ).one()
        response = dict(row.response)
        response["reason"] = "agent supplied refusal reason"
        row.response = response

    tampered_replay = client.request(
        original.method,
        original.path,
        content=original.body,
        headers=dict(original.headers),
    )
    assert tampered_replay.status_code == 503, tampered_replay.text
    assert tampered_replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"
    assert _runtime_mutation_counts(app, org["org_id"]) == before_retry_counts
    assert _identity_count(app, bootstrap["runtime_identity_id"]) == 0


def test_runtime_enrollment_replay_uses_canonical_credential_descriptor(
    client: TestClient,
    tmp_path: Path,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-tamper-key")
    bootstrap = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=key_provider,
    )
    captured: list[RuntimeHttpRequest] = []
    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client, captured=captured),
        audience="control-plane.runtime-enrollment:v1",
    )
    runtime_client.exchange_and_store(
        store=AtomicJsonRuntimeIdentityStore(tmp_path / "runtime-identity.json"),
        issuer_public_key=runtime_descriptor_signer.public_key_bytes(),
        scope=GateScope(
            org_id=org["org_id"],
            project_id=project_id,
            environment=environment_id,
            gate_id=bootstrap["gate_id"],
        ),
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=bootstrap["runtime_identity_id"],
        idempotency_key=f"idem-secret-{new_id()}",
        server_challenge=bootstrap["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=_runtime_timestamp(),
    )
    with app.state.session_factory.begin() as session:
        row = session.scalars(
            sa.select(RuntimeEnrollmentIdempotency).where(
                RuntimeEnrollmentIdempotency.org_id == org["org_id"],
                RuntimeEnrollmentIdempotency.project_id == project_id,
                RuntimeEnrollmentIdempotency.environment_id == environment_id,
                RuntimeEnrollmentIdempotency.identity_id == bootstrap["runtime_identity_id"],
            )
        ).one()
        expected_payload = dict(row.response)
        identity = session.get(RuntimeIdentity, bootstrap["runtime_identity_id"])
        assert identity is not None
        descriptor = dict(identity.descriptor)
        signature = str(descriptor["signature"])
        descriptor["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
        identity.descriptor = descriptor

    before_counts = _runtime_mutation_counts(app, org["org_id"])
    original = captured[0]
    replay = client.request(
        original.method,
        original.path,
        content=original.body,
        headers=dict(original.headers),
    )
    assert replay.status_code == 201, replay.text
    expected_payload.pop("_terminal_response_seal")
    assert replay.json() == expected_payload
    assert _runtime_mutation_counts(app, org["org_id"]) == before_counts


@pytest.mark.parametrize("tamper", ["delete", "ciphertext", "aad"])
def test_runtime_enrollment_replay_rejects_terminal_response_seal_tamper(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
    tamper: str,
) -> None:
    app = cast(Any, client.app)
    original, payload = _successful_enrollment_for_replay(
        client,
        org=org,
        admin_headers=admin_headers,
        runtime_descriptor_signer=runtime_descriptor_signer,
        key_id=f"runtime-seal-{tamper}-key",
    )
    with app.state.session_factory.begin() as session:
        row = session.scalars(
            sa.select(RuntimeEnrollmentIdempotency).where(
                RuntimeEnrollmentIdempotency.org_id == org["org_id"],
                RuntimeEnrollmentIdempotency.identity_id == payload["identity_id"],
            )
        ).one()
        response = dict(row.response)
        if tamper == "delete":
            response.pop("_terminal_response_seal")
        elif tamper == "ciphertext":
            seal = dict(response["_terminal_response_seal"])
            ciphertext = str(seal["ciphertext"])
            seal["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
            response["_terminal_response_seal"] = seal
        else:
            receipt = session.scalars(
                sa.select(ManagedDecisionReceipt).where(
                    ManagedDecisionReceipt.org_id == row.org_id,
                    ManagedDecisionReceipt.receipt_id == row.receipt_id,
                )
            ).one()
            terminal_payload = dict(response)
            terminal_payload.pop("_terminal_response_seal")
            response = runtime_enrollment_module._sealed_terminal_response_payload(
                terminal_payload,
                receipt_sealer=app.state.runtime_enrollment_service._providers.receipt_sealer,
                org_id=row.org_id,
                project_id=row.project_id,
                environment_id=row.environment_id,
                identity_id=row.identity_id,
                action=CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION,
                operation="enroll",
                request_hash=f"wrong-{row.request_hash}",
                idempotency_key_hash=row.idempotency_key_hash,
                receipt_id=row.receipt_id,
                receipt_hash=receipt.receipt_hash,
            )
        row.response = response

    before_counts = _runtime_mutation_counts(app, org["org_id"])
    replay = client.request(
        original.method,
        original.path,
        content=original.body,
        headers=dict(original.headers),
    )
    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"
    assert _runtime_mutation_counts(app, org["org_id"]) == before_counts


def test_runtime_enrollment_replay_rejects_terminal_receipt_swap(
    client: TestClient,
    tmp_path: Path,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-receipt-swap-key")
    bootstrap = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=key_provider,
    )
    captured: list[RuntimeHttpRequest] = []
    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client, captured=captured),
        audience="control-plane.runtime-enrollment:v1",
    )
    runtime_client.exchange_and_store(
        store=AtomicJsonRuntimeIdentityStore(tmp_path / "runtime-identity.json"),
        issuer_public_key=runtime_descriptor_signer.public_key_bytes(),
        scope=GateScope(
            org_id=org["org_id"],
            project_id=project_id,
            environment=environment_id,
            gate_id=bootstrap["gate_id"],
        ),
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=bootstrap["runtime_identity_id"],
        idempotency_key=f"idem-secret-{new_id()}",
        server_challenge=bootstrap["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=_runtime_timestamp(),
    )
    with app.state.session_factory.begin() as session:
        row = session.scalars(
            sa.select(RuntimeEnrollmentIdempotency).where(
                RuntimeEnrollmentIdempotency.org_id == org["org_id"],
                RuntimeEnrollmentIdempotency.project_id == project_id,
                RuntimeEnrollmentIdempotency.environment_id == environment_id,
                RuntimeEnrollmentIdempotency.identity_id == bootstrap["runtime_identity_id"],
            )
        ).one()
        other_receipt = session.scalars(
            sa.select(ManagedDecisionReceipt)
            .where(
                ManagedDecisionReceipt.org_id == org["org_id"],
                ManagedDecisionReceipt.project_id == project_id,
                ManagedDecisionReceipt.environment_id == environment_id,
                ManagedDecisionReceipt.receipt_id != row.receipt_id,
            )
            .order_by(ManagedDecisionReceipt.created_at)
        ).first()
        assert other_receipt is not None
        response = dict(row.response)
        response["receipt_id"] = other_receipt.receipt_id
        row.receipt_id = other_receipt.receipt_id
        row.response = response

    before_counts = _runtime_mutation_counts(app, org["org_id"])
    original = captured[0]
    replay = client.request(
        original.method,
        original.path,
        content=original.body,
        headers=dict(original.headers),
    )
    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"
    assert _runtime_mutation_counts(app, org["org_id"]) == before_counts


def test_runtime_enrollment_replay_rejects_valid_response_substitution_by_event_hash(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-valid-substitution-key")
    bootstrap = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=key_provider,
    )
    captured: list[RuntimeHttpRequest] = []
    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client, captured=captured),
        audience="control-plane.runtime-enrollment:v1",
    )
    scope = GateScope(
        org_id=org["org_id"],
        project_id=project_id,
        environment=environment_id,
        gate_id=bootstrap["gate_id"],
    )
    enrollment = runtime_client.exchange_bootstrap(
        scope=scope,
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=bootstrap["runtime_identity_id"],
        idempotency_key=f"idem-secret-{new_id()}",
        server_challenge=bootstrap["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=_runtime_timestamp(),
    )
    assert enrollment.status_code == 201, enrollment.body.decode()
    descriptor = runtime_client.accept_enrollment_response(
        enrollment,
        issuer_public_key=runtime_descriptor_signer.public_key_bytes(),
        expected_scope=scope,
        expected_runtime_identity_id=bootstrap["runtime_identity_id"],
    )
    renew = runtime_client.renew(
        descriptor=descriptor,
        idempotency_key=f"renew-idem-{new_id()}",
        timestamp=_runtime_timestamp(),
        nonce=f"renew-{new_id()}",
    )
    assert renew.status_code == 200, renew.body.decode()
    renew_payload = json.loads(renew.body)

    with app.state.session_factory.begin() as session:
        row = session.scalars(
            sa.select(RuntimeEnrollmentIdempotency).where(
                RuntimeEnrollmentIdempotency.org_id == org["org_id"],
                RuntimeEnrollmentIdempotency.project_id == project_id,
                RuntimeEnrollmentIdempotency.environment_id == environment_id,
                RuntimeEnrollmentIdempotency.identity_id == bootstrap["runtime_identity_id"],
            )
        ).one()
        substituted = dict(renew_payload)
        substituted["receipt_id"] = row.receipt_id
        row.response = substituted

    before_counts = _runtime_mutation_counts(app, org["org_id"])
    original = captured[0]
    replay = client.request(
        original.method,
        original.path,
        content=original.body,
        headers=dict(original.headers),
    )
    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"
    assert _runtime_mutation_counts(app, org["org_id"]) == before_counts


def test_runtime_replay_rejects_managed_event_result_hash_tamper(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-event-tamper-key")
    bootstrap = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=key_provider,
    )
    captured: list[RuntimeHttpRequest] = []
    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client, captured=captured),
        audience="control-plane.runtime-enrollment:v1",
    )
    scope = GateScope(
        org_id=org["org_id"],
        project_id=project_id,
        environment=environment_id,
        gate_id=bootstrap["gate_id"],
    )
    enrollment = runtime_client.exchange_bootstrap(
        scope=scope,
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=bootstrap["runtime_identity_id"],
        idempotency_key=f"idem-secret-{new_id()}",
        server_challenge=bootstrap["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=_runtime_timestamp(),
    )
    assert enrollment.status_code == 201, enrollment.body.decode()
    enrollment_payload = json.loads(enrollment.body)
    descriptor = runtime_client.accept_enrollment_response(
        enrollment,
        issuer_public_key=runtime_descriptor_signer.public_key_bytes(),
        expected_scope=scope,
        expected_runtime_identity_id=bootstrap["runtime_identity_id"],
    )
    renew = runtime_client.renew(
        descriptor=descriptor,
        idempotency_key=f"renew-idem-{new_id()}",
        timestamp=_runtime_timestamp(),
        nonce=f"renew-{new_id()}",
    )
    assert renew.status_code == 200, renew.body.decode()
    renew_payload = json.loads(renew.body)

    _tamper_event_result_hash_for_receipt(app, org["org_id"], enrollment_payload["receipt_id"])
    before_enroll_counts = _runtime_mutation_counts(app, org["org_id"])
    original_enrollment = captured[0]
    enrollment_replay = client.request(
        original_enrollment.method,
        original_enrollment.path,
        content=original_enrollment.body,
        headers=dict(original_enrollment.headers),
    )
    assert enrollment_replay.status_code == 503, enrollment_replay.text
    assert enrollment_replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"
    assert _runtime_mutation_counts(app, org["org_id"]) == before_enroll_counts

    _tamper_event_result_hash_for_receipt(app, org["org_id"], renew_payload["receipt_id"])
    before_renew_counts = _runtime_mutation_counts(app, org["org_id"])
    original_renew = captured[1]
    renew_replay = client.request(
        original_renew.method,
        original_renew.path,
        content=original_renew.body,
        headers=dict(original_renew.headers),
    )
    assert renew_replay.status_code == 503, renew_replay.text
    assert renew_replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"
    assert _runtime_mutation_counts(app, org["org_id"]) == before_renew_counts


def test_runtime_replay_rejects_correlated_response_and_event_payload_tamper(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    original, payload = _successful_enrollment_for_replay(
        client,
        org=org,
        admin_headers=admin_headers,
        runtime_descriptor_signer=runtime_descriptor_signer,
        key_id="runtime-correlated-tamper-key",
    )
    with app.state.session_factory.begin() as session:
        row = session.scalars(
            sa.select(RuntimeEnrollmentIdempotency).where(
                RuntimeEnrollmentIdempotency.org_id == org["org_id"],
                RuntimeEnrollmentIdempotency.identity_id == payload["identity_id"],
            )
        ).one()
        response = dict(row.response)
        response["generation"] = 2
        row.response = response
        receipt = session.scalars(
            sa.select(ManagedDecisionReceipt).where(
                ManagedDecisionReceipt.org_id == org["org_id"],
                ManagedDecisionReceipt.receipt_id == row.receipt_id,
            )
        ).one()
        event = session.scalars(
            sa.select(ManagedGovernanceEvent).where(
                ManagedGovernanceEvent.org_id == org["org_id"],
                ManagedGovernanceEvent.managed_receipt_id == receipt.id,
            )
        ).one()
        event_payload = dict(event.payload)
        event_payload["result_hash"] = safe_result_hash(
            {"identity_id": payload["identity_id"], "generation": 2}
        )
        event.payload = event_payload
        event.payload_digest = sha256_json(event_payload)

    before_counts = _runtime_mutation_counts(app, org["org_id"])
    replay = client.request(
        original.method,
        original.path,
        content=original.body,
        headers=dict(original.headers),
    )
    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"
    assert _runtime_mutation_counts(app, org["org_id"]) == before_counts


def test_runtime_replay_rejects_partial_successor_chain_rewrite(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-partial-chain-key")
    bootstrap = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=key_provider,
    )
    captured: list[RuntimeHttpRequest] = []
    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client, captured=captured),
        audience="control-plane.runtime-enrollment:v1",
    )
    scope = GateScope(
        org_id=org["org_id"],
        project_id=project_id,
        environment=environment_id,
        gate_id=bootstrap["gate_id"],
    )
    enrollment = runtime_client.exchange_bootstrap(
        scope=scope,
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=bootstrap["runtime_identity_id"],
        idempotency_key=f"idem-secret-{new_id()}",
        server_challenge=bootstrap["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=_runtime_timestamp(),
    )
    assert enrollment.status_code == 201, enrollment.body.decode()
    enrollment_payload = json.loads(enrollment.body)
    descriptor = runtime_client.accept_enrollment_response(
        enrollment,
        issuer_public_key=runtime_descriptor_signer.public_key_bytes(),
        expected_scope=scope,
        expected_runtime_identity_id=bootstrap["runtime_identity_id"],
    )
    renew = runtime_client.renew(
        descriptor=descriptor,
        idempotency_key=f"renew-idem-{new_id()}",
        timestamp=_runtime_timestamp(),
        nonce=f"renew-{new_id()}",
    )
    assert renew.status_code == 200, renew.body.decode()
    renew_payload = json.loads(renew.body)

    with app.state.session_factory.begin() as session:
        row = session.scalars(
            sa.select(RuntimeEnrollmentIdempotency).where(
                RuntimeEnrollmentIdempotency.org_id == org["org_id"],
                RuntimeEnrollmentIdempotency.identity_id == enrollment_payload["identity_id"],
            )
        ).one()
        target_receipt = session.scalars(
            sa.select(ManagedDecisionReceipt).where(
                ManagedDecisionReceipt.org_id == org["org_id"],
                ManagedDecisionReceipt.receipt_id == enrollment_payload["receipt_id"],
            )
        ).one()
        target_event = session.scalars(
            sa.select(ManagedGovernanceEvent).where(
                ManagedGovernanceEvent.org_id == org["org_id"],
                ManagedGovernanceEvent.managed_receipt_id == target_receipt.id,
            )
        ).one()
        successor = session.scalars(
            sa.select(ManagedGovernanceEvent).where(
                ManagedGovernanceEvent.org_id == org["org_id"],
                ManagedGovernanceEvent.sequence == target_event.sequence + 1,
            )
        ).one()
        terminal_payload = dict(renew_payload)
        terminal_payload["receipt_id"] = target_receipt.receipt_id
        row.response = runtime_enrollment_module._sealed_terminal_response_payload(
            terminal_payload,
            receipt_sealer=app.state.runtime_enrollment_service._providers.receipt_sealer,
            org_id=row.org_id,
            project_id=row.project_id,
            environment_id=row.environment_id,
            identity_id=row.identity_id,
            action=CONTROL_PLANE_RUNTIME_IDENTITY_ENROLL_ACTION,
            operation="enroll",
            request_hash=row.request_hash,
            idempotency_key_hash=row.idempotency_key_hash,
            receipt_id=row.receipt_id,
            receipt_hash=target_receipt.receipt_hash,
        )
        target_payload = dict(target_event.payload)
        target_payload["result_hash"] = safe_result_hash(
            {"identity_id": enrollment_payload["identity_id"], "generation": 2}
        )
        target_event.payload = target_payload
        target_event.payload_digest = sha256_json(target_payload)
        target_event.event_hash = _managed_event_hash(target_event)
        target_outbox = session.scalars(
            sa.select(ManagedOutboxMessage).where(
                ManagedOutboxMessage.org_id == org["org_id"],
                ManagedOutboxMessage.managed_event_id == target_event.id,
            )
        ).one()
        outbox_payload = dict(target_outbox.payload)
        outbox_payload["event_hash"] = target_event.event_hash
        outbox_payload["payload_digest"] = target_event.payload_digest
        outbox_payload["result_hash"] = target_payload["result_hash"]
        target_outbox.payload = outbox_payload
        target_outbox.payload_digest = sha256_json(outbox_payload)
        target_outbox.delivery_key = f"managed-mutation-uow/v1:{target_event.event_hash}"
        successor.previous_hash = target_event.event_hash

    before_counts = _runtime_mutation_counts(app, org["org_id"])
    original = captured[0]
    replay = client.request(
        original.method,
        original.path,
        content=original.body,
        headers=dict(original.headers),
    )
    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"
    assert _runtime_mutation_counts(app, org["org_id"]) == before_counts


def test_runtime_replay_rejects_event_chain_tamper(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    original, payload = _successful_enrollment_for_replay(
        client,
        org=org,
        admin_headers=admin_headers,
        runtime_descriptor_signer=runtime_descriptor_signer,
        key_id="runtime-chain-tamper-key",
    )
    with app.state.session_factory.begin() as session:
        receipt = session.scalars(
            sa.select(ManagedDecisionReceipt).where(
                ManagedDecisionReceipt.org_id == org["org_id"],
                ManagedDecisionReceipt.receipt_id == payload["receipt_id"],
            )
        ).one()
        event = session.scalars(
            sa.select(ManagedGovernanceEvent).where(
                ManagedGovernanceEvent.org_id == org["org_id"],
                ManagedGovernanceEvent.managed_receipt_id == receipt.id,
            )
        ).one()
        event.previous_hash = "1" * 64

    before_counts = _runtime_mutation_counts(app, org["org_id"])
    replay = client.request(
        original.method,
        original.path,
        content=original.body,
        headers=dict(original.headers),
    )
    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"
    assert _runtime_mutation_counts(app, org["org_id"]) == before_counts


@pytest.mark.parametrize("artifact", ["outbox", "consumption", "attempt"])
def test_runtime_replay_rejects_missing_managed_replay_artifact(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
    artifact: str,
) -> None:
    app = cast(Any, client.app)
    original, payload = _successful_enrollment_for_replay(
        client,
        org=org,
        admin_headers=admin_headers,
        runtime_descriptor_signer=runtime_descriptor_signer,
        key_id=f"runtime-missing-{artifact}-key",
    )
    with app.state.session_factory.begin() as session:
        receipt = session.scalars(
            sa.select(ManagedDecisionReceipt).where(
                ManagedDecisionReceipt.org_id == org["org_id"],
                ManagedDecisionReceipt.receipt_id == payload["receipt_id"],
            )
        ).one()
        if artifact == "outbox":
            row = session.scalars(
                sa.select(ManagedOutboxMessage).where(
                    ManagedOutboxMessage.org_id == org["org_id"],
                    ManagedOutboxMessage.managed_receipt_id == receipt.id,
                )
            ).one()
        elif artifact == "consumption":
            row = session.scalars(
                sa.select(ManagedReceiptConsumption).where(
                    ManagedReceiptConsumption.org_id == org["org_id"],
                    ManagedReceiptConsumption.managed_receipt_id == receipt.id,
                )
            ).one()
        else:
            row = session.scalars(
                sa.select(ManagedMutationAttempt).where(
                    ManagedMutationAttempt.org_id == org["org_id"],
                    ManagedMutationAttempt.receipt_hash == receipt.receipt_hash,
                )
            ).one()
        session.delete(row)

    before_counts = _runtime_mutation_counts(app, org["org_id"])
    replay = client.request(
        original.method,
        original.path,
        content=original.body,
        headers=dict(original.headers),
    )
    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"
    assert _runtime_mutation_counts(app, org["org_id"]) == before_counts


def test_runtime_replay_rejects_cross_tenant_response_scope(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    original, payload = _successful_enrollment_for_replay(
        client,
        org=org,
        admin_headers=admin_headers,
        runtime_descriptor_signer=runtime_descriptor_signer,
        key_id="runtime-cross-tenant-replay-key",
    )
    with app.state.session_factory.begin() as session:
        row = session.scalars(
            sa.select(RuntimeEnrollmentIdempotency).where(
                RuntimeEnrollmentIdempotency.org_id == org["org_id"],
                RuntimeEnrollmentIdempotency.identity_id == payload["identity_id"],
            )
        ).one()
        response = dict(row.response)
        response["org_id"] = f"other-{org['org_id']}"
        row.response = response

    before_counts = _runtime_mutation_counts(app, org["org_id"])
    replay = client.request(
        original.method,
        original.path,
        content=original.body,
        headers=dict(original.headers),
    )
    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"
    assert _runtime_mutation_counts(app, org["org_id"]) == before_counts


def test_injected_runtime_descriptor_signer_public_key_survives_app_restart(
    tmp_path: Path,
    audit_dir: Path,
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'acp.sqlite3'}"
    upgrade_database(database_url)
    settings = Settings(
        database_url=database_url,
        audit_dir=audit_dir,
        bootstrap_token="test-bootstrap-token",
        create_tables=False,
        runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
    )

    first = create_app(settings, runtime_descriptor_signer=runtime_descriptor_signer)
    first_public_key = runtime_descriptor_signer.public_key_bytes()
    first.state.engine.dispose()

    second = create_app(settings, runtime_descriptor_signer=runtime_descriptor_signer)
    try:
        assert runtime_descriptor_signer.public_key_bytes() == first_public_key
        assert TestClient(second).get("/readyz").status_code == 503
    finally:
        second.state.engine.dispose()


def test_expired_runtime_bootstrap_can_be_replaced(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
) -> None:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    first_key = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-expired-key")
    first = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=first_key,
    )
    with app.state.session_factory.begin() as session:
        bootstrap = session.get(RuntimeEnrollmentBootstrap, first["bootstrap_id"])
        assert bootstrap is not None
        bootstrap.expires_at = utcnow() - timedelta(seconds=1)

    before_counts = _runtime_mutation_counts(app, org["org_id"])
    second_key = InMemoryEd25519WorkloadKeyProvider(key_id="runtime-replacement-key")
    second = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=second_key,
    )

    assert second["bootstrap_id"] != first["bootstrap_id"]
    with app.state.session_factory() as session:
        rows = session.scalars(
            sa.select(RuntimeEnrollmentBootstrap).where(
                RuntimeEnrollmentBootstrap.org_id == org["org_id"],
                RuntimeEnrollmentBootstrap.project_id == project_id,
                RuntimeEnrollmentBootstrap.environment_id == environment_id,
            )
        ).all()
    assert sorted(row.status for row in rows) == ["active", "expired"]
    after_counts = _runtime_mutation_counts(app, org["org_id"])
    assert after_counts == {key: before_counts[key] + 1 for key in ("receipts", "events", "outbox")}


def _seed_scope_trust_and_policy(
    app: Any, org_id: str, *, rules: list[dict[str, Any]] | None = None
) -> tuple[str, str]:
    project_id = f"project-{new_id()}"
    environment_id = f"environment-{new_id()}"
    with app.state.session_factory.begin() as session:
        session.add(Project(id=project_id, org_id=org_id, slug="runtime", name="Runtime"))
        session.add(
            Environment(
                id=environment_id,
                org_id=org_id,
                project_id=project_id,
                slug="production",
                name="Production",
            )
        )
        session.flush()
        runtime_scope = ReceiptTrustScope(
            org_id, project_id, environment_id, DECISION_RECEIPT_PURPOSE
        )
        runtime_signer = app.state.runtime_enrollment_service.issuer.signer_for_scope(
            runtime_scope,
            trust_epoch=1,
        )
        ManagedTrustLifecycleService(session).bootstrap(
            scope=runtime_scope,
            key_id=runtime_signer.key_id,
            algorithm=runtime_signer.algorithm,
            public_key_spki_der=public_spki_der_from_signer(runtime_signer),
            not_after=utcnow() + timedelta(days=1),
        )
        policy_scope = ReceiptTrustScope(
            org_id, project_id, environment_id, POLICY_ENVELOPE_PURPOSE
        )
        policy_issuer = local_policy_registry_issuer()
        policy_signer = policy_issuer.signer_for_scope(policy_scope, trust_epoch=1)
        ManagedTrustLifecycleService(session).bootstrap(
            scope=policy_scope,
            key_id=policy_signer.key_id,
            algorithm=policy_signer.algorithm,
            public_key_spki_der=public_spki_der_from_signer(policy_signer),
            not_after=utcnow() + timedelta(days=1),
        )
        policy_id = f"runtime-policy-{new_id()}"
        policy_rules = rules or [
            {"id": "deny-unrelated", "effect": "deny", "tools": ["unrelated.tool"]}
        ]
        parsed = RuleSetPolicy.from_dict({"id": policy_id, "rules": policy_rules})
        document = {"id": parsed.policy_id, "version": parsed.version, "rules": policy_rules}
        envelope = _signed_envelope(
            issuer=policy_issuer,
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            policy_id=policy_id,
            document=document,
            trust_epoch=1,
        )
        policy_version = PolicyVersion(
            id=new_id(),
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            policy_id=policy_id,
            version=document["version"],
            content_hash=envelope["content_hash"],
            document=document,
            rules=policy_rules,
            canonical_envelope=envelope,
            purpose=envelope["purpose"],
            key_id=envelope["key_id"],
            signature_algorithm=envelope["signature_algorithm"],
            signature=envelope["signature"],
            trust_epoch=envelope["trust_epoch"],
            receipt_id=f"test-policy-receipt-{new_id()}",
        )
        receipt_id = _seed_policy_head_receipt(
            session,
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
        )
        session.add(policy_version)
        session.flush()
        session.add(
            EnvironmentPolicyHead(
                id=new_id(),
                org_id=org_id,
                project_id=project_id,
                environment_id=environment_id,
                active_policy_version_id=policy_version.id,
                generation=1,
                status="active",
                receipt_id=receipt_id,
                created_at=utcnow(),
                updated_at=utcnow(),
            )
        )
    return project_id, environment_id


def _successful_enrollment_for_replay(
    client: TestClient,
    *,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
    key_id: str,
) -> tuple[RuntimeHttpRequest, dict[str, Any]]:
    app = cast(Any, client.app)
    project_id, environment_id = _seed_scope_trust_and_policy(app, org["org_id"])
    key_provider = InMemoryEd25519WorkloadKeyProvider(key_id=key_id)
    bootstrap = _issue_bootstrap(
        client,
        org["org_id"],
        project_id,
        environment_id,
        admin_headers,
        key_provider=key_provider,
    )
    captured: list[RuntimeHttpRequest] = []
    runtime_client = RuntimeEnrollmentClient(
        key_provider=key_provider,
        transport=_runtime_transport(client=client, captured=captured),
        audience="control-plane.runtime-enrollment:v1",
    )
    enrollment = runtime_client.exchange_bootstrap(
        scope=GateScope(
            org_id=org["org_id"],
            project_id=project_id,
            environment=environment_id,
            gate_id=bootstrap["gate_id"],
        ),
        bootstrap_id=bootstrap["bootstrap_id"],
        bootstrap_token=bootstrap["bootstrap_token"],
        runtime_identity_id=bootstrap["runtime_identity_id"],
        idempotency_key=f"idem-secret-{new_id()}",
        server_challenge=bootstrap["server_challenge"],
        client_nonce=f"client-{new_id()}",
        timestamp=_runtime_timestamp(),
    )
    assert enrollment.status_code == 201, enrollment.body.decode()
    runtime_client.accept_enrollment_response(
        enrollment,
        issuer_public_key=runtime_descriptor_signer.public_key_bytes(),
        expected_scope=GateScope(
            org_id=org["org_id"],
            project_id=project_id,
            environment=environment_id,
            gate_id=bootstrap["gate_id"],
        ),
        expected_runtime_identity_id=bootstrap["runtime_identity_id"],
    )
    return captured[0], json.loads(enrollment.body)


def _issue_bootstrap(
    client: TestClient,
    org_id: str,
    project_id: str,
    environment_id: str,
    headers: dict[str, str],
    *,
    key_provider: InMemoryEd25519WorkloadKeyProvider,
) -> dict[str, Any]:
    public_key = key_provider.public_key_bytes()
    resp = client.post(
        f"/orgs/{org_id}/projects/{project_id}/environments/{environment_id}"
        "/runtime-enrollment-bootstraps",
        json={
            "ttl_seconds": 600,
            "workload_key_id": key_provider.key_id,
            "public_key_thumbprint": public_key_thumbprint(public_key),
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    payload = resp.json()
    payload["_headers"] = dict(resp.headers)
    return payload


def _runtime_transport(
    *,
    client: TestClient,
    captured: list[RuntimeHttpRequest] | None = None,
) -> Any:
    def _send(request: RuntimeHttpRequest) -> RuntimeHttpResponse:
        if captured is not None:
            captured.append(request)
        headers = dict(request.headers)
        url = request.path + (f"?{request.query}" if request.query else "")
        response = client.request(
            request.method,
            url,
            content=request.body,
            headers=headers,
        )
        return RuntimeHttpResponse(
            status_code=response.status_code,
            body=response.content,
            headers=dict(response.headers),
        )

    return _send


def _identity_count(app: Any, identity_id: str) -> int:
    with app.state.session_factory() as session:
        return session.scalar(
            sa.select(sa.func.count())
            .select_from(RuntimeIdentity)
            .where(RuntimeIdentity.id == identity_id)
        )


def _runtime_mutation_counts(app: Any, org_id: str) -> dict[str, int]:
    with app.state.session_factory() as session:
        return {
            "receipts": session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedDecisionReceipt)
                .where(ManagedDecisionReceipt.org_id == org_id)
            ),
            "events": session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedGovernanceEvent)
                .where(ManagedGovernanceEvent.org_id == org_id)
            ),
            "outbox": session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedOutboxMessage)
                .where(ManagedOutboxMessage.org_id == org_id)
            ),
        }


def _runtime_replay_counts(app: Any, org_id: str) -> dict[str, int]:
    with app.state.session_factory() as session:
        return {
            "receipts": session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedDecisionReceipt)
                .where(ManagedDecisionReceipt.org_id == org_id)
            ),
            "events": session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedGovernanceEvent)
                .where(ManagedGovernanceEvent.org_id == org_id)
            ),
            "outbox": session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedOutboxMessage)
                .where(ManagedOutboxMessage.org_id == org_id)
            ),
            "enrollment_idempotency": session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeEnrollmentIdempotency)
                .where(RuntimeEnrollmentIdempotency.org_id == org_id)
            ),
            "operation_idempotency": session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeOperationIdempotency)
                .where(RuntimeOperationIdempotency.org_id == org_id)
            ),
            "nonces": session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeRequestNonce)
                .where(RuntimeRequestNonce.org_id == org_id)
            ),
            "identities": session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeIdentity)
                .where(RuntimeIdentity.org_id == org_id)
            ),
            "credentials": session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeCredentialGeneration)
                .where(RuntimeCredentialGeneration.org_id == org_id)
            ),
        }


def _runtime_attempt_count(app: Any, org_id: str) -> int:
    with app.state.session_factory() as session:
        return (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedMutationAttempt)
                .where(ManagedMutationAttempt.org_id == org_id)
            )
            or 0
        )


def _managed_event_hash(event: ManagedGovernanceEvent) -> str:
    return sha256_json(
        {
            "schema": "managed-mutation-event-chain/v1",
            "sequence": event.sequence,
            "previous_hash": event.previous_hash,
            "payload_digest": event.payload_digest,
        }
    )


def _tamper_event_result_hash_for_receipt(app: Any, org_id: str, receipt_id: str) -> None:
    with app.state.session_factory.begin() as session:
        receipt = session.scalars(
            sa.select(ManagedDecisionReceipt).where(
                ManagedDecisionReceipt.org_id == org_id,
                ManagedDecisionReceipt.receipt_id == receipt_id,
            )
        ).one()
        event = session.scalars(
            sa.select(ManagedGovernanceEvent).where(
                ManagedGovernanceEvent.org_id == org_id,
                ManagedGovernanceEvent.managed_receipt_id == receipt.id,
            )
        ).one()
        payload = dict(event.payload)
        payload["result_hash"] = "0" * 64
        event.payload = payload


def _assert_identity_and_credentials(
    app: Any,
    *,
    identity_id: str,
    expected_identity_status: str,
    expected_current_generation: int,
    expected_credential_statuses: dict[int, str],
) -> None:
    with app.state.session_factory() as session:
        identity = session.get(RuntimeIdentity, identity_id)
        assert identity is not None
        assert identity.status == expected_identity_status
        assert identity.current_generation == expected_current_generation
        rows = session.execute(
            sa.select(RuntimeCredentialGeneration.generation, RuntimeCredentialGeneration.status)
            .where(RuntimeCredentialGeneration.identity_id == identity_id)
            .order_by(RuntimeCredentialGeneration.generation)
        ).all()
    assert dict(rows) == expected_credential_statuses


def _assert_runtime_managed_payloads_do_not_contain(app: Any, org_id: str, sentinel: str) -> None:
    with app.state.session_factory() as session:
        receipts = session.scalars(
            sa.select(ManagedDecisionReceipt).where(
                ManagedDecisionReceipt.org_id == org_id,
                ManagedDecisionReceipt.proposed_action.like("control-plane.runtime.%"),
            )
        ).all()
        events = session.scalars(
            sa.select(ManagedGovernanceEvent).where(ManagedGovernanceEvent.org_id == org_id)
        ).all()
        outbox = session.scalars(
            sa.select(ManagedOutboxMessage).where(ManagedOutboxMessage.org_id == org_id)
        ).all()
    persisted = json.dumps(
        {
            "receipts": [
                {
                    "receipt_id": row.receipt_id,
                    "argument_hash": row.argument_hash,
                    "projection": row.projection,
                }
                for row in receipts
            ],
            "events": [row.payload for row in events],
            "outbox": [row.payload for row in outbox],
        },
        sort_keys=True,
        default=str,
    )
    assert sentinel not in persisted


def _seed_policy_head_receipt(
    session: Any,
    *,
    org_id: str,
    project_id: str,
    environment_id: str,
) -> str:
    receipt_id = f"test-policy-head-receipt-{new_id()}"
    now = utcnow()
    session.add(
        ManagedDecisionReceipt(
            id=f"test-policy-head-{new_id()}",
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            receipt_id=receipt_id,
            receipt_hash=sha256_json({"schema": "test-policy-head-receipt/v1", "id": receipt_id}),
            audit_event_hash=sha256_json({"schema": "test-policy-head-audit/v1", "id": receipt_id}),
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


def _runtime_timestamp() -> str:
    return utcnow().isoformat().replace("+00:00", "Z")
