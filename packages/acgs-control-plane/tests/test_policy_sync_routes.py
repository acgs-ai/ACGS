"""Route-level security contract for signed runtime policy synchronization."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from gove_zone.runtime_identity import (
    GateScope,
    InMemoryEd25519WorkloadKeyProvider,
    RuntimeIdentityDescriptor,
    canonical_signed_runtime_request_bytes,
    public_key_thumbprint,
    sha256_bytes,
)
from gove_zone.signing import Ed25519Signer
from gove_zone.trust import ReceiptTrustScope

from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.governance import ProductionPostureBlocked
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import (
    Environment,
    EnvironmentPolicyHead,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    ManagedTrustKey,
    PolicyVersion,
    Project,
    RuntimeCredentialGeneration,
    RuntimeIdentity,
    RuntimeIdentityGate,
    RuntimeRequestNonce,
    new_id,
    utcnow,
)
from acgs_control_plane.policy_registry import (
    POLICY_ENVELOPE_PURPOSE,
    bootstrap_local_policy_registry_trust,
    local_policy_registry_issuer,
    local_policy_registry_receipt_sealer,
)
from acgs_control_plane.policy_sync import (
    POLICY_SYNC_ATTESTATION_PURPOSE,
    POLICY_SYNC_PURPOSE,
    POLICY_SYNC_SCHEMA,
    PolicySyncService,
    local_policy_sync_attestation_issuer,
)
from acgs_control_plane.runtime_enrollment import RUNTIME_ENROLLMENT_AUTHORITY
from acgs_control_plane.tenant_bootstrap import BOOTSTRAP_IDEMPOTENCY_HEADER
from acgs_control_plane.trust import (
    InProcessPlatformIssuer,
    ManagedTrustLifecycleService,
    public_spki_der_from_signer,
)

POLICY_SYNC_PATH = "/v1/runtime-identities/{identity_id}/policy-bundle"


def test_policy_sync_returns_strict_signed_snapshot_and_exact_etag_304(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    seeded = _seed_runtime_policy_sync(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    assert "runtime-identity.policy-sync" not in app.state.mutation_inventory_seal.definitions
    before = _read_path_counts(app, org["org_id"])

    response = _signed_get(client, seeded)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["etag"].startswith('"')
    assert response.headers["etag"].endswith('"')
    payload = response.json()
    assert set(payload) == {
        "schema",
        "purpose",
        "scope",
        "runtime_identity_id",
        "credential_id",
        "credential_generation",
        "cursor",
        "head_generation",
        "head_updated_at",
        "policy_version_id",
        "policy_id",
        "version",
        "content_hash",
        "policy_envelope",
        "activation_receipt_id",
        "activation_receipt_hash",
        "activation_event_hash",
        "attestation_purpose",
        "attestation_trust_epoch",
        "attestation_key_id",
        "attestation_signature_algorithm",
        "issued_at",
        "revocation_checked_at",
        "fresh_until",
        "expires_at",
        "attestation_signature",
    }
    assert payload["schema"] == POLICY_SYNC_SCHEMA
    assert payload["purpose"] == POLICY_SYNC_PURPOSE
    assert payload["scope"] == {
        "org_id": org["org_id"],
        "project_id": seeded["project_id"],
        "environment_id": seeded["environment_id"],
        "gate_id": seeded["gate_id"],
    }
    assert payload["runtime_identity_id"] == seeded["identity_id"]
    assert payload["credential_id"] == seeded["credential_id"]
    assert payload["credential_generation"] == 1
    assert payload["policy_version_id"] == seeded["policy_version_id"]
    assert payload["policy_envelope"] == seeded["policy_envelope"]
    assert payload["content_hash"] == payload["policy_envelope"]["content_hash"]
    assert payload["activation_receipt_id"] == seeded["activation_receipt_id"]
    assert len(payload["activation_receipt_hash"]) == 64
    assert len(payload["activation_event_hash"]) == 64
    assert all(char in "0123456789abcdef" for char in payload["activation_receipt_hash"])
    assert all(char in "0123456789abcdef" for char in payload["activation_event_hash"])
    with app.state.session_factory() as session:
        activation_receipt = session.scalars(
            sa.select(ManagedDecisionReceipt).where(
                ManagedDecisionReceipt.receipt_id == payload["activation_receipt_id"]
            )
        ).one()
        activation_event = session.scalars(
            sa.select(ManagedGovernanceEvent).where(
                ManagedGovernanceEvent.managed_receipt_id == activation_receipt.id
            )
        ).one()
        assert payload["activation_receipt_hash"] == activation_receipt.receipt_hash
        assert payload["activation_event_hash"] == activation_event.event_hash
    assert payload["attestation_purpose"] == POLICY_SYNC_ATTESTATION_PURPOSE
    assert payload["attestation_trust_epoch"] == 1
    assert payload["attestation_key_id"] == seeded["attestation_signer"].key_id
    assert payload["attestation_key_id"] != seeded["policy_signer"].key_id
    assert payload["attestation_signature_algorithm"] == "ed25519"
    unsigned = dict(payload)
    signature = unsigned.pop("attestation_signature")
    assert seeded["attestation_signer"].verify(_canonical_bytes(unsigned), signature)
    assert _read_path_counts(app, org["org_id"]) == before

    cursor_not_modified = _signed_get(
        client,
        seeded,
        query=f"cursor={payload['cursor']}",
    )
    assert cursor_not_modified.status_code == 304
    assert not cursor_not_modified.content
    assert cursor_not_modified.headers["etag"] == response.headers["etag"]
    assert _read_path_counts(app, org["org_id"]) == before


def test_policy_sync_rejects_signature_scope_and_live_state_fail_closed(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    seeded = _seed_runtime_policy_sync(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    before = _read_path_counts(app, org["org_id"])

    bad_signature = _signed_headers(seeded)
    bad_signature["X-ACGS-Runtime-Signature"] = "invalid"
    response = client.get(
        POLICY_SYNC_PATH.format(identity_id=seeded["identity_id"]),
        headers=bad_signature,
    )
    assert response.status_code == 401
    assert response.json()["code"] == "RUNTIME_AUTHENTICATION_FAILED"
    assert seeded["identity_id"] not in response.text

    response = client.get(
        POLICY_SYNC_PATH.format(identity_id=f"wrong-{new_id()}"),
        headers=_signed_headers(seeded),
    )
    assert response.status_code == 401
    assert response.json()["code"] == "RUNTIME_AUTHENTICATION_FAILED"

    with app.state.session_factory.begin() as session:
        gate = session.get(RuntimeIdentityGate, seeded["gate_id"])
        assert gate is not None
        gate.status = "revoked"
        gate.updated_at = utcnow()
    response = _signed_get(client, seeded)
    assert response.status_code == 401
    assert response.json()["code"] == "RUNTIME_AUTHENTICATION_FAILED"
    assert _read_path_counts(app, org["org_id"]) == before


def test_policy_sync_refuses_missing_or_tampered_active_policy_without_mutation(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    seeded = _seed_runtime_policy_sync(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    before = _read_path_counts(app, org["org_id"])

    with app.state.session_factory.begin() as session:
        head = session.scalars(
            sa.select(EnvironmentPolicyHead).where(
                EnvironmentPolicyHead.org_id == org["org_id"],
                EnvironmentPolicyHead.project_id == seeded["project_id"],
                EnvironmentPolicyHead.environment_id == seeded["environment_id"],
            )
        ).one()
        session.delete(head)
    response = _signed_get(client, seeded)
    assert response.status_code == 503
    assert response.json()["code"] == "POLICY_HEAD_UNAVAILABLE"
    assert _read_path_counts(app, org["org_id"]) == before


def test_policy_sync_auth_failures_are_indistinguishable_and_bind_empty_raw_request(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    seeded = _seed_runtime_policy_sync(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    before = _read_path_counts(app, org["org_id"])
    path = POLICY_SYNC_PATH.format(identity_id=seeded["identity_id"])

    existing_headers = _signed_headers(seeded)
    existing_headers["X-ACGS-Runtime-Signature"] = "invalid"
    existing = client.get(path, headers=existing_headers)

    unknown_identity_id = f"unknown-{new_id()}"
    unknown_headers = dict(existing_headers)
    unknown_headers["X-ACGS-Runtime-Identity-ID"] = unknown_identity_id
    unknown = client.get(
        POLICY_SYNC_PATH.format(identity_id=unknown_identity_id),
        headers=unknown_headers,
    )
    assert existing.status_code == unknown.status_code == 401
    assert (
        existing.json()
        == unknown.json()
        == {
            "code": "RUNTIME_AUTHENTICATION_FAILED",
            "status": "unauthorized",
            "detail": "runtime request authentication failed",
        }
    )

    body = b"not-empty"
    nonempty = client.request(
        "GET",
        path,
        content=body,
        headers=_signed_headers(seeded, body=body),
    )
    assert nonempty.status_code == 401
    assert nonempty.json() == existing.json()

    encoded = client.get(
        path.replace("/runtime-identities/", "/%72untime-identities/"),
        headers=_signed_headers(seeded),
    )
    assert encoded.status_code == 401
    assert encoded.json() == existing.json()
    assert _read_path_counts(app, org["org_id"]) == before


def test_policy_sync_refuses_outer_signer_not_matching_active_sql_trust(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    seeded = _seed_runtime_policy_sync(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    mismatched_issuer = InProcessPlatformIssuer(
        Ed25519Signer.generate(key_id=seeded["attestation_signer"].key_id),
        allowed_purposes=frozenset({POLICY_SYNC_ATTESTATION_PURPOSE}),
    )
    app.state.policy_sync_service = PolicySyncService(
        app.state.session_factory,
        attestation_issuer=mismatched_issuer,
        policy_registry_issuer=local_policy_registry_issuer(),
        receipt_sealer=local_policy_registry_receipt_sealer(),
    )

    response = _signed_get(client, seeded)
    assert response.status_code == 503
    assert response.json() == {
        "code": "POLICY_SYNC_ATTESTATION_REFUSED",
        "status": "attestation_refused",
        "detail": "policy synchronization attestation was refused",
    }


def test_policy_sync_production_requires_independent_attestation_provider(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "must-not-be-created.sqlite3"
    with pytest.raises(ProductionPostureBlocked) as stopped:
        create_app(
            Settings(
                database_url=f"sqlite:///{database_path}",
                audit_dir=tmp_path / "audit",
                create_tables=False,
                runtime_posture=RuntimePosture.PRODUCTION,
            )
        )

    assert any(
        blocker.code == "POLICY_SYNC_ATTESTATION_PROVIDER_REQUIRED"
        for blocker in stopped.value.blockers
    )
    assert not database_path.exists()


def test_policy_sync_startup_refuses_reused_publisher_provider(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'provider-reuse.sqlite3'}"
    upgrade_database(database_url)
    publisher = local_policy_registry_issuer()

    with pytest.raises(ProductionPostureBlocked) as stopped:
        create_app(
            Settings(
                database_url=database_url,
                audit_dir=tmp_path / "audit",
                create_tables=False,
                runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
            ),
            policy_registry_issuer=publisher,
            policy_registry_receipt_sealer=local_policy_registry_receipt_sealer(),
            policy_sync_attestation_issuer=publisher,
        )

    assert [blocker.code for blocker in stopped.value.blockers] == [
        "POLICY_SYNC_ATTESTATION_PROVIDER_REUSED"
    ]


def test_policy_sync_startup_refuses_distinct_provider_reusing_publisher_key_id(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'key-id-reuse.sqlite3'}"
    upgrade_database(database_url)
    publisher = local_policy_registry_issuer()
    reused_key_id = InProcessPlatformIssuer(
        Ed25519Signer.generate(key_id=publisher.key_id),
        allowed_purposes=frozenset({POLICY_SYNC_ATTESTATION_PURPOSE}),
    )

    with pytest.raises(ProductionPostureBlocked) as stopped:
        create_app(
            Settings(
                database_url=database_url,
                audit_dir=tmp_path / "audit",
                create_tables=False,
                runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
            ),
            policy_registry_issuer=publisher,
            policy_registry_receipt_sealer=local_policy_registry_receipt_sealer(),
            policy_sync_attestation_issuer=reused_key_id,
        )

    assert [blocker.code for blocker in stopped.value.blockers] == [
        "POLICY_SYNC_ATTESTATION_PROVIDER_REUSED"
    ]


def test_policy_sync_refuses_same_physical_publisher_key_under_alias(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    publisher = local_policy_registry_issuer()
    alias_signer = Ed25519Signer.from_public_bytes(
        cast(Ed25519Signer, publisher.signer).public_bytes(),
        key_id="policy-sync-attestation-alias",
    )
    alias_issuer = InProcessPlatformIssuer(
        alias_signer,
        allowed_purposes=frozenset({POLICY_SYNC_ATTESTATION_PURPOSE}),
    )
    seeded = _seed_runtime_policy_sync(
        client,
        org,
        runtime_descriptor_signer,
        scope_suffix="same-spki-alias",
        attestation_issuer=alias_issuer,
    )
    app = cast(Any, client.app)
    app.state.policy_sync_service = PolicySyncService(
        app.state.session_factory,
        attestation_issuer=alias_issuer,
        policy_registry_issuer=publisher,
        receipt_sealer=local_policy_registry_receipt_sealer(),
    )
    before = _read_path_counts(app, org["org_id"])

    response = _signed_get(client, seeded)

    assert response.status_code == 503
    assert response.json()["code"] == "POLICY_SYNC_ATTESTATION_REFUSED"
    assert _read_path_counts(app, org["org_id"]) == before


def test_compromised_publisher_cannot_sign_policy_sync_attestation(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    publisher = local_policy_registry_issuer()
    compromised = InProcessPlatformIssuer(
        publisher.signer,
        allowed_purposes=frozenset({POLICY_ENVELOPE_PURPOSE, POLICY_SYNC_ATTESTATION_PURPOSE}),
    )
    seeded = _seed_runtime_policy_sync(
        client,
        org,
        runtime_descriptor_signer,
        scope_suffix="compromised-publisher",
        attestation_issuer=compromised,
    )
    app = cast(Any, client.app)
    app.state.policy_sync_service = PolicySyncService(
        app.state.session_factory,
        attestation_issuer=compromised,
        policy_registry_issuer=compromised,
        receipt_sealer=local_policy_registry_receipt_sealer(),
    )
    before = _read_path_counts(app, org["org_id"])

    response = _signed_get(client, seeded)

    assert response.status_code == 503
    assert response.json()["code"] == "POLICY_SYNC_ATTESTATION_REFUSED"
    assert _read_path_counts(app, org["org_id"]) == before


def test_policy_sync_attestation_rotation_changes_cursor_and_invalidates_304(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    seeded = _seed_runtime_policy_sync(
        client, org, runtime_descriptor_signer, scope_suffix="attestation-rotation"
    )
    app = cast(Any, client.app)
    first = _signed_get(client, seeded)
    assert first.status_code == 200, first.text
    first_payload = first.json()

    rotated_signer = Ed25519Signer.generate(key_id="rotated-policy-sync-attestation")
    rotated_issuer = InProcessPlatformIssuer(
        rotated_signer,
        allowed_purposes=frozenset({POLICY_SYNC_ATTESTATION_PURPOSE}),
    )
    with app.state.session_factory.begin() as session:
        ManagedTrustLifecycleService(session).rotate(
            scope=seeded["attestation_scope"],
            key_id=rotated_signer.key_id,
            algorithm=rotated_signer.algorithm,
            public_key_spki_der=public_spki_der_from_signer(rotated_signer),
            not_after=utcnow() + timedelta(hours=1),
            expected_current_epoch=1,
        )
    app.state.policy_sync_service = PolicySyncService(
        app.state.session_factory,
        attestation_issuer=rotated_issuer,
        policy_registry_issuer=local_policy_registry_issuer(),
        receipt_sealer=local_policy_registry_receipt_sealer(),
    )

    response = _signed_get(client, seeded, query=f"cursor={first_payload['cursor']}")

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["cursor"] != first_payload["cursor"]
    assert payload["attestation_trust_epoch"] == 2
    assert payload["attestation_key_id"] == rotated_signer.key_id
    unsigned = dict(payload)
    signature = unsigned.pop("attestation_signature")
    assert rotated_signer.verify(_canonical_bytes(unsigned), signature)


def test_policy_sync_refuses_invalid_validity_credential_and_trust_state(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: InMemoryEd25519WorkloadKeyProvider,
) -> None:
    app = cast(Any, client.app)
    boundary = _seed_runtime_policy_sync(
        client, org, runtime_descriptor_signer, scope_suffix="boundary"
    )
    with app.state.session_factory.begin() as session:
        credential = session.get(RuntimeCredentialGeneration, boundary["credential_id"])
        assert credential is not None
        credential.not_after = utcnow() + timedelta(seconds=30)
    response = _signed_get(client, boundary)
    assert response.status_code == 503
    assert response.json()["code"] == "POLICY_SNAPSHOT_STALE"

    attestation_boundary = _seed_runtime_policy_sync(
        client, org, runtime_descriptor_signer, scope_suffix="attestation-boundary"
    )
    with app.state.session_factory.begin() as session:
        trust = session.scalars(
            sa.select(ManagedTrustKey).where(
                ManagedTrustKey.org_id == org["org_id"],
                ManagedTrustKey.project_id == attestation_boundary["project_id"],
                ManagedTrustKey.environment_id == attestation_boundary["environment_id"],
                ManagedTrustKey.purpose == POLICY_SYNC_ATTESTATION_PURPOSE,
            )
        ).one()
        trust.not_after = utcnow() + timedelta(seconds=30)
        trust.updated_at = utcnow()
    response = _signed_get(client, attestation_boundary)
    assert response.status_code == 503
    assert response.json()["code"] == "POLICY_SNAPSHOT_STALE"

    revoked = _seed_runtime_policy_sync(
        client, org, runtime_descriptor_signer, scope_suffix="revoked-credential"
    )
    with app.state.session_factory.begin() as session:
        credential = session.get(RuntimeCredentialGeneration, revoked["credential_id"])
        assert credential is not None
        credential.status = "revoked"
    response = _signed_get(client, revoked)
    assert response.status_code == 401
    assert response.json()["code"] == "RUNTIME_AUTHENTICATION_FAILED"

    expired = _seed_runtime_policy_sync(
        client, org, runtime_descriptor_signer, scope_suffix="expired-credential"
    )
    with app.state.session_factory.begin() as session:
        credential = session.get(RuntimeCredentialGeneration, expired["credential_id"])
        assert credential is not None
        credential.not_after = utcnow() - timedelta(seconds=1)
    response = _signed_get(client, expired)
    assert response.status_code == 401
    assert response.json()["code"] == "RUNTIME_AUTHENTICATION_FAILED"

    missing_attestation = _seed_runtime_policy_sync(
        client,
        org,
        runtime_descriptor_signer,
        scope_suffix="missing-attestation",
        bootstrap_attestation=False,
    )
    response = _signed_get(client, missing_attestation)
    assert response.status_code == 503
    assert response.json()["code"] == "POLICY_SYNC_ATTESTATION_REFUSED"

    revoked_trust = _seed_runtime_policy_sync(
        client, org, runtime_descriptor_signer, scope_suffix="revoked-attestation"
    )
    with app.state.session_factory.begin() as session:
        trust = session.scalars(
            sa.select(ManagedTrustKey).where(
                ManagedTrustKey.org_id == org["org_id"],
                ManagedTrustKey.project_id == revoked_trust["project_id"],
                ManagedTrustKey.environment_id == revoked_trust["environment_id"],
                ManagedTrustKey.purpose == POLICY_SYNC_ATTESTATION_PURPOSE,
            )
        ).one()
        trust.status = "revoked"
        trust.updated_at = utcnow()
    response = _signed_get(client, revoked_trust)
    assert response.status_code == 503
    assert response.json()["code"] == "POLICY_SYNC_ATTESTATION_REFUSED"

    expired_trust = _seed_runtime_policy_sync(
        client, org, runtime_descriptor_signer, scope_suffix="expired-attestation"
    )
    with app.state.session_factory.begin() as session:
        trust = session.scalars(
            sa.select(ManagedTrustKey).where(
                ManagedTrustKey.org_id == org["org_id"],
                ManagedTrustKey.project_id == expired_trust["project_id"],
                ManagedTrustKey.environment_id == expired_trust["environment_id"],
                ManagedTrustKey.purpose == POLICY_SYNC_ATTESTATION_PURPOSE,
            )
        ).one()
        trust.not_after = utcnow() - timedelta(seconds=1)
        trust.updated_at = utcnow()
    response = _signed_get(client, expired_trust)
    assert response.status_code == 503
    assert response.json()["code"] == "POLICY_SYNC_ATTESTATION_REFUSED"

    seeded = _seed_runtime_policy_sync(
        client, org, runtime_descriptor_signer, scope_suffix="second"
    )
    with app.state.session_factory.begin() as session:
        session.execute(sa.text("DROP TRIGGER environment_policy_heads_monotonic_update"))
        session.execute(
            sa.update(EnvironmentPolicyHead)
            .where(EnvironmentPolicyHead.id == seeded["policy_head_id"])
            .values(receipt_id=seeded["publish_receipt_id"])
        )
    before = _read_path_counts(app, org["org_id"])
    response = _signed_get(client, seeded)
    assert response.status_code == 503
    assert response.json()["code"] == "POLICY_ACTIVATION_EVIDENCE_REFUSED"
    assert _read_path_counts(app, org["org_id"]) == before


def _seed_runtime_policy_sync(
    client: TestClient,
    org: dict[str, Any],
    response_signer: InMemoryEd25519WorkloadKeyProvider,
    *,
    scope_suffix: str = "primary",
    attestation_issuer: InProcessPlatformIssuer | None = None,
    bootstrap_attestation: bool = True,
) -> dict[str, Any]:
    app = cast(Any, client.app)
    org_id = str(org["org_id"])
    now = utcnow()
    project_id = f"project-{scope_suffix}-{new_id()}"
    environment_id = f"environment-{scope_suffix}-{new_id()}"
    gate_id = f"gate-{scope_suffix}-{new_id()}"
    identity_id = f"runtime-{scope_suffix}-{new_id()}"
    credential_id = f"credential-{scope_suffix}-{new_id()}"
    effective_attestation_issuer = attestation_issuer or local_policy_sync_attestation_issuer()
    attestation_scope = ReceiptTrustScope(
        org_id,
        project_id,
        environment_id,
        POLICY_SYNC_ATTESTATION_PURPOSE,
    )
    attestation_signer = effective_attestation_issuer.signer_for_scope(
        attestation_scope,
        trust_epoch=1,
    )
    workload_key = InMemoryEd25519WorkloadKeyProvider(key_id=f"workload-{scope_suffix}")
    descriptor = RuntimeIdentityDescriptor.issue(
        scope=GateScope(org_id, project_id, environment_id, gate_id),
        runtime_identity_id=identity_id,
        credential_id=credential_id,
        credential_generation=1,
        workload_public_key=workload_key.public_key_bytes(),
        issuer="acgs-control-plane",
        audience=RUNTIME_ENROLLMENT_AUTHORITY,
        issued_at=_timestamp(now),
        expires_at=_timestamp(now + timedelta(hours=1)),
        signer=response_signer,
    )
    with app.state.session_factory.begin() as session:
        session.add_all(
            [
                Project(id=project_id, org_id=org_id, slug=scope_suffix, name=scope_suffix.title()),
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
        bootstrap_local_policy_registry_trust(
            session,
            org_id=org_id,
            project_id=project_id,
            environment_id=environment_id,
            issuer=local_policy_registry_issuer(),
        )
        if bootstrap_attestation:
            ManagedTrustLifecycleService(session).bootstrap(
                scope=attestation_scope,
                key_id=attestation_signer.key_id,
                algorithm=attestation_signer.algorithm,
                public_key_spki_der=public_spki_der_from_signer(attestation_signer),
                not_after=now + timedelta(hours=1),
            )
        session.add_all(
            [
                RuntimeIdentityGate(
                    id=gate_id,
                    org_id=org_id,
                    project_id=project_id,
                    environment_id=environment_id,
                    status="active",
                ),
                RuntimeIdentity(
                    id=identity_id,
                    org_id=org_id,
                    project_id=project_id,
                    environment_id=environment_id,
                    gate_id=gate_id,
                    name=f"Runtime {scope_suffix}",
                    actor=f"runtime:{identity_id}",
                    workload_key_id=workload_key.key_id,
                    public_key=descriptor.public_key,
                    public_key_thumbprint=public_key_thumbprint(workload_key.public_key_bytes()),
                    descriptor=descriptor.to_dict(),
                    status="active",
                    current_generation=1,
                ),
                RuntimeCredentialGeneration(
                    id=credential_id,
                    org_id=org_id,
                    project_id=project_id,
                    environment_id=environment_id,
                    identity_id=identity_id,
                    generation=1,
                    workload_key_id=workload_key.key_id,
                    public_key_thumbprint=public_key_thumbprint(workload_key.public_key_bytes()),
                    not_before=now - timedelta(minutes=1),
                    not_after=now + timedelta(hours=1),
                    status="active",
                    descriptor=descriptor.to_dict(),
                ),
            ]
        )
    policy_id = f"runtime-policy-{scope_suffix}-{new_id()}"
    rules = [{"id": "deny-unrelated", "effect": "deny", "tools": ["unrelated.tool"]}]
    management_headers = {
        "X-API-Key": str(org["admin_api_key"]),
        BOOTSTRAP_IDEMPOTENCY_HEADER: f"policy-sync-publish-{scope_suffix}-{new_id()}",
    }
    published = client.post(
        f"/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies",
        json={"policy_id": policy_id, "rules": rules},
        headers=management_headers,
    )
    assert published.status_code == 201, published.text
    publish_payload = published.json()
    policy_version_id = str(publish_payload["bundle_id"])
    activated = client.post(
        f"/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies/{policy_version_id}/activate",
        json={"expected_generation": 0},
        headers={
            "X-API-Key": str(org["admin_api_key"]),
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"policy-sync-activate-{scope_suffix}-{new_id()}",
        },
    )
    assert activated.status_code == 200, activated.text
    with app.state.session_factory() as session:
        version = session.get(PolicyVersion, policy_version_id)
        assert version is not None
        head = session.scalars(
            sa.select(EnvironmentPolicyHead).where(
                EnvironmentPolicyHead.org_id == org_id,
                EnvironmentPolicyHead.project_id == project_id,
                EnvironmentPolicyHead.environment_id == environment_id,
            )
        ).one()
        envelope = dict(version.canonical_envelope)
    policy_scope = ReceiptTrustScope(org_id, project_id, environment_id, POLICY_ENVELOPE_PURPOSE)
    policy_signer = local_policy_registry_issuer().signer_for_scope(policy_scope, trust_epoch=1)
    return {
        "org_id": org_id,
        "project_id": project_id,
        "environment_id": environment_id,
        "gate_id": gate_id,
        "identity_id": identity_id,
        "credential_id": credential_id,
        "descriptor": descriptor,
        "workload_key": workload_key,
        "policy_version_id": policy_version_id,
        "policy_envelope": envelope,
        "policy_signer": policy_signer,
        "attestation_issuer": effective_attestation_issuer,
        "attestation_signer": attestation_signer,
        "attestation_scope": attestation_scope,
        "policy_head_id": head.id,
        "activation_receipt_id": str(activated.json()["receipt_id"]),
        "publish_receipt_id": str(publish_payload["receipt_id"]),
    }


def _signed_get(
    client: TestClient,
    seeded: dict[str, Any],
    *,
    query: str = "",
    body: bytes = b"",
    headers: dict[str, str] | None = None,
) -> Any:
    path = POLICY_SYNC_PATH.format(identity_id=seeded["identity_id"])
    return client.request(
        "GET",
        path + (f"?{query}" if query else ""),
        content=body,
        headers={**_signed_headers(seeded, query=query, body=body), **(headers or {})},
    )


def _signed_headers(
    seeded: dict[str, Any], *, query: str = "", body: bytes = b""
) -> dict[str, str]:
    path = POLICY_SYNC_PATH.format(identity_id=seeded["identity_id"])
    descriptor = cast(RuntimeIdentityDescriptor, seeded["descriptor"])
    workload_key = cast(InMemoryEd25519WorkloadKeyProvider, seeded["workload_key"])
    timestamp = _timestamp(utcnow())
    nonce = f"policy-sync-{new_id()}"
    signing_bytes = canonical_signed_runtime_request_bytes(
        method="GET",
        path=path,
        query=query,
        body=body,
        timestamp=timestamp,
        nonce=nonce,
        key_id=workload_key.key_id,
        identity_id=descriptor.runtime_identity_id,
        credential_id=descriptor.credential_id,
        credential_generation=descriptor.credential_generation,
        idempotency_key=None,
        audience=RUNTIME_ENROLLMENT_AUTHORITY,
    )
    return {
        "X-ACGS-Runtime-Identity-ID": descriptor.runtime_identity_id,
        "X-ACGS-Runtime-Key-ID": workload_key.key_id,
        "X-ACGS-Runtime-Audience": RUNTIME_ENROLLMENT_AUTHORITY,
        "X-ACGS-Runtime-Credential-ID": descriptor.credential_id,
        "X-ACGS-Runtime-Credential-Generation": str(descriptor.credential_generation),
        "X-ACGS-Runtime-Timestamp": timestamp,
        "X-ACGS-Runtime-Nonce": nonce,
        "X-ACGS-Runtime-Body-Sha256": sha256_bytes(body),
        "X-ACGS-Runtime-Signature": workload_key.sign(signing_bytes),
    }


def _read_path_counts(app: Any, org_id: str) -> dict[str, int]:
    with app.state.session_factory() as session:
        models = (
            ManagedDecisionReceipt,
            ManagedGovernanceEvent,
            ManagedOutboxMessage,
            ManagedReceiptConsumption,
            RuntimeRequestNonce,
        )
        return {
            model.__tablename__: cast(
                int,
                session.scalar(
                    sa.select(sa.func.count()).select_from(model).where(model.org_id == org_id)
                ),
            )
            for model in models
        }


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _timestamp(value: Any) -> str:
    return value.isoformat().replace("+00:00", "Z")
