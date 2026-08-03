from __future__ import annotations

import copy
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier
from typing import Any, cast

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from gove_zone.consumption import ReceiptConsumptionLedger
from gove_zone.decision import Decision, canonical_json, sha256_json
from gove_zone.errors import ReceiptValidationError
from gove_zone.gateway import ScopedDecisionReceiptConfig, UniversalGateway
from gove_zone.policy_sync import (
    POLICY_ENVELOPE_PURPOSE,
    POLICY_SYNC_ATTESTATION_PURPOSE,
    AtomicJsonPolicyCache,
    PolicySyncSnapshot,
    SyncedRuleSetPolicy,
)
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import Validator
from gove_zone.runtime_identity import (
    GateScope,
    InMemoryEd25519WorkloadKeyProvider,
    RuntimeIdentityDescriptor,
    canonical_signed_runtime_request_bytes,
    public_key_thumbprint,
    sha256_bytes,
)
from gove_zone.signing import Ed25519Signer
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope
from gove_zone.wiring_attestation import produce_wiring_attestation
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

import acgs_control_plane.runtime_enrollment as runtime_enrollment_module
import acgs_control_plane.runtime_reports as runtime_reports_module
from acgs_control_plane.managed_mutations import ManagedMutationUnitOfWork
from acgs_control_plane.models import (
    Environment,
    EnvironmentPolicyHead,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    ManagedTrustKey,
    PolicyVersion,
    Project,
    RuntimeCredentialGeneration,
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
from acgs_control_plane.runtime_enrollment import (
    RUNTIME_ENROLLMENT_AUTHORITY,
    RuntimeEnrollmentProviderUnavailable,
    _sealed_terminal_response_payload,
    _verified_stored_terminal_payload,
)
from acgs_control_plane.runtime_lineage_schema import SQLITE_RUNTIME_LINEAGE_OBJECTS
from acgs_control_plane.schemas import RuntimeReportRequest
from acgs_control_plane.tenant_bootstrap import BOOTSTRAP_IDEMPOTENCY_HEADER
from acgs_control_plane.trust import (
    ManagedTrustLifecycleService,
    SqlReceiptTrustRegistry,
    public_spki_der_from_signer,
)
from tests.test_policy_sync_routes import _seed_runtime_policy_sync, _signed_get


def test_fleet_registration_is_not_online_or_proven_wired(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    app = cast(Any, client.app)
    now = utcnow()
    project_id = f"project-{new_id()}"
    environment_id = f"environment-{new_id()}"
    gate_id = f"gate-{new_id()}"
    identity_id = f"runtime-{new_id()}"
    credential_id = f"credential-{new_id()}"
    with app.state.session_factory.begin() as session:
        session.add_all(
            [
                Project(id=project_id, org_id=org["org_id"], slug=new_id(), name="Fleet"),
                Environment(
                    id=environment_id,
                    org_id=org["org_id"],
                    project_id=project_id,
                    slug="production",
                    name="Production",
                ),
            ]
        )
        session.flush()
        session.add_all(
            [
                RuntimeIdentityGate(
                    id=gate_id,
                    org_id=org["org_id"],
                    project_id=project_id,
                    environment_id=environment_id,
                    status="active",
                ),
                RuntimeIdentity(
                    id=identity_id,
                    org_id=org["org_id"],
                    project_id=project_id,
                    environment_id=environment_id,
                    gate_id=gate_id,
                    name="Runtime",
                    actor=f"runtime:{identity_id}",
                    workload_key_id="workload-key",
                    public_key="A" * 43,
                    public_key_thumbprint="a" * 64,
                    descriptor={"schema_version": "acgs.runtime-identity/v1"},
                    status="active",
                    current_generation=1,
                ),
                RuntimeCredentialGeneration(
                    id=credential_id,
                    org_id=org["org_id"],
                    project_id=project_id,
                    environment_id=environment_id,
                    identity_id=identity_id,
                    generation=1,
                    workload_key_id="workload-key",
                    public_key_thumbprint="a" * 64,
                    not_before=now - timedelta(minutes=1),
                    not_after=now + timedelta(hours=1),
                    status="active",
                    descriptor={"schema_version": "acgs.runtime-identity/v1"},
                ),
            ]
        )

    response = client.get(
        f"/orgs/{org['org_id']}/projects/{project_id}/environments/{environment_id}/fleet",
        headers=admin_headers,
    )

    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "private, no-store"
    [runtime] = response.json()["runtimes"]
    assert runtime["identity_id"] == identity_id
    assert runtime["registered"]["available"] is True
    assert runtime["registered"]["reason"] == "active_registration"
    assert runtime["online"]["available"] is False
    assert runtime["online"]["reason"] == "no_current_accepted_runtime_report"
    assert runtime["policy_current"]["available"] is False
    assert runtime["proven_wired"]["available"] is False
    assert runtime["proven_wired"]["reason"] == "no_current_observed_wiring_attestation"
    assert runtime["evidence_current"] == {
        "available": False,
        "reason": "accepted_evidence_ingestion_not_implemented",
        "observed_at": None,
    }

    with app.state.session_factory.begin() as session:
        identity = session.get(RuntimeIdentity, identity_id)
        assert identity is not None
        identity.status = "revoked"
        identity.revoked_at = utcnow()
    revoked = client.get(
        f"/orgs/{org['org_id']}/projects/{project_id}/environments/{environment_id}/fleet",
        headers=admin_headers,
    ).json()["runtimes"][0]
    assert revoked["registered"] == {
        "available": True,
        "reason": "durable_registration_revoked",
        "observed_at": revoked["registered"]["observed_at"],
    }
    for state in ("online", "policy_current", "proven_wired", "evidence_current"):
        assert revoked[state]["available"] is False
    for state in ("online", "policy_current"):
        assert revoked[state]["reason"] == "registration_revoked"


def test_report_and_attestation_models_are_append_only_projections() -> None:
    report_columns = set(RuntimeReport.__table__.columns.keys())
    attestation_columns = set(RuntimeWiringAttestation.__table__.columns.keys())

    assert {"status", "green", "is_current"}.isdisjoint(report_columns | attestation_columns)
    assert {
        "org_id",
        "project_id",
        "environment_id",
        "gate_id",
        "identity_id",
        "credential_id",
        "credential_generation",
        "policy_version_id",
        "policy_head_generation",
        "policy_snapshot_hash",
        "policy_provenance_hash",
        "policy_issued_at",
        "policy_revocation_checked_at",
        "policy_fresh_until",
        "policy_expires_at",
        "sequence",
        "nonce",
        "report_hash",
    } <= report_columns
    assert {
        "report_kind",
        "artifact",
        "attestation_hash",
        "assurance_class",
        "evidence_kind",
    } <= (attestation_columns)
    assert any(
        set(constraint.columns.keys()) == {"report_id"}
        for constraint in cast(sa.Table, RuntimeWiringAttestation.__table__).constraints
        if isinstance(constraint, sa.UniqueConstraint)
    )


def test_valid_status_report_is_governed_and_exactly_idempotent(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    path, raw_body, headers = _signed_status_request(seeded)
    before = _governed_counts(app, seeded["org_id"])
    before_attempts = _report_attempt_count(app, seeded["org_id"])

    first = client.post(path, content=raw_body, headers=headers)
    with app.state.session_factory() as session:
        report = session.scalars(sa.select(RuntimeReport)).one()
        identity = session.get(RuntimeIdentity, report.identity_id)
        assert identity is not None
        app.state.runtime_report_service.validate_stored_report_lineage(
            session, report=report, identity=identity
        )
    replay = client.post(path, content=raw_body, headers=headers)

    assert first.status_code == 201, first.text
    assert replay.status_code == 201, replay.text
    assert replay.json() == first.json()
    after = _governed_counts(app, seeded["org_id"])
    assert after == {name: count + 1 for name, count in before.items()}
    assert _report_attempt_count(app, seeded["org_id"]) == before_attempts + 1
    with app.state.session_factory() as session:
        assert session.scalar(sa.select(sa.func.count()).select_from(RuntimeReport)) == 1
        assert session.scalar(sa.select(sa.func.count()).select_from(RuntimeWiringAttestation)) == 0
        assert (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeRequestNonce)
                .where(RuntimeRequestNonce.purpose == "runtime-report-http")
            )
            == 1
        )


def test_batch_lineage_validation_deduplicates_same_report(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    path, raw_body, headers = _signed_status_request(seeded)
    accepted = client.post(path, content=raw_body, headers=headers)
    assert accepted.status_code == 201, accepted.text
    service = app.state.runtime_report_service
    original = type(service).validate_stored_report_lineage
    calls = 0

    def counted(self: Any, session: Any, **kwargs: Any) -> None:
        nonlocal calls
        calls += 1
        original(self, session, **kwargs)

    monkeypatch.setattr(type(service), "validate_stored_report_lineage", counted)
    with app.state.session_factory() as session:
        report = session.get(RuntimeReport, accepted.json()["report_id"])
        assert report is not None
        identity = session.get(RuntimeIdentity, report.identity_id)
        assert identity is not None
        results = service.validate_stored_report_lineages(
            session,
            reports=[(report, identity), (report, identity)],
            now=utcnow(),
        )

    assert results == {accepted.json()["report_id"]: True}
    assert calls == 1


def test_batch_lineage_validation_has_fixed_select_budget_for_long_chain(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    for sequence in range(1, 101):
        path, body, headers = _signed_status_request(
            seeded, payload=_status_payload(seeded, sequence=sequence)
        )
        accepted = client.post(path, content=body, headers=headers)
        assert accepted.status_code == 201, accepted.text

    def select_count(pairs: list[tuple[RuntimeReport, RuntimeIdentity]]) -> int:
        statements: list[str] = []

        def capture(
            _connection: Any,
            _cursor: Any,
            statement: str,
            _parameters: Any,
            _context: Any,
            _executemany: Any,
        ) -> None:
            statements.append(statement)

        sa.event.listen(app.state.engine, "before_cursor_execute", capture)
        try:
            app.state.runtime_report_service.validate_stored_report_lineages(
                session, reports=pairs, now=utcnow()
            )
        finally:
            sa.event.remove(app.state.engine, "before_cursor_execute", capture)
        selects = [
            statement for statement in statements if statement.lstrip().upper().startswith("SELECT")
        ]
        assert all("FOR UPDATE" not in statement.upper() for statement in statements)
        return len(selects)

    with app.state.session_factory() as session:
        identity = session.get(RuntimeIdentity, seeded["identity_id"])
        assert identity is not None
        reports = list(
            session.scalars(
                sa.select(RuntimeReport)
                .where(RuntimeReport.identity_id == identity.id)
                .order_by(RuntimeReport.sequence)
            )
        )
        assert len(reports) == 100
        one_count = select_count([(reports[-1], identity)])
        long_chain_count = select_count([(report, identity) for report in reports])
    persisted_seeds = [seeded]
    for index in range(1, 100):
        persisted_seed = _add_report_identity(
            client,
            seeded,
            runtime_descriptor_signer,
            suffix=f"fleet-{index}",
        )
        for sequence in (1, 2):
            path, body, headers = _signed_status_request(
                persisted_seed,
                payload=_status_payload(persisted_seed, sequence=sequence),
            )
            accepted = client.post(path, content=body, headers=headers)
            assert accepted.status_code == 201, accepted.text
        persisted_seeds.append(persisted_seed)

    with app.state.session_factory() as session:
        persisted_ids = [item["identity_id"] for item in persisted_seeds]
        persisted_identities = {
            identity.id: identity
            for identity in session.scalars(
                sa.select(RuntimeIdentity).where(RuntimeIdentity.id.in_(persisted_ids))
            )
        }
        persisted_reports = list(
            session.scalars(
                sa.select(RuntimeReport)
                .where(RuntimeReport.identity_id.in_(persisted_ids))
                .order_by(RuntimeReport.identity_id, RuntimeReport.sequence.desc())
            )
        )
        latest_two_by_identity: dict[str, list[RuntimeReport]] = {}
        for report in persisted_reports:
            selected = latest_two_by_identity.setdefault(report.identity_id, [])
            if len(selected) < 2:
                selected.append(report)
        persisted_page = [
            (report, persisted_identities[identity_id])
            for identity_id in persisted_ids
            for report in latest_two_by_identity[identity_id]
        ]
        page_count = select_count(persisted_page)

    assert len({report.id for report, _identity in persisted_page}) == 200
    assert len({identity.id for _report, identity in persisted_page}) == 100
    assert one_count == long_chain_count == page_count == 13


def test_fleet_lineage_rejects_balanced_nonce_and_idempotency_substitution(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    accepted: list[dict[str, Any]] = []
    for sequence in (1, 2):
        path, body, headers = _signed_status_request(
            seeded, payload=_status_payload(seeded, sequence=sequence)
        )
        response = client.post(path, content=body, headers=headers)
        assert response.status_code == 201, response.text
        accepted.append(response.json())

    with app.state.session_factory.begin() as session:
        reports = list(
            session.scalars(
                sa.select(RuntimeReport)
                .where(RuntimeReport.identity_id == seeded["identity_id"])
                .order_by(RuntimeReport.sequence)
            )
        )
        earlier, latest = reports
        earlier_idempotency = session.scalars(
            sa.select(RuntimeOperationIdempotency).where(
                RuntimeOperationIdempotency.receipt_id == earlier.receipt_id
            )
        ).one()
        latest_idempotency = session.scalars(
            sa.select(RuntimeOperationIdempotency).where(
                RuntimeOperationIdempotency.receipt_id == latest.receipt_id
            )
        ).one()
        earlier_nonce = session.scalars(
            sa.select(RuntimeRequestNonce).where(RuntimeRequestNonce.nonce == earlier.nonce)
        ).one()
        latest_nonce = session.scalars(
            sa.select(RuntimeRequestNonce).where(RuntimeRequestNonce.nonce == latest.nonce)
        ).one()
        session.delete(latest_idempotency)
        session.delete(latest_nonce)
        session.flush()
        earlier_idempotency.receipt_id = latest.receipt_id
        earlier_idempotency.request_hash = latest_idempotency.request_hash
        earlier_idempotency.idempotency_key_hash = latest_idempotency.idempotency_key_hash
        earlier_nonce.nonce = latest.nonce
        earlier_nonce.receipt_id = latest.receipt_id
        earlier_nonce.request_hash = latest_idempotency.request_hash
        earlier_nonce.idempotency_key_hash = latest_idempotency.idempotency_key_hash
        session.flush()

    with app.state.session_factory() as session:
        latest = session.get(RuntimeReport, accepted[-1]["report_id"])
        identity = session.get(RuntimeIdentity, seeded["identity_id"])
        assert latest is not None and identity is not None
        result = app.state.runtime_report_service.validate_stored_report_lineages(
            session, reports=[(latest, identity)], now=utcnow()
        )
    assert result == {accepted[-1]["report_id"]: False}


def test_historical_reconciliation_detects_old_terminal_lineage_tamper(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    for sequence in range(1, 4):
        path, body, headers = _signed_status_request(
            seeded, payload=_status_payload(seeded, sequence=sequence)
        )
        assert client.post(path, content=body, headers=headers).status_code == 201
    with app.state.session_factory.begin() as session:
        oldest = session.scalars(
            sa.select(RuntimeReport)
            .where(RuntimeReport.identity_id == seeded["identity_id"])
            .order_by(RuntimeReport.sequence)
        ).first()
        assert oldest is not None
        session.execute(
            sa.delete(RuntimeRequestNonce).where(
                RuntimeRequestNonce.identity_id == seeded["identity_id"],
                RuntimeRequestNonce.nonce == oldest.nonce,
            )
        )
    with app.state.session_factory() as session:
        identity = session.get(RuntimeIdentity, seeded["identity_id"])
        assert identity is not None
        assert (
            app.state.runtime_report_service.reconcile_stored_report_history(
                session, identity=identity, now=utcnow()
            )
            is False
        )


def test_concurrent_identical_status_reports_converge_on_one_terminal_result(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    path, raw_body, headers = _signed_status_request(seeded)
    before = _report_path_counts(app, seeded["org_id"])
    before_attempts = _report_attempt_count(app, seeded["org_id"])
    barrier = Barrier(2)

    def submit() -> Any:
        barrier.wait()
        return client.post(path, content=raw_body, headers=headers)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (executor.submit(submit), executor.submit(submit))
        responses = [future.result() for future in futures]

    assert [response.status_code for response in responses] == [201, 201]
    assert responses[0].json() == responses[1].json()
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
    for name in ("attestations", "challenges"):
        assert after[name] == before[name]
    assert _report_attempt_count(app, seeded["org_id"]) == before_attempts + 1


@pytest.mark.parametrize(
    ("target", "model"),
    (
        ("receipt", ManagedDecisionReceipt),
        ("consumption", ManagedReceiptConsumption),
        ("event", ManagedGovernanceEvent),
        ("outbox", ManagedOutboxMessage),
        ("idempotency", RuntimeOperationIdempotency),
        ("nonce", RuntimeRequestNonce),
    ),
)
def test_report_replay_fails_closed_when_terminal_lineage_is_tampered_or_deleted(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    target: str,
    model: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    path, raw_body, headers = _signed_status_request(seeded)
    accepted = client.post(path, content=raw_body, headers=headers)
    assert accepted.status_code == 201, accepted.text

    with app.state.session_factory.begin() as session:
        if target == "receipt":
            session.execute(
                sa.update(model)
                .where(model.receipt_id == accepted.json()["receipt_id"])
                .values(projection={})
            )
        elif target == "event":
            session.execute(
                sa.update(model)
                .where(model.org_id == seeded["org_id"])
                .values(payload_digest="0" * 64)
            )
        elif target == "idempotency":
            session.execute(
                sa.update(model)
                .where(
                    model.org_id == seeded["org_id"],
                    model.operation == "report",
                )
                .values(response={"tampered": True})
            )
        else:
            session.execute(sa.delete(model).where(model.org_id == seeded["org_id"]))

    replay = client.post(path, content=raw_body, headers=headers)

    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"


@pytest.mark.parametrize(
    ("decision", "expected_status"),
    ((Decision.DENY, 403), (Decision.ESCALATE, 202)),
)
def test_non_executable_report_decisions_are_exactly_sealed_and_replayed(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    decision: Decision,
    expected_status: int,
) -> None:
    seeded = _seed_report_scope(
        client,
        org,
        runtime_descriptor_signer,
        report_decision=decision,
    )
    app = cast(Any, client.app)
    path, raw_body, headers = _signed_status_request(seeded)
    before = _report_path_counts(app, seeded["org_id"])

    first = client.post(path, content=raw_body, headers=headers)
    replay = client.post(path, content=raw_body, headers=headers)

    assert first.status_code == expected_status, first.text
    assert replay.status_code == expected_status, replay.text
    first_terminal = {key: value for key, value in first.json().items() if key != "request_id"}
    replay_terminal = {key: value for key, value in replay.json().items() if key != "request_id"}
    assert replay_terminal == first_terminal
    after = _report_path_counts(app, seeded["org_id"])
    for name in ("receipts", "events", "outbox", "idempotency"):
        assert after[name] == before[name] + 1
    for name in ("consumptions", "reports", "attestations", "nonces"):
        assert after[name] == before[name]


@pytest.mark.parametrize("provider_error", [RuntimeError, ValueError, OSError])
@pytest.mark.parametrize("decision", [Decision.DENY, Decision.ESCALATE])
def test_non_executable_terminal_sealer_outage_is_redacted_and_atomic(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
    provider_error: type[Exception],
    decision: Decision,
) -> None:
    seeded = _seed_report_scope(
        client,
        org,
        runtime_descriptor_signer,
        report_decision=decision,
    )
    app = cast(Any, client.app)
    path, raw_body, headers = _signed_status_request(seeded)
    before = _report_path_counts(app, seeded["org_id"])
    before_attempts = _report_attempt_count(app, seeded["org_id"])

    def unavailable_terminal_sealer(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        try:
            raise provider_error("secret refusal sealer endpoint kms://terminal-key")
        except Exception as exc:
            raise RuntimeEnrollmentProviderUnavailable from exc

    monkeypatch.setattr(
        runtime_enrollment_module,
        "_sealed_terminal_response_payload",
        unavailable_terminal_sealer,
    )

    response = client.post(path, content=raw_body, headers=headers)

    assert response.status_code == 503, response.text
    assert response.json() == {
        "code": "RUNTIME_REPORT_PROVIDER_UNAVAILABLE",
        "status": "service_unavailable",
        "detail": "runtime report cryptographic provider is unavailable",
    }
    assert "terminal-key" not in response.text
    assert _report_path_counts(app, seeded["org_id"]) == before
    assert _report_attempt_count(app, seeded["org_id"]) == before_attempts


def test_report_sequence_must_be_the_exact_next_value(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    payload = _status_payload(seeded, sequence=2)
    path, raw_body, headers = _signed_status_request(seeded, payload=payload)
    before = _report_path_counts(app, seeded["org_id"])

    rejected = client.post(path, content=raw_body, headers=headers)

    assert rejected.status_code == 409, rejected.text
    assert _report_path_counts(app, seeded["org_id"]) == before


def test_report_head_prevents_latest_deletion_and_lower_sequence_reuse(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    path, raw_body, headers = _signed_status_request(seeded)
    accepted = client.post(path, content=raw_body, headers=headers)
    assert accepted.status_code == 201, accepted.text
    after_accept = _report_path_counts(app, seeded["org_id"])

    with pytest.raises(IntegrityError):
        with app.state.session_factory.begin() as session:
            session.execute(
                sa.delete(RuntimeReport).where(RuntimeReport.id == accepted.json()["report_id"])
            )

    retry_path, retry_body, retry_headers = _signed_status_request(seeded)
    reused = client.post(retry_path, content=retry_body, headers=retry_headers)
    assert reused.status_code == 409, reused.text
    assert _report_path_counts(app, seeded["org_id"]) == after_accept


def test_report_head_rejects_rollback_anchor_update_and_delete(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    first_path, first_body, first_headers = _signed_status_request(seeded)
    first = client.post(first_path, content=first_body, headers=first_headers)
    assert first.status_code == 201, first.text
    second_path, second_body, second_headers = _signed_status_request(
        seeded, payload=_status_payload(seeded, sequence=2)
    )
    second = client.post(second_path, content=second_body, headers=second_headers)
    assert second.status_code == 201, second.text

    with pytest.raises(IntegrityError, match="must be non-decreasing"):
        with app.state.session_factory.begin() as session:
            session.execute(
                sa.update(RuntimeReportHead)
                .where(RuntimeReportHead.identity_id == seeded["identity_id"])
                .values(
                    last_sequence=1,
                    latest_report_id=first.json()["report_id"],
                )
            )


def test_wiring_attestations_reject_update_and_delete_in_database(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    tmp_path: Path,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    accepted, _request = _submit_wiring_report(
        client, app=app, seeded=seeded, tmp_path=tmp_path, sequence=1
    )
    report_id = accepted.json()["report_id"]

    with pytest.raises(IntegrityError, match="runtime_wiring_attestations are immutable"):
        with app.state.session_factory.begin() as session:
            session.execute(
                sa.update(RuntimeWiringAttestation)
                .where(RuntimeWiringAttestation.report_id == report_id)
                .values(suite_hash="0" * 64)
            )
    with pytest.raises(IntegrityError, match="runtime_wiring_attestations are immutable"):
        with app.state.session_factory.begin() as session:
            session.execute(
                sa.delete(RuntimeWiringAttestation).where(
                    RuntimeWiringAttestation.report_id == report_id
                )
            )


def test_wiring_challenge_consumptions_reject_update_and_delete_in_database(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    tmp_path: Path,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    accepted, _request = _submit_wiring_report(
        client, app=app, seeded=seeded, tmp_path=tmp_path, sequence=1
    )
    report_id = accepted.json()["report_id"]
    with app.state.session_factory() as session:
        accepted_lineage = session.scalars(
            sa.select(RuntimeWiringChallengeConsumption).where(
                RuntimeWiringChallengeConsumption.report_id == report_id
            )
        ).one()
        accepted_id = accepted_lineage.id
        accepted_namespace_digest = accepted_lineage.namespace_digest

    with pytest.raises(IntegrityError, match="runtime_wiring_challenge_consumptions are immutable"):
        with app.state.session_factory.begin() as session:
            session.execute(
                sa.update(RuntimeWiringChallengeConsumption)
                .where(RuntimeWiringChallengeConsumption.report_id == report_id)
                .values(namespace_digest="0" * 64)
            )
    with pytest.raises(IntegrityError, match="runtime_wiring_challenge_consumptions are immutable"):
        with app.state.session_factory.begin() as session:
            session.execute(
                sa.delete(RuntimeWiringChallengeConsumption).where(
                    RuntimeWiringChallengeConsumption.report_id == report_id
                )
            )

    with app.state.session_factory() as session:
        intact_lineage = session.scalars(
            sa.select(RuntimeWiringChallengeConsumption).where(
                RuntimeWiringChallengeConsumption.report_id == report_id
            )
        ).one()
        assert intact_lineage.id == accepted_id
        assert intact_lineage.namespace_digest == accepted_namespace_digest


@pytest.mark.parametrize("out_of_bounds", [0, 9_007_199_254_740_992])
def test_runtime_lineage_sequences_reject_non_ijson_direct_sql_writes(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    tmp_path: Path,
    out_of_bounds: int,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    accepted, _request = _submit_wiring_report(
        client, app=app, seeded=seeded, tmp_path=tmp_path, sequence=1
    )
    assert accepted.status_code == 201, accepted.text

    with pytest.raises(IntegrityError):
        with app.state.session_factory.begin() as session:
            original = (
                session.execute(
                    sa.select(RuntimeReport.__table__).where(
                        RuntimeReport.id == accepted.json()["report_id"]
                    )
                )
                .mappings()
                .one()
            )
            clone = dict(original)
            clone.update(
                id=new_id(),
                sequence=out_of_bounds,
                nonce=f"out-of-bounds-{out_of_bounds}",
                receipt_id=f"out-of-bounds-receipt-{out_of_bounds}",
            )
            session.execute(sa.insert(RuntimeReport).values(**clone))
    with pytest.raises(IntegrityError):
        with app.state.session_factory.begin() as session:
            session.execute(
                sa.update(RuntimeReportHead)
                .where(RuntimeReportHead.identity_id == seeded["identity_id"])
                .values(last_sequence=out_of_bounds)
            )
    with pytest.raises(IntegrityError):
        with app.state.session_factory.begin() as session:
            session.execute(
                sa.update(RuntimeReportHead)
                .where(RuntimeReportHead.identity_id == seeded["identity_id"])
                .values(latest_wiring_sequence=out_of_bounds)
            )
    with pytest.raises(IntegrityError):
        with app.state.session_factory.begin() as session:
            session.execute(
                sa.update(RuntimeWiringChallengeConsumption)
                .where(RuntimeWiringChallengeConsumption.report_id == accepted.json()["report_id"])
                .values(sequence=out_of_bounds)
            )


def test_wiring_head_exact_sequence_fk_allows_status_advancement_but_rejects_mismatch(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    tmp_path: Path,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    wiring, _request = _submit_wiring_report(
        client, app=app, seeded=seeded, tmp_path=tmp_path, sequence=1
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

    with pytest.raises(IntegrityError):
        with app.state.session_factory.begin() as session:
            session.execute(
                sa.update(RuntimeReportHead)
                .where(RuntimeReportHead.identity_id == seeded["identity_id"])
                .values(latest_wiring_sequence=2)
            )
    with pytest.raises(IntegrityError):
        with app.state.session_factory.begin() as session:
            session.execute(
                sa.update(RuntimeWiringChallengeConsumption)
                .where(RuntimeWiringChallengeConsumption.report_id == wiring.json()["report_id"])
                .values(sequence=2)
            )
    with pytest.raises(IntegrityError, match="cannot be deleted"):
        with app.state.session_factory.begin() as session:
            session.execute(
                sa.delete(RuntimeReportHead).where(
                    RuntimeReportHead.identity_id == seeded["identity_id"]
                )
            )


def test_report_sequence_exhaustion_is_explicit_at_ijson_maximum(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    path, raw_body, headers = _signed_status_request(seeded)
    accepted = client.post(path, content=raw_body, headers=headers)
    assert accepted.status_code == 201, accepted.text
    monkeypatch.setattr(runtime_reports_module, "IJSON_MAX_SAFE_INTEGER", 1)

    payload = _status_payload(seeded, sequence=2)
    exhausted_path, exhausted_body, exhausted_headers = _signed_status_request(
        seeded, payload=payload
    )
    exhausted = client.post(exhausted_path, content=exhausted_body, headers=exhausted_headers)
    assert exhausted.status_code == 409, exhausted.text
    assert exhausted.json()["code"] == "SEQUENCE_EXHAUSTED"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("actor", "runtime:tampered"),
        ("policy_provenance_hash", "0" * 64),
        ("runtime_build_digest", "f" * 64),
        ("request_signature", "tampered-signature"),
    ),
)
def test_report_scalar_update_is_rejected_by_database_immutability(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    field: str,
    value: str,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    path, raw_body, headers = _signed_status_request(seeded)
    accepted = client.post(path, content=raw_body, headers=headers)
    assert accepted.status_code == 201, accepted.text
    with pytest.raises(IntegrityError, match="runtime_reports are immutable"):
        with app.state.session_factory.begin() as session:
            session.execute(
                sa.update(RuntimeReport)
                .where(RuntimeReport.id == accepted.json()["report_id"])
                .values({field: value})
            )


@pytest.mark.parametrize(
    "constraint_name",
    (
        "uq_runtime_reports_identity_sequence",
        "uq_runtime_wiring_challenge_identity_nonce",
        "uq_runtime_wiring_challenge_report",
        "unexpected_transient_integrity_failure",
    ),
)
def test_only_named_report_conflicts_receive_semantic_conflict_mapping(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
    constraint_name: str,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    path, raw_body, headers = _signed_status_request(seeded)
    before = _report_path_counts(app, seeded["org_id"])

    class Diagnostic:
        def __init__(self, name: str) -> None:
            self.constraint_name = name

    class DatabaseFailure(Exception):
        def __init__(self, name: str) -> None:
            self.diag = Diagnostic(name)
            super().__init__("redacted database failure")

    def fail_execute(_self: Any, **_kwargs: Any) -> Any:
        raise IntegrityError("INSERT", {}, DatabaseFailure(constraint_name))

    monkeypatch.setattr(ManagedMutationUnitOfWork, "execute", fail_execute)
    rejected = client.post(path, content=raw_body, headers=headers)

    assert rejected.status_code == 503, rejected.text
    assert rejected.json()["code"] == "MUTATION_INVENTORY_DRIFT"
    assert _report_path_counts(app, seeded["org_id"]) == before


@pytest.mark.parametrize(
    "raw_body",
    (
        b'{"kind":"status","kind":"wiring"}',
        b'{"sequence":NaN}',
        b'{"sequence":9007199254740992}',
        b'{"value":"\\ud800"}',
        b"\xff",
        b"\xef\xbb\xbf" + b'{"sequence":1}',
        '{"sequence":1}'.encode("utf-16"),
        '{"sequence":1}'.encode("utf-32"),
    ),
)
def test_runtime_report_raw_ijson_rejection_precedes_auth_and_persistence(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    raw_body: bytes,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    before = _report_path_counts(app, seeded["org_id"])
    path = f"/v1/runtime-identities/{seeded['identity_id']}/reports"

    rejected = client.post(path, content=raw_body, headers={"Content-Type": "application/json"})

    assert rejected.status_code == 400, rejected.text
    assert rejected.json()["code"] == "request_body_invalid_ijson"
    assert _report_path_counts(app, seeded["org_id"]) == before


@pytest.mark.parametrize(
    "raw_body",
    (
        b"[" * 65 + b"null" + b"]" * 65,
        b"[" * 2_000 + b"null" + b"]" * 2_000,
        b'{"items":[' + b",".join([b"null"] * 10_001) + b"]}",
    ),
)
def test_runtime_report_structural_limits_precede_auth_and_persistence(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    raw_body: bytes,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    before = _report_path_counts(app, seeded["org_id"])
    path = f"/v1/runtime-identities/{seeded['identity_id']}/reports"

    rejected = client.post(path, content=raw_body, headers={"Content-Type": "application/json"})

    assert rejected.status_code == 400, rejected.text
    assert rejected.json()["code"] == "request_body_invalid_ijson"
    assert _report_path_counts(app, seeded["org_id"]) == before


@pytest.mark.parametrize(
    ("field_path", "invalid_value"),
    (
        (("sequence",), True),
        (("sequence",), "1"),
        (("expires_at",), 1),
        (("policy_head_generation",), True),
        (("policy_snapshot", "credential_generation"), "1"),
        (("policy_snapshot", "issued_at"), 1),
    ),
)
def test_runtime_report_exact_wire_types_precede_auth_and_persistence(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    field_path: tuple[str, ...],
    invalid_value: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    snapshot_response = _signed_get(client, seeded)
    assert snapshot_response.status_code == 200, snapshot_response.text
    payload: dict[str, Any] = {
        "kind": "status",
        "sequence": 1,
        "expires_at": (utcnow() + timedelta(minutes=5)).isoformat(),
        "policy_version_id": seeded["policy_version_id"],
        "policy_head_generation": seeded["policy_head_generation"],
        "policy_content_hash": seeded["policy_content_hash"],
        "runtime_build_digest": "b" * 64,
        "configuration_digest": "c" * 64,
        "policy_snapshot": snapshot_response.json(),
    }
    target = payload
    for field_name in field_path[:-1]:
        target = cast(dict[str, Any], target[field_name])
    target[field_path[-1]] = invalid_value
    app = cast(Any, client.app)
    before = _report_path_counts(app, seeded["org_id"])
    path = f"/v1/runtime-identities/{seeded['identity_id']}/reports"

    rejected = client.post(
        path,
        content=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

    assert rejected.status_code == 400, rejected.text
    assert rejected.json()["code"] == "request_body_invalid_ijson"
    assert _report_path_counts(app, seeded["org_id"]) == before


def test_oversized_runtime_report_is_rejected_before_auth_and_persistence(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    before = _report_path_counts(app, seeded["org_id"])
    path = f"/v1/runtime-identities/{seeded['identity_id']}/reports"

    rejected = client.post(
        path,
        content=b"{" + b" " * (1024 * 1024),
        headers={"Content-Type": "application/json"},
    )

    assert rejected.status_code == 413, rejected.text
    assert rejected.json()["code"] == "request_body_too_large"
    assert _report_path_counts(app, seeded["org_id"]) == before


def test_database_rejects_cross_bound_report_and_attestation_rows(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    path, raw_body, headers = _signed_status_request(seeded)
    accepted = client.post(path, content=raw_body, headers=headers)
    assert accepted.status_code == 201, accepted.text

    with app.state.session_factory() as session:
        report = session.get(RuntimeReport, accepted.json()["report_id"])
        assert report is not None
        base = {
            column.name: getattr(report, column.name)
            for column in RuntimeReport.__table__.columns
            if column.name != "created_at"
        }

    for offset, mismatch in enumerate(
        (
            {"gate_id": f"wrong-{new_id()}"},
            {"credential_id": f"wrong-{new_id()}"},
            {"receipt_id": f"wrong-{new_id()}"},
        ),
        start=1,
    ):
        values = {
            **base,
            "id": new_id(),
            "sequence": int(base["sequence"]) + offset,
            "nonce": f"db-mismatch-{new_id()}",
            **mismatch,
        }
        with pytest.raises(IntegrityError):
            with app.state.session_factory.begin() as session:
                session.execute(sa.insert(RuntimeReport).values(**values))

    with pytest.raises(IntegrityError):
        with app.state.session_factory.begin() as session:
            session.add(
                RuntimeWiringAttestation(
                    id=new_id(),
                    org_id=str(base["org_id"]),
                    project_id=str(base["project_id"]),
                    environment_id=str(base["environment_id"]),
                    gate_id=str(base["gate_id"]),
                    identity_id=f"wrong-{new_id()}",
                    report_id=str(base["id"]),
                    attestation_hash="d" * 64,
                    assurance_class="observed",
                    evidence_kind="in_process_public_surface_conformance",
                    suite_id="db-boundary-test",
                    suite_hash="e" * 64,
                    artifact={},
                )
            )


def test_report_auth_tamper_and_stale_policy_fail_without_mutation(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    before = _report_path_counts(app, seeded["org_id"])
    path, raw_body, headers = _signed_status_request(seeded)

    tampered_headers = dict(headers)
    tampered_headers["X-ACGS-Runtime-Signature"] = "invalid"
    tampered = client.post(path, content=raw_body, headers=tampered_headers)
    assert tampered.status_code == 401
    assert _report_path_counts(app, seeded["org_id"]) == before

    stale_payload = json.loads(raw_body)
    stale_payload["policy_head_generation"] += 1
    stale_path, stale_body, stale_headers = _signed_status_request(
        seeded,
        payload=stale_payload,
    )
    stale = client.post(stale_path, content=stale_body, headers=stale_headers)
    assert stale.status_code == 409
    assert _report_path_counts(app, seeded["org_id"]) == before


@pytest.mark.parametrize(
    ("target", "field"),
    (
        ("identity", "public_key"),
        ("identity", "public_key_thumbprint"),
        ("identity", "workload_key_id"),
        ("identity", "descriptor"),
        ("credential", "public_key_thumbprint"),
        ("credential", "workload_key_id"),
        ("credential", "descriptor"),
    ),
)
def test_current_runtime_key_and_descriptor_binding_tamper_fails_closed(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: Any,
    target: str,
    field: str,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    report_path, report_body, report_headers = _signed_status_request(seeded)
    before = _report_path_counts(app, seeded["org_id"])

    with app.state.session_factory.begin() as session:
        identity = session.get(RuntimeIdentity, seeded["identity_id"])
        assert identity is not None
        credential = session.scalars(
            sa.select(RuntimeCredentialGeneration).where(
                RuntimeCredentialGeneration.identity_id == identity.id,
                RuntimeCredentialGeneration.status == "active",
            )
        ).one()
        row = identity if target == "identity" else credential
        if field == "public_key":
            setattr(row, field, "A" * 43)
        elif field == "public_key_thumbprint":
            setattr(row, field, "0" * 64)
        elif field == "workload_key_id":
            setattr(row, field, "tampered-workload-key")
        else:
            descriptor = dict(row.descriptor)
            replacement = "A" if descriptor["signature"][0] != "A" else "B"
            descriptor["signature"] = replacement + descriptor["signature"][1:]
            row.descriptor = descriptor

    report = client.post(report_path, content=report_body, headers=report_headers)
    policy = _signed_get(client, seeded)
    fleet = client.get(
        (
            f"/orgs/{seeded['org_id']}/projects/{seeded['project_id']}"
            f"/environments/{seeded['environment_id']}/fleet"
        ),
        headers=admin_headers,
    )

    assert report.status_code == 401, report.text
    assert policy.status_code == 401, policy.text
    assert _report_path_counts(app, seeded["org_id"]) == before
    [runtime] = fleet.json()["runtimes"]
    assert runtime["online"]["available"] is False
    assert runtime["policy_current"]["available"] is False
    assert runtime["proven_wired"]["available"] is False


def test_unexpected_policy_verifier_fault_is_not_reclassified_as_report_rejection(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    body = RuntimeReportRequest.model_validate(_status_payload(seeded))
    with app.state.session_factory() as session:
        identity = session.get(RuntimeIdentity, seeded["identity_id"])
        assert identity is not None
        descriptor = RuntimeIdentityDescriptor.from_dict(identity.descriptor)

        def unexpected_fault(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("unexpected verifier defect")

        monkeypatch.setattr(runtime_reports_module, "verify_policy_sync_snapshot", unexpected_fault)
        with pytest.raises(RuntimeError, match="unexpected verifier defect"):
            runtime_reports_module._verified_policy_provenance(
                session,
                body=body,
                descriptor=descriptor,
                now=utcnow(),
            )


@pytest.mark.parametrize("provider_error", [RuntimeError, ValueError, OSError])
def test_challenge_signer_outage_is_redacted_and_persists_zero_report_rows(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
    provider_error: type[Exception],
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    snapshot = _signed_get(client, seeded).json()
    path, headers = _signed_challenge_request(
        seeded,
        snapshot=snapshot,
        runtime_build_digest="b" * 64,
        configuration_digest="c" * 64,
    )
    before = _report_path_counts(app, seeded["org_id"])
    before_attempts = _report_attempt_count(app, seeded["org_id"])

    class FailingPrivateKey:
        def sign(self, _payload: bytes) -> bytes:
            raise provider_error("secret signer endpoint kms://challenge-key")

    monkeypatch.setattr(runtime_descriptor_signer, "_private_key", FailingPrivateKey())

    response = client.get(path, headers=headers)

    assert response.status_code == 503, response.text
    assert response.json() == {
        "code": "RUNTIME_REPORT_PROVIDER_UNAVAILABLE",
        "status": "service_unavailable",
        "detail": "runtime report cryptographic provider is unavailable",
    }
    assert "challenge-key" not in response.text
    assert _report_path_counts(app, seeded["org_id"]) == before
    assert _report_attempt_count(app, seeded["org_id"]) == before_attempts


@pytest.mark.parametrize("provider_error", [RuntimeError, ValueError, OSError])
def test_runtime_identity_public_key_provider_outage_is_redacted_before_challenge(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
    provider_error: type[Exception],
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    snapshot = _signed_get(client, seeded).json()
    path, headers = _signed_challenge_request(
        seeded,
        snapshot=snapshot,
        runtime_build_digest="b" * 64,
        configuration_digest="c" * 64,
    )
    before = _report_path_counts(app, seeded["org_id"])
    before_attempts = _report_attempt_count(app, seeded["org_id"])

    class FailingPublicKey:
        def public_bytes(self, *_args: Any, **_kwargs: Any) -> bytes:
            raise provider_error("secret public-key provider kms://descriptor-key")

    monkeypatch.setattr(runtime_descriptor_signer, "_public_key", FailingPublicKey())
    response = client.get(path, headers=headers)

    assert response.status_code == 503, response.text
    assert response.json()["code"] == "RUNTIME_REPORT_PROVIDER_UNAVAILABLE"
    assert "descriptor-key" not in response.text
    assert _report_path_counts(app, seeded["org_id"]) == before
    assert _report_attempt_count(app, seeded["org_id"]) == before_attempts


@pytest.mark.parametrize("provider_error", [RuntimeError, ValueError, OSError])
def test_receipt_issuer_provider_outage_is_redacted_before_terminal_lineage(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
    provider_error: type[Exception],
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    path, raw_body, headers = _signed_status_request(seeded)
    before = _report_path_counts(app, seeded["org_id"])
    before_attempts = _report_attempt_count(app, seeded["org_id"])
    receipt_signer = app.state.runtime_enrollment_service.issuer.signer

    class FailingPrivateKey:
        def sign(self, _payload: bytes) -> bytes:
            raise provider_error("secret receipt issuer kms://receipt-key")

    monkeypatch.setattr(receipt_signer, "_private_key", FailingPrivateKey())
    response = client.post(path, content=raw_body, headers=headers)

    assert response.status_code == 503, response.text
    assert response.json()["code"] == "RUNTIME_REPORT_PROVIDER_UNAVAILABLE"
    assert "receipt-key" not in response.text
    assert _report_path_counts(app, seeded["org_id"]) == before
    assert _report_attempt_count(app, seeded["org_id"]) == before_attempts


@pytest.mark.parametrize("provider_error", [RuntimeError, ValueError, OSError])
def test_terminal_sealer_outage_rolls_back_lineage_and_persists_one_failed_attempt(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
    provider_error: type[Exception],
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    path, raw_body, headers = _signed_status_request(seeded)
    before = _report_path_counts(app, seeded["org_id"])
    before_attempts = _report_attempt_count(app, seeded["org_id"])

    def unavailable_terminal_sealer(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        try:
            raise provider_error("secret sealer endpoint kms://terminal-key")
        except Exception as exc:
            raise RuntimeEnrollmentProviderUnavailable from exc

    monkeypatch.setattr(
        runtime_reports_module,
        "_sealed_terminal_response_payload",
        unavailable_terminal_sealer,
    )

    response = client.post(path, content=raw_body, headers=headers)

    assert response.status_code == 503, response.text
    assert response.json() == {
        "code": "RUNTIME_REPORT_PROVIDER_UNAVAILABLE",
        "status": "service_unavailable",
        "detail": "runtime report cryptographic provider is unavailable",
    }
    assert "terminal-key" not in response.text
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


@pytest.mark.parametrize("provider_error", [RuntimeError, ValueError, OSError])
def test_terminal_sealer_boundary_normalizes_provider_sdk_exceptions(
    provider_error: type[Exception],
) -> None:
    class FailingSealer:
        def seal(self, _plaintext: bytes, *, associated_data: bytes) -> dict[str, Any]:
            del associated_data
            raise provider_error("secret provider SDK failure")

    with pytest.raises(RuntimeEnrollmentProviderUnavailable):
        _sealed_terminal_response_payload(
            {"report_id": "report"},
            receipt_sealer=cast(Any, FailingSealer()),
            org_id="org",
            project_id="project",
            environment_id="environment",
            identity_id="identity",
            action="runtime.report.accept",
            operation="report",
            request_hash="a" * 64,
            idempotency_key_hash="b" * 64,
            receipt_id="receipt",
            receipt_hash="c" * 64,
        )


@pytest.mark.parametrize("provider_error", [RuntimeError, ValueError, OSError])
def test_terminal_unsealer_boundary_normalizes_provider_sdk_exceptions(
    provider_error: type[Exception],
) -> None:
    class FailingUnsealer:
        def unseal(self, _envelope: Any, *, associated_data: bytes) -> bytes:
            del associated_data
            raise provider_error("secret provider SDK failure")

    with pytest.raises(RuntimeEnrollmentProviderUnavailable):
        _verified_stored_terminal_payload(
            {"report_id": "report", "_terminal_response_seal": {}},
            receipt_sealer=cast(Any, FailingUnsealer()),
            org_id="org",
            project_id="project",
            environment_id="environment",
            identity_id="identity",
            action="runtime.report.accept",
            operation="report",
            request_hash="a" * 64,
            idempotency_key_hash="b" * 64,
            receipt_id="receipt",
            receipt_hash="c" * 64,
        )


def test_wiring_verification_provider_outage_is_redacted_and_atomic(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    before = _report_path_counts(app, seeded["org_id"])
    original = runtime_reports_module._provider_public_key_bytes
    calls = 0

    class FailingProvider:
        def public_key_bytes(self) -> bytes:
            raise OSError("secret wiring verifier provider kms://wiring-key")

    def fail_wiring_boundary(provider: Any) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 2:
            return original(FailingProvider())
        return original(provider)

    monkeypatch.setattr(
        runtime_reports_module,
        "_provider_public_key_bytes",
        fail_wiring_boundary,
    )
    response, _request = _submit_wiring_report(
        client, app=app, seeded=seeded, tmp_path=tmp_path, sequence=1
    )

    assert response.status_code == 503, response.text
    assert response.json()["code"] == "RUNTIME_REPORT_PROVIDER_UNAVAILABLE"
    assert "wiring-key" not in response.text
    assert _report_path_counts(app, seeded["org_id"]) == before


def test_stored_lineage_provider_outage_is_redacted_and_read_only(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    path, raw_body, headers = _signed_status_request(seeded)
    accepted = client.post(path, content=raw_body, headers=headers)
    assert accepted.status_code == 201, accepted.text
    before = _report_path_counts(app, seeded["org_id"])

    def unavailable_unsealer(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeEnrollmentProviderUnavailable from OSError(
            "secret stored-lineage provider kms://unseal-key"
        )

    monkeypatch.setattr(
        runtime_reports_module,
        "_verified_stored_terminal_payload",
        unavailable_unsealer,
    )
    response = client.get(
        (
            f"/orgs/{seeded['org_id']}/projects/{seeded['project_id']}"
            f"/environments/{seeded['environment_id']}/fleet"
        ),
        headers=admin_headers,
    )

    assert response.status_code == 503, response.text
    assert response.json()["code"] == "RUNTIME_REPORT_PROVIDER_UNAVAILABLE"
    assert "unseal-key" not in response.text
    assert _report_path_counts(app, seeded["org_id"]) == before


def test_uow_drift_is_refused_before_identity_revalidation_hook(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    path, raw_body, headers = _signed_status_request(seeded)
    before = _report_path_counts(app, seeded["org_id"])
    original_execute = ManagedMutationUnitOfWork.execute

    def execute_after_revoke(self: Any, *args: Any, **kwargs: Any) -> Any:
        with app.state.session_factory.begin() as session:
            identity = session.get(RuntimeIdentity, seeded["identity_id"])
            assert identity is not None
            identity.status = "revoked"
            identity.revoked_at = utcnow()
        return original_execute(self, *args, **kwargs)

    monkeypatch.setattr(ManagedMutationUnitOfWork, "execute", execute_after_revoke)
    rejected = client.post(path, content=raw_body, headers=headers)

    assert rejected.status_code == 503, rejected.text
    assert rejected.json()["code"] == "MUTATION_INVENTORY_DRIFT"
    assert _report_path_counts(app, seeded["org_id"]) == before


def test_nonce_and_idempotency_reuse_are_fail_closed(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    idempotency_key = f"runtime-report-{new_id()}"
    nonce = f"runtime-report-{new_id()}"
    path, raw_body, headers = _signed_status_request(
        seeded,
        idempotency_key=idempotency_key,
        nonce=nonce,
    )
    accepted = client.post(path, content=raw_body, headers=headers)
    assert accepted.status_code == 201
    after_accept = _report_path_counts(app, seeded["org_id"])

    changed = json.loads(raw_body)
    changed["sequence"] = 2
    retry_path, retry_body, retry_headers = _signed_status_request(
        seeded,
        payload=changed,
        idempotency_key=idempotency_key,
        nonce=f"runtime-report-{new_id()}",
    )
    mismatch = client.post(retry_path, content=retry_body, headers=retry_headers)
    assert mismatch.status_code == 409
    assert _report_path_counts(app, seeded["org_id"]) == after_accept

    nonce_path, nonce_body, nonce_headers = _signed_status_request(
        seeded,
        payload=changed,
        idempotency_key=f"runtime-report-{new_id()}",
        nonce=nonce,
    )
    replay = client.post(nonce_path, content=nonce_body, headers=nonce_headers)
    assert replay.status_code == 409
    assert _report_path_counts(app, seeded["org_id"]) == after_accept


def test_fleet_is_tenant_isolated(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    make_user: Any,
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    fleet_path = (
        f"/orgs/{org['org_id']}/projects/{seeded['project_id']}"
        f"/environments/{seeded['environment_id']}/fleet"
    )
    assert client.get(fleet_path).status_code == 401
    assert client.get(fleet_path, headers=admin_headers).status_code == 200
    assert client.get(fleet_path, headers=make_user("agent_operator")).status_code == 200
    assert client.get(fleet_path, headers=make_user("auditor")).status_code == 200
    assert client.get(fleet_path, headers=make_user("viewer")).status_code == 403
    response = client.get(
        (
            f"/orgs/not-{org['org_id']}/projects/{seeded['project_id']}"
            f"/environments/{seeded['environment_id']}/fleet"
        ),
        headers=admin_headers,
    )
    assert response.status_code == 404
    assert seeded["identity_id"] not in response.text


def test_fleet_uses_stable_cursor_pagination(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    extra_ids = [f"0-{new_id()}", f"z-{new_id()}"]
    with app.state.session_factory.begin() as session:
        for index, identity_id in enumerate(extra_ids):
            session.add(
                RuntimeIdentity(
                    id=identity_id,
                    org_id=seeded["org_id"],
                    project_id=seeded["project_id"],
                    environment_id=seeded["environment_id"],
                    gate_id=seeded["gate_id"],
                    name=f"Pagination runtime {index}",
                    actor=f"runtime:{identity_id}",
                    workload_key_id=f"pagination-key-{index}",
                    public_key="A" * 43,
                    public_key_thumbprint=f"{index + 1:064x}",
                    descriptor={"schema_version": "acgs.runtime-identity/v1"},
                    status="revoked",
                    current_generation=1,
                    revoked_at=utcnow(),
                )
            )
    fleet_path = (
        f"/orgs/{seeded['org_id']}/projects/{seeded['project_id']}"
        f"/environments/{seeded['environment_id']}/fleet"
    )

    first = client.get(f"{fleet_path}?limit=2", headers=admin_headers)
    assert first.status_code == 200, first.text
    first_payload = first.json()
    assert len(first_payload["runtimes"]) == 2
    assert first_payload["next_cursor"] == first_payload["runtimes"][-1]["identity_id"]

    second = client.get(
        f"{fleet_path}?limit=2&cursor={first_payload['next_cursor']}",
        headers=admin_headers,
    )
    assert second.status_code == 200, second.text
    second_payload = second.json()
    assert len(second_payload["runtimes"]) == 1
    assert second_payload["next_cursor"] is None
    paged_ids = [
        runtime["identity_id"] for runtime in first_payload["runtimes"] + second_payload["runtimes"]
    ]
    assert paged_ids == sorted([seeded["identity_id"], *extra_ids])


def test_challenge_is_state_bound_and_failed_wiring_rolls_back_nonce(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    snapshot_response = _signed_get(client, seeded)
    assert snapshot_response.status_code == 200, snapshot_response.text
    snapshot = snapshot_response.json()
    build_digest = "b" * 64
    config_digest = "c" * 64
    challenge_path, challenge_headers = _signed_challenge_request(
        seeded,
        snapshot=snapshot,
        runtime_build_digest=build_digest,
        configuration_digest=config_digest,
    )
    before = _report_path_counts(app, seeded["org_id"])

    challenge = client.get(challenge_path, headers=challenge_headers)

    assert challenge.status_code == 200, challenge.text
    assert challenge.json()["nonce"].startswith("attest-")
    assert challenge.json()["expected_sequence"] == 1
    assert _report_path_counts(app, seeded["org_id"]) == before

    payload = {
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
        "artifact": {},
    }
    report_path, report_body, report_headers = _signed_status_request(
        seeded,
        payload=payload,
    )
    rejected = client.post(report_path, content=report_body, headers=report_headers)
    assert rejected.status_code == 400
    assert rejected.json()["code"] == "request_body_invalid_ijson"
    assert _report_path_counts(app, seeded["org_id"]) == before


def test_challenge_is_deterministic_for_one_signed_request_and_changes_with_nonce(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    snapshot = seeded["policy_snapshot"]
    timestamp = utcnow().isoformat().replace("+00:00", "Z")
    request_nonce = f"runtime-challenge-{new_id()}"
    path, headers = _signed_challenge_request(
        seeded,
        snapshot=snapshot,
        runtime_build_digest="b" * 64,
        configuration_digest="c" * 64,
        request_nonce=request_nonce,
        request_timestamp=timestamp,
    )
    before = _report_path_counts(app, seeded["org_id"])

    first = client.get(path, headers=headers)
    replay = client.get(path, headers=headers)
    changed_path, changed_headers = _signed_challenge_request(
        seeded,
        snapshot=snapshot,
        runtime_build_digest="b" * 64,
        configuration_digest="c" * 64,
        request_nonce=f"runtime-challenge-{new_id()}",
        request_timestamp=timestamp,
    )
    changed = client.get(changed_path, headers=changed_headers)

    assert first.status_code == 200, first.text
    assert replay.status_code == 200, replay.text
    assert changed.status_code == 200, changed.text
    assert replay.json()["nonce"] == first.json()["nonce"]
    assert replay.json()["expected_sequence"] == first.json()["expected_sequence"]
    assert replay.json()["issued_at"] >= first.json()["issued_at"]
    assert changed.json()["nonce"] != first.json()["nonce"]
    assert changed.json()["token"] != first.json()["token"]
    assert _report_path_counts(app, seeded["org_id"]) == before


def test_challenge_nonce_cannot_be_precomputed_from_public_context(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    tmp_path: Path,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    snapshot = seeded["policy_snapshot"]
    build_digest = "b" * 64
    config_digest = "c" * 64
    timestamp = utcnow().isoformat().replace("+00:00", "Z")
    request_nonce = f"runtime-challenge-{new_id()}"
    path, headers = _signed_challenge_request(
        seeded,
        snapshot=snapshot,
        runtime_build_digest=build_digest,
        configuration_digest=config_digest,
        request_nonce=request_nonce,
        request_timestamp=timestamp,
    )
    with app.state.session_factory() as session:
        identity = session.get(RuntimeIdentity, seeded["identity_id"])
        credential = session.get(RuntimeCredentialGeneration, seeded["descriptor"].credential_id)
        assert identity is not None
        assert credential is not None
        public_context = {
            "schema": "acgs.runtime-attestation-challenge/v1",
            "org_id": seeded["org_id"],
            "project_id": seeded["project_id"],
            "environment_id": seeded["environment_id"],
            "gate_id": seeded["gate_id"],
            "identity_id": seeded["identity_id"],
            "credential_id": credential.id,
            "credential_generation": credential.generation,
            "workload_key_id": credential.workload_key_id,
            "public_key_thumbprint": credential.public_key_thumbprint,
            "policy_version_id": seeded["policy_version_id"],
            "policy_content_hash": seeded["policy_content_hash"],
            "policy_head_generation": seeded["policy_head_generation"],
            "expected_sequence": 1,
            "challenge_signing_key_id": runtime_descriptor_signer.key_id,
            "runtime_build_digest": build_digest,
            "configuration_digest": config_digest,
            "policy_snapshot_hash": sha256_bytes(
                json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
            ),
            "request_timestamp": timestamp,
            "request_nonce": request_nonce,
        }
    publicly_precomputed_nonce = "attest-" + sha256_bytes(
        json.dumps(public_context, sort_keys=True, separators=(",", ":")).encode()
    )
    challenge = client.get(path, headers=headers)
    assert challenge.status_code == 200, challenge.text
    assert challenge.json()["nonce"] != publicly_precomputed_nonce
    artifact = _produce_genuine_wiring_artifact(
        app,
        seeded=seeded,
        snapshot=snapshot,
        challenge_nonce=publicly_precomputed_nonce,
        runtime_build_digest=build_digest,
        configuration_digest=config_digest,
        tmp_path=tmp_path,
        sequence=1,
    )
    report_path, report_body, report_headers = _signed_status_request(
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
    )
    before = _report_path_counts(app, seeded["org_id"])
    before_attempts = _report_attempt_count(app, seeded["org_id"])

    rejected = client.post(report_path, content=report_body, headers=report_headers)

    assert rejected.status_code == 409, rejected.text
    assert rejected.json()["code"] == "REPORT_REJECTED"
    assert _report_path_counts(app, seeded["org_id"]) == before
    assert _report_attempt_count(app, seeded["org_id"]) == before_attempts


def test_future_skewed_request_timestamp_cannot_extend_server_challenge_ttl(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    server_now = utcnow()
    future_client_time = server_now + timedelta(
        seconds=runtime_reports_module.RUNTIME_SIGNED_REQUEST_SKEW_SECONDS - 1
    )
    monkeypatch.setattr(runtime_reports_module, "utcnow", lambda: server_now)
    path, headers = _signed_challenge_request(
        seeded,
        snapshot=seeded["policy_snapshot"],
        runtime_build_digest="b" * 64,
        configuration_digest="c" * 64,
        request_timestamp=future_client_time.isoformat().replace("+00:00", "Z"),
    )

    challenge = client.get(path, headers=headers)

    assert challenge.status_code == 200, challenge.text
    issued_at = runtime_reports_module._parse_runtime_timestamp(challenge.json()["issued_at"])
    expires_at = runtime_reports_module._parse_runtime_timestamp(challenge.json()["expires_at"])
    assert issued_at == server_now
    assert expires_at == server_now + timedelta(
        seconds=runtime_reports_module.CHALLENGE_TTL_SECONDS
    )
    assert expires_at < future_client_time + timedelta(
        seconds=runtime_reports_module.CHALLENGE_TTL_SECONDS
    )


def test_expired_server_challenge_is_rejected_without_persistence(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    challenge_path, challenge_headers = _signed_challenge_request(
        seeded,
        snapshot=seeded["policy_snapshot"],
        runtime_build_digest="b" * 64,
        configuration_digest="c" * 64,
    )
    challenge = client.get(challenge_path, headers=challenge_headers)
    assert challenge.status_code == 200, challenge.text
    body = RuntimeReportRequest.model_validate(
        {
            **_status_payload(seeded),
            "kind": "wiring",
            "challenge_token": challenge.json()["token"],
            "artifact": {},
        }
    )
    before = _report_path_counts(app, seeded["org_id"])
    with app.state.session_factory() as session:
        identity = session.get(RuntimeIdentity, seeded["identity_id"])
        credential = session.get(RuntimeCredentialGeneration, seeded["descriptor"].credential_id)
        gate = session.get(RuntimeIdentityGate, seeded["gate_id"])
        assert identity is not None
        assert credential is not None
        assert gate is not None
        with pytest.raises(ReceiptValidationError, match="invalid or expired"):
            app.state.runtime_report_service._verify_challenge(
                challenge.json()["token"],
                identity=identity,
                credential=credential,
                gate=gate,
                body=body,
                now=runtime_reports_module._parse_runtime_timestamp(challenge.json()["expires_at"]),
            )
    assert _report_path_counts(app, seeded["org_id"]) == before


def test_challenge_is_invalidated_by_an_intervening_report_without_debris(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    tmp_path: Path,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
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


def test_genuine_public_gateway_wiring_artifact_is_accepted_and_drives_fleet(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: Any,
    tmp_path: Path,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    snapshot_response = _signed_get(client, seeded)
    assert snapshot_response.status_code == 200, snapshot_response.text
    snapshot = snapshot_response.json()
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
        tmp_path=tmp_path,
    )
    before = _report_path_counts(app, seeded["org_id"])
    payload: dict[str, Any] = {
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
    }
    wrong_type_artifacts: list[dict[str, Any]] = []
    for field_path, invalid_value in (
        (("runtime", "credential_generation"), "1"),
        (("package", "runtime_build_digest"), 1),
        (("policy_head", "policy_trust_epoch"), "1"),
        (("results", 0, "side_effect_count"), "1"),
        (("results", 0, "receipt", "trust_epoch"), "1"),
        (("results", 0, "receipt", "constraints", "schema"), 1),
        (("results", 0, "receipt", "transformations"), [{"field": 1, "value": 1}]),
        (("results", 0, "receipt", "approval_chain_summary", "proposer"), 1),
        (("results", 0, "audit_event", "path"), "native"),
        (("results", 0, "consumption_entry", "consumed_at"), 1),
    ):
        wrong_type = copy.deepcopy(artifact)
        target: Any = wrong_type
        for part in field_path[:-1]:
            target = target[part]
        target[field_path[-1]] = invalid_value
        wrong_type_artifacts.append(wrong_type)
    missing_nested = copy.deepcopy(artifact)
    del missing_nested["runtime"]["credential_id"]
    wrong_type_artifacts.append(missing_nested)
    report_path = f"/v1/runtime-identities/{seeded['identity_id']}/reports"
    for field_path, invalid_value in (
        (("policy_envelope", "rules", 0, "effect"), 1),
        (("policy_envelope", "rules", 0, "tools"), [1]),
        (("policy_envelope", "rules", 0, "id"), 1),
        (("policy_envelope", "document", "rules", 0, "effect"), 1),
    ):
        wrong_snapshot = copy.deepcopy(snapshot)
        target = wrong_snapshot
        for part in field_path[:-1]:
            target = target[part]
        target[field_path[-1]] = invalid_value
        rejected_snapshot = client.post(
            report_path,
            json={**payload, "policy_snapshot": wrong_snapshot},
        )
        assert rejected_snapshot.status_code == 400, rejected_snapshot.text
        assert rejected_snapshot.json()["code"] == "request_body_invalid_ijson"
        assert _report_path_counts(app, seeded["org_id"]) == before
    for wrong_type in wrong_type_artifacts:
        rejected_wire = client.post(
            report_path,
            json={**payload, "artifact": wrong_type},
        )
        assert rejected_wire.status_code == 400, rejected_wire.text
        assert rejected_wire.json()["code"] == "request_body_invalid_ijson"
        assert _report_path_counts(app, seeded["org_id"]) == before
    tampered_artifacts: list[dict[str, Any]] = []
    for field, value in (
        ("execution_boundary", f"wrong-{seeded['gate_id']}"),
        ("nonce", f"wrong-{challenge.json()['nonce']}"),
        ("signing_key_id", "wrong-workload-key"),
        ("suite_id", "wrong-suite"),
    ):
        tampered = copy.deepcopy(artifact)
        tampered[field] = value
        tampered_artifacts.append(_resign_artifact(tampered, seeded["workload_key"]))
    for field in ("runtime_build_digest", "configuration_digest"):
        tampered = copy.deepcopy(artifact)
        tampered["package"][field] = "d" * 64
        tampered_artifacts.append(_resign_artifact(tampered, seeded["workload_key"]))
    wrong_scope = copy.deepcopy(artifact)
    wrong_scope["scope"]["org_id"] = f"wrong-{seeded['org_id']}"
    tampered_artifacts.append(_resign_artifact(wrong_scope, seeded["workload_key"]))
    expired = copy.deepcopy(artifact)
    expired["expires_at"] = (utcnow() - timedelta(seconds=1)).isoformat()
    tampered_artifacts.append(_resign_artifact(expired, seeded["workload_key"]))
    wrong_policy = copy.deepcopy(artifact)
    wrong_policy["policy_head"]["content_hash"] = "e" * 64
    tampered_artifacts.append(_resign_artifact(wrong_policy, seeded["workload_key"]))
    wrong_sequence = copy.deepcopy(artifact)
    wrong_sequence["sequence"] = 2
    tampered_artifacts.append(_resign_artifact(wrong_sequence, seeded["workload_key"]))
    for tampered in tampered_artifacts:
        rejected_payload = {**payload, "artifact": tampered}
        rejected_path, rejected_body, rejected_headers = _signed_status_request(
            seeded,
            payload=rejected_payload,
        )
        rejected = client.post(
            rejected_path,
            content=rejected_body,
            headers=rejected_headers,
        )
        assert rejected.status_code == 409, rejected.text
        assert _report_path_counts(app, seeded["org_id"]) == before
        with app.state.session_factory() as session:
            assert (
                session.scalar(
                    sa.select(sa.func.count()).select_from(RuntimeWiringChallengeConsumption)
                )
                == 0
            )
    path, body, headers = _signed_status_request(seeded, payload=payload)

    def fail_after_success(
        _mapper: Any, _connection: Any, target: RuntimeOperationIdempotency
    ) -> None:
        if target.operation == "report":
            raise SQLAlchemyError("forced after-success failure")

    sa.event.listen(RuntimeOperationIdempotency, "before_insert", fail_after_success)
    try:
        failed = client.post(path, content=body, headers=headers)
    finally:
        sa.event.remove(RuntimeOperationIdempotency, "before_insert", fail_after_success)
    assert failed.status_code == 503, failed.text
    assert failed.json()["code"] == "DATABASE_UNAVAILABLE"
    assert _report_path_counts(app, seeded["org_id"]) == before
    with app.state.session_factory() as session:
        assert (
            session.scalar(
                sa.select(sa.func.count()).select_from(RuntimeWiringChallengeConsumption)
            )
            == 0
        )

    accepted = client.post(path, content=body, headers=headers)

    assert accepted.status_code == 201, accepted.text
    after = _report_path_counts(app, seeded["org_id"])
    for name in ("receipts", "consumptions", "events", "outbox", "idempotency"):
        assert after[name] == before[name] + 1
    assert after["reports"] == before["reports"] + 1
    assert after["attestations"] == before["attestations"] + 1
    assert after["nonces"] == before["nonces"] + 1
    assert after["heads"] == before["heads"] + 1
    assert after["challenges"] == before["challenges"] + 1
    with app.state.session_factory() as session:
        assert (
            session.scalar(
                sa.select(sa.func.count()).select_from(RuntimeWiringChallengeConsumption)
            )
            == 1
        )
    fleet = client.get(
        (
            f"/orgs/{seeded['org_id']}/projects/{seeded['project_id']}"
            f"/environments/{seeded['environment_id']}/fleet"
        ),
        headers=admin_headers,
    )
    assert fleet.status_code == 200
    [runtime] = fleet.json()["runtimes"]
    assert runtime["online"]["available"] is True
    assert runtime["policy_current"]["available"] is True
    assert runtime["proven_wired"]["available"] is True
    assert runtime["evidence_current"]["available"] is False

    same_tuple_payload = _status_payload(seeded, sequence=2)
    same_tuple_path, same_tuple_body, same_tuple_headers = _signed_status_request(
        seeded,
        payload=same_tuple_payload,
    )
    same_tuple = client.post(
        same_tuple_path,
        content=same_tuple_body,
        headers=same_tuple_headers,
    )
    assert same_tuple.status_code == 201, same_tuple.text
    same_tuple_fleet = client.get(
        (
            f"/orgs/{seeded['org_id']}/projects/{seeded['project_id']}"
            f"/environments/{seeded['environment_id']}/fleet"
        ),
        headers=admin_headers,
    )
    assert same_tuple_fleet.json()["runtimes"][0]["proven_wired"]["available"] is True

    changed_tuple_payload = _status_payload(seeded, sequence=3)
    changed_tuple_payload["configuration_digest"] = "d" * 64
    changed_path, changed_body, changed_headers = _signed_status_request(
        seeded,
        payload=changed_tuple_payload,
    )
    changed = client.post(changed_path, content=changed_body, headers=changed_headers)
    assert changed.status_code == 201, changed.text
    changed_fleet = client.get(
        (
            f"/orgs/{seeded['org_id']}/projects/{seeded['project_id']}"
            f"/environments/{seeded['environment_id']}/fleet"
        ),
        headers=admin_headers,
    )
    changed_runtime = changed_fleet.json()["runtimes"][0]
    assert changed_runtime["online"]["available"] is True
    assert changed_runtime["policy_current"]["available"] is True
    assert changed_runtime["proven_wired"]["available"] is False
    assert changed_runtime["proven_wired"]["reason"] == "wiring_attestation_not_current"

    with app.state.engine.begin() as connection:
        connection.execute(
            sa.text('DROP TRIGGER "runtime_wiring_challenge_consumptions_immutable_update"')
        )
        connection.execute(
            sa.update(RuntimeWiringChallengeConsumption)
            .where(RuntimeWiringChallengeConsumption.report_id == accepted.json()["report_id"])
            .values(namespace_digest="0" * 64)
        )
        connection.execute(
            sa.text(
                SQLITE_RUNTIME_LINEAGE_OBJECTS[
                    "runtime_wiring_challenge_consumptions_immutable_update"
                ]
            )
        )
    replay = client.post(path, content=body, headers=headers)
    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"
    tampered_fleet = client.get(
        (
            f"/orgs/{seeded['org_id']}/projects/{seeded['project_id']}"
            f"/environments/{seeded['environment_id']}/fleet"
        ),
        headers=admin_headers,
    ).json()["runtimes"][0]
    assert tampered_fleet["proven_wired"]["available"] is False
    assert tampered_fleet["proven_wired"]["reason"] == "wiring_attestation_lineage_invalid"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("attestation_hash", "0" * 64),
        ("suite_hash", "0" * 64),
        ("artifact", {}),
        ("created_at", utcnow() + timedelta(seconds=1)),
    ),
)
def test_stored_attestation_columns_are_exactly_bound_to_report_projection(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: Any,
    tmp_path: Path,
    field: str,
    value: Any,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    accepted, request = _submit_wiring_report(
        client, app=app, seeded=seeded, tmp_path=tmp_path, sequence=1
    )
    assert accepted.status_code == 201, accepted.text
    with app.state.engine.begin() as connection:
        connection.execute(sa.text('DROP TRIGGER "runtime_wiring_attestations_immutable_update"'))
        connection.execute(
            sa.update(RuntimeWiringAttestation)
            .where(RuntimeWiringAttestation.report_id == accepted.json()["report_id"])
            .values({field: value})
        )
        connection.execute(
            sa.text(SQLITE_RUNTIME_LINEAGE_OBJECTS["runtime_wiring_attestations_immutable_update"])
        )

    path, body, headers = request
    replay = client.post(path, content=body, headers=headers)
    assert replay.status_code == 503, replay.text
    assert replay.json()["code"] == "TERMINAL_RESPONSE_TAMPERED"
    fleet = client.get(
        (
            f"/orgs/{seeded['org_id']}/projects/{seeded['project_id']}"
            f"/environments/{seeded['environment_id']}/fleet"
        ),
        headers=admin_headers,
    ).json()["runtimes"][0]
    assert fleet["proven_wired"]["available"] is False
    assert fleet["proven_wired"]["reason"] == "wiring_attestation_lineage_invalid"


def test_historical_wiring_replay_is_exact_and_fleet_remains_on_current_anchor(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: Any,
    tmp_path: Path,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    first, first_request = _submit_wiring_report(
        client, app=app, seeded=seeded, tmp_path=tmp_path / "first", sequence=1
    )
    second, _ = _submit_wiring_report(
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
    with app.state.session_factory() as session:
        head = session.get(RuntimeReportHead, seeded["identity_id"])
        assert head is not None
        assert head.latest_wiring_report_id == second.json()["report_id"]
        assert head.latest_wiring_sequence == 2
    fleet = client.get(
        (
            f"/orgs/{seeded['org_id']}/projects/{seeded['project_id']}"
            f"/environments/{seeded['environment_id']}/fleet"
        ),
        headers=admin_headers,
    ).json()["runtimes"][0]
    assert fleet["proven_wired"]["available"] is True


@pytest.mark.parametrize(
    "trust_purpose",
    (POLICY_ENVELOPE_PURPOSE, POLICY_SYNC_ATTESTATION_PURPOSE, DECISION_RECEIPT_PURPOSE),
)
def test_historical_wiring_replay_accepts_retired_trust_but_current_fleet_does_not(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    runtime_descriptor_signer: Any,
    tmp_path: Path,
    trust_purpose: str,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    accepted, request = _submit_wiring_report(
        client, app=app, seeded=seeded, tmp_path=tmp_path, sequence=1
    )
    assert accepted.status_code == 201, accepted.text
    _rotate_report_trust(app, seeded=seeded, trust_purpose=trust_purpose)
    before = _report_path_counts(app, seeded["org_id"])
    before_attempts = _report_attempt_count(app, seeded["org_id"])

    path, body, headers = request
    replay = client.post(path, content=body, headers=headers)

    assert replay.status_code == 201, replay.text
    assert replay.json() == accepted.json()
    assert _report_path_counts(app, seeded["org_id"]) == before
    assert _report_attempt_count(app, seeded["org_id"]) == before_attempts
    fleet = client.get(
        (
            f"/orgs/{seeded['org_id']}/projects/{seeded['project_id']}"
            f"/environments/{seeded['environment_id']}/fleet"
        ),
        headers=admin_headers,
    ).json()["runtimes"][0]
    assert fleet["proven_wired"]["available"] is False
    assert fleet["proven_wired"]["reason"] == "wiring_attestation_lineage_invalid"


@pytest.mark.parametrize(
    ("trust_purpose", "expected_status", "expected_code"),
    (
        (POLICY_ENVELOPE_PURPOSE, 409, "REPORT_REJECTED"),
        (POLICY_SYNC_ATTESTATION_PURPOSE, 409, "REPORT_REJECTED"),
        (DECISION_RECEIPT_PURPOSE, 503, "TERMINAL_RESPONSE_TAMPERED"),
    ),
)
def test_historical_wiring_replay_rejects_revoked_trust_without_deltas(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    tmp_path: Path,
    trust_purpose: str,
    expected_status: int,
    expected_code: str,
) -> None:
    seeded = _seed_report_scope(client, org, runtime_descriptor_signer)
    app = cast(Any, client.app)
    accepted, request = _submit_wiring_report(
        client, app=app, seeded=seeded, tmp_path=tmp_path, sequence=1
    )
    assert accepted.status_code == 201, accepted.text
    retired_key = _rotate_report_trust(app, seeded=seeded, trust_purpose=trust_purpose)
    with app.state.session_factory.begin() as session:
        ManagedTrustLifecycleService(session).revoke(
            scope=retired_key[0], key_id=retired_key[1], algorithm=retired_key[2]
        )
    before = _report_path_counts(app, seeded["org_id"])
    before_attempts = _report_attempt_count(app, seeded["org_id"])

    path, body, headers = request
    replay = client.post(path, content=body, headers=headers)

    assert replay.status_code == expected_status, replay.text
    assert replay.json()["code"] == expected_code
    assert _report_path_counts(app, seeded["org_id"]) == before
    assert _report_attempt_count(app, seeded["org_id"]) == before_attempts


def _rotate_report_trust(
    app: Any, *, seeded: dict[str, Any], trust_purpose: str
) -> tuple[ReceiptTrustScope, str, str]:
    scope = ReceiptTrustScope(
        seeded["org_id"], seeded["project_id"], seeded["environment_id"], trust_purpose
    )
    replacement = Ed25519Signer.generate(key_id=f"replacement-{trust_purpose}-{new_id()}")
    with app.state.session_factory.begin() as session:
        active = session.scalars(
            sa.select(ManagedTrustKey).where(
                ManagedTrustKey.org_id == seeded["org_id"],
                ManagedTrustKey.project_id == seeded["project_id"],
                ManagedTrustKey.environment_id == seeded["environment_id"],
                ManagedTrustKey.purpose == trust_purpose,
                ManagedTrustKey.status == "active",
            )
        ).one()
        old_key = (scope, active.key_id, active.algorithm)
        ManagedTrustLifecycleService(session).rotate(
            scope=scope,
            key_id=replacement.key_id,
            algorithm=replacement.algorithm,
            public_key_spki_der=public_spki_der_from_signer(replacement),
            not_after=utcnow() + timedelta(days=1),
            expected_current_epoch=active.activated_epoch,
        )
    return old_key


def _seed_report_scope(
    client: TestClient,
    org: dict[str, Any],
    runtime_descriptor_signer: Any,
    *,
    report_decision: Decision | None = None,
    scope_suffix: str = "primary",
) -> dict[str, Any]:
    seeded = _seed_runtime_policy_sync(
        client,
        org,
        runtime_descriptor_signer,
        scope_suffix=scope_suffix,
    )
    app = cast(Any, client.app)
    policy_id = f"runtime-report-policy-{new_id()}"
    rules = [
        {
            "id": "deny-conformance",
            "effect": "deny",
            "tools": [
                "acgs.conformance.mcp_deny",
                "acgs.conformance.langgraph_deny",
                "acgs.conformance.rest_deny",
                "runtime.acgs.conformance.claude_deny",
            ],
        },
        {
            "id": "escalate-conformance",
            "effect": "escalate",
            "tools": ["acgs.conformance.openai_escalate"],
        },
    ]
    if report_decision is not None:
        rules.insert(
            0,
            {
                "id": f"runtime-report-{report_decision.value}",
                "effect": report_decision.value,
                "tools": [runtime_reports_module.CONTROL_PLANE_RUNTIME_REPORT_ACCEPT_ACTION],
            },
        )
    policy_base = (
        f"/orgs/{seeded['org_id']}/projects/{seeded['project_id']}"
        f"/environments/{seeded['environment_id']}/policies"
    )
    published = client.post(
        policy_base,
        json={"policy_id": policy_id, "rules": rules},
        headers={
            "X-API-Key": str(org["admin_api_key"]),
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"report-publish-{new_id()}",
        },
    )
    assert published.status_code == 201, published.text
    policy_version_id = str(published.json()["bundle_id"])
    activated = client.post(
        f"{policy_base}/{policy_version_id}/activate",
        json={"expected_generation": 1},
        headers={
            "X-API-Key": str(org["admin_api_key"]),
            BOOTSTRAP_IDEMPOTENCY_HEADER: f"report-activate-{new_id()}",
        },
    )
    assert activated.status_code == 200, activated.text
    seeded["policy_version_id"] = policy_version_id
    runtime_scope = ReceiptTrustScope(
        seeded["org_id"],
        seeded["project_id"],
        seeded["environment_id"],
        DECISION_RECEIPT_PURPOSE,
    )
    runtime_signer = app.state.runtime_enrollment_service.issuer.signer_for_scope(
        runtime_scope,
        trust_epoch=2,
    )
    with app.state.session_factory.begin() as session:
        ManagedTrustLifecycleService(session).rotate(
            scope=runtime_scope,
            key_id=runtime_signer.key_id,
            algorithm=runtime_signer.algorithm,
            public_key_spki_der=public_spki_der_from_signer(runtime_signer),
            not_after=utcnow() + timedelta(days=1),
            expected_current_epoch=1,
        )
        head = session.scalars(
            sa.select(EnvironmentPolicyHead).where(
                EnvironmentPolicyHead.org_id == seeded["org_id"],
                EnvironmentPolicyHead.project_id == seeded["project_id"],
                EnvironmentPolicyHead.environment_id == seeded["environment_id"],
            )
        ).one()
        version = session.get(PolicyVersion, head.active_policy_version_id)
        assert version is not None
        seeded["policy_head_generation"] = head.generation
        seeded["policy_content_hash"] = version.content_hash
    snapshot_response = _signed_get(client, seeded)
    assert snapshot_response.status_code == 200, snapshot_response.text
    seeded["policy_snapshot"] = snapshot_response.json()
    return seeded


def _add_report_identity(
    client: TestClient,
    scope: dict[str, Any],
    runtime_descriptor_signer: Any,
    *,
    suffix: str,
) -> dict[str, Any]:
    app = cast(Any, client.app)
    now = utcnow()
    identity_id = f"runtime-{suffix}-{new_id()}"
    credential_id = f"credential-{suffix}-{new_id()}"
    workload_key = InMemoryEd25519WorkloadKeyProvider(key_id=f"workload-{suffix}")
    descriptor = RuntimeIdentityDescriptor.issue(
        scope=GateScope(
            scope["org_id"],
            scope["project_id"],
            scope["environment_id"],
            scope["gate_id"],
        ),
        runtime_identity_id=identity_id,
        credential_id=credential_id,
        credential_generation=1,
        workload_public_key=workload_key.public_key_bytes(),
        issuer="acgs-control-plane",
        audience=RUNTIME_ENROLLMENT_AUTHORITY,
        issued_at=now.isoformat().replace("+00:00", "Z"),
        expires_at=(now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        signer=runtime_descriptor_signer,
    )
    with app.state.session_factory.begin() as session:
        session.add_all(
            [
                RuntimeIdentity(
                    id=identity_id,
                    org_id=scope["org_id"],
                    project_id=scope["project_id"],
                    environment_id=scope["environment_id"],
                    gate_id=scope["gate_id"],
                    name=f"Runtime {suffix}",
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
                    org_id=scope["org_id"],
                    project_id=scope["project_id"],
                    environment_id=scope["environment_id"],
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
    seeded = {
        **scope,
        "identity_id": identity_id,
        "credential_id": credential_id,
        "descriptor": descriptor,
        "workload_key": workload_key,
    }
    snapshot_response = _signed_get(client, seeded)
    assert snapshot_response.status_code == 200, snapshot_response.text
    seeded["policy_snapshot"] = snapshot_response.json()
    return seeded


def _signed_status_request(
    seeded: dict[str, Any],
    *,
    payload: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
    nonce: str | None = None,
) -> tuple[str, bytes, dict[str, str]]:
    body = payload or _status_payload(seeded)
    raw_body = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    path = f"/v1/runtime-identities/{seeded['identity_id']}/reports"
    effective_key = idempotency_key or f"runtime-report-{new_id()}"
    effective_nonce = nonce or f"runtime-report-{new_id()}"
    timestamp = utcnow().isoformat().replace("+00:00", "Z")
    descriptor = seeded["descriptor"]
    workload_key = seeded["workload_key"]
    signature = workload_key.sign(
        canonical_signed_runtime_request_bytes(
            method="POST",
            path=path,
            query="",
            body=raw_body,
            timestamp=timestamp,
            nonce=effective_nonce,
            key_id=workload_key.key_id,
            identity_id=seeded["identity_id"],
            credential_id=descriptor.credential_id,
            credential_generation=descriptor.credential_generation,
            idempotency_key=effective_key,
            audience=RUNTIME_ENROLLMENT_AUTHORITY,
        )
    )
    return (
        path,
        raw_body,
        {
            "Content-Type": "application/json",
            "Idempotency-Key": effective_key,
            "X-ACGS-Runtime-Identity-ID": seeded["identity_id"],
            "X-ACGS-Runtime-Key-ID": workload_key.key_id,
            "X-ACGS-Runtime-Audience": RUNTIME_ENROLLMENT_AUTHORITY,
            "X-ACGS-Runtime-Credential-ID": descriptor.credential_id,
            "X-ACGS-Runtime-Credential-Generation": str(descriptor.credential_generation),
            "X-ACGS-Runtime-Timestamp": timestamp,
            "X-ACGS-Runtime-Nonce": effective_nonce,
            "X-ACGS-Runtime-Body-Sha256": sha256_bytes(raw_body),
            "X-ACGS-Runtime-Signature": signature,
        },
    )


def _status_payload(seeded: dict[str, Any], *, sequence: int = 1) -> dict[str, Any]:
    return {
        "kind": "status",
        "sequence": sequence,
        "expires_at": (utcnow() + timedelta(minutes=5)).isoformat(),
        "policy_version_id": seeded["policy_version_id"],
        "policy_head_generation": seeded["policy_head_generation"],
        "policy_content_hash": seeded["policy_content_hash"],
        "runtime_build_digest": "b" * 64,
        "configuration_digest": "c" * 64,
        "policy_snapshot": seeded["policy_snapshot"],
    }


def _produce_genuine_wiring_artifact(
    app: Any,
    *,
    seeded: dict[str, Any],
    snapshot: dict[str, Any],
    challenge_nonce: str,
    runtime_build_digest: str,
    configuration_digest: str,
    tmp_path: Path,
    sequence: int = 1,
) -> dict[str, Any]:
    scope = ReceiptTrustScope(
        seeded["org_id"],
        seeded["project_id"],
        seeded["environment_id"],
        DECISION_RECEIPT_PURPOSE,
    )
    receipt_signer = app.state.runtime_enrollment_service.issuer.signer_for_scope(
        scope,
        trust_epoch=2,
    )
    now = utcnow()
    with app.state.session_factory() as session:
        registry = SqlReceiptTrustRegistry(session)
        cache = AtomicJsonPolicyCache(
            tmp_path / "policy.json",
            descriptor=seeded["descriptor"],
            trust_registry=registry,
        )
        cache.install(PolicySyncSnapshot.from_dict(snapshot), now=now)
        ledger = ReceiptConsumptionLedger(tmp_path / "ledger.jsonl")
        gateway = UniversalGateway(
            tenant_id=seeded["org_id"],
            execution_boundary=seeded["gate_id"],
            policy=SyncedRuleSetPolicy(cache, clock=lambda: now),
            profile=GovernanceProfile.production(signer=receipt_signer),
            validator=Validator("control-plane-runtime-report"),
            authority="control-plane.runtime-reports:v1",
            receipt_ttl_seconds=60,
            scoped_receipt_config=ScopedDecisionReceiptConfig(
                seeded["project_id"],
                seeded["environment_id"],
                seeded["gate_id"],
                2,
                registry,
            ),
            audit_path=tmp_path / "audit.jsonl",
            ledger=ledger,
        )
        artifact = produce_wiring_attestation(
            gateway=gateway,
            runtime_identity_descriptor=seeded["descriptor"],
            runtime_identity_issuer_public_key=app.state.runtime_report_service._descriptor_signer.public_key_bytes(),
            runtime_identity_audience=RUNTIME_ENROLLMENT_AUTHORITY,
            workload_key_provider=seeded["workload_key"],
            receipt_consumption_ledger=ledger,
            authenticated_actor=seeded["identity_id"],
            nonce=challenge_nonce,
            sequence=sequence,
            runtime_build_digest=runtime_build_digest,
            configuration_digest=configuration_digest,
            issued_at=now.isoformat().replace("+00:00", "Z"),
            expires_at=(now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            now=now,
        )
    return artifact.to_dict()


def _submit_wiring_report(
    client: TestClient,
    *,
    app: Any,
    seeded: dict[str, Any],
    tmp_path: Path,
    sequence: int,
) -> tuple[Any, tuple[str, bytes, dict[str, str]]]:
    snapshot_response = _signed_get(client, seeded)
    assert snapshot_response.status_code == 200, snapshot_response.text
    snapshot = snapshot_response.json()
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
        tmp_path=tmp_path,
        sequence=sequence,
    )
    request = _signed_status_request(
        seeded,
        payload={
            "kind": "wiring",
            "sequence": sequence,
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
    )
    path, body, headers = request
    return client.post(path, content=body, headers=headers), request


def _resign_artifact(artifact: dict[str, Any], workload_key: Any) -> dict[str, Any]:
    unsigned = dict(artifact)
    unsigned.pop("attestation_hash", None)
    unsigned.pop("signature", None)
    return {
        **unsigned,
        "attestation_hash": sha256_json(unsigned),
        "signature": workload_key.sign(canonical_json(unsigned).encode("utf-8")),
    }


def _signed_challenge_request(
    seeded: dict[str, Any],
    *,
    snapshot: dict[str, Any],
    runtime_build_digest: str,
    configuration_digest: str,
    request_nonce: str | None = None,
    request_timestamp: str | None = None,
) -> tuple[str, dict[str, str]]:
    snapshot_hash = sha256_bytes(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    )
    query = (
        f"runtime_build_digest={runtime_build_digest}"
        f"&configuration_digest={configuration_digest}"
        f"&policy_snapshot_hash={snapshot_hash}"
    )
    path = f"/v1/runtime-identities/{seeded['identity_id']}/attestation-challenges"
    nonce = request_nonce or f"runtime-challenge-{new_id()}"
    timestamp = request_timestamp or utcnow().isoformat().replace("+00:00", "Z")
    descriptor = seeded["descriptor"]
    workload_key = seeded["workload_key"]
    signature = workload_key.sign(
        canonical_signed_runtime_request_bytes(
            method="GET",
            path=path,
            query=query,
            body=b"",
            timestamp=timestamp,
            nonce=nonce,
            key_id=workload_key.key_id,
            identity_id=seeded["identity_id"],
            credential_id=descriptor.credential_id,
            credential_generation=descriptor.credential_generation,
            idempotency_key=None,
            audience=RUNTIME_ENROLLMENT_AUTHORITY,
        )
    )
    return f"{path}?{query}", {
        "X-ACGS-Runtime-Identity-ID": seeded["identity_id"],
        "X-ACGS-Runtime-Key-ID": workload_key.key_id,
        "X-ACGS-Runtime-Audience": RUNTIME_ENROLLMENT_AUTHORITY,
        "X-ACGS-Runtime-Credential-ID": descriptor.credential_id,
        "X-ACGS-Runtime-Credential-Generation": str(descriptor.credential_generation),
        "X-ACGS-Runtime-Timestamp": timestamp,
        "X-ACGS-Runtime-Nonce": nonce,
        "X-ACGS-Runtime-Body-Sha256": sha256_bytes(b""),
        "X-ACGS-Runtime-Signature": signature,
    }


def _governed_counts(app: Any, org_id: str) -> dict[str, int]:
    with app.state.session_factory() as session:
        return {
            "receipts": session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedDecisionReceipt)
                .where(ManagedDecisionReceipt.org_id == org_id)
            )
            or 0,
            "consumptions": session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedReceiptConsumption)
                .where(ManagedReceiptConsumption.org_id == org_id)
            )
            or 0,
            "events": session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedGovernanceEvent)
                .where(ManagedGovernanceEvent.org_id == org_id)
            )
            or 0,
            "outbox": session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedOutboxMessage)
                .where(ManagedOutboxMessage.org_id == org_id)
            )
            or 0,
            "idempotency": session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeOperationIdempotency)
                .where(
                    RuntimeOperationIdempotency.org_id == org_id,
                    RuntimeOperationIdempotency.operation == "report",
                )
            )
            or 0,
        }


def _report_path_counts(app: Any, org_id: str) -> dict[str, int]:
    counts = _governed_counts(app, org_id)
    with app.state.session_factory() as session:
        counts.update(
            reports=session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeReport)
                .where(RuntimeReport.org_id == org_id)
            )
            or 0,
            nonces=session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeRequestNonce)
                .where(
                    RuntimeRequestNonce.org_id == org_id,
                    RuntimeRequestNonce.purpose == "runtime-report-http",
                )
            )
            or 0,
            attestations=session.scalar(
                sa.select(sa.func.count()).select_from(RuntimeWiringAttestation)
            )
            or 0,
            heads=session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeReportHead)
                .where(RuntimeReportHead.org_id == org_id)
            )
            or 0,
            challenges=session.scalar(
                sa.select(sa.func.count())
                .select_from(RuntimeWiringChallengeConsumption)
                .where(RuntimeWiringChallengeConsumption.org_id == org_id)
            )
            or 0,
        )
    return counts


def _report_attempt_count(app: Any, org_id: str) -> int:
    with app.state.session_factory() as session:
        return (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedMutationAttempt)
                .where(
                    ManagedMutationAttempt.org_id == org_id,
                    ManagedMutationAttempt.action
                    == runtime_reports_module.CONTROL_PLANE_RUNTIME_REPORT_ACCEPT_ACTION,
                )
            )
            or 0
        )
