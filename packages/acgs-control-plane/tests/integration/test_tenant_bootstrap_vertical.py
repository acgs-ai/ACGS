from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import timedelta
from functools import partial
from multiprocessing import get_context
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from gove_zone.decision import Decision, sha256_json
from gove_zone.receipt import DecisionReceipt
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope, TrustConfigurationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.migrations import DatabaseSchemaState, upgrade_database
from acgs_control_plane.models import (
    Environment,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    Organization,
    OrganizationMembership,
    PendingApproval,
    PlatformBootstrapInvitation,
    Project,
    ReceiptRow,
    TenantBootstrapIdempotency,
    TenantBootstrapPendingOutbox,
    TenantBootstrapPolicyArtifact,
    User,
    utcnow,
)
from acgs_control_plane.tenant_bootstrap import (
    BOOTSTRAP_AUTHORIZATION_HEADER,
    BOOTSTRAP_IDEMPOTENCY_HEADER,
    BOOTSTRAP_INVITATION_HEADER,
    BOOTSTRAP_INVITEE_ROLE,
    TENANT_BOOTSTRAP_ACTION,
    TENANT_BOOTSTRAP_AUTHORITY,
    TENANT_BOOTSTRAP_POLICY_HASH,
    TENANT_BOOTSTRAP_POLICY_VERSION,
    _mint_receipt,
    create_platform_bootstrap_invitation,
    local_bootstrap_issuer,
    local_platform_trust_registry,
)
from acgs_control_plane.tenant_bootstrap_test_worker import (
    post_bootstrap_from_spawned_process,
)

ACTOR = "platform:invitee:alice"
BEARER_TOKEN = "local-platform-token-alice"
TOKEN = "tenant_bootstrap_allow_000000000000000000000000000000000000000000"
HEADERS = {
    BOOTSTRAP_AUTHORIZATION_HEADER: f"Bearer {BEARER_TOKEN}",
    BOOTSTRAP_INVITATION_HEADER: TOKEN,
    BOOTSTRAP_IDEMPOTENCY_HEADER: "tenant-bootstrap-key-0001",
}
BODY = {
    "display_name": "Acme Governed",
    "admin_name": "Alice Admin",
    "admin_email": "alice@example.com",
}


@pytest.fixture()
def app_client(tmp_path: Path) -> tuple[TestClient, object]:
    database_url = os.environ.get("ACP_TEST_POSTGRES_URL")
    if (
        os.environ.get("ACP_TEST_POSTGRES_GATE_ACTIVE") != "1"
        or os.environ.get("ACP_TEST_POSTGRES_SELECTOR_MODE") != "p2-tenant-bootstrap"
    ):
        pytest.skip("tenant bootstrap vertical requires the exact P2 PostgreSQL gate")
    if not database_url:
        pytest.fail("ACP_TEST_POSTGRES_URL is required by the P2 tenant bootstrap gate")
    expected_database = "acgs_control_plane_test"
    _reset_postgres_schema(database_url, expected_database)
    result = upgrade_database(database_url, expected_database=expected_database)
    assert result.after.state is DatabaseSchemaState.VERSION_0005
    app = create_app(
        Settings(
            database_url=database_url,
            audit_dir=tmp_path / "audit",
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )
    client = TestClient(app)
    try:
        yield client, app
    finally:
        app.state.engine.dispose()
        _reset_postgres_schema(database_url, expected_database)


def _reset_postgres_schema(database_url: str, expected_database: str) -> None:
    if os.environ.get("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE") != "1":
        pytest.fail("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1 is required")
    url = sa.engine.make_url(database_url)
    if url.get_backend_name() != "postgresql" or url.database != expected_database:
        pytest.fail("P2 tenant bootstrap gate must target the exact disposable database")
    engine = sa.create_engine(
        url.update_query_dict({"options": "-csearch_path=pg_catalog,public"}),
        future=True,
    )
    try:
        with engine.begin() as connection:
            assert connection.scalar(sa.text("SELECT pg_catalog.current_database()")) == (
                expected_database
            )
            connection.execute(sa.text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(sa.text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


def _seed_invitation(
    session: Session,
    *,
    token: str = TOKEN,
    outcome: str = "allow",
    role: str = BOOTSTRAP_INVITEE_ROLE,
) -> PlatformBootstrapInvitation:
    return create_platform_bootstrap_invitation(
        session,
        token=token,
        actor=ACTOR,
        expires_at=utcnow() + timedelta(hours=1),
        policy_outcome=outcome,
        role=role,
    )


def _token(label: str) -> str:
    return f"tenant_bootstrap_{label}_000000000000000000000000000000000000000000"


class _UnavailableTrustRegistry:
    def resolve(self, **_kwargs: object) -> object:
        raise TrustConfigurationError("tenant bootstrap trust provider unavailable")


class _UntrustedTrustRegistry:
    def resolve(self, **_kwargs: object) -> object:
        raise TrustConfigurationError("tenant bootstrap platform key is not trusted")


class _RevokedTrustRegistry:
    def resolve(self, **kwargs: object) -> object:
        return replace(local_platform_trust_registry().resolve(**kwargs), status="revoked")


class _ReceiptIssuer:
    def __init__(
        self,
        *,
        scenario: str = "allow",
        app: object | None = None,
    ) -> None:
        self.scenario = scenario
        self.app = app

    def issue(
        self,
        *,
        context: Any,
        args: dict[str, str],
        decision: Decision,
        reason: str,
        request_id: str,
    ) -> tuple[DecisionReceipt | None, str]:
        if self.scenario == "receipt_missing":
            _, audit_hash = _mint_receipt(
                issuer=local_bootstrap_issuer(),
                context=context,
                args=args,
                decision=decision,
                reason=reason,
                request_id=request_id,
            )
            return None, audit_hash
        if self.scenario == "receipt_malformed":
            _, audit_hash = _mint_receipt(
                issuer=local_bootstrap_issuer(),
                context=context,
                args=args,
                decision=decision,
                reason=reason,
                request_id=request_id,
            )
            return object(), audit_hash  # type: ignore[return-value]

        mint_context = context
        mint_args = dict(args)
        mint_decision = decision
        if self.scenario == "wrong_org":
            mint_context = replace(context, org_id="wrong-bootstrap-org")
        elif self.scenario == "wrong_project":
            mint_context = replace(context, project_id="wrong-bootstrap-project")
        elif self.scenario == "wrong_env":
            mint_context = replace(context, environment_id="wrong-bootstrap-env")
        elif self.scenario == "wrong_boundary":
            mint_context = replace(context, execution_boundary="control-plane:wrong/v1")
        elif self.scenario == "wrong_actor":
            mint_context = replace(context, actor="platform:invitee:mallory")
        elif self.scenario == "wrong_authority":
            mint_context = replace(context, authority="platform.wrong/v1")
        elif self.scenario == "wrong_validator":
            mint_context = replace(context, validator_role="platform.wrong-validator/v1")
        elif self.scenario == "wrong_action":
            mint_context = replace(context, action="tenant.bootstrap.wrong")
        elif self.scenario == "wrong_policy":
            mint_context = replace(
                context,
                policy_bundle_id="platform-tenant-bootstrap-wrong",
                policy_hash=sha256_json({"policy": "wrong"}),
            )
        elif self.scenario == "wrong_args":
            mint_args = {**mint_args, "display_name": "Changed after policy"}
        elif self.scenario == "non_allow":
            mint_decision = Decision.DENY

        receipt, audit_hash = _mint_receipt(
            issuer=local_bootstrap_issuer(),
            context=mint_context,
            args=mint_args,
            decision=mint_decision,
            reason=reason,
            request_id=request_id,
        )

        if self.scenario == "receipt_version":
            receipt = _resign_receipt(
                replace(receipt, receipt_schema_version="gove-zone/decision-receipt/v0")
            )
        elif self.scenario == "receipt_missing_field":
            receipt = _resign_receipt(replace(receipt, validator_id=""))
        elif self.scenario == "signature_invalid":
            receipt = replace(receipt, signature="0" * len(receipt.signature))
        elif self.scenario == "expired":
            receipt = _resign_receipt(
                replace(receipt, expires_at=(utcnow() - timedelta(seconds=1)).isoformat())
            )
        elif self.scenario == "wrong_audit":
            receipt = _resign_receipt(
                replace(receipt, audit_event_hash=sha256_json({"audit": "wrong"}))
            )
        elif self.scenario == "replayed":
            _seed_existing_receipt_projection(self.app, receipt)
        elif self.scenario == "consumed":
            _seed_existing_receipt_projection(self.app, receipt, consumed=True)
        elif self.scenario == "idempotency_conflict_executor":
            _seed_idempotency_conflict(self.app, context)

        return receipt, audit_hash


def _resign_receipt(receipt: DecisionReceipt) -> DecisionReceipt:
    receipt = replace(receipt, receipt_hash=receipt.compute_hash())
    signer = local_bootstrap_issuer().signer_for_scope(
        scope=ReceiptTrustScope(
            tenant_id=receipt.tenant_id,
            project_id=receipt.project_id,
            environment_id=receipt.environment_id,
            purpose=DECISION_RECEIPT_PURPOSE,
        ),
        trust_epoch=receipt.trust_epoch,
    )
    return replace(receipt, signature=signer.sign(receipt.receipt_hash.encode("utf-8")))


def _seed_existing_receipt_projection(
    app: object | None,
    receipt: DecisionReceipt,
    *,
    consumed: bool = False,
) -> None:
    assert app is not None
    with app.state.session_factory() as session:
        with session.begin():
            session.add_all(
                [
                    Organization(id=receipt.tenant_id, name=f"Replay {receipt.request_id}"),
                    Project(
                        id=receipt.project_id,
                        org_id=receipt.tenant_id,
                        slug="default",
                        name="Default",
                    ),
                    Environment(
                        id=receipt.environment_id,
                        org_id=receipt.tenant_id,
                        project_id=receipt.project_id,
                        slug="production",
                        name="Production",
                    ),
                ]
            )
            session.flush()
            receipt_row = ManagedDecisionReceipt(
                id=f"seeded-receipt-{receipt.request_id}",
                org_id=receipt.tenant_id,
                project_id=receipt.project_id,
                environment_id=receipt.environment_id,
                receipt_id=receipt.receipt_id,
                receipt_hash=receipt.receipt_hash,
                audit_event_hash=receipt.audit_event_hash,
                decision=receipt.decision,
                actor=receipt.actor,
                proposed_action=receipt.proposed_action,
                execution_boundary=receipt.execution_boundary,
                policy_bundle_id=receipt.policy_bundle_id,
                policy_version=TENANT_BOOTSTRAP_POLICY_VERSION,
                policy_hash=TENANT_BOOTSTRAP_POLICY_HASH,
                argument_hash=receipt.argument_hash,
                signing_key_id=receipt.signing_key_id,
                signature_algorithm=receipt.signature_algorithm,
                receipt_schema_version=receipt.receipt_schema_version,
                trust_epoch=receipt.trust_epoch,
                assurance_class="native",
                source_system="gove-zone",
                issued_at=utcnow(),
                expires_at=utcnow() + timedelta(minutes=10),
                projection={"schema": "test-seeded-replay/v1"},
                created_at=utcnow(),
            )
            session.add(receipt_row)
            session.flush()
            if consumed:
                session.add(
                    ManagedReceiptConsumption(
                        id=f"seeded-consumption-{receipt.request_id}",
                        org_id=receipt.tenant_id,
                        project_id=receipt.project_id,
                        environment_id=receipt.environment_id,
                        managed_receipt_id=receipt_row.id,
                        receipt_hash=receipt.receipt_hash,
                        audit_event_hash=receipt.audit_event_hash,
                        consumed_at=utcnow(),
                    )
                )


def _seed_idempotency_conflict(app: object | None, context: Any) -> None:
    assert app is not None
    with app.state.session_factory() as session:
        with session.begin():
            invitation = session.scalars(
                sa.select(PlatformBootstrapInvitation).where(
                    PlatformBootstrapInvitation.prospective_org_id == context.org_id,
                    PlatformBootstrapInvitation.prospective_project_id == context.project_id,
                    PlatformBootstrapInvitation.prospective_environment_id
                    == context.environment_id,
                )
            ).one()
            session.add(
                Organization(
                    id=context.org_id,
                    name=f"Seeded Org {context.org_id}",
                )
            )
            session.add(
                Project(
                    id=context.project_id,
                    org_id=context.org_id,
                    name="Seeded Project",
                    slug="default",
                )
            )
            session.add(
                Environment(
                    id=context.environment_id,
                    org_id=context.org_id,
                    project_id=context.project_id,
                    name="Production",
                    slug="production",
                )
            )
            storage_key = app.state.platform_bootstrap_secret_hasher.digest(
                {
                    "schema": "tenant-bootstrap-idempotency-storage-key/v1",
                    "route": "POST /v1/tenant-bootstrap",
                    "actor": ACTOR,
                    "invitation_id": invitation.id,
                    "key": "tenant-bootstrap-key-fault-idempotency_conflict_executor",
                }
            )
            session.add(
                TenantBootstrapIdempotency(
                    id="seeded-idempotency-conflict",
                    idempotency_key=storage_key,
                    actor=ACTOR,
                    request_hash=sha256_json({"different": True}),
                    org_id=context.org_id,
                    project_id=context.project_id,
                    environment_id=context.environment_id,
                    response={"org_id": context.org_id},
                )
            )


def _install_tx_abort_trigger(app: object, *, stage: str) -> None:
    _drop_tx_abort_triggers(app)
    target_table = "organizations" if stage == "pre_callback" else "managed_decision_receipts"
    trigger_name = f"tenant_bootstrap_tx_abort_{stage}"
    function_name = f"tenant_bootstrap_tx_abort_{stage}_fn"
    with app.state.engine.begin() as connection:
        connection.execute(
            sa.text(
                f"""
                CREATE OR REPLACE FUNCTION {function_name}()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'tenant bootstrap tx abort {stage}';
                END;
                $$ LANGUAGE plpgsql;
                """
            )
        )
        connection.execute(
            sa.text(
                f"""
                CREATE TRIGGER {trigger_name}
                BEFORE INSERT ON {target_table}
                FOR EACH ROW EXECUTE FUNCTION {function_name}();
                """
            )
        )


def _drop_tx_abort_triggers(app: object) -> None:
    with app.state.engine.begin() as connection:
        for stage, table in (
            ("pre_callback", "organizations"),
            ("post_callback", "managed_decision_receipts"),
        ):
            connection.execute(
                sa.text(f"DROP TRIGGER IF EXISTS tenant_bootstrap_tx_abort_{stage} ON {table}")
            )
            connection.execute(
                sa.text(f"DROP FUNCTION IF EXISTS tenant_bootstrap_tx_abort_{stage}_fn()")
            )


def _count(session: Session, model: type[object]) -> int:
    return int(session.scalar(sa.select(sa.func.count()).select_from(model)) or 0)


def _counts(session: Session) -> dict[str, int]:
    return {
        "organizations": _count(session, Organization),
        "projects": _count(session, Project),
        "environments": _count(session, Environment),
        "users": _count(session, User),
        "memberships": _count(session, OrganizationMembership),
        "legacy_receipts": _count(session, ReceiptRow),
        "managed_receipts": _count(session, ManagedDecisionReceipt),
        "consumptions": _count(session, ManagedReceiptConsumption),
        "events": _count(session, ManagedGovernanceEvent),
        "outbox": _count(session, ManagedOutboxMessage),
        "attempts": _count(session, ManagedMutationAttempt),
        "idempotency": _count(session, TenantBootstrapIdempotency),
        "policy_artifacts": _count(session, TenantBootstrapPolicyArtifact),
        "pending_approvals": _count(session, PendingApproval),
        "pending_outbox": _count(session, TenantBootstrapPendingOutbox),
    }


def _seeded_client(app_client: tuple[TestClient, object]) -> tuple[TestClient, object]:
    client, app = app_client
    with app.state.session_factory() as session:
        with session.begin():
            _seed_invitation(session)
    return client, app


def test_real_api_postgres_bootstrap_allow_atomic(
    app_client: tuple[TestClient, object],
) -> None:
    client, app = _seeded_client(app_client)

    response = client.post("/v1/tenant-bootstrap", json=BODY, headers=HEADERS)

    assert response.status_code == 201
    payload = response.json()
    assert payload["assurance_class"] == "native"
    assert payload["idempotency_key"] == HEADERS[BOOTSTRAP_IDEMPOTENCY_HEADER]
    with app.state.session_factory() as session:
        assert _counts(session) == {
            "organizations": 1,
            "projects": 1,
            "environments": 1,
            "users": 1,
            "memberships": 1,
            "legacy_receipts": 0,
            "managed_receipts": 1,
            "consumptions": 1,
            "events": 1,
            "outbox": 1,
            "attempts": 1,
            "idempotency": 1,
            "policy_artifacts": 0,
            "pending_approvals": 0,
            "pending_outbox": 0,
        }
        invitation = session.scalars(sa.select(PlatformBootstrapInvitation)).one()
        assert invitation.consumed_org_id == payload["org_id"]
        assert invitation.consumed_at is not None
        receipt = session.scalars(sa.select(ManagedDecisionReceipt)).one()
        assert receipt.actor == ACTOR
        assert receipt.proposed_action == TENANT_BOOTSTRAP_ACTION
        assert receipt.projection["authority"] == TENANT_BOOTSTRAP_AUTHORITY
        assert receipt.assurance_class == "native"
        assert receipt.source_system == "gove-zone"
        assert receipt.receipt_hash == payload["receipt_hash"]
        assert receipt.signature_algorithm == "ed25519"
        assert receipt.signing_key_id == "local-platform-tenant-bootstrap"
        assert receipt.receipt_schema_version == "gove-zone/decision-receipt/v2"
        assert receipt.expires_at > receipt.issued_at
        assert receipt.projection["assurance_class"] == "native"
        assert receipt.projection["sealed_receipt"]["schema"] == "managed-receipt-artifact-seal/v1"
        assert "alice@example.com" not in str(receipt.projection).lower()
        event = session.scalars(sa.select(ManagedGovernanceEvent)).one()
        assert event.event_hash == payload["event_hash"]
        assert event.payload["receipt_hash"] == payload["receipt_hash"]
        outbox = session.scalars(sa.select(ManagedOutboxMessage)).one()
        assert outbox.managed_receipt_id == receipt.id
        assert outbox.managed_event_id == event.id
        assert outbox.payload["assurance_class"] == "native"
        assert "alice@example.com" not in str(outbox.payload).lower()
        session.add(
            ManagedOutboxMessage(
                id="orphan-outbox-row",
                org_id="missing-org",
                project_id="missing-project",
                environment_id="missing-env",
                managed_receipt_id="missing-receipt",
                managed_event_id="missing-event",
                delivery_key="orphan",
                payload_digest="0" * 64,
                payload={"schema": "orphan"},
                status="pending",
                attempts=0,
                created_at=utcnow(),
                available_at=utcnow(),
            )
        )
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()

    retry = client.post("/v1/tenant-bootstrap", json=BODY, headers=HEADERS)
    assert retry.status_code == 201
    assert retry.json() == payload
    with app.state.session_factory() as session:
        counts = _counts(session)
        assert counts["managed_receipts"] == 1
        assert counts["consumptions"] == 1
        assert counts["events"] == 1
        assert counts["outbox"] == 1
        assert counts["idempotency"] == 1
        assert counts["pending_approvals"] == 0
        assert counts["pending_outbox"] == 0


def test_real_api_postgres_bootstrap_refusal_matrix(
    app_client: tuple[TestClient, object],
) -> None:
    client, app = _seeded_client(app_client)

    for body in (
        {**BODY, "org_id": "caller-controlled"},
        {**BODY, "actor": "caller-controlled"},
        {**BODY, "environment_id": "caller-controlled"},
    ):
        malformed = client.post(
            "/v1/tenant-bootstrap",
            json=body,
            headers=HEADERS,
        )
        assert malformed.status_code == 400
        assert malformed.json()["code"] == "REQUEST_MALFORMED"

    malformed_auth = client.post(
        "/v1/tenant-bootstrap",
        json=BODY,
        headers={**HEADERS, BOOTSTRAP_AUTHORIZATION_HEADER: f"Basic {ACTOR}"},
    )
    assert malformed_auth.status_code == 401
    assert malformed_auth.json()["code"] == "AUTHENTICATION_REQUIRED"

    no_actor = client.post(
        "/v1/tenant-bootstrap",
        json=BODY,
        headers={k: v for k, v in HEADERS.items() if k != BOOTSTRAP_AUTHORIZATION_HEADER},
    )
    assert no_actor.status_code == 401
    assert no_actor.json()["code"] == "AUTHENTICATION_REQUIRED"

    unauth_bad_invite_and_idem = client.post(
        "/v1/tenant-bootstrap",
        json=BODY,
        headers={
            BOOTSTRAP_INVITATION_HEADER: "not-strong",
            BOOTSTRAP_IDEMPOTENCY_HEADER: "bad",
        },
    )
    assert unauth_bad_invite_and_idem.status_code == 401
    assert unauth_bad_invite_and_idem.json()["code"] == "AUTHENTICATION_REQUIRED"

    no_permission = client.post(
        "/v1/tenant-bootstrap",
        json=BODY,
        headers={
            **HEADERS,
            BOOTSTRAP_AUTHORIZATION_HEADER: "Bearer local-platform-token-viewer",
            BOOTSTRAP_INVITATION_HEADER: _token("missing"),
            BOOTSTRAP_IDEMPOTENCY_HEADER: "bad",
        },
    )
    assert no_permission.status_code == 403
    assert no_permission.json()["code"] == "AUTHORIZATION_DENIED"

    stolen_invite = client.post(
        "/v1/tenant-bootstrap",
        json=BODY,
        headers={
            **HEADERS,
            BOOTSTRAP_AUTHORIZATION_HEADER: "Bearer local-platform-token-eve",
            BOOTSTRAP_IDEMPOTENCY_HEADER: "tenant-bootstrap-key-stolen",
        },
    )
    assert stolen_invite.status_code == 403
    assert stolen_invite.json()["code"] == "BOOTSTRAP_NOT_AUTHORIZED"

    too_large = client.post(
        "/v1/tenant-bootstrap",
        content=json.dumps({**BODY, "padding": "x" * (16 * 1024)}).encode(),
        headers={
            **HEADERS,
            "content-type": "application/json",
        },
    )
    assert too_large.status_code == 413
    assert too_large.json()["code"] == "REQUEST_TOO_LARGE"

    duplicate_key = client.post(
        "/v1/tenant-bootstrap",
        content=b'{"display_name":"Acme","display_name":"Other","admin_name":"Alice","admin_email":"alice@example.com"}',
        headers={**HEADERS, "content-type": "application/json"},
    )
    assert duplicate_key.status_code == 400
    assert duplicate_key.json()["code"] == "REQUEST_MALFORMED"

    with app.state.session_factory() as session:
        with session.begin():
            _seed_invitation(session, token=_token("viewer"), role="viewer")
    wrong_role = client.post(
        "/v1/tenant-bootstrap",
        json=BODY,
        headers={
            **HEADERS,
            BOOTSTRAP_INVITATION_HEADER: _token("viewer"),
            BOOTSTRAP_IDEMPOTENCY_HEADER: "tenant-bootstrap-key-viewer",
        },
    )
    assert wrong_role.status_code == 403
    assert wrong_role.json()["code"] == "BOOTSTRAP_NOT_AUTHORIZED"

    bad_idempotency = client.post(
        "/v1/tenant-bootstrap",
        json=BODY,
        headers={**HEADERS, BOOTSTRAP_IDEMPOTENCY_HEADER: "bad"},
    )
    assert bad_idempotency.status_code == 400
    assert bad_idempotency.json()["code"] == "IDEMPOTENCY_KEY_INVALID"

    missing_invitation = client.post(
        "/v1/tenant-bootstrap",
        json=BODY,
        headers={
            **HEADERS,
            BOOTSTRAP_INVITATION_HEADER: _token("missing"),
            BOOTSTRAP_IDEMPOTENCY_HEADER: "tenant-bootstrap-key-missing",
        },
    )
    assert missing_invitation.status_code == 403
    assert missing_invitation.json()["code"] == "BOOTSTRAP_NOT_AUTHORIZED"

    for token, mutate in (
        (_token("expired"), lambda invite: setattr(invite, "expires_at", utcnow())),
        (_token("revoked"), lambda invite: setattr(invite, "revoked_at", utcnow())),
    ):
        with app.state.session_factory() as session:
            with session.begin():
                invitation = _seed_invitation(session, token=token)
                mutate(invitation)
        refused = client.post(
            "/v1/tenant-bootstrap",
            json=BODY,
            headers={
                **HEADERS,
                BOOTSTRAP_INVITATION_HEADER: token,
                BOOTSTRAP_IDEMPOTENCY_HEADER: f"tenant-bootstrap-key-{token.rsplit('-', 1)[-1]}",
            },
        )
        assert refused.status_code == 403
        assert refused.json()["code"] == "BOOTSTRAP_NOT_AUTHORIZED"

    class BrokenIssuer:
        key_id = "broken-platform-bootstrap"
        algorithm = "Ed25519"

        def signer_for_scope(self, *_args: object, **_kwargs: object) -> object:
            raise RuntimeError("simulated signer outage")

    with app.state.session_factory() as session:
        with session.begin():
            _seed_invitation(session, token=_token("signer_down"))
    app.state.platform_bootstrap_issuer = BrokenIssuer()
    signer_down = client.post(
        "/v1/tenant-bootstrap",
        json=BODY,
        headers={
            **HEADERS,
            BOOTSTRAP_INVITATION_HEADER: _token("signer_down"),
            BOOTSTRAP_IDEMPOTENCY_HEADER: "tenant-bootstrap-key-signer-down",
        },
    )
    assert signer_down.status_code == 503
    assert signer_down.json()["code"] == "SIGNER_UNAVAILABLE"

    app.state.platform_bootstrap_issuer = local_bootstrap_issuer()

    allowed = client.post("/v1/tenant-bootstrap", json=BODY, headers=HEADERS)
    assert allowed.status_code == 201
    conflict = client.post(
        "/v1/tenant-bootstrap",
        json={**BODY, "display_name": "Different"},
        headers=HEADERS,
    )
    assert conflict.status_code == 409
    assert conflict.json()["code"] == "IDEMPOTENCY_CONFLICT"
    consumed = client.post(
        "/v1/tenant-bootstrap",
        json=BODY,
        headers={**HEADERS, BOOTSTRAP_IDEMPOTENCY_HEADER: "tenant-bootstrap-key-0002"},
    )
    assert consumed.status_code == 403
    assert consumed.json()["code"] == "BOOTSTRAP_NOT_AUTHORIZED"

    for token, outcome, status_code, code in (
        (_token("deny"), "deny", 403, "POLICY_DENIED"),
        (_token("escalate"), "escalate", 202, "ESCALATE_PENDING"),
    ):
        with app.state.session_factory() as session:
            with session.begin():
                _seed_invitation(session, token=token, outcome=outcome)
        blocked = client.post(
            "/v1/tenant-bootstrap",
            json=BODY,
            headers={
                **HEADERS,
                BOOTSTRAP_INVITATION_HEADER: token,
                BOOTSTRAP_IDEMPOTENCY_HEADER: f"tenant-bootstrap-key-{outcome}",
            },
        )
        assert blocked.status_code == status_code
        assert blocked.json()["code"] == code
        repeated = client.post(
            "/v1/tenant-bootstrap",
            json=BODY,
            headers={
                **HEADERS,
                BOOTSTRAP_INVITATION_HEADER: token,
                BOOTSTRAP_IDEMPOTENCY_HEADER: f"tenant-bootstrap-key-{outcome}",
            },
        )
        assert repeated.status_code == status_code
        assert repeated.json()["code"] == code

    with app.state.session_factory() as session:
        baseline_after_policy = _counts(session)
    executor_refusals = {
        "receipt_missing": (400, "RECEIPT_MISSING"),
        "receipt_malformed": (400, "RECEIPT_MALFORMED"),
        "receipt_version": (400, "RECEIPT_VERSION_UNSUPPORTED"),
        "receipt_missing_field": (400, "RECEIPT_FIELD_MISSING"),
        "signature_invalid": (403, "SIGNATURE_INVALID"),
        "key_untrusted": (403, "KEY_UNTRUSTED"),
        "key_revoked": (403, "KEY_REVOKED"),
        "trust_unavailable": (503, "TRUST_PROVIDER_UNAVAILABLE"),
        "expired": (403, "EXPIRED"),
        "replayed": (409, "REPLAYED"),
        "consumed": (409, "CONSUMED"),
        "non_allow": (403, "DECISION_NOT_ALLOW"),
        "wrong_org": (403, "ORG_MISMATCH"),
        "wrong_project": (403, "PROJECT_MISMATCH"),
        "wrong_env": (403, "ENV_MISMATCH"),
        "wrong_boundary": (403, "EXECUTION_BOUNDARY_MISMATCH"),
        "wrong_actor": (403, "ACTOR_MISMATCH"),
        "wrong_authority": (403, "AUTHORITY_MISMATCH"),
        "wrong_validator": (403, "VALIDATOR_MISMATCH"),
        "wrong_action": (403, "ACTION_MISMATCH"),
        "wrong_args": (403, "ARGUMENTS_MISMATCH"),
        "wrong_policy": (403, "POLICY_MISMATCH"),
        "wrong_audit": (403, "AUDIT_ANCHOR_MISMATCH"),
        "idempotency_conflict_executor": (409, "IDEMPOTENCY_CONFLICT"),
        "tx_abort_pre_callback": (503, "TX_ABORTED"),
        "tx_abort_post_callback": (503, "TX_ABORTED"),
    }
    expected_after_refusals = dict(baseline_after_policy)
    for index, (scenario, (status_code, code)) in enumerate(executor_refusals.items()):
        token = _token(f"fault_{index}")
        with app.state.session_factory() as session:
            with session.begin():
                _seed_invitation(session, token=token)
        app.state.platform_bootstrap_receipt_issuer = _ReceiptIssuer(scenario=scenario, app=app)
        app.state.platform_bootstrap_trust_registry = local_platform_trust_registry()
        if scenario == "key_untrusted":
            app.state.platform_bootstrap_trust_registry = _UntrustedTrustRegistry()
        elif scenario == "key_revoked":
            app.state.platform_bootstrap_trust_registry = _RevokedTrustRegistry()
        elif scenario == "trust_unavailable":
            app.state.platform_bootstrap_trust_registry = _UnavailableTrustRegistry()
        elif scenario == "tx_abort_pre_callback":
            _install_tx_abort_trigger(app, stage="pre_callback")
        elif scenario == "tx_abort_post_callback":
            _install_tx_abort_trigger(app, stage="post_callback")
        response = client.post(
            "/v1/tenant-bootstrap",
            json=BODY,
            headers={
                **HEADERS,
                BOOTSTRAP_INVITATION_HEADER: token,
                BOOTSTRAP_IDEMPOTENCY_HEADER: f"tenant-bootstrap-key-fault-{scenario}",
            },
        )
        app.state.platform_bootstrap_receipt_issuer = None
        app.state.platform_bootstrap_trust_registry = local_platform_trust_registry()
        _drop_tx_abort_triggers(app)
        assert response.status_code == status_code, (scenario, response.json())
        assert response.json()["code"] == code, scenario
        with app.state.session_factory() as session:
            if scenario == "replayed":
                expected_after_refusals["organizations"] += 1
                expected_after_refusals["projects"] += 1
                expected_after_refusals["environments"] += 1
                expected_after_refusals["managed_receipts"] += 1
            elif scenario == "consumed":
                expected_after_refusals["organizations"] += 1
                expected_after_refusals["projects"] += 1
                expected_after_refusals["environments"] += 1
                expected_after_refusals["managed_receipts"] += 1
                expected_after_refusals["consumptions"] += 1
            elif scenario == "idempotency_conflict_executor":
                expected_after_refusals["organizations"] += 1
                expected_after_refusals["projects"] += 1
                expected_after_refusals["environments"] += 1
                expected_after_refusals["idempotency"] += 1
            assert _counts(session) == expected_after_refusals, scenario

    with app.state.session_factory() as session:
        counts = _counts(session)
        assert counts == expected_after_refusals
        assert (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(Organization)
                .where(Organization.name == BODY["display_name"])
            )
            == 1
        )
        assert counts["legacy_receipts"] == 0
        assert counts["policy_artifacts"] == 2
        assert counts["pending_approvals"] == 1
        assert counts["events"] == 1
        assert counts["outbox"] == 1
        artifacts = session.scalars(sa.select(TenantBootstrapPolicyArtifact)).all()
        assert {artifact.decision for artifact in artifacts} == {"deny", "escalate"}
        assert all(artifact.event["assurance_class"] == "native" for artifact in artifacts)
        assert all(
            "alice@example.com" not in str(artifact.sealed_receipt).lower()
            for artifact in artifacts
        )
        pending = session.scalars(sa.select(PendingApproval)).one()
        assert pending.status == "pending"
        assert pending.actor == ACTOR
        assert pending.action == TENANT_BOOTSTRAP_ACTION
        assert pending.lineage["pending_outbox"]["delivery_key"].startswith(
            "tenant-bootstrap/escalate:"
        )
        pending_outbox = session.scalars(sa.select(TenantBootstrapPendingOutbox)).one()
        assert pending_outbox.payload["schema"] == "tenant-bootstrap-pending-outbox/v1"
        assert pending_outbox.payload["receipt_hash"] == pending.receipt_hash
        assert pending_outbox.payload_digest == pending.lineage["pending_outbox"]["payload_digest"]
        assert pending_outbox.invitation_id == pending.invitation_id


def test_postgres_rejects_cross_invitation_policy_artifact_lineage(
    app_client: tuple[TestClient, object],
) -> None:
    _client, app = app_client
    artifact_a_id = "artifact-lineage-a"
    artifact_b_id = "artifact-lineage-b"
    with app.state.session_factory() as session:
        with session.begin():
            invitation_a = _seed_invitation(
                session,
                token=_token("lineage_a"),
                outcome="escalate",
            )
            invitation_b = _seed_invitation(
                session,
                token=_token("lineage_b"),
                outcome="escalate",
            )
            session.add_all(
                [
                    TenantBootstrapPolicyArtifact(
                        id=artifact_a_id,
                        invitation_id=invitation_a.id,
                        org_id=invitation_a.prospective_org_id,
                        project_id=invitation_a.prospective_project_id,
                        environment_id=invitation_a.prospective_environment_id,
                        decision="escalate",
                        receipt_hash="a" * 64,
                        audit_event_hash="b" * 64,
                        sealed_receipt={"schema": "test-receipt/v1"},
                        event={"schema": "test-event/v1"},
                        created_at=utcnow(),
                    ),
                    TenantBootstrapPolicyArtifact(
                        id=artifact_b_id,
                        invitation_id=invitation_b.id,
                        org_id=invitation_b.prospective_org_id,
                        project_id=invitation_b.prospective_project_id,
                        environment_id=invitation_b.prospective_environment_id,
                        decision="escalate",
                        receipt_hash="c" * 64,
                        audit_event_hash="d" * 64,
                        sealed_receipt={"schema": "test-receipt/v1"},
                        event={"schema": "test-event/v1"},
                        created_at=utcnow(),
                    ),
                ]
            )
        invitation_a_id = invitation_a.id
        invitation_b_id = invitation_b.id

    with pytest.raises(IntegrityError):
        with app.state.session_factory() as session:
            with session.begin():
                session.add(
                    PendingApproval(
                        id="pending-cross-lineage",
                        org_id="pending-org",
                        project_id="pending-project",
                        environment_id="pending-env",
                        actor=ACTOR,
                        action=TENANT_BOOTSTRAP_ACTION,
                        invitation_id=invitation_b_id,
                        policy_artifact_id=artifact_a_id,
                        receipt_hash="e" * 64,
                        audit_event_hash="f" * 64,
                        lineage={"schema": "test-lineage/v1"},
                        status="pending",
                        created_at=utcnow(),
                    )
                )

    with pytest.raises(IntegrityError):
        with app.state.session_factory() as session:
            with session.begin():
                session.add(
                    TenantBootstrapPendingOutbox(
                        id="outbox-cross-lineage",
                        invitation_id=invitation_a_id,
                        policy_artifact_id=artifact_b_id,
                        delivery_key="tenant-bootstrap/escalate:cross-lineage",
                        payload_digest="0" * 64,
                        payload={"schema": "test-pending-outbox/v1"},
                        status="pending",
                        attempts=0,
                        created_at=utcnow(),
                        available_at=utcnow(),
                        delivered_at=None,
                    )
                )

    with app.state.session_factory() as session:
        assert _count(session, PendingApproval) == 0
        assert _count(session, TenantBootstrapPendingOutbox) == 0


def test_100_request_multiprocess_bootstrap_once(
    app_client: tuple[TestClient, object],
) -> None:
    _client, app = _seeded_client(app_client)

    context = get_context("spawn")
    with context.Pool(processes=100) as pool:
        worker = partial(post_bootstrap_from_spawned_process, body=BODY, headers=HEADERS)
        results = pool.map(worker, range(100))

    assert {status for status, _payload in results} == {201}
    first_payload = results[0][1]
    assert all(payload == first_payload for _status, payload in results)
    with app.state.session_factory() as session:
        counts = _counts(session)
        assert counts["organizations"] == 1
        assert counts["projects"] == 1
        assert counts["environments"] == 1
        assert counts["users"] == 1
        assert counts["memberships"] == 1
        assert counts["legacy_receipts"] == 0
        assert counts["managed_receipts"] == 1
        assert counts["consumptions"] == 1
        assert counts["events"] == 1
        assert counts["outbox"] == 1
        assert counts["idempotency"] == 1
        assert counts["pending_approvals"] == 0
        assert counts["pending_outbox"] == 0
