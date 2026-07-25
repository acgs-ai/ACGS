from __future__ import annotations

import inspect
import json
import os
from collections.abc import Iterator, Mapping
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
from gove_zone.errors import (
    ReceiptRejectionReason,
    ReceiptValidationError,
)
from gove_zone.receipt import DecisionReceipt
from gove_zone.trust import (
    DECISION_RECEIPT_PURPOSE,
    ReceiptTrustScope,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import acgs_control_plane.tenant_bootstrap as tenant_bootstrap_module  # type: ignore[import-untyped]
from acgs_control_plane.app import create_app  # type: ignore[import-untyped]
from acgs_control_plane.config import RuntimePosture, Settings  # type: ignore[import-untyped]
from acgs_control_plane.governance import ROUTE_CONTRACTS  # type: ignore[import-untyped]
from acgs_control_plane.managed_mutations import (  # type: ignore[import-untyped]
    TENANT_BOOTSTRAP_EXECUTION_BOUNDARY,
)
from acgs_control_plane.migrations import (  # type: ignore[import-untyped]
    DatabaseSchemaState,
    upgrade_database,
)
from acgs_control_plane.models import (  # type: ignore[import-untyped]
    Environment,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    ManagedTrustKey,
    Organization,
    OrganizationMembership,
    PendingApproval,
    PlatformBootstrapInvitation,
    Project,
    ReceiptRow,
    TenantBootstrapIdempotency,
    TenantBootstrapPendingOutbox,
    TenantBootstrapPolicyArtifact,
    TenantBootstrapRefusalEvent,
    User,
    utcnow,
)
from acgs_control_plane.schemas import TenantBootstrapRequest  # type: ignore[import-untyped]
from acgs_control_plane.tenant_bootstrap import (
    BOOTSTRAP_AUTHORIZATION_HEADER,
    BOOTSTRAP_IDEMPOTENCY_HEADER,
    BOOTSTRAP_INVITATION_HEADER,
    BOOTSTRAP_INVITEE_ROLE,
    PLATFORM_BOOTSTRAP_RECEIPT_PURPOSE,
    TENANT_BOOTSTRAP_ACTION,
    TENANT_BOOTSTRAP_AUTHORITY,
    TENANT_BOOTSTRAP_POLICY_HASH,
    TENANT_BOOTSTRAP_POLICY_VERSION,
    BootstrapKeyUntrusted,
    BootstrapTrustUnavailable,
    TenantBootstrapProviders,
    _context_and_args,
    _mint_receipt,
    create_platform_bootstrap_invitation,
    local_bootstrap_issuer,
    local_bootstrap_secret_hasher,
    local_platform_trust_registry,
    local_receipt_sealer,
)
from acgs_control_plane.tenant_bootstrap_test_worker import (  # type: ignore[import-untyped]
    post_bootstrap_from_spawned_process,
)
from acgs_control_plane.trust import SqlReceiptTrustRegistry  # type: ignore[import-untyped]

ACTOR = "platform:invitee:alice"
BEARER_TOKEN = "local-platform-token-alice"
TOKEN = "tenant_bootstrap_allow_000000000000000000000000000000000000000000"
HEADERS = {
    BOOTSTRAP_AUTHORIZATION_HEADER: f"Bearer {BEARER_TOKEN}",
    BOOTSTRAP_INVITATION_HEADER: TOKEN,
    BOOTSTRAP_IDEMPOTENCY_HEADER: "tenant-bootstrap-key-0001",
}
BODY: dict[str, object] = {
    "display_name": "Acme Governed",
    "admin_name": "Alice Admin",
    "admin_email": "alice@example.com",
}
POLICY_ARTIFACT_SEALER = local_receipt_sealer()


@pytest.fixture()
def app_client(tmp_path: Path) -> Iterator[tuple[TestClient, Any]]:
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


def _seed_invitation_in_app(
    app: Any,
    *,
    token: str = TOKEN,
    outcome: str = "allow",
    role: str = BOOTSTRAP_INVITEE_ROLE,
    mutate: Any | None = None,
) -> None:
    with app.state.session_factory() as session:
        with session.begin():
            invitation = _seed_invitation(session, token=token, outcome=outcome, role=role)
            if mutate is not None:
                mutate(invitation)


def _token(label: str) -> str:
    return f"tenant_bootstrap_{label}_000000000000000000000000000000000000000000"


class _UnavailableTrustRegistry:
    def resolve(self, **_kwargs: object) -> object:
        raise BootstrapTrustUnavailable("tenant bootstrap trust provider unavailable")


class _UntrustedTrustRegistry:
    def resolve(self, **_kwargs: object) -> object:
        raise BootstrapKeyUntrusted("tenant bootstrap platform key is not trusted")


class _RevokedTrustRegistry:
    def resolve(self, **kwargs: Any) -> object:
        return replace(local_platform_trust_registry().resolve(**kwargs), status="revoked")


class _ReceiptIssuer:
    def __init__(
        self,
        *,
        scenario: str = "allow",
        app: object | None = None,
        preissued_receipt: DecisionReceipt | None = None,
    ) -> None:
        self.scenario = scenario
        self.app = app
        self.preissued_receipt = preissued_receipt

    def issue(
        self,
        *,
        context: Any,
        args: dict[str, str],
        decision: Decision,
        reason: str,
        request_id: str,
    ) -> tuple[DecisionReceipt | None, str]:
        if self.preissued_receipt is not None:
            return self.preissued_receipt, self.preissued_receipt.audit_event_hash
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
            return object(), audit_hash

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
        elif self.scenario in {"signature_invalid_deny", "signature_invalid_escalate"}:
            mint_decision = (
                Decision.ESCALATE
                if self.scenario == "signature_invalid_escalate"
                else Decision.DENY
            )

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
        elif self.scenario in {
            "signature_invalid",
            "signature_invalid_deny",
            "signature_invalid_escalate",
        }:
            receipt = replace(receipt, signature="0" * len(receipt.signature))
        elif self.scenario == "expired":
            receipt = _resign_receipt(
                replace(receipt, expires_at=(utcnow() - timedelta(seconds=1)).isoformat())
            )
        elif self.scenario == "future_issued":
            future_issued_at = utcnow() + timedelta(seconds=301)
            receipt = _resign_receipt(
                replace(
                    receipt,
                    timestamp=future_issued_at.isoformat(),
                    expires_at=(future_issued_at + timedelta(minutes=10)).isoformat(),
                )
            )
        elif self.scenario == "wrong_audit":
            receipt = _resign_receipt(
                replace(receipt, audit_event_hash=sha256_json({"audit": "wrong"}))
            )

        return receipt, audit_hash


def _resign_receipt(receipt: DecisionReceipt) -> DecisionReceipt:
    receipt = replace(receipt, receipt_hash=receipt.compute_hash())
    signer = local_bootstrap_issuer().signer_for_scope(
        scope=ReceiptTrustScope(
            tenant_id=receipt.tenant_id,
            project_id=receipt.project_id,
            environment_id=receipt.environment_id,
            purpose=PLATFORM_BOOTSTRAP_RECEIPT_PURPOSE,
        ),
        trust_epoch=receipt.trust_epoch,
    )
    return replace(receipt, signature=signer.sign(receipt.receipt_hash.encode("utf-8")))


def _seed_existing_receipt_projection(
    app: Any | None,
    receipt: DecisionReceipt,
    *,
    consumed: bool = False,
) -> None:
    assert app is not None
    seed_suffix = sha256_json(
        {
            "schema": "tenant-bootstrap-seeded-replay-id/v1",
            "request_id": receipt.request_id,
        }
    )[:24]
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
                id=f"seeded-receipt-{seed_suffix}",
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
                        id=f"seeded-consumption-{seed_suffix}",
                        org_id=receipt.tenant_id,
                        project_id=receipt.project_id,
                        environment_id=receipt.environment_id,
                        managed_receipt_id=receipt_row.id,
                        receipt_hash=receipt.receipt_hash,
                        audit_event_hash=receipt.audit_event_hash,
                        consumed_at=utcnow(),
                    )
                )


def _seed_idempotency_conflict(app: Any | None, context: Any) -> None:
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
            session.flush()
            storage_key = local_bootstrap_secret_hasher().digest(
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


def _preseed_state_for_fault(
    app: Any,
    *,
    scenario: str,
    token: str,
) -> DecisionReceipt | None:
    request_id = f"tenant-bootstrap-key-fault-{scenario}"
    with app.state.session_factory() as session:
        invitation = session.scalars(
            sa.select(PlatformBootstrapInvitation).where(
                PlatformBootstrapInvitation.token_hash
                == local_bootstrap_secret_hasher().digest(
                    {
                        "schema": "tenant-bootstrap-invitation-token/v1",
                        "token": token,
                    }
                )
            )
        ).one()
        context, _args = _context_and_args(
            invitation,
            TenantBootstrapRequest.model_validate(BODY),
            ACTOR,
            request_id,
        )
    if scenario == "idempotency_conflict_executor":
        _seed_idempotency_conflict(app, context)
        return None
    if scenario not in {"replayed", "consumed", "signature_invalid_replayed"}:
        return None
    receipt, _audit_hash = _mint_receipt(
        issuer=local_bootstrap_issuer(),
        context=context,
        args=_args,
        decision=Decision.ALLOW,
        reason="preseeded receipt replay fixture",
        request_id=request_id,
    )
    _seed_existing_receipt_projection(app, receipt, consumed=scenario == "consumed")
    if scenario == "signature_invalid_replayed":
        return replace(receipt, signature="0" * len(receipt.signature))
    return receipt


def _install_tx_abort_trigger(app: Any, *, stage: str) -> None:
    _drop_tx_abort_triggers(app)
    trigger_name = f"tenant_bootstrap_tx_abort_{stage}"
    function_name = f"tenant_bootstrap_tx_abort_{stage}_fn"
    callback_count_statement = (
        "PERFORM nextval('tenant_bootstrap_callback_seq');" if stage == "post_callback" else ""
    )
    with app.state.engine.begin() as connection:
        connection.execute(sa.text("CREATE SEQUENCE IF NOT EXISTS tenant_bootstrap_callback_seq"))
        connection.execute(
            sa.text(
                f"""
                CREATE OR REPLACE FUNCTION {function_name}()
                RETURNS trigger AS $$
                BEGIN
                    {callback_count_statement}
                    RAISE EXCEPTION 'tenant bootstrap tx abort {stage}';
                END;
                $$ LANGUAGE plpgsql;
                """
            )
        )
        if stage == "post_callback":
            connection.execute(
                sa.text(
                    f"""
                    CREATE CONSTRAINT TRIGGER {trigger_name}
                    AFTER INSERT ON organizations
                    DEFERRABLE INITIALLY DEFERRED
                    FOR EACH ROW EXECUTE FUNCTION {function_name}();
                    """
                )
            )
            return
        assert stage == "pre_callback"
        connection.execute(
            sa.text(
                f"""
                CREATE TRIGGER {trigger_name}
                BEFORE INSERT ON managed_receipt_consumptions
                FOR EACH ROW EXECUTE FUNCTION {function_name}();
                """
            )
        )


def _drop_tx_abort_triggers(app: Any, *, drop_counter: bool = False) -> None:
    with app.state.engine.begin() as connection:
        for stage, table in (
            ("pre_callback", "managed_receipt_consumptions"),
            ("post_callback", "organizations"),
        ):
            connection.execute(
                sa.text(f"DROP TRIGGER IF EXISTS tenant_bootstrap_tx_abort_{stage} ON {table}")
            )
            connection.execute(
                sa.text(f"DROP FUNCTION IF EXISTS tenant_bootstrap_tx_abort_{stage}_fn()")
            )
        connection.execute(
            sa.text("DROP TRIGGER IF EXISTS tenant_bootstrap_callback_counter ON organizations")
        )
        connection.execute(
            sa.text("DROP FUNCTION IF EXISTS tenant_bootstrap_callback_counter_fn()")
        )
        if drop_counter:
            connection.execute(sa.text("DROP SEQUENCE IF EXISTS tenant_bootstrap_callback_seq"))


def _callback_count(app: Any) -> int:
    with app.state.engine.connect() as connection:
        exists = connection.scalar(sa.text("SELECT to_regclass('tenant_bootstrap_callback_seq')"))
        if exists is None:
            return 0
        row = connection.execute(
            sa.text("SELECT last_value, is_called FROM tenant_bootstrap_callback_seq")
        ).one()
        return int(row.last_value) if row.is_called else 0


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
        "refusal_events": _count(session, TenantBootstrapRefusalEvent),
    }


_DOMAIN_COUNT_KEYS = (
    "organizations",
    "projects",
    "environments",
    "users",
    "memberships",
)
_ALLOW_EXECUTION_COUNT_KEYS = (
    "managed_receipts",
    "consumptions",
    "events",
    "outbox",
    "attempts",
    "idempotency",
)
_GOVERNANCE_PENDING_COUNT_KEYS = (
    "policy_artifacts",
    "pending_approvals",
    "pending_outbox",
)


def _assert_exact_deltas(
    *,
    label: str,
    before: dict[str, int],
    after: dict[str, int],
    expected: dict[str, int],
) -> None:
    for key, before_value in before.items():
        assert after[key] == before_value + expected.get(key, 0), (
            label,
            key,
            before,
            after,
            expected,
        )


def _assert_tenant_bootstrap_has_no_external_effect_contract(app: Any) -> None:
    contract = [
        route
        for route in ROUTE_CONTRACTS
        if route.method == "POST" and route.path == "/v1/tenant-bootstrap"
    ]
    assert len(contract) == 1
    assert contract[0].permits_external_effect is False
    assert (
        "tenant_bootstrap_external_effect_observer" not in inspect.signature(create_app).parameters
    )
    assert not hasattr(app.state.tenant_bootstrap_service, "_external_effect_observer")
    for provider_slot in (
        "platform_bootstrap_issuer",
        "platform_bootstrap_authenticator",
        "platform_bootstrap_secret_hasher",
        "platform_bootstrap_trust_registry",
        "platform_receipt_sealer",
        "platform_bootstrap_receipt_issuer",
    ):
        assert not hasattr(app.state, provider_slot)


def _assert_tenant_bootstrap_provider_slots_frozen(app: Any) -> None:
    service = app.state.tenant_bootstrap_service
    providers = service._providers
    session_factory = service._session_factory
    provider_identities = {
        name: getattr(providers, name)
        for name in (
            "issuer",
            "authenticator",
            "secret_hasher",
            "trust_registry",
            "receipt_sealer",
            "receipt_issuer",
        )
    }
    rogue_providers = TenantBootstrapProviders(
        issuer=provider_identities["issuer"],
        authenticator=provider_identities["authenticator"],
        secret_hasher=provider_identities["secret_hasher"],
        trust_registry=provider_identities["trust_registry"],
        receipt_sealer=provider_identities["receipt_sealer"],
        receipt_issuer=provider_identities["receipt_issuer"],
    )
    mutation_attempts = [
        (service, "_sealed", False),
        (service, "_session_factory", lambda: None),
        (service, "_providers", rogue_providers),
        (service, "_issuer", provider_identities["issuer"]),
        (service, "_authenticator", provider_identities["authenticator"]),
        (service, "_secret_hasher", provider_identities["secret_hasher"]),
        (service, "_trust_registry", provider_identities["trust_registry"]),
        (service, "_receipt_sealer", provider_identities["receipt_sealer"]),
        (service, "_receipt_issuer", provider_identities["receipt_issuer"]),
        (service, "arbitrary_provider_attr", object()),
        (providers, "issuer", object()),
        (providers, "authenticator", object()),
        (providers, "secret_hasher", object()),
        (providers, "trust_registry", object()),
        (providers, "receipt_sealer", object()),
        (providers, "receipt_issuer", object()),
    ]
    for target, attribute, value in mutation_attempts:
        with pytest.raises(AttributeError):
            setattr(target, attribute, value)
        assert service._providers is providers
        assert service._session_factory is session_factory
        assert {
            name: getattr(service._providers, name) for name in provider_identities
        } == provider_identities


def _assert_no_outbox_delivery_attempted(session: Session) -> None:
    for outbox in session.scalars(sa.select(ManagedOutboxMessage)).all():
        assert outbox.status == "pending"
        assert outbox.attempts == 0
        assert outbox.delivered_at is None
    for pending in session.scalars(sa.select(TenantBootstrapPendingOutbox)).all():
        assert pending.status == "pending"
        assert pending.attempts == 0
        assert pending.delivered_at is None


def _sealed_receipt_associated_data_hash(
    *,
    receipt_hash: str,
) -> str:
    import hashlib

    associated_data = _tenant_bootstrap_policy_artifact_aad(receipt_hash=receipt_hash)
    return hashlib.sha256(associated_data).hexdigest()


def _canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _tenant_bootstrap_policy_artifact_aad(*, receipt_hash: str) -> bytes:
    return _canonical_json_bytes(
        {
            "schema": "tenant-bootstrap-policy-artifact/v1",
            "receipt_hash": receipt_hash,
        }
    )


def _invitation_by_token_hash(session: Session, token: str) -> PlatformBootstrapInvitation:
    token_hash = local_bootstrap_secret_hasher().digest(
        {
            "schema": "tenant-bootstrap-invitation-token/v1",
            "token": token,
        }
    )
    return session.scalars(
        sa.select(PlatformBootstrapInvitation).where(
            PlatformBootstrapInvitation.token_hash == token_hash
        )
    ).one()


def _unseal_policy_artifact_receipt(artifact: TenantBootstrapPolicyArtifact) -> DecisionReceipt:
    associated_data = _tenant_bootstrap_policy_artifact_aad(receipt_hash=artifact.receipt_hash)
    plaintext = POLICY_ARTIFACT_SEALER.unseal(
        artifact.sealed_receipt,
        associated_data=associated_data,
    )
    payload = json.loads(plaintext.decode("utf-8"))
    assert isinstance(payload, dict)
    receipt = DecisionReceipt.from_dict(payload)
    assert _canonical_json_bytes(receipt.to_dict()) == plaintext
    return receipt


def _assert_policy_artifact_receipt_integrity(
    session: Session,
    *,
    artifact: TenantBootstrapPolicyArtifact,
    decision: str,
) -> DecisionReceipt:
    receipt = _unseal_policy_artifact_receipt(artifact)
    assert receipt.compute_hash() == receipt.receipt_hash
    assert receipt.receipt_hash == artifact.receipt_hash
    assert receipt.audit_event_hash == artifact.audit_event_hash
    assert receipt.decision == decision
    assert receipt.tenant_id == artifact.org_id
    assert receipt.project_id == artifact.project_id
    assert receipt.environment_id == artifact.environment_id
    assert receipt.execution_boundary == TENANT_BOOTSTRAP_EXECUTION_BOUNDARY
    assert receipt.proposed_action == TENANT_BOOTSTRAP_ACTION
    assert receipt.actor == ACTOR
    assert receipt.authority == TENANT_BOOTSTRAP_AUTHORITY
    assert receipt.validator_role == "platform.bootstrap-policy/v1"
    assert receipt.policy_bundle_id == "platform-tenant-bootstrap"
    assert receipt.policy_version == TENANT_BOOTSTRAP_POLICY_VERSION
    assert receipt.policy_hash == TENANT_BOOTSTRAP_POLICY_HASH
    assert receipt.signature_algorithm == "ed25519"
    assert receipt.signing_key_id == "local-platform-tenant-bootstrap"
    assert receipt.receipt_schema_version == "gove-zone/decision-receipt/v2"
    invitation = session.get(PlatformBootstrapInvitation, artifact.invitation_id)
    assert invitation is not None
    proof_context, proof_args = _context_and_args(
        invitation,
        TenantBootstrapRequest.model_validate(BODY),
        ACTOR,
        receipt.request_id,
    )
    assert proof_context.org_id == artifact.org_id
    assert proof_context.project_id == artifact.project_id
    assert proof_context.environment_id == artifact.environment_id
    assert proof_context.execution_boundary == receipt.execution_boundary
    expected_terminal_reason = {
        Decision.DENY.value: ReceiptRejectionReason.DENIED_RECEIPT,
        Decision.ESCALATE.value: ReceiptRejectionReason.ESCALATED_RECEIPT,
    }[decision]
    with pytest.raises(ReceiptValidationError) as exc_info:
        receipt.verify(
            expected_tenant_id=artifact.org_id,
            expected_execution_boundary=receipt.execution_boundary,
            expected_action=TENANT_BOOTSTRAP_ACTION,
            expected_actor=ACTOR,
            expected_audit_hash=artifact.audit_event_hash,
            expected_args=proof_args,
            expected_policy_hash=TENANT_BOOTSTRAP_POLICY_HASH,
            expected_policy_bundle_id="platform-tenant-bootstrap",
            expected_project_id=artifact.project_id,
            expected_environment_id=artifact.environment_id,
            expected_validator_role="platform.bootstrap-policy/v1",
            expected_authority=TENANT_BOOTSTRAP_AUTHORITY,
            verifier=None,
            require_signature=True,
            require_expiry=True,
            trust_registry=local_platform_trust_registry(),
            trust_purpose=PLATFORM_BOOTSTRAP_RECEIPT_PURPOSE,
        )
    assert exc_info.value.reason_code == expected_terminal_reason
    return receipt


def _assert_policy_artifact_case(
    session: Session,
    *,
    label: str,
    decision: str,
    before_artifact_ids: set[str],
    before_pending_ids: set[str],
    before_pending_outbox_ids: set[str],
) -> None:
    artifacts = [
        artifact
        for artifact in session.scalars(sa.select(TenantBootstrapPolicyArtifact)).all()
        if artifact.id not in before_artifact_ids
    ]
    assert len(artifacts) == 1, label
    artifact = artifacts[0]
    assert artifact.decision == decision
    receipt = _assert_policy_artifact_receipt_integrity(
        session,
        artifact=artifact,
        decision=decision,
    )
    assert len(artifact.receipt_hash) == 64
    assert len(artifact.audit_event_hash) == 64
    assert artifact.event["decision"] == decision
    assert artifact.event["receipt_hash"] == artifact.receipt_hash
    assert artifact.event["audit_event_hash"] == artifact.audit_event_hash
    assert artifact.event["argument_hash"] == receipt.argument_hash
    assert artifact.event["policy_bundle_id"] == "platform-tenant-bootstrap"
    assert artifact.event["policy_version"] == TENANT_BOOTSTRAP_POLICY_VERSION
    assert artifact.event["policy_hash"] == TENANT_BOOTSTRAP_POLICY_HASH
    assert artifact.event["org_id"] == artifact.org_id
    assert artifact.event["project_id"] == artifact.project_id
    assert artifact.event["environment_id"] == artifact.environment_id
    assert artifact.event["assurance_class"] == "native"
    assert artifact.event["source_system"] == "gove-zone"
    assert artifact.event == {
        "schema": "tenant-bootstrap-policy-artifact-event/v1",
        "decision": receipt.decision,
        "audit_event_hash": receipt.audit_event_hash,
        "actor_hash": sha256_json(receipt.actor),
        "argument_hash": receipt.argument_hash,
        "receipt_hash": receipt.receipt_hash,
        "policy_bundle_id": receipt.policy_bundle_id,
        "policy_version": receipt.policy_version,
        "policy_hash": receipt.policy_hash,
        "org_id": receipt.tenant_id,
        "project_id": receipt.project_id,
        "environment_id": receipt.environment_id,
        "assurance_class": "native",
        "source_system": "gove-zone",
    }
    assert artifact.sealed_receipt["schema"] == "managed-receipt-artifact-seal/v1"
    assert artifact.sealed_receipt["associated_data_sha256"] == (
        _sealed_receipt_associated_data_hash(
            receipt_hash=artifact.receipt_hash,
        )
    )
    pending = [
        row
        for row in session.scalars(sa.select(PendingApproval)).all()
        if row.id not in before_pending_ids
    ]
    pending_outbox = [
        row
        for row in session.scalars(sa.select(TenantBootstrapPendingOutbox)).all()
        if row.id not in before_pending_outbox_ids
    ]
    if decision == Decision.DENY.value:
        assert pending == [], label
        assert pending_outbox == [], label
        return
    assert decision == Decision.ESCALATE.value
    assert len(pending) == 1, label
    assert len(pending_outbox) == 1, label
    approval = pending[0]
    outbox = pending_outbox[0]
    assert approval.invitation_id == artifact.invitation_id
    assert approval.policy_artifact_id == artifact.id
    assert approval.receipt_hash == artifact.receipt_hash
    assert approval.audit_event_hash == artifact.audit_event_hash
    assert approval.org_id == artifact.org_id
    assert approval.project_id == artifact.project_id
    assert approval.environment_id == artifact.environment_id
    assert approval.status == "pending"
    assert outbox.invitation_id == artifact.invitation_id
    assert outbox.policy_artifact_id == artifact.id
    assert outbox.org_id == artifact.org_id
    assert outbox.project_id == artifact.project_id
    assert outbox.environment_id == artifact.environment_id
    assert outbox.delivery_key == f"tenant-bootstrap/escalate:{artifact.receipt_hash}"
    assert outbox.payload_digest == sha256_json(outbox.payload)
    assert outbox.payload["policy_artifact_id"] == artifact.id
    assert outbox.payload["receipt_hash"] == artifact.receipt_hash
    assert outbox.payload["audit_event_hash"] == artifact.audit_event_hash
    assert outbox.payload["argument_hash"] == artifact.event["argument_hash"]
    assert outbox.payload["assurance_class"] == "native"
    assert outbox.payload["source_system"] == "gove-zone"
    assert approval.lineage["policy_artifact_id"] == artifact.id
    assert approval.lineage["receipt_hash"] == artifact.receipt_hash
    assert approval.lineage["audit_event_hash"] == artifact.audit_event_hash
    assert approval.lineage["pending_outbox"]["delivery_key"] == outbox.delivery_key
    assert approval.lineage["pending_outbox"]["payload_digest"] == outbox.payload_digest


def _assert_zero_external_attempt_and_callback(
    *,
    label: str,
    app: Any,
    callback_baseline: int,
) -> None:
    _assert_tenant_bootstrap_has_no_external_effect_contract(app)
    assert _callback_count(app) - callback_baseline == 0, label


def _new_refusal_events(
    session: Session,
    before_refusal_ids: set[str],
) -> list[TenantBootstrapRefusalEvent]:
    return [
        event
        for event in session.scalars(sa.select(TenantBootstrapRefusalEvent)).all()
        if event.id not in before_refusal_ids
    ]


def _client_with_bootstrap_providers(
    app: Any,
    tmp_path: Path,
    **providers: Any,
) -> tuple[TestClient, Any]:
    provider_app = create_app(
        Settings(
            database_url=app.state.settings.database_url,
            audit_dir=tmp_path / f"audit-provider-{len(list(tmp_path.iterdir()))}",
            create_tables=False,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        ),
        **providers,
    )
    receipt_issuer = providers.get("platform_bootstrap_receipt_issuer")
    if isinstance(receipt_issuer, _ReceiptIssuer):
        receipt_issuer.app = provider_app
    return TestClient(provider_app), provider_app


def _close_provider_app(provider_app: Any) -> None:
    provider_app.state.engine.dispose()


def _seeded_client(app_client: tuple[TestClient, Any]) -> tuple[TestClient, Any]:
    client, app = app_client
    with app.state.session_factory() as session:
        with session.begin():
            _seed_invitation(session)
    return client, app


def test_real_api_postgres_bootstrap_allow_atomic(
    app_client: tuple[TestClient, object],
) -> None:
    client, app = _seeded_client(app_client)

    _assert_tenant_bootstrap_provider_slots_frozen(app)
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
            "refusal_events": 0,
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
        assert (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedTrustKey)
                .where(ManagedTrustKey.key_id == "local-platform-tenant-bootstrap")
            )
            == 0
        )
        proof_context, proof_args = _context_and_args(
            invitation,
            TenantBootstrapRequest.model_validate(BODY),
            ACTOR,
            "tenant-bootstrap-key-purpose-proof",
        )
        proof_receipt, proof_audit_hash = _mint_receipt(
            issuer=local_bootstrap_issuer(),
            context=proof_context,
            args=proof_args,
            decision=Decision.ALLOW,
            reason="purpose separation proof",
            request_id="tenant-bootstrap-key-purpose-proof",
        )
        proof_context = replace(proof_context, expected_audit_hash=proof_audit_hash)
        with pytest.raises(ReceiptValidationError):
            proof_receipt.verify(
                expected_tenant_id=proof_context.org_id,
                expected_execution_boundary=proof_context.execution_boundary,
                expected_action=proof_context.action,
                expected_actor=proof_context.actor,
                expected_audit_hash=proof_context.expected_audit_hash,
                expected_args=proof_args,
                expected_policy_hash=proof_context.policy_hash,
                expected_policy_bundle_id=proof_context.policy_bundle_id,
                expected_project_id=proof_context.project_id,
                expected_environment_id=proof_context.environment_id,
                expected_validator_role=proof_context.validator_role,
                expected_authority=proof_context.authority,
                verifier=None,
                require_signature=True,
                require_expiry=True,
                trust_registry=SqlReceiptTrustRegistry(session),
                trust_purpose=DECISION_RECEIPT_PURPOSE,
            )
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
            session.commit()
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
        assert counts["refusal_events"] == 0
        assert counts["refusal_events"] == 0


def test_real_api_postgres_bootstrap_refusal_matrix(
    app_client: tuple[TestClient, object],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, app = _seeded_client(app_client)
    _assert_tenant_bootstrap_has_no_external_effect_contract(app)

    def run_refusal_case(
        label: str,
        *,
        status_code: int,
        code: str,
        headers: dict[str, str],
        body: dict[str, object] | None = BODY,
        content: bytes | None = None,
        setup: Any | None = None,
        expected_deltas: dict[str, int] | None = None,
        provider_client: TestClient | None = None,
        expected_refusal: bool = True,
        policy_decision: str | None = None,
    ) -> None:
        if setup is not None:
            setup()
        request_client = provider_client or client
        with app.state.session_factory() as session:
            before = _counts(session)
            before_refusal_ids = {
                event.id for event in session.scalars(sa.select(TenantBootstrapRefusalEvent)).all()
            }
            before_artifact_ids = {
                artifact.id
                for artifact in session.scalars(sa.select(TenantBootstrapPolicyArtifact)).all()
            }
            before_pending_ids = {
                pending.id for pending in session.scalars(sa.select(PendingApproval)).all()
            }
            before_pending_outbox_ids = {
                outbox.id
                for outbox in session.scalars(sa.select(TenantBootstrapPendingOutbox)).all()
            }
            _assert_no_outbox_delivery_attempted(session)
        callback_baseline = _callback_count(app)
        if content is None:
            response = request_client.post("/v1/tenant-bootstrap", json=body, headers=headers)
        else:
            response = request_client.post("/v1/tenant-bootstrap", content=content, headers=headers)
        assert response.status_code == status_code, (label, response.json())
        assert response.json()["code"] == code, label
        _assert_zero_external_attempt_and_callback(
            label=label,
            app=app,
            callback_baseline=callback_baseline,
        )
        with app.state.session_factory() as session:
            after = _counts(session)
            deltas = dict(expected_deltas or {})
            if expected_refusal:
                deltas["refusal_events"] = 1
            _assert_exact_deltas(label=label, before=before, after=after, expected=deltas)
            for key in _DOMAIN_COUNT_KEYS:
                assert after[key] == before[key], (label, key, before, after)
            for key in _ALLOW_EXECUTION_COUNT_KEYS:
                assert after[key] == before[key], (label, key, before, after)
            if not expected_deltas:
                for key in _GOVERNANCE_PENDING_COUNT_KEYS:
                    assert after[key] == before[key], (label, key, before, after)
            new_refusals = _new_refusal_events(session, before_refusal_ids)
            if expected_refusal:
                assert len(new_refusals) == 1, label
                refusal = new_refusals[0]
                assert refusal.code == code, label
                assert refusal.http_status == status_code, label
            else:
                assert new_refusals == [], label
            if policy_decision is not None:
                _assert_policy_artifact_case(
                    session,
                    label=label,
                    decision=policy_decision,
                    before_artifact_ids=before_artifact_ids,
                    before_pending_ids=before_pending_ids,
                    before_pending_outbox_ids=before_pending_outbox_ids,
                )
            _assert_no_outbox_delivery_attempted(session)

    for label, body in (
        ("caller_org", {**BODY, "org_id": "caller-controlled"}),
        ("caller_actor", {**BODY, "actor": "caller-controlled"}),
        ("caller_environment", {**BODY, "environment_id": "caller-controlled"}),
    ):
        run_refusal_case(
            label,
            status_code=400,
            code="REQUEST_MALFORMED",
            headers=HEADERS,
            body=body,
        )

    run_refusal_case(
        "malformed_auth",
        status_code=401,
        code="AUTHENTICATION_REQUIRED",
        headers={**HEADERS, BOOTSTRAP_AUTHORIZATION_HEADER: f"Basic {ACTOR}"},
    )
    run_refusal_case(
        "no_actor",
        status_code=401,
        code="AUTHENTICATION_REQUIRED",
        headers={k: v for k, v in HEADERS.items() if k != BOOTSTRAP_AUTHORIZATION_HEADER},
    )
    run_refusal_case(
        "unauth_bad_invite_and_idem",
        status_code=401,
        code="AUTHENTICATION_REQUIRED",
        headers={
            BOOTSTRAP_INVITATION_HEADER: "not-strong",
            BOOTSTRAP_IDEMPOTENCY_HEADER: "bad",
        },
    )
    run_refusal_case(
        "no_permission_precedence",
        status_code=403,
        code="AUTHORIZATION_DENIED",
        headers={
            **HEADERS,
            BOOTSTRAP_AUTHORIZATION_HEADER: "Bearer local-platform-token-viewer",
            BOOTSTRAP_INVITATION_HEADER: _token("missing"),
            BOOTSTRAP_IDEMPOTENCY_HEADER: "bad",
        },
    )
    run_refusal_case(
        "stolen_invite",
        status_code=403,
        code="BOOTSTRAP_NOT_AUTHORIZED",
        headers={
            **HEADERS,
            BOOTSTRAP_AUTHORIZATION_HEADER: "Bearer local-platform-token-eve",
            BOOTSTRAP_IDEMPOTENCY_HEADER: "tenant-bootstrap-key-stolen",
        },
    )
    run_refusal_case(
        "too_large",
        status_code=413,
        code="REQUEST_TOO_LARGE",
        headers={**HEADERS, "content-type": "application/json"},
        content=json.dumps({**BODY, "padding": "x" * (16 * 1024)}).encode(),
    )
    run_refusal_case(
        "duplicate_key",
        status_code=400,
        code="REQUEST_MALFORMED",
        headers={**HEADERS, "content-type": "application/json"},
        content=b'{"display_name":"Acme","display_name":"Other","admin_name":"Alice","admin_email":"alice@example.com"}',
    )
    run_refusal_case(
        "wrong_role",
        status_code=403,
        code="BOOTSTRAP_NOT_AUTHORIZED",
        headers={
            **HEADERS,
            BOOTSTRAP_INVITATION_HEADER: _token("viewer"),
            BOOTSTRAP_IDEMPOTENCY_HEADER: "tenant-bootstrap-key-viewer",
        },
        setup=lambda: _seed_invitation_in_app(app, token=_token("viewer"), role="viewer"),
    )

    original_locked_invitation = tenant_bootstrap_module._locked_invitation
    locked_invitation_calls = 0

    def counted_locked_invitation(*args: object, **kwargs: object) -> object:
        nonlocal locked_invitation_calls
        locked_invitation_calls += 1
        return original_locked_invitation(*args, **kwargs)

    monkeypatch.setattr(tenant_bootstrap_module, "_locked_invitation", counted_locked_invitation)
    for label, invitation_header in (
        ("invalid_idempotency_existing_invitation", TOKEN),
        ("invalid_idempotency_missing_invitation", _token("missing")),
    ):
        run_refusal_case(
            label,
            status_code=400,
            code="IDEMPOTENCY_KEY_INVALID",
            headers={
                **HEADERS,
                BOOTSTRAP_INVITATION_HEADER: invitation_header,
                BOOTSTRAP_IDEMPOTENCY_HEADER: "bad",
            },
        )
        assert locked_invitation_calls == 0
    monkeypatch.setattr(tenant_bootstrap_module, "_locked_invitation", original_locked_invitation)

    run_refusal_case(
        "missing_invitation",
        status_code=403,
        code="BOOTSTRAP_NOT_AUTHORIZED",
        headers={
            **HEADERS,
            BOOTSTRAP_INVITATION_HEADER: _token("missing"),
            BOOTSTRAP_IDEMPOTENCY_HEADER: "tenant-bootstrap-key-missing",
        },
    )

    for label, token, mutate in (
        (
            "expired_invitation",
            _token("expired"),
            lambda invite: setattr(invite, "expires_at", utcnow()),
        ),
        (
            "revoked_invitation",
            _token("revoked"),
            lambda invite: setattr(invite, "revoked_at", utcnow()),
        ),
    ):
        run_refusal_case(
            label,
            status_code=403,
            code="BOOTSTRAP_NOT_AUTHORIZED",
            headers={
                **HEADERS,
                BOOTSTRAP_INVITATION_HEADER: token,
                BOOTSTRAP_IDEMPOTENCY_HEADER: f"tenant-bootstrap-key-{token.rsplit('-', 1)[-1]}",
            },
            setup=lambda token=token, mutate=mutate: _seed_invitation_in_app(
                app, token=token, mutate=mutate
            ),
        )

    class BrokenIssuer:
        key_id = "broken-platform-bootstrap"
        algorithm = "Ed25519"

        def signer_for_scope(self, *_args: object, **_kwargs: object) -> object:
            raise RuntimeError("simulated signer outage")

    signer_client, signer_app = _client_with_bootstrap_providers(
        app,
        tmp_path,
        platform_bootstrap_issuer=BrokenIssuer(),
    )
    try:
        run_refusal_case(
            "signer_down",
            status_code=503,
            code="SIGNER_UNAVAILABLE",
            headers={
                **HEADERS,
                BOOTSTRAP_INVITATION_HEADER: _token("signer_down"),
                BOOTSTRAP_IDEMPOTENCY_HEADER: "tenant-bootstrap-key-signer-down",
            },
            setup=lambda: _seed_invitation_in_app(app, token=_token("signer_down")),
            provider_client=signer_client,
        )
    finally:
        _close_provider_app(signer_app)

    allowed = client.post("/v1/tenant-bootstrap", json=BODY, headers=HEADERS)
    assert allowed.status_code == 201
    run_refusal_case(
        "post_success_idempotency_conflict",
        status_code=409,
        code="IDEMPOTENCY_CONFLICT",
        headers=HEADERS,
        body={**BODY, "display_name": "Different"},
    )
    run_refusal_case(
        "post_success_consumed_invitation",
        status_code=403,
        code="BOOTSTRAP_NOT_AUTHORIZED",
        headers={**HEADERS, BOOTSTRAP_IDEMPOTENCY_HEADER: "tenant-bootstrap-key-0002"},
    )

    for label, token, outcome, status_code, code, expected_deltas in (
        (
            "policy_deny",
            _token("deny"),
            "deny",
            403,
            "POLICY_DENIED",
            {"policy_artifacts": 1},
        ),
        (
            "policy_escalate",
            _token("escalate"),
            "escalate",
            202,
            "ESCALATE_PENDING",
            {"policy_artifacts": 1, "pending_approvals": 1, "pending_outbox": 1},
        ),
    ):
        run_refusal_case(
            label,
            status_code=status_code,
            code=code,
            headers={
                **HEADERS,
                BOOTSTRAP_INVITATION_HEADER: token,
                BOOTSTRAP_IDEMPOTENCY_HEADER: f"tenant-bootstrap-key-{outcome}",
            },
            setup=lambda token=token, outcome=outcome: _seed_invitation_in_app(
                app, token=token, outcome=outcome
            ),
            expected_deltas=expected_deltas,
            expected_refusal=False,
            policy_decision=outcome,
        )

    executor_refusals = {
        "receipt_missing": (400, "RECEIPT_MISSING"),
        "receipt_malformed": (400, "RECEIPT_MALFORMED"),
        "receipt_version": (400, "RECEIPT_VERSION_UNSUPPORTED"),
        "receipt_missing_field": (400, "RECEIPT_FIELD_MISSING"),
        "signature_invalid": (403, "SIGNATURE_INVALID"),
        "signature_invalid_deny": (403, "SIGNATURE_INVALID"),
        "signature_invalid_escalate": (403, "SIGNATURE_INVALID"),
        "signature_invalid_replayed": (403, "SIGNATURE_INVALID"),
        "key_untrusted": (403, "KEY_UNTRUSTED"),
        "key_revoked": (403, "KEY_REVOKED"),
        "trust_unavailable": (503, "TRUST_PROVIDER_UNAVAILABLE"),
        "expired": (403, "EXPIRED"),
        "future_issued": (403, "EXPIRED"),
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
        "tx_abort_value_error_callback": (503, "TX_ABORTED"),
        "tx_abort_attribute_error_callback": (503, "TX_ABORTED"),
    }
    original_execute_bootstrap_effect = tenant_bootstrap_module._execute_bootstrap_effect
    for index, (scenario, (status_code, code)) in enumerate(executor_refusals.items()):
        token = _token(f"fault_{index}")
        with app.state.session_factory() as session:
            with session.begin():
                _seed_invitation(session, token=token)
        preissued_receipt = _preseed_state_for_fault(app, scenario=scenario, token=token)
        with app.state.session_factory() as session:
            scenario_baseline = _counts(session)
            before_refusal_ids = {
                event.id for event in session.scalars(sa.select(TenantBootstrapRefusalEvent)).all()
            }
        providers: dict[str, object] = {
            "platform_bootstrap_receipt_issuer": _ReceiptIssuer(
                scenario=scenario,
                preissued_receipt=preissued_receipt,
            ),
        }
        if scenario == "key_untrusted":
            providers["platform_bootstrap_trust_registry"] = _UntrustedTrustRegistry()
        elif scenario == "key_revoked":
            providers["platform_bootstrap_trust_registry"] = _RevokedTrustRegistry()
        elif scenario == "trust_unavailable":
            providers["platform_bootstrap_trust_registry"] = _UnavailableTrustRegistry()
        fault_client, fault_app = _client_with_bootstrap_providers(app, tmp_path, **providers)
        callback_baseline = _callback_count(app)
        operation_callback_entries = 0
        callback_returned = False

        def operation_callback_spy(
            *args: object,
            scenario: str = scenario,
            **kwargs: object,
        ) -> object:
            nonlocal callback_returned, operation_callback_entries
            operation_callback_entries += 1
            if scenario == "tx_abort_value_error_callback":
                raise ValueError("simulated callback value error")
            if scenario == "tx_abort_attribute_error_callback":
                raise AttributeError("simulated callback attribute error")
            result = original_execute_bootstrap_effect(*args, **kwargs)
            callback_returned = True
            return result

        monkeypatch.setattr(
            tenant_bootstrap_module,
            "_execute_bootstrap_effect",
            operation_callback_spy,
        )
        try:
            if scenario == "tx_abort_pre_callback":
                _install_tx_abort_trigger(app, stage="pre_callback")
            elif scenario == "tx_abort_post_callback":
                _install_tx_abort_trigger(app, stage="post_callback")
            request_body = (
                {**BODY, "display_name": f"Fault {index}"}
                if scenario == "tx_abort_post_callback"
                else BODY
            )
            response = fault_client.post(
                "/v1/tenant-bootstrap",
                json=request_body,
                headers={
                    **HEADERS,
                    BOOTSTRAP_INVITATION_HEADER: token,
                    BOOTSTRAP_IDEMPOTENCY_HEADER: f"tenant-bootstrap-key-fault-{scenario}",
                },
            )
        finally:
            _close_provider_app(fault_app)
            _drop_tx_abort_triggers(app)
            monkeypatch.setattr(
                tenant_bootstrap_module,
                "_execute_bootstrap_effect",
                original_execute_bootstrap_effect,
            )
        assert response.status_code == status_code, (scenario, response.json())
        assert response.json()["code"] == code, scenario
        expected_operation_entries = (
            1
            if scenario
            in {
                "tx_abort_post_callback",
                "tx_abort_value_error_callback",
                "tx_abort_attribute_error_callback",
            }
            else 0
        )
        assert operation_callback_entries == expected_operation_entries, scenario
        if scenario == "tx_abort_pre_callback":
            assert _callback_count(app) - callback_baseline == 0
            _drop_tx_abort_triggers(app, drop_counter=True)
        elif scenario == "tx_abort_post_callback":
            assert callback_returned is True
            assert _callback_count(app) - callback_baseline == 1
            _drop_tx_abort_triggers(app, drop_counter=True)
        else:
            assert callback_returned is False
            assert _callback_count(app) - callback_baseline == 0, scenario
        _assert_tenant_bootstrap_has_no_external_effect_contract(app)
        with app.state.session_factory() as session:
            after = _counts(session)
            expected_after = dict(scenario_baseline)
            for key in (
                "organizations",
                "projects",
                "environments",
                "users",
                "memberships",
                "managed_receipts",
                "consumptions",
                "events",
                "outbox",
                "attempts",
                "idempotency",
                "policy_artifacts",
                "pending_approvals",
                "pending_outbox",
            ):
                assert after[key] == expected_after[key], (
                    scenario,
                    key,
                    scenario_baseline,
                    after,
                )
            assert after["refusal_events"] == expected_after["refusal_events"] + 1, scenario
            new_refusals = [
                event
                for event in session.scalars(sa.select(TenantBootstrapRefusalEvent)).all()
                if event.id not in before_refusal_ids
            ]
            assert len(new_refusals) == 1, scenario
            refusal = new_refusals[0]
            assert refusal.code == code, scenario
            assert refusal.http_status == status_code, scenario
            assert refusal.stage in {
                "transport",
                "authn",
                "authz",
                "policy",
                "issuance",
                "executor",
                "tx",
            }
            if code == "TX_ABORTED":
                invitation = _invitation_by_token_hash(session, token)
                assert invitation.consumed_at is None, scenario
                assert invitation.consumed_org_id is None, scenario
            _assert_no_outbox_delivery_attempted(session)

    with app.state.session_factory() as session:
        counts = _counts(session)
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
        refusal_events = session.scalars(sa.select(TenantBootstrapRefusalEvent)).all()
        assert len(refusal_events) == counts["refusal_events"]
        assert all(event.route == "POST /v1/tenant-bootstrap" for event in refusal_events)
        assert all(event.method == "POST" for event in refusal_events)
        persisted = "\n".join(
            " ".join(str(getattr(event, column.name)) for column in event.__table__.columns)
            for event in refusal_events
        )
        assert "alice@example.com" not in persisted.lower()
        assert "tenant_bootstrap_" not in persisted
        assert "local-platform-token" not in persisted


def test_postgres_rejects_cross_invitation_policy_artifact_lineage(
    app_client: tuple[TestClient, Any],
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
                session.add_all(
                    [
                        Organization(id="constraint-org-a", name="Constraint Org A"),
                        Organization(id="constraint-org-b", name="Constraint Org B"),
                    ]
                )
                session.flush()
                session.add(
                    User(
                        id="constraint-user-a",
                        org_id="constraint-org-a",
                        name="Constraint User",
                        email="constraint-user@example.com",
                        role="org_admin",
                        api_key_hash=None,
                    )
                )
                session.flush()
                session.add(
                    OrganizationMembership(
                        id="constraint-membership-cross-org",
                        org_id="constraint-org-b",
                        user_id="constraint-user-a",
                        role="owner",
                    )
                )

    with pytest.raises(IntegrityError):
        with app.state.session_factory() as session:
            with session.begin():
                session.add(
                    TenantBootstrapIdempotency(
                        id="constraint-idem-wrong-env",
                        idempotency_key="constraint-idem-wrong-env-key",
                        actor=ACTOR,
                        request_hash="1" * 64,
                        org_id=invitation_a.prospective_org_id,
                        project_id=invitation_a.prospective_project_id,
                        environment_id="wrong-environment",
                        response={"org_id": invitation_a.prospective_org_id},
                    )
                )

    with pytest.raises(IntegrityError):
        with app.state.session_factory() as session:
            with session.begin():
                session.add(
                    TenantBootstrapPolicyArtifact(
                        id="constraint-artifact-wrong-scope",
                        invitation_id=invitation_a_id,
                        org_id=invitation_b.prospective_org_id,
                        project_id=invitation_a.prospective_project_id,
                        environment_id=invitation_a.prospective_environment_id,
                        decision="escalate",
                        receipt_hash="4" * 64,
                        audit_event_hash="5" * 64,
                        sealed_receipt={"schema": "test-receipt/v1"},
                        event={"schema": "test-event/v1"},
                        created_at=utcnow(),
                    )
                )

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
                        org_id="wrong-org",
                        project_id="wrong-project",
                        environment_id="wrong-env",
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
    app_client: tuple[TestClient, Any],
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
