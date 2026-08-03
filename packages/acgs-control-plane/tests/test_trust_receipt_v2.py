"""Managed receipt v2 trust lifecycle tests extracted from the managed mutation UoW suite."""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import ReceiptAlreadyUsedError, ReceiptValidationError
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.revocation import RevocationList
from gove_zone.signing import Ed25519Signer
from gove_zone.trust import (
    DECISION_RECEIPT_PURPOSE,
    ReceiptTrustScope,
    TrustConfigurationError,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from acgs_control_plane.db import make_engine, make_session_factory
from acgs_control_plane.managed_mutations import (
    AesGcmReceiptArtifactSealer,
    ManagedMutationContext,
    ManagedMutationUnitOfWork,
    managed_mutation_execution_boundary,
)
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import (
    AgentRecord,
    Environment,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    ManagedTrustKey,
    Organization,
    Project,
)
from acgs_control_plane.trust import (
    ManagedTrustError,
    ManagedTrustLifecycleService,
    SqlReceiptTrustRegistry,
    public_spki_der_from_signer,
)

ORG_ID = "org-uow"
SECOND_ORG_ID = "org-uow-sibling"
PROJECT_ID = "project-uow"
ENVIRONMENT_ID = "environment-uow"
SECOND_ENVIRONMENT_ID = "environment-uow-secondary"
ACTOR = "agent-uow"
ACTION = "control-plane.agent.create"
POLICY_BUNDLE_ID = "policy-bundle-uow"
POLICY_HASH = "p" * 64
POLICY_VERSION = "policy-version-uow"
AUTHORITY = "managed-mutation-authority"
VALIDATOR_ROLE = "control-plane-validator"


@pytest.fixture()
def session_factory(tmp_path: Path) -> Iterator[sessionmaker[Session]]:
    database_url = f"sqlite:///{tmp_path / 'control-plane.sqlite3'}"
    upgrade_database(database_url)
    engine = make_engine(database_url)
    try:
        factory = make_session_factory(engine)
        with factory.begin() as session:
            _seed_scope(session)
        yield factory
    finally:
        engine.dispose()


@pytest.fixture()
def signer() -> Ed25519Signer:
    pytest.importorskip("cryptography")
    return Ed25519Signer.generate(key_id="managed-native-test")


@pytest.fixture()
def receipt_sealer() -> AesGcmReceiptArtifactSealer:
    pytest.importorskip("cryptography")
    return AesGcmReceiptArtifactSealer(key_id="local-test-sealer", key=b"k" * 32)


def test_receipt_v2_scoped_trust_roots_bind_tenant_scope_and_trust_epoch(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    receipt = _receipt("v2-scope-bound", args=_agent_args("scope-bound"), signer=signer)

    _signed_uow(session_factory, signer, receipt_sealer).execute(
        context=_context(),
        receipt=receipt,
        args=_agent_args("scope-bound"),
    )

    with session_factory() as session:
        row = session.scalars(sa.select(ManagedDecisionReceipt)).one()
        assert row.receipt_schema_version == receipt.receipt_schema_version
        assert row.trust_epoch == 1
        assert row.project_id == PROJECT_ID
        assert row.environment_id == ENVIRONMENT_ID
        trust_row = session.scalars(sa.select(ManagedTrustKey)).one()
        assert trust_row.public_key_spki_der == public_spki_der_from_signer(signer)
        assert signer.public_bytes() not in str(trust_row.__dict__).encode("utf-8")

    wrong_project = dataclasses.replace(
        receipt,
        receipt_schema_version="",
        project_id="",
        environment_id="",
        trust_epoch=0,
    )
    with pytest.raises(ReceiptValidationError):
        ManagedMutationUnitOfWork(session_factory, receipt_sealer=receipt_sealer).execute(
            context=_context(),
            receipt=wrong_project,
            args=_agent_args("scope-bound"),
        )


def test_active_retired_and_revoked_trust_rotation_preserves_history_and_blocks_new_or_revoked(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    rotated_signer = Ed25519Signer.generate(key_id="managed-native-rotated")
    _bootstrap_trust_root(session_factory, signer)
    with pytest.raises(ManagedTrustError, match="epoch precondition"):
        with session_factory.begin() as session:
            ManagedTrustLifecycleService(session).rotate(
                scope=_scope(),
                key_id=rotated_signer.key_id,
                algorithm=rotated_signer.algorithm,
                public_key_spki_der=public_spki_der_from_signer(rotated_signer),
                not_after=datetime(2099, 1, 1, tzinfo=UTC),
                expected_current_epoch=2,
            )
    with session_factory() as session:
        assert _trust_counts(session) == {"active": 1, "history": 1}

    with session_factory.begin() as session:
        scope = _scope()
        ManagedTrustLifecycleService(session).rotate(
            scope=scope,
            key_id=rotated_signer.key_id,
            algorithm=rotated_signer.algorithm,
            public_key_spki_der=public_spki_der_from_signer(rotated_signer),
            not_after=datetime(2099, 1, 1, tzinfo=UTC),
            expected_current_epoch=1,
        )

    retired_receipt = _receipt(
        "retired-history",
        args=_agent_args("history-only"),
        signer=signer,
        trust_epoch=1,
    )
    with session_factory() as session:
        registry = SqlReceiptTrustRegistry(session)
        verification_time = datetime(2030, 1, 1, tzinfo=UTC).isoformat()
        retired_key = registry.resolve(
            scope=_scope(),
            trust_epoch=1,
            algorithm=signer.algorithm,
            key_id=signer.key_id,
            now_iso=verification_time,
            mode="historical",
        )
        assert retired_key.status == "retired"
        assert retired_key.retired_epoch == 2
        with pytest.raises(TrustConfigurationError):
            registry.resolve(
                scope=_scope(),
                trust_epoch=retired_key.retired_epoch,
                algorithm=signer.algorithm,
                key_id=signer.key_id,
                now_iso=verification_time,
                mode="historical",
            )
        with pytest.raises(TrustConfigurationError):
            registry.resolve(
                scope=_scope(),
                trust_epoch=1,
                algorithm=signer.algorithm,
                key_id=signer.key_id,
                now_iso=verification_time,
            )
        retired_receipt.verify(
            expected_tenant_id=ORG_ID,
            expected_execution_boundary=_boundary(),
            expected_action=ACTION,
            expected_actor=ACTOR,
            expected_args=_agent_args("history-only"),
            expected_policy_hash=POLICY_HASH,
            expected_policy_bundle_id=POLICY_BUNDLE_ID,
            expected_project_id=PROJECT_ID,
            expected_environment_id=ENVIRONMENT_ID,
            expected_validator_role=VALIDATOR_ROLE,
            expected_authority=AUTHORITY,
            require_signature=True,
            require_expiry=True,
            trust_registry=registry,
            historical_trust_verification=True,
        )

    with pytest.raises(ReceiptValidationError):
        ManagedMutationUnitOfWork(session_factory, receipt_sealer=receipt_sealer).execute(
            context=_context(),
            receipt=retired_receipt,
            args=_agent_args("history-only"),
        )

    active_receipt = _receipt(
        "rotated-active",
        args=_agent_args("rotated-agent"),
        signer=rotated_signer,
        trust_epoch=2,
    )
    ManagedMutationUnitOfWork(session_factory, receipt_sealer=receipt_sealer).execute(
        context=_context(),
        receipt=active_receipt,
        args=_agent_args("rotated-agent"),
    )
    with session_factory.begin() as session:
        ManagedTrustLifecycleService(session).revoke(
            scope=_scope(),
            key_id=rotated_signer.key_id,
            algorithm=rotated_signer.algorithm,
        )
    with pytest.raises(ManagedTrustError, match="epoch precondition"):
        with session_factory.begin() as session:
            ManagedTrustLifecycleService(session).rotate(
                scope=_scope(),
                key_id=Ed25519Signer.generate(key_id="managed-native-post-revoke").key_id,
                algorithm=rotated_signer.algorithm,
                public_key_spki_der=public_spki_der_from_signer(rotated_signer),
                not_after=datetime(2099, 1, 1, tzinfo=UTC),
                expected_current_epoch=2,
            )
    revoked_receipt = _receipt(
        "revoked-active",
        args=_agent_args("revoked-agent"),
        signer=rotated_signer,
        trust_epoch=2,
    )
    with pytest.raises(ReceiptValidationError):
        ManagedMutationUnitOfWork(session_factory, receipt_sealer=receipt_sealer).execute(
            context=_context(),
            receipt=revoked_receipt,
            args=_agent_args("revoked-agent"),
        )
    with session_factory() as session:
        assert _count(session, AgentRecord) == 1
        assert _count(session, ManagedReceiptConsumption) == 1


def test_trust_readiness_report_requires_active_root_and_rotation_window(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
) -> None:
    now = datetime.now(UTC)
    with session_factory() as session:
        report = SqlReceiptTrustRegistry(session).readiness([_scope()], now_iso=now.isoformat())
        assert not report.ready
        assert {issue.code for issue in report.issues} == {"missing-root"}

    _bootstrap_trust_root(
        session_factory,
        signer,
        not_after=(now + timedelta(days=1)).isoformat(),
    )
    with session_factory() as session:
        assert SqlReceiptTrustRegistry(session).readiness([_scope()], now_iso=now.isoformat()).ready

    with session_factory.begin() as session:
        key = session.scalars(
            sa.select(ManagedTrustKey).where(ManagedTrustKey.status == "active")
        ).one()
        key.not_after = now - timedelta(seconds=1)
    with session_factory() as session:
        expired = SqlReceiptTrustRegistry(session).readiness([_scope()], now_iso=now.isoformat())
        assert not expired.ready
        assert {issue.code for issue in expired.issues} == {"expired-root"}


def test_wrong_scope_missing_trust_and_replay_reject_without_side_effect(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    receipt = _receipt("wrong-scope-zero", args=_agent_args("zero-agent"), signer=signer)
    with pytest.raises(ReceiptValidationError):
        ManagedMutationUnitOfWork(session_factory, receipt_sealer=receipt_sealer).execute(
            context=_context(environment_id=SECOND_ENVIRONMENT_ID),
            receipt=receipt,
            args=_agent_args("zero-agent"),
        )
    with pytest.raises(ReceiptValidationError):
        ManagedMutationUnitOfWork(session_factory, receipt_sealer=receipt_sealer).execute(
            context=_context(),
            receipt=receipt,
            args=_agent_args("zero-agent"),
        )
    with session_factory() as session:
        assert _counts(session) == {
            "agents": 0,
            "receipts": 0,
            "consumptions": 0,
            "events": 0,
            "outbox": 0,
        }

    _signed_uow(session_factory, signer, receipt_sealer).execute(
        context=_context(),
        receipt=receipt,
        args=_agent_args("zero-agent"),
    )
    with pytest.raises(ReceiptAlreadyUsedError):
        _signed_uow(session_factory, signer, receipt_sealer).execute(
            context=_context(),
            receipt=receipt,
            args=_agent_args("zero-agent"),
        )
    with session_factory() as session:
        assert _counts(session) == {
            "agents": 1,
            "receipts": 1,
            "consumptions": 1,
            "events": 1,
            "outbox": 1,
        }


def _seed_scope(session: Session) -> None:
    session.add(Organization(id=ORG_ID, name="UoW Organization"))
    session.add(Organization(id=SECOND_ORG_ID, name="Sibling UoW Organization"))
    session.add(Project(id=PROJECT_ID, org_id=ORG_ID, slug="core", name="Core"))
    session.add(
        Environment(
            id=ENVIRONMENT_ID,
            org_id=ORG_ID,
            project_id=PROJECT_ID,
            slug="production",
            name="Production",
        )
    )
    session.add(
        Environment(
            id=SECOND_ENVIRONMENT_ID,
            org_id=ORG_ID,
            project_id=PROJECT_ID,
            slug="staging",
            name="Staging",
        )
    )


def _context(
    *,
    org_id: str = ORG_ID,
    environment_id: str = ENVIRONMENT_ID,
    actor: str = ACTOR,
    action: str = ACTION,
    policy_hash: str = POLICY_HASH,
    authority: str = AUTHORITY,
    execution_boundary: str | None = None,
) -> ManagedMutationContext:
    return ManagedMutationContext(
        org_id=org_id,
        project_id=PROJECT_ID,
        environment_id=environment_id,
        actor=actor,
        action=action,
        execution_boundary=execution_boundary
        or _boundary(org_id=org_id, environment_id=environment_id, action=action),
        policy_bundle_id=POLICY_BUNDLE_ID,
        policy_hash=policy_hash,
        validator_role=VALIDATOR_ROLE,
        authority=authority,
    )


def _agent_args(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": "",
        "trust_tier": "internal",
        "allowed_tools": [],
    }


def _receipt(
    event_id: str,
    *,
    args: Mapping[str, Any],
    decision: Decision = Decision.ALLOW,
    org_id: str = ORG_ID,
    environment_id: str = ENVIRONMENT_ID,
    expires_at: str = "2099-01-01T00:00:00+00:00",
    signer: Any = None,
    metadata_sentinel: str = "",
    project_id: str = PROJECT_ID,
    trust_epoch: int = 1,
) -> DecisionReceipt:
    if signer is None:
        signer = Ed25519Signer.generate(key_id="managed-native-test")
    goal = "exercise managed mutation UoW"
    if metadata_sentinel:
        goal = f"{goal} {metadata_sentinel}"
    record = DecisionRecord(
        decision=decision,
        tool=ACTION,
        argument_hash=sha256_json(dict(args)),
        policy_version=POLICY_VERSION,
        event_id=event_id,
        matched_rules=("managed-mutation-uow",),
        reason="test receipt",
        transformed_args={"sealed_metadata": metadata_sentinel} if metadata_sentinel else None,
        goal=goal,
        actor=ACTOR,
        path=("control-plane", "managed-mutation-uow"),
        decision_request_hash=sha256_json({"event_id": event_id, "args": dict(args)}),
    )
    return DecisionReceipt.from_record_v2(
        record,
        audit_hash=sha256_json({"audit": event_id}),
        previous_audit_hash="0" * 64,
        tenant_id=org_id,
        project_id=project_id,
        environment_id=environment_id,
        trust_epoch=trust_epoch,
        execution_boundary=_boundary(org_id=org_id, environment_id=environment_id),
        policy_bundle_id=POLICY_BUNDLE_ID,
        policy_hash=POLICY_HASH,
        request_id=f"request-{event_id}",
        validator=Validator("validator-uow", role=VALIDATOR_ROLE),
        authority=AUTHORITY,
        constraints={"sealed_metadata": metadata_sentinel} if metadata_sentinel else None,
        approval_chain_summary={"sealed_metadata": metadata_sentinel}
        if metadata_sentinel
        else None,
        expires_at=expires_at,
        signer=signer,
    )


def _signed_uow(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
    *,
    revoked_keys: RevocationList | None = None,
) -> ManagedMutationUnitOfWork:
    _bootstrap_trust_root(session_factory, signer)
    return ManagedMutationUnitOfWork(
        session_factory,
        receipt_sealer=receipt_sealer,
        require_signature=True,
        require_expiry=True,
        revoked_keys=revoked_keys,
    )


def _bootstrap_trust_root(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    *,
    org_id: str = ORG_ID,
    project_id: str = PROJECT_ID,
    environment_id: str = ENVIRONMENT_ID,
    not_after: str = "2099-01-01T00:00:00+00:00",
) -> None:
    scope = ReceiptTrustScope(org_id, project_id, environment_id, DECISION_RECEIPT_PURPOSE)
    try:
        with session_factory.begin() as session:
            exists = session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedTrustKey)
                .where(
                    ManagedTrustKey.org_id == org_id,
                    ManagedTrustKey.project_id == project_id,
                    ManagedTrustKey.environment_id == environment_id,
                    ManagedTrustKey.purpose == DECISION_RECEIPT_PURPOSE,
                    ManagedTrustKey.key_id == signer.key_id,
                    ManagedTrustKey.status == "active",
                )
            )
            if exists:
                return
            ManagedTrustLifecycleService(session).bootstrap(
                scope=scope,
                key_id=signer.key_id,
                algorithm=signer.algorithm,
                public_key_spki_der=public_spki_der_from_signer(signer),
                not_after=datetime.fromisoformat(not_after),
            )
    except IntegrityError:
        with session_factory() as session:
            exists_after_race = session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedTrustKey)
                .where(
                    ManagedTrustKey.org_id == org_id,
                    ManagedTrustKey.project_id == project_id,
                    ManagedTrustKey.environment_id == environment_id,
                    ManagedTrustKey.purpose == DECISION_RECEIPT_PURPOSE,
                    ManagedTrustKey.key_id == signer.key_id,
                    ManagedTrustKey.status == "active",
                )
            )
        if exists_after_race:
            return
        raise


def _trust_counts(session: Session) -> dict[str, int]:
    active = (
        session.scalar(
            sa.select(sa.func.count())
            .select_from(ManagedTrustKey)
            .where(
                ManagedTrustKey.org_id == ORG_ID,
                ManagedTrustKey.project_id == PROJECT_ID,
                ManagedTrustKey.environment_id == ENVIRONMENT_ID,
                ManagedTrustKey.purpose == DECISION_RECEIPT_PURPOSE,
                ManagedTrustKey.status == "active",
            )
        )
        or 0
    )
    history = (
        session.scalar(
            sa.select(sa.func.count())
            .select_from(ManagedTrustKey)
            .where(
                ManagedTrustKey.org_id == ORG_ID,
                ManagedTrustKey.project_id == PROJECT_ID,
                ManagedTrustKey.environment_id == ENVIRONMENT_ID,
                ManagedTrustKey.purpose == DECISION_RECEIPT_PURPOSE,
            )
        )
        or 0
    )
    return {"active": active, "history": history}


def _boundary(
    *,
    org_id: str = ORG_ID,
    environment_id: str = ENVIRONMENT_ID,
    action: str = ACTION,
) -> str:
    return managed_mutation_execution_boundary(
        org_id=org_id,
        project_id=PROJECT_ID,
        environment_id=environment_id,
        action=action,
    )


def _scope(
    *,
    org_id: str = ORG_ID,
    project_id: str = PROJECT_ID,
    environment_id: str = ENVIRONMENT_ID,
) -> ReceiptTrustScope:
    return ReceiptTrustScope(org_id, project_id, environment_id, DECISION_RECEIPT_PURPOSE)


def _counts(session: Session) -> dict[str, int]:
    return {
        "agents": _count(session, AgentRecord),
        "receipts": _count(session, ManagedDecisionReceipt),
        "consumptions": _count(session, ManagedReceiptConsumption),
        "events": _count(session, ManagedGovernanceEvent),
        "outbox": _count(session, ManagedOutboxMessage),
    }


def _count(session: Session, model: Any) -> int:
    return session.scalar(sa.select(sa.func.count()).select_from(model)) or 0


def test_duplicate_active_trust_roots_are_blocked_by_index_then_registry(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
) -> None:
    """Two active roots for one scope are refused at the database, then at resolve().

    Layer one is the partial unique index created by revision 0004. Layer two is
    the registry's own count check, which only becomes reachable once that index
    is gone, so it is exercised here against a deliberately tampered schema.
    """
    _bootstrap_trust_root(session_factory, signer)
    second = Ed25519Signer.generate(key_id="managed-native-duplicate")

    def add_second_active(session: Session) -> None:
        session.add(
            ManagedTrustKey(
                id="managed-trust-key-duplicate-active",
                org_id=ORG_ID,
                project_id=PROJECT_ID,
                environment_id=ENVIRONMENT_ID,
                purpose=DECISION_RECEIPT_PURPOSE,
                key_id=second.key_id,
                algorithm=second.algorithm,
                public_key_spki_der=public_spki_der_from_signer(second),
                activated_epoch=2,
                not_after=datetime(2099, 1, 1, tzinfo=UTC),
                status="active",
                retired_epoch=None,
                created_at=datetime(2026, 1, 1, tzinfo=UTC),
                updated_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
        )

    # Layer one: the partial unique index refuses the second active row.
    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            add_second_active(session)

    with session_factory() as session:
        assert _trust_counts(session) == {"active": 1, "history": 1}

    # Layer two: drop the index, force the ambiguity, and confirm resolve()
    # refuses rather than picking a winner.
    with session_factory.begin() as session:
        session.execute(sa.text("DROP INDEX uq_managed_trust_key_active_scope"))
        add_second_active(session)

    with session_factory() as session:
        assert _trust_counts(session) == {"active": 2, "history": 2}
        with pytest.raises(TrustConfigurationError, match="multiple active trust roots"):
            SqlReceiptTrustRegistry(session).resolve(
                scope=_scope(),
                trust_epoch=1,
                algorithm=signer.algorithm,
                key_id=signer.key_id,
                now_iso="2026-07-25T00:00:00+00:00",
            )
