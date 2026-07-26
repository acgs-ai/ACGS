"""Managed mutation UoW tests for SQL-owned receipt/event/outbox atomicity."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
from collections.abc import Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import ReceiptAlreadyUsedError, ReceiptValidationError
from gove_zone.receipt import (
    DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS,
    DecisionReceipt,
    Validator,
)
from gove_zone.revocation import RevocationList
from gove_zone.signing import Ed25519Signer
from gove_zone.trust import DECISION_RECEIPT_PURPOSE, ReceiptTrustScope
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from acgs_control_plane import managed_mutations as managed_mutations_module
from acgs_control_plane.db import make_engine, make_session_factory
from acgs_control_plane.managed_mutations import (
    ASSURANCE_CLASS_NATIVE,
    AesGcmReceiptArtifactSealer,
    ManagedMutationContext,
    ManagedMutationUnitOfWork,
    managed_mutation_execution_boundary,
    managed_receipt_artifact_aad,
)
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import (
    AgentRecord,
    Environment,
    ManagedDecisionReceipt,
    ManagedGovernanceEvent,
    ManagedMutationAttempt,
    ManagedOutboxMessage,
    ManagedReceiptConsumption,
    ManagedTrustKey,
    Organization,
    Project,
)
from acgs_control_plane.trust import (
    InProcessPlatformIssuer,
    ManagedTrustError,
    ManagedTrustLifecycleService,
    SqlReceiptTrustRegistry,
    mint_managed_decision_receipt_v2,
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


def test_receipt_sealer_repr_never_exposes_raw_key(
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    rendered = repr(receipt_sealer)

    assert "local-test-sealer" in rendered
    assert "key=" not in rendered
    assert repr(b"k" * 32) not in rendered
    assert receipt_sealer == AesGcmReceiptArtifactSealer(
        key_id="local-test-sealer",
        key=b"z" * 32,
    )


def test_receipt_sealer_unseal_rejects_tampered_or_noncanonical_envelopes(
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    plaintext = b'{"receipt":"canonical"}'
    associated_data = b'{"scope":"tenant-project-environment-receipt"}'
    envelope = dict(receipt_sealer.seal(plaintext, associated_data=associated_data))

    assert receipt_sealer.unseal(envelope, associated_data=associated_data) == plaintext

    tampered_cases = [
        ("schema", {"schema": "managed-receipt-artifact-seal/v0"}),
        ("algorithm", {"algorithm": "AES-128-GCM"}),
        ("key-id", {"key_id": "other-key"}),
        ("aad-digest", {"associated_data_sha256": "0" * 64}),
        ("nonce-base64", {"nonce": f"{envelope['nonce']}$"}),
        ("ciphertext-base64", {"ciphertext": f"{envelope['ciphertext']}$"}),
        ("nonce-length", {"nonce": _b64(b"short")}),
        ("ciphertext-too-short", {"ciphertext": _b64(b"short")}),
        ("extra-metadata", {"unexpected": "metadata"}),
    ]
    for _label, updates in tampered_cases:
        tampered = dict(envelope)
        tampered.update(updates)
        with pytest.raises(ValueError):
            receipt_sealer.unseal(tampered, associated_data=associated_data)

    missing_key = dict(envelope)
    missing_key.pop("schema")
    with pytest.raises(ValueError):
        receipt_sealer.unseal(missing_key, associated_data=associated_data)

    nonce_tamper = dict(envelope)
    nonce_tamper["nonce"] = _b64(_flip_first_byte(base64.b64decode(envelope["nonce"])))
    with pytest.raises(ValueError):
        receipt_sealer.unseal(nonce_tamper, associated_data=associated_data)

    ciphertext_tamper = dict(envelope)
    ciphertext_tamper["ciphertext"] = _b64(
        _flip_first_byte(base64.b64decode(envelope["ciphertext"]))
    )
    with pytest.raises(ValueError):
        receipt_sealer.unseal(ciphertext_tamper, associated_data=associated_data)

    digest_tamper = dict(envelope)
    digest_tamper["plaintext_sha256"] = hashlib.sha256(b"other").hexdigest()
    with pytest.raises(ValueError):
        receipt_sealer.unseal(digest_tamper, associated_data=associated_data)

    wrong_key = AesGcmReceiptArtifactSealer(key_id="local-test-sealer", key=b"z" * 32)
    with pytest.raises(ValueError):
        wrong_key.unseal(envelope, associated_data=associated_data)

    with pytest.raises(ValueError):
        receipt_sealer.unseal(envelope, associated_data=b"wrong-aad")


def test_allow_mutation_commits_consumption_receipt_event_and_outbox_atomically(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    receipt = _receipt(
        "allow-atomic",
        args={"name": "governed-agent"},
        signer=signer,
    )
    result = _signed_uow(session_factory, signer, receipt_sealer).execute(
        context=_context(),
        receipt=receipt,
        args={"name": "governed-agent"},
    )

    assert result.result["agent_name_hash"] == sha256_json("governed-agent")
    with session_factory() as session:
        assert _count(session, AgentRecord) == 1
        assert _count(session, ManagedDecisionReceipt) == 1
        assert _count(session, ManagedReceiptConsumption) == 1
        assert _count(session, ManagedGovernanceEvent) == 1
        assert _count(session, ManagedOutboxMessage) == 1
        assert _count(session, ManagedMutationAttempt) == 1

        receipt_row = session.scalars(sa.select(ManagedDecisionReceipt)).one()
        assert receipt_row.receipt_hash == receipt.receipt_hash
        assert receipt_row.argument_hash == receipt.argument_hash
        assert receipt_row.receipt_schema_version == receipt.receipt_schema_version
        assert receipt_row.trust_epoch == receipt.trust_epoch
        assert receipt_row.assurance_class == ASSURANCE_CLASS_NATIVE
        assert receipt_row.projection["assurance_class"] == ASSURANCE_CLASS_NATIVE
        assert receipt_row.projection["argument_hash"] == receipt.argument_hash
        assert receipt_row.projection["receipt_schema_version"] == receipt.receipt_schema_version
        assert receipt_row.projection["trust_epoch"] == receipt.trust_epoch
        assert "sealed_receipt" in receipt_row.projection
        assert "receipt" not in receipt_row.projection
        assert "governed-agent" not in str(receipt_row.projection)

        consumption = session.scalars(sa.select(ManagedReceiptConsumption)).one()
        event = session.scalars(sa.select(ManagedGovernanceEvent)).one()
        outbox = session.scalars(sa.select(ManagedOutboxMessage)).one()
        persisted_payloads = f"{event.payload!r} {outbox.payload!r}"
        assert "governed-agent" not in persisted_payloads
        assert event.payload["assurance_class"] == ASSURANCE_CLASS_NATIVE
        assert outbox.payload["assurance_class"] == ASSURANCE_CLASS_NATIVE
        assert consumption.managed_receipt_id == receipt_row.id
        assert event.managed_receipt_id == receipt_row.id
        assert outbox.managed_receipt_id == receipt_row.id
        assert outbox.managed_event_id == event.id
        assert event.event_hash == result.event_hash
        attempt = session.scalars(sa.select(ManagedMutationAttempt)).one()
        assert attempt.status == "succeeded"
        assert attempt.failure_class_hash is None
        assert attempt.failure_digest is None


def test_uow_pins_canonical_receipt_clock_skew_at_gate(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _receipt(
        "explicit-clock-skew-pin",
        args={"name": "clock-skew-agent"},
        signer=signer,
    )
    observed_gate_kwargs: dict[str, Any] = {}
    original_execute_with_receipt = managed_mutations_module.execute_with_receipt

    def observed_execute_with_receipt(*args: Any, **kwargs: Any) -> Any:
        observed_gate_kwargs.update(kwargs)
        return original_execute_with_receipt(*args, **kwargs)

    monkeypatch.setattr(
        managed_mutations_module,
        "execute_with_receipt",
        observed_execute_with_receipt,
    )

    _signed_uow(session_factory, signer, receipt_sealer).execute(
        context=_context(),
        receipt=receipt,
        args={"name": "clock-skew-agent"},
    )

    assert (
        observed_gate_kwargs["max_clock_skew_seconds"] == DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS == 300
    )


def test_injected_failure_before_commit_rolls_back_consumption_receipt_event_outbox_and_side_effect(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _receipt(
        "allow-rollback",
        args={"name": "rolled-back-agent"},
        signer=signer,
    )

    def fail_after_reservation(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("sk-secret-rollback-cause")

    monkeypatch.setattr(
        managed_mutations_module,
        "_execute_verified_operation",
        fail_after_reservation,
    )

    with pytest.raises(RuntimeError):
        _signed_uow(session_factory, signer, receipt_sealer).execute(
            context=_context(),
            receipt=receipt,
            args={"name": "rolled-back-agent"},
        )

    with session_factory() as session:
        assert _counts(session) == {
            "agents": 0,
            "receipts": 0,
            "consumptions": 0,
            "events": 0,
            "outbox": 0,
        }
        attempt = session.scalars(sa.select(ManagedMutationAttempt)).one()
        assert attempt.status == "failed"
        assert attempt.failure_class_hash is not None
        assert attempt.failure_digest is not None
        assert "sk-secret" not in str(attempt.failure_class_hash)
        assert "sk-secret" not in str(attempt.failure_digest)

    def retry_must_not_execute(*_args: object, **_kwargs: object) -> None:
        pytest.fail("failed attempt retry reached the side-effect executor")

    monkeypatch.setattr(
        managed_mutations_module,
        "_execute_verified_operation",
        retry_must_not_execute,
    )
    with pytest.raises(ReceiptAlreadyUsedError):
        _signed_uow(session_factory, signer, receipt_sealer).execute(
            context=_context(),
            receipt=receipt,
            args={"name": "rolled-back-agent"},
        )
    with session_factory() as session:
        assert _counts(session) == {
            "agents": 0,
            "receipts": 0,
            "consumptions": 0,
            "events": 0,
            "outbox": 0,
        }
        assert _count(session, ManagedMutationAttempt) == 1


def test_deny_and_escalate_do_not_consume_or_execute_or_persist_success(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    for decision in (Decision.DENY, Decision.ESCALATE):
        receipt = _receipt(
            f"{decision.value}-blocked",
            args={"name": decision.value},
            decision=decision,
            signer=signer,
        )
        with pytest.raises(ReceiptValidationError):
            _signed_uow(session_factory, signer, receipt_sealer).execute(
                context=_context(),
                receipt=receipt,
                args={"name": decision.value},
            )

    with session_factory() as session:
        assert _counts(session) == {
            "agents": 0,
            "receipts": 0,
            "consumptions": 0,
            "events": 0,
            "outbox": 0,
        }
        assert _count(session, ManagedMutationAttempt) == 0


def test_default_uow_rejects_unsigned_receipt_without_verifier_and_persists_zero_rows(
    session_factory: sessionmaker[Session],
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    receipt = _receipt("unsigned-default-rejected", args={"name": "unsigned-agent"})

    with pytest.raises(ReceiptValidationError):
        ManagedMutationUnitOfWork(session_factory, receipt_sealer=receipt_sealer).execute(
            context=_context(),
            receipt=receipt,
            args={"name": "unsigned-agent"},
        )

    with session_factory() as session:
        assert _counts(session) == {
            "agents": 0,
            "receipts": 0,
            "consumptions": 0,
            "events": 0,
            "outbox": 0,
        }
        assert _count(session, ManagedMutationAttempt) == 0


def test_uow_rejects_disabled_signature_or_expiry_posture_without_persisting_rows(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    with pytest.raises(ValueError, match="signed-only"):
        ManagedMutationUnitOfWork(
            session_factory,
            receipt_sealer=receipt_sealer,
            require_signature=False,
        )
    with pytest.raises(ValueError, match="bounded expiry"):
        ManagedMutationUnitOfWork(
            session_factory,
            receipt_sealer=receipt_sealer,
            require_expiry=False,
        )
    with pytest.raises(ValueError, match="receipt artifact sealer"):
        ManagedMutationUnitOfWork(session_factory)
    with pytest.raises(ValueError, match="SQL trust registry"):
        ManagedMutationUnitOfWork(
            session_factory,
            verifier={signer.key_id: signer},
            receipt_sealer=receipt_sealer,
        )

    with session_factory() as session:
        assert _counts(session) == {
            "agents": 0,
            "receipts": 0,
            "consumptions": 0,
            "events": 0,
            "outbox": 0,
        }
        assert _count(session, ManagedMutationAttempt) == 0


def test_wrong_scope_receipt_rejected_by_database_tenant_environment_constraints(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    receipt = _receipt(
        "wrong-scope-db",
        args={"name": "wrong-scope-agent"},
        environment_id="missing-environment",
        signer=signer,
    )
    context = _context(environment_id="missing-environment")

    with pytest.raises(ReceiptValidationError):
        _signed_uow(session_factory, signer, receipt_sealer).execute(
            context=context,
            receipt=receipt,
            args={"name": "wrong-scope-agent"},
        )

    with session_factory() as session:
        assert _counts(session) == {
            "agents": 0,
            "receipts": 0,
            "consumptions": 0,
            "events": 0,
            "outbox": 0,
        }


def test_receipt_rejection_variants_execute_zero_sql_and_persist_zero_evidence(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    base_args = {"name": "blocked-agent"}
    unknown_signer = Ed25519Signer.generate(key_id="unknown-managed-key")
    cases = [
        (
            "missing-receipt",
            None,
            _context(),
            _signed_uow(session_factory, signer, receipt_sealer),
            base_args,
        ),
        (
            "tampered-payload",
            dataclasses.replace(
                _receipt("tampered-payload", args=base_args, signer=signer),
                policy_hash="q" * 64,
            ),
            _context(),
            _signed_uow(session_factory, signer, receipt_sealer),
            base_args,
        ),
        (
            "expired",
            _receipt(
                "expired",
                args=base_args,
                signer=signer,
                expires_at="2000-01-01T00:00:00+00:00",
            ),
            _context(),
            _signed_uow(session_factory, signer, receipt_sealer),
            base_args,
        ),
        (
            "unknown-key",
            _receipt("unknown-key", args=base_args, signer=unknown_signer),
            _context(),
            _signed_uow(session_factory, signer, receipt_sealer),
            base_args,
        ),
        (
            "revoked-key",
            _receipt("revoked-key", args=base_args, signer=signer),
            _context(),
            _signed_uow(
                session_factory,
                signer,
                receipt_sealer,
                revoked_keys=RevocationList([signer.key_id]),
            ),
            base_args,
        ),
        (
            "wrong-tenant",
            _receipt("wrong-tenant", args=base_args, signer=signer),
            _context(org_id="different-org"),
            _signed_uow(session_factory, signer, receipt_sealer),
            base_args,
        ),
        (
            "wrong-actor",
            _receipt("wrong-actor", args=base_args, signer=signer),
            _context(actor="different-actor"),
            _signed_uow(session_factory, signer, receipt_sealer),
            base_args,
        ),
        (
            "wrong-action",
            _receipt("wrong-action", args=base_args, signer=signer),
            _context(action="control-plane.agent.delete"),
            _signed_uow(session_factory, signer, receipt_sealer),
            base_args,
        ),
        (
            "wrong-arguments",
            _receipt("wrong-arguments", args=base_args, signer=signer),
            _context(),
            _signed_uow(session_factory, signer, receipt_sealer),
            {"name": "different-args"},
        ),
        (
            "unknown-arguments",
            _receipt(
                "unknown-arguments",
                args={"name": "blocked-agent", "role": "owner"},
                signer=signer,
            ),
            _context(),
            _signed_uow(session_factory, signer, receipt_sealer),
            {"name": "blocked-agent", "role": "owner"},
        ),
        (
            "wrong-policy",
            _receipt("wrong-policy", args=base_args, signer=signer),
            _context(policy_hash="q" * 64),
            _signed_uow(session_factory, signer, receipt_sealer),
            base_args,
        ),
        (
            "wrong-authority",
            _receipt("wrong-authority", args=base_args, signer=signer),
            _context(authority="different-authority"),
            _signed_uow(session_factory, signer, receipt_sealer),
            base_args,
        ),
        (
            "noncanonical-boundary",
            _receipt("noncanonical-boundary", args=base_args, signer=signer),
            _context(execution_boundary="agent-controlled-boundary"),
            _signed_uow(session_factory, signer, receipt_sealer),
            base_args,
        ),
    ]

    for _label, receipt, context, uow, presented_args in cases:
        with pytest.raises(ReceiptValidationError), session_factory() as before:
            assert _counts(before) == {
                "agents": 0,
                "receipts": 0,
                "consumptions": 0,
                "events": 0,
                "outbox": 0,
            }
            uow.execute(
                context=context,
                receipt=receipt,
                args=presented_args,
            )
        with session_factory() as session:
            assert _counts(session) == {
                "agents": 0,
                "receipts": 0,
                "consumptions": 0,
                "events": 0,
                "outbox": 0,
            }
            assert _count(session, ManagedMutationAttempt) == 0


def test_concurrent_receipt_consumption_has_single_committed_winner(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    receipt = _receipt("concurrent-single-winner", args={"name": "only-winner"}, signer=signer)
    _bootstrap_trust_root(session_factory, signer)

    def run_once() -> str:
        try:
            _signed_uow(session_factory, signer, receipt_sealer).execute(
                context=_context(),
                receipt=receipt,
                args={"name": "only-winner"},
            )
            return "committed"
        except Exception as exc:
            return type(exc).__name__

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: run_once(), range(2)))

    assert outcomes.count("committed") == 1
    assert outcomes.count("ReceiptAlreadyUsedError") == 1
    with session_factory() as session:
        assert _counts(session) == {
            "agents": 1,
            "receipts": 1,
            "consumptions": 1,
            "events": 1,
            "outbox": 1,
        }
        attempt = session.scalars(sa.select(ManagedMutationAttempt)).one()
        assert attempt.status == "succeeded"


def test_outbox_rows_appear_only_after_sql_commit(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failing_receipt = _receipt(
        "outbox-rolled-back",
        args={"name": "outbox-fail"},
        signer=signer,
    )

    with monkeypatch.context() as patch:
        patch.setattr(
            managed_mutations_module,
            "_execute_verified_operation",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("outbox-secret")),
        )
        with pytest.raises(RuntimeError):
            _signed_uow(session_factory, signer, receipt_sealer).execute(
                context=_context(),
                receipt=failing_receipt,
                args={"name": "outbox-fail"},
            )
    with session_factory() as session:
        assert _count(session, ManagedOutboxMessage) == 0
        failed_attempt = session.scalars(sa.select(ManagedMutationAttempt)).one()
        assert failed_attempt.status == "failed"

    committed_receipt = _receipt(
        "outbox-commit-boundary",
        args={"name": "commit-agent"},
        signer=signer,
    )
    _signed_uow(session_factory, signer, receipt_sealer).execute(
        context=_context(),
        receipt=committed_receipt,
        args={"name": "commit-agent"},
    )

    with session_factory() as session:
        assert _count(session, ManagedOutboxMessage) == 1
        assert _count(session, ManagedMutationAttempt) == 2


def test_same_receipt_cannot_replay_across_second_environment(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    receipt = _receipt("cross-env-replay", args={"name": "cross-env-agent"}, signer=signer)
    _signed_uow(session_factory, signer, receipt_sealer).execute(
        context=_context(),
        receipt=receipt,
        args={"name": "cross-env-agent"},
    )

    with pytest.raises(ReceiptValidationError):
        _signed_uow(session_factory, signer, receipt_sealer).execute(
            context=_context(environment_id=SECOND_ENVIRONMENT_ID),
            receipt=receipt,
            args={"name": "cross-env-agent"},
        )

    with session_factory() as session:
        assert _count(session, AgentRecord) == 1
        assert (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedDecisionReceipt)
                .where(ManagedDecisionReceipt.environment_id == SECOND_ENVIRONMENT_ID)
            )
            == 0
        )
        assert (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(ManagedReceiptConsumption)
                .where(ManagedReceiptConsumption.environment_id == SECOND_ENVIRONMENT_ID)
            )
            == 0
        )
        assert _count(session, ManagedMutationAttempt) == 1


def test_in_progress_attempt_retry_fails_closed_without_takeover(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _receipt("stale-in-progress", args={"name": "stale-agent"}, signer=signer)
    with session_factory.begin() as session:
        session.add(
            ManagedMutationAttempt(
                id="attempt-stale-in-progress",
                org_id=ORG_ID,
                project_id=PROJECT_ID,
                environment_id=ENVIRONMENT_ID,
                receipt_hash=receipt.receipt_hash,
                audit_event_hash=receipt.audit_event_hash,
                action=ACTION,
                actor_hash=sha256_json(ACTOR),
                argument_hash=receipt.argument_hash,
                status="in_progress",
                failure_class_hash=None,
                failure_digest=None,
            )
        )

    def retry_must_not_execute(*_args: object, **_kwargs: object) -> None:
        pytest.fail("in-progress attempt retry reached the side-effect executor")

    monkeypatch.setattr(
        managed_mutations_module,
        "_execute_verified_operation",
        retry_must_not_execute,
    )
    with pytest.raises(ReceiptAlreadyUsedError):
        _signed_uow(session_factory, signer, receipt_sealer).execute(
            context=_context(),
            receipt=receipt,
            args={"name": "stale-agent"},
        )

    with session_factory() as session:
        attempt = session.scalars(sa.select(ManagedMutationAttempt)).one()
        assert attempt.status == "in_progress"
        assert _counts(session) == {
            "agents": 0,
            "receipts": 0,
            "consumptions": 0,
            "events": 0,
            "outbox": 0,
        }


def test_uow_has_no_arbitrary_python_callback_surface(
    session_factory: sessionmaker[Session],
    tmp_path: Path,
) -> None:
    receipt = _receipt("callback-surface-rejected", args={"name": "callback-agent"})
    marker = tmp_path / "callback-ran"

    def former_callback(_session: Session, _args: Mapping[str, Any]) -> None:
        marker.write_text("external side effect before commit")

    with pytest.raises(TypeError):
        ManagedMutationUnitOfWork(
            session_factory,
            receipt_sealer=AesGcmReceiptArtifactSealer(key_id="local-test-sealer", key=b"k" * 32),
        ).execute(
            context=_context(),
            receipt=receipt,
            args={"name": "callback-agent"},
            callback=former_callback,  # type: ignore[call-arg]
        )

    assert not marker.exists()
    with session_factory() as session:
        assert _counts(session) == {
            "agents": 0,
            "receipts": 0,
            "consumptions": 0,
            "events": 0,
            "outbox": 0,
        }


def test_uow_has_no_caller_supplied_sql_or_result_surface(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    receipt = _receipt("caller-sql-rejected", args={"name": "caller-sql"}, signer=signer)

    with pytest.raises(TypeError):
        _signed_uow(session_factory, signer, receipt_sealer).execute(
            context=_context(),
            receipt=receipt,
            args={"name": "caller-sql"},
            mutation=sa.insert(AgentRecord).values(
                id="attacker-agent",
                org_id=SECOND_ORG_ID,
                name="sibling-tenant-agent",
                description="attacker supplied SQL",
                trust_tier="managed",
                allowed_tools=[],
                status="active",
            ),  # type: ignore[call-arg]
            result={"agent_name_hash": "attacker-controlled"},  # type: ignore[call-arg]
        )
    with pytest.raises(TypeError):
        _signed_uow(session_factory, signer, receipt_sealer).execute(
            context=_context(),
            receipt=receipt,
            args={"name": "caller-sql"},
            mutation=sa.update(AgentRecord).values(status="attacker-active"),  # type: ignore[call-arg]
        )
    with pytest.raises(TypeError):
        _signed_uow(session_factory, signer, receipt_sealer).execute(
            context=_context(),
            receipt=receipt,
            args={"name": "caller-sql"},
            mutation=sa.delete(AgentRecord),  # type: ignore[call-arg]
        )

    with session_factory() as session:
        assert _counts(session) == {
            "agents": 0,
            "receipts": 0,
            "consumptions": 0,
            "events": 0,
            "outbox": 0,
        }


def test_trust_bootstrap_is_one_time_and_preserves_key_history_on_reject(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
) -> None:
    duplicate_signer = Ed25519Signer.generate(key_id="managed-native-duplicate")
    recovery_signer = Ed25519Signer.generate(key_id="managed-native-recovery")
    _bootstrap_trust_root(session_factory, signer)
    with session_factory() as session:
        assert _trust_counts(session) == {"active": 1, "history": 1}

    with pytest.raises(ManagedTrustError, match="bootstrap is one-time"):
        with session_factory.begin() as session:
            ManagedTrustLifecycleService(session).bootstrap(
                scope=_scope(),
                key_id=duplicate_signer.key_id,
                algorithm=duplicate_signer.algorithm,
                public_key_spki_der=public_spki_der_from_signer(duplicate_signer),
                not_after=datetime(2099, 1, 1, tzinfo=UTC),
            )
    with session_factory() as session:
        assert _trust_counts(session) == {"active": 1, "history": 1}

    with session_factory.begin() as session:
        ManagedTrustLifecycleService(session).revoke(
            scope=_scope(),
            key_id=signer.key_id,
            algorithm=signer.algorithm,
        )
    with session_factory() as session:
        assert _trust_counts(session) == {"active": 0, "history": 1}

    with pytest.raises(ManagedTrustError, match="bootstrap is one-time"):
        with session_factory.begin() as session:
            ManagedTrustLifecycleService(session).bootstrap(
                scope=_scope(),
                key_id=recovery_signer.key_id,
                algorithm=recovery_signer.algorithm,
                public_key_spki_der=public_spki_der_from_signer(recovery_signer),
                not_after=datetime(2099, 1, 1, tzinfo=UTC),
            )
    with session_factory() as session:
        assert _trust_counts(session) == {"active": 0, "history": 1}


def test_mint_managed_decision_receipt_v2_rejects_agent_controlled_actor(
    signer: Ed25519Signer,
) -> None:
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json({"name": "actor-bound"}),
        policy_version=POLICY_VERSION,
        event_id="mint-actor-mismatch",
        matched_rules=("managed-mint",),
        reason="test mint actor binding",
        goal="prove actor binding before mint",
        actor="agent-controlled-actor",
        path=("control-plane", "managed-mint"),
        decision_request_hash=sha256_json({"event_id": "mint-actor-mismatch"}),
    )

    with pytest.raises(ReceiptValidationError, match="actor does not match"):
        mint_managed_decision_receipt_v2(
            issuer=InProcessPlatformIssuer(signer),
            context=_context(),
            record=record,
            audit_hash=sha256_json({"audit": "mint-actor-mismatch"}),
            previous_audit_hash="0" * 64,
            trust_epoch=1,
            request_id="request-mint-actor-mismatch",
            expires_at="2099-01-01T00:00:00+00:00",
        )


def test_signed_native_receipt_projection_round_trips_for_offline_verification(
    session_factory: sessionmaker[Session],
    signer: Ed25519Signer,
    receipt_sealer: AesGcmReceiptArtifactSealer,
) -> None:
    secret_sentinel = "sk-native-secret-never-persist"
    args = {"name": "signed-native-agent"}
    receipt = _receipt("signed-native", args=args, signer=signer, metadata_sentinel=secret_sentinel)

    _signed_uow(session_factory, signer, receipt_sealer).execute(
        context=_context(),
        receipt=receipt,
        args=args,
    )

    with session_factory() as session:
        receipt_row = session.scalars(sa.select(ManagedDecisionReceipt)).one()
        assert receipt_row.assurance_class == ASSURANCE_CLASS_NATIVE
        assert receipt_row.projection["assurance_class"] == ASSURANCE_CLASS_NATIVE
        assert secret_sentinel not in str(receipt_row.projection)
        event = session.scalars(sa.select(ManagedGovernanceEvent)).one()
        outbox = session.scalars(sa.select(ManagedOutboxMessage)).one()
        assert secret_sentinel not in str(event.payload)
        assert secret_sentinel not in str(outbox.payload)

        sealed = receipt_row.projection["sealed_receipt"]
        plaintext = receipt_sealer.unseal(
            sealed,
            associated_data=managed_receipt_artifact_aad(
                org_id=ORG_ID,
                project_id=PROJECT_ID,
                environment_id=ENVIRONMENT_ID,
                receipt_hash=receipt.receipt_hash,
            ),
        )
        assert secret_sentinel in plaintext.decode("utf-8")
        canonical_receipt = json.loads(plaintext.decode("utf-8"))
        assert canonical_receipt == receipt.to_dict()
        restored = DecisionReceipt.from_dict(canonical_receipt)
        assert restored.to_dict() == receipt.to_dict()
        restored.verify(
            expected_tenant_id=ORG_ID,
            expected_execution_boundary=_boundary(),
            expected_action=ACTION,
            expected_actor=ACTOR,
            expected_args=dict(args),
            expected_policy_hash=POLICY_HASH,
            expected_policy_bundle_id=POLICY_BUNDLE_ID,
            expected_project_id=PROJECT_ID,
            expected_environment_id=ENVIRONMENT_ID,
            expected_validator_role=VALIDATOR_ROLE,
            expected_authority=AUTHORITY,
            require_signature=True,
            require_expiry=True,
            trust_registry=SqlReceiptTrustRegistry(session),
        )


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


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _flip_first_byte(value: bytes) -> bytes:
    if not value:
        return value
    return bytes([value[0] ^ 1]) + value[1:]
