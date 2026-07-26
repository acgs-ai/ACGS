"""Integration evidence for the transactional native-receipt prerequisite."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from gove_zone.consumption import ReceiptConsumptionLedger
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import ProductionProfileError, ReceiptAlreadyUsedError, ReceiptValidationError
from gove_zone.executor import execute_with_receipt
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.revocation import RevocationList
from gove_zone.signing import Ed25519Signer
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from acgs_control_plane.db import make_engine
from acgs_control_plane.migrations import upgrade_database
from acgs_control_plane.models import (
    AgentRecord,
    NativeDecisionReceiptRow,
    NativeReceiptConsumption,
    Organization,
)
from acgs_control_plane.native_receipts import (
    DatabaseNativeReceiptStore,
    DatabaseReceiptConsumptionLedger,
    ManagedConsumptionAttestationTrust,
    ManagedNativeReceiptTrust,
    NativeReceiptContext,
    TenantPrivacyProvider,
    native_receipt_pseudonym,
    native_receipt_reference,
)

ORG_A = "org-native-a"
ORG_B = "org-native-b"
PRIVACY = TenantPrivacyProvider(b"native-ledger-privacy-key-32bytes!!")
ACTOR = native_receipt_pseudonym("actor", "agent-native", tenant_id=ORG_A, privacy=PRIVACY)
ACTION = "database.agent.create"
BOUNDARY = "control-plane/sql-transaction"
POLICY_BUNDLE = native_receipt_reference(
    "policy_bundle_id", "bundle-native-v1", tenant_id=ORG_A, privacy=PRIVACY
)
VALIDATOR_ID = native_receipt_pseudonym(
    "validator_id", "validator-1", tenant_id=ORG_A, privacy=PRIVACY
)
VALIDATOR_ROLE = native_receipt_pseudonym(
    "validator_role", "policy-validator", tenant_id=ORG_A, privacy=PRIVACY
)
AUTHORITY = native_receipt_pseudonym(
    "authority", "execute:database.agent.create", tenant_id=ORG_A, privacy=PRIVACY
)
POLICY_HASH = "a" * 64
ARGS = {"name": "governed-agent"}
_SAME_KEY_MATERIAL = bytes.fromhex(
    "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
)


class _FakeSigner:
    def __init__(self, *, key_id: str, algorithm: str) -> None:
        self._key_id = key_id
        self._algorithm = algorithm

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def sign(self, payload: bytes) -> str:
        return sha256_json({"payload": payload.hex(), "key_id": self.key_id})

    def verify(self, payload: bytes, signature: str) -> bool:
        return signature == self.sign(payload)


@pytest.fixture()
def engine(tmp_path: Path) -> Iterator[sa.Engine]:
    database_url = f"sqlite:///{tmp_path / 'native-receipts.sqlite3'}"
    upgrade_database(database_url)
    engine = make_engine(database_url)
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
    with Session(engine) as session, session.begin():
        session.add_all(
            [
                Organization(id=ORG_A, name="Native A"),
                Organization(id=ORG_B, name="Native B"),
            ]
        )
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture()
def signer() -> Ed25519Signer:
    return Ed25519Signer.generate(key_id="native-key-v1")


@pytest.fixture()
def attestor() -> Ed25519Signer:
    return Ed25519Signer.generate(key_id="native-consumption-attestor-v1")


def _trust(
    signer: Ed25519Signer,
    *,
    trusted: bool = True,
    revoked: bool = False,
) -> ManagedNativeReceiptTrust:
    return ManagedNativeReceiptTrust(
        signer=signer,
        verifiers={signer.key_id: signer} if trusted else {},
        revoked_keys=RevocationList([signer.key_id] if revoked else []),
        max_lifetime=timedelta(minutes=5),
    )


def _consumption_trust(attestor: Ed25519Signer) -> ManagedConsumptionAttestationTrust:
    return ManagedConsumptionAttestationTrust(
        signer=attestor,
        verifiers={attestor.key_id: attestor},
    )


def _same_key_material_signers() -> tuple[Ed25519Signer, Ed25519Signer]:
    return (
        Ed25519Signer.from_private_bytes(_SAME_KEY_MATERIAL, key_id="native-issuer-same-material"),
        Ed25519Signer.from_private_bytes(
            _SAME_KEY_MATERIAL, key_id="native-attestor-same-material"
        ),
    )


def _context(
    *,
    org_id: str = ORG_A,
    execution_boundary: str = BOUNDARY,
    actor: str = ACTOR,
    action: str = ACTION,
    policy_bundle_id: str = POLICY_BUNDLE,
    policy_hash: str = POLICY_HASH,
    audit_hash: str | None = "b" * 64,
    args: dict[str, Any] | None = ARGS,
    validator_role: str | None = VALIDATOR_ROLE,
    authority: str | None = AUTHORITY,
) -> NativeReceiptContext:
    return NativeReceiptContext(
        org_id=org_id,
        execution_boundary=execution_boundary,
        actor=actor,
        action=action,
        policy_bundle_id=policy_bundle_id,
        policy_hash=policy_hash,
        audit_hash=audit_hash,
        args=args,
        validator_role=validator_role,
        authority=authority,
    )


def _receipt(
    signer: Ed25519Signer | None,
    *,
    now: datetime | None = None,
    expires_delta: timedelta = timedelta(minutes=2),
    decision: Decision = Decision.ALLOW,
    request_id: str = "native-request-1",
    goal: str = "",
    subject: str = "",
    matched_rules: tuple[str, ...] = (),
    transformed_args: dict[str, Any] | None = None,
    constraints: dict[str, Any] | None = None,
    approval_chain_summary: dict[str, Any] | None = None,
) -> DecisionReceipt:
    issued = (now or datetime.now(UTC)).astimezone(UTC)
    record = DecisionRecord(
        decision=decision,
        tool=ACTION,
        argument_hash=sha256_json(ARGS),
        policy_version="policy-v1",
        event_id="native-event-1",
        actor=ACTOR,
        timestamp_iso=issued.isoformat(),
        goal=goal,
        matched_rules=matched_rules,
        transformed_args=transformed_args,
    )
    return DecisionReceipt.from_record(
        record,
        audit_hash="b" * 64,
        previous_audit_hash="0" * 64,
        tenant_id=ORG_A,
        execution_boundary=BOUNDARY,
        policy_bundle_id=POLICY_BUNDLE,
        policy_hash=POLICY_HASH,
        request_id=request_id,
        validator=Validator(VALIDATOR_ID, VALIDATOR_ROLE),
        authority=AUTHORITY,
        subject=subject,
        constraints=constraints,
        approval_chain_summary=approval_chain_summary,
        expires_at=(issued + expires_delta).isoformat(),
        signer=signer,
    )


def _receipt_with_fake_issuer(fake: _FakeSigner) -> DecisionReceipt:
    issued = datetime.now(UTC)
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(ARGS),
        policy_version="policy-v1",
        event_id="native-fake-issuer-event",
        actor=ACTOR,
        timestamp_iso=issued.isoformat(),
    )
    return DecisionReceipt.from_record(
        record,
        audit_hash="b" * 64,
        previous_audit_hash="0" * 64,
        tenant_id=ORG_A,
        execution_boundary=BOUNDARY,
        policy_bundle_id=POLICY_BUNDLE,
        policy_hash=POLICY_HASH,
        request_id="native-fake-issuer-request",
        validator=Validator(VALIDATOR_ID, VALIDATOR_ROLE),
        authority=AUTHORITY,
        expires_at=(issued + timedelta(minutes=2)).isoformat(),
        signer=fake,
    )


def _execute(
    session: Session,
    receipt: DecisionReceipt,
    trust: ManagedNativeReceiptTrust,
    context: NativeReceiptContext,
    attestor: Ed25519Signer,
    *,
    execution_args: dict[str, Any] = ARGS,
) -> str:
    ledger = DatabaseReceiptConsumptionLedger(
        session,
        trust=trust,
        consumption_trust=_consumption_trust(attestor),
        context=context,
    )

    def protected_effect(name: str) -> str:
        session.add(AgentRecord(org_id=ORG_A, name=name))
        session.flush()
        return name

    return execute_with_receipt(
        protected_effect,
        execution_args,
        receipt,
        expected_tenant_id=context.org_id,
        expected_execution_boundary=context.execution_boundary,
        expected_action=context.action,
        expected_actor=context.actor,
        expected_audit_hash=context.audit_hash,
        expected_policy_hash=context.policy_hash,
        expected_policy_bundle_id=context.policy_bundle_id,
        expected_validator_role=context.validator_role,
        expected_authority=context.authority,
        verifier=trust.verifiers,
        require_signature=True,
        require_expiry=True,
        revoked_keys=trust.revoked_keys,
        consumption_ledger=cast(ReceiptConsumptionLedger, ledger),
    )


def _counts(session: Session) -> tuple[int, int, int]:
    return (
        session.scalar(sa.select(sa.func.count()).select_from(NativeDecisionReceiptRow)) or 0,
        session.scalar(sa.select(sa.func.count()).select_from(NativeReceiptConsumption)) or 0,
        session.scalar(sa.select(sa.func.count()).select_from(AgentRecord)) or 0,
    )


def test_signed_native_allow_persists_and_executes_exactly_once(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    receipt = _receipt(signer)
    trust = _trust(signer)
    context = _context()

    # Exercise the canonical public primitives explicitly before the DB adapters.
    receipt.verify(
        expected_tenant_id=ORG_A,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_args=ARGS,
        expected_actor=ACTOR,
        expected_policy_hash=POLICY_HASH,
        expected_policy_bundle_id=POLICY_BUNDLE,
        verifier=trust.verifiers,
        require_signature=True,
        require_expiry=True,
    )
    with Session(engine) as session, session.begin():
        row = DatabaseNativeReceiptStore(session, trust=trust).persist(receipt, context)
        assert _execute(session, receipt, trust, context, attestor) == ARGS["name"]
        assert "args" not in row.__table__.columns
        assert "request_id" not in row.__table__.columns
        assert row.assurance_class == "native"
        assert row.source_system == "gove-zone"
        assert row.projection["schema"] == "acgs.native-receipt-projection.v1"
        assert row.projection["receipt_hash"] == receipt.receipt_hash
        assert row.projection["argument_hash"] == receipt.argument_hash
        assert row.projection["signature"] == receipt.signature

    with Session(engine) as session:
        assert _counts(session) == (1, 1, 1)
        with pytest.raises(ReceiptAlreadyUsedError):
            _execute(session, receipt, trust, context, attestor)
        assert _counts(session) == (1, 1, 1)


@pytest.mark.parametrize(
    ("case", "context"),
    [
        ("wrong-tenant", _context(org_id=ORG_B)),
        ("wrong-actor", _context(actor="different-agent")),
        ("wrong-boundary", _context(execution_boundary="different-boundary")),
        ("wrong-action", _context(action="database.agent.delete")),
        ("wrong-policy", _context(policy_hash="c" * 64)),
        ("wrong-policy-bundle", _context(policy_bundle_id="different-bundle")),
        ("wrong-arguments", _context(args={"name": "different-agent"})),
    ],
)
def test_bound_context_mismatch_executes_zero_side_effects(
    engine: sa.Engine,
    signer: Ed25519Signer,
    attestor: Ed25519Signer,
    case: str,
    context: NativeReceiptContext,
) -> None:
    del case
    receipt = _receipt(signer)
    trust = _trust(signer)
    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError):
            DatabaseNativeReceiptStore(session, trust=trust).persist(receipt, context)
        with pytest.raises(ReceiptValidationError):
            _execute(session, receipt, trust, context, attestor)
        session.rollback()
        assert _counts(session) == (0, 0, 0)


@pytest.mark.parametrize("case", ["unsigned", "expired", "untrusted", "revoked"])
def test_authenticity_or_liveness_failure_executes_zero_side_effects(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer, case: str
) -> None:
    now = datetime.now(UTC)
    receipt = _receipt(None if case == "unsigned" else signer, now=now)
    trust = _trust(signer, trusted=case != "untrusted", revoked=case == "revoked")
    if case == "expired":
        receipt = _receipt(
            signer, now=now - timedelta(minutes=3), expires_delta=timedelta(minutes=1)
        )

    with Session(engine) as session:
        with pytest.raises((ReceiptValidationError, ProductionProfileError)):
            DatabaseNativeReceiptStore(session, trust=trust).persist(receipt, _context())
        with pytest.raises((ReceiptValidationError, ProductionProfileError)):
            _execute(session, receipt, trust, _context(), attestor)
        session.rollback()
        assert _counts(session) == (0, 0, 0)


@pytest.mark.parametrize("decision", [Decision.DENY, Decision.ESCALATE])
def test_non_allow_native_receipt_is_never_persisted_or_executable(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer, decision: Decision
) -> None:
    receipt = _receipt(signer, decision=decision)
    trust = _trust(signer)
    context = _context()
    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError):
            DatabaseNativeReceiptStore(session, trust=trust).persist(receipt, context)
        with pytest.raises(ReceiptValidationError):
            _execute(session, receipt, trust, context, attestor)
        session.rollback()
        assert _counts(session) == (0, 0, 0)


@pytest.mark.parametrize(
    "receipt",
    [
        pytest.param("tampered-signature", id="tampered-signature"),
        pytest.param("overlong-expiry", id="overlong-expiry"),
    ],
)
def test_signature_tamper_or_unbounded_lifetime_executes_zero_side_effects(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer, receipt: str
) -> None:
    candidate = _receipt(
        signer,
        expires_delta=timedelta(minutes=10)
        if receipt == "overlong-expiry"
        else timedelta(minutes=2),
    )
    if receipt == "tampered-signature":
        candidate = replace(candidate, signature="00" * 64)
    trust = _trust(signer)
    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError):
            DatabaseNativeReceiptStore(session, trust=trust).persist(candidate, _context())
        with pytest.raises(ReceiptValidationError):
            _execute(session, candidate, trust, _context(), attestor)
        session.rollback()
        assert _counts(session) == (0, 0, 0)


def test_caller_rollback_removes_receipt_burn_and_effect(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    receipt = _receipt(signer)
    trust = _trust(signer)
    context = _context()
    with pytest.raises(RuntimeError, match="injected failure"):
        with Session(engine) as session, session.begin():
            DatabaseNativeReceiptStore(session, trust=trust).persist(receipt, context)
            _execute(session, receipt, trust, context, attestor)
            raise RuntimeError("injected failure")

    with Session(engine) as session:
        assert _counts(session) == (0, 0, 0)


def test_valid_but_unpersisted_receipt_executes_zero_side_effects(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    receipt = _receipt(signer)
    trust = _trust(signer)
    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError, match="must be persisted before consumption"):
            _execute(session, receipt, trust, _context(), attestor)
        session.rollback()
        assert _counts(session) == (0, 0, 0)


def test_tampered_persisted_receipt_executes_zero_side_effects(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    receipt = _receipt(signer)
    trust = _trust(signer)
    context = _context()
    with Session(engine) as session, session.begin():
        row = DatabaseNativeReceiptStore(session, trust=trust).persist(receipt, context)
        row.receipt_hash = "f" * 64

    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError, match="does not match input"):
            _execute(session, receipt, trust, context, attestor)
        session.rollback()
        assert _counts(session) == (1, 0, 0)


def test_composite_foreign_key_rejects_cross_tenant_consumption(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    receipt = _receipt(signer)
    trust = _trust(signer)
    with Session(engine) as session, session.begin():
        persisted = DatabaseNativeReceiptStore(session, trust=trust).persist(receipt, _context())
        persisted_id = persisted.id

    with Session(engine) as session:
        session.add(
            NativeReceiptConsumption(
                org_id=ORG_B,
                native_receipt_id=persisted_id,
                receipt_hash=receipt.receipt_hash,
                audit_event_hash=receipt.audit_event_hash,
            )
        )
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()
        assert session.scalar(sa.select(sa.func.count()).select_from(NativeReceiptConsumption)) == 0


def test_store_rejects_tampered_receipt_without_persisting(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    receipt = replace(_receipt(signer), actor="tampered-agent")
    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError):
            DatabaseNativeReceiptStore(session, trust=_trust(signer)).persist(receipt, _context())
        session.rollback()
        assert _counts(session) == (0, 0, 0)


@pytest.mark.parametrize(
    "receipt_kwargs",
    [
        pytest.param({"subject": "secret-sentinel"}, id="subject"),
        pytest.param({"goal": "secret-sentinel"}, id="declared-goal"),
        pytest.param({"constraints": {"api_token": "secret-sentinel"}}, id="constraints"),
        pytest.param(
            {"approval_chain_summary": {"review_note": "secret-sentinel"}},
            id="approval-metadata",
        ),
        pytest.param(
            {
                "decision": Decision.TRANSFORM,
                "transformed_args": {"name": "secret-sentinel"},
            },
            id="transformation",
        ),
    ],
)
def test_freeform_receipt_values_are_rejected_without_leak_or_side_effect(
    engine: sa.Engine,
    signer: Ed25519Signer,
    attestor: Ed25519Signer,
    receipt_kwargs: dict[str, Any],
) -> None:
    secret = "secret-sentinel"
    receipt = _receipt(signer, **receipt_kwargs)
    trust = _trust(signer)
    context = _context()

    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError) as store_error:
            DatabaseNativeReceiptStore(session, trust=trust).persist(receipt, context)
        assert secret not in str(store_error.value)

        ledger = DatabaseReceiptConsumptionLedger(
            session,
            trust=trust,
            consumption_trust=_consumption_trust(attestor),
            context=context,
        )
        with pytest.raises(ReceiptValidationError) as ledger_error:
            ledger.consume(receipt)
        assert secret not in str(ledger_error.value)

        with pytest.raises(ReceiptValidationError) as execution_error:
            execution_args = (
                {"name": secret} if receipt.decision == Decision.TRANSFORM.value else ARGS
            )
            _execute(
                session,
                receipt,
                trust,
                context,
                attestor,
                execution_args=execution_args,
            )
        assert secret not in str(execution_error.value)
        session.rollback()
        assert _counts(session) == (0, 0, 0)


def test_request_and_rule_identifiers_are_stored_only_as_hashes(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    secret = "secret-sentinel"
    receipt = _receipt(signer, request_id=secret, matched_rules=(secret,))
    trust = _trust(signer)
    context = _context()

    with Session(engine) as session, session.begin():
        row = DatabaseNativeReceiptStore(session, trust=trust).persist(receipt, context)
        assert _execute(session, receipt, trust, context, attestor) == ARGS["name"]
        persisted_text = json.dumps(row.projection, sort_keys=True)
        scalar_text = "|".join(
            [
                row.receipt_id,
                row.receipt_hash,
                row.audit_event_hash,
                row.assurance_class,
                row.source_system,
                row.actor,
                row.execution_boundary,
                row.proposed_action,
                row.policy_bundle_id,
                row.policy_version,
                row.policy_hash,
                row.signing_key_id,
                row.signature_algorithm,
            ]
        )
        assert secret not in persisted_text
        assert secret not in scalar_text
        assert row.projection["request_id_hash"] == sha256_json(secret)
        assert row.projection["matched_rules_hash"] == sha256_json([secret])

    with Session(engine) as session:
        assert _counts(session) == (1, 1, 1)


def test_consumption_attestor_must_be_distinct_from_receipt_issuer(
    engine: sa.Engine, signer: Ed25519Signer
) -> None:
    receipt = _receipt(signer)
    trust = _trust(signer)
    context = _context()

    with Session(engine) as session, session.begin():
        DatabaseNativeReceiptStore(session, trust=trust).persist(receipt, context)

    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError, match="distinct from receipt issuer"):
            _execute(session, receipt, trust, context, signer)
        session.rollback()
        assert _counts(session) == (1, 0, 0)


def test_consumption_attestor_must_use_distinct_key_material_from_issuer(
    engine: sa.Engine,
) -> None:
    issuer, attestor = _same_key_material_signers()
    receipt = _receipt(issuer)
    trust = _trust(issuer)
    context = _context()

    with Session(engine) as session, session.begin():
        DatabaseNativeReceiptStore(session, trust=trust).persist(receipt, context)

    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError, match="distinct key material"):
            _execute(session, receipt, trust, context, attestor)
        session.rollback()
        assert _counts(session) == (1, 0, 0)


def test_database_rejects_native_assurance_class_flattening(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    receipt = _receipt(signer)
    with Session(engine) as session, session.begin():
        DatabaseNativeReceiptStore(session, trust=_trust(signer)).persist(receipt, _context())
    with Session(engine) as session:
        row = session.scalar(sa.select(NativeDecisionReceiptRow))
        assert row is not None
        row.assurance_class = "federated"
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()
        assert session.scalar(sa.select(NativeDecisionReceiptRow.assurance_class)) == "native"


def test_managed_trust_never_silently_mints_unsigned(signer: Ed25519Signer) -> None:
    with pytest.raises(ProductionProfileError):
        ManagedNativeReceiptTrust(signer=None, verifiers={}).assert_ready()
    with pytest.raises(ProductionProfileError):
        ManagedNativeReceiptTrust(signer=signer, verifiers={}).assert_ready()
    with pytest.raises(ProductionProfileError):
        ManagedNativeReceiptTrust(
            signer=signer,
            verifiers={signer.key_id: signer},
            revoked_keys=RevocationList([signer.key_id]),
        ).assert_ready()


def test_managed_issuer_trust_rejects_alias_and_non_ed25519_keys(
    signer: Ed25519Signer,
) -> None:
    alias_trust = ManagedNativeReceiptTrust(
        signer=signer,
        verifiers={"alias-issuer-key": signer},
    )
    with pytest.raises(ProductionProfileError, match="trust map key mismatch"):
        alias_trust.assert_ready()

    fake = _FakeSigner(key_id="fake-issuer-key", algorithm="sha256")
    fake_trust = ManagedNativeReceiptTrust(
        signer=fake,
        verifiers={fake.key_id: fake},
    )
    with pytest.raises(ProductionProfileError, match="Ed25519 signer"):
        fake_trust.assert_ready()

    none = _FakeSigner(key_id="none-issuer-key", algorithm="none")
    none_trust = ManagedNativeReceiptTrust(
        signer=none,
        verifiers={none.key_id: none},
    )
    with pytest.raises(ProductionProfileError, match="Ed25519 signer"):
        none_trust.assert_ready()

    unsafe_key = Ed25519Signer.generate(key_id="sk_live_secret_sentinel")
    unsafe_trust = ManagedNativeReceiptTrust(
        signer=unsafe_key,
        verifiers={unsafe_key.key_id: unsafe_key},
    )
    with pytest.raises(ReceiptValidationError, match="unsafe receipt_signing_key_id"):
        unsafe_trust.assert_ready()


def test_non_ed25519_issuer_cannot_mint_or_persist_native_receipt(engine: sa.Engine) -> None:
    fake = _FakeSigner(key_id="fake-issuer-key", algorithm="sha256")
    trust = ManagedNativeReceiptTrust(signer=fake, verifiers={fake.key_id: fake})
    issued = datetime.now(UTC)
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(ARGS),
        policy_version="policy-v1",
        event_id="managed-fake-issuer-event",
        actor=ACTOR,
        timestamp_iso=issued.isoformat(),
    )

    with pytest.raises(ProductionProfileError, match="Ed25519 signer"):
        trust.mint(
            record,
            audit_hash="b" * 64,
            previous_audit_hash="0" * 64,
            tenant_id=ORG_A,
            execution_boundary=BOUNDARY,
            policy_bundle_id=POLICY_BUNDLE,
            policy_hash=POLICY_HASH,
            request_id="managed-fake-issuer-request",
            validator=Validator(VALIDATOR_ID, VALIDATOR_ROLE),
            authority=AUTHORITY,
            expires_at=(issued + timedelta(minutes=2)).isoformat(),
            now=issued,
        )

    receipt = _receipt_with_fake_issuer(fake)
    with Session(engine) as session:
        with pytest.raises(ProductionProfileError, match="Ed25519 signer"):
            DatabaseNativeReceiptStore(session, trust=trust).persist(receipt, _context())
        session.rollback()
        assert _counts(session) == (0, 0, 0)


def test_consumption_attestor_trust_rejects_alias_and_non_ed25519_keys(
    attestor: Ed25519Signer,
) -> None:
    alias_trust = ManagedConsumptionAttestationTrust(
        signer=attestor,
        verifiers={"alias-attestor-key": attestor},
    )
    with pytest.raises(ProductionProfileError, match="trust map key mismatch"):
        alias_trust.assert_ready()

    fake = _FakeSigner(key_id="fake-attestor-key", algorithm="sha256")
    fake_trust = ManagedConsumptionAttestationTrust(
        signer=fake,
        verifiers={fake.key_id: fake},
    )
    with pytest.raises(ProductionProfileError, match="Ed25519 attestor"):
        fake_trust.assert_ready()

    none = _FakeSigner(key_id="none-attestor-key", algorithm="none")
    none_trust = ManagedConsumptionAttestationTrust(
        signer=none,
        verifiers={none.key_id: none},
    )
    with pytest.raises(ProductionProfileError, match="Ed25519 attestor"):
        none_trust.assert_ready()

    unsafe_key = Ed25519Signer.generate(key_id="sk_live_secret_sentinel")
    unsafe_trust = ManagedConsumptionAttestationTrust(
        signer=unsafe_key,
        verifiers={unsafe_key.key_id: unsafe_key},
    )
    with pytest.raises(ReceiptValidationError, match="unsafe attestor_key_id"):
        unsafe_trust.assert_ready()

    artifact = {"schema": "test", "value": "alias-check"}
    artifact_hash = sha256_json(artifact)
    alias_signature = attestor.sign(artifact_hash.encode())
    with pytest.raises(ReceiptValidationError, match="signer identity mismatch"):
        ManagedConsumptionAttestationTrust(
            signer=attestor,
            verifiers={"alias-attestor-key": attestor},
        ).verify(
            artifact,
            artifact_hash=artifact_hash,
            algorithm="ed25519",
            key_id="alias-attestor-key",
            signature=alias_signature,
        )


def test_managed_trust_mint_returns_signed_receipt_and_missing_trust_fails_loud(
    signer: Ed25519Signer,
) -> None:
    issued = datetime.now(UTC)
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(ARGS),
        policy_version="policy-v1",
        event_id="managed-mint-event",
        actor=ACTOR,
        timestamp_iso=issued.isoformat(),
    )
    receipt = _trust(signer).mint(
        record,
        audit_hash="b" * 64,
        previous_audit_hash="0" * 64,
        tenant_id=ORG_A,
        execution_boundary=BOUNDARY,
        policy_bundle_id=POLICY_BUNDLE,
        policy_hash=POLICY_HASH,
        request_id="managed-mint-request",
        validator=Validator(VALIDATOR_ID, VALIDATOR_ROLE),
        authority=AUTHORITY,
        expires_at=(issued + timedelta(minutes=2)).isoformat(),
        now=issued,
    )
    assert receipt.signature_algorithm == signer.algorithm
    assert receipt.signing_key_id == signer.key_id
    assert receipt.signature != "unsigned_local"
    receipt.verify(
        expected_tenant_id=ORG_A,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_args=ARGS,
        expected_actor=ACTOR,
        expected_policy_hash=POLICY_HASH,
        expected_policy_bundle_id=POLICY_BUNDLE,
        verifier={signer.key_id: signer},
        require_signature=True,
        require_expiry=True,
        now_iso=issued.isoformat(),
    )

    missing_signer = ManagedNativeReceiptTrust(signer=None, verifiers={signer.key_id: signer})
    with pytest.raises(ProductionProfileError, match="Ed25519 signer"):
        missing_signer.mint(
            record,
            audit_hash="b" * 64,
            previous_audit_hash="0" * 64,
            tenant_id=ORG_A,
            execution_boundary=BOUNDARY,
            policy_bundle_id=POLICY_BUNDLE,
            policy_hash=POLICY_HASH,
            request_id="managed-mint-request",
            validator=Validator(VALIDATOR_ID, VALIDATOR_ROLE),
            authority=AUTHORITY,
            expires_at=(issued + timedelta(minutes=2)).isoformat(),
            now=issued,
        )
