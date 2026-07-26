"""Verifier evidence for reconstructible native Decision Receipt artifacts."""

from __future__ import annotations

import copy
import json
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from gove_zone.audit import GENESIS_HASH
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import ProductionProfileError, ReceiptValidationError
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.revocation import RevocationList
from gove_zone.signing import Ed25519Signer
from sqlalchemy.orm import Session

from acgs_control_plane import governance
from acgs_control_plane.db import make_engine
from acgs_control_plane.governance import DatabaseGovernanceEventAppender
from acgs_control_plane.migrations import DatabaseSchemaState, inspect_schema, upgrade_database
from acgs_control_plane.models import (
    GovernanceEvent,
    GovernanceEventCutover,
    GovernanceEventHead,
    NativeDecisionReceiptRow,
    NativeReceiptConsumption,
    Organization,
    ReceiptRow,
)
from acgs_control_plane.native_receipts import (
    DatabaseNativeReceiptStore,
    DatabaseReceiptConsumptionLedger,
    ManagedConsumptionAttestationTrust,
    ManagedNativeReceiptTrust,
    NativeReceiptContext,
    TenantPrivacyProvider,
    assess_native_cutover_readiness,
    native_receipt_pseudonym,
    native_receipt_reference,
    verify_native_evidence_chain,
)

ORG_A = "org-native-evidence-a"
ORG_B = "org-native-evidence-b"
PRIVACY = TenantPrivacyProvider(b"native-evidence-privacy-key-32b!!")
ACTOR = native_receipt_pseudonym("actor", "agent-native", tenant_id=ORG_A, privacy=PRIVACY)
ACTION = "database.agent.create"
BOUNDARY = "control-plane/sql-transaction"
POLICY_BUNDLE = native_receipt_reference(
    "policy_bundle_id", "bundle-native-v1", tenant_id=ORG_A, privacy=PRIVACY
)
POLICY_HASH = "a" * 64
ARGS = {"name": "governed-agent"}
REQUEST_ID = "1" * 64
MATCHED_RULE = "2" * 64
_SAME_KEY_MATERIAL = bytes.fromhex(
    "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
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
_AUTO = object()


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
    database_url = f"sqlite:///{tmp_path / 'native-evidence.sqlite3'}"
    result = upgrade_database(database_url)
    assert result.after.state is DatabaseSchemaState.VERSION_0009
    assert inspect_schema(database_url).state is DatabaseSchemaState.VERSION_0009
    engine = make_engine(database_url)
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
    with Session(engine) as session, session.begin():
        session.add_all(
            [
                Organization(id=ORG_A, name="Native Evidence A"),
                Organization(id=ORG_B, name="Native Evidence B"),
            ]
        )
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture()
def signer() -> Ed25519Signer:
    return Ed25519Signer.generate(key_id="native-evidence-key-v1")


@pytest.fixture()
def attestor() -> Ed25519Signer:
    return Ed25519Signer.generate(key_id="native-consumption-attestor-v1")


def _trust(signer: Ed25519Signer, *, revoked: bool = False) -> ManagedNativeReceiptTrust:
    return ManagedNativeReceiptTrust(
        signer=signer,
        verifiers={signer.key_id: signer},
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
        Ed25519Signer.from_private_bytes(
            _SAME_KEY_MATERIAL, key_id="native-evidence-issuer-same-material"
        ),
        Ed25519Signer.from_private_bytes(
            _SAME_KEY_MATERIAL, key_id="native-evidence-attestor-same-material"
        ),
    )


def _context(*, audit_hash: str, previous_hash: str = GENESIS_HASH) -> NativeReceiptContext:
    del previous_hash
    return NativeReceiptContext(
        org_id=ORG_A,
        execution_boundary=BOUNDARY,
        actor=ACTOR,
        action=ACTION,
        policy_bundle_id=POLICY_BUNDLE,
        policy_hash=POLICY_HASH,
        audit_hash=audit_hash,
        args=ARGS,
        validator_role=VALIDATOR_ROLE,
        authority=AUTHORITY,
    )


def _record(
    *,
    event_id: str = "native-evidence-event-1",
    issued: datetime | None = None,
    argument_hash: str | None = None,
) -> DecisionRecord:
    return DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=argument_hash or sha256_json(ARGS),
        policy_version="policy-v1",
        event_id=event_id,
        actor=ACTOR,
        timestamp_iso=(issued or datetime.now(UTC)).isoformat(),
        matched_rules=(MATCHED_RULE,),
        path=(ORG_A, "project-native", "env-prod"),
        decision_request_hash="3" * 64,
    )


def _receipt_for_event(
    signer: Ed25519Signer | _FakeSigner,
    record: DecisionRecord,
    *,
    audit_hash: str,
    previous_hash: str = GENESIS_HASH,
    expires_delta: timedelta = timedelta(minutes=2),
) -> DecisionReceipt:
    issued = datetime.fromisoformat(record.timestamp_iso)
    return DecisionReceipt.from_record(
        record,
        audit_hash,
        previous_hash,
        ORG_A,
        BOUNDARY,
        POLICY_BUNDLE,
        POLICY_HASH,
        REQUEST_ID,
        validator=Validator(VALIDATOR_ID, VALIDATOR_ROLE),
        authority=AUTHORITY,
        expires_at=(issued + expires_delta).isoformat(),
        signer=signer,
    )


def _counts(session: Session) -> tuple[int, int, int]:
    return (
        int(session.scalar(sa.select(sa.func.count()).select_from(GovernanceEvent)) or 0),
        int(session.scalar(sa.select(sa.func.count()).select_from(NativeDecisionReceiptRow)) or 0),
        int(session.scalar(sa.select(sa.func.count()).select_from(NativeReceiptConsumption)) or 0),
    )


def _persist_one(
    session: Session,
    signer: Ed25519Signer,
    attestor: Ed25519Signer,
    *,
    event_id: str = "native-evidence-event-1",
    now: datetime | None = None,
    consume: bool = True,
) -> NativeDecisionReceiptRow:
    record = _record(event_id=event_id, issued=now)
    event = DatabaseGovernanceEventAppender(session, ORG_A).append(record)
    receipt = _receipt_for_event(
        signer,
        record,
        audit_hash=str(event["event_hash"]),
        previous_hash=str(event["previous_hash"]),
    )
    trust = _trust(signer)
    row = DatabaseNativeReceiptStore(session, trust=trust).persist_verifiable(
        receipt,
        _context(audit_hash=str(event["event_hash"])),
        now=now,
    )
    if consume:
        DatabaseReceiptConsumptionLedger(
            session,
            trust=trust,
            consumption_trust=_consumption_trust(attestor),
            context=_context(audit_hash=str(event["event_hash"])),
        ).consume(receipt)
    return row


def _set_cutover_ready(
    session: Session,
    *,
    cutover_at: datetime | None = None,
    legacy_audit_anchor_count: int = 0,
    legacy_audit_anchor_hash: str = "",
    native_event_count: int | object | None = _AUTO,
    native_event_head_hash: str | object | None = _AUTO,
) -> None:
    head = session.get(GovernanceEventHead, ORG_A)
    if native_event_count is _AUTO:
        native_event_count = head.last_sequence if head is not None else None
    if native_event_head_hash is _AUTO:
        native_event_head_hash = head.last_event_hash if head is not None else None
    session.add(
        GovernanceEventCutover(
            org_id=ORG_A,
            state="native_artifacts_ready",
            legacy_audit_anchor_count=legacy_audit_anchor_count,
            legacy_audit_anchor_hash=legacy_audit_anchor_hash,
            native_event_count=native_event_count,
            native_event_head_hash=native_event_head_hash,
            cutover_at=cutover_at or datetime.now(UTC),
        )
    )


def _artifact(row: NativeDecisionReceiptRow) -> dict[str, object]:
    artifact = row.receipt_artifact
    assert artifact is not None
    return artifact


def _recompute_event_hash(session: Session, event: GovernanceEvent) -> None:
    payload = copy.deepcopy(event.payload)
    payload.pop("event_hash", None)
    payload["event_hash"] = sha256_json(payload)
    event.payload = payload
    event.event_hash = str(payload["event_hash"])
    head = session.get(GovernanceEventHead, ORG_A)
    assert head is not None
    head.last_event_hash = event.event_hash


def _disable_legacy_route_contracts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        governance,
        "ROUTE_CONTRACTS",
        tuple(
            contract
            for contract in governance.ROUTE_CONTRACTS
            if contract.execution_class is not governance.ExecutionClass.LEGACY_UNSIGNED_WRITE
        ),
    )


def test_native_receipt_pseudonym_is_typed_and_versioned() -> None:
    pseudonym = native_receipt_pseudonym("actor", "agent-native", tenant_id=ORG_A, privacy=PRIVACY)

    assert pseudonym.startswith(f"acgs-pseudo-v1:{ORG_A}:")
    assert len(pseudonym) == len(f"acgs-pseudo-v1:{ORG_A}:") + 64


def test_tenant_privacy_provider_is_keyed_and_tenant_bound() -> None:
    with pytest.raises(ValueError):
        TenantPrivacyProvider(b"too-short")

    same_secret_a = native_receipt_pseudonym(
        "actor", "same-secret", tenant_id=ORG_A, privacy=PRIVACY
    )
    same_secret_b = native_receipt_pseudonym(
        "actor", "same-secret", tenant_id=ORG_B, privacy=PRIVACY
    )
    assert same_secret_a != same_secret_b
    assert same_secret_a.startswith(f"acgs-pseudo-v1:{ORG_A}:")
    assert same_secret_b.startswith(f"acgs-pseudo-v1:{ORG_B}:")


def test_verifiable_native_receipt_artifact_reconstructs_and_chain_verifies(
    engine: sa.Engine,
    signer: Ed25519Signer,
    attestor: Ed25519Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    with Session(engine) as session, session.begin():
        row = _persist_one(session, signer, attestor, now=now)
        _set_cutover_ready(session, cutover_at=now - timedelta(seconds=1))
        artifact = _artifact(row)
        reconstructed = DecisionReceipt.from_dict(artifact)
        assert reconstructed.receipt_hash == row.receipt_hash
        assert reconstructed.compute_hash() == row.receipt_hash
        assert row.receipt_artifact_hash == sha256_json(artifact)

    with Session(engine) as session:
        _disable_legacy_route_contracts(monkeypatch)
        result = verify_native_evidence_chain(
            session,
            ORG_A,
            trust=_trust(signer),
            consumption_trust=_consumption_trust(attestor),
            now=now,
        )
        assert result.receipt_count == 1
        assert result.event_count == 1
        readiness = assess_native_cutover_readiness(
            session,
            ORG_A,
            trust=_trust(signer),
            consumption_trust=_consumption_trust(attestor),
            legacy_write_paths_active=False,
            now=now,
        )
        assert readiness.ready is True
        assert readiness.last_event_hash == result.last_event_hash


def test_verifiable_artifact_excludes_secret_sentinels(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    with Session(engine) as session:
        event = DatabaseGovernanceEventAppender(session, ORG_A).append(_record())
        receipt = _receipt_for_event(
            signer,
            _record(),
            audit_hash=str(event["event_hash"]),
            previous_hash=str(event["previous_hash"]),
        )
        secret_receipt = replace(receipt, request_id="secret-sentinel")
        with pytest.raises(ReceiptValidationError):
            DatabaseNativeReceiptStore(session, trust=_trust(signer)).persist_verifiable(
                secret_receipt,
                _context(audit_hash=str(event["event_hash"])),
            )
        session.rollback()

    with Session(engine) as session, session.begin():
        row = _persist_one(session, signer, attestor)
        persisted = json.dumps(row.receipt_artifact, sort_keys=True) + json.dumps(
            row.projection, sort_keys=True
        )
        assert "secret-sentinel" not in persisted
        assert row.receipt_artifact is not None
        assert row.receipt_artifact["request_id"] == REQUEST_ID
        assert row.receipt_artifact["matched_rules"] == [MATCHED_RULE]


def test_verifiable_artifact_rejects_raw_identity_sentinels(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    with Session(engine) as session:
        event = DatabaseGovernanceEventAppender(session, ORG_A).append(_record())
        receipt = _receipt_for_event(
            signer,
            _record(),
            audit_hash=str(event["event_hash"]),
            previous_hash=str(event["previous_hash"]),
        )
        raw_actor_receipt = replace(receipt, actor="sk-proj-secret-sentinel")
        with pytest.raises(ReceiptValidationError) as error:
            DatabaseNativeReceiptStore(session, trust=_trust(signer)).persist_verifiable(
                raw_actor_receipt,
                _context(audit_hash=str(event["event_hash"])),
            )
        assert "sk-proj-secret-sentinel" not in str(error.value)


def test_verifiable_artifact_rejects_bare_hash_identity(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    with Session(engine) as session:
        event = DatabaseGovernanceEventAppender(session, ORG_A).append(_record())
        receipt = _receipt_for_event(
            signer,
            _record(),
            audit_hash=str(event["event_hash"]),
            previous_hash=str(event["previous_hash"]),
        )
        bare_hash_receipt = replace(receipt, actor="a" * 64)
        with pytest.raises(ReceiptValidationError):
            DatabaseNativeReceiptStore(session, trust=_trust(signer)).persist_verifiable(
                bare_hash_receipt,
                _context(audit_hash=str(event["event_hash"])),
            )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("policy_bundle_id", "sk_live_secret_sentinel"),
        ("policy_bundle_id", "a" * 64),
        ("proposed_action", "sk_live_secret_sentinel"),
        ("execution_boundary", "sk_live_secret_sentinel"),
    ],
)
def test_verifiable_artifact_rejects_raw_or_secret_like_references(
    engine: sa.Engine,
    signer: Ed25519Signer,
    attestor: Ed25519Signer,
    field: str,
    replacement: str,
) -> None:
    with Session(engine) as session:
        event = DatabaseGovernanceEventAppender(session, ORG_A).append(_record())
        receipt = _receipt_for_event(
            signer,
            _record(),
            audit_hash=str(event["event_hash"]),
            previous_hash=str(event["previous_hash"]),
        )
        if field == "policy_bundle_id":
            unsafe = replace(receipt, policy_bundle_id=replacement)
        elif field == "proposed_action":
            unsafe = replace(receipt, proposed_action=replacement)
        elif field == "execution_boundary":
            unsafe = replace(receipt, execution_boundary=replacement)
        else:  # pragma: no cover - guarded by parametrization above.
            raise AssertionError(f"unexpected field {field!r}")
        with pytest.raises(ReceiptValidationError):
            DatabaseNativeReceiptStore(session, trust=_trust(signer)).persist_verifiable(
                unsafe,
                _context(audit_hash=str(event["event_hash"])),
            )


def test_non_ed25519_issuer_cannot_persist_verifiable_native_receipt(
    engine: sa.Engine,
) -> None:
    fake = _FakeSigner(key_id="fake-verifiable-issuer-key", algorithm="sha256")
    trust = ManagedNativeReceiptTrust(signer=fake, verifiers={fake.key_id: fake})

    with Session(engine) as session:
        with pytest.raises(ProductionProfileError, match="Ed25519 signer"):
            with session.begin():
                record = _record(event_id="fake-verifiable-issuer-event")
                event = DatabaseGovernanceEventAppender(session, ORG_A).append(record)
                receipt = _receipt_for_event(
                    fake,
                    record,
                    audit_hash=str(event["event_hash"]),
                    previous_hash=str(event["previous_hash"]),
                )
                DatabaseNativeReceiptStore(session, trust=trust).persist_verifiable(
                    receipt,
                    _context(audit_hash=str(event["event_hash"])),
                )
        session.rollback()
        assert _counts(session) == (0, 0, 0)


@pytest.mark.parametrize(
    "field",
    [
        "signature",
        "artifact_hash",
        "projection",
        "argument_hash",
        "validator_id",
        "authority",
        "previous_hash",
        "timestamp",
        "expires_at",
        "evidence_profile",
    ],
)
def test_native_evidence_verifier_rejects_tampered_artifact_bindings(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer, field: str
) -> None:
    now = datetime.now(UTC)
    with Session(engine) as session, session.begin():
        row = _persist_one(session, signer, attestor, now=now)
        if field == "signature":
            artifact = copy.deepcopy(_artifact(row))
            artifact["signature"] = "00" * 64
            row.receipt_artifact = artifact
        elif field == "artifact_hash":
            row.receipt_artifact_hash = "f" * 64
        elif field == "projection":
            projection = copy.deepcopy(row.projection)
            projection["actor"] = "different-agent"
            row.projection = projection
        elif field == "argument_hash":
            artifact = copy.deepcopy(_artifact(row))
            artifact["argument_hash"] = "e" * 64
            row.receipt_artifact = artifact
            row.receipt_artifact_hash = sha256_json(artifact)
        elif field == "validator_id":
            artifact = copy.deepcopy(_artifact(row))
            artifact["validator_id"] = "validator-2"
            row.receipt_artifact = artifact
            row.receipt_artifact_hash = sha256_json(artifact)
        elif field == "authority":
            artifact = copy.deepcopy(_artifact(row))
            artifact["authority"] = "execute:other"
            artifact["receipt_hash"] = DecisionReceipt.from_dict(artifact).compute_hash()
            row.receipt_artifact = artifact
            row.receipt_artifact_hash = sha256_json(artifact)
        elif field == "previous_hash":
            artifact = copy.deepcopy(_artifact(row))
            artifact["previous_audit_hash"] = "e" * 64
            artifact["receipt_hash"] = DecisionReceipt.from_dict(artifact).compute_hash()
            row.receipt_artifact = artifact
            row.receipt_artifact_hash = sha256_json(artifact)
        elif field == "timestamp":
            row.issued_at = row.issued_at + timedelta(seconds=1)
        elif field == "expires_at":
            row.expires_at = row.expires_at + timedelta(seconds=1)
        elif field == "evidence_profile":
            row.evidence_profile = "observed"

    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError):
            verify_native_evidence_chain(
                session,
                ORG_A,
                trust=_trust(signer),
                consumption_trust=_consumption_trust(attestor),
                now=now,
            )


@pytest.mark.parametrize(
    "case",
    [
        "missing-row",
        "allow-with-freeform-metadata",
        "extra-row",
        "duplicate-artifact",
        "missing-consumption",
        "malformed-artifact",
    ],
)
def test_native_evidence_verifier_rejects_artifact_coverage_gaps(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer, case: str
) -> None:
    now = datetime.now(UTC)
    with Session(engine) as session, session.begin():
        first = _persist_one(
            session,
            signer,
            attestor,
            event_id="native-evidence-event-1",
            now=now,
            consume=case != "missing-consumption",
        )
        if case == "missing-row":
            DatabaseGovernanceEventAppender(session, ORG_A).append(
                _record(event_id="native-evidence-event-2", issued=now)
            )
        elif case == "allow-with-freeform-metadata":
            event_payload = DatabaseGovernanceEventAppender(session, ORG_A).append(
                _record(event_id="native-evidence-event-2", issued=now)
            )
            event = session.scalar(
                sa.select(GovernanceEvent).where(
                    GovernanceEvent.event_hash == event_payload["event_hash"]
                )
            )
            assert event is not None
            payload = copy.deepcopy(event.payload)
            payload["goal"] = "optional metadata must not exempt native ALLOW coverage"
            payload["reason"] = "still executable"
            payload["transformed_args"] = {"name": "changed"}
            event.payload = payload
            _recompute_event_hash(session, event)
        elif case == "extra-row":
            event = session.scalar(sa.select(GovernanceEvent))
            assert event is not None
            event.decision = "deny"
        elif case == "duplicate-artifact":
            second = _persist_one(
                session, signer, attestor, event_id="native-evidence-event-2", now=now
            )
            second.receipt_artifact_hash = first.receipt_artifact_hash
        elif case == "malformed-artifact":
            first.receipt_artifact = {}
            first.receipt_artifact_hash = sha256_json({})

    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError):
            verify_native_evidence_chain(
                session,
                ORG_A,
                trust=_trust(signer),
                consumption_trust=_consumption_trust(attestor),
                now=now,
            )


@pytest.mark.parametrize(
    "case",
    ["artifact", "signature", "wrong-key", "issuer-key", "before-issue", "at-expiry"],
)
def test_native_evidence_verifier_rejects_consumption_attestation_tamper(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer, case: str
) -> None:
    now = datetime.now(UTC)
    with Session(engine) as session, session.begin():
        row = _persist_one(session, signer, attestor, now=now)
        consumption = session.scalar(sa.select(NativeReceiptConsumption))
        assert consumption is not None
        if case == "artifact":
            artifact = copy.deepcopy(consumption.attestation_artifact)
            assert isinstance(artifact, dict)
            artifact["actor"] = native_receipt_pseudonym(
                "actor", "other-agent", tenant_id=ORG_A, privacy=PRIVACY
            )
            consumption.attestation_artifact = artifact
        elif case == "signature":
            consumption.attestation_signature = "00" * 64
        elif case == "wrong-key":
            other = Ed25519Signer.generate(key_id="other-consumption-attestor")
            assert consumption.attestation_artifact is not None
            consumption.attestation_signature = other.sign(
                str(consumption.attestation_artifact_hash).encode()
            )
            consumption.attestation_signing_key_id = other.key_id
        elif case == "issuer-key":
            attest = copy.deepcopy(consumption.attestation_artifact)
            assert isinstance(attest, dict)
            attest["attestor_key_id"] = signer.key_id
            consumption.attestation_artifact = attest
            consumption.attestation_artifact_hash = sha256_json(attest)
            consumption.attestation_signing_key_id = signer.key_id
            consumption.attestation_signature = signer.sign(
                consumption.attestation_artifact_hash.encode()
            )
        elif case == "before-issue":
            consumed = now - timedelta(seconds=1)
            artifact = copy.deepcopy(consumption.attestation_artifact)
            assert isinstance(artifact, dict)
            artifact["consumed_at"] = consumed.isoformat()
            consumption.consumed_at = consumed
            consumption.attestation_artifact = artifact
            consumption.attestation_artifact_hash = sha256_json(artifact)
            consumption.attestation_signature = attestor.sign(
                consumption.attestation_artifact_hash.encode()
            )
        elif case == "at-expiry":
            artifact = _artifact(row)
            expires = datetime.fromisoformat(str(artifact["expires_at"]))
            attest = copy.deepcopy(consumption.attestation_artifact)
            assert isinstance(attest, dict)
            attest["consumed_at"] = expires.isoformat()
            consumption.consumed_at = expires
            consumption.attestation_artifact = attest
            consumption.attestation_artifact_hash = sha256_json(attest)
            consumption.attestation_signature = attestor.sign(
                consumption.attestation_artifact_hash.encode()
            )

    attestation_trust = (
        ManagedConsumptionAttestationTrust(signer=signer, verifiers={signer.key_id: signer})
        if case == "issuer-key"
        else _consumption_trust(attestor)
    )
    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError):
            verify_native_evidence_chain(
                session,
                ORG_A,
                trust=_trust(signer),
                consumption_trust=attestation_trust,
                now=now,
            )


def test_native_evidence_verifier_rejects_attestor_with_issuer_key_material(
    engine: sa.Engine,
) -> None:
    issuer, attestor = _same_key_material_signers()
    now = datetime.now(UTC)
    with Session(engine) as session, session.begin():
        record = _record(issued=now)
        event = DatabaseGovernanceEventAppender(session, ORG_A).append(record)
        receipt = _receipt_for_event(
            issuer,
            record,
            audit_hash=str(event["event_hash"]),
            previous_hash=str(event["previous_hash"]),
        )
        context = _context(audit_hash=str(event["event_hash"]))
        row = DatabaseNativeReceiptStore(session, trust=_trust(issuer)).persist_verifiable(
            receipt,
            context,
            now=now,
        )
        consumed_at = now + timedelta(milliseconds=1)
        artifact = {
            "schema": "acgs.native-consumption-attestation.v1",
            "org_id": context.org_id,
            "native_receipt_id": row.id,
            "receipt_id": receipt.receipt_id,
            "receipt_hash": receipt.receipt_hash,
            "audit_event_hash": receipt.audit_event_hash,
            "execution_boundary": context.execution_boundary,
            "actor": context.actor,
            "proposed_action": context.action,
            "policy_bundle_id": context.policy_bundle_id,
            "policy_hash": context.policy_hash,
            "issued_at": datetime.fromisoformat(receipt.timestamp).isoformat(),
            "expires_at": datetime.fromisoformat(receipt.expires_at).isoformat(),
            "consumed_at": consumed_at.isoformat(),
            "receipt_signing_key_id": receipt.signing_key_id,
            "receipt_signature_algorithm": receipt.signature_algorithm,
            "attestor_key_id": attestor.key_id,
            "attestor_algorithm": attestor.algorithm,
        }
        artifact_hash = sha256_json(artifact)
        session.add(
            NativeReceiptConsumption(
                org_id=context.org_id,
                native_receipt_id=row.id,
                receipt_hash=receipt.receipt_hash,
                audit_event_hash=receipt.audit_event_hash,
                consumed_at=consumed_at,
                attestation_artifact=artifact,
                attestation_artifact_hash=artifact_hash,
                attestation_signature_algorithm=attestor.algorithm,
                attestation_signing_key_id=attestor.key_id,
                attestation_signature=attestor.sign(artifact_hash.encode()),
            )
        )

    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError, match="distinct key material"):
            verify_native_evidence_chain(
                session,
                ORG_A,
                trust=_trust(issuer),
                consumption_trust=_consumption_trust(attestor),
                now=now,
            )


@pytest.mark.parametrize("case", ["fake-non-ed25519", "alias"])
def test_native_evidence_chain_rejects_unsafe_issuer_verifier_map(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer, case: str
) -> None:
    now = datetime.now(UTC)
    with Session(engine) as session, session.begin():
        _persist_one(session, signer, attestor, now=now)

    if case == "fake-non-ed25519":
        fake = _FakeSigner(key_id=signer.key_id, algorithm="sha256")
        trust = ManagedNativeReceiptTrust(signer=None, verifiers={fake.key_id: fake})
    else:
        trust = ManagedNativeReceiptTrust(
            signer=None,
            verifiers={"alias-issuer-key": signer},
        )

    with Session(engine) as session:
        with pytest.raises(ProductionProfileError, match="trust map key mismatch"):
            verify_native_evidence_chain(
                session,
                ORG_A,
                trust=trust,
                consumption_trust=_consumption_trust(attestor),
                now=now,
            )
        session.rollback()
        assert _counts(session) == (1, 1, 1)


def test_historical_native_evidence_verifies_after_recorded_expiry(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    issued = datetime.now(UTC)
    future_clock = issued + timedelta(days=1)
    with Session(engine) as session, session.begin():
        _persist_one(session, signer, attestor, now=issued)

    with Session(engine) as session:
        result = verify_native_evidence_chain(
            session,
            ORG_A,
            trust=_trust(signer),
            consumption_trust=_consumption_trust(attestor),
            now=future_clock,
        )
        assert result.receipt_count == 1


@pytest.mark.parametrize("field", ["payload", "decision", "hash", "previous", "sequence", "head"])
def test_native_evidence_verifier_rejects_tampered_governance_chain(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer, field: str
) -> None:
    now = datetime.now(UTC)
    with Session(engine) as session, session.begin():
        _persist_one(session, signer, attestor, event_id="native-evidence-event-1", now=now)
        _persist_one(session, signer, attestor, event_id="native-evidence-event-2", now=now)
        events = list(
            session.scalars(sa.select(GovernanceEvent).order_by(GovernanceEvent.sequence))
        )
        if field == "payload":
            payload = copy.deepcopy(events[1].payload)
            payload["actor"] = "different-agent"
            events[1].payload = payload
        elif field == "decision":
            payload = copy.deepcopy(events[1].payload)
            payload["decision"] = "deny"
            events[1].payload = payload
            _recompute_event_hash(session, events[1])
        elif field == "hash":
            events[1].event_hash = "f" * 64
        elif field == "previous":
            events[1].previous_hash = "e" * 64
        elif field == "sequence":
            events[1].sequence = 4
        elif field == "head":
            head = session.get(GovernanceEventHead, ORG_A)
            assert head is not None
            head.last_event_hash = "d" * 64

    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError):
            verify_native_evidence_chain(
                session,
                ORG_A,
                trust=_trust(signer),
                consumption_trust=_consumption_trust(attestor),
                now=now,
            )


def test_cutover_readiness_fails_closed_for_missing_marker_and_legacy_writes(
    engine: sa.Engine,
    signer: Ed25519Signer,
    attestor: Ed25519Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    with Session(engine) as session, session.begin():
        _persist_one(session, signer, attestor, now=now)

    with Session(engine) as session:
        _disable_legacy_route_contracts(monkeypatch)
        missing = assess_native_cutover_readiness(
            session,
            ORG_A,
            trust=_trust(signer),
            consumption_trust=_consumption_trust(attestor),
            legacy_write_paths_active=False,
            now=now,
        )
        assert missing.ready is False
        assert missing.reason == "native cutover marker is missing"

    with Session(engine) as session, session.begin():
        _set_cutover_ready(session, cutover_at=now - timedelta(seconds=1))
        session.add(
            ReceiptRow(
                id="legacy-receipt-after-boundary",
                org_id=ORG_A,
                tool=ACTION,
                decision="allow",
                actor=ACTOR,
                goal="legacy write after boundary",
                argument_hash=sha256_json(ARGS),
                audit_hash="c" * 64,
                policy_version="policy-v1",
                payload={},
                created_at=now,
            )
        )

    with Session(engine) as session:
        active = assess_native_cutover_readiness(
            session,
            ORG_A,
            trust=_trust(signer),
            consumption_trust=_consumption_trust(attestor),
            legacy_write_paths_active=True,
            now=now,
        )
        assert active.ready is False
        assert active.reason == "legacy write path remains active"
        _disable_legacy_route_contracts(monkeypatch)
        legacy_write = assess_native_cutover_readiness(
            session,
            ORG_A,
            trust=_trust(signer),
            consumption_trust=_consumption_trust(attestor),
            legacy_write_paths_active=False,
            now=now,
        )
        assert legacy_write.ready is False
        assert legacy_write.reason == "legacy receipts exist beyond cutover boundary"


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("missing-anchors", "cutover marker lacks native chain anchors"),
        ("future", "cutover marker is in the future"),
        ("count", "cutover marker native event count mismatch"),
        ("head", "cutover marker native head hash mismatch"),
    ],
)
def test_cutover_readiness_validates_marker_native_chain_anchors(
    engine: sa.Engine,
    signer: Ed25519Signer,
    attestor: Ed25519Signer,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected: str,
) -> None:
    now = datetime.now(UTC)
    with Session(engine) as session, session.begin():
        _persist_one(session, signer, attestor, now=now)
        if case == "missing-anchors":
            _set_cutover_ready(
                session,
                cutover_at=now - timedelta(seconds=1),
                native_event_count=None,
                native_event_head_hash=None,
            )
        elif case == "future":
            _set_cutover_ready(session, cutover_at=now + timedelta(seconds=30))
        elif case == "count":
            _set_cutover_ready(
                session,
                cutover_at=now - timedelta(seconds=1),
                native_event_count=99,
            )
        elif case == "head":
            _set_cutover_ready(
                session,
                cutover_at=now - timedelta(seconds=1),
                native_event_head_hash="f" * 64,
            )

    with Session(engine) as session:
        _disable_legacy_route_contracts(monkeypatch)
        readiness = assess_native_cutover_readiness(
            session,
            ORG_A,
            trust=_trust(signer),
            consumption_trust=_consumption_trust(attestor),
            legacy_write_paths_active=False,
            now=now,
        )
        assert readiness.ready is False
        assert readiness.reason == expected


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("zero-hash", "cutover marker legacy anchor hash mismatch"),
        ("count", "cutover marker legacy anchor count mismatch"),
        ("unsafe", "cutover marker legacy anchor hash is unsafe"),
        ("hash", "cutover marker legacy anchor hash mismatch"),
        ("snapshot-required", "verified legacy chain snapshot required"),
    ],
)
def test_cutover_readiness_validates_marker_legacy_anchors(
    engine: sa.Engine,
    signer: Ed25519Signer,
    attestor: Ed25519Signer,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected: str,
) -> None:
    now = datetime.now(UTC)
    cutover_at = now - timedelta(seconds=1)
    legacy_hash = "d" * 64
    with Session(engine) as session, session.begin():
        _persist_one(session, signer, attestor, now=now)
        org = session.get(Organization, ORG_A)
        assert org is not None
        if case in {"count", "unsafe", "hash"}:
            session.add(
                ReceiptRow(
                    id=f"legacy-receipt-before-boundary-{case}",
                    org_id=ORG_A,
                    tool=ACTION,
                    decision="allow",
                    actor=ACTOR,
                    goal="legacy write before boundary",
                    argument_hash=sha256_json(ARGS),
                    audit_hash=legacy_hash,
                    policy_version="policy-v1",
                    payload={},
                    created_at=now - timedelta(seconds=2),
                )
            )
        if case == "unsafe":
            org.audit_anchor_count = 1
            org.audit_anchor_hash = "not-a-safe-hash"
        elif case == "hash":
            org.audit_anchor_count = 1
            org.audit_anchor_hash = legacy_hash
        elif case == "snapshot-required":
            org.audit_anchor_count = 1
            org.audit_anchor_hash = legacy_hash
        if case == "zero-hash":
            _set_cutover_ready(
                session,
                cutover_at=cutover_at,
                legacy_audit_anchor_count=0,
                legacy_audit_anchor_hash="c" * 64,
            )
        elif case == "count":
            _set_cutover_ready(
                session,
                cutover_at=cutover_at,
                legacy_audit_anchor_count=0,
                legacy_audit_anchor_hash="",
            )
        elif case == "unsafe":
            _set_cutover_ready(
                session,
                cutover_at=cutover_at,
                legacy_audit_anchor_count=1,
                legacy_audit_anchor_hash="not-a-safe-hash",
            )
        elif case == "hash":
            _set_cutover_ready(
                session,
                cutover_at=cutover_at,
                legacy_audit_anchor_count=1,
                legacy_audit_anchor_hash="e" * 64,
            )
        elif case == "snapshot-required":
            _set_cutover_ready(
                session,
                cutover_at=cutover_at,
                legacy_audit_anchor_count=1,
                legacy_audit_anchor_hash=legacy_hash,
            )

    with Session(engine) as session:
        _disable_legacy_route_contracts(monkeypatch)
        readiness = assess_native_cutover_readiness(
            session,
            ORG_A,
            trust=_trust(signer),
            consumption_trust=_consumption_trust(attestor),
            legacy_write_paths_active=False,
            now=now,
        )
        assert readiness.ready is False
        assert readiness.reason == expected


def test_cutover_readiness_refuses_org_legacy_anchor_without_verified_snapshot(
    engine: sa.Engine,
    signer: Ed25519Signer,
    attestor: Ed25519Signer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    cutover_at = now - timedelta(seconds=1)
    legacy_hash = "d" * 64
    with Session(engine) as session, session.begin():
        _persist_one(session, signer, attestor, now=now)
        org = session.get(Organization, ORG_A)
        assert org is not None
        org.audit_anchor_count = 1
        org.audit_anchor_hash = legacy_hash
        _set_cutover_ready(
            session,
            cutover_at=cutover_at,
            legacy_audit_anchor_count=1,
            legacy_audit_anchor_hash=legacy_hash,
        )

    with Session(engine) as session:
        _disable_legacy_route_contracts(monkeypatch)
        readiness = assess_native_cutover_readiness(
            session,
            ORG_A,
            trust=_trust(signer),
            consumption_trust=_consumption_trust(attestor),
            legacy_write_paths_active=False,
            now=now,
        )
        assert readiness.ready is False
        assert readiness.reason == "verified legacy chain snapshot required"


def test_cutover_readiness_refuses_default_legacy_route_registry(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    now = datetime.now(UTC)
    with Session(engine) as session, session.begin():
        _persist_one(session, signer, attestor, now=now)
        _set_cutover_ready(session, cutover_at=now - timedelta(seconds=1))

    with Session(engine) as session:
        readiness = assess_native_cutover_readiness(
            session,
            ORG_A,
            trust=_trust(signer),
            consumption_trust=_consumption_trust(attestor),
            legacy_write_paths_active=False,
            now=now,
        )
        assert readiness.ready is False
        assert readiness.reason == "legacy write path remains active"


def test_cross_tenant_native_evidence_is_rejected(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    now = datetime.now(UTC)
    with Session(engine) as session, session.begin():
        row = _persist_one(session, signer, attestor, now=now)
        artifact = copy.deepcopy(_artifact(row))
        artifact["tenant_id"] = ORG_B
        artifact["receipt_hash"] = DecisionReceipt.from_dict(artifact).compute_hash()
        row.receipt_artifact = artifact
        row.receipt_artifact_hash = sha256_json(artifact)

    with Session(engine) as session:
        with pytest.raises(ReceiptValidationError):
            verify_native_evidence_chain(
                session,
                ORG_A,
                trust=_trust(signer),
                consumption_trust=_consumption_trust(attestor),
                now=now,
            )


def test_transaction_rollback_removes_artifact_and_chain(
    engine: sa.Engine, signer: Ed25519Signer, attestor: Ed25519Signer
) -> None:
    now = datetime.now(UTC)
    with pytest.raises(RuntimeError, match="injected failure"):
        with Session(engine) as session, session.begin():
            _persist_one(session, signer, attestor, now=now)
            raise RuntimeError("injected failure")

    with Session(engine) as session:
        assert session.scalar(sa.select(sa.func.count()).select_from(NativeDecisionReceiptRow)) == 0
        assert session.scalar(sa.select(sa.func.count()).select_from(GovernanceEvent)) == 0
