from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")

from gove_zone import (  # noqa: E402
    DECISION_RECEIPT_PURPOSE,
    RECEIPT_V2,
    Decision,
    DecisionReceipt,
    DecisionRecord,
    Ed25519Signer,
    GovernedExecutor,
    ReceiptAlreadyUsedError,
    ReceiptConsumptionLedger,
    ReceiptRejectionReason,
    ReceiptValidationError,
    ReceiptVerifier,
    StaticReceiptTrustRegistry,
    TrustConfigurationError,
    TrustedReceiptKey,
    Validator,
    execute_with_receipt,
    sha256_json,
)
from gove_zone.receipt import (  # noqa: E402
    DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS,
    MAX_RECEIPT_CLOCK_SKEW_SECONDS,
)
from gove_zone.trust import ReceiptTrustScope  # noqa: E402

TENANT = "tenant-a"
PROJECT = "project-main"
ENV = "prod"
BOUNDARY = "runtime/prod"
ACTION = "runtime.file.write"
ARGS: dict[str, Any] = {"path": "/safe.txt", "body": "ok"}
ACTOR = "agent-1"
VALIDATOR = "council-1"
FUTURE = "2099-01-01T00:00:00+00:00"
NOW = "2026-01-01T00:00:00+00:00"
PAST = "2025-01-01T00:00:00+00:00"
V1_GOLDEN_PRIVATE_BYTES = bytes(range(1, 33))
V1_GOLDEN_HASH = "aae660ec33f45749617d3ad61a3dafc01e23f91321b05c6d89fc3375ccb2e7d3"
V1_GOLDEN_SIGNATURE = (
    "133448bd4fcbbbbd41d9c5965d2749f7c3f1de3e2a6ec5aac370419c13255b3d"
    "1b20859df99248ec98439d588a5fa0c92bed69836b0d19a18b11f0ca87b6f908"
)


class _SideEffect:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def run(self, **kwargs: Any) -> str:
        self.calls.append(dict(kwargs))
        return "ran"


def _record(
    *,
    args: dict[str, Any] | None = None,
    event_id: str = "event-1",
    decision: Decision = Decision.ALLOW,
    timestamp_iso: str = NOW,
) -> DecisionRecord:
    return DecisionRecord(
        decision=decision,
        tool=ACTION,
        argument_hash=sha256_json(args or ARGS),
        policy_version="policy-v1",
        event_id=event_id,
        actor=ACTOR,
        timestamp_iso=timestamp_iso,
    )


def _v1_receipt(*, signer: Ed25519Signer | None = None) -> DecisionReceipt:
    return DecisionReceipt.from_record(
        record=_record(),
        audit_hash="audit-1",
        previous_audit_hash="prev-1",
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="bundle-1",
        policy_hash="policy-hash-1",
        request_id="req-1",
        validator=Validator(VALIDATOR),
        authority="grant-write",
        signer=signer,
    )


def _v2_receipt(
    signer: Ed25519Signer,
    *,
    trust_epoch: int = 1,
    event_id: str = "event-1",
    project_id: str = PROJECT,
    environment_id: str = ENV,
    expires_at: str = FUTURE,
    decision: Decision = Decision.ALLOW,
    timestamp_iso: str = NOW,
) -> DecisionReceipt:
    return DecisionReceipt.from_record_v2(
        record=_record(event_id=event_id, decision=decision, timestamp_iso=timestamp_iso),
        audit_hash=f"audit-{event_id}",
        previous_audit_hash=f"prev-{event_id}",
        tenant_id=TENANT,
        project_id=project_id,
        environment_id=environment_id,
        trust_epoch=trust_epoch,
        execution_boundary=BOUNDARY,
        policy_bundle_id="bundle-1",
        policy_hash="policy-hash-1",
        request_id=f"req-{event_id}",
        validator=Validator(VALIDATOR),
        authority="grant-write",
        signer=signer,
        expires_at=expires_at,
    )


def _registry(
    signer: Ed25519Signer,
    *,
    scope: ReceiptTrustScope | None = None,
    status: str = "active",
    activated_epoch: int = 1,
    not_after: str = FUTURE,
    retired_epoch: int | None = None,
    key_id: str | None = None,
    algorithm: str | None = None,
) -> StaticReceiptTrustRegistry:
    return StaticReceiptTrustRegistry(
        [
            TrustedReceiptKey(
                scope=scope or ReceiptTrustScope(TENANT, PROJECT, ENV, DECISION_RECEIPT_PURPOSE),
                key_id=key_id or signer.key_id,
                algorithm=algorithm or signer.algorithm,
                public_key_spki_der=_public_spki_der(signer),
                activated_epoch=activated_epoch,
                not_after=not_after,
                retired_epoch=retired_epoch,
                status=status,  # type: ignore[arg-type]
            )
        ]
    )


def _run(
    receipt: DecisionReceipt,
    registry: StaticReceiptTrustRegistry | None,
    side_effect: _SideEffect,
    *,
    expected_project_id: str | None = PROJECT,
    expected_environment_id: str | None = ENV,
    ledger: ReceiptConsumptionLedger | None = None,
) -> str:
    return execute_with_receipt(
        tool_fn=side_effect.run,
        args=ARGS,
        receipt=receipt,
        expected_tenant_id=TENANT,
        expected_project_id=expected_project_id,
        expected_environment_id=expected_environment_id,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor=ACTOR,
        require_signature=True,
        trust_registry=registry,
        consumption_ledger=ledger,
    )


def _assert_no_consumption(ledger: ReceiptConsumptionLedger | None) -> None:
    if ledger is None:
        return
    assert not ledger.path.exists() or ledger.path.read_text(encoding="utf-8") == ""


def _assert_rejects_without_side_effect(
    fn: Any,
    side_effect: _SideEffect,
    *,
    ledger: ReceiptConsumptionLedger | None = None,
    reason: ReceiptRejectionReason | None = None,
) -> None:
    before = list(side_effect.calls)
    with pytest.raises(ReceiptValidationError) as exc_info:
        fn()
    if reason is not None:
        assert exc_info.value.reason_code == reason
    assert side_effect.calls == before
    _assert_no_consumption(ledger)


def _ledger(tmp_path, label: str) -> ReceiptConsumptionLedger:
    return ReceiptConsumptionLedger(tmp_path / f"{label}.jsonl")


def _public_spki_der(signer: Ed25519Signer) -> bytes:
    return Ed25519Signer.from_public_bytes(signer.public_bytes())._public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _resign(receipt: DecisionReceipt, signer: Ed25519Signer) -> DecisionReceipt:
    updated = dataclasses.replace(receipt, receipt_hash="")
    receipt_hash = updated.compute_hash()
    return dataclasses.replace(
        updated,
        receipt_hash=receipt_hash,
        signature=signer.sign(receipt_hash.encode("utf-8")),
    )


def _iso_after(seconds: int) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()


def test_v1_receipt_wire_and_hash_are_byte_compatible() -> None:
    signer = Ed25519Signer.generate(key_id="v1-key")
    receipt = _v1_receipt(signer=signer)
    before_dict = receipt.to_dict()
    before_hash = receipt.compute_hash()
    assert "receipt_schema_version" not in before_dict
    assert "project_id" not in before_dict
    assert "environment_id" not in before_dict
    assert "trust_epoch" not in before_dict

    round_trip = DecisionReceipt.from_json(receipt.to_json())
    assert round_trip.to_dict() == before_dict
    assert round_trip.compute_hash() == before_hash
    assert round_trip.receipt_hash == receipt.receipt_hash


def test_v1_receipt_has_frozen_golden_hash_and_signature_vector() -> None:
    signer = Ed25519Signer.from_private_bytes(V1_GOLDEN_PRIVATE_BYTES, key_id="golden-v1-key")
    receipt = DecisionReceipt(
        receipt_id="golden-event-1",
        request_id="request-golden-1",
        tenant_id=TENANT,
        actor=ACTOR,
        proposed_action=ACTION,
        declared_goal="golden v1 compatibility",
        execution_boundary=BOUNDARY,
        policy_bundle_id="bundle-1",
        policy_version="policy-v1",
        policy_hash="p" * 64,
        decision=Decision.ALLOW.value,
        matched_rules=["rule-a"],
        constraints={"max_bytes": 128},
        transformations=[],
        approval_chain_summary={
            "validator_id": "validator-1",
            "validator_role": "policy-validator",
            "proposer": ACTOR,
            "authority": "grant-write",
        },
        timestamp="2026-01-02T03:04:05+00:00",
        previous_audit_hash="0" * 64,
        audit_event_hash="a" * 64,
        subject="subject-1",
        expires_at=FUTURE,
        authority="grant-write",
        validator_id="validator-1",
        validator_role="policy-validator",
        argument_hash=sha256_json({"body": "ok", "path": "/safe.txt"}),
        signature_algorithm=signer.algorithm,
        signing_key_id=signer.key_id,
    )
    receipt_hash = receipt.compute_hash()
    signed = dataclasses.replace(
        receipt,
        receipt_hash=receipt_hash,
        signature=signer.sign(receipt_hash.encode("utf-8")),
    )

    assert "receipt_schema_version" not in signed.to_dict()
    assert signed.receipt_hash == V1_GOLDEN_HASH
    assert signed.signature == V1_GOLDEN_SIGNATURE
    assert signed.to_json() == (
        '{"actor": "agent-1", "approval_chain_summary": {"authority": "grant-write", '
        '"proposer": "agent-1", "validator_id": "validator-1", '
        '"validator_role": "policy-validator"}, "argument_hash": '
        '"5aaec0602f637e9ccda6d259456f6b43f713cdc3fb4f8bc1d171233fb54b2e82", '
        '"audit_event_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", '
        '"authority": "grant-write", "constraints": {"max_bytes": 128}, '
        '"decision": "allow", "declared_goal": "golden v1 compatibility", '
        '"execution_boundary": "runtime/prod", "expires_at": '
        '"2099-01-01T00:00:00+00:00", "matched_rules": ["rule-a"], '
        '"policy_bundle_id": "bundle-1", "policy_hash": '
        '"pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp", '
        '"policy_version": "policy-v1", "previous_audit_hash": '
        '"0000000000000000000000000000000000000000000000000000000000000000", '
        '"proposed_action": "runtime.file.write", "receipt_hash": '
        f'"{V1_GOLDEN_HASH}", "receipt_id": "golden-event-1", '
        '"request_id": "request-golden-1", "signature": '
        f'"{V1_GOLDEN_SIGNATURE}", "signature_algorithm": "ed25519", '
        '"signing_key_id": "golden-v1-key", "subject": "subject-1", '
        '"tenant_id": "tenant-a", "timestamp": "2026-01-02T03:04:05+00:00", '
        '"transformations": [], "validator_id": "validator-1", '
        '"validator_role": "policy-validator"}'
    )


def test_mixed_unknown_and_partial_schema_reject_closed() -> None:
    v1 = _v1_receipt()
    for field, value in (
        ("project_id", PROJECT),
        ("environment_id", ENV),
        ("trust_epoch", 1),
    ):
        payload = v1.to_dict()
        payload[field] = value
        with pytest.raises(ReceiptValidationError):
            DecisionReceipt.from_dict(payload)

    payload = v1.to_dict()
    payload["receipt_schema_version"] = "unknown"
    with pytest.raises(ReceiptValidationError):
        DecisionReceipt.from_dict(payload)

    payload = v1.to_dict()
    payload["receipt_schema_version"] = RECEIPT_V2
    payload["project_id"] = PROJECT
    payload["environment_id"] = ENV
    with pytest.raises(ReceiptValidationError):
        DecisionReceipt.from_dict(payload)

    signed_v2 = _v2_receipt(Ed25519Signer.generate(key_id="schema-key")).to_dict()
    for malformed_epoch in ("1", True, 1.0):
        payload = dict(signed_v2)
        payload["trust_epoch"] = malformed_epoch
        with pytest.raises(ReceiptValidationError):
            DecisionReceipt.from_dict(payload)

    for malformed_epoch in (True, 1.0):  # type: ignore[arg-type]
        with pytest.raises(ReceiptValidationError):
            _v2_receipt(
                Ed25519Signer.generate(key_id=f"mint-bad-{malformed_epoch!r}"),
                trust_epoch=malformed_epoch,  # type: ignore[arg-type]
                event_id=f"mint-bad-{malformed_epoch!r}",
            )

    with pytest.raises(ReceiptValidationError):
        _v2_receipt(Ed25519Signer.generate(key_id="missing-expiry"), expires_at="")


def test_receipt_v2_scoped_trust_verification_requires_scope_binding(tmp_path) -> None:
    signer = Ed25519Signer.generate(key_id="scoped-key")
    receipt = _v2_receipt(signer)
    registry = _registry(signer)
    side_effect = _SideEffect()

    verifier = ReceiptVerifier(
        expected_tenant_id=TENANT,
        expected_project_id=PROJECT,
        expected_environment_id=ENV,
        expected_execution_boundary=BOUNDARY,
        expected_actor=ACTOR,
        trust_registry=registry,
    )
    verifier.verify(receipt, expected_action=ACTION, expected_args=ARGS, now_iso=NOW)

    ledger = _ledger(tmp_path, "missing-registry")
    _assert_rejects_without_side_effect(
        lambda: _run(receipt, None, side_effect, ledger=ledger),
        side_effect,
        ledger=ledger,
        reason=ReceiptRejectionReason.SCOPED_TRUST_REQUIRED,
    )
    ledger = _ledger(tmp_path, "missing-project")
    _assert_rejects_without_side_effect(
        lambda: _run(receipt, registry, side_effect, expected_project_id=None, ledger=ledger),
        side_effect,
        ledger=ledger,
        reason=ReceiptRejectionReason.SCOPED_TRUST_REQUIRED,
    )
    ledger = _ledger(tmp_path, "wrong-project")
    _assert_rejects_without_side_effect(
        lambda: _run(
            receipt,
            registry,
            side_effect,
            expected_project_id="other-project",
            ledger=ledger,
        ),
        side_effect,
        ledger=ledger,
        reason=ReceiptRejectionReason.SCOPED_TRUST_MISMATCH,
    )
    ledger = _ledger(tmp_path, "wrong-env")
    _assert_rejects_without_side_effect(
        lambda: _run(
            receipt,
            registry,
            side_effect,
            expected_environment_id="staging",
            ledger=ledger,
        ),
        side_effect,
        ledger=ledger,
        reason=ReceiptRejectionReason.SCOPED_TRUST_MISMATCH,
    )

    assert _run(receipt, registry, side_effect) == "ran"
    assert side_effect.calls == [ARGS]


def test_receipt_v2_trust_purpose_defaults_and_custom_scope_passthrough(tmp_path) -> None:
    signer = Ed25519Signer.generate(key_id="purpose-key")
    receipt = _v2_receipt(signer, event_id="purpose-ok")
    default_registry = _registry(signer)
    customer_registry = _registry(
        signer,
        scope=ReceiptTrustScope(TENANT, PROJECT, ENV, "customer-runtime"),
    )

    default_side_effect = _SideEffect()
    assert _run(receipt, default_registry, default_side_effect) == "ran"
    assert default_side_effect.calls == [ARGS]

    wrong_purpose_side_effect = _SideEffect()
    wrong_purpose_ledger = _ledger(tmp_path, "wrong-purpose-default")
    _assert_rejects_without_side_effect(
        lambda: execute_with_receipt(
            tool_fn=wrong_purpose_side_effect.run,
            args=ARGS,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_project_id=PROJECT,
            expected_environment_id=ENV,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            require_signature=True,
            trust_registry=customer_registry,
            consumption_ledger=wrong_purpose_ledger,
        ),
        wrong_purpose_side_effect,
        ledger=wrong_purpose_ledger,
        reason=ReceiptRejectionReason.SCOPED_TRUST_MISMATCH,
    )

    custom_side_effect = _SideEffect()
    assert (
        execute_with_receipt(
            tool_fn=custom_side_effect.run,
            args=ARGS,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_project_id=PROJECT,
            expected_environment_id=ENV,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            require_signature=True,
            trust_registry=customer_registry,
            trust_purpose="customer-runtime",
        )
        == "ran"
    )
    assert custom_side_effect.calls == [ARGS]

    empty_purpose_side_effect = _SideEffect()
    _assert_rejects_without_side_effect(
        lambda: execute_with_receipt(
            tool_fn=empty_purpose_side_effect.run,
            args=ARGS,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_project_id=PROJECT,
            expected_environment_id=ENV,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            require_signature=True,
            trust_registry=default_registry,
            trust_purpose=" ",
        ),
        empty_purpose_side_effect,
        reason=ReceiptRejectionReason.SCOPED_TRUST_REQUIRED,
    )


def test_receipt_v2_trust_purpose_threads_through_wrappers() -> None:
    signer = Ed25519Signer.generate(key_id="purpose-wrapper-key")
    receipt = _v2_receipt(signer, event_id="purpose-wrapper")
    registry = _registry(
        signer,
        scope=ReceiptTrustScope(TENANT, PROJECT, ENV, "platform-bootstrap"),
    )

    default_verifier = ReceiptVerifier(
        expected_tenant_id=TENANT,
        expected_project_id=PROJECT,
        expected_environment_id=ENV,
        expected_execution_boundary=BOUNDARY,
        expected_actor=ACTOR,
        trust_registry=registry,
    )
    assert not default_verifier.is_valid(receipt, expected_action=ACTION, expected_args=ARGS)

    purpose_verifier = ReceiptVerifier(
        expected_tenant_id=TENANT,
        expected_project_id=PROJECT,
        expected_environment_id=ENV,
        expected_execution_boundary=BOUNDARY,
        expected_actor=ACTOR,
        trust_registry=registry,
        trust_purpose="platform-bootstrap",
    )
    purpose_verifier.verify(receipt, expected_action=ACTION, expected_args=ARGS, now_iso=NOW)
    assert purpose_verifier.is_valid(receipt, expected_action=ACTION, expected_args=ARGS)

    side_effect = _SideEffect()
    executor = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=ACTOR,
        expected_project_id=PROJECT,
        expected_environment_id=ENV,
        trust_registry=registry,
        trust_purpose="platform-bootstrap",
    )
    executor.register(ACTION, side_effect.run)
    assert executor.execute(ACTION, ARGS, receipt) == "ran"
    assert side_effect.calls == [ARGS]


def test_future_issued_receipt_within_default_skew_verifies_through_wrapper() -> None:
    signer = Ed25519Signer.generate(key_id="future-within-skew-key")
    receipt = _v2_receipt(
        signer,
        event_id="future-within-skew",
        timestamp_iso="2026-01-01T00:04:59+00:00",
        expires_at="2026-01-01T01:00:00+00:00",
    )
    verifier = ReceiptVerifier(
        expected_tenant_id=TENANT,
        expected_project_id=PROJECT,
        expected_environment_id=ENV,
        expected_execution_boundary=BOUNDARY,
        expected_actor=ACTOR,
        trust_registry=_registry(signer),
    )

    verifier.verify(receipt, expected_action=ACTION, expected_args=ARGS, now_iso=NOW)
    assert verifier.is_valid(receipt, expected_action=ACTION, expected_args=ARGS, now_iso=NOW)


def test_future_issued_receipt_beyond_default_skew_rejects_before_side_effect(
    tmp_path,
) -> None:
    signer = Ed25519Signer.generate(key_id="future-beyond-skew-key")
    issued_too_late = _iso_after(DEFAULT_RECEIPT_CLOCK_SKEW_SECONDS + 60)
    receipt = _v2_receipt(
        signer,
        event_id="future-beyond-skew",
        timestamp_iso=issued_too_late,
        expires_at=FUTURE,
    )
    registry = _registry(signer)
    side_effect = _SideEffect()
    ledger = _ledger(tmp_path, "future-beyond-skew")

    _assert_rejects_without_side_effect(
        lambda: execute_with_receipt(
            tool_fn=side_effect.run,
            args=ARGS,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_project_id=PROJECT,
            expected_environment_id=ENV,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            require_signature=True,
            trust_registry=registry,
            consumption_ledger=ledger,
        ),
        side_effect,
        ledger=ledger,
        reason=ReceiptRejectionReason.RECEIPT_EXPIRED,
    )


def test_clock_skew_override_can_tighten_but_not_weaken_verification(tmp_path) -> None:
    signer = Ed25519Signer.generate(key_id="bounded-skew-key")
    receipt = _v2_receipt(
        signer,
        event_id="bounded-skew",
        timestamp_iso="2026-01-01T00:05:00+00:00",
        expires_at="2026-01-01T01:00:00+00:00",
    )
    registry = _registry(signer)
    max_skew = MAX_RECEIPT_CLOCK_SKEW_SECONDS
    too_large_skew = max_skew + 1

    receipt.verify(
        expected_tenant_id=TENANT,
        expected_project_id=PROJECT,
        expected_environment_id=ENV,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor=ACTOR,
        expected_args=ARGS,
        trust_registry=registry,
        require_signature=True,
        now_iso=NOW,
        max_clock_skew_seconds=max_skew,
    )
    with pytest.raises(ReceiptValidationError) as direct_exc:
        receipt.verify(
            expected_tenant_id=TENANT,
            expected_project_id=PROJECT,
            expected_environment_id=ENV,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            expected_args=ARGS,
            trust_registry=registry,
            require_signature=True,
            now_iso=NOW,
            max_clock_skew_seconds=too_large_skew,
        )
    assert direct_exc.value.reason_code == ReceiptRejectionReason.EXPIRY_UNPARSEABLE
    for invalid_skew in (True, 1.5, -1):
        with pytest.raises(ReceiptValidationError) as invalid_exc:
            receipt.verify(
                expected_tenant_id=TENANT,
                expected_project_id=PROJECT,
                expected_environment_id=ENV,
                expected_execution_boundary=BOUNDARY,
                expected_action=ACTION,
                expected_actor=ACTOR,
                expected_args=ARGS,
                trust_registry=registry,
                require_signature=True,
                now_iso=NOW,
                max_clock_skew_seconds=invalid_skew,  # type: ignore[arg-type]
            )
        assert invalid_exc.value.reason_code == ReceiptRejectionReason.EXPIRY_UNPARSEABLE

    execute_side_effect = _SideEffect()
    assert (
        execute_with_receipt(
            tool_fn=execute_side_effect.run,
            args=ARGS,
            receipt=_v2_receipt(signer, event_id="bounded-skew-execute"),
            expected_tenant_id=TENANT,
            expected_project_id=PROJECT,
            expected_environment_id=ENV,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            require_signature=True,
            trust_registry=registry,
            max_clock_skew_seconds=max_skew,
        )
        == "ran"
    )
    assert execute_side_effect.calls == [ARGS]

    execute_reject_side_effect = _SideEffect()
    execute_reject_ledger = _ledger(tmp_path, "bounded-skew-execute-reject")
    _assert_rejects_without_side_effect(
        lambda: execute_with_receipt(
            tool_fn=execute_reject_side_effect.run,
            args=ARGS,
            receipt=_v2_receipt(signer, event_id="bounded-skew-execute-reject"),
            expected_tenant_id=TENANT,
            expected_project_id=PROJECT,
            expected_environment_id=ENV,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            require_signature=True,
            trust_registry=registry,
            max_clock_skew_seconds=too_large_skew,
            consumption_ledger=execute_reject_ledger,
        ),
        execute_reject_side_effect,
        ledger=execute_reject_ledger,
        reason=ReceiptRejectionReason.EXPIRY_UNPARSEABLE,
    )

    constructor_executor = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=ACTOR,
        expected_project_id=PROJECT,
        expected_environment_id=ENV,
        trust_registry=registry,
        max_clock_skew_seconds=max_skew,
    )
    constructor_executor_side_effect = _SideEffect()
    constructor_executor.register(ACTION, constructor_executor_side_effect.run)
    assert (
        constructor_executor.execute(
            ACTION,
            ARGS,
            _v2_receipt(signer, event_id="bounded-skew-executor-constructor-ok"),
        )
        == "ran"
    )
    assert constructor_executor_side_effect.calls == [ARGS]
    with pytest.raises(ReceiptValidationError) as executor_constructor_exc:
        GovernedExecutor(
            tenant_id=TENANT,
            execution_boundary=BOUNDARY,
            expected_actor=ACTOR,
            expected_project_id=PROJECT,
            expected_environment_id=ENV,
            trust_registry=registry,
            max_clock_skew_seconds=too_large_skew,
        )
    assert executor_constructor_exc.value.reason_code == ReceiptRejectionReason.EXPIRY_UNPARSEABLE

    per_call_executor = GovernedExecutor(
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        expected_actor=ACTOR,
        expected_project_id=PROJECT,
        expected_environment_id=ENV,
        trust_registry=registry,
    )
    per_call_executor_side_effect = _SideEffect()
    per_call_executor.register(ACTION, per_call_executor_side_effect.run)
    assert (
        per_call_executor.execute(
            ACTION,
            ARGS,
            _v2_receipt(signer, event_id="bounded-skew-executor-call-ok"),
            max_clock_skew_seconds=max_skew,
        )
        == "ran"
    )
    per_call_reject_ledger = _ledger(tmp_path, "bounded-skew-executor-call-reject")
    with pytest.raises(ReceiptValidationError) as executor_call_exc:
        per_call_executor.execute(
            ACTION,
            ARGS,
            _v2_receipt(signer, event_id="bounded-skew-executor-call-reject"),
            max_clock_skew_seconds=too_large_skew,
            consumption_ledger=per_call_reject_ledger,
        )
    assert executor_call_exc.value.reason_code == ReceiptRejectionReason.EXPIRY_UNPARSEABLE
    assert per_call_executor_side_effect.calls == [ARGS]
    _assert_no_consumption(per_call_reject_ledger)

    constructor_verifier = ReceiptVerifier(
        expected_tenant_id=TENANT,
        expected_project_id=PROJECT,
        expected_environment_id=ENV,
        expected_execution_boundary=BOUNDARY,
        expected_actor=ACTOR,
        trust_registry=registry,
        max_clock_skew_seconds=max_skew,
    )
    constructor_verifier.verify(
        _v2_receipt(signer, event_id="bounded-skew-verifier-constructor-ok"),
        expected_action=ACTION,
        expected_args=ARGS,
        now_iso=NOW,
    )
    with pytest.raises(ReceiptValidationError) as verifier_constructor_exc:
        ReceiptVerifier(
            expected_tenant_id=TENANT,
            expected_project_id=PROJECT,
            expected_environment_id=ENV,
            expected_execution_boundary=BOUNDARY,
            expected_actor=ACTOR,
            trust_registry=registry,
            max_clock_skew_seconds=too_large_skew,
        )
    assert verifier_constructor_exc.value.reason_code == ReceiptRejectionReason.EXPIRY_UNPARSEABLE

    per_call_verifier = ReceiptVerifier(
        expected_tenant_id=TENANT,
        expected_project_id=PROJECT,
        expected_environment_id=ENV,
        expected_execution_boundary=BOUNDARY,
        expected_actor=ACTOR,
        trust_registry=registry,
    )
    per_call_verifier.verify(
        _v2_receipt(signer, event_id="bounded-skew-verifier-call-ok"),
        expected_action=ACTION,
        expected_args=ARGS,
        now_iso=NOW,
        max_clock_skew_seconds=max_skew,
    )
    with pytest.raises(ReceiptValidationError) as verifier_call_exc:
        per_call_verifier.verify(
            _v2_receipt(signer, event_id="bounded-skew-verifier-call-reject"),
            expected_action=ACTION,
            expected_args=ARGS,
            now_iso=NOW,
            max_clock_skew_seconds=too_large_skew,
        )
    assert verifier_call_exc.value.reason_code == ReceiptRejectionReason.EXPIRY_UNPARSEABLE


def test_receipt_expires_before_issued_rejects_as_liveness_failure() -> None:
    signer = Ed25519Signer.generate(key_id="invalid-lifespan-key")
    receipt = _v2_receipt(
        signer,
        event_id="invalid-lifespan",
        timestamp_iso="2026-01-01T00:10:00+00:00",
        expires_at="2026-01-01T00:09:59+00:00",
    )
    verifier = ReceiptVerifier(
        expected_tenant_id=TENANT,
        expected_project_id=PROJECT,
        expected_environment_id=ENV,
        expected_execution_boundary=BOUNDARY,
        expected_actor=ACTOR,
        trust_registry=_registry(signer),
    )

    with pytest.raises(ReceiptValidationError) as exc_info:
        verifier.verify(receipt, expected_action=ACTION, expected_args=ARGS, now_iso=NOW)
    assert exc_info.value.reason_code == ReceiptRejectionReason.RECEIPT_EXPIRED


@pytest.mark.parametrize(
    ("decision", "wrong_expected_action", "expected_reason"),
    (
        (Decision.DENY, "runtime.file.delete", ReceiptRejectionReason.ACTION_MISMATCH),
        (Decision.ESCALATE, "runtime.file.delete", ReceiptRejectionReason.ACTION_MISMATCH),
    ),
)
def test_signed_non_allow_receipts_report_late_binding_before_decision_reason(
    tmp_path,
    decision: Decision,
    wrong_expected_action: str,
    expected_reason: ReceiptRejectionReason,
) -> None:
    signer = Ed25519Signer.generate(key_id=f"{decision.value}-late-binding-key")
    receipt = _v2_receipt(signer, event_id=f"{decision.value}-late-binding", decision=decision)
    registry = _registry(signer)
    side_effect = _SideEffect()
    ledger = _ledger(tmp_path, f"{decision.value}-late-binding")

    _assert_rejects_without_side_effect(
        lambda: execute_with_receipt(
            tool_fn=side_effect.run,
            args=ARGS,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_project_id=PROJECT,
            expected_environment_id=ENV,
            expected_execution_boundary=BOUNDARY,
            expected_action=wrong_expected_action,
            expected_actor=ACTOR,
            require_signature=True,
            trust_registry=registry,
            consumption_ledger=ledger,
        ),
        side_effect,
        ledger=ledger,
        reason=expected_reason,
    )


@pytest.mark.parametrize("decision", (Decision.DENY, Decision.ESCALATE))
def test_signed_non_allow_receipts_report_wrong_args_before_decision_reason(
    tmp_path,
    decision: Decision,
) -> None:
    signer = Ed25519Signer.generate(key_id=f"{decision.value}-wrong-args-key")
    receipt = _v2_receipt(signer, event_id=f"{decision.value}-wrong-args", decision=decision)
    registry = _registry(signer)
    side_effect = _SideEffect()
    ledger = _ledger(tmp_path, f"{decision.value}-wrong-args")

    _assert_rejects_without_side_effect(
        lambda: execute_with_receipt(
            tool_fn=side_effect.run,
            args={"path": "/safe.txt", "body": "tampered"},
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_project_id=PROJECT,
            expected_environment_id=ENV,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            require_signature=True,
            trust_registry=registry,
            consumption_ledger=ledger,
        ),
        side_effect,
        ledger=ledger,
        reason=ReceiptRejectionReason.ARGUMENT_MISMATCH,
    )


@pytest.mark.parametrize(
    ("decision", "expected_reason"),
    (
        (Decision.DENY, ReceiptRejectionReason.DENIED_RECEIPT),
        (Decision.ESCALATE, ReceiptRejectionReason.ESCALATED_RECEIPT),
    ),
)
def test_fully_bound_signed_non_allow_receipts_reject_before_side_effect(
    tmp_path,
    decision: Decision,
    expected_reason: ReceiptRejectionReason,
) -> None:
    signer = Ed25519Signer.generate(key_id=f"{decision.value}-bound-key")
    receipt = _v2_receipt(signer, event_id=f"{decision.value}-bound", decision=decision)
    registry = _registry(signer)
    side_effect = _SideEffect()
    ledger = _ledger(tmp_path, f"{decision.value}-bound")

    _assert_rejects_without_side_effect(
        lambda: execute_with_receipt(
            tool_fn=side_effect.run,
            args=ARGS,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_project_id=PROJECT,
            expected_environment_id=ENV,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            expected_audit_hash=receipt.audit_event_hash,
            expected_policy_hash=receipt.policy_hash,
            expected_policy_bundle_id=receipt.policy_bundle_id,
            expected_validator_role=receipt.validator_role,
            expected_authority=receipt.authority,
            require_signature=True,
            trust_registry=registry,
            consumption_ledger=ledger,
        ),
        side_effect,
        ledger=ledger,
        reason=expected_reason,
    )


def test_receipt_v2_unsigned_receipt_rejects_even_when_signature_not_required() -> None:
    signer = Ed25519Signer.generate(key_id="unsigned-v2-key")
    receipt = _v2_receipt(signer)
    unsigned = dataclasses.replace(
        receipt,
        signature_algorithm="none",
        signing_key_id="",
        signature="unsigned_local",
    )
    unsigned = dataclasses.replace(unsigned, receipt_hash=unsigned.compute_hash())
    registry = _registry(signer)
    side_effect = _SideEffect()

    _assert_rejects_without_side_effect(
        lambda: execute_with_receipt(
            tool_fn=side_effect.run,
            args=ARGS,
            receipt=unsigned,
            expected_tenant_id=TENANT,
            expected_project_id=PROJECT,
            expected_environment_id=ENV,
            expected_execution_boundary=BOUNDARY,
            expected_action=ACTION,
            expected_actor=ACTOR,
            require_signature=False,
            trust_registry=registry,
        ),
        side_effect,
    )


def test_active_retired_revoked_runtime_rotation_verifies_historical_retired_and_denies_revoked(
    tmp_path,
) -> None:
    active_signer = Ed25519Signer.generate(key_id="active-key")
    retired_signer = Ed25519Signer.generate(key_id="retired-key")
    revoked_signer = Ed25519Signer.generate(key_id="revoked-key")
    active_registry = _registry(active_signer, status="active", activated_epoch=1)
    retired_registry = _registry(
        retired_signer,
        status="retired",
        activated_epoch=1,
        retired_epoch=3,
    )
    revoked_registry = _registry(revoked_signer, status="revoked", activated_epoch=1)

    retired_receipt = _v2_receipt(retired_signer, trust_epoch=2, event_id="retired-historical")
    retired_receipt.verify(
        expected_tenant_id=TENANT,
        expected_project_id=PROJECT,
        expected_environment_id=ENV,
        expected_execution_boundary=BOUNDARY,
        expected_action=ACTION,
        expected_actor=ACTOR,
        expected_args=ARGS,
        trust_registry=retired_registry,
        require_signature=True,
        historical_trust_verification=True,
        now_iso=NOW,
    )
    side_effect = _SideEffect()
    assert _run(
        _v2_receipt(active_signer, trust_epoch=2, event_id="active-ok"),
        active_registry,
        side_effect,
    )
    assert len(side_effect.calls) == 1

    ledger = _ledger(tmp_path, "retired-live")
    _assert_rejects_without_side_effect(
        lambda: _run(retired_receipt, retired_registry, side_effect, ledger=ledger),
        side_effect,
        ledger=ledger,
        reason=ReceiptRejectionReason.SCOPED_TRUST_MISMATCH,
    )
    ledger = _ledger(tmp_path, "revoked-live")
    _assert_rejects_without_side_effect(
        lambda: _run(
            _v2_receipt(revoked_signer, trust_epoch=1, event_id="revoked-bad"),
            revoked_registry,
            side_effect,
            ledger=ledger,
        ),
        side_effect,
        ledger=ledger,
        reason=ReceiptRejectionReason.SCOPED_TRUST_MISMATCH,
    )


def test_trust_readiness_runtime_reports_missing_or_expired_roots() -> None:
    signer = Ed25519Signer.generate(key_id="ready-key")
    scope = ReceiptTrustScope(TENANT, PROJECT, ENV, DECISION_RECEIPT_PURPOSE)
    empty_report = StaticReceiptTrustRegistry().readiness([scope], now_iso=NOW)
    assert not empty_report.ready
    assert {issue.code for issue in empty_report.issues} == {"missing-root"}

    retired_report = _registry(
        signer, status="retired", activated_epoch=1, retired_epoch=2
    ).readiness([scope], now_iso=NOW)
    assert not retired_report.ready
    assert {issue.code for issue in retired_report.issues} == {"no-active-root"}

    revoked_report = _registry(signer, status="revoked", activated_epoch=1).readiness(
        [scope], now_iso=NOW
    )
    assert not revoked_report.ready
    assert {issue.code for issue in revoked_report.issues} == {"no-active-root"}

    active = TrustedReceiptKey(
        scope=scope,
        key_id=signer.key_id,
        algorithm=signer.algorithm,
        public_key_spki_der=_public_spki_der(signer),
        activated_epoch=3,
        not_after=FUTURE,
        status="active",
    )
    retired = TrustedReceiptKey(
        scope=scope,
        key_id="ready-retired",
        algorithm=signer.algorithm,
        public_key_spki_der=_public_spki_der(signer),
        activated_epoch=1,
        not_after=PAST,
        retired_epoch=2,
        status="retired",
    )
    revoked = TrustedReceiptKey(
        scope=scope,
        key_id="ready-revoked",
        algorithm=signer.algorithm,
        public_key_spki_der=_public_spki_der(signer),
        activated_epoch=1,
        not_after=PAST,
        status="revoked",
    )
    mixed_report = StaticReceiptTrustRegistry([retired, revoked, active]).readiness(
        [scope], now_iso=NOW
    )
    assert mixed_report.ready
    assert mixed_report.issues == ()
    expired_active = dataclasses.replace(active, not_after=PAST)
    expired_report = StaticReceiptTrustRegistry([expired_active]).readiness([scope], now_iso=NOW)
    assert not expired_report.ready
    assert {issue.code for issue in expired_report.issues} == {"expired-root"}

    duplicate_active = dataclasses.replace(active, key_id="other-active")
    malformed_report = StaticReceiptTrustRegistry([active, duplicate_active]).readiness(
        [scope], now_iso=NOW
    )
    assert not malformed_report.ready
    assert {issue.code for issue in malformed_report.issues} == {"malformed-root"}
    forged_active = _unsafe_trusted_key(active, activated_epoch=True)
    forged_report = StaticReceiptTrustRegistry([forged_active]).readiness([scope], now_iso=NOW)
    assert not forged_report.ready
    assert {issue.code for issue in forged_report.issues} == {"malformed-root", "missing-root"}

    with pytest.raises(TypeError):
        StaticReceiptTrustRegistry([active]).readiness([scope])

    with pytest.raises(TrustConfigurationError):
        TrustedReceiptKey(
            scope=scope,
            key_id="bad-public",
            algorithm=signer.algorithm,
            public_key_spki_der=b"short",
            activated_epoch=1,
            not_after=FUTURE,
        )
    with pytest.raises(TrustConfigurationError):
        TrustedReceiptKey(
            scope=scope,
            key_id="raw-public-not-der",
            algorithm=signer.algorithm,
            public_key_spki_der=signer.public_bytes(),
            activated_epoch=1,
            not_after=FUTURE,
        )
    with pytest.raises(TrustConfigurationError):
        TrustedReceiptKey(
            scope=scope,
            key_id="private-seed-not-public-der",
            algorithm=signer.algorithm,
            public_key_spki_der=V1_GOLDEN_PRIVATE_BYTES,
            activated_epoch=1,
            not_after=FUTURE,
        )
    with pytest.raises(TrustConfigurationError):
        TrustedReceiptKey(
            scope=scope,
            key_id="bad-epoch",
            algorithm=signer.algorithm,
            public_key_spki_der=_public_spki_der(signer),
            activated_epoch=True,  # type: ignore[arg-type]
            not_after=FUTURE,
        )
    with pytest.raises(TrustConfigurationError):
        TrustedReceiptKey(
            scope=scope,
            key_id="private-holder",
            algorithm=signer.algorithm,
            public_key_spki_der=signer,  # type: ignore[arg-type]
            activated_epoch=1,
            not_after=FUTURE,
        )
    with pytest.raises(TrustConfigurationError):
        TrustedReceiptKey(
            scope=scope,
            key_id="naive-expiry",
            algorithm=signer.algorithm,
            public_key_spki_der=_public_spki_der(signer),
            activated_epoch=1,
            not_after="2099-01-01T00:00:00",
        )


def test_wrong_scope_missing_trust_and_replay_runtime_do_not_execute(tmp_path) -> None:
    signer = Ed25519Signer.generate(key_id="runtime-key")
    receipt = _v2_receipt(signer, event_id="runtime")
    registry = _registry(signer)
    side_effect = _SideEffect()

    same_key_wrong_scope = _registry(
        signer,
        scope=ReceiptTrustScope(TENANT, "other-project", ENV, DECISION_RECEIPT_PURPOSE),
    )
    ledger = _ledger(tmp_path, "same-key-wrong-scope")
    _assert_rejects_without_side_effect(
        lambda: _run(receipt, same_key_wrong_scope, side_effect, ledger=ledger),
        side_effect,
        ledger=ledger,
        reason=ReceiptRejectionReason.SCOPED_TRUST_MISMATCH,
    )
    ledger = _ledger(tmp_path, "missing-key")
    _assert_rejects_without_side_effect(
        lambda: _run(
            dataclasses.replace(receipt, signing_key_id="missing-key"),
            registry,
            side_effect,
            ledger=ledger,
        ),
        side_effect,
        ledger=ledger,
        reason=ReceiptRejectionReason.RECEIPT_HASH_MISMATCH,
    )
    ledger = _ledger(tmp_path, "wrong-alg")
    _assert_rejects_without_side_effect(
        lambda: _run(
            dataclasses.replace(receipt, signature_algorithm="other-alg"),
            registry,
            side_effect,
            ledger=ledger,
        ),
        side_effect,
        ledger=ledger,
        reason=ReceiptRejectionReason.RECEIPT_HASH_MISMATCH,
    )

    for field, value in (
        ("project_id", "tampered-project"),
        ("environment_id", "tampered-env"),
        ("trust_epoch", 2),
        ("trust_epoch", True),
        ("trust_epoch", 1.0),
        ("trust_epoch", "1"),
    ):
        tampered = dataclasses.replace(receipt, **{field: value})
        ledger = _ledger(tmp_path, f"tampered-{field}-{value!r}".replace("/", "_"))
        _assert_rejects_without_side_effect(
            lambda tampered=tampered, ledger=ledger: _run(
                tampered, registry, side_effect, ledger=ledger
            ),
            side_effect,
            ledger=ledger,
        )

    missing_expiry = _resign(dataclasses.replace(receipt, expires_at=""), signer)
    ledger = _ledger(tmp_path, "missing-expiry")
    _assert_rejects_without_side_effect(
        lambda: _run(missing_expiry, registry, side_effect, ledger=ledger),
        side_effect,
        ledger=ledger,
        reason=ReceiptRejectionReason.EXPIRY_REQUIRED,
    )

    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    assert _run(receipt, registry, side_effect, ledger=ledger) == "ran"
    assert len(side_effect.calls) == 1
    with pytest.raises(ReceiptAlreadyUsedError):
        _run(receipt, registry, side_effect, ledger=ledger)
    assert len(side_effect.calls) == 1


class _AdversarialRegistry:
    def __init__(self, key: TrustedReceiptKey | None = None, *, raises: bool = False) -> None:
        self._key = key
        self._raises = raises

    def resolve(self, **kwargs: Any) -> TrustedReceiptKey:
        if self._raises:
            raise RuntimeError("backend secret should not leak")
        assert self._key is not None
        return self._key

    def readiness(self, scopes=()) -> Any:
        return None


def _unsafe_trusted_key(base: TrustedReceiptKey, **updates: Any) -> TrustedReceiptKey:
    values = {
        "scope": base.scope,
        "key_id": base.key_id,
        "algorithm": base.algorithm,
        "public_key_spki_der": base.public_key_spki_der,
        "activated_epoch": base.activated_epoch,
        "not_after": base.not_after,
        "status": base.status,
        "retired_epoch": base.retired_epoch,
        "public_key_fingerprint": base.public_key_fingerprint,
    }
    values.update(updates)
    key = object.__new__(TrustedReceiptKey)
    for field_name, value in values.items():
        object.__setattr__(key, field_name, value)
    return key


def test_adversarial_registry_metadata_mismatch_is_stable_zero_effect(tmp_path) -> None:
    signer = Ed25519Signer.generate(key_id="adversarial-key")
    receipt = _v2_receipt(signer, event_id="adversarial")
    scope = ReceiptTrustScope(TENANT, PROJECT, ENV, DECISION_RECEIPT_PURPOSE)
    good_key = TrustedReceiptKey(
        scope=scope,
        key_id=signer.key_id,
        algorithm=signer.algorithm,
        public_key_spki_der=_public_spki_der(signer),
        activated_epoch=1,
        not_after=FUTURE,
        status="active",
    )
    variants = [
        dataclasses.replace(
            good_key,
            scope=ReceiptTrustScope(TENANT, PROJECT, ENV, "other-purpose"),
        ),
        dataclasses.replace(good_key, key_id="other-key"),
        _unsafe_trusted_key(good_key, algorithm="other-alg"),
        _unsafe_trusted_key(good_key, public_key_spki_der=b"short"),
        _unsafe_trusted_key(good_key, public_key_spki_der=signer.public_bytes()),
        _unsafe_trusted_key(good_key, activated_epoch=0),
        _unsafe_trusted_key(good_key, activated_epoch=True),
        _unsafe_trusted_key(good_key, public_key_fingerprint="0" * 64),
        dataclasses.replace(good_key, activated_epoch=2),
        dataclasses.replace(good_key, not_after=PAST),
        dataclasses.replace(good_key, status="retired", retired_epoch=3),
    ]
    side_effect = _SideEffect()
    for index, key in enumerate(variants):
        ledger = _ledger(tmp_path, f"adversarial-{index}")
        _assert_rejects_without_side_effect(
            lambda key=key, ledger=ledger: _run(
                receipt,
                _AdversarialRegistry(key),  # type: ignore[arg-type]
                side_effect,
                ledger=ledger,
            ),
            side_effect,
            ledger=ledger,
            reason=ReceiptRejectionReason.SCOPED_TRUST_MISMATCH,
        )

    ledger = _ledger(tmp_path, "adversarial-runtime-error")
    _assert_rejects_without_side_effect(
        lambda: _run(
            receipt,
            _AdversarialRegistry(raises=True),  # type: ignore[arg-type]
            side_effect,
            ledger=ledger,
        ),
        side_effect,
        ledger=ledger,
        reason=ReceiptRejectionReason.SCOPED_TRUST_MISMATCH,
    )
