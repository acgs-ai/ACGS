"""D2 runtime-capture tests for UniversalGateway issuer paths.

Capture is an evidence precondition before DecisionReceipt issuance on the
configured gateway surfaces. It is not executor input and it is off when no
capture_config is supplied.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest

from gove_zone import gateway as gateway_module
from gove_zone.capture import (
    CaptureAck,
    CaptureConfig,
    CaptureConfigurationError,
    CaptureMode,
    CaptureProjectionError,
    CaptureRecord,
    CaptureTenantError,
    JsonlCaptureStore,
    capture_record_for_decision,
)
from gove_zone.decision import Decision
from gove_zone.gateway import UniversalGateway
from gove_zone.policy import PolicyRule, RuleSetPolicy
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import Validator


class FakeSigner:
    """Deterministic HMAC signer implementing the ReceiptSigner protocol."""

    algorithm = "test-hmac-sha256"

    def __init__(self, key: bytes = b"test-key", key_id: str = "test-key-1") -> None:
        self._key = key
        self.key_id = key_id

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


class RecordingStore:
    def __init__(self) -> None:
        self.records: list[CaptureRecord] = []

    def append(self, record: CaptureRecord) -> CaptureAck:
        self.records.append(record)
        return CaptureAck(
            tenant_id=record.tenant_id,
            event_id=record.event_id,
            audit_event_hash=record.audit_event_hash,
        )


class FailingStore:
    def append(self, record: CaptureRecord) -> CaptureAck:
        raise RuntimeError("capture write failed")


class MismatchingStore:
    def append(self, record: CaptureRecord) -> CaptureAck:
        return CaptureAck(
            tenant_id=record.tenant_id,
            event_id="wrong-event",
            audit_event_hash=record.audit_event_hash,
        )


class FailOnSecondStore:
    def __init__(self) -> None:
        self.records: list[CaptureRecord] = []

    def append(self, record: CaptureRecord) -> CaptureAck:
        self.records.append(record)
        if len(self.records) == 2:
            raise RuntimeError("second capture failed")
        return CaptureAck(
            tenant_id=record.tenant_id,
            event_id=record.event_id,
            audit_event_hash=record.audit_event_hash,
        )


class RecordingObservationSink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def append(self, event: dict[str, Any]) -> None:
        self.events.append(dict(event))


class FailingObservationSink:
    def append(self, event: dict[str, Any]) -> None:
        raise RuntimeError("observation write failed")


def make_policy() -> RuleSetPolicy:
    return RuleSetPolicy(
        policy_id="runtime-capture-tests",
        rules=(
            PolicyRule(
                rule_id="deny-runtime-bash",
                effect=Decision.DENY,
                tools=frozenset({"runtime.Bash"}),
                reason="runtime Bash is denied for hook tests",
            ),
        ),
    )


def required_capture_config(
    *,
    store: Any | None = None,
    observation_sink: Any | None = None,
) -> CaptureConfig:
    sink = observation_sink if observation_sink is not None else RecordingObservationSink()
    return CaptureConfig(
        mode=CaptureMode.REQUIRED,
        store=store if store is not None else RecordingStore(),
        observation_sink=sink,
        evaluator_version="gateway-evaluator/v1",
        projection_version="gateway-projection/v1",
    )


def make_gateway(
    tmp_path: Path,
    *,
    capture_config: CaptureConfig | None = None,
    profile: GovernanceProfile | None = None,
) -> UniversalGateway:
    signer = FakeSigner()
    return UniversalGateway(
        tenant_id="tenant-1",
        execution_boundary="boundary-1",
        policy=make_policy(),
        profile=profile or GovernanceProfile.production(signer=signer, verifier=signer),
        validator=Validator(validator_id="validator-1"),
        authority="authority-1",
        audit_path=tmp_path / "audit.jsonl",
        ledger_path=tmp_path / "ledger.jsonl",
        policy_bundle_id="bundle-1",
        capture_config=capture_config,
    )


def _patch_receipt_and_executor_to_fail(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def fail_receipt(*args: Any, **kwargs: Any) -> Any:
        calls.append("receipt")
        raise AssertionError("receipt factory must not be called")

    def fail_executor(*args: Any, **kwargs: Any) -> Any:
        calls.append("executor")
        raise AssertionError("executor must not be called")

    monkeypatch.setattr(gateway_module.DecisionReceipt, "from_record", staticmethod(fail_receipt))
    monkeypatch.setattr(gateway_module, "execute_with_receipt", fail_executor)
    return calls


def test_required_capture_success_precedes_side_effect(tmp_path: Path) -> None:
    store = RecordingStore()
    sink = RecordingObservationSink()
    gateway = make_gateway(
        tmp_path,
        capture_config=required_capture_config(store=store, observation_sink=sink),
    )
    side_effects: list[str] = []

    gateway.register_tool("echo", lambda message: side_effects.append(message) or f"echo:{message}")

    outcome = gateway.invoke("agent-a", "echo", {"message": "hi"})

    assert outcome.executed
    assert outcome.receipt is not None
    assert side_effects == ["hi"]
    assert len(store.records) == 1
    capture = store.records[0]
    assert capture.capture_outcome == "captured"
    assert capture.tenant_id == "tenant-1"
    assert capture.policy_bundle_id == "bundle-1"
    assert capture.policy_hash == make_policy().version
    assert capture.event_id
    assert capture.audit_event_hash == outcome.audit_hash
    assert sink.events == [
        {
            "kind": "capture_persisted",
            "tenant_id": "tenant-1",
            "event_id": capture.event_id,
            "audit_event_hash": outcome.audit_hash,
            "capture_outcome": "captured",
        }
    ]


def test_required_capture_store_failure_blocks_receipt_executor_and_side_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = RecordingObservationSink()
    gateway = make_gateway(
        tmp_path,
        capture_config=required_capture_config(store=FailingStore(), observation_sink=sink),
    )
    side_effects: list[dict[str, Any]] = []
    gateway.register_tool("echo", lambda **kwargs: side_effects.append(kwargs))
    forbidden_calls = _patch_receipt_and_executor_to_fail(monkeypatch)

    outcome = gateway.invoke("agent-a", "echo", {"message": "hi"})

    assert outcome.status == "error"
    assert outcome.error_class == "CaptureError"
    assert side_effects == []
    assert forbidden_calls == []
    assert len(sink.events) == 1
    assert sink.events[0]["kind"] == "capture_failed"
    assert sink.events[0]["capture_outcome"] == "capture_failed"
    assert sink.events[0]["error_class"] == "RuntimeError"


def test_required_capture_store_and_failure_observation_failure_still_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gateway = make_gateway(
        tmp_path,
        capture_config=required_capture_config(
            store=FailingStore(), observation_sink=FailingObservationSink()
        ),
    )
    side_effects: list[dict[str, Any]] = []
    gateway.register_tool("echo", lambda **kwargs: side_effects.append(kwargs))
    forbidden_calls = _patch_receipt_and_executor_to_fail(monkeypatch)

    outcome = gateway.invoke("agent-a", "echo", {"message": "hi"})

    assert outcome.status == "error"
    assert outcome.error_class == "CaptureError"
    assert side_effects == []
    assert forbidden_calls == []


def test_required_capture_observation_failure_blocks_receipt_executor_and_side_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gateway = make_gateway(
        tmp_path,
        capture_config=required_capture_config(
            store=RecordingStore(), observation_sink=FailingObservationSink()
        ),
    )
    side_effects: list[dict[str, Any]] = []
    gateway.register_tool("echo", lambda **kwargs: side_effects.append(kwargs))
    forbidden_calls = _patch_receipt_and_executor_to_fail(monkeypatch)

    outcome = gateway.invoke("agent-a", "echo", {"message": "hi"})

    assert outcome.status == "error"
    assert outcome.error_class == "CaptureError"
    assert side_effects == []
    assert forbidden_calls == []


def test_required_capture_ack_mismatch_blocks_receipt_executor_and_side_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gateway = make_gateway(
        tmp_path,
        capture_config=required_capture_config(
            store=MismatchingStore(), observation_sink=RecordingObservationSink()
        ),
    )
    side_effects: list[dict[str, Any]] = []
    gateway.register_tool("echo", lambda **kwargs: side_effects.append(kwargs))
    forbidden_calls = _patch_receipt_and_executor_to_fail(monkeypatch)

    outcome = gateway.invoke("agent-a", "echo", {"message": "hi"})

    assert outcome.status == "error"
    assert outcome.error_class == "CaptureBindingError"
    assert side_effects == []
    assert forbidden_calls == []


def test_production_profile_rejects_best_effort_and_disabled_capture(tmp_path: Path) -> None:
    signer = FakeSigner()
    profile = GovernanceProfile.production(signer=signer, verifier=signer)
    best_effort = CaptureConfig(
        mode=CaptureMode.BEST_EFFORT,
        observation_sink=RecordingObservationSink(),
        evaluator_version="gateway-evaluator/v1",
        projection_version="gateway-projection/v1",
    )
    with pytest.raises(ValueError, match="rejects BEST_EFFORT and DISABLED"):
        make_gateway(tmp_path, profile=profile, capture_config=best_effort)

    disabled = CaptureConfig(mode=CaptureMode.DISABLED)
    with pytest.raises(ValueError, match="rejects BEST_EFFORT and DISABLED"):
        make_gateway(tmp_path, profile=profile, capture_config=disabled)


def test_required_capture_config_rejects_missing_authority_bindings() -> None:
    with pytest.raises(CaptureConfigurationError, match="capture store"):
        CaptureConfig(
            mode=CaptureMode.REQUIRED,
            observation_sink=RecordingObservationSink(),
            evaluator_version="gateway-evaluator/v1",
            projection_version="gateway-projection/v1",
        )
    with pytest.raises(CaptureConfigurationError, match="evaluator_version"):
        CaptureConfig(
            mode=CaptureMode.REQUIRED,
            store=RecordingStore(),
            observation_sink=RecordingObservationSink(),
            projection_version="gateway-projection/v1",
        )


def test_capture_record_serialization_is_metadata_only() -> None:
    record = capture_record_for_decision(
        tenant_id="tenant-1",
        event_id="event-1",
        audit_event_hash="audit-hash",
        policy_bundle_id="bundle-1",
        policy_version="policy/v1",
        policy_hash="policy-hash",
        evaluator_version="eval/v1",
        projection_version="projection/v1",
        decision_time="2026-07-27T00:00:00+00:00",
        field_status={"argument_hash": "present", "state_hash": "present"},
        privacy_outcome="metadata_only",
    )

    payload = record.to_dict()

    assert set(payload) == {
        "schema_version",
        "tenant_id",
        "event_id",
        "audit_event_hash",
        "policy_bundle_id",
        "policy_version",
        "policy_hash",
        "evaluator_version",
        "projection_version",
        "decision_time",
        "field_status",
        "privacy_outcome",
        "capture_outcome",
        "capture_reason",
    }
    assert "args" not in payload
    assert "state" not in payload
    assert "goal" not in payload
    assert "reason" not in payload
    assert "transformed_args" not in payload
    assert "secret-value" not in json.dumps(payload)


def test_field_status_rejects_unapproved_keys_and_values() -> None:
    with pytest.raises(CaptureProjectionError, match="key is not approved"):
        CaptureConfig(mode=CaptureMode.DISABLED, field_status={"raw_args": "not_retained"})
    with pytest.raises(CaptureProjectionError, match="value is not approved"):
        CaptureConfig(mode=CaptureMode.DISABLED, field_status={"argument_hash": "secret-value"})
    with pytest.raises(CaptureProjectionError, match="key is not approved"):
        capture_record_for_decision(
            tenant_id="tenant-1",
            event_id="event-1",
            audit_event_hash="audit-hash",
            policy_bundle_id="bundle-1",
            policy_version="policy/v1",
            policy_hash="policy-hash",
            evaluator_version="eval/v1",
            projection_version="projection/v1",
            decision_time="2026-07-27T00:00:00+00:00",
            field_status={"raw_args": "not_retained"},
            privacy_outcome="metadata_only",
        )
    with pytest.raises(CaptureProjectionError, match="value is not approved"):
        capture_record_for_decision(
            tenant_id="tenant-1",
            event_id="event-1",
            audit_event_hash="audit-hash",
            policy_bundle_id="bundle-1",
            policy_version="policy/v1",
            policy_hash="policy-hash",
            evaluator_version="eval/v1",
            projection_version="projection/v1",
            decision_time="2026-07-27T00:00:00+00:00",
            field_status={"argument_hash": "secret-value"},
            privacy_outcome="metadata_only",
        )
    with pytest.raises(CaptureProjectionError, match="key is not approved"):
        CaptureRecord.from_dict(
            {
                "schema_version": "gove-zone.capture/v1",
                "tenant_id": "tenant-1",
                "event_id": "event-1",
                "audit_event_hash": "audit-hash",
                "policy_bundle_id": "bundle-1",
                "policy_version": "policy/v1",
                "policy_hash": "policy-hash",
                "evaluator_version": "eval/v1",
                "projection_version": "projection/v1",
                "decision_time": "2026-07-27T00:00:00+00:00",
                "field_status": {"raw_args": "secret-value"},
                "privacy_outcome": "metadata_only",
                "capture_outcome": "captured",
                "capture_reason": "captured-after-audit-before-receipt",
            }
        )


def test_field_status_is_immutable_snapshot() -> None:
    source = {"argument_hash": "present"}
    config = CaptureConfig(mode=CaptureMode.DISABLED, field_status=source)
    source["argument_hash"] = "secret-value"

    assert dict(config.field_status) == {"argument_hash": "present"}
    with pytest.raises(TypeError):
        config.field_status["argument_hash"] = "absent"  # type: ignore[index]


def test_jsonl_capture_store_lookup_is_tenant_bound(tmp_path: Path) -> None:
    store = JsonlCaptureStore(tmp_path / "capture.jsonl")
    record = capture_record_for_decision(
        tenant_id="tenant-a",
        event_id="event-1",
        audit_event_hash="audit-hash",
        policy_bundle_id="bundle-1",
        policy_version="policy/v1",
        policy_hash="policy-hash",
        evaluator_version="eval/v1",
        projection_version="projection/v1",
        decision_time="2026-07-27T00:00:00+00:00",
        field_status={"argument_hash": "present"},
        privacy_outcome="metadata_only",
    )
    ack = store.append(record)

    assert ack.tenant_id == "tenant-a"
    assert store.get(tenant_id="tenant-a", event_id="event-1") == record
    with pytest.raises(CaptureTenantError):
        store.get(tenant_id="tenant-b", event_id="event-1")


def test_legacy_unconfigured_gateway_keeps_existing_execution_path(tmp_path: Path) -> None:
    gateway = make_gateway(tmp_path, capture_config=None)
    side_effects: list[str] = []
    gateway.register_tool("echo", lambda message: side_effects.append(message) or message)

    outcome = gateway.invoke("agent-a", "echo", {"message": "legacy"})

    assert outcome.executed
    assert outcome.receipt is not None
    assert side_effects == ["legacy"]


def test_disabled_capture_dev_profile_is_explicit_skip(tmp_path: Path) -> None:
    gateway = make_gateway(
        tmp_path,
        profile=GovernanceProfile.dev(),
        capture_config=CaptureConfig(mode=CaptureMode.DISABLED),
    )
    side_effects: list[str] = []
    gateway.register_tool("echo", lambda message: side_effects.append(message) or message)

    outcome = gateway.invoke("agent-a", "echo", {"message": "dev-disabled"})

    assert outcome.executed
    assert outcome.receipt is not None
    assert side_effects == ["dev-disabled"]


def test_best_effort_store_failure_observes_failure_and_execution_continues(
    tmp_path: Path,
) -> None:
    sink = RecordingObservationSink()
    gateway = make_gateway(
        tmp_path,
        profile=GovernanceProfile.dev(),
        capture_config=CaptureConfig(
            mode=CaptureMode.BEST_EFFORT,
            store=FailingStore(),
            observation_sink=sink,
            evaluator_version="gateway-evaluator/v1",
            projection_version="gateway-projection/v1",
        ),
    )
    side_effects: list[str] = []
    gateway.register_tool("echo", lambda message: side_effects.append(message) or message)

    outcome = gateway.invoke("agent-a", "echo", {"message": "best-effort"})

    assert outcome.executed
    assert side_effects == ["best-effort"]
    assert sink.events == [
        {
            "kind": "capture_failed",
            "tenant_id": "tenant-1",
            "event_id": sink.events[0]["event_id"],
            "audit_event_hash": outcome.audit_hash,
            "capture_outcome": "capture_failed",
            "error_class": "RuntimeError",
        }
    ]


def test_hook_batch_capture_failure_denies_before_any_receipt_anchors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = FailOnSecondStore()
    gateway = make_gateway(
        tmp_path,
        capture_config=required_capture_config(
            store=store, observation_sink=RecordingObservationSink()
        ),
    )
    forbidden_calls = _patch_receipt_and_executor_to_fail(monkeypatch)

    response = gateway.handle_claude_hook(
        {
            "tool_calls": [
                {"function": {"name": "Read", "arguments": '{"file_path": "/tmp/a"}'}},
                {"function": {"name": "Glob", "arguments": '{"pattern": "*.py"}'}},
            ]
        },
        actor="claude-session-1",
    )

    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "gove_zone" not in response
    assert len(store.records) == 2
    assert forbidden_calls == []
