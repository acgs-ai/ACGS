from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from gove_zone import (
    AllowAllPolicy,
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    GovernanceEngine,
    GovernanceRequest,
    GovernedExecutor,
    Policy,
    PolicyBundleBinding,
    ReceiptVerificationError,
    StaticPolicyBundleRegistry,
    parse_and_verify_decision_receipt,
    sha256_json,
    verify_decision_receipt,
)
from gove_zone.tool import ToolCall


def _request(
    *,
    request_id: str = "req-001",
    tenant_id: str = "tenant-alpha",
    policy_bundle_id: str = "bundle-alpha",
    body: str = "hello",
    boundary: dict[str, Any] | None = None,
) -> GovernanceRequest:
    return GovernanceRequest(
        request_id=request_id,
        tenant_id=tenant_id,
        actor={"id": "agent-1"},
        subject={"id": "workflow-1"},
        proposed_action={"tool": "message.send", "args": {"body": body}},
        declared_goal="send a governed message",
        execution_boundary=boundary or {"environment": "local", "risk": "low"},
        policy_bundle_id=policy_bundle_id,
    )


def _engine(
    tmp_path: Path, policy: Policy | None = None
) -> tuple[GovernanceEngine, ChainHashAuditStore]:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    binding = PolicyBundleBinding(
        tenant_id="tenant-alpha",
        policy_bundle_id="bundle-alpha",
        policy_version="alpha/v1",
        constitutional_hash=sha256_json({"tenant": "tenant-alpha", "version": "alpha/v1"}),
        policy=policy or AllowAllPolicy(),
    )
    return (
        GovernanceEngine(
            policy_registry=StaticPolicyBundleRegistry([binding]),
            audit=audit,
        ),
        audit,
    )


class _EscalatePolicy(Policy):
    @property
    def version(self) -> str:
        return "escalate/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.ESCALATE,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id="ev_escalate",
            matched_rules=("REQUIRES_HUMAN",),
            reason="approval required",
        )


class _TransformPolicy(Policy):
    @property
    def version(self) -> str:
        return "transform/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.TRANSFORM,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id="ev_transform",
            matched_rules=("REDACT",),
            reason="redact body",
            transformed_args={"body": "[redacted]"},
        )


def _executor() -> tuple[GovernedExecutor, list[str]]:
    executor = GovernedExecutor()
    reached: list[str] = []

    @executor.tool("message.send")
    def send(body: str) -> str:
        reached.append(body)
        return "sent:" + body

    return executor, reached


def test_receipt_schema_includes_audit_event_hash_and_approval_chain_summary(
    tmp_path: Path,
) -> None:
    engine, audit = _engine(tmp_path)

    receipt = engine.precheck(_request())
    raw = receipt.to_dict()

    assert raw["audit_event_hash"]
    assert raw["approval_chain_summary"] == []
    assert raw["previous_audit_hash"] == "0" * 64
    assert verify_decision_receipt(raw, audit=audit) is True


def test_receipt_verifier_rejects_missing_fields_unknown_decision_and_bad_hash(
    tmp_path: Path,
) -> None:
    engine, _audit = _engine(tmp_path)
    raw = engine.precheck(_request()).to_dict()

    missing = dict(raw)
    missing.pop("tenant_id")
    with pytest.raises(ReceiptVerificationError, match="missing required fields"):
        verify_decision_receipt(missing)

    unknown = dict(raw)
    unknown["decision"] = "APPROVE"
    with pytest.raises(ReceiptVerificationError, match="unknown receipt decision"):
        verify_decision_receipt(unknown)

    tampered = dict(raw)
    tampered["declared_goal"] = "different"
    with pytest.raises(ReceiptVerificationError, match="receipt_hash"):
        verify_decision_receipt(tampered)


def test_receipt_verifier_rejects_audit_hash_mismatch(tmp_path: Path) -> None:
    engine, audit = _engine(tmp_path)
    raw = engine.precheck(_request()).to_dict()
    raw["audit_event_hash"] = "f" * 64

    with pytest.raises(ReceiptVerificationError, match="audit_event_hash"):
        verify_decision_receipt(raw, audit=audit)


def test_receipt_verifier_rejects_reparented_audit_event(tmp_path: Path) -> None:
    engine, audit = _engine(tmp_path)
    first = engine.precheck(_request(request_id="req-first"))
    second = engine.precheck(_request(request_id="req-second"))
    lines = audit.path.read_text(encoding="utf-8").splitlines()

    inserted = json.loads(lines[0])
    inserted["event_id"] = "ev_inserted"
    inserted["request_id"] = "req-inserted"
    inserted["previous_hash"] = first.audit_event_hash
    inserted.pop("event_hash")
    inserted["event_hash"] = sha256_json(inserted)

    reparented = json.loads(lines[1])
    reparented["previous_hash"] = inserted["event_hash"]
    reparented.pop("event_hash")
    reparented["event_hash"] = sha256_json(reparented)

    audit.path.write_text(
        "\n".join(
            [
                lines[0],
                json.dumps(inserted, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
                json.dumps(reparented, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert audit.verify_chain()["valid"] is True

    raw = second.to_dict()
    raw["audit_event_hash"] = reparented["event_hash"]

    with pytest.raises(ReceiptVerificationError, match="previous_audit_hash"):
        verify_decision_receipt(raw, audit=audit)

    assert first.audit_event_hash == second.previous_audit_hash


def test_receipt_verifier_rejects_malformed_transform(tmp_path: Path) -> None:
    engine, _audit = _engine(tmp_path, policy=_TransformPolicy())
    receipt = engine.precheck(_request())
    draft = dataclasses.replace(
        receipt,
        transformations={"proposed_action": {"tool": "message.send"}},
        receipt_hash="",
    )
    malformed = dataclasses.replace(draft, receipt_hash=sha256_json(draft.unsigned_payload()))

    with pytest.raises(ReceiptVerificationError, match="malformed transformed action"):
        parse_and_verify_decision_receipt(malformed)


def test_executor_blocks_escalated_tenant_boundary_and_policy_hash_mismatch(
    tmp_path: Path,
) -> None:
    engine, audit = _engine(tmp_path)
    receipt = engine.precheck(_request(boundary={"environment": "local"}))
    executor, reached = _executor()

    with pytest.raises(ReceiptVerificationError, match="tenant mismatch"):
        executor.execute(
            "message.send",
            {"body": "hello"},
            receipt=receipt,
            tenant_id="tenant-beta",
            audit=audit,
        )

    with pytest.raises(ReceiptVerificationError, match="execution boundary mismatch"):
        executor.execute(
            "message.send",
            {"body": "hello"},
            receipt=receipt,
            tenant_id="tenant-alpha",
            execution_boundary={"environment": "prod"},
            audit=audit,
        )

    with pytest.raises(ReceiptVerificationError, match="policy hash mismatch"):
        executor.execute(
            "message.send",
            {"body": "hello"},
            receipt=receipt,
            tenant_id="tenant-alpha",
            constitutional_hash="bad",
            audit=audit,
        )

    assert reached == []


def test_executor_blocks_escalated_receipt(tmp_path: Path) -> None:
    engine, audit = _engine(tmp_path, policy=_EscalatePolicy())
    receipt = engine.precheck(_request())
    executor, reached = _executor()

    with pytest.raises(ReceiptVerificationError, match="not executable"):
        executor.execute(
            "message.send",
            {"body": "hello"},
            receipt=receipt,
            tenant_id="tenant-alpha",
            audit=audit,
        )

    assert reached == []
