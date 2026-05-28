from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gove_zone import (
    AllowAllPolicy,
    BoundaryPolicy,
    ChainHashAuditStore,
    Decision,
    DenyAllPolicy,
    GovernanceEngine,
    GovernanceRequest,
    GovernedExecutor,
    InMemoryGovernanceMetrics,
    PolicyBundleBinding,
    ReceiptVerificationError,
    StaticPolicyBundleRegistry,
    verify_decision_receipt,
)
from gove_zone.decision import DecisionRecord, sha256_json
from gove_zone.policy import Policy
from gove_zone.tool import ToolCall


def _request(
    *,
    tenant_id: str = "tenant-alpha",
    policy_bundle_id: str = "bundle-alpha",
    body: str = "hello",
) -> GovernanceRequest:
    return GovernanceRequest(
        request_id="req-001",
        tenant_id=tenant_id,
        actor={"id": "agent-1", "role": "agent"},
        subject={"id": "workflow-1", "type": "agentic_workflow"},
        proposed_action={"tool": "message.send", "args": {"body": body}},
        declared_goal="send a governed status update",
        execution_boundary={"environment": "local", "network": "disabled"},
        policy_bundle_id=policy_bundle_id,
    )


def _registry() -> StaticPolicyBundleRegistry:
    return StaticPolicyBundleRegistry(
        [
            PolicyBundleBinding(
                tenant_id="tenant-alpha",
                policy_bundle_id="bundle-alpha",
                policy_version="alpha/v1",
                constitutional_hash=sha256_json({"tenant": "tenant-alpha", "version": "alpha/v1"}),
                policy=AllowAllPolicy(),
            ),
            PolicyBundleBinding(
                tenant_id="tenant-beta",
                policy_bundle_id="bundle-beta",
                policy_version="beta/v1",
                constitutional_hash=sha256_json({"tenant": "tenant-beta", "version": "beta/v1"}),
                policy=DenyAllPolicy("beta is locked down"),
            ),
        ]
    )


def test_precheck_emits_canonical_receipt_and_audit_event(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    engine = GovernanceEngine(policy_registry=_registry(), audit=audit)

    receipt = engine.precheck(_request())

    assert receipt.receipt_id.startswith("rcpt_")
    assert receipt.request_id == "req-001"
    assert receipt.tenant_id == "tenant-alpha"
    assert receipt.policy_bundle_id == "bundle-alpha"
    assert receipt.policy_version == "alpha/v1"
    assert receipt.constitutional_hash
    assert receipt.decision is Decision.ALLOW
    assert receipt.previous_audit_hash == "0" * 64
    assert receipt.receipt_hash
    assert receipt.signature["type"] == "unsigned-local-dev"
    assert verify_decision_receipt(receipt) is True

    events = list(audit.iter_events())
    assert len(events) == 1
    assert events[0]["request_id"] == "req-001"
    assert events[0]["tenant_id"] == "tenant-alpha"
    assert events[0]["policy_bundle_id"] == "bundle-alpha"
    assert events[0]["receipt_hash"] == receipt.receipt_hash
    assert audit.verify_chain()["valid"] is True


def test_receipt_verifier_rejects_tampered_fields(tmp_path: Path) -> None:
    engine = GovernanceEngine(
        policy_registry=_registry(),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
    )
    receipt = engine.precheck(_request())
    tampered = receipt.to_dict()
    tampered["tenant_id"] = "tenant-beta"

    with pytest.raises(ReceiptVerificationError, match="receipt_hash"):
        verify_decision_receipt(tampered)


def test_cross_tenant_policy_bundle_misuse_fails_closed(tmp_path: Path) -> None:
    engine = GovernanceEngine(
        policy_registry=_registry(),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
    )

    receipt = engine.precheck(
        _request(tenant_id="tenant-alpha", policy_bundle_id="bundle-beta"),
    )

    assert receipt.decision is Decision.DENY
    assert "TENANT_POLICY_BUNDLE_MISMATCH" in receipt.matched_rules
    assert verify_decision_receipt(receipt) is True


def test_governed_executor_requires_valid_allow_receipt(tmp_path: Path) -> None:
    engine = GovernanceEngine(
        policy_registry=_registry(),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
    )
    receipt = engine.precheck(_request(body="hello"))
    executor = GovernedExecutor()
    executed: list[str] = []

    @executor.tool("message.send")
    def send(body: str) -> str:
        executed.append(body)
        return "sent:" + body

    with pytest.raises(ReceiptVerificationError, match="missing receipt"):
        executor.execute("message.send", {"body": "hello"}, receipt=None)

    malformed: dict[str, Any] = {"decision": "ALLOW"}
    with pytest.raises(ReceiptVerificationError):
        executor.execute("message.send", {"body": "hello"}, receipt=malformed)

    tampered = receipt.to_dict()
    tampered["proposed_action"]["args"]["body"] = "changed"
    with pytest.raises(ReceiptVerificationError):
        executor.execute("message.send", {"body": "hello"}, receipt=tampered)

    assert executor.execute("message.send", {"body": "hello"}, receipt=receipt) == "sent:hello"
    assert executed == ["hello"]


def test_governed_executor_blocks_denied_receipt(tmp_path: Path) -> None:
    engine = GovernanceEngine(
        policy_registry=StaticPolicyBundleRegistry(
            [
                PolicyBundleBinding(
                    tenant_id="tenant-alpha",
                    policy_bundle_id="bundle-alpha",
                    policy_version="alpha/v1",
                    constitutional_hash=sha256_json("alpha/v1"),
                    policy=DenyAllPolicy("locked"),
                )
            ]
        ),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
    )
    receipt = engine.precheck(_request())
    executor = GovernedExecutor()
    executed: list[str] = []

    @executor.tool("message.send")
    def send(body: str) -> None:
        executed.append(body)

    with pytest.raises(ReceiptVerificationError, match="not executable"):
        executor.execute("message.send", {"body": "hello"}, receipt=receipt)

    assert executed == []


class _RedactingPolicy(Policy):
    @property
    def version(self) -> str:
        return "redact/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.TRANSFORM,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id="ev_transform",
            matched_rules=("REDACT_SECRET",),
            reason="replace secret-bearing body",
            transformed_args={"body": "[redacted]"},
        )


def test_transformed_receipt_only_allows_transformed_action(tmp_path: Path) -> None:
    engine = GovernanceEngine(
        policy_registry=StaticPolicyBundleRegistry(
            [
                PolicyBundleBinding(
                    tenant_id="tenant-alpha",
                    policy_bundle_id="bundle-alpha",
                    policy_version="redact/v1",
                    constitutional_hash=sha256_json("redact/v1"),
                    policy=_RedactingPolicy(),
                )
            ]
        ),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
    )
    receipt = engine.precheck(_request(body="secret token"))
    executor = GovernedExecutor()
    executed: list[str] = []

    @executor.tool("message.send")
    def send(body: str) -> str:
        executed.append(body)
        return body

    with pytest.raises(ReceiptVerificationError, match="action mismatch"):
        executor.execute("message.send", {"body": "secret token"}, receipt=receipt)

    assert executor.execute("message.send", {"body": "[redacted]"}, receipt=receipt) == "[redacted]"
    assert executed == ["[redacted]"]


def test_metrics_record_governance_decisions_and_verification_failures(tmp_path: Path) -> None:
    metrics = InMemoryGovernanceMetrics()
    engine = GovernanceEngine(
        policy_registry=StaticPolicyBundleRegistry(
            [
                PolicyBundleBinding(
                    tenant_id="tenant-alpha",
                    policy_bundle_id="bundle-alpha",
                    policy_version="alpha/v1",
                    constitutional_hash=sha256_json("alpha/v1"),
                    policy=BoundaryPolicy(forbidden_keywords=["secret"]),
                )
            ]
        ),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        metrics=metrics,
    )
    denied = engine.precheck(_request(body="secret token"))

    with pytest.raises(ReceiptVerificationError):
        tampered = denied.to_dict()
        tampered["decision"] = "ALLOW"
        verify_decision_receipt(tampered, metrics=metrics)

    snapshot = metrics.snapshot()
    assert snapshot["decisions_total"]["DENY"] == 1
    assert snapshot["denied_total"] == 1
    assert snapshot["receipt_verification_failed_total"] == 1
    assert snapshot["events"][0]["tenant_id"] == "tenant-alpha"
    assert snapshot["events"][0]["policy_bundle_id"] == "bundle-alpha"
    assert snapshot["events"][0]["request_id"] == "req-001"
