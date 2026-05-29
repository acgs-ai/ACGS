"""End-to-end proof of the core invariant: **No valid Decision Receipt, no side effect.**

Other suites cover the two halves separately — receipt *issuance* under tenant
isolation (``test_tenant_safety``) and receipt *gating* of execution
(``test_executor_guard``). This suite joins them into a single thread:

    GovernanceRequest
      → evaluate_tenant_action  (real policy evaluation + audit append)
      → DecisionReceipt          (issued, anchored in the audit chain)
      → ReceiptVerifier / execute_with_receipt  (the gate)
      → side effect runs ONLY for a valid ALLOW/approved-TRANSFORM receipt
      → audit chain verifies + AuditEvent projects the evidence

so the invariant is proven as one flow, not inferred from two.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from gove_zone import (
    AuditEvent,
    ChainHashAuditStore,
    GovernanceRequest,
    ProposedAction,
    ReceiptValidationError,
    ReceiptVerifier,
    RuleSetPolicy,
    TenantPolicyStore,
    Validator,
    evaluate_tenant_action,
    execute_with_receipt,
)
from gove_zone.tenant import TransformPolicy

BOUNDARY = "local-sandbox"
# A distinct MACI validating principal — never the proposer ("agent-1").
VALIDATOR = Validator("constitutional-council")
AUTHORITY = "tenant-A/write-grant"


class SideEffect:
    """A stand-in high-risk tool. Records whether — and how — it actually ran."""

    def __init__(self) -> None:
        self.ran = False
        self.args: dict[str, Any] | None = None

    def run(self, **kwargs: Any) -> str:
        self.ran = True
        self.args = kwargs
        return "executed"


def _allow_policy() -> RuleSetPolicy:
    # Denies a *different* tool, so our target tool falls through to default ALLOW.
    return RuleSetPolicy.from_dict(
        {"id": "policy-A", "rules": [{"id": "R1", "effect": "deny", "tools": ["shell.exec"]}]}
    )


def _deny_policy() -> RuleSetPolicy:
    return RuleSetPolicy.from_dict(
        {
            "id": "policy-A",
            "rules": [{"id": "R1", "effect": "deny", "tools": ["runtime.file.write"]}],
        }
    )


def _issue(
    store: TenantPolicyStore,
    audit: ChainHashAuditStore,
    request: GovernanceRequest,
    *,
    requester: str | None = None,
) -> Any:
    return evaluate_tenant_action(
        store=store,
        tenant_id=request.tenant_id,
        requester_tenant_id=requester or request.tenant_id,
        action=request.proposed_action.tool,
        args=request.proposed_action.args,
        execution_boundary=request.execution_boundary,
        request_id=request.request_id,
        actor=request.actor,
        validator=VALIDATOR,
        authority=AUTHORITY,
        audit_store=audit,
    )


def _request(
    tool: str = "runtime.file.write", args: dict[str, Any] | None = None
) -> GovernanceRequest:
    action = ProposedAction(tool=tool, args=args or {"path": "safe.txt", "content": "hi"})
    return GovernanceRequest(
        tenant_id="tenant-A",
        actor="agent-1",
        request_id="req-1",
        proposed_action=action,
        execution_boundary=BOUNDARY,
    )


def test_allow_path_executes_and_produces_audit_evidence(tmp_path: Path) -> None:
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle("tenant-A", _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    request = _request()

    receipt = _issue(store, audit, request)
    assert receipt.decision == "allow"

    # The gate verifies before the side effect can run.
    verifier = ReceiptVerifier(expected_tenant_id="tenant-A", expected_execution_boundary=BOUNDARY)
    verifier.verify(
        receipt,
        expected_action="runtime.file.write",
        expected_args=request.proposed_action.args,
    )

    side = SideEffect()
    result = execute_with_receipt(
        tool_fn=side.run,
        args=request.proposed_action.args,
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary=BOUNDARY,
        expected_action="runtime.file.write",
    )
    assert result == "executed"
    assert side.ran

    # Audit evidence exists, chains intact, and links back to the receipt.
    chain = audit.verify_chain()
    assert chain["valid"]
    assert chain["checked"] >= 1
    events = audit.query()
    event = AuditEvent.from_receipt_and_event(receipt, events[-1])
    assert event.tenant_id == "tenant-A"
    assert event.decision == "allow"
    assert event.event_hash == receipt.audit_event_hash


def test_missing_receipt_blocks_side_effect() -> None:
    side = SideEffect()
    with pytest.raises(ReceiptValidationError, match="No receipt provided"):
        execute_with_receipt(
            tool_fn=side.run,
            args={"path": "safe.txt"},
            receipt=None,
            expected_tenant_id="tenant-A",
            expected_execution_boundary=BOUNDARY,
            expected_action="runtime.file.write",
        )
    assert not side.ran


def test_denied_receipt_blocks_but_still_audits(tmp_path: Path) -> None:
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle("tenant-A", _deny_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    receipt = _issue(store, audit, _request())
    assert receipt.decision == "deny"

    side = SideEffect()
    with pytest.raises(ReceiptValidationError, match="Denied receipt"):
        execute_with_receipt(
            tool_fn=side.run,
            args={"path": "safe.txt", "content": "hi"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary=BOUNDARY,
            expected_action="runtime.file.write",
        )
    assert not side.ran
    # A denial is still a decision: it must leave audit evidence.
    assert audit.verify_chain()["valid"]
    assert audit.query()


def test_tampered_issued_receipt_blocks(tmp_path: Path) -> None:
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle("tenant-A", _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    receipt = _issue(store, audit, _request())

    # Flip the approved action without recomputing the receipt hash.
    tampered = dataclasses.replace(receipt, proposed_action="shell.exec")
    side = SideEffect()
    with pytest.raises(ReceiptValidationError, match="receipt_hash mismatch"):
        execute_with_receipt(
            tool_fn=side.run,
            args={"path": "safe.txt", "content": "hi"},
            receipt=tampered,
            expected_tenant_id="tenant-A",
            expected_execution_boundary=BOUNDARY,
            expected_action="shell.exec",
        )
    assert not side.ran


def test_cross_tenant_issued_receipt_blocks(tmp_path: Path) -> None:
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle("tenant-A", _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    receipt = _issue(store, audit, _request())  # issued for tenant-A

    side = SideEffect()
    # A tenant-B executor must refuse a tenant-A receipt.
    with pytest.raises(ReceiptValidationError, match="Tenant mismatch"):
        execute_with_receipt(
            tool_fn=side.run,
            args={"path": "safe.txt", "content": "hi"},
            receipt=receipt,
            expected_tenant_id="tenant-B",
            expected_execution_boundary=BOUNDARY,
            expected_action="runtime.file.write",
        )
    assert not side.ran


def test_issued_receipt_carries_expiry_and_expired_blocks(tmp_path: Path) -> None:
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle("tenant-A", _allow_policy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    # The real issuer can mint an expiring receipt (not just hand-built ones).
    expired = evaluate_tenant_action(
        store=store,
        tenant_id="tenant-A",
        requester_tenant_id="tenant-A",
        action="runtime.file.write",
        args={"path": "safe.txt", "content": "hi"},
        execution_boundary=BOUNDARY,
        request_id="req-expired",
        actor="agent-1",
        validator=VALIDATOR,
        authority=AUTHORITY,
        audit_store=audit,
        expires_at="2020-01-01T00:00:00+00:00",  # unambiguously in the past
    )
    assert expired.decision == "allow"
    assert expired.expires_at == "2020-01-01T00:00:00+00:00"

    # The executor uses the real wall clock — an expired receipt is refused.
    side = SideEffect()
    with pytest.raises(ReceiptValidationError, match="expired"):
        execute_with_receipt(
            tool_fn=side.run,
            args={"path": "safe.txt", "content": "hi"},
            receipt=expired,
            expected_tenant_id="tenant-A",
            expected_execution_boundary=BOUNDARY,
            expected_action="runtime.file.write",
        )
    assert not side.ran

    # A far-future expiry on an otherwise-valid ALLOW still reaches execution.
    live = evaluate_tenant_action(
        store=store,
        tenant_id="tenant-A",
        requester_tenant_id="tenant-A",
        action="runtime.file.write",
        args={"path": "safe.txt", "content": "hi"},
        execution_boundary=BOUNDARY,
        request_id="req-live",
        actor="agent-1",
        validator=VALIDATOR,
        authority=AUTHORITY,
        audit_store=audit,
        expires_at="2999-01-01T00:00:00+00:00",
    )
    side = SideEffect()
    execute_with_receipt(
        tool_fn=side.run,
        args={"path": "safe.txt", "content": "hi"},
        receipt=live,
        expected_tenant_id="tenant-A",
        expected_execution_boundary=BOUNDARY,
        expected_action="runtime.file.write",
    )
    assert side.ran


def test_transform_receipt_executes_only_approved_action(tmp_path: Path) -> None:
    store = TenantPolicyStore(tmp_path / "pol")
    store.store_bundle("tenant-A", TransformPolicy())
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    request = _request(args={"path": "original.txt"})
    receipt = _issue(store, audit, request)
    assert receipt.decision == "transform"

    # Running the ORIGINAL (un-approved) args must be refused.
    side = SideEffect()
    with pytest.raises(ReceiptValidationError, match="Transform mismatch"):
        execute_with_receipt(
            tool_fn=side.run,
            args={"path": "original.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary=BOUNDARY,
            expected_action="runtime.file.write",
        )
    assert not side.ran

    # Only the approved transformed args reach the side effect.
    approved = {"path": "transformed.txt"}
    result = execute_with_receipt(
        tool_fn=side.run,
        args=approved,
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary=BOUNDARY,
        expected_action="runtime.file.write",
    )
    assert result == "executed"
    assert side.ran
    assert side.args == {"path": "transformed.txt"}
