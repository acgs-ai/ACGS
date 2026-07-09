"""Tests for the GPA Enforcement Plane (kernel & executor updates)."""

from __future__ import annotations

import time

import pytest

from gove_zone.audit import ChainHashAuditStore
from gove_zone.decision import Decision
from gove_zone.errors import DeniedError
from gove_zone.executor import StateRollbackHandler
from gove_zone.kernel import GovernedTool, Kernel
from gove_zone.policy import PolicyRule, RuleSetPolicy


class MockDb:
    def __init__(self) -> None:
        self.variables = {"purchase_order_approved": False}
        self.rollbacks = 0

    def rollback(self) -> None:
        self.rollbacks += 1
        self.variables["purchase_order_approved"] = False


def test_context_hydration(tmp_path) -> None:
    db = MockDb()

    # Define a policy that denies unless po is approved
    rule = PolicyRule(
        rule_id="check-po-approval",
        effect=Decision.DENY,
        tools=frozenset(["sap.invoice.approve"]),
        state_equals={"purchase_order_approved": False},
        reason="PO is not approved",
    )
    policy = RuleSetPolicy(policy_id="test-p", rules=[rule])
    audit_file = tmp_path / "audit.jsonl"
    audit = ChainHashAuditStore(audit_file)

    # Hydration fetches status from MockDb
    def hydrate(tool_name: str, args: dict) -> dict:
        return {"purchase_order_approved": db.variables["purchase_order_approved"]}

    kernel = Kernel(policy=policy, audit=audit, context_hydrator=hydrate)

    @kernel.tool("sap.invoice.approve")
    def approve_invoice(invoice_id: str) -> str:
        return "approved"

    # Should deny initially because PO is not approved
    with pytest.raises(DeniedError) as excinfo:
        kernel.dispatch("sap.invoice.approve", {"invoice_id": "INV-1"})
    assert "PO is not approved" in str(excinfo.value)

    # Approve PO and try again
    db.variables["purchase_order_approved"] = True
    res, _ = kernel.dispatch("sap.invoice.approve", {"invoice_id": "INV-1"})
    assert res == "approved"


def test_governed_tool_wrapper(tmp_path) -> None:
    rule = PolicyRule(
        rule_id="deny-all-custom",
        effect=Decision.DENY,
        tools=frozenset(["high_risk_tool"]),
        reason="Forced deny",
    )
    policy = RuleSetPolicy(policy_id="test-p", rules=[rule])
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=policy, audit=audit)

    def my_tool(arg_0: str) -> str:
        return f"result: {arg_0}"

    governed = GovernedTool(kernel, "high_risk_tool", my_tool)

    with pytest.raises(DeniedError):
        governed("test-val")


def test_ast_evaluation_performance() -> None:
    # Build a policy with 50 rules to test scale
    rules = [
        PolicyRule(
            rule_id=f"rule-{i}",
            effect=Decision.DENY,
            tools=frozenset([f"tool-{i}"]),
            state_equals={"test_key": i},
        )
        for i in range(50)
    ]
    policy = RuleSetPolicy(policy_id="perf-p", rules=rules)

    # Generate a tool call
    from gove_zone.tool import ToolCall

    call = ToolCall(name="tool-49", args={}, goal="test", actor="agent", state={"test_key": 49})

    # Benchmark
    t0 = time.perf_counter()
    for _ in range(100):
        policy.evaluate(call)
    t1 = time.perf_counter()

    avg_ms = ((t1 - t0) / 100) * 1000
    print(f"Average RuleSetPolicy evaluation time: {avg_ms:.4f} ms")
    assert avg_ms < 5.0, f"Evaluation time is too slow: {avg_ms:.4f} ms"


def test_state_rollback_handler() -> None:
    db = MockDb()
    db.variables["purchase_order_approved"] = True

    # Transaction success
    with StateRollbackHandler(db.rollback):
        # Perform action
        db.variables["purchase_order_approved"] = True

    assert db.rollbacks == 0

    # Transaction failure
    with pytest.raises(DeniedError), StateRollbackHandler(db.rollback):
        db.variables["purchase_order_approved"] = True
        raise ValueError("Something went wrong")

    assert db.rollbacks == 1
    assert db.variables["purchase_order_approved"] is False
