"""Regression tests for AutonomousOperationsEngine approval linkage.

Codex adversarial-review finding #3: ApprovalGate.approve_request only
mutated the approval-request dict, leaving the linked operation stuck on
PENDING. execute_operation then failed with "Operation not approved". The
existing smoke test compensated by manually setting operation.status =
APPROVED, which hid the bug from any caller using the public engine API.

These tests pin the new contract:
- propose_operation populates operation.approval_request_id
- approve_operation flips both the gate request and operation atomically
- execute_operation then succeeds without anyone touching operation.status
"""

from __future__ import annotations

import os
from typing import Any

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-" + "x" * 16)


class _FakeAuditLogger:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def log_decision(self, **kwargs):
        self.calls.append(("decision", kwargs))

    def log_approval_response(self, **kwargs):
        self.calls.append(("approval_response", kwargs))

    def log_enforcement(self, **kwargs):
        self.calls.append(("enforcement", kwargs))


class _FakeGovernance:
    """Stand-in for ACGSIntegration with the minimum surface used by the engine."""

    def __init__(self) -> None:
        self.audit_logger = _FakeAuditLogger()

    def validate_operation(self, **kwargs):
        return {"action": "ALLOW", "valid": True, "violations": []}

    def request_approval(self, **kwargs):
        return {"request_id": "gov_req_test_id", "status": "pending"}


@pytest.fixture
def engine():
    from backend.ai.autonomous_ops import AutonomousOperationsEngine

    # Override handlers with no-op stubs so we don't drag in real handler
    # imports and their dependencies.
    class _NoopHandler:
        async def execute(self, details, context):
            return {"echo": details}

    engine = AutonomousOperationsEngine.__new__(AutonomousOperationsEngine)
    engine.governance = _FakeGovernance()
    engine.recommendation_engine = None
    from backend.governance.approval_gates import ApprovalGate

    engine.approval_gate = ApprovalGate(engine.governance)
    engine.operation_handlers = {"task_assignment": _NoopHandler()}
    engine.active_operations = {}
    engine.operation_history = []
    return engine


@pytest.mark.asyncio
async def test_propose_links_operation_to_approval_request(engine):
    # High-risk context to force pending status.
    high_risk_context = {
        "impact_scope": "organization",
        "financial_impact": 50_000,
        "reversible": False,
        "confidence": 0.6,
    }

    result = await engine.propose_operation(
        operation_type="task_assignment",
        details={"summary": "expand cluster"},
        context=high_risk_context,
    )

    operation_id = result["operation"]["operation_id"]
    operation = engine.active_operations[operation_id]
    request_id = result["approval_request"]["request_id"]

    assert operation.status == "pending"
    assert operation.approval_request_id == request_id
    # And the gate sees it on its pending queue.
    assert request_id in engine.approval_gate.pending_approvals


@pytest.mark.asyncio
async def test_approve_then_execute_via_public_api(engine):
    high_risk_context = {
        "impact_scope": "organization",
        "financial_impact": 50_000,
        "reversible": False,
        "confidence": 0.6,
    }

    proposed = await engine.propose_operation(
        operation_type="task_assignment",
        details={"summary": "expand cluster"},
        context=high_risk_context,
    )
    operation_id = proposed["operation"]["operation_id"]

    # Approve through the public engine API — NOT by poking operation.status.
    approval = engine.approve_operation(
        operation_id, approver="manager@example.com", reason="ok"
    )

    operation = engine.active_operations[operation_id]
    assert operation.status == "approved"
    assert approval["approval_request"]["status"] == "approved"

    # Now execute should succeed without raising "Operation not approved".
    exec_result = await engine.execute_operation(operation_id)
    assert exec_result["success"] is True
    assert exec_result["operation"]["status"] == "completed"


def test_approve_rejects_unknown_operation(engine):
    with pytest.raises(ValueError, match="Operation not found"):
        engine.approve_operation("does_not_exist", approver="x", reason="y")


@pytest.mark.asyncio
async def test_deny_blocks_execution(engine):
    high_risk_context = {
        "impact_scope": "organization",
        "financial_impact": 50_000,
        "reversible": False,
        "confidence": 0.6,
    }

    proposed = await engine.propose_operation(
        operation_type="task_assignment",
        details={"summary": "expand cluster"},
        context=high_risk_context,
    )
    operation_id = proposed["operation"]["operation_id"]

    engine.deny_operation(operation_id, approver="manager@example.com", reason="no")

    operation = engine.active_operations[operation_id]
    assert operation.status == "denied"

    with pytest.raises(ValueError, match="Operation not approved"):
        await engine.execute_operation(operation_id)
