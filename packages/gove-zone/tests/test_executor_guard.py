"""Tests for the receipt-required executor guard (execute_with_receipt, GovernedExecutor)."""

from __future__ import annotations

from typing import Any

import pytest

from gove_zone import (
    Decision,
    DecisionReceipt,
    DecisionRecord,
    GovernedExecutor,
    ReceiptValidationError,
    Validator,
    execute_with_receipt,
)


class SideEffectTracker:
    def __init__(self) -> None:
        self.called = False
        self.called_with: dict[str, Any] | None = None

    def run_tool(self, **kwargs: Any) -> str:
        self.called = True
        self.called_with = kwargs
        return "success"


_DEFAULT_ALLOW_ARGS: dict[str, Any] = {"path": "safe.txt"}


def make_test_receipt(
    decision: str = "allow",
    transformations: list[dict[str, Any]] | None = None,
    tenant_id: str = "tenant-A",
    execution_boundary: str = "local-sandbox",
    action: str = "runtime.file.write",
    args: dict[str, Any] | None = None,
) -> DecisionReceipt:
    from gove_zone.decision import sha256_json

    effective_args = args if args is not None else _DEFAULT_ALLOW_ARGS
    record = DecisionRecord(
        decision=Decision(decision),
        tool=action,
        argument_hash=sha256_json(effective_args),
        policy_version="v1",
        event_id="ev_abc",
        transformed_args={"path": "transformed.txt"} if decision == "transform" else None,
    )
    receipt = DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id=tenant_id,
        execution_boundary=execution_boundary,
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        request_id="req-123",
        validator=Validator("validator-1"),
        authority="tenant-A/write-grant",
    )
    if transformations is not None:
        import dataclasses

        receipt = dataclasses.replace(receipt, transformations=transformations)
        h = receipt.compute_hash()
        receipt = dataclasses.replace(receipt, receipt_hash=h)
    return receipt


def test_executor_refuses_no_receipt() -> None:
    tracker = SideEffectTracker()
    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=None,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
        )
    assert "No receipt provided" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_malformed_receipt() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt()
    import dataclasses

    # Make it malformed by clearing receipt_id
    receipt = dataclasses.replace(receipt, receipt_id="")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
        )
    assert "Missing or empty required field" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_tampered_receipt() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt()
    import dataclasses

    # Tamper with tenant_id without recomputing receipt_hash
    receipt = dataclasses.replace(receipt, tenant_id="tenant-B")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
        )
    assert "receipt_hash mismatch" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_denied_receipt() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("deny")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
        )
    assert "Denied receipt cannot authorize execution" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_escalated_receipt() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("escalate")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
        )
    assert "Escalated receipt cannot authorize execution" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_wrong_tenant() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt(tenant_id="tenant-B")

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            args={"path": "safe.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
        )
    assert "Tenant mismatch" in str(exc_info.value)
    assert not tracker.called


def test_executor_refuses_transform_mismatch() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("transform")
    # Expected transform args has path="transformed.txt"

    with pytest.raises(ReceiptValidationError) as exc_info:
        execute_with_receipt(
            tool_fn=tracker.run_tool,
            # Pass original untransformed arg
            args={"path": "original.txt"},
            receipt=receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
            expected_actor="anonymous",
        )
    assert "Transform mismatch" in str(exc_info.value)
    assert not tracker.called


def test_executor_allows_valid_allowed_receipt() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("allow")

    res = execute_with_receipt(
        tool_fn=tracker.run_tool,
        args={"path": "safe.txt"},
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="anonymous",
    )
    assert res == "success"
    assert tracker.called
    assert tracker.called_with == {"path": "safe.txt"}


def test_executor_allows_valid_transformed_receipt() -> None:
    tracker = SideEffectTracker()
    receipt = make_test_receipt("transform")
    # Expected transform args must have path="transformed.txt"

    res = execute_with_receipt(
        tool_fn=tracker.run_tool,
        args={"path": "transformed.txt"},
        receipt=receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
        expected_actor="anonymous",
    )
    assert res == "success"
    assert tracker.called
    assert tracker.called_with == {"path": "transformed.txt"}


def test_governed_executor_workflow() -> None:
    tracker = SideEffectTracker()
    executor = GovernedExecutor(
        tenant_id="tenant-A", execution_boundary="local-sandbox", expected_actor="anonymous"
    )
    executor.register("runtime.file.write", tracker.run_tool)

    receipt = make_test_receipt("allow", args={"path": "test.txt"})
    res = executor.execute("runtime.file.write", {"path": "test.txt"}, receipt)
    assert res == "success"
    assert tracker.called
