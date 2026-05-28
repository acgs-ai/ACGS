"""Governed executor and receipt-gate runner.

Guarantees that high-risk tool execution fail-closes before any side effects
can be run.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from gove_zone.errors import ReceiptValidationError
from gove_zone.receipt import DecisionReceipt


def execute_with_receipt(
    tool_fn: Callable[..., Any],
    args: dict[str, Any],
    receipt: DecisionReceipt | None,
    *,
    expected_tenant_id: str,
    expected_execution_boundary: str,
    expected_action: str,
    expected_audit_hash: str | None = None,
    expected_policy_hash: str | None = None,
    expected_policy_bundle_id: str | None = None,
) -> Any:
    """Execute *tool_fn* with *args* iff *receipt* is valid and matches constraints.

    Refuses execution with ReceiptValidationError if:
    - No receipt is provided
    - Receipt verification fails (altered, tampered, invalid hashes, wrong tenant/boundary)
    - Receipt is denied or escalated
    - Transformations in a TRANSFORM receipt do not match execution arguments
    """
    if receipt is None:
        raise ReceiptValidationError("No receipt provided for governed execution")

    # verify will check missing fields, signature, hashes, decision type,
    # tenant, boundary, action, audit hash, and transform mismatches.
    receipt.verify(
        expected_tenant_id=expected_tenant_id,
        expected_execution_boundary=expected_execution_boundary,
        expected_audit_hash=expected_audit_hash,
        expected_args=args,
        expected_action=expected_action,
        expected_policy_hash=expected_policy_hash,
        expected_policy_bundle_id=expected_policy_bundle_id,
    )

    return tool_fn(**args)


class GovernedExecutor:
    """A wrapper for a tool registry that enforces receipt-gated execution."""

    def __init__(
        self,
        *,
        tenant_id: str,
        execution_boundary: str,
    ) -> None:
        self.tenant_id = tenant_id
        self.execution_boundary = execution_boundary
        self.registry: dict[str, Callable[..., Any]] = {}

    def register(self, name: str, fn: Callable[..., Any]) -> None:
        self.registry[name] = fn

    def execute(
        self,
        action: str,
        args: dict[str, Any],
        receipt: DecisionReceipt | None,
        *,
        expected_audit_hash: str | None = None,
        expected_policy_hash: str | None = None,
        expected_policy_bundle_id: str | None = None,
    ) -> Any:
        if action not in self.registry:
            raise KeyError(f"Tool {action!r} not registered with executor")
        tool_fn = self.registry[action]
        return execute_with_receipt(
            tool_fn=tool_fn,
            args=args,
            receipt=receipt,
            expected_tenant_id=self.tenant_id,
            expected_execution_boundary=self.execution_boundary,
            expected_action=action,
            expected_audit_hash=expected_audit_hash,
            expected_policy_hash=expected_policy_hash,
            expected_policy_bundle_id=expected_policy_bundle_id,
        )
