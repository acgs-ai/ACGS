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
    expected_actor: str | None = None,
) -> Any:
    """Execute *tool_fn* with *args* iff *receipt* is valid and matches constraints.

    Refuses execution with ReceiptValidationError if:
    - No receipt is provided
    - Receipt verification fails (altered, tampered, invalid hashes, wrong tenant/boundary)
    - Receipt is denied or escalated
    - Transformations in a TRANSFORM receipt do not match execution arguments

    Pass ``expected_actor`` (the invoking principal's identity, from the caller's
    runtime context — NOT read from the receipt) to anchor the MACI self-validation
    check against an identity the receipt author cannot forge by editing receipt fields.
    """
    if receipt is None:
        raise ReceiptValidationError("No receipt provided for governed execution")

    # verify will check missing fields, signature, hashes, decision type,
    # tenant, boundary, action, audit hash, transform mismatches, and — when
    # expected_actor is supplied — that the receipt was issued for this caller
    # and that the caller is not also the validator.
    receipt.verify(
        expected_tenant_id=expected_tenant_id,
        expected_execution_boundary=expected_execution_boundary,
        expected_audit_hash=expected_audit_hash,
        expected_args=args,
        expected_action=expected_action,
        expected_policy_hash=expected_policy_hash,
        expected_policy_bundle_id=expected_policy_bundle_id,
        expected_actor=expected_actor,
    )

    return tool_fn(**args)


class GovernedExecutor:
    """A wrapper for a tool registry that enforces receipt-gated execution.

    ``expected_actor`` (the proposing principal's identity) can be supplied at
    construction time as the default contract for all calls made through this
    executor, and overridden per-call when needed. Supplying it activates the
    strong caller-anchored proposer-binding check in :meth:`DecisionReceipt.verify`
    (check 2b), which anchors the MACI self-validation guard against an identity
    the receipt author cannot forge by editing receipt fields. Omitting it
    everywhere falls back to the weak ``validator_id == actor`` heuristic (check
    2c) documented in :meth:`DecisionReceipt.verify`.
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        execution_boundary: str,
        expected_actor: str | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.execution_boundary = execution_boundary
        self.expected_actor = expected_actor
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
        expected_actor: str | None = None,
    ) -> Any:
        if action not in self.registry:
            raise KeyError(f"Tool {action!r} not registered with executor")
        tool_fn = self.registry[action]
        # Per-call expected_actor overrides the constructor default; both are
        # optional so omitting everywhere is valid (falls back to weak heuristic).
        effective_actor = expected_actor if expected_actor is not None else self.expected_actor
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
            expected_actor=effective_actor,
        )
