"""Governed executor and receipt-gate runner.

Guarantees that high-risk tool execution fail-closes before any side effects
can be run.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Mapping
from typing import Any

from gove_zone.decision import Decision, DecisionRecord
from gove_zone.errors import (
    PRODUCTION_NO_VERIFIER_MSG,
    DeniedError,
    GoveZoneError,
    ProductionProfileError,
    ReceiptValidationError,
)
from gove_zone.receipt import DecisionReceipt
from gove_zone.signing import ReceiptSigner


def execute_with_receipt(
    tool_fn: Callable[..., Any],
    args: dict[str, Any],
    receipt: DecisionReceipt | None,
    *,
    expected_tenant_id: str,
    expected_execution_boundary: str,
    expected_action: str,
    expected_actor: str,
    expected_audit_hash: str | None = None,
    expected_policy_hash: str | None = None,
    expected_policy_bundle_id: str | None = None,
    verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
    require_signature: bool = True,
) -> Any:
    """Execute *tool_fn* with *args* iff *receipt* is valid and matches constraints.

    Refuses execution with ReceiptValidationError if:
    - No receipt is provided
    - Receipt verification fails (altered, tampered, invalid hashes, wrong tenant/boundary)
    - Receipt is denied or escalated
    - Transformations in a TRANSFORM receipt do not match execution arguments

    ``expected_actor`` (the invoking principal's identity, from the caller's
    runtime context — NOT read from the receipt) is **required**. It anchors the
    MACI self-validation/proposer-binding check against an identity the receipt
    author cannot forge by editing receipt fields, so the strong check is the
    default at the gate rather than an opt-in. Omitting it is a ``TypeError``
    (it has no default); passing an empty string fails closed with
    ``ReceiptValidationError``. The relocated trust lives with the integrator:
    this does not manufacture an authenticated identity the architecture lacks —
    signed issuance (``require_signature=True`` + a trusted verifier) is the
    cryptographic closure.
    """
    if not expected_actor or not expected_actor.strip():
        raise ReceiptValidationError(
            "expected_actor is required for governed execution (fail-closed)"
        )
    if require_signature and verifier is None:
        raise ProductionProfileError(PRODUCTION_NO_VERIFIER_MSG)
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
        verifier=verifier,
        require_signature=require_signature,
    )

    return tool_fn(**args)


class GovernedExecutor:
    """A wrapper for a tool registry that enforces receipt-gated execution.

    ``expected_actor`` (the proposing principal's identity) is supplied at
    construction time as the default contract for all calls made through this
    executor, and may be overridden per-call when needed. It is **required**:
    construction with no ``expected_actor`` is a ``TypeError`` and an empty
    string fails closed with ``ReceiptValidationError``. Supplying it activates
    the strong caller-anchored proposer-binding check in
    :meth:`DecisionReceipt.verify` (check 2b) by default, anchoring the MACI
    self-validation guard against an identity the receipt author cannot forge by
    editing receipt fields. There is no silent downgrade to the weak
    ``validator_id == actor`` heuristic (check 2c) through this gate; 2c remains
    only as residual defense for direct :meth:`DecisionReceipt.verify` calls.
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        execution_boundary: str,
        expected_actor: str,
        verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
        require_signature: bool = True,
    ) -> None:
        if not expected_actor or not expected_actor.strip():
            raise ReceiptValidationError(
                "expected_actor is required for GovernedExecutor (fail-closed)"
            )
        self.tenant_id = tenant_id
        self.execution_boundary = execution_boundary
        self.expected_actor = expected_actor
        self.verifier = verifier
        self.require_signature = require_signature
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
        verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
        require_signature: bool | None = None,
    ) -> Any:
        if action not in self.registry:
            raise KeyError(f"Tool {action!r} not registered with executor")
        tool_fn = self.registry[action]
        # Per-call values override the constructor defaults. expected_actor is
        # required at construction, so the effective anchor is always set unless a
        # per-call override blanks it — defend against expected_actor="" here.
        effective_actor = expected_actor if expected_actor is not None else self.expected_actor
        if not effective_actor or not effective_actor.strip():
            raise ReceiptValidationError(
                "expected_actor is required for governed execution (fail-closed)"
            )
        effective_verifier = verifier if verifier is not None else self.verifier
        effective_require = (
            require_signature if require_signature is not None else self.require_signature
        )
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
            verifier=effective_verifier,
            require_signature=effective_require,
        )


class StateRollbackHandler:
    """Fail-safe context manager that tracks transaction state and rolls back on failure."""

    def __init__(self, rollback_fn: Callable[[], None] | None = None) -> None:
        self.rollback_fn = rollback_fn

    def __enter__(self) -> StateRollbackHandler:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        if exc_type is not None:
            if self.rollback_fn is not None:
                with contextlib.suppress(Exception):
                    self.rollback_fn()
            # Wrap standard/assertion errors into DeniedError standard security error format
            if not isinstance(exc_val, GoveZoneError):
                raise DeniedError(
                    DecisionRecord(
                        decision=Decision.DENY,
                        tool="unknown",
                        argument_hash="",
                        policy_version="rollback/v0",
                        event_id="ev_rollback",
                        reason=f"Execution aborted and rolled back due to: {exc_val}",
                    ),
                    audit_hash="",
                ) from exc_val
