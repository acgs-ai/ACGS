"""Formalized named governance contracts — the typed vocabulary layer.

These types give explicit names to concepts the kernel already enforces today
through bare strings and scattered parameters. They are **purely additive**:
no existing call site requires them, no existing API changed to accommodate
them. They exist so consumers — agents, MCP tools, workflow engines, CI
runners, custom executors — can speak the governance vocabulary in typed code
rather than threading positional strings.

Mapping to the underlying enforcement primitives:

==========================  ==========================================
Contract                    Backed by
==========================  ==========================================
``ProposedAction``          :class:`gove_zone.tool.ToolCall` inputs
``ExecutionBoundary``       the ``execution_boundary`` string field
``GovernanceRequest``       inputs to :func:`evaluate_tenant_action`
``PolicyBundleRef``         ``policy_bundle_id`` + ``policy_version`` +
                            ``policy_hash`` on the receipt
``TenantPolicyBinding``     a tenant ↔ bundle pairing
                            (storage lives in
                            :class:`gove_zone.tenant.TenantPolicyStore`)
``DecisionReceipt``         re-exported from :mod:`gove_zone.receipt`
``ReceiptVerifier``         wraps :meth:`DecisionReceipt.verify`
``AuditEvent``              a typed projection of one persisted
                            audit-chain event
==========================  ==========================================

The single fail-closed gate remains :meth:`DecisionReceipt.verify`. This module
adds typing and ergonomics; it does not add a second enforcement path.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, NewType

from gove_zone.errors import (
    PRODUCTION_NO_VERIFIER_MSG,
    ProductionProfileError,
    ReceiptValidationError,
)
from gove_zone.receipt import DecisionReceipt
from gove_zone.signing import ReceiptSigner

# An execution boundary is an opaque label for *where* an approved action may
# run (e.g. "local-sandbox", "tenant-A/prod-egress"). It is a string today;
# NewType makes intent explicit without imposing runtime cost or new behavior.
ExecutionBoundary = NewType("ExecutionBoundary", str)


@dataclass(frozen=True)
class ProposedAction:
    """A high-risk action proposed for governance, *before* any decision.

    This is what an executor submits — the raw intent. It is not yet
    authorized; only a valid ALLOW/TRANSFORM :class:`DecisionReceipt`
    authorizes execution.
    """

    tool: str
    args: dict[str, Any]
    goal: str = ""

    def summary(self) -> str:
        """A short, log-safe one-line description (no argument values)."""
        return f"{self.tool}({', '.join(sorted(self.args))})"


@dataclass(frozen=True)
class PolicyBundleRef:
    """A stable reference to the policy bundle that governed a decision.

    Bundles the three fields that together identify *which* policy produced a
    receipt: a human-stable id, a version label, and the content hash that
    makes the binding tamper-evident.
    """

    bundle_id: str
    version: str
    policy_hash: str


@dataclass(frozen=True)
class GovernanceRequest:
    """Everything an executor submits for one pre-execution governance check.

    The request carries identity (``tenant_id``, ``actor``), correlation
    (``request_id``), the :class:`ProposedAction`, and the
    :class:`ExecutionBoundary` the caller intends to run within. A request is
    *not* an authorization — it is the input to the decision that may produce
    one.
    """

    tenant_id: str
    actor: str
    request_id: str
    proposed_action: ProposedAction
    execution_boundary: str

    def __post_init__(self) -> None:
        # Fail-closed at the contract boundary: a request missing tenant
        # identity can never be governed safely, so reject it at construction
        # rather than letting an empty tenant flow into policy evaluation.
        if not self.tenant_id:
            raise ValueError("GovernanceRequest.tenant_id is required (fail-closed)")
        if not self.request_id:
            raise ValueError("GovernanceRequest.request_id is required (fail-closed)")


@dataclass(frozen=True)
class TenantPolicyBinding:
    """Binds a tenant to the policy bundle that is authoritative for it.

    A binding answers "which bundle governs tenant X?". Bundle *storage and
    lookup* live in :class:`gove_zone.tenant.TenantPolicyStore`; this type is
    the in-memory, typed assertion of the pairing. Lifecycle state (active /
    stale / revoked) is intentionally not modeled here — the kernel does not
    implement bundle lifecycle yet (see docs/policy-bundles.md, Roadmap).
    """

    tenant_id: str
    policy_bundle: PolicyBundleRef

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("TenantPolicyBinding.tenant_id is required (fail-closed)")


@dataclass(frozen=True)
class AuditEvent:
    """A typed projection over one persisted audit-chain event.

    The audit chain (:class:`gove_zone.audit.ChainHashAuditStore`) persists
    events as bare JSON dicts. ``AuditEvent`` is a read-side view that names
    the fields the governance contract cares about. It does **not** change what
    is written to disk — see :meth:`from_receipt_and_event` for how the
    tenant/request/receipt linkage (which lives on the receipt, not the chain
    record) is joined back in.
    """

    event_id: str
    request_id: str
    receipt_id: str
    tenant_id: str
    actor: str
    action_summary: str
    decision: str
    policy_bundle_id: str
    timestamp: str
    previous_hash: str
    event_hash: str

    @classmethod
    def from_receipt_and_event(cls, receipt: DecisionReceipt, event: dict[str, Any]) -> AuditEvent:
        """Join a receipt with its persisted chain *event* into one view.

        The chain record carries the cryptographic anchor (``event_hash``,
        ``previous_hash``); the receipt carries the governance linkage
        (``tenant_id``, ``request_id``, ``receipt_id``, ``policy_bundle_id``).
        Together they form the complete audit evidence for one decision.
        """
        return cls(
            event_id=str(event.get("event_id", receipt.receipt_id)),
            request_id=receipt.request_id,
            receipt_id=receipt.receipt_id,
            tenant_id=receipt.tenant_id,
            actor=receipt.actor,
            action_summary=receipt.proposed_action,
            decision=receipt.decision,
            policy_bundle_id=receipt.policy_bundle_id,
            timestamp=str(event.get("timestamp_iso", receipt.timestamp)),
            previous_hash=str(event.get("previous_hash", receipt.previous_audit_hash)),
            event_hash=str(event.get("event_hash", receipt.audit_event_hash)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "request_id": self.request_id,
            "receipt_id": self.receipt_id,
            "tenant_id": self.tenant_id,
            "actor": self.actor,
            "action_summary": self.action_summary,
            "decision": self.decision,
            "policy_bundle_id": self.policy_bundle_id,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
        }


class ReceiptVerifier:
    """Typed, reusable verifier bound to a tenant + execution boundary.

    A thin, stateful wrapper over :meth:`DecisionReceipt.verify` — the single
    fail-closed gate. It exists so an executor can construct one verifier for
    its boundary and reuse it across many receipts, rather than re-passing the
    same ``expected_*`` arguments on every call.

    This adds **no** new enforcement logic: every check still lives in
    ``DecisionReceipt.verify``. A ``None`` receipt is rejected here, mirroring
    :func:`gove_zone.executor.execute_with_receipt`.

    ``expected_actor`` (the invoking principal's identity) is **required** at
    construction as the default anchor for the MACI proposer-binding check, and
    may be overridden per-call. Construction with no ``expected_actor`` is a
    ``TypeError``; an empty string fails closed with ``ReceiptValidationError``.
    This keeps the strong check the default at this gate, with no silent
    downgrade to the weak ``validator_id == actor`` heuristic.

    **Production profile is the default.** ``require_signature`` defaults to
    ``True``. A verifier constructed in this posture with no ``verifier`` fails
    closed loud (:class:`~gove_zone.errors.ProductionProfileError`) when
    :meth:`verify` runs. For the explicit unsigned dev mode, construct with
    ``require_signature=False`` (or feed a
    :meth:`gove_zone.profile.GovernanceProfile.dev` bundle). :meth:`is_valid`
    still returns ``False`` in that misconfiguration because
    ``ProductionProfileError`` subclasses ``ReceiptValidationError``.
    """

    def __init__(
        self,
        *,
        expected_tenant_id: str,
        expected_execution_boundary: str,
        expected_actor: str,
        expected_policy_bundle_id: str | None = None,
        expected_policy_hash: str | None = None,
        verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
        require_signature: bool = True,
        require_expiry: bool = False,
    ) -> None:
        if not expected_actor or not expected_actor.strip():
            raise ReceiptValidationError(
                "expected_actor is required for ReceiptVerifier (fail-closed)"
            )
        self.expected_tenant_id = expected_tenant_id
        self.expected_execution_boundary = expected_execution_boundary
        self.expected_actor = expected_actor
        self.expected_policy_bundle_id = expected_policy_bundle_id
        self.expected_policy_hash = expected_policy_hash
        self.verifier = verifier
        self.require_signature = require_signature
        self.require_expiry = require_expiry

    def verify(
        self,
        receipt: DecisionReceipt | None,
        *,
        expected_action: str | None = None,
        expected_args: dict[str, Any] | None = None,
        expected_audit_hash: str | None = None,
        expected_actor: str | None = None,
        now_iso: str | None = None,
    ) -> None:
        """Raise :class:`ReceiptValidationError` unless *receipt* authorizes the action.

        Fail-closed on ``None`` (no receipt → no side effect).

        The MACI proposer-binding anchor defaults to the construction-time
        ``expected_actor``; pass ``expected_actor`` here to override it per-call.
        The anchor — the invoking principal's identity from the caller's runtime
        context — cannot be forged by editing receipt fields. The effective
        anchor must be non-empty or it fails closed.
        """
        if receipt is None:
            raise ReceiptValidationError("No receipt provided for governed execution")
        if self.require_signature and self.verifier is None:
            raise ProductionProfileError(PRODUCTION_NO_VERIFIER_MSG)
        effective_actor = expected_actor if expected_actor is not None else self.expected_actor
        if not effective_actor or not effective_actor.strip():
            raise ReceiptValidationError(
                "expected_actor is required for governed verification (fail-closed)"
            )
        receipt.verify(
            expected_tenant_id=self.expected_tenant_id,
            expected_execution_boundary=self.expected_execution_boundary,
            expected_policy_bundle_id=self.expected_policy_bundle_id,
            expected_policy_hash=self.expected_policy_hash,
            expected_action=expected_action,
            expected_args=expected_args,
            expected_audit_hash=expected_audit_hash,
            expected_actor=effective_actor,
            verifier=self.verifier,
            require_signature=self.require_signature,
            require_expiry=self.require_expiry,
            now_iso=now_iso,
        )

    def is_valid(
        self,
        receipt: DecisionReceipt | None,
        *,
        expected_action: str | None = None,
        expected_args: dict[str, Any] | None = None,
        expected_audit_hash: str | None = None,
        expected_actor: str | None = None,
        now_iso: str | None = None,
    ) -> bool:
        """Boolean form of :meth:`verify` — never raises, returns False on any failure."""
        try:
            self.verify(
                receipt,
                expected_action=expected_action,
                expected_args=expected_args,
                expected_audit_hash=expected_audit_hash,
                expected_actor=expected_actor,
                now_iso=now_iso,
            )
            return True
        except ReceiptValidationError:
            return False
