"""A2A receipt-gated delegation — agent→agent delegation bound to the gate.

Wave 3 (Plug). This is a **pure composition** over the sealed gove-zone kernel:
it calls the existing PUBLIC primitives (:func:`evaluate_tenant_action`,
:func:`execute_with_receipt`) and reimplements no gate logic. The property it
adds is an honest agent→agent delegation boundary: a *remote* agent runs a
delegated action **only** through the gate, bound to the **delegating**
principal. No valid Decision Receipt for that delegating actor → the remote
side effect never runs.

Scope (honest): this mirrors the A2A delegation *contract* (client agent →
AgentCard-identified remote agent → delegated task); it does NOT depend on the
``a2a`` SDK and does NOT implement transport, discovery, or JSON-RPC. It is a
mechanism demonstration, not a compliance artifact.

Trust boundary (load-bearing): ``authenticated_delegator`` MUST be the
transport-authenticated identity of the calling agent (mutual TLS / signed JWT /
A2A handshake). This module consumes an already-authenticated identity; it does
not establish one. Passing an unauthenticated or caller-chosen string here voids
the actor-binding guarantee — the gate binds the receipt to this value but
cannot itself authenticate it.

Zero runtime deps: importing this module never imports ``cryptography``. Only the
signed path (a signer at mint, a verifier at the server) requires the optional
``crypto`` extra, lazily through :mod:`gove_zone.signing`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from gove_zone.audit import ChainHashAuditStore
from gove_zone.errors import ReceiptValidationError
from gove_zone.executor import execute_with_receipt
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.signing import ReceiptSigner
from gove_zone.tenant import TenantPolicyStore, evaluate_tenant_action


@dataclass(frozen=True)
class AgentCard:
    """Minimal A2A-shaped identity for a remote agent (no discovery service).

    ``capabilities`` is advisory metadata only — the server's registry is the
    authoritative source of which actions can actually run.
    """

    agent_id: str
    execution_boundary: str
    capabilities: tuple[str, ...] = ()


@dataclass(frozen=True)
class DelegatedTask:
    """A delegated unit of work: the action and the exact args it must run with."""

    action: str
    args: Mapping[str, Any]
    declared_goal: str = ""


class A2ADelegationError(Exception):
    """Raised when a delegated task is not admissible at the remote boundary.

    Wraps the underlying :class:`~gove_zone.errors.ReceiptValidationError` so
    callers get one A2A-level exception type for every fail-closed vector.
    """


def mint_delegation(
    *,
    store: TenantPolicyStore,
    audit_store: ChainHashAuditStore,
    delegating_actor: str,
    task: DelegatedTask,
    tenant_id: str,
    execution_boundary: str,
    request_id: str,
    validator: Validator,
    authority: str,
    signer: ReceiptSigner | None = None,
) -> DecisionReceipt:
    """Delegating side: mint a (optionally signed) Decision Receipt.

    Binds the delegated action+args to ``delegating_actor`` (the receipt's
    proposer/``actor``). Pure composition over :func:`evaluate_tenant_action`.

    MACI is preserved by the kernel: if ``validator`` equals ``delegating_actor``
    the kernel raises :class:`~gove_zone.errors.ReceiptValidationError`
    (self-validation) — that error is surfaced raw, not wrapped.
    """
    return evaluate_tenant_action(
        store=store,
        tenant_id=tenant_id,
        requester_tenant_id=tenant_id,  # same-tenant delegation only (v1 scope)
        action=task.action,
        args=dict(task.args),
        goal=task.declared_goal,
        execution_boundary=execution_boundary,
        request_id=request_id,
        actor=delegating_actor,
        validator=validator,
        authority=authority,
        audit_store=audit_store,
        signer=signer,
    )


class GovernedA2AServer:
    """Remote side: accepts delegated tasks and runs them ONLY via the gate."""

    def __init__(
        self,
        *,
        card: AgentCard,
        tenant_id: str,
        verifier: ReceiptSigner | None = None,
        require_signature: bool = True,
    ) -> None:
        # Secure by default (constraint 6). A2A crosses trust boundaries, so the
        # server is signed-by-default. Fail closed on a contradictory config:
        # demanding signatures with no verifier can never verify anything.
        # require_signature=False is the EXPLICIT unsigned same-domain opt-in.
        if require_signature and verifier is None:
            raise ValueError("signed A2A server requires a verifier")
        self.card = card
        self.tenant_id = tenant_id
        self.verifier = verifier
        self.require_signature = require_signature
        self._registry: dict[str, Callable[..., Any]] = {}

    def register(self, action: str, fn: Callable[..., Any]) -> None:
        """Register the real side-effecting handler for ``action``.

        The registry is authoritative: the registered fn is reachable ONLY
        through :meth:`accept_delegation` (i.e. only through the gate).
        """
        self._registry[action] = fn

    def accept_delegation(
        self,
        *,
        authenticated_delegator: str,
        task: DelegatedTask,
        receipt: DecisionReceipt | None,
    ) -> Any:
        """Run ``task.action(**task.args)`` iff the gate admits ``receipt``.

        ``authenticated_delegator`` is the transport-authenticated caller id, a
        parameter SEPARATE from the receipt. It is passed to the gate as
        ``expected_actor`` — NEVER ``receipt.actor``, which the receipt author
        could forge. A receipt whose ``actor`` != ``authenticated_delegator`` is
        rejected by the kernel; the server must not "fix up" the mismatch.

        Raises :class:`A2ADelegationError` (wrapping
        :class:`~gove_zone.errors.ReceiptValidationError`) on any fail-closed
        vector — missing receipt, wrong delegator, substituted args, tampered or
        unsigned/forged signature.
        """
        fn = self._registry.get(task.action)
        if fn is None:
            raise A2ADelegationError(f"no handler registered for action {task.action!r}")
        try:
            return execute_with_receipt(
                tool_fn=fn,
                args=dict(task.args),
                receipt=receipt,
                expected_tenant_id=self.tenant_id,
                expected_execution_boundary=self.card.execution_boundary,
                expected_action=task.action,
                expected_actor=authenticated_delegator,
                verifier=self.verifier,
                require_signature=self.require_signature,
            )
        except ReceiptValidationError as exc:
            raise A2ADelegationError(str(exc)) from exc
