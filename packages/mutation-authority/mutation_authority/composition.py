"""Two-receipt composition: gove-zone action authorization ⊕ mutation authorization.

DESIGN-PROOF MODULE — NOT A WIRED ENFORCEMENT PATH.

This module expresses, and lets the adversarial proof exercise, the binding
by which a gove-zone *action* authorization (a ``DecisionReceipt`` — "may this
actor run this classified command") is composed with a mutation-authority
*state-transition* authorization (a ``MutationDecisionReceipt`` — "may this
exact path go from hash X to hash Y") so that **neither can launder the
other**. It is the concrete form of deliverable §3.

It deliberately does NOT import gove_zone: the gove-zone side is represented by
``GovernedActionClaim``, a frozen contract shape mirroring the fields of a real
``gove_zone.receipt.DecisionReceipt`` that the binding depends on. The real
wiring (blocked — see REPORT.md) would pass the genuine DecisionReceipt and
would live at the gove-zone effect boundary (``executor.py`` ``execute_with_receipt``),
not here. Nothing in this file mutates a repository or proves gove-zone calls it.

Binding rule (anti-laundering):

* ordering is fixed — classify → gove-zone action decision → Mutation Intent →
  mutation decision → effect; the API makes the action claim a *precondition
  argument*, so the effect cannot precede it;
* a gove-zone DENY (or any non-ALLOW) yields zero mutation — the gateway is
  never reached;
* the Mutation Intent's ``task_reference`` MUST equal the action claim's
  ``effect_id`` — so a mutation receipt issued for effect A cannot satisfy
  action B, and an action authorization for a benign command cannot be paired
  with a mutation receipt minted for a different effect;
* the action claim's declared target resource MUST equal the mutation's
  resource — an ALLOW to run command C cannot authorize writing an unrelated
  path.
"""

from __future__ import annotations

from dataclasses import dataclass

from .adapters import AuthorityContext, GatewayResult, MutationGateway

REFUSED = "REFUSED"


@dataclass(frozen=True)
class GovernedActionClaim:
    """Contract shape mirroring the gove-zone ``DecisionReceipt`` fields the
    binding relies on. In real wiring this is the genuine DecisionReceipt.

    ``decision`` is the gove-zone verdict ("allow" | "deny" | "ask").
    ``effect_id`` is the gove-zone effect/receipt identifier that the mutation
    ``task_reference`` must echo. ``target_resource`` is the repository path the
    classified action declares it will affect.
    """

    effect_id: str
    actor: str
    action_kind: str
    classified_command: str
    target_resource: str
    decision: str


@dataclass(frozen=True)
class ComposedResult:
    status: str  # APPLIED | DENIED | REJECTED | REFUSED
    reason: str
    effect_id: str | None = None
    mutation_receipt_id: str | None = None
    evidence_id: str | None = None


def compose_mutation(
    action: GovernedActionClaim,
    gateway: MutationGateway,
    context: AuthorityContext,
    resource: str,
    operation: str,
    new_content: bytes | None,
) -> ComposedResult:
    """Bind a gove-zone action authorization to a mutation authorization.

    Returns REFUSED (with zero mutation attempted) if the gove-zone leg does
    not authorize, if identities/targets do not agree, or if the binding
    between the two receipts would not hold. Otherwise defers to the mutation
    gateway and surfaces both identifiers for evidence.
    """
    # 1. gove-zone must have ALLOWED the action. A DENY/ASK laundering attempt
    #    stops here — the mutation gateway is never called, so zero state change.
    if action.decision != "allow":
        return ComposedResult(
            REFUSED,
            f"gove-zone action not authorized (decision={action.decision!r}); "
            "mutation refused before any effect",
            effect_id=action.effect_id,
        )

    # 2. Identity binding: the actor authorized for the action is the actor
    #    that must carry the mutation.
    if action.actor != context.actor_id:
        return ComposedResult(
            REFUSED,
            f"actor mismatch: action authorized for {action.actor!r}, "
            f"mutation presented by {context.actor_id!r}",
            effect_id=action.effect_id,
        )

    # 3. Target binding: the action's declared resource must be the mutation's
    #    resource. An ALLOW to run a command cannot authorize an unrelated path.
    if action.target_resource != resource:
        return ComposedResult(
            REFUSED,
            f"target mismatch: action targets {action.target_resource!r}, "
            f"mutation targets {resource!r}",
            effect_id=action.effect_id,
        )

    # 4. Receipt binding: the mutation intent's task_reference is pinned to the
    #    gove-zone effect_id. The gateway builds the intent's task_reference
    #    from context.task_reference, so we require the caller to have set it to
    #    the effect_id — enforced here so a receipt for effect A cannot be
    #    replayed to satisfy action B.
    if context.task_reference != action.effect_id:
        return ComposedResult(
            REFUSED,
            "receipt binding broken: mutation task_reference "
            f"({context.task_reference!r}) is not pinned to the gove-zone "
            f"effect_id ({action.effect_id!r})",
            effect_id=action.effect_id,
        )

    # 5. Both legs agree — defer to the mutation gateway for the state-transition
    #    authorization + effect. The gateway independently re-verifies actor,
    #    scope, task authority, pre-state binding, concurrency, and emits
    #    evidence. This module adds NO new writable surface.
    result: GatewayResult = gateway.request_mutation(context, resource, operation, new_content)
    return ComposedResult(
        status=result.status,
        reason=result.reason,
        effect_id=action.effect_id,
        mutation_receipt_id=(result.receipt.receipt_id if result.receipt else None),
        evidence_id=result.evidence_id,
    )


def composed_evidence_fields(action: GovernedActionClaim, result: ComposedResult) -> dict:
    """The fields a fully-wired integration would bind into ONE evidence record
    so the effect is traceable across both layers (deliverable §7). Provided so
    the proof can assert both identifiers are present and agree."""
    return {
        "actor": action.actor,
        "action_kind": action.action_kind,
        "gove_zone_effect_id": action.effect_id,
        "classified_command": action.classified_command,
        "resource": action.target_resource,
        "mutation_receipt_id": result.mutation_receipt_id,
        "mutation_evidence_id": result.evidence_id,
        "status": result.status,
    }
