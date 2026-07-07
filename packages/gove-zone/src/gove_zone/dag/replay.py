"""Offline replay verification of a multi-agent governance DAG.

Given a declared :class:`~gove_zone.dag.graph.GovernanceDAG` and the actual
:class:`~gove_zone.receipt.DecisionReceipt` objects for its receipt nodes,
:func:`verify_dag_replay` re-proves the whole chain without any executor or
ledger present — the multi-agent analogue of
:func:`gove_zone.workflow.verify_workflow_replay`. It **raises** on the first
failure (graph verification raises; policy replay in :mod:`gove_zone.replay`
returns results — both styles exist in the codebase, and this module is graph
verification).

What is proven, fail-closed:

1. The graph is structurally valid and acyclic, and every agent acted inside
   its inherited authority (:func:`gove_zone.dag.authority.validate_authority`).
2. When ``expected_dag_hash`` is supplied (an externally recorded value — a
   plan store, an audit event, a pinned config), the graph presented for
   replay is byte-identical in canonical form to the declared one; topology
   swaps are rejected.
3. Every receipt node is backed by a supplied receipt whose ``receipt_hash``
   equals the node's ``ref`` (node/receipt binding), and no receipt is
   supplied for a non-receipt node (no smuggling).
4. The proposer chain is complete and single-actor: each decision has exactly
   one proposing agent, each receipt exactly one decision, each receipt gates
   exactly one tool call, and each tool call is executed by exactly one agent
   — the same agent that proposed it (``receipt.actor`` binding, matching the
   ``expected_actor`` discipline of the executor gates).
5. Each receipt's ``authority`` names a root grant that actually delivered
   the executed action to the proposer through the delegation graph
   (:func:`gove_zone.dag.authority.resolve_authority_grants`) — a receipt
   minted under an unrelated grant fails even if action and actor match, and
   a grant whose own scope never covered the action cannot justify it merely
   because the agent holds that action under a different grant.
6. Each receipt re-verifies via :meth:`DecisionReceipt.verify` with the
   gated tool call's action and the proposing agent bound in — so a tampered,
   forged, mis-actored, or mis-actioned receipt fails exactly as it would at
   the gate.
7. Every tool call is receipt-gated (no valid Decision Receipt, no side
   effect) and every side effect is produced by a tool call and carries a
   non-empty evidence ``ref``.

Honest scope: with ``require_signature=False`` (default, matching
``verify_workflow_replay``) this proves internal chain consistency, not
unforgeability — pass a verifier and ``require_signature=True`` for the
signed posture. The ``roots`` grants and ``expected_dag_hash`` are the
*premises* of the proof: they must come from a source independent of the
party presenting the chain (see :mod:`gove_zone.dag.authority`).
"""

from __future__ import annotations

from collections.abc import Mapping

from gove_zone.dag.authority import (
    AuthorityGrant,
    resolve_authority_grants,
    validate_authority,
)
from gove_zone.dag.graph import (
    DagValidationError,
    EdgeKind,
    GovernanceDAG,
    GovernanceNode,
    NodeKind,
)
from gove_zone.errors import ReceiptRejectionReason
from gove_zone.receipt import DecisionReceipt
from gove_zone.revocation import RevocationList
from gove_zone.signing import ReceiptSigner


class DagReplayError(DagValidationError):
    """Raised when DAG replay verification fails at the graph level.

    Receipt-level failures raise the underlying
    :class:`~gove_zone.errors.ReceiptValidationError` from
    :meth:`DecisionReceipt.verify` unchanged, so ``reason_code`` taxonomies
    keep working; both land on the same fail-closed catch path. Graph-level
    failures default ``reason_code`` to
    :attr:`~gove_zone.errors.ReceiptRejectionReason.DAG_REPLAY_INVALID`.
    """

    def __init__(self, *args: object, reason_code: ReceiptRejectionReason | None = None) -> None:
        super().__init__(
            *args, reason_code=reason_code or ReceiptRejectionReason.DAG_REPLAY_INVALID
        )


def _sole_edge_src(
    dag: GovernanceDAG,
    node: GovernanceNode,
    kind: EdgeKind,
    src_kind: NodeKind,
    role: str,
) -> str:
    """The single *src_kind* node pointing at *node* via *kind*, fail-closed."""
    sources = [
        e.src for e in dag.edges_into(node.node_id, kind) if dag.nodes[e.src].kind is src_kind
    ]
    if len(sources) != 1:
        raise DagReplayError(
            f"{node.kind} node {node.node_id!r} requires exactly one {role} "
            f"({src_kind} --{kind}--> {node.kind}); found {len(sources)}"
        )
    return sources[0]


def verify_dag_replay(
    dag: GovernanceDAG,
    receipts: Mapping[str, DecisionReceipt],
    *,
    roots: Mapping[str, AuthorityGrant],
    expected_dag_hash: str | None = None,
    verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
    require_signature: bool = False,
    revoked_keys: RevocationList | None = None,
) -> None:
    """Offline, fail-closed replay verification of the whole governance DAG.

    ``receipts`` maps receipt **node ids** to the actual
    :class:`DecisionReceipt` objects. ``expected_dag_hash``, when supplied,
    pins the graph to an externally recorded declaration (``None`` skips the
    binding, mirroring the ``expected_*`` convention of
    :meth:`DecisionReceipt.verify`). Raises :class:`DagReplayError` (graph
    level) or :class:`~gove_zone.errors.ReceiptValidationError` (receipt
    level) on the first failure; returns ``None`` when every check passes.
    """
    validate_authority(dag, roots)
    grants = resolve_authority_grants(dag, roots)

    if expected_dag_hash is not None and expected_dag_hash != dag.dag_hash():
        raise DagReplayError(
            "governance DAG hash mismatch: the graph presented for replay is not the declared one"
        )

    receipt_node_ids = {node.node_id for node in dag.nodes_of_kind(NodeKind.RECEIPT)}
    unknown = set(receipts) - receipt_node_ids
    if unknown:
        raise DagReplayError(
            f"receipts supplied for non-receipt or unknown node ids: {sorted(unknown)!r}"
        )

    for receipt_node in dag.nodes_of_kind(NodeKind.RECEIPT):
        receipt = receipts.get(receipt_node.node_id)
        if receipt is None:
            raise DagReplayError(f"receipt node {receipt_node.node_id!r} has no supplied receipt")
        if not receipt_node.ref or receipt_node.ref != receipt.receipt_hash:
            raise DagReplayError(
                f"receipt node {receipt_node.node_id!r} ref does not match the "
                "supplied receipt's receipt_hash"
            )

        # Provenance: exactly one decision approved into this receipt, and
        # exactly one agent proposed that decision.
        decision_id = _sole_edge_src(
            dag, receipt_node, EdgeKind.APPROVAL, NodeKind.DECISION, "approving decision"
        )
        decision = dag.nodes[decision_id]
        proposer = _sole_edge_src(
            dag, decision, EdgeKind.APPROVAL, NodeKind.AGENT, "proposing agent"
        )
        if decision.action != receipt.proposed_action:
            raise DagReplayError(
                f"decision {decision_id!r} action {decision.action!r} does not match "
                f"receipt {receipt_node.node_id!r} proposed_action "
                f"{receipt.proposed_action!r}"
            )

        # The receipt's claimed authority must have actually delivered THIS
        # action to the proposer — a label that reached the agent carrying
        # only other actions cannot justify this one (joint label-action
        # binding, not two independent checks).
        delivered = grants.get(proposer, {}).get(receipt.authority, frozenset())
        if decision.action not in delivered:
            raise DagReplayError(
                f"receipt {receipt_node.node_id!r} authority {receipt.authority!r} "
                f"never delivered action {decision.action!r} to proposer "
                f"{proposer!r} (delivered under that grant: {sorted(delivered)!r})"
            )

        # One receipt authorizes exactly one execution (single-use discipline).
        gated = [
            e.dst
            for e in dag.edges_from(receipt_node.node_id, EdgeKind.EXECUTION)
            if dag.nodes[e.dst].kind is NodeKind.TOOL_CALL
        ]
        if len(gated) != 1:
            raise DagReplayError(
                f"receipt node {receipt_node.node_id!r} must gate exactly one tool "
                f"call; found {len(gated)}"
            )
        tool_call = dag.nodes[gated[0]]

        # Single-actor binding: the executing agent is the proposing agent,
        # mirroring the expected_actor discipline at the executor gates.
        executor = _sole_edge_src(
            dag, tool_call, EdgeKind.EXECUTION, NodeKind.AGENT, "executing agent"
        )
        if executor != proposer:
            raise DagReplayError(
                f"tool call {tool_call.node_id!r} executed by {executor!r} but "
                f"proposed by {proposer!r}; proposer and executor must be the same "
                "agent (receipt.actor binding)"
            )

        # Re-verify the receipt exactly as a gate would, with the graph's
        # action and actor bindings folded in. Raises ReceiptValidationError.
        receipt.verify(
            expected_action=tool_call.action,
            expected_actor=proposer,
            verifier=verifier,
            require_signature=require_signature,
            revoked_keys=revoked_keys,
        )

    # Every decision must materialize into exactly one receipt — an approved
    # decision with zero receipts (or one fanned into several) is untracked
    # authority.
    for decision_node in dag.nodes_of_kind(NodeKind.DECISION):
        materialized = [
            e.dst
            for e in dag.edges_from(decision_node.node_id, EdgeKind.APPROVAL)
            if dag.nodes[e.dst].kind is NodeKind.RECEIPT
        ]
        if len(materialized) != 1:
            raise DagReplayError(
                f"decision {decision_node.node_id!r} must materialize into exactly "
                f"one receipt; found {len(materialized)}"
            )

    # No valid Decision Receipt, no side effect: every tool call must be
    # gated by exactly one receipt, and every side effect must come from a
    # tool call and carry evidence.
    for tool_call in dag.nodes_of_kind(NodeKind.TOOL_CALL):
        _sole_edge_src(dag, tool_call, EdgeKind.EXECUTION, NodeKind.RECEIPT, "gating receipt")

    for side_effect in dag.nodes_of_kind(NodeKind.SIDE_EFFECT):
        producers = [
            e.src
            for e in dag.edges_into(side_effect.node_id, EdgeKind.EXECUTION)
            if dag.nodes[e.src].kind is NodeKind.TOOL_CALL
        ]
        if not producers:
            raise DagReplayError(f"side effect {side_effect.node_id!r} has no producing tool call")
        if not side_effect.ref:
            raise DagReplayError(f"side effect {side_effect.node_id!r} carries no evidence ref")
