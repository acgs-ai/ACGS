"""Governance DAG replay — offline re-verification of a multi-agent chain.

The invariant under test: ``verify_dag_replay`` re-proves the whole declared
chain against the real receipts, fail-closed. Every receipt must re-verify
with the graph's action/actor bindings folded in; every tool call must be
receipt-gated; every side effect must be produced and evidenced. Receipts are
minted the same way as in ``test_workflow_receipt_chain``.
"""

from __future__ import annotations

import dataclasses

import pytest

from gove_zone import (
    AuthorityGrant,
    DagReplayError,
    Decision,
    DecisionReceipt,
    DecisionRecord,
    EdgeKind,
    GovernanceDAG,
    GovernanceEdge,
    GovernanceNode,
    NodeKind,
    ReceiptRejectionReason,
    ReceiptValidationError,
    Validator,
    verify_dag_replay,
)
from gove_zone.decision import sha256_json

TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
DELEGATOR = "agent-a"
WORKER = "agent-b"
VALIDATOR = Validator("constitutional-council")
AUTHORITY = "tenant-A/write-grant"
ACTION = "runtime.file.write"


def _receipt(
    *,
    action: str = ACTION,
    actor: str = WORKER,
    decision: Decision = Decision.ALLOW,
    event_id: str = "ev-1",
) -> DecisionReceipt:
    record = DecisionRecord(
        decision=decision,
        tool=action,
        argument_hash=sha256_json({"path": "/tmp/out.txt"}),
        policy_version="v1",
        event_id=event_id,
        actor=actor,
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id=TENANT,
        execution_boundary=BOUNDARY,
        policy_bundle_id="policy-bundle",
        policy_hash="policy-hash",
        request_id="req-" + event_id,
        validator=VALIDATOR,
        authority=AUTHORITY,
    )


def _chain(
    receipt: DecisionReceipt,
    *,
    edges_override: tuple[GovernanceEdge, ...] | None = None,
    receipt_ref: str | None = None,
    evidence_ref: str = "sha256:artifact",
) -> GovernanceDAG:
    """The canonical chain: a delegates to b; b proposes, executes, evidences."""
    edges = edges_override or (
        GovernanceEdge(DELEGATOR, WORKER, EdgeKind.AUTHORITY_DELEGATION, scope=(ACTION,)),
        GovernanceEdge(WORKER, "dec", EdgeKind.APPROVAL),
        GovernanceEdge("dec", "rcpt", EdgeKind.APPROVAL),
        GovernanceEdge("rcpt", "call", EdgeKind.EXECUTION),
        GovernanceEdge(WORKER, "call", EdgeKind.EXECUTION),
        GovernanceEdge("call", "fx", EdgeKind.EXECUTION),
    )
    return GovernanceDAG(
        nodes={
            DELEGATOR: GovernanceNode(DELEGATOR, NodeKind.AGENT),
            WORKER: GovernanceNode(WORKER, NodeKind.AGENT),
            "dec": GovernanceNode("dec", NodeKind.DECISION, action=ACTION),
            "rcpt": GovernanceNode(
                "rcpt",
                NodeKind.RECEIPT,
                ref=receipt.receipt_hash if receipt_ref is None else receipt_ref,
            ),
            "call": GovernanceNode("call", NodeKind.TOOL_CALL, action=ACTION),
            "fx": GovernanceNode("fx", NodeKind.SIDE_EFFECT, ref=evidence_ref),
        },
        edges=edges,
    )


# The root grant's authority label matches the receipts' AUTHORITY — replay
# cross-checks that the label actually reached the proposer.
ROOTS = {DELEGATOR: AuthorityGrant(DELEGATOR, AUTHORITY, frozenset({ACTION}))}


def test_happy_chain_passes() -> None:
    receipt = _receipt()
    verify_dag_replay(_chain(receipt), {"rcpt": receipt}, roots=ROOTS)


def test_expected_dag_hash_binding_passes() -> None:
    receipt = _receipt()
    dag = _chain(receipt)
    verify_dag_replay(dag, {"rcpt": receipt}, roots=ROOTS, expected_dag_hash=dag.dag_hash())


def test_expected_dag_hash_mismatch_rejected() -> None:
    # The declared hash pins the topology; presenting a different (individually
    # valid) graph for replay is rejected.
    receipt = _receipt()
    dag = _chain(receipt)
    with pytest.raises(DagReplayError, match="hash mismatch"):
        verify_dag_replay(dag, {"rcpt": receipt}, roots=ROOTS, expected_dag_hash="not-the-hash")


def test_unrelated_authority_label_rejected() -> None:
    # Grant covers the action but under a different authority label than the
    # receipt claims — action/actor match alone must not be enough.
    receipt = _receipt()
    roots = {DELEGATOR: AuthorityGrant(DELEGATOR, "tenant-B/other-grant", frozenset({ACTION}))}
    with pytest.raises(DagReplayError, match="never empowered"):
        verify_dag_replay(_chain(receipt), {"rcpt": receipt}, roots=roots)


def test_graph_level_errors_carry_reason_code() -> None:
    receipt = _receipt()
    with pytest.raises(DagReplayError) as exc:
        verify_dag_replay(_chain(receipt), {}, roots=ROOTS)
    assert exc.value.reason_code is ReceiptRejectionReason.DAG_REPLAY_INVALID


def test_missing_receipt_rejected() -> None:
    receipt = _receipt()
    with pytest.raises(DagReplayError, match="no supplied receipt"):
        verify_dag_replay(_chain(receipt), {}, roots=ROOTS)


def test_receipt_for_unknown_node_rejected() -> None:
    receipt = _receipt()
    with pytest.raises(DagReplayError, match="non-receipt or unknown"):
        verify_dag_replay(_chain(receipt), {"rcpt": receipt, "call": receipt}, roots=ROOTS)


def test_node_ref_mismatch_rejected() -> None:
    receipt = _receipt()
    dag = _chain(receipt, receipt_ref="not-the-receipt-hash")
    with pytest.raises(DagReplayError, match="ref does not match"):
        verify_dag_replay(dag, {"rcpt": receipt}, roots=ROOTS)


def test_empty_node_ref_rejected() -> None:
    receipt = _receipt()
    dag = _chain(receipt, receipt_ref="")
    with pytest.raises(DagReplayError, match="ref does not match"):
        verify_dag_replay(dag, {"rcpt": receipt}, roots=ROOTS)


def test_tampered_receipt_rejected() -> None:
    receipt = _receipt()
    dag = _chain(receipt)
    tampered = dataclasses.replace(receipt, declared_goal="exfiltrate")
    # The node still binds the original hash; the tampered body no longer
    # matches its own receipt_hash, exactly as at a gate.
    with pytest.raises(ReceiptValidationError) as exc:
        verify_dag_replay(dag, {"rcpt": tampered}, roots=ROOTS)
    assert exc.value.reason_code is ReceiptRejectionReason.RECEIPT_HASH_MISMATCH


def test_denied_receipt_never_replays_as_executed(  # no valid receipt, no side effect
) -> None:
    receipt = _receipt(decision=Decision.DENY)
    dag = _chain(receipt)
    with pytest.raises(ReceiptValidationError) as exc:
        verify_dag_replay(dag, {"rcpt": receipt}, roots=ROOTS)
    assert exc.value.reason_code is ReceiptRejectionReason.DENIED_RECEIPT


def test_wrong_actor_receipt_rejected() -> None:
    # Receipt minted by the delegator, chain says the worker proposed/executed.
    receipt = _receipt(actor=DELEGATOR)
    dag = _chain(receipt)
    with pytest.raises(ReceiptValidationError) as exc:
        verify_dag_replay(dag, {"rcpt": receipt}, roots=ROOTS)
    assert exc.value.reason_code is ReceiptRejectionReason.ACTOR_MISMATCH


def test_receipt_action_vs_tool_call_rejected() -> None:
    receipt = _receipt(action="runtime.http.get")
    dag = _chain(receipt)  # decision/call nodes still say ACTION
    with pytest.raises(DagReplayError, match="does not match"):
        verify_dag_replay(dag, {"rcpt": receipt}, roots=ROOTS)


def _edges_without(
    dag_edges: tuple[GovernanceEdge, ...], **match: object
) -> tuple[GovernanceEdge, ...]:
    return tuple(
        e for e in dag_edges if not all(getattr(e, key) == value for key, value in match.items())
    )


def test_receipt_without_decision_rejected() -> None:
    receipt = _receipt()
    base = _chain(receipt)
    dag = GovernanceDAG(nodes=base.nodes, edges=_edges_without(base.edges, src="dec", dst="rcpt"))
    with pytest.raises(DagReplayError, match="exactly one approving decision"):
        verify_dag_replay(dag, {"rcpt": receipt}, roots=ROOTS)


def test_decision_without_proposer_rejected() -> None:
    receipt = _receipt()
    base = _chain(receipt)
    dag = GovernanceDAG(nodes=base.nodes, edges=_edges_without(base.edges, src=WORKER, dst="dec"))
    with pytest.raises(DagReplayError, match="exactly one proposing agent"):
        verify_dag_replay(dag, {"rcpt": receipt}, roots=ROOTS)


def test_receipt_gating_nothing_rejected() -> None:
    receipt = _receipt()
    base = _chain(receipt)
    dag = GovernanceDAG(nodes=base.nodes, edges=_edges_without(base.edges, src="rcpt", dst="call"))
    with pytest.raises(DagReplayError, match="exactly one tool"):
        verify_dag_replay(dag, {"rcpt": receipt}, roots=ROOTS)


def test_receipt_gating_two_calls_rejected() -> None:
    receipt = _receipt()
    base = _chain(receipt)
    nodes = dict(base.nodes)
    nodes["call2"] = GovernanceNode("call2", NodeKind.TOOL_CALL, action=ACTION)
    edges = (
        *base.edges,
        GovernanceEdge("rcpt", "call2", EdgeKind.EXECUTION),
        GovernanceEdge(WORKER, "call2", EdgeKind.EXECUTION),
    )
    with pytest.raises(DagReplayError, match="exactly one tool"):
        verify_dag_replay(GovernanceDAG(nodes=nodes, edges=edges), {"rcpt": receipt}, roots=ROOTS)


def test_executor_differs_from_proposer_rejected() -> None:
    receipt = _receipt()
    base = _chain(receipt)
    # Re-point the executing edge at the delegator (worker still proposes).
    edges = (
        *_edges_without(base.edges, src=WORKER, dst="call"),
        GovernanceEdge(DELEGATOR, "call", EdgeKind.EXECUTION),
    )
    with pytest.raises(DagReplayError, match="must be the same"):
        verify_dag_replay(
            GovernanceDAG(nodes=base.nodes, edges=edges), {"rcpt": receipt}, roots=ROOTS
        )


def test_ungoverned_tool_call_rejected() -> None:
    receipt = _receipt()
    base = _chain(receipt)
    nodes = dict(base.nodes)
    nodes["rogue"] = GovernanceNode("rogue", NodeKind.TOOL_CALL, action=ACTION)
    edges = (*base.edges, GovernanceEdge(WORKER, "rogue", EdgeKind.EXECUTION))
    with pytest.raises(DagReplayError, match="exactly one gating receipt"):
        verify_dag_replay(GovernanceDAG(nodes=nodes, edges=edges), {"rcpt": receipt}, roots=ROOTS)


def test_unmaterialized_decision_rejected() -> None:
    receipt = _receipt()
    base = _chain(receipt)
    nodes = dict(base.nodes)
    nodes["dec2"] = GovernanceNode("dec2", NodeKind.DECISION, action=ACTION)
    edges = (*base.edges, GovernanceEdge(WORKER, "dec2", EdgeKind.APPROVAL))
    with pytest.raises(DagReplayError, match="materialize into exactly"):
        verify_dag_replay(GovernanceDAG(nodes=nodes, edges=edges), {"rcpt": receipt}, roots=ROOTS)


def test_side_effect_without_producer_rejected() -> None:
    receipt = _receipt()
    base = _chain(receipt)
    dag = GovernanceDAG(nodes=base.nodes, edges=_edges_without(base.edges, src="call", dst="fx"))
    with pytest.raises(DagReplayError, match="no producing tool call"):
        verify_dag_replay(dag, {"rcpt": receipt}, roots=ROOTS)


def test_side_effect_without_evidence_rejected() -> None:
    receipt = _receipt()
    dag = _chain(receipt, evidence_ref="")
    with pytest.raises(DagReplayError, match="no evidence ref"):
        verify_dag_replay(dag, {"rcpt": receipt}, roots=ROOTS)
