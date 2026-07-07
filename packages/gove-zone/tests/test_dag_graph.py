"""Governance DAG structure — typed nodes/edges, fail-closed validation.

Every negative path asserts :class:`DagValidationError` (which subclasses
``ReceiptValidationError``, so graph defects stay on the single fail-closed
refusal path). Hash tests prove ``dag_hash`` is declaration-order independent
but structure sensitive.
"""

from __future__ import annotations

import pytest

from gove_zone import (
    DagValidationError,
    EdgeKind,
    GovernanceDAG,
    GovernanceEdge,
    GovernanceNode,
    NodeKind,
    ReceiptValidationError,
)

ACTION = "runtime.file.write"


def _agent(node_id: str) -> GovernanceNode:
    return GovernanceNode(node_id, NodeKind.AGENT)


def _chain_nodes() -> dict[str, GovernanceNode]:
    return {
        "a": _agent("a"),
        "b": _agent("b"),
        "dec": GovernanceNode("dec", NodeKind.DECISION, action=ACTION),
        "rcpt": GovernanceNode("rcpt", NodeKind.RECEIPT, ref="rhash"),
        "call": GovernanceNode("call", NodeKind.TOOL_CALL, action=ACTION),
        "fx": GovernanceNode("fx", NodeKind.SIDE_EFFECT, ref="evidence"),
    }


def _chain_edges() -> tuple[GovernanceEdge, ...]:
    return (
        GovernanceEdge("a", "b", EdgeKind.AUTHORITY_DELEGATION, scope=(ACTION,)),
        GovernanceEdge("b", "dec", EdgeKind.APPROVAL),
        GovernanceEdge("dec", "rcpt", EdgeKind.APPROVAL),
        GovernanceEdge("rcpt", "call", EdgeKind.EXECUTION),
        GovernanceEdge("b", "call", EdgeKind.EXECUTION),
        GovernanceEdge("call", "fx", EdgeKind.EXECUTION),
    )


def _chain_dag() -> GovernanceDAG:
    return GovernanceDAG(nodes=_chain_nodes(), edges=_chain_edges())


class TestNodeConstruction:
    def test_empty_node_id_rejected(self) -> None:
        with pytest.raises(DagValidationError, match="non-empty node_id"):
            GovernanceNode("", NodeKind.AGENT)

    @pytest.mark.parametrize("kind", [NodeKind.DECISION, NodeKind.TOOL_CALL])
    def test_action_kinds_require_action(self, kind: NodeKind) -> None:
        with pytest.raises(DagValidationError, match="requires a non-empty action"):
            GovernanceNode("n", kind)

    @pytest.mark.parametrize("kind", [NodeKind.AGENT, NodeKind.RECEIPT, NodeKind.SIDE_EFFECT])
    def test_non_action_kinds_reject_action(self, kind: NodeKind) -> None:
        with pytest.raises(DagValidationError, match="must not carry an action"):
            GovernanceNode("n", kind, action=ACTION)


class TestEdgeConstruction:
    def test_empty_endpoints_rejected(self) -> None:
        with pytest.raises(DagValidationError, match="non-empty src and dst"):
            GovernanceEdge("", "b", EdgeKind.DEPENDENCY)

    def test_delegation_requires_scope(self) -> None:
        with pytest.raises(DagValidationError, match="requires a\\s+non-empty scope"):
            GovernanceEdge("a", "b", EdgeKind.AUTHORITY_DELEGATION)

    def test_delegation_rejects_empty_action_in_scope(self) -> None:
        with pytest.raises(DagValidationError, match="non-empty action names"):
            GovernanceEdge("a", "b", EdgeKind.AUTHORITY_DELEGATION, scope=(ACTION, ""))

    @pytest.mark.parametrize("kind", [EdgeKind.APPROVAL, EdgeKind.DEPENDENCY, EdgeKind.EXECUTION])
    def test_scope_forbidden_off_delegation(self, kind: EdgeKind) -> None:
        with pytest.raises(DagValidationError, match="must not carry a scope"):
            GovernanceEdge("a", "b", kind, scope=(ACTION,))


class TestValidate:
    def test_valid_chain_passes(self) -> None:
        _chain_dag().validate()

    def test_error_is_receipt_validation_error(self) -> None:
        # Fail-closed path compatibility: one catch site refuses everything.
        assert issubclass(DagValidationError, ReceiptValidationError)

    def test_key_node_id_mismatch(self) -> None:
        dag = GovernanceDAG(nodes={"x": _agent("y")})
        with pytest.raises(DagValidationError, match="node id mismatch"):
            dag.validate()

    def test_missing_endpoint(self) -> None:
        dag = GovernanceDAG(
            nodes={"a": _agent("a")},
            edges=(GovernanceEdge("a", "ghost", EdgeKind.DEPENDENCY),),
        )
        with pytest.raises(DagValidationError, match="missing node 'ghost'"):
            dag.validate()

    def test_self_loop(self) -> None:
        dag = GovernanceDAG(
            nodes={"a": _agent("a")},
            edges=(GovernanceEdge("a", "a", EdgeKind.DEPENDENCY),),
        )
        with pytest.raises(DagValidationError, match="self-loop"):
            dag.validate()

    def test_duplicate_edge(self) -> None:
        dag = GovernanceDAG(
            nodes={"a": _agent("a"), "b": _agent("b")},
            edges=(
                GovernanceEdge("a", "b", EdgeKind.DEPENDENCY),
                GovernanceEdge("a", "b", EdgeKind.DEPENDENCY),
            ),
        )
        with pytest.raises(DagValidationError, match="duplicate"):
            dag.validate()

    @pytest.mark.parametrize(
        ("src", "dst", "kind"),
        [
            ("a", "rcpt", EdgeKind.AUTHORITY_DELEGATION),  # delegation to non-agent
            ("a", "rcpt", EdgeKind.APPROVAL),  # agent may not approve a receipt
            ("rcpt", "fx", EdgeKind.EXECUTION),  # receipt may not produce evidence
            ("dec", "call", EdgeKind.EXECUTION),  # decision may not execute
        ],
    )
    def test_endpoint_typing_rejected(self, src: str, dst: str, kind: EdgeKind) -> None:
        scope = (ACTION,) if kind is EdgeKind.AUTHORITY_DELEGATION else ()
        dag = GovernanceDAG(
            nodes=_chain_nodes(), edges=(GovernanceEdge(src, dst, kind, scope=scope),)
        )
        with pytest.raises(DagValidationError, match="not a permitted"):
            dag.validate()

    def test_dependency_is_unrestricted_across_kinds(self) -> None:
        dag = GovernanceDAG(
            nodes=_chain_nodes(),
            edges=(GovernanceEdge("fx", "dec", EdgeKind.DEPENDENCY),),
        )
        dag.validate()

    def test_delegation_cycle_detected(self) -> None:
        dag = GovernanceDAG(
            nodes={"a": _agent("a"), "b": _agent("b")},
            edges=(
                GovernanceEdge("a", "b", EdgeKind.AUTHORITY_DELEGATION, scope=(ACTION,)),
                GovernanceEdge("b", "a", EdgeKind.AUTHORITY_DELEGATION, scope=(ACTION,)),
            ),
        )
        with pytest.raises(DagValidationError, match="cycle"):
            dag.validate()

    def test_mixed_kind_cycle_detected(self) -> None:
        # A dependency edge closing a loop through typed edges is still a cycle.
        edges = (*_chain_edges(), GovernanceEdge("fx", "a", EdgeKind.DEPENDENCY))
        dag = GovernanceDAG(nodes=_chain_nodes(), edges=edges)
        with pytest.raises(DagValidationError, match="cycle"):
            dag.validate()


class TestTopologicalOrder:
    def test_order_respects_edges(self) -> None:
        order = _chain_dag().topological_order()
        assert order.index("a") < order.index("b")
        assert order.index("b") < order.index("dec")
        assert order.index("dec") < order.index("rcpt")
        assert order.index("rcpt") < order.index("call")
        assert order.index("call") < order.index("fx")

    def test_order_is_deterministic_under_declaration_order(self) -> None:
        nodes = _chain_nodes()
        shuffled = dict(reversed(list(nodes.items())))
        edges = _chain_edges()
        assert (
            GovernanceDAG(nodes=nodes, edges=edges).topological_order()
            == GovernanceDAG(nodes=shuffled, edges=tuple(reversed(edges))).topological_order()
        )

    def test_order_validates_first(self) -> None:
        dag = GovernanceDAG(nodes={"x": _agent("y")})
        with pytest.raises(DagValidationError, match="node id mismatch"):
            dag.topological_order()


class TestDagHash:
    def test_declaration_order_independent(self) -> None:
        nodes = _chain_nodes()
        edges = _chain_edges()
        shuffled = GovernanceDAG(
            nodes=dict(reversed(list(nodes.items()))), edges=tuple(reversed(edges))
        )
        assert GovernanceDAG(nodes=nodes, edges=edges).dag_hash() == shuffled.dag_hash()

    def test_scope_order_independent(self) -> None:
        def dag_with(scope: tuple[str, ...]) -> GovernanceDAG:
            return GovernanceDAG(
                nodes={"a": _agent("a"), "b": _agent("b")},
                edges=(GovernanceEdge("a", "b", EdgeKind.AUTHORITY_DELEGATION, scope=scope),),
            )

        assert dag_with(("x", "y")).dag_hash() == dag_with(("y", "x")).dag_hash()

    def test_structure_sensitive(self) -> None:
        base = _chain_dag()
        tampered_nodes = _chain_nodes()
        tampered_nodes["call"] = GovernanceNode("call", NodeKind.TOOL_CALL, action="other.action")
        tampered = GovernanceDAG(nodes=tampered_nodes, edges=_chain_edges())
        assert base.dag_hash() != tampered.dag_hash()


class TestAccessors:
    def test_edges_from_filters_by_kind(self) -> None:
        dag = _chain_dag()
        assert {e.dst for e in dag.edges_from("b")} == {"dec", "call"}
        assert [e.dst for e in dag.edges_from("b", EdgeKind.APPROVAL)] == ["dec"]

    def test_edges_into_filters_by_kind(self) -> None:
        dag = _chain_dag()
        assert {e.src for e in dag.edges_into("call")} == {"rcpt", "b"}
        assert [e.src for e in dag.edges_into("call", EdgeKind.EXECUTION)] == ["rcpt", "b"]

    def test_nodes_of_kind_sorted(self) -> None:
        dag = _chain_dag()
        assert [n.node_id for n in dag.nodes_of_kind(NodeKind.AGENT)] == ["a", "b"]
