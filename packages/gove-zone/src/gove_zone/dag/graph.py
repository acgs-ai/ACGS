"""Typed multi-agent governance DAG — nodes, edges, and fail-closed validation.

This module is **additive**: it does not change the single-action receipt gate
or the workflow receipt chain. It gives multi-agent chains a first-class,
hashable structure:

    Agent A --(authority delegation)--> Agent B
    Agent B --(approval)--> Decision --(approval)--> Decision Receipt
    Decision Receipt --(execution)--> Tool Call --(execution)--> Side Effect

Node kinds: ``agent``, ``decision``, ``receipt``, ``tool_call``,
``side_effect``. Edge kinds: ``authority_delegation``, ``approval``,
``dependency``, ``execution``. Every edge kind has an explicit endpoint-type
allow-table; anything not in the table is rejected (fail-closed). The whole
graph must be acyclic — cycle detection is Kahn topological sort, mirroring
:meth:`gove_zone.workflow.WorkflowDAG.validate`.

Scope of the guarantee: this is structural governance *tracking*. It proves a
declared chain is well-formed and (via :func:`gove_zone.dag.replay
.verify_dag_replay`) internally consistent with its receipts. It does not, by
itself, prevent an ungoverned executor from acting — the executor gates in
:mod:`gove_zone.executor` remain the enforcement point.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from gove_zone.decision import sha256_json
from gove_zone.errors import ReceiptRejectionReason, ReceiptValidationError


class DagValidationError(ReceiptValidationError):
    """Raised when a governance DAG is structurally invalid.

    Subclasses :class:`~gove_zone.errors.ReceiptValidationError` deliberately
    (the :class:`~gove_zone.errors.ProductionProfileError` precedent): DAG
    defects stay on the single fail-closed "execution refused" path, so every
    caller that treats ``ReceiptValidationError`` as refusal handles graph
    defects with no new catch site. Defaults ``reason_code`` to
    :attr:`~gove_zone.errors.ReceiptRejectionReason.DAG_STRUCTURE_INVALID` so
    every raise site carries a machine-readable reason.
    """

    def __init__(self, *args: object, reason_code: ReceiptRejectionReason | None = None) -> None:
        super().__init__(
            *args, reason_code=reason_code or ReceiptRejectionReason.DAG_STRUCTURE_INVALID
        )


class NodeKind(StrEnum):
    """The five governance node types."""

    AGENT = "agent"
    DECISION = "decision"
    RECEIPT = "receipt"
    TOOL_CALL = "tool_call"
    SIDE_EFFECT = "side_effect"


class EdgeKind(StrEnum):
    """The four governance edge types."""

    AUTHORITY_DELEGATION = "authority_delegation"
    APPROVAL = "approval"
    DEPENDENCY = "dependency"
    EXECUTION = "execution"


# Endpoint-type allow-table. An edge kind maps to the set of permitted
# (src_kind, dst_kind) pairs; DEPENDENCY is unrestricted (pure ordering) and is
# handled separately. Anything absent is rejected — fail-closed.
_ALLOWED_ENDPOINTS: dict[EdgeKind, frozenset[tuple[NodeKind, NodeKind]]] = {
    EdgeKind.AUTHORITY_DELEGATION: frozenset({(NodeKind.AGENT, NodeKind.AGENT)}),
    EdgeKind.APPROVAL: frozenset(
        {
            (NodeKind.AGENT, NodeKind.DECISION),
            (NodeKind.DECISION, NodeKind.RECEIPT),
        }
    ),
    EdgeKind.EXECUTION: frozenset(
        {
            (NodeKind.RECEIPT, NodeKind.TOOL_CALL),
            (NodeKind.AGENT, NodeKind.TOOL_CALL),
            (NodeKind.TOOL_CALL, NodeKind.SIDE_EFFECT),
        }
    ),
}

# Node kinds that carry an ``action`` (what is proposed / executed).
_ACTION_KINDS = frozenset({NodeKind.DECISION, NodeKind.TOOL_CALL})


@dataclass(frozen=True)
class GovernanceNode:
    """A single typed node in a :class:`GovernanceDAG`.

    ``ref`` binds the node to an external artifact and its meaning depends on
    ``kind``: for ``RECEIPT`` it must equal the receipt's ``receipt_hash``; for
    ``SIDE_EFFECT`` it is the evidence hash/identifier; for ``AGENT`` it is an
    optional external identity reference. ``action`` is required for
    ``DECISION`` and ``TOOL_CALL`` nodes and forbidden elsewhere.
    """

    node_id: str
    kind: NodeKind
    ref: str = ""
    action: str = ""

    def __post_init__(self) -> None:
        if not self.node_id:
            raise DagValidationError("governance node requires a non-empty node_id")
        if self.kind in _ACTION_KINDS:
            if not self.action:
                raise DagValidationError(
                    f"{self.kind} node {self.node_id!r} requires a non-empty action"
                )
        elif self.action:
            raise DagValidationError(
                f"{self.kind} node {self.node_id!r} must not carry an action (got {self.action!r})"
            )


@dataclass(frozen=True)
class GovernanceEdge:
    """A directed, typed edge between two governance nodes.

    ``scope`` is the set of actions delegated along an
    ``AUTHORITY_DELEGATION`` edge. It is **required** there (delegating nothing
    is a bug, not a grant) and **forbidden** on every other edge kind.
    """

    src: str
    dst: str
    kind: EdgeKind
    scope: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.src or not self.dst:
            raise DagValidationError("governance edge requires non-empty src and dst")
        if self.kind is EdgeKind.AUTHORITY_DELEGATION:
            if not self.scope or any(not action for action in self.scope):
                raise DagValidationError(
                    f"authority delegation edge {self.src!r}->{self.dst!r} requires a "
                    "non-empty scope of non-empty action names"
                )
        elif self.scope:
            raise DagValidationError(
                f"{self.kind} edge {self.src!r}->{self.dst!r} must not carry a scope"
            )


@dataclass(frozen=True)
class GovernanceDAG:
    """A declared multi-agent governance graph.

    ``validate`` is fail-closed: id mismatches, dangling endpoints, self-loops,
    edge-type violations, duplicate edges, and cycles all raise
    :class:`DagValidationError`. Cycle detection runs over **all** edge kinds,
    not just delegation — deliberately conservative; a topology that loops
    through any edge kind is rejected. Edge identity for the duplicate check is
    ``(src, dst, kind)``: two delegation edges between the same ordered pair
    must be merged into one edge with the union scope.

    ``dag_hash`` is the canonical structure hash. On its own it detects
    nothing — tampering with the declared chain is detected only when a caller
    binds an externally recorded value via
    :func:`gove_zone.dag.replay.verify_dag_replay`'s ``expected_dag_hash``.
    """

    nodes: dict[str, GovernanceNode]
    edges: tuple[GovernanceEdge, ...] = field(default_factory=tuple)

    def validate(self) -> None:
        """Fail-closed structural validation (including cycle detection)."""
        for key, node in self.nodes.items():
            if key != node.node_id:
                raise DagValidationError(
                    f"DAG node id mismatch: key {key!r} != node.node_id {node.node_id!r}"
                )

        seen: set[tuple[str, str, EdgeKind]] = set()
        for edge in self.edges:
            for endpoint in (edge.src, edge.dst):
                if endpoint not in self.nodes:
                    raise DagValidationError(
                        f"{edge.kind} edge {edge.src!r}->{edge.dst!r} references "
                        f"missing node {endpoint!r}"
                    )
            if edge.src == edge.dst:
                raise DagValidationError(f"{edge.kind} edge on {edge.src!r} is a self-loop")
            identity = (edge.src, edge.dst, edge.kind)
            if identity in seen:
                raise DagValidationError(f"duplicate {edge.kind} edge {edge.src!r}->{edge.dst!r}")
            seen.add(identity)
            if edge.kind is not EdgeKind.DEPENDENCY:
                pair = (self.nodes[edge.src].kind, self.nodes[edge.dst].kind)
                if pair not in _ALLOWED_ENDPOINTS[edge.kind]:
                    raise DagValidationError(
                        f"{edge.kind} edge {edge.src!r}->{edge.dst!r} connects "
                        f"{pair[0]} -> {pair[1]}, which is not a permitted "
                        "endpoint pair for that edge kind"
                    )

        self._kahn_order()

    def topological_order(self) -> tuple[str, ...]:
        """Deterministic topological order of node ids (validates first)."""
        self.validate()
        return self._kahn_order()

    def _kahn_order(self) -> tuple[str, ...]:
        """Kahn topological sort over all edges; raises on any cycle.

        The ready queue is kept sorted so the order is deterministic for a
        given graph, independent of node/edge declaration order.
        """
        indegree: dict[str, int] = {nid: 0 for nid in self.nodes}
        successors: dict[str, list[str]] = {nid: [] for nid in self.nodes}
        for edge in self.edges:
            indegree[edge.dst] += 1
            successors[edge.src].append(edge.dst)

        ready = sorted(nid for nid, deg in indegree.items() if deg == 0)
        order: list[str] = []
        while ready:
            current = ready.pop(0)
            order.append(current)
            for nxt in sorted(successors[current]):
                indegree[nxt] -= 1
                if indegree[nxt] == 0:
                    ready.append(nxt)
            ready.sort()
        if len(order) != len(self.nodes):
            raise DagValidationError("governance DAG contains a cycle (topological sort failed)")
        return tuple(order)

    def dag_hash(self) -> str:
        """``sha256_json`` of the canonical graph structure.

        Canonical form sorts nodes by id and edges by (src, dst, kind), and
        sorts each delegation scope, so the hash is independent of declaration
        order.
        """
        canonical = {
            "nodes": {
                nid: {"kind": str(node.kind), "ref": node.ref, "action": node.action}
                for nid, node in sorted(self.nodes.items())
            },
            "edges": [
                {
                    "src": edge.src,
                    "dst": edge.dst,
                    "kind": str(edge.kind),
                    "scope": sorted(edge.scope),
                }
                for edge in sorted(self.edges, key=lambda e: (e.src, e.dst, str(e.kind)))
            ],
        }
        return sha256_json(canonical)

    def edges_from(self, node_id: str, kind: EdgeKind | None = None) -> tuple[GovernanceEdge, ...]:
        """All edges whose ``src`` is *node_id*, optionally filtered by kind."""
        return tuple(e for e in self.edges if e.src == node_id and (kind is None or e.kind is kind))

    def edges_into(self, node_id: str, kind: EdgeKind | None = None) -> tuple[GovernanceEdge, ...]:
        """All edges whose ``dst`` is *node_id*, optionally filtered by kind."""
        return tuple(e for e in self.edges if e.dst == node_id and (kind is None or e.kind is kind))

    def nodes_of_kind(self, kind: NodeKind) -> tuple[GovernanceNode, ...]:
        """All nodes of *kind*, in sorted node-id order (deterministic)."""
        return tuple(node for _, node in sorted(self.nodes.items()) if node.kind is kind)
