"""Authority inheritance over a governance DAG — narrowing-only delegation.

Authority enters the graph as **root grants** (trusted anchors supplied by the
integrator, outside the graph) and flows only along ``AUTHORITY_DELEGATION``
edges. The inheritance rules are fail-closed:

1. A root grant must name an existing ``AGENT`` node, and the grant's
   ``agent_id`` must equal that node id (no aliasing).
2. A delegation edge may only delegate actions the delegator itself holds at
   that point — **narrowing only, never broadening**. Because the graph is
   acyclic, "at that point" is well-defined: agents are processed in
   topological order, so every inbound delegation is resolved before the
   agent's own outbound delegations are checked.
3. An agent's effective scope is the union of its root grant (if any) and
   every validated inbound delegation.
4. An agent may only propose a decision or execute a tool call whose
   ``action`` is inside its effective scope. No scope, no act.

This models delegated authority as capability attenuation: authority can be
split and narrowed down a chain of agents but can never grow, and a cycle can
never manufacture authority because the graph itself must be acyclic.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from gove_zone.dag.graph import (
    DagValidationError,
    EdgeKind,
    GovernanceDAG,
    NodeKind,
)


class AuthorityViolationError(DagValidationError):
    """Raised when authority inheritance rules are violated.

    Covers broadened delegations, grants anchored to unknown or non-agent
    nodes, and agents acting outside their effective scope. Stays on the
    fail-closed :class:`~gove_zone.errors.ReceiptValidationError` path via
    :class:`~gove_zone.dag.graph.DagValidationError`.
    """


@dataclass(frozen=True)
class AuthorityGrant:
    """A root authority grant anchored to one agent node.

    ``authority`` is the grant identifier (the same vocabulary as
    :attr:`gove_zone.receipt.DecisionReceipt.authority`, e.g.
    ``"tenant-A/write-grant"``). ``scope`` is the set of action names the
    grant covers; an empty scope is rejected — a grant of nothing is a bug,
    not a grant.
    """

    agent_id: str
    authority: str
    scope: frozenset[str]

    def __post_init__(self) -> None:
        if not self.agent_id:
            raise AuthorityViolationError("authority grant requires a non-empty agent_id")
        if not self.authority:
            raise AuthorityViolationError(
                f"authority grant for {self.agent_id!r} requires a non-empty authority"
            )
        if not self.scope or any(not action for action in self.scope):
            raise AuthorityViolationError(
                f"authority grant for {self.agent_id!r} requires a non-empty scope "
                "of non-empty action names"
            )


def resolve_effective_scopes(
    dag: GovernanceDAG,
    roots: Mapping[str, AuthorityGrant],
) -> dict[str, frozenset[str]]:
    """Resolve every agent's effective action scope, fail-closed.

    Validates the graph, anchors the root grants, then propagates scopes
    along delegation edges in topological order. Raises
    :class:`AuthorityViolationError` on a mis-anchored grant or on any
    delegation that exceeds the delegator's effective scope at that point.
    Agents with no grant and no inbound delegation resolve to an empty scope.
    """
    dag.validate()

    for node_id, grant in roots.items():
        node = dag.nodes.get(node_id)
        if node is None:
            raise AuthorityViolationError(f"root grant references missing node {node_id!r}")
        if node.kind is not NodeKind.AGENT:
            raise AuthorityViolationError(
                f"root grant on {node_id!r} targets a {node.kind} node, not an agent"
            )
        if grant.agent_id != node_id:
            raise AuthorityViolationError(
                f"root grant on {node_id!r} carries mismatched agent_id {grant.agent_id!r}"
            )

    effective: dict[str, set[str]] = {
        node.node_id: set(roots[node.node_id].scope) if node.node_id in roots else set()
        for node in dag.nodes.values()
        if node.kind is NodeKind.AGENT
    }

    # Topological order guarantees every inbound delegation of an agent is
    # applied before that agent's own outbound delegations are checked.
    for node_id in dag.topological_order():
        node = dag.nodes[node_id]
        if node.kind is not NodeKind.AGENT:
            continue
        for edge in dag.edges_from(node_id, EdgeKind.AUTHORITY_DELEGATION):
            delegated = set(edge.scope)
            excess = delegated - effective[node_id]
            if excess:
                raise AuthorityViolationError(
                    f"delegation {edge.src!r}->{edge.dst!r} exceeds the delegator's "
                    f"effective scope: {sorted(excess)!r} (narrowing only)"
                )
            effective[edge.dst] |= delegated

    return {agent_id: frozenset(scope) for agent_id, scope in effective.items()}


def validate_authority(
    dag: GovernanceDAG,
    roots: Mapping[str, AuthorityGrant],
) -> dict[str, frozenset[str]]:
    """Enforce that every agent acts only inside its effective scope.

    Checks every ``APPROVAL`` edge from an agent to a decision and every
    ``EXECUTION`` edge from an agent to a tool call against the resolved
    scopes; raises :class:`AuthorityViolationError` on the first violation.
    Returns the effective scope map on success so callers can reuse it.
    """
    effective = resolve_effective_scopes(dag, roots)

    for edge in dag.edges:
        src = dag.nodes[edge.src]
        dst = dag.nodes[edge.dst]
        if src.kind is not NodeKind.AGENT:
            continue
        if edge.kind is EdgeKind.APPROVAL and dst.kind is NodeKind.DECISION:
            verb = "propose decision"
        elif edge.kind is EdgeKind.EXECUTION and dst.kind is NodeKind.TOOL_CALL:
            verb = "execute tool call"
        else:
            continue
        if dst.action not in effective.get(edge.src, frozenset()):
            raise AuthorityViolationError(
                f"agent {edge.src!r} may not {verb} {edge.dst!r}: action "
                f"{dst.action!r} is outside its effective scope "
                f"{sorted(effective.get(edge.src, frozenset()))!r}"
            )

    return effective
