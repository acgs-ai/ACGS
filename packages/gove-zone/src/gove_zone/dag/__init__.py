"""Multi-agent governance DAG — typed tracking of who authorized what.

Composes the existing receipt primitives into a graph:
:mod:`~gove_zone.dag.graph` (typed nodes/edges, fail-closed validation, cycle
detection, canonical hashing), :mod:`~gove_zone.dag.authority`
(narrowing-only authority inheritance along delegation edges), and
:mod:`~gove_zone.dag.replay` (offline replay verification of the whole chain
against the real :class:`~gove_zone.receipt.DecisionReceipt` objects).
"""

from __future__ import annotations

from gove_zone.dag.authority import (
    AuthorityGrant,
    AuthorityViolationError,
    resolve_authority_grants,
    resolve_effective_scopes,
    validate_authority,
)
from gove_zone.dag.graph import (
    DagValidationError,
    EdgeKind,
    GovernanceDAG,
    GovernanceEdge,
    GovernanceNode,
    NodeKind,
)
from gove_zone.dag.replay import DagReplayError, verify_dag_replay

__all__ = [
    "AuthorityGrant",
    "AuthorityViolationError",
    "DagReplayError",
    "DagValidationError",
    "EdgeKind",
    "GovernanceDAG",
    "GovernanceEdge",
    "GovernanceNode",
    "NodeKind",
    "resolve_authority_grants",
    "resolve_effective_scopes",
    "validate_authority",
    "verify_dag_replay",
]
