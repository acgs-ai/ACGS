"""Authority inheritance — narrowing-only delegation over the governance DAG.

The invariant under test: authority enters only via root grants, flows only
along delegation edges, can be split and narrowed but never broadened, and an
agent may not propose or execute an action outside its effective scope.
"""

from __future__ import annotations

import pytest

from gove_zone import (
    AuthorityGrant,
    AuthorityViolationError,
    EdgeKind,
    GovernanceDAG,
    GovernanceEdge,
    GovernanceNode,
    NodeKind,
    ReceiptRejectionReason,
    resolve_authority_grants,
    resolve_effective_scopes,
    validate_authority,
)

WRITE = "runtime.file.write"
READ = "runtime.http.get"
DEPLOY = "runtime.deploy"


def _agent(node_id: str) -> GovernanceNode:
    return GovernanceNode(node_id, NodeKind.AGENT)


def _grant(agent_id: str, *actions: str) -> AuthorityGrant:
    return AuthorityGrant(agent_id, "tenant-A/root-grant", frozenset(actions))


def _delegation(src: str, dst: str, *actions: str) -> GovernanceEdge:
    return GovernanceEdge(src, dst, EdgeKind.AUTHORITY_DELEGATION, scope=tuple(actions))


class TestAuthorityGrant:
    def test_empty_agent_id_rejected(self) -> None:
        with pytest.raises(AuthorityViolationError, match="non-empty agent_id"):
            AuthorityGrant("", "auth", frozenset({WRITE}))

    def test_empty_authority_rejected(self) -> None:
        with pytest.raises(AuthorityViolationError, match="non-empty authority"):
            AuthorityGrant("a", "", frozenset({WRITE}))

    def test_empty_scope_rejected(self) -> None:
        with pytest.raises(AuthorityViolationError, match="non-empty scope"):
            AuthorityGrant("a", "auth", frozenset())

    def test_empty_action_name_rejected(self) -> None:
        with pytest.raises(AuthorityViolationError, match="non-empty action names"):
            AuthorityGrant("a", "auth", frozenset({WRITE, ""}))

    def test_violation_carries_reason_code(self) -> None:
        with pytest.raises(AuthorityViolationError) as exc:
            AuthorityGrant("", "auth", frozenset({WRITE}))
        assert exc.value.reason_code is ReceiptRejectionReason.AUTHORITY_VIOLATION


class TestResolveEffectiveScopes:
    def test_root_grant_anchors_scope(self) -> None:
        dag = GovernanceDAG(nodes={"a": _agent("a")})
        scopes = resolve_effective_scopes(dag, {"a": _grant("a", WRITE, READ)})
        assert scopes == {"a": frozenset({WRITE, READ})}

    def test_agent_without_grant_or_delegation_has_empty_scope(self) -> None:
        dag = GovernanceDAG(nodes={"a": _agent("a"), "b": _agent("b")})
        scopes = resolve_effective_scopes(dag, {"a": _grant("a", WRITE)})
        assert scopes["b"] == frozenset()

    def test_root_on_missing_node_rejected(self) -> None:
        dag = GovernanceDAG(nodes={"a": _agent("a")})
        with pytest.raises(AuthorityViolationError, match="missing node 'ghost'"):
            resolve_effective_scopes(dag, {"ghost": _grant("ghost", WRITE)})

    def test_root_on_non_agent_node_rejected(self) -> None:
        dag = GovernanceDAG(nodes={"fx": GovernanceNode("fx", NodeKind.SIDE_EFFECT, ref="ev")})
        with pytest.raises(AuthorityViolationError, match="not an agent"):
            resolve_effective_scopes(dag, {"fx": _grant("fx", WRITE)})

    def test_root_agent_id_mismatch_rejected(self) -> None:
        dag = GovernanceDAG(nodes={"a": _agent("a")})
        with pytest.raises(AuthorityViolationError, match="mismatched agent_id"):
            resolve_effective_scopes(dag, {"a": _grant("other", WRITE)})

    def test_multi_hop_narrowing_chain(self) -> None:
        dag = GovernanceDAG(
            nodes={"a": _agent("a"), "b": _agent("b"), "c": _agent("c")},
            edges=(
                _delegation("a", "b", WRITE, READ),
                _delegation("b", "c", WRITE),
            ),
        )
        scopes = resolve_effective_scopes(dag, {"a": _grant("a", WRITE, READ, DEPLOY)})
        assert scopes["a"] == frozenset({WRITE, READ, DEPLOY})
        assert scopes["b"] == frozenset({WRITE, READ})
        assert scopes["c"] == frozenset({WRITE})

    def test_broadening_delegation_rejected(self) -> None:
        dag = GovernanceDAG(
            nodes={"a": _agent("a"), "b": _agent("b"), "c": _agent("c")},
            edges=(
                _delegation("a", "b", READ),
                _delegation("b", "c", READ, DEPLOY),  # b never held DEPLOY
            ),
        )
        with pytest.raises(AuthorityViolationError, match="narrowing only"):
            resolve_effective_scopes(dag, {"a": _grant("a", READ, DEPLOY)})

    def test_delegation_without_any_authority_rejected(self) -> None:
        dag = GovernanceDAG(
            nodes={"a": _agent("a"), "b": _agent("b")},
            edges=(_delegation("a", "b", WRITE),),
        )
        with pytest.raises(AuthorityViolationError, match="narrowing only"):
            resolve_effective_scopes(dag, {})

    def test_diamond_delegation_unions_inbound_scopes(self) -> None:
        # a -> b (WRITE), a -> c (READ), b -> d (WRITE), c -> d (READ):
        # d unions both inbound delegations; d may re-delegate what it received
        # through EITHER branch, and nothing more.
        dag = GovernanceDAG(
            nodes={nid: _agent(nid) for nid in ("a", "b", "c", "d", "e")},
            edges=(
                _delegation("a", "b", WRITE),
                _delegation("a", "c", READ),
                _delegation("b", "d", WRITE),
                _delegation("c", "d", READ),
                _delegation("d", "e", WRITE, READ),
            ),
        )
        scopes = resolve_effective_scopes(dag, {"a": _grant("a", WRITE, READ)})
        assert scopes["d"] == frozenset({WRITE, READ})
        assert scopes["e"] == frozenset({WRITE, READ})

    def test_inbound_delegation_enables_outbound_redelegation(self) -> None:
        # b holds nothing of its own; everything it delegates must have arrived
        # first — topological processing makes this well-defined.
        dag = GovernanceDAG(
            nodes={"a": _agent("a"), "b": _agent("b"), "c": _agent("c")},
            edges=(_delegation("a", "b", WRITE), _delegation("b", "c", WRITE)),
        )
        scopes = resolve_effective_scopes(dag, {"a": _grant("a", WRITE)})
        assert scopes["c"] == frozenset({WRITE})


class TestResolveAuthorityGrants:
    def test_grants_propagate_with_their_actions(self) -> None:
        dag = GovernanceDAG(
            nodes={"a": _agent("a"), "b": _agent("b"), "c": _agent("c")},
            edges=(_delegation("a", "b", WRITE), _delegation("b", "c", WRITE)),
        )
        grants = resolve_authority_grants(dag, {"a": _grant("a", WRITE, READ)})
        assert grants == {
            "a": {"tenant-A/root-grant": frozenset({WRITE, READ})},
            "b": {"tenant-A/root-grant": frozenset({WRITE})},
            "c": {"tenant-A/root-grant": frozenset({WRITE})},
        }

    def test_grants_union_across_roots(self) -> None:
        dag = GovernanceDAG(
            nodes={"a": _agent("a"), "b": _agent("b"), "c": _agent("c")},
            edges=(_delegation("a", "c", WRITE), _delegation("b", "c", READ)),
        )
        roots = {
            "a": _grant("a", WRITE),
            "b": AuthorityGrant("b", "tenant-B/read-grant", frozenset({READ})),
        }
        grants = resolve_authority_grants(dag, roots)
        assert grants["c"] == {
            "tenant-A/root-grant": frozenset({WRITE}),
            "tenant-B/read-grant": frozenset({READ}),
        }

    def test_label_never_stretches_to_actions_it_did_not_carry(self) -> None:
        # Regression for the cross-root confusion attack: c legitimately holds
        # WRITE (via b's grant) and the read-grant label (via a's grant), but
        # the read-grant must NOT be recorded as delivering WRITE to c.
        dag = GovernanceDAG(
            nodes={"a": _agent("a"), "b": _agent("b"), "c": _agent("c")},
            edges=(_delegation("a", "c", READ), _delegation("b", "c", WRITE)),
        )
        roots = {
            "a": AuthorityGrant("a", "tenant-A/read-grant", frozenset({READ})),
            "b": AuthorityGrant("b", "tenant-B/write-grant", frozenset({WRITE})),
        }
        grants = resolve_authority_grants(dag, roots)
        assert grants["c"]["tenant-A/read-grant"] == frozenset({READ})
        assert WRITE not in grants["c"]["tenant-A/read-grant"]
        assert grants["c"]["tenant-B/write-grant"] == frozenset({WRITE})

    def test_ungranted_unconnected_agent_has_no_grants(self) -> None:
        dag = GovernanceDAG(nodes={"a": _agent("a"), "b": _agent("b")})
        grants = resolve_authority_grants(dag, {"a": _grant("a", WRITE)})
        assert grants["b"] == {}


class TestValidateAuthority:
    def _acting_dag(self, *, decision_action: str, call_action: str) -> GovernanceDAG:
        return GovernanceDAG(
            nodes={
                "a": _agent("a"),
                "b": _agent("b"),
                "dec": GovernanceNode("dec", NodeKind.DECISION, action=decision_action),
                "rcpt": GovernanceNode("rcpt", NodeKind.RECEIPT, ref="rhash"),
                "call": GovernanceNode("call", NodeKind.TOOL_CALL, action=call_action),
            },
            edges=(
                _delegation("a", "b", WRITE),
                GovernanceEdge("b", "dec", EdgeKind.APPROVAL),
                GovernanceEdge("dec", "rcpt", EdgeKind.APPROVAL),
                GovernanceEdge("rcpt", "call", EdgeKind.EXECUTION),
                GovernanceEdge("b", "call", EdgeKind.EXECUTION),
            ),
        )

    def test_acting_within_scope_passes_and_returns_scopes(self) -> None:
        dag = self._acting_dag(decision_action=WRITE, call_action=WRITE)
        scopes = validate_authority(dag, {"a": _grant("a", WRITE, READ)})
        assert scopes["b"] == frozenset({WRITE})

    def test_proposing_outside_scope_rejected(self) -> None:
        dag = self._acting_dag(decision_action=DEPLOY, call_action=WRITE)
        with pytest.raises(AuthorityViolationError, match="propose decision"):
            validate_authority(dag, {"a": _grant("a", WRITE, DEPLOY)})

    def test_executing_outside_scope_rejected(self) -> None:
        dag = self._acting_dag(decision_action=WRITE, call_action=DEPLOY)
        with pytest.raises(AuthorityViolationError, match="execute tool call"):
            validate_authority(dag, {"a": _grant("a", WRITE, DEPLOY)})

    def test_agent_with_no_authority_cannot_act(self) -> None:
        dag = GovernanceDAG(
            nodes={
                "b": _agent("b"),
                "dec": GovernanceNode("dec", NodeKind.DECISION, action=WRITE),
            },
            edges=(GovernanceEdge("b", "dec", EdgeKind.APPROVAL),),
        )
        with pytest.raises(AuthorityViolationError, match="outside its effective scope"):
            validate_authority(dag, {})
