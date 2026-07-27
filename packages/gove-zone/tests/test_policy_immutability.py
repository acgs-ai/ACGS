"""Policy identity and deep-immutability invariants.

The invariant under test: **no supported API, retained alias, or returned object
may change what ``Policy.evaluate`` decides while ``Policy.version`` stays the
same.** A receipt binds ``policy_hash``/``policy_version`` (``tenant.py``,
``executor.py``), so a policy whose behaviour drifts under a stable version would
let a receipt authorize an action the policy no longer permits.

The second invariant: every content-addressed policy version carries the **full**
lowercase 64-hex SHA-256 digest, never a truncation.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from gove_zone import (
    ActionTier,
    AllowAllPolicy,
    BoundaryPolicy,
    CompositePolicy,
    Decision,
    DenyAllPolicy,
    PathBoundaryPolicy,
    PolicyRule,
    RuleSetPolicy,
    ToolCall,
    ToolTierRegistry,
)
from gove_zone.policy import (
    Policy,
    PolicyArtifactSnapshot,
    PolicySnapshotUnavailableError,
)

_FULL_SHA256 = re.compile(r"[0-9a-f]{64}")


def policy_version_digest(version: str) -> str:
    """Extract the trailing digest segment, asserting it is a full SHA-256."""
    candidate = version.rsplit("/", 1)[-1]
    assert _FULL_SHA256.fullmatch(candidate), f"{version!r} lacks a full SHA-256 digest"
    return candidate


def _call(tool: str = "fs.delete", **state: Any) -> ToolCall:
    return ToolCall(name=tool, args={"path": "x"}, actor="agent", state=state)


def _bundle(rules: list[dict[str, Any]], policy_id: str = "immutability/v1") -> RuleSetPolicy:
    return RuleSetPolicy.from_dict({"id": policy_id, "rules": rules})


# --------------------------------------------------------------------------
# Full SHA-256 identity
# --------------------------------------------------------------------------


def test_ruleset_version_carries_full_sha256_digest() -> None:
    policy = _bundle([{"id": "R1", "effect": "deny", "tools": ["fs.delete"]}])
    digest = policy_version_digest(policy.version)
    assert _FULL_SHA256.fullmatch(digest)
    assert len(digest) == 64
    assert digest == digest.lower()
    assert policy.version.startswith("ruleset/immutability/v1/")


def test_boundary_and_path_boundary_versions_carry_full_digest() -> None:
    boundary = BoundaryPolicy(forbidden_keywords=["secret"])
    path_boundary = PathBoundaryPolicy(blocked_prefixes=["tenant/private"])
    for policy in (boundary, path_boundary):
        assert len(policy_version_digest(policy.version)) == 64
    assert boundary.version.startswith("boundary/")
    assert path_boundary.version.startswith("path-boundary/")


def test_tool_tier_registry_version_hash_is_full_digest() -> None:
    registry = ToolTierRegistry.from_dict({"fs.read": "explore"})
    assert _FULL_SHA256.fullmatch(registry.version_hash())


def test_one_byte_semantic_change_changes_the_version() -> None:
    base = _bundle([{"id": "R1", "effect": "deny", "tools": ["fs.delete"]}])
    changed = _bundle([{"id": "R2", "effect": "deny", "tools": ["fs.delete"]}])
    assert base.version != changed.version
    assert policy_version_digest(base.version) != policy_version_digest(changed.version)


def test_truncated_digest_is_not_a_valid_policy_version() -> None:
    """The old ``sha256[:16]`` shape is rejected, not silently accepted."""
    policy = _bundle([{"id": "R1", "effect": "deny", "tools": ["fs.delete"]}])
    legacy = policy.version[: policy.version.rindex("/") + 17]
    assert len(policy_version_digest(policy.version)) == 64
    assert not _FULL_SHA256.fullmatch(legacy.rsplit("/", 1)[-1])
    assert legacy != policy.version


def test_registry_change_changes_the_bundle_version() -> None:
    rules = [PolicyRule(rule_id="R1", effect=Decision.DENY, tools=frozenset({"fs.read"}))]
    without = RuleSetPolicy(policy_id="tiered/v1", rules=rules)
    with_registry = RuleSetPolicy(
        policy_id="tiered/v1",
        rules=rules,
        tier_registry=ToolTierRegistry.from_dict({"fs.read": "explore"}),
    )
    other_registry = RuleSetPolicy(
        policy_id="tiered/v1",
        rules=rules,
        tier_registry=ToolTierRegistry.from_dict({"fs.read": "commit"}),
    )
    assert len({without.version, with_registry.version, other_registry.version}) == 3


# --------------------------------------------------------------------------
# Constructor data is copied
# --------------------------------------------------------------------------


def test_mutating_the_source_bundle_document_changes_nothing() -> None:
    document: dict[str, Any] = {
        "id": "immutability/v1",
        "rules": [
            {
                "id": "R1",
                "effect": "deny",
                "tools": ["fs.delete"],
                "state_equals": {"env": "prod"},
            }
        ],
    }
    policy = RuleSetPolicy.from_dict(document)
    before_version = policy.version
    before_document = policy.to_dict()
    denied = policy.evaluate(_call(env="prod"))

    document["rules"][0]["tools"].append("fs.write")
    document["rules"][0]["state_equals"]["env"] = "dev"
    document["rules"].append({"id": "R2", "effect": "deny"})

    assert policy.version == before_version
    assert policy.to_dict() == before_document
    assert policy.evaluate(_call(env="prod")).decision is denied.decision
    assert policy.evaluate(_call("fs.write", env="prod")).decision is Decision.ALLOW


def test_mutating_constructor_collections_cannot_change_behaviour() -> None:
    tools = {"fs.delete"}
    actors = {"trusted"}
    state_equals: dict[str, Any] = {"env": "prod"}
    rule = PolicyRule(
        rule_id="R1",
        effect=Decision.DENY,
        tools=tools,
        allowed_actors=actors,
        state_equals=state_equals,
    )
    rules = [rule]
    policy = RuleSetPolicy(policy_id="immutability/v1", rules=rules)
    before_version = policy.version

    tools.add("fs.write")
    actors.add("agent")
    state_equals["env"] = "dev"
    rules.append(PolicyRule(rule_id="R2", effect=Decision.DENY))

    assert policy.version == before_version
    assert len(policy.rules) == 1
    assert policy.rules[0].tools == frozenset({"fs.delete"})
    assert policy.rules[0].allowed_actors == frozenset({"trusted"})
    # ``agent`` never became an exempt actor, so the deny still stands.
    assert policy.evaluate(_call(env="prod")).decision is Decision.DENY
    assert policy.evaluate(_call("fs.write", env="prod")).decision is Decision.ALLOW


def test_boundary_policy_copies_its_constructor_sequences() -> None:
    keywords = ["secret"]
    only_tools = ["fs.write"]
    policy = BoundaryPolicy(forbidden_keywords=keywords, only_tools=only_tools)
    before_version = policy.version

    keywords.append("password")
    only_tools.append("fs.delete")

    assert policy.version == before_version
    call = ToolCall(name="fs.write", args={"note": "password"}, actor="agent")
    assert policy.evaluate(call).decision is Decision.ALLOW


def test_path_boundary_policy_copies_its_constructor_sequences() -> None:
    prefixes: list[str] = ["tenant/private"]
    actors = ["ops"]
    policy = PathBoundaryPolicy(blocked_prefixes=prefixes, allowed_actors=actors)
    before_version = policy.version

    prefixes.append("tenant/public")
    actors.append("agent")

    assert policy.version == before_version
    blocked = ToolCall(
        name="fs.read",
        args={},
        actor="agent",
        path=("tenant", "private", "notes"),
    )
    assert policy.evaluate(blocked).decision is Decision.DENY


# --------------------------------------------------------------------------
# Nested and unsupported values
# --------------------------------------------------------------------------


def test_nested_mappings_and_sequences_are_deeply_frozen() -> None:
    nested: dict[str, Any] = {"matter": {"tags": ["privileged"], "meta": {"level": 1}}}
    rule = PolicyRule(rule_id="R1", effect=Decision.DENY, state_equals=nested)

    nested["matter"]["tags"].append("public")

    frozen = rule.state_equals["matter"]
    # Sequences become tuples and mappings become read-only views, so neither
    # in-place mutation nor item assignment reaches the rule.
    assert frozen["tags"] == ("privileged",)
    assert not hasattr(frozen["tags"], "append")
    with pytest.raises(TypeError):
        frozen["meta"]["level"] = 2  # type: ignore[index]
    with pytest.raises(TypeError):
        frozen["tags"] = ("public",)  # type: ignore[index]


def test_unsupported_mutable_values_are_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported value"):
        PolicyRule(rule_id="R1", effect=Decision.DENY, state_equals={"tags": {"a", "b"}})
    with pytest.raises(ValueError, match="unsupported value"):
        PolicyRule(rule_id="R1", effect=Decision.DENY, state_contains={"o": object()})
    with pytest.raises(ValueError, match="object keys must be strings"):
        PolicyRule(rule_id="R1", effect=Decision.DENY, state_equals={1: "x"})


def test_rule_effect_is_validated_on_direct_construction() -> None:
    """A directly built rule cannot smuggle in a positive ALLOW effect."""
    with pytest.raises(ValueError, match="limited to deny/escalate"):
        PolicyRule(rule_id="R1", effect=Decision.ALLOW, tools=frozenset({"fs.delete"}))
    with pytest.raises(ValueError, match="non-empty id"):
        PolicyRule(rule_id="  ", effect=Decision.DENY)


def test_unknown_tier_on_direct_construction_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown action tier"):
        PolicyRule(rule_id="R1", effect=Decision.DENY, tiers=frozenset({"nonsense"}))  # type: ignore[arg-type]


def test_tier_criterion_survives_set_input() -> None:
    rule = PolicyRule(rule_id="R1", effect=Decision.DENY, tiers={ActionTier.COMMIT})
    assert rule.tiers == frozenset({ActionTier.COMMIT})


# --------------------------------------------------------------------------
# Public surfaces expose no live state
# --------------------------------------------------------------------------


def test_public_rule_tuple_cannot_be_reassigned_or_mutated() -> None:
    policy = _bundle([{"id": "R1", "effect": "deny", "tools": ["fs.delete"]}])
    assert isinstance(policy.rules, tuple)
    with pytest.raises(AttributeError):
        policy.rules[0].tools |= {"fs.write"}  # type: ignore[misc]
    with pytest.raises(AttributeError):
        policy._rules = ()  # type: ignore[misc]


@pytest.mark.parametrize(
    "policy",
    [
        AllowAllPolicy(),
        DenyAllPolicy(),
        BoundaryPolicy(forbidden_keywords=["secret"]),
        PathBoundaryPolicy(blocked_prefixes=["tenant/private"]),
        CompositePolicy([DenyAllPolicy()]),
    ],
)
def test_built_in_policies_are_sealed_after_construction(policy: Policy) -> None:
    with pytest.raises(AttributeError, match="immutable after construction"):
        policy._injected = "x"  # type: ignore[attr-defined]
    with pytest.raises(AttributeError, match="immutable after construction"):
        del policy.__dict__  # type: ignore[misc]


def test_tier_registry_mapping_is_read_only() -> None:
    registry = ToolTierRegistry.from_dict({"fs.read": "explore"})
    with pytest.raises(TypeError):
        registry.tiers["fs.write"] = ActionTier.EXPLORE  # type: ignore[index]


def test_mutating_to_dict_output_cannot_affect_live_state() -> None:
    policy = _bundle(
        [
            {
                "id": "R1",
                "effect": "deny",
                "tools": ["fs.delete"],
                "state_equals": {"env": "prod"},
            }
        ]
    )
    before_version = policy.version
    exported = policy.to_dict()

    exported["id"] = "hijacked"
    exported["rules"][0]["effect"] = "allow"
    exported["rules"][0]["state_equals"]["env"] = "dev"
    exported["rules"].append({"id": "R2", "effect": "deny"})

    assert policy.version == before_version
    assert policy.policy_id == "immutability/v1"
    assert policy.to_dict() != exported
    assert policy.evaluate(_call(env="prod")).decision is Decision.DENY


def test_rule_to_dict_and_version_payload_are_detached_copies() -> None:
    rule = PolicyRule(
        rule_id="R1",
        effect=Decision.DENY,
        state_equals={"matter": {"tags": ["privileged"]}},
    )
    exported = rule.to_dict()
    exported["state_equals"]["matter"]["tags"].append("public")
    assert rule.state_equals["matter"]["tags"] == ("privileged",)
    assert rule.to_dict()["state_equals"]["matter"]["tags"] == ["privileged"]

    payload = rule.version_payload()
    payload["id"] = "hijacked"
    assert rule.version_payload()["id"] == "R1"


def test_snapshot_artifact_view_is_frozen_and_detached() -> None:
    policy = _bundle([{"id": "R1", "effect": "deny", "tools": ["fs.delete"]}])
    snapshot = policy.authorization_snapshot()
    assert len(snapshot.digest) == 64
    with pytest.raises(TypeError):
        snapshot.artifact["id"] = "hijacked"  # type: ignore[index]
    assert snapshot.evaluator is not policy
    assert snapshot.evaluator.version == policy.version


# --------------------------------------------------------------------------
# Composite safety
# --------------------------------------------------------------------------


class _MutableCustomPolicy(Policy):
    """The previously vulnerable shape: constant version, mutable behaviour."""

    def __init__(self) -> None:
        self.decision = Decision.ALLOW

    @property
    def version(self) -> str:
        return "custom/v1"

    def evaluate(self, call: ToolCall) -> Any:
        from gove_zone.decision import DecisionRecord, sha256_json
        from gove_zone.policy import new_event_id

        return DecisionRecord(
            decision=self.decision,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
        )


def test_composite_rejects_a_mutable_custom_child() -> None:
    """The prior vulnerable path: a child could flip its decision under a
    version the composite had already cached. Now refused at construction."""
    child = _MutableCustomPolicy()

    # The hole this closes is real: the child flips its decision while its
    # ``version`` string stays constant, so a composite that cached that version
    # would have kept serving a stale identity for changed behaviour.
    child.decision = Decision.ALLOW
    allowed = child.evaluate(_call("fs.write")).decision
    child.decision = Decision.DENY
    denied = child.evaluate(_call("fs.write")).decision
    assert allowed is Decision.ALLOW
    assert denied is Decision.DENY
    assert child.version == "custom/v1"

    # Such a policy can no longer enter a composite at all.
    with pytest.raises(PolicySnapshotUnavailableError, match="cannot be composed"):
        CompositePolicy([child, DenyAllPolicy()])


class _SnapshotCapableButMutablePolicy(_MutableCustomPolicy):
    """Implements ``authorization_snapshot`` yet stays mutable.

    This is the shape a presence-check gate would wave through: the snapshot is
    metadata *about* the policy, while ``CompositePolicy`` evaluates the live
    object. A snapshot may even name the mutable policy itself as its evaluator,
    so snapshot-capability can never stand in for immutability.
    """

    def authorization_snapshot(self) -> PolicyArtifactSnapshot:
        artifact = {"kind": "custom-policy", "version": self.version}
        return PolicyArtifactSnapshot.from_artifact(artifact, evaluator=self)


def test_composite_rejects_a_snapshot_capable_but_mutable_child() -> None:
    """Regression: implementing authorization_snapshot must not buy admission.

    Before this gate, such a child was composed and then flipped the composite's
    decision while ``composite.version`` stayed byte-identical.
    """
    child = _SnapshotCapableButMutablePolicy()
    # The snapshot is well-formed, so a presence check would accept the child...
    assert len(child.authorization_snapshot().digest) == 64
    # ...yet the object it names as evaluator is the mutable policy itself.
    assert child.authorization_snapshot().evaluator is child

    with pytest.raises(PolicySnapshotUnavailableError, match="not sufficient"):
        CompositePolicy([child, DenyAllPolicy()])


def test_composite_version_is_a_content_hash_not_a_concatenation() -> None:
    """A joined string would not be injective — ``policy_id`` accepts any
    character, including the separators a concatenated encoding relies on."""
    composite = CompositePolicy([_bundle([{"id": "R1", "effect": "deny"}]), DenyAllPolicy()])
    assert composite.version.startswith("composite/")
    assert len(policy_version_digest(composite.version)) == 64

    # Member identity and order both bind the composite version.
    reordered = CompositePolicy([DenyAllPolicy(), _bundle([{"id": "R1", "effect": "deny"}])])
    other = CompositePolicy([_bundle([{"id": "R2", "effect": "deny"}]), DenyAllPolicy()])
    assert composite.version != reordered.version
    assert composite.version != other.version


def test_composite_accepts_built_in_children_and_caches_a_stable_version() -> None:
    composite = CompositePolicy(
        [
            _bundle([{"id": "R1", "effect": "deny", "tools": ["fs.delete"]}]),
            DenyAllPolicy(),
        ]
    )
    version = composite.version
    assert composite.evaluate(_call("fs.write")).decision is Decision.DENY
    assert composite.evaluate(_call("fs.delete")).decision is Decision.DENY
    assert composite.version == version


def test_composite_children_cannot_be_swapped_after_construction() -> None:
    composite = CompositePolicy([AllowAllPolicy(), DenyAllPolicy()])
    with pytest.raises(AttributeError, match="immutable after construction"):
        composite._policies = (AllowAllPolicy(),)  # type: ignore[misc]


def test_composite_child_bundle_cannot_be_mutated_through_its_alias() -> None:
    child = _bundle([{"id": "R1", "effect": "deny", "tools": ["fs.delete"]}])
    composite = CompositePolicy([child, DenyAllPolicy()])
    version = composite.version

    with pytest.raises(AttributeError):
        child._rules = ()  # type: ignore[misc]

    assert composite.version == version
    assert composite.evaluate(_call("fs.delete")).decision is Decision.DENY
