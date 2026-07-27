"""Policy identity and immutability invariants.

Two properties are under test:

1. **Full-digest identity.** Every content-addressed policy version carries the
   complete 64-hex SHA-256. The digest is authorization-bound — it reaches
   ``DecisionReceipt.policy_hash`` via ``tenant.py`` and is what a policy-bound
   ``GovernedExecutor`` derives ``expected_policy_hash`` from — so a truncated
   digest must not be constructible.

2. **Behaviour cannot drift under a stable version.** Built-in policies cache a
   content hash at construction but evaluate live attributes. Every constructor
   input is therefore copied and deeply frozen, and instances are sealed.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from gove_zone.decision import Decision, DecisionRecord
from gove_zone.policy import (
    AllowAllPolicy,
    BoundaryPolicy,
    CompositePolicy,
    DenyAllPolicy,
    PathBoundaryPolicy,
    Policy,
    PolicyCompositionError,
    PolicyRule,
    RiskTier,
    RiskTierPolicy,
    RuleSetPolicy,
    new_event_id,
)
from gove_zone.tool import ToolCall, normalize_path_context

FULL_DIGEST = re.compile(r"[0-9a-f]{64}")


def _call(name: str = "fs.write", **kwargs: Any) -> ToolCall:
    # ToolCall.path is a tuple of segments and applies no coercion of its own.
    kwargs["path"] = normalize_path_context(kwargs.get("path"))
    return ToolCall(name=name, args=kwargs.pop("args", {"path": "/etc/passwd"}), **kwargs)


def _rules() -> list[PolicyRule]:
    return [PolicyRule.from_dict({"id": "R1", "effect": "deny", "tools": ["fs.write"]})]


def _ruleset() -> RuleSetPolicy:
    return RuleSetPolicy(policy_id="p/v1", rules=_rules())


def _risk_tier() -> RiskTierPolicy:
    return RiskTierPolicy(
        tiers=[
            RiskTier(name="low", enforcement=Decision.ALLOW, requirements=["receipt"]),
            RiskTier(name="high", enforcement=Decision.DENY),
        ],
        tool_tiers={"fs.read": "low"},
    )


# --------------------------------------------------------------------------
# 1. Full-digest identity
# --------------------------------------------------------------------------


def test_every_content_addressed_version_carries_a_full_sha256() -> None:
    versions = {
        "ruleset": _ruleset().version,
        "boundary": BoundaryPolicy(forbidden_keywords=["~/.ssh"]).version,
        "path-boundary": PathBoundaryPolicy(blocked_prefixes=["etc"]).version,
        "risk-tier": _risk_tier().version,
        "composite": CompositePolicy([AllowAllPolicy(), _ruleset()]).version,
    }
    for label, version in versions.items():
        digest = version.rsplit("/", 1)[-1]
        assert FULL_DIGEST.fullmatch(digest), f"{label} digest not a full SHA-256: {version}"


def test_a_truncated_digest_cannot_be_built_into_a_version() -> None:
    from gove_zone.policy import _content_addressed_version

    with pytest.raises(ValueError, match="64 lowercase SHA-256 hex"):
        _content_addressed_version("ruleset/x/", "0" * 16)
    with pytest.raises(ValueError, match="64 lowercase SHA-256 hex"):
        _content_addressed_version("ruleset/x/", "A" * 64)  # uppercase is not canonical


def test_one_byte_semantic_change_changes_the_version() -> None:
    a = RuleSetPolicy(policy_id="p/v1", rules=_rules())
    b = RuleSetPolicy(
        policy_id="p/v1",
        rules=[PolicyRule.from_dict({"id": "R1", "effect": "deny", "tools": ["fs.writf"]})],
    )
    assert a.version != b.version


def test_composite_identity_is_order_sensitive() -> None:
    """First-non-ALLOW-wins is a pipeline, so order is part of the identity."""
    a, b = AllowAllPolicy(), _ruleset()
    assert CompositePolicy([a, b]).version != CompositePolicy([b, a]).version


def test_composite_identity_is_injective_over_member_versions() -> None:
    """A concatenating scheme could collide; a hashed canonical JSON cannot.

    ``policy_id`` is free-form, so it can contain the separator a joined string
    would rely on. These two composites differ only in where the boundary
    between member versions falls.
    """
    left = CompositePolicy([RuleSetPolicy(policy_id="a+b", rules=_rules())])
    right = CompositePolicy([RuleSetPolicy(policy_id="a", rules=_rules())])
    assert left.version != right.version


# --------------------------------------------------------------------------
# 2. Constructor data is copied
# --------------------------------------------------------------------------


def test_mutating_the_source_bundle_document_changes_nothing() -> None:
    raw: dict[str, Any] = {
        "id": "p/v1",
        "rules": [{"id": "R1", "effect": "deny", "tools": ["fs.write"]}],
    }
    policy = RuleSetPolicy.from_dict(raw)
    before = policy.version
    raw["rules"][0]["tools"].append("fs.read")  # type: ignore[index]
    raw["id"] = "hijacked"
    assert policy.version == before
    assert policy.evaluate(_call("fs.read")).decision is Decision.ALLOW


def test_mutating_constructor_collections_cannot_change_behaviour() -> None:
    tools = ["fs.write"]
    actors = ["alice"]
    rule = PolicyRule(
        rule_id="R1",
        effect=Decision.DENY,
        tools=tools,  # type: ignore[arg-type]
        allowed_actors=actors,  # type: ignore[arg-type]
    )
    policy = RuleSetPolicy(policy_id="p/v1", rules=[rule])
    before = policy.version

    tools.append("fs.read")
    actors.append("mallory")

    assert policy.version == before
    assert policy.evaluate(_call("fs.read")).decision is Decision.ALLOW
    assert policy.evaluate(_call("fs.write", actor="mallory")).decision is Decision.DENY


def test_boundary_policy_copies_its_constructor_sequences() -> None:
    keywords = ["~/.ssh"]
    only = ["fs.write"]
    policy = BoundaryPolicy(forbidden_keywords=keywords, only_tools=only)
    before = policy.version
    keywords.append("secret")
    only.append("fs.read")
    assert policy.version == before
    assert policy.evaluate(_call(args={"x": "secret"})).decision is Decision.ALLOW


def test_path_boundary_policy_copies_its_constructor_sequences() -> None:
    actors = ["alice"]
    policy = PathBoundaryPolicy(blocked_prefixes=["etc"], allowed_actors=actors)
    before = policy.version
    actors.append("mallory")
    assert policy.version == before
    assert policy.evaluate(_call(path="etc/passwd", actor="mallory")).decision is Decision.DENY


def test_risk_tier_copies_its_constructor_collections() -> None:
    requirements = ["receipt"]
    tool_tiers = {"fs.read": "low"}
    policy = RiskTierPolicy(
        tiers=[
            RiskTier(name="low", enforcement=Decision.ALLOW, requirements=requirements),  # type: ignore[arg-type]
            RiskTier(name="high", enforcement=Decision.DENY),
        ],
        tool_tiers=tool_tiers,
    )
    before = policy.version
    requirements.append("human-approval")
    tool_tiers["fs.write"] = "low"
    assert policy.version == before
    # fs.write was never assigned, so it still falls to the fail-closed default.
    assert policy.evaluate(_call("fs.write")).decision is Decision.DENY


# --------------------------------------------------------------------------
# 3. Nested freezing and rejection of unsupported values
# --------------------------------------------------------------------------


def test_nested_mappings_and_sequences_are_deeply_frozen() -> None:
    rule = PolicyRule(
        rule_id="R1",
        effect=Decision.DENY,
        state_equals={"outer": {"inner": ["a", "b"]}},
    )
    frozen = rule.state_equals["outer"]
    with pytest.raises(TypeError):
        frozen["inner"] = ["hijacked"]  # type: ignore[index]
    # The nested list became a tuple, so it has no in-place mutators at all.
    assert not hasattr(frozen["inner"], "append")
    with pytest.raises(TypeError):
        frozen["inner"][0] = "hijacked"  # type: ignore[index]


def test_unsupported_mutable_values_are_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported value"):
        PolicyRule(rule_id="R1", effect=Decision.DENY, state_equals={"k": {1, 2}})
    with pytest.raises(ValueError, match="unsupported value"):
        PolicyRule(rule_id="R1", effect=Decision.DENY, state_equals={"k": object()})
    with pytest.raises(ValueError, match="keys must be strings"):
        PolicyRule(rule_id="R1", effect=Decision.DENY, state_equals={"k": {1: "v"}})


def test_risk_tier_requirements_reject_an_unordered_set() -> None:
    """Fail closed rather than mint a non-deterministic identity.

    ``requirements`` is serialized positionally into the version payload, so an
    unordered ``set`` would hash differently between runs — the same tier could
    produce two versions. Rejecting is correct; silently sorting would hide the
    caller's mistake.
    """
    with pytest.raises(ValueError, match="sequence of strings"):
        RiskTier(name="t", enforcement=Decision.ALLOW, requirements={"a", "b"})  # type: ignore[arg-type]


def test_non_finite_numbers_are_rejected() -> None:
    with pytest.raises(ValueError, match="finite"):
        PolicyRule(rule_id="R1", effect=Decision.DENY, state_equals={"k": float("nan")})


def test_rule_effect_is_validated_on_direct_construction() -> None:
    """Regression: validation must not live only in ``from_dict``.

    A rule built directly with ALLOW would return an ALLOW record naming itself
    in ``matched_rules``, defeating exemption-only positive authorization.
    """
    with pytest.raises(ValueError, match="limited to deny/escalate"):
        PolicyRule(rule_id="R1", effect=Decision.ALLOW)
    with pytest.raises(ValueError, match="non-empty id"):
        PolicyRule(rule_id="   ", effect=Decision.DENY)


# --------------------------------------------------------------------------
# 4. No mutable live state is exposed
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "policy",
    [
        AllowAllPolicy(),
        DenyAllPolicy(),
        BoundaryPolicy(forbidden_keywords=["x"]),
        PathBoundaryPolicy(blocked_prefixes=["etc"]),
        _ruleset(),
        _risk_tier(),
        CompositePolicy([AllowAllPolicy()]),
    ],
)
def test_built_in_policies_are_sealed_after_construction(policy: Policy) -> None:
    with pytest.raises(AttributeError, match="immutable after construction"):
        policy._version = "hijacked/" + "0" * 64  # type: ignore[attr-defined]
    with pytest.raises(AttributeError, match="immutable after construction"):
        del policy._version  # type: ignore[attr-defined]


def test_public_rule_tuple_cannot_be_mutated() -> None:
    policy = _ruleset()
    assert isinstance(policy.rules, tuple)
    with pytest.raises(TypeError):
        policy.rules[0] = PolicyRule(rule_id="R2", effect=Decision.DENY)  # type: ignore[index]


def test_risk_tier_lookup_tables_are_read_only() -> None:
    policy = _risk_tier()
    with pytest.raises(TypeError):
        policy._tool_tiers["fs.write"] = "low"  # type: ignore[index]
    with pytest.raises(TypeError):
        policy._by_name["low"] = RiskTier(name="low", enforcement=Decision.ALLOW)  # type: ignore[index]
    assert isinstance(policy.tiers, tuple)


def test_mutating_to_dict_output_cannot_affect_live_state() -> None:
    policy = _ruleset()
    before = policy.version
    document = policy.to_dict()
    document["id"] = "hijacked"
    document["rules"][0]["tools"].append("fs.read")  # type: ignore[index]
    assert policy.version == before
    assert policy.evaluate(_call("fs.read")).decision is Decision.ALLOW


def test_rule_to_dict_and_version_payload_are_detached_copies() -> None:
    rule = PolicyRule(
        rule_id="R1",
        effect=Decision.DENY,
        state_equals={"outer": {"inner": "v"}},
    )
    for document in (rule.to_dict(), rule.version_payload()):
        state = document["state_equals"]
        assert isinstance(state, dict)  # plain JSON, not a MappingProxyType
        state["outer"]["inner"] = "hijacked"
        assert rule.state_equals["outer"]["inner"] == "v"


def test_risk_tier_to_dict_is_detached() -> None:
    policy = _risk_tier()
    before = policy.version
    document = policy.to_dict()
    document["tools"]["fs.write"] = "low"
    document["tiers"][0]["requirements"].append("hijacked")
    assert policy.version == before
    assert policy.evaluate(_call("fs.write")).decision is Decision.DENY


# --------------------------------------------------------------------------
# 5. Composite safety boundary
# --------------------------------------------------------------------------


class _MutableCustomPolicy(Policy):
    """A custom policy whose decision can be flipped after construction."""

    def __init__(self) -> None:
        self.decision = Decision.ALLOW

    @property
    def version(self) -> str:
        return "custom/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=self.decision,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            reason="custom",
        )


def test_composite_rejects_a_mutable_custom_child() -> None:
    """The exploit this gate closes.

    Without it, the composite would cache a version over ``custom/v0`` and then
    evaluate the child live — so flipping ``child.decision`` changes the
    composite's decisions while its version stays byte-identical.
    """
    child = _MutableCustomPolicy()
    with pytest.raises(PolicyCompositionError, match="cannot be composed"):
        CompositePolicy([child])


def test_composite_rejects_a_non_policy_member() -> None:
    with pytest.raises(TypeError, match="must implement Policy"):
        CompositePolicy([object()])  # type: ignore[list-item]


def test_sealing_is_mutation_resistance_not_tamper_resistance() -> None:
    """Documents the trust boundary rather than overclaiming it.

    ``object.__setattr__`` bypasses the seal. This is deliberate and matches how
    the repo treats permission deny-rules: an accident-preventer, not a control
    that binds hostile in-process code. The test exists so the boundary is
    explicit and cannot be silently upgraded into a security claim.
    """
    policy = BoundaryPolicy(forbidden_keywords=["~/.ssh"])
    before = policy.version
    object.__setattr__(policy, "_keywords", ())
    assert policy.version == before  # version did NOT track the tampering
    assert policy.evaluate(_call(args={"p": "~/.ssh"})).decision is Decision.ALLOW
