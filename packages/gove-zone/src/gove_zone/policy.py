"""Policy ABC and concrete policy implementations.

A :class:`Policy` produces a :class:`~gove_zone.decision.DecisionRecord` from
a :class:`~gove_zone.tool.ToolCall`. The kernel calls ``policy.evaluate(call)``
exactly once per dispatch and appends the result to the audit chain before
any side effect runs.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import uuid
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from gove_zone.decision import (
    Decision,
    DecisionRecord,
    canonical_json,
    sha256_json,
)
from gove_zone.tool import ToolCall, normalize_path_context


def new_event_id() -> str:
    """Generate a 16-hex-char event id prefixed with ``ev_``."""
    return f"ev_{uuid.uuid4().hex[:16]}"


class Policy(ABC):
    """Abstract policy. Subclasses implement :meth:`evaluate`."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Stable identifier for this policy instance.

        Two policies with the same version MUST produce the same decision for
        the same input — that's what makes replay meaningful.
        """

    @abstractmethod
    def evaluate(self, call: ToolCall) -> DecisionRecord:
        """Decide what to do about *call*. Must not raise on policy-internal
        errors — return a DENY record instead. The kernel's fail-closed
        wrapper catches any leaked exception and converts it to a DENY.
        """


class AllowAllPolicy(Policy):
    """Allows every call. Useful only in tests."""

    @property
    def version(self) -> str:
        return "allow-all/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.ALLOW,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            reason="allow-all policy",
        )


class DenyAllPolicy(Policy):
    """Denies every call. Useful for kill-switches and tests."""

    def __init__(self, reason: str = "deny-all policy") -> None:
        self._reason = reason

    @property
    def version(self) -> str:
        return "deny-all/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.DENY,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("DENY_ALL",),
            reason=self._reason,
        )


class BoundaryPolicy(Policy):
    """Hard-deny when the canonical-JSON of the args matches a forbidden
    keyword (substring, case-insensitive) or regex pattern.

    Generalized from ``acgs-lite/src/acgs_lite/constitution/boundaries.py``
    to operate on the structured tool-call arguments rather than free-text
    actions — keywords and patterns now match against
    ``canonical_json(call.args)``.
    """

    def __init__(
        self,
        *,
        forbidden_keywords: Sequence[str] = (),
        forbidden_patterns: Sequence[str] = (),
        rule_id: str = "BOUNDARY",
        only_tools: Sequence[str] | None = None,
    ) -> None:
        self._keywords = tuple(k.lower() for k in forbidden_keywords)
        self._patterns = tuple(re.compile(p, re.IGNORECASE) for p in forbidden_patterns)
        self._raw_patterns = tuple(forbidden_patterns)
        self._rule_id = rule_id
        self._only_tools = None if only_tools is None else frozenset(only_tools)
        self._version = self._compute_version()

    def _compute_version(self) -> str:
        h = hashlib.sha256()
        h.update(canonical_json(list(self._keywords)).encode())
        h.update(b"|")
        h.update(canonical_json(list(self._raw_patterns)).encode())
        h.update(b"|")
        h.update(self._rule_id.encode())
        h.update(b"|")
        only = sorted(self._only_tools) if self._only_tools else []
        h.update(canonical_json(only).encode())
        return f"boundary/{h.hexdigest()[:16]}"

    @property
    def version(self) -> str:
        return self._version

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        if self._only_tools is not None and call.name not in self._only_tools:
            return DecisionRecord(
                decision=Decision.ALLOW,
                tool=call.name,
                argument_hash=sha256_json(dict(call.args)),
                policy_version=self.version,
                event_id=new_event_id(),
                reason=f"out of scope for {self._rule_id}",
            )

        canonical = canonical_json(dict(call.args))
        lower = canonical.lower()
        matched: list[str] = []
        for kw in self._keywords:
            if kw in lower:
                matched.append(f"{self._rule_id}:keyword:{kw}")
        for pat in self._patterns:
            if pat.search(canonical):
                matched.append(f"{self._rule_id}:pattern:{pat.pattern}")

        decision = Decision.DENY if matched else Decision.ALLOW
        return DecisionRecord(
            decision=decision,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=tuple(matched),
            reason=(f"matched {len(matched)} boundary rule(s)" if matched else "no boundary match"),
        )


def _path_has_prefix(path: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    return len(path) >= len(prefix) and path[: len(prefix)] == prefix


class PathBoundaryPolicy(Policy):
    """Deny actor/tool calls against protected path prefixes.

    This is the minimal policies-on-paths primitive: the policy evaluates the
    tuple ``(actor, path, proposed action)`` before the side effect runs. A
    matching protected path denies unless ``allowed_actors`` explicitly names
    the actor. Empty or unmatched path context is allowed so this policy can be
    composed with regular argument-boundary checks.
    """

    def __init__(
        self,
        *,
        blocked_prefixes: Sequence[str | Sequence[str]],
        allowed_actors: Sequence[str] = (),
        rule_id: str = "PATH_BOUNDARY",
        only_tools: Sequence[str] | None = None,
    ) -> None:
        if not blocked_prefixes:
            raise ValueError("PathBoundaryPolicy requires at least one blocked prefix")
        self._blocked_prefixes = tuple(
            normalize_path_context(prefix) for prefix in blocked_prefixes
        )
        self._allowed_actors = frozenset(allowed_actors)
        self._rule_id = rule_id
        self._only_tools = None if only_tools is None else frozenset(only_tools)
        self._version = self._compute_version()

    def _compute_version(self) -> str:
        h = hashlib.sha256()
        h.update(canonical_json([list(prefix) for prefix in self._blocked_prefixes]).encode())
        h.update(b"|")
        h.update(canonical_json(sorted(self._allowed_actors)).encode())
        h.update(b"|")
        h.update(self._rule_id.encode())
        h.update(b"|")
        only = sorted(self._only_tools) if self._only_tools else []
        h.update(canonical_json(only).encode())
        return f"path-boundary/{h.hexdigest()[:16]}"

    @property
    def version(self) -> str:
        return self._version

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        if self._only_tools is not None and call.name not in self._only_tools:
            return DecisionRecord(
                decision=Decision.ALLOW,
                tool=call.name,
                argument_hash=call.argument_hash(),
                policy_version=self.version,
                event_id=new_event_id(),
                reason=f"out of scope for {self._rule_id}",
            )

        matched = [
            f"{self._rule_id}:path:{'/'.join(prefix)}"
            for prefix in self._blocked_prefixes
            if prefix and _path_has_prefix(call.path, prefix)
        ]
        actor_allowed = bool(self._allowed_actors) and call.actor in self._allowed_actors
        decision = Decision.ALLOW if not matched or actor_allowed else Decision.DENY
        if matched and actor_allowed:
            reason = f"actor {call.actor} allowed for protected path"
        elif matched:
            reason = f"actor {call.actor or 'unknown'} denied for protected path"
        else:
            reason = "no protected path match"
        return DecisionRecord(
            decision=decision,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=tuple(matched),
            reason=reason,
        )


def _is_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _string_tuple(value: Any, *, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if _is_sequence(value):
        return tuple(str(item) for item in value)
    raise ValueError(f"{field_name} must be a string or sequence of strings")


def _mapping_dict(value: Any, *, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be a mapping")
    return {str(key): item for key, item in value.items()}


def _path_prefix(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, str) and not _is_sequence(value):
        raise ValueError("path_prefix must be a string or sequence of strings")
    return normalize_path_context(value)


def _rule_effect(value: Any) -> Decision:
    try:
        decision = value if isinstance(value, Decision) else Decision(str(value).lower())
    except ValueError as exc:
        raise ValueError(f"unsupported rule effect: {value!r}") from exc
    if decision not in (Decision.DENY, Decision.ESCALATE):
        raise ValueError("RuleSetPolicy effects are limited to deny/escalate")
    return decision


def _state_contains(actual: Any, expected: Any) -> bool:
    if _is_sequence(expected):
        return all(_state_contains(actual, item) for item in expected)
    if actual is None:
        return False
    if isinstance(actual, str):
        return str(expected) in actual
    if isinstance(actual, Mapping):
        return any(key == expected or str(key) == str(expected) for key in actual)
    if isinstance(actual, (set, frozenset, list, tuple)):
        return any(item == expected for item in actual)
    return bool(actual == expected)


@dataclasses.dataclass(frozen=True)
class PolicyRule:
    """One declarative path/state/trust rule used by :class:`RuleSetPolicy`.

    A rule matches when its tool, path prefix, exact state fields, and
    containment state fields all match the proposed :class:`ToolCall`. Matching
    rules deny or escalate unless the actor or its trust tier is explicitly
    exempted. Trust tier defaults to ``call.state["trust_tier"]``.
    """

    rule_id: str
    effect: Decision = Decision.DENY
    path_prefix: tuple[str, ...] = ()
    tools: frozenset[str] = dataclasses.field(default_factory=frozenset)
    state_equals: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    state_contains: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    allowed_actors: frozenset[str] = dataclasses.field(default_factory=frozenset)
    allowed_trust_tiers: frozenset[str] = dataclasses.field(default_factory=frozenset)
    trust_tier_key: str = "trust_tier"
    reason: str = ""

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> PolicyRule:
        rule_id = str(raw.get("id", "")).strip()
        if not rule_id:
            raise ValueError("policy rule requires a non-empty id")
        allow = _mapping_dict(raw.get("allow"), field_name="allow")
        return cls(
            rule_id=rule_id,
            effect=_rule_effect(raw.get("effect", "deny")),
            path_prefix=_path_prefix(raw.get("path_prefix")),
            tools=frozenset(_string_tuple(raw.get("tools"), field_name="tools")),
            state_equals=_mapping_dict(raw.get("state_equals"), field_name="state_equals"),
            state_contains=_mapping_dict(
                raw.get("state_contains"),
                field_name="state_contains",
            ),
            allowed_actors=frozenset(_string_tuple(allow.get("actors"), field_name="allow.actors")),
            allowed_trust_tiers=frozenset(
                _string_tuple(allow.get("trust_tiers"), field_name="allow.trust_tiers")
            ),
            trust_tier_key=str(raw.get("trust_tier_key", "trust_tier")),
            reason=str(raw.get("reason", "")),
        )

    def version_payload(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "effect": self.effect.value,
            "path_prefix": list(self.path_prefix),
            "tools": sorted(self.tools),
            "state_equals": dict(self.state_equals),
            "state_contains": dict(self.state_contains),
            "allowed_actors": sorted(self.allowed_actors),
            "allowed_trust_tiers": sorted(self.allowed_trust_tiers),
            "trust_tier_key": self.trust_tier_key,
            "reason": self.reason,
        }

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.rule_id,
            "effect": self.effect.value,
        }
        if self.tools:
            payload["tools"] = sorted(self.tools)
        if self.path_prefix:
            payload["path_prefix"] = list(self.path_prefix)
        if self.state_equals:
            payload["state_equals"] = dict(self.state_equals)
        if self.state_contains:
            payload["state_contains"] = dict(self.state_contains)

        allow: dict[str, list[str]] = {}
        if self.allowed_actors:
            allow["actors"] = sorted(self.allowed_actors)
        if self.allowed_trust_tiers:
            allow["trust_tiers"] = sorted(self.allowed_trust_tiers)
        if allow:
            payload["allow"] = allow

        if self.trust_tier_key != "trust_tier":
            payload["trust_tier_key"] = self.trust_tier_key
        if self.reason:
            payload["reason"] = self.reason
        return payload

    def matches(self, call: ToolCall) -> bool:
        if self.tools and call.name not in self.tools:
            return False
        if self.path_prefix and not _path_has_prefix(call.path, self.path_prefix):
            return False
        for key, expected in self.state_equals.items():
            if call.state.get(key) != expected:
                return False
        for key, expected in self.state_contains.items():
            if not _state_contains(call.state.get(key), expected):
                return False
        return True

    def exemption_match(self, call: ToolCall) -> str | None:
        if self.allowed_actors and call.actor in self.allowed_actors:
            return f"{self.rule_id}:allow:actor"
        trust_tier = str(call.state.get(self.trust_tier_key, ""))
        if self.allowed_trust_tiers and trust_tier in self.allowed_trust_tiers:
            return f"{self.rule_id}:allow:trust_tier"
        return None


class RuleSetPolicy(Policy):
    """Declarative policy bundle over path + organization state + trust tier.

    ``RuleSetPolicy`` is intentionally small and deterministic: bundles are
    plain dictionaries/lists, policy versions are content-addressed, and rules
    can only ``deny`` or ``escalate``. Positive authorization is expressed as
    explicit actor/trust-tier exemptions so a broad allow rule cannot mask a
    later denial by accident.
    """

    def __init__(self, *, policy_id: str, rules: Sequence[PolicyRule]) -> None:
        if not rules:
            raise ValueError("RuleSetPolicy requires at least one rule")
        self._policy_id = policy_id.strip() or "ruleset/v0"
        self._rules = tuple(rules)
        self._version = self._compute_version()

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> RuleSetPolicy:
        policy_id = str(raw.get("id", "ruleset/v0"))
        raw_rules = raw.get("rules")
        if not _is_sequence(raw_rules):
            raise ValueError("RuleSetPolicy requires a rules sequence")
        rules: list[PolicyRule] = []
        for raw_rule in cast(Sequence[Any], raw_rules):
            if not isinstance(raw_rule, Mapping):
                raise ValueError("each policy rule must be a mapping")
            rules.append(PolicyRule.from_dict(raw_rule))
        return cls(policy_id=policy_id, rules=tuple(rules))

    @classmethod
    def from_json(cls, text: str) -> RuleSetPolicy:
        raw = json.loads(text)
        if not isinstance(raw, Mapping):
            raise ValueError("RuleSetPolicy JSON must be an object")
        return cls.from_dict(raw)

    @classmethod
    def load(cls, path: str | Path) -> RuleSetPolicy:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    def _compute_version(self) -> str:
        digest = hashlib.sha256(
            canonical_json(
                {
                    "id": self._policy_id,
                    "rules": [rule.version_payload() for rule in self._rules],
                }
            ).encode()
        ).hexdigest()
        return f"ruleset/{self._policy_id}/{digest[:16]}"

    @property
    def version(self) -> str:
        return self._version

    @property
    def policy_id(self) -> str:
        return self._policy_id

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        return self._rules

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self._policy_id,
            "rules": [rule.to_dict() for rule in self._rules],
        }

    def to_json(self) -> str:
        return (
            json.dumps(
                self.to_dict(),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

    def dump(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        exemptions: list[str] = []
        for rule in self._rules:
            if not rule.matches(call):
                continue
            exemption = rule.exemption_match(call)
            if exemption:
                exemptions.append(exemption)
                continue
            return DecisionRecord(
                decision=rule.effect,
                tool=call.name,
                argument_hash=call.argument_hash(),
                policy_version=self.version,
                event_id=new_event_id(),
                matched_rules=(rule.rule_id,),
                reason=rule.reason or f"matched rule {rule.rule_id}",
            )

        return DecisionRecord(
            decision=Decision.ALLOW,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=tuple(exemptions),
            reason=("matched rule exemption(s)" if exemptions else "no rules matched"),
        )


# Severity order used to pick the fail-closed default tier: DENY is the most
# restrictive enforcement, ALLOW the least.
_TIER_SEVERITY: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.ESCALATE: 1,
    Decision.DENY: 2,
}


def _tier_enforcement(value: Any) -> Decision:
    try:
        decision = value if isinstance(value, Decision) else Decision(str(value).lower())
    except ValueError as exc:
        raise ValueError(f"unsupported tier enforcement: {value!r}") from exc
    if decision not in _TIER_SEVERITY:
        raise ValueError("risk-tier enforcement is limited to allow/escalate/deny")
    return decision


@dataclasses.dataclass(frozen=True)
class RiskTier:
    """One named risk tier used by :class:`RiskTierPolicy`.

    ``enforcement`` is the decision every call in this tier receives:
    ``allow`` (receipt-logged like every governed call), ``escalate``
    (human-in-the-loop), or ``deny``. ``requirements`` is free-form policy
    metadata (e.g. ``("signed", "single-use", "human-approval")``) that
    downstream profiles and integrators can read via
    :meth:`RiskTierPolicy.tier_for` — it adds no new enforcement code path.
    """

    name: str
    enforcement: Decision = Decision.DENY
    requirements: tuple[str, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("risk tier requires a non-empty name")
        object.__setattr__(self, "enforcement", _tier_enforcement(self.enforcement))

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> RiskTier:
        return cls(
            name=str(raw.get("name", "")).strip(),
            enforcement=_tier_enforcement(raw.get("enforcement", "deny")),
            requirements=_string_tuple(raw.get("requirements"), field_name="requirements"),
            description=str(raw.get("description", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "enforcement": self.enforcement.value,
        }
        if self.requirements:
            payload["requirements"] = list(self.requirements)
        if self.description:
            payload["description"] = self.description
        return payload

    def version_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "enforcement": self.enforcement.value,
            "requirements": list(self.requirements),
            "description": self.description,
        }


class RiskTierPolicy(Policy):
    """Risk-tiered enforcement surface: per-tool enforcement depth as policy data.

    Answers the uniform-governance objection — one blanket gate for every
    action class over- or under-governs — by classifying tools into named
    risk tiers whose enforcement scales with risk (low-risk read → allowed and
    receipt-logged; high-risk delete/exfiltrate/deploy → escalate or deny).

    Tiers are **policy metadata, not new enforcement code paths**: this class
    is an ordinary :class:`Policy`, the kernel/executor stay the single gate,
    and DENY/ESCALATE records remain non-executable. The fail-closed default
    is preserved — a tool with no tier assignment falls into ``default_tier``,
    which (unless explicitly configured) is the **most restrictive** tier
    defined in the bundle.
    """

    def __init__(
        self,
        *,
        policy_id: str = "risk-tier/v0",
        tiers: Sequence[RiskTier],
        tool_tiers: Mapping[str, str] | None = None,
        default_tier: str | None = None,
    ) -> None:
        if not tiers:
            raise ValueError("RiskTierPolicy requires at least one tier")
        self._policy_id = policy_id.strip() or "risk-tier/v0"
        self._tiers = tuple(tiers)
        self._by_name: dict[str, RiskTier] = {}
        for tier in self._tiers:
            if tier.name in self._by_name:
                raise ValueError(f"duplicate risk tier name: {tier.name!r}")
            self._by_name[tier.name] = tier

        self._tool_tiers = {
            str(tool): str(tier_name) for tool, tier_name in (tool_tiers or {}).items()
        }
        for tool, tier_name in self._tool_tiers.items():
            if tier_name not in self._by_name:
                raise ValueError(f"tool {tool!r} references undefined risk tier {tier_name!r}")

        if default_tier is not None:
            if default_tier not in self._by_name:
                raise ValueError(f"default_tier references undefined risk tier {default_tier!r}")
            self._default_tier = default_tier
        else:
            # Fail-closed: unassigned tools get the most restrictive tier
            # (DENY > ESCALATE > ALLOW; first declared wins ties).
            self._default_tier = max(
                self._tiers,
                key=lambda tier: _TIER_SEVERITY[tier.enforcement],
            ).name
        self._version = self._compute_version()

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> RiskTierPolicy:
        raw_tiers = raw.get("tiers")
        if not _is_sequence(raw_tiers):
            raise ValueError("RiskTierPolicy requires a tiers sequence")
        tiers: list[RiskTier] = []
        for raw_tier in cast(Sequence[Any], raw_tiers):
            if not isinstance(raw_tier, Mapping):
                raise ValueError("each risk tier must be a mapping")
            tiers.append(RiskTier.from_dict(raw_tier))
        tools = _mapping_dict(raw.get("tools"), field_name="tools")
        raw_default = raw.get("default_tier")
        return cls(
            policy_id=str(raw.get("id", "risk-tier/v0")),
            tiers=tuple(tiers),
            tool_tiers={tool: str(tier_name) for tool, tier_name in tools.items()},
            default_tier=None if raw_default is None else str(raw_default),
        )

    @classmethod
    def from_json(cls, text: str) -> RiskTierPolicy:
        raw = json.loads(text)
        if not isinstance(raw, Mapping):
            raise ValueError("RiskTierPolicy JSON must be an object")
        return cls.from_dict(raw)

    @classmethod
    def load(cls, path: str | Path) -> RiskTierPolicy:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    def _compute_version(self) -> str:
        digest = hashlib.sha256(
            canonical_json(
                {
                    "id": self._policy_id,
                    "tiers": [tier.version_payload() for tier in self._tiers],
                    "tools": dict(sorted(self._tool_tiers.items())),
                    "default_tier": self._default_tier,
                }
            ).encode()
        ).hexdigest()
        return f"risk-tier/{self._policy_id}/{digest[:16]}"

    @property
    def version(self) -> str:
        return self._version

    @property
    def policy_id(self) -> str:
        return self._policy_id

    @property
    def tiers(self) -> tuple[RiskTier, ...]:
        return self._tiers

    @property
    def default_tier(self) -> str:
        return self._default_tier

    def tier_for(self, tool_name: str) -> RiskTier:
        """Resolved tier for *tool_name* (the default tier when unassigned)."""
        return self._by_name[self._tool_tiers.get(tool_name, self._default_tier)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self._policy_id,
            "tiers": [tier.to_dict() for tier in self._tiers],
            "tools": dict(sorted(self._tool_tiers.items())),
            "default_tier": self._default_tier,
        }

    def to_json(self) -> str:
        return (
            json.dumps(
                self.to_dict(),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

    def dump(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        tier_name = self._tool_tiers.get(call.name)
        defaulted = tier_name is None
        tier = self._by_name[self._default_tier if tier_name is None else tier_name]

        matched: tuple[str, ...] = (f"RISK_TIER:{tier.name}",)
        if defaulted:
            matched = (*matched, "RISK_TIER:default")
            reason = (
                f"tool {call.name!r} has no tier assignment; fail-closed default tier "
                f"{tier.name!r} -> {tier.enforcement.value}"
            )
        else:
            reason = f"tool {call.name!r} in risk tier {tier.name!r} -> {tier.enforcement.value}"

        return DecisionRecord(
            decision=tier.enforcement,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=matched,
            reason=reason,
        )


class CompositePolicy(Policy):
    """Run N policies in order; first non-ALLOW wins.

    The returned record's ``policy_version`` is set to this composite's own
    version (``+``-joined member versions) so replay against the composite is
    stable.
    """

    def __init__(self, policies: Sequence[Policy]) -> None:
        if not policies:
            raise ValueError("CompositePolicy requires at least one policy")
        self._policies = tuple(policies)
        self._version = "composite[" + "+".join(p.version for p in policies) + "]"

    @property
    def version(self) -> str:
        return self._version

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        last: DecisionRecord | None = None
        for p in self._policies:
            record = p.evaluate(call)
            last = record
            if record.decision is not Decision.ALLOW:
                return dataclasses.replace(record, policy_version=self.version)
        assert last is not None  # at least one policy enforced in __init__
        return dataclasses.replace(
            last,
            policy_version=self.version,
            reason=f"all {len(self._policies)} policies allowed",
        )
