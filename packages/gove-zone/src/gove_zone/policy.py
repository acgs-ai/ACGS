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
import math
import re
import uuid
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from gove_zone.decision import (
    Decision,
    DecisionRecord,
    canonical_json,
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


class PolicyCompositionError(TypeError):
    """Raised when a policy cannot be safely composed into a CompositePolicy."""


_FULL_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _content_addressed_version(prefix: str, digest: str) -> str:
    """Build a ``<prefix><full sha256>`` policy version.

    The digest segment of a content-addressed policy version is an
    authorization-bound identity: it reaches
    :attr:`~gove_zone.receipt.DecisionReceipt.policy_hash` (``tenant.py``) and is
    what ``GovernedExecutor``/``execute_with_receipt`` derive
    ``expected_policy_hash`` from when bound to a policy. It therefore carries
    the full lowercase 64-hex SHA-256 — a truncated digest is rejected here so a
    shortened identity cannot be reintroduced silently.
    """
    if not _FULL_SHA256_RE.fullmatch(digest):
        raise ValueError("policy version digest must be 64 lowercase SHA-256 hex characters")
    return f"{prefix}{digest}"


def _composite_digest(members: Sequence[Policy]) -> str:
    """Content hash over the ordered member versions of a composite.

    Concatenating member versions would not be injective: ``policy_id`` may
    contain any character, so a joined string could in principle be parsed more
    than one way. Hashing canonical JSON makes the encoding unambiguous —
    ordering, separators, and escaping are all decided by the serializer.
    """
    payload = {
        "type": "composite-policy",
        "schema": 1,
        "children": [member.version for member in members],
    }
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


class _SealedPolicy(Policy):
    """Policy whose instance attributes are frozen once :meth:`_seal` runs.

    Built-in policies cache a content-addressed ``version`` at construction while
    ``evaluate`` reads live attributes. Sealing closes the gap: after
    construction no attribute can be rebound or deleted, so behaviour cannot
    change while the cached version stays stable.
    """

    _sealed: bool = False

    def _seal(self) -> None:
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError(f"{type(self).__name__} is immutable after construction")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError(f"{type(self).__name__} is immutable after construction")
        object.__delattr__(self, name)


def _freeze_policy_json(value: Any) -> Any:
    """Copy JSON-shaped policy data into deeply immutable containers."""
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("policy rule numbers must be finite")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("policy rule object keys must be strings")
            frozen[key] = _freeze_policy_json(item)
        return MappingProxyType(frozen)
    if _is_sequence(value):
        return tuple(_freeze_policy_json(item) for item in cast("Sequence[Any]", value))
    raise ValueError(f"policy rule contains unsupported value {type(value).__name__}")


def _thaw_policy_json(value: Any) -> Any:
    """Return plain, detached JSON containers from frozen policy data."""
    if isinstance(value, Mapping):
        return {str(key): _thaw_policy_json(item) for key, item in value.items()}
    if _is_sequence(value):
        return [_thaw_policy_json(item) for item in cast("Sequence[Any]", value)]
    return value


def _string_frozenset(value: Any, *, field_name: str) -> frozenset[str]:
    """Coerce a caller-supplied collection into a detached ``frozenset[str]``."""
    if isinstance(value, (set, frozenset)):
        return frozenset(str(item) for item in cast("frozenset[Any]", value))
    return frozenset(_string_tuple(value, field_name=field_name))


class AllowAllPolicy(_SealedPolicy):
    """Allows every call. Useful only in tests."""

    def __init__(self) -> None:
        self._seal()

    @property
    def version(self) -> str:
        return "allow-all/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.ALLOW,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            reason="allow-all policy",
        )


class DenyAllPolicy(_SealedPolicy):
    """Denies every call. Useful for kill-switches and tests."""

    def __init__(self, reason: str = "deny-all policy") -> None:
        self._reason = str(reason)
        self._seal()

    @property
    def version(self) -> str:
        return "deny-all/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.DENY,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("DENY_ALL",),
            reason=self._reason,
        )


class BoundaryPolicy(_SealedPolicy):
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
        self._keywords = tuple(str(k).lower() for k in forbidden_keywords)
        self._raw_patterns = tuple(str(p) for p in forbidden_patterns)
        self._patterns = tuple(re.compile(p, re.IGNORECASE) for p in self._raw_patterns)
        self._rule_id = str(rule_id)
        self._only_tools = (
            None if only_tools is None else _string_frozenset(only_tools, field_name="only_tools")
        )
        self._version = self._compute_version()
        self._seal()

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
        return _content_addressed_version("boundary/", h.hexdigest())

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
            # Master's gated hot-path form: reuse the canonical string already
            # built for the keyword/regex scan (byte-identical to
            # call.argument_hash(), which re-canonicalizes).
            argument_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=tuple(matched),
            reason=(f"matched {len(matched)} boundary rule(s)" if matched else "no boundary match"),
        )


def _path_has_prefix(path: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    return len(path) >= len(prefix) and path[: len(prefix)] == prefix


class PathBoundaryPolicy(_SealedPolicy):
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
        self._allowed_actors = _string_frozenset(allowed_actors, field_name="allowed_actors")
        self._rule_id = str(rule_id)
        self._only_tools = (
            None if only_tools is None else _string_frozenset(only_tools, field_name="only_tools")
        )
        self._version = self._compute_version()
        self._seal()

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
        return _content_addressed_version("path-boundary/", h.hexdigest())

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


def _json_equal(actual: Any, expected: Any) -> bool:
    """Structural equality that ignores frozen-vs-plain container differences.

    Rule data is deep-frozen at construction (``list`` -> ``tuple``, ``dict`` ->
    ``MappingProxyType``) while runtime ``call.state`` arrives as plain
    JSON-decoded containers. A bare ``!=`` would therefore report a mismatch for
    equal content whenever the value is a sequence — ``["a"] != ("a",)`` — which
    silently turns a written DENY rule into an ALLOW. ``MappingProxyType``
    happens to compare equal to ``dict``, so only sequences are affected, but
    both are normalized here so the comparison cannot depend on which container
    type either side happens to use.
    """
    if isinstance(expected, Mapping):
        if not isinstance(actual, Mapping) or len(actual) != len(expected):
            return False
        return all(
            key in actual and _json_equal(actual[key], value) for key, value in expected.items()
        )
    if _is_sequence(expected):
        if not _is_sequence(actual) or len(actual) != len(expected):
            return False
        return all(_json_equal(a, e) for a, e in zip(actual, expected, strict=True))
    return bool(actual == expected)


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

    def __post_init__(self) -> None:
        """Copy and deep-freeze every caller-supplied field.

        ``PolicyRule`` is content-addressed into ``RuleSetPolicy.version``, so a
        field that stayed aliased to a caller-owned ``dict``/``list`` would let
        matching behaviour drift while the version stayed stable. Validation
        also runs here rather than only in :meth:`from_dict`, so a rule built
        directly cannot carry an effect the bundle format forbids.
        """
        rule_id = str(self.rule_id).strip()
        if not rule_id:
            raise ValueError("policy rule requires a non-empty id")
        object.__setattr__(self, "rule_id", rule_id)
        object.__setattr__(self, "effect", _rule_effect(self.effect))
        object.__setattr__(self, "path_prefix", _path_prefix(self.path_prefix))
        object.__setattr__(self, "tools", _string_frozenset(self.tools, field_name="tools"))
        object.__setattr__(
            self,
            "state_equals",
            _freeze_policy_json(_mapping_dict(self.state_equals, field_name="state_equals")),
        )
        object.__setattr__(
            self,
            "state_contains",
            _freeze_policy_json(_mapping_dict(self.state_contains, field_name="state_contains")),
        )
        object.__setattr__(
            self,
            "allowed_actors",
            _string_frozenset(self.allowed_actors, field_name="allowed_actors"),
        )
        object.__setattr__(
            self,
            "allowed_trust_tiers",
            _string_frozenset(self.allowed_trust_tiers, field_name="allowed_trust_tiers"),
        )
        object.__setattr__(self, "trust_tier_key", str(self.trust_tier_key))
        object.__setattr__(self, "reason", str(self.reason))

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
            "state_equals": _thaw_policy_json(self.state_equals),
            "state_contains": _thaw_policy_json(self.state_contains),
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
            payload["state_equals"] = _thaw_policy_json(self.state_equals)
        if self.state_contains:
            payload["state_contains"] = _thaw_policy_json(self.state_contains)

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
            if not _json_equal(call.state.get(key), expected):
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


class RuleSetPolicy(_SealedPolicy):
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
        self._policy_id = str(policy_id).strip() or "ruleset/v0"
        rule_tuple = tuple(rules)
        for rule in rule_tuple:
            if not isinstance(rule, PolicyRule):
                raise TypeError("RuleSetPolicy rules must be PolicyRule instances")
        self._rules = rule_tuple
        self._version = self._compute_version()
        self._seal()

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
        return _content_addressed_version(f"ruleset/{self._policy_id}/", digest)

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
        name = str(self.name).strip()
        if not name:
            raise ValueError("risk tier requires a non-empty name")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "enforcement", _tier_enforcement(self.enforcement))
        # Copy caller-owned sequences: `requirements` is content-addressed into
        # RiskTierPolicy.version, so an aliased list would let tier metadata
        # drift under a stable version.
        object.__setattr__(
            self, "requirements", _string_tuple(self.requirements, field_name="requirements")
        )
        object.__setattr__(self, "description", str(self.description))

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


class RiskTierPolicy(_SealedPolicy):
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
        self._policy_id = str(policy_id).strip() or "risk-tier/v0"
        self._tiers = tuple(tiers)
        by_name: dict[str, RiskTier] = {}
        for tier in self._tiers:
            if not isinstance(tier, RiskTier):
                raise TypeError("RiskTierPolicy tiers must be RiskTier instances")
            if tier.name in by_name:
                raise ValueError(f"duplicate risk tier name: {tier.name!r}")
            by_name[tier.name] = tier
        # MappingProxyType, not dict: sealing stops the attribute being rebound,
        # but a plain dict would still be mutable through the live reference and
        # could retarget tier lookup under a stable version.
        self._by_name: Mapping[str, RiskTier] = MappingProxyType(by_name)

        self._tool_tiers: Mapping[str, str] = MappingProxyType(
            {str(tool): str(tier_name) for tool, tier_name in (tool_tiers or {}).items()}
        )
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
        self._seal()

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
        return _content_addressed_version(f"risk-tier/{self._policy_id}/", digest)

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


class CompositePolicy(_SealedPolicy):
    """Run N policies in order; first non-ALLOW wins.

    The returned record's ``policy_version`` is set to this composite's own
    version — a content hash over the ordered member versions — so replay
    against the composite is stable.

    Member **order is part of the identity**: this is a first-non-ALLOW-wins
    pipeline, so ``CompositePolicy([A, B])`` and ``CompositePolicy([B, A])`` are
    different policies and hash differently. That is intended; composition is
    not an order-free ``AND``.

    Every member must be a sealed built-in policy. The composite caches its
    version at construction but evaluates each member *live*, so a member whose
    attributes could still be rebound would change decisions under a stable
    composite version.
    """

    def __init__(self, policies: Sequence[Policy]) -> None:
        if not policies:
            raise ValueError("CompositePolicy requires at least one policy")
        members = tuple(policies)
        for member in members:
            if not isinstance(member, Policy):
                raise TypeError("CompositePolicy members must implement Policy")
            # Type membership alone is not enough: `_sealed` defaults to False,
            # so a subclass that never calls _seal(), or an instance built via
            # __new__, would satisfy isinstance() while staying fully mutable —
            # exactly the drift this gate exists to stop. Require both.
            if not isinstance(member, _SealedPolicy) or not getattr(member, "_sealed", False):
                raise PolicyCompositionError(
                    f"{type(member).__name__} cannot be composed: a CompositePolicy caches "
                    "its version but evaluates each member live, so every member must be a "
                    "sealed built-in policy whose attributes are frozen at construction. "
                    "Express custom logic as a RuleSetPolicy bundle instead."
                )
        self._policies = members
        self._version = _content_addressed_version("composite/", _composite_digest(members))
        self._seal()

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
