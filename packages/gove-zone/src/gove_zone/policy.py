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
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from gove_zone.decision import (
    ActionTier,
    Decision,
    DecisionRecord,
    canonical_json,
    sha256_json,
)
from gove_zone.tier import ToolTierRegistry, effective_action_tier
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

    def authorization_snapshot(self) -> PolicyArtifactSnapshot:
        """Return an immutable, content-addressed evaluator for authorization.

        The ordinary :class:`Kernel` path deliberately remains compatible with
        arbitrary ``Policy`` implementations.  The stricter side-effect
        authorization path must not evaluate an opaque, mutable policy while
        trusting a separately supplied digest, though, so custom policies fail
        closed unless they explicitly implement this contract.
        """
        raise PolicySnapshotUnavailableError(
            f"{type(self).__name__} does not provide an authorization snapshot"
        )


class PolicySnapshotUnavailableError(RuntimeError):
    """Raised when a policy cannot produce a trusted authorization snapshot."""


def _freeze_policy_json(value: Any) -> Any:
    """Copy JSON-shaped policy data into deeply immutable containers."""
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("policy artifact numbers must be finite")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("policy artifact object keys must be strings")
            frozen[key] = _freeze_policy_json(item)
        return MappingProxyType(frozen)
    if _is_sequence(value):
        return tuple(_freeze_policy_json(item) for item in value)
    raise ValueError(f"policy artifact contains unsupported value {type(value).__name__}")


def _thaw_policy_json(value: Any) -> Any:
    """Return plain JSON containers without exposing a mutable snapshot."""
    if isinstance(value, Mapping):
        return {str(key): _thaw_policy_json(item) for key, item in value.items()}
    if _is_sequence(value):
        return [_thaw_policy_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class PolicyArtifactSnapshot:
    """Immutable policy artifact and the evaluator rebuilt from that artifact.

    ``digest`` is the full SHA-256 of ``canonical_artifact``.  ``evaluator`` is
    a fresh policy reconstructed from that exact canonical artifact, not the
    potentially mutable object on which ``authorization_snapshot`` was called.
    """

    canonical_artifact: str
    digest: str
    policy_version: str
    evaluator: Policy

    def __post_init__(self) -> None:
        if not isinstance(self.canonical_artifact, str) or not self.canonical_artifact:
            raise ValueError("canonical policy artifact must be a non-empty JSON object")
        try:
            parsed = json.loads(self.canonical_artifact)
        except (TypeError, ValueError):
            raise ValueError("canonical policy artifact must be valid JSON") from None
        if not isinstance(parsed, Mapping):
            raise ValueError("canonical policy artifact must be a JSON object")
        if canonical_json(parsed) != self.canonical_artifact:
            raise ValueError("policy artifact is not canonical JSON")
        if not re.fullmatch(r"[0-9a-f]{64}", self.digest):
            raise ValueError("policy artifact digest must be 64 lowercase SHA-256 hex characters")
        computed = hashlib.sha256(self.canonical_artifact.encode("utf-8")).hexdigest()
        if self.digest != computed:
            raise ValueError("policy artifact digest does not match canonical artifact")
        if not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise ValueError("policy snapshot version must be a non-empty string")
        if not isinstance(self.evaluator, Policy):
            raise TypeError("policy snapshot evaluator must implement Policy")
        if self.evaluator.version != self.policy_version:
            raise ValueError("policy snapshot evaluator version does not match artifact version")

    @classmethod
    def from_artifact(
        cls,
        artifact: Mapping[str, Any],
        *,
        evaluator: Policy,
    ) -> PolicyArtifactSnapshot:
        canonical = canonical_json(_thaw_policy_json(_freeze_policy_json(artifact)))
        return cls(
            canonical_artifact=canonical,
            digest=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            policy_version=evaluator.version,
            evaluator=evaluator,
        )

    @property
    def artifact(self) -> Mapping[str, Any]:
        """A deeply immutable parsed view of ``canonical_artifact``."""
        parsed = json.loads(self.canonical_artifact)
        assert isinstance(parsed, Mapping)
        return cast(Mapping[str, Any], _freeze_policy_json(parsed))


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


def _tier_set(value: Any) -> frozenset[ActionTier]:
    """Parse a rule's optional ``tiers`` criterion into a frozenset.

    ``None``/absent → empty set (matches every tier, preserving pre-tiering
    semantics). Unknown tier strings are a hard error — a bundle typo must fail
    loudly rather than silently match nothing.
    """
    if value is None:
        return frozenset()
    raw = value if _is_sequence(value) else (value,)
    tiers: set[ActionTier] = set()
    for item in raw:
        try:
            tiers.add(item if isinstance(item, ActionTier) else ActionTier(str(item)))
        except ValueError as exc:
            raise ValueError(
                f"unknown action tier {item!r}; expected one of {[t.value for t in ActionTier]}"
            ) from exc
    return frozenset(tiers)


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
    tiers: frozenset[ActionTier] = dataclasses.field(default_factory=frozenset)
    reason: str = ""

    def __post_init__(self) -> None:
        # ``frozen=True`` only prevents rebinding.  Snapshot nested rule values
        # too so a caller cannot mutate the source dictionaries after policy
        # construction and silently change evaluation under a cached version.
        object.__setattr__(
            self,
            "state_equals",
            cast(Mapping[str, Any], _freeze_policy_json(self.state_equals)),
        )
        object.__setattr__(
            self,
            "state_contains",
            cast(Mapping[str, Any], _freeze_policy_json(self.state_contains)),
        )

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
            tiers=_tier_set(raw.get("tiers")),
            reason=str(raw.get("reason", "")),
        )

    def version_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
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
        # C7: only fold the tier criterion into the version hash when a rule
        # actually uses it, so pre-tiering bundles keep their original hash
        # (mirrors to_dict). A tier-scoped rule shifts the hash by design.
        if self.tiers:
            payload["tiers"] = sorted(t.value for t in self.tiers)
        return payload

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
        if self.tiers:
            payload["tiers"] = sorted(t.value for t in self.tiers)
        if self.reason:
            payload["reason"] = self.reason
        return payload

    def matches(self, call: ToolCall, *, effective_tier: ActionTier | None = None) -> bool:
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
        if self.tiers:
            # An empty ``tiers`` set matches every tier (pre-tiering semantics).
            # ``effective_tier`` is the registry-resolved tier the RuleSetPolicy
            # computes. A direct caller that omits it gets the strict default
            # (COMMIT) — never explore leniency without an explicit resolution.
            tier = effective_tier if effective_tier is not None else ActionTier.COMMIT
            if tier not in self.tiers:
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

    def __init__(
        self,
        *,
        policy_id: str,
        rules: Sequence[PolicyRule],
        tier_registry: ToolTierRegistry | None = None,
    ) -> None:
        if not rules:
            raise ValueError("RuleSetPolicy requires at least one rule")
        self._policy_id = policy_id.strip() or "ruleset/v0"
        self._rules = tuple(rules)
        self._tier_registry = tier_registry
        self._version = self._compute_version()
        self._sealed = True

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("RuleSetPolicy is immutable after construction")
        object.__setattr__(self, name, value)

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
        raw_tiers = raw.get("tool_tiers")
        tier_registry = (
            ToolTierRegistry.from_dict(cast(Mapping[str, Any], raw_tiers))
            if raw_tiers is not None
            else None
        )
        return cls(policy_id=policy_id, rules=tuple(rules), tier_registry=tier_registry)

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
        payload: dict[str, Any] = {
            "id": self._policy_id,
            "rules": [rule.version_payload() for rule in self._rules],
        }
        # Fold the tool-tier registry into the version ONLY when configured, so
        # a changed registry changes the bundle version (a receipt bound to the
        # bundle is bound to the registry too) while pre-tiering bundles keep
        # their existing content-addressed version unchanged.
        if self._tier_registry is not None:
            payload["tool_tiers"] = self._tier_registry.version_hash()
        digest = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
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
        payload: dict[str, Any] = {
            "id": self._policy_id,
            "rules": [rule.to_dict() for rule in self._rules],
        }
        if self._tier_registry is not None:
            payload["tool_tiers"] = {
                name: self._tier_registry.tiers[name].value
                for name in sorted(self._tier_registry.tiers)
            }
        return payload

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

    def authorization_snapshot(self) -> PolicyArtifactSnapshot:
        """Freeze this complete bundle into its canonical evaluator artifact."""
        artifact = self.to_dict()
        # Rebuild the evaluator from the artifact instead of returning ``self``.
        # That makes the object evaluated by the authorization path identical to
        # the object whose bytes are hashed, closing digest/evaluator TOCTOU.
        evaluator = RuleSetPolicy.from_dict(artifact)
        snapshot = PolicyArtifactSnapshot.from_artifact(artifact, evaluator=evaluator)
        if snapshot.policy_version != self.version:
            # Defensive fail-closed check: serialization must preserve the
            # existing short compatibility version exactly.
            raise PolicySnapshotUnavailableError(
                "canonical policy artifact changed the policy compatibility version"
            )
        return snapshot

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        # Effective tier is registry-resolved (min(declared, registered) with
        # COMMIT as the strict default). The declared tier is untrusted; the
        # registry is authoritative — a commit-only tool can never be evaluated
        # under explore regardless of declaration (C5). Both tiers are stamped
        # onto every returned record for audit telemetry (C4/§3.6).
        effective = effective_action_tier(call, self._tier_registry)
        declared = ActionTier.coerce(call.state.get("action_tier")).value

        exemptions: list[str] = []
        for rule in self._rules:
            if not rule.matches(call, effective_tier=effective):
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
                action_tier=effective.value,
                declared_action_tier=declared,
            )

        return DecisionRecord(
            decision=Decision.ALLOW,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=tuple(exemptions),
            reason=("matched rule exemption(s)" if exemptions else "no rules matched"),
            action_tier=effective.value,
            declared_action_tier=declared,
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
