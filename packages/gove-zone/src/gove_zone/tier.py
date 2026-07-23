"""Tool tier registry — the authoritative source of each tool's max tier.

The declared action tier on a :class:`~gove_zone.tool.ToolCall`
(``state["action_tier"]``) is proposed by the agent and is therefore
**untrusted**. This registry is the trusted counterpart: it records, per tool,
the *highest leniency* that tool may ever be evaluated under. A side-effecting
tool registered as ``commit`` can never be evaluated under the ``explore`` tier,
regardless of what the caller declares (constraint C5).

Effective tier = ``min(declared, registered)`` with ``COMMIT`` as the top/strict
value: the result is ``EXPLORE`` only when the declaration AND the registration
are both ``EXPLORE``; every other combination — including an unregistered tool
or no registry at all — is ``COMMIT`` (constraint C4, fail-closed).

The registry is content-addressed (:meth:`ToolTierRegistry.version_hash`) so a
policy bundle can fold it into its own version/hash; a changed registry changes
the bundle version, so a receipt bound to a bundle is bound to the registry too.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from gove_zone.decision import ActionTier, canonical_json
from gove_zone.tool import ToolCall


@dataclass(frozen=True)
class ToolTierRegistry:
    """Immutable ``tool name -> max ActionTier`` map.

    Unregistered tools default to :attr:`ActionTier.COMMIT` (unknown tools are
    treated as side-effecting until explicitly declared otherwise).
    """

    tiers: Mapping[str, ActionTier]

    def __post_init__(self) -> None:
        # ``frozen=True`` only blocks rebinding ``self.tiers``, not mutation of
        # the underlying mapping. A policy caches its content-addressed version
        # at construction while evaluation reads the live registry, so a mutated
        # registry would change decisions without changing the policy version
        # (breaking the "changed registry ⇒ changed version" binding in §3.3).
        # Snapshot into a copy and expose it read-only so contents are frozen too.
        object.__setattr__(self, "tiers", MappingProxyType(dict(self.tiers)))

    @classmethod
    def from_dict(cls, raw: Mapping[str, object] | None) -> ToolTierRegistry:
        """Build a registry from a ``{tool: "explore"|"commit"}`` mapping.

        The registry is authoritative configuration, not untrusted input, so an
        unrecognised tier string is a hard error (a config typo must fail loudly,
        not silently widen leniency).
        """
        parsed: dict[str, ActionTier] = {}
        for tool, value in dict(raw or {}).items():
            try:
                tier = value if isinstance(value, ActionTier) else ActionTier(str(value))
            except ValueError as exc:
                raise ValueError(
                    f"tool_tiers[{tool!r}] has unknown tier {value!r}; "
                    f"expected one of {[t.value for t in ActionTier]}"
                ) from exc
            parsed[str(tool)] = tier
        return cls(tiers=parsed)

    def max_tier(self, tool_name: str) -> ActionTier:
        """The highest tier *tool_name* may be evaluated under.

        Unregistered tools are ``COMMIT`` (fail-closed).
        """
        return self.tiers.get(tool_name, ActionTier.COMMIT)

    def resolve(self, tool_name: str, declared: ActionTier) -> ActionTier:
        """Effective tier for *tool_name* given an already-coerced *declared*.

        ``EXPLORE`` only when both the declaration and the registration permit
        it; otherwise ``COMMIT``.
        """
        if declared is ActionTier.EXPLORE and self.max_tier(tool_name) is ActionTier.EXPLORE:
            return ActionTier.EXPLORE
        return ActionTier.COMMIT

    def effective_tier(self, call: ToolCall) -> ActionTier:
        """Effective tier for *call*, reading its untrusted declared tier."""
        declared = ActionTier.coerce(call.state.get("action_tier"))
        return self.resolve(call.name, declared)

    def version_hash(self) -> str:
        """Content hash of the registry, for folding into a policy version."""
        payload = {name: self.tiers[name].value for name in sorted(self.tiers)}
        return hashlib.sha256(canonical_json(payload).encode()).hexdigest()[:16]


def effective_action_tier(call: ToolCall, registry: ToolTierRegistry | None) -> ActionTier:
    """Effective tier for *call* under *registry*.

    With no registry configured, no tool is explore-capable, so the result is
    always ``COMMIT`` — the strict default. Explore leniency requires an explicit
    registry that names the tool.
    """
    if registry is None:
        return ActionTier.COMMIT
    return registry.effective_tier(call)
