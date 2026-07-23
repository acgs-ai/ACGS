"""Tool registry and tool-call schema.

A ``ToolCall`` is the structured payload the kernel evaluates. A
``ToolRegistry`` maps a tool name to a callable that produces the side effect.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from gove_zone.decision import sha256_json
from gove_zone.errors import SideEffectCallableAccessError


class ToolEffect(StrEnum):
    """Declared effect class for a registered tool."""

    SIDE_EFFECT = "side_effect"
    PURE_READ_ONLY = "pure_read_only"


@dataclass(frozen=True, slots=True)
class RegisteredTool:
    """Package-internal registry entry pairing a callable with its effect."""

    fn: Callable[..., Any]
    effect: ToolEffect


def normalize_path_context(path: str | Sequence[str] | None = None) -> tuple[str, ...]:
    """Normalize a runtime path/context into canonical path segments.

    The "path" in policies-on-paths is broader than a filesystem path: it can
    be a tenant/matter/resource chain, a repo path, or a workflow lane. Strings
    are split on ``/`` (and ``\\`` for host-runtime file paths); sequences are
    stringified segment-by-segment. Empty segments are discarded so callers can
    pass ``"/tenant/matter"`` and ``("tenant", "matter")`` interchangeably.
    """
    if path is None:
        return ()
    if isinstance(path, str):
        raw_segments = path.replace("\\", "/").split("/")
    else:
        raw_segments = [str(segment) for segment in path]
    return tuple(segment for segment in (s.strip() for s in raw_segments) if segment)


@dataclass(frozen=True)
class ToolCall:
    """A proposed tool invocation.

    ``args`` is captured as an immutable view of the caller's dict so callers
    can't mutate it after a policy has hashed it. ``goal`` is the caller's
    high-level intent — opaque to the kernel, available to policies that want
    to reason about purpose.

    ``actor``, ``path``, and ``state`` make the call compatible with
    policies-on-paths: policies can evaluate who is acting, where in the
    workflow/resource path they are acting, and which organizational state was
    known before the side effect.
    """

    name: str
    args: Mapping[str, Any] = field(default_factory=dict)
    goal: str = ""
    actor: str = ""
    path: tuple[str, ...] = ()
    state: Mapping[str, Any] = field(default_factory=dict)

    def with_args(self, args: Mapping[str, Any]) -> ToolCall:
        """Return a new ToolCall with the same context but replaced args.

        Used by the kernel after a TRANSFORM decision to re-canonicalize.
        """
        return ToolCall(
            name=self.name,
            args=args,
            goal=self.goal,
            actor=self.actor,
            path=self.path,
            state=self.state,
        )

    def argument_hash(self) -> str:
        """Hash only the proposed tool arguments."""
        return sha256_json(dict(self.args))

    def state_hash(self) -> str | None:
        """Hash organizational/runtime state when supplied."""
        return sha256_json(dict(self.state)) if self.state else None

    def decision_request_hash(self) -> str:
        """Hash the full pre-execution decision request.

        This hash binds actor + path + goal + tool + argument hash + state
        hash without storing potentially large/sensitive state inline.
        """
        return sha256_json(
            {
                "actor": self.actor,
                "path": list(self.path),
                "goal": self.goal,
                "tool": self.name,
                "argument_hash": self.argument_hash(),
                "state_hash": self.state_hash(),
            }
        )


class ToolRegistry:
    """Simple name → callable registry. Single registration per name."""

    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}

    def register(
        self,
        name: str,
        fn: Callable[..., Any],
        *,
        effect: ToolEffect = ToolEffect.SIDE_EFFECT,
    ) -> None:
        """Register *fn* under *name*. Raises if *name* is already registered."""
        if name in self._tools:
            raise ValueError(f"tool already registered: {name!r}")
        self._tools[name] = RegisteredTool(fn=fn, effect=ToolEffect(effect))

    def get(self, name: str) -> Callable[..., Any]:
        """Return a pure callable; side-effect callables are never public."""
        entry = self._get_registered(name)
        if entry.effect is ToolEffect.SIDE_EFFECT:
            raise SideEffectCallableAccessError(name)
        return entry.fn

    def _get_pure_callable(self, name: str) -> Callable[..., Any]:
        """Return the private legacy callable only when it is explicitly pure."""
        entry = self._get_registered(name)
        if entry.effect is not ToolEffect.PURE_READ_ONLY:
            raise SideEffectCallableAccessError(name)
        return entry.fn

    def _seal_side_effect(
        self,
        name: str,
        sentinel: Callable[..., Any],
    ) -> Callable[..., Any]:
        """Replace a side-effect callable and return it for dispatcher adoption."""
        entry = self._get_registered(name)
        if entry.effect is not ToolEffect.SIDE_EFFECT:
            raise ValueError(f"tool is not side-effectful: {name!r}")
        self._tools[name] = RegisteredTool(fn=sentinel, effect=entry.effect)
        return entry.fn

    def effect(self, name: str) -> ToolEffect:
        """Return the declared effect class for *name*."""
        return self._get_registered(name).effect

    def _get_registered(self, name: str) -> RegisteredTool:
        """Return the package-internal registration record for *name*."""
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name!r}")
        return self._tools[name]

    def has(self, name: str) -> bool:
        return name in self._tools

    def names(self) -> tuple[str, ...]:
        return tuple(self._tools)

    def __len__(self) -> int:
        return len(self._tools)
