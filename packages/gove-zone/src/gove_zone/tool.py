"""Tool registry and tool-call schema.

A ``ToolCall`` is the structured payload the kernel evaluates. A
``ToolRegistry`` maps a tool name to a callable that produces the side effect.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolCall:
    """A proposed tool invocation.

    ``args`` is captured as an immutable view of the caller's dict so callers
    can't mutate it after a policy has hashed it. ``goal`` is the caller's
    high-level intent — opaque to the kernel, available to policies that want
    to reason about purpose.
    """

    name: str
    args: Mapping[str, Any] = field(default_factory=dict)
    goal: str = ""

    def with_args(self, args: Mapping[str, Any]) -> ToolCall:
        """Return a new ToolCall with the same name + goal but replaced args.

        Used by the kernel after a TRANSFORM decision to re-canonicalize.
        """
        return ToolCall(name=self.name, args=args, goal=self.goal)


class ToolRegistry:
    """Simple name → callable registry. Single registration per name."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}

    def register(self, name: str, fn: Callable[..., Any]) -> None:
        """Register *fn* under *name*. Raises if *name* is already registered."""
        if name in self._tools:
            raise ValueError(f"tool already registered: {name!r}")
        self._tools[name] = fn

    def get(self, name: str) -> Callable[..., Any]:
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name!r}")
        return self._tools[name]

    def has(self, name: str) -> bool:
        return name in self._tools

    def names(self) -> tuple[str, ...]:
        return tuple(self._tools)

    def __len__(self) -> int:
        return len(self._tools)
