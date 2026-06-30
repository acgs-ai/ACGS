"""AutoGen integration adapter for gove-zone.

Enables wrapping and governing AutoGen agent functions and tool invocations,
routing execution through the gove-zone Kernel and Sandbox.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from gove_zone.agent import ManagedAgent


def govern_autogen_tool(
    agent: ManagedAgent,
    name: str,
    fn: Callable[..., Any],
) -> Callable[..., Any]:
    """Wraps a tool function for AutoGen.

    Ensures execution is routed through the ManagedAgent's kernel and sandbox,
    while preserving the original function signature for AutoGen's prompt generation.
    """
    # Register the original function with the agent (which registers it in the sandbox)
    agent.register_tool(name, fn)

    # Resolve function signature for AutoGen tool mapping
    sig = inspect.signature(fn)

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        # Bind positional args to kwargs to match the schema
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()

        # Dispatch through the governed agent
        result, _receipt = agent.dispatch(name, bound.arguments)
        return result

    # Set metadata and signature to match the original function
    wrapper.__name__ = name
    wrapper.__doc__ = fn.__doc__
    wrapper.__signature__ = sig  # type: ignore[attr-defined]
    return wrapper
