"""LangChain and LangGraph integration adapter for gove-zone.

Wraps standard LangChain/LangGraph tools in the gove-zone governance kernel, so
that executions of the tools this adapter wraps pass through policy checks,
auditing, and sandboxing. Tools left unwrapped, and side effects an agent
reaches without calling a wrapped tool, are not mediated by it.
"""

from __future__ import annotations

from typing import Any

from gove_zone.agent import ManagedAgent

try:
    from langchain_core.tools import BaseTool  # type: ignore[import-not-found]

    LANGCHAIN_AVAILABLE = True
except ImportError:
    # Fallback class for environments without langchain installed
    class BaseTool:  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

    LANGCHAIN_AVAILABLE = False


class GovernedTool(BaseTool):  # type: ignore[misc]
    """A LangChain BaseTool wrapper that delegates execution to a ManagedAgent."""

    def __init__(self, tool: Any, agent: ManagedAgent) -> None:
        if not LANGCHAIN_AVAILABLE:
            raise ImportError("langchain-core is required to use GovernedTool")

        # Map basic attributes from the original tool
        super().__init__(
            name=tool.name,
            description=tool.description,
            args_schema=tool.args_schema,
            return_direct=tool.return_direct,
            verbose=tool.verbose,
        )
        self._original_tool = tool
        self._agent = agent

        # Register the original execution function in the agent (and sandbox)
        # LangChain tools execute synchronous tool runs via `_run`
        self._agent.register_tool(self.name, self._original_tool._run)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Enforces policy check, auditing, and sandboxed execution of the tool."""
        # Convert positional args to keyword arguments if any (standard tools use kwargs)
        # Delegate to the agent's dispatch loop
        result, _receipt = self._agent.dispatch(self.name, kwargs)
        return result

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """Enforces policy check and execution for async tool runs."""
        # Standard fallback uses sync _run in executor thread
        return self._run(*args, **kwargs)


def govern_langgraph_tools(tools: list[Any], agent: ManagedAgent) -> list[BaseTool]:
    """Wrap a list of LangChain/LangGraph tools with gove-zone governance."""
    if not LANGCHAIN_AVAILABLE:
        raise ImportError("langchain-core is required to use govern_langgraph_tools")
    return [GovernedTool(tool, agent) for tool in tools]
