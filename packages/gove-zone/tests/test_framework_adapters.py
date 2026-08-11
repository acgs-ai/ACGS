"""Tests for the optional framework adapters (autogen, langgraph).

These exercise the wiring: a wrapped tool must route through the ManagedAgent's
governed dispatch (policy + audit), not call the raw function directly. The
langgraph adapter must also degrade gracefully when langchain-core is absent.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from gove_zone.adapters import govern_autogen_tool, govern_langgraph_tools
from gove_zone.adapters.langgraph import LANGCHAIN_AVAILABLE
from gove_zone.agent import ManagedAgent
from gove_zone.errors import DeniedError
from gove_zone.policy import AllowAllPolicy, DenyAllPolicy, Policy


def _agent(policy: Policy, tmpdir: str) -> ManagedAgent:
    return ManagedAgent(name="adapter-bot", policy=policy, audit_path=Path(tmpdir) / "audit.jsonl")


def test_govern_autogen_tool_dispatches_and_allows() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        agent = _agent(AllowAllPolicy(), tmpdir)

        def add(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b

        wrapped = govern_autogen_tool(agent, "add", add)
        assert wrapped(2, 3) == 5
        # Signature/metadata preserved for the framework's prompt generation.
        assert wrapped.__name__ == "add"
        assert wrapped.__doc__ == "Add two numbers."


def test_govern_autogen_tool_blocks_under_deny_policy() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        agent = _agent(DenyAllPolicy(reason="blocked by policy"), tmpdir)

        def add(a: int, b: int) -> int:
            return a + b

        wrapped = govern_autogen_tool(agent, "add", add)
        # Governed path is enforced through the wrapper, not bypassed.
        with pytest.raises(DeniedError):
            wrapped(2, 3)


def test_langgraph_adapter_degradation_and_governance() -> None:
    """langgraph adapter: fail-closed without langchain; governed dispatch with it.

    When langchain-core is absent the adapter raises ImportError (never a silent
    ungoverned path). When present (CI installs the ``langchain`` extra), a
    wrapped tool's ``_run`` must route through the agent's governed dispatch, so
    a DenyAllPolicy blocks it with DeniedError rather than executing the tool.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        if not LANGCHAIN_AVAILABLE:
            agent = _agent(AllowAllPolicy(), tmpdir)
            with pytest.raises(ImportError):
                govern_langgraph_tools([], agent)
            return

        from langchain_core.tools import StructuredTool

        def echo(value: str) -> str:
            return value

        base = StructuredTool.from_function(func=echo, name="echo", description="echo")
        agent = _agent(DenyAllPolicy(reason="blocked by policy"), tmpdir)
        wrapped = govern_langgraph_tools([base], agent)[0]
        with pytest.raises(DeniedError):
            wrapped._run(value="hi")


# The installed-path tests below run in CI's dedicated langchain lane (see
# .github/workflows/python-gove-zone.yml), which installs the declared
# `langchain` extra. The main package gate deliberately omits it so the
# missing-dependency guards in test_langgraph_adapter_guards.py exercise a
# real absence.
_needs_langchain = pytest.mark.skipif(
    not LANGCHAIN_AVAILABLE, reason="requires the langchain extra (CI langchain lane)"
)


@_needs_langchain
def test_langgraph_governed_tool_maps_the_original_tools_attributes() -> None:
    """The wrapper must present the original tool's metadata to the framework,
    or the agent's prompts and tool-selection break silently."""
    from langchain_core.tools import StructuredTool

    def echo(value: str) -> str:
        """Echo the value back."""
        return value

    base = StructuredTool.from_function(func=echo, name="echo", description="echo tool")
    with tempfile.TemporaryDirectory() as tmpdir:
        wrapped = govern_langgraph_tools([base], _agent(AllowAllPolicy(), tmpdir))[0]

        assert wrapped.name == "echo"
        assert wrapped.description == "echo tool"
        assert wrapped.args_schema is base.args_schema
        assert wrapped.return_direct is base.return_direct


@_needs_langchain
def test_langgraph_governed_run_dispatches_and_returns_the_tool_result() -> None:
    """REGRESSION. The adapter registered the tool's private ``_run`` as the
    execution function; langchain-core versions that inject a required
    keyword-only ``config`` into ``_run`` made every ALLOWED dispatch die with
    TypeError. Execution now goes through the tool's public ``run`` entry
    point, so the positive path must actually return the tool's result."""
    from langchain_core.tools import StructuredTool

    def shout(value: str) -> str:
        return value.upper()

    base = StructuredTool.from_function(func=shout, name="shout", description="shout")
    with tempfile.TemporaryDirectory() as tmpdir:
        wrapped = govern_langgraph_tools([base], _agent(AllowAllPolicy(), tmpdir))[0]

        assert wrapped._run(value="hi") == "HI"


@_needs_langchain
def test_langgraph_governed_arun_routes_through_the_same_governance() -> None:
    """``_arun`` is the entry LangGraph's async executor uses; it must share
    ``_run``'s governed dispatch on both the allow and deny paths, with the
    denied tool's side effect provably never running."""
    from langchain_core.tools import StructuredTool

    ran: list[str] = []

    def witness(value: str) -> str:
        ran.append(value)
        return value

    with tempfile.TemporaryDirectory() as tmpdir:
        base = StructuredTool.from_function(func=witness, name="witness", description="w")
        allowed = govern_langgraph_tools([base], _agent(AllowAllPolicy(), tmpdir))[0]
        assert asyncio.run(allowed._arun(value="ok")) == "ok"
        assert ran == ["ok"]

    with tempfile.TemporaryDirectory() as tmpdir:
        base = StructuredTool.from_function(func=witness, name="witness", description="w")
        denied = govern_langgraph_tools([base], _agent(DenyAllPolicy(reason="no"), tmpdir))[0]
        with pytest.raises(DeniedError):
            asyncio.run(denied._arun(value="blocked"))
        assert ran == ["ok"], "denied tool executed anyway"
