"""Tests for the optional framework adapters (autogen, langgraph).

These exercise the wiring: a wrapped tool must route through the ManagedAgent's
governed dispatch (policy + audit), not call the raw function directly. The
langgraph adapter must also degrade gracefully when langchain-core is absent.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from gove_zone.adapters import govern_autogen_tool, govern_langgraph_tools
from gove_zone.adapters.langgraph import LANGCHAIN_AVAILABLE
from gove_zone.agent import ManagedAgent
from gove_zone.errors import DeniedError
from gove_zone.policy import AllowAllPolicy, DenyAllPolicy, Policy


def _agent(policy: Policy, tmpdir: str) -> ManagedAgent:
    return ManagedAgent(
        name="adapter-bot", policy=policy, audit_path=Path(tmpdir) / "audit.jsonl"
    )


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
