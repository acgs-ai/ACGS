"""Integration and unit tests for the ManagedAgent SDK."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from gove_zone.agent import ManagedAgent
from gove_zone.decision import Decision
from gove_zone.errors import DeniedError
from gove_zone.policy import AllowAllPolicy, DenyAllPolicy
from gove_zone.sandbox import LocalProcessSandbox
from gove_zone.tool import ToolEffect
from gove_zone.yaml_policy import YAMLPolicy


def my_agent_test_tool(x: int, y: int) -> int:
    """A standard top-level test tool."""
    return x * y


def test_managed_agent_explicit_allow_policy_executes() -> None:
    """Positive control: with an explicit AllowAllPolicy the agent registers and
    dispatches tools successfully (configured execution still works)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_path = Path(tmpdir) / "audit.jsonl"
        agent = ManagedAgent(name="test-bot", policy=AllowAllPolicy(), audit_path=audit_path)

        # Register tool
        @agent.tool("multiply", effect=ToolEffect.PURE_READ_ONLY)
        def multiply(a: int, b: int) -> int:
            return a * b

        assert agent._kernel.registry.effect("multiply") is ToolEffect.PURE_READ_ONLY

        # Dispatch call
        res, receipt = agent.dispatch("multiply", {"a": 4, "b": 5}, goal="Test multiplication")
        assert res == 20
        assert receipt.record.decision == Decision.ALLOW
        assert receipt.record.actor == "test-bot"
        assert receipt.record.tool == "multiply"

        # Verify audit ledger contains the event
        assert audit_path.exists()
        events = [line for line in audit_path.read_text(encoding="utf-8").splitlines() if line]
        assert len(events) == 1


def test_managed_agent_default_fails_closed() -> None:
    """Security default (negative control): a ManagedAgent constructed WITHOUT a
    policy installs DenyAllPolicy, so dispatch is blocked and the tool body never
    runs. The denial is still anchored in the audit chain."""
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_path = Path(tmpdir) / "audit.jsonl"
        agent = ManagedAgent(name="default-bot", audit_path=audit_path)

        ran: dict[str, int] = {"count": 0}

        @agent.tool("multiply")
        def multiply(a: int, b: int) -> int:
            ran["count"] += 1
            return a * b

        with pytest.raises(DeniedError):
            agent.dispatch("multiply", {"a": 4, "b": 5}, goal="Should be denied")

        # The side effect must NOT have run, and the deny must be recorded.
        assert ran["count"] == 0
        assert audit_path.exists()
        events = [line for line in audit_path.read_text(encoding="utf-8").splitlines() if line]
        assert len(events) == 1
        assert '"decision":"deny"' in events[0]


def test_managed_agent_deny_policy() -> None:
    """Verify that ManagedAgent correctly fails closed when policy denies a tool call."""
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_path = Path(tmpdir) / "audit.jsonl"
        policy = DenyAllPolicy(reason="Hard deny policy")
        agent = ManagedAgent(name="secure-bot", policy=policy, audit_path=audit_path)

        agent.register_tool(
            "multiply",
            my_agent_test_tool,
            effect=ToolEffect.PURE_READ_ONLY,
        )

        # Dispatch should raise DeniedError
        with pytest.raises(DeniedError) as exc_info:
            agent.dispatch("multiply", {"x": 3, "y": 4})

        assert "Hard deny policy" in str(exc_info.value)

        # Audit ledger should record the denial
        assert audit_path.exists()
        events = [line for line in audit_path.read_text(encoding="utf-8").splitlines() if line]
        assert len(events) == 1
        assert '"decision":"deny"' in events[0]


def test_managed_agent_with_local_sandbox() -> None:
    """Verify that ManagedAgent routes tool calls through the configured sandbox provider."""
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_path = Path(tmpdir) / "audit.jsonl"
        sandbox = LocalProcessSandbox(use_bwrap=False)
        agent = ManagedAgent(
            name="isolated-bot",
            policy=AllowAllPolicy(),
            sandbox=sandbox,
            audit_path=audit_path,
        )

        agent.register_tool(
            "multiply",
            my_agent_test_tool,
            effect=ToolEffect.PURE_READ_ONLY,
        )

        assert agent._kernel.registry.effect("multiply") is ToolEffect.PURE_READ_ONLY
        assert agent._kernel.registry.get("multiply") is not my_agent_test_tool

        # Execute
        res, receipt = agent.dispatch("multiply", {"x": 6, "y": 7})
        assert res == 42
        assert receipt.record.decision == Decision.ALLOW


def test_managed_agent_with_yaml_policy() -> None:
    """Verify that ManagedAgent works seamlessly with loaded YAML policies."""
    yaml_text = """
id: bot-rules
rules:
  - id: block-unsafe-action
    effect: deny
    tools:
      - multiply
    state_contains:
      unsafe: true
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_path = Path(tmpdir) / "audit.jsonl"
        policy = YAMLPolicy.from_yaml(yaml_text)
        agent = ManagedAgent(name="yaml-bot", policy=policy, audit_path=audit_path)

        agent.register_tool(
            "multiply",
            my_agent_test_tool,
            effect=ToolEffect.PURE_READ_ONLY,
        )

        # Dispatch clean call
        res, receipt = agent.dispatch("multiply", {"x": 2, "y": 3}, state={"unsafe": False})
        assert res == 6

        # Dispatch blocked call
        with pytest.raises(DeniedError) as exc_info:
            agent.dispatch("multiply", {"x": 2, "y": 3}, state={"unsafe": True})

        assert "block-unsafe-action" in str(exc_info.value)
