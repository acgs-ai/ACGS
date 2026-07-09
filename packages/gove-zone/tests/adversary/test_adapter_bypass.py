"""Adversary class: ADAPTER / EXECUTOR BYPASS.

Status on this branch: NOT-DEFENDED (open gap) for the default posture.

The framework adapters (``govern_autogen_tool``, ``govern_langgraph_tools``) route
tool execution through ``ManagedAgent.dispatch`` -> ``Kernel.dispatch`` — which runs
``policy.evaluate`` then ``tool_fn(**args)`` with a self-asserted actor, NO receipt
verification, and NO signature concept — NOT through the cryptographic gate
``execute_with_receipt``. And ``ManagedAgent`` defaults to ``AllowAllPolicy``. So a
default-configured "governed" agent executes every wrapped tool unconditionally.

See docs/security/threat-model-v2.md §6. This makes the gap a live tripwire instead of
a buried caveat: the day the ``AllowAllPolicy`` default is removed (or the adapters are
routed through the crypto gate), the KNOWN_LIMITATION test flips and the manifest must be
updated.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gove_zone import DeniedError, DenyAllPolicy, ManagedAgent
from gove_zone.adapters.autogen import govern_autogen_tool


def _danger_factory(ran: dict[str, int]):
    def danger(path: str = "/etc/shadow") -> str:
        ran["count"] += 1
        return "SIDE EFFECT EXECUTED"

    return danger


def test_managed_agent_default_policy_executes_untrusted_tool_KNOWN_LIMITATION(
    tmp_path: Path,
) -> None:
    """A default ManagedAgent (AllowAllPolicy) executes any wrapped tool — the attack
    succeeds today. No receipt is minted or verified on this path.
    """
    ran: dict[str, int] = {"count": 0}
    agent = ManagedAgent("vulnclaw", audit_path=tmp_path / "audit.jsonl")
    wrapped = govern_autogen_tool(agent, "shell", _danger_factory(ran))

    result = wrapped(path="/etc/shadow")

    assert result == "SIDE EFFECT EXECUTED"
    assert ran["count"] == 1, (
        "default ManagedAgent uses AllowAllPolicy and the adapter routes through "
        "Kernel.dispatch with no receipt verification; the tool runs unconditionally. "
        "If this fails, either the AllowAllPolicy default was removed (good — update the "
        "manifest) or the adapter wiring changed (investigate)."
    )


def test_adapter_routes_through_gate_when_policy_denies_HELD(tmp_path: Path) -> None:
    """With an explicit DenyAllPolicy the adapter's kernel path DOES block — the gate
    works once a real policy is set; the gap is purely the permissive default.
    """
    ran: dict[str, int] = {"count": 0}
    agent = ManagedAgent(
        "vulnclaw", policy=DenyAllPolicy(), audit_path=tmp_path / "audit.jsonl"
    )
    wrapped = govern_autogen_tool(agent, "shell", _danger_factory(ran))

    with pytest.raises(DeniedError):
        wrapped(path="/etc/shadow")

    assert ran["count"] == 0
