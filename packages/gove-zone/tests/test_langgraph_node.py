"""Focused tests for the LangGraph tool-node wrapper in ``gove_zone.integration``.

``make_langgraph_tool_node`` is the first-class, dependency-free LangGraph
integration point: it models a LangGraph tool node (``fn(state) -> state``) as a
pre-execution governance intercept that routes the proposed tool call through the
SAME passive adapter plumbing (:func:`emit_receipt_for_hook`) every other runtime
family uses, and only runs the wrapped side effect on ALLOW. The load-bearing
invariant here is fail-closed: a DENY (or a missing/malformed call, or a failed
emission) must NOT run the side effect.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gove_zone.decision import Decision
from gove_zone.integration import make_langgraph_tool_node
from gove_zone.policy import DenyAllPolicy

ACTION_KIND = "conformance"
ACTOR = "conformance-bridge"
GOAL = "persist governed conformance evidence"
STATE = {"trust_tier": "analyst"}
CANONICAL_ARGS = {"path": "repo/out/manifest.json", "content": "evidence"}


class _WitnessTool:
    """Records whether its side effect actually ran."""

    def __init__(self) -> None:
        self.ran = False
        self.last_args: dict[str, object] | None = None

    def write(self, *, path: str, content: str) -> str:
        self.ran = True
        self.last_args = {"path": path, "content": content}
        return f"wrote {len(content)} bytes to {path}"


@pytest.fixture(autouse=True)
def _observe_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Isolated audit dir + explicit observe mode so the passive auditor records
    # without the production/enforce signer requirement (covered elsewhere).
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.delenv("GOVE_ZONE_AUDIT_PATH", raising=False)
    monkeypatch.setenv("GOVE_ZONE_GATE_MODE", "observe")
    monkeypatch.delenv("GOVE_ZONE_PROFILE", raising=False)


def _state() -> dict[str, object]:
    return {
        "tool_call": {
            "name": "file.write",
            "args": dict(CANONICAL_ARGS),
            "id": "call_1",
            "type": "tool_call",
        },
        "goal": GOAL,
        "state": STATE,
    }


def test_langgraph_node_allows_and_runs_side_effect() -> None:
    tool = _WitnessTool()
    node = make_langgraph_tool_node(tool.write, action_kind=ACTION_KIND, actor=ACTOR)

    out_state = node(_state())

    assert out_state["governed"]["decision"] == "allowed"
    assert tool.ran is True
    assert tool.last_args == CANONICAL_ARGS
    receipt = out_state["governed"]["receipt"]
    assert receipt is not None
    assert receipt.record.decision is Decision.ALLOW
    assert receipt.record.tool == "runtime.file.write"


def test_langgraph_node_denies_and_side_effect_never_runs() -> None:
    """Fail-closed: a denying policy blocks the node and the tool never runs."""
    tool = _WitnessTool()
    node = make_langgraph_tool_node(
        tool.write,
        action_kind=ACTION_KIND,
        actor=ACTOR,
        policy=DenyAllPolicy(),
    )

    out_state = node(_state())

    assert out_state["governed"]["decision"] == "blocked"
    assert tool.ran is False, "side effect ran despite a DENY decision"
    receipt = out_state["governed"]["receipt"]
    assert receipt is not None
    assert receipt.record.decision is Decision.DENY
    assert receipt.result_hash is None


def test_langgraph_node_missing_tool_call_fails_closed() -> None:
    """A missing/malformed tool call blocks without running the side effect."""
    tool = _WitnessTool()
    node = make_langgraph_tool_node(tool.write, action_kind=ACTION_KIND, actor=ACTOR)

    out_state = node({"goal": GOAL, "state": STATE})

    assert out_state["governed"]["decision"] == "blocked"
    assert tool.ran is False
