"""CopilotKit-governed execution — local proof.

Where ACGS sits relative to CopilotKit:

    user ── CopilotKit chat UI ── agent (LangGraph/CrewAI/…) ── tool call
                                                                    │
                                                             ┌──────▼───────┐
                                                             │  ACGS kernel │  ← this file
                                                             │  + receipt   │
                                                             └──────┬───────┘
                                                              side effect

CopilotKit's runtime speaks MCP. When it is pointed at a governed MCP server,
every tool call the copilot makes becomes a ``tools/call`` that ACGS gates
before any side effect runs. This script simulates exactly the calls a
CopilotKit copilot would emit and drives them through the real ACGS kernel.

It proves three things with the real gove-zone kernel (no LLM, no network):

1. ALLOW  — a benign copilot tool call runs and yields a Decision Receipt.
2. DENY   — a forbidden copilot tool call is blocked; no side effect.
3. ESCALATE — a high-risk call pauses for human approval (CopilotKit's
   human-in-the-loop maps to an ACGS ESCALATE). No side effect until a human
   approves; the escalation is anchored in the audit chain regardless.

Run:

    uv run --package gove-zone python examples/copilotkit_governed/demo.py

Expected: JSON with ``status: "pass"`` and ``side_effect_count: 1`` (only the
ALLOW call executed).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    Kernel,
)
from gove_zone.decision import sha256_json
from gove_zone.errors import DeniedError, EscalateError
from gove_zone.policy import Policy, new_event_id
from gove_zone.tool import ToolCall

ACTOR = "copilotkit-copilot"


class CopilotKitDemoPolicy(Policy):
    """Example policy mapping a copilot's tool calls to ACGS decisions.

    This is illustrative, not a production policy. It shows the three outcomes
    a CopilotKit copilot will hit in practice:

    * DENY      when the canonical args contain a forbidden secret path.
    * ESCALATE  when the copilot calls a tool flagged human-in-the-loop.
    * ALLOW     otherwise.

    Real deployments compose the shipped policies (``BoundaryPolicy``,
    ``PathBoundaryPolicy``, ``RuleSetPolicy``) instead of hand-rolling this.
    """

    #: Tools that require a human to approve before executing — i.e. the calls
    #: CopilotKit would surface through its human-in-the-loop UI.
    HUMAN_IN_THE_LOOP_TOOLS = frozenset({"runtime.payment.send"})

    #: Forbidden substrings (case-insensitive) in string argument values.
    FORBIDDEN = ("/.ssh/", "id_rsa", "secrets/")

    @property
    def version(self) -> str:
        return "copilotkit-demo-policy/v1"

    def _first_forbidden_value(self, value: Any) -> str | None:
        if isinstance(value, str):
            lowered = value.lower()
            return next((kw for kw in self.FORBIDDEN if kw in lowered), None)
        if isinstance(value, dict):
            for child in value.values():
                matched = self._first_forbidden_value(child)
                if matched:
                    return matched
        elif isinstance(value, (list, tuple, set)):
            for child in value:
                matched = self._first_forbidden_value(child)
                if matched:
                    return matched
        return None

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        args = dict(call.args)
        args_blob = sha256_json(args)

        matched_kw = self._first_forbidden_value(args)
        matched = [matched_kw] if matched_kw else []
        if matched:
            decision, reason = Decision.DENY, f"forbidden arg: {matched[0]}"
        elif call.name in self.HUMAN_IN_THE_LOOP_TOOLS:
            decision, reason = Decision.ESCALATE, "human-in-the-loop approval required"
        else:
            decision, reason = Decision.ALLOW, "within copilot tool boundary"

        return DecisionRecord(
            decision=decision,
            tool=call.name,
            argument_hash=args_blob,
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=tuple(matched),
            reason=reason,
        )


# --- the side-effectful tool a CopilotKit MCP server would expose -----------


class GovernedTools:
    def __init__(self) -> None:
        self.side_effects = 0

    def file_write(self, path: str, content: str) -> str:
        self.side_effects += 1
        return f"WROTE {len(content)} bytes to {path}"

    def payment_send(self, to: str, amount: float) -> str:  # pragma: no cover
        # Never reached in this demo: the policy escalates it first.
        self.side_effects += 1
        return f"SENT {amount} to {to}"


# --- the tool calls a CopilotKit copilot would emit, as MCP-style payloads --

COPILOT_TOOL_CALLS: list[dict[str, Any]] = [
    {
        "name": "runtime.file.write",
        "arguments": {"path": "evidence/report.json", "content": "governed proof"},
        "goal": "persist a governed evidence file",
        "expect": "allow",
    },
    {
        "name": "runtime.file.write",
        "arguments": {"path": "/home/user/.ssh/authorized_keys", "content": "attacker-key"},
        "goal": "exfiltrate by writing an SSH key",
        "expect": "deny",
    },
    {
        "name": "runtime.payment.send",
        "arguments": {"to": "vendor-x", "amount": 5000.0},
        "goal": "pay an invoice the copilot drafted",
        "expect": "escalate",
    },
]


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        audit = ChainHashAuditStore(Path(tmp) / "copilotkit-audit.jsonl")
        tools = GovernedTools()
        kernel = Kernel(policy=CopilotKitDemoPolicy(), audit=audit, actor=ACTOR)

        kernel.registry.register("runtime.file.write", tools.file_write)
        kernel.registry.register("runtime.payment.send", tools.payment_send)

        outcomes: list[dict[str, Any]] = []
        for tc in COPILOT_TOOL_CALLS:
            entry: dict[str, Any] = {
                "tool": tc["name"],
                "goal": tc["goal"],
                "expected": tc["expect"],
            }
            try:
                result, receipt = kernel.dispatch(tc["name"], tc["arguments"], goal=tc["goal"])
                entry["decision"] = "allow"
                entry["executed"] = True
                entry["result"] = result
                entry["receipt_audit_hash"] = receipt.audit_hash
            except DeniedError as exc:
                entry["decision"] = "deny"
                entry["executed"] = False
                entry["audit_hash"] = exc.audit_hash
                entry["reason"] = exc.record.reason
            except EscalateError as exc:
                entry["decision"] = "escalate"
                entry["executed"] = False
                entry["audit_hash"] = exc.audit_hash
                entry["reason"] = exc.record.reason
                entry["pending"] = "awaiting human approval (CopilotKit HITL)"
            entry["matched_expectation"] = entry["decision"] == tc["expect"]
            outcomes.append(entry)

        executed = [o for o in outcomes if o["executed"]]
        all_matched = all(o["matched_expectation"] for o in outcomes)
        only_allow_ran = tools.side_effects == 1 and executed and executed[0]["decision"] == "allow"

        report = {
            "status": "pass" if all_matched and only_allow_ran else "fail",
            "side_effect_count": tools.side_effects,
            "outcomes": outcomes,
            "invariant": "No valid Decision Receipt, no side effect.",
            "note": (
                "CopilotKit remains the chat/agent UX; ACGS governs whether each "
                "copilot tool call may produce a side effect."
            ),
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
