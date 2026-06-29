# The Agent Stack Governance Map

Where ACGS / gove-zone sits in the modern agent-builder stack, and how it
differs from the alternatives. Companion to [COMPARISON.md](COMPARISON.md).

## The stack, and the line everyone skips

The agent ecosystem races to give agents more agency — protocol-level
delegation (A2A), tool access (MCP), autonomous planners (Deep Agents), and
voice agents that take real actions for real customers. "The best agents are
simple" — but simple agents still fire irreversible side effects.

All that energy sits *above* the action line. The line itself — *should this
action actually execute?* — is mostly ungoverned, or governed only by
after-the-fact logging.

ACGS owns the line. It is the execution membrane below agent reasoning and
above side-effectful tools, where **no valid Decision Receipt → no side
effect**.

```
  AGENT REASONING / ORCHESTRATION              models: Claude · GPT · Gemini
  Sierra · LangGraph · Deep Agents · planners      (decide WHAT to do)
                     │ proposes action
                     ▼
   ╔══════════════════════════════════════════════════════════════╗
   ║  ACGS GOVERNANCE MEMBRANE   "no valid receipt → no effect"    ║
   ║  policy gate → Decision Receipt → fail-closed executor        ║
   ║  audit chain · single-use receipts · replay / proof-pack      ║
   ╚══════════════════════════════════════════════════════════════╝
      ▲ MCP                  ▲ LangGraph              ▲ A2A / agent-bus
   governed_mcp_v0 +      adapters/langgraph.py    integration.py
   acgs-lite MCP          (reference sketch)       (docstring only)
   [exists]              [partial]                [thin]
                     │ permitted action only
                     ▼
  SIDE-EFFECTFUL TOOLS / WORLD
  refunds · bookings · DB writes · sends · code edits
```

The ecosystem adds agency *above* the line; ACGS owns the line; and it already
reaches into the stack at three honest maturity levels.

## Insertion points (verified maturity)

Each maturity flag was verified by reading the file. Nothing is flagged
`exists` without a runnable, tested implementation.

| Stack entry | ACGS insertion point | File(s) | Maturity |
|---|---|---|---|
| MCP tool calls | Governed MCP server (gate before tool admission) | `acgs_governance_eval_mvp/governed_mcp_v0/mcp_server.py`; `packages/acgs-lite/src/acgs_lite/integrations/mcp_server.py` | **exists** |
| Generic runtime hooks (Claude Code `PreToolUse`, Codex `apply_patch`) | Canonical hook → ToolCall → Receipt adapter | `packages/gove-zone/src/gove_zone/integration.py` | **exists** |
| Agent-eval (Tau-bench style) | Security/governance benchmark adapters | `acgs_governance_eval_mvp/governance/benchmarks/agentdojo_adapter.py` (+ injecagent, toolemu) | **exists (adjacent)** |
| LangGraph tool nodes | `before_tool_node` governance pre-check | `acgs_governance_eval_mvp/governance/adapters/langgraph.py` | **partial** (reference sketch, no real `langgraph` dep) |
| A2A agent↔agent | Receipt-gated delegation at the boundary | `packages/gove-zone/src/gove_zone/integration.py` (docstring only) | **thin** (no adapter/AgentCard/discovery yet) |

The **partial** and **thin** rows are the roadmap: a LangGraph demo that fails
closed without a receipt (next), then A2A-native receipts (after).

## How this differs

See [COMPARISON.md](COMPARISON.md#governance-posture-none-vs-audit-centric-vs-receipt-centric)
for the three-tier posture contrast (ungoverned vs audit-centric vs
receipt-centric).

> **Honest scope.** ACGS is a technical governance membrane — a mechanism for
> gating actions and emitting verifiable receipts. It is **not a compliance certification**,
> not regulator approval, and not a production-readiness guarantee.
> This map describes mechanism, not accreditation.
