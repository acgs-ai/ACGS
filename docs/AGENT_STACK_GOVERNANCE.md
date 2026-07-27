# The Agent Stack Governance Map

Where ACGS sits in the modern agent-builder stack, and how it
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
   governed_mcp_v0 +      langgraph_governed_agent  a2a.py delegation
   acgs-lite MCP          (contract mirror)         (contract-level)
   [exists]              [exists]                 [exists]
                     │ permitted action only
                     ▼
  SIDE-EFFECTFUL TOOLS / WORLD
  refunds · bookings · DB writes · sends · code edits
```

The ecosystem adds agency *above* the line; ACGS owns the line; and it already
reaches into the stack at verified, honestly-qualified maturity levels.

## Insertion points (verified maturity)

Each maturity flag was verified by reading the file. Nothing is flagged
`exists` without a runnable, tested implementation.

| Stack entry | ACGS insertion point | File(s) | Maturity |
|---|---|---|---|
| MCP tool calls | Governed MCP server (gate before tool admission) | `acgs_governance_eval_mvp/governed_mcp_v0/mcp_server.py`; `packages/acgs-lite/src/acgs_lite/integrations/mcp_server.py` | **exists** |
| Generic runtime hooks (Claude Code `PreToolUse`, Codex `apply_patch`) | Canonical hook → ToolCall → Receipt adapter | `packages/gove-zone/src/gove_zone/integration.py` | **exists** |
| Agent-eval (Tau-bench style) | Security/governance benchmark adapters | `acgs_governance_eval_mvp/governance/benchmarks/agentdojo_adapter.py` (+ injecagent, toolemu) | **exists (adjacent)** |
| LangGraph tool nodes | Governed tool node + conditional-edge remediation; denial raises before the executor is ever invoked | `acgs_governance_eval_mvp/examples/langgraph_governed_agent/governed_graph.py` (via `governance/adapters/langgraph.py`); `acgs_governance_eval_mvp/tests/test_langgraph_graph_wiring.py` | **exists (contract mirror)** — mirrors LangGraph's node-dispatch + conditional-edge contract; no real `langgraph` dep by design (adapters target the callback contract, not the SDK) |
| A2A agent↔agent | Receipt-gated delegation bound to the delegating principal (AgentCard-identified remote agent) | `packages/gove-zone/src/gove_zone/a2a.py`; `packages/gove-zone/examples/a2a_governed_delegation/`; `packages/gove-zone/tests/test_a2a_delegation.py` | **exists (contract-level)** — mirrors the A2A delegation contract; no transport/discovery/JSON-RPC, and it consumes an already transport-authenticated delegator identity |

The two former gap rows have landed: the LangGraph governed graph fails closed
before its side-effect executor is invoked, and A2A delegation fails closed on
forged or unbound delegations (see the listed tests). Remaining roadmap for
these surfaces: conformance adapters against the real `langgraph` / `a2a`
SDKs, A2A transport/discovery, and AutoGen / CrewAI (see
[INTEGRATION_MATRIX.md](INTEGRATION_MATRIX.md)).

## How this differs

See [COMPARISON.md](COMPARISON.md#governance-posture-none-vs-audit-centric-vs-receipt-centric)
for the three-tier posture contrast (ungoverned vs audit-centric vs
receipt-centric).

> **Honest scope.** ACGS is a technical governance membrane — a mechanism for
> gating actions and emitting verifiable receipts. It is **not a compliance certification**,
> not regulator approval, and not a production-readiness guarantee.
> This map describes mechanism, not accreditation.
