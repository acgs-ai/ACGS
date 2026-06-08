# CopilotKit-governed execution example

Shows where ACGS belongs relative to [CopilotKit](https://github.com/CopilotKit/CopilotKit): **not as a replacement, but as the membrane underneath it.** CopilotKit owns the chat / agent UX; ACGS governs whether each tool call the copilot makes may actually produce a side effect.

```
 user ── CopilotKit chat UI ── agent (LangGraph/CrewAI/…) ── tool call
                                                                 │
                                                          ┌──────▼───────┐
                                                          │  ACGS kernel │  ← this example
                                                          │  + receipt   │
                                                          └──────┬───────┘
                                                           side effect
```

CopilotKit's runtime speaks **MCP**. Point it at a governed MCP server and every copilot tool call becomes a `tools/call` that ACGS gates before execution.

## Run

```bash
uv run --package gove-zone python examples/copilotkit_governed/demo.py
```

Expected output: JSON with `status: "pass"`, `side_effect_count: 1`, and three outcomes whose decisions are `allow`, `deny`, `escalate`. Only the ALLOW call executes and receives a Decision Receipt; the DENY and ESCALATE calls are blocked but still anchored in the audit chain (each carries an `audit_hash`).

## What it proves

| Copilot tool call | ACGS decision | Side effect? | Receipt |
|---|---|---|---|
| `runtime.file.write` → benign path | **ALLOW** | yes | issued |
| `runtime.file.write` → `~/.ssh/authorized_keys` | **DENY** | no | none |
| `runtime.payment.send` (high-risk) | **ESCALATE** | no — awaits human | none until approved |

The script drives the **real `gove_zone` kernel** (`Kernel.dispatch`), real policy evaluation, and the real hash-chained audit store. No LLM, no network.

### CopilotKit human-in-the-loop ↔ ACGS ESCALATE

CopilotKit's [human-in-the-loop](https://docs.copilotkit.ai) pauses an agent to ask a human before continuing. That pause maps cleanly onto an ACGS `ESCALATE` decision: the kernel refuses to execute and raises `EscalateError`, so the action stays pending until a human approves — at which point a receipt is issued and the side effect may run. The escalation itself is auditable whether or not the human ever approves.

## Wiring a real CopilotKit runtime (illustrative)

The demo simulates the tool calls a copilot emits. In a real app, CopilotKit's runtime forwards them to a governed MCP server. The shape (verify against current CopilotKit + MCP docs — this is wiring intent, not a tested integration):

```ts
// CopilotKit runtime → governed MCP server (stdio)
const runtime = new CopilotRuntime({
  mcpServers: [
    {
      // the ACGS governed MCP server in this repo
      command: "uv",
      args: ["run", "python", "-m", "acgs_governance_eval_mvp.governed_mcp_v0.mcp_server"],
    },
  ],
});
```

Every `tools/call` the copilot makes is then admitted (or denied/escalated) by `GovernedMCPServer.admit(...)` before any side effect, exactly as this demo proves at the kernel level.

## Limitations

This example is **local-only**. It proves executor placement and ALLOW/DENY/ESCALATE failure behavior against the real kernel. It does **not** prove:

- a live, end-to-end CopilotKit ↔ governed-MCP integration (the TypeScript snippet is illustrative wiring, not a tested path);
- production deployment, compliance certification, or regulator approval;
- any claim about the CopilotKit project itself beyond "its runtime speaks MCP."

The policy in `demo.py` (`CopilotKitDemoPolicy`) is illustrative. Real deployments compose the shipped policies (`BoundaryPolicy`, `PathBoundaryPolicy`, `RuleSetPolicy`) instead.

See `examples/mcp_tool_gate/` for the minimal MCP-transport version of the same boundary, and `docs/COPILOTKIT_EVALUATION.md` for the full "should we adopt CopilotKit?" analysis.
