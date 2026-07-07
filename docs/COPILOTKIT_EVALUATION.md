# CopilotKit Evaluation — Replace our agent interface?

**Date:** 2026-06-06
**Verdict in one line:** CopilotKit is **not a replacement** for anything ACGS owns. It is a *complementary* layer that could (a) build the in-app console chat UI we don't yet have, and (b) become a flagship integration that ACGS governs. The "replace what we have now" framing rests on a layer mismatch.

---

## 1. The layer mismatch (read this first)

ACGS / gove-zone is the **execution membrane below agent reasoning and above side-effectful tools**. Its invariant is *"No valid Decision Receipt, no side effect."* It does not plan, chat, or reason — it decides whether an executor may run an action and emits a verifiable receipt.

CopilotKit is the **copilot UX layer above agent reasoning**. It is a React/Angular/Vue frontend SDK plus a Node backend runtime that connects agent frameworks (LangGraph, CrewAI, Mastra, PydanticAI) to a chat/generative-UI surface via the **AG-UI protocol**. MIT-licensed.

```
 user ── CopilotKit chat UI ── agent framework (LangGraph/CrewAI/…) ── tool calls
                                                                          │
                                                                   ┌──────▼───────┐
                                                                   │  ACGS gate   │  ← we live HERE
                                                                   │  + receipt   │
                                                                   └──────┬───────┘
                                                                     side effect
```

They sit on **opposite sides** of the tool-call boundary. You cannot swap one for the other any more than you can replace a database with a charting library.

## 2. What "our agent interface" actually is today

| Surface | Reality | File |
|---|---|---|
| Frontend console | Read-only governance dashboards + a trace/run-path viewer. **No conversational/chat surface found.** | `acgi-ai/src/routes/**` (incl. `workbench-content.ts` — static trace content) |
| Hook/integration adapter | Maps Claude Code `PreToolUse` + MCP events → decision → receipt | `packages/gove-zone/src/gove_zone/integration.py` |
| Governed MCP server | `admit(action_id, tool_name, args)` → `AdmissionDecision` + JSONL receipts | `acgs_governance_eval_mvp/governed_mcp_v0/` |
| Lifecycle HTTP API | FastAPI `/draft /submit /eval /approve /stage /activate`, HMAC + actor headers | `packages/acgs-lite/src/acgs_lite/constitution/lifecycle_router.py` |
| Frontend API client | Typed, **polling only** (5–60s); no websocket/SSE | `acgi-ai/src/api/` |

No agent-UI dependency is installed anywhere (no CopilotKit / Vercel AI SDK / assistant-ui / LangGraph in any `package.json`).

## 3. Three honest readings of the request

**Reading A — "Replace the governance backend with CopilotKit."**
→ **No.** Category error. Different layer. CopilotKit has no policy engine, no receipts, no fail-closed executor. Adopting it here would delete our entire reason to exist.

**Reading B — "Build the in-app console chat/copilot UI we lack."**
→ **Plausible candidate, but gated.** CopilotKit is a legitimate way to add a conversational console surface *on top of* ACGS. **It is blocked by the privileged-origin / CSP rule** (CLAUDE.md #4; AGENTS.md "no public-only CDN/script patterns in console routes"). CopilotKit needs either:
  - *CopilotKit Cloud* → third-party origin → **CSP violation in console routes.** Disqualified as-is.
  - *Self-hosted Node runtime + an LLM provider key* → a brand-new always-on service and a fresh attack surface, for a product whose pitch is fail-closed minimalism. Possible, but a real architectural commitment, not a drop-in.
  - **Must-verify before any console adoption:** exact CSP footprint, whether the runtime can be same-origin, and whether streaming can go through our existing API origin.

**Reading C — "Position ACGS as the governance/receipt layer under CopilotKit-style agents."**
→ **This is the on-strategy play. Recommended.** CopilotKit speaks AG-UI and **MCP**. Its runtime can call our `governed_mcp_v0` MCP server; every tool call the copilot attempts is gated and produces a receipt. That is a demo that *showcases* ACGS to the exact audience building agent apps — an integration, not a replacement. Low risk: it touches the example/integration layer, not the kernel or the privileged console.

## 4. Recommendation

1. **Do not replace** any ACGS component (Reading A is off the table).
2. **Pursue Reading C first** — build a small `examples/copilotkit_governed/` proof: a CopilotKit app whose MCP tool calls route through our governed MCP server and fail closed without a receipt. Highest narrative value, lowest blast radius, stays out of sealed/console code.
3. **Defer Reading B** (console chat UI) until the CSP/same-origin runtime question is answered. If we ever want it, prefer a same-origin self-hosted runtime; never CopilotKit Cloud in console routes.

## 5. Scope note

This document is analysis only. No dependencies added, no migration started, no kernel/console files touched. Next concrete action, if approved: scaffold the Reading-C example under `examples/`.
