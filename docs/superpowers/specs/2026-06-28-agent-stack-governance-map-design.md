# Design — Agent Stack Governance Map (Wave 1 of "Connect the Stacks")

- **Date:** 2026-06-28
- **Status:** Draft for review
- **Owner:** Martin
- **Skill trail:** brainstorming → (this spec) → writing-plans

## Why this exists

We analyzed the citation list from the Max Agency Podcast episode *"The best
agents are simpler than you think"* (LangChain × Sierra). It maps the live
agent-builder ecosystem: models (Claude/GPT/Gemini), frameworks (LangGraph,
Deep Agents), protocols (MCP, A2A), evals (Tau-bench), voice (Silero VAD), and
real deployments (Sierra agents for SiriusXM, Redfin).

That whole ecosystem races to give agents **more agency** — and stops at the
point where an agent actually *does* something irreversible. ACGS / gove-zone
owns exactly that point: the execution membrane below agent reasoning and above
side-effectful tools, where **no valid Decision Receipt → no side effect**.

The connection is mostly *already built* (see the maturity grid). This wave makes
it **legible**: one map that places ACGS in the stack and names every insertion
point, honestly flagged by maturity.

## The 3-wave workflow (decomposition)

This spec is **Wave 1 only**. Waves 2–3 get their own spec → plan → build cycles,
each gated on what the prior wave learned (the "dynamic" part).

| Wave | Name | Output | Gate from prior |
|---|---|---|---|
| **1 (this spec)** | Position | The Stack Map doc + COMPARISON contrast block | — |
| **2** | Prove | Runnable demo gating a real stack agent's tool calls with ACGS receipts | Built against the map's `partial` rows |
| **3** | Plug | Close the highest-value gap the demo exposes (likely A2A-native receipts) | Targets the map's `thin` rows |

## Wave 1 design

### Artifact

- **New file:** `docs/AGENT_STACK_GOVERNANCE.md` — the map: diagram + narrative +
  insertion-point table.
- **Edit:** add a 3-tier contrast block to `docs/COMPARISON.md`.
- **Format:** Markdown with an embedded diagram (ASCII first; a mermaid block may
  be added if it renders in the docs pipeline). No SVG/design tooling in Wave 1.
- **No marketing-page change** — the 200 KiB marketing perf budget makes that a
  separate, later task.

### The diagram (structure)

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
  refunds (Stripe) · bookings · DB writes · sends · code edits
```

The argument in one image: the ecosystem adds agency *above* the line; ACGS owns
the line; three plugs already reach it, at three honest maturity levels.

### The narrative arc

1. **Setup** — the ecosystem races to add agency (A2A delegation, MCP tools,
   autonomous Deep Agents, voice agents acting for real customers). Simple agents
   still fire irreversible side effects.
2. **Gap** — that energy is all *above* the action line. The line itself —
   "should this action execute?" — is ungoverned or only logged after the fact.
3. **Wedge** — ACGS is the membrane *at* the line: policy-gated, emits a
   verifiable Decision Receipt, fails closed without one. Not a framework, not a
   model — the execution membrane.
4. **Proof of fit** — ACGS already speaks the stack's languages (MCP, LangGraph,
   A2A-shaped events). Connecting is wiring, not greenfield.

### The 3-tier contrast (for COMPARISON.md)

| Posture | Acts… | You get | Example |
|---|---|---|---|
| **Ungoverned** (most of stack today) | agent → tool directly | speed, zero accountability | raw MCP server, vanilla LangGraph |
| **Audit-centric** | logs *after* the action | a trail you read after harm | Microsoft Agent Governance Toolkit |
| **Receipt-centric (ACGS)** | gates *before* the action | every action carries a verifiable, single-use receipt; fail-closed | gove-zone |

**Honest caveat (required by `AGENTS.md` forbidden-claims rules):** ACGS is a
technical membrane, not a compliance certification, regulator approval, or a
"production-ready" guarantee. The map describes mechanism, not accreditation.

### Insertion-point table (the keystone) — verified maturity

Each row's maturity was verified by reading the file on 2026-06-28. No row is
flagged `exists` without a runnable, tested implementation.

| Stack entry | ACGS insertion point | File(s) | Maturity | Evidence |
|---|---|---|---|---|
| **MCP tool calls** | Governed MCP server (gate before tool admission) | `acgs_governance_eval_mvp/governed_mcp_v0/*` ; `packages/acgs-lite/src/acgs_lite/integrations/mcp_server.py` | **exists** | FastMCP server + `DeterministicPolicyEngine`, replay verify, `test_governed_mcp_v0.py` + concurrency test; acgs-lite server is 810 LoC, runnable via `python -m`, hash-sealed |
| **LangGraph tool nodes** | `before_tool_node` governance pre-check wrapper | `acgs_governance_eval_mvp/governance/adapters/langgraph.py` | **partial** | 58-LoC *reference adapter*, "no real `langgraph` dependency required"; covered by `test_reference_adapters.py` but not wired to an actual LangGraph graph |
| **A2A agent↔agent** | Receipt-gated delegation at the integration boundary | `packages/gove-zone/src/gove_zone/integration.py` | **thin** | Only a docstring mention ("generic A2A/MCP tool events"); no A2A adapter, AgentCard, or discovery handling |
| **Generic runtime hooks** (Claude Code PreToolUse, Codex apply_patch) | Canonical hook→ToolCall→Receipt adapter | `packages/gove-zone/src/gove_zone/integration.py` | **exists** | Documented canonical adapter, observation-by-default, `enforce` mode fails closed |
| **Tau-bench-style eval** | Security/governance benchmark adapters | `acgs_governance_eval_mvp/governance/benchmarks/{agentdojo,injecagent,toolemu}_adapter.py` | **exists (adjacent)** | Real adapters for AgentDojo / InjecAgent / ToolEmu; not yet a Tau-bench adapter specifically |

### Scope / YAGNI

**In scope:** the two doc artifacts above and the verified maturity table.

**Out of scope (Wave 1):** any new code or adapter; marketing-page edits; SVG/diagram
tooling; a full thought-leadership essay (optional follow-up, not now); a Tau-bench
adapter (Wave 3 candidate).

### Success criteria

1. A stack-literate reader who doesn't know ACGS can, in ~60s, state where ACGS
   sits and how it differs (receipt vs audit vs none).
2. Every `exists` cell is backed by a real file path verified by reading it — zero
   overclaim. `partial`/`thin` are labeled as such, not dressed up.
3. The `partial` and `thin` rows form an explicit, ordered Wave-2/3 target list.
4. Lands gate-clean: `make lint-docs` and the `tests-docs` suite pass.

## Hand-off to Wave 2

The map's honest grid sets the Wave-2 demo target: take the **`partial` LangGraph
row** (or the solid MCP row) and build a runnable agent whose tool call is gated by
a real ACGS receipt and fails closed without one. The **`thin` A2A row** is the
leading Wave-3 capability gap (A2A-native receipts / AgentCard-bound delegation).

## Risks / open questions

- **Mermaid rendering** in the docs pipeline is unverified — default to ASCII; add
  mermaid only if it renders. (Low risk.)
- **COMPARISON.md** already contains a Microsoft AGT contrast (per project memory);
  the new 3-tier block must extend, not duplicate it. Reconcile on edit.
- **"Ungoverned/audit-centric" framing of named competitors** must stay factual and
  sourced (AGT's own docs say audit-centric) to avoid an unfair-claim violation.
