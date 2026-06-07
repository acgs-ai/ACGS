# CopilotKit front-end integration — build-ready plan

**Date:** 2026-06-07 (revised after empirical gate testing)
**Decision:** Run CopilotKit **server-side only** (`@copilotkit/runtime` as a same-origin `/api/copilotkit` endpoint) and talk to it from a **thin custom AG-UI browser client** built in the `acgi-ai` design system. Do **not** ship any CopilotKit browser package (`@copilotkit/react-core` or `@copilotkit/react-ui`) to either surface. The copilot's tool calls route through ACGS governance. Companion analysis: `docs/COPILOTKIT_EVALUATION.md`. Governance boundary proof: `examples/copilotkit_governed/`.

## Why no CopilotKit browser package (verified 2026-06-07)

Two of `acgi-ai`'s locked gates each independently rule out the CopilotKit React client. Both were confirmed by installing `@copilotkit/react-core@1.59.5` and running the gates, then reverting.

### Gate 1 — marketing performance budget (the hard blocker)

`scripts/check-performance-budget.mjs` sums the gzip of **all** emitted `.js`/`.css` and enforces **marketing ≤ 200 KiB**. The budget is locked: `scripts/check-security-invariants.mjs` fails if the perf gate is unwired or the docs drop the 200 KB figure.

Measured with react-core wired (lazy + flag-gated):

```
marketing gzipped JS+CSS budget exceeded: 3280.5 KiB > 200.0 KiB
```

`@copilotkit/react-core` is **not** a lean headless core. Its direct dependencies include `katex`, `react-markdown`, `streamdown`, `@copilotkit/a2ui-renderer` (generative UI), `@copilotkit/web-inspector`, and `@radix-ui/*`. The tree is ~3.28 MiB gzip — **16× the budget**. Lazy-loading does not help: the gate counts total emitted bytes by design, and an enabled feature would still ship multi-MB to a marketing page.

### Gate 2 — console strict CSP

`infra/Caddyfile`: `style-src 'self'` with no `'unsafe-inline'`. CopilotKit's browser tree (`react-ui` → react-syntax-highlighter/Headless UI; `react-core` → Radix UI) injects runtime inline styles, which the console CSP hard-blocks. (Marketing's report-only CSP would render but log violations.)

Either gate alone is disqualifying. Together they close the browser-package path completely.

## Target architecture

Keep CopilotKit where it is light and valuable — the **runtime + AG-UI protocol, server-side** — and own the browser surface ourselves.

```
 browser (same-origin only — connect-src 'self')
   └─ thin AG-UI client (~few KB, design-system UI, no inline styles)
        ├─ POST/SSE  /api/copilotkit         (AG-UI events: messages, tool calls)
        └─ governed action → POST /api/governance/admit  (same-origin)
   ─────────────────────────────────────────────────────────────────────────────
 server (LLM key + governance live here; never in the browser)
   ├─ /api/copilotkit   CopilotRuntime (@copilotkit/runtime, Node) ── LLM provider
   └─ /api/governance/* ACGS governance bridge (HTTP) ──► gove_zone kernel / governed_mcp_v0
                                                          ALLOW→receipt→execute · else fail closed
```

The thin client implements the AG-UI event stream (or wraps `@ag-ui/client` only if it tree-shakes under budget — to be measured) plus a CSP-clean chat UI from the design system. The fail-closed governed-action client (`admitAction`: any non-ALLOW / error → no side effect) is framework-agnostic and was prototyped during this investigation; it is reusable as-is.

**Bridge is HTTP, not stdio.** Vercel functions (marketing) can't reliably spawn the Python `governed_mcp_v0` over stdio per request; expose governance over HTTP (precedent: `acgs-lite` `lifecycle_router`). Cloud Run (console) could use stdio but should use the same HTTP bridge for parity.

### Per-surface runtime placement

| Surface | Host | Runtime route | Governance bridge |
|---|---|---|---|
| Marketing | Vercel (static SPA) | `api/copilotkit.ts` serverless function | HTTP to governance service |
| Console | Cloud Run + Caddy | same-origin Node runtime service behind Caddy `/api/copilotkit` | HTTP to governed bus (existing fail-closed `/api/*` proxy precedent) |

Both keep `connect-src 'self'`: the browser only talks to its own origin; the runtime talks to the LLM and governance server-side.

## Phasing

- **Phase 1 — server runtime + thin client spike:** stand up `@copilotkit/runtime` behind `/api/copilotkit`; build a minimal AG-UI browser client + CSP-clean panel; verify the marketing bundle stays **< 200 KiB** (the gate that killed react-core) and CSP gates stay green. *Needs an LLM key for the live loop — that part deferred.*
- **Phase 2 — governed actions:** wire `/api/governance/admit` to the ACGS kernel/governed-MCP; reuse the fail-closed `admitAction` client; add a negative-path test proving DENY/ESCALATE/error → no side effect (`~/.claude/rules/review-handler-wiring.md`).
- **Phase 3 — console surface:** reuse the thin client; stand up the same-origin Node runtime in the Caddy/Cloud Run topology; confirm strict CSP holds in-browser and the fail-closed bus is preserved.
- **Phase 4 — deploy:** human-gated (Vercel + GCP-WIF secrets; `gh`/`gcloud`/`vercel` denied to agents). Prep only.

## Explicitly deferred / not verifiable this session

- Live chat loop (no LLM key in this environment).
- The thin AG-UI client itself (this session proved what is **not** viable and fixed the plan; it did not build the client).
- Deploy (human-gated).
- Whether `@ag-ui/client` alone fits the 200 KiB budget — must be measured before depending on it; otherwise hand-roll the SSE client.

## Risk register

- **Supply chain:** even the server `@copilotkit/runtime` pulls a large tree (graphql, etc.); it runs server-side so it doesn't hit the browser budget, but vet it. `@scarf/scarf` (transitive) phones home at install — set `SCARF_ANALYTICS=false`.
- **Budget discipline:** never raise the marketing 200 KiB budget to fit a browser SDK; it ships to users and the gate is security-locked.
- **Design + privilege:** thin-client UI must pass DESIGN.md review (separate lane) and the governed action must fail closed with a negative-path test before being called "governed".
