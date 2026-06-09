# `src/copilot` — governed copilot (Phase 1 spike)

A CSP-clean, design-system chat panel that talks to a same-origin CopilotKit runtime over the **AG-UI protocol**, with every side-effectful tool call gated by ACGS.

Why this shape (not `@copilotkit/react-ui` / `@copilotkit/react-core`): those pull katex/markdown/Radix (~3.28 MB) and blow the locked **200 KiB** marketing perf budget + the strict console CSP. This module uses only `@ag-ui/client` (the lightweight protocol client). Full rationale: `docs/COPILOTKIT_FRONTEND_PLAN.md`; memory note `acgs-copilotkit-frontend-incompatible`.

## Files

| File | Role |
|---|---|
| `governance.ts` | `admitAction()` — same-origin `/api/governance/admit` client. **Fail-closed**: only `allow` + a `receiptAuditHash` authorises a side effect; DENY/ESCALATE/error/non-2xx/malformed → no execution. Framework-agnostic. |
| `transport.ts` | `createTransport()` — wraps `HttpAgent` (`@ag-ui/client`) pointed at same-origin `/api/copilotkit`. |
| `CopilotPanel.tsx` | The chat UI. No inline styles; visuals are `.copilot-*` classes in `src/csp-utilities.css`. Handles the no-runtime-yet case without crashing. |
| `CopilotMount.tsx` | Default export → lazy chunk boundary. |

## Enabling

Off by default. The panel is lazy-loaded and only mounts when:

```bash
VITE_COPILOT_ENABLED=true pnpm dev        # show the panel
VITE_COPILOT_RUNTIME_URL=/api/copilotkit  # same-origin runtime (default)
```

Wired into `src/surfaces/marketing/App.tsx` via `lazy()` + the flag. The flag gates runtime **mount/download**, not bundle cost: the chunk is always emitted and counts toward the perf budget — **+44.5 KiB gzip** (marketing total 174.1 / 200 KiB). Phase-2 streaming + tool-call wiring eats into the remaining 25.9 KiB, so re-measure then.

## Verified (2026-06-07)

`build:marketing`, `test:performance` (174.1/200), `lint`, `test:marketing-csp`, `test:security`, `test:surfaces` all green.

## Deferred to Phase 2 (need an LLM key / server runtime)

- `/api/copilotkit` runtime route (`@copilotkit/runtime`, server-side, holds the LLM key).
- `/api/governance/admit` HTTP bridge to the ACGS kernel / `governed_mcp_v0`.
- Wiring `admitAction` into the agent's tool-call path + a **negative-path test** proving DENY/ESCALATE/error → no side effect (currently `governance.ts` is ready but not yet on a live tool-call path).
- Streaming responses (the panel currently reads `agent.messages` after the run completes).
- Console surface (Phase 3) + deploy (Phase 4, human-gated).
- Design-review (`DESIGN.md`) before enabling on a shipped surface.
