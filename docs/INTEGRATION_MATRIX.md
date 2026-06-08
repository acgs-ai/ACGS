# Integration matrix

> **Core invariant: No valid Decision Receipt, no side effect.**

This is the honest, even-handed answer to "does ACGS support my runtime, and how thoroughly?" It is the evidence behind the neutrality claim: **the gate mechanism is identical regardless of which framework, model, or protocol issued the call.** One executor boundary, one [Decision Receipt](DECISION_RECEIPT_SPEC.md) format.

## Why this table is not symmetric (and that is the point)

Neutrality here means *the gate treats every caller the same*, **not** that every runtime ships identical documentation. A flat "everything fully supported" table would be an overclaim. So each runtime is labelled by the proof actually in the repository:

- **Shipped + tested** — code path, an automated test, and a runnable example all exist.
- **Pattern** — a documented integration snippet exists; a *tested conformance adapter* for that runtime is on the [roadmap](ROADMAP.md), not built.
- **Roadmap** — named for orientation; a payload from this runtime generally falls through the generic parse path, but there is **no named, tested example**, so we do not claim it.

Where the neutrality actually lives in code: `packages/gove-zone/src/gove_zone/integration.py` (`_tool_name_and_input_from_payload`) is documented runtime-neutral and resolves hook-style (`tool_name`/`tool_input`), MCP `tools/call`, OpenAI function-call/Responses, OpenAI-Chat/LangChain `tool_calls`, and generic `{name, args}` shapes — hook style is checked first, no runtime is the privileged default. The receipt schema in `receipt.py` carries no vendor-specific fields. See `docs/CLAIMS.md` for the claim-to-evidence rows.

## Matrix

| Runtime / surface | Tier | Backing artifact |
|---|---|---|
| Plain Python tool wrapper | Shipped + tested | `examples/python_tool_gate/`, `executor.py`, `tests/test_executor_guard.py` |
| Runtime hooks (`tool_name`/`tool_input`, e.g. Claude/Codex-style) | Shipped + tested | `integration.py` (first parse branch), `tests/test_integration_hook.py`, `packages/gove-zone/examples/runtime_hook_demo.py` |
| MCP `tools/call` | Shipped + tested | `integration.py`, `examples/mcp_tool_gate/`, `docs/mcp/` |
| OpenAI function-call / Responses shapes | Shipped (shape parse); example is generic | `integration.py` (`_responses_function_call_items`); parse tested in `tests/test_integration_hook.py`; `examples/agent_framework_gate/` is a generic gate, not an OpenAI-named live integration |
| OpenAI-Chat / LangChain `tool_calls` shape | Shipped (shape parse); example is generic | `integration.py` `tool_calls` branch — parse is tested; no LangChain-named example yet |
| CI/CD deploy gate | Shipped + tested | `examples/ci_deploy_gate/` |
| Generic HTTP side-effect API | Pattern | `INTEGRATION_GUIDE.md` snippet; no shipped server example |
| LangGraph node / tool | Pattern | `INTEGRATION_GUIDE.md` snippet; conformance tests are roadmap (`ROADMAP.md`) |
| OpenAI Agents SDK (framework loop) | Pattern | generic wrapper snippet; conformance tests are roadmap (`ROADMAP.md`) |
| AutoGen / CrewAI / Anthropic-branded SDK | Roadmap | tool-call dicts generally reach the generic parse path, but no named, tested example exists — not claimed |

## How to read a tier before you rely on it

1. **Shipped + tested** — copy the example, swap your tool, run the listed test. The gate behaves identically to every other shipped surface.
2. **Pattern** — the snippet shows correct placement; you own writing and testing the adapter until a conformance adapter ships. Do not present a pattern as a certified adapter.
3. **Roadmap** — treat as unsupported today. If you wire it through the generic `{name, args}` path, verify argument/actor binding yourself and contribute a named example.

## Moving a runtime up a tier

A runtime advances from Roadmap → Pattern → Shipped when: (Roadmap→Pattern) a documented placement snippet lands in `INTEGRATION_GUIDE.md`; (Pattern→Shipped) a runnable example plus an automated conformance test land, and a `CLAIMS.md` row records the evidence. Until both exist, keep the lower tier — fail closed on the claim, not just on the gate.
