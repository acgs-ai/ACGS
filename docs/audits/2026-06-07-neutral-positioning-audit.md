# Neutral cross-platform positioning — findings & change plan

Date: 2026-06-07 · Branch: `docs/gove-zone-readme-honesty` · Status: **all 7 change-plan steps implemented; passed independent claim-discipline review (0 BLOCK); docs gate green** — awaiting final human review of diffs

Goal: make ACGS / gove-zone read unmistakably as the **vendor-neutral governance, receipt, and audit layer that sits across every agent runtime and privileges none** — with neutrality *proven by the integration surface*, not asserted. Every neutrality/capability claim must trace to a shipped, tested artifact, or be labeled roadmap. Pre-existing honest caveats must be preserved or sharpened, never weakened.

---

## Governing rule for this pass (the claim tie-breaker)

Split every positioning claim into two classes and treat them differently:

- **STRUCTURAL / FORMAT claims — SAFE.** "The gate sits at the executor boundary, *below* whatever framework issued the call, so it is framework-agnostic by construction." / "The Decision Receipt is a vendor-neutral *format*." These are true by architecture and verified below.
- **ENUMERATED / CROSS-RUNTIME claims — ROADMAP unless a shipped+tested adapter/example exists per runtime.** "Works across Anthropic, OpenAI, LangChain, AutoGen, CrewAI today" / "receipts are portable across every runtime today" are **overclaims against shipped reality**. They belong in the matrix *with tier labels*, never in the hero.

> ⚠️ The goal brief's own Outcome sentence enumerates "Anthropic, OpenAI, LangChain, AutoGen, CrewAI, MCP." **Do not transcribe that list into the hero as if all are supported** — three of those six have no shipped example or named adapter. Claim the *position*, not the vendor list.

---

## What the repo already gets right (assets — preserve, don't re-invent)

1. **The neutral thesis is already latent.** `docs/introduction.md:27` already says "a framework-neutral governance plane that can sit under those agents." README/llms.txt already lead with "**not another agent framework**" and "complements agent frameworks, MCP, guardrails, sandboxes, IAM." The reframe is **promotion of an existing true claim to the headline**, not a new claim.
2. **`docs/CLAIMS.md` is a mature claim ledger** (claim → status → evidence → test → limitation → safe wording). Task 5 ("add a claims guardrail") is ~80% already done; the work is *extending* it with neutrality/portability rows, not creating it.
3. **Honest caveats already in place** — e.g. "adapter *shapes*" (not "certified adapters"), "Local JSONL is not WORM," "`acgs verify` … license key integrity only" pattern, ROADMAP wording rule. These stay verbatim.
4. **COMPARISON.md is non-attack and even-handed** already (no competitor named pejoratively). Matches constraint #3.

---

## Findings — where positioning falls short of the neutral thesis

### F1 — Neutrality is buried, framed as "narrow membrane" not "portable layer"
The headline frames ACGS as a *narrow* execution membrane ("answers the narrower question…"). True and honest, but it under-sells the **structural** reason it is the layer a buyer reaches for: it is the one governance plane that is *not* owned by any runtime vendor. **Fix:** lead with neutrality + portability; keep the "membrane / below the framework" mechanism as the *proof* of why it's neutral. (README:17–19, docs/introduction hero.)

### F2 — Named examples tilt toward OpenAI / LangGraph; the *architecture* does not
Vendor mention counts across the public surface: **OpenAI 5, LangGraph 4, Claude 1, CrewAI 1, LangChain 0, AutoGen 0, Anthropic 0.** The named integration patterns and the one "agent framework" example read OpenAI-/LangGraph-first.

**Critical nuance (verified in code, prevents a misdiagnosis):** the *API design is NOT OpenAI-privileged.* `packages/gove-zone/src/gove_zone/integration.py:305` (`_tool_name_and_input_from_payload`) is documented "runtime-neutral" and resolves shapes in this order — **hook style (`tool_name`/`tool_input`, i.e. Claude/Codex) is checked FIRST**, then MCP `tools/call`, then OpenAI function-call/Responses, then OpenAI-Chat/LangChain `tool_calls`, then a generic `{name, args|arguments|input}` / `{tool:{…}}` fallback. The OpenAI-specific helpers (`_responses_function_call_items`, …) are *one branch among many*, sequenced after the hook branch.

So the privileging is **in the copy/examples, not the abstraction.** Fix is documentation symmetry (F2) + an honest tier matrix (F4) — **not** rearchitecting (out of scope).

### F3 — Decision Receipt is not yet elevated as *the portable evidence artifact*
The receipt is described as an internal contract, not as "the one vendor-agnostic record a buyer keeps no matter which model/framework they switch to." **Verified safe to elevate as a FORMAT claim:** `receipt.py` fields are fully vendor-neutral — `receipt_id, request_id, tenant_id, actor, proposed_action, declared_goal, execution_boundary, policy_bundle_id, policy_version, policy_hash, decision, matched_rules, constraints, transformations, approval_chain_summary, timestamp, previous_audit_hash, audit_event_hash, subject, expires_at, authority, validator_id, validator_role, argument_hash, receipt_hash, signature_*` — **zero vendor-shaped fields.**
**But:** "portable *across every runtime today*" = the ROADMAP item *"Ecosystem: standard receipt schema for agent runtimes / reference validators in multiple hosts"* (ROADMAP.md:15). Elevate the **format** neutrality (shipped); label cross-host **portability validators** roadmap. Fail-closed.

### F4 — No single matrix shows shipped vs pattern-only vs roadmap per runtime
INTEGRATION_GUIDE and COMPARISON exist but don't give a buyer one even-handed "which runtimes, at what proof depth" table. **Fix:** add a tiered integration matrix (below). Asymmetric-but-honest tiers are *more* persuasive to a skeptic than fake symmetry.

### F5 — LangGraph / OpenAI-Agents snippets shown without an "illustrative, not tested" caveat (pre-existing soft overclaim)
ROADMAP.md:10 lists MCP + agent-framework + LangGraph *conformance tests* as **roadmap (unbuilt)**, yet INTEGRATION_GUIDE.md presents LangGraph node and OpenAI-Agents wrapper snippets with no "illustrative pattern; conformance is roadmap" label. Constraint #2 forbids silently weakening *or* strengthening — **surfacing this is the audit's job.** Recommend a one-line caveat per pattern (a *sharpening*, consistent with existing honesty), not a rewrite.

---

## Proposed honest integration matrix (for human review before it ships)

Tiers: **Shipped+tested** (code + test + runnable example) · **Pattern** (documented snippet, conformance is roadmap) · **Roadmap** (named, no shipped adapter/example).

| Runtime / surface | Tier | Backing artifact |
|---|---|---|
| Plain Python tool wrapper | Shipped+tested | `examples/python_tool_gate/`, `executor.py`, `test_executor_guard.py` |
| Runtime hooks (`tool_name`/`tool_input`; Claude/Codex-style) | Shipped+tested | `integration.py` (1st branch), `test_integration_hook.py`, `examples/.../runtime_hook_demo.py` |
| MCP `tools/call` | Shipped+tested | `integration.py`, `examples/mcp_tool_gate/`, `docs/mcp/` |
| OpenAI function-call / Responses shapes | Shipped+tested (shape parse) | `integration.py` (`_responses_function_call_items`), `examples/agent_framework_gate/` |
| OpenAI-Chat / LangChain `tool_calls` shape | Shipped (shape parse), example generic | `integration.py` `tool_calls` branch — *parse-tested, no LangChain-named example* |
| Generic HTTP side-effect API | Pattern | INTEGRATION_GUIDE snippet — no shipped server example |
| CI/CD deploy gate | Shipped+tested | `examples/ci_deploy_gate/` |
| LangGraph node/tool | Pattern | INTEGRATION_GUIDE snippet; conformance = ROADMAP.md:10 |
| OpenAI Agents SDK (framework loop) | Pattern | generic wrapper; conformance = ROADMAP.md:10 |
| AutoGen / CrewAI / Anthropic-branded SDK | Roadmap | falls through generic `{name,args}` path but **no named/tested example** — do not claim |

**Why asymmetric is correct (write this into the matrix preamble):** neutrality is proven by *"the gate mechanism is identical regardless of caller"* — one boundary, one receipt format — **not** by every runtime having identical docs. A flat "everything fully supported" table would be the overclaim.

---

## Change plan (incremental, reviewable diffs — human gates each step)

1. **CLAIMS.md first** — add rows: *framework-neutral gate position* (implemented; `integration.py` runtime-neutral parse + `executor.py`), *vendor-neutral receipt format* (implemented; `receipt.py` field audit), *receipt portability across hosts* (roadmap; ROADMAP.md:15), *per-runtime adapter tiers* (mixed — point to matrix). Ledger leads so every later edit cites a row.
2. **README hero + first-screen** — promote neutrality/portability to the lead; keep membrane mechanism as the proof; **no vendor enumeration as "supported."** Preserve the "What this repository is not claiming" block verbatim.
3. **docs/introduction + docs/README hero** — mirror the README thesis (single consistent hero sentence ≤3 load-bearing primitives).
4. **New `docs/INTEGRATION_MATRIX.md`** (or a section in INTEGRATION_GUIDE) — ship the tiered matrix above; link from README "Read next" and COMPARISON.
5. **INTEGRATION_GUIDE F5 caveats** — one-line "illustrative pattern; conformance is roadmap (see ROADMAP)" on LangGraph + OpenAI-Agents snippets.
6. **Elevate Decision Receipt** — in DECISION_RECEIPT_SPEC + README, frame as the portable, vendor-agnostic evidence record (format = shipped; multi-host validators = roadmap).
7. **(Optional) `docs/POSITIONING.md`** — short evidence-based answer to the "feature, not a company" objection via neutrality + portability + cross-runtime audit; non-attack.

## Out of scope (confirmed)
Rearchitecting `integration.py`; building AutoGen/CrewAI/Anthropic adapters to back a claim; renaming/rebranding; any license-key/commercial change.

## Definition of done (verification)
- Every neutrality/capability/compliance claim on the public surface → a CLAIMS.md row → shipped+tested artifact, or labeled roadmap.
- Matrix shows even-handed tiers; no vendor privileged in copy or abstraction.
- All pre-existing caveats preserved or sharpened (diff-check F5 didn't weaken anything).
- `uv run python -m pytest tests/docs --import-mode=importlib -q` + `make lint-docs` green after each doc step.
