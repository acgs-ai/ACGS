# Agent-Native Architecture Audit — gove-zone / ACGS

> Lens: compound-engineering `ce-agent-native-architecture` (refs 14 checklists, 13 refactoring, 5 execution, 3 tool-design, 8 parity).
> Invariant under audit: **No valid Decision Receipt, no side effect.**
> Read-only audit. No source changed. Guardrail: every recommendation below is checked against `AGENTS.md` *Forbidden changes without explicit user approval*.

---

## 0. Scope — what was actually read

| Surface | Path | Role (ground truth) |
|---|---|---|
| Kernel | `packages/gove-zone/src/gove_zone/kernel.py` | In-process structural gate: `dispatch()` → `policy.evaluate` → audit → execute |
| Pre-exec gate | `packages/gove-zone/src/gove_zone/executor.py` | `execute_with_receipt` / `GovernedExecutor`: verify an *already-issued* `DecisionReceipt` before running |
| Receipts | `packages/gove-zone/src/gove_zone/receipt.py` | **Two classes**: `Receipt` (l.40, post-exec audit anchor) and `DecisionReceipt` (l.90, pre-exec authz token, signed, MACI actor-binding, `verify` l.340) |
| Agent adapter | `packages/gove-zone/src/gove_zone/integration.py` | "**single canonical adapter** between agent-runtime hook payloads" (l.1-18). Parses Claude + OpenAI-Responses tool calls. **Observe-by-default** via `_ObserverPolicy` (l.553-569, ALLOW all) |
| MCP binding | `acgs_governance_eval_mvp/governed_mcp_v0/` | **Eval/demo harness** (`fixtures.py`: "tests / demos"). FastMCP-bound `GovernedMCPServer`, hardcoded fixture-allowlist policy |
| Tool registry | `packages/gove-zone/src/gove_zone/tool.py` | `ToolRegistry` (l.96), single-registration-per-name |

This corrects an easy misread: `governed_mcp_v0` is **not production**. The strong receipt machinery (`DecisionReceipt`) and the canonical agent adapter (`integration.py`) live in `gove_zone`; the only FastMCP binding is the eval demo.

---

## 1. Current architecture judgment

**gove-zone is deliberately NOT agent-native at its core, and that is correct.** It is the *deterministic execution membrane* the agent-native refactoring guide itself says to keep in code (`refactoring-to-prompt-native.md` l.279-289: "Keep in code: Security validation, Audit logging"). "Agent" here is the **conceptual caller**, not an LLM in the loop — confirmed: zero `anthropic|openai|llm|max_iterations|system_prompt` references anywhere in the gate path; the only file that even mentions agents is `integration.py`, and it is a *payload adapter*, not an agent runtime.

So the right question is not "is the kernel agent-native?" (it shouldn't be — a model must never decide *whether a side effect is allowed*). The right question is: **at the edges where agents actually touch the system, does the design give the agent the primitives, parity, and execution affordances of an agent-native system — without weakening fail-closed?**

Verdict by component:

- **Kernel (`dispatch`) — structurally sound, genuinely fail-closed.** Execution (`tool_fn(**args)`, l.150) only occurs *inside* dispatch, *after* the decision, and *after* audit append. Policy raise/timeout → synthesized DENY (l.181-200); audit-append failure → `AuditError`, never silent allow (l.217-220); TRANSFORM-without-args → DENY (l.140-144). You cannot register a tool that bypasses the gate. This is the model the rest of the system should inherit.
- **`execute_with_receipt` — strongest closure.** `expected_actor` is required, has no default, anchors MACI proposer-binding against an identity the receipt author can't forge (l.41-75). This is the cryptographic floor.
- **The agent-facing surface is the weak link, not the kernel.** The canonical adapter agents hit (`integration.py`) defaults to **observe-only** (`_ObserverPolicy` allows everything and just records receipts). The strong enforcement path is opt-in. This is the central finding.

**One-line judgment: a well-built deterministic governance core wrapped by an observe-by-default agent edge and an unwired human-approval half-loop. Not "a service pretending to be an agent" — rather, a strong membrane whose agent-native *affordances* are under-built at the boundary.**

---

## 2. Agent-native compliance points (keep these)

- ✅ **Granularity at the kernel — primitives, not workflows.** `@kernel.tool("write_file")` registers a bare side effect; the *decision* lives in `policy.evaluate`, not baked into the tool (`kernel.py` l.84-97). This is exactly "tools are primitives" (`mcp-tool-design.md`).
- ✅ **Inverted parity solved structurally.** For a governance layer the parity discipline is *every side-effecting tool routes through the gate*. The kernel enforces this by construction — there is no un-gated execution path.
- ✅ **Composability of policy (kernel side).** `RuleSetPolicy` (`policy.py` l.287) is rule/data-driven (effects limited to deny/escalate). New policy ≈ new rules, not new gate code — the composability the checklist wants, applied to the *safe* layer (policy data), not the dangerous one (the model).
- ✅ **Audit as a first-class, tamper-evident substrate.** `ChainHashAuditStore` hash-links every decision; receipts carry `policy_hash`, `policy_bundle_id`, `audit_hash`, `decision_request_hash` (`tool.py` l.78-93) — replayability is built in, not bolted on.
- ✅ **Multi-runtime adapter abstraction.** `integration.py` normalizes Claude- and OpenAI-shaped payloads behind one `tool_call_from_hook_payload` (l.488) — the "API as validator / don't hardcode one shape" instinct, applied to agent runtimes.

---

## 3. Non-compliance points / risk points

Mapped to the five principles. Each tagged with the relevant skill ref.

| # | Finding | Evidence | Principle / ref |
|---|---|---|---|
| R1 | **Observe-by-default at the agent edge.** The canonical adapter defaults to allow-all + record. The strong gate (`execute_with_receipt`, MACI binding) is *not* what an agent hits unless explicitly wired in enforce mode. | `integration.py` l.553-569 `_ObserverPolicy`; `GateMode` l.64 | Parity (8) — the agent's real surface ≠ the enforcing surface |
| R2 | **ESCALATE is a terminal exception, not a resumable state.** Human-in-the-loop is the headline use case for a governance layer, yet ESCALATE just `raise EscalateError` with no approve→resume path. `frontend_contract.py` even labels it "partial" (l.40) but nothing can resume it. | `kernel.py` l.138; `errors.py` l.43-48 | Execution patterns (5) — partial completion / resume |
| R3 | **DENY/ESCALATE are exceptions, not rich structured outputs.** A calling agent gets a raised error, not a machine-readable "denied because X; allowed set = Y" it can self-correct from and re-propose. | `kernel.py` l.136-139 raises `DeniedError`/`EscalateError` | Tool design (3) — "rich outputs" |
| R4 | **No dry-run / capability-discovery primitive.** An agent cannot ask "would this be allowed?" before producing a side effect, so it learns policy only by getting denied — more rejected attempts, more audit noise. | No `would_allow` / `simulate` / `list_capabilities` tool in any surface | Tool design (3) — dynamic capability discovery |
| R5 | **The only MCP/tool binding is the eval demo, with hand-wired per-method admission.** Each guarded method hardcodes its own `self.admit("filesystem.write_file", …)`; forgetting it = a silent un-gated side effect. Policy is hardcoded `if/else` over fixture allowlists (not data-driven, not composable without code). | `governed_mcp_v0/server.py` l.209-264; `policy.py` l.17-101; `constants.py` triple-binding | Handler-wiring + composability |
| R6 | **Two receipt types, two phases, never bridged.** `Receipt` (audit anchor) is produced *after* execution; `DecisionReceipt` (authz token) is consumed *before*. They are complementary halves of an issue→approve→execute loop that is not connected. | `receipt.py` l.40 vs l.90; `execute_with_receipt` consumes `DecisionReceipt`, `dispatch` emits `Receipt` | Composability (R2's mechanism) |

**Explicitly N/A (do not force):** *CRUD completeness* (`mcp-tool-design.md`). The tools map real external side effects (deploy, email, shell), not an internal entity store. "Can the agent delete what it created?" is the wrong question here — irreversibility is the *point*. Marking N/A rather than inventing delete tools.

---

## 4. High-priority refactor list

Ordered by leverage. **Every item is net-positive or neutral on fail-closed — none move a allow/deny decision into a model.** Guardrail column cites the relevant `AGENTS.md` forbidden-change it must respect.

| Pri | Refactor | How it preserves / strengthens fail-closed | Guardrail |
|---|---|---|---|
| **P0** | **R6→R2: wire the escalation-resume loop.** ESCALATE → human approves → **issue a fresh signed `DecisionReceipt`** (approver = actor, bound to the *same* `decision_request_hash`) → run through `execute_with_receipt`. | Resume is *not* "re-run the original call" (that would be a bypass). It is "a legitimate receipt now exists," re-verified at the gate. `expected_actor` anchoring (executor.py l.41-75) is already the other half. **Strengthens** the system: turns a dead-end into a governed path. | Must not "treat ESCALATE as executable" — and it doesn't: execution still requires a valid receipt that passes `verify`. |
| **P0** | **R1: make enforce-mode the default at the agent edge** (or fail-closed if gate-mode is unset/unreadable). Observe-only becomes an explicit opt-in, logged. | Removes the silent allow-all default; unknown mode → DENY. | "Do not weaken fail-closed"; "do not turn unsigned dev mode into a production claim." |
| **P1** | **R3: structured rejection outputs.** Alongside the raised error, return a machine-readable rejection (`reason`, `matched_rules`, `allowed_alternatives`) so a calling agent can self-correct. | Pure additive — the gate still denies; it just explains. No decision logic moves. | None triggered (output enrichment only). |
| **P1** | **R4: add a `simulate` / `would_this_be_allowed` read-only primitive.** Runs `policy.evaluate` with **no execution, no audit-chain mutation** (or a clearly-separated `dry-run` audit kind). | Read-only by construction; cannot produce a side effect. Reduces denied-attempt noise. | Must be provably side-effect-free — assert no `tool_fn` call, no chain append on the hot path. |
| **P2** | **R5: give the strong kernel a first-class MCP binding** that inherits `Kernel.dispatch`'s structural gating, and demote `governed_mcp_v0` to clearly-labeled eval-only. New production MCP tools register via the kernel registry (structural admission), never per-method `self.admit`. | Replaces hand-wired admission (omission = silent allow) with structural admission (impossible to bypass). | "Handler wiring" rule — every guarded tool provably routes through the gate, with a dispatcher-level test, not a unit test. |
| **P2** | **R5b: make demo policy data-driven** to match the kernel's `RuleSetPolicy`, so eval policies are bundles, not `if/else`. | Composability without touching gate code. | Keep deterministic; no model-decided allow/deny. |

---

## 5. Minimal executable PR slicing

Each PR is independently shippable, independently testable, and touches one boundary. Sequenced so the safe/additive ones land first and de-risk the structural ones.

- **PR-1 (additive, zero behavior change): structured rejection payload.** Add `to_rejection_dict()` to `DeniedError`/`EscalateError`; return it from the adapter. Test: deny → assert payload shape + `allowed_alternatives`. *No gate logic touched.* (R3)
- **PR-2 (additive): `simulate` read-only primitive.** New function `evaluate_only(call) -> DecisionRecord` that calls `policy.evaluate` and **never** executes or mutates the main chain. Test: simulate a DENY and an ALLOW, assert no `tool_fn` invocation and no audit-chain growth. (R4)
- **PR-3 (default flip, guarded): enforce-by-default gate mode.** Unset/unreadable `GateMode` → enforce (or DENY), not observe. Migration note + explicit `OBSERVE` opt-in env. Test: missing mode file → call is gated, not allowed. (R1)
- **PR-4 (the keystone): ESCALATE→approve→resume.** `issue_approval_receipt(record, approver)` → signed `DecisionReceipt` bound to the original `decision_request_hash`; `resume(receipt)` routes to `execute_with_receipt`. Tests: (a) approval receipt with mismatched `decision_request_hash` → DENY; (b) resume with approver == proposer → DENY (MACI self-validation); (c) happy path executes exactly once. (R6/R2)
- **PR-5 (structural, larger): kernel-backed production MCP binding** + demote `governed_mcp_v0` to `*_eval` naming. Dispatcher-level wiring test: every guarded tool returns DENY when no receipt/observe path is active. (R5)

PR-1/2/3 are small and safe; PR-4 is the highest-value design change; PR-5 is the largest and should follow the `subproject-orchestrate` four-lane flow (it crosses `gove_zone` ↔ `acgs_governance_eval_mvp` boundaries).

---

## 6. Success criteria

Done when all of the following hold (evidence-based, not assertions):

1. **Enforce is the floor.** With no explicit observe opt-in, an agent tool call that lacks a valid receipt is **denied** — proven by an integration test that drives a payload through `integration.py` end-to-end (not a unit call to `verify`). (R1)
2. **ESCALATE is resumable and un-bypassable.** A test suite proves: approve→resume executes exactly once; resume without a fresh valid receipt fails closed; approver == proposer fails closed (MACI). Re-running the original call without a new receipt does **not** execute. (R2/R6)
3. **Rejections are self-correctable.** A denied call returns structured `reason`/`matched_rules`/`allowed_alternatives`; a follow-up corrected proposal is allowed. (R3)
4. **Dry-run is provably side-effect-free.** `simulate` produces a decision with zero executions and zero main-chain audit growth, asserted in test. (R4)
5. **Every guarded tool is structurally gated.** A dispatcher-level test (per `~/.claude/rules/review-handler-wiring.md`) shows each production MCP tool routes through the gate; a new tool added without registration is *impossible to call un-gated* (not "the dev remembered to call admit"). (R5)
6. **No decision moved into a model.** Grep proves the allow/deny/escalate verdict is still 100% deterministic code; the LLM-keyword count in the gate path stays at zero. (Invariant preserved.)
7. **Regression floor intact.** `uv run --package gove-zone python -m pytest packages/gove-zone/tests` and `tests/docs` stay green; constitutional hashes unchanged.

**The ultimate test (governance-flavored):** describe a side effect the system was never explicitly coded for, hand it to an agent through the real adapter. Outcome must be one of {executed *with* a valid receipt, denied *with* a structured reason, escalated *into a resumable approval*} — never {silently allowed} and never {dead-ended}. If all three governed outcomes are reachable and the fourth (silent allow) is unreachable, the *edge* is agent-native and the *core* is still a deterministic membrane. That is the target state.
