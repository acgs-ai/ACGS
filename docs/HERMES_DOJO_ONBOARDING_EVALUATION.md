# Hermes Repo Dojo Evaluation — Borrow the onboarding ideas?

**Date:** 2026-06-07
**Source:** [Hermes Repo Dojo](https://dev.to/jpablortiz96/hermes-repo-dojo-most-agents-answer-hermes-learns-then-it-safely-contributes-1kda) (Hermes Agent CLI hackathon project)
**Verdict in one line:** Most of what Hermes Dojo *builds* (Repo DNA, Architecture Mapping, the guided tour), ACGS **already ships** as `AGENTS.md` + `llms.txt` + `docs/START_HERE.md`. The one idea worth borrowing is **Skill Forge** — codifying recurring repo-specific procedures as explicit, copy-followable runbooks — and the highest-leverage target is an **"add a runtime adapter" runbook**, because three of our existing good-first-issues are that exact shape and the pattern is currently implicit.

---

## 1. What Hermes Repo Dojo is

A pipeline that turns a GitHub repo into an interactive onboarding system. Its thesis: *"A repository should not only store code. It should teach. It should remember. It should safely guide contribution."* Six phases:

1. **Repo DNA** — extract purpose, stack, commands, entry points.
2. **Architecture Mapping** — folders → logical areas.
3. **Skill Forge** — generate reusable, repo-specific procedures ("skills").
4. **Second Pass** — re-run analysis using the generated skills.
5. **Patch Arena** — sandboxed workspace for safe contribution (no `git push`/`sudo`/`apt-get`/destructive ops; diff verification; timestamped sandbox clone).
6. **Brain Replay** — visualize the agent's learning process.

## 2. The framing: ACGS is already a "teaching repo"

Hermes Dojo's value proposition is *generating* the onboarding artifacts that ACGS has already written by hand (and gated with tests). Phase-by-phase:

| Hermes phase | The idea | ACGS already has | Verdict |
|---|---|---|---|
| Repo DNA | purpose, stack, commands, entry points | `AGENTS.md` (purpose, repo map, test/demo commands), `llms.txt` (important source files + tests) | **Covered** — don't rebuild |
| Architecture Mapping | folders → logical areas | `AGENTS.md` repo map, `docs/ARCHITECTURE.md`, `MONOREPO.md`, safe/dangerous edit zones | **Covered** — and richer (security zoning) |
| Skill Forge | reusable repo-specific procedures | Procedures exist as *scattered prose* (CONTRIBUTING good-first-issues, CLAIMS update procedure, AGENTS "verify before editing docs"). **No `.claude/skills/` and no `docs/runbooks/` for contribution patterns** (only submodule-token runbooks) | **Borrow this** |
| Second Pass | re-analyze with generated skills | n/a (meta loop) | **Skip** — low ROI for alpha |
| Patch Arena | sandboxed safe contribution | scoped-commit rules, nested-repo discipline, the receipt gate itself | **Note, don't build** — positioning angle (§4) |
| Brain Replay | visualize learning | `START_HERE.md` is already a linear 10-min tour; ACGS "replay" means decision replay (different concept) | **Skip** — tour already exists |

The honest read: ACGS's `AGENTS.md`/`llms.txt`/`START_HERE.md` triad is *ahead* of what Hermes Dojo auto-generates, because ours encodes security zoning and claim discipline that a generic analyzer can't infer. We are not behind on "the repo teaches" or "the repo remembers."

## 3. The one strong borrow — Skill Forge → contribution runbooks

Where Hermes Dojo's "Skill Forge" maps to a real gap: our recurring contribution procedures are documented as *prose to read*, not *steps to follow*. The clearest case is the **runtime adapter** pattern. `CONTRIBUTING.md` lists three good-first-issues that are the same task:

- CrewAI tool-call normalization + dispatcher-level test
- AutoGen tool-call normalization + dispatcher-level test
- LlamaIndex tool-call normalization + dispatcher-level test

…all following an implicit pattern in `gove_zone.integration` (`tool_call_from_hook_payload` / `tool_calls_from_hook_payload`, with the fail-closed `runtime.malformed_batch` rule). Today a contributor must reverse-engineer that pattern from `integration.py` + `test_integration_hook.py`. A "Skill Forge" output would make it a checklist.

**Proposed:** `docs/runbooks/add-a-runtime-adapter.md` — a step-by-step that names the exact function to extend, the normalization contract, the fail-closed batch rule, the test it must add, and the package-local gate to run. **Corrected by CCA review (2026-06-07):** there is **no adapter registry** — adding a framework means extending the hardcoded parse/expand branches in `_tool_name_and_input_from_payload` (`integration.py:305-394`) and batch expansion (`integration.py:252-302`), not registering a plugin. The test must be a **CLI-gate enforcement test + a `runtime.malformed_batch` negative-path test** (the real inbound path is `gove-zone gate → _gate → emit_receipts_for_hook → tool_calls_from_hook_payload`, `cli.py:188-240`), **not** a parser-only unit test called "dispatcher-level". A *real* framework adapter (vs a parser shape) additionally requires proof the framework's execution path calls the gate before the raw tool runs — `integration.py` provides no host registration, so an unwired parser is dead code. This:

- directly unblocks the top 3 good-first-issues;
- enforces the handler-wiring rule (`~/.claude/rules/review-handler-wiring.md`) at authoring time, not just review time;
- is vendor-neutral (a plain runbook, not a Claude-only `.claude/skill`), matching ACGS's positioning;
- reuses an existing convention (`docs/runbooks/` already exists).

Secondary candidate: `add-a-policy-bundle.md` (the policy good-first-issue) — but **scoped to bundle shape + fixture/gate tests only**, not lifecycle/registry (`RuleSetPolicy` supports only `deny`/`escalate` with exemption-based positive auth, `policy.py:282-289`; policy lifecycle is explicitly incomplete, `SECURITY_MODEL.md:24`).

**Cut by CCA review (2026-06-07):** a `add-or-change-a-claim.md` runbook. Both lanes agreed it is the weakest: agy classed it a *maintainer duty, not an onboarding flow*; Codex found `docs/CLAIMS.md` has only a public-wording rule (`CLAIMS.md:35-37`) and **no numbered "Update Procedure"** — that procedure lives in `acgi-ai/CLAIM_VALIDATION.md`, so the eval's original framing was inaccurate. Writing it would mean *creating* a missing procedure, not codifying an existing one — out of scope for a "borrow the existing implicit procedure" initiative.

## 4. Patch Arena is the receipts-vs-guardrails contrast, not an onboarding feature

Hermes Dojo's safety model — **Scout Mode** (read-only) + **Patch Arena** (denylist: no `git push`/`sudo`/`apt-get`) + diff verification + sandbox clone — is a clean illustration of a **guardrail**: a curated allow/deny list around an agent, enforced by the agent's own runtime. It is exactly the foil for the `docs/blog/2026-06-receipts-vs-guardrails-*` thesis:

- A denylist is **bypassable** (anything not on the list runs) and **unprovable after the fact** (no portable evidence the rule held).
- ACGS's gate is **fail-closed** (no valid receipt → no side effect) and **replayable/auditable** (tamper-evident receipt + hash chain).

This is a *positioning* observation, not an onboarding mechanism — and per the standing claim-discipline + non-attack rules, the blog should use it as a neutral worked example, **not** name or trash Hermes. Worth a one-line cross-reference in the blog draft; not worth building a "Patch Arena" for ACGS (our equivalent is worktree isolation + scoped commits + the gate dogfooding itself).

## 5. Recommendation

| Action | Effort | Value |
|---|---|---|
| **Write `docs/runbooks/add-a-runtime-adapter.md`** | S | **High** — unblocks 3 good-first-issues, enforces wiring rule (see CCA corrections in §3) |
| Add `add-a-policy-bundle.md` (scoped to bundle shape + gate tests, not lifecycle) | S | Medium |
| ~~`add-or-change-a-claim.md`~~ | — | **Cut by CCA** — maintainer duty; CLAIMS.md has no Update Procedure to codify (§3) |
| Link both runbooks from `CONTRIBUTING.md` + one REQUIRED_DOCS-scanned doc so the link checker validates them | XS | enables discovery without an orphan check |
| ~~Blog "denylist guardrail" cross-ref~~ | — | **Defer to a separate positioning PR** — claim-sensitive; do not couple with onboarding docs |
| Auto-generate Repo DNA / Architecture Mapping / Brain Replay | — | **Skip** — already covered better by hand |

**Next concrete step:** build the `add-a-runtime-adapter.md` runbook (the genuine Skill Forge borrow), per the CCA-corrected pattern in §3. Everything else Hermes Dojo does, ACGS already does — usually with more rigor.

> **CCA validation (2026-06-07):** Codex (GPT-5, correctness/wiring) + agy (governance/critic) both returned **AMEND — plan shape correct**. Net amendments folded above: 2 runbooks not 3 (claim runbook cut), blog cross-ref deferred, adapter runbook test reframed to CLI-gate + malformed-batch (no registry implied). `tests/docs` confirmed not broken by new runbooks (`7 passed`, `lint-docs` passed); discoverability needs a resolving link from a scanned doc.
