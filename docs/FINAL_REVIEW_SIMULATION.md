# Final Review Simulation (Phase 8)

> Simulated external-reviewer pass over a clean `origin/master` clone
> (`feat/pre-launch-hardening` @ `93df49a`). All commands were actually run;
> results are literal. This is the capstone of the pre-launch hardening pass.

## Method

Audited a fresh worktree created from `origin/master` — exactly what an anonymous
reviewer clones — with **no submodules initialized** and no tokens. Ran the
README's "Verify the invariant locally" path, the documented test gates, and the
constitutional-hash check.

## The four questions

### 1. Can a reviewer understand the system in 10 minutes? — **Mostly yes.**

The README leads with a crisp one-liner ("receipt-gated runtime governance for
AI-agent side effects"), a `mermaid` decision-flow, a **working** "Verify the
invariant locally" block, an evidence table mapping each capability to source +
tests, and an explicit "Scope and claim boundary." `docs/START_HERE.md` and
`docs/PROOF_PATH.md` give guided entry. A reviewer gets the thesis and can prove
it fast. Deduction: the monorepo's breadth (many packages, `docs/saas` target
specs, strategy docs) can distract from "the kernel is `packages/gove-zone`."

### 2. Are the claims supported? — **Yes.**

Strong pre-existing discipline: `docs/CLAIMS.md` ledger, a static overclaim CI
gate, frontend copy that disclaims certification. Forbidden claims (formally
verified / production-certified / regulator-approved / guaranteed-safe) appear
**only as disclaimers**. This pass downgraded three affirmative "tamper-proof"
→ "tamper-evident" wordings (`docs/CLAIM_AUDIT.md`). No fabricated claims found.

### 3. Are there credibility traps? — **Yes; some fixed, some staged.**

| Trap | Severity | Status |
|---|---|---|
| `/home/martin/...` local paths in public docs | High | **Fixed** — 7 public files scrubbed this pass |
| Affirmative "tamper-proof" wording | Med | **Fixed** — 3 downgrades this pass |
| `hub-verification-report.md` at root says live site returns **404** | High | Staged for `docs/internal/` (Phase 4) |
| Version skew: Alpha `0.1.0.dev0` vs Beta `1.0.0rc1` on reviewer surfaces | Med | Documented (`docs/VERSIONING.md`); sweep staged |
| Internal GTM/strategy/SaaS/investor docs in public tree | Med | Staged for `docs/internal/` |
| "Built by agents" `docs/codex-goals/*`, CCA/Codex review tells | Med | Staged for `docs/internal/` |
| 4 third-party `external/*` submodules (unrelated upstreams) | Med | Removal staged (`docs/REPRODUCIBILITY.md`) |
| Archived second frontend `docs/archive/acgs-enterprise-ai-manager/` | Low | Removal staged (Phase 7) |

### 4. Are there reproducibility blockers? — **No hard blocker for the core.**

Verified on a submodule-free clone (literal results):

```
gove-zone smoke                      → "status": "pass"  (exit 0)
receipt-gated-execution/demo.py      → "All invariants held…"  (exit 0)
examples/tamper_demo/demo.py         → "status": "pass", tampered_receipt_blocked: true  (exit 0)
pytest tests/docs                    → 77 passed, 5 skipped  (exit 0)
pytest packages/gove-zone/tests
   + --extra crypto yaml mcp         → 1101 passed, 0 failed, 2 skipped  (exit 0)
```

Two documented **traps** (not blockers): the bare package-test command omits
required extras (false red), and the constitutional-hash check needs submodules
(fails closed on a bare clone). Both are in `docs/REPRODUCIBILITY.md`.

## What this pass changed (executed)

- **Baseline recorded** on the correct tree (`docs/PRE_LAUNCH_BASELINE.md`) —
  the initial checkout was 350 commits behind with 285 dirty files; audit was
  re-based onto a clean `origin/master` worktree.
- **Scrubbed `/home/martin/...` leaks** from 7 public docs (`acgi-ai/DESIGN.md`,
  `DEPLOY.md`, `PLAN.md`, `CLAUDE.md`, `docs/CLAUDE_CODE_PLAYBOOK.md`, `AGENTS.md`,
  `packages/ai-governance-research/validation/README.md`).
- **Downgraded 3 "tamper-proof" → "tamper-evident"** claims in `docs/design/*`.
- **Fixed a stale build path** in `packages/ai-governance-research/validation/README.md`.
- **Authored** `PRE_LAUNCH_BASELINE`, `REPOSITORY_POLICY`, `VERSIONING`,
  `HASH_VERIFICATION_REPORT`, `CLAIM_AUDIT`, `REPRODUCIBILITY`, `internal/README`,
  this file.
- Verified `make lint-docs` stays **green** after every edit.

## Execution pass 2 — conditions executed

A second pass executed most of the checklist. Verified green after each batch
(`make lint-docs` exit 0; `tests/docs` 82 passed; `make review` exit 0).

**Done:**

1. **Relocated the safely-movable internal material** to `docs/internal/`:
   `hub-verification-report.md` (the worst credibility item), `docs/productization/`,
   `docs/architecture-audit.md`, `docs/HERMES_DOJO_ONBOARDING_EVALUATION.md`,
   `docs/superpowers/` — each with an "Internal engineering document" header and
   all inbound links updated.
2. **Removed the 4 `external/*` submodules** from `.gitmodules`; added
   `external/README.md` (pinned commit + license-per-upstream reference list).
   `.gitmodules` now holds only the 4 first-party dislovelhl submodules. Updated
   `MONOREPO.md` and `docs/REPRODUCIBILITY.md` accordingly.
3. **Added `make review`** — the bare-clone-safe canonical reviewer command
   (docs smoke + gove-zone kernel suite + invariant smoke). Fixed the README
   "Development checks" gove-zone command that used the extras-omitting root form.
4. **Version sweep** on public surfaces (`COMPARISON.md`, `docs/EU_AI_ACT_MAPPING.md`,
   `docs/adr/0009`, `docs/performance-report.md`, 3 example READMEs,
   `ROADMAP-ENFORCEMENT-SUBSTRATE.md`): `0.1.0.dev0`/`0.1.0a1`/alpha →
   `1.0.0rc1`/beta, matching verified `gove-zone --version` output and the Beta
   classifier. **All "not certified" disclaimers left verbatim.** Fixed the
   acgs-lite `v2.10.0` → `v2.10.1` drift in `docs/reconstruction/*`.

**Deliberately NOT done (blocked or judgment call):**

1. **The test/script-pinned "internal" docs stay public** — `docs/saas/`,
   `docs/readiness-*`, `docs/strategy/`, `docs/reconstruction/`, `docs/research/`,
   `docs/codex-goals/`, `docs/audits/`, `docs/handoffs/`, `docs/refactor/`,
   `docs/plans/`, `docs/integration-readiness-task-map.md`, `docs/vibe-kanban-*`,
   `docs/governance-stack-index.md`. Each is referenced by a test, script, or the
   `lint-docs` governance-stack check; moving them requires editing `.py`, which
   the brief's final rule and the repo's security rules forbid. A doc under test
   is a contract doc, not scratch. **To make these private, a dedicated PR must
   also update the pinning tests/scripts — a code change for human review.**
2. **`docs/archive/acgs-enterprise-ai-manager/`, `.ci-trigger`, the duplicate
   archive ROADMAP** — left for a maintainer decision (removing the archived app
   is a larger delete; `.ci-trigger`/archive-dup are low-risk follow-ups).
3. **Internal `docs/reconstruction/*` residual version strings** — several are
   *meta descriptions of the version skew itself* ("skew: `0.1.0a1` vs
   `0.1.0.dev0`"); rewriting them would corrupt the audit record. Left as-is.
4. **`docs/blog/*` / `docs/saas/*` relocate-vs-banner** — a public/private policy
   decision for the maintainer.

## Launch recommendation: **READY WITH CONDITIONS**

**Why ready:** the core product is real and honestly represented. The
enforcement kernel is green (1101 tests), the invariant is reproducible on an
anonymous clone, and claim discipline is already strong and now tighter. Nothing
found is a correctness or security defect.

**Conditions — status after execution pass 2:**

1. ✅ Worst credibility item removed from public root (`hub-verification-report.md`
   → `docs/internal/`), plus the other safely-movable internal docs.
2. ✅ 4 `external/*` third-party submodules de-submoduled → `external/README.md`.
3. ✅ Canonical `make review` added; README trap command fixed.
4. ✅ Alpha→Beta / version drift swept on public surfaces; disclaimers preserved.

**Remaining before launch (maintainer decisions, not blockers to the core):**

- The test/script-pinned internal docs (`docs/saas`, `docs/strategy`,
  `docs/reconstruction`, `docs/readiness-*`, …) can only be made private in a
  dedicated PR that also updates the pinning tests/scripts (a reviewed code
  change). Until then they remain public but are correctly framed.
- Remove the archived second frontend + `.ci-trigger` (low-risk follow-up).
- Decide relocate-vs-banner for `docs/blog/*` and `docs/saas/*`.

None of the above touches the governance kernel, security model, tests, or
fail-closed behavior. `make review` is green on this clone; run `make verify`
(full gate, needs submodules) on the merge target before tagging.
