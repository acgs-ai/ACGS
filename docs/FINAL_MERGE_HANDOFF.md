# Final Merge Handoff

> Maintainer merge package for the pre-launch hardening branch. Documentation
> only — no runtime, kernel, or security-invariant changes. Prepared by the
> release-assistant pass; **merge only after human review.**

## Branch

`feat/pre-launch-hardening`

## Base commit

`93df49a` — `Merge pull request #349 from dislovelhl/docs-version-pin-fix`
(the `origin/master` merge-base at hardening time).

## Purpose

Make the repository reviewer-safe for a public / paper-companion release without
changing what the software does: scrub local-path leaks, tighten claim wording
(tamper-proof → tamper-evident), relocate the worst internal/credibility items
to `docs/internal/`, de-submodule 4 unrelated third-party `external/*` repos,
add the bare-clone reviewer command `make review`, clarify version semantics
(artifact `0.1.0` vs `gove-zone` package `1.0.0rc1`), and clarify the
constitutional-hash / reproducibility model. All changes are documentation,
repository metadata (`.gitmodules`), or the `Makefile` reviewer alias.

## Files changed

- **Tracked:** 42 files, **+126 / −58**. Breakdown:
  - `README.md` — reviewer path, version honesty, hash clarification, `make review`.
  - `Makefile` — added the `review` target + help line (no change to `verify`).
  - `.gitmodules` — removed 4 `external/*` third-party submodule stanzas (D:
    `external/UI-TARS-desktop`, `external/openswarm`,
    `external/everything-claude-code`, `external/natural_language_autoencoders`).
  - `MONOREPO.md` — external `submodules` → `references`.
  - 16 files **relocated** into `docs/internal/` (RM) — `hub-verification-report.md`,
    `docs/productization/` (8), `architecture-audit.md`,
    `HERMES_DOJO_ONBOARDING_EVALUATION.md`, `docs/superpowers/` (5) — each with an
    internal header, links updated.
  - Path-leak scrubs (`/home/martin/...` → `$HOME`/`~`/repo-relative) in
    `AGENTS.md`, 4× `acgi-ai/*.md`, `docs/CLAUDE_CODE_PLAYBOOK.md`,
    `packages/ai-governance-research/validation/README.md`.
  - `tamper-proof` → `tamper-evident` in 3 `docs/design/*` files.
  - Version sweep (alpha/`0.1.0.dev0`/`0.1.0a1` → `1.0.0rc1`/beta; acgs-lite
    `v2.10.0` → `v2.10.1`) on public surfaces: `COMPARISON.md`,
    `docs/EU_AI_ACT_MAPPING.md`, `docs/adr/0009`, `docs/performance-report.md`,
    `ROADMAP-ENFORCEMENT-SUBSTRATE.md`, 3 example READMEs,
    `docs/reconstruction/{00,01,04}`.
- **Untracked (new, authored this pass):** `docs/PRE_LAUNCH_BASELINE.md`,
  `REPOSITORY_POLICY.md`, `VERSIONING.md`, `HASH_VERIFICATION_REPORT.md`,
  `CLAIM_AUDIT.md`, `REPRODUCIBILITY.md`, `FINAL_REVIEW_SIMULATION.md`,
  `internal/README.md`, this file, and `external/README.md` (pinned-commit
  reference list for the de-submoduled projects).

## Runtime impact

**None.** `git diff --name-only` across tracked + untracked shows **zero**
`.py` / `.pyi` / `.ts` / `.tsx` / `.js` files. No governance kernel, receipt
validation, executor gate, audit chain, constitutional-hash logic, or CI
behavior was modified.

## Security impact

**None.** Fail-closed behavior, receipt binding, executor enforcement, and the
`verify_constitutional_hashes.py` gate are unchanged. No hash values changed.
The full `make verify` gate (`submodule-status lint typecheck test
test-fail-closed bench-gate`) was **not** weakened or redefined — `make review`
was added alongside it as a bare-clone reviewer subset.

## Verification results

| Gate | Command | Result |
|---|---|---|
| Docs invariants | `make lint-docs` | exit 0 |
| Docs + examples smoke | `pytest tests/docs -q` | **82 passed**, 1 warning |
| Reviewer path | `make review` | **exit 0** — docs 82 passed; gove-zone kernel suite green; invariant smoke `status: pass` (allow-before-side-effect, deny-before-side-effect, audit-chain-verifies all `pass`) |
| gove-zone kernel suite | (in-package pytest) | green on exit 0; prior authoritative `--junitxml` count = **1101 passed, 0 failed, 2 skipped** (with `--extra crypto yaml mcp`) |
| Runtime scope | `git diff --name-only \| grep -E '\.(py\|pyi\|ts\|tsx\|js)$'` | **no output** |

**`make verify` was executed against a full checkout and FAILED (exit 2) on a
pre-existing, non-branch blocker.** After initializing the public submodules
(`acgs-lite`, `Acgs-Swarm`, `ACGS-agency-agents` — all cloned clean, exit 0) and
running `make install`:

```
make install (pnpm ok; uv sync --all-extras)  → exit 2
  × Failed to build `acgs-lite @ …/packages/acgs-lite`
  ╰─▶ `gove-zone` is included as a workspace member, but is missing an entry
      in `tool.uv.sources` (e.g., `gove-zone = { workspace = true }`)
make verify                                    → exit 2 (stops at lint-py, same error)
  submodule-status ✓ · lint-js/turbo ✓ (93 files, 2 infos) · lint-py ✗ (uv resolve)
```

**Root cause is inside the pinned `acgs-lite` submodule, not this branch.** The
`acgs-lite` `pyproject.toml` (pin `4233e351`) declares `gove-zone` as a uv
workspace member without the corresponding `[tool.uv.sources] gove-zone =
{ workspace = true }` entry, so `uv sync` and `lint-py` both fail resolving the
workspace. This is the known cross-repo uv.sources gap. This branch does **not**
touch the `acgs-lite` pin (identical to base `93df49a`) and changes no `.py` /
`.toml`, so the same failure reproduces on `origin/master` from a fresh
submodule checkout — it is a baseline condition, independent of the doc-only
diff. **This branch does not own the fix** (nested-repo config; out of scope by
Rule 0 + submodule-boundary rules).

## Remaining known limitations

1. **`make verify` fails on a fresh full checkout** — blocked by the `acgs-lite`
   submodule uv.sources gap (see Verification results above and the follow-up
   issue below). Pre-existing, not owned by this branch. `make review` (the
   bare-clone reviewer gate) passes.
2. **Test/script-pinned internal docs stay public** — `docs/saas/`,
   `docs/strategy/`, `docs/reconstruction/`, `docs/readiness-*`,
   `docs/research/`, `docs/codex-goals/`, `docs/audits/`, `docs/handoffs/`,
   `docs/refactor/`, `docs/plans/`, and a few index files are referenced by a
   test, script, or the `lint-docs` governance-stack check. Making them private
   needs a dedicated PR that also edits the pinning `.py`/scripts — out of scope
   for a docs-only pass.
3. **Residual `0.1.0a1` / ALPHA strings in internal/strategy/blog docs** —
   `docs/strategy/auditor-validation/*`, `docs/blog/*` (labeled DRAFT),
   `docs/reconstruction/*` (some are meta-descriptions of the skew itself).
   Internal-classified, not reviewer-facing product surfaces; relocate-vs-banner
   is a maintainer decision.
4. **Stray untracked `.claude/hooks/__pycache__/`** — operational bytecode; do
   **not** stage it. Merge only the intended doc/metadata paths.
5. **Archived second frontend + `.ci-trigger`** — low-risk maintainer delete,
   deferred.
6. **Constitutional-hash check fails closed on a bare clone** — documented
   (`docs/HASH_VERIFICATION_REPORT.md`, `REPRODUCIBILITY.md`); correct behavior,
   not a defect.

## Required follow-up issue — `acgs-lite` uv.sources gap (separate from this branch)

> File against the `acgs-lite` repo (or as a parent submodule-pin bump), **not**
> this hardening branch.

- **Title:** `acgs-lite: gove-zone workspace member missing [tool.uv.sources] entry`
- **Symptom:** `uv sync --all-extras` and root `make verify` (`lint-py`) fail with
  ``Failed to build `acgs-lite` … `gove-zone` is included as a workspace member,
  but is missing an entry in `tool.uv.sources` ``.
- **Repro:** fresh clone of ACGS at any commit whose `acgs-lite` submodule pins
  `4233e351` → `git submodule update --init packages/acgs-lite` → `make install`.
- **Root cause:** `acgs-lite/pyproject.toml` lists `gove-zone` as a uv workspace
  member without `[tool.uv.sources] gove-zone = { workspace = true }`.
- **Fix (in `acgs-lite`, not here):** add the missing `tool.uv.sources` entry, then
  bump the parent `acgs-lite` submodule pin to the fixed commit in a dedicated PR.
- **Why not fixed in this branch:** nested-repo config change across a submodule
  boundary; forbidden by the hardening scope (Rule 0) and repo boundary rules. The
  doc-only branch does not modify the `acgs-lite` pin (identical to base `93df49a`).
- **Interim:** the bare-clone reviewer gate `make review` is green and proves the
  core invariant; CI's per-package path-filtered workflows gate `gove-zone`
  independently.

## Recommended merge action

**Merge after human review.** Stage only the intended documentation, `.gitmodules`,
`Makefile`, and `external/README.md` paths (never `.claude/hooks/__pycache__/`).
Run `make verify` on the full checkout, then tag as **ACGS 0.1.0 — Research
Artifact Release** (`gove-zone 1.0.0rc1` package line). `git push` / `gh pr merge`
/ tag creation remain human actions.
