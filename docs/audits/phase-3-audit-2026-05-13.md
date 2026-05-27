# Phase 3 Coherence Audit — 2026-05-13

**Branch:** `feat/phase-3-audit`
**Auditor:** w3 (Stage 2 audit agent)
**Plan sources:**
- `.omc/plans/govern-zone-phase-b3-revised.md` §Stage 2 (Check 5 revised)
- `.omc/plans/govern-zone-phase-b3.md` §Stage 2 (7 check definitions)
**Scope:** `dislovelhl/govern-zone` workspace — ACGS child repo at `ACGS/`, sibling `pi/`
**Date:** 2026-05-13

---

## Summary

| Check | Name | Initial Verdict | Re-Run Verdict (post PR #24) |
|-------|------|-----------------|------------------------------|
| 1 | AGENTS.md / CLAUDE.md accuracy | PARTIAL | PARTIAL |
| 2 | Generated index accuracy | FAIL | FAIL |
| 3 | Per-subproject gate green | FAIL | FAIL |
| 4 | Cross-subproject dependency drift | PASS | PASS |
| 5 | ADR coverage for monorepo decisions | FAIL | **PARTIAL** ↑ |
| 6 | Security/permissions on SUBMODULE_TOKEN workflows | PARTIAL | PARTIAL |
| 7 | Sealed-file integrity | PARTIAL | PARTIAL |

**Initial: PASS 1 / FAIL 3 / PARTIAL 3**
**Re-Run: PASS 1 / FAIL 2 / PARTIAL 4** (Check 5 flipped FAIL → PARTIAL after Stage 1a merge)

See [Re-Run Results — Post PR #24 Merge](#re-run-results--post-pr-24-merge-d6d1793) at end of document.

---

## Check 1: AGENTS.md / CLAUDE.md Accuracy

### Command

```bash
cd '/home/martin/finished work/govern-zone'
test -f ACGS/AGENTS.md && echo "EXISTS: ACGS/AGENTS.md" || echo "MISSING: ACGS/AGENTS.md"
test -f pi/AGENTS.md && echo "EXISTS: pi/AGENTS.md" || echo "MISSING: pi/AGENTS.md"
grep -n "make\|npm\|uv run\|pnpm\|pytest\|ruff\|cargo" ACGS/AGENTS.md | head -20
```

### Output

```
EXISTS: ACGS/AGENTS.md
MISSING: pi/AGENTS.md

[ACGS/AGENTS.md grep for commands — 0 matches for make/npm/uv/pnpm/pytest/ruff/cargo]
2 matches in 1F:
   166: - Prefer role-appropriate `reasoning_effort` over explicit `model` overrides ...
   383: - Lock behavior with tests first, then make one smell-focused pass at a time.
```

### Verdict

PARTIAL

### Notes

- `ACGS/AGENTS.md` exists and is 27.6K of orchestration/OMX runtime directives. It does not contain
  specific build/test command references (`make`, `uv run`, `pnpm`, `pytest`, `ruff`, `cargo`), so
  there are no dead command references — but also no verified-accurate command inventory.
- `pi/AGENTS.md` does not exist. The `pi/` sibling directory does not exist in this working tree at
  all (`ls pi/` → "No such file or directory"). The plan assumes `pi/` exists but it is absent.
  This is a scope gap in the plan, not a corruption of existing instructions.
- No CLAUDE.md path/command references found to be stale (AGENTS.md is OMX-style, not command-list
  style).

**Deferred — non-critical:** `pi/` subproject is absent from this working tree; plan Check 3 and
Check 4 checks against `pi/` are N/A until the subproject is present.

---

## Check 2: Generated Index Accuracy

### Command

```bash
cd '/home/martin/finished work/govern-zone'
for f in PROJECT_INDEX.md ARCHITECTURE.md DOCUMENTATION_INDEX.md; do
  test -f "ACGS/$f" && echo "EXISTS: ACGS/$f" || echo "MISSING: ACGS/$f"
done
```

### Output

```
MISSING: ACGS/PROJECT_INDEX.md
MISSING: ACGS/ARCHITECTURE.md
MISSING: ACGS/DOCUMENTATION_INDEX.md
```

### Verdict

FAIL

### Notes

None of the three expected generated index files exist in `ACGS/`. The `ACGS/docs/` directory
contains architecture diagrams (`architecture.png`, `architecture.svg`) and narrative docs but no
`ARCHITECTURE.md` at the repo root. No regeneration command was found in `ACGS/Makefile` (0 matches
for "verify"; no `docs:` or `index:` targets inspected).

**Deferred — non-critical:** Generated index files are absent; regen procedure is undocumented.
No committed index to diff against. Recommend adding regen procedure to `ACGS/AGENTS.md` or
`ACGS/Makefile` in a follow-up sprint.

---

## Check 3: Per-Subproject Gate Green

### Command

```bash
cd '/home/martin/finished work/govern-zone'
grep -E '^verify:' ACGS/Makefile
ls pi/ 2>&1
```

### Output

```
[grep for 'verify:' in ACGS/Makefile — 0 matches]
"pi/": No such file or directory (os error 2)
```

### Verdict

FAIL

### Notes

- `ACGS/Makefile` exists (14.1K) but has **no `verify:` target**. The plan's Check 3 acceptance
  criterion (`grep -E '^verify:' ACGS/govern-zone/Makefile` exits 0) cannot be satisfied.
  The Makefile does reference constitutional hash tests at line 93:
  `src/core/services/api_gateway/tests/unit/test_lifespan.py::TestVerifyConstitutionalHashAtStartup`
  but no top-level `verify` phony target is defined.
- `pi/` sibling subproject does not exist in this working tree. `npm run check` cannot be run.
- Neither gate can be executed. Per plan principle "Evidence over assertion" — this is a FAIL, not
  a skip.

**Deferred — multi-scope:** `make verify` target missing from ACGS Makefile. Recommend adding a
`verify:` phony target that chains lint + test + typecheck in a follow-up PR scoped to `ACGS/`.

---

## Check 4: Cross-Subproject Dependency Drift

### Command

```bash
cd '/home/martin/finished work/govern-zone'
# pi -> acgs imports
find pi -name "*.ts" -o -name "*.tsx" -o -name "*.js" 2>/dev/null \
  | xargs grep -lE "^from acgs|^import.*acgs" 2>/dev/null | head -10
# ACGS/src -> @pi/ imports
grep -rE "@pi/" ACGS/src/ 2>/dev/null | head -10
```

### Output

```
[pi -> acgs: no output — pi/ does not exist]
[ACGS/src -> @pi/: no output — no matches found]
```

### Verdict

PASS

### Notes

No cross-subproject import drift detected. `ACGS/src/` contains no `@pi/` references. `pi/` is
absent so the inverse check is vacuously true — no drift is possible. If `pi/` is added in future,
this check should be re-run.

---

## Check 5: ADR Coverage for Monorepo Decisions

### Command

```bash
cd '/home/martin/finished work/govern-zone'
test -f ACGS/docs/workspace-PLAN.md && echo EXISTS || echo MISSING
find ACGS -maxdepth 2 -name "MACI-ROADMAP.md"
ls ACGS/docs/adr/
```

### Output

```
MISSING
[MACI-ROADMAP.md — 0 results]
ADR-019-evoskills.md  20.5K
```

### Verdict

FAIL

### Notes

- `ACGS/docs/workspace-PLAN.md` is **missing**. This is the Stage 1a deliverable (roadmap duo).
  Per the revised plan §Stage 2: "Check 5 (ADR coverage) now consumes workspace-PLAN.md only."
  Since workspace-PLAN.md does not exist, ADR coverage of its decisions cannot be assessed.
- `ACGS/MACI-ROADMAP.md` is **missing**. The MACI-ROADMAP.md at workspace root
  (`/home/martin/finished work/govern-zone/MACI-ROADMAP.md`, 14.6K) exists but is not inside the
  ACGS child repo at `ACGS/MACI-ROADMAP.md`.
- Only one ADR exists: `ADR-019-evoskills.md` (EvoSkills self-evolving skill packages). No ADRs
  covering MACI architecture, workspace-level monorepo decisions, or SUBMODULE_TOKEN token strategy.

**ADR gap inventory:**
| Decision area | Expected ADR | Status |
|---|---|---|
| MACI 4-role architecture | ADR for MACI separation of powers | MISSING |
| Workspace-level monorepo split (ACGS + pi) | ADR for monorepo topology | MISSING |
| SUBMODULE_TOKEN PAT strategy | ADR for token rotation | MISSING |
| EvoSkills skill evolution | ADR-019-evoskills.md | EXISTS |

**Deferred — blocked on Stage 1a merge:** workspace-PLAN.md and MACI-ROADMAP.md must land in
`ACGS/` before ADR gap analysis can be completed. This check is FAIL because Stage 2 was launched
before Stage 1a merged (plan gate violated).

---

## Check 6: Security/Permissions on SUBMODULE_TOKEN-Consumer Workflows

### Command

```bash
cd '/home/martin/finished work/govern-zone'
ls ACGS/.github/workflows/
grep -n "permissions" ACGS/.github/workflows/ci.yml
grep -A3 "permissions" ACGS/.github/workflows/ci.yml
grep -n "permissions" ACGS/.github/workflows/claude-ci-fix.yml
grep -A5 "permissions" ACGS/.github/workflows/claude-ci-fix.yml
```

### Output

```
ACGS/.github/workflows/:
  ci.yml             10.6K
  claude-ci-fix.yml  15.3K
  claude.yml          1.8K
  deploy-clinicalguard.yml  2.0K
  deploy-worker.yml   3.6K
  eval-rules.yml      3.5K
  release.yml         6.0K

--- ci.yml ---
[line 31]: permissions:
[line 33]:   pull-requests: read
    permissions:
      contents: read
      pull-requests: read

--- claude-ci-fix.yml ---
[line 19]: permissions:
[line 30]: permissions:
[line 32]:   contents: write
permissions:
  contents: read

jobs:
  fix:
    name: Auto-diagnose and fix CI failure
--
    permissions:
      contents: write
      pull-requests: write
      actions: read
    timeout-minutes: 25
```

### Verdict

PARTIAL

### Notes

The four SUBMODULE_TOKEN-consumer workflows named in the plan (`constitutional-hash.yml`,
`python-acgs-lite.yml`, `python-acgs-swarm.yml`, `python-clinicalguard.yml`) **do not exist** in
`ACGS/.github/workflows/`. The actual workflow set is different:

| Workflow file | Exists | Notes |
|---|---|---|
| `constitutional-hash.yml` | NO | Named in plan — absent |
| `python-acgs-lite.yml` | NO | Named in plan — absent |
| `python-acgs-swarm.yml` | NO | Named in plan — absent |
| `python-clinicalguard.yml` | NO | Named in plan — absent |
| `ci.yml` | YES | permissions: contents:read, pull-requests:read — SAFE |
| `claude-ci-fix.yml` | YES | Top-level: contents:read; job-level: contents:write, pull-requests:write, actions:read — ELEVATED |
| `claude.yml` | YES | Not inspected |
| `deploy-clinicalguard.yml` | YES | Not inspected |
| `deploy-worker.yml` | YES | Not inspected |
| `eval-rules.yml` | YES | Not inspected |
| `release.yml` | YES | Not inspected |

**Finding:** `claude-ci-fix.yml` has a job-level `contents: write` + `pull-requests: write`
permission block. This is wider than `contents:read` only. The elevated permissions are scoped to
the auto-fix job and appear intentional for the CI-fix workflow, but constitute an elevated
permission surface that was not flagged in the plan's original workflow inventory.

**`id-token: write` not found** in any inspected workflow — no OIDC widening detected.

**Deferred — non-critical:** The four plan-named workflows are absent; the actual workflows have
different names. Stage 1b runbook should update the workflow inventory. `claude-ci-fix.yml` elevated
permissions should be documented and confirmed intentional.

---

## Check 7: Sealed-File Integrity

### Command

```bash
cd '/home/martin/finished work/govern-zone'
# Find files with Constitutional Hash markers
grep -rl "# Constitutional Hash:" ACGS/ --include="*.py" | head -10
# Check for constitutional-hashes.lock
test -f ACGS/docs/constitutional-hashes.lock && echo EXISTS || echo MISSING
# Sample hash from a sealed file
grep -n "# Constitutional Hash:" \
  ACGS/packages/acgs-lite/src/acgs_lite/integrations/github.py | head -3
# ADR-019 hash
grep "Constitutional Hash" ACGS/docs/adr/ADR-019-evoskills.md
```

### Output

```
Files with Constitutional Hash markers:
ACGS/examples/lightning_ai_studio/server.py
ACGS/packages/acgs-lite/src/acgs_lite/integrations/litserve.py
ACGS/packages/acgs-lite/src/acgs_lite/integrations/litdata.py
ACGS/packages/acgs-lite/src/acgs_lite/integrations/github.py
ACGS/packages/acgs-lite/src/acgs_lite/integrations/gitlab.py
ACGS/packages/enhanced_agent_bus/constitutional_cache.py
ACGS/packages/enhanced_agent_bus/_ext_langgraph.py
ACGS/packages/enhanced_agent_bus/_ext_cognitive.py
ACGS/packages/enhanced_agent_bus/_ext_explanation_service.py
ACGS/packages/enhanced_agent_bus/api/config.py

docs/constitutional-hashes.lock: MISSING

github.py line 694: " + const_hash + "\n"   [hash written dynamically, not static marker]

ADR-019: **Constitutional Hash**: `608508a9bd224290`
```

### Verdict

PARTIAL

### Notes

- At least 10 Python files contain `# Constitutional Hash:` markers (10 found by grep; actual
  count may be higher — only `--include="*.py"` searched).
- `docs/constitutional-hashes.lock` does **not exist**. There is no lock file to compare hashes
  against; integrity verification against a known-good baseline is not possible.
- `ACGS/packages/acgs-lite/src/acgs_lite/integrations/github.py` line 694 writes a constitutional
  hash dynamically at runtime (`" + const_hash + "\n"`). The hash is not a static embedded value
  in this file — it is computed at runtime. This is consistent with the test at
  `src/core/services/api_gateway/tests/unit/test_lifespan.py::TestVerifyConstitutionalHashAtStartup`
  found in the Makefile.
- `ADR-019-evoskills.md` contains a static `Constitutional Hash: 608508a9bd224290` in its
  frontmatter — this is the only static hash found in the spot-check.
- No recomputation command found in `ACGS/Makefile` (no `constitutional-hash` target at top level).
  The Makefile references the test but not a hash recomputation script.

**Deferred — non-critical:** `constitutional-hashes.lock` is absent; hash verification cannot be
performed end-to-end. Recommend documenting the hash recomputation procedure and creating the lock
file in a follow-up sprint.

---

## Deferred Findings

### Deferred — multi-scope

| Finding | Source | Severity |
|---|---|---|
| `make verify` target missing from ACGS Makefile | Check 3 | CRIT (blocks gate) |
| Stage 1a deliverables (workspace-PLAN.md, MACI-ROADMAP.md) not in ACGS/ | Check 5 | CRIT (blocks ADR gap analysis) |

### Deferred — non-critical

| Finding | Source | Severity |
|---|---|---|
| `pi/` subproject absent from working tree | Checks 1,3,4 | INFO |
| Generated index files (PROJECT_INDEX.md, ARCHITECTURE.md, DOCUMENTATION_INDEX.md) absent | Check 2 | LOW |
| No regen procedure documented for generated indexes | Check 2 | LOW |
| 3 of 4 ADR areas missing (MACI, monorepo topology, SUBMODULE_TOKEN) | Check 5 | LOW |
| Plan-named SUBMODULE_TOKEN workflows absent (renamed or not yet created) | Check 6 | INFO |
| `claude-ci-fix.yml` job-level contents:write + pull-requests:write elevated permissions | Check 6 | LOW (appears intentional) |
| `constitutional-hashes.lock` absent; hash recomputation undocumented | Check 7 | LOW |

---

## Audit Notes

This audit was executed with Stage 1a (feat/roadmap-duo) **not yet merged** into master. The
revised plan §Stage 2 states: "Stage 2 launch is now gated on both Stage 1a merge and Stage 0a'
merge." Running the audit before Stage 1a merges explains the FAIL verdicts on Check 3 (no
`verify:` target) and Check 5 (workspace-PLAN.md and MACI-ROADMAP.md absent from ACGS/).

The two CRIT-class deferred findings should be resolved by merging Stage 1a (adds the deliverables)
and adding a `verify:` Makefile target. A re-run of Checks 3 and 5 after Stage 1a merges would
likely flip those to PASS.

---

## Re-Run Results — Post PR #24 Merge (d6d1793)

**Re-run date:** 2026-05-13 (post Stage 1a merge)
**Master commit:** `d6d1793` (Merge pull request #24 from dislovelhl/feat/roadmap-duo)
**Trigger:** initial audit Check 5 was deferred pending Stage 1a merge; PR #24 merged 2026-05-13T09:59:38Z.

### Re-evaluation commands

```bash
cd '/home/martin/finished work/govern-zone'
git fetch origin --prune
git log --oneline -3 origin/master
# Check 3 — verify target on new master
git show origin/master:ACGS/Makefile | grep -E '^verify:'
git ls-tree origin/master:pi
# Check 5 — Stage 1a deliverables
git show origin/master:MACI-ROADMAP.md | head -5
git show origin/master:docs/workspace-PLAN.md | head -5
git show origin/master:ACGS/MACI-ROADMAP.md       # path the original audit checked
git show origin/master:ACGS/docs/workspace-PLAN.md
git ls-tree origin/master:docs/adr
# Check 6 — plan-named workflows
git ls-tree origin/master:.github/workflows
# Check 7 — sealed-file lock
git show origin/master:docs/constitutional-hashes.lock | head -3
```

### Re-evaluation findings

#### Check 3 — UNCHANGED (FAIL)

- `ACGS/Makefile` on `origin/master` still has **no `verify:` target** (`grep -E '^verify:'` exits with 0 matches).
- `pi/` still absent at `origin/master` (`git ls-tree origin/master:pi` → `fatal: Not a valid object name`).
- PR #24 only added MACI-ROADMAP.md + workspace-PLAN.md; it did not touch ACGS/Makefile or create `pi/`.
- **Verdict: FAIL (unchanged).** Resolution still requires a separate `make verify` PR scoped to ACGS submodule.

#### Check 5 — FLIPPED (FAIL → PARTIAL)

Stage 1a deliverables are now present, but **at workspace root** (not under `ACGS/` as the original audit's command checked):

| Path | Initial audit expected | PR #24 placed | Status |
|---|---|---|---|
| MACI roadmap | `ACGS/MACI-ROADMAP.md` | `MACI-ROADMAP.md` (workspace root) | PRESENT at different path |
| Workspace plan | `ACGS/docs/workspace-PLAN.md` | `docs/workspace-PLAN.md` (workspace root) | PRESENT at different path |
| ADR-019 | `ACGS/docs/adr/ADR-019-evoskills.md` | unchanged | PRESENT |
| ADR-0001 | (n/a in initial audit) | `docs/adr/0001-in-context-procedure-execution-external-runtime-governance.md` | NEWLY discovered at workspace root |

The workspace-PLAN.md preamble explicitly states: *"Canonical location: `ACGS/govern-zone/docs/workspace-PLAN.md`. Workspace-root readers: see `/home/martin/Downloads/govern-zone/PLAN.md` for a pointer."* — so the workspace-root copy is intentional, with the canonical version expected to land inside ACGS later.

**ADR gap inventory (re-evaluated):**

| Decision area | Expected ADR | Status |
|---|---|---|
| MACI 4-role architecture | ADR for MACI separation of powers | **STILL MISSING** |
| Workspace-level monorepo split | ADR for monorepo topology | **STILL MISSING** |
| SUBMODULE_TOKEN PAT strategy | ADR for token rotation | **STILL MISSING** |
| External runtime governance | `docs/adr/0001-in-context-procedure-execution-external-runtime-governance.md` | NEW (workspace root) |
| EvoSkills skill evolution | `ACGS/docs/adr/ADR-019-evoskills.md` | EXISTS |

- **Verdict: PARTIAL (was FAIL).** Stage 1a deliverables exist (at workspace root); ADR coverage still incomplete for MACI/monorepo/SUBMODULE_TOKEN. Cannot flip to PASS until those 3 ADRs land.

#### Check 6 — UNCHANGED (PARTIAL), with scope-cite clarification

The 4 plan-named workflows DO exist — but at **workspace-root** `.github/workflows/`, not at `ACGS/.github/workflows/` (which the initial audit checked):

| Workflow | `ACGS/.github/workflows/` (initial audit) | workspace-root `.github/workflows/` (re-run) |
|---|---|---|
| `constitutional-hash.yml` | absent | **EXISTS** |
| `python-acgs-lite.yml` | absent | **EXISTS** |
| `python-acgs-swarm.yml` | absent | **EXISTS** |
| `python-clinicalguard.yml` | absent | **EXISTS** |

The initial audit's scope (look inside `ACGS/`) was different from where the workflows actually live (workspace root). The plan's intent (per `.omc/plans/govern-zone-phase-b3-revised.md`) appears to refer to workspace-root workflows. **Permissions on these workflows have NOT been re-inspected as part of this re-run** — defer to a Check 6 amendment or follow-up.

- **Verdict: PARTIAL (unchanged).** Permissions inspection of the now-located workflows is deferred.

#### Check 7 — UNCHANGED (PARTIAL), with scope-cite clarification

`docs/constitutional-hashes.lock` exists at **workspace root** (the initial audit checked `ACGS/docs/constitutional-hashes.lock`, which is still absent). Same scope-cite pattern as Checks 5 and 6: the audit's expectation that all governance artifacts live inside `ACGS/` does not match how the workspace actually organizes them.

- The workspace-root `docs/constitutional-hashes.lock` exists and could be used as the canonical baseline; the ACGS-internal hash recomputation procedure remains undocumented.
- **Verdict: PARTIAL (unchanged).**

### Summary of re-run

- 1 check flipped: **Check 5 FAIL → PARTIAL** (because Stage 1a deliverables now exist, even if at the workspace-root pattern).
- 3 checks (5, 6, 7) revealed the **same scope-cite ambiguity**: the audit expected paths inside `ACGS/`, but PR #24 (and prior workspace-level commits) placed governance artifacts at workspace root with explicit pointers to the canonical-inside-ACGS location. This is a **plan-vs-implementation scope mismatch**, not a defect.
- 2 CRIT-class blockers from initial audit:
  1. ✅ Stage 1a deliverables now present (at workspace root); Check 5 unblocked partially.
  2. ❌ `make verify` target still missing from `ACGS/Makefile`; Check 3 still blocked.

### New deferred findings (re-run only)

| Finding | Source | Severity |
|---|---|---|
| Scope-cite mismatch: plan refers to artifacts at `ACGS/` but they live at workspace root | Checks 5, 6, 7 | LOW (interpretive, not a defect) |
| `docs/adr/0001-in-context-procedure-execution-external-runtime-governance.md` at workspace root is a previously-uninventoried ADR | Check 5 | INFO |
| Workflow permissions on `constitutional-hash.yml`, `python-acgs-lite.yml`, `python-acgs-swarm.yml`, `python-clinicalguard.yml` at workspace root not yet inspected | Check 6 | LOW (defer to Check 6 amendment) |

### Recommendation

- **Do NOT merge this PR as PASS-gate.** Two FAIL verdicts remain (Checks 2 and 3). Check 3 requires adding a `verify:` Makefile target inside the ACGS submodule.
- **Do consider merging this PR for archival value** — the audit captures the workspace's current state, identifies a structural scope-cite ambiguity worth raising at plan level, and provides a clean baseline for a Phase 3.5 re-audit after Check 3 is unblocked.
- **Next blocker:** Add `verify:` target to `ACGS/Makefile` in a separate PR scoped to the ACGS submodule, then re-run Check 3. (User-action: SUBMODULE_TOKEN PAT rotation is unrelated to this audit but blocks PRs #25/#26/#27.)
