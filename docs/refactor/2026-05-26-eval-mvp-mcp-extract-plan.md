# 2026-05-26 — Eval-MVP MCP Server Extract: Inspection + Plan

Scope: `acgs_governance_eval_mvp/governed_mcp_v0/`. Driven by `/goal` directive to
"inspect first, then propose a small migration plan; make incremental,
reviewable changes." This document is deliverable 1 (inspection report) +
deliverable 2 (architecture map) + deliverable 3 (refactor plan) + deliverable 5
(baseline capture) + deliverable 7 (tech-debt list). No source code edited yet.

---

## 1. Project inspection report

### 1.1 Workspace topology

- Root: `/home/martin/finished work/govern-zone` — multi-package monorepo,
  submodule-parent topology.
- Python workspace: uv, members in `pyproject.toml [tool.uv.workspace]` —
  `packages/acgs-lite`, `packages/Acgs-Swarm`, `packages/clinicalguard`,
  `acgs_governance_eval_mvp`, `acgs-cft-governance-pack`.
- JS workspace: pnpm + Turborepo — `acgi-ai`, `acgs-enterprise-ai-manager/frontend`.
- Submodules (independent repos, hard boundaries): `packages/acgs-lite`,
  `packages/Acgs-Swarm`, `packages/clinicalguard`, `ca-legal-agent-skills`,
  `craft-agents-oss`, plus 3 read-only `external/*` deps.
- Worktrees: `ACGS-pr52-review`, `clinicalguard-privacy-hardening`,
  **`/tmp/govern-zone-mcp-refactor`** (this matters — see §1.3).
- Build/test gates: `make verify` (root), per-package gates authoritative
  (`pnpm -F acgi-ai …`, `cd packages/acgs-lite && make …`, etc.).

### 1.2 Dirty state inventory (NOT this session's work)

These belong to other agents / prior sessions. Out of scope; do not touch.

| Path | Kind | Owner signal |
|---|---|---|
| `packages/Acgs-Swarm` | submodule pointer drift (`+` in status) | another lane |
| `ACGS/` (nested repo) | dirty, 0/2 behind | feat/agency-swarm-bridge |
| `ca-legal-agent-skills/` | submodule dirty | design/codex-landing |
| `.gitignore` | modified | unknown |
| `??` untracked dirs (`.codegraph/`, `.cursor/`, `.gove-zone/`, `acgi-ai/dist-*`, `docs/superpowers/`, etc.) | tooling cache + earlier session artifacts | leave alone |
| `pnpm-lock.yaml`, `uv.lock` (untracked at root) | generated; do not stage | leave alone |
| `external/openswarm/` | untracked external dep | another lane |

Sealed-file markers: `PLAN.md` at root (scope-detect flagged it). No
constitutional-hash markers in eval-mvp scope (verified by grep).

### 1.3 Branch reality: this worktree vs `/tmp` worktree

| Worktree | Branch | vs origin/master | Refactor state |
|---|---|---|---|
| `/home/martin/finished work/govern-zone` (this) | `refactor/eval-mvp-mcp-server-extract` | **0 / 0** (identical) | nothing |
| `/tmp/govern-zone-mcp-refactor` | `refactor/eval-mvp-mcp-server-extract-v2` | **9 commits ahead** of origin/master, plus ~107 commits in local master beyond origin/master | **steps 1–9/10 DONE** (step 9 committed as `b8ae8cf` mid-session); step 10 (ruff format + docs sweep) pending |

**The canonical refactor work is in `/tmp`, not here.** This worktree's branch
is a stale name. Doing extraction here from scratch would create a third
divergent branch.

**⚠️ Another agent is actively committing in `/tmp/govern-zone-mcp-refactor` right now.**
Between two `wc -l` snapshots taken minutes apart in this session, three new
commits landed (step 6, step 7, step 8) and `mcp_server.py` shrank from 475 →
81 lines. **Do not edit anything in /tmp until the other agent has stopped.**
Confirm by re-running `git -C /tmp/govern-zone-mcp-refactor log -1` and
verifying the tip hash hasn't moved for ≥5 minutes before touching anything.

### 1.4 Eval-MVP package shape (master/this worktree)

```
acgs_governance_eval_mvp/
├── pyproject.toml         (3.10+, ruff line-length=120, packages: governance*, governed_mcp_v0*)
├── governance/            (separate package — out of scope for this refactor)
├── governed_mcp_v0/
│   ├── __init__.py        (23 lines)
│   ├── eval_gate.py       (308 lines)
│   ├── graph.py           (428 lines)
│   └── mcp_server.py      (726 lines — the extraction target)
├── tests/                 (16 test files, 113 pass at baseline)
└── docs/, scripts/, governed_*.html
```

### 1.5 Eval-MVP package shape (v2 worktree, latest snapshot)

```
governed_mcp_v0/
├── __init__.py       23 lines
├── constants.py      28 lines    (step 1/10)
├── errors.py         10 lines    (step 2/10)
├── models.py         93 lines    (step 3/10 — dataclasses + PolicyEngine Protocol)
├── _io.py           105 lines    (step 4/10)
├── policy.py        102 lines    (step 5/10)
├── verify.py        197 lines    (step 6/10)
├── fixtures.py       51 lines    (step 7/10)
├── server.py        252 lines    (step 8/10 — GovernedMCPServer orchestration)
├── eval_gate.py     308 lines    (unchanged)
├── graph.py         428 lines    (unchanged)
└── mcp_server.py     81 lines    (down from 726 — FastMCP entrypoint + re-exports)
```

Untracked on v2: `acgs_governance_eval_mvp/tests/test_import_surface.py` —
in-progress evidence for step 9/10 (public-surface stability test).

### 1.6 Baseline verification (literal output)

```
$ cd acgs_governance_eval_mvp && uv run pytest -q --no-header
........................................................................ [ 63%]
.........................................                                [100%]
113 passed in 0.82s
```

This is the master baseline. Any refactor step must preserve `113 passed`.

---

## 2. Architecture map (eval-mvp lane)

### 2.1 Current (master)

`mcp_server.py` (726 lines) is doing too many jobs in one file:

| Concern | Current location | Smells |
|---|---|---|
| Constants (hashes, tool allowlists) | top of `mcp_server.py` | module-level data mixed with orchestration |
| Custom exceptions | top of `mcp_server.py` | imported but co-located with handlers |
| Dataclasses (`AdmissionDecision`, `ReplayResult`, `RuntimeTargets`) | inside `mcp_server.py` | no `from __future__ import annotations` workarounds for forward refs |
| `PolicyEngine` Protocol | inside `mcp_server.py` | mixes interface with default impl |
| `DeterministicPolicyEngine` | inside `mcp_server.py` | concrete policy lives with admission orchestration |
| File-IO helpers (`_append_jsonl`, `_read_json`, `sha256_json`, etc.) | inside `mcp_server.py` | persistence concerns mixed with policy + admission |
| Replay verification (`verify_replay_bundle`) | inside `mcp_server.py` | independent invariant check, big enough to own a file |
| `GovernedMCPServer.admit` + replay orchestration | inside `mcp_server.py` | the only thing that *should* live in `mcp_server.py` |

### 2.2 Target (per v2 worktree — already realised)

```
governed_mcp_v0/
├── constants.py        # GENESIS_HASH, SAFE_TOOLS, GUARDED_TOOLS
├── errors.py           # GovernanceDenied, GovernanceStorageError
├── models.py           # AdmissionDecision, ReplayResult, RuntimeTargets, PolicyEngine Protocol
├── _io.py              # _append_jsonl, _read_json, sha256_json, _resolve_fixture_path, ...
├── policy.py           # DeterministicPolicyEngine
├── verify.py           # verify_replay_bundle + replay invariants
├── eval_gate.py        # (untouched)
├── graph.py            # (untouched)
└── mcp_server.py       # GovernedMCPServer orchestration only
```

Dependency direction: `mcp_server.py → policy.py → models.py`,
`mcp_server.py → _io.py`, `verify.py → models.py + _io.py`. No cycles.
Co-locating `PolicyEngine` Protocol with `RuntimeTargets`/`AdmissionDecision`
in `models.py` avoids a circular import (Protocol forward-refers to both).

### 2.3 What v2 still has to do (steps 9–10)

Updated after observing v2 land steps 6/7/8 mid-session:

- **step 9/10 (in progress):** `tests/test_import_surface.py` exists as
  untracked. Likely pinned to assert that every name in
  `governed_mcp_v0.__all__` resolves and re-exports from `mcp_server` for
  back-compat. Finishing this step means: review the test, ensure it locks
  the public surface, commit it.
- **step 10/10 (pending):** ruff format + docs pass. Touches every new module
  for docstring + comment polish, possibly tightens `__init__.py` re-exports,
  and lands a `docs/refactor/README.md` cross-reference. No behavioural
  changes.

The exact list was never written to disk on v2 — it lives in commit messages
only. Recover it from `git log --oneline` on the v2 branch before starting.

---

## 3. Refactor plan (incremental, reviewable)

### 3.1 The blocking decision — RESOLVED

**Decision resolved during this session: option A.** v2 landed steps 6, 7, 8,
and 9 mid-session, taking ownership of the refactor lane. The primary
worktree's `refactor/eval-mvp-mcp-server-extract` branch is now obsolete and
should be deleted after v2 merges to master (see §3.2 Follow-up 1).

Historical record of the alternatives that were rejected:

**A. (CHOSEN) Continue in `/tmp/govern-zone-mcp-refactor` (v2 worktree).** v2
   is the canonical branch. Smallest blast radius. Steps 1–9 already there.

**B. Fast-forward this branch to v2 first, then continue here.** Rejected:
   risks force-updating a branch other worktrees may reference.

**C. Cherry-pick v2's extraction commits onto this branch.** Rejected:
   produces a third divergent history of the same logical work.

### 3.2 Concrete next steps (assuming option A)

The other agent already finished step 9 mid-session (`b8ae8cf`). Only step 10
remains in the 10-step plan. Two follow-ups belong to this primary worktree.

**Step 10/10 (lives in `/tmp` v2) — format + docs sweep.** Owned by the
other agent. Don't pre-empt. Wait for the `step 10/10` commit to land.
Verify with `git -C /tmp/govern-zone-mcp-refactor log -1`.

**Follow-up 1 (this worktree) — branch cleanup.** Once v2 lands and merges
to master, the stale `refactor/eval-mvp-mcp-server-extract` branch in this
worktree can be deleted. Suggested sequence (after v2 merge):

```
git fetch origin
git checkout master && git pull --ff-only origin master
git branch -d refactor/eval-mvp-mcp-server-extract
```

Do NOT force-delete (`-D`) — if the branch has unique commits, that's a
warning to investigate, not silence.

**Follow-up 2 (this worktree) — commit this planning doc.** The file
`docs/refactor/2026-05-26-eval-mvp-mcp-extract-plan.md` is currently
untracked. Decide:
- (a) Discard — the v2 commit history is enough record.
- (b) Commit to master on a small `docs/eval-mvp-refactor-recap` branch,
  open a docs-only PR.

Recommended: (b), because the 10-step plan never lived in a doc on v2; this
file is the only durable artifact of the *meta-process* (option A/B/C
decision, multi-agent safety rules).

Each follow-up uses the same shape as the refactor steps: read → change →
re-import / verify → test → commit. No batching, no parallel steps.

### 3.3 Hard rules (must not violate)

- Never `git add -A` or `git add .` — use explicit paths.
- Never touch files outside `acgs_governance_eval_mvp/governed_mcp_v0/` and
  its tests in a single refactor commit.
- Never edit `packages/Acgs-Swarm`, `ca-legal-agent-skills`, `ACGS/`,
  `external/*`, sealed `PLAN.md`, or `constitutional-hashes.lock`.
- Never amend an already-pushed commit. Always create a new commit.
- If a step changes the test count, STOP and revert. Either the refactor
  moved behaviour or the test was finding behaviour incidentally — neither
  is OK in a "move only" step.

### 3.4 Definition of done (per step)

- Diff touches only `governed_mcp_v0/<extracted>.py`, `mcp_server.py`, and
  test files that import from it.
- `uv run pytest -q` → `113 passed`.
- `uv run ruff check governed_mcp_v0/` → clean.
- New file has a one-line module docstring stating its single responsibility.
- `__init__.py` re-exports updated if the extracted name was public.
- Commit message follows `refactor(eval-mvp): <verb> X from mcp_server.py (step N/10)`.

---

## 4. Tech-debt list (eval-mvp scope only)

Carried into the refactor backlog but NOT this step:

1. `acgs_governance_eval_mvp/pyproject.toml` overrides `line-length = 120`;
   monorepo uses 100. Re-aligning is a separate PR after the extract finishes.
2. Two top-level packages (`governance/`, `governed_mcp_v0/`) inside one
   distribution. Long-term these should split into two distributions; for
   now setuptools `packages.find` whitelists both.
3. Multiple `__pycache__` and `.egg-info` directories tracked under the
   workspace — `.gitignore` should cover them all consistently.
4. `governance/` package is unanalysed in this report — out of scope.
5. `eval_gate.py` (308 lines) and `graph.py` (428 lines) were not part of the
   v2 split. Whether they need decomposition is open.
6. Test coverage for `governed_mcp_v0` after the split should be measured;
   today there's no coverage gate.

Out of eval-mvp scope (do not let it leak in): submodule pointer drift,
nested-repo dirty state, untracked tooling caches, frontend, packaging.

---

## 5. Deliverable status

| Deliverable | Status |
|---|---|
| 1. Project inspection report | done (§1) |
| 2. Current architecture map | done (§2.1) + target map (§2.2) |
| 3. Refactor/restructure plan | done (§3), pending option A/B/C selection |
| 4. Incremental implementation | **gated** on §3.1 decision |
| 5. Updated tests / smoke checks | baseline captured (§1.6); per-step gate defined (§3.4) |
| 6. Final verification report | will follow each implemented step |
| 7. Remaining tech-debt list | done (§4) |

## 6. Risks remaining

- **Three-branch divergence** if option A isn't chosen. Mitigation: pick A.
- **Other agents' dirty state** could be staged accidentally. Mitigation: only
  ever `git add <explicit path inside governed_mcp_v0>`.
- **v2's plan doc may name different file targets** for steps 6–10. Mitigation:
  read v2's plan before starting step 6.
- **`governance/` and `governed_mcp_v0/` cross-imports** — not audited.
  Mitigation: grep for `from governance import` and `from governed_mcp_v0` in
  both packages before each step.
