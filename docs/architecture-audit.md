# govern-zone Architecture Audit — 2026-05-22

> **Status:** Audit + plan only. No structural moves executed. Pre-existing
> WIP on branches `feat/agency-swarm-bridge`, `chore/tighten-module-boundaries-doc-positioning`,
> `design/codex-landing`, `design/chat-surface-token-migration` is the user's own
> work (`dislovelhl` / MartinLyu) — left untouched per multi-agent git safety.
>
> **Scope:** parent repo `dislovelhl/govern-zone` at `/home/martin/finished work/govern-zone/`,
> currently checked out on worktree branch `001-enhanced-agent-bus-analysis` (`ecc09de`).
>
> **Companion docs:** `MONOREPO.md` (registry), `docs/PLAN-MONOREPO.md` (the
> existing unification plan, Phases 0–5 landed), `CLAUDE.md` (parent agent guide).
> This file is **not** a replacement — it surfaces drift between those
> declarations and the actual filesystem and lists the cleanup work that
> remains.

---

## §1 Executive summary

The monorepo's *declared* architecture is sound — see `CLAUDE.md` and
`MONOREPO.md`. The trouble is drift between declaration and reality:

1. **5 orphan nested git repos at the parent root** are NOT registered in
   `.gitmodules`, NOT listed in `MONOREPO.md`, and NOT in any workspace file.
   They contain real branches and uncommitted work.
2. **3 untracked top-level dirs with real Python code** (`govern_zone_acgs/`)
   and orientation pointers (`codex/`, `omx/`) sit invisible to git.
3. **`MONOREPO.md` is out of sync with `pyproject.toml [tool.uv.workspace]`:**
   `packages/legalguard` doesn't exist; `packages/gove-zone` and
   `packages/agent-bus-analyzer` exist but aren't in the registry table.
4. **Root `AGENTS.md` and `CLAUDE.md` have drifted** — the parent's hard rule
   ("if you update one, update both") was violated; `git status` flags
   `AGENTS.md` modified.
5. **The `packages/clinicalguard` submodule is uninitialized** in this
   checkout (`git submodule status` shows the leading `-`).
6. **8 worktrees registered** across `/tmp`, `~/.local/share/warp-terminal/`,
   `~/Downloads/`, and `~/Downloads/self-improve-workspaces/`. 3 are
   `prunable`.
7. **Documentation routing is confused.** `docs/workspace-PLAN.md` declares
   itself canonical at a path that doesn't exist (`ACGS/govern-zone/docs/...`)
   and points to workspace state in a *different* directory tree
   (`/home/martin/Downloads/govern-zone/.omc/...`).
8. **Test-snapshot files at root** (4× `gove-zone-actions-*.md`, gitignored,
   ~30 KB) should live under `acgi-ai/test-snapshots/` or be deleted.

None of these is catastrophic. None changes the *intended* architecture.
But each one violates one of the seven success criteria in the goal
(clear structure / feature-first / strong boundaries / minimal / consistent
naming / verifiable / documentation-ready), and the cumulative effect is
exactly the "feels unprofessional" symptom the goal targets.

The fix is largely **delete or relocate**, not "redesign." A handful of
parent-only commits clears most of it without entering any submodule.

---

## §2 Topology snapshot (literal)

```
$ scope-detect.py "/home/martin/finished work/govern-zone"

topology:       submodule-parent
git root (cwd): /home/martin/finished work/govern-zone
.gitmodules:    yes
sealed markers: AUTHZ-ROADMAP.md, PLAN.md
generated:      pnpm-lock.yaml, uv.lock
subprojects:    27
```

> ⚠ `scope-detect.py` labels three top-level dirs (`ACGS-pr52-review/`,
> `clinicalguard-privacy-hardening/`, `eab-production-hardening/`) as `worktree`
> based on filesystem heuristics, but `git rev-parse --git-common-dir` inside
> each fails with `not a git repository: (null)`. They are **plain
> directories** that happen to carry `CLAUDE.md`/`AGENTS.md` — almost
> certainly snapshots copied out of real worktrees elsewhere. Treat them as
> plain dirs, not worktrees. The §10 matrix reflects this; §4.A does too.

**Registered submodules** (`.gitmodules` — 6):

| Path | Branch | Status today |
|---|---|---|
| `packages/acgs-lite` | `main` | clean, at `a6c58c42` (v2.7.0-138) |
| `packages/Acgs-Swarm` | `langgraph-runtime/unit-10-coordinator` | clean, at `38dfe5ab` |
| `packages/clinicalguard` | `main` | **uninitialized** (`-99a7416…`) |
| `external/natural_language_autoencoders` | (default) | clean |
| `external/UI-TARS-desktop` | (default) | clean |
| `external/everything-claude-code` | (default) | clean |

**Workspace members** (`pyproject.toml [tool.uv.workspace]` — 7):
```
packages/acgs-lite           (also submodule)
packages/Acgs-Swarm          (also submodule)
packages/clinicalguard       (also submodule, uninitialized)
packages/gove-zone           ← NOT in MONOREPO.md
packages/agent-bus-analyzer  ← NOT in MONOREPO.md
acgs_governance_eval_mvp     (parent-tracked)
acgs-cft-governance-pack     (parent-tracked)
```

**pnpm workspace** (`pnpm-workspace.yaml` — 2):
```
acgi-ai
acgs-enterprise-ai-manager/frontend
```

**Worktrees** (`git worktree list` — 8 + current):
```
.                                                                  001-enhanced-agent-bus-analysis  [primary]
~/.local/share/warp-terminal/worktrees/govern-zone/caprock-sotol            caprock-sotol
~/.local/share/warp-terminal/worktrees/govern-zone/olla-pinyon              olla-pinyon
~/.local/share/warp-terminal/worktrees/govern-zone/petrified-metate         petrified-metate
~/.local/share/warp-terminal/worktrees/govern-zone/travertine-candelilla    travertine-candelilla  [same SHA as caprock-sotol]
~/.local/share/warp-terminal/worktrees/govern-zone/tumbleweed-moonrise      tumbleweed-moonrise
~/Downloads/govern-zone-frontend-plan                                       plan/complete-platform-frontend
~/Downloads/self-improve-workspaces/govern-zone-pr-eval-regression-coverage improve/eval-regression-coverage-hardening-pr
/tmp/govern-fix                                                             fix/governance-critical-c1-c2-c3  [prunable]
/tmp/govern-zone-format-fix-2026-05-13                                      chore/ruff-format-test-audit-chain-2026-05-13  [prunable]
/tmp/govern-zone-pr24                                                       (detached HEAD)  [prunable]
```

---

## §3 WIP ownership inventory (read-only, no edits)

| Scope | Kind | Branch | Author of unpushed | Last commit | Action |
|---|---|---|---|---|---|
| `ACGS/` (root nested repo) | orphan repo | `feat/agency-swarm-bridge` | `dislovelhl` | 2026-05-07 | leave — user's WIP, see §4.A |
| `acgs-lite/` (root, ≠ submodule!) | orphan repo | `chore/tighten-module-boundaries-doc-positioning` | `dislovelhl` | 2026-05-09 | leave — user's WIP, see §4.A |
| `ca-legal-agent-skills/` (root) | orphan repo | `design/codex-landing` | `dislovelhl` | 2026-05-09 | leave — user's WIP, see §4.A |
| `craft-agents-oss/` (root) | orphan repo | `design/chat-surface-token-migration` | `dislovelhl` | 2026-05-09 | leave — user's WIP, see §4.A |
| `packages/clinicalguard/` | submodule (uninit) | n/a | — | — | initialize or commit decision to leave bare |

Untracked parent files (8 paths in `git status`):
```
 M .claude/settings.json     ← user-edited
 M AGENTS.md                 ← drift from CLAUDE.md (see §4.D)
?? .agents/                  ← skills dir, see §4.E
?? .claude/hooks/acgs-emit-receipt.py
?? .plugin-eval/             ← metric-packs + reports
?? .specify/                 ← SpecKit init artifacts
?? codex/                    ← stub AGENTS.md only
?? govern_zone_acgs/         ← REAL Python code (§4.E)
?? omx/                      ← stub AGENTS.md only
```

**All dirty work belongs to the user.** No other agent's WIP detected.

---

## §4 State-vs-declaration drift

### 4.A — Orphan nested git repos at root

Five directories at the parent root are git repos but are **not** in
`.gitmodules` and **not** in any workspace file:

| Path | Why it exists (apparent) | Recommendation |
|---|---|---|
| `ACGS/` | Earlier-generation ACGS monorepo before unification | **DECIDE**: register as submodule, fold into `packages/`, or move out of tree entirely. Has 0/2 ahead/behind upstream and active feature branch — not abandoned. |
| `acgs-lite/` (root) | **Duplicate of `packages/acgs-lite/`** at a different SHA on a different branch | **REMOVE** (after capturing the chore branch upstream or merging into `packages/acgs-lite`). Two copies of a PyPI package on disk is a footgun. |
| `ca-legal-agent-skills/` (root) | Standalone skills repo, exists at root **and** referenced in `MONOREPO.md` as `packages/ca-legal-agent-skills/` (which does not exist) | Either move under `packages/` and register as submodule, OR delete the MONOREPO.md row pointing to the non-existent `packages/` path. |
| `craft-agents-oss/` (root) | Vendored OSS — no clear "why here" in any doc | **DECIDE**: external dependency → move to `external/`, vendor → leave at root but add to `MONOREPO.md`, or remove if unused. |
| `clinicalguard-privacy-hardening/` | **NOT a worktree** — plain directory with `CLAUDE.md` + `AGENTS.md`, no `.git`. `scope-detect.py` mislabels it. Likely a snapshot/copy of work that was done in a real worktree elsewhere. | Decide: archive under `docs/archive/` if historical, or delete if superseded. |

### 4.B — Workspace ↔ registry drift

| Where it appears | What it says |
|---|---|
| `pyproject.toml [tool.uv.workspace]` | lists `packages/gove-zone`, `packages/agent-bus-analyzer` |
| `MONOREPO.md` | does NOT mention either |
| `MONOREPO.md` | references `packages/legalguard/` and `packages/ca-legal-agent-skills/` |
| Filesystem | neither path exists |

Fix: **`MONOREPO.md` is the registry**. Update it (single source of truth) and
delete dead rows. New rows for `gove-zone` and `agent-bus-analyzer` with their
CI workflow assignment.

`hermes_acgs_bundle/` is a separate inconsistency — listed in `MONOREPO.md` as
parent-tracked + has CI (`python-hermes-bundle.yml`) but is NOT in
`[tool.uv.workspace]`. Either add it (preferred) or drop the CI row.

### 4.C — `external/` has an unregistered submodule

```
external/
├── UI-TARS-desktop                   submodule (.gitmodules)
├── everything-claude-code            submodule
├── natural_language_autoencoders     submodule
└── openswarm                         ← unregistered nested repo
```

Either register `openswarm` in `.gitmodules` or vendor it as a plain directory
(no `.git`). Today it's neither.

### 4.D — Root `AGENTS.md` ↔ `CLAUDE.md` drift

`CLAUDE.md` self-describes as the source of truth that "every package's
`CLAUDE.md` references via `../../CLAUDE.md`." The hard rule:

> Both files stay in sync — if you update one, update both.

The current `diff CLAUDE.md AGENTS.md` shows substantive divergence in §Layout
and §Hard constraints. `git status` flags `AGENTS.md` as modified — meaning
`CLAUDE.md` was updated and `AGENTS.md` was forgotten.

Fix: regenerate `AGENTS.md` as a Codex-specific *mirror* of `CLAUDE.md` (one
section delta: Codex CLI workflow). Add a lint/CI check that hashes both and
fails when they drift apart on shared sections.

### 4.E — Untracked top-level dirs with real content

| Path | Content | Recommendation |
|---|---|---|
| `govern_zone_acgs/` | `__init__.py`, `integration.py`, `FAILURE_MODES.md`, `tests/` — real Python integration module | **Decide its home**: add to `[tool.uv.workspace]` if it's a workspace package, move under `acgi-ai/` or `packages/` if it belongs to one, or delete if it's a leftover experiment. Today it's invisible to `make test`. |
| `.specify/` | SpecKit project artifacts: `extensions.yml`, `feature.json`, `init-options.json`, `integration.json`, `memory/`, `scripts/`, `templates/`, `workflows/` | Add to `.gitignore` if SpecKit owns it locally; commit if any part is intended to be checked in. The presence of `.pr-body-fix-ci-clinicalguard.md` inside it suggests transient work. |
| `.agents/` | `skills/` only | Empty-ish; likely OMC/agent state. Add to `.gitignore`. |
| `.plugin-eval/` | `metric-packs/`, `reports/` | Eval output / artifacts. `.gitignore`. |
| `codex/AGENTS.md` | one-file stub directory | Either inline the pointer into root `AGENTS.md` or delete. Empty wrapper directories add noise. |
| `omx/AGENTS.md` | one-file stub directory | Same — collapse or delete. |
| `.claude/hooks/acgs-emit-receipt.py` | untracked hook | Decide: commit if it's repo policy, gitignore if it's user-local. |

### 4.F — Top-level test-snapshot dump files

```
gove-zone-actions-live-after-test.md     9.7 KB  gitignored
gove-zone-actions-live-denied-test.md    9.7 KB  gitignored
gove-zone-actions-live-e2e.md            9.4 KB  gitignored
gove-zone-actions-snapshot.md            2.7 KB  gitignored
```

These are test artifacts from `acgi-ai`. They're already gitignored — so
they're invisible to commits — but they pollute the repo root listing.

Fix: relocate to `acgi-ai/test-snapshots/` (already gitignored via parent
`.gitignore` patterns) or `.benchmarks/`, or delete after each test run.

### 4.G — Worktree sprawl

3 worktrees in `/tmp/` are flagged `prunable` (their dirs are gone). Prune
them: `git worktree prune` is non-destructive when the underlying dir is
already missing.

The 5 warp-terminal worktrees use a unique convention (random pair-name slugs
like `caprock-sotol`). Two share the same SHA (`7974ed5`) — likely one is
abandoned.

Fix: `git worktree prune` first (clears the `/tmp/` ones). Then audit the
warp-terminal set with the user — most are auto-created by Warp's Conductor
feature and may be safe to remove from outside.

### 4.H — Documentation routing drift

| File | Problem |
|---|---|
| `docs/workspace-PLAN.md` | Self-declares canonical at `ACGS/govern-zone/docs/workspace-PLAN.md` — that path **does not exist** in this checkout. References workspace state at `/home/martin/Downloads/govern-zone/.omc/...` — a *different* directory tree. The doc was authored in a different workspace and copied here without updating the pointer. |
| `PLAN.md` (root, 84 KB) | Scoped to `acgi-ai/` only per `CLAUDE.md` §6, but the filename "PLAN.md" implies repo-wide. **Rename to `PLAN-FRONTEND.md`** or move to `acgi-ai/PLAN.md`. |
| `docs/PLAN-MONOREPO.md` | Canonical monorepo plan. Keep. |
| `docs/PLAN-GOVE-ZONE-KERNEL.md` | Kernel plan, 15 KB. Keep but cross-reference from `MONOREPO.md`. |
| Per-subproject `CLAUDE.md` references `../../CLAUDE.md` | Resolves correctly post-Phase-1. Keep. |

### 4.I — Naming inconsistency

Mixed casing for the same prefix:

| Style | Examples |
|---|---|
| `snake_case` | `acgs_governance_eval_mvp/`, `hermes_acgs_bundle/`, `govern_zone_acgs/` |
| `kebab-case` | `acgs-cft-governance-pack/`, `acgs-lite/`, `acgi-ai/`, `acgs-enterprise-ai-manager/` |
| `PascalCase` | `Acgs-Swarm/` |
| `lowercase-no-sep` | `clinicalguard/`, `legalguard/` |

This is the most disruptive thing to standardize because renames break
imports, CI path filters, submodule URLs, and constitutional-hash markers.
**Recommendation: leave Python-import-bearing names (`acgs_governance_eval_mvp`,
`govern_zone_acgs`, `hermes_acgs_bundle`) alone** — they have to match
Python's `import` syntax. Standardize *new* additions on kebab-case for
non-import dirs. Rename `Acgs-Swarm` → `acgs-swarm` only if accompanied by a
constitutional-hash rebuild and a CI workflow rename (`python-acgs-swarm.yml`
already lowercase — small win). Defer to a separate sprint.

---

## §5 Recommended reorg — phased, scope-respecting

Each phase is a separate PR. Each PR touches only the parent repo unless
explicitly noted. Per `CLAUDE.md` rule #2 — submodule changes are made
*inside* the submodule first, parent pointer bumped second.

### Phase 0 — Worktree + root hygiene (parent only, low blast radius)

1. `git worktree prune` — drops the 3 `prunable` `/tmp/` entries.
2. Move `gove-zone-actions-*.md` snapshots into `acgi-ai/test-snapshots/`
   (or delete; they regenerate).
3. Add to `.gitignore`:
   ```
   .agents/
   .plugin-eval/
   .specify/
   ```
   (verify none of their contents is intended to be committed first).
4. Decide on `codex/AGENTS.md` and `omx/AGENTS.md`: inline pointers into root
   `AGENTS.md` and delete the wrapper dirs.
5. Decide on `.claude/hooks/acgs-emit-receipt.py`: commit or gitignore.

**Verify gate:** `git status` shows only intentional changes;
`git worktree list` is clean.

### Phase 1 — `MONOREPO.md` and `AGENTS.md` parity (parent only)

1. Rebuild `AGENTS.md` from `CLAUDE.md`. Diff should be:
   - Title row
   - One §Codex CLI workflow section
   - Nothing else.
2. Update `MONOREPO.md`:
   - Add rows for `packages/gove-zone/` and `packages/agent-bus-analyzer/`
     (toolchain, CI workflow, maintainer).
   - Remove the row for `packages/legalguard/` (doesn't exist).
   - Disambiguate `packages/ca-legal-agent-skills/` row: either reflect that
     it lives at root today or commit to moving it under `packages/`.
   - Reconcile `hermes_acgs_bundle/`: add to `[tool.uv.workspace]` (preferred)
     or drop the MONOREPO.md row.
3. Add a CI check (`scripts/verify_claude_agents_parity.py`) that diffs
   `CLAUDE.md` and `AGENTS.md` minus the known-divergent sections; fails on
   unexpected drift.

**Verify gate:** `diff CLAUDE.md AGENTS.md` produces only the
expected/whitelisted section; the new CI job passes locally.

### Phase 2 — `PLAN.md` rename (parent only)

1. `git mv PLAN.md acgi-ai/PLAN.md` (or `PLAN-FRONTEND.md` at root if you
   want it visible from the root listing).
2. Update every reference: `CLAUDE.md`, `AGENTS.md`, `MONOREPO.md`,
   `docs/PLAN-MONOREPO.md` §6.
3. Confirm PLAN.md is **not** carrying a `Constitutional Hash:` marker that
   would invalidate; if it is, run `scripts/hardening_report.py` after the
   move.

**Verify gate:** `grep -r "PLAN.md" --include='*.md'` returns only updated
references.

### Phase 3 — `docs/workspace-PLAN.md` decision (parent only)

This doc was written in a different workspace and copied. Three options:
- **Delete** if its content lives elsewhere (most likely — it documents
  Phase B/3 work that's complete).
- **Re-anchor** by updating the "canonical location" pointer to this repo
  and replacing the `/home/martin/Downloads/...` reference with a
  `docs/` path.
- **Move** to `docs/archive/2026-05-12-phase-b3.md` if it's historical.

**Recommend:** archive (option 3) so the audit trail survives without
implying it's current.

### Phase 4 — Orphan nested git repos at root (parent + per-repo decisions)

For each of `ACGS/`, `acgs-lite/` (root), `ca-legal-agent-skills/` (root),
`craft-agents-oss/` (root):

1. Decide intent:
   - **submodule** under `packages/` or `external/` → follow `docs/PLAN-MONOREPO.md` §5 Phase 2 recipe (move .git aside, re-add as submodule).
   - **vendor** → drop the `.git`, commit contents into parent.
   - **remove** → confirm no unmerged work, then `rm -rf`.
2. Resolve any pending WIP first (each is on an in-progress branch — push or
   merge before any restructure).
3. For `acgs-lite/` (root) specifically: it's a duplicate of
   `packages/acgs-lite/` on a different branch. Decide which copy is
   authoritative (almost certainly `packages/acgs-lite/`); the root copy is
   most likely a stale clone from before the submodule registration in
   `docs/PLAN-MONOREPO.md` Phase 2.

**Verify gate:** `scope-detect.py` reports zero orphan repos at root;
`.gitmodules` matches every nested `.git` under tracked paths.

### Phase 5 — Untracked top-level code (parent only)

`govern_zone_acgs/` is real Python with tests but is invisible to
`make test`, `[tool.uv.workspace]`, and `MONOREPO.md`. Decide:

- **It's a workspace package** → add to `[tool.uv.workspace]`, give it a
  `pyproject.toml` if it doesn't have one, add a row in `MONOREPO.md`, wire
  up CI workflow.
- **It's part of another package** → move under that package's tree.
- **It's defunct** → delete it.

Today's state is the worst of those — it exists, has tests, and nothing
runs them.

### Phase 6 — `packages/clinicalguard` initialization

```bash
cd "/home/martin/finished work/govern-zone"
git submodule update --init --recursive packages/clinicalguard
```

Then verify it lines up with the SHA `99a7416ecaed118af23e5852ad5c643709f8e829`
that the parent points to.

If initialization is intentionally deferred (e.g. the private repo isn't
checked out everywhere), document that in `MONOREPO.md` under the
`clinicalguard` row.

### Phase 7 — `external/openswarm` registration

Either:
- `cd external/openswarm && git remote get-url origin`, then
  `git submodule add <url> external/openswarm` from parent, OR
- `rm -rf external/openswarm/.git` and commit the contents to vendor.

Pick based on whether you want pointer-tracked external code or vendored
copies.

### Phase 8 — Naming standardization (DEFERRED to a later sprint)

Only the truly-cosmetic renames. Constraints:
- Don't rename anything that's a Python import path
  (`acgs_governance_eval_mvp`, `hermes_acgs_bundle`, `govern_zone_acgs`).
- Don't rename anything published to PyPI (`acgs-lite`).
- `Acgs-Swarm` → `acgs-swarm` is the only candidate worth it; cost is
  rebuilding 201 constitutional-hash markers and updating
  `python-acgs-swarm.yml`. Skip unless someone is actively annoyed.

---

## §6 What stays out of scope

These are tempting but should NOT be folded into this audit's execution:

| Out of scope | Why |
|---|---|
| Touching any submodule's internal layout | Each submodule has its own `CLAUDE.md`; reorg there is a separate scope. |
| Replacing per-package toolchains (`acgs-lite` Makefile, `acgi-ai` Biome) | `docs/PLAN-MONOREPO.md` §8 explicitly defers this. |
| Constitutional-hash semantics changes | Sealed by governance contract. |
| `PLAN.md` content edits (acgi-ai roadmap) | Rename only — content is owned by acgi-ai. |
| Splitting/merging workflows in `.github/workflows/` | Path-filtered CI works; don't churn. |
| Rewriting `docs/PLAN-MONOREPO.md` | It's the authoritative plan; this audit feeds *into* it, not over it. |

---

## §7 Verification matrix (after the recommended phases land)

| Goal success criterion | How verified |
|---|---|
| Clear project structure | `scope-detect.py` reports zero orphan repos; `MONOREPO.md` matches `pyproject.toml` + `pnpm-workspace.yaml` |
| Feature-first organization | Each `packages/<name>/` is self-contained with own `CLAUDE.md`; no cross-package imports outside `[tool.uv.sources]` |
| Strong architecture boundaries | Submodule boundaries enforced; `make verify` per-package gates intact |
| Minimal but powerful | Phase 0 deletes the snapshot files, stub dirs, and prunable worktrees; Phase 4 resolves orphan duplicates |
| Consistent naming | Phase 1 reconciles `MONOREPO.md` ↔ workspaces; Phase 8 stays deferred for cosmetic renames |
| Reliable verification | `make verify` exits 0; CI `constitutional-hash.yml` green; new parity check added in Phase 1 |
| Documentation-ready | `CLAUDE.md` + `AGENTS.md` + `MONOREPO.md` + `docs/PLAN-MONOREPO.md` already form the canonical map; Phase 1 + Phase 3 close the doc-drift gaps |

---

## §8 Suggested PR sequencing

```
P0 hygiene     →  P1 docs parity  →  P2 PLAN rename
                                        |
                                        v
                                   P3 workspace-PLAN archive
                                        |
                                        v
P4 orphan nested repos (one PR per orphan — 4 PRs)
                                        |
                                        v
P5 govern_zone_acgs decision
                                        |
                                        v
P6 clinicalguard init    P7 openswarm   (independent)
                                        |
                                        v
P8 (deferred indefinitely)
```

Estimated: 9 small parent-only PRs + however many submodule PRs the orphan
resolutions require. Each parent PR should be reviewable in under 15
minutes. None of them require entering a submodule unless Phase 4 picks
"register as submodule" for an orphan.

---

## §9 Risks of executing this plan

| Risk | Likelihood | Mitigation |
|---|---|---|
| Phase 0 `.gitignore` adds catch something intended-to-commit | Low | Inspect `.agents/`, `.plugin-eval/`, `.specify/` contents first; commit anything needed before adding to ignore. |
| Phase 1 AGENTS.md regeneration drops a Codex-specific note | Low | Diff before/after; preserve the §Codex CLI workflow section verbatim. |
| Phase 2 PLAN.md rename breaks `CLAUDE.md` links | Medium | grep + replace all references in the same commit; CI rendering test if available. |
| Phase 4 orphan-repo move loses unmerged work | **High if rushed** | Each orphan has active branch + uncommitted files (per §3). **Resolve WIP per-repo first.** Do not start Phase 4 until §3 inventory has been cleared. |
| Phase 5 `govern_zone_acgs/` deletion deletes real integration tests | Medium | Read `govern_zone_acgs/integration.py` + `tests/` first; confirm with the user whether the module is live or vestigial. |
| Phase 6 clinicalguard init fails (private repo, no token) | Medium | Confirm `SUBMODULE_TOKEN` per `MONOREPO.md` §Required Actions secrets; init may need to run in CI rather than locally. |
| Constitutional-hash markers in any moved file | Medium | Run `scripts/hardening_report.py` after every move; recompute before committing. |

---

## §10 Appendix — full 27-subproject matrix

This anchors the thematic sections above against `scope-detect.py`'s
complete list, so nothing is silently dropped. "Recommended action" is the
phase from §5 that owns it; `—` means no action needed.

| # | Subproject | scope-detect kind | Local instructions | Git state today | Recommended action |
|---|---|---|---|---|---|
| 1 | `.agents/` | plain | none | untracked | P0: `.gitignore` |
| 2 | `.omc/` | plain | none | tracked (state files) | — (already in use) |
| 3 | `ACGS/` | repo | CLAUDE.md, AGENTS.md, .claude/, local-skills | dirty, `feat/agency-swarm-bridge`, 0/2 | P4: decide submodule / vendor / remove |
| 4 | `ACGS-pr52-review/` | plain (misclassified by scope-detect) | CLAUDE.md, AGENTS.md | plain dir, not a git repo | P3-style: archive under `docs/archive/` if historical, else delete |
| 5 | `acgi-ai/` | plain | (own CLAUDE.md, DEPLOY.md, DESIGN.md) | tracked, pnpm workspace member | — (canonical frontend) |
| 6 | `acgs-cft-governance-pack/` | plain | none at root, README + pyproject | tracked, uv workspace member | — (canonical) |
| 7 | `acgs-enterprise-ai-manager/` | plain | none | tracked; only `frontend/` is a workspace member | P1: update `MONOREPO.md` row if non-`frontend/` content is intended |
| 8 | `acgs-lite/` (root, ≠ `packages/acgs-lite`) | repo | (own) | dirty, `chore/tighten-module-boundaries…` | P4: duplicate of `packages/acgs-lite/` — almost certainly delete after capturing chore branch |
| 9 | `acgs_governance_eval_mvp/` | plain | none | tracked, uv workspace member | — (canonical) |
| 10 | `atomic-agents-playground/` | plain | none | **gitignored** (`.gitignore:101`) | — (local experiments, ignored by design) |
| 11 | `automation/` | plain | own README | tracked | — (canonical: policies/proposals/workflows) |
| 12 | `ca-legal-agent-skills/` (root) | repo | CLAUDE.md, AGENTS.md | dirty, `design/codex-landing` | P4: reconcile with `MONOREPO.md` row referencing `packages/ca-legal-agent-skills/` (which doesn't exist) |
| 13 | `clinicalguard-privacy-hardening/` | plain (misclassified) | CLAUDE.md, AGENTS.md | plain dir | P3-style: archive or delete |
| 14 | `codex/` | plain | AGENTS.md (stub only) | untracked | P0: inline pointer into root `AGENTS.md`, delete dir |
| 15 | `craft-agents-oss/` | repo | CLAUDE.md | clean working tree on `design/chat-surface-token-migration` | P4: decide external (→ `external/`) vs vendor vs remove |
| 16 | `docs/` | plain | none | tracked | — (canonical: ADRs, plans) |
| 17 | `eab-production-hardening/` | plain (misclassified) | CLAUDE.md, AGENTS.md, .claude/, local-skills | plain dir | P3-style: archive or delete |
| 18 | `external/` | plain | none | mix of submodules + unregistered `openswarm/` | P7: register or vendor `openswarm` |
| 19 | `govern_zone_acgs/` | plain | none (has FAILURE_MODES.md) | untracked, **real Python code with tests** | P5: decide workspace pkg / sub-module of another pkg / delete |
| 20 | `hermes_acgs_bundle/` | plain | none at root | tracked but NOT in `[tool.uv.workspace]` | P1: add to workspace OR drop the MONOREPO.md row |
| 21 | `local-chatgpt-bridge/` | plain | none (has README via `.gitignore`) | untracked, has `bin/`, `config.json`, own `.env` | P5-style: decide commit / gitignore / move under a package |
| 22 | `omx/` | plain | AGENTS.md (stub only) | untracked | P0: inline pointer into root `AGENTS.md`, delete dir |
| 23 | `packages/` | plain | none at this level | tracked, holds submodules | — (canonical packages root) |
| 24 | `scheduled-todos-backup-2026-04-30/` | plain | none | tracked, single file: `bump-acgs-lite-pointer.md` | P0: delete or move to `docs/archive/` |
| 25 | `scripts/` | plain | none | tracked: `hardening_report.py`, `verify_constitutional_hashes.py` | — (canonical) |
| 26 | `specs/` | plain | none | tracked: SpecKit feature spec | — (canonical) |
| 27 | `tests/` | plain | none | tracked: monorepo-level tests (`test_monorepo_invariants.py`) | — (canonical) |

Also at the parent root, not in the 27 subprojects list but relevant:
- `.env` at root: **gitignored** (line 2 of `.gitignore`). 104 bytes, last modified 2026-05-08. Confirmed safe from accidental commit; no action.
- `.plugin-eval/`: untracked dotfile dir (eval artifacts). P0: `.gitignore`.
- `.specify/`: untracked dotfile dir (SpecKit config). P0: `.gitignore` after confirming nothing inside is intended-to-commit.

---

## §11 What this audit deliberately does NOT do

- Does not move, delete, or rename any file.
- Does not enter any submodule.
- Does not stage anything.
- Does not bump submodule pointers.
- Does not edit sealed files (`PLAN.md`, `AUTHZ-ROADMAP.md`).
- Does not regenerate constitutional-hash markers.
- Does not modify any worktree outside this checkout.

Every action above is **a recommendation requiring explicit user approval**
before execution. The next step is for the user to pick which phase to run
first (suggest P0 → P1 → P2 as a low-risk warm-up sequence) and we
re-enter the workflow at that scope, *not* across all 8 phases.
