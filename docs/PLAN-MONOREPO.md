# govern-zone Monorepo Unification Plan

> Historical note: this file records the original unification plan. The current
> truth for package inventory, CI fan-out, and active carve-outs is
> `../MONOREPO.md`.

> Scope: turn `govern-zone/` from "single repo + three uncommitted external repos in
> `packages/`" into a true Turborepo + uv-workspace monorepo, while preserving the
> independent publish lifecycle of `acgs-lite` (PyPI) and the existing CI for
> `acgi-ai`.
>
> Companion to `../acgi-ai/PLAN.md` (which is scoped to `acgi-ai/` only).

---

## §1 Premises (challenge first)

1. **Today is not a monorepo.** Parent repo tracks 251 files; none live under
   `packages/`. `packages/acgs-lite`, `packages/Acgs-Swarm`, `packages/clinicalguard`
   are nested git repos. There is no `.gitmodules`. Each package's `CLAUDE.md`
   references `../../CLAUDE.md` and that file does not exist.
2. **`acgs-lite` is published to PyPI**. Downstreams pin `acgs-lite>=2.8.1`.
   The workspace must NOT break PyPI consumers; local cross-linking is dev-mode only.
3. **The frontend (`acgi-ai/`) is the only thing with parent CI.** Workflows
   `console.yml` + `marketing.yml` deploy to GCP Cloud Run via WIF. They must keep
   working unchanged after unification.
4. **Python package floors differ** (`acgs-lite >=3.10`, `Acgs-Swarm >=3.11`,
   others vary). Workspace floor will be the highest: **Python 3.11**.
5. **Constitutional-hash markers exist on multiple files** and are part of the
   governance contract. Unification must not silently invalidate any hash.

If any premise is wrong, halt before executing.

---

## §2 Definition of done

| Dimension | Bar |
|---|---|
| **Single build** | `make all` (or `pnpm turbo run build`) from repo root produces all package artifacts; exit code 0. |
| **Single test** | `make test` runs Python (pytest fan-out) + JS (`pnpm -r test`); exit code 0. |
| **Single lint** | `make lint` runs ruff for Python + biome for JS + (if added) shellcheck for `*.sh`. |
| **Doc references resolve** | Every `../../CLAUDE.md` and `../../AGENTS.md` reference in any package resolves to a real file. |
| **Local cross-link** | A local edit to `packages/acgs-lite/src/` is picked up by `packages/Acgs-Swarm` tests without manual `pip install -e`. PyPI publish artifacts unchanged. |
| **Submodule registry** | `.gitmodules` exists and registers `packages/Acgs-Swarm`, `packages/acgs-lite`, `packages/clinicalguard`. `git submodule status` is clean from a fresh clone. |
| **CI fan-out** | Path-filtered workflow runs only the affected package; full-matrix runs nightly + on `master`. |
| **Constitutional hashes** | A root-level CI job re-verifies every file with a `Constitutional Hash:` marker. Any drift fails the build. |

---

## §3 Current state inventory

Tracked surfaces (251 files):
- `acgi-ai/` — React 19 + Vite + Tailwind 4 + Biome (frontend, has CI)
- `automation/` — policies, proposals, workflows, scripts, tests
- `docs/` — adr/, design/, registry.yaml
- `acgs_governance_eval_mvp/` — Python, has pyproject.toml
- `acgs-cft-governance-pack/` — Python, has pyproject.toml
- `hermes_acgs_bundle/` — needs inspection
- `.github/workflows/console.yml`, `marketing.yml`
- `PLAN.md`, `.gitignore`, `.omc/skills/governance-deferred-lane-mapping.md`

Untracked nested git repos (NOT in parent history):
- `packages/acgs-lite/` — Python, FastAPI, MkDocs, ~22 files at top level, published to PyPI
- `packages/Acgs-Swarm/` — Python, constitutional swarm, has uv.lock (590KB)
- `packages/clinicalguard/` — Python, agent + constitution + skills
- `packages/legalguard/` — directory exists, status TBD
- `packages/ca-legal-agent-skills/` — directory exists, status TBD

Cross-package references currently in source:
- `acgs-lite>=2.8.1` declared in `packages/Acgs-Swarm/pyproject.toml` (PyPI dep)
- Each package `CLAUDE.md` references `../../CLAUDE.md` (broken)
- `packages/AGENTS.md` exists at `packages/` level

---

## §4 Target architecture

```
govern-zone/                           (parent git repo)
├── CLAUDE.md                          NEW — root agent guide
├── AGENTS.md                          NEW — root agent guide for Codex/OMX
├── Makefile                           NEW — top-level fan-out
├── package.json                       NEW — pnpm workspace root
├── pnpm-workspace.yaml                NEW — declares acgi-ai/ + future JS pkgs
├── turbo.json                         NEW — turbo pipelines (build/test/lint)
├── pyproject.toml                     NEW — uv workspace + dev tooling
├── .gitmodules                        NEW — registers packages/* as submodules
├── .github/
│   ├── workflows/
│   │   ├── console.yml                EXISTING — unchanged
│   │   ├── marketing.yml              EXISTING — unchanged
│   │   ├── python-acgs-lite.yml       NEW — path-filtered
│   │   ├── python-acgs-swarm.yml      NEW — path-filtered
│   │   ├── python-clinicalguard.yml   NEW — path-filtered
│   │   ├── python-other.yml           NEW — covers eval-mvp, cft-pack, hermes
│   │   └── constitutional-hash.yml    NEW — verifies hash markers
├── docs/
│   ├── PLAN-MONOREPO.md               THIS FILE
│   ├── adr/                           EXISTING
│   └── ...
├── acgi-ai/                           EXISTING — unchanged
├── automation/                        EXISTING — unchanged
├── packages/
│   ├── acgs-lite/                     SUBMODULE
│   ├── Acgs-Swarm/                    SUBMODULE — pyproject patched with [tool.uv.sources]
│   ├── clinicalguard/                 SUBMODULE
│   ├── legalguard/                    SUBMODULE if it has its own .git, else plain dir
│   └── ca-legal-agent-skills/         SUBMODULE if it has its own .git, else plain dir
├── acgs_governance_eval_mvp/          EXISTING — joins uv workspace
├── acgs-cft-governance-pack/          EXISTING — joins uv workspace
└── hermes_acgs_bundle/                EXISTING — TBD whether to add to workspace
```

### Key design decisions

**Submodule registration** (not subtree, not absorption): preserves each package's
independent history and publish lifecycle. Parent tracks pinned commits. CI guards
against pointer drift.

**uv workspace `[tool.uv.sources]`** (not editable installs): the cleanest way to
say "in dev, resolve `acgs-lite` from `packages/acgs-lite`; in publish, resolve
from PyPI." The `pyproject.toml` `dependencies` array is unchanged for downstream
consumers. Only the dev resolver sees the workspace mapping.

**Turborepo over Nx**: lighter, no task graph DSL to learn, native pnpm workspace
support. `turbo run build --filter=acgi-ai` for partial builds.

**Python `>=3.11` floor**: matches the highest current package floor (Acgs-Swarm).
`acgs-lite` becomes effectively `>=3.11` only at the workspace level; published
metadata still says `>=3.10`.

---

## §5 Phased execution

### Phase 0 — Plan record (ZERO blast radius)

- [x] Write this file (`docs/PLAN-MONOREPO.md`)
- [ ] Confirm phase 1 and 2 with user

### Phase 1 — Additive root files (LOW blast radius — new files only)

Touch only files that do not currently exist. No package-internal mutations.

1. Author `CLAUDE.md` (root) — agent guide that the package files reference
2. Author `AGENTS.md` (root) — Codex/OMX equivalent
3. Author `package.json` + `pnpm-workspace.yaml` — declare `acgi-ai` as workspace member
4. Author `turbo.json` — pipelines: `build`, `test`, `lint`, `typecheck`, `dev`
5. Author `pyproject.toml` (root) — `[tool.uv.workspace]` listing members
6. Author `Makefile` — fan-out targets that call turbo for JS, uv for Python
7. Verification: `pnpm install` succeeds; `make lint` runs (may fail on existing issues — that's fine, structure works)

**Stop gate after Phase 1.** Show the user the new files; confirm before Phase 2.

### Phase 2 — Submodule registration (MEDIUM blast radius — touches `.git` topology)

This is the destructive-ish part. Requires explicit confirmation.

For each nested repo in `packages/`:

```bash
# 1. Capture the current commit of the nested repo
cd packages/<name> && git rev-parse HEAD > /tmp/<name>-pin && cd ../..

# 2. Note the remote URL
cd packages/<name> && git remote get-url origin > /tmp/<name>-url && cd ../..

# 3. Move nested .git aside (do not delete)
mv packages/<name>/.git packages/<name>/.git.bak-$(date +%s)

# 4. Move the directory aside
mv packages/<name> packages/<name>.staging

# 5. Register as submodule pinned to the captured commit
git submodule add -b master $(cat /tmp/<name>-url) packages/<name>
cd packages/<name> && git checkout $(cat /tmp/<name>-pin) && cd ../..

# 6. Validate file parity
diff -rq packages/<name> packages/<name>.staging
# Resolve any deltas (working-tree changes) before deleting .staging
```

**This is reversible up until step 6.** If anything looks wrong, restore from `.bak`
and `.staging`.

### Phase 3 — Cross-package reference patches (LOW blast radius — surgical)

1. `packages/Acgs-Swarm/pyproject.toml` — add `[tool.uv.sources]` workspace map for
   `acgs-lite`. Do NOT change the `dependencies` array.
2. Same patch in any other package that depends on `acgs-lite` locally.
3. Update each package's `CLAUDE.md` to reflect that `../../CLAUDE.md` now exists.
4. Add a `versions.toml` at root if we want a single place to bump cross-package floors.

### Phase 4 — Path-filtered CI (LOW blast radius — new workflows only)

Mirror the per-package CI from each nested `.github/` into the parent's
`.github/workflows/` as path-filtered jobs. The nested CI continues to run on the
external repo's pushes; the parent CI runs on monorepo PRs.

```yaml
# Example: python-acgs-lite.yml
name: python-acgs-lite
on:
  pull_request:
    paths: [packages/acgs-lite/**]
  push:
    branches: [master]
    paths: [packages/acgs-lite/**]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { submodules: recursive }
      - uses: astral-sh/setup-uv@v3
      - run: uv sync --package acgs-lite
      - run: cd packages/acgs-lite && make lint typecheck test
```

### Phase 5 — Constitutional-hash CI (LOW blast radius)

Single job that finds every file containing `Constitutional Hash:` and verifies the
declared hash matches the recomputed hash. Fails the build on any drift.

### Phase 6 — Doc cleanup (LOW blast radius)

- Update each package `CLAUDE.md` "see ../../CLAUDE.md for repo-wide rules" line
  now that the root file exists.
- Add a `MONOREPO.md` table mapping each package → CI workflow → maintainer.
- Tag the existing `PLAN.md` clearly as "scoped to acgi-ai" to avoid confusion.

---

## §6 Risks & mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Submodule conversion loses uncommitted work in a nested repo | Low | Phase 2 step 4 stages the directory, never deletes; explicit diff check in step 6. |
| `[tool.uv.sources]` breaks PyPI consumers of `Acgs-Swarm` | Very low | `[tool.uv.sources]` is dev-resolver only; published wheel metadata unaffected. Verify with `uv build` and `twine check` before tagging. |
| Python floor bump (3.10→3.11) breaks `acgs-lite` users on 3.10 | Low | Keep `acgs-lite/pyproject.toml` `requires-python = ">=3.10"` unchanged. Workspace floor is local-only. |
| Turborepo + existing `acgi-ai/package.json` `packageManager: pnpm@9.15.4` mismatch | Low | Root `package.json` declares same `packageManager` value; `pnpm-workspace.yaml` includes `acgi-ai` as member. |
| Constitutional-hash CI fails on first run | Medium | Run it locally first; fix any drift in a separate commit before adding to CI. |
| Existing GCP Cloud Run deploys break | Very low | `console.yml` + `marketing.yml` paths unchanged; their working directory is `acgi-ai/` which is unchanged. |
| `legalguard/` and `ca-legal-agent-skills/` turn out to NOT be git repos | Medium | If true, they stay as plain directories — no submodule needed; just include in workspace. Phase 2 inspects each before acting. |

---

## §7 Verification gates

After each phase, run:

```bash
make verify        # alias for: lint + typecheck + test (Python + JS)
make verify-fresh  # rm -rf node_modules + .venv, then make verify
git submodule foreach 'git status'   # all clean
git status                           # parent clean
```

Phase 1 PASS = `pnpm install` exits 0 and `make` lists all targets.
Phase 2 PASS = `git submodule status` lists every external repo with a SHA, no `+` or `-`.
Phase 3 PASS = `cd packages/Acgs-Swarm && python -c "import acgs_lite; print(acgs_lite.__file__)"` resolves to `packages/acgs-lite/src/...` not `site-packages/`.
Phase 4 PASS = open a PR touching one package; only that workflow runs.
Phase 5 PASS = constitutional-hash job green on a fresh master checkout.

---

## §8 Out of scope (explicitly deferred)

- Replacing per-package `Makefile`s with a unified turbo task graph for Python
  (turbo can shell out, but adds little over `make` here).
- Migrating any package away from its current toolchain (`acgs-lite` keeps its
  Makefile; `acgi-ai` keeps Biome).
- Switching `acgi-ai`'s package manager. Stays on pnpm 9.15.4.
- Changing constitutional-hash semantics. Only verifying.
- Adding new packages to `packages/`. This plan unifies what exists.
- Cleaning up `.omc/`, `.codex/`, `.agents/` automation surfaces — separate concern.

---

## §9 Decision log

| Date | Decision | Rationale |
|---|---|---|
| 2026-05-10 | Submodules over subtree | Preserves independent history + PyPI publish lifecycle of `acgs-lite`. |
| 2026-05-10 | Turborepo over Nx | Lighter, native pnpm workspace integration, no DSL to learn. |
| 2026-05-10 | uv workspace over Poetry monorepo | uv is already in use (`uv.lock` in `Acgs-Swarm`); faster resolver; first-class workspace + sources. |
| 2026-05-10 | Python floor 3.11 (workspace) / 3.10 (per-package metadata unchanged) | Matches Acgs-Swarm without forcing acgs-lite published metadata to bump. |
| 2026-05-10 | Defer subtree-style absorption | Reversibility matters more than single-history aesthetics. |
