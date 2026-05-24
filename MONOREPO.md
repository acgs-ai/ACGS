# govern-zone monorepo registry

Single source of truth for "what's in this monorepo and how it's gated."
Companion to `docs/PLAN-MONOREPO.md` (historical unification plan) and the hardening
report at `artifacts/hardening_reports/` (the most recent verification run).

For per-package conventions see each package's own `CLAUDE.md` / `AGENTS.md`.

## Workspace members

Parent-tracked packages (declared in `pyproject.toml` `[tool.uv.workspace]` or
`pnpm-workspace.yaml`):

| Package | Tracking | Toolchain | Parent CI | Maintainer / notes |
|---|---|---|---|---|
| `acgi-ai/` | parent files | Node 24, pnpm 9.15.4, Vite 5, Tailwind 4, Biome | `.github/workflows/console.yml`, `marketing.yml` | Frontend — deploys to GCP Cloud Run via WIF; CSP rules in `acgi-ai/DEPLOY.md` §4–§7; generated bus API types cover only `/api/bus/*` |
| `acgs-enterprise-ai-manager/frontend/` | parent files | Vue 3, Vite 5, npm package metadata | TBD | Enterprise manager frontend — included in pnpm workspace so dependency installs and Turbo package discovery see it |
| `acgs_governance_eval_mvp/` | parent files | Python ≥3.11, pytest | `.github/workflows/python-eval-mvp.yml` | Eval MVP — path-filtered on `acgs_governance_eval_mvp/**` |
| `acgs-cft-governance-pack/` | parent files | Python ≥3.11, pytest | `.github/workflows/python-cft-pack.yml` | CFT governance pack — path-filtered |
| `hermes_acgs_bundle/` | parent files | Python ≥3.11, pytest | `.github/workflows/python-hermes-bundle.yml` | Hermes bundle integration — path-filtered |
| `packages/gove-zone/` | parent files | Python ≥3.11, pytest, ruff | `.github/workflows/python-gove-zone.yml` | Minimal governed runtime kernel; root Makefile fan-out member |
| `packages/agent-bus-analyzer/` | parent files | Python ≥3.11, FastAPI, pytest, ruff, mypy | `.github/workflows/python-agent-bus-analyzer.yml` | Observer-only bus analysis API; exports `acgi-ai/src/api/openapi.json` for generated `/api/bus/*` types |
| `automation/` | parent files | YAML + Python helpers | (covered by `python-other` umbrella when added) | Policies, proposals, workflows |

## Nested packages

Registered as submodules — parent pins each at a specific SHA in
`.gitmodules`. The packages remain independent repos; commits inside any
submodule must be made from inside the package, then the parent bumps the
pinned SHA in a follow-up parent commit.

| Package | Submodule pin (branch) | PyPI? | uv.sources dev resolver | Planned parent CI |
|---|---|---|---|---|
| `packages/acgs-lite/` | `main` | yes — v2.10.0 (`requires-python = ">=3.10"`) | n/a (it IS acgs-lite) | `python-acgs-lite.yml` |
| `packages/Acgs-Swarm/` | `langgraph-runtime/unit-10-coordinator` (in-flight feature) | no — depends on `acgs-lite>=2.8.1` | active — `[tool.uv.sources] acgs-lite = { workspace = true }` | `python-acgs-swarm.yml` |
| `packages/clinicalguard/` | `main` | no | inactive until submodule init is reliable | `python-clinicalguard.yml` (path-filtered, skips when private checkout is unavailable) |
| `packages/legalguard/` | **plain dir** (no own git) | no | n/a | TBD — joins workspace, no submodule needed |
| `packages/ca-legal-agent-skills/` | **plain dir** (no own git) | no | n/a | TBD — joins workspace, no submodule needed |

`legalguard/` and `ca-legal-agent-skills/` were unknown in the original plan
(`docs/PLAN-MONOREPO.md` §6 listed them as "Medium" risk pending inspection);
confirmed here as plain directories — no submodule conversion required for
either.

`packages/clinicalguard/` remains in `.gitmodules`, but is deliberately absent
from root `Makefile` and uv workspace fan-out while local and CI initialization
can fail without `SUBMODULE_TOKEN`.

`hermes_acgs_bundle/` and `acgs_governance_eval_mvp/` stay as top-level
carve-outs because their import-bearing directory names are part of existing
tests, docs, and workflow filters.

The duplicate root `acgs-lite/` checkout and the standalone
`local-chatgpt-bridge/` package were extracted from this repo to the scratch
archive recorded in `~/scratch/govern-zone-experiments/`; `packages/acgs-lite/`
remains authoritative.

## Cross-cutting CI

| Workflow | File | Trigger | What it gates |
|---|---|---|---|
| Constitutional-hash drift | `.github/workflows/constitutional-hash.yml` | PR + push to `master` | Recomputes every `# Constitutional Hash:` marker against `docs/constitutional-hashes.lock`. Lock holds 201 markers post-Phase 2 — drilled from the now-visible submodules; 2 fixture-bearing files (`scripts/hardening_report.py`, `tests/test_verify_constitutional_hashes.py`) are in `SKIP_FILES` so synthetic markers don't pollute the inventory. |
| Cloud Run console | `.github/workflows/console.yml` | path-filtered on `acgi-ai/**` | Lint + build + deploy of privileged console origin |
| Vercel marketing | `.github/workflows/marketing.yml` | path-filtered on `acgi-ai/**` | Lint + build of public marketing origin |
| Analyzer OpenAPI drift | `.github/workflows/python-agent-bus-analyzer.yml` | path-filtered on `packages/agent-bus-analyzer/**` | Regenerates `acgi-ai/src/api/openapi.json` and fails on diff |

## Required Actions secrets

| Secret | Used by | What it does |
|---|---|---|
| `SUBMODULE_TOKEN` | `constitutional-hash.yml`, `python-acgs-lite.yml`, `python-acgs-swarm.yml`, `python-clinicalguard.yml` | Fine-grained PAT (or GitHub App token) with `contents:read` on every submodule repo (notably the private `dislovelhl/clinicalguard`). Default `github.token` is repo-scoped — submodule `recursive` clones 404 without this. Workflows fall back to `github.token` when the secret is absent, so public-only checkouts still work; the four submodule-aware jobs simply fail at the clone step until it's added. |

## Verification snapshot

Latest hardening report: `artifacts/hardening_reports/` (regenerated per run,
gitignored — audit evidence, not checked-in state). Current bar: **10/10
pass, 0 fail, 0 pending** post-Phase-2.

Regenerate with:

```bash
python3 scripts/hardening_report.py
```

## Plan files

| File | Scope |
|---|---|
| `acgi-ai/PLAN.md` | Frontend completion plan for `acgi-ai/` only — does **not** cover monorepo unification |
| `docs/PLAN-MONOREPO.md` | Historical multi-phase plan for unifying the workspace; use this for context, not current registry truth |
| `MONOREPO.md` (this file) | Read-only registry — the truthful map of what exists and what is gated where |

## How to update this file

When you add a new package, change a workflow, or land a phase from
`docs/PLAN-MONOREPO.md`, update the relevant row in the same commit. Do not
let this file drift from the actual `.github/workflows/` and
`pyproject.toml` / `pnpm-workspace.yaml` declarations.
