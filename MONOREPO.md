# ACGS monorepo registry

Single source of truth for "what's in this monorepo and how it's gated."

ACGS is the project and the monorepo. `packages/gove-zone` contains the runtime
enforcement kernel; the other packages are separate components with their own
maturity levels and gates, and are not covered by the kernel's guarantees.
Companion to `docs/PLAN-MONOREPO.md` (the execution plan) and the hardening
report at `artifacts/hardening_reports/` (the most recent verification run).

For per-package conventions, use each package's local `CLAUDE.md`, `AGENTS.md`,
or `README.md` where present.

## Workspace members

Parent-tracked packages (declared in `pyproject.toml` `[tool.uv.workspace]` or
`pnpm-workspace.yaml`):

| Package | Tracking | Toolchain | Parent CI | Maintainer / notes |
|---|---|---|---|---|
| `acgi-ai/` | parent files | Node 20, pnpm 9.15.4, Vite 5, Tailwind 4, Biome | `.github/workflows/console.yml`, `marketing.yml` | Frontend — deploys to GCP Cloud Run via WIF; CSP rules in `acgi-ai/DEPLOY.md` §4–§7 |
| `docs/archive/acgs-enterprise-ai-manager/frontend/` | parent files | Vue 3, Vite 5 (archived) | none (archived) | Enterprise manager frontend — archived 2026-07-05, removed from pnpm workspace; rationale in `docs/archive/acgs-enterprise-ai-manager/ARCHIVED.md` |
| `acgs_governance_eval_mvp/` | parent files | Python ≥3.11, pytest | `.github/workflows/python-eval-mvp.yml` | Eval MVP — path-filtered on `acgs_governance_eval_mvp/**`; also hosts the Hermes/Phoenix host adapter (`governance/adapters/hermes/`, folded in from the retired `hermes_acgs_bundle/`) |
| `acgs-cft-governance-pack/` | parent files | Python ≥3.11, pytest | `.github/workflows/python-cft-pack.yml` | CFT governance pack — path-filtered |
| `packages/agent-bus-analyzer/` | parent files | Python ≥3.11, pytest, ruff | `.github/workflows/python-agent-bus-analyzer.yml` (path-filtered); also in root Makefile fan-out | Enhanced Agent Bus observability layer |
| `packages/research-engine/` | parent files | Python ≥3.11, pytest, ruff, mypy `--strict` | `.github/workflows/python-research-engine.yml` (path-filtered); also in root Makefile fan-out (`lint-py`/`test-py`/`typecheck-py`) | `delve` — self-deepening research engine (fan-out research, citation-backed knowledge graph, adversarial verification); core has zero runtime deps, real backends are optional extras |
| `packages/gove-zone/` | parent files | Python ≥3.11, pytest, ruff | `.github/workflows/python-gove-zone.yml` (path-filtered); also in root Makefile fan-out | Governed runtime kernel — main receipt-gated execution membrane |
| `automation/` | parent files | YAML + Python helpers | (covered by `python-other` umbrella when added) | Policies, proposals, workflows |

`packages/ai-governance-research/` is parent-tracked but **not** a uv/pnpm
workspace member — it is a Markdown + Makefile governance-research collection
(playbooks, solution catalog, templates, validation), not a code package. Its
`make validate` gate is wired into the root `lint-docs` target (so it runs in
`make lint` / `make verify`); it is not part of the Python lint/test/typecheck
fan-out.

## Experimental surfaces

Parent-tracked experiments are not production deployment surfaces. Keep their CI
path-filtered and static unless an experiment-specific plan explicitly promotes
one into a package or service.

| Experiment | Tracking | Toolchain | Parent CI | Maintainer / notes |
|---|---|---|---|---|
| `experiments/iii-governance-lab/` | parent files | Python 3.11, Node/TypeScript, locked npm deps, iii-sdk examples | `.github/workflows/iii-governance-lab-static.yml` | Stage 1 local iii governance lab; static contract only, no live iii engine or deploy gate |

## Nested packages

Registered as submodules — parent pins each at a specific SHA in
`.gitmodules`. The packages remain independent repos; commits inside any
submodule must be made from inside the package, then the parent bumps the
pinned SHA in a follow-up parent commit.

| Package | Submodule pin (branch) | PyPI? | uv.sources dev resolver | Parent CI |
|---|---|---|---|---|
| `packages/acgs-lite/` | `main` | yes — v2.10.1 (`requires-python = ">=3.10"`) | n/a (it IS acgs-lite) | `python-acgs-lite.yml` |
| `packages/Acgs-Swarm/` | `main` | no — depends on `acgs-lite>=2.8.1` | active — `[tool.uv.sources] acgs-lite = { workspace = true }` | `python-acgs-swarm.yml` |
| `packages/clinicalguard/` | `main` | no | active — `[tool.uv.sources] acgs-lite = { workspace = true }` | `python-clinicalguard.yml` |
| `packages/acgs-control-plane/` | `main` — **private** `acgs-ai/acgs-control-plane` (proprietary; history through `9c6168f` remains Apache-2.0) | no | still a `[tool.uv.workspace]` member — requires an initialized submodule for root `uv` commands | `python-acgs-control-plane.yml`; also built by `saas-beta-required.yml` (required gate) and `saas-beta-p0-evidence.yml` — all three hard-fail without `SUBMODULE_TOKEN` access to the private repo |
| `packages/ACGS-agency-agents/` | pinned SHA (no `branch` in `.gitmodules`) | no | n/a — not a uv workspace member; often an empty checkout locally | none |

## Third-party `external/` references

Upstream research/agent projects referenced for provenance. These are **not
first-party ACGS code**: they carry their own upstream licenses and are **not**
built, linted, imported, or gated by any CI workflow — nothing in the tree
imports them.

They are **no longer git submodules.** Embedding them as submodules made
`git clone --recursive` pull megabytes of unrelated upstream code (and fail when
an upstream remote was unavailable), so they were removed from `.gitmodules` and
are recorded as a pinned reference list in [`external/README.md`](external/README.md)
(project, purpose, upstream URL, pinned commit, license). A plain `git clone`
now succeeds for any reviewer. See [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md).

Before reusing any of this code in first-party packages, confirm the upstream
license permits redistribution.

## Cross-cutting CI

| Workflow | File | Trigger | What it gates |
|---|---|---|---|
| Constitutional-hash drift | `.github/workflows/constitutional-hash.yml` | PR + push to `master` | Recomputes every `# Constitutional Hash:` marker against `docs/constitutional-hashes.lock`. Lock holds 201 markers post-Phase 2 — drilled from the now-visible submodules; 2 fixture-bearing files (`scripts/hardening_report.py`, `tests/test_verify_constitutional_hashes.py`) are in `SKIP_FILES` so synthetic markers don't pollute the inventory. |
| Cloud Run console | `.github/workflows/console.yml` | path-filtered on `acgi-ai/**` | Lint + build + deploy of privileged console origin |
| Marketing verify | `.github/workflows/marketing.yml` | path-filtered on `acgi-ai/**` | Lint + build + readiness of public marketing origin (verify-only; deploy is in `marketing-cloudflare.yml`) |
| iii governance lab static | `.github/workflows/iii-governance-lab-static.yml` | path-filtered on `experiments/iii-governance-lab/**`, its invariant test, and static workflow changes | Static contract checks only: Python compile, shell syntax, TypeScript typecheck, and pytest invariants; no live iii engine |

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
| `docs/PLAN-MONOREPO.md` | Multi-phase plan for unifying the workspace; 6 phases, 5 of 6 landed for parent-tracked surfaces |
| `MONOREPO.md` (this file) | Read-only registry — the truthful map of what exists and what is gated where |

## How to update this file

When you add a new package, change a workflow, or land a phase from
`docs/PLAN-MONOREPO.md`, update the relevant row in the same commit. Do not
let this file drift from the actual `.github/workflows/` and
`pyproject.toml` / `pnpm-workspace.yaml` declarations.
