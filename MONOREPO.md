# govern-zone monorepo registry

Single source of truth for "what's in this monorepo and how it's gated."
Companion to `docs/PLAN-MONOREPO.md` (the execution plan) and the hardening
report at `artifacts/hardening_reports/` (the most recent verification run).

For per-package conventions see each package's own `CLAUDE.md` / `AGENTS.md`.

## Workspace members

Parent-tracked packages (declared in `pyproject.toml` `[tool.uv.workspace]` or
`pnpm-workspace.yaml`):

| Package | Tracking | Toolchain | Parent CI | Maintainer / notes |
|---|---|---|---|---|
| `acgi-ai/` | parent files | Node 20, pnpm 9.15.4, Vite 5, Tailwind 4, Biome | `.github/workflows/console.yml`, `marketing.yml` | Frontend — deploys to GCP Cloud Run via WIF; CSP rules in `acgi-ai/DEPLOY.md` §4–§7 |
| `acgs_governance_eval_mvp/` | parent files | Python ≥3.11, pytest | `.github/workflows/python-eval-mvp.yml` | Eval MVP — path-filtered on `acgs_governance_eval_mvp/**` |
| `acgs-cft-governance-pack/` | parent files | Python ≥3.11, pytest | `.github/workflows/python-cft-pack.yml` | CFT governance pack — path-filtered |
| `hermes_acgs_bundle/` | parent files | Python ≥3.11, pytest | `.github/workflows/python-hermes-bundle.yml` | Hermes bundle integration — path-filtered |
| `automation/` | parent files | YAML + Python helpers | (covered by `python-other` umbrella when added) | Policies, proposals, workflows |

## Nested packages (pending Phase 2 submodule registration)

Each has its own `.git/` and is **not** currently tracked by the parent. Parent
CI for these is gated on Phase 2 of `docs/PLAN-MONOREPO.md` landing — the
workflows reference `submodules: recursive`, which is a no-op until
`.gitmodules` exists.

| Package | Own git? | Upstream | PyPI? | Planned parent CI | Phase 2 status |
|---|---|---|---|---|---|
| `packages/acgs-lite/` | yes (`main`) | independent | yes — v2.10.0 (`requires-python = ">=3.10"`) | `python-acgs-lite.yml` (deferred) | pending |
| `packages/Acgs-Swarm/` | yes (feature branch) | independent | no — depends on `acgs-lite>=2.8.1` | `python-acgs-swarm.yml` (deferred) | pending |
| `packages/clinicalguard/` | yes (`main`) | independent | no | `python-clinicalguard.yml` (deferred) | pending |
| `packages/legalguard/` | **no** — plain dir | n/a | no | TBD — joins workspace, no submodule needed | n/a |
| `packages/ca-legal-agent-skills/` | **no** — plain dir | n/a | no | TBD — joins workspace, no submodule needed | n/a |

`legalguard/` and `ca-legal-agent-skills/` were unknown in the original plan
(`docs/PLAN-MONOREPO.md` §6 listed them as "Medium" risk pending inspection);
confirmed here as plain directories — no submodule conversion required for
either.

## Cross-cutting CI

| Workflow | File | Trigger | What it gates |
|---|---|---|---|
| Constitutional-hash drift | `.github/workflows/constitutional-hash.yml` | PR + push to `master` | Recomputes every `# Constitutional Hash:` marker against `docs/constitutional-hashes.lock`. Lock is empty until Phase 2 makes nested-repo markers visible to the parent checkout. |
| Cloud Run console | `.github/workflows/console.yml` | path-filtered on `acgi-ai/**` | Lint + build + deploy of privileged console origin |
| Vercel marketing | `.github/workflows/marketing.yml` | path-filtered on `acgi-ai/**` | Lint + build of public marketing origin |

## Verification snapshot

Latest hardening report: `artifacts/hardening_reports/` (regenerated per run,
gitignored — audit evidence, not checked-in state). Current bar: **9/10 pass, 0
fail, 1 pending**. The pending item is Phase 2.

Regenerate with:

```bash
python3 scripts/hardening_report.py
```

## Plan files

| File | Scope |
|---|---|
| `PLAN.md` | Frontend completion plan for `acgi-ai/` only — does **not** cover monorepo unification |
| `docs/PLAN-MONOREPO.md` | Multi-phase plan for unifying the workspace; 6 phases, 5 of 6 landed for parent-tracked surfaces |
| `MONOREPO.md` (this file) | Read-only registry — the truthful map of what exists and what is gated where |

## How to update this file

When you add a new package, change a workflow, or land a phase from
`docs/PLAN-MONOREPO.md`, update the relevant row in the same commit. Do not
let this file drift from the actual `.github/workflows/` and
`pyproject.toml` / `pnpm-workspace.yaml` declarations.
