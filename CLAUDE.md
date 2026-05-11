# govern-zone — Claude Code Guide

Multi-package monorepo: regulated-AI governance platform. Python (uv workspace) + TypeScript (pnpm + Turborepo). This file is the parent that every package's `CLAUDE.md` references via `../../CLAUDE.md`.

## First steps in any session

1. `pwd` — confirm you are at `govern-zone/` root
2. `git status` — note dirty state before editing
3. Check the affected package's local `CLAUDE.md` before editing inside it
4. For multi-package work, read `docs/PLAN-MONOREPO.md`

## Layout

| Path | Purpose | Toolchain |
|---|---|---|
| `acgi-ai/` | Frontend — marketing + console; deploys to GCP Cloud Run via WIF | React 19, Vite, Tailwind 4, Biome, pnpm |
| `packages/acgs-lite/` | Published library on PyPI (v2.10.0) | Python 3.10+, FastAPI, Pydantic, ruff, mypy |
| `packages/Acgs-Swarm/` | Constitutional swarm research | Python 3.11+, numpy, cryptography, optional torch |
| `packages/clinicalguard/` | Clinical-domain governance agent | Python |
| `packages/legalguard/`, `packages/ca-legal-agent-skills/` | Legal-domain agent + skill bundles | Claude plugin format |
| `packages/acgs-cft-governance-pack/` | CFT governance pack | Python |
| `acgs_governance_eval_mvp/` | Eval MVP | Python |
| `hermes_acgs_bundle/` | Hermes bundle integration | Python |
| `automation/` | Policies, proposals, workflows, scripts | YAML + Python |
| `docs/` | ADRs, design notes, plans | Markdown |
| `.github/workflows/` | CI — `console.yml`, `marketing.yml` for `acgi-ai`; per-package fan-out | GitHub Actions |

## Build commands

```bash
make install      # One-shot: pnpm install + uv sync
make verify       # lint + typecheck + test across Python + JS
make build        # Produce all artifacts
make all          # verify + build
make clean        # Drop node_modules + .venv
```

Per-package gates remain authoritative for their own package:

| Package | Local gate |
|---|---|
| `acgi-ai` | `pnpm -F acgi-ai lint && pnpm -F acgi-ai build && pnpm -F acgi-ai test` |
| `acgs-lite` | `cd packages/acgs-lite && make lint typecheck test` |
| `Acgs-Swarm` | `cd packages/Acgs-Swarm && python -m pytest tests/ --import-mode=importlib` |
| `clinicalguard` | `cd packages/clinicalguard && pytest --import-mode=importlib` |

## Hard constraints

1. **Constitutional hashes are sealed.** Files with `# Constitutional Hash:` markers must not change without recomputing the hash. CI verifies on every PR (Phase 5 of `docs/PLAN-MONOREPO.md`).
2. **Submodule boundaries are real.** `packages/acgs-lite`, `packages/Acgs-Swarm`, `packages/clinicalguard` are independent git repos. Run `git add` / `git commit` from inside the package, not the parent. After Phase 2 they will also be registered in `.gitmodules`.
3. **Stage explicitly.** Never `git add -A` or `git add .`. Use file paths.
4. **`acgs-lite` is published to PyPI.** Do not break its public API or its `requires-python = ">=3.10"` floor in published metadata. The workspace local floor is 3.11; the package's published floor is 3.10. They are intentionally different.
5. **Console origin is privileged.** Never extend public-only patterns (CDN fonts, third-party scripts, anonymous endpoints) into `acgi-ai/src/routes/console/**`. See `acgi-ai/CLAUDE.md` and `acgi-ai/DEPLOY.md` §4–§7 for the full CSP rules.
6. **Two PLAN files exist.** `PLAN.md` is scoped to `acgi-ai/` only. `docs/PLAN-MONOREPO.md` covers monorepo unification. Do not conflate them.

## Where to look first

| Need | File |
|---|---|
| Per-package conventions | `<package>/CLAUDE.md` |
| Workspace registry — what exists + what is gated where | `MONOREPO.md` |
| Frontend completion plan | `PLAN.md` |
| Monorepo unification plan | `docs/PLAN-MONOREPO.md` |
| ADRs | `docs/adr/` |
| CI workflows | `.github/workflows/` |
| Frontend deploy contract | `acgi-ai/DEPLOY.md` |
| Frontend design contract | `acgi-ai/DESIGN.md` |
| Automation policies | `automation/policies/` |

## Verification discipline

- Always run the local gate before claiming work complete.
- Paste literal output before any pass/fail claim.
- For multi-package changes, run `make verify` at the root.
- A passing unit test does not prove handler wiring — see `~/.claude/rules/review-handler-wiring.md`.

## Multi-agent / multi-worktree safety

This repo has nested git repos (`packages/*`). Before any commit:

1. Identify which repo your change belongs to (`git -C packages/<name> status` vs root `git status`).
2. Stage only files you authored. Never `git add -A`.
3. After Phase 2 of unification, the parent repo will track submodule pointers — do not commit pointer drift unless that is the explicit task.
4. See `~/.claude/rules/multi-agent-git-safety.md` and `~/.claude/rules/scope-gate.md`.

## OMC and agent invocation

Repo uses oh-my-claudecode (`.omc/`). Use `/team`, `/autopilot`, `/ultrawork` only when explicitly requested. For trivial single-file edits, work directly. State lives under `.omc/state/`.
