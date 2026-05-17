# govern-zone — Claude Code Guide

Multi-package monorepo: regulated-AI governance platform. Python (uv workspace) + TypeScript (pnpm + Turborepo). This file is the parent that every package's `CLAUDE.md` references via `../../CLAUDE.md`.

## Layout

| Path | Purpose | Toolchain |
|---|---|---|
| `acgi-ai/` | Frontend — marketing + console; deploys to GCP Cloud Run via WIF | React 19, Vite, Tailwind 4, Biome, pnpm |
| `packages/acgs-lite/` | Published library on PyPI (v2.10.0) — *nested git repo* | Python 3.10+, FastAPI, Pydantic, ruff, mypy |
| `packages/Acgs-Swarm/` | Constitutional swarm research — *nested git repo* | Python 3.11+, numpy, cryptography, optional torch |
| `packages/clinicalguard/` | Clinical-domain governance agent — *nested git repo* | Python |
| `packages/ca-legal-agent-skills/` | Legal-domain skill bundle | Claude plugin format |
| `packages/agent-bus-analyzer/` | Enhanced Agent Bus observability layer | Python |
| `acgs_governance_eval_mvp/` | Eval MVP | Python |
| `hermes_acgs_bundle/` | Hermes bundle integration | Python |
| `automation/` | Policies, proposals, workflows, scripts | YAML + Python |
| `docs/` | ADRs, design notes, plans | Markdown |
| `.github/workflows/` | CI — `console.yml`, `marketing.yml` for `acgi-ai`; per-package fan-out | GitHub Actions |

## Build commands

```bash
make install      # pnpm install + uv sync
make verify       # lint + typecheck + test across Python + JS
make build        # Produce all artifacts
```

Per-package gates remain authoritative. Run them from inside the package; see each `<package>/CLAUDE.md`.

## Hard constraints

1. **Constitutional hashes are sealed.** Files with `# Constitutional Hash:` markers must not change without recomputing the hash. CI verifies on every PR (Phase 5 of `docs/PLAN-MONOREPO.md`).
2. **Nested git repos are real.** `packages/acgs-lite`, `packages/Acgs-Swarm`, `packages/clinicalguard` are independent repos. Run `git add` / `git commit` from inside the package, not the parent. After Phase 2 they will also be registered in `.gitmodules` — at which point treat parent pointer drift as out-of-scope unless that *is* the task.
3. **`acgs-lite` is published to PyPI.** Do not break its public API or its `requires-python = ">=3.10"` floor in published metadata. The workspace local floor is 3.11; the package's published floor is 3.10. They are intentionally different.
4. **Console origin is privileged.** Never extend public-only patterns (CDN fonts, third-party scripts, anonymous endpoints) into `acgi-ai/src/routes/console/**`. See `acgi-ai/CLAUDE.md` and `acgi-ai/DEPLOY.md` §4–§7 for the full CSP rules.
5. **Two PLAN files exist.** `PLAN.md` is scoped to `acgi-ai/` only. `docs/PLAN-MONOREPO.md` covers monorepo unification. Do not conflate them.

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

## Verification

Run the local package gate before claiming work complete. For multi-package changes, run `make verify` at root. A passing unit test does not prove handler wiring — see `~/.claude/rules/review-handler-wiring.md`.
