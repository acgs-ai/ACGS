# govern-zone — Claude Code Guide

Multi-package monorepo: regulated-AI governance platform. Python (uv workspace) + TypeScript (pnpm + Turborepo). This file is the parent that every package's `CLAUDE.md` references via `../../CLAUDE.md`.

## Layout

| Path | Purpose | Toolchain |
|---|---|---|
| `acgi-ai/` | Frontend — marketing + console; deploys to GCP Cloud Run via WIF | React 19, Vite, Tailwind 4, Biome, pnpm |
| `packages/acgs-lite/` | Published library on PyPI (v2.10.0) — *nested git repo* | Python 3.10+, FastAPI, Pydantic, ruff, mypy |
| `packages/Acgs-Swarm/` | Constitutional swarm research — *nested git repo* | Python 3.11+, numpy, cryptography, optional torch |
| `packages/clinicalguard/` | Clinical-domain governance agent — *nested git repo* | Python 3.11+, ruff, pytest |
| `packages/agent-bus-analyzer/` | Enhanced Agent Bus observability layer | Python |
| `acgs_governance_eval_mvp/` | Eval MVP | Python |
| `acgs-cft-governance-pack/` | CFT governance pack | Python 3.11+, pytest |
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

Per-package gates remain authoritative. Run them from inside the package; prefer
package-local `CLAUDE.md` / `AGENTS.md` / `README.md` where present.

Local runtime and agent state such as `.acgs-swarm/`, `.omc/`, `.omx/`,
`.remember/`, `.coverage`, `htmlcov/`, `__pycache__/`, virtualenvs, and build
outputs is not source architecture. Keep it ignored and do not stage it from the
parent repo.

## Hard constraints

1. **Constitutional hashes are sealed.** Files with `# Constitutional Hash:` markers must not change without recomputing the hash. CI verifies on every PR (Phase 5 of `docs/PLAN-MONOREPO.md`).
2. **Nested git repos are real.** `packages/acgs-lite`, `packages/Acgs-Swarm`, and `packages/clinicalguard` are independent repos registered in `.gitmodules`. Run `git add` / `git commit` from inside the package, not the parent. Treat parent pointer drift as out-of-scope unless that *is* the task.
3. **`acgs-lite` is published to PyPI.** Do not break its public API or its `requires-python = ">=3.10"` floor in published metadata. The workspace local floor is 3.11; the package's published floor is 3.10. They are intentionally different.
4. **Console origin is privileged.** Never extend public-only patterns (CDN fonts, third-party scripts, anonymous endpoints) into `acgi-ai/src/routes/console/**`. See `acgi-ai/CLAUDE.md` and `acgi-ai/DEPLOY.md` §4–§7 for the full CSP rules.
5. **Two PLAN files exist.** `PLAN.md` is scoped to `acgi-ai/` only. `docs/PLAN-MONOREPO.md` covers monorepo unification. Do not conflate them.

## Where to look first

| Need | File |
|---|---|
| Per-package conventions | Package-local `CLAUDE.md` / `AGENTS.md` / `README.md` |
| Workspace registry — what exists + what is gated where | `MONOREPO.md` |
| Frontend completion plan | `PLAN.md` |
| Monorepo unification plan | `docs/PLAN-MONOREPO.md` |
| ADRs | `docs/adr/` |
| CI workflows | `.github/workflows/` |
| Frontend deploy contract | `acgi-ai/DEPLOY.md` |
| Frontend design contract | `acgi-ai/DESIGN.md` |
| Automation policies | `automation/policies/` |
| Documented solutions (bugs, patterns, workflow learnings) | `docs/solutions/` — by category, YAML frontmatter (`module`, `tags`, `problem_type`) |
| Shared domain vocabulary | `CONCEPTS.md` |

## Verification

Run the local package gate before claiming work complete. For multi-package changes, run `make verify` at root. A passing unit test does not prove handler wiring — see `~/.claude/rules/review-handler-wiring.md`.

## Modular rules

`AGENTS.md` is the full operating manual. For fine-grained, single-topic guidance, these
`.claude/rules/` files are the canonical extractions (AGENTS.md remains authoritative):

| Rule file | Covers |
|---|---|
| `.claude/rules/repo-boundaries.md` | Repository map, nested-repo/submodule discipline, scope gate, git discipline |
| `.claude/rules/claim-safety.md` | Safe vs unsafe claim wording, reporting uncertainty, verify-before-editing-docs |
| `.claude/rules/security-sensitive-files.md` | Dangerous edit zones, forbidden changes, required behavior for receipt/policy/audit/signing/executor changes |
| `.claude/rules/verification-gates.md` | All test/demo/proof commands, path-selected gates |

See also `.claude/rules/permission-posture.md` (permission modes),
`.claude/rules/headless-delegation.md` (Claude-headless lane), and
`.claude/rules/worktree-lanes.md` (parallel `claude -w` worktree lanes).
