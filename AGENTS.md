# govern-zone — AGENTS.md (Codex / OMX)

Canonical agent guide for Codex CLI, OpenAI agents, and any non-Claude AGI tooling. Mirror of `CLAUDE.md` with Codex-specific operational notes. Both files stay in sync — if you update one, update both.

## Layout

| Path | Purpose |
|---|---|
| `acgi-ai/` | Frontend (React 19, Vite, Tailwind 4) — deploys to Cloud Run via WIF |
| `packages/acgs-lite/` | PyPI library v2.10.0 — FastAPI/Pydantic governance |
| `packages/Acgs-Swarm/` | Constitutional swarm research — Python ≥3.11 |
| `packages/clinicalguard/` | Clinical-domain governance agent |
| `packages/legalguard/`, `packages/ca-legal-agent-skills/` | Legal-domain agent + skill bundles |
| `packages/acgs-cft-governance-pack/` | CFT governance pack |
| `acgs_governance_eval_mvp/`, `acgs-cft-governance-pack/`, `hermes_acgs_bundle/` | Python eval / governance tooling |
| `automation/` | Policies, proposals, workflows, scripts, tests |
| `docs/` | ADRs, design notes, `PLAN-MONOREPO.md` |
| `.github/workflows/` | `console.yml`, `marketing.yml`, per-package CI fan-out |

## Build commands

```bash
make install      # pnpm install + uv sync (one-shot)
make verify       # lint + typecheck + test across Python + JS
make build        # Produce all artifacts
make all          # verify + build
```

Per-package gates remain authoritative:

```bash
# Frontend
pnpm -F acgi-ai lint && pnpm -F acgi-ai build && pnpm -F acgi-ai test

# acgs-lite (uses its own Makefile)
cd packages/acgs-lite && make lint typecheck test

# Acgs-Swarm
cd packages/Acgs-Swarm && python -m pytest tests/ --import-mode=importlib
```

## Codex CLI workflow

```bash
# Investigate without writing
codex exec --readonly "explain how acgs-lite policy enforcement works"

# Resume a session in this repo
codex resume

# Single-file refactor (Codex picks up AGENTS.md automatically)
codex exec "rename PolicyEnforcer to PolicyGate in packages/acgs-lite/src/"
```

Codex sandbox respects `.gitignore`. The nested git repos in `packages/` are visible to Codex but writes to them must be staged from inside the nested repo.

## Hard constraints

1. **Constitutional hashes are sealed.** Files with `# Constitutional Hash:` markers must not change without recomputing the hash.
2. **Submodule boundaries.** `packages/acgs-lite`, `packages/Acgs-Swarm`, `packages/clinicalguard` are independent repos. Stage and commit from inside.
3. **Stage explicitly.** Never `git add -A` or `git add .`.
4. **`acgs-lite` is on PyPI.** Do not break public API or `requires-python = ">=3.10"` floor.
5. **Console origin is privileged.** No public-only patterns (CDN fonts, third-party scripts) in `acgi-ai/src/routes/console/**`.
6. **Two PLAN files.** `PLAN.md` is for `acgi-ai/` only. `docs/PLAN-MONOREPO.md` covers monorepo unification.

## Verification

- Always run the local gate before claiming complete.
- Paste literal output before pass/fail claims.
- For multi-package changes, run `make verify` at the root.
- Unit tests do not prove handler wiring. Confirm registration paths.

## Where to look first

| Need | File |
|---|---|
| Per-package conventions | `<package>/AGENTS.md` or `<package>/CLAUDE.md` |
| Workspace registry — what exists + what is gated where | `MONOREPO.md` |
| Frontend plan | `PLAN.md` |
| Monorepo plan | `docs/PLAN-MONOREPO.md` |
| ADRs | `docs/adr/` |
| Deploy contract | `acgi-ai/DEPLOY.md` |
| Design contract | `acgi-ai/DESIGN.md` |
