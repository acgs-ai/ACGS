# govern-zone — AGENTS.md (Codex / OMX)

Canonical agent guide for Codex CLI, OpenAI agents, and any non-Claude AGI tooling. This guide cross-references `CLAUDE.md`; the files are intentionally separate because Codex/OMX and Claude surfaces have different local instructions.

## Layout

| Path | Purpose |
|---|---|
| `acgi-ai/` | Frontend (React 19, Vite, Tailwind 4) — deploys to Cloud Run via WIF |
| `packages/acgs-lite/` | PyPI library v2.10.0 — FastAPI/Pydantic governance |
| `packages/Acgs-Swarm/` | Constitutional swarm research — Python ≥3.11 |
| `packages/clinicalguard/` | Clinical-domain governance agent — private submodule, path-filtered CI only until initialization is reliable |
| `packages/gove-zone/` | Governed runtime kernel — Python ≥3.11 |
| `packages/agent-bus-analyzer/` | Observer-only bus analysis API — Python ≥3.11, FastAPI |
| `packages/legalguard/`, `packages/ca-legal-agent-skills/` | Legal-domain agent + skill bundles |
| `acgs-cft-governance-pack/` | CFT governance pack |
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

Local runtime and agent state such as `.acgs-swarm/`, `.omc/`, `.omx/`,
`.remember/`, `.coverage`, `htmlcov/`, `__pycache__/`, virtualenvs, and build
outputs is not source architecture. Keep it ignored and do not stage it from the
parent repo.

## Hard constraints

1. **Constitutional hashes are sealed.** Files with `# Constitutional Hash:` markers must not change without recomputing the hash.
2. **Submodule boundaries.** `packages/acgs-lite`, `packages/Acgs-Swarm`, `packages/clinicalguard` are independent repos. Stage and commit from inside.
3. **Stage explicitly.** Never `git add -A` or `git add .`.
4. **`acgs-lite` is on PyPI.** Do not break public API or `requires-python = ">=3.10"` floor.
5. **Console origin is privileged.** No public-only patterns (CDN fonts, third-party scripts) in `acgi-ai/src/routes/console/**`.
6. **Plan scopes.** `acgi-ai/PLAN.md` is for frontend completion only. `docs/PLAN-MONOREPO.md` is historical monorepo-unification context; `MONOREPO.md` is the current registry.
7. **Generated agent guides are not boilerplate by default.** Per-directory `AGENTS.md` files with `<!-- Generated: ... -->` headers may still contain hand-written purpose, key-file, and boundary guidance; delete only stub-only files after content review.

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
| Frontend plan | `acgi-ai/PLAN.md` |
| Monorepo history | `docs/PLAN-MONOREPO.md` |
| ADRs | `docs/adr/` |
| Deploy contract | `acgi-ai/DEPLOY.md` |
| Design contract | `acgi-ai/DESIGN.md` |

<!-- SPECKIT START -->
For additional context about technologies to be used, project structure,
shell commands, and other important information, read the current plan
<!-- SPECKIT END -->
