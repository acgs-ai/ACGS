# Repo Boundaries (govern-zone)

> Always-On: Extraction of AGENTS.md — repository map, nested-repo discipline, scope gate,
> git discipline. AGENTS.md remains the authoritative source; this is the fine-grained slice.

## Repository map

| Path | Owner/meaning | Notes |
|---|---|---|
| `packages/gove-zone/` | Governed runtime kernel | Main receipt-gated execution code. Python >=3.11. |
| `packages/acgs-lite/` | PyPI-facing governance library | Nested repo/submodule. Do not stage from parent. Public API stability matters. |
| `packages/Acgs-Swarm/` | Constitutional swarm research | Nested repo/submodule. Package-local tests only. |
| `packages/clinicalguard/` | Clinical-domain agent | Nested/private submodule; path-filtered, may be unavailable. |
| `acgi-ai/` | Frontend/console | Privileged origin; no public-only CDN/script patterns in console routes. |
| `acgs_governance_eval_mvp/` | Evaluation/governance MVP | Python package. |
| `acgs-cft-governance-pack/` | Infrastructure governance pack | Python package. |
| `docs/` | Claim-safe documentation | Do not edit sealed/hash-marked files without the regeneration path. |
| `examples/` | Root integration examples | Lightweight, local-only, runnable. |
| `tests/docs/` | Documentation/example smoke checks | Keeps docs from rotting. |

## Mandatory scope gate

Before editing, reviewing, testing, documenting, or planning:

1. Detect the real git root and submodule topology.
2. Read the nearest `AGENTS.md`, `CLAUDE.md`, `.codex/`, `.claude/`, package manifest, and
   local README for the touched directory.
3. Split work by subproject boundary.
4. Do not stage or commit across nested-repo/submodule boundaries.
5. Use the package-local validation command, not one copied from another package.

```bash
python3 /home/martin/.claude/scripts/scope-detect.py --json .
python3 /home/martin/.claude/scripts/validate-subproject.py .
```

Trust the script output over filesystem guesses.

## Nested repo / submodule discipline

`packages/acgs-lite`, `packages/Acgs-Swarm`, and `packages/clinicalguard` are independent
repos registered in `.gitmodules`. Run `git add` / `git commit` **from inside the package**,
never from the parent. Treat parent gitlink pointer drift as out-of-scope unless that *is*
the task. Parent-repo validation is not proof a nested repo is valid; validate both.

## Git discipline — explicit paths only

```bash
git status --short
git diff --stat
git diff --check
git add README.md docs/CLAIMS.md examples/tamper_demo/demo.py   # name the files
```

Never `git add -A` or `git add .` in this workspace. For submodules/nested repos, enter the
nested repo and stage there; do not accidentally stage parent gitlink drift.
