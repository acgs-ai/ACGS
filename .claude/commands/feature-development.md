---
name: feature-development
description: Feature implementation workflow for govern-zone with scope gate and path-selected verification.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /feature-development

Implement a feature in `govern-zone`. Target package/feature: **$ARGUMENTS**.

## 1. Scope gate (run first, trust its output over guesses)

```bash
python3 /home/martin/.claude/scripts/scope-detect.py --json .
```

Load the nearest `AGENTS.md` / `CLAUDE.md` / package manifest for the touched directory.
Split work by subproject boundary; never cross a nested-repo boundary in one pass.

## 2. Implement

1. Understand the current state and failure mode before editing $ARGUMENTS.
2. Make the smallest coherent change that satisfies the feature goal.
3. New handlers/routes must be wired into the dispatch path in the same change — a passing
   unit test does not prove wiring (`~/.claude/rules/review-handler-wiring.md`).

## 3. Verify — select the gate by touched path

- Root docs / examples (`tests/docs/**`, `examples/**`, root `docs/*.md`):
  ```bash
  uv run python -m pytest tests/docs --import-mode=importlib -q
  make lint-docs
  ```
- gove-zone runtime (`packages/gove-zone/**`):
  ```bash
  uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
  ```
- Frontend/console (`acgi-ai/**`) — run inside `acgi-ai/`:
  ```bash
  pnpm run lint && pnpm run typecheck && pnpm run test
  ```
- Whole workspace, only when intentionally validating everything:
  ```bash
  make verify
  ```

Paste literal command output before any pass/fail claim. Security-sensitive files
(receipt/executor/kernel/audit/policy/signing) also require a negative-path test.

## 4. Stage — explicit paths only

```bash
git status --short
git add <exact/paths/you/changed>          # never git add -A / git add .
```

For a nested repo (`packages/acgs-lite`, `packages/Acgs-Swarm`, `packages/clinicalguard`),
`cd` into the nested repo and `git add` there. Do not stage parent gitlink drift.

## Notes

- Common feature surfaces: `acgi-ai/src/api/*`, `acgi-ai/src/mocks/data/*`, `**/api/**`, `**/*.test.*`.
- Update this command if the workflow evolves materially.
