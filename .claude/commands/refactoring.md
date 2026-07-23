---
name: refactoring
description: Refactor/cleanup workflow for govern-zone with scope gate and path-selected verification.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /refactoring

Refactor / clean up code in `govern-zone`. Target package/area: **$ARGUMENTS**.

## 1. Scope gate (run first, trust its output over guesses)

```bash
python3 /home/martin/.claude/scripts/scope-detect.py --json .
```

Load the nearest `AGENTS.md` / `CLAUDE.md` / package manifest for the touched directory.
Split work by subproject boundary; never cross a nested-repo boundary in one pass.

## 2. Baseline before touching code

Run the touched-path gate (below) once to capture a green baseline. A refactor that
starts red cannot prove it preserved behavior.

## 3. Refactor

1. Make behavior-preserving changes only unless $ARGUMENTS explicitly asks otherwise.
2. Keep the diff small and coherent; do not bundle unrelated cleanup.
3. Do not change public API surfaces, model names, schema/stability flags, or
   constitutional-hash-bound content as a side effect.

## 4. Verify — select the gate by touched path (re-run after the change)

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

Pass count must match the baseline. Paste literal output before any pass/fail claim.
If failures exceed baseline, revert before attempting fixes.

## 5. Stage — explicit paths only

```bash
git status --short
git add <exact/paths/you/changed>          # never git add -A / git add .
```

For a nested repo (`packages/acgs-lite`, `packages/Acgs-Swarm`, `packages/clinicalguard`),
`cd` into the nested repo and `git add` there. Do not stage parent gitlink drift.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update this command if the workflow evolves materially.
