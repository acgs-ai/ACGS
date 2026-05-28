---
name: pr-evidence
description: Collect PR-ready govern-zone evidence without pushing, posting, merging, or mutating review state.
disable-model-invocation: true
---

# pr-evidence

Collect evidence only. Do not push, post, merge, approve, or edit unless explicitly assigned.

Required capture set:

1. `git status --short`
2. `git diff --stat`
3. Root eval gate when parent-tracked Python changed:
   - `uv run --package acgs_governance_eval_mvp python -m pytest tests/ -q`
4. Package-local pytest when relevant:
   - `cd acgs_governance_eval_mvp && uv run --package acgs_governance_eval_mvp python -m pytest tests/ -q`
   - `cd packages/gove-zone && uv run python -m pytest --import-mode=importlib`
5. Frontend gate when relevant:
   - `pnpm -F acgi-ai lint && pnpm -F acgi-ai build`
6. Python lint evidence when relevant:
   - `uv run ruff check`
7. Constitutional hash check:
   - `python3 scripts/verify_constitutional_hashes.py`
8. `git submodule status`
9. Phase 2 caveats:
   - note unverified cross-package integrations
   - note any sealed/hash files touched
   - note nested-repo pointer drift separately from file diffs

Output rule: paste literal commands and literal outputs, then list anything not run with the reason.
