---
name: phase-gate
description: ACGS preflight for scope, sealed files, authoritative gates, and literal validation evidence.
---

# phase-gate

Use before and after non-trivial edits in `ACGS/govern-zone`.

1. Load the nearest `AGENTS.md` / `AGENTS.md` for the directory you will touch.
2. Inspect git scope first: parent repo vs nested repo vs submodule; stage only inside that boundary.
3. Detect sealed material before editing:
   - `# Constitutional Hash:` markers
   - generated / do-not-edit banners
   - submodule pointer drift
4. Identify the authoritative package gate for the touched path instead of inventing one:
   - `acgs_governance_eval_mvp/**` → `cd acgs_governance_eval_mvp && uv run --package acgs_governance_eval_mvp python -m pytest tests/ -q`
   - root `tests/**` or `scripts/**` → `uv run --package acgs_governance_eval_mvp python -m pytest tests/ -q`
   - `acgi-ai/**` → `pnpm -F acgi-ai lint && pnpm -F acgi-ai build`
   - `packages/gove-zone/**` → `cd packages/gove-zone && uv run python -m pytest --import-mode=importlib`
5. After edits, run the matching validation, not a broader substitute.
6. Capture literal evidence: exact command, exact output, exit status, and anything intentionally not run.
7. Do not claim complete if handler wiring, audit-chain integrity, or constitutional hash verification remains unproven.
