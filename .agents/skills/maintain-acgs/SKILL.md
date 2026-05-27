---
name: maintain-acgs
description: Manual ACGS workspace maintenance checklist for boundaries, gates, sealed files, and Codex automation self-checks.
disable-model-invocation: true
---

# maintain-acgs

Manual maintenance only. Do not treat this as implementation guidance.

Checklist:
1. Load the nearest `AGENTS.md` / `AGENTS.md` for every directory you inspect or modify.
2. Verify sealed material before and after edits:
   - find `# Constitutional Hash:` markers
   - confirm generated or do-not-edit banners were not hand-edited
   - run the workspace hash verifier when sealed files were touched
3. Check repository boundaries:
   - root repo status
   - nested repo / submodule status for `packages/acgs-lite`, `packages/Acgs-Swarm`, and `packages/clinicalguard`
   - parent pointer drift separately from file diffs
4. Run the authoritative gates for the touched scope instead of substitutes:
   - root Python lint: `uv run ruff check`
   - root pytest fallback: `uv run --package acgs_governance_eval_mvp python -m pytest tests/ -q`
   - eval package pytest: `cd acgs_governance_eval_mvp && uv run --package acgs_governance_eval_mvp python -m pytest tests/ -q`
   - package-local gates from package manifests or local instructions when work stays inside one package
5. For `.Codex` maintenance, run automation self-checks:
   - `python3 -c 'import json, pathlib; json.load(open(pathlib.Path(".Codex/settings.json")))'`
   - `bash -n .Codex/hooks/*.sh`
   - smoke the hook payload path extraction with small JSON stdin fixtures
6. Capture literal commands, literal output, and anything intentionally not run.
