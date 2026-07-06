# ARCHIVED — acgs-enterprise-ai-manager

**Status:** Archived 2026-07-05. Not maintained, not built, not deployed.

**Moved from:** `acgs-enterprise-ai-manager/` (repo root) to
`docs/archive/acgs-enterprise-ai-manager/`.

## Why

Per the platform-reconstruction audit
(`docs/reconstruction/01-internal-audit.md` §2, verdict: **Archive**;
`docs/reconstruction/04-platform-blueprint.md` §(d);
roadmap item `00#5:archive-orphan-vue-app`):

- Vue 3 skeleton frontend with **no backend, no tests, and no CI gate**.
- It was a live pnpm workspace member despite being un-gated, so installs and
  Turbo package discovery kept picking it up without any quality gate.
- The real console/product surface is `acgi-ai/`; a parallel admin UI must not
  compete with it as a source of truth.

## What changed

- Tree moved here verbatim (`git mv`) — no source edits.
- Removed `acgs-enterprise-ai-manager/frontend` from `pnpm-workspace.yaml`, so
  pnpm installs and Turbo no longer discover it.
- Registry rows updated: `MONOREPO.md`, `docs/governance-stack-index.md`.
- Guard tests updated to pin the archived state
  (`tests/test_monorepo_invariants.py`,
  `tests/test_readiness_evidence_boundaries.py`).

## Un-archiving

If an enterprise admin surface is ever needed, prefer building it inside
`acgi-ai/` against the shared evidence API rather than reviving this skeleton.
