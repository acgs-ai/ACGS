# docs/internal — Retained Engineering History

This directory holds engineering and process material that is **kept for
maintainers but is not part of the public product documentation set**. It exists
so that internal history is preserved without cluttering the reviewer-facing
docs or leaking go-to-market / strategy material into the public surface.

Public product docs live in `docs/` (root), `README.md`, and package-local docs.
Nothing in `docs/internal/` is a product claim or a support commitment.

## Status

**Moved here in the hardening pass** (each carries an internal header; links
updated; `make lint-docs` green):

- `hub-verification-report.md` (from repo root)
- `productization/` (investor brief + productization pack)
- `architecture-audit.md`
- `HERMES_DOJO_ONBOARDING_EVALUATION.md`
- `superpowers/` (plans + specs)

**Not moved — pinned by tests/scripts/lint (cannot relocate without a code
change):** `docs/saas/`, `docs/readiness-*`, `docs/strategy/`,
`docs/reconstruction/`, `docs/research/`, `docs/codex-goals/`, `docs/audits/`,
`docs/handoffs/`, `docs/refactor/`, `docs/plans/`,
`docs/integration-readiness-task-map.md`, `docs/vibe-kanban-govern-zone.md`,
`docs/governance-stack-index.md`. Each is referenced by a test, script, or the
`lint-docs` governance-stack check. Making them private requires a dedicated PR
that also updates the pinning `.py`/scripts — out of scope for a
documentation-only pass (the brief and the repo security rules forbid touching
test/runtime code here).

## Original relocation manifest (reference)

The audit identified the material below as internal-only. The items above were
moved; the rest are blocked as noted. Run any future move behind `make lint-docs`
(fix dangling links before publishing).

### Candidates (`git mv … docs/internal/`)

- `hub-verification-report.md` — internal QA report that finds the live site
  returning 404; reads as vaporware to a public visitor. **Highest priority.**
- `docs/strategy/` — SWOT, startup canvas, mcp-gateway gap analysis (pre-revenue,
  competitively sensitive).
- `docs/saas/` — internal SaaS product-requirements / entitlement / threat-model
  drafts (target, not shipped).
- `docs/research/` — market roadmap / thesis.
- `docs/reconstruction/` — internal audit + platform blueprint + marketing
  research (contains ACVs, pilot pricing).
- `docs/productization/` — investor brief + productization pack.
- `docs/codex-goals/` — AI-orchestration `/goal` contracts ("built by agents"
  tells; undermines a governance vendor).
- `docs/audits/` — dated internal audit notes with RED/PRESENT risk labels.
- `docs/handoffs/`, `docs/superpowers/`, `docs/refactor/`, `docs/plans/` —
  session handoffs and dated implementation plans (process exhaust).
- `docs/architecture-audit.md` — WIP ownership inventory + agent-lane method.
- `docs/readiness-*` and `docs/integration-readiness-task-map.md` — stale dated
  readiness snapshots (May 2026); regenerate on demand instead of shipping stale.
- `docs/HERMES_DOJO_ONBOARDING_EVALUATION.md` — "Cut by CCA review" agent tells.
- `docs/vibe-kanban-govern-zone.md` — internal runbook with local paths.

### Edit in place (kept public — local-path leaks already scrubbed in this pass)

- `acgi-ai/DESIGN.md`, `acgi-ai/DEPLOY.md`, `acgi-ai/PLAN.md`, `acgi-ai/CLAUDE.md`
- `docs/CLAUDE_CODE_PLAYBOOK.md`, `AGENTS.md`
- `packages/ai-governance-research/validation/README.md`

  (These no longer contain `/home/martin/...` paths — done in the Phase-4 pass.
  Remaining internal-planning content in `acgi-ai/PLAN.md`, e.g. "Considered +
  rejected", is a judgment call: relocate the decision-log section or keep as a
  package planning doc.)

### Delete

- `acgi-ai/DESIGN-legacy.md` — superseded "legacy" doc with local-path leaks.
  **Caveat:** referenced by `acgi-ai/infra/cloudflare/_redirects` — update or
  remove that redirect target in the same change.

### Blog / launch drafts — decide

`docs/blog/*` platform threads (LinkedIn/Reddit/HN/X/Dev.to) are honestly labeled
"DRAFT — do not post until a human reviews," but shipping raw outreach drafts in
a public repo reads unfinished. Move to `docs/internal/` or keep only the
finished posts.

## Cross-reference

- Identity & public/private split: `docs/REPOSITORY_POLICY.md`
- Claim wording: `docs/CLAIM_AUDIT.md`
- Consolidated execution checklist + launch call: `docs/FINAL_REVIEW_SIMULATION.md`
