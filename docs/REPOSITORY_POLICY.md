# Repository Policy (Phase 1 — Canonical Identity)

## Canonical repository statement

`dislovelhl/ACGS` is the **canonical public source-of-record for the ACGS /
gove-zone platform**, organized as a multi-package monorepo. It is
simultaneously:

- **(A) the primary public implementation repo** — Apache-2.0 licensed,
  contribution-ready (`CONTRIBUTING.md` with ground rules + good-first-issues),
  self-referenced as the public repo (`github.com/dislovelhl/ACGS`), and linked
  from the `acgs.ai` website; and
- **(B) a development monorepo** — a `uv` (Python) + `pnpm`/Turborepo (JS)
  workspace coordinating multiple sub-packages and a frontend/console.

It is **not (C) a paper-companion artifact**. There is no paper/LaTeX framing;
the docs are an engineering + product set. A defensive-publication / prior-art
record exists (`docs/` prior-art commits) but the repository's purpose is the
implementation, not a single paper's reproducibility appendix.

### Evidence

- `MONOREPO.md:1-3` — "Single source of truth for 'what's in this monorepo and
  how it's gated.'"
- `README.md:22-24` — "The ACGS monorepo contains several governance components;
  `packages/gove-zone` is the core Python enforcement kernel."
- `pyproject.toml:3-5` — "Virtual workspace — this root is NOT a publishable
  package. It exists to coordinate Python sub-packages via uv workspace."
- `LICENSE` — Apache-2.0, "Copyright (C) 2024-2026 ACGS Contributors".

## Relationship with other ACGS repositories

The platform is deliberately split across repos, wired here as submodules:

| Submodule | Owner | Role | Public? |
|---|---|---|---|
| `packages/acgs-lite` | dislovelhl | Governance library published to **PyPI** (v2.10.1) | Public |
| `packages/Acgs-Swarm` | dislovelhl | Constitutional-swarm research | Public |
| `packages/clinicalguard` | dislovelhl | Clinical-domain agent | **May be private** (path-filtered) |
| `packages/ACGS-agency-agents` | dislovelhl | Agency agents | Public |
| `external/UI-TARS-desktop` | bytedance | Third-party reference checkout | Third-party |
| `external/openswarm` | VRSEN | Third-party reference checkout | Third-party |
| `external/everything-claude-code` | affaan-m | Third-party reference checkout | Third-party |
| `external/natural_language_autoencoders` | kitft | Third-party reference checkout | Third-party |

`packages/gove-zone` (the enforcement kernel) lives **directly in this repo**,
not as a submodule — it is the core artifact.

`MONOREPO.md:59-65` states the `external/*` checkouts are "not first-party ACGS
code … nothing in the tree imports them." They are a reproducibility and
credibility liability at launch — see `docs/REPRODUCIBILITY.md` (recommend
replacing them with a pinned reference list rather than embedded submodules).

## What should be public

- The enforcement kernel `packages/gove-zone/` and its tests/examples.
- Public governance packages (`acgs-lite`, `Acgs-Swarm`, `ACGS-agency-agents`),
  the eval MVP, CFT pack, control-plane, proofpack-verifier, bus-analyzer.
- The frontend/console `acgi-ai/` (unpublished app; `0.0.0` private is fine).
- Reviewer-facing docs: `README.md`, `docs/START_HERE.md`, `docs/PROOF_PATH.md`,
  `docs/CLAIMS.md`, `docs/SECURITY_MODEL.md`, `docs/DECISION_RECEIPT_SPEC.md`,
  `docs/INTEGRATION_MATRIX.md`, `docs/ARCHITECTURE.md`, `COMPARISON.md`,
  `CONTRIBUTING.md`, `LICENSE`.

## What should remain private / internal

Move to `docs/internal/` (retained engineering history, not shipped as product
docs) or a private repo. See the Phase-4 relocation manifest in
`docs/internal/README.md`. Categories:

- Business / go-to-market — **relocated to the private store**: pricing, investor
  material, SWOT, startup canvas, pilot-offer economics, outreach drafts, the
  marketing/ICP/GTM research, and the reconstruction executive summary.
- AI-orchestration process exhaust — **relocated to the private store**: the Codex
  `/goal` contracts (they also carried maintainer filesystem paths). Still public and
  under review: `docs/handoffs/`, `docs/superpowers/`, `docs/refactor/`, `docs/audits/`,
  `docs/internal/architecture-audit.md`.
- Deliberately kept public: `docs/saas/` (target-beta contracts — `OPEN_CORE_BOUNDARY.md`
  is a binding public commitment that no billing or entitlement failure may disable
  local enforcement) and `docs/research/` (technical research + `limitations.md`).
- Internal QA / risk ledgers: `hub-verification-report.md`,
  `docs/readiness-*`, `docs/integration-readiness-task-map.md`.
- Raw launch drafts: `docs/blog/*` platform-thread scratch.

## Ambiguity flagged for the maintainer

`docs/saas/*` describes a **target** SaaS product/architecture, explicitly
"target contract, not an implementation claim." A reviewer could misread it as
current product. Either relocate to `docs/internal/` or add a prominent
"TARGET — NOT SHIPPED" banner at the top of each `docs/saas/*` file.

> This policy records the intended identity; it does not by itself perform the
> relocations. The Phase-4/7 moves are staged as a maintainer-gated checklist in
> `docs/FINAL_REVIEW_SIMULATION.md` because they change what is public.
