# Workspace Plan — govern-zone Phase B/3

> **Canonical location:** `ACGS/govern-zone/docs/workspace-PLAN.md`
> Workspace-root readers: see `/home/martin/Downloads/govern-zone/PLAN.md` for a pointer.
>
> **Last updated:** 2026-05-12
> **Sprint:** Phase B / Stage 3

---

## Overview

Phase B/3 has four active work components. Each is tracked as a separate branch
and PR against `ACGS/govern-zone` master (or its sibling eval repo).

---

## Component 1 — Phase-3 Investigation (`phase-3-investigation`)

**Status:** Stage 0a in progress (branch `feat/fix-swarm-ruff-baseline`)

Empirical surface survey of the ACGS monorepo to establish a clean lint/type
baseline before roadmap authoring. Covers:

- Acgs-Swarm ruff lint violations (fix baseline, not feature work)
- Identification of real vs. phantom code surfaces (AUTHZ confirmed phantom;
  MACI confirmed present)

**Gate:** `make verify` passes with exit 0 on `packages/Acgs-Swarm/` before
Stage 1 PRs can merge cleanly.

---

## Component 2 — Roadmap Specs Duo (`roadmap-specs-duo`)

**Status:** Stage 1a in progress (branch `feat/roadmap-duo`)

Originally planned as a trio (MACI + AUTHZ + workspace-PLAN). Reduced to a duo
after Stage 0 empirical investigation confirmed the AUTHZ surface does not exist
in the current ACGS master. See §Deferred below.

Deliverables:
- `ACGS/govern-zone/MACI-ROADMAP.md` — 4-role inventory, gaps, and change order
  anchored to `packages/acgs-lite/` MACI surface
- `ACGS/govern-zone/docs/workspace-PLAN.md` — this file

---

## Component 3 — Submodule Token Follow-ups (`submodule-token-followups`)

**Status:** Pending (Stage 1b, blocked by Stage 1a PR merge)

Branch: `feat/submodule-token-runbook-v0`

Deliverables:
- Verify 4 CI workflow files use `SUBMODULE_TOKEN` correctly
- Write runbook `docs/runbooks/submodule-token.md` with rotation procedure,
  required secret names, and verification steps
- Record 4 recent CI run IDs as evidence in the PR description

No workflow YAML changes in this stage — verify-and-document only.

---

## Component 4 — Eval Phase B Round 2 (`eval-phase-b-round-2`)

**Status:** In progress (sibling repo, independent branch)

Runs in the eval workspace sibling to `govern-zone`. Targets the
`eval-regression-coverage-hardening` topic identified in Phase B Round 1.
Independent of the ACGS monorepo gate — does not block or get blocked by
Components 1–3.

---

## Deferred

### AUTHZ-ROADMAP.md

**Deferred pending:** `api_gateway` + WorkOS source landing in ACGS master.

**Rationale:** Stage 0 empirical investigation (commit `94f570a` on ACGS
`master`) found zero matches for `WorkOSConfig`, `SAMLConfig`, and an
`api_gateway` directory. The AUTHZ surface referenced in prior planning
documents does not exist in the repository. Evidence is documented in
`.omc/state/team/govern-zone-phase-b3/stage-0-findings.md` (artifact to be
committed by Stage 0a' — file absent from working tree at time of authoring;
see Phase B/3 PR #stage-1a description for the inline empirical note).

When the AUTHZ surface lands, the roadmap should cover:
- WorkOS / SAML authentication integration points
- `api_gateway` directory structure and governance hooks
- Authorization policy enforcement wiring

---

## Sequencing

```
Stage 0a  (w1) — fix Acgs-Swarm lint baseline
    |
Stage 1a  (w2) — MACI-ROADMAP + workspace-PLAN [this PR]
    |
Stage 1b  (w2) — SUBMODULE_TOKEN verify + runbook
Stage 1c  (w4) — Eval Phase B Round 2 (independent, runs in parallel)
```

Stage 1b is blocked on Stage 1a PR open (not merge) to allow parallel progress.
Stage 1c is fully independent.
