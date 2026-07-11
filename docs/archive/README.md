# docs/archive — superseded roadmaps and plans

**The roadmap of record is [`docs/ROADMAP.md`](../ROADMAP.md).** It is the only
forward-looking roadmap maintained for this repository; it is claim-safe
(planned work is never described as implemented) and its status marks are
verified against `origin/master`.

Everything in this directory is a **frozen historical snapshot**. These
documents are kept for provenance — ADRs, audits, and commit messages cite
them — but they are no longer maintained, their status claims may be stale,
and their internal relative links may no longer resolve from this location.
Do not plan new work from them.

## Archived documents

| Document | Was | Superseded by / why archived |
|---|---|---|
| [`ROADMAP.md`](ROADMAP.md) | Root 12-week development roadmap (draft, 2026-05-22) | `docs/ROADMAP.md` is the roadmap of record; the 12-week draft's kernel-first Phase 1 track was largely executed and its reconciliation table is now historical |
| [`ROADMAP-ENFORCEMENT-SUBSTRATE.md`](ROADMAP-ENFORCEMENT-SUBSTRATE.md) | Enforcement-substrate framing companion to the root roadmap | Its adversary-model spine was canonicalized into `docs/SECURITY_MODEL.md` (locked by `tests/docs/test_adversary_model.py`); the wider-aperture roadmap is not the plan of record |
| [`AUTHZ-ROADMAP.md`](AUTHZ-ROADMAP.md) | Authorization-propagation phased plan (single-author preprint basis) | Accepted scope lives in ADR-0005/ADR-0008 and shipped code (`packages/gove-zone/src/gove_zone/authz.py`); remaining phases were conditional on a validation gate |
| [`MACI-ROADMAP.md`](MACI-ROADMAP.md) | MACI surface roadmap for `packages/acgs-lite/` | Architecture recorded in ADR-0002; the MACI surface shipped in `packages/acgs-lite/` |
| [`PLAN-GOVE-ZONE-KERNEL.md`](PLAN-GOVE-ZONE-KERNEL.md) | Kernel-first build plan for `packages/gove-zone/` | The kernel is built; current kernel status is tracked in `docs/ROADMAP.md` stages |
| [`workspace-PLAN.md`](workspace-PLAN.md) | Early workspace unification plan | Duplicated by `docs/PLAN-MONOREPO.md`, which remains the active monorepo unification plan |

## What is NOT archived

- `docs/ROADMAP.md` — the roadmap of record.
- `docs/PLAN-MONOREPO.md` — active monorepo unification plan; load-bearing for
  CI path filters and `scripts/hardening_report.py`.
- `acgi-ai/PLAN.md` — frontend completion plan, scoped to `acgi-ai/` only.
  Do not conflate it with `docs/PLAN-MONOREPO.md`.

## Update rule

When a roadmap or plan document is superseded, `git mv` it here, add a row to
the table above, and update any live pointers (`CONTRIBUTING.md`, `CLAUDE.md`,
`docs/governance-stack-index.md`, `docs/README.md`). Then run `make lint-docs`.
