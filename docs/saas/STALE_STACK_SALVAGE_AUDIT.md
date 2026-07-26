# Salvage audit — PRs #366–#371 (`native_*` / `governance_*` generation)

Date: 2026-07-26. Author: automated PR-landing pass. Status: analysis, no code changed.

## Why this exists

PRs #366–#371 were authored when `master` was at migration `0002`. Since then
`0003_managed_mutation_uow`, `0004_managed_trust_v2`, and `0005_tenant_bootstrap`
landed and introduced the `managed_*` schema generation.

The stack does not merely collide on revision numbers. Most of it **re-implements
concepts master already carries in a more developed form** — the merged `managed_*`
tables are project/environment-scoped and receipt-linked, while the stack's
`native_*` / `governance_*` tables are org-only. Landing the stack as-is would
install a second parallel receipt ledger and a second audit chain, in a product
whose value rests on there being one tamper-evident chain.

The 73 merge-conflict hunks are themselves the evidence: both sides edit the same
`_COLUMNS`, `_PRIMARY_KEYS`, `_FOREIGN_KEYS`, and `_UNIQUES` dictionaries for
equivalent tables.

## Per-PR verdict

| PR | Proposes | Master equivalent | Verdict |
|---|---|---|---|
| #366 | `governance_events`, `governance_event_heads` | `managed_governance_events`, `managed_governance_event_heads` | superseded |
| #366 | `audit_projection_outbox` | `managed_outbox` (richer: `delivery_key`, `payload`, `status`, `attempts`) | superseded |
| #366 | `governance_event_cutover` | **none** | **SALVAGE** |
| #367 | `native_decision_receipts`, `native_receipt_consumptions` | `managed_decision_receipts`, `managed_receipt_consumptions` | superseded |
| #368 | `native_receipts.py`, `0005_native_receipt_artifacts` | builds on #367's native ledger | superseded |
| #369 | `projects`, `environments` | created in `0002_project_environment` | superseded |
| #369 | agent / policy environment scope attachment | **none** — `agents` carries only `org_id` | **SALVAGE** |
| #370 | wires agent creation to native receipts | master governs via the managed mutation path | superseded |
| #371 | `managed_idempotency_results` | `tenant_bootstrap_idempotency` replays responses for **one** route only; `managed_mutation_attempts` is mutation dedup | **SALVAGE (generalize)** |

## The three salvageable capabilities

### 1. Legacy → managed audit-chain cutover (from #366)

`governance_event_cutover` records, per org, the state of migrating from the
legacy file-based `ChainHashAuditStore` to the database chain, anchoring the
legacy chain's `count` and `hash` at cutover so the pre-cutover history stays
verifiable. Master has no cutover concept at all — grep for `cutover`,
`projection_outbox`, `legacy_audit_anchor` returns nothing under `src/`.

Must be rebuilt against `managed_governance_events` rather than the PR's
`governance_events`.

### 2. Agent / policy environment scope attachment (from #369)

Master's `agents` columns are `id, org_id, name, description, trust_tier,
allowed_tools, status, created_at` — no `project_id` / `environment_id`. Every
`managed_*` table is env-scoped, so agents and policy bundles are currently the
un-scoped exception. This is a genuine modelling gap, not a duplicate.

Riskier than the other two: it alters existing populated tables, so it needs a
backfill story and a nullable→enforced sequence.

### 3. Durable HTTP idempotency results (from #371)

Master is **not** starting from zero here, and an earlier draft of this audit
overstated the gap. `0005_tenant_bootstrap` added `tenant_bootstrap_idempotency`
(`idempotency_key`, `actor`, `request_hash`, scope columns, full `response` JSON),
which does replay a prior response — but only for `POST /v1/tenant-bootstrap`.
Separately, `managed_mutation_attempts` (`receipt_hash`, `audit_event_hash`,
`action`, `actor_hash`, `argument_hash`, `status`) dedups *mutations* and cannot
reproduce a response.

What #371 contributes is the **generalization** of the bootstrap-only pattern to
every managed write, plus explicit versioning of the digest inputs:
`key_digest`, `request_digest` + `request_digest_version`,
`canonicalizer_version`, `terminal_decision`, `response_status`,
`response_body_hash` (a hash rather than the full body).

The version fields are the substantive addition: without them a change to the
canonicalizer silently changes what counts as "the same request", which is a
correctness hazard for an idempotency contract.

This is the capability `docs/saas/DELIVERY_DAG.yaml` still records as missing:
aggregate G102 "still lacks ... durable idempotency persistence".

**It is not a straight port.** The PR's table is entangled with the rest of the
stale stack in three ways, all of which must be undone before it can land:

- `native_receipt_row_id` and `receipt_id` bind each row to the **native**
  receipt ledger from #367/#368, which is superseded. These must be re-bound to
  `managed_decision_receipts`.
- `down_revision = "0006"` chains it behind #369's scope-attachment migration.
- `upgrade()` runs `batch_alter_table("agents")` to add `uq_agents_org_id_id` —
  a constraint that belongs to #369's scope work, not to idempotency.

An earlier draft of this audit called this slice "self-contained (one table plus
request middleware)". That was wrong; the coupling above is the actual work.

The parts worth keeping are the digest-versioning fields and the terminal-only
storage discipline (no pending row, no lease, no expiry — so a pre-governance or
transient failure leaves no idempotency state behind), which is a sound design.

## Recommended sequence

Note the dependency inversion the entanglement creates: #371 wants #369's
`agents` unique constraint, so scope attachment has to come first even though it
is the riskier migration.

1. **#369 scope attachment** — `agents` / `policy_bundles` gain
   `project_id` / `environment_id` plus `uq_agents_org_id_id`. Alters populated
   tables, so it needs a nullable→backfill→enforce sequence.
2. **#371 idempotency** — re-bound to `managed_decision_receipts`, with the
   `agents` constraint removed from its own migration.
3. **#366 cutover** — purely additive; can land at any point after (1).

Each lands as its own PR against the `managed_*` schema, numbered from master's
head (`0005`) onward, with the live-PostgreSQL migration suites run per PR.

## Effort assessment

This is a re-design, not a port. Every salvaged piece has to be re-bound from the
`native_*` / `governance_*` model to the `managed_*` model, and each carries a
migration against populated tables. Treat it as three feature PRs, not three
cherry-picks.

## What to do with the originals

Close #366–#371 with a pointer to this file and to the salvage PRs. The design
intent is preserved; the `native_*` / `governance_*` naming generation is not.
