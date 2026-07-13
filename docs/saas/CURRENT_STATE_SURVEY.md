# Frozen Current-State Survey

**Node:** G006
**Baseline:** `origin/master` at `1d9c9b21372ebdbd20aefc3ca454a47a3d5d1f96`
**Program-record parent:** `beta/p0-program-record-005` began at `b2aa0c928b6ba21baa8e4a123452eebeeda3e050`; it was observed at `e4af0731aece89c1b7bcc050b609260571497145` after a test-only hardening commit. Rebase this stacked record before publication.
**Observed:** `2026-07-13T09:59:25Z`
**Machine-readable record:** [current-state-survey.json](../../evidence/saas/g006/current-state-survey.json)

This is a bounded local reconciliation record for the SaaS-beta program. It
summarizes source, test, tracked-documentation, and forge metadata observations
at the frozen baseline. It is not deployment, customer-use, independent-assessment,
certification, or production-readiness evidence. It deliberately excludes
credential material, request payloads, machine-local paths, and raw command output.

## Built / partial / missing / conflicting matrix

| Plane | State | Current evidence boundary | Required next proof |
|---|---|---|---|
| Open local execution and data | partial | `DecisionReceipt` and `execute_with_receipt` provide canonical local receipt and executor controls, including signature, expected-actor, and expiry; single-use is enforced when a consumption ledger is configured. | Join local enforcement to the managed canonical journey without changing its fail-closed contract. |
| Managed control | partial | A local alpha control-plane surface exists, but it dispatches a legacy `Kernel`/`Receipt` flow and lacks surveyed migration, idempotency, outbox, and canonical-enforcement evidence. | Prove signed canonical receipt enforcement, atomicity, versioned API, migration, and tenant constraints. |
| Managed evidence and assurance | missing | Per-organization JSONL chains and hash manifests are not a durable, independently witnessed managed evidence plane. Local/MCP approval-resume exists, but no surveyed managed control-plane approval/resume API, external ingestion, sync, spool, or witness surface exists. | Build authenticated ingestion, durable evidence storage, independent checkpointing, and offline proof verification. |
| Single console | conflicting | Browser-boundary tests and non-production fixtures exist, while the console's relative API/session model does not match the control-plane service-credential surface. | Define and test one server-side browser-to-upstream boundary and contract. |
| Delivery and operations | missing | Version label `v0.1.0a1` and deployment metadata are not deployment, monitoring, recovery, customer, or production-readiness proof. | Produce authorized staging, recovery, observability, and operations evidence. |

## Hypothesis disposition

| ID | Disposition | Bounded finding |
|---|---|---|
| H-RUNTIME-CANONICAL-001 | confirmed | The local runtime has canonical receipt issuance and executor verification with signature, expected-actor, and expiry controls; single-use applies when a consumption ledger is configured. |
| H-CP-LEGACY-002 | confirmed | The control-plane governance path imports `Kernel` and `Receipt` and dispatches the legacy receipt flow rather than the signed canonical executor flow. |
| H-CP-AUDIT-SCALING-003 | confirmed | Control-plane audit storage is a per-organization JSONL chain with linear verification scans. |
| H-CP-AUDIT-ATOMICITY-004 | unverified | No injected SQL-commit failure proof was found for potential audit-versus-mutation orphan behavior. |
| H-CP-EXPORT-PROVENANCE-005 | confirmed | Exports use hash manifests; signed provenance and independent witnessing were not evidenced. |
| H-POLICY-ACTIVATION-RACE-006 | unverified | No uniqueness, locked-activation, or concurrent-activation proof was found for exactly-one-active policy behavior. |
| H-CP-FOUNDATION-007 | confirmed | The surveyed foundation uses `create_all`, has no Alembic surface, and lacks observed v1, idempotency, and transactional-outbox foundations. |
| H-EVIDENCE-INGESTION-008 | contradicted | Local/MCP approval-resume exists; the surveyed gap is a managed control-plane approval/resume API or durable managed approval operation, together with receipt ingestion, signed policy sync, durable spool, and independent witness surfaces. |
| H-CONSOLE-CONTRACT-009 | confirmed | The console uses relative api-v1 and api-bus routes with a browser session and fixture model that does not match the current organization-scoped service surface. |
| H-FORGE-STATE-010 | confirmed | At the frozen observation, pull request 317 was open and draft, 308 open and unmerged, 267 closed and unmerged, and issues 167 and 168 open. |
| H-VALIDATION-011 | confirmed | Control-plane tests passed 25 with a warning; console boundary checks passed under Node 22 rather than requested Node 24; the first broad gove-zone cause was absent optional cryptography and PyYAML dependencies, without a rerun. |

The [machine-readable record](../../evidence/saas/g006/current-state-survey.json)
holds the source-reference summaries and prescribed next validations for each
hypothesis. It is the authoritative G006 snapshot; this page is its readable
projection.

## Forge, release, and delivery boundary

The frozen forge snapshot records 317 as open/draft, 308 as open/unmerged, and
267 as closed/unmerged. The latter is historical only. Issues 167 and 168 were
open. `v0.1.0a1` was observed as a version label, with no published release
observed. Deployment metadata remains non-proof until an authorized deployment
and post-deployment evidence exist.

## Validation boundary

- The control-plane package test snapshot was **25 passed with one warning**.
- The console authentication-boundary check passed under host **Node 22**; its
  requested runtime is **Node 24**, so this is partial rather than exact-runtime
  evidence.
- The first observed gove-zone broad-gate cause was absent optional
  **cryptography** and **PyYAML** dependencies. It was not rerun; that environmental
  first cause remains recorded rather than masked.

The machine-readable record contains the sanitized command, exit code, tool or
environment profile, warning classification, and a digest of each retained
summary. Raw command output is neither retained nor published.

## Next safe validations

1. Add injected SQL-failure integration proof for mutation, receipt, event, and
   outbox behavior.
2. Add a database invariant and concurrency test for exactly one active policy.
3. Migrate control-plane mutation paths to canonical signed receipts and prove
   dispatcher-level executor wiring.
4. Define one server-side browser-to-upstream boundary with contract tests before
   replacing fixture behavior.
5. Re-run the declared package gates once in a clean environment with the
   optional dependencies and Node 24; do not overwrite the recorded first cause.

No hypothesis in this survey upgrades public claims. The delivery DAG and
acceptance matrix remain conservative until independent review and the named
evidence gates pass.
