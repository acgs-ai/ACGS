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

## Branch-local delta after the frozen survey

The G006 findings below remain the frozen `2026-07-13T09:59:25Z` survey record.
On branch `beta/p3-approval-003-reconciled` in draft PR #413, the managed
control plane adds
a narrow approval/resume proof path for `agent.register` only:

- Alembic head is now `0010`: revision `0008` adds the managed policy registry;
  revision `0009` adds additive, forward-only approval request, vote, outcome,
  and resume-authorization tables; and revision `0010` binds each approval vote
  to the approver credential and exact managed vote receipt. Revision `0010`
  refuses ambiguous pre-existing vote/resume rows rather than inventing their
  provenance.
- `POST /orgs/{org}/agents` now creates a scoped pending approval request when
  the active managed policy returns ESCALATE for `agent.register`; the parked
  request stores sealed arguments and binds scope, action, policy, trust epoch,
  execution boundary, ESCALATE receipt, and audit-event hashes.
- `POST /orgs/{org}/approvals/{approval_request_id}/votes` records a governed
  approval vote, and `POST /orgs/{org}/approvals/{approval_request_id}/resume`
  resumes only the original `control-plane.agent.create` action.
- Resume requires a distinct active credential-bound approver, live policy and
  trust revalidation, requester/approver/caller checks, a fresh short-lived
  signed `DecisionReceipt`, `execute_with_receipt` verification, SQL
  single-use consumption, and one atomic commit for the agent row, receipt,
  event, outbox, mutation attempt, and resume authorization.

This delta resolves the prior "no managed control-plane approval/resume API"
gap only for the local/test `agent.register` path. Bootstrap approvals remain a
separate pre-tenant domain; policy publish/activate escalations remain
unsupported and fail closed. The activated request threshold is fixed at one
approver and there is no cancel endpoint. The tested guarantee is at-most-once
authorized SQL execution for this one action, not exactly-once arbitrary
external effects. Customer-runtime evidence ingestion, signed policy sync,
durable spool, independent witnessing, deployment, customer use, external
audit, compliance, and production readiness remain unclaimed.

The branch evidence is local tests plus live local PostgreSQL harness coverage:

```bash
cd packages/acgs-control-plane
./scripts/run_postgres_gate.sh \
  tests/integration/test_approval_resume_postgres.py::test_pg_escalate_creates_scoped_pending_without_agent_or_consumption \
  tests/integration/test_approval_resume_postgres.py::test_pg_self_and_wrong_role_approval_are_non_executable \
  tests/integration/test_approval_resume_postgres.py::test_pg_resume_before_required_vote_is_non_executable \
  tests/integration/test_approval_resume_postgres.py::test_pg_approved_resume_executes_once_and_replay_is_stable \
  tests/integration/test_approval_resume_postgres.py::test_pg_rejected_and_expired_requests_resume_zero_side_effects \
  tests/integration/test_approval_resume_postgres.py::test_pg_concurrent_vote_refusal_replay_records_one_evidence_set \
  tests/integration/test_approval_resume_postgres.py::test_pg_mixed_refusal_then_allow_same_vote_key_has_one_terminal_artifact \
  tests/integration/test_approval_resume_postgres.py::test_pg_stale_policy_trust_and_requester_resume_zero_side_effects \
  tests/integration/test_approval_resume_postgres.py::test_pg_tampered_sealed_payload_resume_zero_side_effects \
  tests/integration/test_approval_resume_postgres.py::test_pg_multiprocess_resume_race_authorizes_one_agent \
  tests/integration/test_approval_resume_postgres.py::test_pg_approval_composite_constraints_reject_cross_scope_rows
```

```bash
uv run --extra mcp --package gove-zone python -m pytest \
  packages/gove-zone/tests/test_mcp_gateway_conformance.py::test_escalate_approve_resume_single_use \
  packages/gove-zone/tests/test_mcp_gateway_conformance.py::test_cross_pending_reuse \
  packages/gove-zone/tests/test_receipt_consumption.py::test_resume_replay_blocked_with_ledger \
  packages/gove-zone/tests/test_receipt_consumption.py::test_concurrent_consumers_single_winner \
  --import-mode=importlib -q
```

```bash
packages/acgs-control-plane/.venv/bin/python -m pytest -q \
  tests/saas_beta/test_cross_plane_contracts.py::test_approval_contract_locks_vote_and_resume_assurance
```

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
