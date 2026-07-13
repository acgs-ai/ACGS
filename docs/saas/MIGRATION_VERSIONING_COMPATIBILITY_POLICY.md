# SaaS beta migration, versioning, and compatibility policy

**Status:** Phase-0 target beta contract (G008).

**Not an implementation claim:** This policy defines the required safety
properties for future schema, API, receipt, policy, evidence, and client
changes. It does not claim that Alembic, PostgreSQL migrations, project/
environment data, /v1 compatibility, backup/restore, or rollback drills are
implemented or deployed.

## Current-state boundary

The frozen [G006 survey](CURRENT_STATE_SURVEY.md) records a control-plane
foundation that uses create-all rather than an Alembic migration surface and
does not evidence project/environment scope, /v1, idempotency, transactional
outbox, or current migration/rollback proof. Existing local JSONL and export
behavior is not a durable managed migration system. This policy does not
retroactively classify current data as migrated.

The target API/data contract is in [API_AND_DATA_CONTRACT.md](API_AND_DATA_CONTRACT.md);
the target trust and evidence properties are in [ARCHITECTURE.md](ARCHITECTURE.md)
and [THREAT_MODEL.md](THREAT_MODEL.md). [ROADMAP.md](../ROADMAP.md) remains the
roadmap of record.

## Migration system target

The managed control/evidence plane must use an explicit, reviewed Alembic
migration history against supported PostgreSQL versions. Application startup
must not use create-all as a production schema-management substitute. A local
development profile may bootstrap disposable state only when it is unmistakably
insecure/non-production and cannot be mistaken for a production migration path.

Every migration has an owner, ordered revision, forward path, expected lock and
runtime impact, data classification impact, tenant/RLS impact, recovery plan,
and evidence command. Irreversible or destructive operations require a
verified backup before execution and an approved forward-recovery plan. A
rollback label is never permission to silently rewrite or discard evidence.

## Expand, migrate, validate, contract

The default sequence for a compatible change is:

1. **Expand.** Add backward-compatible schema/API fields, indexes, tables,
   constraints in non-blocking form where possible, and dual-read/write paths
   needed for safe transition.
2. **Migrate/backfill.** Run resumable, bounded, idempotent jobs with explicit
   tenant context, checkpoints, progress/error state, rate limits, and
   reconciliation. Backfills do not manufacture signatures, native assurance,
   or a new audit anchor for historical artifacts.
3. **Validate.** Verify row counts/digests, tenant isolation, referential and
   lifecycle invariants, application behavior, worker behavior, object
   references, and old/new reader compatibility. Capture a reviewable report.
4. **Contract.** Remove obsolete paths only after all supported clients,
   gates, workers, exports, and offline verifiers have passed the documented
   deprecation window and compatibility checks.

A failed or interrupted migration remains visible and recoverable. It may be
retried idempotently, repaired forward, or restored according to its plan; it
must not leave a partially converted artifact represented as accepted evidence.

## Database and tenancy rules

- Organization, project, and environment scope must be represented in keys,
  constraints, and repository query predicates; URL matching alone is not
  tenant isolation.
- PostgreSQL RLS may provide defense in depth, but each request and worker must
  set and verify tenant context explicitly. Database owners or BYPASSRLS roles
  are not evidence that RLS isolation applies.
- New uniqueness and exclusion constraints must enforce policy lifecycle,
  idempotency, one-time consumption, approval/resume, and evidence sequence
  rules at the durable store rather than only in process memory.
- Locking/isolation behavior is specified and tested for concurrent policy
  activation, approval, export, worker restart, and evidence ingestion.
- Partitioning, retention, deletion, legal hold, and object references preserve
  tenant scope and do not permit a cross-tenant query, object key, cache hit,
  or background worker leak.

## Artifact compatibility rules

| Artifact | Target compatibility guarantee | Forbidden migration behavior |
|---|---|---|
| API /v1 | Stable error codes, documented deprecation, cursor/ETag/idempotency semantics, and generated-client or bidirectional contract checks. | Changing authentication/authorization or response semantics through an undocumented UI-only change. |
| Policy bundle | Canonical bytes, content hash, signature/key id, scope, lifecycle, compatibility metadata, and signed LKG cache semantics remain verifiable. | Re-signing a substituted policy as though it were the original, silently changing scope/status, or allowing an incompatible stale/revoked bundle. |
| Native receipt | Original schema/version/canonical bytes/digest/signature/bindings remain verifiable by an appropriate verifier. | Dropping tenant/project/environment/actor/action/argument/policy/audit binding, weakening key/expiry/consumption, or treating an old receipt as a new authorization without verification. |
| Federated or observed evidence | Original source provenance, source decision digest where applicable, class, limitations, and retained artifact references stay visible. | Reclassifying, countersigning, importing, or exporting it as native authorization evidence. |
| Audit/checkpoint/proof pack | Manifest, receipt-event equivalence, chain, key status, provenance, and checkpoint remain independently checkable by an offline verifier. | Rewriting a chain tip/object/checkpoint relationship without retaining a truthful migration/recovery record. |
| OpenAPI/client and adapter profile | Versioned schema compatibility is checked against supported console/client/gate/adapter consumers. | A breaking enum, field, signature, or adapter mapping change without a compatibility test and published transition. |

## API and client evolution

Additive changes must preserve the documented behavior of supported consumers.
Breaking path, required-field, error-code, authentication, scope, semantic, or
canonicalization changes require a new major API version or a documented,
time-bounded migration/deprecation plan. Feature flags are server-side and
tenant-scoped; they cannot turn an invalid receipt, weak trust configuration,
or missing local enforcement into an allow.

OpenAPI changes require schema-diff review and generated-client or
bidirectional contract validation. Browser UI tests do not replace upstream
authentication, error-envelope, pagination, or mutation-transaction tests.

## Receipt, policy, evidence, and key transitions

- Validators retain sufficient versioned verifier code and trust metadata to
  verify historical artifacts under their original canonicalization and
  algorithm. Historical validity is not retroactive current authorization.
- Key rotation introduces new trusted key material before issuance changes,
  retains appropriate verification/revocation evidence, and tests old/new key
  overlap and compromised/revoked key behavior.
- Policy changes follow draft/review/active/stale/superseded/revoked lifecycle
  transitions and atomic scope-level activation. A concurrent activation cannot
  leave two active policies or replace the valid LKG cache with an invalid one.
- Evidence-store migrations preserve object reference, tenant encryption
  context, retention/legal-hold state, source provenance, assurance class, and
  witness/checkpoint reference. A failed sealing/witness transition is not
  equivalent to accepted durable evidence.

## Backup, restore, rollback, and forward recovery

Before a destructive migration, operators create and verify a backup including
the database, required evidence metadata/object references, trust/configuration
needed for recovery, and the documented point-in-time recovery boundary.
Restores use an isolated environment first and verify tenant separation,
receipt/policy/evidence/offline proof integrity, worker/outbox reconciliation,
and the stated RPO/RTO target before any promotion.

Rollback is valid only for an explicitly reversible code/schema step. For
irreversible backfills, key rotations, object transitions, retention/legal-hold
changes, or externally observed API states, the plan uses forward recovery and
a truthful incident/audit record. No automated rollback may delete or rewrite
accepted evidence, bypass a legal hold, or make a receipt/proof appear valid
when the recovery evidence is incomplete.

## Required migration evidence gate

Before G101 or a dependent implementation node is accepted, the affected
change must include:

- clean-install migration from empty supported PostgreSQL;
- upgrade from the last supported current schema and at least one prior
  supported schema, including resumable/partial failure behavior;
- backup-before-destructive proof and isolated restore verification;
- negative tests for tenant-context/RLS bypass, cross-tenant query/object/cache/
  worker leakage, duplicate idempotency, concurrent policy activation, and
  one-time approval/resume;
- receipt/policy/evidence/export/adapter compatibility and offline verification
  across old/new artifacts;
- OpenAPI/client compatibility or generated-client validation;
- explicit rollback or forward-recovery procedure, owner, limitations, and
  machine-readable evidence report.

## Evidence and next gate

G008 records a target-only compatibility policy. G101 supplies the initial
Alembic and API/migration evidence, G102-G106 the tenant/transaction/credential/
BFF evidence, and G301-G303 the evidence/object/witness recovery evidence.
G603 must later provide an authorized backup/PITR/restore drill. Until then,
this document is not an operational recovery, retention, or availability claim.
