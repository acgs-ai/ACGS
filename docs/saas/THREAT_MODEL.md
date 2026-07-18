# SaaS beta target threat model

**Status:** Phase-0 target beta contract (G008).

**Not an implementation claim:** This is a forward-looking threat model and
test contract. It does not assert that the managed control/evidence planes,
BFF, tenant RLS deployment, durable object retention, independent witness,
identity federation, billing, or the listed controls are implemented,
deployed, externally reviewed, or production-ready.

## Current-state boundary

The frozen [G006 survey](CURRENT_STATE_SURVEY.md) is authoritative for current
evidence. It records a partial local receipt/executor foundation, a legacy
control-plane receipt path, organization-only models, create-all schema setup,
per-organization JSONL audit behavior, unkeyed export manifests, and missing
surveyed managed ingestion/sync/spool/witness/BFF foundations. In particular,
it does not prove SQL/audit atomicity or exactly-one-active-policy concurrency.

The [G007 product contract](PRODUCT_REQUIREMENTS.md) and
[ASSURANCE_CLASSES.md](ASSURANCE_CLASSES.md) state the target invariants. This
document adds STRIDE and agent-specific adversarial requirements; it does not
alter the current [SECURITY_MODEL.md](../SECURITY_MODEL.md), which remains the
source for local-alpha security claims. [ROADMAP.md](../ROADMAP.md) remains the
roadmap of record.

## Security objectives

The target platform must preserve these objectives across the local, control,
and evidence planes:

1. No valid native Decision Receipt, no side effect. Missing, unsigned,
   tampered, unknown-key, revoked, expired, consumed, stale, or scope/binding
   mismatched artifacts execute zero side effects.
2. DENY and ESCALATE are never executable. An escalation can resume only through
   a separated, authorized, race-safe approval path and only once.
3. Tenant, project, environment, expected actor, authority, action,
   canonicalization algorithm/version and canonical argument digest, policy
   id/version/content hash, validator, execution boundary, expiry, key id, and
   pre-effect audit anchor remain bound to a native authorization.
4. Hosted loss cannot turn into allow-by-default. Only a bounded,
   signed, compatible, in-window LKG policy is locally usable; new approvals,
   trust changes, and activation fail closed.
5. Native, federated, and observed evidence remain immutable assurance classes.
   Ingestion, countersigning, export, or UI presentation cannot promote a lower
   class to native.
6. Evidence is independently verifiable. A service must not be able to rewrite
   both evidence and its only trust anchor silently.
7. Default evidence and observability exclude raw secrets, credentials, tokens,
   unnecessary tool arguments, and unnecessary regulated/personal data.

## Assets, actors, and trust boundaries

| Asset or boundary | Threat-relevant trust rule | Target owner/evidence gate |
|---|---|---|
| Runtime identity and gate credential | Actor, tenant, project, environment, and gate identity originate from authenticated runtime context, not prompts or request bodies. | G102/G201 dispatcher and credential tests. |
| Native receipt, policy, and trust material | Canonical bytes and all bindings are verified before a side effect; trusted key status, expiry, and consumption are enforced. | G104/G202/G204 negative-path tests. |
| Browser session and BFF | Browser receives a session, not a service key; BFF rejects CSRF, stale session, wrong origin, and unauthorized role before mutation. | G103/G401 browser and contract tests. |
| Tenant-scoped metadata and workers | API, repositories, RLS/session context, worker/queue, cache, object key, encryption context, exports, logs, metrics, webhooks, usage, and support tooling remain tenant-isolated. | G102/G106/G301 adversarial boundary tests. |
| Spool, object artifact, and witness checkpoint | Durable local queueing is bounded; accepted evidence is distinguishable from pending/failed sealing and witness delivery. | G203/G301/G302/G603 failure-injection tests. |
| Approval state | Requester, validator, and approver are separated; role/quorum and one-time resume survive concurrent retries. | G305/G405 race and zero-side-effect tests. |
| Adapter provenance | Upstream decision material is authenticated, retained, and classed as federated or observed as applicable. | G206/G301/G404 conformance tests. |
| Entitlement and billing records | Entitlement/usage mutations are governed, server-side, idempotent, and cannot weaken the open local gate. | G501/G502/G503 tests and owner approval. |

## STRIDE and agent-specific threat analysis

| Threat | Example attack | Target mitigation | Required negative evidence |
|---|---|---|---|
| Spoofing | An agent body supplies another tenant, environment, actor, or gate identity; a browser carries a reusable service key. | Authenticated runtime/gate identity, environment-bound credential scopes, BFF session boundary, rotation/revocation, and origin/CSRF defenses. | Forged actor/scope, expired/revoked credential, service-key browser exposure, wrong-origin, and expired-session requests fail before mutation. |
| Tampering | A receipt, policy, policy status, key id, canonicalizer version/action/argument digest, body digest, object key, outbox row, or checkpoint is substituted. | Canonical signatures/digests, explicit canonicalizer version, scope bindings, conditional updates, key/trust registry, object key isolation, signed checkpoint verification, and append-only state transitions. | Tampered receipt/policy/checkpoint, unknown/mismatched canonicalizer or arguments, same idempotency key with a different digest, cross-tenant object key, and modified outbox tests reject without an accepted effect. |
| Repudiation | An admin denies a policy/approval/entitlement/export mutation; a worker retry hides a failed delivery. | Canonical receipt/event/outbox transaction, immutable actor/role/time fields, idempotency record, durable failure state, and independent checkpoint/proof verification. | Inject database, outbox, worker, object, and witness failures; prove no orphan is presented as accepted evidence. |
| Information disclosure | Full tool arguments, secrets, or one tenant's evidence reaches telemetry, billing, exports, cache, metrics, logs, or support tooling. | Data classification, hashes/redaction by default, encrypted classified payload references, tenant-bound encryption/object keys, least privilege, and redacted observability. | Seed secrets/PII/full arguments and assert absence from default receipts, errors, telemetry, usage, exports, and support queries; cross-tenant query tests fail. |
| Denial of service | Signer, database, object store, witness, queue, or hosted plane is unavailable; an adversary fills the spool or sends oversized evidence batches. | Bounded LKG/degraded rules, signed-trust freshness, payload/rate limits, bounded durable spool, dependency-aware readiness, retry/dead-letter/reconciliation, and high-risk fail-closed policy. | Network partition including revocation after last sync, clock skew, retry storm, storage/witness outage, oversized batch, stale LKG/trust, and full-spool tests do not create an allow-by-default path. |
| Elevation of privilege | Policy author self-validates, requester self-approves, validator approves, an adapter upgrades observed evidence, or raw tool invocation bypasses the executor. | Separation of duties/quorum, role constraints, immutable assurance class, dispatcher conformance, raw-tool boundary documentation, and no browser-held service credential. | Self-approval, role collision, insufficient quorum, concurrent approval/retry, direct original ESCALATE use, class promotion, and bypass attempts execute zero side effects. |
| Agent-specific TOCTOU | An agent changes action/arguments after evaluation, reuses a receipt, abuses clock skew, or submits malformed upstream provenance. | Exact canonicalizer version/action/argument-digest binding, executor recanonicalization, bounded expiry, single-use consumption before effect, adapter schema validation, source decision digest, and trusted runtime context. | Wrong action/arguments, unknown/mismatched canonicalizer, replay/consumption, expired/clock-skew, malformed upstream decision, and adapter downgrade tests fail before execution. |
| Anchor equivocation | A single managed writer rewrites both evidence and its chain tip or supplies different histories to different viewers. | Independent checkpoint/witness interface, signed manifests, checkpoint inclusion/consistency checks, and offline verification. | Full self-consistent rewrite, missing/regressed/conflicting checkpoint, and manifest/receipt/chain/class tamper fail offline verification. |

## Control-plane mutation and evidence failure model

A target managed mutation is either rejected at authentication/RBAC before
governance or follows the canonical receipt, side-effect, event, outbox, and
evidence model. The database mutation, receipt/event record, idempotency state,
and outbox entry share one transaction. External object sealing, witness
publication, webhooks, and notifications use explicit pending/failed/retry
states and reconciliation; they cannot be represented as accepted evidence
until the stated acceptance boundary is reached.

This is deliberately stricter than an unverified claim of atomic behavior.
G006 did not find injected SQL-commit failure proof for current audit behavior.
G101 and G301 must establish the concrete transaction and recovery semantics.

## Policy outage and evidence-spool threat rules

A hosted outage is not an authorization signal. A local gate may only use a
signed, scope-bound, compatible, unexpired LKG policy inside a documented
degraded-mode window. The cache must retain trust epoch/key status, lifecycle
status, canonical content hash, compatibility metadata, and signed trust-
material maximum freshness. Locally known revocations apply immediately; a
remote revocation that occurs after the last synchronization is not instantly
detectable during isolation, so trust-freshness expiry fails closed. New
activation, trust changes, and approvals fail closed while disconnected.

The spool has durable acknowledgment rules and bounded records, bytes, and age.
A full high-risk spool, expired window, stale/revoked cache, unavailable trust
material, or failed required witness/evidence policy produces a documented
refusal, not silent evidence loss or a permitted action.

## Assurance and provenance attack boundary

| Class | Target source | What it never means |
|---|---|---|
| Native receipt | Signed before execution and directly verified by the ACGS executor. | A claim that a federated or observed record is native. |
| Federated attestation | Authenticated upstream decision retained with its original provenance and countersigned by a trusted adapter. | Proof that ACGS itself authorized the original action before execution. |
| Observed evidence | Log/trace-derived post-execution evidence with explicit source and limitations. | Pre-execution authorization proof or a verified governed action. |

Any conversion or export preserves the original class and source decision
digest/provenance. Countersigning, ingestion, retention, usage aggregation, or
a console badge must not silently upgrade federated or observed evidence to
native.

## Required future adversarial test corpus

Before a corresponding DAG node is accepted, tests must prove at least the
following forbidden-side-effect cases:

- Every missing, tampered, unsigned, unknown-key, revoked, expired, consumed,
  wrong tenant/project/environment/actor/action/arguments/policy artifact calls
  the protected tool zero times.
- Pre-effect audit append/issuance-anchor persistence or digest verification
  failure, receipt validation failure, and consumption failure each invoke the
  protected tool zero times. A post-effect outcome-recording failure becomes a
  durable pending/reconciliation state and never invokes the effect again.
- Changed action/arguments or an unknown/mismatched canonicalization
  algorithm/version fail before consumption and execute zero side effects.
- Duplicate same idempotency key and digest returns the original outcome; the
  same key with a different digest rejects and produces no second mutation or
  evidence record.
- No governance/evidence/security-sensitive mutation has an idempotency opt-
  out; any permitted operational exception proves equivalent durable duplicate
  prevention and cannot create a second effect/event/outbox record.
- Concurrent policy activation leaves exactly one active policy; failed
  activation never replaces an LKG cache.
- Failure before/after mutation, receipt persistence, outbox insertion, worker
  delivery, object sealing, and witness submission preserves a truthful pending,
  failure, or reconciled state.
- Cross-tenant access/inference fails for HTTP, repository, RLS/session
  context, workers, cache, object store, export, webhook, metrics/log query,
  usage, and support surfaces.
- Ingestion rejects unauthenticated, wrong-scope, replayed, out-of-order,
  conflicting, oversized, invalid-signature, and class-invalid evidence before
  accepted storage.
- Approval rejects self-approval, requester/validator/approver role collision,
  insufficient quorum, concurrency/retry, cancellation/expiry races, and direct
  use of the original ESCALATE artifact; none executes the side effect.
- Hosted outage permits only valid in-window LKG capacity; stale/revoked cache,
  a revocation after last sync once signed trust freshness expires, new approval/
  trust change, expired window, and a full high-risk spool fail closed.
- Default evidence, telemetry, errors, billing, and exports omit seeded
  credentials, tokens, PII, and raw arguments unless a separately classified,
  encrypted payload reference is expressly authorized.

## Residual risks and owner gates

This model does not select an identity provider, KMS/HSM, object-retention
provider, witness, billing provider, retention duration, data residency,
licensing boundary, legal term, or deployment environment. The proposed
build-vs-buy ADRs carry those owner/counsel/procurement decisions. The absence
of a decision is a blocker, not permission to assume one.

Current local and alpha-control-plane residuals are deliberately retained until
the named code and tests pass. Historical threat analyses elsewhere in the
repository are not a substitute for this target contract or for a future
independent security assessment.

## Evidence and next gate

G008 acceptance requires independent review of this model alongside
[ARCHITECTURE.md](ARCHITECTURE.md), [API_AND_DATA_CONTRACT.md](API_AND_DATA_CONTRACT.md),
[MIGRATION_VERSIONING_COMPATIBILITY_POLICY.md](MIGRATION_VERSIONING_COMPATIBILITY_POLICY.md),
and the proposed ADR packet. G101-G606 must turn each listed threat control
into implementation, adversarial, integration, resilience, and operations
evidence. G703 remains the independent external security-assessment gate.
