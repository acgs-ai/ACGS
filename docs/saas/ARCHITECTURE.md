# SaaS beta target architecture

**Status:** Phase-0 target beta contract (G008).

**Not an implementation claim:** This document freezes the beta architecture
and acceptance boundary, with explicit current-local exceptions. The G201
enrollment and G202/G203 policy lifecycle/sync slices described below do not
assert that a managed service, browser BFF, durable evidence store, independent
witness, deployment, customer use, production readiness, or commercial offering
exists today.

## Current-state boundary

The frozen [G006 survey](CURRENT_STATE_SURVEY.md) is the source of truth for
what exists. It records a partial local receipt/executor foundation, a local
alpha control-plane path that uses a legacy receipt flow, per-organization JSONL
audit behavior, and no surveyed managed ingestion, signed policy sync, durable
spool, independent witness, browser BFF, migration system, or
project/environment scope. Those observations remain the frozen survey baseline;
later current-local exceptions must be supported by code, tests, and the delivery
DAG. It is not safe to infer any other target component below from a local proof
or from a UI fixture.

Current-local exception for G202/G203: branch `beta/p4-policy-sync-002` contains
a governed signed policy publication/activation substrate, an authenticated
read-only `/v1/runtime-identities/{identity_id}/policy-bundle` endpoint, strict
policy-sync v2 verification, and an owner-only last-known-good cache with a
durable high-water floor. The cache and floor are separately atomically
replaced, not pairwise transactional. `UniversalGateway` can evaluate that verified policy
under a cache lease and return native assurance only after a signed, expiring,
single-use receipt-v2 executes successfully. This is an implementation-only
slice. G203 remains incomplete because G202 and bounded evidence-spool/capacity
semantics are incomplete. Separately, aggregate G017 remains incomplete because
no G204 signed persisted wiring attestation, G205 operator fleet-status surface,
or canonical `run.json` exists.

The [G007 product contract](PRODUCT_REQUIREMENTS.md) defines the user outcome
and invariants. [ROADMAP.md](../ROADMAP.md) remains the roadmap of record;
[DELIVERY_DAG.yaml](DELIVERY_DAG.yaml) carries the implementation and evidence
gates. Current local limitations remain governed by
[SECURITY_MODEL.md](../SECURITY_MODEL.md) and [CLAIMS.md](../CLAIMS.md).

## Target architecture and trust boundaries

The target is a modular monolith with explicit provider interfaces, not a
premature microservice estate. A future service split requires an ADR proving
why a module is insufficient and documenting transaction consistency, tenant
isolation, retry/idempotency behavior, failure modes, deployment burden, and
an operational owner.

~~~text
 Customer runtime / restricted-egress boundary
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ authenticated runtime context                                              │
 │       │ (tenant, project, environment, expected actor)                    │
 │       ▼                                                                    │
 │ local policy evaluator ──► receipt signer ──► issuance/audit anchor       │
 │       │ signed policy / trust cache       │              │                  │
 │       │                                    ▼              ▼                  │
 │       └──── local audit/replay ◄──── executor verifier ─► governed effect  │
 │                         │                                                   │
 │                         └── durable bounded evidence spool ── async ───────┼──┐
 └──────────────────────────────────────────────────────────────────────────┘  │
                                                                                │
 Managed control and assurance boundary                                         │
 ┌──────────────────────────────────────────────────────────────────────────┐  │
 │ console ── session ──► server-side BFF ──► /v1 management / ingestion API │◄─┘
 │                                      │             │                       │
 │                                      │             ├── PostgreSQL metadata │
 │                                      │             ├── transactional outbox│
 │                                      │             └── durable worker      │
 │                                      ▼                                     │
 │                         policy/trust distribution, approvals, exports      │
 │                                      │                                     │
 │                         sealed evidence object provider ─► witness provider│
 └──────────────────────────────────────────────────────────────────────────┘
                       │
                       └── offline verifier checks receipt, provenance,
                           manifest, chain/event equivalence, and checkpoint
~~~

The control plane distributes signed, scoped policy and trust material; it is
not a remote authorization dependency for a side effect. The evidence plane is
asynchronous. Loss of the hosted plane must never create an ungoverned effect.

| Boundary | Target rule | Required evidence before implementation is accepted |
|---|---|---|
| Executor boundary | The local executor derives expected actor, tenant, project, and environment from authenticated runtime context or durable gate identity, never from an agent-controlled tool/API body. | Dispatcher-level positive and zero-side-effect negative tests. |
| Local trust boundary | A native receipt is checked for trusted signing key/status, canonicalization algorithm/version and action/argument digest, scope, policy id/version/content hash, expiry, pre-effect audit binding, and durable single-use consumption before the effect. | Tamper, wrong-scope, expiry, audit-anchor, canonicalizer, revocation, and replay tests. |
| Browser boundary | A browser has a server-side session to a BFF; it never receives or stores a service API key. The BFF enforces CSRF, session, origin, and role checks before calling the upstream API. | Browser, contract, CSRF, expired-session, and credential-exposure tests. |
| Tenant boundary | Isolation covers API authorization, repositories, database constraints/RLS session context, workers, queues, caches, object keys, encryption context, exports, logs, metrics, webhooks, billing, and support tools. PostgreSQL RLS is defense in depth; owner or BYPASSRLS roles must not be treated as tenant-isolated access. | Cross-tenant adversarial tests for every listed surface. |
| Evidence boundary | Ingestion verifies authenticated gate identity, sequence/replay behavior, idempotency key/body digest, signature/provenance, assurance class, and tenant/environment binding before acceptance. | Invalid, duplicate, out-of-order, wrong-scope, and class-invalid ingestion tests. |
| Anchor boundary | The evidence writer, evidence object store, and independent checkpoint/witness cannot share the sole authority capable of silently rewriting all evidence and its only anchor. | Offline rewrite/split-view/checkpoint-regression negative tests. |
| External-provider boundary | Identity, KMS, object retention, witness, email/webhook/SIEM, and billing are accessed through provider interfaces. A contract does not select or attest a provider. | Focused ADR approval plus provider conformance/failure tests. |

## Three deliberately separate planes

### Open local execution and data plane

The customer-colocated local plane evaluates policy and verifies receipts at
the executor. It retains the open safety properties: trusted verification,
signing, expiry, anti-replay, single-use consumption, local audit/replay,
proof-pack verification, CLI support, and conformance tests. It has **no
mandatory network call in the side-effect hot path** and must support private
cloud, on-premise, restricted-egress, and air-gapped deployments.

When hosted evidence is configured, the local plane writes a signed,
minimized record to a durable bounded spool for asynchronous delivery. The
spool is not an authorization bypass or a permission to discard required
evidence.

### Managed control plane

The future FastAPI management API, SQLAlchemy 2 persistence layer, PostgreSQL,
Alembic migration system, transactional outbox, durable worker, and BFF manage
organizations, projects, environments, human and workload identities, gates,
policy bundles, approvals, trust material, fleet state, exports, and governed
administrative mutations. A future control-plane mutation either fails before
governance at authentication/RBAC or uses the canonical receipt, side effect,
event, outbox, and durable evidence contract; otherwise it rolls back and
preserves the correct refusal/failure evidence.

### Managed evidence and assurance plane

The future evidence service accepts evidence asynchronously and idempotently;
verifies its native/federated/observed provenance; stores query metadata in
PostgreSQL; seals the retained artifact through an object-retention-capable
provider; publishes checkpoints to an independent witness interface; and
supports retention, legal-hold policy, query, replay, alerting, export, and
offline verification. Local instance disk is not the target system of record.

The evidence plane does not turn federated or observed records into native
authorization proof. Assurance is immutable in storage, UI, alerts, usage, and
exports as specified in [ASSURANCE_CLASSES.md](ASSURANCE_CLASSES.md).

## Canonical transaction spine and failure behavior

### Local authorization and effect

1. The runtime authenticates the caller/gate and supplies trusted tenant,
   project, environment, and expected-actor context to the local gate.
2. The local gate selects a signed, canonical, content-addressed,
   tenant/project/environment-bound policy bundle and trusted key material.
3. It issues a native receipt only for ALLOW and durably persists a pre-effect
   issuance/audit-anchor record. The record digest is bound into the receipt;
   the receipt binds authority, actor, validator, action, canonicalization
   algorithm/version and canonical argument digest, policy identifier/version/
   content hash, execution boundary, expiry, key id, and that audit anchor.
4. Before the side effect, the executor independently recanonicalizes the
   actual invocation with the named algorithm/version, verifies the action and
   argument digest, validates the durable audit-anchor record/digest and all
   other bindings, then consumes the single-use authorization. DENY and
   ESCALATE are never executable.
5. Audit append/anchor verification, receipt validation, canonicalization, or
   consumption failure invokes the protected callable zero times. After a
   successful effect, a failed outcome append becomes a durable pending/
   reconciliation state; reconciliation must not perform the effect a second
   time.

### Managed mutations and asynchronous evidence

1. The API derives scope and principal from authenticated context; it does not
   accept agent-controlled scope as authority.
2. Idempotency identity and canonical body digest are recorded. Same key and
   digest replay the first result; the same key with a different digest is a
   conflict and causes no second mutation.
3. The database mutation, canonical receipt/event record, and outbox row share
   one database transaction. A worker performs retryable external delivery.
4. Evidence ingestion verifies its artifact before it is marked accepted.
   Object sealing and witness publication have explicit pending/failed/retry
   states; a partially delivered record cannot be presented as accepted,
   independently anchored evidence.
5. Reconciliation detects missing outbox delivery, object artifacts, or witness
   checkpoints without inventing a successful record.

### Exact minimized action/argument binding

The signed native receipt carries an action identifier plus a canonicalization
algorithm/version and digest of the canonical arguments. The executor uses the
same named canonicalizer to derive an independent digest from the invocation
it is about to call; unknown, unsupported, or mismatched canonicalization
versions, actions, or argument digests fail before consumption and invoke the
callable zero times. This provides exact binding without putting raw arguments
into the default receipt.

If a policy or investigation requires raw material, it is a separately
classified, encrypted, access-controlled payload reference. That reference is
not a substitute for, or a mutable input to, the signed algorithm/version/
argument digest. Its access, retention, deletion, and export rules are
explicitly governed by data classification.

## Policy distribution, outage, and degraded operation

The current-local G203 slice implements the core signed LKG behavior for one
enrolled gate. It authenticates sync requests, verifies separate policy-envelope
and sync-attestation trust, pins activation commitments and monotonic cursor/head
state, and performs local evaluation without a network call. Fresh snapshots are
usable locally; stale snapshots are usable only inside both their signed expiry
and the configured degraded window. Expired, locally revoked, rollbacked,
equivocated, corrupt, or untrusted state fails closed. The cache and high-water
sidecar are owner-only and each is atomically replaced, but the pair is not a
transaction. The high-water record advances first; if a crash occurs before the
cache replacement, restart forces an unconditional authenticated fetch and still
rejects a response below the preserved floor. Both files share one filesystem
trust boundary; independent/off-host anti-rollback anchoring is not implemented.
The bounded evidence spool and its record/byte/time limits, durable
acknowledgement, observability, and capacity-exhaustion failure behavior are also
not implemented, so G203 remains incomplete.

The remainder of this section is the beta target contract.

Only a signed, compatible, scope-bound, unexpired last-known-good (LKG) policy
and trust cache may be used locally while the managed plane is unavailable.
The cache pins policy lifecycle status, trust epoch/key status, canonical
content hash, compatibility metadata, signed trust-material maximum freshness,
and an explicit degraded-mode validity window. Locally known revocations apply
immediately. A gate isolated after its last synchronization cannot detect a
new remote revocation instantly; it must fail closed when signed trust-material
freshness or the degraded window expires. New policy activation, trust changes,
and approvals fail closed during the outage.

The local evidence spool has configured record/byte/time limits, durable
acknowledgement semantics, and observability. When the degraded window expires,
a required policy is stale/revoked, or a configured high-risk spool capacity is
exhausted, the high-risk path fails closed. This is a target acceptance rule,
not evidence that current local profiles enforce every element.

## Target data classification and minimization

| Class | Target treatment | Prohibited default destinations |
|---|---|---|
| Authentication secrets, credentials, access tokens, private keys | Never place in receipts, telemetry, analytics, billing events, errors, proof packs, or logs. | All evidence and observability surfaces. |
| Tool arguments and regulated/personal data | Store canonicalization algorithm/version plus action/argument digest and redacted metadata in the default receipt/evidence event. If retention is explicitly required, keep an encrypted, access-controlled payload reference with classification and retention policy; it cannot replace the signed digest. | Default receipts, metrics, analytics, usage, error text, and exports. |
| Policy/trust artifacts and immutable evidence | Canonical bytes, digest, signature/key id, scope, lifecycle, and provenance are retained under tenant-scoped encryption/object-key rules. | Cross-tenant lookup, unauthenticated export, and browser-local storage. |
| Operational metadata | Collect request/trace IDs, minimized status, counters, and timing needed for operation; redact before logs/metrics. | Raw request/tool payloads and secrets. |

No row states that current receipt transforms or local logs already satisfy this
target minimization contract; the G006 survey and current security model remain
the factual source.

## Provisional beta envelope and operational targets

The following are **provisional planning assumptions**, not measured capacity,
SLO, RPO/RTO, deployment, or service-level commitments. An operational owner
must ratify them, and G601-G605 must measure and demonstrate them before any
external capability claim.

| Planning dimension | Provisional target assumption | Required future evidence |
|---|---|---|
| Supported beta cohort | Up to 10 design-partner organizations, 50 production environments, and 250 enrolled gates. | Load model, enrollment/fleet data, and capacity report. |
| Local authorization overhead | p99 additional local gate overhead at or below 25 ms for the supported canonical action profile, excluding the downstream side effect. | Reproducible benchmark with hardware/profile and percentile report. |
| Policy distribution | A compatible signed policy reaches an online gate within 5 minutes; LKG behavior is explicit when it does not. | Multi-gate sync, outage, stale-cache, and rollback tests. |
| Evidence durability and lag | Accepted evidence is durably acknowledged only after the specified metadata/artifact boundary; p95 ingestion-to-query lag at or below 5 minutes under the beta envelope. | Failure-injection, queue-backlog, and retention/object-store evidence. |
| Availability/recovery | Management API monthly objective 99.5%; policy/evidence recovery targets RPO 15 minutes and RTO 4 hours. | Authorized staging DR drill, backup/PITR/restore, and operational sign-off. |
| Local outage behavior | Local safety remains functional under the documented LKG and signed-trust freshness window; high-risk routes fail closed after expiry, freshness loss, or spool exhaustion. | Partition including a revocation after last sync, clock-skew, full-spool, and key-revocation tests. |

## Evidence and next gate

G008 is satisfied only by independent review of this target contract and its
companion [threat model](THREAT_MODEL.md),
[API/data contract](API_AND_DATA_CONTRACT.md),
[migration/versioning policy](MIGRATION_VERSIONING_COMPATIBILITY_POLICY.md),
and proposed owner-gated ADRs. It does not implement this architecture. G101
and later DAG nodes must supply the database, transaction, local gate,
ingestion, BFF, provider, browser, resilience, and operations evidence.
