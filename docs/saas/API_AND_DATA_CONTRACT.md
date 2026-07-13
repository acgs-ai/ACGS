# SaaS beta API and data contract

**Status:** Phase-0 target beta contract (G008).

**Not an implementation claim:** This is a versioned contract for future
management, policy, approval, fleet, and evidence APIs. It does not claim that
the current control plane exposes /v1, browser sessions, a BFF, generated
clients, project/environment scope, idempotency, ingestion, exports, or the
resources described here.

## Current-state boundary

The [G006 survey](CURRENT_STATE_SURVEY.md) records the current organization-
scoped service surface and API-key model as distinct from this target. It also
records absent surveyed /v1, idempotency, transactional outbox, project/
environment scope, external receipt ingestion, signed policy sync, and browser-
to-upstream boundary. Current routes and fixtures must not be relabeled as this
contract without the corresponding implementation and integration evidence.

This contract implements the product-level target in
[PRODUCT_REQUIREMENTS.md](PRODUCT_REQUIREMENTS.md), preserves provenance in
[ASSURANCE_CLASSES.md](ASSURANCE_CLASSES.md), and is governed by
[ROADMAP.md](../ROADMAP.md) and [DELIVERY_DAG.yaml](DELIVERY_DAG.yaml).

## Versioning and caller boundaries

The future public management and evidence API is rooted at **/v1**. Internal
worker calls may use private interfaces but must preserve the same authenticated
scope, idempotency, audit/event, and data-classification rules.

| Caller type | Target authentication boundary | Never allowed |
|---|---|---|
| Browser user | A server-side session to the BFF. The BFF performs CSRF, origin, session, and role checks and holds any upstream service credential server-side. A browser never receives or stores a service API key. | A service API key, gate credential, signing key, or raw-secret response in browser storage, source, or logs. |
| Human API automation | Short-lived user/delegated credentials with organization/project/environment scopes and audit identity. | Agent-supplied actor/environment authority or cross-tenant resource access. |
| Workload/service client | Non-reversible, scoped, environment-bound service credential with prefix, entropy, rotation, expiry/revocation, last-used evidence, and rate limit. | A human session impersonation or a browser-delivered key. |
| Enrolled gate | Durable environment-bound gate identity plus one-time enrollment/bootstrap protocol and rotation/revocation. | A reusable bootstrap secret, cross-environment sync, or evidence acceptance without identity proof. |
| External adapter/webhook | Authenticated integration identity, narrow scope, signed delivery/provenance, replay protection, and explicit assurance class. | Treating an upstream assertion or outbound delivery as a native receipt. |

The authenticated principal and the resource relationship are the authority for
tenant, project, environment, actor, and role. Request bodies can name a
resource for lookup but cannot override authenticated runtime context. Any
mismatch is a forbidden request, not a best-effort remapping.

## Canonical resource model

~~~text
organization
 ├── project
 │    └── environment
 │         ├── enrolled gate / workload identity
 │         ├── trust material
 │         ├── signed policy bundle versions and deployment state
 │         ├── approval requests and resumptions
 │         └── receipt/evidence stream
 ├── human members and role bindings
 ├── service accounts
 ├── integrations / webhooks
 └── usage and entitlement records
~~~

| Resource | Required target identity and state |
|---|---|
| Organization, project, environment | Stable immutable IDs; parent relationships; tenant-bound authorization; environment classification and lifecycle. |
| Human/workload/gate identity | Principal type, scoped role/capability, lifecycle, issuer/key metadata, rotation/revocation and last-used evidence. |
| Policy bundle/version | Canonical bytes/content hash, signature/key id, scope, compatibility metadata, lifecycle of draft, review, active, stale, superseded, or revoked, and exactly-one-active invariant per scope. |
| Trust material | Key id, issuer, algorithm, scope, validity, trust epoch, rotation/revocation state, and no secret redisplay. |
| Approval request | Requested action digest, authority, requester/validator/approver identities, role/quorum policy, expiry/cancel/reject state, and one-time resume linkage. |
| Native receipt/evidence | Receipt digest/canonical bytes or classified reference, signature/key status, canonicalization algorithm/version plus action/argument digest, full binding hashes, assurance class, source provenance, verification state, sequence, and retention/object/checkpoint status. |
| Export/proof pack | Immutable request parameters, authorization, status, manifest digest/signature, provenance and checkpoint references, retention/legal-hold policy, and offline verifier version. |
| Usage/entitlement | Immutable, evidence-derived usage event references, server-side plan/limit/grace state, and governed administrative audit/event linkage. |
| Webhook/SIEM delivery | Destination identity, secret/key version, payload digest, delivery id, retry/dead-letter state, and delivery evidence. |

A native receipt is a pre-execution authorization artifact. Federated
attestation and observed evidence retain their original source, source-decision
digest where applicable, and immutable assurance class. No endpoint, worker,
export, dashboard, alert, or usage calculation may silently promote an
assurance class.

## Request, response, and mutation rules

### Stable envelopes

All target API responses carry a request ID and may carry a trace ID. Errors
use a stable machine-readable envelope:

~~~json
{
  "error": {
    "code": "policy_conflict",
    "title": "Policy activation conflict",
    "detail": "A different active version exists for this environment.",
    "request_id": "req_...",
    "trace_id": "trace_...",
    "retryable": false
  }
}
~~~

The code is stable within /v1. The title/detail are operator-facing and
redacted; neither contains raw credentials, access tokens, full tool
arguments, or unclassified personal/regulated data.

### Idempotency, concurrency, and pagination

- All mutating management, gate, and evidence requests require an
  Idempotency-Key. The server stores the principal, scope, endpoint, key,
  canonical request digest, first response, and expiry window.
- The same principal/scope/key/digest replays the first completed result. The
  same key with a different digest returns a conflict and performs no second
  mutation, receipt, event, or outbox delivery.
- Gate enrollment; credential creation, rotation, or revocation; policy/trust
  lifecycle; approval/resume; evidence ingestion; export job creation;
  entitlement/billing mutation; and every governed effect have no
  non-idempotent opt-out. A narrowly exceptional non-governed operational
  endpoint needs equivalent durable replay/duplicate prevention and cannot
  cause a second effect, receipt, event, outbox record, or accepted evidence.
- Conditional updates use version/ETag preconditions. Policy activation and
  approval/resume additionally have database-backed concurrency invariants.
- Collections use opaque, tenant-scoped cursor pagination with bounded page
  size. A cursor never reveals another tenant's ordering or identifier.
- Payload, batch, export-filter, and upload limits are explicit per endpoint;
  oversized inputs fail before durable acceptance.
- Long-running proof-pack and export generation creates an asynchronous job
  resource. A request does not become a completed export merely because it was
  queued.

### Mutation transaction contract

For a governed administrative mutation, authorization happens before the
governance decision. A permitted change then uses the canonical receipt path
and records the resource mutation, receipt/event, idempotency result, and
outbox entry in one database transaction. The worker owns external delivery,
object sealing, witness submission, and webhook retry state. If an external
step fails, the API and evidence state remain explicitly pending/failed/retry;
they never imply accepted, independently anchored evidence.

## Target endpoint families

These are resource families, not an assertion that every endpoint exists now.

| Family | Example target operations | Critical contract |
|---|---|---|
| Scope and members | Create/list organization, project, environment; invite/remove member; role binding/access review. | Parent scope is authenticated and tenant-bound; no URL/body comparison-only authorization. |
| Sessions and service identities | Start/end browser session through BFF; create/rotate/revoke service or gate credential. | No secret redisplay; server-side audit; rotation/revocation prevents use. |
| Gates and fleet | One-time enroll, heartbeat, capability/version report, wiring attestation, status query. | Registered, online, policy-current, proven-wired, and evidence-current are separate states. |
| Policy and trust | Draft, validate, simulate, submit/review, activate, rollback, revoke; fetch signed sync delta/LKG material. | Canonical signature/hash/scope/lifecycle; exactly one active policy; signed compatibility and staleness state. |
| Approvals | Request, inspect, approve, reject, cancel, expire, and resume. | Requester, validator, and approver separation; role/quorum; original ESCALATE not executable; one-time resume. |
| Evidence and exports | Batch ingest, verification status, query, replay, proof-pack job/download, offline verifier metadata. | Gate identity, sequence, idempotency, signature/provenance, scope, class, retention, and checkpoint before accepted state. |
| Integrations | Register/rotate/revoke webhook/SIEM adapter; signed delivery status. | Tenant scope, replay/idempotency, secret rotation, dead-letter, and no class promotion. |
| Entitlements and usage | Read plan/limits/usage; internal governed entitlement mutation; test-mode billing-event reconciliation. | Server-side enforcement, immutable accepted-evidence source, and no impact on local safety. |

## Data classification and minimization

| Data category | Target API behavior |
|---|---|
| Secrets and credentials | Accept only where necessary over protected transport; store non-reversibly or through a key provider; never return after creation or include in responses/errors/logs/telemetry/billing/evidence. |
| Action/argument payloads | Use canonicalization algorithm/version plus action/argument digest and redacted summary in default receipts and events. The executor independently recanonicalizes the actual invocation; an unknown version or mismatch fails before effect. An explicit data-classification policy is required for any encrypted payload reference, access path, retention, deletion, and export handling; a reference cannot replace the signed digest. |
| Evidence/provenance | Preserve canonical digest, signature/key status, source decision digest, assurance class, scope bindings, and verification result. |
| Personal/regulated data | Minimize collection, record classification and legal-hold/retention relationship, require tenant isolation and encryption context, and redact observability. |
| Observability and usage | Use request/trace IDs, digests, minimized outcome counters, and byte/retention measures; do not use raw arguments or credentials as analytics/billing dimensions. |

## Compatibility and generated contract policy

The OpenAPI specification is the target machine-readable contract for /v1.
A generated TypeScript client or bidirectional contract tests must prove
alignment with the single console. Compatibility requires:

- additive fields and enum values have documented tolerant-client behavior;
- breaking URL, required-field, authentication, semantic, or error-code changes
  use a new version or a published deprecation/migration window;
- receipts, policy bundles, evidence, exports, and adapter profiles retain their
  original schema/version/canonical bytes for offline verification;
- a migration cannot downgrade signature requirements, erase scope/provenance,
  or promote a weaker assurance class;
- removal follows published compatibility evidence, not a UI-only change.

No current generated client, browser authentication boundary, or OpenAPI
artifact is asserted by this policy.

## Evidence and next gate

G008 supplies only the target contract. G101-G106 must implement versioned API,
migration, tenant, credential, BFF, and canonical mutation evidence. G201-G305
must implement policy, gate, ingestion, witness, and approval evidence; G401
must prove browser wiring. Every endpoint family requires API/dispatcher/browser
wiring proof and a forbidden-side-effect negative test where it authorizes,
blocks, or resumes work.
