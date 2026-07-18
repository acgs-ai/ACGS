# SaaS beta product requirements

**Status:** Phase-0 target beta contract (G007).

**Not an implementation claim:** This document defines the acceptance contract
for future work. It does not assert a deployed managed service, customer use,
production readiness, certification, or a completed commercial offering.

## Current-state boundary

The frozen [G006 survey](CURRENT_STATE_SURVEY.md) is the factual baseline. It
records a partial local receipt/executor foundation and a local alpha
control-plane surface, but not a managed canonical transaction spine, managed
evidence plane, browser/BFF integration, policy sync, durable spool, witness,
or billing implementation. In particular:

- receipt signing, expiry, and single-use are configuration-dependent local
  controls; a consumption ledger is required for one-time use;
- current receipt data does not yet provide the target project/environment
  binding required below;
- the surveyed control plane uses a legacy receipt path and file-backed audit
  behavior; it is not evidence of the target managed plane.

The local-runtime limits remain governed by [CLAIMS.md](../CLAIMS.md) and
[SECURITY_MODEL.md](../SECURITY_MODEL.md). [ROADMAP.md](../ROADMAP.md) remains
the single roadmap of record.

## Target beta contract

### Three deliberately separated planes

1. **Open local execution and data plane.** The customer-colocated gate
   evaluates local policy and verifies the receipt at the executor boundary.
   It has no mandatory hosted authorization call in the side-effect hot path.
   Signing, trusted verification, anti-replay, local audit/replay, proof packs,
   CLI support, and conformance testing remain available without entitlement.
2. **Managed control plane.** A future modular-monolith control plane manages
   tenant scope, projects, environments, identities, policies, approvals,
   trust material, fleet status, and governed administrative mutations. It
   distributes signed, versioned, scope-bound policy and trust material; it is
   not a remote per-call allow service.
3. **Managed evidence and assurance plane.** A future asynchronous service
   accepts, verifies, retains, queries, exports, and independently checkpoints
   evidence. Its paid value is evidence and control operations, not permission
   to bypass the local gate.

### First complete customer journey

The target acceptance journey is: create organization/project/environment;
enroll a local gate; publish and activate a canonical, signed, scope-bound
policy bundle; prove dispatcher wiring; execute one native `ALLOW`; prove
`DENY` has zero side effects; park an `ESCALATE`; reject self-approval; obtain
a policy-authorized separated approval and resume exactly once; asynchronously
ingest verified evidence; display its assurance class; export a proof pack; and
verify the export offline. Each step requires its own code, integration, and
negative evidence gate before it may be described as implemented.

### Target beta invariants

- No valid Decision Receipt, no side effect; `DENY` and `ESCALATE` are never
  executable.
- A target native authorization binds tenant, project, environment,
  authenticated actor, authority, action, canonical arguments, policy
  identifier, version, canonical content hash, validator, execution boundary,
  expiry, key identifier, and audit anchor.
- A target policy bundle is canonical, content-addressed, signed,
  tenant/project/environment-bound, and versioned; it has draft, review,
  active, stale, superseded, and revoked lifecycle states.
- The executor, not an agent-controlled request body, obtains expected actor
  and environment identity from authenticated runtime context.
- Missing, tampered, replayed, consumed, expired, revoked, stale, or
  scope-mismatched artifacts cause zero side effects.
- Managed-plane mutations either fail authentication/RBAC before governance or
  use the same canonical receipt, side-effect, event, outbox, and evidence
  transaction contract.
- A high-risk approval separates requester, policy validator, and authorized
  approver; self-approval is rejected. Policy can require quorum and role
  constraints, and concurrent/retried approval processing cannot resume the
  same side effect more than once.
- Assurance provenance and data classification follow the
  [assurance-class contract](ASSURANCE_CLASSES.md); a record is never promoted
  to a stronger class because it was exported, countersigned, or ingested.

### Outage and degraded-mode contract

This is a target acceptance contract, not a current hosted capability. Hosted
loss must never yield allow-by-default. Only a signed, tenant/project/
environment-bound, unexpired last-known-good policy may be used locally within
an explicit degraded-mode validity window. New policy activation, trust change,
and approval fail closed while hosted state is unavailable. Evidence buffers
under a bounded, durable rule; exhaustion of the configured high-risk spool
path fails closed rather than silently discarding required evidence.

### Deliberate non-goals

ACGS is not an agent framework, model host, prompt/content-moderation product,
sandbox, SIEM, IAM/PKI/KMS replacement, generic marketplace, or a cloud
authorization dependency for each side effect. It is designed to compose with
policy engines, gateways, identity systems, guardrails, storage, and existing
agent runtimes.

## Evidence and next gate

G007 is satisfied only by reviewed contract documents and regression checks. It
does not implement the target planes. G008 must define architecture, threat,
API/data, migration, and owner-gated build-vs-buy decisions; G101-G606 then
provide implementation evidence. See [DELIVERY_DAG.yaml](DELIVERY_DAG.yaml)
and [ACCEPTANCE_MATRIX.md](ACCEPTANCE_MATRIX.md).
