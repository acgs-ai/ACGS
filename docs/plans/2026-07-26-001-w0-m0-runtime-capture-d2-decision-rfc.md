---
title: "W0-M0 Runtime Capture / D2 Decision RFC"
status: "APPROVED FOR INITIAL IMPLEMENTATION SLICE / NOT PRODUCTION-READY / NOT PRIVACY-APPROVED"
date: 2026-07-26
head: 596a1c0
scope: packages/gove-zone
---

# W0-M0 Runtime Capture / D2 Decision RFC

## Purpose

This RFC is a decision record, not an implementation plan. It exists to
separate the W0-M0 capture/privacy work from the runtime executor path until the
write-order and failure-semantics decision set is approved.

## Implementation Authorization Boundary

On 2026-07-27, the requesting human/user in the current task authorized
implementation of the PR #405 D2 runtime-capture choices only. That
authorization is limited to the initial runtime-capture slice described here:

- UniversalGateway issuer paths only (`invoke` and Claude hook receipt anchors);
- no DecisionReceipt schema change;
- no executor-trusted `CaptureRecord`;
- no production-readiness, privacy-compliance, qualified-corpus, or broader
  lifecycle acceptance claim;
- no merge, release, or production rollout authorization.

## Current Evidence at HEAD `314de455`

The current codebase already contains the core runtime evidence primitives:

- `DecisionRecord` is the audit unit and is emitted before a governed action
  runs. See [`decision.py`](../../packages/gove-zone/src/gove_zone/decision.py).
- `DecisionReceipt` is the canonical public receipt schema and binds proposer,
  validator, authority, policy, and signature fields. See
  [`receipt.py`](../../packages/gove-zone/src/gove_zone/receipt.py).
- `Receipt` is a separate proof-of-decision wrapper returned alongside a
  successful dispatch. See
  [`receipt.py`](../../packages/gove-zone/src/gove_zone/receipt.py).
- `ChainHashAuditStore` is the append-only hash-chained audit trail. See
  [`audit.py`](../../packages/gove-zone/src/gove_zone/audit.py).
- `ReplaySideStore` is an opt-in, off-by-default lookup table for raw call
  retention and replay. It is intentionally not a chain or authority source.
  See [`replay_store.py`](../../packages/gove-zone/src/gove_zone/replay_store.py).
- `ReceiptConsumptionStore` is the durable single-use consumption state, and it
  deliberately stores only minimal binding and digest data. See
  [`consumption.py`](../../packages/gove-zone/src/gove_zone/consumption.py).
- `kernel.py:411-416` still suppresses side-store write failures, so capture
  observation is currently non-authoritative and can be silently dropped.
- `replay_store.py` currently persists raw `tool`, `actor`, `goal`, `path`,
  `args`, `state`, `argument_hash`, `policy_version`, and `decision`, but there
  is no tenant-scoped capture API yet.
- `Receipt` and `DecisionReceipt` both remain in the codebase; the first is the
  dispatch proof wrapper and the second is the canonical public schema. The
  first runtime slice must not bump the `DecisionReceipt` schema.
- The executor boundary is already fail-closed on `expected_actor` and receipt
  verification, and the governed executor remains the final authorization
  boundary.
- `DecisionRecord` audit data includes `goal`, `reason`, and
  `transformed_args`, so the audit record is not metadata-only. See
  [`decision.py`](../../packages/gove-zone/src/gove_zone/decision.py).

The current documented security boundary remains:

> No valid Decision Receipt, no side effect.

See [`SECURITY_MODEL.md`](../../docs/SECURITY_MODEL.md) and
[`CLAIMS.md`](../../docs/CLAIMS.md).

## D2 Decision Set

### Decision 1: runtime capture write order

Recommended order:

1. evaluate
2. audit
3. capture
4. pre-execution `DecisionReceipt` issuance
5. executor PEP
6. side effect

Legacy `Receipt` remains the post-execution, non-executable proof wrapper and is
excluded from the REQUIRED authorization sequence.

Alternatives and consequences:

- capture before audit: not recommended; it weakens the audit anchor and makes
  observation harder to cross-check.
- capture after side effect: not allowed for production; it can create a false
  impression that observed execution was already authorized and recorded.
- no capture object at all: preserves current behavior, but leaves the W0-M0
  evidence gap open.

Failure policy:

- REQUIRED: fail closed, emit no executable receipt, and do not call the
  executor.
- BEST_EFFORT: local/dev only; any failure is observability-only and never a
  capture success claim.
- DISABLED: local/dev only; no capture record is created.

Capture success is only defined after a durable append succeeds. In REQUIRED
mode, a capture-store failure or an independent observation-sink failure means
no executable `DecisionReceipt` and no executor call. In BEST_EFFORT mode, the
system may emit an explicit `capture_failed` observation through a separate
sink, but that remains local/dev only and never implies capture success.
DISABLED is an explicit config choice, not an inferred fallback.

### Decision 2: legacy receipt coexistence

`Receipt` and `DecisionReceipt` already coexist and serve different roles.
This RFC treats them as pre-existing runtime primitives, not as a blocker.

- `Receipt` remains the kernel-returned local proof-of-decision wrapper.
- `DecisionReceipt` remains the canonical public schema.
- The proposed capture work must not introduce a third authority-bearing
  record.

### Decision 3: evidence envelope shape

Choose a separate, non-authoritative, versioned `CaptureRecord` for the first
runtime slice.

Recommended shape:

- `schema_version`
- `tenant_id` (even local/dev, to avoid a future migration)
- `event_id`
- `audit_event_hash`
- `policy_bundle_id`
- `policy_version`
- `policy_hash`
- `evaluator_version`
- `projection_version`
- `decision_time`
- `field_status`
- `privacy_outcome`
- `capture_outcome`
- `capture_reason`
- no raw `args`
- no raw `state`
- no `goal`
- no `reason`
- no `transformed_args`

CaptureRecord binds only to `DecisionRecord` / audit at initial write.
`Receipt` / `DecisionReceipt` remain unchanged; later correlation is derived by
shared `event_id` / `audit_event_hash`. There is no backpatch or receipt
dependency in the first slice.
Missing `policy_hash`, `policy_bundle_id`, `policy_version`, `evaluator_version`,
`projection_version`, or `decision_time` is an `insufficient-projection` case
and is never replayable.
Private replay inputs, if they exist later, remain in a separate local/dev data
plane and are not part of `CaptureRecord`.

### No-schema-bump limitation

The first runtime slice is an issuer-path precondition only:

- it does not add cryptographic `DecisionReceipt` ↔ `CaptureRecord` binding;
- it does not make `CaptureRecord` authoritative for the executor;
- it does not unlock production or qualified-corpus claims;
- any executor-enforced capture flow requires a later schema and approval step.

## Recommended Minimal First Implementation Slice

**Recommended slice: PR #404 completed the derived view; next slice is approved
runtime capture.**

The first runtime PR after approval should introduce:

1. a mode enum;
2. REQUIRED fail-closed capture behavior;
3. explicit best-effort observability;
4. default-off / backcompat preservation.

It must not claim a public production capture guarantee.

## Lifecycle Order

Proposed lifecycle order for the W0 path:

1. Phase 0: W0-M0 capture/privacy contract and evidence mapping.
2. Phase 1: W0-M1 production signing.
3. Phase 2: W0-M2 locking/durability.
4. Phase 3: qualified partner + corpus.
5. Phase 4: W3 replay diff.
6. Phase 5: W2 mining.
7. Phase 6: control plane / meta-governance.

Only Phase 0 is in scope for this RFC. The later phases remain roadmap items and
must not be pulled forward by this document.

## Authority Boundaries

The current authoritative boundary remains the governed executor path.

- Hook, middleware, and plugin surfaces are request interception surfaces only.
- External systems are adapters or evidence sources only.
- OPA, OpenTelemetry, ReBAC, and framework integrations must not become
  execution authorities.
- Final authorization remains with the executor PEP.
- Capture observations are never authority sources.
- The executor never treats `CaptureRecord` as authoritative input.

The RFC does not propose any new authority layer.

## Privacy and Tenant Unresolved Items

These items are unresolved and must be approved before any production profile.
The first local/dev slice may only reuse the existing explicit opt-in redaction
behavior and makes no privacy claim:

- whether any capture payload may retain raw arguments;
- whether tenant isolation is enforced in the capture store or only at query
  time;
- whether deletion evidence is required for capture lifecycle;
- whether PHI / PII is ever allowed in retained evidence, even in redacted form;
- whether the capture store is per-tenant, per-partner, or global with tenant
  partitioning;
- whether replayability is required for all governed actions or only for a
  supported fragment;
- whether redaction failure is tombstoned or treated as a hard reject;
- whether the capture store exposes a mandatory per-tenant storage API before
  production;
- local/dev may only reuse the existing explicit opt-in redaction behavior and
  must not claim production privacy coverage.

## Acceptance Criteria

This RFC is acceptable only if all of the following remain true:

- no new persisted core authority record is introduced;
- no runtime write-order change is made before D2 approval;
- no fail-open path is added;
- no executor boundary is weakened;
- no executor-trusted `CaptureRecord` is introduced;
- production claims remain absent until tenant/privacy prerequisites are
  satisfied;
- no sealed or generated files are edited;
- the resulting plan can be mapped back to existing runtime primitives;
- any future capture implementation remains compatible with
  `No valid Decision Receipt, no side effect`.

## Negative Tests

The eventual implementation must prove the following negative cases:

- missing receipt does not produce a side effect;
- invalid or unbound evidence does not authorize execution;
- capture-store failure does not silently downgrade authority;
- durable append failure does not produce a captured success claim;
- independent observation-sink failure in REQUIRED does not produce an
  executable `DecisionReceipt` or executor call;
- raw payloads are not retained in the authorization receipt path;
- replay without the required capture input is honestly classified as
  unsupported or incomplete;
- tenant A cannot read tenant B evidence;
- redacted evidence does not masquerade as fully replayable evidence;
- REQUIRED capture failure does not call the executor and does not produce an
  executable receipt.
- missing policy hash, bundle, evaluator, projection, or decision time is
  insufficient-projection and never replayable.
- raw args, state, goal, reason, and transformed_args are absent from
  `CaptureRecord`.
- production profile rejects BEST_EFFORT and DISABLED capture modes.
- rollback cannot downgrade REQUIRED to BEST_EFFORT or DISABLED.

## Non-Goals

- no OPA rollout;
- no Paseo integration;
- no all-agentic integration;
- no registry platform;
- no OpenFGA / SpiceDB introduction unless a real design-partner ReBAC need is
  demonstrated;
- no rewrite of the executor authority boundary;
- no production readiness claim;
- no compliance certification claim.

## Rollout / Rollback

### Rollout

1. Approve D2.
2. Implement the first runtime slice: mode enum + REQUIRED fail-closed +
   explicit best-effort observability.
3. Run an independent security review on that slice.
4. Only later, if tenant/privacy prerequisites are satisfied, move to a
   production profile.
5. Never downgrade REQUIRED to DISABLED or BEST_EFFORT by rollback; rollback
   must preserve REQUIRED semantics by refusing startup or denying issuance, or
   revert the full runtime version.

### Rollback

If any future capture change causes authority drift, rollback is to:

1. for REQUIRED mode, refuse startup or deny issuance, or revert the full
   runtime version;
2. for non-production modes, disable or remove runtime capture mode
   integration;
3. keep the existing receipt, audit, and executor paths intact;
4. preserve all current fail-closed checks.

## Human Approval Record

Decision: [x] APPROVE INITIAL IMPLEMENTATION SLICE  [ ] REJECT

Approver role: requesting human/user in current task
Approver name: not recorded in this RFC; do not infer identity from the tool session
Signature date: 2026-07-27
Scope: PR #405 D2 runtime-capture choices only; no production, privacy, qualified
corpus, merge, release, or broader lifecycle approval.

Approved choices to initial if approved:

- [x] evaluate → audit → capture → pre-execution `DecisionReceipt` issuance →
  executor PEP → side effect
- [x] separate non-authoritative versioned `CaptureRecord` with no
  `DecisionReceipt` schema bump in the first runtime slice
- [x] CaptureRecord uses the pre-receipt fields listed in Decision 3
- [x] CaptureRecord carries no raw args, state, goal, reason, or transformed_args
- [x] missing policy hash / bundle / evaluator / projection / decision time is
  insufficient-projection and never replayable
- [x] private replay inputs, if any, remain in a separate local/dev data plane
- [x] REQUIRED means fail closed, no executable receipt, no executor call
- [x] REQUIRED capture-store failure or observation-sink failure blocks
  `DecisionReceipt` issuance and executor invocation
- [x] BEST_EFFORT / DISABLED are local-dev only
- [x] BEST_EFFORT emits explicit `capture_failed` observation through a
  separate sink
- [x] DISABLED is an explicit config choice, not an inferred fallback
- [x] existing audit decision remains, plus separate capture-failure observation
- [x] capture failure observation is logged / metered and never claimed as
  captured
- [x] per-tenant storage API is mandatory before production
- [x] no production claim
- [x] `Receipt` remains post-execution and non-executable in the authorization
  sequence

## Notes on Current Merge-Ready State

This RFC is intentionally weaker than any runtime implementation claim. It
creates a documentation and decision boundary only. It does not change:

- executor PEP authority;
- receipt validation;
- audit hashing;
- consumption atomicity;
- replay semantics;
- managed side-effect routing.
