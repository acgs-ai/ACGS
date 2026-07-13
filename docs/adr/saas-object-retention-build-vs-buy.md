# ADR: SaaS evidence object retention build-vs-buy boundary

## Status

**Proposed — decision required.** This ADR is not evidence of an object store,
object lock, legal hold, encryption, retention schedule, data residency, or
durable managed evidence service.

## Date

2026-07-13

## Context

The [G006 survey](../saas/CURRENT_STATE_SURVEY.md) finds local per-organization
JSONL audit behavior and hash manifests, not a durable independently anchored
managed evidence plane. The target architecture separates PostgreSQL query
metadata from retained evidence artifacts and requires tenant isolation,
encryption context, retention, legal-hold policy, deletion, recovery, and an
offline-verifiable relationship to a witness checkpoint.

## Proposed direction pending ratification

Use a storage-provider interface for tenant-scoped artifact write/read,
immutable/versioned reference, encryption context, retention capability,
legal-hold capability, deletion request, recovery, integrity metadata, and
failure classification. PostgreSQL holds minimized metadata and lifecycle
state; the retained canonical artifact is a distinct object reference. An
artifact is not represented as sealed/accepted merely because a local hash or
database row exists.

Retention/object-lock capability is a target requirement to evaluate, not a
selection or guarantee. The implementation must preserve native/federated/
observed provenance and must not change assurance class while moving objects.

## Decision required

**Accountable owners:** platform owner and security owner; privacy/legal owner
owns retention, deletion, legal-hold, residency, and discovery decisions;
procurement participates in provider selection.

The owners must decide:

1. provider(s), regions, encryption/key integration, object immutability/
   versioning, recovery, availability, and cost model;
2. classes of evidence retained, default/customer retention windows, deletion,
   legal hold, export, and data-residency requirements;
3. tenant isolation model for bucket/container, object keys, encryption
   context, access roles, support access, and backup/restore;
4. what acknowledgement boundary qualifies as durable accepted evidence;
5. incident, subpoena/discovery, customer offboarding, and recovery handling.

## Safe fallback

Until a decision and evidence exist, do not claim durable object-retained
evidence, WORM/object-lock behavior, legal hold, residency, or deletion
guarantees. A local spool remains bounded and does not become the managed
system of record. Local enforcement remains independent of hosted retention.

## Alternatives considered

- Keep all evidence on application instance disk: rejected as a target system
  of record because it lacks managed durability/isolation/recovery properties.
- Store full raw tool arguments in every event: rejected; default evidence
  remains hashes/redacted metadata, with explicit classified encrypted
  references only where required.
- Treat a database hash chain as a retention or witness substitute: rejected.

## Consequences and non-goals

This ADR does not provide a WORM-storage replacement, legal retention advice,
certification, or an automatic deletion/hold policy. It does not pick a
provider or a retention duration.

## Evidence required after approval

- storage-provider conformance, tenant object-key/encryption-context, retention
  state, legal-hold, deletion, restore, and unauthorized-access tests;
- failure injection before/after metadata commit, object write/seal, and
  recovery/reconciliation;
- proof-pack/offline verification of object reference, provenance, manifest,
  and checkpoint relation;
- data-classification, privacy, and operator-runbook review.

## Downstream nodes and validation after unblock

Blocked/affected nodes: G301, G302, G303, G603, G606.

After approval, run G301-G303 ingestion/storage/proof tests and G603 recovery
validation from [DELIVERY_DAG.yaml](../saas/DELIVERY_DAG.yaml).
