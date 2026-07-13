# Assurance classes and provenance contract

**Status:** Phase-0 target beta contract (G007).

**Not an implementation claim:** The classes below specify future acceptance
semantics. The G006 survey found no shipped managed ingestion, witness,
cross-platform adapter profile, or class-aware managed console.

## Current-state boundary

Current local receipts and executor controls are partial evidence only. A signer,
trusted verifier, expiry, and consumption ledger are configuration-dependent;
project/environment binding is a target requirement, not a universal current
receipt property. The local control plane and local/MCP approval surfaces do not
establish the managed evidence or approval operation defined here.
[ROADMAP.md](../ROADMAP.md) remains the sole roadmap of record.

## Target beta contract

| Class | Origin and timing | Required verifier semantics | Permitted meaning | Required rendering |
|---|---|---|---|---|
| **Native receipt** | ACGS signs before the side effect and the ACGS executor verifies before execution. | Direct executor verification of trusted key status, authenticated actor/context, exact action and canonical arguments, tenant/project/environment, policy identifier/version/canonical content hash, expiry, revocation, audit binding, and single-use consumption. | Pre-execution authorization proof only when every listed condition is met. | `native` badge/filter/export field with receipt and verifier outcome. |
| **Federated attestation** | A trusted adapter authenticates an upstream policy decision, preserves its original provenance/digest, and countersigns the mapping. | Verify upstream source, upstream key/material status, adapter identity/version, mapping, original decision digest, and countersignature. | Evidence of an upstream decision; never native assurance by equivalence. | `federated` badge/filter/export field with upstream and adapter provenance. |
| **Observed evidence** | Logs, traces, or events are collected after execution. | Verify collection provenance and integrity only; no verifier may infer a prior authorization. | Investigation, telemetry, and reconciliation evidence only. | `observed` badge/filter/export field that says post-execution. |

**Observed evidence is post-execution evidence, never pre-execution
authorization proof.** A federated record is likewise not a native receipt.

### Immutable class and no-promotion rule

`assurance_class` is immutable from intake through storage, query, UI, usage,
export, proof verification, alerting, and retention. A countersignature,
successful ingestion, hash-chain inclusion, export, or human interpretation
must not silently upgrade federated or observed evidence to native. Only a new
native transaction that satisfies the native conditions may carry `native`.

### Provenance and data minimization requirements

Target storage preserves the source identifier, source decision digest,
adapter identity/version, key identifier/status, mapping version, class, and
verification result. It must store hashes, redacted fields, or encrypted payload
references according to explicit data classification rather than raw secrets,
credentials, unnecessary tool arguments, or unrestricted personal data.

For a native receipt, the referenced policy bundle must be canonical,
content-addressed, signed, tenant/project/environment-bound, and versioned.
Its identifier, version, and canonical content hash are verifier inputs, not
display-only metadata; lifecycle validation covers draft, review, active,
stale, superseded, and revoked states.

### Adapter profile boundary

Profiles for Microsoft ACS/AGT, AWS AgentCore, OPA/Cedar, Galileo, generic MCP,
and OpenTelemetry are planned interoperability work. Mention of a profile in
this contract does not mean an adapter is shipped, trusted, interoperable, or
eligible to issue native assurance.

## Evidence and next gate

The class model is a contract for G203, G204, G301-G304, G404, and G502. It
must receive API, storage, verifier, UI, export, and negative-path tests before
any class is shown as implemented. Current local assurance limits remain in
[CLAIMS.md](../CLAIMS.md), [SECURITY_MODEL.md](../SECURITY_MODEL.md), and the
[G006 survey](CURRENT_STATE_SURVEY.md).
