# Decision Receipt specification

This is the public contract for integrators that want to place ACGS / gove-zone before side-effectful execution.

The Decision Receipt is the **vendor-neutral evidence artifact** at the center of ACGS: a single record that binds actor, action, arguments, policy, authority, and audit anchor for one decision. Its fields carry no framework- or model-specific shape (see the schema below and `receipt.py`), so the same record format describes a governed action whether the call came from a hook host, an MCP gateway, a function-call bridge, or a custom executor — and it is the artifact a team keeps regardless of which runtime it later switches to.

> Scope note (fail closed): the *format* is vendor-neutral and implemented today. Making receipts verifiable across multiple independent agent hosts via reference validators is on the [roadmap](ROADMAP.md) ("standard receipt schema for agent runtimes"), not a current cross-host portability guarantee.

Core invariant:

> **No valid Decision Receipt, no side effect.**

## Status

Implemented locally in `packages/gove-zone/src/gove_zone/receipt.py` as `DecisionReceipt`. This is alpha (`0.1.0.dev0`) and not a compliance certification.

## Schema

| Field | Required | Binding role |
|---|---:|---|
| `receipt_id` | yes | Unique receipt/event id. |
| `request_id` | yes | Caller correlation id. |
| `tenant_id` | yes | Tenant boundary; cross-tenant reuse fails. |
| `actor` | yes | Principal proposing the action. |
| `subject` | no | Optional resource/person/object label. |
| `proposed_action` | yes | Tool/action name. |
| `declared_goal` | yes | Human-readable intent. |
| `execution_boundary` | yes | Boundary where execution is allowed. |
| `policy_bundle_id` | yes | Stable policy bundle id. |
| `policy_version` | yes | Policy version string. |
| `policy_hash` | yes | Policy content/version hash binding. |
| `decision` | yes | `allow`, `deny`, `transform`, or `escalate`. Only `allow` and approved `transform` can execute. |
| `action_tier` | no | Policy-routing tier: `explore` or `commit`. `commit` is the strict default; unknown/missing coerces to `commit`. Bound into `receipt_hash`. Legacy receipts without it default to `commit`. |
| `matched_rules` | yes | Rule ids or policy reasons that fired. |
| `constraints` | yes | Free-form decision constraints. |
| `transformations` | yes | Approved transformed args as `{field, value}` entries. Empty for non-transform. |
| `approval_chain_summary` | yes | Proposer/validator/authority linkage. |
| `timestamp` | yes | ISO-8601 issuance time. |
| `expires_at` | no | ISO-8601 expiry. Empty means no expiry. Bound into hash. |
| `authority` | yes | Authority grant used by validator. |
| `validator_id` | yes | Principal validating the action. Must differ from actor/caller. |
| `validator_role` | yes | Validator role. |
| `argument_hash` | yes | SHA-256 over canonical JSON args. |
| `previous_audit_hash` | yes | Previous hash-chain head. |
| `audit_event_hash` | yes | Audit event hash anchoring this decision. |
| `signature_algorithm` | yes | `none` or `ed25519`. Bound into receipt hash. |
| `signing_key_id` | yes | Key id for signature verification. Bound into receipt hash. |
| `receipt_hash` | yes | SHA-256 over canonical receipt JSON except `receipt_hash` and `signature`. |
| `signature` | yes | `unsigned_local` or signature over `receipt_hash`. |

## Three distinct schemas — do not conflate

The table above is the **Decision Receipt** schema and is the only one of the
three that is a receipt. Two adjacent record formats are versioned and evolve
independently:

| Artifact | Where | What it is | Version/field note |
|---|---|---|---|
| **Decision Receipt** | `receipt.py` (`DecisionReceipt`) | The authorization artifact for one decision, hash-bound and optionally signed. | The schema table above. It has **no** lifecycle fields and **no** `record_kind`. |
| **Consumption-store schema v4** | `consumption.py` (`_SCHEMA_VERSION = 4`) | Persistent single-use consumption, receipt revocation, idempotency binding, and terminal state (`RESERVED` → `SUCCEEDED`/`UNKNOWN`). Stores tenant-scoped HMAC-SHA-256 digests only — never raw nonces, raw idempotency keys, receipt bodies, or arguments. | "v4" is the **store** schema. It is **not** Decision Receipt schema v4 and not a signing-key revocation service. |
| **Audit record kind + lifecycle attestation** | `decision.py` (`RecordKind`, `DecisionRecord.lifecycle`), `signing.py` (`LifecycleAttestation`), `authorization.py` (`ExecutionRefusalEvidence`) | An authenticated audit-record classification with **three** kinds — `POLICY_DECISION`, `EXECUTION_LIFECYCLE`, and `EXECUTION_REFUSAL` — plus, for lifecycle records, an Ed25519 attestation and, for refusal records, execution-refusal evidence. | `record_kind` is an **audit-record** field. It is not a receipt field and not a consumption-schema field. |

### Lifecycle attestation

An execution-lifecycle audit record carries a `LifecycleAttestation` — an
independent authorization proof for one exact lifecycle record.

- **Evidence.** `execution_evidence` binds tenant, execution boundary, adapter id
  and pinned adapter artifact digest, receipt id/hash, authorization audit hash,
  tenant-bound nonce and idempotency digests, `attempt_id`, `binding_hash`,
  `argument_hash`, `phase` (`claim_committed` / `terminal`), `reason_code`, and
  `consumption_state`.
- **Signing payload.** `lifecycle_signing_payload(payload)` is canonical JSON over
  the full record **excluding** `lifecycle_attestation` itself, under the domain
  separator `gove-zone:lifecycle-authorization:v1`. Supplying a payload that
  already contains an attestation is rejected. `payload_hash` must be SHA-256.
- **Trust roots are independent.** Lifecycle authorities live in a frozen,
  immutable `LifecycleVerifierRegistry` keyed by authority id, snapshotting raw
  Ed25519 public-key bytes. The lifecycle authority is **separate from the audit
  checkpoint authority**: the executor refuses to append a lifecycle record when
  the lifecycle signer's `key_id` equals the checkpoint `key_id`, or when the
  lifecycle authority id collides with `audit-checkpoint` /
  `audit-checkpoint:<namespace>`. This yields two distinct verification
  identities/roots; separate physical custody is an operator responsibility —
  the code enforces distinct `key_id`/authority identities, not that different
  people or systems hold the keys.
- **Fail closed.** Unsigned attestations are refused at construction
  (`unsigned lifecycle attestations are not trusted`). Strict replay rejects a
  lifecycle record whose attestation is missing, malformed, or unverifiable, and
  forbidden key/authority ids can be excluded explicitly.
- **Legacy.** Records predating `record_kind` deserialize as `POLICY_DECISION`.
  They are **policy-compatible only** — an old unattested record can never be
  promoted into execution-lifecycle evidence, and `from_dict` refuses to let a
  policy record acquire lifecycle material.

Evidence: `decision.py`, `signing.py`, `executor.py`, `replay.py`,
`tests/test_lifecycle_verifier_registry.py`.

### Execution-refusal evidence

`EXECUTION_REFUSAL` is a first-class third `record_kind`, distinct from both
`POLICY_DECISION` (no policy was re-evaluated) and `EXECUTION_LIFECYCLE` (no
attempt was reserved-and-run). It records that a final execution gate refused a
bound attempt **before any adapter ran**, and it never reuses either other
schema.

- **What it proves.** `ExecutionRefusalEvidence` (v1) is integrity evidence that
  one bound attempt *never reached an adapter*: `adapter_invoked` is always
  `False` and the type refuses to represent a claim that the adapter ran. Only
  reason codes that prove the adapter was never entered may be carried; codes
  that describe a possibly-mid-flight or post-adapter state — `TIMEOUT`,
  `OUTCOME_UNKNOWN`, `ADAPTER_FAILED`, `SUCCEEDED` — are rejected at
  construction. A refusal record must be non-executable (`DENY`) and must not
  carry a lifecycle attestation.
- **What it is not.** A refusal record must **never** be used to represent
  `OUTCOME_UNKNOWN`. `OUTCOME_UNKNOWN` means the adapter may already have acted
  (see the exactly-once boundary below); that ambiguity is carried only by a
  terminal `EXECUTION_LIFECYCLE` record, never by refusal evidence.

Evidence: `authorization.py` (`ExecutionRefusalEvidence`, `ExecutionReasonCode`,
`EXECUTION_REFUSAL_REASON_CODES`), `decision.py` (`RecordKind`),
`side_effect_kernel.py`, `release_proof.py`.

## Actor binding

The receipt's `actor` is the proposer. The executor must supply `expected_actor` from trusted runtime context. The verifier rejects a receipt issued for a different actor and rejects a receipt where the invoking principal is also the validator.

Evidence: `receipt.py`, `executor.py`, `contracts.py`, `tests/test_maci_role_separation.py`, `tests/test_executor_guard.py`.

## Action binding

`proposed_action` must match the action about to execute. A receipt for `runtime.file.write` cannot authorize `runtime.shell.run`.

Evidence: `tests/test_decision_receipt.py`, `tests/test_executor_guard.py`.

## Argument binding

For `ALLOW`, the executor hashes the arguments about to run and compares them to `argument_hash`. For `TRANSFORM`, the executed args must exactly match the approved transformed arguments.

Evidence: `tests/test_argument_binding.py`, `tests/test_executor_guard.py`.

## Policy binding

`policy_bundle_id`, `policy_version`, and `policy_hash` bind a receipt to a policy context. The gate can require expected policy id/hash and reject substitutions.

Evidence: `tests/test_policy_bundle_io.py`, `tests/test_tenant_safety.py`.

## Action tier

`action_tier` separates information-gathering (`explore`) actions from goal-executing (`commit`) actions. It is a *policy-routing* dimension — it changes which rules match, never whether the receipt gate applies. Every tier still requires a valid receipt, `expected_actor`, and an audit append; `DENY`/`ESCALATE` stay non-executable for all tiers.

The declared tier travels as untrusted input on the call (`state["action_tier"]`). A tool-tier registry is authoritative: the effective tier is `min(declared, registered)` with `commit` as the strict top value, so a tool the registry marks commit-only can never be evaluated under `explore` regardless of what the caller declares. No registry, or an unregistered tool, means `commit`. The registry is content-addressed and folds into the policy version/hash.

`action_tier` is bound into `receipt_hash`, so a post-issuance tier swap fails verification. `from_dict` defaults a missing field to `commit` (legacy compatibility). The verifier rejects unknown tier strings, and — when a registry is supplied at the gate — refuses an `explore` receipt for a commit-only tool as a belt-and-suspenders check against the policy-side evaluation. The registry is manual/declarative in v1: it is not semantic detection of whether a tool has side effects; operators must register side-effecting tools as `commit` (which is already the default).

Evidence: `decision.py` (`ActionTier`), `tier.py` (`ToolTierRegistry`), `policy.py` (rule `tiers` criterion), `receipt.py`, `tests/test_action_tiering.py`.

## Expiry

`expires_at` is optional. When set, it is bound into `receipt_hash`; expired or unparseable timestamps fail closed.

Evidence: `tests/test_receipt_expiry.py`.

## Validator identity and self-validation

The validator is distinct from the actor. `DecisionReceipt.from_record` refuses to mint self-validated receipts, and the gate refuses receipts whose validator is the invoking actor.

Evidence: `receipt.py`, `tests/test_maci_role_separation.py`.

## Signature behavior

Default local mode is unsigned: `signature_algorithm="none"`, `signature="unsigned_local"`. This is for development/local proof. It is not a production signing claim.

**Unsigned mode is a low-level compatibility affordance only.** It exists so the
low-level receipt APIs (`DecisionReceipt.verify`, `ReceiptVerifier`) remain usable
for local development and policy projection. It is *rejected* by every strict
path: strict standalone execution verifies with `require_signature=True`, and the
P0 Release Gate, P1 MCP Gateway, and P2 Spend Guard managed paths require a
trusted signature. An unsigned receipt cannot authorize a strict side effect and
must never be presented as production evidence.

Opt-in signing uses Ed25519:

- signer signs `receipt_hash` with a private key;
- executor verifies with the trusted public key;
- `require_signature=True` rejects unsigned receipts;
- signed receipts presented without a verifier fail closed;
- key id and algorithm are bound into `receipt_hash` to prevent downgrade.

Evidence: `signing.py`, `tests/test_receipt_signing.py`.

## Hash behavior

`receipt_hash = sha256(canonical_json(receipt_without_receipt_hash_and_signature))`.

Changing any bound field without reissuing the receipt produces a hash mismatch. Recomputing a hash without a trusted signature is not production-grade proof; signing mode closes that residual only when engaged.

## Validation algorithm

Verifier rejects on the first failure:

1. required fields missing or empty;
2. missing or mismatched `receipt_hash`;
3. signed receipt without a configured verifier;
4. invalid signature;
5. unsigned receipt when signature is required;
6. actor mismatch or self-validation;
7. approval-chain summary disagreement;
8. unknown decision;
9. `deny` or `escalate` decision;
10. tenant mismatch;
11. execution-boundary mismatch;
12. action mismatch;
13. audit hash mismatch;
14. malformed transformations;
15. transform mismatch or extra/missing transformed args;
16. allow argument mismatch;
17. policy hash mismatch;
18. policy bundle id mismatch;
19. validator role or authority mismatch when required;
20. expired or unparseable expiry.

## Strict execution algorithm

Receipt verification above is step 1 of the strict path, not the whole path. The
strict standalone and managed paths extend it:

1. **Verify the receipt** (the algorithm above), with `require_signature=True`
   and a trusted verifier.
2. **Claim durably and atomically.** `reserve` the receipt in the anchored
   schema-v4 consumption store under a fresh `attempt_id`, binding the receipt
   hash, the tenant-scoped nonce digest, the idempotency digest, and the
   `binding_hash` (actor/action/args/adapter identity + pinned adapter artifact
   digest). Replay, revocation, or store failure ⇒ DENY and fail-stop with no
   execution. The refusal is appended as audit evidence only while the audit
   dependency remains available; if the audit sink is itself unavailable the
   path still refuses to execute, but an audited DENY record cannot be
   guaranteed.
3. **Commit an attested lifecycle claim.** Append an `EXECUTION_LIFECYCLE` audit
   record at `phase="claim_committed"`, signed by the lifecycle authority and
   checkpointed. This happens **after** the reservation and **before** the
   adapter runs. If the append fails, the path attempts a best-effort mark of the
   reservation as `UNKNOWN` and then fail-stops — the adapter is not invoked. If
   the consumption store or audit dependency is itself unavailable, that
   `UNKNOWN` mark may not be confirmed, so terminal lifecycle evidence is
   recorded only when those dependencies remain available.
4. **Make at most one adapter attempt**, gated on the claim being committed. The
   reservation is re-read and must still be `RESERVED` with the same
   `attempt_id`, `binding_hash`, and idempotency digest; revocation is
   re-checked; the receipt is re-verified immediately before the call. Any of
   these revalidations can fail-stop the attempt before the adapter callable
   runs, so "at most one attempt" is the bound — not "exactly one".
5. **Commit a terminal lifecycle record.** Either `SUCCEEDED` (the adapter
   confirmed success) or `UNKNOWN` (ambiguous outcome, exception, or unconfirmed
   state), each appended as an attested `EXECUTION_LIFECYCLE` record at
   `phase="terminal"`. This terminal record is recorded only while the
   consumption store and audit dependencies remain available; if either is
   unavailable the path fail-stops, and the terminal state may be unconfirmed
   rather than durably recorded.
6. **Deny later reuse.** A receipt in a terminal state — `SUCCEEDED` *or*
   `UNKNOWN` — is not re-authorizable. There is no blind retry of an `UNKNOWN`.

### Reconciliation requirement and the exactly-once boundary

`UNKNOWN` means ACGS does not know whether the side effect happened. The kernel
deliberately refuses to guess: it will not retry, because a retry could duplicate
a real effect. **Operators must reconcile `UNKNOWN` records against the
downstream system out of band.** The lifecycle evidence identifies exactly which
attempt is unresolved; resolving it is outside ACGS.

Consequently the guarantee is **at-most-once authorized attempt, not exactly-once
effect**. Exactly-once effect is not claimed and cannot be, since the downstream
adapter may already have acted before the outcome became ambiguous.

## Deployment artifact digest binding (P0 Release Gate)

The P0 Release Gate binds the deployment **artifact digest** into the receipt
argument (`artifact_digest` — a lowercase SHA-256) and into the executor
`binding_hash`. The bytes and pathname of the artifact are **not** part of the
receipted arguments and are **not** serialized into the receipt or the exported
proof pack:

- The immutable byte snapshot the kernel captures immediately before the final
  adapter boundary is *execution-local*. Only its recomputed digest is compared,
  constant-time, against the receipted `artifact_digest`; the snapshot itself,
  the source pathname, and the raw bytes are never written into the receipt or
  the proof pack. A mutable lexical path is never treated as proof.
- `PolicyArtifactAttestation` binds the content-addressed *policy* artifact only.
  It attests which policy authorized the decision; it never covers the
  deployment bytes. Policy-artifact attestation and deployment-artifact digest
  binding are two independent bindings — do not present one as evidence of the
  other.

A pre-adapter refusal caused by an artifact that no longer matches its receipted
digest is a `FAILED_CLOSED` denial with an `EXECUTION_REFUSAL` record proving the
adapter was never entered — distinct from a post-adapter `OUTCOME_UNKNOWN` (see
below). Evidence: `release_gate.py` (`RELEASE_ARTIFACT_ARGUMENT`,
`RELEASE_ARTIFACT_SNAPSHOT_PARAMETER`, atomic `register_route` /
`register_artifact_requirement`), `path_capability.py`
(`ImmutableArtifactSnapshot`, `capture_immutable_artifact`), `release_proof.py`.

## FAILED_CLOSED versus OUTCOME_UNKNOWN

Two refusal shapes are deliberately kept distinct, because they carry different
residual risk:

- **`FAILED_CLOSED`** — the gate refused *before* the adapter was entered
  (`adapter_attempted=False`). No side effect can have occurred. The Release Gate
  reports this as `decision="DENY"` / `execution_status="FAILED_CLOSED"` and
  emits an `EXECUTION_REFUSAL` record.
- **`OUTCOME_UNKNOWN`** — the adapter was entered and the outcome became
  ambiguous. The side effect may already have happened. The Release Gate reports
  this as `decision="UNKNOWN"` / `execution_status="OUTCOME_UNKNOWN"`; there is
  **no blind retry**, and the receipt is not re-authorizable once the terminal
  `UNKNOWN` is confirmed.

`decision="UNKNOWN"` is never downgraded to a proven `DENY`, and a `FAILED_CLOSED`
refusal is never labelled `UNKNOWN`. Evidence: `release_proof.py` (the
`FAILED_CLOSED`/`OUTCOME_UNKNOWN` and `decision` branch), `side_effect_kernel.py`.

## Invalid receipt cases

- Missing receipt: no side effect.
- Malformed receipt: no side effect.
- `DENY`/`ESCALATE`: no side effect.
- Valid receipt for another tenant/action/actor/args/policy: no side effect.
- Expired receipt: no side effect.
- Signed receipt with unknown key or bad signature: no side effect.
- Unsigned receipt when `require_signature=True`: no side effect.

## Minimal valid receipt example

Illustrative only; use the Python API to mint hashes correctly.

```json
{
  "receipt_id": "ev_abc123",
  "request_id": "req-1",
  "tenant_id": "tenant-A",
  "actor": "agent-1",
  "subject": "",
  "proposed_action": "runtime.file.write",
  "declared_goal": "write approved evidence",
  "execution_boundary": "local-sandbox",
  "policy_bundle_id": "policy-A",
  "policy_version": "policy-A/v1",
  "policy_hash": "policy-hash",
  "decision": "allow",
  "matched_rules": [],
  "constraints": {},
  "transformations": [],
  "approval_chain_summary": {"proposer": "agent-1", "validator_id": "constitutional-council", "authority": "tenant-A/write-grant"},
  "timestamp": "2026-06-06T00:00:00+00:00",
  "expires_at": "",
  "authority": "tenant-A/write-grant",
  "validator_id": "constitutional-council",
  "validator_role": "validator",
  "argument_hash": "sha256-of-canonical-args",
  "previous_audit_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "audit_event_hash": "audit-event-hash",
  "signature_algorithm": "none",
  "signing_key_id": "",
  "receipt_hash": "computed-receipt-hash",
  "signature": "unsigned_local"
}
```

## Invalid example: argument substitution

A receipt issued for:

```json
{"path":"/tmp/safe.txt","content":"ok"}
```

must not authorize:

```json
{"path":"/etc/shadow","content":"pwned"}
```

`execute_with_receipt(..., expected_args=about_to_run_args)` catches this with `argument mismatch`.

## Compatibility guidance for external runtimes

- Treat the receipt as a narrow authorization for one actor/action/argument/policy context.
- Store receipts with audit anchors; do not store only model text.
- Always verify at the executor boundary, not only in a planner or prompt.
- Pass `expected_actor`, `expected_action`, `expected_args`, tenant, boundary, and policy expectations from runtime context.
- Use signing mode for production-adjacent pilots; do not promote unsigned local mode as production security.
- Keep direct tool implementations private behind the gate.
