# Decision Receipts

> Status: foundational / Alpha (`0.1.0.dev0`). This document describes what is
> implemented in code today and what is roadmap. gove-zone is **not**
> production-, compliance-, or regulator-certified.

A **Decision Receipt** is the verifiable proof-of-decision artifact that gates
every governed side effect. The core invariant is:

> **No valid Decision Receipt, no side effect.**

A receipt is issued by the governance check *before* execution and verified by
the executor *before* the side effect runs. If verification fails for any
reason, execution is refused (fail-closed).

## Schema

Implemented as the frozen dataclass `gove_zone.receipt.DecisionReceipt`
(`src/gove_zone/receipt.py`). Serialization is canonical JSON (sorted keys),
and the receipt is self-hashing.

| Field | Type | Meaning |
|---|---|---|
| `receipt_id` | str | Unique id of this receipt (derived from the decision event id). |
| `request_id` | str | Caller-supplied correlation id for the originating request. |
| `tenant_id` | str | Tenant the receipt was issued for. Bound; cross-tenant use is refused. |
| `actor` | str | Identity that proposed the action. |
| `subject` | str | Optional subject/resource label. |
| `proposed_action` | str | The tool/action name the decision authorizes. |
| `declared_goal` | str | The high-level intent recorded for replay/debug. |
| `execution_boundary` | str | Where the approved action may run (e.g. `local-sandbox`). Bound. |
| `policy_bundle_id` | str | Id of the policy bundle that produced the decision. |
| `policy_version` | str | Version label of the policy bundle. |
| `policy_hash` | str | Content hash of the policy bundle (tamper-evidence for the policy). |
| `decision` | str | One of `allow`, `deny`, `transform`, `escalate`. |
| `matched_rules` | list[str] | Rule ids that fired. |
| `constraints` | dict | Decision-scoped constraints (free-form). |
| `transformations` | list[{field,value}] | For `transform`: the approved argument overrides. |
| `approval_chain_summary` | dict | Summary of any approval chain (for `escalate`/manual approval). |
| `timestamp` | str | ISO-8601 issuance time. |
| `expires_at` | str | Optional ISO-8601 expiry. Empty = no expiry. Bound into the hash. |
| `previous_audit_hash` | str | The audit chain head the decision linked from. |
| `audit_event_hash` | str | The audit event hash the decision anchored to. |
| `receipt_hash` | str | SHA-256 over all fields except `receipt_hash`/`signature`. |
| `signature` | str | Signature placeholder (`unsigned_local` today — see Roadmap). |

`receipt_hash` is computed by `compute_hash()` over the canonical JSON of every
field except `receipt_hash` and `signature`. Because `expires_at` and the
policy/tenant/boundary fields are inside the hash, altering any of them without
re-issuing is detected as tampering.

## Verification (fail-closed)

`DecisionReceipt.verify(...)` performs all of the following and raises
`ReceiptValidationError` on the first failure (see `test_decision_receipt.py`):

1. Required fields present and non-empty.
2. `receipt_hash` present and matches a recomputation (catches any tampering).
3. `decision` is a known value.
4. `decision` is not `deny` and not `escalate` (those never authorize execution).
5. `tenant_id` matches the executor's expected tenant.
6. `execution_boundary` matches the executor's expected boundary.
7. `proposed_action` matches the expected action.
8. `audit_event_hash` matches the expected anchor (when supplied).
9. `transformations` are well-formed (`{field, value}` dicts, string fields).
10. For `transform`: each transformed field matches the execution arguments.
11. `policy_hash` matches the expected policy hash (when supplied).
12. `policy_bundle_id` matches the expected bundle id (when supplied).
13. `expires_at` (when set) is not in the past. The clock is injectable
    (`now_iso=`) for deterministic testing; defaults to UTC wall time.

A `None` receipt is refused before verification by both the functional gate
(`execute_with_receipt`) and the OO gate (`ReceiptVerifier`).

## Named contract vocabulary

The typed contract layer (`gove_zone.contracts`) names the concepts the receipt
flow uses:

| Contract | Role |
|---|---|
| `ProposedAction` | The action proposed for governance (tool + args + goal), pre-decision. |
| `ExecutionBoundary` | Typed alias for the boundary label string. |
| `GovernanceRequest` | The full pre-execution check input (identity + action + boundary). Fails closed on missing tenant/request id. |
| `PolicyBundleRef` | Stable reference to the bundle that governed a decision. |
| `TenantPolicyBinding` | Tenant ↔ bundle pairing. |
| `ReceiptVerifier` | Reusable typed wrapper over `DecisionReceipt.verify` (same gate). |
| `AuditEvent` | Typed projection of one persisted audit event joined to its receipt. |

These are additive: they do not replace the existing string-based fields or
introduce a second enforcement path. The single fail-closed gate remains
`DecisionReceipt.verify`.

## Roadmap (not implemented today)

- **Cryptographic signatures.** `signature` is a placeholder (`unsigned_local`).
  Integrity rests on `receipt_hash` + the tamper-evident audit chain, not on a
  public-key signature. Signed receipts are roadmap.
- **Bundle lifecycle state.** Receipts reference a bundle id + hash; active /
  stale / revoked lifecycle is not modeled (see `policy-bundles.md`).
- **Distributed receipt storage / revocation lists.** Out of scope for the
  local kernel.

## See also

- `governed-execution.md` — how receipts gate execution end to end.
- `audit-evidence.md` — the audit chain receipts anchor to.
- `examples/receipt-gated-execution/demo.py` — runnable proof of every rule above.
