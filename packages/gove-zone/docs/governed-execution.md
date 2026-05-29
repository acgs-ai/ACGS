# Governed Execution

> Status: foundational / Alpha. Implemented-vs-roadmap is marked below.
> gove-zone is **not** production-, compliance-, or regulator-certified.

gove-zone is **not an agent framework**. It is the enforcement layer
immediately before a high-risk side effect. Agents, MCP tools, workflow
engines, CI runners, and custom executors call gove-zone *before* they act.

## The end-to-end path

```
GovernanceRequest
  → pre-execution governance check        (policy evaluation)
  → deterministic decision                (ALLOW | DENY | TRANSFORM | ESCALATE)
  → DecisionReceipt                        (issued + anchored in the audit chain)
  → executor verifies the receipt         (fail-closed gate)
  → side effect runs ONLY for a valid ALLOW / approved-TRANSFORM receipt
  → audit evidence for the decision        (tamper-evident chain)
```

This whole thread is proven in one test — `tests/test_end_to_end.py` — and in
the runnable demo `examples/receipt-gated-execution/demo.py`.

## Issuing a receipt

`evaluate_tenant_action(...)` (`gove_zone.tenant`) is the tenant-isolated
issuer. It:

1. Fails closed if tenant identity is missing or a requester tries to load
   another tenant's bundle.
2. Loads the tenant's active policy bundle.
3. Runs the kernel (`Kernel._evaluate_and_record`), which evaluates the policy
   and appends the decision to the audit chain **before** any execution.
4. Returns a `DecisionReceipt` bound to the tenant, boundary, bundle, and audit
   anchor. Pass `expires_at` (ISO-8601) to mint a time-bounded receipt; the
   executor refuses it past expiry using timezone-aware comparison (fail-closed
   on unparseable timestamps).

The kernel itself is fail-closed: if `policy.evaluate` raises or times out, it
synthesizes a `DENY`; if the audit append fails, it raises `AuditError` — never
a silent allow (see `kernel.py`, `test_fail_closed.py`).

## Gating execution

Two equivalent entry points, both fail-closed, both backed by
`DecisionReceipt.verify`:

- **Functional:** `execute_with_receipt(tool_fn, args, receipt, *, expected_tenant_id, expected_execution_boundary, expected_action, ...)`
- **Object:** `GovernedExecutor(tenant_id=..., execution_boundary=...)` with
  registered tools, or `ReceiptVerifier(...)` for verification without a registry.

### Block rules (every one has a test)

| Condition | Result | Test |
|---|---|---|
| No receipt (`None`) | block | `test_executor_refuses_no_receipt` |
| Malformed (missing field) | block | `test_executor_refuses_malformed_receipt` |
| Tampered (`receipt_hash` mismatch) | block | `test_executor_refuses_tampered_receipt` |
| `DENY` receipt | block | `test_executor_refuses_denied_receipt` |
| `ESCALATE` receipt | block | `test_executor_refuses_escalated_receipt` |
| Wrong tenant | block | `test_executor_refuses_wrong_tenant` |
| Wrong policy bundle / hash | block | `test_policy_hash_mismatch_fails_closed` |
| Expired (`expires_at` past) | block | `test_expired_receipt_fails_closed` |
| `TRANSFORM` with un-approved args | block | `test_executor_refuses_transform_mismatch` |
| `TRANSFORM` with approved args | execute approved only | `test_transform_receipt_executes_only_approved_action` |
| Valid `ALLOW` | execute exact approved action | `test_executor_allows_valid_allowed_receipt` |

### TRANSFORM semantics

A `TRANSFORM` receipt authorizes a *modified* action. The executor refuses the
originally-proposed arguments and runs only the arguments that match the
receipt's `transformations`. The demo proves both halves: original args
refused, approved transformed args executed.

### ESCALATE semantics

An `ESCALATE` decision blocks execution. Explicit external approval that turns
an escalation into an authorization is **roadmap** — today an escalated receipt
cannot authorize a side effect.

## Roadmap

- Async dispatch shim (`await dispatch_async`).
- Approval workflow that resolves `ESCALATE` into a follow-on authorization.
- Signed receipts (see `decision-receipts.md`).

## See also

- `decision-receipts.md` — the receipt schema and verification checks.
- `policy-bundles.md` — how decisions are produced and bound to tenants.
- `audit-evidence.md` — the evidence every decision leaves behind.
