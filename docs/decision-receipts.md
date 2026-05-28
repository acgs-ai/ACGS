---
title: Decision Receipts
description: Canonical Decision Receipt schema and verification rules for governed execution.
---

# Decision Receipts

A Decision Receipt is the pre-execution proof artifact for one governed action.
It is emitted before the executor can perform a side effect.

## Required fields

```json
{
  "receipt_id": "rcpt_...",
  "request_id": "req-001",
  "tenant_id": "tenant-alpha",
  "actor": {"id": "agent-1", "role": "agent"},
  "subject": {"id": "workflow-1", "type": "agentic_workflow"},
  "proposed_action": {"tool": "message.send", "args": {"body": "hello"}},
  "declared_goal": "send a governed status update",
  "execution_boundary": {"environment": "local"},
  "policy_bundle_id": "bundle-alpha",
  "policy_version": "alpha/v1",
  "constitutional_hash": "<sha256 policy hash>",
  "decision": "ALLOW",
  "matched_rules": [],
  "constraints": [],
  "transformations": null,
  "approval_chain_summary": [],
  "timestamp": "2026-05-28T...Z",
  "previous_audit_hash": "0000...",
  "audit_event_hash": "<sha256 audit event hash>",
  "receipt_hash": "<sha256 canonical receipt body>",
  "signature": {"type": "unsigned-local-dev", "status": "verification-placeholder"}
}
```

`receipt_hash` is computed over the canonical authorization body excluding
`audit_event_hash`, `receipt_hash`, and `signature`. The audit event includes
the `receipt_hash`, then the returned receipt carries `audit_event_hash` so
callers can verify the receipt-to-audit linkage without creating a circular
hash. The placeholder signature is explicit so callers do not confuse local
integrity hashing with deployment signing.

## Verification rules

`verify_decision_receipt()` rejects missing fields, unknown decisions, malformed
objects, invalid signature placeholders, malformed transforms, and any receipt
hash mismatch. When called with an audit store, it also rejects invalid audit
chains and `audit_event_hash` mismatches. Tests in
`packages/gove-zone/tests/test_decision_receipt.py` and
`packages/gove-zone/tests/test_receipt_first_foundation.py` alter receipt fields
and assert verification fails.

## Transform receipts

For `TRANSFORM`, the original `proposed_action` remains in the receipt and
`transformations.proposed_action` carries the only executable replacement. The
executor rejects attempts to run the original action.
