---
title: Governed execution
description: How requests, receipts, executor enforcement, and audit evidence fit together.
---

# Governed execution

`gove-zone` separates decision from execution. The governance engine evaluates a
`GovernanceRequest`, emits a Decision Receipt, appends an audit event, and only
then can a receipt-gated executor call the side-effectful function.

## Local demo

```bash
uv run --package gove-zone gove-zone smoke
uv run --package gove-zone gove-zone proofpack
PYTHONPATH=packages/gove-zone/src python3 packages/gove-zone/examples/receipt_first_demo.py
```

The smoke command and demo show an allowed action, a denied action, a
missing-receipt block, a tampered-receipt block, and a verified audit chain.
The proof pack writes the same evidence into a reviewable local directory.

## Fail-closed cases

Execution is blocked when:

- no receipt is provided;
- the receipt is malformed or tampered;
- the decision is `DENY` or `ESCALATE`;
- the requested tool or args differ from the authorized action;
- a `TRANSFORM` receipt is used with the original action;
- the expected tenant, execution boundary, policy bundle, or policy hash differs
  from the receipt;
- tenant policy binding is missing or mismatched;
- audit append fails before the receipt can be returned.

## Policy engine posture

The first implementation is deterministic and local. If an OPA/Rego or remote
policy engine is wired later, missing adapter configuration must deny rather
than allow. The existing `Policy` interface is the adapter boundary.
