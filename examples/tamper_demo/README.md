# Tamper demo

Shows receipt tampering, argument substitution, and audit-chain tampering failures.

Run:

```bash
uv run --package gove-zone python examples/tamper_demo/demo.py
```

Expected output: JSON with:

- `valid_receipt_executed: true`
- `tampered_receipt_blocked: true`
- `argument_mismatch_blocked: true`
- `audit_chain_valid_before_tamper: true`
- `audit_chain_valid_after_tamper: false`

Failure case: the demo edits a receipt field and later edits persisted audit JSONL. Both are detected before being treated as valid evidence.

What is proven: a valid Decision Receipt is narrow; tampering with receipt fields or replay evidence does not silently authorize a side effect.

This example is local-only. It proves executor placement and failure behavior; it does not prove production deployment, compliance certification, or live framework integration.
