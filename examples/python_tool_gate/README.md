# Python tool gate example

Shows a plain Python side-effect function protected by a Decision Receipt gate.

Run:

```bash
uv run --package gove-zone python examples/python_tool_gate/demo.py
```

Expected output: JSON with `status: "pass"`, `valid_receipt_executed: true`, `missing_receipt_blocked: true`, and `side_effect_count: 1`.

Failure case: the same function is called with `receipt=None`; the governed executor raises `ReceiptValidationError` and the side effect counter does not increment.

What is proven: a normal Python function can remain unchanged while the wrapper enforces **No valid Decision Receipt, no side effect.**

This example is local-only. It proves executor placement and failure behavior; it does not prove production deployment, compliance certification, or live framework integration.
