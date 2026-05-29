# Example: receipt-gated execution

A single runnable proof of the gove-zone core invariant:

> **No valid Decision Receipt, no side effect.**

```bash
# from the monorepo root
uv run --package gove-zone python \
    packages/gove-zone/examples/receipt-gated-execution/demo.py
```

The script is an executable proof, not a slide: each scenario asserts its
expected outcome and the process exits non-zero if any invariant is violated.

Scenarios:

1. allowed action executes
2. denied action is blocked
3. missing receipt is blocked
4. tampered receipt is blocked
5. cross-tenant receipt is blocked
6. a transformed action runs **only** as approved
7. every decision left tamper-evident audit evidence

> Status: foundational / Alpha. This proves the local invariant; it is **not**
> a production, compliance, or regulator-ready certification.

See `../../docs/governed-execution.md` and `../../docs/decision-receipts.md`.
