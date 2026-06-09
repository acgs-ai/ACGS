# Five-minute demo script

Goal: make the invariant emotionally and technically obvious.

> **No valid Decision Receipt, no side effect.**

## Setup line

"This is not another agent framework. The agent can ask. The executor must verify a Decision Receipt before changing anything."

## 0:00-1:00 — local smoke proof

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/acgs-gove-zone-smoke-audit.jsonl"
```

Narrate:

- One safe write is allowed and executed.
- One secret-path write is denied before file creation.
- The audit chain verifies.
- The output explicitly says this is local proof, not production certification.

## 1:00-2:30 — full receipt-gated execution proof

```bash
uv run --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
```

Point to these lines in output:

- allowed action executes;
- denied action is blocked;
- missing receipt is blocked;
- tampered receipt is blocked;
- cross-tenant receipt is blocked;
- transformed action runs only as approved;
- audit replay verifies;
- signed receipt succeeds and forged/recomputed receipt fails when signing mode is engaged.

## 2:30-3:30 — proof pack

```bash
uv run --package gove-zone bash -lc 'tmp=$(mktemp -d); cd "$tmp"; python -m gove_zone.cli proofpack; find dist-govern-zone-proofpack -maxdepth 2 -type f | sort'
```

Narrate:

"A buyer/reviewer should not trust a slide. They should inspect receipts, audit JSONL, verification output, conformance results, and limitations."

## 3:30-4:30 — tamper attempt

```bash
uv run --package gove-zone python examples/tamper_demo/demo.py
```

Narrate:

- A valid receipt permits a simulated side effect.
- A tampered receipt fails.
- A receipt reused with different args fails.
- An audit chain verifies before tampering.
- The same chain fails verification after tampering.

## 4:30-5:00 — integration conclusion

"The model may request an action. The executor enforces the gate. The policy decision, receipt, audit evidence, and replay outcome are all separate from model confidence. If there is no valid Decision Receipt, there is no side effect."

## Failure cases shown

- denied action failure;
- missing receipt failure;
- tampered receipt failure;
- argument mismatch failure;
- audit replay/integrity success;
- audit replay/integrity failure after tampering.
