# Canonical proof path

This is the central proof narrative of ACGS / gove-zone.

> **Denied action → Decision Receipt → evidence bundle → audit replay → tamper attempt → replay failure.**

Core invariant:

> **No valid Decision Receipt, no side effect.**

## Step 1 — denied action

Run:

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/acgs-gove-zone-smoke-audit.jsonl"
```

The smoke policy denies a write whose path contains `id_rsa`. The side effect file is not created. The output includes a `deny` object with matched rule evidence.

## Step 2 — Decision Receipt

Run:

```bash
uv run --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
```

The demo mints receipts and proves:

- an `ALLOW` receipt can execute only with matching actor/action/args;
- a `DENY` receipt cannot authorize execution;
- missing receipt fails closed;
- tampered receipt fails closed;
- transformed receipt can execute only as transformed.

## Step 3 — evidence bundle

Run:

```bash
uv run --package gove-zone bash -lc 'tmp=$(mktemp -d); cd "$tmp"; python -m gove_zone.cli proofpack; find dist-govern-zone-proofpack -maxdepth 2 -type f | sort'
```

Inspect:

- `receipts/allowed_receipt.json`
- `receipts/denied_receipt.json`
- `receipts/transformed_receipt.json`
- `audit.jsonl`
- `verification.json`
- `conformance-results.json`
- `limitations.md`

## Step 4 — audit replay / integrity

The audit chain verifies by recomputing every event hash and every `previous_hash` link. Replay helpers can re-derive decisions when raw call context is retained in the side store.

Evidence:

- `packages/gove-zone/src/gove_zone/audit.py`
- `packages/gove-zone/src/gove_zone/replay.py`
- `packages/gove-zone/tests/test_audit_chain.py`
- `packages/gove-zone/tests/test_replay.py`

## Step 5 — tamper attempt

Run:

```bash
uv run --package gove-zone python examples/tamper_demo/demo.py
```

The script:

1. executes a valid receipt;
2. tampers with the receipt action and verifies it is blocked;
3. reuses a valid receipt with different arguments and verifies it is blocked;
4. verifies the audit chain;
5. edits the persisted audit JSONL;
6. verifies the chain fails after tampering.

## Step 6 — failure is the point

A good governance demo should show failure paths. If tampering, missing receipts, or argument substitution still allow execution, the invariant is broken. The proof path is successful because unsafe paths fail closed.
