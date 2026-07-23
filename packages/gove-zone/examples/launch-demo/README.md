# gove-zone launch demo

The launch narrative as an **executable proof**, not a slide. Five beats, each
asserted against the real policy evaluator, receipt issuer, executor gate, audit
chain, and replay engine. Any violated invariant exits non-zero.

```bash
# from the monorepo root
uv run --package gove-zone python packages/gove-zone/examples/launch-demo/demo.py
```

## The five beats

1. **ALLOW** — a safe `runtime.file.write` runs under a valid Decision Receipt.
2. **DENY** — an unsafe `shell.exec` is blocked *before* the side effect fires
   (the stand-in tool's `ran` flag stays `False`).
3. **RECEIPT** — the real receipt that authorized beat 1 is printed: decision,
   tenant/actor, validator (≠ proposer — MACI), `argument_hash`, `receipt_hash`,
   signature status.
4. **AUDIT** — `verify_chain()` confirms a tamper-evident, hash-chained record of
   every decision, 0 failures.
5. **REPLAY** — `replay_call()` re-runs each recorded decision against the policy;
   ALLOW replays to ALLOW and DENY replays to DENY (`matches=True`).

## Honest scope

- **Alpha** (`0.1.0.dev0`). Proves the *local* invariant; **not** a production,
  compliance, or regulator-ready certification.
- This fixture-only demo creates an explicitly labelled temporary state root. Receipts
  are Ed25519-signed, and execution uses a checkpointed audit plus persistent schema-v4
  receipt-consumption state under that root.
- The registered tool is a stand-in. gove-zone decides *whether* and *with which
  arguments* an action runs; it does **not** sandbox the side effect. Run your
  tools in your own sandbox.
