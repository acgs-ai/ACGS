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
- This demo runs in explicit **dev mode** (`require_signature=False`; receipts are
  `unsigned_local`). The library default is the signed **production profile** — see
  `../../SECURITY.md` and `../receipt-gated-execution/demo.py` (scenarios 8–9) for the
  signed path.
- The registered tool is a stand-in. gove-zone decides *whether* and *with which
  arguments* an action runs; it does **not** sandbox the side effect. Run your
  tools in your own sandbox.
