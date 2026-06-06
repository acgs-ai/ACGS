# Undeniable evidence path

The flagship gove-zone demo: a single runnable script that walks the full
chain of custody from a blocked action to tamper-proof evidence.

    No valid Decision Receipt, no side effect.

## What it shows

A 5-step spine, each step printing undeniable evidence against the **real**
gove-zone API (policy evaluator, signed-receipt issuer, executor gate, audit
chain), led by the **production profile** (signed receipts required — the
secure default):

| Step | Proof |
|------|-------|
| `[0]` | An ALLOWED companion write executes for real (shows the gate is not blocking everything). |
| `[1]` | **DENIED** — a privileged write into `secrets/prod/**` is blocked; the side effect provably never ran (gateway flag false + no file on disk). |
| `[2]` | **RECEIPT** — the signed `DecisionReceipt` for that denial: `receipt_id`, `decision`, `signature_algorithm=ed25519`, `signing_key_id`, `receipt_hash`. |
| `[3]` | **EVIDENCE BUNDLE** — a portable tempdir bundle: `receipts/*.json` + a copy of the append-only `audit.jsonl` + `verification.json` + `manifest.json`. |
| `[4]` | **AUDIT REPLAY** — the bundle is re-verified **offline** (fresh `ChainHashAuditStore` over the copied chain): `valid=True`, `checked=N`. |
| `[5]` | **TAMPER FAILS** — two independent attacks both rejected: (a) mutating one audit event → hash-chain mismatch; (b) forging the DENY into an ALLOW with a recomputed `receipt_hash` → `invalid signature` (no private key). |

Plus a clearly separated **Bonus**: re-running the same content-addressed
policy against the retained raw args reproduces the DENY verdict.

## How to run

From the monorepo root:

```bash
uv run --package gove-zone python \
    packages/gove-zone/examples/undeniable-demo/demo.py
```

or with any venv that has gove-zone (with the `crypto` extra) installed:

```bash
python packages/gove-zone/examples/undeniable-demo/demo.py
```

Exit code `0` and the `ALL 5 STEPS PROVEN` banner mean every assertion held.
The script writes only to a `tempfile` directory and exits non-zero if any
invariant is violated — there is no fake green.

## What to look for

- Step `[1]`: the two asserted lines — `gateway.invoke never ran` and `no file
  written on disk`. The deny path is the whole point.
- Step `[2]`: `signature_algorithm = ed25519` and a non-`unsigned_local`
  signature — this is the production (signed) profile, not dev mode.
- Step `[5a]`: the failure `type` is `event_hash_mismatch` /
  `previous_hash_mismatch` (a *hash* failure, not a JSON parse error).
- Step `[5b]`: the rejection message contains `invalid signature` — the forged
  DENY→ALLOW is caught by the cryptographic signature check, not merely by the
  "denied receipt cannot authorize" rule.

## Integration pattern, not a vendored SDK

`PrivilegedToolGateway` is a tiny in-file stub that models the **call shape** of
an agent-framework tool (MCP tool server / LangGraph node / OpenAI-Agents
tool). The demo does **not** import `mcp`, `langgraph`, or `openai-agents`; it
shows WHERE the gove-zone gate slots into such a framework, governed with the
real API. The only runtime dependency is gove-zone itself (the Ed25519 signing
needs the `crypto` extra).

## Honest scope

Status: foundational / Alpha (`0.1.0.dev0`). The Ed25519 keypair is generated
inside the process — correct and self-contained for a pedagogical example, but
obviously not real key custody. This is **local alpha proof of the invariant**,
**not** a production, compliance, or regulator-ready certification. See the
package `SECURITY.md` for the full enforced-vs-out-of-scope boundary, and the
package `README.md` section *Replay (what it actually verifies)* for why a cold
audit event alone cannot re-derive a decision.
