# Canonical proof path

This is the central proof narrative of ACGS / gove-zone.

> **Denied action → Decision Receipt → evidence bundle → audit replay → tamper attempt → replay failure.**

Core invariant:

> **No valid Decision Receipt, no side effect.**

## Prerequisites

Python 3.11+, [uv](https://docs.astral.sh/uv/), and a clone of this repository.
Run every command below from the repository root. Once dependencies are
installed (`make install`), no network access or external service is required.

## Step 1 — denied action

Run:

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/acgs-gove-zone-smoke-audit.jsonl"
```

The smoke policy denies a write whose path contains `id_rsa`. The side effect file is not created. The output includes a `deny` object with matched rule evidence.

## Step 2 — Decision Receipt

Run:

```bash
uv run --extra crypto --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
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

## Step 7 — offline proof-pack verification

The steps above run *inside* the runtime. A relying party outside the enforcement
runtime can verify a bundle of receipts **offline**, as a unit, without importing or
running the kernel. That bundle is a **proof pack** — a self-contained directory:

```
manifest.json            # schema_version, receipts[], audit_chain, optional replay / consumption_ledger
receipts/<name>.json     # DecisionReceipt canonical JSON
audit.jsonl              # tamper-evident audit chain
policy_bundle.json       # optional — RuleSetPolicy (decision-replay tier)
replay_side_store.jsonl  # optional — raw args for re-derivation (decision-replay tier)
consumed.jsonl           # optional — consumption ledger (anti-replay tier)
```

### Generate / locate a pack

- `gove-zone proofpack` writes a conformance pack to `dist-govern-zone-proofpack/`
  (its `manifest.json` carries `schema_version: gove-zone/proof-pack/v1`).
- The fixture corpus lives at `packages/gove-zone/tests/fixtures/proofpacks/`, generated
  deterministically-in-shape by `tests/fixtures/_generate_proofpacks.py` (run it as
  `python …/_generate_proofpacks.py` to regenerate; the kernel path uses wall-clock and
  uuid, so the committed packs are a snapshot — the verdict, not the bytes, is the contract).

### Run the verifier

```bash
gove-zone verify-proofpack <pack-dir>        # exit 0 iff valid, else 1; prints the JSON result

# A SIGNED pack needs the trust anchor supplied out-of-band (NOT from the pack):
gove-zone verify-proofpack <pack-dir> --verifier-key trusted.pub --key-id <signing_key_id>

# Optionally reject receipts signed by a revoked key (supplied out-of-band):
gove-zone verify-proofpack <pack-dir> --verifier-key trusted.pub --key-id <id> --revoked-keys revoked.json
```

`--verifier-key` is a raw 32-byte Ed25519 **public** key you obtained from a source you
trust, separate from the pack. Omit it for unsigned (dev) packs; a signed pack verified
without it fails closed with `SIGNED_RECEIPT_NO_VERIFIER`.

`--revoked-keys` is an optional JSON array of revoked signing `key_id`s (e.g.
`["key-2024-q1"]`), also supplied out-of-band. A receipt whose `signing_key_id` is on the
list fails closed with `SIGNING_KEY_REVOKED` even when its signature is otherwise valid —
so a key compromised *after* the pack was minted cannot be verified as valid. Omit it to
apply no revocation; a malformed list fails closed (exit 2) rather than degrading to "none".

Or via the Python API:

```python
from gove_zone import verify_proof_pack
result = verify_proof_pack("<pack-dir>", verifier=<ReceiptSigner public key>, now_iso=None)
result.valid       # the single fail-closed gate
result.reasons     # machine-readable failure codes (empty iff valid)
```

A signed pack needs a `verifier` (a public-key `ReceiptSigner` or a `{key_id: signer}`
map); `None` verifies unsigned (dev) packs only — a signed receipt presented with no
verifier is **rejected**, not skipped.

### What `valid=true` means

The pack's receipts are internally consistent and bound: each `receipt_hash` recomputes,
each declared-accept receipt is anchored in the supplied audit chain, the chain's hash
links verify, and — when the pack ships replay material — the recorded decisions
re-derive byte-for-byte under the supplied policy. When a consumption ledger is present,
no declared-accept receipt's audit anchor has already been burned.

### What `valid=true` does NOT mean

- **Not an ALLOW / authorization verdict.** `valid=true` means the pack is internally
  consistent with what it *declares* — its integrity holds. A pack whose only receipt is a
  declared-and-observed *reject* (e.g. a DENY) is still `valid=true`: it faithfully proves a
  refusal. Read the per-receipt `decision` / `declared_verdict`, not just the top-level
  `valid`, to learn whether an action was permitted.
- **Signatures are only checked when you supply a key.** Without a `verifier`, signatures are
  not verified at all (dev posture). *With* a `verifier`, every declared-accept receipt must
  be signed and verify — an unsigned or signature-stripped accept is rejected
  (`UNSIGNED_REJECTED`), so the trust anchor is load-bearing rather than advisory.
- **Trust-anchor circularity (threat-model §7).** A public key shipped *inside* the pack
  next to the signer is not independent trust — it only proves the bytes were signed by
  whoever you chose to trust. Supply the verifier key out-of-band from a source you trust;
  the verifier checks consistency, not provenance.
- **Decision-replay is conditional.** Re-derivation only runs when the pack ships
  `policy_bundle.json` + `replay_side_store.jsonl`. A pack without replay material proves
  receipt + chain integrity, not that the decisions reproduce.
- **Not a compliance, certification, or production-readiness claim.** `valid=true` is an
  integrity verdict over the supplied artifacts. It is not evidence of conformance with any
  security framework, law, or regulator.

### Fail-closed invariant

`verify_proof_pack` **never raises**: a missing manifest, unreadable chain, corrupt ledger,
unsupported schema, or any unexpected exception all resolve to `valid=false` with a stable
reason. Uncertainty is always rejection — a verifier that fails *open* is worse than none.

### Failure codes

Pack-level codes are `gove_zone.verifier.ProofPackRejectionReason`:

`PROOFPACK_NOT_FOUND`, `MANIFEST_MISSING`, `MANIFEST_MALFORMED`, `SCHEMA_VERSION_MISSING`,
`SCHEMA_VERSION_UNSUPPORTED`, `AUDIT_CHAIN_MISSING`, `AUDIT_CHAIN_UNREADABLE`,
`AUDIT_CHAIN_BROKEN`, `RECEIPT_FILE_MISSING`, `RECEIPT_MALFORMED`, `RECEIPT_NOT_ANCHORED`,
`RECEIPT_UNEXPECTED_ACCEPT`, `RECEIPT_UNEXPECTED_REJECT`, `RECEIPT_WRONG_REASON`,
`REPLAY_MATERIAL_MALFORMED`, `REPLAY_MISMATCH`, `CONSUMPTION_LEDGER_UNPROVABLE`,
`RECEIPT_ALREADY_USED`, `VERIFIER_ERROR`.

Receipt-level failures surface the receipt's own `gove_zone.errors.ReceiptRejectionReason`
verbatim (e.g. `RECEIPT_HASH_MISMATCH`, `SIGNATURE_INVALID`, `RECEIPT_EXPIRED`), so a
declared-accept receipt that fails reports both `RECEIPT_UNEXPECTED_REJECT` and the
underlying receipt code.
