# Compliance Evidence Pack — governed-action inputs

These four files are the **committed reference governed action** that
`compliance/evidence_pack.py` packages as the runtime evidence in the ACGS
Compliance Evidence Pack. Keeping them here makes the pack self-contained and
byte-reproducible — the compliance tooling does not reach into gove-zone's test
fixtures at build time.

| File | What it is |
|---|---|
| `decision-receipt.json` | The Decision Receipt for one governed action (`compliance-officer` → `runtime.file.write`, decided ALLOW), tamper-evident via `receipt_hash`. |
| `audit.jsonl` | The append-only, hash-chained audit log the receipt is anchored in (two decisions). |
| `policy-bundle.json` | The `RuleSetPolicy` bundle that decided the action, enabling decision replay. |
| `side-store.jsonl` | Retained raw arguments enabling full-argument replay re-derivation. |

**Provenance.** Copied verbatim from the already-verified proof-pack fixture
`packages/gove-zone/tests/fixtures/proofpacks/valid-replay` (real kernel-path
artifacts: the receipt hash re-derives, the chain verifies, and the recorded
decisions replay byte-for-byte). They are a single reference action, **not a
sample of production traffic**.

Regenerate the pack from these inputs with:

```bash
uv run --package gove-zone python compliance/evidence_pack.py generate \
    --out compliance/evidence-pack
```
