# START HERE — ACGS / gove-zone in 10 minutes

## 60-second explanation

ACGS / gove-zone is a receipt-gated governance layer for AI-agent side effects. It does not replace agent frameworks, MCP, guardrails, sandboxes, IAM, or model safety systems. It sits between an agent's request and the executor's side effect.

The invariant is:

> **No valid Decision Receipt, no side effect.**

A model or agent may request `write_file`, `send_email`, `db.update`, `deploy`, or `tools/call`. The executor must ask ACGS for a governance decision first. If the Decision Receipt is missing, malformed, expired, tampered, actor-mismatched, action-mismatched, argument-mismatched, policy-mismatched, or denied, the side effect does not run.

## 5-minute demo

Run the local smoke proof:

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/acgs-gove-zone-smoke-audit.jsonl"
```

What it proves:

- an allowed `write_file` executes only after the governance path records evidence;
- an `id_rsa`-shaped write is denied before the file is created;
- the two audit events verify as a hash chain;
- the output carries a claim boundary: local proof only, not production certification.

Run the full receipt-gated execution proof:

```bash
uv run --extra crypto --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
```

What it proves:

- allowed action executes;
- denied action fails closed;
- missing receipt fails closed;
- tampered receipt fails closed;
- cross-tenant receipt fails closed;
- transformed action can execute only with approved transformed arguments;
- signed receipt verification can reject recomputed forgeries when signing mode is engaged.

## 10-minute verification path

1. Run the smoke proof and keep audit evidence:

   ```bash
   tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/acgs-gove-zone-smoke-audit.jsonl"
   ```

2. Inspect the retained audit evidence:

   ```bash
   sed -n '1,2p' "$tmp/acgs-gove-zone-smoke-audit.jsonl"
   ```

3. Generate a local proof pack in a temp directory:

   ```bash
   uv run --package gove-zone bash -lc 'tmp=$(mktemp -d); cd "$tmp"; python -m gove_zone.cli proofpack; find dist-govern-zone-proofpack -maxdepth 2 -type f | sort'
   ```

4. Prove tampering fails:

   ```bash
   uv run --package gove-zone python examples/tamper_demo/demo.py
   ```

5. Run doc/example smoke tests:

   ```bash
   uv run python -m pytest tests/docs --import-mode=importlib -q
   ```

6. If changing runtime code, run gove-zone tests:

   ```bash
   uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
   ```

## Where to go next

| Need | Read |
|---|---|
| Canonical proof narrative | `docs/PROOF_PATH.md` |
| Human evaluator explanation | `docs/HUMAN_GUIDE.md` |
| Runtime architecture | `docs/ARCHITECTURE.md` |
| Receipt public contract | `docs/DECISION_RECEIPT_SPEC.md` |
| Threat model | `docs/SECURITY_MODEL.md` |
| Safe claim ledger | `docs/CLAIMS.md` |
| Integrator examples | `docs/INTEGRATION_GUIDE.md` and `examples/**` |
| Agent operating rules | `AGENTS.md` and `llms.txt` |

## What not to assume

Do not assume:

- this is production-certified;
- this is compliance-certified;
- unsigned local receipts are production-grade signatures;
- a local proof pack proves a live deployment;
- ACGS replaces sandboxing, IAM, SIEM, content moderation, or model guardrails;
- direct `verify()` calls are equivalent to wiring the executor gate into a real side-effect path.

The executor, not the model, must enforce the gate.
