# Quickstart

> **Core invariant: No valid Decision Receipt, no side effect.**


This is the fastest copy-paste path for a local evaluator.

## Prerequisites

- Python compatible with the workspace (`>=3.11`).
- `uv` installed.
- From the repository root: `/home/martin/Documents/ACGS` or equivalent clone.

Install/sync command from the root Makefile. **Unverified in this documentation pass if your environment is already synced; run when starting fresh:**

```bash
uv sync --all-extras
```

## Clone

Use your fork/remote URL. **Unverified here because this checkout already exists:**

```bash
git clone <repo-url> ACGS
cd ACGS
```

## Run tests

Documentation/example smoke tests:

```bash
uv run python -m pytest tests/docs --import-mode=importlib -q
```

Runtime kernel tests for gove-zone:

```bash
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
```

## Run the demo

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/acgs-gove-zone-smoke-audit.jsonl"
uv run --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
```

Expected: JSON or terminal output proving allowed execution, denied failure, missing receipt failure, tamper failure, and audit-chain verification.

## Inspect a receipt/evidence artifact

Generate a proof pack in a temporary directory:

```bash
uv run --package gove-zone bash -lc 'tmp=$(mktemp -d); cd "$tmp"; python -m gove_zone.cli proofpack; find dist-govern-zone-proofpack -maxdepth 2 -type f | sort'
```

Expected files:

- `manifest.json`
- `receipts/allowed_receipt.json`
- `receipts/denied_receipt.json`
- `receipts/transformed_receipt.json`
- `audit.jsonl`
- `verification.json`
- `conformance-results.json`
- `limitations.md`

## Tamper with receipt/evidence and observe failure

Run the local tamper demo:

```bash
uv run --package gove-zone python examples/tamper_demo/demo.py
```

Expected JSON fields:

- `valid_receipt_executed: true`
- `tampered_receipt_blocked: true`
- `argument_mismatch_blocked: true`
- `audit_chain_valid_before_tamper: true`
- `audit_chain_valid_after_tamper: false`

## Next steps

- Read `docs/PROOF_PATH.md` for the canonical proof narrative.
- Read `docs/DECISION_RECEIPT_SPEC.md` before integrating.
- Use `examples/python_tool_gate`, `examples/mcp_tool_gate`, `examples/agent_framework_gate`, and `examples/ci_deploy_gate` as local reference patterns.
- Read `docs/CLAIMS.md` before making public claims.
