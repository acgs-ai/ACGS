# Quickstart

> **Core invariant: No valid Decision Receipt, no side effect.**

This is the canonical 5-minute, copy-paste path for a local evaluator. It is the
single source of truth for getting the runtime kernel (`gove-zone`) running and
proving the invariant. Other onboarding docs link here for the install + proof
steps:

- `docs/START_HERE.md` — the 10-minute narrated tour.
- `docs/PROOF_PATH.md` — the canonical proof narrative.
- `docs/DEMO_SCRIPT.md` — the timed live-demo script.

## Prerequisites

- Python 3.11+ (the workspace floor; `gove-zone`'s published floor is 3.10).
- [`uv`](https://docs.astral.sh/uv/) installed.
- A clone of this repository; run every command from the repository root.

## Install (single block)

Sync the runtime kernel **with the signing extra** so Ed25519 receipt signing is
available — the receipt-gated demo below needs it:

```bash
uv sync --package gove-zone --extra crypto
```

> Do **not** use `uv sync --all-extras` from the workspace root. This root is a
> *virtual* uv workspace, so `--all-extras` resolves the root's (empty) extras
> and **uninstalls** `gove-zone` and `cryptography`. If your environment is
> already in that state, the proof block below still self-heals: every
> `uv run --extra crypto --package gove-zone ...` invocation re-syncs the extra
> on the fly.

## Prove the invariant (single block)

Run all four proof commands. The receipt-gated demo prints **`All invariants
held`** and exits 0; the doc/example smoke tests exit 0:

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/acgs-gove-zone-smoke-audit.jsonl"
uv run --extra crypto --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
uv run --package gove-zone python examples/tamper_demo/demo.py
uv run python -m pytest tests/docs --import-mode=importlib -q
```

What each command proves:

- **smoke** — an allowed `write_file` executes only after the governance path
  records evidence; an `id_rsa`-shaped write is denied before the file is
  created; both audit events verify as a hash chain.
- **receipt-gated demo** — allowed executes; denied / missing / tampered /
  cross-tenant receipts fail closed; a transformed action runs only as approved;
  a signed receipt verifies and a forged/recomputed one is rejected.
- **tamper demo** — a valid receipt permits a simulated side effect; a tampered
  receipt, a reused receipt with different args, and a hand-edited audit JSONL
  all fail verification.
- **tests/docs** — the documentation and example smoke suite is green.

## Runtime kernel tests (optional)

```bash
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
```

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

## Next steps

- Read `docs/PROOF_PATH.md` for the canonical proof narrative.
- Read `docs/DECISION_RECEIPT_SPEC.md` before integrating.
- Read `docs/INTEGRATION_GUIDE.md` for the copy-paste "first receipt" snippet.
- Use `examples/python_tool_gate`, `examples/mcp_tool_gate`,
  `examples/agent_framework_gate`, and `examples/ci_deploy_gate` as local
  reference patterns.
- Read `docs/CLAIMS.md` before making public claims.
