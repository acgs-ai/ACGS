# Verification Gates (govern-zone)

> Always-On: Extraction of AGENTS.md — all test/demo/proof commands. AGENTS.md remains
> authoritative. Select the gate by touched path; never claim a result without literal output.

## Root documentation smoke

```bash
uv run python -m pytest tests/docs --import-mode=importlib -q
```

## Main gove-zone runtime gate

```bash
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
```

## Fast proof commands

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/acgs-gove-zone-smoke-audit.jsonl"
uv run --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
uv run --package gove-zone python examples/tamper_demo/demo.py
```

## Root docs invariant check

```bash
make lint-docs
```

## Frontend / console (run inside `acgi-ai/`)

```bash
pnpm run lint && pnpm run typecheck && pnpm run test
```

## Broad monorepo gate (only when intentionally validating the whole workspace)

```bash
make verify
```

## Rules

- Run the local package gate before claiming work complete; use `make verify` only for
  intentional multi-package validation.
- A passing unit test does not prove handler wiring — see `~/.claude/rules/review-handler-wiring.md`.
- Paste the literal command output (or a stable digest) immediately before any numeric or
  pass/fail claim.
