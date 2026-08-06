# CLI reference

This page summarizes the local `gove-zone` CLI surfaces used by the ACGS docs. Run `--help` in the current checkout for the authoritative command list.

## Setup

```bash
uv run --package gove-zone gove-zone setup --format json
```

Produces host integration guidance.

## Doctor

```bash
uv run --package gove-zone gove-zone doctor
```

Checks local setup health.

## Smoke

```bash
uv run --package gove-zone gove-zone smoke
```

Runs a bounded allow/deny/audit-chain smoke path.

## Gate

```bash
uv run --package gove-zone gove-zone gate --actor <actor> < event.json
```

Evaluates a proposed tool-call event before execution.

## Proof pack

```bash
uv run --package gove-zone gove-zone proofpack
uv run --package gove-zone gove-zone verify-proofpack <pack_dir>
```

Generates a local conformance proof pack (allowed, denied, and transformed
evidence), and verifies a pack directory offline, fail-closed. Local conformance
evidence only — not a compliance certification. Pass `--verifier-key` to
`verify-proofpack` for signed packs; a signed pack without it fails closed.

## Validation

For full repository validation, use the root gate documented in `README.md`:

```bash
make verify
```
