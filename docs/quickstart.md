# Quickstart

This quickstart uses the local `gove-zone` package as the current ACGS runtime kernel surface.

## Prerequisites

From the repository root, use the versions documented in `README.md` and `MONOREPO.md`:

- Python 3.11+
- `uv`
- Node 24.x when running frontend gates
- `pnpm` 9.x when running frontend gates

## Install and verify

```bash
make install
make verify
```

For a bounded runtime-only smoke path:

```bash
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
uv run --package gove-zone gove-zone smoke
```

## Generate host setup guidance

```bash
uv run --package gove-zone gove-zone setup --format json
uv run --package gove-zone gove-zone doctor
```

## Gate a proposed tool call

```bash
printf '{"tool_name":"Edit","tool_input":{"file_path":"README.md","new_string":"demo"}}' \
  | uv run --package gove-zone gove-zone gate --actor quickstart
```

The gate should emit a decision payload. Denied or escalated decisions must block the side effect in an enforceable host.

## Retain audit evidence

When retaining release or review evidence, pass an explicit audit path where supported and include the exact command output in the handoff.

```bash
uv run --package gove-zone gove-zone smoke --audit .gove-zone/quickstart-audit.jsonl
```

Do not treat this local smoke evidence as production deployment proof.
