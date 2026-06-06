---
title: "CI gate parity — verify with the full CI gate set locally, not just `ruff check`"
date: 2026-06-06
category: workflow-issues
module: gove-zone (govern-zone monorepo) — CI / local verification
problem_type: workflow_issue
component: development_workflow
severity: medium
applies_when:
  - "Verifying a Python package change locally before pushing to a PR"
  - "A package's CI Lint step runs more than one ruff invocation"
  - "Local checks pass but CI fails on a lint/format step"
tags: [ci, ruff, ruff-format, lint, gate-parity, local-verification, gove-zone, pre-push]
---

# CI gate parity — verify with the full CI gate set locally, not just `ruff check`

## Context

While shipping PR #79 (`feat/gove-zone-replay-side-store`), local verification ran
`ruff check src tests` (lint) and it passed. The PR was pushed and CI failed on
`test (3.11)` in **8 seconds** — far too fast for a test-logic failure. The CI Lint
step runs **two** ruff invocations:

```
.venv/bin/python -m ruff check src tests examples        # lint   → passed
.venv/bin/python -m ruff format --check src tests examples  # format → FAILED
```

`ruff format --check` reported `tests/test_cli.py` "would be reformatted"
(`1 file would be reformatted, 59 files already formatted`) and exited 1. The
local run had exercised only the first invocation, so a format-only violation
slipped through and cost a full CI round-trip plus an autofix commit.

This is a **gate-parity** gap: local verification reproduced only a subset of the
CI gate set. `ruff check` (lint rules) and `ruff format --check` (formatter
conformance) are **independent gates** — passing one says nothing about the other.

## Guidance

Before pushing a Python package change, run the **exact command set the CI Lint
step runs**, not an approximation. For the `gove-zone` package that is both ruff
invocations against the same paths CI uses (`src tests examples`):

```bash
cd packages/gove-zone
uv run ruff check src tests examples          # lint gate
uv run ruff format --check src tests examples # format gate (separately!)
```

Treat the package's CI workflow as the source of truth for the gate set. When in
doubt, read the workflow's Lint step and mirror every command and every path
argument — including `examples/`, which local habit often omits.

The fix when `format --check` fails is mechanical: `uv run ruff format <file>`
(or the whole tree), then re-run `--check` to confirm, then commit.

## Why This Matters

- **Lint ≠ format.** `ruff check` enforces lint rules; `ruff format` enforces
  formatter output. A file can be lint-clean and format-dirty simultaneously
  (exactly what happened to `test_cli.py`). Running only `ruff check` gives false
  confidence.
- **Path scope matters.** CI checks `src tests examples`; a local run scoped to
  `src tests` misses `examples/` drift entirely.
- **Fast CI failures are a tell.** An 8-second "test" failure is almost never a
  test — it's a lint/format/collection/import error in the setup or Lint step.
  Read the failing step's log before assuming a logic bug.
- **Cost.** Each missed gate is a full CI queue + run + an extra fix commit. The
  govern-zone runners were queue-backed up during this incident, turning a
  one-line format fix into a multi-minute round-trip.

## When to Apply

- Before pushing any change to a package whose CI Lint step runs multiple checks.
- Whenever a CI check fails much faster than its name implies (lint/format/import,
  not logic).
- When adding or editing test files — formatters frequently reflow test code
  (long arg lists, dict literals) that hand-edits leave non-conformant.

## Examples

Before (local verification that passed but let CI fail):

```bash
cd packages/gove-zone
uv run ruff check src tests   # ✅ passed locally → false confidence
# (ruff format --check never run; examples/ never checked)
```

After (mirrors the CI Lint step exactly):

```bash
cd packages/gove-zone
uv run ruff check src tests examples            # ✅
uv run ruff format --check src tests examples   # ❌ tests/test_cli.py would reformat
uv run ruff format tests/test_cli.py            # fix
uv run ruff format --check src tests examples   # ✅ re-confirm before commit
```

## Related

- (session history) A concurrent CI-monitoring session independently caught this
  same `#79` failure, classified it as a **real PR problem, not an environment
  issue**, and confirmed the red→green transition across commits
  (`6af56d` red → `f7108ec` green). Independent confirmation that the failure was
  a genuine gate-parity miss, not runner flakiness.
- (session history) CI-noise gotcha worth remembering: in this repo the
  `claude.yml` bot workflow fails on **every** branch as a pre-existing
  environment issue unrelated to PR code. When triaging red checks, separate that
  always-red bot workflow from real per-package CI (`test`, `verify`) before
  concluding a PR is broken.
- Parent guidance: the workspace `CLAUDE.md` already warns "Always run the FULL
  lint script ... not just black/isort. flake8/ruff errors are commonly missed" —
  this learning extends it specifically to `ruff format --check` as a gate
  distinct from `ruff check`, and to mirroring CI path arguments.
