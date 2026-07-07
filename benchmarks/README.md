# Benchmarks

Workspace-level index of runnable performance benchmarks. Benchmark code lives
with the package it measures; this directory is the entry point.

## gove-zone runtime

| Suite | Measures | Run |
|---|---|---|
| [`governed_actions_bench.py`](../packages/gove-zone/benchmarks/governed_actions_bench.py) | Policy evaluation, audit write (per-event fsync + batched), receipt validation (unsigned + Ed25519), replay verification, end-to-end dispatch, concurrent dispatch — at 100 / 1,000 / 100,000 governed actions | `./benchmarks/run_gove_zone.sh` |
| [`overhead_receipt_gate.py`](../packages/gove-zone/benchmarks/overhead_receipt_gate.py) | Membrane overhead per call: governed vs ungoverned latency across kernel / unsigned gate / signed gate arms | `uv run --package gove-zone --extra crypto python packages/gove-zone/benchmarks/overhead_receipt_gate.py` |

Results and methodology: [`docs/performance-report.md`](../docs/performance-report.md).

## Cautions

- Run with `--audit-dir` on a **real disk**. The default temp dir often lands
  on tmpfs, where `fsync` is nearly free and audit-write numbers become
  meaninglessly fast.
- Numbers from a developer workstation are indicative, not a controlled
  environment. Quote absolute per-call overhead, not percentages against a
  no-op tool body.
