#!/usr/bin/env python3
"""Gated membrane-overhead benchmark for the gove-zone self-improve loop.

SEALED — this wrapper is part of the evaluation harness, not a candidate under
optimization. It must not be edited by improvement candidates.

Pipeline
--------
1. **Correctness gate (hard precondition).** Runs the full gove-zone test suite
   (including ``tests/adversary/``). If any test fails, prints a worst-possible
   score and exits non-zero — no benchmark is run. A candidate that weakens any
   governance / durability / fail-closed guarantee fails here and can never
   score.
2. **Benchmark.** Imports ``benchmarks/overhead_receipt_gate.py`` and runs it
   ``PASSES`` times (fresh audit dir per pass), taking the median pass to damp
   run-to-run latency noise. The Ed25519-signed arm is mandatory: if it was
   skipped (crypto extra missing) the wrapper errors out — the loop must always
   measure the signed path.
3. **Score.** ``primary`` = composite p50 overhead vs the ungoverned baseline:
   ``0.4*kernel_dispatch + 0.3*receipt_gate_unsigned +
   0.3*receipt_gate_signed_ed25519`` (each the p50 ms from
   ``overhead_vs_ungoverned_ms``). Lower is better.

Output
------
The LAST line of stdout is exactly one JSON object::

    {"primary": <composite_p50_ms>, "sub_scores": {...}}

All diagnostics go to stderr. Exit 0 on success, non-zero on any gate failure.

Invoke (cwd = any experiment worktree root of this monorepo)::

    uv run --package gove-zone --extra dev --extra crypto \\
        python packages/gove-zone/scripts/si_benchmark_gated.py
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# scripts/si_benchmark_gated.py -> scripts -> gove-zone -> packages -> repo root
REPO_ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_PATH = REPO_ROOT / "packages" / "gove-zone" / "benchmarks" / "overhead_receipt_gate.py"
TESTS_REL = "packages/gove-zone/tests"

ITERATIONS = 5000
WARMUP = 500
PASSES = 3

WEIGHTS = {
    "kernel_dispatch": 0.4,
    "receipt_gate_unsigned": 0.3,
    "receipt_gate_signed_ed25519": 0.3,
}


def _emit(obj: dict[str, Any]) -> None:
    """Write the single machine-readable result line to stdout."""
    print(json.dumps(obj))


def _fail(message: str, *, correctness: str = "passed") -> None:
    """Emit a worst-possible score and exit non-zero."""
    print(f"[si_benchmark_gated] FAIL: {message}", file=sys.stderr)
    _emit({"primary": 999999.0, "correctness": correctness, "error": message})
    sys.exit(1)


def run_correctness_gate() -> None:
    print("[si_benchmark_gated] running correctness gate (pytest)...", file=sys.stderr)
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", TESTS_REL, "--import-mode=importlib", "-q"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    tail = "\n".join((proc.stdout + proc.stderr).splitlines()[-15:])
    print(tail, file=sys.stderr)
    if proc.returncode != 0:
        _fail("correctness gate failed (see pytest output above)", correctness="failed")
    print("[si_benchmark_gated] correctness gate PASSED", file=sys.stderr)


def load_benchmark() -> Any:
    spec = importlib.util.spec_from_file_location("overhead_receipt_gate", BENCHMARK_PATH)
    if spec is None or spec.loader is None:
        _fail(f"cannot load benchmark module at {BENCHMARK_PATH}")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    # Register before exec so frozen-dataclass decorators can resolve
    # ``cls.__module__`` against sys.modules during class creation.
    sys.modules[spec.name] = module  # type: ignore[union-attr]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def composite_from_report(report: dict[str, Any]) -> dict[str, float]:
    skipped = report.get("signed_arm_skipped")
    if skipped:
        _fail(f"signed Ed25519 arm was skipped: {skipped}")
    overhead = report["overhead_vs_ungoverned_ms"]
    for arm in WEIGHTS:
        if arm not in overhead:
            _fail(f"arm '{arm}' missing from overhead_vs_ungoverned_ms")
    p50 = {arm: float(overhead[arm]["p50_ms"]) for arm in WEIGHTS}
    composite = sum(WEIGHTS[arm] * p50[arm] for arm in WEIGHTS)
    return {"composite": composite, **p50}


def main() -> None:
    run_correctness_gate()

    benchmark = load_benchmark()

    passes: list[dict[str, float]] = []
    for i in range(PASSES):
        print(f"[si_benchmark_gated] benchmark pass {i + 1}/{PASSES}...", file=sys.stderr)
        with tempfile.TemporaryDirectory(prefix="si-overhead-") as tmp:
            report = benchmark.run(ITERATIONS, WARMUP, Path(tmp))
        passes.append(composite_from_report(report))

    passes.sort(key=lambda p: p["composite"])
    median = passes[len(passes) // 2]  # PASSES is odd -> a real pass

    print(
        "[si_benchmark_gated] composites: "
        + ", ".join(f"{p['composite']:.4f}" for p in passes)
        + f" -> median {median['composite']:.4f}",
        file=sys.stderr,
    )

    _emit(
        {
            "primary": round(median["composite"], 4),
            "sub_scores": {
                "kernel_dispatch_p50_ms": round(median["kernel_dispatch"], 4),
                "receipt_gate_unsigned_p50_ms": round(median["receipt_gate_unsigned"], 4),
                "receipt_gate_signed_p50_ms": round(median["receipt_gate_signed_ed25519"], 4),
                "correctness_tests": "passed",
            },
        }
    )


if __name__ == "__main__":
    main()
