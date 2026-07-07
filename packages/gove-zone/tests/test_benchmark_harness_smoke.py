"""Smoke test: the governed-actions benchmark harness runs and enforces.

Keeps the benchmark from rotting: a tiny scale exercises every arm (policy
evaluation, audit write incl. the batched arm, receipt validation, dispatch,
replay, concurrency) plus the built-in sanity checks (deny works, tampered
receipt rejected, replay valid).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# Loaded by explicit file path so this test is collected and importable from
# any invocation cwd (CI runs `pytest tests/` from the package dir; the repo
# root also has an unrelated `benchmarks/` directory that would shadow a
# name-based `import benchmarks`).
_BENCH_FILE = Path(__file__).resolve().parents[1] / "benchmarks" / "governed_actions_bench.py"
_spec = importlib.util.spec_from_file_location("governed_actions_bench", _BENCH_FILE)
assert _spec is not None and _spec.loader is not None
bench = importlib.util.module_from_spec(_spec)
# Must be registered before exec: the module defines dataclasses, and the
# dataclass machinery resolves sys.modules[cls.__module__] at class creation.
sys.modules[_spec.name] = bench
_spec.loader.exec_module(bench)


def test_harness_runs_all_arms_at_tiny_scale(tmp_path: Path) -> None:
    report = bench.run([25], tmp_path)

    assert report["benchmark"] == "governed_actions"
    assert len(report["scales"]) == 1
    scale = report["scales"][0]
    assert scale["n"] == 25
    metrics = scale["metrics"]

    for arm in (
        "policy_evaluation",
        "audit_write",
        "receipt_validation_unsigned",
        "end_to_end_dispatch",
        "replay_verification",
        "concurrent_dispatch",
    ):
        assert arm in metrics, f"missing benchmark arm: {arm}"

    assert metrics["policy_evaluation"]["iterations"] == 25
    assert metrics["replay_verification"]["valid"] is True
    assert (
        metrics["replay_verification"]["events_matched"]
        == (metrics["replay_verification"]["events_total"])
    )
    assert metrics["concurrent_dispatch"]["iterations"] == 25
    # append_many exists on ChainHashAuditStore, so the batched arm must report.
    assert metrics["audit_write_batched"]["iterations"] == 25
