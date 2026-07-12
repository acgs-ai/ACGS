"""Phase 1 Week 2 propagation-overhead benchmark gate."""

from __future__ import annotations

import statistics
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import pytest

from benchmarks.agent_chain import AgentChainRunner, ChainRunResult
from benchmarks.authz_propagation import PropagationAuthzStrategy
from benchmarks.authz_token_baseline import TokenBaselineAuthzStrategy
from gove_zone import DeniedError

CONCURRENCY = 10

THRESHOLDS: dict[str, float] = {
    "mean_latency_overhead_pct": 15.0,
    "p95_latency_overhead_pct": 25.0,
    "token_consumption_overhead_pct": 10.0,
    "heap_growth_mb": 5.0,
    "timeout_fail_closed_ms": 500.0,
}


def gate_verdict(measured: dict[str, float], thresholds: dict[str, float] = THRESHOLDS) -> str:
    """PASS/FAIL verdict for a measurement against the gate thresholds.

    Mirrors ``benchmarks.emit_gate_artifact.build_gate_record``'s rule: every
    measured metric must stay within its threshold. Factored out so the
    fail-closed negative control can prove the comparison actually GATES without a
    timing-dependent benchmark run.
    """
    return "PASS" if all(measured[key] <= thresholds[key] for key in thresholds) else "FAIL"


@dataclass(frozen=True)
class GateMeasurement:
    mean_latency_overhead_pct: float
    p95_latency_overhead_pct: float
    token_consumption_overhead_pct: float
    heap_growth_mb: float
    timeout_fail_closed_ms: float
    propagation_mean_ms: float
    propagation_p95_ms: float
    propagation_token_units: int
    token_baseline_mean_ms: float
    token_baseline_p95_ms: float
    token_baseline_token_units: int
    concurrency: int
    payload_kb: int

    def to_dict(self) -> dict[str, int | float]:
        return {
            "mean_latency_overhead_pct": round(self.mean_latency_overhead_pct, 3),
            "p95_latency_overhead_pct": round(self.p95_latency_overhead_pct, 3),
            "token_consumption_overhead_pct": round(self.token_consumption_overhead_pct, 3),
            "heap_growth_mb": round(self.heap_growth_mb, 3),
            "timeout_fail_closed_ms": round(self.timeout_fail_closed_ms, 3),
            "propagation_mean_ms": round(self.propagation_mean_ms, 3),
            "propagation_p95_ms": round(self.propagation_p95_ms, 3),
            "propagation_token_units": self.propagation_token_units,
            "token_baseline_mean_ms": round(self.token_baseline_mean_ms, 3),
            "token_baseline_p95_ms": round(self.token_baseline_p95_ms, 3),
            "token_baseline_token_units": self.token_baseline_token_units,
            "concurrency": self.concurrency,
            "payload_kb": self.payload_kb,
        }


def measure_gate() -> GateMeasurement:
    """Run both benchmark arms and return threshold-facing measurements."""
    tracemalloc.start()
    start_current, _start_peak = tracemalloc.get_traced_memory()
    token_latencies, token_units = _run_arm(TokenBaselineAuthzStrategy())
    propagation_latencies, propagation_units = _run_arm(PropagationAuthzStrategy())
    end_current, end_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    timeout_ms = _measure_timeout_fail_closed()
    baseline_mean = statistics.fmean(token_latencies)
    propagation_mean = statistics.fmean(propagation_latencies)
    baseline_p95 = _p95(token_latencies)
    propagation_p95 = _p95(propagation_latencies)

    return GateMeasurement(
        mean_latency_overhead_pct=_pct_over(propagation_mean, baseline_mean),
        p95_latency_overhead_pct=_pct_over(propagation_p95, baseline_p95),
        token_consumption_overhead_pct=_pct_over(propagation_units, token_units),
        heap_growth_mb=max(0.0, end_current - start_current, end_peak - start_current)
        / (1024 * 1024),
        timeout_fail_closed_ms=timeout_ms,
        propagation_mean_ms=propagation_mean * 1000,
        propagation_p95_ms=propagation_p95 * 1000,
        propagation_token_units=propagation_units,
        token_baseline_mean_ms=baseline_mean * 1000,
        token_baseline_p95_ms=baseline_p95 * 1000,
        token_baseline_token_units=token_units,
        concurrency=CONCURRENCY,
        payload_kb=50,
    )


GATE_SAMPLES = 5
_INT_KEYS = frozenset(
    {"propagation_token_units", "token_baseline_token_units", "concurrency", "payload_kb"}
)


def median_measurement(samples: int = GATE_SAMPLES) -> dict[str, float]:
    """Median per metric over ``samples`` independent ``measure_gate()`` runs.

    The latency-overhead metric is noise-dominated: both arms perform identical
    bounded work, so a single run swings widely (roughly -20%..+17% under load)
    and can spuriously trip the ``<= 15%`` mean threshold. The median is the
    robust central tendency the gate asserts on. Shared with
    ``benchmarks/emit_gate_artifact.py`` so the committed artifact and the gate
    agree by construction. See ADR-0006 for the per-chain methodology.
    """
    runs = [measure_gate().to_dict() for _ in range(samples)]
    out: dict[str, float] = {}
    for key in runs[0]:
        median = statistics.median(float(run[key]) for run in runs)
        out[key] = round(median) if key in _INT_KEYS else round(median, 3)
    return out


def test_propagation_gate_thresholds() -> None:
    # Median over GATE_SAMPLES runs: the latency-overhead metric is noise-dominated
    # (both arms do identical work), so a single run is flaky. Assert on the median.
    data = median_measurement()
    assert data["mean_latency_overhead_pct"] <= THRESHOLDS["mean_latency_overhead_pct"]
    assert data["p95_latency_overhead_pct"] <= THRESHOLDS["p95_latency_overhead_pct"]
    assert data["token_consumption_overhead_pct"] <= THRESHOLDS["token_consumption_overhead_pct"]
    assert data["heap_growth_mb"] <= THRESHOLDS["heap_growth_mb"]
    assert data["timeout_fail_closed_ms"] <= THRESHOLDS["timeout_fail_closed_ms"]


def test_gate_fails_closed_when_threshold_breached(monkeypatch: pytest.MonkeyPatch) -> None:
    # Deterministic fail-closed negative control (no wall-clock): a synthetic
    # in-budget measurement must PASS, and tightening ONE threshold to an
    # impossible value must flip the verdict to FAIL — proving the gate gates.
    # monkeypatch.setitem restores THRESHOLDS after the test, so no mutation leaks.
    within_budget = {key: value / 2 for key, value in THRESHOLDS.items()}
    assert gate_verdict(within_budget) == "PASS"

    monkeypatch.setitem(THRESHOLDS, "token_consumption_overhead_pct", -1.0)
    assert (
        within_budget["token_consumption_overhead_pct"]
        > THRESHOLDS["token_consumption_overhead_pct"]
    )
    assert gate_verdict(within_budget) == "FAIL"


def _run_arm(strategy: Any) -> tuple[list[float], int]:
    """Run CONCURRENCY chains in parallel, returning REAL per-chain latencies.

    Each chain self-times its full Orchestrator -> Planner -> Executor walk
    so that ``p95`` and ``mean`` operate on a genuine distribution. The
    earlier wall-clock-total / N approach made p95 mathematically identical
    to mean, which silently disabled the 25% p95 threshold.
    """
    runner = AgentChainRunner(strategy, tool_work=_tool_work)
    try:
        with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            timed: list[tuple[float, ChainRunResult]] = list(
                pool.map(lambda i: _timed_run_one(runner, i), range(CONCURRENCY))
            )
        latencies = [elapsed for elapsed, _ in timed]
        chain_results = [r for _, r in timed]
        return latencies, sum(r.token_units for r in chain_results)
    finally:
        runner.close()


def _timed_run_one(runner: AgentChainRunner, chain_id: int) -> tuple[float, ChainRunResult]:
    started = time.perf_counter()
    result = runner.run_one(chain_id)
    return time.perf_counter() - started, result


def _tool_work(payload: Any) -> None:
    # Simulates bounded in-process payload handling without external network.
    repr(payload).encode("utf-8")
    time.sleep(0.002)


def _measure_timeout_fail_closed() -> float:
    runner = AgentChainRunner(
        PropagationAuthzStrategy(lookup_delay_seconds=1.0),
        policy_timeout=0.45,
    )
    started = time.perf_counter()
    try:
        with pytest.raises(DeniedError):
            runner.run_one(999)
    finally:
        runner.close()
    return (time.perf_counter() - started) * 1000


def _p95(values: list[float]) -> float:
    return statistics.quantiles(values, n=100, method="inclusive")[94]


def _pct_over(candidate: float, baseline: float) -> float:
    if baseline <= 0:
        return 0.0
    return ((candidate - baseline) / baseline) * 100
