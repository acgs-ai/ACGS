"""Integrity guard for the committed Week-2 propagation-gate artifact.

Closes the B7 failure class: ADR-0005 and ``ROADMAP.md`` cite a committed artifact
at ``.benchmarks/propagation-gate-week2.json`` with verdict ``PASS``. This test
fails if that artifact is missing, malformed, no longer reads ``PASS``, has its
thresholds tampered to a more permissive value, or contradicts its own
``measured`` vs the *canonical* thresholds — the silent-drift / hand-written-number
mode that produced ADR-0006.

It deliberately does NOT run the benchmark: the latency-overhead metric is
noise-dominated, so running it in CI would reintroduce flakiness. Running the
(median-hardened) benchmark is the job of
``packages/gove-zone/benchmarks/test_propagation_overhead.py``; this guards the
*committed evidence* against drift.

``EXPECTED_THRESHOLDS`` is the source-of-truth contract, kept in lockstep with
``THRESHOLDS`` in that benchmark module. Importing it would couple this
lightweight guard to the benchmark's heavy import chain
(``benchmarks.agent_chain``, the authz strategies, ``gove_zone``) and need a
``sys.path`` insert (``benchmarks`` is not an installed package), so the contract
is pinned here instead; if the gate thresholds ever legitimately change, update
BOTH — a mismatch failing this test is the intended signal. (``emit_gate_artifact``
writes the artifact's ``thresholds`` from the real ``THRESHOLDS``, so on
regeneration ``test_artifact_thresholds_match_canonical`` transitively forces
``EXPECTED_THRESHOLDS == THRESHOLDS`` or fails.)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ARTIFACT = Path(__file__).resolve().parents[1] / ".benchmarks" / "propagation-gate-week2.json"
REQUIRED_KEYS = {"gate", "verdict", "thresholds", "measured", "ran_at", "kernel_sha"}
EXPECTED_THRESHOLDS = {
    "mean_latency_overhead_pct": 15.0,
    "p95_latency_overhead_pct": 25.0,
    "token_consumption_overhead_pct": 10.0,
    "heap_growth_mb": 5.0,
    "timeout_fail_closed_ms": 500.0,
}


def _load() -> dict[str, Any]:
    assert ARTIFACT.exists(), f"Week-2 gate artifact missing: {ARTIFACT}"
    data: dict[str, Any] = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    return data


def test_artifact_present_and_well_formed() -> None:
    data = _load()
    missing = REQUIRED_KEYS - set(data)
    assert not missing, f"artifact missing required keys: {missing}"
    assert data["gate"] == "propagation-overhead-week2"


def test_artifact_thresholds_match_canonical() -> None:
    # Binds to the source-of-truth contract: a tampered/hand-written artifact that
    # loosens a threshold (e.g. mean -> 999) fails here instead of sailing through.
    data = _load()
    assert data["thresholds"] == EXPECTED_THRESHOLDS, (
        f"artifact thresholds {data['thresholds']} != canonical {EXPECTED_THRESHOLDS} "
        f"(tampered or drifted from the benchmark gate — regenerate the artifact)"
    )


def test_artifact_verdict_is_pass_and_self_consistent() -> None:
    data = _load()
    assert data["verdict"] == "PASS", f"committed verdict is {data['verdict']!r}, expected PASS"
    measured: dict[str, float] = data["measured"]
    # Every canonical metric must be present (an empty/partial measured dict must not
    # pass vacuously) and within its canonical threshold.
    missing_metrics = set(EXPECTED_THRESHOLDS) - set(measured)
    assert not missing_metrics, f"measured is missing metrics: {missing_metrics}"
    over = [key for key in EXPECTED_THRESHOLDS if measured[key] > EXPECTED_THRESHOLDS[key]]
    assert not over, (
        f"verdict says PASS but these metrics exceed their canonical thresholds: {over} "
        f"(measured-vs-threshold drift — regenerate the artifact)"
    )
