"""Emit the Week-2 propagation-gate verdict artifact.

Runs the SAME ``measure_gate()`` the pytest gate
(``benchmarks/test_propagation_overhead.py``) asserts and writes the verdict to
``.benchmarks/propagation-gate-week2.json`` at the repository root, in the shape
``docs/codex-goals/phase1-week2-paper-gate.md`` specifies. This makes the
``ROADMAP.md`` ``test -f .benchmarks/propagation-gate-week2.json`` acceptance and
ADR-0005's "benchmark artifact is committed at ..." statement true with a real,
regenerable run rather than a hand-written number.

Why median-of-N: the latency-overhead metric is noise-dominated. Both benchmark
arms perform identical bounded work, so the "overhead" between them is mostly
scheduling jitter; a single run swings widely (observed roughly -20%..+17% on a
loaded machine) and can spuriously trip the <= 15% mean / <= 25% p95 thresholds.
We therefore record the MEDIAN over ``SAMPLES`` runs (central tendency, not
best-of, so this does not flatter the result) and compute the verdict from the
medians. Token-consumption, timeout-fail-closed, and heap figures are effectively
deterministic and pass regardless. See ADR-0006 for the per-chain methodology.

Usage::

    cd packages/gove-zone
    uv run --extra dev python -m benchmarks.emit_gate_artifact

Exit code mirrors the verdict (0 = PASS, 1 = FAIL).
"""

from __future__ import annotations

import json
import statistics
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from benchmarks.test_propagation_overhead import THRESHOLDS, measure_gate

ARTIFACT_RELPATH = Path(".benchmarks/propagation-gate-week2.json")
GATE_NAME = "propagation-overhead-week2"
SAMPLES = 5
_INT_KEYS = frozenset(
    {"propagation_token_units", "token_baseline_token_units", "concurrency", "payload_kb"}
)


def _git_output(*args: str) -> str:
    try:
        completed = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, OSError):
        return ""
    return completed.stdout.strip()


def _repo_root() -> Path:
    top = _git_output("rev-parse", "--show-toplevel")
    return Path(top) if top else Path.cwd()


def _median_measured(samples: int) -> dict[str, float]:
    """Median per metric over ``samples`` independent runs."""
    runs: list[dict[str, int | float]] = [measure_gate().to_dict() for _ in range(samples)]
    measured: dict[str, float] = {}
    for key in runs[0]:
        median = statistics.median(float(run[key]) for run in runs)
        measured[key] = round(median) if key in _INT_KEYS else round(median, 3)
    return measured


def build_gate_record(samples: int = SAMPLES) -> dict[str, object]:
    measured = _median_measured(samples)
    verdict = "PASS" if all(measured[key] <= THRESHOLDS[key] for key in THRESHOLDS) else "FAIL"
    return {
        "gate": GATE_NAME,
        "verdict": verdict,
        "thresholds": dict(THRESHOLDS),
        "measured": measured,
        "samples": samples,
        "aggregation": "median",
        "note": (
            "Latency-overhead metrics are median-of-N and timing-dependent (noise-dominated; "
            "both arms do identical work). The gate asserts staying within threshold, not a "
            "fixed figure. Token/timeout/heap are effectively deterministic. See ADR-0006."
        ),
        "ran_at": datetime.now(UTC).isoformat(),
        "kernel_sha": _git_output("rev-parse", "HEAD") or "unknown",
    }


def main() -> int:
    record = build_gate_record()
    out_path = _repo_root() / ARTIFACT_RELPATH
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out_path} (verdict={record['verdict']}, samples={record['samples']})")
    return 0 if record["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
