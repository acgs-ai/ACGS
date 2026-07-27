"""Emit the Week-2 propagation-gate verdict artifact.

Records the SAME ``median_measurement()`` the pytest gate
(``benchmarks/test_propagation_overhead.py``) asserts, then writes the verdict to
``.benchmarks/propagation-gate-week2.json`` at the repository root, in the shape
this module's ``build_gate_record()`` defines (the artifact schema is owned here; the
originating goal contract is kept in the maintainers' private store). This makes the
``ROADMAP.md`` ``test -f .benchmarks/propagation-gate-week2.json`` acceptance and
ADR-0005's "benchmark artifact is committed at ..." statement true with a real,
regenerable run rather than a hand-written number.

The shared ``median_measurement`` is median-of-N because the latency-overhead
metric is noise-dominated (both benchmark arms do identical work); a single run
swings widely and can spuriously trip the threshold. The median is central
tendency, not best-of, so it does not flatter the result. Token-consumption,
timeout-fail-closed, and heap figures are effectively deterministic. See ADR-0006.

Usage::

    cd packages/gove-zone
    uv run --extra dev python -m benchmarks.emit_gate_artifact

Exit code mirrors the verdict (0 = PASS, 1 = FAIL).
"""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from benchmarks.test_propagation_overhead import GATE_SAMPLES, THRESHOLDS, median_measurement

ARTIFACT_RELPATH = Path(".benchmarks/propagation-gate-week2.json")
GATE_NAME = "propagation-overhead-week2"


def _git_output(*args: str) -> str:
    try:
        completed = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, OSError):
        return ""
    return completed.stdout.strip()


def _repo_root() -> Path:
    top = _git_output("rev-parse", "--show-toplevel")
    return Path(top) if top else Path.cwd()


def build_gate_record(samples: int = GATE_SAMPLES) -> dict[str, object]:
    measured = median_measurement(samples)
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
