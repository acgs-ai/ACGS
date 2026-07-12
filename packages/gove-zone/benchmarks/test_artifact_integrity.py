"""Deterministic artifact-integrity guard for the ADR-0005 propagation budget gate.

No perf run: these tests only parse the committed
``.benchmarks/propagation-gate-week2.json`` artifact and cross-check it against the
live ``THRESHOLDS`` that the pytest gate asserts on. A drift or tamper between the
committed verdict artifact and the in-code gate therefore fails CI deterministically,
independent of any timing-sensitive benchmark run.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from benchmarks.test_propagation_overhead import THRESHOLDS

ARTIFACT_RELPATH = Path(".benchmarks/propagation-gate-week2.json")


def _repo_root() -> Path:
    """Resolve the repo root the same way ``emit_gate_artifact._repo_root`` does.

    Mirrors the generator so the artifact is located by ``git rev-parse`` rather
    than a hardcoded absolute path — the guard and the writer agree by construction.
    """
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, OSError):
        return Path.cwd()
    top = completed.stdout.strip()
    return Path(top) if top else Path.cwd()


def _load_artifact() -> dict[str, object]:
    path = _repo_root() / ARTIFACT_RELPATH
    assert path.exists(), f"gate artifact missing: {path}"
    return json.loads(path.read_text(encoding="utf-8"))


def test_artifact_exists_and_verdict_pass() -> None:
    record = _load_artifact()
    assert record["verdict"] == "PASS"


def test_artifact_thresholds_match_gate() -> None:
    # The committed thresholds MUST equal the live gate THRESHOLDS. If someone
    # relaxes the artifact without touching the code (or vice versa), this trips.
    record = _load_artifact()
    assert record["thresholds"] == THRESHOLDS


def test_artifact_measured_within_thresholds() -> None:
    # The artifact must be internally consistent: every measured metric stays
    # within its own threshold, matching the PASS verdict it records.
    record = _load_artifact()
    measured = record["measured"]
    assert isinstance(measured, dict)
    for key in THRESHOLDS:
        assert measured[key] <= THRESHOLDS[key], (
            f"{key}: measured {measured[key]} exceeds threshold {THRESHOLDS[key]}"
        )
