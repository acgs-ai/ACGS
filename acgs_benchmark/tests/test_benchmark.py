"""Benchmark integrity + discrimination tests.

The critical property under test is **discrimination**: a benchmark that can
only ever report 100 is worthless. These tests prove that

* the reference gove-zone target scores 100 (it enforces correctly), AND
* a permissive (accept-everything) target scores far lower and trips critical
  failures, AND
* a paranoid (deny-everything) target cannot game the score either — it fails
  the positive controls embedded in every category.
"""

from __future__ import annotations

import pytest

from acgs_benchmark.schema import (
    CATEGORIES,
    Observation,
    Scenario,
    default_suite_dir,
    grade_for_score,
    load_suite,
)
from acgs_benchmark.scoring import run_benchmark, score_category
from acgs_benchmark.targets import GovernanceTarget

SCENARIOS = load_suite(default_suite_dir())


# --- corpus integrity -------------------------------------------------------


def test_corpus_has_100_scenarios() -> None:
    assert len(SCENARIOS) == 100


def test_scenario_ids_unique() -> None:
    ids = [s.id for s in SCENARIOS]
    assert len(ids) == len(set(ids))


def test_every_category_populated() -> None:
    counts = {c: sum(1 for s in SCENARIOS if s.category == c) for c in CATEGORIES}
    for category, count in counts.items():
        assert count > 0, f"category {category} is empty"
    assert sum(counts.values()) == 100


def test_every_category_has_positive_control() -> None:
    # Non-attack (positive-control) scenarios are what stop a deny-everything
    # target from scoring 100. Each category must carry at least one.
    for category in CATEGORIES:
        controls = [s for s in SCENARIOS if s.category == category and not s.attack]
        assert controls, f"category {category} lacks a positive control"


# --- discriminating mock targets -------------------------------------------


class _FixedTarget(GovernanceTarget):
    """Maps each probe kind to a fixed outcome, ignoring the actual system."""

    def __init__(self, name: str, mapping: dict[str, str], default: str) -> None:
        self.name = name
        self._mapping = mapping
        self._default = default

    def run_probe(self, scenario: Scenario) -> Observation:
        return Observation(self._mapping.get(scenario.probe, self._default), "mock")


def _permissive_target() -> _FixedTarget:
    # Always does the unsafe/permissive thing: accept, allow, and never detect.
    mapping = {
        "policy_decision": "allow",
        "replay_match": "match",
        "replay_arg_tamper": "match",
        "replay_policy_drift": "match",
        "audit_intact": "valid",
        "audit_gap": "valid",
        "audit_reorder": "valid",
        "audit_tamper": "valid",
        "failclosed_policy_error": "allow",
    }
    return _FixedTarget("permissive-mock", mapping, default="accept")


def _paranoid_target() -> _FixedTarget:
    # Always blocks: reject, deny, detect, diverge. Fails positive controls.
    mapping = {
        "policy_decision": "deny",
        "replay_match": "diverge",
        "replay_arg_tamper": "diverge",
        "replay_policy_drift": "diverge",
        "audit_intact": "detect",
        "audit_gap": "detect",
        "audit_reorder": "detect",
        "audit_tamper": "detect",
        "failclosed_policy_error": "deny",
    }
    return _FixedTarget("paranoid-mock", mapping, default="reject")


def test_permissive_target_scores_low_with_critical_failures() -> None:
    report = run_benchmark(_permissive_target(), SCENARIOS)
    # It should only pass the positive controls, so well under half.
    assert report.governance_score < 40.0
    assert report.grade in {"D", "F"}
    # An accept-everything runtime bypasses authorization, receipts, and
    # fail-closed — those must show up as critical failures.
    assert len(report.critical_failures) >= 20


def test_paranoid_target_cannot_game_the_score() -> None:
    report = run_benchmark(_paranoid_target(), SCENARIOS)
    # Denying everything fails every positive control, so it is NOT 100.
    assert report.governance_score < 100.0
    failed_controls = [r for r in report.results if not r.passed and not r.attack]
    assert failed_controls, "paranoid target should fail the positive controls"


def test_scores_span_the_range() -> None:
    permissive = run_benchmark(_permissive_target(), SCENARIOS).governance_score
    paranoid = run_benchmark(_paranoid_target(), SCENARIOS).governance_score
    # The benchmark must separate a permissive runtime from a paranoid one.
    assert permissive < paranoid


# --- scoring math -----------------------------------------------------------


def test_grade_bands() -> None:
    assert grade_for_score(95) == "A"
    assert grade_for_score(80) == "B"
    assert grade_for_score(65) == "C"
    assert grade_for_score(45) == "D"
    assert grade_for_score(10) == "F"


def test_category_score_is_severity_weighted() -> None:
    report = run_benchmark(_permissive_target(), SCENARIOS)
    for c in report.category_scores:
        subset = [r for r in report.results if r.category == c.category]
        assert c.weighted_total == sum(r.weight for r in subset)
        recomputed = score_category(c.category, report.results)
        assert recomputed.score == pytest.approx(c.score)


# --- reference target (requires gove_zone) ----------------------------------


def _gove_zone_available() -> bool:
    try:
        import gove_zone  # noqa: F401
    except ImportError:
        return False
    return True


@pytest.mark.skipif(not _gove_zone_available(), reason="gove_zone not importable")
def test_reference_target_scores_100() -> None:
    from acgs_benchmark.targets import GoveZoneTarget

    report = run_benchmark(GoveZoneTarget(), SCENARIOS)
    assert report.total_scenarios == 100
    assert report.governance_score == pytest.approx(100.0), (
        f"reference regressed: {[r.id for r in report.results if not r.passed]}"
    )
    assert not report.critical_failures
    assert report.grade == "A"


@pytest.mark.skipif(not _gove_zone_available(), reason="gove_zone not importable")
def test_reference_observations_are_real_enforcement() -> None:
    # Guard against a probe that trivially returns the expected value: the
    # reject/detect details must carry a real gove_zone error/failure message.
    from acgs_benchmark.targets import GoveZoneTarget

    report = run_benchmark(GoveZoneTarget(), SCENARIOS)
    rejects = [r for r in report.results if r.observed_outcome == "reject"]
    assert rejects
    assert all("Error" in r.detail or "error" in r.detail for r in rejects)
    detects = [r for r in report.results if r.observed_outcome == "detect"]
    assert detects
    assert all(r.detail for r in detects)
