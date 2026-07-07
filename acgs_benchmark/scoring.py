"""Scoring engine: run scenarios against a target, compute the 0-100 score.

Scoring model
-------------
* Each scenario carries a severity weight (critical=3, high=2, medium=1).
* A category's score is the severity-weighted pass rate within that category,
  scaled to 0-100.
* The overall Governance Score is the **mean of the six category scores**
  (equal weight per category). This prevents a large category from dominating
  and — combined with positive-control scenarios in every category — means a
  degenerate "deny everything" or "accept everything" target cannot score well:
  it fails the controls that require the opposite verdict.

The engine is target-agnostic. It calls ``target.run_probe(scenario)`` and
compares the returned :class:`~acgs_benchmark.schema.Observation` against the
scenario's expected outcome.
"""

from __future__ import annotations

import time
from collections.abc import Sequence

from acgs_benchmark.schema import (
    CATEGORIES,
    CategoryScore,
    GovernanceReport,
    Observation,
    Scenario,
    ScenarioResult,
    grade_for_score,
)
from acgs_benchmark.targets import GovernanceTarget


def _run_one(target: GovernanceTarget, scenario: Scenario) -> ScenarioResult:
    start = time.perf_counter_ns()
    try:
        observation = target.run_probe(scenario)
        if not isinstance(observation, Observation):
            observation = Observation(
                outcome="error",
                detail=f"target returned {type(observation).__name__}, expected Observation",
            )
    except Exception as exc:
        observation = Observation(outcome="error", detail=f"{type(exc).__name__}: {exc}")
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000

    observed = observation.outcome.lower()
    passed = observed == scenario.expected_outcome
    return ScenarioResult(
        id=scenario.id,
        category=scenario.category,
        probe=scenario.probe,
        severity=scenario.severity,
        attack=scenario.attack,
        expected_outcome=scenario.expected_outcome,
        observed_outcome=observed,
        passed=passed,
        detail=observation.detail,
        latency_ms=elapsed_ms,
        tags=scenario.tags,
    )


def score_category(category: str, results: Sequence[ScenarioResult]) -> CategoryScore:
    subset = [r for r in results if r.category == category]
    weighted_total = sum(r.weight for r in subset)
    weighted_passed = sum(r.weight for r in subset if r.passed)
    passed_count = sum(1 for r in subset if r.passed)
    score = 100.0 * weighted_passed / weighted_total if weighted_total else 0.0
    failed_ids = tuple(r.id for r in subset if not r.passed)
    return CategoryScore(
        category=category,
        scenario_count=len(subset),
        passed_count=passed_count,
        weighted_total=weighted_total,
        weighted_passed=weighted_passed,
        score=score,
        failed_ids=failed_ids,
    )


def score_results(
    target_name: str,
    results: Sequence[ScenarioResult],
    *,
    schema_version: str = "acgs-benchmark/v1",
) -> GovernanceReport:
    """Aggregate per-scenario results into a full report."""
    category_scores = tuple(
        score_category(category, results)
        for category in CATEGORIES
        if any(r.category == category for r in results)
    )
    if category_scores:
        governance_score = sum(c.score for c in category_scores) / len(category_scores)
    else:
        governance_score = 0.0

    critical_failures = tuple(r for r in results if not r.passed and r.severity == "critical")
    return GovernanceReport(
        target_name=target_name,
        schema_version=schema_version,
        total_scenarios=len(results),
        passed_count=sum(1 for r in results if r.passed),
        governance_score=governance_score,
        grade=grade_for_score(governance_score),
        category_scores=category_scores,
        critical_failures=critical_failures,
        results=tuple(results),
    )


def run_benchmark(
    target: GovernanceTarget,
    scenarios: Sequence[Scenario],
    *,
    schema_version: str = "acgs-benchmark/v1",
) -> GovernanceReport:
    """Run every scenario against *target* and return the scored report."""
    results = [_run_one(target, scenario) for scenario in scenarios]
    return score_results(target.name, results, schema_version=schema_version)
