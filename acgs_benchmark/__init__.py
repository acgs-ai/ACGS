"""ACGS Agent Governance Capability Benchmark.

A pluggable, adversarial benchmark that scores how well a governed-agent
runtime enforces its safety contract. It exercises six capability categories
with 100 attack scenarios, runs each against a :class:`~acgs_benchmark.targets.GovernanceTarget`,
and produces a 0-100 Governance Score plus an Agent Governance Capability Report.

The reference target (:class:`~acgs_benchmark.targets.GoveZoneTarget`) drives the
real ``gove_zone`` receipt-gated kernel. Any other runtime can be scored by
implementing the small ``GovernanceTarget`` interface.
"""

from __future__ import annotations

from acgs_benchmark.schema import (
    CATEGORIES,
    SEVERITY_WEIGHT,
    CategoryScore,
    GovernanceReport,
    Observation,
    Scenario,
    ScenarioResult,
    grade_for_score,
    load_scenarios,
    load_suite,
)
from acgs_benchmark.scoring import run_benchmark, score_results

__all__ = [
    "CATEGORIES",
    "SEVERITY_WEIGHT",
    "CategoryScore",
    "GovernanceReport",
    "Observation",
    "Scenario",
    "ScenarioResult",
    "grade_for_score",
    "load_scenarios",
    "load_suite",
    "run_benchmark",
    "score_results",
]

__version__ = "1.0.0"
SCHEMA_VERSION = "acgs-benchmark/v1"
