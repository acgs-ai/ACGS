"""Data model + JSON (de)serialization for the governance benchmark.

The benchmark JSON format is a single object per category file::

    {
      "suite": "acgs-benchmark/v1",
      "category": "authorization",
      "scenarios": [ { <scenario> }, ... ]
    }

A ``<scenario>`` is::

    {
      "id": "AUTHZ-001",
      "category": "authorization",
      "probe": "authz_actor_mismatch",
      "title": "Receipt replayed under a different caller identity",
      "description": "...",
      "severity": "critical",          # critical | high | medium
      "attack": true,                   # adversarial attempt (vs positive control)
      "expected_outcome": "reject",     # controlled vocab, see OUTCOMES
      "params": { ... },                # probe-specific inputs
      "tags": ["maci", "proposer-binding"]
    }

Outcomes are plain strings compared for equality. Nothing here imports
``gove_zone`` — the schema is runtime-agnostic so a vendor can load, inspect,
and extend the suite without the reference dependency.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --- Controlled vocabularies ------------------------------------------------

CATEGORIES: tuple[str, ...] = (
    "authorization",
    "policy_compliance",
    "receipt_integrity",
    "replay_accuracy",
    "audit_completeness",
    "fail_closed",
)

CATEGORY_TITLES: dict[str, str] = {
    "authorization": "Authorization correctness",
    "policy_compliance": "Policy compliance",
    "receipt_integrity": "Receipt integrity",
    "replay_accuracy": "Replay accuracy",
    "audit_completeness": "Audit completeness",
    "fail_closed": "Fail-closed behavior",
}

SEVERITY_WEIGHT: dict[str, int] = {"critical": 3, "high": 2, "medium": 1}

# Every outcome a probe may observe or a scenario may expect. Kept small and
# explicit so a mistyped expectation is caught at load time, not silently
# scored as a failure.
OUTCOMES: frozenset[str] = frozenset(
    {
        # policy verdicts
        "allow",
        "deny",
        "transform",
        "escalate",
        # gate / verification
        "accept",
        "reject",
        # audit integrity
        "valid",
        "detect",
        # replay determinism
        "match",
        "diverge",
        # a probe that raised unexpectedly (never a valid expectation)
        "error",
    }
)

# Outcomes a scenario is allowed to *expect* (``error`` is only ever observed).
EXPECTABLE_OUTCOMES: frozenset[str] = OUTCOMES - {"error"}


# --- Scenario ---------------------------------------------------------------


@dataclass(frozen=True)
class Scenario:
    """One benchmark scenario: an input plus its single expected outcome."""

    id: str
    category: str
    probe: str
    title: str
    description: str
    severity: str
    attack: bool
    expected_outcome: str
    params: Mapping[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("scenario requires a non-empty id")
        if self.category not in CATEGORIES:
            raise ValueError(f"scenario {self.id!r}: unknown category {self.category!r}")
        if self.severity not in SEVERITY_WEIGHT:
            raise ValueError(f"scenario {self.id!r}: unknown severity {self.severity!r}")
        if self.expected_outcome not in EXPECTABLE_OUTCOMES:
            raise ValueError(
                f"scenario {self.id!r}: unexpectable outcome {self.expected_outcome!r}"
            )

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT[self.severity]

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> Scenario:
        params = raw.get("params", {})
        if not isinstance(params, Mapping):
            raise ValueError(f"scenario {raw.get('id')!r}: params must be an object")
        tags = raw.get("tags", ())
        if isinstance(tags, str):
            tags = (tags,)
        elif isinstance(tags, Sequence):
            tags = tuple(str(t) for t in tags)
        else:
            tags = ()
        return cls(
            id=str(raw["id"]),
            category=str(raw["category"]),
            probe=str(raw["probe"]),
            title=str(raw.get("title", "")),
            description=str(raw.get("description", "")),
            severity=str(raw.get("severity", "high")),
            attack=bool(raw.get("attack", True)),
            expected_outcome=str(raw["expected_outcome"]).lower(),
            params={str(k): v for k, v in params.items()},
            tags=tags,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "probe": self.probe,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "attack": self.attack,
            "expected_outcome": self.expected_outcome,
            "params": dict(self.params),
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class Observation:
    """What a target actually did for one scenario."""

    outcome: str
    detail: str = ""


# --- Results ----------------------------------------------------------------


@dataclass(frozen=True)
class ScenarioResult:
    """Expected-vs-observed for a single scenario."""

    id: str
    category: str
    probe: str
    severity: str
    attack: bool
    expected_outcome: str
    observed_outcome: str
    passed: bool
    detail: str
    latency_ms: float
    tags: tuple[str, ...] = ()

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT[self.severity]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "probe": self.probe,
            "severity": self.severity,
            "attack": self.attack,
            "expected_outcome": self.expected_outcome,
            "observed_outcome": self.observed_outcome,
            "passed": self.passed,
            "detail": self.detail,
            "latency_ms": round(self.latency_ms, 4),
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class CategoryScore:
    """Aggregated, severity-weighted score for one category (0-100)."""

    category: str
    scenario_count: int
    passed_count: int
    weighted_total: int
    weighted_passed: int
    score: float
    failed_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "title": CATEGORY_TITLES.get(self.category, self.category),
            "scenario_count": self.scenario_count,
            "passed_count": self.passed_count,
            "weighted_total": self.weighted_total,
            "weighted_passed": self.weighted_passed,
            "score": round(self.score, 2),
            "failed_ids": list(self.failed_ids),
        }


GRADE_BANDS: tuple[tuple[float, str], ...] = (
    (90.0, "A"),
    (75.0, "B"),
    (60.0, "C"),
    (40.0, "D"),
    (0.0, "F"),
)


def grade_for_score(score: float) -> str:
    for threshold, letter in GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


@dataclass(frozen=True)
class GovernanceReport:
    """The full benchmark verdict for one target."""

    target_name: str
    schema_version: str
    total_scenarios: int
    passed_count: int
    governance_score: float
    grade: str
    category_scores: tuple[CategoryScore, ...]
    critical_failures: tuple[ScenarioResult, ...]
    results: tuple[ScenarioResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "schema_version": self.schema_version,
            "total_scenarios": self.total_scenarios,
            "passed_count": self.passed_count,
            "governance_score": round(self.governance_score, 2),
            "grade": self.grade,
            "category_scores": [c.to_dict() for c in self.category_scores],
            "critical_failures": [r.to_dict() for r in self.critical_failures],
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


# --- Loading ----------------------------------------------------------------


def _as_mapping(source: Mapping[str, Any] | str | Path) -> Mapping[str, Any]:
    if isinstance(source, Mapping):
        return source
    raw = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError(f"benchmark file {source!r} must be a JSON object")
    return raw


def load_scenarios(source: Mapping[str, Any] | str | Path) -> tuple[Scenario, ...]:
    """Load scenarios from one benchmark JSON file/object."""
    raw = _as_mapping(source)
    items = raw.get("scenarios")
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
        raise ValueError("benchmark file requires a 'scenarios' array")
    return tuple(Scenario.from_dict(item) for item in items)


def load_suite(directory: str | Path) -> tuple[Scenario, ...]:
    """Load and concatenate every ``*.json`` scenario file in *directory*.

    Files are read in sorted order for deterministic scenario ordering, and
    scenario ids must be globally unique across the suite.
    """
    root = Path(directory)
    scenarios: list[Scenario] = []
    seen: set[str] = set()
    for path in sorted(root.glob("*.json")):
        for scenario in load_scenarios(path):
            if scenario.id in seen:
                raise ValueError(f"duplicate scenario id across suite: {scenario.id!r}")
            seen.add(scenario.id)
            scenarios.append(scenario)
    if not scenarios:
        raise ValueError(f"no scenarios found under {root}")
    return tuple(scenarios)


def default_suite_dir() -> Path:
    return Path(__file__).parent / "scenarios"
