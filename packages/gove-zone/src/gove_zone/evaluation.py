"""Fixture evaluation for policy bundles.

This module is the local, no-dependency bridge from reviewable
``RuleSetPolicy`` bundles to benchmark-style fixtures inspired by
AgentDojo/InjecAgent/ToolEmu. It does not emulate a full agent environment;
it deterministically replays proposed tool calls against a policy bundle and
reports whether expected pre-execution decisions were produced.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from gove_zone.decision import Decision
from gove_zone.policy import Policy
from gove_zone.tool import ToolCall, normalize_path_context

JsonSource = Mapping[str, Any] | str | Path


def _as_mapping(source: JsonSource) -> Mapping[str, Any]:
    if isinstance(source, Mapping):
        return source
    raw = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("evaluation fixture must be a JSON object")
    return raw


def _as_string_sequence(value: Any, *, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return tuple(str(item) for item in value)
    raise ValueError(f"{field_name} must be a string or sequence")


def _decision(value: Any) -> Decision:
    try:
        return value if isinstance(value, Decision) else Decision(str(value).lower())
    except ValueError as exc:
        raise ValueError(f"unsupported expected_decision: {value!r}") from exc


@dataclass(frozen=True)
class EvaluationScenario:
    """One expected policy decision for a proposed tool call."""

    scenario_id: str
    tool: str
    expected_decision: Decision
    category: str = "regression"
    actor: str = "fixture-agent"
    args: Mapping[str, Any] = field(default_factory=dict)
    goal: str = ""
    path: tuple[str, ...] = ()
    state: Mapping[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> EvaluationScenario:
        scenario_id = str(raw.get("id", "")).strip()
        tool = str(raw.get("tool", "")).strip()
        if not scenario_id:
            raise ValueError("evaluation scenario requires a non-empty id")
        if not tool:
            raise ValueError(f"evaluation scenario {scenario_id!r} requires a non-empty tool")
        args = raw.get("args", {})
        state = raw.get("state", {})
        if not isinstance(args, Mapping):
            raise ValueError(f"evaluation scenario {scenario_id!r} args must be a mapping")
        if not isinstance(state, Mapping):
            raise ValueError(f"evaluation scenario {scenario_id!r} state must be a mapping")
        return cls(
            scenario_id=scenario_id,
            tool=tool,
            expected_decision=_decision(raw.get("expected_decision", "allow")),
            category=str(raw.get("category", "regression")),
            actor=str(raw.get("actor", "fixture-agent")),
            args={str(key): value for key, value in args.items()},
            goal=str(raw.get("goal", "")),
            path=normalize_path_context(raw.get("path")),
            state={str(key): value for key, value in state.items()},
            tags=_as_string_sequence(raw.get("tags"), field_name="tags"),
        )

    def to_call(self) -> ToolCall:
        return ToolCall(
            name=self.tool,
            args=self.args,
            goal=self.goal,
            actor=self.actor,
            path=self.path,
            state=self.state,
        )


@dataclass(frozen=True)
class EvaluationResult:
    """Actual policy result for one fixture scenario."""

    scenario_id: str
    category: str
    expected_decision: Decision
    actual_decision: Decision
    passed: bool
    matched_rules: tuple[str, ...]
    reason: str
    latency_ms: float
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.scenario_id,
            "category": self.category,
            "expected_decision": self.expected_decision.value,
            "actual_decision": self.actual_decision.value,
            "passed": self.passed,
            "matched_rules": list(self.matched_rules),
            "reason": self.reason,
            "latency_ms": round(self.latency_ms, 6),
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class EvaluationReport:
    """Aggregate evaluation metrics for a policy bundle."""

    dataset: str
    policy_version: str
    results: tuple[EvaluationResult, ...]

    @property
    def scenario_count(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for result in self.results if result.passed)

    @property
    def failed(self) -> int:
        return self.scenario_count - self.passed

    @property
    def attack_success_rate(self) -> float | None:
        attacks = [result for result in self.results if result.category == "attack"]
        if not attacks:
            return None
        allowed = sum(1 for result in attacks if result.actual_decision is Decision.ALLOW)
        return allowed / len(attacks)

    @property
    def utility_retention_rate(self) -> float | None:
        utility = [result for result in self.results if result.category == "utility"]
        if not utility:
            return None
        retained = sum(1 for result in utility if result.actual_decision is Decision.ALLOW)
        return retained / len(utility)

    @property
    def p95_latency_ms(self) -> float | None:
        if not self.results:
            return None
        latencies = sorted(result.latency_ms for result in self.results)
        index = max(0, min(len(latencies) - 1, int((len(latencies) * 0.95) - 1)))
        return latencies[index]

    def to_dict(self) -> dict[str, Any]:
        p95 = self.p95_latency_ms
        return {
            "dataset": self.dataset,
            "policy_version": self.policy_version,
            "scenario_count": self.scenario_count,
            "passed": self.passed,
            "failed": self.failed,
            "attack_success_rate": self.attack_success_rate,
            "utility_retention_rate": self.utility_retention_rate,
            "p95_latency_ms": None if p95 is None else round(p95, 6),
            "results": [result.to_dict() for result in self.results],
        }


def load_evaluation_scenarios(source: JsonSource) -> tuple[EvaluationScenario, ...]:
    raw = _as_mapping(source)
    raw_scenarios = raw.get("scenarios")
    if not isinstance(raw_scenarios, Sequence) or isinstance(
        raw_scenarios, (str, bytes, bytearray)
    ):
        raise ValueError("evaluation fixture requires a scenarios sequence")
    scenarios: list[EvaluationScenario] = []
    for item in raw_scenarios:
        if not isinstance(item, Mapping):
            raise ValueError("each evaluation scenario must be a JSON object")
        scenarios.append(EvaluationScenario.from_dict(cast(Mapping[str, Any], item)))
    return tuple(scenarios)


def load_evaluation_suite(source: JsonSource) -> tuple[str, tuple[EvaluationScenario, ...]]:
    raw = _as_mapping(source)
    return str(raw.get("dataset", "fixture-suite")), load_evaluation_scenarios(raw)


def evaluate_policy_scenarios(
    policy: Policy,
    scenarios: Sequence[EvaluationScenario],
    *,
    dataset: str = "fixture-suite",
) -> EvaluationReport:
    results: list[EvaluationResult] = []
    for scenario in scenarios:
        start_ns = time.perf_counter_ns()
        try:
            record = policy.evaluate(scenario.to_call())
            actual = record.decision
            matched_rules = record.matched_rules
            reason = record.reason
        except Exception as exc:  # pragma: no cover - defensive fail-closed adapter path
            actual = Decision.DENY
            matched_rules = (f"POLICY_EVAL_ERROR:{type(exc).__name__}",)
            reason = f"policy evaluation raised: {exc}"
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
        results.append(
            EvaluationResult(
                scenario_id=scenario.scenario_id,
                category=scenario.category,
                expected_decision=scenario.expected_decision,
                actual_decision=actual,
                passed=actual is scenario.expected_decision,
                matched_rules=matched_rules,
                reason=reason,
                latency_ms=elapsed_ms,
                tags=scenario.tags,
            )
        )
    return EvaluationReport(
        dataset=dataset,
        policy_version=policy.version,
        results=tuple(results),
    )
