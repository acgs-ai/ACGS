"""Deterministic agent drift and emerging-risk detection."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from agent_bus_analyzer.process_mining.errors import TenantIsolationError
from agent_bus_analyzer.process_mining.miners.discovery import reconstruct_workflows
from agent_bus_analyzer.process_mining.schemas.process_event import (
    GovernanceDecision,
    ProcessEvent,
    ProcessEventKind,
)

RISK_ALGORITHM_VERSION = "behavior-risk-2.1"
DRIFT_METRIC_VERSION = "smoothed-total-variation-1.0"


class RiskSignalKind(StrEnum):
    BEHAVIOR_DRIFT = "behavior_drift"
    NEW_TOOL = "new_tool"
    NEW_PATH = "new_path"
    NEW_PERMISSION = "new_permission"
    NEW_FAILURE = "new_failure"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DriftStatus(StrEnum):
    STABLE = "stable"
    DRIFT_DETECTED = "drift_detected"
    INSUFFICIENT_DATA = "insufficient_data"


@dataclass(frozen=True, slots=True)
class RiskSignal:
    kind: RiskSignalKind
    subject: str
    score: int
    level: RiskLevel
    support: int
    case_ids: tuple[str, ...]
    event_ids: tuple[str, ...]
    execution_observed: bool | None
    rationale: str


@dataclass(frozen=True, slots=True)
class VariantFrequency:
    path: tuple[str, ...]
    count: int
    frequency: float


@dataclass(frozen=True, slots=True)
class BehaviorRiskReport:
    tenant_id: str
    algorithm_version: str
    baseline_case_count: int
    current_case_count: int
    baseline_usable_case_count: int
    current_usable_case_count: int
    baseline_quarantined_case_count: int
    current_quarantined_case_count: int
    baseline_ordering_issue_codes: tuple[str, ...]
    current_ordering_issue_codes: tuple[str, ...]
    data_quality_limitations: tuple[str, ...]
    drift_score: int
    drift_status: DriftStatus
    drift_metric_version: str
    drift_threshold: float
    minimum_drift_cases: int
    smoothing_alpha: float
    baseline_variant_frequencies: tuple[VariantFrequency, ...]
    current_variant_frequencies: tuple[VariantFrequency, ...]
    new_variants: tuple[tuple[str, ...], ...]
    removed_variants: tuple[tuple[str, ...], ...]
    signals: tuple[RiskSignal, ...]


@dataclass(frozen=True, slots=True)
class _PathIndex:
    paths: dict[tuple[str, ...], tuple[str, ...]]
    case_count: int
    quarantined_case_ids: tuple[str, ...]
    ordering_issue_codes: tuple[str, ...]
    data_quality_flags: tuple[str, ...]

    @property
    def usable_case_count(self) -> int:
        return sum(len(case_ids) for case_ids in self.paths.values())


def _tenant(events: list[ProcessEvent]) -> str:
    tenants = {event.tenant_id for event in events}
    if len(tenants) != 1:
        raise TenantIsolationError("behavior comparison requires one tenant partition")
    return next(iter(tenants))


def _level(score: int) -> RiskLevel:
    if score >= 90:
        return RiskLevel.CRITICAL
    if score >= 70:
        return RiskLevel.HIGH
    if score >= 40:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _score(base: int, support: int, *, critical: bool = False) -> int:
    return min(100, base + min(max(support - 1, 0) * 3, 15) + (20 if critical else 0))


def _tool_name(event: ProcessEvent) -> str | None:
    if event.governance.tool_name:
        return event.governance.tool_name
    if event.kind in {ProcessEventKind.TOOL_CALL, ProcessEventKind.TOOL_RESULT}:
        return event.activity
    return None


def _execution_observed(event: ProcessEvent) -> bool | None:
    if event.kind is ProcessEventKind.TOOL_RESULT and event.governance.is_side_effect:
        return True
    if event.governance.decision in {
        GovernanceDecision.DENY,
        GovernanceDecision.ESCALATE,
    }:
        return False
    explicit = event.attributes.get("execution_observed")
    if isinstance(explicit, bool):
        return explicit
    if event.kind is ProcessEventKind.TOOL_RESULT:
        return True
    return None


def _aggregate_execution(events: Iterable[ProcessEvent]) -> bool | None:
    states = [_execution_observed(event) for event in events]
    if True in states:
        return True
    if False in states:
        return False
    return None


def _permissions(event: ProcessEvent) -> tuple[str, ...]:
    return event.permission_ids


def _tool_index(
    events: list[ProcessEvent],
) -> dict[str, list[ProcessEvent]]:
    indexed: dict[str, list[ProcessEvent]] = defaultdict(list)
    for event in events:
        tool = _tool_name(event)
        if tool is not None:
            indexed[tool].append(event)
    return indexed


def _permission_index(events: list[ProcessEvent]) -> dict[str, list[ProcessEvent]]:
    indexed: dict[str, list[ProcessEvent]] = defaultdict(list)
    for event in events:
        for permission in _permissions(event):
            indexed[permission].append(event)
    return indexed


def _path_index(events: list[ProcessEvent]) -> _PathIndex:
    indexed: dict[tuple[str, ...], list[str]] = defaultdict(list)
    workflows = reconstruct_workflows(events)
    quarantined_case_ids: list[str] = []
    ordering_issue_codes: set[str] = set()
    data_quality_flags: set[str] = set()
    for workflow in workflows:
        if (
            not workflow.directly_follows_safe
            or workflow.ordering_confidence == "ambiguous"
            or not workflow.complete
        ):
            quarantined_case_ids.append(workflow.case_id)
            ordering_issue_codes.update(workflow.issues)
            data_quality_flags.update(workflow.data_quality_flags)
            continue
        signature = tuple(step.activity for step in workflow.steps)
        indexed[signature].append(workflow.case_id)
    return _PathIndex(
        paths={signature: tuple(sorted(case_ids)) for signature, case_ids in indexed.items()},
        case_count=len(workflows),
        quarantined_case_ids=tuple(sorted(quarantined_case_ids)),
        ordering_issue_codes=tuple(sorted(ordering_issue_codes)),
        data_quality_flags=tuple(sorted(data_quality_flags)),
    )


def _data_quality_limitations(
    baseline: _PathIndex,
    current: _PathIndex,
    *,
    minimum_drift_cases: int,
) -> tuple[str, ...]:
    limitations: set[str] = set()
    for window_name, index in (("baseline", baseline), ("current", current)):
        if index.quarantined_case_ids:
            limitations.add(f"{window_name}:workflows_quarantined")
        limitations.update(f"{window_name}:{flag}" for flag in index.data_quality_flags)
        if index.usable_case_count < minimum_drift_cases:
            limitations.add(f"{window_name}:usable_cases_below_minimum")
    return tuple(sorted(limitations))


def _failure_index(events: list[ProcessEvent]) -> dict[str, list[ProcessEvent]]:
    indexed: dict[str, list[ProcessEvent]] = defaultdict(list)
    for event in events:
        if event.kind in {ProcessEventKind.FAILURE, ProcessEventKind.EXCEPTION}:
            indexed[event.activity].append(event)
    return indexed


def _variant_distribution(
    paths: dict[tuple[str, ...], tuple[str, ...]],
    universe: tuple[tuple[str, ...], ...],
    *,
    smoothing_alpha: float,
) -> tuple[VariantFrequency, ...]:
    total = sum(len(case_ids) for case_ids in paths.values())
    denominator = total + smoothing_alpha * len(universe)
    return tuple(
        VariantFrequency(
            path=path,
            count=len(paths.get(path, ())),
            frequency=round(
                (len(paths.get(path, ())) + smoothing_alpha) / denominator,
                12,
            ),
        )
        for path in universe
    )


def _total_variation_score(
    baseline: tuple[VariantFrequency, ...],
    current: tuple[VariantFrequency, ...],
) -> int:
    baseline_by_path = {item.path: item.frequency for item in baseline}
    current_by_path = {item.path: item.frequency for item in current}
    distance = 0.5 * sum(
        abs(baseline_by_path[path] - current_by_path[path]) for path in sorted(baseline_by_path)
    )
    return round(100 * distance)


def detect_behavior_changes(
    baseline: Iterable[ProcessEvent],
    current: Iterable[ProcessEvent],
    *,
    min_support: int = 2,
    critical_tools: frozenset[str] = frozenset(),
    drift_threshold: float = 0.20,
    minimum_drift_cases: int = 5,
    smoothing_alpha: float = 0.5,
) -> BehaviorRiskReport:
    """Compare immutable baseline/current windows and surface new behavior."""
    if min_support < 1:
        raise ValueError("min_support must be positive")
    if not 0.0 <= drift_threshold <= 1.0:
        raise ValueError("drift_threshold must be between zero and one")
    if minimum_drift_cases < 1:
        raise ValueError("minimum_drift_cases must be positive")
    if smoothing_alpha <= 0.0:
        raise ValueError("smoothing_alpha must be positive")
    baseline_events = list(baseline)
    current_events = list(current)
    if not baseline_events or not current_events:
        raise ValueError("baseline and current windows must both contain events")
    baseline_tenant = _tenant(baseline_events)
    current_tenant = _tenant(current_events)
    if baseline_tenant != current_tenant:
        raise TenantIsolationError("behavior windows cannot cross tenants")

    signals: list[RiskSignal] = []
    baseline_tools = _tool_index(baseline_events)
    current_tools = _tool_index(current_events)
    for tool in sorted(set(current_tools) - set(baseline_tools)):
        observations = current_tools[tool]
        support = len({event.case_id for event in observations})
        if support < min_support and tool not in critical_tools:
            continue
        score = _score(60, support, critical=tool in critical_tools)
        signals.append(
            RiskSignal(
                kind=RiskSignalKind.NEW_TOOL,
                subject=tool,
                score=score,
                level=_level(score),
                support=support,
                case_ids=tuple(sorted({event.case_id for event in observations})),
                event_ids=tuple(sorted(event.event_id for event in observations)),
                execution_observed=_aggregate_execution(observations),
                rationale="tool was absent from the versioned baseline window",
            )
        )

    baseline_permissions = _permission_index(baseline_events)
    current_permissions = _permission_index(current_events)
    for permission in sorted(set(current_permissions) - set(baseline_permissions)):
        observations = current_permissions[permission]
        support = len({event.case_id for event in observations})
        if support < min_support:
            continue
        score = _score(75, support)
        signals.append(
            RiskSignal(
                kind=RiskSignalKind.NEW_PERMISSION,
                subject=permission,
                score=score,
                level=_level(score),
                support=support,
                case_ids=tuple(sorted({event.case_id for event in observations})),
                event_ids=tuple(sorted(event.event_id for event in observations)),
                execution_observed=_aggregate_execution(observations),
                rationale="permission was absent from the versioned baseline window",
            )
        )

    baseline_path_index = _path_index(baseline_events)
    current_path_index = _path_index(current_events)
    baseline_paths = baseline_path_index.paths
    current_paths = current_path_index.paths
    for path in sorted(set(current_paths) - set(baseline_paths)):
        case_ids = current_paths[path]
        if len(case_ids) < min_support:
            continue
        score = _score(70, len(case_ids))
        path_events = [event for event in current_events if event.case_id in case_ids]
        signals.append(
            RiskSignal(
                kind=RiskSignalKind.NEW_PATH,
                subject=" -> ".join(path),
                score=score,
                level=_level(score),
                support=len(case_ids),
                case_ids=case_ids,
                event_ids=(),
                execution_observed=_aggregate_execution(path_events),
                rationale="workflow variant was absent from the versioned baseline window",
            )
        )

    baseline_failures = _failure_index(baseline_events)
    current_failures = _failure_index(current_events)
    for failure in sorted(set(current_failures) - set(baseline_failures)):
        observations = current_failures[failure]
        support = len({event.case_id for event in observations})
        if support < min_support:
            continue
        score = _score(55, support)
        signals.append(
            RiskSignal(
                kind=RiskSignalKind.NEW_FAILURE,
                subject=failure,
                score=score,
                level=_level(score),
                support=support,
                case_ids=tuple(sorted({event.case_id for event in observations})),
                event_ids=tuple(sorted(event.event_id for event in observations)),
                execution_observed=False,
                rationale="failure pattern was absent from the versioned baseline window",
            )
        )

    baseline_path_set = set(baseline_paths)
    current_path_set = set(current_paths)
    universe = tuple(sorted(baseline_path_set | current_path_set))
    baseline_distribution = _variant_distribution(
        baseline_paths,
        universe,
        smoothing_alpha=smoothing_alpha,
    )
    current_distribution = _variant_distribution(
        current_paths,
        universe,
        smoothing_alpha=smoothing_alpha,
    )
    drift_score = _total_variation_score(baseline_distribution, current_distribution)
    baseline_usable_case_count = baseline_path_index.usable_case_count
    current_usable_case_count = current_path_index.usable_case_count
    if (
        baseline_usable_case_count < minimum_drift_cases
        or current_usable_case_count < minimum_drift_cases
    ):
        drift_status = DriftStatus.INSUFFICIENT_DATA
    elif drift_score / 100 >= drift_threshold:
        drift_status = DriftStatus.DRIFT_DETECTED
    else:
        drift_status = DriftStatus.STABLE
    current_usable_case_ids = tuple(
        sorted(case_id for case_ids in current_paths.values() for case_id in case_ids)
    )
    current_usable_events = [
        event for event in current_events if event.case_id in current_usable_case_ids
    ]
    if drift_status is DriftStatus.DRIFT_DETECTED:
        signals.append(
            RiskSignal(
                kind=RiskSignalKind.BEHAVIOR_DRIFT,
                subject="workflow-variant-distribution",
                score=drift_score,
                level=_level(drift_score),
                support=len(current_usable_case_ids),
                case_ids=current_usable_case_ids,
                event_ids=tuple(sorted(event.event_id for event in current_usable_events)),
                execution_observed=_aggregate_execution(current_usable_events),
                rationale=(
                    "smoothed variant frequencies exceeded the configured total-variation "
                    f"threshold ({drift_score / 100:.2f} >= {drift_threshold:.2f})"
                ),
            )
        )
    elif drift_status is DriftStatus.INSUFFICIENT_DATA and drift_score > 0:
        signals.append(
            RiskSignal(
                kind=RiskSignalKind.BEHAVIOR_DRIFT,
                subject="workflow-variant-distribution",
                score=0,
                level=RiskLevel.LOW,
                support=len(current_usable_case_ids),
                case_ids=current_usable_case_ids,
                event_ids=tuple(sorted(event.event_id for event in current_usable_events)),
                execution_observed=_aggregate_execution(current_usable_events),
                rationale=(
                    "inconclusive variant-frequency change: baseline and current windows "
                    f"each require at least {minimum_drift_cases} cases"
                ),
            )
        )
    signals.sort(key=lambda signal: (-signal.score, signal.kind.value, signal.subject))
    return BehaviorRiskReport(
        tenant_id=baseline_tenant,
        algorithm_version=RISK_ALGORITHM_VERSION,
        baseline_case_count=baseline_path_index.case_count,
        current_case_count=current_path_index.case_count,
        baseline_usable_case_count=baseline_usable_case_count,
        current_usable_case_count=current_usable_case_count,
        baseline_quarantined_case_count=len(baseline_path_index.quarantined_case_ids),
        current_quarantined_case_count=len(current_path_index.quarantined_case_ids),
        baseline_ordering_issue_codes=baseline_path_index.ordering_issue_codes,
        current_ordering_issue_codes=current_path_index.ordering_issue_codes,
        data_quality_limitations=_data_quality_limitations(
            baseline_path_index,
            current_path_index,
            minimum_drift_cases=minimum_drift_cases,
        ),
        drift_score=drift_score,
        drift_status=drift_status,
        drift_metric_version=DRIFT_METRIC_VERSION,
        drift_threshold=drift_threshold,
        minimum_drift_cases=minimum_drift_cases,
        smoothing_alpha=smoothing_alpha,
        baseline_variant_frequencies=baseline_distribution,
        current_variant_frequencies=current_distribution,
        new_variants=tuple(sorted(current_path_set - baseline_path_set)),
        removed_variants=tuple(sorted(baseline_path_set - current_path_set)),
        signals=tuple(signals),
    )
