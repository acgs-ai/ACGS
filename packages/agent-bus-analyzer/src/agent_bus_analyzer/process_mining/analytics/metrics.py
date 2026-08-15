"""Deterministic process-duration and bottleneck metrics."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from itertools import pairwise
from statistics import fmean

from agent_bus_analyzer.process_mining.miners.discovery import reconstruct_workflows
from agent_bus_analyzer.process_mining.schemas.process_event import ProcessEvent, ProcessEventKind

METRICS_ALGORITHM_VERSION = "bottlenecks-1.0"


def _percentile(values: Sequence[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * weight


@dataclass(frozen=True, slots=True)
class DurationDistribution:
    sample_count: int
    excluded_count: int
    average_seconds: float | None
    p50_seconds: float | None
    p95_seconds: float | None


@dataclass(frozen=True, slots=True)
class ActivityBottleneck:
    activity: str
    waiting: DurationDistribution
    service: DurationDistribution
    approval_delay: DurationDistribution
    rework_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class BottleneckAnalysis:
    tenant_id: str
    algorithm_version: str
    case_count: int
    activities: tuple[ActivityBottleneck, ...]
    incomplete_case_count: int

    def ranked_by_wait_p95(self) -> tuple[ActivityBottleneck, ...]:
        """Return activities in deterministic worst-wait-first order."""
        return tuple(
            sorted(
                self.activities,
                key=lambda metric: (
                    -(metric.waiting.p95_seconds or 0.0),
                    metric.activity,
                ),
            )
        )


def _distribution(values: list[float], excluded: int) -> DurationDistribution:
    return DurationDistribution(
        sample_count=len(values),
        excluded_count=excluded,
        average_seconds=fmean(values) if values else None,
        p50_seconds=_percentile(values, 0.50),
        p95_seconds=_percentile(values, 0.95),
    )


def _duration_attribute(event: ProcessEvent, key: str) -> tuple[float | None, bool]:
    value = event.attributes.get(key)
    if value is None:
        return None, True
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None, True
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < 0:
        return None, True
    return numeric, False


def analyze_bottlenecks(events: Iterable[ProcessEvent]) -> BottleneckAnalysis:
    """Calculate wait/service/approval/rework/failure metrics with exclusions."""
    event_list = list(events)
    reconstructions = reconstruct_workflows(event_list)
    by_id = {event.event_id: event for event in event_list}

    waiting: dict[str, list[float]] = defaultdict(list)
    service: dict[str, list[float]] = defaultdict(list)
    approval: dict[str, list[float]] = defaultdict(list)
    waiting_excluded: Counter[str] = Counter()
    service_excluded: Counter[str] = Counter()
    approval_excluded: Counter[str] = Counter()
    rework: Counter[str] = Counter()
    failures: Counter[str] = Counter()
    activities: set[str] = set()

    for reconstruction in reconstructions:
        visits: Counter[str] = Counter(step.activity for step in reconstruction.steps)
        for activity, count in visits.items():
            rework[activity] += max(0, count - 1)
        for step in reconstruction.steps:
            event = by_id[step.event_id]
            activities.add(event.activity)
            duration, excluded = _duration_attribute(event, "service_duration_seconds")
            if excluded:
                service_excluded[event.activity] += 1
            elif duration is not None:
                service[event.activity].append(duration)
            if event.kind in {ProcessEventKind.FAILURE, ProcessEventKind.EXCEPTION}:
                failures[event.activity] += 1

        for previous, current in pairwise(reconstruction.steps):
            delta = (current.occurred_at - previous.occurred_at).total_seconds()
            target_event = by_id[current.event_id]
            if delta < 0:
                waiting_excluded[current.activity] += 1
                if target_event.kind is ProcessEventKind.APPROVAL:
                    approval_excluded[current.activity] += 1
                continue
            waiting[current.activity].append(delta)
            if target_event.kind is ProcessEventKind.APPROVAL:
                approval[current.activity].append(delta)

    metrics = tuple(
        ActivityBottleneck(
            activity=activity,
            waiting=_distribution(waiting[activity], waiting_excluded[activity]),
            service=_distribution(service[activity], service_excluded[activity]),
            approval_delay=_distribution(approval[activity], approval_excluded[activity]),
            rework_count=rework[activity],
            failure_count=failures[activity],
        )
        for activity in sorted(activities)
    )
    tenant_id = reconstructions[0].tenant_id if reconstructions else ""
    return BottleneckAnalysis(
        tenant_id=tenant_id,
        algorithm_version=METRICS_ALGORITHM_VERSION,
        case_count=len(reconstructions),
        activities=metrics,
        incomplete_case_count=sum(
            not reconstruction.complete for reconstruction in reconstructions
        ),
    )
