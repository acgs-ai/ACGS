"""Deterministic directly-follows discovery and workflow reconstruction.

The miner is deliberately pure: it consumes immutable normalized events and
returns frozen value objects.  It does not update the observer, source audit
chain, policies, receipts, or derived stores.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise
from statistics import fmean
from typing import Literal

from agent_bus_analyzer.process_mining.errors import TenantIsolationError
from agent_bus_analyzer.process_mining.schemas.process_event import (
    ProcessEvent,
    SourceChainStatus,
)

DISCOVERY_ALGORITHM_VERSION: Literal["dfg-1.1"] = "dfg-1.1"
OrderingBasis = Literal["sequence", "timestamp"]
OrderingConfidence = Literal["known", "inferred", "ambiguous"]


def _percentile(values: Sequence[float], percentile: float) -> float | None:
    """Return a deterministic linearly interpolated percentile."""
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


@dataclass(frozen=True, slots=True)
class ActivityFrequency:
    activity: str
    count: int


@dataclass(frozen=True, slots=True)
class CaseIssue:
    case_id: str
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CaseOrderingMetadata:
    """Truth-preserving ordering metadata for one discovered case."""

    case_id: str
    ordering_basis: OrderingBasis
    ordering_confidence: OrderingConfidence
    data_quality_flags: tuple[str, ...]
    directly_follows_safe: bool


@dataclass(frozen=True, slots=True)
class DirectlyFollowsEdge:
    source: str
    target: str
    count: int
    duration_samples_seconds: tuple[float, ...]
    excluded_duration_count: int = 0

    @property
    def average_duration_seconds(self) -> float | None:
        if not self.duration_samples_seconds:
            return None
        return fmean(self.duration_samples_seconds)

    @property
    def p50_duration_seconds(self) -> float | None:
        return _percentile(self.duration_samples_seconds, 0.50)

    @property
    def p95_duration_seconds(self) -> float | None:
        return _percentile(self.duration_samples_seconds, 0.95)


@dataclass(frozen=True, slots=True)
class WorkflowStep:
    position: int
    event_id: str
    activity: str
    event_kind: str
    occurred_at: datetime
    actor_id: str | None


@dataclass(frozen=True, slots=True)
class WorkflowReconstruction:
    tenant_id: str
    case_id: str
    steps: tuple[WorkflowStep, ...]
    ordering_basis: OrderingBasis
    ordering_confidence: OrderingConfidence
    data_quality_flags: tuple[str, ...]
    directly_follows_safe: bool
    complete: bool
    issues: tuple[str, ...]
    duration_seconds: float


@dataclass(frozen=True, slots=True)
class DirectlyFollowsGraph:
    tenant_id: str
    process_id: str
    algorithm_version: Literal["dfg-1.1"]
    case_count: int
    event_count: int
    activity_counts: tuple[ActivityFrequency, ...]
    start_activity_counts: tuple[ActivityFrequency, ...]
    end_activity_counts: tuple[ActivityFrequency, ...]
    edges: tuple[DirectlyFollowsEdge, ...]
    case_ordering: tuple[CaseOrderingMetadata, ...]
    incomplete_cases: tuple[CaseIssue, ...]
    excluded_case_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _OrderingResult:
    events: tuple[ProcessEvent, ...]
    basis: OrderingBasis
    confidence: OrderingConfidence
    data_quality_flags: tuple[str, ...]
    issues: tuple[str, ...]
    directly_follows_safe: bool


def _require_single_tenant(events: Sequence[ProcessEvent]) -> str:
    if not events:
        raise ValueError("process discovery requires at least one event")
    tenants = {event.tenant_id for event in events}
    if len(tenants) != 1:
        raise TenantIsolationError("process discovery cannot combine tenant partitions")
    return next(iter(tenants))


def _ordered_events(
    events: Sequence[ProcessEvent],
) -> _OrderingResult:
    sequences = [event.sequence for event in events]
    issues: list[str] = []
    data_quality_flags: list[str] = []
    directly_follows_safe = True

    if all(sequence is not None for sequence in sequences):
        concrete = sorted(sequence for sequence in sequences if sequence is not None)
        ordered = sorted(
            events,
            key=lambda event: (
                event.sequence if event.sequence is not None else 2**63 - 1,
                event.occurred_at,
                event.event_id,
            ),
        )
        basis: OrderingBasis = "sequence"
        confidence: OrderingConfidence = "known"
        if len(set(concrete)) != len(concrete):
            issues.append("duplicate_sequence")
            data_quality_flags.append("sequence_duplicate")
            confidence = "ambiguous"
            directly_follows_safe = False
        elif concrete != list(range(concrete[0], concrete[-1] + 1)):
            issues.append("sequence_gap")
            data_quality_flags.append("sequence_gap")
            confidence = "ambiguous"
            directly_follows_safe = False

        if any(later.occurred_at < earlier.occurred_at for earlier, later in pairwise(ordered)):
            issues.extend(("negative_timestamp_delta", "sequence_timestamp_conflict"))
            data_quality_flags.append("sequence_timestamp_conflict")
            confidence = "ambiguous"
            directly_follows_safe = False
    elif all(sequence is None for sequence in sequences):
        ordered = sorted(events, key=lambda event: (event.occurred_at, event.event_id))
        basis = "timestamp"
        confidence = "inferred"
        data_quality_flags.extend(("sequence_absent", "ordering_inferred_from_timestamp"))
        timestamp_counts = Counter(event.occurred_at for event in ordered)
        if any(count > 1 for count in timestamp_counts.values()):
            issues.append("timestamp_tie_without_sequence")
            data_quality_flags.append("timestamp_tie")
            confidence = "ambiguous"
            directly_follows_safe = False
    else:
        issues.extend(("missing_sequence", "partial_sequence"))
        data_quality_flags.extend(("sequence_partial", "ordering_inferred_from_timestamp"))
        ordered = sorted(events, key=lambda event: (event.occurred_at, event.event_id))
        basis = "timestamp"
        confidence = "ambiguous"
        directly_follows_safe = False
        timestamp_counts = Counter(event.occurred_at for event in ordered)
        if any(count > 1 for count in timestamp_counts.values()):
            issues.append("timestamp_tie_without_sequence")
            data_quality_flags.append("timestamp_tie")

    if any(event.integrity.chain_status is SourceChainStatus.UNVERIFIED for event in ordered):
        issues.append("source_chain_unverified")
        data_quality_flags.append("source_chain_unverified")
    return _OrderingResult(
        events=tuple(ordered),
        basis=basis,
        confidence=confidence,
        data_quality_flags=tuple(sorted(set(data_quality_flags))),
        issues=tuple(sorted(set(issues))),
        directly_follows_safe=directly_follows_safe,
    )


def reconstruct_workflow(events: Sequence[ProcessEvent]) -> WorkflowReconstruction:
    """Reconstruct one tenant-scoped case without inventing causal order."""
    tenant_id = _require_single_tenant(events)
    case_ids = {event.case_id for event in events}
    if len(case_ids) != 1:
        raise ValueError("workflow reconstruction requires exactly one case")
    ordering = _ordered_events(events)
    ordered = ordering.events
    duration = (ordered[-1].occurred_at - ordered[0].occurred_at).total_seconds()
    steps = tuple(
        WorkflowStep(
            position=position,
            event_id=event.event_id,
            activity=event.activity,
            event_kind=event.kind.value,
            occurred_at=event.occurred_at,
            actor_id=event.actor_id,
        )
        for position, event in enumerate(ordered)
    )
    return WorkflowReconstruction(
        tenant_id=tenant_id,
        case_id=next(iter(case_ids)),
        steps=steps,
        ordering_basis=ordering.basis,
        ordering_confidence=ordering.confidence,
        data_quality_flags=ordering.data_quality_flags,
        directly_follows_safe=ordering.directly_follows_safe,
        complete=not ordering.issues,
        issues=ordering.issues,
        duration_seconds=max(duration, 0.0),
    )


def reconstruct_workflows(events: Iterable[ProcessEvent]) -> tuple[WorkflowReconstruction, ...]:
    event_list = list(events)
    _require_single_tenant(event_list)
    grouped: dict[str, list[ProcessEvent]] = defaultdict(list)
    for event in event_list:
        grouped[event.case_id].append(event)
    return tuple(reconstruct_workflow(grouped[case_id]) for case_id in sorted(grouped))


def discover_dfg(
    events: Iterable[ProcessEvent],
    *,
    process_id: str = "discovered-process",
    include_incomplete: bool = True,
) -> DirectlyFollowsGraph:
    """Discover a deterministic directly-follows graph from normalized events.

    Cases whose observed ordering cannot establish safe adjacency are reported
    in ``case_ordering`` and ``incomplete_cases`` but are always excluded from
    directly-follows counts. ``include_incomplete`` applies only when ordering
    is safe and another quality issue (for example an unverified source chain)
    makes the reconstruction incomplete.
    """
    event_list = list(events)
    tenant_id = _require_single_tenant(event_list)
    reconstructions = reconstruct_workflows(event_list)

    activity_counts: Counter[str] = Counter()
    start_counts: Counter[str] = Counter()
    end_counts: Counter[str] = Counter()
    edge_counts: Counter[tuple[str, str]] = Counter()
    edge_durations: dict[tuple[str, str], list[float]] = defaultdict(list)
    edge_exclusions: Counter[tuple[str, str]] = Counter()
    incomplete: list[CaseIssue] = []
    excluded: list[str] = []
    included_event_count = 0

    for reconstruction in reconstructions:
        if not reconstruction.complete:
            incomplete.append(CaseIssue(reconstruction.case_id, reconstruction.issues))
        if not reconstruction.directly_follows_safe or (
            not reconstruction.complete and not include_incomplete
        ):
            excluded.append(reconstruction.case_id)
            continue
        if not reconstruction.steps:
            continue
        included_event_count += len(reconstruction.steps)
        start_counts[reconstruction.steps[0].activity] += 1
        end_counts[reconstruction.steps[-1].activity] += 1
        activity_counts.update(step.activity for step in reconstruction.steps)
        for source, target in pairwise(reconstruction.steps):
            edge = (source.activity, target.activity)
            edge_counts[edge] += 1
            duration = (target.occurred_at - source.occurred_at).total_seconds()
            if duration < 0:
                edge_exclusions[edge] += 1
            else:
                edge_durations[edge].append(duration)

    def frequencies(counter: Counter[str]) -> tuple[ActivityFrequency, ...]:
        return tuple(ActivityFrequency(name, counter[name]) for name in sorted(counter))

    edges = tuple(
        DirectlyFollowsEdge(
            source=source,
            target=target,
            count=edge_counts[(source, target)],
            duration_samples_seconds=tuple(sorted(edge_durations[(source, target)])),
            excluded_duration_count=edge_exclusions[(source, target)],
        )
        for source, target in sorted(edge_counts)
    )
    return DirectlyFollowsGraph(
        tenant_id=tenant_id,
        process_id=process_id,
        algorithm_version=DISCOVERY_ALGORITHM_VERSION,
        case_count=len(reconstructions) - len(excluded),
        event_count=included_event_count,
        activity_counts=frequencies(activity_counts),
        start_activity_counts=frequencies(start_counts),
        end_activity_counts=frequencies(end_counts),
        edges=edges,
        case_ordering=tuple(
            CaseOrderingMetadata(
                case_id=reconstruction.case_id,
                ordering_basis=reconstruction.ordering_basis,
                ordering_confidence=reconstruction.ordering_confidence,
                data_quality_flags=reconstruction.data_quality_flags,
                directly_follows_safe=reconstruction.directly_follows_safe,
            )
            for reconstruction in reconstructions
        ),
        incomplete_cases=tuple(incomplete),
        excluded_case_ids=tuple(sorted(excluded)),
    )
