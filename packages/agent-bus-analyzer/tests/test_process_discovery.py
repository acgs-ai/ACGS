"""Deterministic DFG, variants, reconstruction, and bottleneck tests."""

from __future__ import annotations

import random

import pytest

from agent_bus_analyzer.process_mining.analytics.metrics import analyze_bottlenecks
from agent_bus_analyzer.process_mining.errors import TenantIsolationError
from agent_bus_analyzer.process_mining.miners.discovery import (
    discover_dfg,
    reconstruct_workflow,
)
from agent_bus_analyzer.process_mining.miners.variants import detect_variants
from agent_bus_analyzer.process_mining.schemas.process_event import ProcessEventKind
from tests.test_process_discovery_support import make_event


def _corpus() -> list[object]:
    rows = []
    paths = {
        "case-1": ("Request", "KYC", "Approve", "Payment"),
        "case-2": ("Request", "KYC", "Approve", "Payment"),
        "case-3": ("Request", "ManualReview", "Approve", "Payment"),
    }
    for case_index, (case_id, path) in enumerate(paths.items()):
        for sequence, activity in enumerate(path):
            rows.append(
                make_event(
                    event_id=f"{case_id}-{sequence}",
                    case_id=case_id,
                    sequence=sequence,
                    minute=case_index * 20 + sequence * 2,
                    activity=activity,
                )
            )
    return rows


def test_dfg_counts_starts_ends_edges_and_is_order_independent() -> None:
    events = _corpus()
    graph = discover_dfg(events, process_id="loan-approval")
    shuffled = list(events)
    random.Random(42).shuffle(shuffled)

    assert discover_dfg(shuffled, process_id="loan-approval") == graph
    assert graph.case_count == 3
    assert graph.event_count == 12
    assert {(item.activity, item.count) for item in graph.start_activity_counts} == {("Request", 3)}
    assert {(item.activity, item.count) for item in graph.end_activity_counts} == {("Payment", 3)}
    assert {(edge.source, edge.target): edge.count for edge in graph.edges} == {
        ("Approve", "Payment"): 3,
        ("KYC", "Approve"): 2,
        ("ManualReview", "Approve"): 1,
        ("Request", "KYC"): 2,
        ("Request", "ManualReview"): 1,
    }


def test_variants_are_canonical_and_frequency_sorted() -> None:
    analysis = detect_variants(_corpus())
    assert analysis.case_count == 3
    assert [variant.count for variant in analysis.variants] == [2, 1]
    assert analysis.variants[0].signature == ("Request", "KYC", "Approve", "Payment")
    assert analysis.variants[0].case_ids == ("case-1", "case-2")
    assert analysis.variants[0].frequency == pytest.approx(2 / 3)


def test_reconstruction_prefers_explicit_sequence_and_marks_negative_time() -> None:
    events = [
        make_event(
            event_id="step-1",
            case_id="case-sequence",
            sequence=0,
            minute=10,
            activity="First",
        ),
        make_event(
            event_id="step-2",
            case_id="case-sequence",
            sequence=1,
            minute=5,
            activity="Second",
        ),
    ]
    reconstruction = reconstruct_workflow(events)
    assert [step.activity for step in reconstruction.steps] == ["First", "Second"]
    assert reconstruction.ordering_basis == "sequence"
    assert reconstruction.ordering_confidence == "ambiguous"
    assert reconstruction.directly_follows_safe is False
    assert reconstruction.complete is False
    assert "negative_timestamp_delta" in reconstruction.issues
    assert "sequence_timestamp_conflict" in reconstruction.issues


def test_unique_timestamp_order_is_explicitly_inferred_not_authoritative() -> None:
    events = [
        make_event(
            event_id="timestamp-first",
            case_id="case-timestamp",
            sequence=None,
            minute=0,
            activity="First",
        ),
        make_event(
            event_id="timestamp-second",
            case_id="case-timestamp",
            sequence=None,
            minute=1,
            activity="Second",
        ),
    ]

    reconstruction = reconstruct_workflow(events)
    graph = discover_dfg(events)
    reversed_graph = discover_dfg(reversed(events))

    assert [step.activity for step in reconstruction.steps] == ["First", "Second"]
    assert reconstruction.ordering_basis == "timestamp"
    assert reconstruction.ordering_confidence == "inferred"
    assert reconstruction.data_quality_flags == (
        "ordering_inferred_from_timestamp",
        "sequence_absent",
    )
    assert reconstruction.directly_follows_safe is True
    assert reconstruction.complete is True
    assert graph.case_ordering[0].ordering_confidence == "inferred"
    assert [(edge.source, edge.target) for edge in graph.edges] == [("First", "Second")]
    assert reversed_graph == graph


@pytest.mark.parametrize(
    ("sequences", "minutes", "expected_issue"),
    [
        ((None, None), (0, 0), "timestamp_tie_without_sequence"),
        ((0, None), (0, 1), "partial_sequence"),
        ((0, 2), (0, 1), "sequence_gap"),
        ((0, 0), (0, 1), "duplicate_sequence"),
        ((0, 1), (1, 0), "sequence_timestamp_conflict"),
    ],
    ids=(
        "equal-timestamps-without-sequence",
        "mixed-missing-sequence",
        "gapped-sequence",
        "duplicate-sequence",
        "sequence-time-conflict",
    ),
)
def test_ambiguous_or_incomplete_order_never_creates_dfg_edges(
    sequences: tuple[int | None, int | None],
    minutes: tuple[int, int],
    expected_issue: str,
) -> None:
    events = [
        make_event(
            event_id=f"event-{index}",
            case_id="case-ambiguous",
            sequence=sequences[index],
            minute=minutes[index],
            activity=f"Step {index}",
        )
        for index in range(2)
    ]

    reconstruction = reconstruct_workflow(events)
    graph = discover_dfg(events)
    reversed_graph = discover_dfg(reversed(events))

    assert reconstruction.ordering_confidence == "ambiguous"
    assert reconstruction.directly_follows_safe is False
    assert reconstruction.complete is False
    assert expected_issue in reconstruction.issues
    assert graph.edges == ()
    assert graph.case_count == 0
    assert graph.event_count == 0
    assert graph.excluded_case_ids == ("case-ambiguous",)
    assert graph.case_ordering[0].directly_follows_safe is False
    assert graph.incomplete_cases[0].case_id == "case-ambiguous"
    assert expected_issue in graph.incomplete_cases[0].reasons
    assert reversed_graph == graph


def test_valid_contiguous_sequence_remains_known_and_deterministic() -> None:
    events = [
        make_event(
            event_id="second",
            case_id="case-known",
            sequence=11,
            minute=0,
            activity="Second",
        ),
        make_event(
            event_id="first",
            case_id="case-known",
            sequence=10,
            minute=0,
            activity="First",
        ),
    ]

    reconstruction = reconstruct_workflow(events)

    assert [step.activity for step in reconstruction.steps] == ["First", "Second"]
    assert reconstruction.ordering_basis == "sequence"
    assert reconstruction.ordering_confidence == "known"
    assert reconstruction.data_quality_flags == ()
    assert reconstruction.directly_follows_safe is True
    assert reconstruction.complete is True


def test_bottlenecks_report_p50_p95_approval_rework_failure_and_exclusions() -> None:
    events = [
        make_event(
            event_id="a-0",
            case_id="case-a",
            sequence=0,
            minute=0,
            activity="Review",
            attributes={"service_duration_seconds": 60.0},
        ),
        make_event(
            event_id="a-1",
            case_id="case-a",
            sequence=1,
            minute=10,
            activity="Approval",
            kind=ProcessEventKind.APPROVAL,
            attributes={"service_duration_seconds": 30.0},
        ),
        make_event(
            event_id="a-2",
            case_id="case-a",
            sequence=2,
            minute=20,
            activity="Review",
            attributes={"service_duration_seconds": -1.0},
        ),
        make_event(
            event_id="a-3",
            case_id="case-a",
            sequence=3,
            minute=21,
            activity="Failure",
            kind=ProcessEventKind.FAILURE,
        ),
    ]
    analysis = analyze_bottlenecks(events)
    by_activity = {metric.activity: metric for metric in analysis.activities}

    assert by_activity["Approval"].waiting.p50_seconds == 600.0
    assert by_activity["Approval"].approval_delay.p95_seconds == 600.0
    assert by_activity["Review"].rework_count == 1
    assert by_activity["Review"].service.excluded_count == 1
    assert by_activity["Failure"].failure_count == 1
    assert analysis.ranked_by_wait_p95()[0].activity in {"Approval", "Review"}


def test_discovery_rejects_cross_tenant_input() -> None:
    events = [
        make_event(
            event_id="a",
            case_id="case-a",
            sequence=0,
            minute=0,
            activity="A",
            tenant_id="tenant-A",
        ),
        make_event(
            event_id="b",
            case_id="case-b",
            sequence=0,
            minute=0,
            activity="B",
            tenant_id="tenant-B",
        ),
    ]
    with pytest.raises(TenantIsolationError):
        discover_dfg(events)
