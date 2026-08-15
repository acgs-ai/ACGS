"""Agent drift, emerging-risk, and inactive policy-gap tests."""

from __future__ import annotations

import pytest

from agent_bus_analyzer.process_mining.analytics.recommendations import (
    ProposalStatus,
    discover_policy_gaps,
)
from agent_bus_analyzer.process_mining.errors import TenantIsolationError
from agent_bus_analyzer.process_mining.miners.risk import (
    DRIFT_METRIC_VERSION,
    DriftStatus,
    RiskLevel,
    RiskSignalKind,
    detect_behavior_changes,
)
from agent_bus_analyzer.process_mining.schemas.process_event import (
    GovernanceContext,
    GovernanceDecision,
    ProcessEventKind,
)
from tests.test_process_discovery_support import HASH_A, HASH_B, HASH_C, make_event


def _window(path: tuple[str, ...], *, current: bool) -> list[object]:
    events = []
    for case_number in range(2):
        case_id = f"{'current' if current else 'baseline'}-{case_number}"
        for sequence, activity in enumerate(path):
            governance = GovernanceContext()
            kind = ProcessEventKind.AGENT
            permissions: tuple[str, ...] = ()
            attributes: dict[str, object] = {}
            if activity in {"Search", "Export Data"}:
                kind = ProcessEventKind.TOOL_CALL
                governance = GovernanceContext(
                    tool_name="search" if activity == "Search" else "export_data"
                )
            if activity == "Export Data":
                permissions = ("data.export",)
                attributes["execution_observed"] = True
            events.append(
                make_event(
                    event_id=f"{case_id}-{sequence}",
                    case_id=case_id,
                    sequence=sequence,
                    minute=case_number * 10 + sequence,
                    activity=activity,
                    kind=kind,
                    governance=governance,
                    permission_ids=permissions,
                    attributes=attributes,
                )
            )
    return events


def _variant_window(
    variants: tuple[tuple[tuple[str, ...], int], ...],
    *,
    current: bool,
) -> list[object]:
    events: list[object] = []
    case_number = 0
    for path, count in variants:
        for _ in range(count):
            case_id = f"{'current' if current else 'baseline'}-{case_number}"
            for sequence, activity in enumerate(path):
                events.append(
                    make_event(
                        event_id=f"{case_id}-{sequence}",
                        case_id=case_id,
                        sequence=sequence,
                        minute=case_number * 10 + sequence,
                        activity=activity,
                    )
                )
            case_number += 1
    return events


def _ambiguous_tie_window(
    *,
    current: bool,
    case_prefix: str,
    count: int = 5,
) -> list[object]:
    events: list[object] = []
    for case_number in range(count):
        case_id = f"{case_prefix}-{case_number}"
        observed = (
            (("z-search", "Search"), ("a-approve", "Approve"))
            if current
            else (("a-search", "Search"), ("z-approve", "Approve"))
        )
        for event_suffix, activity in observed:
            events.append(
                make_event(
                    event_id=f"{case_id}-{event_suffix}",
                    case_id=case_id,
                    sequence=None,
                    minute=case_number,
                    activity=activity,
                )
            )
    return events


def test_drift_new_tool_path_and_permission_are_high_risk_and_deterministic() -> None:
    baseline = _window(("Search", "Analyze", "Approve"), current=False)
    current = _window(("Search", "Export Data", "Approve"), current=True)
    report = detect_behavior_changes(
        baseline,
        current,
        min_support=2,
        minimum_drift_cases=2,
    )
    reversed_report = detect_behavior_changes(
        reversed(baseline),
        reversed(current),
        min_support=2,
        minimum_drift_cases=2,
    )

    assert report == reversed_report
    assert report.drift_score == 67
    assert report.drift_status is DriftStatus.DRIFT_DETECTED
    assert report.drift_metric_version == DRIFT_METRIC_VERSION
    assert report.new_variants == (("Search", "Export Data", "Approve"),)
    assert report.removed_variants == (("Search", "Analyze", "Approve"),)
    by_kind = {signal.kind: signal for signal in report.signals}
    assert by_kind[RiskSignalKind.BEHAVIOR_DRIFT].level is RiskLevel.MEDIUM
    assert by_kind[RiskSignalKind.NEW_TOOL].subject == "export_data"
    assert by_kind[RiskSignalKind.NEW_TOOL].execution_observed is True
    assert by_kind[RiskSignalKind.NEW_PATH].level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert by_kind[RiskSignalKind.NEW_PERMISSION].subject == "data.export"


def test_equal_timestamp_tie_breaker_order_is_quarantined_from_drift() -> None:
    baseline = _ambiguous_tie_window(
        current=False,
        case_prefix="baseline-unsafe",
    )
    current = _ambiguous_tie_window(
        current=True,
        case_prefix="current-unsafe",
    )

    report = detect_behavior_changes(baseline, current)
    reversed_report = detect_behavior_changes(reversed(baseline), reversed(current))

    assert report == reversed_report
    assert report.algorithm_version == "behavior-risk-2.1"
    assert report.baseline_case_count == 5
    assert report.current_case_count == 5
    assert report.baseline_usable_case_count == 0
    assert report.current_usable_case_count == 0
    assert report.baseline_quarantined_case_count == 5
    assert report.current_quarantined_case_count == 5
    assert report.baseline_ordering_issue_codes == ("timestamp_tie_without_sequence",)
    assert report.current_ordering_issue_codes == ("timestamp_tie_without_sequence",)
    assert report.drift_status is DriftStatus.INSUFFICIENT_DATA
    assert report.drift_score == 0
    assert report.baseline_variant_frequencies == ()
    assert report.current_variant_frequencies == ()
    assert report.new_variants == ()
    assert report.removed_variants == ()
    assert "baseline:workflows_quarantined" in report.data_quality_limitations
    assert "current:workflows_quarantined" in report.data_quality_limitations
    assert not {
        RiskSignalKind.BEHAVIOR_DRIFT,
        RiskSignalKind.NEW_PATH,
    } & {signal.kind for signal in report.signals}


def test_mixed_safe_and_ambiguous_windows_mine_only_safe_paths() -> None:
    safe_path = ("Search", "Approve")
    baseline = _variant_window(((safe_path, 5),), current=False)
    current = _variant_window(((safe_path, 5),), current=True)
    baseline.extend(
        _ambiguous_tie_window(
            current=False,
            case_prefix="baseline-unsafe",
        )
    )
    current.extend(
        _ambiguous_tie_window(
            current=True,
            case_prefix="current-unsafe",
        )
    )

    report = detect_behavior_changes(baseline, current)

    assert report.baseline_case_count == 10
    assert report.current_case_count == 10
    assert report.baseline_usable_case_count == 5
    assert report.current_usable_case_count == 5
    assert report.baseline_quarantined_case_count == 5
    assert report.current_quarantined_case_count == 5
    assert report.drift_status is DriftStatus.STABLE
    assert report.drift_score == 0
    assert report.baseline_variant_frequencies == report.current_variant_frequencies
    assert report.baseline_variant_frequencies[0].path == safe_path
    assert report.baseline_variant_frequencies[0].count == 5
    assert report.new_variants == ()
    assert report.removed_variants == ()
    assert not {
        RiskSignalKind.BEHAVIOR_DRIFT,
        RiskSignalKind.NEW_PATH,
    } & {signal.kind for signal in report.signals}


def test_frequency_only_variant_drift_uses_observed_case_counts() -> None:
    path_a = ("Search", "Analyze", "Approve")
    path_b = ("Search", "Review", "Approve")
    baseline = _variant_window(((path_a, 8), (path_b, 2)), current=False)
    current = _variant_window(((path_a, 2), (path_b, 8)), current=True)

    report = detect_behavior_changes(baseline, current)

    assert report.new_variants == ()
    assert report.removed_variants == ()
    assert report.baseline_case_count == 10
    assert report.current_case_count == 10
    assert report.drift_score == 55
    assert report.drift_status is DriftStatus.DRIFT_DETECTED
    assert [item.count for item in report.baseline_variant_frequencies] == [8, 2]
    assert [item.count for item in report.current_variant_frequencies] == [2, 8]
    assert any(signal.kind is RiskSignalKind.BEHAVIOR_DRIFT for signal in report.signals)


def test_low_sample_variant_change_is_explicitly_inconclusive() -> None:
    baseline = _window(("Search", "Analyze"), current=False)
    current = _window(("Search", "Export"), current=True)

    report = detect_behavior_changes(baseline, current)

    assert report.drift_status is DriftStatus.INSUFFICIENT_DATA
    assert report.minimum_drift_cases == 5
    assert report.drift_score > 0
    signal = next(
        signal for signal in report.signals if signal.kind is RiskSignalKind.BEHAVIOR_DRIFT
    )
    assert signal.score == 0
    assert signal.level is RiskLevel.LOW
    assert "inconclusive" in signal.rationale


def test_denied_new_tool_attempt_is_not_reported_as_executed() -> None:
    baseline = _window(("Search",), current=False)
    denied = GovernanceContext(tool_name="exfiltrate", decision=GovernanceDecision.DENY)
    current = _window(("Search",), current=True)
    current.append(
        make_event(
            event_id="denied-tool",
            case_id="current-0",
            sequence=1,
            minute=1,
            activity="Exfiltrate",
            kind=ProcessEventKind.TOOL_CALL,
            governance=denied,
        )
    )
    report = detect_behavior_changes(baseline, current, min_support=1)
    signal = next(item for item in report.signals if item.kind is RiskSignalKind.NEW_TOOL)
    assert signal.subject == "exfiltrate"
    assert signal.execution_observed is False


@pytest.mark.parametrize(
    "decision",
    [GovernanceDecision.DENY, GovernanceDecision.ESCALATE],
)
def test_side_effect_tool_result_is_executed_even_with_blocking_decision(
    decision: GovernanceDecision,
) -> None:
    baseline = _window(("Search",), current=False)
    current = _window(("Search",), current=True)
    current.append(
        make_event(
            event_id=f"result-{decision.value}",
            case_id="current-0",
            sequence=1,
            minute=1,
            activity="Payment",
            kind=ProcessEventKind.TOOL_RESULT,
            governance=GovernanceContext(
                is_side_effect=True,
                tool_name="payment.execute",
                decision=decision,
            ),
        )
    )
    report = detect_behavior_changes(baseline, current, min_support=1)
    signal = next(item for item in report.signals if item.kind is RiskSignalKind.NEW_TOOL)
    assert signal.subject == "payment.execute"
    assert signal.execution_observed is True


def test_policy_block_without_tool_result_is_not_executed() -> None:
    baseline = _window(("Search",), current=False)
    current = _window(("Search",), current=True)
    current.append(
        make_event(
            event_id="blocked-payment",
            case_id="current-0",
            sequence=1,
            minute=1,
            activity="Payment",
            kind=ProcessEventKind.TOOL_CALL,
            governance=GovernanceContext(
                is_side_effect=True,
                tool_name="payment.execute",
                decision=GovernanceDecision.DENY,
            ),
        )
    )
    report = detect_behavior_changes(baseline, current, min_support=1)
    signal = next(item for item in report.signals if item.kind is RiskSignalKind.NEW_TOOL)
    assert signal.execution_observed is False


def test_policy_gap_proposals_are_inactive_and_evidence_backed() -> None:
    uncovered = GovernanceContext.model_validate(
        {
            "is_side_effect": True,
            "actor_authority_id": "authority-1",
            "tool_name": "payment.execute",
            "argument_hash": HASH_A,
            "decision": GovernanceDecision.ALLOW,
            "decision_receipt_id": "receipt-1",
            "decision_receipt_hash": HASH_B,
            "evidence_bundle_ids": ("evidence-1",),
            "audit_event_id": "audit-1",
            "audit_event_hash": HASH_C,
            "replay_verified": True,
        }
    )
    event = make_event(
        event_id="payment-1",
        case_id="case-payment",
        sequence=0,
        minute=0,
        activity="Execute payment",
        kind=ProcessEventKind.TOOL_RESULT,
        governance=uncovered,
    )
    proposals = discover_policy_gaps([event])
    assert len(proposals) == 1
    proposal = proposals[0]
    assert proposal.status is ProposalStatus.INACTIVE
    assert proposal.activates_policy is False
    assert proposal.analytical_only is True
    assert proposal.evidence_event_ids == ("payment-1",)
    assert discover_policy_gaps([event]) == proposals


def test_policy_gap_does_not_treat_a_tool_request_as_confirmed_execution() -> None:
    uncovered_request = GovernanceContext(
        is_side_effect=True,
        tool_name="payment.execute",
        decision=GovernanceDecision.ALLOW,
    )
    event = make_event(
        event_id="payment-request-1",
        case_id="case-payment",
        sequence=0,
        minute=0,
        activity="Request payment",
        kind=ProcessEventKind.TOOL_CALL,
        governance=uncovered_request,
    )

    assert discover_policy_gaps([event]) == ()


def test_behavior_comparison_rejects_cross_tenant_windows() -> None:
    baseline = _window(("Search",), current=False)
    current = [
        make_event(
            event_id="other",
            case_id="other",
            sequence=0,
            minute=0,
            activity="Search",
            tenant_id="tenant-B",
        )
    ]
    with pytest.raises(TenantIsolationError):
        detect_behavior_changes(baseline, current, min_support=1)
