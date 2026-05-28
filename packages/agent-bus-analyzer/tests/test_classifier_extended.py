"""T036 — classifier_with_context extended rules (US2 scope).

Tests each new status: dispatch-failure, unwired-handler, orphan-response,
incomplete-pair. Also verifies that US1 policy-violation is not shadowed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from agent_bus_analyzer.classifier import classify, classify_with_context
from agent_bus_analyzer.models import HandlerDescriptor, HandlerRegistrySnapshot

# ---- helpers ---------------------------------------------------------------


def _registry(*handler_names: str) -> HandlerRegistrySnapshot:
    handlers = {
        name: HandlerDescriptor(
            name=name,
            declared_in_source=False,
            registered_in_runtime=True,
            last_seen_at=None,
        )
        for name in handler_names
    }
    return HandlerRegistrySnapshot(
        snapshot_id=str(uuid.uuid4()),
        sampled_at=datetime.now(UTC),
        handlers=handlers,
        source="enhanced_agent_bus",
    )


# ---- us1 backward compat ---------------------------------------------------


def test_us1_classify_still_works() -> None:
    assert classify({"kind": "decision", "decision": "deny"}) == "policy-violation"
    assert classify({"kind": "dispatch"}) == "completed"


# ---- policy-violation wins over wiring rules --------------------------------


def test_policy_violation_not_shadowed_by_wiring() -> None:
    """deny decision → policy-violation even if dispatch has no match."""
    event = {"kind": "decision", "decision": "deny", "target_handler_declared": "h"}
    reg = _registry()  # empty — h not in registry
    pairing = {"matched_response": False, "timeout_exceeded": True, "observer_crashed": False}
    result = classify_with_context(event, registry=reg, pairing=pairing)
    assert result == "policy-violation"


# ---- dispatch-failure -------------------------------------------------------


def test_dispatch_failure_handler_in_registry() -> None:
    event = {"kind": "dispatch", "target_handler_declared": "policy.evaluate"}
    reg = _registry("policy.evaluate")
    pairing = {"matched_response": False, "timeout_exceeded": True, "observer_crashed": False}
    assert classify_with_context(event, registry=reg, pairing=pairing) == "dispatch-failure"


def test_dispatch_failure_no_match_not_timeout_no_registry() -> None:
    """No registry, timeout_exceeded=True → dispatch-failure (safe fallback)."""
    event = {"kind": "dispatch", "target_handler_declared": "h"}
    pairing = {"matched_response": False, "timeout_exceeded": True, "observer_crashed": False}
    assert classify_with_context(event, pairing=pairing) == "dispatch-failure"


# ---- unwired-handler --------------------------------------------------------


def test_unwired_handler_target_not_in_registry() -> None:
    event = {"kind": "dispatch", "target_handler_declared": "ghost.handler"}
    reg = _registry("policy.evaluate")  # ghost.handler not present
    pairing = {"matched_response": False, "timeout_exceeded": True, "observer_crashed": False}
    assert classify_with_context(event, registry=reg, pairing=pairing) == "unwired-handler"


def test_unwired_handler_matched_response_false_not_timeout() -> None:
    """matched_response=False without timeout also triggers wiring check."""
    event = {"kind": "dispatch", "target_handler_declared": "ghost"}
    reg = _registry()  # empty
    pairing = {"matched_response": False, "timeout_exceeded": False, "observer_crashed": False}
    assert classify_with_context(event, registry=reg, pairing=pairing) == "unwired-handler"


# ---- orphan-response --------------------------------------------------------


def test_orphan_response_no_prior_dispatch() -> None:
    event = {"kind": "response", "target_handler_declared": "policy.evaluate"}
    pairing = {"matched_response": False, "timeout_exceeded": False, "observer_crashed": False}
    assert classify_with_context(event, pairing=pairing) == "orphan-response"


def test_orphan_response_with_matched_response_false() -> None:
    event = {"kind": "response"}
    pairing = {"matched_response": False}
    assert classify_with_context(event, pairing=pairing) == "orphan-response"


def test_response_with_prior_dispatch_is_completed() -> None:
    event = {"kind": "response"}
    pairing = {"matched_response": True}
    assert classify_with_context(event, pairing=pairing) == "completed"


# ---- incomplete-pair --------------------------------------------------------


def test_incomplete_pair_observer_crashed() -> None:
    event = {"kind": "dispatch", "target_handler_declared": "h"}
    pairing = {"matched_response": False, "timeout_exceeded": False, "observer_crashed": True}
    assert classify_with_context(event, pairing=pairing) == "incomplete-pair"


def test_incomplete_pair_wins_over_unwired() -> None:
    """observer_crashed is checked before timeout/registry logic."""
    event = {"kind": "dispatch", "target_handler_declared": "ghost"}
    reg = _registry()  # empty
    pairing = {"matched_response": False, "timeout_exceeded": True, "observer_crashed": True}
    assert classify_with_context(event, registry=reg, pairing=pairing) == "incomplete-pair"


# ---- default completed ------------------------------------------------------


def test_completed_when_no_pairing_issues() -> None:
    event = {"kind": "dispatch", "target_handler_declared": "h"}
    reg = _registry("h")
    pairing = {"matched_response": True, "timeout_exceeded": False, "observer_crashed": False}
    assert classify_with_context(event, registry=reg, pairing=pairing) == "completed"


def test_completed_decision_event_allow() -> None:
    event = {"kind": "decision", "decision": "allow"}
    assert classify_with_context(event) == "completed"


def test_no_pairing_no_registry_defaults_to_completed() -> None:
    """Without any pairing context we default to completed."""
    event = {"kind": "dispatch", "target_handler_declared": "h"}
    assert classify_with_context(event) == "completed"


# ---- resolved target fallback -----------------------------------------------


def test_uses_target_handler_resolved_when_declared_absent() -> None:
    event = {"kind": "dispatch", "target_handler_resolved": "policy.evaluate"}
    reg = _registry("policy.evaluate")
    pairing = {"matched_response": False, "timeout_exceeded": True, "observer_crashed": False}
    assert classify_with_context(event, registry=reg, pairing=pairing) == "dispatch-failure"
