"""Event status classification — US1 + US2 scope.

US1 covers ``completed`` and ``policy-violation`` via the ``classify``
function. US2 (T040) adds ``classify_with_context`` which applies
additional rules for wiring defects:

    dispatch-failure
        A dispatch event has no matching response within timeout, AND
        the target IS in the handler registry.

    unwired-handler
        A dispatch event has no matching response within timeout, AND
        the target is NOT in the handler registry.

    orphan-response
        A response event has no prior dispatch in the same correlation_id.

    incomplete-pair
        A dispatch followed by an analyzer crash (``observer_crashed=True``
        in the pairing dict).

US1 ``classify(event)`` is unchanged — existing tests depend on it.

The ``pairing`` dict passed to ``classify_with_context`` is computed by
the caller from pair-tracking context:

    {
        "matched_response": bool,   # a response was found for this dispatch
        "timeout_exceeded": bool,   # no response arrived within window
        "observer_crashed": bool,   # the capture observer crashed mid-pair
    }
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from agent_bus_analyzer.models import EventStatus

if TYPE_CHECKING:
    from agent_bus_analyzer.models import HandlerRegistrySnapshot

_US2_STATUSES: frozenset[EventStatus] = frozenset(
    {"dispatch-failure", "unwired-handler", "orphan-response", "incomplete-pair"}
)


def classify(event: dict[str, Any]) -> EventStatus:
    """Return the status for a captured event (mutates nothing).

    US1 scope: covers ``completed`` and ``policy-violation`` only.
    """
    if event.get("kind") == "decision":
        decision = event.get("decision")
        if decision == "deny":
            return "policy-violation"
        if decision == "escalate" and event.get("flagged_rule"):
            return "policy-violation"
    return "completed"


def classify_with_context(
    event: dict[str, Any],
    *,
    registry: HandlerRegistrySnapshot | None = None,
    pairing: dict[str, Any] | None = None,
) -> EventStatus:
    """Return the status for an event enriched with pair-tracking context.

    US2 extension (T040). The US1 policy-violation check runs FIRST so that
    a ``deny`` decision is never shadowed by a wiring-defect classification.

    Parameters
    ----------
    event:
        The raw event dict (same shape as ``classify`` expects).
    registry:
        Optional ``HandlerRegistrySnapshot``. When provided, ``dispatch``
        events with no matched response are checked against it to
        distinguish ``dispatch-failure`` (handler in registry) from
        ``unwired-handler`` (handler absent from registry).
    pairing:
        Caller-computed pair context with boolean keys:
        - ``matched_response`` — a response was paired with this dispatch.
        - ``timeout_exceeded``  — no response arrived within the window.
        - ``observer_crashed``  — the capture observer crashed mid-pair.
    """
    # --- US1 rule: policy-violation wins over everything ---
    us1_status = classify(event)
    if us1_status == "policy-violation":
        return "policy-violation"

    # --- Replay path: event carries an already-classified US2 status ---
    # When no pairing context is provided (corpus replay, store re-read),
    # trust the status field if it is a known US2 status.
    if pairing is None and registry is None:
        embedded = event.get("status")
        if embedded in _US2_STATUSES:
            return cast(EventStatus, embedded)

    kind = event.get("kind")
    p = pairing or {}

    # --- US2 rules ---

    if kind == "response":
        # orphan-response: response with no prior dispatch in same correlation_id.
        if not p.get("matched_response", True):
            return "orphan-response"

    if kind == "dispatch":
        # incomplete-pair: dispatch followed by observer crash.
        if p.get("observer_crashed", False):
            return "incomplete-pair"

        # timeout / no matching response.
        if p.get("timeout_exceeded", False) or not p.get("matched_response", True):
            target = event.get("target_handler_declared") or event.get("target_handler_resolved")
            if registry is not None and target is not None:
                if target in registry.handlers:
                    return "dispatch-failure"
                else:
                    return "unwired-handler"
            # No registry available — fall back to dispatch-failure.
            if p.get("timeout_exceeded", False):
                return "dispatch-failure"

    return "completed"
