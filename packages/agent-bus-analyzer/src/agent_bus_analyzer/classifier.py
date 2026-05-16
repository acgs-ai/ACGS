"""Event status classification — US1 scope.

US1 covers ``completed`` and ``policy-violation``. The remaining statuses
(``dispatch-failure``, ``unwired-handler``, ``orphan-response``,
``incomplete-pair``) extend in US2 (Phase 4) under T040.

A captured event is ``policy-violation`` when ``kind="decision"`` and
``decision="deny"`` (or ``escalate`` with a deny outcome), with a
``flagged_rule`` attached. Otherwise it defaults to ``completed`` — the
spec is explicit that the default is not "unknown" but the observed
positive class (FR-006).
"""

from __future__ import annotations

from typing import Any

from agent_bus_analyzer.models import EventStatus


def classify(event: dict[str, Any]) -> EventStatus:
    """Return the status for a captured event (mutates nothing)."""
    if event.get("kind") == "decision":
        decision = event.get("decision")
        if decision == "deny":
            return "policy-violation"
        if decision == "escalate" and event.get("flagged_rule"):
            return "policy-violation"
    return "completed"
