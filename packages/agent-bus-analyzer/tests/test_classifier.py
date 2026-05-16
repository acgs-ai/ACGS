"""T025 — classifier basic rules (US1 scope).

US1 covers ``completed`` and ``policy-violation``. The other statuses are
covered in US2 (T036).
"""

from __future__ import annotations

import pytest

from agent_bus_analyzer.classifier import classify


@pytest.mark.parametrize(
    "event,expected",
    [
        ({"kind": "dispatch"}, "completed"),
        ({"kind": "response"}, "completed"),
        ({"kind": "decision", "decision": "allow"}, "completed"),
        ({"kind": "decision", "decision": "transform"}, "completed"),
        ({"kind": "decision", "decision": "deny"}, "policy-violation"),
        (
            {"kind": "decision", "decision": "escalate", "flagged_rule": "r.x"},
            "policy-violation",
        ),
        ({"kind": "decision", "decision": "escalate"}, "completed"),
    ],
)
def test_classifier_basic(event: dict[str, object], expected: str) -> None:
    assert classify(event) == expected
