"""T015 — observer MUST NOT mutate upstream BusEvent / audit record (FR-003).

We replay a series of input dicts through the projection helpers and the
observer callback, then assert the inputs are byte-identical after.
Object-identity check is insufficient — a copy that mutates a nested dict
still violates FR-003.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from agent_bus_analyzer.capture import CaptureQueue
from agent_bus_analyzer.observer import Observer, project_audit_record, project_bus_event


def _bus_msg() -> dict[str, Any]:
    return {
        "message_id": "01234567-89ab-cdef-0123-456789abcdef",
        "conversation_id": "89abcdef-0123-4567-89ab-cdef01234567",
        "from_agent": "claude:worker-03",
        "to_agent": "policy.evaluate",
        "payload": {"k": [1, 2, {"deep": "ok"}]},
        "constitutional_hash": "608508a9bd224290",
    }


def _audit_record() -> dict[str, Any]:
    return {
        "event_id": "01234567-89ab-cdef-0123-456789abcdef",
        "conversation_id": "89abcdef-0123-4567-89ab-cdef01234567",
        "actor": "acgs:handler/policy-evaluator",
        "tool_name": "policy.evaluate",
        "args": {"x": 1, "y": [2, 3]},
        "decision": "deny",
        "matched_rules": ["rule.no-pii-in-output"],
        "event_hash": "b" * 64,
        "constitutional_hash": "608508a9bd224290",
    }


def test_project_bus_event_does_not_mutate_input() -> None:
    msg = _bus_msg()
    before = copy.deepcopy(msg)
    project_bus_event(msg, "608508a9bd224290")
    assert msg == before


def test_project_audit_record_does_not_mutate_input() -> None:
    record = _audit_record()
    before = copy.deepcopy(record)
    project_audit_record(record, "608508a9bd224290")
    assert record == before


@pytest.mark.asyncio
async def test_observer_callback_does_not_mutate_input() -> None:
    queue = CaptureQueue(capacity=10)
    observer = Observer(queue=queue, constitutional_hash="608508a9bd224290")
    msg = _bus_msg()
    before = copy.deepcopy(msg)
    await observer.on_bus_event(msg)
    assert msg == before


def test_projection_synthesizes_correlation_when_missing() -> None:
    msg = {"message_id": "abc"}
    projected = project_bus_event(msg, "608508a9bd224290")
    assert projected["correlation_id"]  # not empty
    assert projected["source_agent"] == "unknown"


def test_projection_truncates_long_constitutional_hash() -> None:
    msg = _bus_msg()
    msg["constitutional_hash"] = "608508a9bd224290abcdef"  # >16 chars
    projected = project_bus_event(msg, "608508a9bd224290")
    assert projected["constitutional_hash"] == "608508a9bd224290"
