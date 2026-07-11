"""Tests for trace linker and Celonis/Signavio serializers."""

from __future__ import annotations

import json

from agent_bus_analyzer.linker import (
    CelonisLogFormatter,
    SignavioLogFormatter,
    TraceLinker,
)


def test_trace_linker_parse_and_link() -> None:
    linker = TraceLinker()
    # Standard W3C traceparent format: version-trace_id-parent_id-trace_flags
    traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

    parsed = linker.parse_w3c_header(traceparent)
    assert parsed["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert parsed["parent_span_id"] == "00f067aa0ba902b7"

    event = {"event_id": "ev-1", "correlation_id": "case-123"}
    linked = linker.link_trace(event, traceparent)
    assert linked["phoenix_trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert linked["phoenix_parent_span_id"] == "00f067aa0ba902b7"
    assert linked["w3c_traceparent"] == traceparent


def test_celonis_formatter() -> None:
    formatter = CelonisLogFormatter()
    event = {
        "correlation_id": "case-99",
        "target_handler_resolved": "sap.invoice.approve",
        "recorded_at": "2026-06-30T10:00:00Z",
        "source_agent": "agent-alpha",
        "decision": "deny",
        "event_id": "ev-99",
        "audit_receipt_hash": "hash123",
        "status": "policy-violation",
    }

    formatted = formatter.format_event(event)
    assert formatted["CASE_ID"] == "case-99"
    assert formatted["ACTIVITY"] == "sap.invoice.approve"
    assert formatted["TIMESTAMP"] == "2026-06-30T10:00:00Z"
    assert formatted["ACTOR"] == "agent-alpha"
    assert formatted["DECISION"] == "deny"
    assert formatted["STATUS"] == "policy-violation"

    batch_json = formatter.format_batch([event])
    assert "sap.invoice.approve" in batch_json


def test_signavio_formatter() -> None:
    formatter = SignavioLogFormatter()
    event = {
        "correlation_id": "case-100",
        "target_handler_resolved": "sap.payment.send",
        "recorded_at": "2026-06-30T11:00:00Z",
        "source_agent": "agent-beta",
        "decision": "allow",
        "flagged_rule": None,
    }

    formatted = formatter.format_insight_event(event)
    assert formatted["processInstanceId"] == "case-100"
    assert formatted["activityName"] == "sap.payment.send"
    assert formatted["outcome"] == "EXECUTED"
    assert formatted["severity"] == "INFO"

    batch = json.loads(formatter.format_batch([event]))
    assert len(batch) == 1
    assert batch[0]["processInstanceId"] == "case-100"
