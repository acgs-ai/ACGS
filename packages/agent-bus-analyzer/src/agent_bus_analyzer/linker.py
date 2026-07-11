"""Trace interoperability linker and conformance log serializers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any


class TraceLinker:
    """Links W3C traceparent headers to internal audit trace event frames."""

    def parse_w3c_header(self, traceparent: str) -> dict[str, str]:
        """Parse W3C traceparent header: 'version-trace_id-parent_id-trace_flags'."""
        parts = traceparent.strip().split("-")
        if len(parts) < 4:
            return {}
        return {
            "version": parts[0],
            "trace_id": parts[1],
            "parent_span_id": parts[2],
            "trace_flags": parts[3],
        }

    def link_trace(self, event: dict[str, Any], traceparent: str | None) -> dict[str, Any]:
        """Bind W3C traceparent context directly to the event payload."""
        if not traceparent:
            return event

        parsed = self.parse_w3c_header(traceparent)
        if parsed:
            event["phoenix_trace_id"] = parsed["trace_id"]
            event["phoenix_parent_span_id"] = parsed["parent_span_id"]
            event["w3c_traceparent"] = traceparent
        return event


class CelonisLogFormatter:
    """Formats decision and execution logs into standard Celonis OCPM format."""

    def format_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Convert gove-zone event to Celonis event log row."""
        return {
            "CASE_ID": event.get("correlation_id", ""),
            "ACTIVITY": (
                event.get("target_handler_resolved")
                or event.get("target_handler_declared", "unknown")
            ),
            "TIMESTAMP": event.get("recorded_at", datetime.now(UTC).isoformat()),
            "ACTOR": event.get("source_agent", "unknown"),
            "DECISION": event.get("decision", "ALLOW"),
            "RECEIPT_ID": event.get("event_id", ""),
            "AUDIT_HASH": event.get("audit_receipt_hash", ""),
            "STATUS": event.get("status", "unknown"),
        }

    def format_batch(self, events: list[dict[str, Any]]) -> str:
        """Serialize a batch of events to JSON line-delimited format."""
        return "\n".join(json.dumps(self.format_event(e)) for e in events)


class SignavioLogFormatter:
    """Formats logs for SAP Signavio Process Insights ingestion."""

    def format_insight_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Format event log for Signavio."""
        return {
            "processInstanceId": event.get("correlation_id", ""),
            "activityName": (
                event.get("target_handler_resolved")
                or event.get("target_handler_declared", "unknown")
            ),
            "timestamp": event.get("recorded_at", datetime.now(UTC).isoformat()),
            "user": event.get("source_agent", "unknown"),
            "outcome": "BLOCKED" if event.get("decision") in ("deny", "escalate") else "EXECUTED",
            "severity": "CRITICAL" if event.get("decision") == "deny" else "INFO",
            "ruleId": event.get("flagged_rule") or "",
        }

    def format_batch(self, events: list[dict[str, Any]]) -> str:
        return json.dumps([self.format_insight_event(e) for e in events], indent=2)
