"""Pydantic v2 data models — single source of truth for traces, events, findings.

Mirrors ``specs/001-enhanced-agent-bus-analysis/data-model.md`` and the JSON
Schemas in ``contracts/``. Concrete instances are validated against those
schemas in ``tests/test_schema_export.py`` to catch drift.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

EventStatus = Literal[
    "completed",
    "policy-violation",
    "dispatch-failure",
    "unwired-handler",
    "orphan-response",
    "incomplete-pair",
    "ingest-gap",
]

IntegrityStatus = Literal["intact", "tampered", "unknown"]

EventKind = Literal["dispatch", "response", "decision"]

Decision = Literal["allow", "deny", "transform", "escalate"]

WiringDefectKind = Literal["unwired_dispatch", "declared_but_unrouted"]

HashSource = Literal["env", "constant", "unset"]

HandlerRegistrySource = Literal["enhanced_agent_bus", "gove_zone_kernel"]

ConstitutionalHashStr = Annotated[
    str,
    Field(pattern=r"^[a-f0-9]{16}$", description="16-char hex form"),
]

EventHashStr = Annotated[
    str,
    Field(pattern=r"^[a-f0-9]{64}$", description="SHA-256 hex digest"),
]


class _Strict(BaseModel):
    """Base class: forbids unknown fields so contract drift fails loudly."""

    model_config = ConfigDict(extra="forbid")


class Event(_Strict):
    """One captured event. data-model.md §Event."""

    event_id: str
    correlation_id: str
    causal_index: int = Field(ge=0)
    recorded_at: datetime
    source_agent: str
    target_handler_declared: str | None = None
    target_handler_resolved: str | None = None
    payload_ref: str
    kind: EventKind
    decision: Decision | None = None
    flagged_rule: str | None = None
    audit_receipt_hash: str | None = None
    constitutional_hash: ConstitutionalHashStr
    event_hash: EventHashStr
    prev_hash: EventHashStr | None = None
    status: EventStatus
    gap_started_at: datetime | None = None
    gap_ended_at: datetime | None = None


class Trace(_Strict):
    """A complete record of one governance-relevant run."""

    correlation_id: str
    started_at: datetime
    completed_at: datetime | None = None
    constitutional_hash: ConstitutionalHashStr
    event_count: int = Field(ge=0)
    integrity_status: IntegrityStatus
    worst_event_status: EventStatus
    events: list[Event] = Field(default_factory=list)


class HandlerDescriptor(_Strict):
    name: str
    declared_in_source: bool
    registered_in_runtime: bool
    last_seen_at: datetime | None = None


class HandlerRegistrySnapshot(_Strict):
    snapshot_id: str
    sampled_at: datetime
    handlers: dict[str, HandlerDescriptor]
    source: HandlerRegistrySource


class WiringDefectFinding(_Strict):
    finding_id: str
    detected_at: datetime
    kind: WiringDefectKind
    handler_name: str
    expected_role: str | None = None
    example_event_ids: list[str] = Field(default_factory=list, max_length=5)


class ConstitutionalHashAnchor(_Strict):
    """A reference, recorded on every Event. See data-model.md §ConstitutionalHashAnchor."""

    hash: ConstitutionalHashStr
    source: HashSource
    recorded_at: datetime


# --- Query API response shapes (mirror trace-query.schema.json) ---


class TraceListItem(_Strict):
    correlation_id: str
    started_at: datetime
    completed_at: datetime | None = None
    event_count: int = Field(ge=0)
    worst_event_status: EventStatus
    integrity_status: IntegrityStatus
    constitutional_hash: ConstitutionalHashStr


class TraceList(_Strict):
    kind: Literal["trace-list"] = "trace-list"
    items: list[TraceListItem] = Field(default_factory=list)
    next_cursor: str | None = None


class SingleTrace(_Strict):
    kind: Literal["single-trace"] = "single-trace"
    trace: TraceListItem
    events: list[Event] = Field(default_factory=list)
    integrity_status: IntegrityStatus
    rotation_at_index: int | None = None


class WiringDefectSummary(_Strict):
    kind: Literal["wiring-defect-summary"] = "wiring-defect-summary"
    refreshed_at: datetime
    findings: list[WiringDefectFinding] = Field(default_factory=list)


class RetentionPolicy(_Strict):
    max_age_days: int = Field(ge=1)
    purged_at: datetime


class Expired(_Strict):
    kind: Literal["expired"] = "expired"
    correlation_id: str
    retention_policy: RetentionPolicy
