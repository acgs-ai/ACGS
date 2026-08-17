"""Strict aggregate model for a normalized process case."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Literal, Self

from pydantic import AwareDatetime, Field, field_validator, model_validator

from agent_bus_analyzer.process_mining._canonical import sha256_canonical, utc_datetime
from agent_bus_analyzer.process_mining.schemas.process_event import (
    NonEmptyStr,
    ProcessEvent,
    Sha256Hex,
    SourceChainStatus,
    TenantId,
    _StrictModel,
    validated_event_snapshot,
)

PROCESS_CASE_SCHEMA_VERSION: Literal["1.0"] = "1.0"


class _ProcessCaseCore(_StrictModel):
    schema_version: Literal["1.0"] = PROCESS_CASE_SCHEMA_VERSION
    tenant_id: TenantId
    case_id: NonEmptyStr
    process_id: NonEmptyStr | None = None
    process_name: NonEmptyStr | None = None
    started_at: AwareDatetime
    completed_at: AwareDatetime
    event_count: int = Field(ge=1)
    event_ids: tuple[NonEmptyStr, ...]
    event_hashes: tuple[Sha256Hex, ...]
    source_chain_status: SourceChainStatus
    evidence_coverage: float = Field(ge=0.0, le=1.0)

    @field_validator("started_at", "completed_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return utc_datetime(value)

    @model_validator(mode="after")
    def validate_aggregate(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")
        if len(self.event_ids) != self.event_count or len(self.event_hashes) != self.event_count:
            raise ValueError("event_count must match event_ids and event_hashes")
        if len(set(self.event_ids)) != len(self.event_ids):
            raise ValueError("event_ids must be unique within a process case")
        return self


class ProcessCase(_ProcessCaseCore):
    case_hash: Sha256Hex

    @model_validator(mode="after")
    def verify_case_hash(self) -> Self:
        payload = self.model_dump(mode="python", exclude={"case_hash"})
        if self.case_hash != sha256_canonical(payload):
            raise ValueError("case_hash does not match canonical process case")
        return self


def build_process_case(
    events: Sequence[ProcessEvent],
    *,
    process_id: str | None = None,
    process_name: str | None = None,
) -> ProcessCase:
    """Build a deterministic case summary from one tenant/case event set."""
    if not events:
        raise ValueError("a process case requires at least one event")
    snapshots = tuple(validated_event_snapshot(event) for event in events)
    tenant_id = snapshots[0].tenant_id
    case_id = snapshots[0].case_id
    if any(event.tenant_id != tenant_id or event.case_id != case_id for event in snapshots):
        raise ValueError("all events in a process case must share tenant_id and case_id")
    ordered = sorted(
        snapshots,
        key=lambda event: (
            event.sequence is None,
            event.sequence if event.sequence is not None else 2**63 - 1,
            event.occurred_at,
            event.event_id,
        ),
    )
    statuses = {event.integrity.chain_status for event in ordered}
    if statuses == {SourceChainStatus.VERIFIED}:
        chain_status = SourceChainStatus.VERIFIED
    elif statuses == {SourceChainStatus.NOT_APPLICABLE}:
        chain_status = SourceChainStatus.NOT_APPLICABLE
    else:
        chain_status = SourceChainStatus.UNVERIFIED
    side_effect_events = [event for event in ordered if event.governance.is_side_effect]
    evidence_coverage = (
        sum(event.completeness.evidence_coverage for event in side_effect_events)
        / len(side_effect_events)
        if side_effect_events
        else 1.0
    )
    core = _ProcessCaseCore(
        tenant_id=tenant_id,
        case_id=case_id,
        process_id=process_id,
        process_name=process_name,
        started_at=min(event.occurred_at for event in ordered),
        completed_at=max(event.occurred_at for event in ordered),
        event_count=len(ordered),
        event_ids=tuple(event.event_id for event in ordered),
        event_hashes=tuple(event.normalization_hash for event in ordered),
        source_chain_status=chain_status,
        evidence_coverage=evidence_coverage,
    )
    payload = core.model_dump(mode="python")
    return ProcessCase(**payload, case_hash=sha256_canonical(payload))
