"""Runtime capture records for W0-M0 D2 evidence collection.

Capture records are metadata-only evidence projections. They are never an
authorization source, never executor input, and intentionally do not change the
DecisionReceipt schema.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

APPROVED_FIELD_STATUS_FIELDS = frozenset({"argument_hash", "state_hash"})
APPROVED_FIELD_STATUS_VALUES = frozenset({"present", "absent", "redacted", "not_retained"})


class CaptureMode(StrEnum):
    """Runtime capture modes approved for the D2 slice."""

    REQUIRED = "required"
    BEST_EFFORT = "best_effort"
    DISABLED = "disabled"


class CaptureError(RuntimeError):
    """Base class for runtime-capture failures."""


class CaptureConfigurationError(CaptureError):
    """Capture configuration is missing required D2 bindings."""


class CaptureBindingError(CaptureError):
    """Capture acknowledgement does not bind to the audited decision."""


class CaptureProjectionError(CaptureError):
    """Required metadata projection is incomplete."""


class CaptureTenantError(CaptureError):
    """A tenant-scoped capture lookup crossed a tenant boundary."""


class CaptureStore(Protocol):
    """Durable metadata-only capture sink."""

    def append(self, record: CaptureRecord) -> CaptureAck:
        """Persist *record* and return a binding acknowledgement."""


class CaptureObservationSink(Protocol):
    """Independent observation sink for capture lifecycle events."""

    def append(self, event: Mapping[str, Any]) -> None:
        """Persist or emit a capture lifecycle observation."""


@dataclass(frozen=True)
class CaptureAck:
    """Append acknowledgement bound to the audited decision event."""

    tenant_id: str
    event_id: str
    audit_event_hash: str

    def validate_for(self, record: CaptureRecord) -> None:
        """Fail closed if the acknowledgement does not match *record*."""

        if self.tenant_id != record.tenant_id:
            raise CaptureBindingError("capture acknowledgement tenant_id mismatch")
        if self.event_id != record.event_id:
            raise CaptureBindingError("capture acknowledgement event_id mismatch")
        if self.audit_event_hash != record.audit_event_hash:
            raise CaptureBindingError("capture acknowledgement audit_event_hash mismatch")


@dataclass(frozen=True)
class CaptureRecord:
    """Metadata-only D2 capture projection.

    Top-level fields intentionally mirror the approved RFC shape. Raw args,
    state, goal, reasons, and transformed arguments are not accepted.
    """

    schema_version: str
    tenant_id: str
    event_id: str
    audit_event_hash: str
    policy_bundle_id: str
    policy_version: str
    policy_hash: str
    evaluator_version: str
    projection_version: str
    decision_time: str
    field_status: Mapping[str, str]
    privacy_outcome: str
    capture_outcome: str
    capture_reason: str

    def __post_init__(self) -> None:
        required = {
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
            "event_id": self.event_id,
            "audit_event_hash": self.audit_event_hash,
            "policy_bundle_id": self.policy_bundle_id,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "evaluator_version": self.evaluator_version,
            "projection_version": self.projection_version,
            "decision_time": self.decision_time,
            "privacy_outcome": self.privacy_outcome,
            "capture_outcome": self.capture_outcome,
            "capture_reason": self.capture_reason,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise CaptureProjectionError(
                "insufficient-projection: missing " + ", ".join(sorted(missing))
            )
        if self.capture_outcome not in {"captured", "capture_failed", "disabled"}:
            raise CaptureProjectionError(f"invalid capture_outcome {self.capture_outcome!r}")
        object.__setattr__(self, "field_status", _validated_field_status(self.field_status))

    def to_dict(self) -> dict[str, Any]:
        """Return the stable JSON representation."""

        return {
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
            "event_id": self.event_id,
            "audit_event_hash": self.audit_event_hash,
            "policy_bundle_id": self.policy_bundle_id,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "evaluator_version": self.evaluator_version,
            "projection_version": self.projection_version,
            "decision_time": self.decision_time,
            "field_status": dict(self.field_status),
            "privacy_outcome": self.privacy_outcome,
            "capture_outcome": self.capture_outcome,
            "capture_reason": self.capture_reason,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CaptureRecord:
        """Decode a persisted capture record."""

        field_status = payload.get("field_status")
        if not isinstance(field_status, Mapping):
            raise CaptureProjectionError("insufficient-projection: missing field_status")
        return cls(
            schema_version=_string(payload, "schema_version"),
            tenant_id=_string(payload, "tenant_id"),
            event_id=_string(payload, "event_id"),
            audit_event_hash=_string(payload, "audit_event_hash"),
            policy_bundle_id=_string(payload, "policy_bundle_id"),
            policy_version=_string(payload, "policy_version"),
            policy_hash=_string(payload, "policy_hash"),
            evaluator_version=_string(payload, "evaluator_version"),
            projection_version=_string(payload, "projection_version"),
            decision_time=_string(payload, "decision_time"),
            field_status={str(key): str(value) for key, value in field_status.items()},
            privacy_outcome=_string(payload, "privacy_outcome"),
            capture_outcome=_string(payload, "capture_outcome"),
            capture_reason=_string(payload, "capture_reason"),
        )


@dataclass(frozen=True)
class CaptureConfig:
    """Runtime capture configuration for UniversalGateway issuer paths."""

    mode: CaptureMode
    store: CaptureStore | None = None
    observation_sink: CaptureObservationSink | None = None
    evaluator_version: str = ""
    projection_version: str = ""
    field_status: Mapping[str, str] = field(
        default_factory=lambda: {
            "argument_hash": "present",
            "state_hash": "present",
        }
    )
    privacy_outcome: str = "metadata_only"

    def __post_init__(self) -> None:
        mode = CaptureMode(self.mode)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "field_status", _validated_field_status(self.field_status))
        if mode in (CaptureMode.REQUIRED, CaptureMode.BEST_EFFORT):
            if not self.evaluator_version:
                raise CaptureConfigurationError(
                    f"{mode.value} capture mode needs evaluator_version"
                )
            if not self.projection_version:
                raise CaptureConfigurationError(
                    f"{mode.value} capture mode needs projection_version"
                )
        if mode is CaptureMode.REQUIRED:
            if self.store is None:
                raise CaptureConfigurationError("required capture mode needs a capture store")
            if self.observation_sink is None:
                raise CaptureConfigurationError("required capture mode needs an observation sink")
        if mode is CaptureMode.BEST_EFFORT and self.observation_sink is None:
            raise CaptureConfigurationError("best-effort capture mode needs an observation sink")


class JsonlCaptureStore:
    """Durable tenant-scoped JSONL capture store for metadata-only records."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record: CaptureRecord) -> CaptureAck:
        payload = record.to_dict()
        data = _canonical_line(payload)
        with self.path.open("ab") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        return CaptureAck(
            tenant_id=record.tenant_id,
            event_id=record.event_id,
            audit_event_hash=record.audit_event_hash,
        )

    def get(self, *, tenant_id: str, event_id: str) -> CaptureRecord | None:
        """Return a tenant-bound record, rejecting cross-tenant event reuse."""

        if not self.path.exists():
            return None
        found_other_tenant = False
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    raise CaptureProjectionError("capture line is not a JSON object")
                if payload.get("event_id") != event_id:
                    continue
                if payload.get("tenant_id") != tenant_id:
                    found_other_tenant = True
                    continue
                return CaptureRecord.from_dict(payload)
        if found_other_tenant:
            raise CaptureTenantError("capture record belongs to a different tenant")
        return None


class JsonlCaptureObservationSink:
    """Durable JSONL observation sink for capture lifecycle events."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: Mapping[str, Any]) -> None:
        with self.path.open("ab") as fh:
            fh.write(_canonical_line(dict(event)))
            fh.flush()
            os.fsync(fh.fileno())


def capture_record_for_decision(
    *,
    tenant_id: str,
    event_id: str,
    audit_event_hash: str,
    policy_bundle_id: str,
    policy_version: str,
    policy_hash: str,
    evaluator_version: str,
    projection_version: str,
    decision_time: str,
    field_status: Mapping[str, str],
    privacy_outcome: str,
    capture_outcome: str = "captured",
    capture_reason: str = "captured-after-audit-before-receipt",
) -> CaptureRecord:
    """Build the approved D2 capture projection for one audited decision."""

    return CaptureRecord(
        schema_version="gove-zone.capture/v1",
        tenant_id=tenant_id,
        event_id=event_id,
        audit_event_hash=audit_event_hash,
        policy_bundle_id=policy_bundle_id,
        policy_version=policy_version,
        policy_hash=policy_hash,
        evaluator_version=evaluator_version,
        projection_version=projection_version,
        decision_time=decision_time,
        field_status=field_status,
        privacy_outcome=privacy_outcome,
        capture_outcome=capture_outcome,
        capture_reason=capture_reason,
    )


def capture_observation(
    kind: str, record: CaptureRecord, *, error_class: str = ""
) -> dict[str, Any]:
    """Build a non-authoritative capture lifecycle observation."""

    event: dict[str, Any] = {
        "kind": kind,
        "tenant_id": record.tenant_id,
        "event_id": record.event_id,
        "audit_event_hash": record.audit_event_hash,
        "capture_outcome": record.capture_outcome,
    }
    if error_class:
        event["error_class"] = error_class
    return event


def _canonical_line(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    return value if isinstance(value, str) else ""


def _validated_field_status(field_status: Mapping[str, str]) -> Mapping[str, str]:
    validated: dict[str, str] = {}
    for key, value in field_status.items():
        if key not in APPROVED_FIELD_STATUS_FIELDS:
            raise CaptureProjectionError(f"field_status key is not approved: {key!r}")
        if value not in APPROVED_FIELD_STATUS_VALUES:
            raise CaptureProjectionError(f"field_status value is not approved: {value!r}")
        validated[str(key)] = str(value)
    return MappingProxyType(validated)
