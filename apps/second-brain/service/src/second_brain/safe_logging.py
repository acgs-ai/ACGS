from __future__ import annotations

import logging
import math
import re
from collections.abc import Mapping
from uuid import UUID

_EVENT = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_.]{0,63}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")
_ERROR_CLASS = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,99}$")

_ID_FIELDS = {
    "answer_id",
    "audit_id",
    "chunk_id",
    "job_id",
    "memory_id",
    "owner_id",
    "policy_id",
    "project_id",
    "request_id",
    "source_id",
    "tag_id",
    "workspace_id",
}
_COUNT_FIELDS = {
    "byte_count",
    "chunk_count",
    "citation_count",
    "count",
    "retrieval_result_count",
}
_TOKEN_FIELDS = {
    "action",
    "decision",
    "policy_version",
    "provider",
    "model_identifier",
}
_STATE_FIELDS = {"semantic_status", "state", "status"}
_STATES = {
    "active",
    "approved",
    "archived",
    "available",
    "dead",
    "failed",
    "grounded",
    "insufficient_evidence",
    "pending",
    "processing",
    "proposed",
    "provider_unavailable",
    "purge_pending",
    "purged",
    "queued",
    "ready",
    "rejected",
    "superseded",
    "unavailable",
    "validation_failed",
    "complete",
}
_ALLOWED_FIELDS = (
    _ID_FIELDS
    | _COUNT_FIELDS
    | _TOKEN_FIELDS
    | _STATE_FIELDS
    | {"error_class", "latency_ms", "reason_code"}
)


def _safe_value(key: str, value: object) -> str | int | float:
    if key in _ID_FIELDS:
        if isinstance(value, UUID):
            return str(value)
        if key in {"audit_id", "policy_id"} and isinstance(value, str) and _TOKEN.fullmatch(value):
            return value
        raise ValueError(f"{key} must be a UUID or bounded identifier")
    if key in _COUNT_FIELDS:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{key} must be a non-negative integer")
        return value
    if key == "latency_ms":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("latency_ms must be finite and non-negative")
        numeric = float(value)
        if not math.isfinite(numeric) or numeric < 0:
            raise ValueError("latency_ms must be finite and non-negative")
        return numeric
    if key in _STATE_FIELDS:
        if not isinstance(value, str) or value not in _STATES:
            raise ValueError(f"{key} is not an allowed state")
        return value
    if key == "reason_code":
        if not isinstance(value, str) or not _REASON.fullmatch(value):
            raise ValueError("reason_code must be a bounded namespaced code")
        return value
    if key == "error_class":
        if not isinstance(value, str) or not _ERROR_CLASS.fullmatch(value):
            raise ValueError("error_class must be a class name")
        return value
    if key in _TOKEN_FIELDS:
        if not isinstance(value, str) or not _TOKEN.fullmatch(value):
            raise ValueError(f"{key} must be a bounded token")
        return value
    raise ValueError(f"logging field is not allowlisted: {key}")


def safe_metadata(
    *, error: BaseException | None = None, **metadata: object
) -> dict[str, str | int | float]:
    """Return content-free structured logging metadata or reject the event."""
    unknown = set(metadata) - _ALLOWED_FIELDS
    if unknown:
        raise ValueError(f"logging fields are not allowlisted: {','.join(sorted(unknown))}")
    if error is not None:
        if "error_class" in metadata:
            raise ValueError("supply error or error_class, not both")
        metadata["error_class"] = type(error).__name__
    return {key: _safe_value(key, value) for key, value in sorted(metadata.items())}


def safe_log(
    logger: logging.Logger,
    level: int,
    event: str,
    *,
    error: BaseException | None = None,
    **metadata: object,
) -> None:
    """Emit an allowlisted event without exception messages or arbitrary values."""
    if not _EVENT.fullmatch(event):
        raise ValueError("event must be a bounded snake-case token")
    fields: Mapping[str, str | int | float] = safe_metadata(error=error, **metadata)
    suffix = " ".join(f"{key}={value}" for key, value in fields.items())
    logger.log(level, "%s%s", event, f" {suffix}" if suffix else "")
