"""Framework-neutral governance request adapters.

The adapter layer normalizes common tool-call envelopes into the single
``GovernanceRequest`` contract used by the receipt-first engine. Unsupported or
malformed envelopes fail closed by raising ``AdapterError``.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from typing import Any

from gove_zone.errors import GoveZoneError
from gove_zone.foundation import GovernanceRequest


class AdapterError(GoveZoneError):
    """Raised when an external tool-call envelope cannot be governed safely."""


def normalize_governance_request(envelope: Mapping[str, Any]) -> GovernanceRequest:
    """Normalize a supported external envelope into ``GovernanceRequest``.

    Supported shapes are intentionally small and explicit: MCP ``tools/call``,
    OpenAI/Responses function calls, LangChain tool calls, generic JSON tool
    calls, CI/CD executor actions, and workflow-engine steps.
    """
    if not isinstance(envelope, Mapping):
        raise AdapterError("governance envelope must be a mapping")

    tool, args, request_id = _extract_action(envelope)
    return GovernanceRequest(
        request_id=_string(envelope.get("request_id") or request_id or _new_request_id()),
        tenant_id=_required_string(envelope, "tenant_id"),
        actor=envelope.get("actor", "unknown-actor"),
        subject=envelope.get("subject", "unknown-subject"),
        proposed_action={"tool": tool, "args": args},
        declared_goal=_string(envelope.get("declared_goal") or envelope.get("goal") or ""),
        execution_boundary=_mapping(envelope.get("execution_boundary") or {}),
        policy_bundle_id=_required_string(envelope, "policy_bundle_id"),
    )


def _extract_action(envelope: Mapping[str, Any]) -> tuple[str, dict[str, Any], str | None]:
    method = envelope.get("method")
    if method == "tools/call":
        params = _mapping(envelope.get("params"))
        return _required_string(params, "name"), _arguments(params.get("arguments", {})), None

    envelope_type = envelope.get("type")
    if envelope_type == "function_call":
        return (
            _required_string(envelope, "name"),
            _arguments(envelope.get("arguments", {})),
            _optional_string(envelope.get("call_id")),
        )
    if envelope_type == "langchain.tool_call":
        return (
            _required_string(envelope, "name"),
            _arguments(envelope.get("args", {})),
            _optional_string(envelope.get("id")),
        )
    if envelope_type == "ci.exec":
        args = _arguments(envelope.get("args", {}))
        args["job"] = _required_string(envelope, "job")
        return "ci.exec", args, _optional_string(envelope.get("request_id"))
    if envelope_type == "workflow.step":
        args = _arguments(envelope.get("inputs", {}))
        args["step_id"] = _required_string(envelope, "step_id")
        return (
            _required_string(envelope, "action"),
            args,
            _optional_string(envelope.get("request_id") or envelope.get("step_id")),
        )

    if "tool" in envelope:
        return (
            _required_string(envelope, "tool"),
            _arguments(envelope.get("args", {})),
            _optional_string(envelope.get("request_id")),
        )

    raise AdapterError("unsupported governance envelope")


def _arguments(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise AdapterError(f"arguments are not valid JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise AdapterError("arguments must be a mapping")
    return dict(value)


def _mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AdapterError("expected mapping in governance envelope")
    return dict(value)


def _required_string(mapping: Mapping[str, Any], key: str) -> str:
    return _string(mapping.get(key), field=key, required=True)


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    return _string(value)


def _string(value: Any, *, field: str = "value", required: bool = False) -> str:
    if isinstance(value, str) and value:
        return value
    if required:
        raise AdapterError(f"{field} is required")
    if value is None:
        return ""
    return str(value)


def _new_request_id() -> str:
    return f"req_{uuid.uuid4().hex[:16]}"
