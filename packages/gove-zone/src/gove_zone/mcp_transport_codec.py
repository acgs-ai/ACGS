"""Shared, fail-closed MCP result sanitization."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from mcp import types

from gove_zone.mcp_gateway import MCPDownstreamCredential


def contains_downstream_authority(
    value: Any,
    credential: MCPDownstreamCredential,
    *,
    reserved_keys: Sequence[str] = (),
) -> bool:
    """Inspect an entire JSON-shaped result for downstream authority data."""

    forbidden = (credential.secret, credential.credential_id, *reserved_keys)
    reserved = frozenset(reserved_keys)
    pending = [value]
    seen = 0
    while pending:
        current = pending.pop()
        seen += 1
        if seen > 8192:
            return True
        if isinstance(current, str):
            if any(item and item in current for item in forbidden):
                return True
        elif type(current) is dict:
            if reserved.intersection(current):
                return True
            pending.extend(current.keys())
            pending.extend(current.values())
        elif type(current) in (list, tuple):
            pending.extend(current)
    return False


def safe_call_result(
    result: types.CallToolResult,
    credential: MCPDownstreamCredential,
    *,
    reserved_keys: Sequence[str] = (),
) -> dict[str, Any] | None:
    """Return an explicit authority-free upstream payload or fail closed."""

    try:
        raw = result.model_dump(mode="json", by_alias=True, exclude_none=False)
    except Exception:
        return None
    if contains_downstream_authority(raw, credential, reserved_keys=reserved_keys):
        return None
    payload: dict[str, Any] = {
        "content": [
            item.model_dump(mode="json", by_alias=True, exclude_none=True)
            for item in result.content
        ],
        "isError": False,
    }
    if result.structuredContent is not None:
        payload["structuredContent"] = result.structuredContent
    return payload


__all__ = ["contains_downstream_authority", "safe_call_result"]
