from __future__ import annotations

from typing import Any

from governance.models import sha256_json


def canonical_input_hash(tool_input: dict[str, Any]) -> str:
    """Stable hash of a tool-call input for cross-adapter replay.

    Reuses the same canonical-JSON SHA-256 derivation that
    ActionRequest.from_dict applies, so an inputs_hash produced here is
    identical to the one a downstream ActionRequest would derive from the
    same tool_input. Reference adapters call this to ensure that the same
    tool call governed through OpenAI Agents SDK, LangGraph, or Anthropic
    Claude Agent SDK produces an identical inputs_hash, which makes
    cross-adapter replay sound.
    """
    return sha256_json(tool_input)


__all__ = ["canonical_input_hash"]
