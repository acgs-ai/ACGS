"""ACGS reference adapter for the Anthropic Claude Agent SDK.

Claude Agent SDK exposes a tool-use callback per session: each tool_use
block can be intercepted before the SDK invokes the underlying function.
ACGS plugs in by wrapping the tool executor with a governance pre-check.

Integration sketch (no real `anthropic` SDK dependency required):

    from anthropic import Agent
    from governance.adapters.anthropic_claude import govern_anthropic_tool_call

    def on_tool_use(session_id, name, args):
        return govern_anthropic_tool_call(
            session_id=session_id, tool_name=name, tool_args=args,
            principal=session_principal(session_id),
            adapter=governed_adapter, tool_executor=tool_dispatch[name],
        )

If governance denies, guard() raises (PermissionError today, typed
GovernanceDeniedError after Lane 2). The Claude Agent SDK surfaces the
raised exception to the model as a tool-use failure.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from governance.adapters.tools import GovernedToolAdapter
from governance.models import ActionRequest, Principal
from governance.utils import canonical_input_hash


def govern_anthropic_tool_call(
    session_id: str,
    tool_name: str,
    tool_args: dict[str, Any],
    principal: dict[str, Any],
    adapter: GovernedToolAdapter,
    tool_executor: Callable[[dict[str, Any]], Any],
) -> Any:
    resource = str(tool_args.get("resource", f"anthropic-claude/{session_id}"))
    metadata: dict[str, Any] = {"adapter": "anthropic-claude", "session_id": session_id}
    if "policy_citations" in tool_args:
        metadata["policy_citations"] = list(tool_args["policy_citations"])
    request = ActionRequest.from_dict(
        {
            "actor": Principal.from_dict(principal),
            "intent": f"anthropic-claude:{session_id}:{tool_name}",
            "action_type": tool_name,
            "resource": resource,
            "inputs_hash": canonical_input_hash(tool_args),
            "tool_input": tool_args,
            "metadata": metadata,
        }
    )
    return adapter.guard(request, tool_executor)
