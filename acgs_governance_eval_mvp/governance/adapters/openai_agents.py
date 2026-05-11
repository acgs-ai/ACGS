"""ACGS reference adapter for the OpenAI Agents SDK.

The OpenAI Agents SDK exposes guardrails and tool-use callbacks where each
tool invocation can be intercepted before execution. ACGS plugs into that
surface by wrapping the tool executor with a governance pre-check.

Integration sketch (no real `openai-agents` dependency required):

    from openai_agents import Agent, function_tool
    from governance.adapters.openai_agents import govern_openai_agent_tool_call

    @function_tool
    def redline_contract(args: dict) -> dict:
        return govern_openai_agent_tool_call(
            agent_name="legal-bot", tool_name="contract.redline",
            tool_args=args, principal=current_principal(),
            adapter=governed_adapter, tool_executor=do_redline,
        )

If governance denies the call, guard() raises (PermissionError today, the
typed GovernanceDeniedError once Lane 2 lands). The exception propagates
to the SDK so the agent sees a tool-call failure and can react.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from governance.adapters.tools import GovernedToolAdapter
from governance.models import ActionRequest, Principal
from governance.utils import canonical_input_hash


def govern_openai_agent_tool_call(
    agent_name: str,
    tool_name: str,
    tool_args: dict[str, Any],
    principal: dict[str, Any],
    adapter: GovernedToolAdapter,
    tool_executor: Callable[[dict[str, Any]], Any],
) -> Any:
    resource = str(tool_args.get("resource", f"openai-agents/{agent_name}"))
    metadata: dict[str, Any] = {"adapter": "openai-agents", "agent_name": agent_name}
    if "policy_citations" in tool_args:
        metadata["policy_citations"] = list(tool_args["policy_citations"])
    request = ActionRequest.from_dict(
        {
            "actor": Principal.from_dict(principal),
            "intent": f"openai-agents:{agent_name}:{tool_name}",
            "action_type": tool_name,
            "resource": resource,
            "inputs_hash": canonical_input_hash(tool_args),
            "tool_input": tool_args,
            "metadata": metadata,
        }
    )
    return adapter.guard(request, tool_executor)
