"""ACGS reference adapter for LangGraph.

LangGraph models agents as graphs of nodes; tool nodes accept a
`before_tool_node` (or equivalent pre-execution) hook where a callable can
intercept and either approve, mutate, or reject the tool call. ACGS plugs
into that hook by wrapping the tool executor with a governance pre-check.

Integration sketch (no real `langgraph` dependency required):

    from langgraph.graph import StateGraph
    from governance.adapters.langgraph import govern_langgraph_tool_call

    def tool_node(state, tool_args):
        return govern_langgraph_tool_call(
            node_name="redline-node", tool_name="contract.redline",
            tool_args=tool_args, principal=state["principal"],
            adapter=governed_adapter, tool_executor=do_redline,
        )

If governance denies, guard() raises (PermissionError today, typed
GovernanceDeniedError after Lane 2). LangGraph surfaces the exception as
the node's error, which the graph can route to a remediation node.
"""

from __future__ import annotations

from typing import Any, Callable

from governance.adapters.tools import GovernedToolAdapter
from governance.models import ActionRequest, Principal
from governance.utils import canonical_input_hash


def govern_langgraph_tool_call(
    node_name: str,
    tool_name: str,
    tool_args: dict[str, Any],
    principal: dict[str, Any],
    adapter: GovernedToolAdapter,
    tool_executor: Callable[[dict[str, Any]], Any],
) -> Any:
    resource = str(tool_args.get("resource", f"langgraph/{node_name}"))
    metadata: dict[str, Any] = {"adapter": "langgraph", "node_name": node_name}
    if "policy_citations" in tool_args:
        metadata["policy_citations"] = list(tool_args["policy_citations"])
    request = ActionRequest.from_dict(
        {
            "actor": Principal.from_dict(principal),
            "intent": f"langgraph:{node_name}:{tool_name}",
            "action_type": tool_name,
            "resource": resource,
            "inputs_hash": canonical_input_hash(tool_args),
            "tool_input": tool_args,
            "metadata": metadata,
        }
    )
    return adapter.guard(request, tool_executor)
