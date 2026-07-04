"""Receipt-gated LangGraph governed graph — self-contained mini-runner.

This module mirrors LangGraph's node-dispatch + conditional-edge contract
*without* a real ``langgraph`` dependency (the package's own
``governance/adapters/AGENTS.md`` mandates that adapters target only the
SDK's callback contract, not the SDK). A governed tool node calls the
existing :func:`governance.adapters.langgraph.govern_langgraph_tool_call`
adapter; if governance denies, the adapter's ``guard()`` raises *before* the
side-effect executor is ever invoked, and the conditional edge routes the
exception to a remediation node. The "receipt" is the persisted
``DecisionRecord`` in the adapter's ``ChainHashAuditStore``.

Fail-closed proof: the executor is handed only to ``govern_langgraph_tool_call``
(→ ``adapter.guard``). On a deny it is provably never called, so a spy's call
list stays empty.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from governance.adapters.langgraph import govern_langgraph_tool_call
from governance.adapters.tools import GovernedToolAdapter


class ToolExecuted:
    """Spy-friendly side-effect sentinel for the governed tool.

    Records each (validated) ``tool_input`` it is invoked with, so callers can
    prove the side effect ran exactly when expected — and, on a governance
    deny, that ``calls`` stays empty (fail-closed).
    """

    def __init__(self, return_value: Any | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._return_value: Any = {"ok": True} if return_value is None else return_value

    def __call__(self, tool_input: dict[str, Any]) -> Any:
        self.calls.append(tool_input)
        return self._return_value


class MiniGraph:
    """Minimal node-dispatch graph mirroring LangGraph's conditional edge.

    Two nodes — the governed tool node and a remediation node — wired by a
    single conditional edge: if the tool node raises a governance denial
    (``PermissionError`` / ``GovernanceDeniedError``), dispatch routes to
    remediation; otherwise the graph terminates with the tool result.
    """

    def __init__(
        self,
        *,
        govern_node: Callable[[dict[str, Any]], dict[str, Any]],
        remediation_node: Callable[[dict[str, Any], PermissionError], dict[str, Any]],
    ) -> None:
        self._govern_node = govern_node
        self._remediation_node = remediation_node

    def invoke(self, state: dict[str, Any]) -> dict[str, Any]:
        try:
            return self._govern_node(state)
        except PermissionError as err:
            # Conditional edge: a node that raises routes to remediation,
            # mirroring "exception becomes the node's error -> remediation".
            return self._remediation_node(state, err)


def build_governed_graph(
    adapter: GovernedToolAdapter,
    tool_executor: Callable[[dict[str, Any]], Any],
    *,
    node_name: str = "redline-node",
    tool_name: str = "contract.redline",
) -> MiniGraph:
    """Build a governed mini-graph around ``govern_langgraph_tool_call``.

    The graph's input state is ``{"principal": {...}, "tool_args": {...}}``.
    ``invoke`` returns the final state with keys:
      ``terminal``: ``"done"`` (allowed) or ``"remediation"`` (denied)
      ``result``:   the executor return value (only when ``terminal == "done"``)
      ``denial``:   ``{"reason_codes": [...], "event_hash": str}`` (only on deny)
    """

    def govern_node(state: dict[str, Any]) -> dict[str, Any]:
        # The executor is passed ONLY into the adapter's guard — never called
        # here directly — so a denial provably never runs the side effect.
        result = govern_langgraph_tool_call(
            node_name=node_name,
            tool_name=tool_name,
            tool_args=state["tool_args"],
            principal=state["principal"],
            adapter=adapter,
            tool_executor=tool_executor,
        )
        return {**state, "terminal": "done", "result": result}

    def remediation_node(state: dict[str, Any], err: PermissionError) -> dict[str, Any]:
        decision = getattr(err, "decision", None)
        denial = {
            "reason_codes": list(decision.reason_codes) if decision is not None else [],
            "event_hash": decision.event_hash if decision is not None else None,
        }
        return {**state, "terminal": "remediation", "denial": denial}

    return MiniGraph(govern_node=govern_node, remediation_node=remediation_node)
