"""ACGS MCP Governance Gateway — governed interception for MCP tool calls.

Flow::

    Agent -> MCP request -> ACGS policy check -> Decision Receipt -> tool execution

This package is a thin, dependency-free assembly over the sealed gove-zone
kernel primitives. It adds **no new gate logic**: every decision goes through
:meth:`gove_zone.kernel.Kernel.evaluate_and_record`, and every execution is
authorised by a :class:`gove_zone.receipt.DecisionReceipt` verified inside
:func:`gove_zone.executor.execute_with_receipt`.

Bindings enforced at the execution gate:

- **tool name binding** — the receipt authorises exactly one tool
  (``expected_action``); a receipt minted for tool A cannot execute tool B.
- **argument hashing** — the receipt carries the canonical hash of the
  proposed arguments; modified arguments are refused.
- **identity binding** — the receipt is anchored to the invoking principal
  (``expected_actor``); a different identity cannot spend it.
- **receipt verification** — hash integrity, signature posture (per
  :class:`gove_zone.profile.GovernanceProfile`), and expiry (``expires_at``)
  are all checked before the tool callable runs.
"""

from mcp_gateway.gateway import (
    GatewayDecision,
    MCPGovernanceGateway,
)

__all__ = [
    "GatewayDecision",
    "MCPGovernanceGateway",
]
