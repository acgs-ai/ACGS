"""First-class MCP binding for the gove-zone kernel (audit R5 / PR-5).

Maps MCP ``tools/call`` / ``tools/list`` requests onto :class:`~gove_zone.kernel.Kernel`
so every MCP-exposed tool inherits ``Kernel.dispatch``'s structural gating:

- **Structural admission, not hand-wired admission.** The set of callable
  tools IS the kernel registry. There is no per-tool ``admit`` branch in this
  module and no "safe tool" bypass list — a tool that is not registered cannot
  run (:class:`~gove_zone.errors.UnknownToolError`), and a registered tool
  cannot run without a policy decision and an audit append. Forgetting to wire
  a tool means it is *unavailable*, never silently allowed.
- **Machine-readable denials.** DENY/ESCALATE surface as MCP ``isError: true``
  results carrying the structured rejection envelope
  (:meth:`~gove_zone.errors.DeniedError.to_rejection_dict`) in
  ``_meta.gove_zone`` — the calling agent can read ``resolution`` /
  ``matched_rules`` / ``resumable`` and self-correct instead of parsing prose.
- **Fail-closed error surface.** Tool-level failures are reported as
  ``isError: true`` *results* (per the MCP spec — the model should see and
  reason about them), never as silent successes. Tool-raised exception
  messages are not echoed (error class only; full detail stays in the audit
  chain), matching the rejection envelope's leak posture.

This module is dependency-free by design (gove-zone ships zero runtime
dependencies): it operates on already-parsed request ``dict``\\s and returns
result ``dict``\\s. Transport — stdio JSON-RPC framing, an ``mcp``-SDK server,
HTTP — is the caller's concern; wrap these handlers in the transport of your
choice. ``examples/mcp-tool-gateway`` shows the end-to-end pattern including a
signed execution gate.

The eval-grade ``governed_mcp_v0`` package (in ``acgs_governance_eval_mvp``)
predates this binding and keeps its hand-wired admission for benchmark
scenarios only — new production MCP tools register on a kernel and route
through this module.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from gove_zone.errors import (
    AuditError,
    DeniedError,
    EscalateError,
    GoveZoneError,
    UnknownToolError,
)
from gove_zone.kernel import Kernel

__all__ = ["mcp_tools_call", "mcp_tools_list"]

#: ``_meta.gove_zone.decision`` value for requests rejected before any policy
#: evaluation (malformed shape, wrong method, unregistered tool). Distinct from
#: the kernel decisions ("allow"/"deny"/...) so a consumer can tell "the gate
#: said no" apart from "the request never reached the gate".
_NOT_EVALUATED = "not_evaluated"


def mcp_tools_list(kernel: Kernel) -> dict[str, Any]:
    """MCP ``tools/list`` result: exactly the kernel registry, nothing else.

    The advertised tool set and the callable tool set are the same object by
    construction — there is no second list to drift out of sync.
    """
    return {"tools": [{"name": name} for name in sorted(kernel.registry.names())]}


def mcp_tools_call(kernel: Kernel, request: Mapping[str, Any]) -> dict[str, Any]:
    """Route one MCP ``tools/call`` request through ``Kernel.dispatch``.

    Accepts either a full JSON-RPC request (``{"method": "tools/call",
    "params": {"name": ..., "arguments": {...}}}``) or the bare params mapping.
    Returns the MCP ``tools/call`` *result* payload (the caller wraps it in its
    JSON-RPC envelope).

    If ``arguments`` carries a ``path`` entry it is additionally lifted into
    the governed call's path context (mirroring
    :mod:`gove_zone.integration`) so path-boundary policies can match it;
    the argument itself still reaches the tool unchanged.
    """
    method = request.get("method")
    if method is not None and method != "tools/call":
        return _error(f"unsupported method {method!r}; this binding handles tools/call")
    params = request.get("params") if "params" in request else request
    if not isinstance(params, Mapping):
        return _error("malformed tools/call request: params is not a mapping")
    tool_name = params.get("name")
    if not isinstance(tool_name, str) or not tool_name:
        return _error("malformed tools/call request: missing tool name")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, Mapping):
        return _error("malformed tools/call request: arguments is not a mapping")

    path = arguments.get("path")
    try:
        result, receipt = kernel.dispatch(
            tool_name,
            arguments,
            path=path if isinstance(path, str) else None,
        )
    except UnknownToolError:
        # Structural admission: not in the registry == not callable. No audit
        # event exists (nothing was evaluated), and no tool ran.
        return _error(f"tool not registered: {tool_name!r}")
    except (DeniedError, EscalateError) as exc:
        envelope = exc.to_rejection_dict()
        return {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": f"gove-zone {envelope['outcome']} {tool_name}: "
                    f"{envelope['reason']} [resolution: {envelope['resolution']}]",
                }
            ],
            "_meta": {"gove_zone": envelope},
        }
    except AuditError as exc:
        # Audit append failed -> the kernel refused to execute (fail-closed).
        return _error(f"audit append failed; call not executed: {type(exc).__name__}")
    except GoveZoneError as exc:
        return _error(f"governance error; call not executed: {type(exc).__name__}")
    except Exception as exc:  # noqa: BLE001 — tool fn raised mid-execution
        # The decision was ALLOW and the failure is recorded in the audit
        # chain (Kernel._record_execution_failure). Convey the class only —
        # tool exception text may echo raw arguments.
        return _error(
            f"tool execution failed: {type(exc).__name__}; see the audit chain",
        )

    return {
        "isError": False,
        "content": [{"type": "text", "text": _render(result)}],
        "_meta": {
            "gove_zone": {
                "decision": receipt.record.decision.value,
                "audit_hash": receipt.audit_hash,
                "decision_request_hash": receipt.record.decision_request_hash,
                "result_hash": receipt.result_hash,
                "actor": receipt.actor,
            }
        },
    }


def _render(result: Any) -> str:
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(result)


def _error(message: str) -> dict[str, Any]:
    return {
        "isError": True,
        "content": [{"type": "text", "text": f"gove-zone: {message}"}],
        "_meta": {"gove_zone": {"decision": _NOT_EVALUATED}},
    }
