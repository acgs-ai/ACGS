"""Runtime-hook integration adapter for gove-zone.

This is the **single canonical adapter** between agent-runtime hook payloads
(Claude Code ``PreToolUse``, Codex ``apply_patch``, generic A2A/MCP tool
events) and the gove-zone governance kernel.

A runtime hook hands us an opaque payload like::

    {"tool_name": "Edit", "tool_input": {"file_path": "...", "new_string": "..."}}

We map it onto:

1. A :class:`~gove_zone.tool.ToolCall` describing the proposed action.
2. A :class:`~gove_zone.decision.DecisionRecord` (the gate verdict).
3. A :class:`~gove_zone.receipt.Receipt` (the audit anchor) appended to a
   :class:`~gove_zone.audit.ChainHashAuditStore`.

The adapter is observation-by-default: it records what Claude (or any other
runtime) is about to do, because the runtime itself owns allow/deny. In
``GOVE_ZONE_GATE_MODE=enforce`` it fails closed — missing audit store,
import failure, or emission failure raises rather than silently dropping
the receipt.

Hooks MUST go through this module rather than calling kernel/audit
primitives directly. The contract here is the integration boundary; the
kernel is implementation detail.
"""

from __future__ import annotations

import dataclasses
import json
import os
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from gove_zone.audit import ChainHashAuditStore
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.policy import Policy, new_event_id
from gove_zone.receipt import Receipt
from gove_zone.tool import ToolCall, normalize_path_context

__all__ = [
    "GateMode",
    "current_gate_mode",
    "resolve_audit_path",
    "resolve_gate_mode_path",
    "emit_receipt_for_hook",
    "tool_call_from_hook_payload",
    "GateModeError",
]

_DEFAULT_AUDIT_SUBPATH = Path(".gove-zone") / "audit.jsonl"
_GATE_MODE_SUBPATH = Path(".gove-zone") / "gate.mode"
_OBSERVER_POLICY_VERSION = "hook-observer/v0"


class GateMode(StrEnum):
    OBSERVE = "observe"
    ENFORCE = "enforce"


class GateModeError(RuntimeError):
    """Raised in ENFORCE mode when receipt emission cannot complete."""


def resolve_gate_mode_path() -> Path:
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    base = Path(project_dir) if project_dir else Path.cwd()
    return base / _GATE_MODE_SUBPATH


def _read_gate_mode_file() -> str | None:
    path = resolve_gate_mode_path()
    try:
        return path.read_text(encoding="utf-8").strip().lower() or None
    except FileNotFoundError:
        return None
    except OSError:
        return None


def current_gate_mode() -> GateMode:
    """Resolve gate mode in this order:

    1. ``$GOVE_ZONE_GATE_MODE``
    2. ``$CLAUDE_PROJECT_DIR/.gove-zone/gate.mode`` (single line, "observe" or "enforce")
    3. default ``observe``
    """
    raw = (os.environ.get("GOVE_ZONE_GATE_MODE") or "").strip().lower()
    if raw == GateMode.ENFORCE.value:
        return GateMode.ENFORCE
    if raw == GateMode.OBSERVE.value:
        return GateMode.OBSERVE
    file_mode = _read_gate_mode_file()
    if file_mode == GateMode.ENFORCE.value:
        return GateMode.ENFORCE
    return GateMode.OBSERVE


def resolve_audit_path() -> Path:
    """Audit JSONL location, in resolution order.

    1. ``$GOVE_ZONE_AUDIT_PATH`` (explicit override).
    2. ``$CLAUDE_PROJECT_DIR/.gove-zone/audit.jsonl``.
    3. ``$PWD/.gove-zone/audit.jsonl``.
    """
    override = os.environ.get("GOVE_ZONE_AUDIT_PATH")
    if override:
        return Path(override)
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if project_dir:
        return Path(project_dir) / _DEFAULT_AUDIT_SUBPATH
    return Path.cwd() / _DEFAULT_AUDIT_SUBPATH


def _summarize_tool_input(tool_input: dict[str, Any]) -> dict[str, Any]:
    """Reduce tool_input to a stable, hash-friendly fingerprint.

    Hooks see full file contents on Edit/Write. Storing those verbatim in
    every audit record explodes the chain. We keep keys, types, and (for
    string values) a length + sha256 of the value.
    """
    summary: dict[str, Any] = {}
    for key, value in sorted(tool_input.items()):
        if isinstance(value, str):
            summary[key] = {
                "type": "str",
                "len": len(value),
                "sha256": sha256_json(value),
            }
        elif isinstance(value, (int, float, bool)) or value is None:
            summary[key] = value
        else:
            summary[key] = {"type": type(value).__name__, "sha256": sha256_json(value)}
    return summary


def _arguments_to_mapping(value: Any) -> dict[str, Any]:
    """Normalize runtime argument payloads into a dict for hashing.

    Agent runtimes disagree on where tool arguments live. Claude-style hooks
    pass a dict in ``tool_input``; MCP and function-call bridges often pass
    ``arguments`` as either an object or a JSON string. Non-object arguments
    are still hashable and reviewable under a stable ``arguments`` key.
    """
    if value is None:
        return {}
    if isinstance(value, dict):
        return cast(dict[str, Any], value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"arguments": value}
        if isinstance(parsed, dict):
            return cast(dict[str, Any], parsed)
        return {"arguments": parsed}
    return {"arguments": value}


def _tool_name_and_input_from_payload(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Return a runtime-neutral tool name and argument mapping.

    Supported shapes are intentionally dependency-free and conservative:

    * Claude/Codex-style hook events: ``{tool_name, tool_input}``
    * MCP JSON-RPC tool calls: ``{method: "tools/call", params: {name, arguments}}``
    * OpenAI/function-call style events: ``{type: "function_call", name, arguments}``
      or ``{function: {name, arguments}}``
    * OpenAI Chat/LangChain-style single tool calls:
      ``{tool_calls: [{function: {name, arguments}}]}`` or
      ``{tool_calls: [{name, args}]}``
    * Generic bridges: ``{name, arguments|args|input}`` or
      ``{tool: {name, arguments|args}}``
    """
    tool_name = payload.get("tool_name")
    if tool_name:
        return str(tool_name), _arguments_to_mapping(payload.get("tool_input"))

    params = payload.get("params")
    if isinstance(params, dict) and (
        payload.get("method") == "tools/call" or params.get("name") or params.get("tool_name")
    ):
        name = params.get("name") or params.get("tool_name")
        arguments = params.get("arguments", params.get("args", params.get("tool_input")))
        if name:
            return str(name), _arguments_to_mapping(arguments)

    tool_calls = payload.get("tool_calls")
    if isinstance(tool_calls, list) and len(tool_calls) == 1 and isinstance(tool_calls[0], dict):
        tool_call = cast(dict[str, Any], tool_calls[0])
        function_call = tool_call.get("function")
        if isinstance(function_call, dict) and function_call.get("name"):
            return str(function_call["name"]), _arguments_to_mapping(function_call.get("arguments"))
        if tool_call.get("name"):
            arguments = tool_call.get(
                "arguments",
                tool_call.get("args", tool_call.get("input")),
            )
            return str(tool_call["name"]), _arguments_to_mapping(arguments)

    if isinstance(tool_calls, list) and len(tool_calls) > 1:
        names: list[str] = []
        for tool_call in tool_calls:
            if not isinstance(tool_call, dict):
                continue
            function_call = tool_call.get("function")
            if isinstance(function_call, dict) and function_call.get("name"):
                names.append(str(function_call["name"]))
            elif tool_call.get("name"):
                names.append(str(tool_call["name"]))
        return "tool_calls.batch", {
            "tool_call_count": len(tool_calls),
            "tool_call_names": names,
        }

    function = payload.get("function")
    if isinstance(function, dict) and function.get("name"):
        return str(function["name"]), _arguments_to_mapping(function.get("arguments"))

    if payload.get("type") == "function_call" and payload.get("name"):
        return str(payload["name"]), _arguments_to_mapping(payload.get("arguments"))

    if payload.get("name"):
        arguments = payload.get("arguments", payload.get("args", payload.get("input")))
        return str(payload["name"]), _arguments_to_mapping(arguments)

    tool = payload.get("tool")
    if isinstance(tool, str):
        arguments = payload.get("arguments", payload.get("args", payload.get("input")))
        return tool, _arguments_to_mapping(arguments)
    if isinstance(tool, dict) and tool.get("name"):
        arguments = tool.get("arguments", tool.get("args", payload.get("arguments")))
        return str(tool["name"]), _arguments_to_mapping(arguments)

    return "unknown", {}


def _first_mapping(*values: Any) -> dict[str, Any]:
    for value in values:
        if isinstance(value, dict):
            return cast(dict[str, Any], value)
    return {}


def _runtime_context_from_payload(
    payload: dict[str, Any],
    tool_input: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Extract optional goal/state context for policy-bundle evaluation.

    Runtime bridges can provide raw organizational state at top level, inside
    JSON-RPC ``params``, or inside generic/function-call argument payloads.
    The audit record stores only ``state_hash``; the raw state is used only for
    policy matching before the side effect.
    """
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
    function = payload.get("function") if isinstance(payload.get("function"), dict) else {}
    tool = payload.get("tool") if isinstance(payload.get("tool"), dict) else {}
    tool_calls = payload.get("tool_calls")
    single_tool_call = (
        tool_calls[0]
        if isinstance(tool_calls, list) and len(tool_calls) == 1 and isinstance(tool_calls[0], dict)
        else {}
    )
    tool_call_function = (
        single_tool_call.get("function")
        if isinstance(single_tool_call.get("function"), dict)
        else {}
    )

    goal = ""
    for source in (
        payload,
        params,
        function,
        tool,
        single_tool_call,
        tool_call_function,
        tool_input,
    ):
        if not isinstance(source, dict):
            continue
        for key in ("goal", "intent", "purpose"):
            value = source.get(key)
            if isinstance(value, str) and value:
                goal = value
                break
        if goal:
            break

    state = _first_mapping(
        payload.get("state"),
        payload.get("context"),
        cast(dict[str, Any], params).get("state"),
        cast(dict[str, Any], params).get("context"),
        cast(dict[str, Any], function).get("state"),
        cast(dict[str, Any], function).get("context"),
        cast(dict[str, Any], tool).get("state"),
        cast(dict[str, Any], tool).get("context"),
        cast(dict[str, Any], single_tool_call).get("state"),
        cast(dict[str, Any], single_tool_call).get("context"),
        cast(dict[str, Any], tool_call_function).get("state"),
        cast(dict[str, Any], tool_call_function).get("context"),
        tool_input.get("state"),
        tool_input.get("context"),
    )
    return goal, state


def _path_from_tool_input(tool_input: dict[str, Any]) -> tuple[str, ...]:
    for key in ("file_path", "path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return normalize_path_context(value)
    return ()


def tool_call_from_hook_payload(
    payload: dict[str, Any],
    *,
    action_kind: str,
    actor: str,
) -> ToolCall:
    """Normalize an opaque runtime event into a governed :class:`ToolCall`.

    This public helper lets framework bridges inspect or policy-check the
    exact canonical pre-execution request that ``emit_receipt_for_hook`` will
    audit, without forcing the bridge to duplicate hook-shape parsing.
    """
    tool_name, tool_input = _tool_name_and_input_from_payload(payload)
    goal, state = _runtime_context_from_payload(payload, tool_input)
    summary = _summarize_tool_input(tool_input)
    path = _path_from_tool_input(tool_input)
    return ToolCall(
        name=f"runtime.{tool_name}",
        args={"action_kind": action_kind, "summary": summary},
        goal=goal,
        actor=actor,
        path=path,
        state=state,
    )


class _ObserverPolicy(Policy):
    """Default policy for runtime-hook adapter: every call ALLOWED.

    Observation-by-default: the host runtime owns deny via its own
    permission system. The kernel still records a deterministic decision.
    Callers that want allow/deny/transform routing pass their own ``Policy``
    to :func:`emit_receipt_for_hook`.
    """

    def __init__(self, action_kind: str) -> None:
        self._action_kind = action_kind

    @property
    def version(self) -> str:
        return _OBSERVER_POLICY_VERSION

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.ALLOW,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=(f"action_kind:{self._action_kind}",),
            reason="runtime-hook observation receipt",
        )


def emit_receipt_for_hook(
    payload: dict[str, Any],
    *,
    action_kind: str,
    actor: str,
    run_id: str | None = None,
    policy: Policy | None = None,
) -> Receipt | None:
    """Emit one governance receipt for a runtime-hook event.

    Uses the supplied :class:`~gove_zone.policy.Policy` to produce the
    :class:`Decision`. Default is an observer that always emits
    :attr:`Decision.ALLOW` (the host runtime's own permission system owns
    deny). Pass a custom policy to surface DENY/TRANSFORM/ESCALATE
    decisions in the audit chain.

    Returns the :class:`Receipt` on success.

    In :attr:`GateMode.OBSERVE` (default), returns ``None`` on any internal
    failure — preserving existing fail-open behavior.

    In :attr:`GateMode.ENFORCE`, raises :class:`GateModeError` on any failure
    that would have been swallowed. Callers must propagate the failure
    (exit non-zero in a hook context).
    """
    mode = current_gate_mode()
    active_policy = policy if policy is not None else _ObserverPolicy(action_kind)
    try:
        call = tool_call_from_hook_payload(payload, action_kind=action_kind, actor=actor)
        try:
            record = active_policy.evaluate(call)
        except Exception as exc:  # noqa: BLE001 — fail-closed on policy error
            record = DecisionRecord(
                decision=Decision.DENY,
                tool=call.name,
                argument_hash=call.argument_hash(),
                policy_version=getattr(active_policy, "version", "unknown"),
                event_id=new_event_id(),
                matched_rules=(f"action_kind:{action_kind}", "policy_error"),
                reason=f"policy raised: {type(exc).__name__}: {exc}",
            )
        record = dataclasses.replace(
            record,
            goal=call.goal,
            actor=call.actor,
            path=call.path,
            state_hash=call.state_hash(),
            decision_request_hash=call.decision_request_hash(),
        )
        audit_path = resolve_audit_path()
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        store = ChainHashAuditStore(str(audit_path))
        event = store.append(record)
        return Receipt(
            record=record,
            audit_hash=str(event.get("event_hash", "")),
            actor=actor,
            result_hash=None,
            error_class=None,
        )
    except Exception as exc:  # noqa: BLE001 — adapter boundary
        if mode is GateMode.ENFORCE:
            raise GateModeError(
                f"receipt emission failed under enforce mode: {exc!r} "
                f"(action_kind={action_kind}, actor={actor}, run_id={run_id})"
            ) from exc
        return None
