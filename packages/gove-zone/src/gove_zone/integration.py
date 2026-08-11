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

The adapter is **fail-closed by default**: with no gate mode configured it
runs in ``enforce`` mode, where a missing audit store, import failure, or
emission failure raises rather than silently dropping the receipt — an
unrecognized or unreadable mode also resolves to ``enforce``. Observation-only
mode (record but never block, because the runtime itself owns allow/deny) is
an explicit, logged opt-in via ``GOVE_ZONE_GATE_MODE=observe`` or an
``observe`` line in the gate-mode file.

Hooks MUST go through this module rather than calling kernel/audit
primitives directly. The contract here is the integration boundary; the
kernel is implementation detail.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
from collections.abc import Callable
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
    "emit_receipts_for_hook",
    "tool_call_from_hook_payload",
    "tool_calls_from_hook_payload",
    "individual_tool_payloads",
    "tool_name_and_input",
    "GateModeError",
    "make_langgraph_tool_node",
]

_DEFAULT_AUDIT_SUBPATH = Path(".gove-zone") / "audit.jsonl"
_GATE_MODE_SUBPATH = Path(".gove-zone") / "gate.mode"
_OBSERVER_POLICY_VERSION = "hook-observer/v0"
_MALFORMED_BATCH_PAYLOAD_KEY = "_gove_zone_malformed_batch"
_MALFORMED_BATCH_TOOL_NAME = "runtime.malformed_batch"
_MALFORMED_BATCH_POLICY_VERSION = "runtime-malformed-batch/v0"


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


_LOGGER = logging.getLogger("gove_zone.integration")


def _log_observe_opt_in(source: str) -> None:
    # WARNING so the downgrade surfaces on stderr even with no logging config
    # (logging's last-resort handler emits WARNING+). This is a logger record
    # only — it is NOT appended to the audit chain.
    _LOGGER.warning("gove-zone gate mode DOWNGRADED to observe (explicit opt-in via %s)", source)


def current_gate_mode() -> GateMode:
    """Resolve gate mode in this order:

    1. ``$GOVE_ZONE_GATE_MODE`` ("observe" or "enforce")
    2. ``$CLAUDE_PROJECT_DIR/.gove-zone/gate.mode`` (single line, "observe" or "enforce")
    3. default ``enforce``

    Fail-closed: an unset, unreadable, or unrecognized mode resolves to
    :attr:`GateMode.ENFORCE` — never silently to observe. Observation-only
    mode is an explicit opt-in; selecting it emits a WARNING through the
    ``gove_zone.integration`` logger (visible on stderr by default via
    logging's last-resort handler — but a logger record only, not an
    audit-chain event).
    """
    raw = (os.environ.get("GOVE_ZONE_GATE_MODE") or "").strip().lower()
    if raw == GateMode.ENFORCE.value:
        return GateMode.ENFORCE
    if raw == GateMode.OBSERVE.value:
        _log_observe_opt_in("environment variable GOVE_ZONE_GATE_MODE")
        return GateMode.OBSERVE
    file_mode = _read_gate_mode_file()
    if file_mode == GateMode.OBSERVE.value:
        _log_observe_opt_in(f"gate-mode file {resolve_gate_mode_path()}")
        return GateMode.OBSERVE
    return GateMode.ENFORCE


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


def _response_output_items_from_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Return Responses-style output items carried by a runtime payload.

    OpenAI Responses returns function calls as output items instead of Chat
    Completions ``tool_calls``. Bridges may forward either the whole response
    object, its ``output`` list, or a streaming ``item`` wrapper. Keep this
    adapter dependency-free by accepting only plain mapping/list shapes.
    """
    response = payload.get("response")
    candidates: list[Any] = [payload.get("output")]
    if isinstance(response, dict):
        candidates.append(response.get("output"))
    if isinstance(payload.get("item"), dict):
        candidates.append([payload["item"]])

    output_items: list[dict[str, Any]] = []
    for candidate in candidates:
        if not isinstance(candidate, list):
            continue
        for item in candidate:
            if isinstance(item, dict):
                output_items.append(cast(dict[str, Any], item))
    return output_items


def _responses_function_call_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item
        for item in _response_output_items_from_payload(payload)
        if item.get("type") == "function_call" and item.get("name")
    ]


def _with_top_level_runtime_context(
    payload: dict[str, Any],
    child: dict[str, Any],
) -> dict[str, Any]:
    """Carry batch-level goal/state context into one child tool-call item.

    OpenAI Chat, OpenAI Responses, and LangChain-style runtimes can emit
    multiple tool calls in one assistant turn. The authorization context often
    lives beside the batch rather than inside each child item, so preserve it
    before evaluating individual calls.
    """
    merged: dict[str, Any] = {}
    response_value = payload.get("response")
    response = cast(dict[str, Any], response_value) if isinstance(response_value, dict) else {}
    for source in (payload, response):
        for key in ("goal", "intent", "purpose", "state", "context"):
            if key in source and key not in merged:
                merged[key] = source[key]
    merged.update(child)
    return merged


def _is_parseable_tool_call_item(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    function_call = item.get("function")
    return bool((isinstance(function_call, dict) and function_call.get("name")) or item.get("name"))


def _malformed_batch_payload(
    payload: dict[str, Any],
    *,
    batch_shape: str,
    reason: str,
    item_count: int,
    parseable_count: int,
) -> dict[str, Any]:
    """Return an internal fail-closed payload for unsafe batch containers."""
    return {
        **_with_top_level_runtime_context(payload, {}),
        _MALFORMED_BATCH_PAYLOAD_KEY: True,
        "summary": {
            "batch_shape": batch_shape,
            "reason": reason,
            "item_count": item_count,
            "parseable_count": parseable_count,
            "unparseable_count": max(item_count - parseable_count, 0),
        },
    }


def _individual_tool_payloads_from_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    """Expand recognizable multi-call runtime batches into child payloads.

    ``tool_call_from_hook_payload`` intentionally preserves the historical
    single-call contract by returning a synthetic ``*.batch`` summary for
    multiple calls. The policy gate, however, must evaluate every proposed
    side effect. This helper returns the child payloads for known multi-call
    shapes and falls back to the original payload for single-call or unknown
    shapes.
    """
    response_function_call_items = [
        item
        for item in _response_output_items_from_payload(payload)
        if item.get("type") == "function_call"
    ]
    responses_function_calls = [item for item in response_function_call_items if item.get("name")]
    if len(response_function_call_items) > 1:
        if len(responses_function_calls) != len(response_function_call_items):
            return (
                _malformed_batch_payload(
                    payload,
                    batch_shape="responses.output",
                    reason="unparseable function_call output item in batch",
                    item_count=len(response_function_call_items),
                    parseable_count=len(responses_function_calls),
                ),
            )
        return tuple(
            _with_top_level_runtime_context(payload, item) for item in responses_function_calls
        )

    tool_calls = payload.get("tool_calls")
    if isinstance(tool_calls, list) and len(tool_calls) > 1:
        children = [
            _with_top_level_runtime_context(payload, cast(dict[str, Any], item))
            for item in tool_calls
            if _is_parseable_tool_call_item(item)
        ]
        if len(children) != len(tool_calls):
            return (
                _malformed_batch_payload(
                    payload,
                    batch_shape="tool_calls",
                    reason="unparseable child tool call in batch",
                    item_count=len(tool_calls),
                    parseable_count=len(children),
                ),
            )
        return tuple(children)

    return (payload,)


def _tool_name_and_input_from_payload(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Return a runtime-neutral tool name and argument mapping.

    Supported shapes are intentionally dependency-free and conservative:

    * Claude/Codex-style hook events: ``{tool_name, tool_input}``
    * MCP JSON-RPC tool calls: ``{method: "tools/call", params: {name, arguments}}``
    * OpenAI/function-call style events: ``{type: "function_call", name, arguments}``
      or ``{function: {name, arguments}}``
    * OpenAI Responses-style output items:
      ``{output: [{type: "function_call", name, arguments}]}`` or
      ``{response: {output: [{type: "function_call", name, arguments}]}}``
    * OpenAI Chat/LangChain/LangGraph-style single tool calls:
      ``{tool_calls: [{function: {name, arguments}}]}`` or
      ``{tool_calls: [{name, args}]}``. LangGraph forwards
      ``AIMessage.tool_calls`` items that additionally carry idiomatic
      ``id`` + ``type: "tool_call"`` fields; those are runtime bookkeeping and
      are ignored here so the call routes to the same ``(name, args)`` result.
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

    responses_function_calls = _responses_function_call_items(payload)
    if len(responses_function_calls) == 1:
        item = responses_function_calls[0]
        return str(item["name"]), _arguments_to_mapping(item.get("arguments"))

    if len(responses_function_calls) > 1:
        return "responses.output.batch", {
            "function_call_count": len(responses_function_calls),
            "function_call_names": [str(item["name"]) for item in responses_function_calls],
        }

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
    response = payload.get("response") if isinstance(payload.get("response"), dict) else {}
    responses_function_calls = _responses_function_call_items(payload)
    single_response_function_call = (
        responses_function_calls[0] if len(responses_function_calls) == 1 else {}
    )
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
        response,
        function,
        tool,
        single_response_function_call,
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
        cast(dict[str, Any], response).get("state"),
        cast(dict[str, Any], response).get("context"),
        cast(dict[str, Any], function).get("state"),
        cast(dict[str, Any], function).get("context"),
        cast(dict[str, Any], tool).get("state"),
        cast(dict[str, Any], tool).get("context"),
        single_response_function_call.get("state"),
        single_response_function_call.get("context"),
        cast(dict[str, Any], single_tool_call).get("state"),
        cast(dict[str, Any], single_tool_call).get("context"),
        cast(dict[str, Any], tool_call_function).get("state"),
        cast(dict[str, Any], tool_call_function).get("context"),
        tool_input.get("state"),
        tool_input.get("context"),
    )
    return goal, state


def _path_from_tool_input(tool_input: dict[str, Any]) -> tuple[str, ...]:
    # ``notebook_path`` is the standard NotebookEdit target key. Missing it
    # would leave the call with an empty path, so a notebook under a protected
    # segment (``.gove-zone``, ``.claude``) would evaluate as an ordinary
    # source edit instead of receiving its governance path tier.
    for key in ("file_path", "path", "notebook_path"):
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
    if payload.get(_MALFORMED_BATCH_PAYLOAD_KEY) is True:
        summary = payload.get("summary")
        if not isinstance(summary, dict):
            summary = {
                "batch_shape": "unknown",
                "reason": "unparseable runtime batch",
                "item_count": 0,
                "parseable_count": 0,
                "unparseable_count": 0,
            }
        goal, state = _runtime_context_from_payload(payload, {})
        return ToolCall(
            name=_MALFORMED_BATCH_TOOL_NAME,
            args={"action_kind": action_kind, "summary": cast(dict[str, Any], summary)},
            goal=goal,
            actor=actor,
            path=(),
            state=state,
        )

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


def tool_calls_from_hook_payload(
    payload: dict[str, Any],
    *,
    action_kind: str,
    actor: str,
) -> tuple[ToolCall, ...]:
    """Normalize a runtime event into one or more governed ``ToolCall`` objects.

    Single-call payloads return one call. Recognized multi-call OpenAI
    Responses/OpenAI Chat/LangChain-style batches return one call per proposed
    tool invocation so policy-bundle evaluation cannot be bypassed by wrapping
    a denied operation in a batch.
    """
    return tuple(
        tool_call_from_hook_payload(child, action_kind=action_kind, actor=actor)
        for child in _individual_tool_payloads_from_payload(payload)
    )


def individual_tool_payloads(payload: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    """Expand one runtime event into its per-call child payloads.

    The public form of the expansion :func:`tool_calls_from_hook_payload`
    performs internally. A caller that needs the *raw* per-call payload — not
    the lossy :class:`ToolCall` projection, which keeps only a summary — uses
    this. :mod:`gove_zone.execution` needs the raw ``command`` string to
    classify a shell invocation structurally, and a batch-wrapped call must
    reach that classifier too, or wrapping an install in a batch would evade it.
    """
    return _individual_tool_payloads_from_payload(payload)


def tool_name_and_input(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Runtime-neutral ``(tool_name, tool_input)`` for one per-call payload.

    Public form of the shape normalization documented on
    :func:`_tool_name_and_input_from_payload`. Exposed so a classifier can read
    a specific argument (e.g. ``command``) without re-implementing support for
    every runtime's payload shape.
    """
    return _tool_name_and_input_from_payload(payload)


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


def _decision_record_for_call(
    call: ToolCall,
    *,
    action_kind: str,
    active_policy: Policy,
) -> DecisionRecord:
    if call.name == _MALFORMED_BATCH_TOOL_NAME:
        record = DecisionRecord(
            decision=Decision.DENY,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=_MALFORMED_BATCH_POLICY_VERSION,
            event_id=new_event_id(),
            matched_rules=("malformed_batch",),
            reason="runtime batch contains unparseable tool calls",
        )
    else:
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
    return dataclasses.replace(
        record,
        goal=call.goal,
        actor=call.actor,
        path=call.path,
        state_hash=call.state_hash(),
        decision_request_hash=call.decision_request_hash(),
    )


def emit_receipts_for_hook(
    payload: dict[str, Any],
    *,
    action_kind: str,
    actor: str,
    run_id: str | None = None,
    policy: Policy | None = None,
) -> tuple[Receipt, ...] | None:
    """Emit governance receipts for every proposed call in a runtime event.

    This is the batch-aware variant used by CLI gate enforcement. It preserves
    the same observe/enforce failure semantics as ``emit_receipt_for_hook``.

    **Profile consultation (orthogonal to GateMode).** This passive auditor emits
    a :class:`~gove_zone.receipt.Receipt` (the audit anchor), which carries no
    cryptographic ``signature`` field — there is no signed-receipt path to engage
    here, and no signer parameter is threaded in (see the module docstring and
    SECURITY.md "Runtime-hook auditing is unsigned"). To keep the production
    profile honest without silently emitting an unsigned receipt where signing was
    expected, we fail closed LOUD only at the intersection of *enforcement* and
    *production*: ``GateMode.ENFORCE`` **and** the production profile (the default)
    with no signer configured. The passive ``GateMode.OBSERVE`` audit path is left
    intact and may legitimately stay unsigned even under the production profile —
    signing stays orthogonal to GateMode. Select ``GOVE_ZONE_PROFILE=dev`` to opt
    out of this loud check under enforcement.
    """
    from gove_zone.profile import GovernanceProfile

    mode = current_gate_mode()
    profile = GovernanceProfile.from_env()
    if mode is GateMode.ENFORCE and profile.is_production and profile.signer is None:
        raise GateModeError(
            "production profile under enforce mode requires a configured signer for "
            "runtime-hook receipts, but this auditor emits unsigned audit-anchor "
            "Receipts (no signer is threaded into emit_receipt_for_hook). Either run the "
            "passive auditor in observe mode (GOVE_ZONE_GATE_MODE=observe), or explicitly "
            "select the dev profile (GOVE_ZONE_PROFILE=dev) to acknowledge unsigned "
            "runtime-hook auditing under enforcement."
        )
    active_policy = policy if policy is not None else _ObserverPolicy(action_kind)
    try:
        calls = tool_calls_from_hook_payload(payload, action_kind=action_kind, actor=actor)
        audit_path = resolve_audit_path()
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        store = ChainHashAuditStore(str(audit_path))
        receipts: list[Receipt] = []
        for call in calls:
            record = _decision_record_for_call(
                call,
                action_kind=action_kind,
                active_policy=active_policy,
            )
            event = store.append(record)
            receipts.append(
                Receipt(
                    record=record,
                    audit_hash=str(event.get("event_hash", "")),
                    actor=call.actor,
                    result_hash=None,
                    error_class=None,
                )
            )
        return tuple(receipts)
    except Exception as exc:  # noqa: BLE001 — adapter boundary
        if mode is GateMode.ENFORCE:
            raise GateModeError(
                f"receipt emission failed under enforce mode: {exc!r} "
                f"(action_kind={action_kind}, actor={actor}, run_id={run_id})"
            ) from exc
        return None


def emit_receipt_for_hook(
    payload: dict[str, Any],
    *,
    action_kind: str,
    actor: str,
    run_id: str | None = None,
    policy: Policy | None = None,
) -> Receipt | None:
    """Emit the primary governance receipt for a runtime-hook event.

    Uses the supplied :class:`~gove_zone.policy.Policy` to produce the
    :class:`Decision`. Default is an observer that always emits
    :attr:`Decision.ALLOW` (the host runtime's own permission system owns
    deny). Pass a custom policy to surface DENY/TRANSFORM/ESCALATE
    decisions in the audit chain.

    Returns the blocking receipt for batch events when any child is denied or
    escalated; otherwise returns the final emitted receipt for compatibility.

    In :attr:`GateMode.OBSERVE` (opt-in), returns ``None`` on any internal
    failure — preserving existing fail-open behavior.

    In :attr:`GateMode.ENFORCE` (the default; :func:`current_gate_mode` falls
    through to ENFORCE / fail-closed unless OBSERVE is explicitly opted into),
    raises :class:`GateModeError` on any failure that would have been swallowed.
    Callers must propagate the failure (exit non-zero in a hook context).
    """
    receipts = emit_receipts_for_hook(
        payload,
        action_kind=action_kind,
        actor=actor,
        run_id=run_id,
        policy=policy,
    )
    if not receipts:
        return None
    for receipt in receipts:
        if receipt.record.decision in {Decision.DENY, Decision.ESCALATE}:
            return receipt
    return receipts[-1]


def make_langgraph_tool_node(
    tool_fn: Callable[..., Any],
    *,
    action_kind: str,
    actor: str,
    policy: Policy | None = None,
    state_key: str = "tool_call",
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Return a LangGraph-style node fn that governs *tool_fn* before running it.

    LangGraph models a workflow as a graph of nodes, each ``fn(state) -> state``.
    A common governance integration point is a **pre-execution intercept** on a
    tool node: gate the proposed tool call *before* the node performs its side
    effect. This helper is the first-class, dependency-free form of that pattern
    (the ``agent-framework-wrapper`` example demonstrates it; this is the
    importable API) — no ``langgraph``/``langchain`` import is required, only the
    payload SHAPE is modelled.

    The returned node reads the proposed call from ``state[state_key]`` — a
    LangGraph ``AIMessage.tool_calls`` item
    ``{"name", "args", "id", "type": "tool_call"}`` — routes it through the SAME
    passive adapter plumbing every other runtime family uses
    (:func:`emit_receipt_for_hook`, which normalizes via
    :func:`tool_call_from_hook_payload`), and only runs *tool_fn* on ALLOW.

    Fail-closed by construction: a DENY/ESCALATE decision, a missing or
    unparseable tool call, or a swallowed emission failure (``None`` receipt in
    observe mode) all route to ``decision == "blocked"`` and *tool_fn* is never
    called — so no side effect runs without a recorded ALLOW receipt. The gate
    mode / signing posture is inherited from :func:`emit_receipt_for_hook`
    (fail-closed ENFORCE by default); this wrapper never weakens it.

    The outcome is written back under ``state["governed"]`` as
    ``{"decision": "allowed"|"blocked", "receipt": Receipt|None, ...}``; the
    original state is not mutated.
    """

    def tool_node(state: dict[str, Any]) -> dict[str, Any]:
        new_state = dict(state)
        call = state.get(state_key)
        if not isinstance(call, dict) or not call.get("name"):
            new_state["governed"] = {
                "decision": "blocked",
                "reason": f"no parseable LangGraph tool call at state[{state_key!r}]",
                "receipt": None,
            }
            return new_state

        payload: dict[str, Any] = {
            "tool_calls": [call],
            "goal": state.get("goal", ""),
            "state": state.get("state", {}),
        }
        receipt = emit_receipt_for_hook(
            payload,
            action_kind=action_kind,
            actor=actor,
            policy=policy,
        )
        if receipt is None or receipt.record.decision is not Decision.ALLOW:
            new_state["governed"] = {
                "decision": "blocked",
                "reason": (
                    receipt.record.reason if receipt is not None else "receipt emission failed"
                ),
                "receipt": receipt,
            }
            return new_state

        args = call.get("args") if isinstance(call.get("args"), dict) else {}
        result = tool_fn(**cast(dict[str, Any], args))
        new_state["governed"] = {
            "decision": "allowed",
            "result": result,
            "receipt": receipt,
        }
        return new_state

    return tool_node
