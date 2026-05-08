from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Callable

try:  # pragma: no cover - exercised only when optional deps are installed.
    from pydantic import BaseModel, Field
except Exception:  # pragma: no cover - local tests do not require pydantic.
    BaseModel = object  # type: ignore[assignment]
    Field = None  # type: ignore[assignment]


def list_reducer(left: list[Any], right: list[Any]) -> list[Any]:
    """Append-only reducer for DeltaChannel message/tool-result history."""

    return left + right


try:  # pragma: no cover - optional LangGraph 1.2 alpha surface.
    from langgraph.channels import DeltaChannel as _LangGraphDeltaChannel
except Exception:  # pragma: no cover - compatibility fallback for tests.

    @dataclass(frozen=True)
    class _LangGraphDeltaChannel:
        """Small marker compatible with Annotated state declarations."""

        reducer: Callable[[list[Any], list[Any]], list[Any]]
        snapshot_frequency: int = 5


DeltaChannel = _LangGraphDeltaChannel


def _messages_channel() -> Any:
    try:
        return DeltaChannel(list_reducer, snapshot_frequency=5)
    except TypeError:
        # Defensive compatibility with prerelease LangGraph API movement.
        return DeltaChannel(list_reducer)


MESSAGES_CHANNEL = _messages_channel()


if BaseModel is not object:

    class GovernedGraphState(BaseModel):
        """LangGraph-style state schema for governed tool admission.

        LangGraph 1.2.0a7 adds DeltaChannel for append-heavy state. The
        messages field follows the recommended pattern:
        Annotated[list, DeltaChannel(list_reducer, snapshot_frequency=5)].
        Local tests use the fallback marker when langgraph is absent.
        """

        messages: Annotated[list[dict[str, Any]], MESSAGES_CHANNEL] = Field(default_factory=list)
        tool_name: str | None = None
        action_id: str | None = None
        tool_args: dict[str, Any] = Field(default_factory=dict)
        approved: bool = False
        decision_reason: str | None = None

else:

    @dataclass
    class GovernedGraphState:
        messages: Annotated[list[dict[str, Any]], MESSAGES_CHANNEL] = field(default_factory=list)
        tool_name: str | None = None
        action_id: str | None = None
        tool_args: dict[str, Any] = field(default_factory=dict)
        approved: bool = False
        decision_reason: str | None = None


def interrupt_for_approval(state: GovernedGraphState) -> dict[str, Any]:
    """Local equivalent of LangGraph interrupt() for deterministic tests.

    In a real graph this is where `interrupt({"action_id": ..., "args": ...})`
    would pause for human approval before calling the governed MCP tool. The
    v0 proof artifact keeps approval deterministic: the governance admission
    decision is the only approval source used by tests.
    """

    return {
        "action_id": getattr(state, "action_id", None),
        "tool_name": getattr(state, "tool_name", None),
        "tool_args": getattr(state, "tool_args", {}),
        "approval_required": True,
    }


def apply_admission_decision(
    state: GovernedGraphState,
    *,
    allowed: bool,
    reason: str,
) -> GovernedGraphState:
    """Return state updated with a deterministic admission result."""

    updates = {"approved": allowed, "decision_reason": reason}
    if hasattr(state, "model_copy"):
        return state.model_copy(update=updates)  # type: ignore[no-any-return]
    for key, value in updates.items():
        setattr(state, key, value)
    return state


def _copy_state(state: GovernedGraphState, updates: dict[str, Any]) -> GovernedGraphState:
    if hasattr(state, "model_copy"):
        return state.model_copy(update=updates)  # type: ignore[no-any-return]
    values = {
        "messages": list(getattr(state, "messages", [])),
        "tool_name": getattr(state, "tool_name", None),
        "action_id": getattr(state, "action_id", None),
        "tool_args": getattr(state, "tool_args", {}),
        "approved": getattr(state, "approved", False),
        "decision_reason": getattr(state, "decision_reason", None),
    }
    values.update(updates)
    return GovernedGraphState(**values)


def _latest_receipt(server: Any) -> dict[str, Any] | None:
    targets = getattr(server, "targets", None)
    receipts_dir = getattr(targets, "receipts_dir", None)
    if receipts_dir is None:
        return None
    receipts = sorted(Path(receipts_dir).glob("*.json"))
    if not receipts:
        return None
    try:
        with receipts[-1].open("r", encoding="utf-8") as handle:
            receipt = json.load(handle)
    except Exception:
        return {"receipt_path": str(receipts[-1])}
    if isinstance(receipt, dict):
        receipt["receipt_path"] = str(receipts[-1])
        return receipt
    return {"receipt_path": str(receipts[-1])}


def _message(
    *,
    tool_name: str | None,
    action_id: str | None,
    status: str,
    reason: str,
    result: Any = None,
    receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "role": "tool",
        "tool_name": tool_name,
        "action_id": action_id,
        "status": status,
        "reason": reason,
    }
    if result is not None:
        entry["result"] = str(result) if isinstance(result, Path) else result
    if receipt is not None:
        entry["receipt_path"] = receipt.get("receipt_path")
        entry["event_hash"] = receipt.get("event_hash")
        entry["decision"] = receipt.get("decision")
    return entry


def _append_result(
    state: GovernedGraphState,
    *,
    allowed: bool,
    reason: str,
    message: dict[str, Any],
) -> GovernedGraphState:
    messages = list(getattr(state, "messages", []))
    messages.append(message)
    return _copy_state(
        state,
        {
            "messages": messages,
            "approved": allowed,
            "decision_reason": reason,
        },
    )


def _fail_closed(
    state: GovernedGraphState,
    server: Any,
    *,
    reason: str,
    record: bool = True,
) -> GovernedGraphState:
    tool_name = getattr(state, "tool_name", None)
    action_id = getattr(state, "action_id", None)
    args = getattr(state, "tool_args", {})
    if record and hasattr(server, "admit"):
        try:
            if hasattr(server, "_record_decision"):
                server._record_decision(  # noqa: SLF001 - graph adapter records fail-closed evidence for malformed calls.
                    action_id or "unknown.action",
                    tool_name or "unknown",
                    args if isinstance(args, dict) else {},
                    "deny",
                    reason,
                    ["fail-closed"],
                )
            else:
                server.admit(action_id or "unknown.action", tool_name or "unknown", args if isinstance(args, dict) else args)
        except Exception as exc:
            reason = str(exc) or reason
    receipt = _latest_receipt(server)
    return _append_result(
        state,
        allowed=False,
        reason=reason,
        message=_message(
            tool_name=tool_name,
            action_id=action_id,
            status="deny",
            reason=reason,
            receipt=receipt,
        ),
    )


def _require_args(args: dict[str, Any], required: list[str]) -> str | None:
    for key in required:
        if key not in args:
            return f"missing required field: {key}"
    return None


def execute_governed_tool_call(state: GovernedGraphState, server: Any) -> GovernedGraphState:
    """Execute one deterministic governed tool call and return updated state.

    The loop is intentionally a thin graph-side adapter. Guarded side effects
    remain enforced by GovernedMCPServer.admit(), which records replay evidence
    before a side effect can run.
    """

    tool_name = getattr(state, "tool_name", None)
    action_id = getattr(state, "action_id", None)
    args = getattr(state, "tool_args", {})
    if not isinstance(tool_name, str) or not tool_name:
        return _fail_closed(state, server, reason="missing tool_name")
    if not isinstance(action_id, str) or not action_id:
        return _fail_closed(state, server, reason="missing action_id")
    if not isinstance(args, dict):
        return _fail_closed(state, server, reason="malformed tool_args")

    try:
        if tool_name == "read_file":
            missing = _require_args(args, ["path"])
            if missing:
                return _fail_closed(state, server, reason=missing)
            result = server.read_file(args["path"])
            reason = "safe read tool executed"
            return _append_result(
                state,
                allowed=True,
                reason=reason,
                message=_message(tool_name=tool_name, action_id=action_id, status="allow", reason=reason, result=result),
            )

        if tool_name == "list_files":
            result = server.list_files()
            reason = "safe list tool executed"
            return _append_result(
                state,
                allowed=True,
                reason=reason,
                message=_message(tool_name=tool_name, action_id=action_id, status="allow", reason=reason, result=result),
            )

        if tool_name == "query_sql_select":
            missing = _require_args(args, ["sql"])
            if missing:
                return _fail_closed(state, server, reason=missing)
            result = server.query_sql_select(args["sql"])
            reason = "safe sql select tool executed"
            return _append_result(
                state,
                allowed=True,
                reason=reason,
                message=_message(tool_name=tool_name, action_id=action_id, status="allow", reason=reason, result=result),
            )

        if tool_name == "github_read_issue":
            missing = _require_args(args, ["repo", "issue_number"])
            if missing:
                return _fail_closed(state, server, reason=missing)
            result = server.github_read_issue(args["repo"], args["issue_number"])
            reason = "safe github read tool executed"
            return _append_result(
                state,
                allowed=True,
                reason=reason,
                message=_message(tool_name=tool_name, action_id=action_id, status="allow", reason=reason, result=result),
            )

        interrupt_for_approval(state)
        if tool_name == "write_file":
            missing = _require_args(args, ["path", "content"])
            if missing:
                return _fail_closed(state, server, reason=missing)
            result = server.write_file(args["path"], args["content"])
        elif tool_name == "execute_sql":
            missing = _require_args(args, ["sql"])
            if missing:
                return _fail_closed(state, server, reason=missing)
            result = server.execute_sql(args["sql"])
        elif tool_name == "send_email":
            missing = _require_args(args, ["to", "subject", "body"])
            if missing:
                return _fail_closed(state, server, reason=missing)
            result = server.send_email(args["to"], args["subject"], args["body"])
        elif tool_name == "deploy_service":
            missing = _require_args(args, ["service", "environment"])
            if missing:
                return _fail_closed(state, server, reason=missing)
            result = server.deploy_service(args["service"], args["environment"])
        elif tool_name == "mutate_github":
            missing = _require_args(args, ["repo", "mutation", "payload"])
            if missing:
                return _fail_closed(state, server, reason=missing)
            result = server.mutate_github(args["repo"], args["mutation"], args["payload"])
        elif tool_name == "run_shell":
            missing = _require_args(args, ["command"])
            if missing:
                return _fail_closed(state, server, reason=missing)
            result = server.run_shell(args["command"])
        else:
            return _fail_closed(state, server, reason=f"unknown tool: {tool_name}")
    except Exception as exc:
        reason = str(exc) or f"fail closed: {exc.__class__.__name__}"
        return _append_result(
            state,
            allowed=False,
            reason=reason,
            message=_message(
                tool_name=tool_name,
                action_id=action_id,
                status="deny",
                reason=reason,
                receipt=_latest_receipt(server),
            ),
        )

    receipt = _latest_receipt(server)
    reason = str(receipt.get("reason") if receipt else "governed tool executed")
    return _append_result(
        state,
        allowed=True,
        reason=reason,
        message=_message(
            tool_name=tool_name,
            action_id=action_id,
            status="allow",
            reason=reason,
            result=result,
            receipt=receipt,
        ),
    )


__all__ = [
    "DeltaChannel",
    "GovernedGraphState",
    "apply_admission_decision",
    "execute_governed_tool_call",
    "interrupt_for_approval",
    "list_reducer",
]
