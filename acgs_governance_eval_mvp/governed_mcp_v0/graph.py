from __future__ import annotations

from dataclasses import dataclass, field
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


__all__ = [
    "DeltaChannel",
    "GovernedGraphState",
    "apply_admission_decision",
    "interrupt_for_approval",
    "list_reducer",
]
