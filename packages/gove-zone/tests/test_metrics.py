"""Receipt-emission metrics boundary-wrapper tests.

Proves the opt-in, default-OFF :func:`gove_zone.metrics.metered_dispatch`:

- flag OFF => no file written, ALLOW dispatch behaves identically.
- ALLOW path: a raising metric emitter still lets the action execute and the
  result return — a metrics failure never blocks a decision.
- DENY path: a raising metric emitter still lets ``DeniedError`` propagate, and
  a DENY event was attempted.
- ESCALATE path: symmetric to DENY.
- leak-safety: the emitted JSONL contains no raw argument values.

These hit ``metered_dispatch`` (the wrapper), which dispatches through
``kernel.dispatch`` (the real dispatcher path) — never the tool function
directly — so the wiring is exercised end to end.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from gove_zone import (
    AllowAllPolicy,
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    DeniedError,
    DenyAllPolicy,
    EscalateError,
    Kernel,
    Policy,
    metrics,
    new_event_id,
    sha256_json,
)
from gove_zone.tool import ToolCall


class _EscalatePolicy(Policy):
    """Test policy: escalate every call (needs a human)."""

    @property
    def version(self) -> str:
        return "test-escalate/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.ESCALATE,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("ESCALATE:needs-human",),
            reason="needs human approval",
        )


def _kernel(tmp_path: Path, policy_obj: Any) -> Kernel:
    return Kernel(
        policy=policy_obj,
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
    )


# --- flag OFF: transparent pass-through ------------------------------------


def test_flag_off_writes_nothing_and_behaves_identically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(metrics.METRICS_ENV, raising=False)
    sink = tmp_path / "metrics.jsonl"
    monkeypatch.setenv(metrics.METRICS_PATH_ENV, str(sink))

    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("echo")
    def echo(msg: str) -> str:
        return msg.upper()

    result, receipt = metrics.metered_dispatch(k, "echo", {"msg": "hi"})

    assert result == "HI"
    assert receipt.record.decision is Decision.ALLOW
    assert not sink.exists()  # nothing written while OFF


def test_flag_off_does_not_record_even_if_emitter_would_raise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(metrics.METRICS_ENV, raising=False)

    def _boom(_event: dict[str, Any]) -> None:
        raise RuntimeError("emitter should never be called while OFF")

    monkeypatch.setattr(metrics, "_record", _boom)

    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("noop")
    def noop() -> int:
        return 7

    result, _ = metrics.metered_dispatch(k, "noop")
    assert result == 7  # emitter never invoked => no raise


# --- ALLOW: emitter failure must not block the action ----------------------


def test_allow_path_emitter_raise_does_not_block_or_leak_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(metrics.METRICS_ENV, "1")

    recorded: list[dict[str, Any]] = []

    def _spy_then_raise(event: dict[str, Any]) -> None:
        recorded.append(event)
        raise OSError("disk full")

    monkeypatch.setattr(metrics, "_record", _spy_then_raise)

    k = _kernel(tmp_path, AllowAllPolicy())
    executed: list[str] = []

    @k.tool("act")
    def act(msg: str) -> str:
        executed.append("ran")
        return msg.upper()

    # No exception leaks despite the emitter raising.
    result, receipt = metrics.metered_dispatch(k, "act", {"msg": "hi"})

    assert executed == ["ran"]  # action still executed
    assert result == "HI"  # result returned unchanged
    assert receipt.record.decision is Decision.ALLOW
    assert recorded and recorded[0]["decision"] == "allow"  # event attempted


# --- DENY: emitter failure must not swallow the governance exception -------


def test_deny_path_emitter_raise_still_propagates_and_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(metrics.METRICS_ENV, "1")

    recorded: list[dict[str, Any]] = []

    def _spy_then_raise(event: dict[str, Any]) -> None:
        recorded.append(event)
        raise OSError("disk full")

    monkeypatch.setattr(metrics, "_record", _spy_then_raise)

    k = _kernel(tmp_path, DenyAllPolicy(reason="blocked"))
    executed: list[str] = []

    @k.tool("side_effect")
    def side_effect() -> None:
        executed.append("ran")

    with pytest.raises(DeniedError):
        metrics.metered_dispatch(k, "side_effect")

    assert executed == []  # action blocked
    assert recorded and recorded[0]["decision"] == "deny"  # DENY event attempted


# --- ESCALATE: symmetric to DENY -------------------------------------------


def test_escalate_path_emitter_raise_still_propagates_and_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(metrics.METRICS_ENV, "1")

    recorded: list[dict[str, Any]] = []

    def _spy_then_raise(event: dict[str, Any]) -> None:
        recorded.append(event)
        raise OSError("disk full")

    monkeypatch.setattr(metrics, "_record", _spy_then_raise)

    k = _kernel(tmp_path, _EscalatePolicy())
    executed: list[str] = []

    @k.tool("side_effect")
    def side_effect() -> None:
        executed.append("ran")

    with pytest.raises(EscalateError):
        metrics.metered_dispatch(k, "side_effect")

    assert executed == []  # action blocked pending approval
    assert recorded and recorded[0]["decision"] == "escalate"  # ESCALATE event attempted


# --- leak-safety: no raw argument values in the JSONL ----------------------


def test_emitted_jsonl_contains_no_raw_argument_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(metrics.METRICS_ENV, "1")
    sink = tmp_path / "metrics.jsonl"
    monkeypatch.setenv(metrics.METRICS_PATH_ENV, str(sink))

    secret = "hunter2-super-secret-token"

    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("login")
    def login(password: str) -> str:
        return "ok"

    # goal can echo argument content too — assert it never leaks either.
    metrics.metered_dispatch(
        k, "login", {"password": secret}, goal=f"log in with {secret}"
    )

    assert sink.exists()
    raw = sink.read_text(encoding="utf-8")
    assert secret not in raw  # the sensitive value never appears anywhere

    event = json.loads(raw.splitlines()[0])
    assert event["decision"] == "allow"
    assert set(event) == {"ts", "decision", "tool", "argument_hash", "event_id"}
    # The argument reference is a hash, not the raw value.
    assert event["tool"] == "login"
    assert isinstance(event["argument_hash"], str) and len(event["argument_hash"]) == 64
