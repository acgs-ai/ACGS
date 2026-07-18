"""Kernel dispatch path tests.

Proves the central loop:

- ALLOW path returns ``(result, receipt)`` with an audit-chained receipt.
- DENY path raises :class:`DeniedError` carrying the record + audit hash.
- ESCALATE path raises :class:`EscalateError`.
- Unknown-tool dispatch raises :class:`UnknownToolError`.
- Every dispatch — ALLOW or non-ALLOW — appends exactly one event to the
  audit chain, anchoring the decision.

These tests hit ``kernel.dispatch`` (the dispatcher path), not the tool
function directly — that's the wiring proof per the review-handler-wiring rule.
"""

from __future__ import annotations

from pathlib import Path

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
    UnknownToolError,
    sha256_json,
)
from gove_zone.tool import ToolCall


def _kernel(tmp_path: Path, policy_obj) -> Kernel:
    return Kernel(
        policy=policy_obj,
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
    )


def test_allow_dispatch_executes_tool_and_returns_receipt(tmp_path: Path) -> None:
    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("echo")
    def echo(msg: str) -> str:
        return msg.upper()

    result, receipt = k.dispatch("echo", {"msg": "hi"})

    assert result == "HI"
    assert receipt.record.decision is Decision.ALLOW
    assert receipt.audit_hash and receipt.audit_hash != "0" * 64
    assert receipt.result_hash is not None
    assert receipt.actor == "anonymous"


def test_deny_dispatch_raises_and_does_not_execute(tmp_path: Path) -> None:
    k = _kernel(tmp_path, DenyAllPolicy(reason="test deny"))
    executed: list[str] = []

    @k.tool("side_effect")
    def side_effect() -> None:
        executed.append("ran")

    with pytest.raises(DeniedError) as exc_info:
        k.dispatch("side_effect")

    assert executed == []  # side effect was blocked
    assert exc_info.value.record.decision is Decision.DENY
    assert exc_info.value.audit_hash != "0" * 64
    assert "test deny" in str(exc_info.value)


def test_unknown_tool_raises_before_any_audit_append(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    k = Kernel(policy=AllowAllPolicy(), audit=ChainHashAuditStore(audit_path))

    with pytest.raises(UnknownToolError):
        k.dispatch("not_registered", {})

    # No events should have been appended.
    assert not audit_path.exists() or audit_path.read_text() == ""


def test_every_dispatch_anchors_in_audit_chain(tmp_path: Path) -> None:
    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("noop")
    def noop() -> int:
        return 1

    for _ in range(5):
        k.dispatch("noop")

    result = k.audit.verify_chain()
    assert result["valid"] is True
    assert result["checked"] == 5


def test_dispatch_returns_receipt_linked_to_audit_event(tmp_path: Path) -> None:
    """The receipt's audit_hash must equal the event_hash recorded in audit."""
    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("ping")
    def ping() -> str:
        return "pong"

    _, receipt = k.dispatch("ping")
    events = list(k.audit.iter_events())
    assert len(events) == 1
    assert events[0]["event_hash"] == receipt.audit_hash
    assert events[0]["event_id"] == receipt.record.event_id


class _EscalateAllPolicy(Policy):
    @property
    def version(self) -> str:
        return "escalate-all/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.ESCALATE,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id="ev_escalate",
            reason="requires human approval",
        )


class _RedactPolicy(Policy):
    """TRANSFORM: replaces the ``secret`` argument before execution."""

    @property
    def version(self) -> str:
        return "redact/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        redacted = {**dict(call.args), "secret": "[REDACTED]"}
        return DecisionRecord(
            decision=Decision.TRANSFORM,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id="ev_transform",
            reason="secret redacted",
            transformed_args=redacted,
        )


def test_escalate_dispatch_raises_and_does_not_execute(tmp_path: Path) -> None:
    k = _kernel(tmp_path, _EscalateAllPolicy())
    executed: list[str] = []

    @k.tool("wire_transfer")
    def wire_transfer() -> None:
        executed.append("ran")

    with pytest.raises(EscalateError) as exc_info:
        k.dispatch("wire_transfer")

    assert executed == []  # blocked pending approval
    assert exc_info.value.record.decision is Decision.ESCALATE
    events = list(k.audit.iter_events())
    assert len(events) == 1  # the escalation is audit-anchored
    assert events[0]["decision"] == "escalate"


def test_transform_dispatch_executes_with_transformed_args(tmp_path: Path) -> None:
    """Positive TRANSFORM path: the tool runs with the policy-supplied args."""
    k = _kernel(tmp_path, _RedactPolicy())
    received: list[dict[str, str]] = []

    @k.tool("send")
    def send(message: str, secret: str) -> str:
        received.append({"message": message, "secret": secret})
        return secret

    result, receipt = k.dispatch("send", {"message": "hi", "secret": "hunter2"})

    assert received == [{"message": "hi", "secret": "[REDACTED]"}]  # not the original
    assert result == "[REDACTED]"
    assert receipt.record.decision is Decision.TRANSFORM
    assert receipt.record.transformed_args == {"message": "hi", "secret": "[REDACTED]"}


def test_tool_registry_rejects_duplicate_names(tmp_path: Path) -> None:
    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("dup")
    def first() -> None:
        return None

    with pytest.raises(ValueError, match="already registered"):

        @k.tool("dup")
        def second() -> None:
            return None
