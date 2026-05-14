"""Fail-closed invariant tests.

Proves the second MVP acceptance criterion: *if policy checking, receipt
generation, storage, or validation fails, the action is blocked.*

Cases covered:

1. Policy.evaluate raises an exception → kernel synthesizes a DENY record
   carrying the exception class, appends it, and raises ``DeniedError``.
2. Audit.append raises → kernel raises ``AuditError``; the tool never runs.
3. Tool execution raises after ALLOW → kernel propagates the exception AND
   appends a failure record to the chain (best-effort, non-blocking).
4. TRANSFORM decision without ``transformed_args`` → kernel treats as DENY.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from gove_zone import (
    AllowAllPolicy,
    AuditError,
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    DeniedError,
    Kernel,
    Policy,
    sha256_json,
)
from gove_zone.tool import ToolCall


class _RaisingPolicy(Policy):
    @property
    def version(self) -> str:
        return "raising/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        raise RuntimeError("policy is broken")


class _BrokenAudit:
    """Audit-store stand-in that always raises on append."""

    def append(self, _decision: Any) -> dict[str, Any]:
        raise OSError("disk full")


class _TransformPolicy(Policy):
    """Always emits TRANSFORM but forgets transformed_args."""

    @property
    def version(self) -> str:
        return "transform-bug/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.TRANSFORM,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id="ev_bug",
            transformed_args=None,
        )


def test_policy_raised_synthesizes_deny_and_records(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    k = Kernel(policy=_RaisingPolicy(), audit=audit)
    executed: list[str] = []

    @k.tool("never_runs")
    def never_runs() -> None:
        executed.append("ran")

    with pytest.raises(DeniedError) as exc_info:
        k.dispatch("never_runs")

    assert executed == []
    assert exc_info.value.record.decision is Decision.DENY
    # The synthetic record names the underlying exception class
    assert any(
        "POLICY_ERROR:RuntimeError" in r
        for r in exc_info.value.record.matched_rules
    )
    # The audit chain holds the DENY record
    events = list(audit.iter_events())
    assert len(events) == 1
    assert events[0]["decision"] == "deny"


def test_audit_append_failure_raises_audit_error(tmp_path: Path) -> None:
    k = Kernel(policy=AllowAllPolicy(), audit=_BrokenAudit())  # type: ignore[arg-type]
    executed: list[str] = []

    @k.tool("noop")
    def noop() -> None:
        executed.append("ran")

    with pytest.raises(AuditError, match="disk full"):
        k.dispatch("noop")

    assert executed == []  # never executed — fail closed


def test_execution_failure_propagates_and_records_failure(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    k = Kernel(policy=AllowAllPolicy(), audit=audit)

    @k.tool("explode")
    def explode() -> None:
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        k.dispatch("explode")

    # The decision was ALLOW, then execution failed. Chain must hold:
    #   event 1: ALLOW decision
    #   event 2: synthetic DENY failure record
    events = list(audit.iter_events())
    assert len(events) == 2
    assert events[0]["decision"] == "allow"
    assert events[1]["decision"] == "deny"
    assert any(
        "EXEC_FAILURE:ValueError" in r for r in events[1]["matched_rules"]
    )
    assert audit.verify_chain()["valid"] is True


def test_transform_without_args_is_treated_as_deny(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    k = Kernel(policy=_TransformPolicy(), audit=audit)
    executed: list[str] = []

    @k.tool("t")
    def t(**_: Any) -> None:
        executed.append("ran")

    with pytest.raises(DeniedError) as exc_info:
        k.dispatch("t", {"foo": 1})

    assert executed == []
    assert exc_info.value.record.decision is Decision.DENY
    assert any(
        "POLICY_ERROR:MALFORMED_TRANSFORM" in rule
        for rule in exc_info.value.record.matched_rules
    )
    events = list(audit.iter_events())
    assert len(events) == 1
    assert events[0]["decision"] == "deny"
    assert any(
        "POLICY_ERROR:MALFORMED_TRANSFORM" in rule
        for rule in events[0]["matched_rules"]
    )


def test_audit_chain_holds_under_mixed_outcomes(tmp_path: Path) -> None:
    """One ALLOW, one DENY, one POLICY_ERROR-DENY — chain must verify."""
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")

    @dataclasses.dataclass
    class FlipFlop(Policy):
        i: int = 0

        @property
        def version(self) -> str:
            return "flipflop/v0"

        def evaluate(self, call: ToolCall) -> DecisionRecord:
            self.i += 1
            if self.i == 1:
                return AllowAllPolicy().evaluate(call)
            if self.i == 2:
                from gove_zone import DenyAllPolicy

                return DenyAllPolicy().evaluate(call)
            raise RuntimeError("third call broke")

    k = Kernel(policy=FlipFlop(), audit=audit)

    @k.tool("x")
    def x() -> int:
        return 0

    k.dispatch("x")  # allow
    with pytest.raises(DeniedError):
        k.dispatch("x")  # deny
    with pytest.raises(DeniedError):
        k.dispatch("x")  # policy raised → synthesized deny

    result = audit.verify_chain()
    assert result["valid"] is True
    assert result["checked"] == 3
