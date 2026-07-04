"""Tests for the public ``Kernel.evaluate_and_record`` primitive (Option B).

``evaluate_and_record`` is a thin public alias for the private
``_evaluate_and_record`` that ``dispatch`` already calls. These tests pin the
four contract obligations the design (§3.6 Option B) requires of the sealed-file
change, plus the AGENTS.md negative-path obligation that no side effect runs:

1. **Parity** — for the same call, the returned record's decision content equals
   the record ``dispatch`` reaches (allow / deny / escalate / transform, and the
   synthesized fail-closed DENY when a policy raises).
2. **Exactly one audit append** per call.
3. **No tool executed** — the primitive never touches a registry or a tool_fn.
4. **AuditError** surfaces (fail-closed) when the append fails, and nothing runs.
"""

from __future__ import annotations

import dataclasses
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
)
from gove_zone.audit import AuditError
from gove_zone.decision import sha256_json
from gove_zone.errors import AuditError as ErrorsAuditError
from gove_zone.policy import new_event_id
from gove_zone.tenant import TransformPolicy
from gove_zone.tool import ToolCall


class _EscalatePolicy(Policy):
    """Escalates every call (test stub)."""

    @property
    def version(self) -> str:
        return "escalate/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        return DecisionRecord(
            decision=Decision.ESCALATE,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=("ESCALATE_ALL",),
            reason="needs human approval",
        )


class _RaisingPolicy(Policy):
    """Policy that raises — exercises the kernel's fail-closed DENY synthesis."""

    @property
    def version(self) -> str:
        return "raiser/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        raise RuntimeError("boom in policy")


class _FailingAuditStore(ChainHashAuditStore):
    """Audit store whose append always fails (drives the AuditError path)."""

    def append(self, decision: DecisionRecord) -> dict[str, Any]:
        raise OSError("disk full")


_ACTOR = "agent:a"


def _kernel(tmp_path: Path, policy_obj: Policy, name: str = "audit") -> Kernel:
    return Kernel(
        policy=policy_obj,
        audit=ChainHashAuditStore(tmp_path / f"{name}.jsonl"),
        actor=_ACTOR,
    )


def _stable(record: DecisionRecord) -> DecisionRecord:
    """Drop the two inherently non-deterministic fields (random ``event_id``,
    wall-clock ``timestamp_iso``) so parity compares decision *content*."""
    return dataclasses.replace(record, event_id="", timestamp_iso="")


def _call(name: str = "write_file") -> ToolCall:
    return ToolCall(name=name, args={"path": "/tmp/x", "content": "hi"}, actor="agent:a")


def _dispatch_record(kernel: Kernel, call: ToolCall) -> DecisionRecord:
    """The record ``dispatch`` reaches for *call*, however it surfaces it."""
    try:
        _result, receipt = kernel.dispatch(
            call.name, dict(call.args), goal=call.goal, path=call.path
        )
        return receipt.record
    except DeniedError as exc:
        return exc.record
    except EscalateError as exc:
        return exc.record


@pytest.mark.parametrize(
    "policy_factory",
    [
        AllowAllPolicy,
        lambda: DenyAllPolicy(reason="nope"),
        _EscalatePolicy,
        TransformPolicy,
        _RaisingPolicy,
    ],
)
def test_parity_with_dispatch(tmp_path: Path, policy_factory: Any) -> None:
    """The record ``evaluate_and_record`` returns matches the one ``dispatch``
    reaches for the same call (content-equal, ignoring random id/timestamp)."""
    call = _call()

    # dispatch needs the tool registered (ALLOW/TRANSFORM execute); register an
    # inert echo so it can run without a real side effect.
    kd = _kernel(tmp_path, policy_factory(), name="dispatch")
    kd.registry.register(call.name, lambda **a: a)
    dispatched = _dispatch_record(kd, call)

    ke = _kernel(tmp_path, policy_factory(), name="evaluate")
    record, audit_hash = ke.evaluate_and_record(call)

    assert _stable(record) == _stable(dispatched)
    assert audit_hash and audit_hash != "0" * 64


def test_exactly_one_audit_append(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    kernel = Kernel(policy=DenyAllPolicy(), audit=ChainHashAuditStore(audit_path))

    kernel.evaluate_and_record(_call())

    lines = [ln for ln in audit_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1


def test_no_tool_executed(tmp_path: Path) -> None:
    """The primitive never invokes a registered tool_fn — even one registered on
    the kernel is untouched (no registry lookup happens)."""
    executed: list[str] = []
    kernel = _kernel(tmp_path, AllowAllPolicy())

    @kernel.tool("write_file")
    def _write_file(**kwargs: Any) -> str:
        executed.append("ran")
        return "SIDE EFFECT"

    record, _hash = kernel.evaluate_and_record(_call())

    assert record.decision is Decision.ALLOW
    assert executed == []


def test_audit_error_fail_closed(tmp_path: Path) -> None:
    """An append failure raises AuditError (fail-closed); no tool runs."""
    executed: list[str] = []
    kernel = Kernel(policy=AllowAllPolicy(), audit=_FailingAuditStore(tmp_path / "a.jsonl"))
    kernel.registry.register("write_file", lambda **a: executed.append("ran"))

    with pytest.raises(ErrorsAuditError):
        kernel.evaluate_and_record(_call())
    assert executed == []
    # AuditError from errors and audit modules are the same symbol.
    assert AuditError is ErrorsAuditError
