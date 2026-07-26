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
from gove_zone.kernel import AuditedDecision, _freeze_mapping
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


class _StaticAuditStore:
    """Structural AuditAppender test double returning controlled append payloads."""

    def __init__(self, **overrides: Any) -> None:
        self.overrides = overrides
        self.appended: list[DecisionRecord] = []

    def append(self, decision: DecisionRecord) -> dict[str, Any]:
        self.appended.append(decision)
        payload = decision.to_dict()
        payload["previous_hash"] = "0" * 64
        payload.update(self.overrides)
        payload.setdefault("event_hash", sha256_json(payload))
        return payload


class _NonMappingAuditStore:
    """Structural AuditAppender test double returning a non-mapping payload."""

    def __init__(self) -> None:
        self.appended: list[DecisionRecord] = []

    def append(self, decision: DecisionRecord) -> Any:
        self.appended.append(decision)
        return [decision.to_dict()]


class _SecondAppendFailsAuditStore(ChainHashAuditStore):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.append_count = 0

    def append(self, decision: DecisionRecord) -> dict[str, Any]:
        self.append_count += 1
        if self.append_count == 2:
            raise OSError("failure audit sink down")
        return super().append(decision)


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


def test_evaluate_and_append_returns_full_immutable_append_result(tmp_path: Path) -> None:
    kernel = _kernel(tmp_path, AllowAllPolicy())

    audited = kernel.evaluate_and_append(_call())

    assert isinstance(audited, AuditedDecision)
    assert audited.record.decision is Decision.ALLOW
    assert audited.audit_hash == audited.append_result["event_hash"]
    assert audited.append_result["event_id"] == audited.record.event_id
    assert audited.append_result["previous_hash"] == "0" * 64
    assert audited.append_result["matched_rules"] == ()
    with pytest.raises(TypeError):
        audited.append_result["event_id"] = "mutated"  # type: ignore[index]


def test_kernel_retains_concrete_audit_type_for_type_checkers(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel: Kernel[ChainHashAuditStore] = Kernel(policy=AllowAllPolicy(), audit=audit)

    def _requires_chain_hash_store(store: ChainHashAuditStore) -> None:
        assert store.path == audit.path

    _requires_chain_hash_store(kernel.audit)


def test_evaluate_and_append_rejects_mismatched_append_response() -> None:
    audit = _StaticAuditStore(tool="different_tool")
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)

    with pytest.raises(AuditError, match="mismatched 'tool'"):
        kernel.evaluate_and_append(_call())
    assert len(audit.appended) == 1


def test_evaluate_and_append_rejects_malformed_append_hash() -> None:
    audit = _StaticAuditStore(previous_hash="not-a-sha")
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)

    with pytest.raises(AuditError, match="invalid previous_hash"):
        kernel.evaluate_and_append(_call())
    assert len(audit.appended) == 1


def test_evaluate_and_append_rejects_non_mapping_append_response() -> None:
    audit = _NonMappingAuditStore()
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)

    with pytest.raises(AuditError, match="non-mapping"):
        kernel.evaluate_and_append(_call())
    assert len(audit.appended) == 1


def test_evaluate_and_append_rejects_malformed_event_hash() -> None:
    audit = _StaticAuditStore(event_hash="not-a-sha")
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)

    with pytest.raises(AuditError, match="invalid event_hash"):
        kernel.evaluate_and_append(_call())
    assert len(audit.appended) == 1


def test_evaluate_and_append_rejects_mismatched_event_hash() -> None:
    audit = _StaticAuditStore(event_hash="f" * 64)
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)

    with pytest.raises(AuditError, match="mismatched event_hash"):
        kernel.evaluate_and_append(_call())
    assert len(audit.appended) == 1


def test_private_tuple_api_delegates_to_full_append_result(tmp_path: Path) -> None:
    kernel = _kernel(tmp_path, AllowAllPolicy())

    record, audit_hash = kernel._evaluate_and_record(_call())

    event = next(iter(kernel.audit.iter_events()))
    assert record.event_id == event["event_id"]
    assert audit_hash == event["event_hash"]


def test_append_execution_failure_is_strict_bound_and_redacted(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)
    call = _call()
    audited = kernel.evaluate_and_append(call)

    failure = kernel.append_execution_failure(
        call,
        audited,
        RuntimeError("secret-token-123"),
    )

    events = list(audit.iter_events())
    assert len(events) == 2
    assert failure.record.event_id == audited.record.event_id + ":failure"
    assert failure.audit_hash == events[1]["event_hash"]
    assert events[1]["decision"] == "deny"
    assert events[1]["argument_hash"] == audited.record.argument_hash
    assert events[1]["decision_request_hash"] == audited.record.decision_request_hash
    assert events[1]["matched_rules"] == ["EXEC_FAILURE:RuntimeError"]
    assert events[1]["reason"] == "execution raised: RuntimeError"
    assert "secret-token-123" not in str(events[1])


@pytest.mark.parametrize(
    ("policy_obj", "decision"),
    [
        (DenyAllPolicy(reason="blocked"), Decision.DENY),
        (_EscalatePolicy(), Decision.ESCALATE),
    ],
)
def test_append_execution_failure_rejects_non_executable_decisions_without_append(
    tmp_path: Path,
    policy_obj: Policy,
    decision: Decision,
) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=policy_obj, audit=audit)
    call = _call()
    audited = kernel.evaluate_and_append(call)
    assert audited.record.decision is decision

    with pytest.raises(AuditError, match="ALLOW or TRANSFORM"):
        kernel.append_execution_failure(call, audited, RuntimeError("boom"))

    events = list(audit.iter_events())
    assert len(events) == 1
    assert events[0]["event_id"] == audited.record.event_id


def test_append_execution_failure_rejects_mismatched_call_without_append(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)
    call = _call()
    audited = kernel.evaluate_and_append(call)

    with pytest.raises(AuditError, match="argument_hash"):
        kernel.append_execution_failure(
            call.with_args({"path": "/tmp/y"}),
            audited,
            ValueError("x"),
        )

    assert len(list(audit.iter_events())) == 1


@pytest.mark.parametrize(
    ("field", "tampered"),
    [
        ("tool", "other_tool"),
        ("goal", "other goal"),
        ("actor", "agent:other"),
        ("path", ("other", "path")),
        ("state_hash", "f" * 64),
        ("decision_request_hash", "f" * 64),
    ],
)
def test_append_execution_failure_rejects_tampered_record_binding_without_append(
    tmp_path: Path,
    field: str,
    tampered: Any,
) -> None:
    """Each record/call binding field is enforced individually; nothing appends."""
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)
    call = _call()
    audited = kernel.evaluate_and_append(call)
    tampered_audited = AuditedDecision(
        record=dataclasses.replace(audited.record, **{field: tampered}),
        append_result=audited.append_result,
    )

    with pytest.raises(AuditError, match=f"binding mismatch: {field}"):
        kernel.append_execution_failure(call, tampered_audited, RuntimeError("boom"))

    assert len(list(audit.iter_events())) == 1


@pytest.mark.parametrize(
    ("label", "overrides"),
    [
        ("tool", {"name": "other_tool"}),
        ("goal", {"goal": "other goal"}),
        ("actor", {"actor": "agent:other"}),
        ("path", {"path": ("other", "path")}),
        ("state_hash", {"state": {"region": "eu"}}),
    ],
)
def test_append_execution_failure_rejects_diverged_executed_call_context_without_append(
    tmp_path: Path,
    label: str,
    overrides: dict[str, Any],
) -> None:
    """An executed_call may only diverge in args; any context drift fails closed."""
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)
    call = _call()
    audited = kernel.evaluate_and_append(call)
    executed_call = ToolCall(
        name=overrides.get("name", call.name),
        args=dict(call.args),
        goal=overrides.get("goal", call.goal),
        actor=overrides.get("actor", call.actor),
        path=overrides.get("path", call.path),
        state=overrides.get("state", dict(call.state)),
    )

    with pytest.raises(AuditError, match=f"effective call mismatch: {label}"):
        kernel.append_execution_failure(
            call,
            audited,
            RuntimeError("boom"),
            executed_call=executed_call,
        )

    assert len(list(audit.iter_events())) == 1


def test_freeze_mapping_freezes_set_values_into_frozensets() -> None:
    frozen = _freeze_mapping({"tags": {"a", "b"}, "nested": {"inner": {"c"}}})

    assert frozen["tags"] == frozenset({"a", "b"})
    assert isinstance(frozen["tags"], frozenset)
    assert frozen["nested"]["inner"] == frozenset({"c"})
    with pytest.raises(TypeError):
        frozen["tags"] = frozenset()  # type: ignore[index]


def test_dispatch_rethrows_original_exception_when_failure_audit_fails(tmp_path: Path) -> None:
    audit = _SecondAppendFailsAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)

    @kernel.tool("explode")
    def explode() -> None:
        raise ValueError("original tool error")

    with pytest.raises(ValueError, match="original tool error"):
        kernel.dispatch("explode")

    assert audit.append_count == 2
    events = list(audit.iter_events())
    assert len(events) == 1
    assert events[0]["decision"] == "allow"


def test_transform_failure_hashes_executed_args_and_preserves_original_binding(
    tmp_path: Path,
) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=TransformPolicy(), audit=audit, actor=_ACTOR)

    @kernel.tool("write_file")
    def write_file(path: str, content: str, payload: dict[str, Any]) -> None:
        assert path == "transformed.txt"
        payload["marker"] = "mutated-secret-value"
        raise RuntimeError("secret-token-456")

    original_args = {
        "path": "/tmp/original.txt",
        "content": "hi",
        "payload": {"marker": "before"},
    }
    with pytest.raises(RuntimeError, match="secret-token-456"):
        kernel.dispatch("write_file", original_args, goal="transform goal")

    events = list(audit.iter_events())
    assert len(events) == 2
    decision_event, failure_event = events
    assert decision_event["decision"] == "transform"
    assert failure_event["decision"] == "deny"
    assert failure_event["argument_hash"] == sha256_json(
        {
            "path": "transformed.txt",
            "content": "hi",
            "payload": {"marker": "mutated-secret-value"},
        }
    )
    assert failure_event["argument_hash"] != decision_event["argument_hash"]
    assert failure_event["decision_request_hash"] == decision_event["decision_request_hash"]
    assert failure_event["state_hash"] == decision_event["state_hash"]
    assert failure_event["matched_rules"] == [
        "EXEC_FAILURE:RuntimeError",
        "EXEC_ARGS_DIVERGED",
    ]
    assert failure_event["reason"] == "execution raised: RuntimeError"
    failure_text = str(failure_event)
    assert "mutated-secret-value" not in failure_text
    assert "secret-token-456" not in failure_text
    assert "transformed.txt" not in failure_text
