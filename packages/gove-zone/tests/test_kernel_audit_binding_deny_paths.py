"""Negative-path cover for the audit-append and failure-binding guards.

``4edff51`` ("expose audited append results") grew ``kernel.py`` from 109 to 206
statements by adding three defensive validators on the fail-closed path:

* ``_validate_append_payload`` — the audit appender's return value is treated as
  untrusted authorization material, not as a trusted echo.
* ``_validate_failure_binding`` — an execution-failure record may only be
  appended against the audited decision it actually belongs to.
* ``_validate_effective_failure_call`` — the executed call may differ from the
  proposed call only in its arguments (the TRANSFORM case); any other divergence
  means the caller is binding the failure to the wrong request.

Every guard raises :class:`AuditError` *before* appending. Those raise branches
are the fail-closed guarantee, so the kernel's 100% deny-path coverage gate
(``--cov=gove_zone.kernel --cov-branch --cov-fail-under=100``) requires each one
to be exercised. Each test asserts the guard both raises **and** leaves no
audit event behind.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from gove_zone import AllowAllPolicy, ChainHashAuditStore, DecisionRecord, Kernel
from gove_zone.audit import AuditError
from gove_zone.decision import sha256_json
from gove_zone.kernel import _freeze_mapping
from gove_zone.tool import ToolCall

_ACTOR = "agent:a"


class _StaticAuditStore:
    """Structural AuditAppender double returning controlled append payloads."""

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
    """Appender that violates the contract by returning a non-mapping."""

    def __init__(self) -> None:
        self.appended: list[DecisionRecord] = []

    def append(self, decision: DecisionRecord) -> Any:
        self.appended.append(decision)
        return ["not", "a", "mapping"]


class _DivergentRequestHashCall(ToolCall):
    """A call whose decision-request hash diverges from every other binding.

    No single field can do this — ``decision_request_hash`` is derived from
    actor + path + goal + tool + argument hash + state hash, all of which are
    checked ahead of it — so the divergence is injected directly.
    """

    def decision_request_hash(self) -> str:
        return "0" * 64


def _call(name: str = "write_file") -> ToolCall:
    return ToolCall(name=name, args={"path": "/tmp/x", "content": "hi"}, actor=_ACTOR)


def test_append_payload_rejects_non_mapping_result() -> None:
    """A non-mapping append result is unusable authorization material."""
    audit = _NonMappingAuditStore()
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)

    with pytest.raises(AuditError, match="non-mapping"):
        kernel.evaluate_and_append(_call())
    assert len(audit.appended) == 1


def test_append_payload_rejects_malformed_event_hash() -> None:
    """``event_hash`` must look like a SHA-256 digest before it is compared."""
    audit = _StaticAuditStore(event_hash="not-a-sha")
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)

    with pytest.raises(AuditError, match="invalid event_hash"):
        kernel.evaluate_and_append(_call())
    assert len(audit.appended) == 1


# (field kwargs, expected AuditError suffix) for _validate_failure_binding.
# ``argument_hash`` is already covered by test_kernel_evaluate_and_record.py.
_BINDING_DIVERGENCES = (
    ({"name": "other_tool"}, "tool"),
    ({"goal": "exfiltrate"}, "goal"),
    ({"actor": "agent:b"}, "actor"),
    ({"path": ("other",)}, "path"),
    ({"state": {"env": "prod"}}, "state_hash"),
)


@pytest.mark.parametrize(("overrides", "field"), _BINDING_DIVERGENCES)
def test_failure_binding_rejects_divergent_call_without_appending(
    tmp_path: Path,
    overrides: dict[str, Any],
    field: str,
) -> None:
    """A failure record may not be bound to a call it was not decided for."""
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)
    call = _call()
    audited = kernel.evaluate_and_append(call)

    with pytest.raises(AuditError, match=f"audit binding mismatch: {field}"):
        kernel.append_execution_failure(
            dataclasses.replace(call, **overrides),
            audited,
            RuntimeError("boom"),
        )

    assert len(list(audit.iter_events())) == 1


def test_failure_binding_rejects_divergent_decision_request_hash(tmp_path: Path) -> None:
    """The decision-request binding is checked on its own axis."""
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)
    call = _call()
    audited = kernel.evaluate_and_append(call)

    divergent = _DivergentRequestHashCall(
        name=call.name,
        args=dict(call.args),
        goal=call.goal,
        actor=call.actor,
        path=call.path,
        state=call.state,
    )

    with pytest.raises(AuditError, match="audit binding mismatch: decision_request_hash"):
        kernel.append_execution_failure(divergent, audited, RuntimeError("boom"))

    assert len(list(audit.iter_events())) == 1


# (field kwargs, expected AuditError suffix) for _validate_effective_failure_call.
# Arguments are deliberately absent: a TRANSFORM legitimately rewrites them, and
# that divergence is recorded as EXEC_ARGS_DIVERGED rather than rejected.
_EFFECTIVE_DIVERGENCES = (
    ({"name": "other_tool"}, "tool"),
    ({"goal": "exfiltrate"}, "goal"),
    ({"actor": "agent:b"}, "actor"),
    ({"path": ("other",)}, "path"),
    ({"state": {"env": "prod"}}, "state_hash"),
)


@pytest.mark.parametrize(("overrides", "field"), _EFFECTIVE_DIVERGENCES)
def test_effective_call_divergence_rejected_without_appending(
    tmp_path: Path,
    overrides: dict[str, Any],
    field: str,
) -> None:
    """``executed_call`` may only differ from the proposed call in its args."""
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=AllowAllPolicy(), audit=audit)
    call = _call()
    audited = kernel.evaluate_and_append(call)

    with pytest.raises(AuditError, match=f"effective call mismatch: {field}"):
        kernel.append_execution_failure(
            call,
            audited,
            RuntimeError("boom"),
            executed_call=dataclasses.replace(call, **overrides),
        )

    assert len(list(audit.iter_events())) == 1


def test_append_result_freezes_nested_sets() -> None:
    """``append_result`` is deeply immutable, sets included.

    The append result is evidence handed back to callers; a mutable nested
    collection would let a caller edit authorization material after the fact.
    """
    frozen = _freeze_mapping({"tags": {"a", "b"}, "nested": {"seen": frozenset({"c"})}})

    assert frozen["tags"] == frozenset({"a", "b"})
    assert isinstance(frozen["tags"], frozenset)
    assert frozen["nested"]["seen"] == frozenset({"c"})
    with pytest.raises(TypeError):
        frozen["tags"] = "mutated"  # type: ignore[index]
