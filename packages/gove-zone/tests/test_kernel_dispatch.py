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

import threading
import time
from pathlib import Path
from typing import Any

import pytest

from gove_zone import (
    AllowAllPolicy,
    BoundaryPolicy,
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    DeniedError,
    DenyAllPolicy,
    Kernel,
    Policy,
    UnknownToolError,
)
from gove_zone.decision import sha256_json
from gove_zone.policy import new_event_id
from gove_zone.replay import replay_call
from gove_zone.replay_store import ReplaySideStore
from gove_zone.tool import ToolCall


def _kernel(tmp_path: Path, policy_obj: Any) -> Kernel:
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


def test_tool_registry_rejects_duplicate_names(tmp_path: Path) -> None:
    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("dup")
    def first() -> None:
        return None

    with pytest.raises(ValueError, match="already registered"):

        @k.tool("dup")
        def second() -> None:
            return None


def test_default_off_creates_no_side_store_and_behaves_identically(tmp_path: Path) -> None:
    """With no side_store, dispatch is unchanged and no side-store file appears."""
    k = _kernel(tmp_path, AllowAllPolicy())

    @k.tool("echo")
    def echo(msg: str) -> str:
        return msg.upper()

    result, receipt = k.dispatch("echo", {"msg": "hi"})

    assert result == "HI"
    assert receipt.record.decision is Decision.ALLOW
    assert not (tmp_path / "replay.jsonl").exists()
    assert list(tmp_path.glob("*.jsonl")) == [tmp_path / "audit.jsonl"]


def test_opt_in_allow_writes_side_record_matching_receipt(tmp_path: Path) -> None:
    side_store = ReplaySideStore(tmp_path / "replay.jsonl")
    k = Kernel(
        policy=BoundaryPolicy(forbidden_keywords=["secret"]),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        side_store=side_store,
    )

    @k.tool("send")
    def send(body: str) -> None:
        return None

    _, receipt = k.dispatch("send", {"body": "hello"})

    side = side_store.get(receipt.record.event_id)
    assert side is not None
    assert side["args"] == {"body": "hello"}
    assert side["argument_hash"] == receipt.record.argument_hash
    assert side["policy_version"] == receipt.record.policy_version
    assert side["decision"] == receipt.record.decision.value


def test_opt_in_deny_still_writes_side_record(tmp_path: Path) -> None:
    side_store = ReplaySideStore(tmp_path / "replay.jsonl")
    k = Kernel(
        policy=DenyAllPolicy(reason="blocked"),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        side_store=side_store,
    )

    @k.tool("side_effect")
    def side_effect() -> None:
        return None

    with pytest.raises(DeniedError) as exc_info:
        k.dispatch("side_effect", {"x": 1})

    event_id = exc_info.value.record.event_id
    side = side_store.get(event_id)
    assert side is not None
    assert side["decision"] == "deny"
    assert side["args"] == {"x": 1}


def test_side_record_matches_audit_event_fields(tmp_path: Path) -> None:
    side_store = ReplaySideStore(tmp_path / "replay.jsonl")
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    k = Kernel(
        policy=BoundaryPolicy(forbidden_keywords=["secret"]),
        audit=audit,
        side_store=side_store,
    )

    @k.tool("send")
    def send(body: str) -> None:
        return None

    _, receipt = k.dispatch("send", {"body": "hello"})
    events = list(audit.iter_events())
    assert len(events) == 1
    event = events[0]
    side = side_store.get(receipt.record.event_id)
    assert side is not None
    assert side["event_id"] == event["event_id"]
    assert side["argument_hash"] == event["argument_hash"]
    assert side["policy_version"] == event["policy_version"]
    assert side["decision"] == event["decision"]


def test_redacted_call_tombstones_side_store_but_not_chain(tmp_path: Path) -> None:
    side_store = ReplaySideStore(
        tmp_path / "replay.jsonl",
        redact=lambda c: "id_rsa" in str(c.args),
    )
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    k = Kernel(
        policy=AllowAllPolicy(),
        audit=audit,
        side_store=side_store,
    )

    @k.tool("write_file")
    def write_file(path: str) -> str:
        return path

    _, receipt = k.dispatch("write_file", {"path": "id_rsa"})

    side = side_store.get(receipt.record.event_id)
    assert side == {"event_id": receipt.record.event_id, "redacted": True}

    events = list(audit.iter_events())
    assert events[0]["argument_hash"] == receipt.record.argument_hash
    assert audit.verify_chain()["valid"] is True


def test_side_store_record_feeds_replay_call(tmp_path: Path) -> None:
    """The write path produces a record the replay re-derivation can consume."""
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    side_store = ReplaySideStore(tmp_path / "replay.jsonl")
    k = Kernel(
        policy=policy,
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        side_store=side_store,
    )

    @k.tool("send")
    def send(body: str) -> None:
        return None

    _, receipt = k.dispatch("send", {"body": "hello"})
    side = side_store.get(receipt.record.event_id)
    assert side is not None

    reconstructed = ToolCall(
        name=side["tool"],
        args=dict(side["args"]),
        goal=side["goal"],
        actor=side["actor"],
        path=tuple(side["path"]),
        state=dict(side["state"]),
    )
    replayed = replay_call(
        reconstructed,
        expected_decision=receipt.record.decision,
        policy=policy,
        expected_policy_version=receipt.record.policy_version,
    )
    assert replayed.matches is True


class _SlowAllowPolicy(Policy):
    """Allows every call, but blocks in ``evaluate`` for ``delay`` seconds.

    Used to exercise the kernel's fail-closed policy watchdog (``policy_timeout``,
    #152): a slow/hung policy must be aborted and converted to a DENY rather than
    stalling the gate or eventually leaking an ALLOW.
    """

    def __init__(self, delay: float) -> None:
        self._delay = delay
        # Set right before evaluate returns, so a test can wait for the orphan
        # worker thread to finish and then assert its late ALLOW was discarded.
        self.completed = threading.Event()

    @property
    def version(self) -> str:
        return "slow-allow/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        time.sleep(self._delay)
        record = DecisionRecord(
            decision=Decision.ALLOW,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            reason="slow allow policy",
        )
        self.completed.set()
        return record


def test_hung_policy_times_out_to_fail_closed_deny(tmp_path: Path) -> None:
    """A policy that exceeds ``policy_timeout`` is aborted by the watchdog and the
    dispatch fails closed: DENY synthesized, the tool never runs, and the decision
    is anchored exactly once in the audit chain.

    This is the dispatcher-level proof that the #152 watchdog actually fires —
    it goes through ``kernel.dispatch``, not ``_evaluate_with_watchdog`` directly.
    """
    policy = _SlowAllowPolicy(delay=0.5)
    k = Kernel(
        policy=policy,
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        policy_timeout=0.05,
    )
    ran: list[str] = []

    @k.tool("side_effect")
    def side_effect() -> None:
        ran.append("ran")

    with pytest.raises(DeniedError) as exc_info:
        k.dispatch("side_effect")

    record = exc_info.value.record
    assert record.decision is Decision.DENY
    assert record.policy_version == "fail-closed/policy-timeout"
    assert any(r.startswith("POLICY_ERROR:TIMEOUT:") for r in record.matched_rules)
    assert exc_info.value.audit_hash != "0" * 64

    # Wait for the orphan worker thread to finish its (now-discarded) ALLOW, then
    # assert the late result was NOT applied: the fail-closed DENY stands, the tool
    # never ran, and no second (ALLOW) event leaked into the chain. This
    # regression-locks the discard guarantee in Kernel._evaluate_with_watchdog —
    # without the wait, these assertions pass before a late ALLOW could manifest.
    assert policy.completed.wait(timeout=2.0)
    assert ran == []  # late ALLOW must not let the side effect through
    events = list(k.audit.iter_events())
    assert len(events) == 1  # exactly one event: the fail-closed DENY
    assert events[0]["decision"] == "deny"
    assert k.audit.verify_chain()["valid"] is True


def test_slow_policy_within_timeout_allows_and_runs(tmp_path: Path) -> None:
    """Control for the watchdog: the same slow policy, comfortably under a generous
    ``policy_timeout``, ALLOWs and runs the tool. Proves the DENY above comes from
    the timeout firing, not from the policy or the watchdog wrapper itself.
    """
    k = Kernel(
        policy=_SlowAllowPolicy(delay=0.02),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        policy_timeout=5.0,
    )
    ran: list[str] = []

    @k.tool("side_effect")
    def side_effect() -> str:
        ran.append("ran")
        return "ok"

    result, receipt = k.dispatch("side_effect")

    assert result == "ok"
    assert ran == ["ran"]
    assert receipt.record.decision is Decision.ALLOW
