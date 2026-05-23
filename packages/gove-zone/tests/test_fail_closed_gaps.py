"""Fail-closed gap-fill: Scenario C (watchdog / timeout / hang).

Complements ``test_fail_closed.py`` which already covers Scenarios A
(audit append failure) and B (policy evaluation raised). This module
asserts that a hanging or excessively slow policy evaluation MUST NOT
block the dispatch indefinitely — the kernel's watchdog must abort the
call within a configured deadline, synthesize a DENY record, anchor it
in the audit chain, and raise :class:`DeniedError`. The wrapped tool
must never execute.

Identified as a gap by the /cca round-2 advisor pass (agy) against the
existing fail-closed suite.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    DeniedError,
    Kernel,
    Policy,
)
from gove_zone.tool import ToolCall


class _HangingPolicy(Policy):
    """Policy whose ``evaluate`` blocks for ``hang_seconds`` before returning.

    Bounded sleep (not an infinite hang) so the test cannot deadlock the
    suite if the kernel's watchdog is missing — the elapsed-time
    assertion will fail loudly instead of timing pytest out.
    """

    def __init__(self, hang_seconds: float = 1.0) -> None:
        self.hang_seconds = hang_seconds
        self.evaluated = 0

    @property
    def version(self) -> str:
        return "hanging/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        self.evaluated += 1
        time.sleep(self.hang_seconds)
        # If the watchdog did NOT fire, return a (now-stale) ALLOW so the
        # absence of fail-closed semantics is visible: tool would run.
        from gove_zone import AllowAllPolicy

        return AllowAllPolicy().evaluate(call)


def test_watchdog_timeout_fails_closed(tmp_path: Path) -> None:
    """A policy that hangs MUST be aborted by the kernel watchdog.

    Contract under test (NOT YET IMPLEMENTED — this test is the red bar):
      * ``Kernel`` accepts a ``policy_timeout`` kw-arg (seconds)
      * If ``policy.evaluate`` exceeds ``policy_timeout``, the kernel
        synthesizes a DENY record with matched_rules containing
        ``POLICY_ERROR:TIMEOUT`` (or an equivalent timeout marker)
      * The synthesized DENY is appended to the audit chain
      * ``DeniedError`` is raised
      * The registered tool is never invoked
      * Dispatch returns within ``policy_timeout`` + a small margin
        (i.e. the watchdog does not wait for the hung policy to finish)
    """
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    policy = _HangingPolicy(hang_seconds=1.0)
    # 200ms watchdog matches the agy critique recommendation.
    kernel = Kernel(policy=policy, audit=audit, policy_timeout=0.2)

    executed: list[str] = []

    @kernel.tool("never_runs")
    def never_runs() -> None:
        executed.append("ran")

    started = time.monotonic()
    with pytest.raises(DeniedError) as exc_info:
        kernel.dispatch("never_runs")
    elapsed = time.monotonic() - started

    # Tool MUST NOT have executed.
    assert executed == [], "fail-closed violated: tool ran despite hung policy"

    # Watchdog fired well before the policy would have returned (1.0s).
    assert elapsed < 0.6, (
        f"watchdog did not interrupt the hung policy: elapsed={elapsed:.3f}s "
        f"(expected < 0.6s with policy_timeout=0.2)"
    )

    # Synthesized DENY carries a timeout marker.
    assert exc_info.value.record.decision is Decision.DENY
    assert any(
        "TIMEOUT" in rule or "POLICY_ERROR:TIMEOUT" in rule
        for rule in exc_info.value.record.matched_rules
    ), f"expected a TIMEOUT marker in matched_rules, got {exc_info.value.record.matched_rules!r}"

    # Audit chain holds exactly one event (the synthesized DENY).
    events = list(audit.iter_events())
    assert len(events) == 1
    assert events[0]["decision"] == "deny"
    assert audit.verify_chain()["valid"] is True


def test_watchdog_does_not_fire_on_fast_policy(tmp_path: Path) -> None:
    """Negative control: a fast policy must NOT trip the watchdog.

    Confirms the watchdog has a real threshold and isn't denying
    legitimate dispatches.
    """
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    policy = _HangingPolicy(hang_seconds=0.01)  # 10ms — well under threshold
    kernel = Kernel(policy=policy, audit=audit, policy_timeout=0.5)

    @kernel.tool("noop")
    def noop() -> str:
        return "ok"

    result, receipt = kernel.dispatch("noop")
    assert result == "ok"
    assert receipt.record.decision is Decision.ALLOW
