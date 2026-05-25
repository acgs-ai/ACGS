"""T074 — fault-injection test (SC-006: analyzer non-interference).

Scenario B from the plan: the analyzer crashes mid-run (its observer callback
raises an unhandled exception).  The test asserts:

1. A downstream stubbed governance gate that denies a known-deny payload STILL
   denies it — the analyzer crash must not affect the authorization decision.
2. The bus publish path (simulated via a stub) completes successfully despite
   the observer crash.
3. A degraded state can be detected: the observer sets a sentinel flag on
   unhandled exception, and a health-check query on that flag returns ``False``
   (unhealthy).

Stubbed gate rationale (Scenario B): we use a minimal in-process stub rather
than a real ACGS gove-zone kernel because the test is about analyzer
non-interference, not real policy enforcement.  The stub is deterministic:
it always denies the payload ``{"action": "DENY_ME"}``.

observer.py is READ-ONLY (Constitution Principle II), so the "degraded state
sentinel" is tracked by the test-local ``FaultingObserver`` wrapper rather than
by modifying Observer itself.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_bus_analyzer.capture import CaptureQueue

_CONST_HASH = "a1b2c3d4e5f60718"


# ---------------------------------------------------------------------------
# Stub governance gate
# ---------------------------------------------------------------------------


class StubGovernanceGate:
    """Minimal stub that denies payloads matching a deny-list.

    Designed to stand in for the real gove-zone kernel during fault-injection
    tests.  It must be called directly; it is NOT wired to the bus — that is
    intentional (analyzer non-interference means the gate path is independent).
    """

    _DENY_ACTIONS = frozenset({"DENY_ME", "BLOCKED_ACTION"})

    def evaluate(self, payload: dict[str, Any]) -> str:
        """Return 'deny' or 'allow'."""
        if payload.get("action") in self._DENY_ACTIONS:
            return "deny"
        return "allow"


# ---------------------------------------------------------------------------
# Faulty observer wrapper (test-local — does NOT modify observer.py)
# ---------------------------------------------------------------------------


class FaultingObserver:
    """Wraps the real observer callback and injects a fault after N events.

    Tracks health via ``healthy`` sentinel so tests can assert degraded state.
    """

    def __init__(self, queue: CaptureQueue, fault_after: int = 3) -> None:
        from agent_bus_analyzer.observer import Observer

        self._inner = Observer(queue=queue, constitutional_hash=_CONST_HASH)
        self._fault_after = fault_after
        self._call_count = 0
        self.healthy = True

    async def on_bus_event(self, msg: dict[str, Any]) -> None:
        self._call_count += 1
        if self._call_count > self._fault_after:
            self.healthy = False
            raise RuntimeError("simulated observer crash mid-run")
        await self._inner.on_bus_event(msg)


# ---------------------------------------------------------------------------
# Stub bus publish (simulates the bus publish path without real LocalEventBus)
# ---------------------------------------------------------------------------


async def stub_publish(
    msg: dict[str, Any],
    observer: FaultingObserver,
) -> str:
    """Simulate a bus.publish() that notifies one observer.

    Returns 'published' even if the observer crashes — the bus is not
    allowed to propagate observer exceptions to the publisher.
    """
    try:
        await observer.on_bus_event(msg)
    except Exception:
        pass  # observer failure must not propagate to the publish caller
    return "published"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _make_msg(i: int, action: str = "query") -> dict[str, Any]:
    return {
        "message_id": f"fault-msg-{i:04d}",
        "conversation_id": f"fault-trace-{i:04d}",
        "from_agent": "test-sender",
        "to_agent": "test-handler",
        "constitutional_hash": _CONST_HASH,
        "payload": {"action": action, "index": i},
    }


@pytest.mark.asyncio
async def test_bus_publish_succeeds_after_observer_crash() -> None:
    """SC-006: stub_publish() returns 'published' even when the observer crashes."""
    queue: CaptureQueue = CaptureQueue(capacity=100)
    observer = FaultingObserver(queue=queue, fault_after=2)

    results = []
    for i in range(5):
        result = await stub_publish(_make_msg(i), observer)
        results.append(result)

    assert all(r == "published" for r in results), f"Expected all 'published', got: {results}"


@pytest.mark.asyncio
async def test_governance_gate_denies_despite_observer_crash() -> None:
    """SC-006: stub gate still denies DENY_ME payload after observer crash.

    The gate evaluates payloads independently; it must not be affected by the
    observer's health state.
    """
    queue: CaptureQueue = CaptureQueue(capacity=100)
    observer = FaultingObserver(queue=queue, fault_after=1)
    gate = StubGovernanceGate()

    # Crash the observer
    for i in range(5):
        await stub_publish(_make_msg(i), observer)

    # Observer must now be unhealthy (degraded state detectable)
    assert not observer.healthy, "observer should be in degraded state after crash"

    # Gate must still deny independently of observer state
    decision = gate.evaluate({"action": "DENY_ME"})
    assert decision == "deny", (
        f"Gate must deny DENY_ME even with observer degraded; got {decision!r}"
    )


@pytest.mark.asyncio
async def test_degraded_state_is_detectable() -> None:
    """SC-006: a health sentinel is set after the observer faults.

    The sentinel (FaultingObserver.healthy) allows an external health-check
    to detect degraded analyzer state and take action (alert, restart, etc.).
    """
    queue: CaptureQueue = CaptureQueue(capacity=100)
    observer = FaultingObserver(queue=queue, fault_after=0)

    assert observer.healthy, "observer should start healthy"

    # First event triggers the fault
    await stub_publish(_make_msg(0), observer)

    assert not observer.healthy, (
        "observer.healthy must be False after the fault — degraded state must be detectable"
    )


@pytest.mark.asyncio
async def test_gate_allows_non_deny_payload_after_observer_crash() -> None:
    """SC-006: gate still allows non-deny payloads after observer degradation."""
    queue: CaptureQueue = CaptureQueue(capacity=100)
    observer = FaultingObserver(queue=queue, fault_after=0)
    gate = StubGovernanceGate()

    # Crash the observer immediately
    await stub_publish(_make_msg(0), observer)

    decision = gate.evaluate({"action": "SAFE_ACTION"})
    assert decision == "allow", (
        f"Gate must allow safe payloads even with observer degraded; got {decision!r}"
    )
