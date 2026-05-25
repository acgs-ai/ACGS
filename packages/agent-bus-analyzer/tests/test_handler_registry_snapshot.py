"""T033 — HandlerRegistrySnapshot sampling unit tests.

Tests cover sample_registry() with both bus and kernel stubs, empty
surfaces, and the Protocol runtime check.
"""

from __future__ import annotations

from datetime import UTC, datetime

from agent_bus_analyzer.models import HandlerRegistrySnapshot
from agent_bus_analyzer.wiring import BusWithHandlers, KernelWithTools, sample_registry


class _StubBus:
    """Minimal bus stub that satisfies BusWithHandlers protocol."""

    def __init__(self, handlers: dict) -> None:
        self._handlers = handlers

    def get_registered_handlers(self) -> dict:
        return self._handlers


class _StubKernel:
    """Minimal kernel stub that satisfies KernelWithTools protocol."""

    def __init__(self, tools: dict) -> None:
        self._tools = tools

    def get_registered_tools(self) -> dict:
        return self._tools


def test_sample_registry_from_bus() -> None:
    bus = _StubBus({"policy.evaluate": {}, "audit.log": {}})
    snap = sample_registry(bus)
    assert isinstance(snap, HandlerRegistrySnapshot)
    assert "policy.evaluate" in snap.handlers
    assert "audit.log" in snap.handlers
    assert snap.handlers["policy.evaluate"].registered_in_runtime is True
    assert snap.source == "enhanced_agent_bus"


def test_sample_registry_empty_bus() -> None:
    bus = _StubBus({})
    snap = sample_registry(bus)
    assert snap.handlers == {}
    assert isinstance(snap.snapshot_id, str)
    assert isinstance(snap.sampled_at, datetime)


def test_sample_registry_from_kernel_overrides_source() -> None:
    kernel = _StubKernel({"kernel.tool.a": {}, "kernel.tool.b": {}})
    snap = sample_registry(None, gove_zone_kernel=kernel)
    assert snap.source == "gove_zone_kernel"
    assert "kernel.tool.a" in snap.handlers
    assert "kernel.tool.b" in snap.handlers


def test_sample_registry_bus_and_kernel_merged() -> None:
    bus = _StubBus({"bus.handler": {}})
    kernel = _StubKernel({"kernel.tool": {}})
    snap = sample_registry(bus, gove_zone_kernel=kernel)
    # Both sources contribute to the handlers dict.
    assert "bus.handler" in snap.handlers
    assert "kernel.tool" in snap.handlers


def test_sample_registry_no_bus_no_kernel() -> None:
    snap = sample_registry(None)
    assert snap.handlers == {}
    assert snap.source == "enhanced_agent_bus"


def test_sample_registry_bus_with_last_seen_datetime() -> None:
    now = datetime.now(UTC)

    class _BusWithTs:
        def get_registered_handlers(self) -> dict:
            return {"h": {"last_seen_at": now.isoformat()}}

    snap = sample_registry(_BusWithTs())
    assert snap.handlers["h"].last_seen_at is not None


def test_sample_registry_non_protocol_bus_ignored() -> None:
    """An object that doesn't satisfy BusWithHandlers yields empty snapshot."""

    class _NotABus:
        pass

    snap = sample_registry(_NotABus())
    assert snap.handlers == {}


def test_protocol_check_satisfied() -> None:
    bus = _StubBus({})
    assert isinstance(bus, BusWithHandlers)

    kernel = _StubKernel({})
    assert isinstance(kernel, KernelWithTools)
