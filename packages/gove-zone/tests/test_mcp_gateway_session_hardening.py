"""Session-hardening conformance tests for the governed-MCP gateway.

These extend ``test_mcp_gateway_conformance.py`` with the four net-new hardening
behaviours (weakref session eviction, concurrent live-session isolation,
cross-actor escalation-resume denial, and bounded-capacity back-pressure).

They reuse that module's fixtures/helpers (``_Harness``, ``_config``,
``_build_fixture``, ``_audit_records``, the principal constants). Under
``--import-mode=importlib`` a plain ``import test_mcp_gateway_conformance`` fails
(the tests directory is not on ``sys.path``), so the sibling module is loaded
directly from its file path — a robust reuse that does not depend on import mode.
"""

from __future__ import annotations

import gc
import importlib.util
from contextlib import AsyncExitStack
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

pytest.importorskip("mcp")

import mcp.types as types  # noqa: E402
from mcp.shared.memory import (  # noqa: E402
    create_connected_server_and_client_session as connect,
)

from gove_zone import Kernel  # noqa: E402
from gove_zone.adapters.mcp_gateway import (  # noqa: E402
    GovernedGateway,
    SessionContext,
)
from gove_zone.errors import ReceiptValidationError  # noqa: E402

# --------------------------------------------------------------------------- #
# Reuse the conformance harness by loading the sibling module from its path.
# --------------------------------------------------------------------------- #

_CONF_PATH = Path(__file__).with_name("test_mcp_gateway_conformance.py")
_spec = importlib.util.spec_from_file_location("_gw_conformance_helpers", _CONF_PATH)
assert _spec is not None and _spec.loader is not None
_conf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_conf)

_build_fixture = _conf._build_fixture
_config = _conf._config
_audit_records = _conf._audit_records
_PRINCIPAL = _conf._PRINCIPAL
_PRINCIPAL_DESKTOP = _conf._PRINCIPAL_DESKTOP


@pytest.fixture
def anyio_backend() -> str:
    # Pin the anyio pytest plugin to asyncio (no trio dependency required).
    return "asyncio"


# --------------------------------------------------------------------------- #
# 1a. WeakKeyDictionary session cache auto-evicts when the session is GC'd.
#     Deterministic stand-in for the un-forceable id()-reuse collision the
#     WeakKeyDictionary keying defends against.
# --------------------------------------------------------------------------- #


def test_session_context_evicts_on_weakref_gc(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    # __init__ does not touch the downstream; a bare sentinel is enough here.
    gateway = GovernedGateway(cfg, cast(Any, object()))

    class _FakeSession:  # weak-referenceable (a raw object() is not).
        pass

    fake = _FakeSession()
    ctx = SessionContext(
        principal=_PRINCIPAL,
        kernel=Kernel(policy=cfg.policy, audit=gateway._audit, actor=_PRINCIPAL),
    )
    gateway._sessions[fake] = ctx
    assert len(gateway._sessions) == 1

    del fake  # drop the only strong ref to the key
    gc.collect()
    assert len(gateway._sessions) == 0  # weakref auto-evicted


# --------------------------------------------------------------------------- #
# 1b. Two host sessions OPEN + LIVE simultaneously each keep their own
#     principal — proves the per-session keying holds under concurrency, not
#     only sequentially (test_session_isolation closes A before opening B).
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_concurrent_live_sessions_isolate_principal(tmp_path: Path) -> None:
    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    cfg = _config(tmp_path)
    async with AsyncExitStack() as stack:
        downstream = await stack.enter_async_context(
            connect(fixture, client_info=types.Implementation(name="gw", version="0"))
        )
        gateway = GovernedGateway(cfg, downstream)
        server = gateway.build_server()
        # Both sessions live at once — A is NOT closed before B opens.
        host_a = await stack.enter_async_context(
            connect(server, client_info=types.Implementation(name="claude-code", version="1"))
        )
        host_b = await stack.enter_async_context(
            connect(server, client_info=types.Implementation(name="claude-desktop", version="1"))
        )
        # Interleave a call on each while both remain open.
        await host_a.call_tool("write_file", {"path": "a.txt", "content": "a"})
        await host_b.call_tool("write_file", {"path": "b.txt", "content": "b"})
        await host_a.call_tool("write_file", {"path": "a2.txt", "content": "a2"})

    actors = [r["actor"] for r in _audit_records(cfg.audit_path) if r["decision"] == "allow"]
    assert actors == [_PRINCIPAL, _PRINCIPAL_DESKTOP, _PRINCIPAL]


# --------------------------------------------------------------------------- #
# 1c. Cross-actor escalation-resume is denied (characterization, not a fix):
#     two DIFFERENT-principal live sessions each park an ESCALATE; presenting
#     one actor's approval receipt to resume the other's pending fails closed.
#     Differs from conformance #8a (whose two pendings share ONE actor) —
#     proves the per-pending expected_actor / expected_audit_hash pin already
#     denies cross-actor reuse.
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_cross_actor_escalation_resume_denied(tmp_path: Path) -> None:
    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    cfg = _config(tmp_path)
    async with AsyncExitStack() as stack:
        downstream = await stack.enter_async_context(
            connect(fixture, client_info=types.Implementation(name="gw", version="0"))
        )
        gateway = GovernedGateway(cfg, downstream)
        server = gateway.build_server()
        host_a = await stack.enter_async_context(
            connect(server, client_info=types.Implementation(name="claude-code", version="1"))
        )
        host_b = await stack.enter_async_context(
            connect(server, client_info=types.Implementation(name="claude-desktop", version="1"))
        )
        await host_a.call_tool("write_file", {"path": "a.txt", "content": "ESCALATEME"})
        await host_b.call_tool("write_file", {"path": "b.txt", "content": "ESCALATEME"})

        pend = gateway.pending_ids()
        a_id = next(e for e in pend if gateway._pending[e].record.actor == _PRINCIPAL)
        b_id = next(e for e in pend if gateway._pending[e].record.actor == _PRINCIPAL_DESKTOP)

        # Approve BOTH with their own validated approvals, then present actor A's
        # approval receipt to resume actor B's pending. The gate pins
        # expected_actor=B and expected_audit_hash=B's approval hash, so A's
        # receipt is refused fail-closed (actor / audit-hash mismatch).
        receipt_a = gateway.approve(a_id, validator=cfg.validator)
        gateway.approve(b_id, validator=cfg.validator)
        with pytest.raises(ReceiptValidationError):
            await gateway.resume(b_id, receipt_a)
        assert calls == []  # no cross-actor side effect


# --------------------------------------------------------------------------- #
# 1d. Bounded-capacity back-pressure: once the escalation cap is full, a new
#     ESCALATE is refused fail-closed (audited DENY, not parked, no forward),
#     while the already-parked escalations remain individually resumable.
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_pending_capacity_backpressure(tmp_path: Path) -> None:
    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    # Small caps so the (N+1)th escalation trips the global cap.
    cfg = replace(_config(tmp_path), max_pending=2, max_pending_per_principal=2)
    async with AsyncExitStack() as stack:
        downstream = await stack.enter_async_context(
            connect(fixture, client_info=types.Implementation(name="gw", version="0"))
        )
        gateway = GovernedGateway(cfg, downstream)
        server = gateway.build_server()
        host = await stack.enter_async_context(
            connect(server, client_info=types.Implementation(name="claude-code", version="1"))
        )

        # Park N=2 escalations (fills the cap).
        await host.call_tool("write_file", {"path": "p1.txt", "content": "ESCALATEME"})
        await host.call_tool("write_file", {"path": "p2.txt", "content": "ESCALATEME"})
        assert len(gateway.pending_ids()) == 2

        # (N+1)th ESCALATE → fail-closed capacity rejection.
        result = await host.call_tool("write_file", {"path": "p3.txt", "content": "ESCALATEME"})
        assert result.isError is True
        assert result.structuredContent is not None
        assert result.structuredContent["decision"] == "deny"
        assert len(gateway.pending_ids()) == 2  # not parked
        assert calls == []  # no downstream side effect

        # The rejection is EVIDENCED, never a silent drop.
        recs = _audit_records(cfg.audit_path)
        assert any(r["matched_rules"] == ["CAPACITY_REJECTED:pending"] for r in recs)

        # The already-parked pendings remain individually resumable.
        e0 = gateway.pending_ids()[0]
        receipt = gateway.approve(e0, validator=cfg.validator)
        run = await gateway.resume(e0, receipt)
        assert run.isError is False
        assert len(calls) == 1  # exactly the one resumed escalation forwarded
