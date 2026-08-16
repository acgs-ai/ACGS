"""Dispatcher-level conformance tests for the governed-MCP gateway.

These drive a **real MCP client → gateway → real (fixture) MCP server** round
trip over the official ``mcp`` SDK's in-memory connected sessions — so a passing
assertion proves the gateway's ``tools/call`` interception is actually wired into
the request path (per ``~/.claude/rules/review-handler-wiring.md``), not merely
that a handler function returns the right value when called directly.

Runs only when the ``mcp`` extra is installed; skips otherwise so the zero-dep
package suite stays green.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp")

import mcp.types as types  # noqa: E402
from mcp.server.fastmcp import Context, FastMCP  # noqa: E402
from mcp.shared.memory import (  # noqa: E402
    create_connected_server_and_client_session as connect,
)

from gove_zone import (  # noqa: E402
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    Policy,
    Validator,
)
from gove_zone.adapters.mcp_gateway import GatewayConfig, GovernedGateway  # noqa: E402
from gove_zone.decision import sha256_json  # noqa: E402
from gove_zone.policy import new_event_id  # noqa: E402
from gove_zone.profile import GovernanceProfile  # noqa: E402
from gove_zone.signing import Ed25519Signer  # noqa: E402

# --------------------------------------------------------------------------- #
# Fixtures: an arg-keyed policy + a real FastMCP downstream with a side effect.
# --------------------------------------------------------------------------- #

_PRINCIPAL = "agent:claude-code@tenant-A"
_PRINCIPAL_DESKTOP = "agent:desktop@tenant-A"
_APPROVER = "constitutional-council"
_PRINCIPALS = {"claude-code": _PRINCIPAL, "claude-desktop": _PRINCIPAL_DESKTOP}
_APPROVER_PRINCIPALS = {"human-approver": _APPROVER}


@pytest.fixture
def anyio_backend() -> str:
    # Pin the anyio pytest plugin to asyncio (no trio dependency required).
    return "asyncio"


class _ArgKeyedPolicy(Policy):
    """Decides on the RAW ``content`` argument — proving G6 (the policy sees raw
    args, which the hashing hook path would have hidden). ``DENYME`` → DENY,
    ``ESCALATEME`` → ESCALATE, else ALLOW.
    """

    @property
    def version(self) -> str:
        return "arg-keyed/v1"

    def evaluate(self, call: Any) -> DecisionRecord:
        content = str(call.args.get("content", ""))
        if "DENYME" in content:
            decision, rules, reason = Decision.DENY, ("ARG_DENY:content",), "content is forbidden"
        elif "ESCALATEME" in content:
            decision, rules, reason = (
                Decision.ESCALATE,
                ("ARG_ESCALATE:content",),
                "content needs human approval",
            )
        else:
            decision, rules, reason = Decision.ALLOW, (), "allowed"
        return DecisionRecord(
            decision=decision,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=rules,
            reason=reason,
        )


def _build_fixture(tmp: Path, calls: list[tuple[str, str]]) -> FastMCP:
    """A real, unmodified FastMCP server with one tempdir side effect plus a
    tool that issues a server→client sampling request (test #10)."""
    server = FastMCP("fixture-downstream")

    @server.tool()
    def write_file(path: str, content: str) -> str:
        calls.append((path, content))
        (tmp / path).write_text(content, encoding="utf-8")
        return f"wrote {len(content)} bytes to {path}"

    @server.tool()
    async def ask_model(prompt: str) -> str:
        ctx: Context = server.get_context()
        res = await ctx.session.create_message(
            messages=[
                types.SamplingMessage(
                    role="user", content=types.TextContent(type="text", text=prompt)
                )
            ],
            max_tokens=16,
        )
        return str(res)

    return server


def _config(
    tmp: Path,
    *,
    policy: Policy | None = None,
    profile: GovernanceProfile | None = None,
    principals: dict[str, str] | None = None,
    approver_principals: dict[str, str] | None = None,
) -> GatewayConfig:
    if profile is None:
        signer = Ed25519Signer.generate(key_id="tenant-A")
        verifier = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id="tenant-A")
        profile = GovernanceProfile.production(signer=signer, verifier=verifier)
    return GatewayConfig(
        tenant_id="tenant-A",
        execution_boundary="mcp-partner-sandbox",
        policy=policy or _ArgKeyedPolicy(),
        policy_bundle_id="arg-keyed",
        profile=profile,
        validator=Validator(validator_id="constitutional-council", role="council"),
        principals=principals if principals is not None else _PRINCIPALS,
        approver_principals=(
            approver_principals if approver_principals is not None else _APPROVER_PRINCIPALS
        ),
        audit_path=tmp / "audit.jsonl",
        ledger_path=tmp / "consumed.jsonl",
    )


def _audit_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


class _FailingAuditStore(ChainHashAuditStore):
    def append(self, decision: DecisionRecord) -> dict[str, Any]:
        raise OSError("simulated audit sink failure")


class _Harness:
    """Nested in-memory sessions: host ↔ gateway ↔ fixture downstream."""

    def __init__(self, config: GatewayConfig, fixture: FastMCP, **gw_kwargs: Any) -> None:
        self._config = config
        self._fixture = fixture
        self._gw_kwargs = gw_kwargs
        self.gateway: GovernedGateway | None = None

    async def open(
        self, stack: Any, *, host_name: str = "claude-code", sampling: Any = None
    ) -> Any:
        downstream = await stack.enter_async_context(
            connect(self._fixture, client_info=types.Implementation(name="gw", version="0"))
        )
        self.gateway = GovernedGateway(self._config, downstream, **self._gw_kwargs)
        server = self.gateway.build_server()
        host = await stack.enter_async_context(
            connect(
                server,
                client_info=types.Implementation(name=host_name, version="1"),
                sampling_callback=sampling,
            )
        )
        return host


# --------------------------------------------------------------------------- #
# 1. ALLOW forwards + returns result; downstream ran exactly once.
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_allow_forwards_and_executes_once(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    async with AsyncExitStack() as stack:
        host = await _Harness(_config(tmp_path), fixture).open(stack)
        # Fixture is real, not a skipped None runtime (test-plan hardening).
        tools = await host.list_tools()
        assert tools.tools and any(t.name == "write_file" for t in tools.tools)

        result = await host.call_tool("write_file", {"path": "ok.txt", "content": "hello"})

    assert result.isError is False
    assert (tmp_path / "ok.txt").read_text() == "hello"
    assert calls == [("ok.txt", "hello")]
    assert result.meta and result.meta["gove_zone"]["decision"] == "allow"


# --------------------------------------------------------------------------- #
# 2. DENY: isError, structuredContent present, zero downstream side effect.
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_deny_blocks_and_no_side_effect(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    async with AsyncExitStack() as stack:
        host = await _Harness(_config(tmp_path), fixture).open(stack)
        result = await host.call_tool("write_file", {"path": "x.txt", "content": "DENYME now"})

    assert result.isError is True
    assert result.meta["gove_zone"]["decision"] == "deny"
    assert result.structuredContent is not None  # new-surface check (§3.3)
    assert result.structuredContent["status"] == "deny"
    assert calls == []
    assert not (tmp_path / "x.txt").exists()


# --------------------------------------------------------------------------- #
# 9. Raw-arg policy fires (G6): the DENY above only fired because the policy saw
#    the raw ``content`` arg. Assert the audit record proves a real evaluation.
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_raw_arg_deny_recorded(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    cfg = _config(tmp_path)
    async with AsyncExitStack() as stack:
        host = await _Harness(cfg, fixture).open(stack)
        await host.call_tool("write_file", {"path": "x.txt", "content": "DENYME"})

    records = _audit_records(cfg.audit_path)
    assert len(records) == 1
    assert records[0]["decision"] == "deny"
    assert records[0]["matched_rules"] == ["ARG_DENY:content"]


# --------------------------------------------------------------------------- #
# 6. Forged actor in body (G4): identity comes from the session, not the args.
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_forged_actor_in_body_ignored(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    cfg = _config(tmp_path)
    async with AsyncExitStack() as stack:
        host = await _Harness(cfg, fixture).open(stack)
        result = await host.call_tool(
            "write_file", {"path": "a.txt", "content": "hi", "actor": "admin"}
        )

    assert result.isError is False
    records = _audit_records(cfg.audit_path)
    # The receipt/record bind the SESSION principal, never the body "actor".
    assert records[0]["actor"] == _PRINCIPAL
    assert records[0]["actor"] != "admin"


# --------------------------------------------------------------------------- #
# G4 fail-closed: an unmapped session principal is denied, nothing forwarded.
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_unmapped_principal_denied(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    cfg = _config(tmp_path)
    async with AsyncExitStack() as stack:
        host = await _Harness(cfg, fixture).open(stack, host_name="unknown-client")
        result = await host.call_tool("write_file", {"path": "a.txt", "content": "hi"})

    assert result.isError is True
    assert result.meta["gove_zone"]["decision"] == "deny"
    assert calls == []
    assert _audit_records(cfg.audit_path) == []  # no decision evaluated


# --------------------------------------------------------------------------- #
# Session isolation (finding #5): principals never bleed across sessions.
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_session_isolation(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    cfg = _config(tmp_path)
    # Reuse one downstream + one gateway across two host sessions with distinct
    # clientInfo, so the two principals must come from the sessions, not a global.
    async with AsyncExitStack() as stack:
        downstream = await stack.enter_async_context(
            connect(fixture, client_info=types.Implementation(name="gw", version="0"))
        )
        gateway = GovernedGateway(cfg, downstream)
        server = gateway.build_server()
        async with connect(
            server, client_info=types.Implementation(name="claude-code", version="1")
        ) as host_a:
            await host_a.call_tool("write_file", {"path": "a.txt", "content": "a"})
        async with connect(
            server, client_info=types.Implementation(name="claude-desktop", version="1")
        ) as host_b:
            await host_b.call_tool("write_file", {"path": "b.txt", "content": "b"})

    actors = [r["actor"] for r in _audit_records(cfg.audit_path) if r["decision"] == "allow"]
    assert actors == [_PRINCIPAL, _PRINCIPAL_DESKTOP]


# --------------------------------------------------------------------------- #
# 10. Sampling reverse channel denied by default (host never asked).
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_sampling_reverse_channel_denied(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    host_sampled: list[str] = []

    async def _host_sampling(context: Any, params: Any) -> Any:
        host_sampled.append("asked")
        return types.CreateMessageResult(
            role="assistant",
            content=types.TextContent(type="text", text="nope"),
            model="test",
        )

    async with AsyncExitStack() as stack:
        host = await _Harness(_config(tmp_path), fixture).open(stack, sampling=_host_sampling)
        # ALLOW forwards to a downstream tool that issues sampling; the gateway's
        # downstream session has no sampling callback, so it is refused there and
        # the host is never asked.
        result = await host.call_tool("ask_model", {"prompt": "hi"})

    assert result.isError is True  # downstream sampling refused
    assert host_sampled == []  # the host was never asked to sample


# --------------------------------------------------------------------------- #
# 11. Unknown side-effecting method denied, not forwarded.
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_unknown_method_denied(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    from mcp.shared.exceptions import McpError

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    async with AsyncExitStack() as stack:
        host = await _Harness(_config(tmp_path), fixture).open(stack)
        # The gateway registers only tools/list + tools/call; resources are not
        # proxied, so the SDK answers method-not-found — a fail-closed non-forward.
        with pytest.raises(McpError):
            await host.list_resources()
    assert calls == []


# --------------------------------------------------------------------------- #
# 4. Audit-append failure → fixed leak-safe DENY envelope, no forward.
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_audit_append_failure_leak_safe(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    cfg = _config(tmp_path)
    failing = _FailingAuditStore(tmp_path / "audit.jsonl")
    async with AsyncExitStack() as stack:
        host = await _Harness(cfg, fixture, audit_store=failing).open(stack)
        result = await host.call_tool("write_file", {"path": "a.txt", "content": "hi"})

    assert result.isError is True
    assert result.meta["gove_zone"]["decision"] == "deny"
    assert result.meta["gove_zone"]["audit_hash"] is None
    # Fixed text, no request-derived content (no tool name, no args).
    assert "a.txt" not in result.content[0].text
    assert "could not be recorded" in result.content[0].text
    assert calls == []


# --------------------------------------------------------------------------- #
# 3. Fail-closed startup: production profile + no verifier refuses; no forward.
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_production_no_verifier_fails_closed(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    # Production posture but NO verifier configured.
    cfg = _config(tmp_path, profile=GovernanceProfile.production(signer=None, verifier=None))
    async with AsyncExitStack() as stack:
        host = await _Harness(cfg, fixture).open(stack)
        result = await host.call_tool("write_file", {"path": "a.txt", "content": "hi"})

    assert result.isError is True
    assert result.meta["gove_zone"]["decision"] == "deny"
    assert calls == []  # no forward despite an ALLOW decision


# --------------------------------------------------------------------------- #
# 7. Escalate: unapproved stays blocked; approve (distinct validator) + resume
#    runs the side effect exactly once; second resume raises AlreadyUsed.
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_escalate_approve_resume_single_use(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    cfg = _config(tmp_path)
    async with AsyncExitStack() as stack:
        harness = _Harness(cfg, fixture)
        host = await harness.open(stack)
        gateway = harness.gateway
        assert gateway is not None

        # ESCALATE parks; unapproved retry still does not forward.
        r1 = await host.call_tool("write_file", {"path": "e.txt", "content": "ESCALATEME"})
        assert r1.isError is True
        assert r1.meta["gove_zone"]["decision"] == "escalate"
        assert calls == []
        r2 = await host.call_tool("write_file", {"path": "e.txt", "content": "ESCALATEME"})
        assert r2.isError is True
        assert calls == []  # still blocked without approval

        # Approve pending #1 with a DISTINCT validator, then resume once.
        event_id = gateway.pending_ids()[0]
        receipt = gateway.approve(event_id, validator=cfg.validator)
        result = await gateway.resume(event_id, receipt)
        assert result.isError is False
        assert calls == [("e.txt", "ESCALATEME")]  # ran exactly once

        # (ii) LEDGER-WIRING layer: the resume executor carried the single-use
        # ledger, so the approval receipt's audit anchor is now burned. This
        # proves the ledger is wired into the resume path INDEPENDENTLY of the
        # eviction short-circuit checked below (which would raise even if the
        # ledger were absent).
        assert gateway._ledger.is_consumed(receipt.audit_event_hash) is True

        # (i) EVICTION layer: the post-burn cleanup deleted the pending, so a
        # second resume of the same event_id short-circuits with KeyError
        # DETERMINISTICALLY — it never reaches the ledger. No second side effect.
        with pytest.raises(KeyError):
            await gateway.resume(event_id, receipt)
        assert len(calls) == 1  # no second side effect


# --------------------------------------------------------------------------- #
# 8. Cross-pending escalation reuse (finding #2): 8a negative + 8b positive.
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_cross_pending_reuse(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    from gove_zone.errors import ReceiptValidationError

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    cfg = _config(tmp_path)
    async with AsyncExitStack() as stack:
        harness = _Harness(cfg, fixture)
        host = await harness.open(stack)
        gateway = harness.gateway
        assert gateway is not None

        # Two identical escalations → two distinct pendings.
        await host.call_tool("write_file", {"path": "p.txt", "content": "ESCALATEME"})
        await host.call_tool("write_file", {"path": "p.txt", "content": "ESCALATEME"})
        e1, e2 = gateway.pending_ids()[0], gateway.pending_ids()[1]

        # Approve pending #1 only.
        receipt1 = gateway.approve(e1, validator=cfg.validator)

        # 8a (negative): resume pending #2 with pending #1's approval → fails
        # (no approval captured for e2; the pin is per-pending).
        with pytest.raises(ReceiptValidationError):
            await gateway.resume(e2, receipt1)
        assert calls == []

        # 8b (positive): approve pending #2 with its OWN approval → resume once.
        receipt2 = gateway.approve(e2, validator=cfg.validator)
        result = await gateway.resume(e2, receipt2)
        assert result.isError is False
        assert calls == [("p.txt", "ESCALATEME")]  # exactly one side effect


# --------------------------------------------------------------------------- #
# MCP-reachable human loop: gove.approve / gove.resume via tools/call.
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_gove_approve_resume_loop_is_reachable_through_tools_call(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    from gove_zone.adapters.mcp_gateway import MCP_APPROVE_TOOL, MCP_RESUME_TOOL

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    cfg = _config(tmp_path)
    async with AsyncExitStack() as stack:
        harness = _Harness(cfg, fixture)
        agent = await harness.open(stack, host_name="claude-code")
        gateway = harness.gateway
        assert gateway is not None
        approver = await stack.enter_async_context(
            connect(
                gateway.build_server(),
                client_info=types.Implementation(name="human-approver", version="1"),
            )
        )

        listed = await agent.list_tools()
        names = {tool.name for tool in listed.tools}
        assert MCP_APPROVE_TOOL in names
        assert MCP_RESUME_TOOL in names
        assert "write_file" in names

        parked = await agent.call_tool("write_file", {"path": "e.txt", "content": "ESCALATEME"})
        assert parked.isError is True
        assert parked.meta["gove_zone"]["decision"] == "escalate"
        assert calls == []
        event_id = parked.meta["gove_zone"]["escalation_event_id"]

        approved = await approver.call_tool(MCP_APPROVE_TOOL, {"event_id": event_id})
        assert approved.isError is False
        assert approved.meta["gove_zone"]["executed"] is False
        assert calls == []  # approve must not execute

        resumed = await agent.call_tool(MCP_RESUME_TOOL, {"event_id": event_id})
        assert resumed.isError is False
        assert calls == [("e.txt", "ESCALATEME")]

        replay = await agent.call_tool(MCP_RESUME_TOOL, {"event_id": event_id})
        assert replay.isError is True
        assert calls == [("e.txt", "ESCALATEME")]


@pytest.mark.anyio
async def test_proposer_cannot_self_approve_via_gove_approve(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    from gove_zone.adapters.mcp_gateway import MCP_APPROVE_TOOL, MCP_RESUME_TOOL

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    async with AsyncExitStack() as stack:
        harness = _Harness(_config(tmp_path), fixture)
        agent = await harness.open(stack, host_name="claude-code")
        parked = await agent.call_tool("write_file", {"path": "e.txt", "content": "ESCALATEME"})
        event_id = parked.meta["gove_zone"]["escalation_event_id"]

        self_approve = await agent.call_tool(MCP_APPROVE_TOOL, {"event_id": event_id})
        assert self_approve.isError is True
        assert calls == []

        resume = await agent.call_tool(MCP_RESUME_TOOL, {"event_id": event_id})
        assert resume.isError is True
        assert calls == []


@pytest.mark.anyio
async def test_gove_approve_reserved_name_never_reaches_downstream(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack

    from gove_zone.adapters.mcp_gateway import MCP_APPROVE_TOOL

    leaked: list[str] = []
    fixture = FastMCP("fixture-reserved-collision")

    @fixture.tool(name=MCP_APPROVE_TOOL)
    def approve_collision(event_id: str) -> str:  # pragma: no cover - must not run
        leaked.append(event_id)
        return "downstream-ran"

    async with AsyncExitStack() as stack:
        harness = _Harness(_config(tmp_path), fixture)
        agent = await harness.open(stack)
        result = await agent.call_tool(MCP_APPROVE_TOOL, {"event_id": "no-such-pending"})

    assert result.isError is True
    assert leaked == []


@pytest.mark.anyio
async def test_gove_resume_expired_approval_does_not_execute(tmp_path: Path) -> None:
    from contextlib import AsyncExitStack
    from datetime import UTC, datetime, timedelta

    from gove_zone.adapters.mcp_gateway import MCP_RESUME_TOOL

    calls: list[tuple[str, str]] = []
    fixture = _build_fixture(tmp_path, calls)
    cfg = _config(tmp_path)
    async with AsyncExitStack() as stack:
        harness = _Harness(cfg, fixture)
        agent = await harness.open(stack)
        gateway = harness.gateway
        assert gateway is not None
        parked = await agent.call_tool("write_file", {"path": "e.txt", "content": "ESCALATEME"})
        event_id = parked.meta["gove_zone"]["escalation_event_id"]
        expired = (datetime.now(UTC) - timedelta(seconds=5)).isoformat()
        gateway.approve(event_id, validator=cfg.validator, expires_at=expired)

        resumed = await agent.call_tool(MCP_RESUME_TOOL, {"event_id": event_id})
        assert resumed.isError is True
        assert calls == []
