"""Strict-profile conformance for the governed-MCP gateway adapter.

Regression suite for the ``consumption_ledger`` double-keyword defect: the
gateway passed ``consumption_ledger=self._ledger`` explicitly *and* splatted
``**profile.as_gate_kwargs()`` — which under
:meth:`~gove_zone.profile.GovernanceProfile.production_strict` also emits
``consumption_ledger`` — so every governed call raised ``TypeError`` and the
one profile documented as the hardened anti-replay posture could not run
through the gateway at all (same class of bug fixed in the ``mcp_gateway``
package, PR #223).

Like the conformance suite, these tests drive a real MCP client → gateway →
fixture MCP server round trip over the SDK's in-memory sessions. Runs only
when the ``mcp`` extra is installed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp")
pytest.importorskip("cryptography")

import mcp.types as types  # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.shared.memory import (  # noqa: E402
    create_connected_server_and_client_session as connect,
)

from gove_zone import Validator  # noqa: E402
from gove_zone.adapters.mcp_gateway import GatewayConfig, GovernedGateway  # noqa: E402
from gove_zone.consumption import ReceiptConsumptionLedger  # noqa: E402
from gove_zone.policy import AllowAllPolicy  # noqa: E402
from gove_zone.profile import GovernanceProfile  # noqa: E402
from gove_zone.signing import Ed25519Signer  # noqa: E402

_PRINCIPALS = {"claude-code": "agent:claude-code@tenant-A"}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _fixture_server(tmp: Path, calls: list[str]) -> FastMCP:
    server = FastMCP("downstream-fixture")

    @server.tool()
    def write_file(path: str, content: str) -> str:
        target = tmp / path
        target.write_text(content, encoding="utf-8")
        calls.append(path)
        return f"wrote {len(content)} bytes to {path}"

    return server


def _strict_pieces(tmp: Path) -> tuple[GovernanceProfile, ReceiptConsumptionLedger]:
    signer = Ed25519Signer.generate(key_id="tenant-A")
    verifier = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id="tenant-A")
    ledger = ReceiptConsumptionLedger(tmp / "strict-consumed.jsonl")
    profile = GovernanceProfile.production_strict(
        verifier=verifier, consumption_ledger=ledger, signer=signer
    )
    return profile, ledger


def _config(tmp: Path, profile: GovernanceProfile, **overrides: Any) -> GatewayConfig:
    config: dict[str, Any] = dict(
        tenant_id="tenant-A",
        execution_boundary="mcp-partner-sandbox",
        policy=AllowAllPolicy(),
        policy_bundle_id="allow-all",
        profile=profile,
        validator=Validator(validator_id="constitutional-council", role="council"),
        principals=_PRINCIPALS,
        audit_path=tmp / "audit.jsonl",
        ledger_path=tmp / "consumed.jsonl",
    )
    config.update(overrides)
    return GatewayConfig(**config)


async def _call_through_gateway(
    tmp: Path, config: GatewayConfig, calls: list[str]
) -> types.CallToolResult:
    from contextlib import AsyncExitStack

    fixture = _fixture_server(tmp, calls)
    async with AsyncExitStack() as stack:
        downstream = await stack.enter_async_context(
            connect(fixture, client_info=types.Implementation(name="gw", version="0"))
        )
        gateway = GovernedGateway(config, downstream)
        server = gateway.build_server()
        host = await stack.enter_async_context(
            connect(server, client_info=types.Implementation(name="claude-code", version="1"))
        )
        return await host.call_tool("write_file", {"path": "out.txt", "content": "hello"})


@pytest.mark.anyio
async def test_production_strict_forwards_through_the_gate(tmp_path: Path) -> None:
    """The hardened posture actually runs: signed receipt + single-use ledger +
    TTL, one downstream execution. Pre-fix this raised TypeError (duplicate
    consumption_ledger keyword) on every governed call."""
    calls: list[str] = []
    profile, _ledger = _strict_pieces(tmp_path)
    config = _config(tmp_path, profile, receipt_ttl_seconds=3600.0)

    result = await _call_through_gateway(tmp_path, config, calls)

    assert result.isError is False
    assert calls == ["out.txt"]
    assert (tmp_path / "out.txt").read_text(encoding="utf-8") == "hello"


@pytest.mark.anyio
async def test_production_strict_without_ttl_fails_closed(tmp_path: Path) -> None:
    """Strict requires expiry; a TTL-less gateway mints non-expiring receipts,
    so the gate refuses them — an error result, never a silent forward."""
    calls: list[str] = []
    profile, _ledger = _strict_pieces(tmp_path)
    config = _config(tmp_path, profile)  # receipt_ttl_seconds unset

    result = await _call_through_gateway(tmp_path, config, calls)

    assert result.isError is True
    assert calls == []
    assert not (tmp_path / "out.txt").exists()


@pytest.mark.anyio
async def test_ambiguous_double_ledger_rejected_at_construction(tmp_path: Path) -> None:
    """A strict profile's ledger plus a different injected ledger is a config
    error, refused before any traffic."""
    from contextlib import AsyncExitStack

    profile, _ledger = _strict_pieces(tmp_path)
    config = _config(tmp_path, profile, receipt_ttl_seconds=3600.0)
    other = ReceiptConsumptionLedger(tmp_path / "other-consumed.jsonl")

    async with AsyncExitStack() as stack:
        downstream = await stack.enter_async_context(
            connect(
                _fixture_server(tmp_path, []),
                client_info=types.Implementation(name="gw", version="0"),
            )
        )
        with pytest.raises(ValueError, match="ambiguous consumption ledger"):
            GovernedGateway(config, downstream, ledger=other)


@pytest.mark.anyio
async def test_gate_kwargs_carry_exactly_the_profile_ledger(tmp_path: Path) -> None:
    """Under strict, the gate uses the profile's ledger (one source of truth);
    under plain production, the gateway's own ledger fills the gap."""
    from contextlib import AsyncExitStack

    async with AsyncExitStack() as stack:
        downstream = await stack.enter_async_context(
            connect(
                _fixture_server(tmp_path, []),
                client_info=types.Implementation(name="gw", version="0"),
            )
        )
        strict_profile, strict_ledger = _strict_pieces(tmp_path)
        strict_gw = GovernedGateway(
            _config(tmp_path, strict_profile, receipt_ttl_seconds=3600.0), downstream
        )
        kwargs = strict_gw._gate_kwargs()
        assert kwargs["consumption_ledger"] is strict_ledger

        signer = Ed25519Signer.generate(key_id="tenant-B")
        verifier = Ed25519Signer.from_public_bytes(signer.public_bytes(), key_id="tenant-B")
        plain_profile = GovernanceProfile.production(signer=signer, verifier=verifier)
        own = ReceiptConsumptionLedger(tmp_path / "own-consumed.jsonl")
        plain_gw = GovernedGateway(_config(tmp_path, plain_profile), downstream, ledger=own)
        kwargs = plain_gw._gate_kwargs()
        assert kwargs["consumption_ledger"] is own
