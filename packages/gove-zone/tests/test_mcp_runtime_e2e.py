"""Official-client E2E tests for Remote HTTP and outer stdio P1 entrypoints."""

from __future__ import annotations

import base64
import json
import os
import signal
import socket
import ssl
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import McpError

from gove_zone.authorization import ExecutionRefusalEvidence
from gove_zone.mcp_runtime import (
    RemoteIdentityTrust,
    RemoteMCPBudgets,
    RemoteMCPConfig,
    RemoteMCPConfigError,
    RemoteReadiness,
    build_remote_app,
    build_remote_uvicorn_config,
    remote_tls_snapshot,
)

_TOKEN = "inbound-fixture-token"
_SESSION = "fixture-session"
#: Readiness is an operator signal, so it answers only its own peer.
_ADMIN_PEER = ("127.0.0.1", 54321)
_PUBLIC_PEER = ("203.0.113.7", 51234)
_REFERENCE_STDIO_SCRIPT = """
import sys
from pathlib import Path
import anyio
from gove_zone.mcp_reference import create_reference_runtime
from gove_zone.mcp_runtime import build_mcp_server, read_secret_file, run_stdio_server

async def serve():
    token = read_secret_file(Path(sys.argv[2]))
    runtime = await create_reference_runtime(
        Path(sys.argv[1]),
        inbound_token=token,
        session_id=sys.argv[3],
        catalog_mode=sys.argv[4],
    )
    try:
        server = build_mcp_server(
            runtime.gateway,
            stdio_token=token,
            stdio_session_id=sys.argv[3],
        )
        await run_stdio_server(server)
    finally:
        await runtime.aclose()

anyio.run(serve)
"""


def _token_file(tmp_path: Path) -> Path:
    path = tmp_path / "token"
    path.write_text(_TOKEN + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _authorization(nonce: str, idempotency: str) -> dict[str, Any]:
    return {
        "io.acgs/authorization": {
            "nonce": nonce,
            "idempotencyKey": idempotency,
            "requestedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "evidence": [],
            "goal": "write one deterministic local fixture record",
        }
    }


def _ledger(state: Path) -> list[dict[str, Any]]:
    path = state / "fixture-ledger.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _process_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


async def _fixture_pid(state: Path) -> int:
    path = state / "fixture.pid"
    for _ in range(100):
        if path.exists():
            return int(path.read_text(encoding="utf-8").strip())
        await anyio.sleep(0.05)
    raise RuntimeError("fixture PID was not recorded")


async def _wait_for_process_exit(pid: int) -> None:
    for _ in range(100):
        if not _process_is_alive(pid):
            return
        await anyio.sleep(0.05)
    raise RuntimeError(f"fixture process {pid} was not reaped")


def _stdio_parameters(tmp_path: Path) -> tuple[StdioServerParameters, Path]:
    state = tmp_path / "stdio-state"
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "gove_zone.cli",
            "mcp",
            "serve-stdio",
            "--state-dir",
            str(state),
            "--token-file",
            str(_token_file(tmp_path)),
            "--session-id",
            _SESSION,
        ],
        cwd=str(Path.cwd()),
    )
    return params, state


def _poison_stdio_parameters(tmp_path: Path) -> tuple[StdioServerParameters, Path]:
    state = tmp_path / "poison-stdio-state"
    token_file = _token_file(tmp_path)
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-c",
            _REFERENCE_STDIO_SCRIPT,
            str(state),
            str(token_file),
            _SESSION,
            "poison-description",
        ],
        cwd=str(Path.cwd()),
    )
    return params, state


def test_outer_stdio_allow_missing_receipt_and_replay_are_end_to_end(tmp_path: Path) -> None:
    async def run() -> None:
        params, state = _stdio_parameters(tmp_path)
        assert _TOKEN not in repr(params.args)
        async with stdio_client(params) as streams, ClientSession(*streams) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert [tool.name for tool in tools.tools] == [
                "fixture.write_once",
                "fixture.ambiguous_write",
                "fixture.read",
            ]

            missing = await session.call_tool("fixture.write_once", {"record": "blocked"})
            assert missing.isError is True
            assert missing.meta is not None
            refusal = missing.meta["io.acgs/decision"]
            assert refusal["decision"] == "deny"
            assert refusal["refusalEvidence"]["signed"] is True
            assert _ledger(state) == []

            metadata = _authorization("nonce-stdio-1", "idempotency-stdio-1")
            allowed = await session.call_tool(
                "fixture.write_once",
                {"record": "stdio-allowed"},
                meta=metadata,
            )
            assert allowed.isError is False
            assert allowed.meta is not None
            decision = allowed.meta["io.acgs/decision"]
            assert decision["status"] == "succeeded"
            assert decision["receipt"]["decision"] == "allow"

            replay = await session.call_tool(
                "fixture.write_once",
                {"record": "stdio-allowed"},
                meta=metadata,
            )
            assert replay.isError is True
            assert replay.meta is not None
            assert replay.meta["io.acgs/decision"]["status"] == "failed_closed"

            changed_arguments = await session.call_tool(
                "fixture.write_once",
                {"record": "changed-after-approval"},
                meta=metadata,
            )
            assert changed_arguments.isError is True
            assert changed_arguments.meta is not None
            assert changed_arguments.meta["io.acgs/decision"]["status"] == "failed_closed"

            changed_tool = await session.call_tool(
                "fixture.read",
                {},
                meta=metadata,
            )
            assert changed_tool.isError is True
            assert changed_tool.meta is not None
            assert changed_tool.meta["io.acgs/decision"]["status"] == "failed_closed"
            assert _ledger(state) == [{"record": "stdio-allowed"}]
            assert _jsonl(state / "fixture-calls.jsonl") == [{"tool": "fixture.write_once"}]

            decisions = [
                missing.meta["io.acgs/decision"],
                allowed.meta["io.acgs/decision"],
                replay.meta["io.acgs/decision"],
                changed_arguments.meta["io.acgs/decision"],
                changed_tool.meta["io.acgs/decision"],
            ]
            audit = {item["event_id"]: item for item in _jsonl(state / "audit.jsonl")}
            side = {item["event_id"]: item for item in _jsonl(state / "replay.jsonl")}
            assert decisions[0]["auditEventId"] in audit
            assert decisions[0]["auditEventId"] not in side
            for decision in decisions[1:]:
                event_id = decision["auditEventId"]
                assert event_id in audit
                assert event_id in side
                assert side[event_id]["event_id"] == audit[event_id]["event_id"]
                assert side[event_id]["argument_hash"] == audit[event_id]["argument_hash"]
                assert side[event_id]["decision"] == audit[event_id]["decision"]

            serialized = repr([missing, allowed, replay, changed_arguments, changed_tool])
            assert _TOKEN not in serialized
            assert "fixture-downstream-secret" not in serialized
            assert "nonce-stdio-1" not in serialized
            assert "idempotency-stdio-1" not in serialized

    anyio.run(run)


def test_outer_stdio_replay_exposes_verifiable_execution_refusal_to_the_client(
    tmp_path: Path,
) -> None:
    """The official client must receive the executor's own proof, whole and verifiable.

    A replayed call is refused at the execution gate, so the response carries
    execution refusal evidence that is bound to the exact receipted attempt.
    That evidence has to survive the wire intact and re-verify against the audit
    chain on its own, without being conflated with the authorization's record.
    """

    async def run() -> None:
        params, state = _stdio_parameters(tmp_path)
        async with stdio_client(params) as streams, ClientSession(*streams) as session:
            await session.initialize()
            await session.list_tools()
            metadata = _authorization("nonce-refusal-e2e", "idempotency-refusal-e2e")
            allowed = await session.call_tool(
                "fixture.write_once",
                {"record": "refusal-e2e"},
                meta=metadata,
            )
            assert allowed.isError is False

            replay = await session.call_tool(
                "fixture.write_once",
                {"record": "refusal-e2e"},
                meta=metadata,
            )

            assert replay.isError is True
            assert replay.meta is not None
            decision = replay.meta["io.acgs/decision"]
            assert decision["status"] == "failed_closed"
            assert decision["executed"] is False

            # The full evidence is consumer-visible, not a summary of it.
            wire = decision["executionRefusalEvidence"]
            assert wire["reason_code"] == decision["reasonCodes"][0]
            assert wire["reason_code"] in {
                "execution.replay",
                "execution.reservation_failed",
            }
            assert wire["adapter_invoked"] is False
            assert decision["executionRefusalAudited"] is True
            assert decision["executionRefusalSigned"] is wire["signed"]

            # The execution refusal's audit record is its own, not the
            # authorization's: conflating them would leave the consumer
            # verifying the wrong event.
            refusal_event_id = decision["executionRefusalAuditEventId"]
            assert refusal_event_id == wire["audit_event_id"]
            assert refusal_event_id != decision["auditEventId"]

            # Independently verifiable: the wire evidence re-derives from the
            # audit record itself, with no help from the response that carried it.
            audit = {item["event_id"]: item for item in _jsonl(state / "audit.jsonl")}
            assert refusal_event_id in audit
            record = audit[refusal_event_id]
            assert record["record_kind"] == "execution_refusal"
            assert record["decision"] == "deny"
            rebuilt = ExecutionRefusalEvidence.from_audit_evidence(record["execution_evidence"])
            assert rebuilt.audit_evidence() == record["execution_evidence"]
            assert rebuilt.reason_code.value == wire["reason_code"]
            assert rebuilt.receipt_hash == wire["receipt_hash"]
            assert rebuilt.binding_hash == wire["binding_hash"]
            assert rebuilt.argument_hash == wire["argument_hash"]
            assert rebuilt.attempt_id_digest == wire["attempt_id_digest"]
            assert rebuilt.adapter_invoked is False

            # The refused attempt produced no second side effect.
            assert _ledger(state) == [{"record": "refusal-e2e"}]
            assert _jsonl(state / "fixture-calls.jsonl") == [{"tool": "fixture.write_once"}]
            # And no secret rides along with the proof.
            assert _TOKEN not in repr(decision)
            assert "nonce-refusal-e2e" not in repr(decision)

    anyio.run(run)


def test_ambiguous_stdio_write_is_not_blindly_retried(tmp_path: Path) -> None:
    async def run() -> None:
        params, state = _stdio_parameters(tmp_path)
        async with stdio_client(params) as streams, ClientSession(*streams) as session:
            await session.initialize()
            await session.list_tools()
            result = await session.call_tool(
                "fixture.ambiguous_write",
                {"record": "ambiguous-once"},
                meta=_authorization("nonce-ambiguous", "idempotency-ambiguous"),
            )
            assert result.isError is True
            assert result.meta is not None
            decision = result.meta["io.acgs/decision"]
            assert decision["outcomeUnknown"] is True
            assert decision["retryable"] is False
            assert _ledger(state) == [{"record": "ambiguous-once"}]
            assert _jsonl(state / "fixture-calls.jsonl") == [{"tool": "fixture.ambiguous_write"}]
            event_id = decision["auditEventId"]
            audit = {item["event_id"]: item for item in _jsonl(state / "audit.jsonl")}
            side = {item["event_id"]: item for item in _jsonl(state / "replay.jsonl")}
            assert event_id in audit
            assert event_id in side
            assert side[event_id]["decision"] == audit[event_id]["decision"] == "allow"

    anyio.run(run)


def test_outer_stdio_child_failure_has_no_direct_fallback(tmp_path: Path) -> None:
    async def run() -> None:
        params, state = _stdio_parameters(tmp_path)
        async with stdio_client(params) as streams, ClientSession(*streams) as session:
            await session.initialize()
            await session.list_tools()
            fixture_pid = await _fixture_pid(state)
            os.kill(fixture_pid, 15)
            await _wait_for_process_exit(fixture_pid)

            result = await session.call_tool(
                "fixture.write_once",
                {"record": "must-not-fallback"},
                meta=_authorization("nonce-child-dead", "idempotency-child-dead"),
            )
            assert result.isError is True
            assert result.meta is not None
            decision = result.meta["io.acgs/decision"]
            assert decision["decision"] == "deny"
            assert decision["executed"] is False
            assert decision["refusalEvidence"]["signed"] is True
            assert _ledger(state) == []
            assert _jsonl(state / "fixture-calls.jsonl") == []

    anyio.run(run)


def test_outer_stdio_poisoned_catalog_is_signed_denial_without_write(tmp_path: Path) -> None:
    async def run() -> None:
        params, state = _poison_stdio_parameters(tmp_path)
        assert _TOKEN not in repr(params.args)
        fixture_pid: int
        async with stdio_client(params) as streams, ClientSession(*streams) as session:
            await session.initialize()
            fixture_pid = await _fixture_pid(state)
            denied = await session.call_tool(
                "fixture.write_once",
                {"record": "must-not-run"},
                meta=_authorization("poison-call-nonce", "poison-call-idempotency"),
            )
            assert denied.isError is True
            assert denied.meta is not None
            evidence = denied.meta["io.acgs/decision"]
            assert evidence["decision"] == "deny"
            assert evidence["reasonCodes"] == ["mcp.gateway.catalog_mismatch"]
            assert evidence["refusalEvidence"]["signed"] is True
            assert evidence["auditEventId"] == evidence["refusalEvidence"]["audit_event_id"]
            assert "tools/list" not in repr(denied)
            assert _ledger(state) == []
            assert _jsonl(state / "fixture-calls.jsonl") == []
            audit = {item["event_id"]: item for item in _jsonl(state / "audit.jsonl")}
            assert evidence["auditEventId"] in audit
            assert _TOKEN not in repr(evidence)
            assert "fixture-downstream-secret" not in repr(evidence)
        await _wait_for_process_exit(fixture_pid)

    anyio.run(run)


def test_outer_stdio_shutdown_reaps_nested_fixture_process(tmp_path: Path) -> None:
    async def run() -> None:
        params, state = _stdio_parameters(tmp_path)
        fixture_pid: int
        with anyio.fail_after(10):
            async with stdio_client(params) as streams, ClientSession(*streams) as session:
                await session.initialize()
                fixture_pid = await _fixture_pid(state)
                assert _process_is_alive(fixture_pid)
        await _wait_for_process_exit(fixture_pid)

    anyio.run(run)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _wait_for_port(port: int, process: subprocess.Popen[str]) -> None:
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("HTTP reference gateway exited before accepting requests")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                return
        except OSError:
            await anyio.sleep(0.05)
    raise RuntimeError("HTTP reference gateway did not start")


def test_remote_streamable_http_client_reaches_same_governed_child(tmp_path: Path) -> None:
    async def run() -> None:
        state = tmp_path / "http-state"
        port = _free_port()
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "gove_zone.cli",
                "mcp",
                "serve-http",
                "--state-dir",
                str(state),
                "--token-file",
                str(_token_file(tmp_path)),
                "--session-id",
                _SESSION,
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            cwd=Path.cwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            await _wait_for_port(port, process)
            async with httpx.AsyncClient() as probe:
                invalid_host = await probe.post(
                    f"http://127.0.0.1:{port}/mcp",
                    headers={"Host": "attacker.invalid", "Content-Type": "application/json"},
                    json={},
                )
                invalid_origin = await probe.post(
                    f"http://127.0.0.1:{port}/mcp",
                    headers={
                        "Host": f"127.0.0.1:{port}",
                        "Origin": "https://attacker.invalid",
                        "Content-Type": "application/json",
                    },
                    json={},
                )
                assert invalid_host.status_code == 421
                assert invalid_origin.status_code == 403
            async with (
                httpx.AsyncClient(
                    headers={
                        "Authorization": f"Bearer {_TOKEN}",
                        "X-ACGS-Session-ID": _SESSION,
                    }
                ) as client,
                streamable_http_client(
                    f"http://127.0.0.1:{port}/mcp",
                    http_client=client,
                ) as streams,
                ClientSession(streams[0], streams[1]) as session,
            ):
                await session.initialize()
                tools = await session.list_tools()
                assert "fixture.write_once" in {tool.name for tool in tools.tools}
                result = await session.call_tool(
                    "fixture.write_once",
                    {"record": "http-allowed"},
                    meta=_authorization("nonce-http-1", "idempotency-http-1"),
                )
                assert result.isError is False
                assert result.meta is not None
                assert result.meta["io.acgs/decision"]["status"] == "succeeded"
                assert _ledger(state) == [{"record": "http-allowed"}]
            async with (
                httpx.AsyncClient(
                    headers={
                        "Authorization": "Bearer wrong-audience-token",
                        "X-ACGS-Session-ID": _SESSION,
                    }
                ) as denied_client,
                streamable_http_client(
                    f"http://127.0.0.1:{port}/mcp",
                    http_client=denied_client,
                ) as denied_streams,
                ClientSession(denied_streams[0], denied_streams[1]) as denied_session,
            ):
                await denied_session.initialize()
                with pytest.raises(McpError) as denied:
                    await denied_session.list_tools()
                denied_data = denied.value.error.data
                assert isinstance(denied_data, dict)
                assert denied_data["decision"] == "deny"
                assert denied_data["refusalEvidence"]["signed"] is True
            assert _ledger(state) == [{"record": "http-allowed"}]
        finally:
            try:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            finally:
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()

    anyio.run(run)


def test_capability_child_death_has_no_fallback_or_second_spawn(tmp_path: Path) -> None:
    import os
    import signal

    import anyio

    from gove_zone.mcp_proof_export import _authorization
    from gove_zone.mcp_reference import create_reference_runtime
    from gove_zone.mcp_runtime import _in_process_client_session, build_mcp_server
    from gove_zone.proof_pack import PinnedOutputRoot

    async def exercise() -> None:
        state = tmp_path / "death-state"
        with PinnedOutputRoot.create(state) as pinned, pinned.attest() as capability:
            runtime = await create_reference_runtime(
                state,
                inbound_token="fixture-token",
                session_id="capability-child-death",
                state_capability=capability,
            )
            try:
                pid = int(capability.read_bytes("fixture.pid").decode().strip())
                os.kill(pid, signal.SIGKILL)
                await anyio.sleep(0.1)
                server = build_mcp_server(
                    runtime.gateway,
                    stdio_token="fixture-token",
                    stdio_session_id=runtime.session_id,
                )
                try:
                    async with _in_process_client_session(server) as session:
                        await session.call_tool(
                            "fixture.write_once",
                            {"record": "must-not-fallback"},
                            meta=_authorization("normal"),
                        )
                except Exception:
                    pass
                assert capability.read_bytes("fixture.pid").decode().strip() == str(pid)
                try:
                    ledger = capability.read_bytes("fixture-ledger.jsonl")
                except FileNotFoundError:
                    ledger = b""
                assert b"must-not-fallback" not in ledger
            finally:
                await runtime.aclose()

    anyio.run(exercise)


def test_capability_ambiguous_timeout_writes_once_and_is_not_retried(tmp_path: Path) -> None:
    import anyio

    from gove_zone.mcp_proof_export import _authorization
    from gove_zone.mcp_reference import create_reference_runtime
    from gove_zone.mcp_runtime import _in_process_client_session, build_mcp_server
    from gove_zone.proof_pack import PinnedOutputRoot

    async def exercise() -> None:
        state = tmp_path / "timeout-state"
        with PinnedOutputRoot.create(state) as pinned, pinned.attest() as capability:
            runtime = await create_reference_runtime(
                state,
                inbound_token="fixture-token",
                session_id="capability-timeout",
                ambiguous_delay_ms=500,
                adapter_timeout=0.05,
                state_capability=capability,
            )
            try:
                server = build_mcp_server(
                    runtime.gateway,
                    stdio_token="fixture-token",
                    stdio_session_id=runtime.session_id,
                )
                async with _in_process_client_session(server) as session:
                    await session.call_tool(
                        "fixture.ambiguous_write",
                        {"record": "ambiguous-once"},
                        meta=_authorization("normal"),
                    )
                await anyio.sleep(0.6)
                ledger = capability.read_bytes("fixture-ledger.jsonl").splitlines()
                calls = capability.read_bytes("fixture-calls.jsonl").splitlines()
                assert len([line for line in ledger if b"ambiguous-once" in line]) == 1
                assert len([line for line in calls if b"fixture.ambiguous_write" in line]) == 1
            finally:
                await runtime.aclose()

    anyio.run(exercise)


# ==========================================================================
# P1 remote mode: negative-first.  Remote mode is defined by what it refuses,
# so the happy path is last.
# ==========================================================================

_CANONICAL_HOST = "localhost:8443"
_ALLOWED_ORIGIN = "https://client.fixture.invalid"


def _issue_fixture_certificate(directory: Path, *, lifetime: timedelta) -> tuple[Path, Path]:
    """Mint one throwaway self-signed server certificate for localhost."""

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    key = ed25519.Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + lifetime)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, None)
    )
    certfile = directory / "server.crt"
    keyfile = directory / "server.key"
    certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    certfile.chmod(0o644)
    keyfile.chmod(0o600)
    return certfile, keyfile


@pytest.fixture
def certificate(tmp_path: Path) -> tuple[Path, Path]:
    directory = tmp_path / "tls"
    directory.mkdir()
    return _issue_fixture_certificate(directory, lifetime=timedelta(days=30))


def _remote_config(certificate: tuple[Path, Path], **overrides: Any) -> RemoteMCPConfig:
    certfile, keyfile = certificate
    kwargs: dict[str, Any] = {
        "canonical_host": _CANONICAL_HOST,
        "allowed_origins": (_ALLOWED_ORIGIN,),
        "certfile": certfile,
        "keyfile": keyfile,
        "bind_host": "127.0.0.1",
        "bind_port": 8443,
    }
    kwargs.update(overrides)
    return RemoteMCPConfig(**kwargs)


def _workload_config(certificate: tuple[Path, Path], **overrides: Any) -> RemoteMCPConfig:
    """A listener for non-browser workload clients, which send no Origin."""

    overrides.setdefault("allow_absent_origin", True)
    overrides.setdefault("identity_trust", RemoteIdentityTrust.ASYMMETRIC_JWS)
    return _remote_config(certificate, **overrides)


@pytest.fixture
def tls_server() -> Iterator[Callable[[Any, RemoteMCPConfig], Any]]:
    """Build Uvicorn servers over private TLS snapshots, cleaned up after the test."""

    import uvicorn

    with ExitStack() as stack:

        def build(app: Any, config: RemoteMCPConfig) -> Any:
            certfile, keyfile = stack.enter_context(remote_tls_snapshot(config))
            return uvicorn.Server(
                build_remote_uvicorn_config(app, config, certfile=certfile, keyfile=keyfile)
            )

        yield build


# -- startup rejection ------------------------------------------------------


def test_remote_non_loopback_publish_requires_explicit_optin(
    certificate: tuple[Path, Path],
) -> None:
    with pytest.raises(RemoteMCPConfigError, match="explicit remote opt-in"):
        _remote_config(certificate, bind_host="0.0.0.0")  # noqa: S104 - the rejected case


def test_remote_non_loopback_publish_accepted_with_optin(
    certificate: tuple[Path, Path],
) -> None:
    config = _remote_config(
        certificate,
        bind_host="0.0.0.0",  # noqa: S104 - asserting the opt-in path
        allow_non_loopback=True,
        identity_trust=RemoteIdentityTrust.ASYMMETRIC_JWS,
    )
    assert config.bind_host == "0.0.0.0"  # noqa: S104 - asserting the opt-in path


def test_remote_missing_certificate_is_rejected(tmp_path: Path) -> None:
    directory = tmp_path / "tls-a"
    directory.mkdir()
    _, keyfile = _issue_fixture_certificate(directory, lifetime=timedelta(days=30))
    with pytest.raises(RemoteMCPConfigError, match="certfile"):
        RemoteMCPConfig(
            canonical_host=_CANONICAL_HOST,
            allowed_origins=(_ALLOWED_ORIGIN,),
            certfile=tmp_path / "absent.crt",
            keyfile=keyfile,
        )


def test_remote_missing_private_key_is_rejected(tmp_path: Path) -> None:
    directory = tmp_path / "tls-b"
    directory.mkdir()
    certfile, _ = _issue_fixture_certificate(directory, lifetime=timedelta(days=30))
    with pytest.raises(RemoteMCPConfigError, match="keyfile"):
        RemoteMCPConfig(
            canonical_host=_CANONICAL_HOST,
            allowed_origins=(_ALLOWED_ORIGIN,),
            certfile=certfile,
            keyfile=tmp_path / "absent.key",
        )


def test_remote_world_readable_private_key_is_rejected(certificate: tuple[Path, Path]) -> None:
    certfile, keyfile = certificate
    keyfile.chmod(0o644)
    with pytest.raises(RemoteMCPConfigError, match="owner-only"):
        RemoteMCPConfig(
            canonical_host=_CANONICAL_HOST,
            allowed_origins=(_ALLOWED_ORIGIN,),
            certfile=certfile,
            keyfile=keyfile,
        )


def test_remote_symlinked_private_key_is_rejected(
    certificate: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    certfile, keyfile = certificate
    link = tmp_path / "link.key"
    link.symlink_to(keyfile)
    with pytest.raises(RemoteMCPConfigError):
        RemoteMCPConfig(
            canonical_host=_CANONICAL_HOST,
            allowed_origins=(_ALLOWED_ORIGIN,),
            certfile=certfile,
            keyfile=link,
        )


def test_remote_hardlinked_private_key_is_rejected(
    certificate: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    certfile, keyfile = certificate
    hardlink = tmp_path / "hard.key"
    os.link(keyfile, hardlink)
    with pytest.raises(RemoteMCPConfigError, match="exactly one"):
        RemoteMCPConfig(
            canonical_host=_CANONICAL_HOST,
            allowed_origins=(_ALLOWED_ORIGIN,),
            certfile=certfile,
            keyfile=hardlink,
        )


@pytest.mark.parametrize(
    "host",
    [
        "",
        "localhost",
        "localhost:",
        "*:8443",
        "*.fixture.invalid:8443",
        "localhost.:8443",
        "LOCALHOST:8443",
        "localhost:0",
        "localhost:08443",
        "::1:8443",
    ],
)
def test_remote_malformed_canonical_host_is_rejected(
    certificate: tuple[Path, Path],
    host: str,
) -> None:
    with pytest.raises(RemoteMCPConfigError):
        _remote_config(certificate, canonical_host=host)


@pytest.mark.parametrize(
    "origin",
    ["null", "*", "https://*.fixture.invalid", "client.invalid", "https://client.invalid/path"],
)
def test_remote_malformed_allowed_origin_is_rejected(
    certificate: tuple[Path, Path],
    origin: str,
) -> None:
    with pytest.raises(RemoteMCPConfigError):
        _remote_config(certificate, allowed_origins=(origin,))


def test_remote_uvicorn_config_terminates_tls_and_refuses_proxy_headers(
    certificate: tuple[Path, Path],
) -> None:
    certfile, keyfile = certificate
    config = _remote_config(certificate)
    with remote_tls_snapshot(config) as (snapshot_cert, snapshot_key):
        uvicorn_config = build_remote_uvicorn_config(
            _RemoteSpyApp(),
            config,
            certfile=snapshot_cert,
            keyfile=snapshot_key,
        )
        # Uvicorn is pointed at the private snapshot, never at the operator's
        # source paths, so there is no second open of attacker-reachable material.
        assert uvicorn_config.ssl_certfile == str(snapshot_cert)
        assert uvicorn_config.ssl_keyfile == str(snapshot_key)
        assert uvicorn_config.ssl_certfile != str(certfile)
        assert uvicorn_config.ssl_keyfile != str(keyfile)
    assert uvicorn_config.proxy_headers is False
    assert not uvicorn_config.forwarded_allow_ips
    assert uvicorn_config.limit_concurrency == config.budgets.limit_concurrency
    assert uvicorn_config.backlog == config.budgets.backlog
    assert uvicorn_config.timeout_keep_alive == config.budgets.timeout_keep_alive
    assert uvicorn_config.limit_max_requests == config.budgets.limit_max_requests


def test_remote_tls_snapshot_is_owner_only_and_cleaned_on_exit(
    certificate: tuple[Path, Path],
) -> None:
    config = _remote_config(certificate)
    with remote_tls_snapshot(config) as (snapshot_cert, snapshot_key):
        directory = snapshot_cert.parent
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        for path in (snapshot_cert, snapshot_key):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert snapshot_key.read_bytes() == config.private_key_pem
    # No key material outlives the listener.
    assert not directory.exists()


def test_remote_tls_source_replacement_after_config_cannot_change_served_material(
    tmp_path: Path,
) -> None:
    """The reviewer's swap: replace the source cert/key after config construction."""

    directory = tmp_path / "tls-swap"
    directory.mkdir()
    certfile, keyfile = _issue_fixture_certificate(directory, lifetime=timedelta(days=30))
    config = RemoteMCPConfig(
        canonical_host=_CANONICAL_HOST,
        allowed_origins=(_ALLOWED_ORIGIN,),
        certfile=certfile,
        keyfile=keyfile,
    )
    trusted_cert = config.certificate_pem
    trusted_key = config.private_key_pem

    # Mint entirely different material and replace the source paths underneath.
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    rogue_cert, rogue_key = _issue_fixture_certificate(attacker, lifetime=timedelta(days=30))
    rogue_cert_bytes = rogue_cert.read_bytes()
    assert rogue_cert_bytes != trusted_cert
    keyfile.chmod(0o600)
    certfile.write_bytes(rogue_cert_bytes)
    os.replace(rogue_key, keyfile)

    # The config still holds the validated bytes...
    assert config.certificate_pem == trusted_cert
    assert config.private_key_pem == trusted_key
    # ...and the snapshot Uvicorn is handed serves those, not the swapped source.
    with remote_tls_snapshot(config) as (snapshot_cert, snapshot_key):
        assert snapshot_cert.read_bytes() == trusted_cert
        assert snapshot_key.read_bytes() == trusted_key
        assert snapshot_cert.read_bytes() != rogue_cert_bytes


# -- request guard ----------------------------------------------------------


class _RemoteSpyApp:
    """Stand-in for the MCP app that records whether dispatch was reached."""

    def __init__(self) -> None:
        self.dispatched = 0
        self.lifespan_started = False

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            # Only HTTP requests count as dispatch; the real MCP app needs its
            # lifespan forwarded, so the spy must accept it without counting it.
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    self.lifespan_started = True
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        self.dispatched += 1
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect" or not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b'{"dispatched":true}'})


def _guarded(config: RemoteMCPConfig) -> tuple[Any, _RemoteSpyApp]:
    spy = _RemoteSpyApp()
    return build_remote_app(spy, config, readiness=None), spy


def _remote_request(
    app: Any,
    *,
    headers: list[tuple[bytes, bytes]],
    body: bytes = b"{}",
    path: str = "/mcp",
    raw_path: bytes | None = None,
    stream: list[bytes] | None = None,
    method: str = "POST",
    client: tuple[str, int] = _PUBLIC_PEER,
) -> tuple[int, bytes]:
    """Drive one ASGI request directly, bypassing client-side normalization."""

    status: dict[str, int] = {}
    chunks: list[bytes] = []
    sent = list(stream) if stream is not None else [body]

    async def receive() -> dict[str, Any]:
        if sent:
            chunk = sent.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(sent)}
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            status["code"] = message["status"]
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": path,
        "raw_path": raw_path if raw_path is not None else path.encode("ascii"),
        "query_string": b"",
        "headers": headers,
        "client": client,
        "server": ("127.0.0.1", 8443),
    }
    anyio.run(app, scope, receive, send)
    return status.get("code", 0), b"".join(chunks)


async def _remote_request_async(
    app: Any,
    *,
    headers: list[tuple[bytes, bytes]],
    body: bytes = b"{}",
    path: str = "/mcp",
    client: tuple[str, int] = _PUBLIC_PEER,
) -> tuple[int, bytes]:
    """Drive one ASGI request inside an existing event loop."""

    status: dict[str, int] = {}
    chunks: list[bytes] = []
    sent = [body]

    async def receive() -> dict[str, Any]:
        if sent:
            return {"type": "http.request", "body": sent.pop(0), "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            status["code"] = message["status"]
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": headers,
            "client": client,
            "server": ("127.0.0.1", 8443),
        },
        receive,
        send,
    )
    return status.get("code", 0), b"".join(chunks)


def _dummy_server() -> Any:
    from mcp.server.lowlevel import Server

    return Server("acgs-remote-mode-probe", version="1.0")


def _session_manager(app: Any) -> Any:
    """Reach the SDK session manager the remote app was built around."""

    return app.state.session_manager


def _remote_headers(**overrides: Any) -> list[tuple[bytes, bytes]]:
    base: list[tuple[bytes, bytes]] = [
        (b"host", _CANONICAL_HOST.encode("ascii")),
        (b"origin", _ALLOWED_ORIGIN.encode("ascii")),
        (b"authorization", b"Bearer fixture-token"),
        (b"content-type", b"application/json"),
    ]
    drop = {name.replace("_", "-").encode("ascii") for name in overrides.pop("drop", ())}
    base = [(name, value) for name, value in base if name not in drop]
    for name, value in overrides.items():
        base.append((name.replace("_", "-").encode("ascii"), value))
    return base


def test_remote_exact_host_is_accepted(certificate: tuple[Path, Path]) -> None:
    app, spy = _guarded(_remote_config(certificate))
    status, _ = _remote_request(app, headers=_remote_headers())
    assert status == 200
    assert spy.dispatched == 1


@pytest.mark.parametrize(
    "host",
    [
        b"localhost:8444",
        b"localhost.:8443",
        b"*.fixture.invalid:8443",
        b"LOCALHOST :8443",
        b"localhost:8443\x00",
        b"evil.invalid:8443",
        b"[::1]:8443",
        b"xn--localhost-.:8443",
        b"localhost",
        b"localhost:8443, evil.invalid:8443",
    ],
)
def test_remote_wrong_host_is_rejected_before_dispatch(
    certificate: tuple[Path, Path],
    host: bytes,
) -> None:
    app, spy = _guarded(_remote_config(certificate))
    status, _ = _remote_request(app, headers=_remote_headers(drop=("host",), host=host))
    assert status == 400
    assert spy.dispatched == 0


def test_remote_duplicate_host_is_rejected_before_dispatch(
    certificate: tuple[Path, Path],
) -> None:
    app, spy = _guarded(_remote_config(certificate))
    headers = _remote_headers()
    headers.append((b"host", _CANONICAL_HOST.encode("ascii")))
    status, _ = _remote_request(app, headers=headers)
    assert status == 400
    assert spy.dispatched == 0


def test_remote_missing_host_is_rejected_before_dispatch(
    certificate: tuple[Path, Path],
) -> None:
    app, spy = _guarded(_remote_config(certificate))
    status, _ = _remote_request(app, headers=_remote_headers(drop=("host",)))
    assert status == 400
    assert spy.dispatched == 0


def test_remote_absolute_form_target_mismatch_is_rejected(
    certificate: tuple[Path, Path],
) -> None:
    app, spy = _guarded(_remote_config(certificate))
    status, _ = _remote_request(
        app,
        headers=_remote_headers(),
        raw_path=b"https://evil.invalid:8443/mcp",
    )
    assert status == 400
    assert spy.dispatched == 0


def test_remote_absolute_form_target_matching_canonical_host_is_accepted(
    certificate: tuple[Path, Path],
) -> None:
    app, spy = _guarded(_remote_config(certificate))
    status, _ = _remote_request(
        app,
        headers=_remote_headers(),
        raw_path=b"https://localhost:8443/mcp",
    )
    assert status == 200
    assert spy.dispatched == 1


@pytest.mark.parametrize(
    "origin",
    [b"null", b"*", b"https://evil.invalid", b"HTTPS://client.fixture.invalid", b""],
)
def test_remote_wrong_origin_is_rejected_before_dispatch(
    certificate: tuple[Path, Path],
    origin: bytes,
) -> None:
    app, spy = _guarded(_remote_config(certificate))
    status, _ = _remote_request(app, headers=_remote_headers(drop=("origin",), origin=origin))
    assert status == 403
    assert spy.dispatched == 0


def test_remote_duplicate_origin_is_rejected_before_dispatch(
    certificate: tuple[Path, Path],
) -> None:
    app, spy = _guarded(_remote_config(certificate))
    headers = _remote_headers()
    headers.append((b"origin", _ALLOWED_ORIGIN.encode("ascii")))
    status, _ = _remote_request(app, headers=headers)
    assert status == 403
    assert spy.dispatched == 0


def test_remote_absent_origin_is_denied_when_not_configured(
    certificate: tuple[Path, Path],
) -> None:
    app, spy = _guarded(_remote_config(certificate))
    status, _ = _remote_request(app, headers=_remote_headers(drop=("origin", "authorization")))
    assert status == 403
    assert spy.dispatched == 0


def test_remote_absent_origin_bearer_shaped_string_bypass_is_denied(
    certificate: tuple[Path, Path],
) -> None:
    """The reviewer's reproducer: a bearer-shaped string is not authentication.

    The previous guard let any ``Authorization: Bearer <anything>`` header stand
    in for an Origin.  Every string is bearer-shaped, so that check authenticated
    nobody while reading as though it did.
    """

    app, spy = _guarded(_remote_config(certificate))
    for shaped in (b"Bearer x", b"Bearer " + b"a" * 512, b"Bearer ../../etc/passwd"):
        headers = _remote_headers(drop=("origin", "authorization"))
        headers.append((b"authorization", shaped))
        status, body = _remote_request(app, headers=headers)
        assert status == 403
        assert json.loads(body) == {"error": "an absent Origin is not accepted by this listener"}
    assert spy.dispatched == 0


def test_remote_absent_origin_flag_requires_the_asymmetric_verifier(
    certificate: tuple[Path, Path],
) -> None:
    with pytest.raises(RemoteMCPConfigError, match="bearer-shaped string is not authentication"):
        _remote_config(
            certificate,
            allow_absent_origin=True,
            identity_trust=RemoteIdentityTrust.FIXTURE_STATIC,
        )


def test_remote_absent_origin_is_accepted_only_with_flag_and_asymmetric_trust(
    certificate: tuple[Path, Path],
) -> None:
    config = _remote_config(
        certificate,
        allow_absent_origin=True,
        identity_trust=RemoteIdentityTrust.ASYMMETRIC_JWS,
    )
    app, spy = _guarded(config)
    status, _ = _remote_request(app, headers=_remote_headers(drop=("origin",)))
    # The guard admits the request; the EdDSA verifier behind it is what decides
    # whether the token authenticates anyone.
    assert status == 200
    assert spy.dispatched == 1


def test_remote_public_bind_refuses_the_fixture_static_verifier(
    certificate: tuple[Path, Path],
) -> None:
    with pytest.raises(RemoteMCPConfigError, match="fixture .*is refused beyond loopback"):
        _remote_config(
            certificate,
            bind_host="0.0.0.0",  # noqa: S104 - the rejected case under test
            allow_non_loopback=True,
            identity_trust=RemoteIdentityTrust.FIXTURE_STATIC,
        )


@pytest.mark.parametrize(
    "name",
    [
        b"forwarded",
        b"x-forwarded-for",
        b"x-forwarded-host",
        b"x-forwarded-proto",
        b"x-forwarded-port",
        b"X-Forwarded-For",
    ],
)
def test_remote_forwarded_headers_are_rejected_before_dispatch(
    certificate: tuple[Path, Path],
    name: bytes,
) -> None:
    app, spy = _guarded(_remote_config(certificate))
    headers = _remote_headers()
    headers.append((name, b"198.51.100.9"))
    status, _ = _remote_request(app, headers=headers)
    assert status == 400
    assert spy.dispatched == 0


def test_remote_last_event_id_resume_is_rejected(certificate: tuple[Path, Path]) -> None:
    app, spy = _guarded(_remote_config(certificate))
    status, _ = _remote_request(app, headers=_remote_headers(last_event_id=b"42"))
    assert status == 400
    assert spy.dispatched == 0


@pytest.mark.parametrize("method", ["GET", "HEAD", "PUT", "DELETE", "OPTIONS"])
def test_remote_non_post_mcp_is_rejected_before_dispatch(
    certificate: tuple[Path, Path],
    method: str,
) -> None:
    """GET /mcp is the Streamable HTTP SSE subscription; this listener has none."""

    app, spy = _guarded(_remote_config(certificate))
    status, _ = _remote_request(app, headers=_remote_headers(), method=method)
    assert status == 405
    assert spy.dispatched == 0


def test_remote_sse_only_accept_is_rejected_before_dispatch(
    certificate: tuple[Path, Path],
) -> None:
    app, spy = _guarded(_remote_config(certificate))
    status, _ = _remote_request(app, headers=_remote_headers(accept=b"text/event-stream"))
    assert status == 406
    assert spy.dispatched == 0


def test_remote_official_client_accept_is_still_accepted(
    certificate: tuple[Path, Path],
) -> None:
    """The official SDK sends both media types; only SSE-*only* is refused."""

    app, spy = _guarded(_remote_config(certificate))
    status, _ = _remote_request(
        app, headers=_remote_headers(accept=b"application/json, text/event-stream")
    )
    assert status == 200
    assert spy.dispatched == 1


def test_remote_session_id_resume_is_rejected_before_dispatch(
    certificate: tuple[Path, Path],
) -> None:
    app, spy = _guarded(_remote_config(certificate))
    status, _ = _remote_request(app, headers=_remote_headers(mcp_session_id=b"prior-session"))
    assert status == 400
    assert spy.dispatched == 0


def test_remote_streamable_http_is_configured_json_only(certificate: tuple[Path, Path]) -> None:
    """Prove the SDK is in stateless JSON-response mode, not an SSE stream."""

    from gove_zone.mcp_runtime import build_streamable_http_app

    app = build_streamable_http_app(
        _dummy_server(),
        allowed_hosts=[_CANONICAL_HOST],
        allowed_origins=[_ALLOWED_ORIGIN],
    )
    manager = _session_manager(app)
    assert manager.json_response is True
    assert manager.stateless is True


def test_remote_concurrency_budget_is_enforced_before_child_dispatch(
    certificate: tuple[Path, Path],
) -> None:
    """A saturated listener refuses rather than queueing work at the downstream."""

    config = _remote_config(certificate, budgets=RemoteMCPBudgets(limit_concurrency=2))
    blocked = anyio.Event()
    inflight: list[int] = []
    rejected: list[int] = []

    class _SlowApp:
        def __init__(self) -> None:
            self.dispatched = 0

        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            self.dispatched += 1
            inflight.append(self.dispatched)
            await blocked.wait()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})

    slow = _SlowApp()
    app = build_remote_app(slow, config, readiness=None)

    async def one(record: list[int]) -> None:
        status, _ = await _remote_request_async(app, headers=_remote_headers())
        record.append(status)

    async def run() -> None:
        async with anyio.create_task_group() as tasks:
            for _ in range(config.budgets.limit_concurrency):
                tasks.start_soon(one, [])
            # Let the first two occupy every slot.
            while len(inflight) < config.budgets.limit_concurrency:
                await anyio.sleep(0.01)
            # The third finds no slot and is refused *before* reaching the child.
            await one(rejected)
            assert slow.dispatched == config.budgets.limit_concurrency
            blocked.set()

    anyio.run(run)
    assert rejected == [503]
    assert slow.dispatched == config.budgets.limit_concurrency


def test_remote_guard_never_echoes_the_inbound_token(certificate: tuple[Path, Path]) -> None:
    app, _ = _guarded(_remote_config(certificate))
    status, body = _remote_request(
        app,
        headers=_remote_headers(drop=("host",), host=b"evil.invalid:8443"),
    )
    assert status == 400
    assert b"fixture-token" not in body
    assert b"evil.invalid" not in body


# -- resource budgets -------------------------------------------------------


def test_remote_oversized_content_length_is_rejected_before_dispatch(
    certificate: tuple[Path, Path],
) -> None:
    config = _remote_config(certificate, budgets=RemoteMCPBudgets(max_body_bytes=64))
    app, spy = _guarded(config)
    status, _ = _remote_request(app, headers=_remote_headers(content_length=b"65"), body=b"{}")
    assert status == 413
    assert spy.dispatched == 0


def test_remote_duplicate_content_length_is_rejected_before_dispatch(
    certificate: tuple[Path, Path],
) -> None:
    app, spy = _guarded(_remote_config(certificate))
    headers = _remote_headers(content_length=b"2")
    headers.append((b"content-length", b"3"))
    status, _ = _remote_request(app, headers=headers)
    assert status == 400
    assert spy.dispatched == 0


def test_remote_streamed_chunked_body_over_budget_fails_closed(
    certificate: tuple[Path, Path],
) -> None:
    """A chunked body declares no length; the cap must hold without buffering it."""

    config = _remote_config(certificate, budgets=RemoteMCPBudgets(max_body_bytes=64))
    app, spy = _guarded(config)
    status, _ = _remote_request(
        app,
        headers=_remote_headers(transfer_encoding=b"chunked"),
        stream=[b"a" * 32, b"b" * 32, b"c" * 32],
    )
    assert status == 413
    assert spy.dispatched == 0


def test_remote_compressed_request_body_is_rejected_before_dispatch(
    certificate: tuple[Path, Path],
) -> None:
    app, spy = _guarded(_remote_config(certificate))
    status, _ = _remote_request(app, headers=_remote_headers(content_encoding=b"gzip"))
    assert status == 415
    assert spy.dispatched == 0


def test_remote_identity_content_encoding_is_accepted(certificate: tuple[Path, Path]) -> None:
    app, spy = _guarded(_remote_config(certificate))
    status, _ = _remote_request(app, headers=_remote_headers(content_encoding=b"identity"))
    assert status == 200
    assert spy.dispatched == 1


def test_remote_header_count_bomb_is_rejected_before_dispatch(
    certificate: tuple[Path, Path],
) -> None:
    config = _remote_config(certificate, budgets=RemoteMCPBudgets(max_header_count=8))
    app, spy = _guarded(config)
    headers = _remote_headers()
    headers.extend((f"x-pad-{index}".encode("ascii"), b"1") for index in range(32))
    status, _ = _remote_request(app, headers=headers)
    assert status == 431
    assert spy.dispatched == 0


def test_remote_aggregate_header_bytes_bomb_is_rejected_before_dispatch(
    certificate: tuple[Path, Path],
) -> None:
    config = _remote_config(certificate, budgets=RemoteMCPBudgets(max_header_bytes=512))
    app, spy = _guarded(config)
    headers = _remote_headers(x_pad=b"p" * 4096)
    status, _ = _remote_request(app, headers=headers)
    assert status == 431
    assert spy.dispatched == 0


# -- secret files -----------------------------------------------------------


def _keyfile_config(certfile: Path, keyfile: Path) -> RemoteMCPConfig:
    return RemoteMCPConfig(
        canonical_host=_CANONICAL_HOST,
        allowed_origins=(_ALLOWED_ORIGIN,),
        certfile=certfile,
        keyfile=keyfile,
    )


def test_remote_keyfile_round_trips(certificate: tuple[Path, Path]) -> None:
    certfile, keyfile = certificate
    assert _keyfile_config(certfile, keyfile).keyfile == keyfile


def test_remote_keyfile_rejects_a_directory(
    certificate: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    certfile, _ = certificate
    directory = tmp_path / "keydir"
    directory.mkdir(mode=0o700)
    with pytest.raises(RemoteMCPConfigError):
        _keyfile_config(certfile, directory)


def test_remote_keyfile_rejects_replacement_during_validation(
    certificate: tuple[Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rename-over during validation must not be validated as the real key.

    A rename-over unlinks the inode this descriptor holds, so the fail-closed
    identity invariant (nlink, then the pre/post fstat comparison) catches it
    before the path can be handed to the TLS layer.
    """

    certfile, keyfile = certificate
    replacement = tmp_path / "attacker.key"
    replacement.write_bytes(b"attacker-key-material\n")
    replacement.chmod(0o600)
    original_open = os.open

    def swap_after_open(path: Any, flags: int, *args: Any) -> int:
        descriptor = original_open(path, flags, *args)
        if Path(path) == keyfile:
            os.replace(replacement, keyfile)
        return descriptor

    monkeypatch.setattr(os, "open", swap_after_open)
    with pytest.raises(RemoteMCPConfigError, match="keyfile"):
        _keyfile_config(certfile, keyfile)


def test_remote_keyfile_rejects_a_same_link_count_identity_change(
    certificate: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defense in depth: the pre/post fstat catches a swap nlink alone would miss."""

    certfile, keyfile = certificate
    original_fstat = os.fstat
    state = {"first": True}

    def drifting_fstat(fd: int) -> os.stat_result:
        info = original_fstat(fd)
        if state["first"]:
            state["first"] = False
            return info
        fields = list(info)
        fields[1] = info.st_ino + 1  # a different inode behind the same path
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", drifting_fstat)
    with pytest.raises(RemoteMCPConfigError, match="replaced"):
        _keyfile_config(certfile, keyfile)


# -- readiness --------------------------------------------------------------


class _Probe:
    def __init__(self, *, tools: tuple[str, ...] = ("fixture.read",)) -> None:
        self.calls = 0
        self._tools = tools
        self.failure: Exception | None = None

    def __call__(self) -> tuple[str, ...]:
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return self._tools


def _readiness(probe: _Probe, **overrides: Any) -> RemoteReadiness:
    kwargs: dict[str, Any] = {
        "probe": probe,
        "expected_tools": ("fixture.read",),
        "certificate_expiry": datetime.now(UTC) + timedelta(days=30),
        "expiry_margin_seconds": 604800,
    }
    kwargs.update(overrides)
    return RemoteReadiness(**kwargs)


def test_readyz_flood_never_triggers_a_probe() -> None:
    """A readyz flood must not become an anonymous credential-bearing proxy."""

    probe = _Probe()
    readiness = _readiness(probe)
    readiness.refresh()
    assert probe.calls == 1
    for _ in range(50):
        readiness.public_state()
    assert probe.calls == 1


def test_public_ready_exposes_only_ready_checked_at_and_age() -> None:
    readiness = _readiness(_Probe())
    readiness.refresh()
    state = readiness.public_state()
    assert set(state) == {"ready", "checked_at", "age_seconds"}
    assert state["ready"] is True


def test_public_ready_never_leaks_catalog_or_downstream_error() -> None:
    probe = _Probe()
    probe.failure = RuntimeError("downstream credential 'hunter2' rejected by mcp://backend")
    readiness = _readiness(probe)
    readiness.refresh()
    rendered = json.dumps(readiness.public_state())
    assert readiness.public_state()["ready"] is False
    assert "hunter2" not in rendered
    assert "backend" not in rendered
    assert "fixture.read" not in rendered


def test_unprobed_readiness_is_unready() -> None:
    readiness = _readiness(_Probe())
    state = readiness.public_state()
    assert state["ready"] is False
    assert state["checked_at"] is None


def test_downstream_failure_means_unready_with_no_fallback() -> None:
    probe = _Probe()
    readiness = _readiness(probe)
    readiness.refresh()
    assert readiness.public_state()["ready"] is True
    probe.failure = RuntimeError("downstream is gone")
    readiness.refresh()
    assert readiness.public_state()["ready"] is False


def test_empty_catalog_is_unready() -> None:
    readiness = _readiness(_Probe(tools=()))
    readiness.refresh()
    assert readiness.public_state()["ready"] is False


def test_poisoned_catalog_is_unready() -> None:
    readiness = _readiness(_Probe(tools=("fixture.read", "fixture.exfiltrate")))
    readiness.refresh()
    assert readiness.public_state()["ready"] is False


def test_colliding_catalog_is_unready() -> None:
    readiness = _readiness(_Probe(tools=("fixture.read", "fixture.read")))
    readiness.refresh()
    assert readiness.public_state()["ready"] is False


def test_expiring_certificate_makes_the_listener_unready() -> None:
    readiness = _readiness(_Probe(), certificate_expiry=datetime.now(UTC) + timedelta(hours=1))
    readiness.refresh()
    assert readiness.public_state()["ready"] is False


def test_concurrent_refresh_is_serialized() -> None:
    """A readyz flood behind the probe must collapse to one downstream call."""

    probe = _Probe()
    readiness = _readiness(probe, min_interval_seconds=3600)
    for _ in range(20):
        readiness.refresh()
    assert probe.calls == 1


def test_healthz_is_process_only(certificate: tuple[Path, Path]) -> None:
    probe = _Probe()
    app = build_remote_app(
        _RemoteSpyApp(),
        _remote_config(certificate),
        readiness=_readiness(probe),
    )
    status, body = _remote_request(app, headers=_remote_headers(), path="/healthz")
    assert status == 200
    assert json.loads(body) == {"process": "ok"}
    assert probe.calls == 0


def test_public_readyz_route_serves_cached_state_without_probing(
    certificate: tuple[Path, Path],
) -> None:
    probe = _Probe()
    readiness = _readiness(probe)
    readiness.refresh()
    app = build_remote_app(_RemoteSpyApp(), _remote_config(certificate), readiness=readiness)
    status, body = _remote_request(
        app, headers=_remote_headers(), path="/readyz", client=_ADMIN_PEER
    )
    assert status == 200
    state = json.loads(body)
    # Liveness facts only: no catalog, token, error string, or receipt.
    assert set(state) == {"ready", "checked_at", "age_seconds"}
    assert probe.calls == 1


def test_public_readyz_is_unready_when_the_probe_failed(
    certificate: tuple[Path, Path],
) -> None:
    probe = _Probe()
    probe.failure = RuntimeError("downstream gone")
    readiness = _readiness(probe)
    readiness.refresh()
    app = build_remote_app(_RemoteSpyApp(), _remote_config(certificate), readiness=readiness)
    status, body = _remote_request(
        app, headers=_remote_headers(), path="/readyz", client=_ADMIN_PEER
    )
    assert status == 503
    body_text = body.decode("utf-8")
    assert json.loads(body)["ready"] is False
    # The downstream failure reason must never reach the caller.
    assert "downstream" not in body_text


def test_readyz_still_enforces_the_host_guard(certificate: tuple[Path, Path]) -> None:
    readiness = _readiness(_Probe())
    readiness.refresh()
    app = build_remote_app(_RemoteSpyApp(), _remote_config(certificate), readiness=readiness)
    status, _ = _remote_request(
        app,
        headers=_remote_headers(drop=("host",), host=b"evil.invalid:8443"),
        path="/readyz",
        client=_ADMIN_PEER,
    )
    assert status == 400


def test_readyz_is_invisible_to_a_public_peer(certificate: tuple[Path, Path]) -> None:
    readiness = _readiness(_Probe())
    readiness.refresh()
    app = build_remote_app(_RemoteSpyApp(), _remote_config(certificate), readiness=readiness)
    status, body = _remote_request(
        app, headers=_remote_headers(), path="/readyz", client=_PUBLIC_PEER
    )
    # Not 403: a public caller must not even learn the route exists, let alone
    # whether the listener is ready.
    assert status == 404
    assert json.loads(body) == {"error": "not found"}


def test_readyz_without_a_configured_probe_never_claims_ready(
    certificate: tuple[Path, Path],
) -> None:
    """A CLI that passes readiness=None must not serve a ready-looking route."""

    app = build_remote_app(_RemoteSpyApp(), _remote_config(certificate), readiness=None)
    status, body = _remote_request(
        app, headers=_remote_headers(), path="/readyz", client=_ADMIN_PEER
    )
    assert status == 503
    assert json.loads(body) == {"ready": False, "checked_at": None, "age_seconds": None}


def test_readyz_flood_serves_cached_state_and_runs_exactly_one_probe(
    certificate: tuple[Path, Path],
) -> None:
    """An anonymous readyz flood must not become a proxy to the downstream."""

    probe = _Probe()
    readiness = _readiness(probe, min_interval_seconds=3600)
    readiness.refresh()
    app = build_remote_app(_RemoteSpyApp(), _remote_config(certificate), readiness=readiness)
    for _ in range(50):
        status, _ = _remote_request(
            app, headers=_remote_headers(), path="/readyz", client=_ADMIN_PEER
        )
        assert status == 200
    # The route reads the cache; it never triggers work.
    assert probe.calls == 1


# -- remote happy path over real TLS ---------------------------------------


async def _await_startup(server: Any) -> None:
    for _ in range(200):
        if getattr(server, "started", False):
            return
        await anyio.sleep(0.05)
    raise RuntimeError("remote gateway did not start")


def test_remote_happy_path_terminates_tls_and_enforces_host(
    certificate: tuple[Path, Path],
    tls_server: Callable[[Any, RemoteMCPConfig], Any],
) -> None:
    """Client -> TLS gateway with SAN verification and exact raw Host validation."""

    certfile, _ = certificate
    port = _free_port()
    config = _workload_config(certificate, bind_port=port, canonical_host=f"localhost:{port}")
    spy = _RemoteSpyApp()
    server = tls_server(build_remote_app(spy, config, readiness=None), config)

    async def run() -> None:
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(server.serve)
            await _await_startup(server)
            context = ssl.create_default_context(cafile=str(certfile))
            async with httpx.AsyncClient(verify=context) as client:
                good = await client.post(
                    f"https://localhost:{port}/mcp",
                    content=b"{}",
                    headers={"Authorization": "Bearer fixture-token"},
                )
                assert good.status_code == 200
                assert spy.dispatched == 1
                assert spy.lifespan_started is True

                bad_host = await client.post(
                    f"https://localhost:{port}/mcp",
                    content=b"{}",
                    headers={
                        "Authorization": "Bearer fixture-token",
                        "Host": "evil.invalid:1",
                    },
                )
                assert bad_host.status_code == 400
                assert spy.dispatched == 1
            server.should_exit = True

    anyio.run(run)


def test_remote_client_rejects_a_certificate_from_the_wrong_ca(
    certificate: tuple[Path, Path],
    tmp_path: Path,
    tls_server: Callable[[Any, RemoteMCPConfig], Any],
) -> None:
    other = tmp_path / "other-ca"
    other.mkdir()
    other_certfile, _ = _issue_fixture_certificate(other, lifetime=timedelta(days=30))
    port = _free_port()
    config = _workload_config(certificate, bind_port=port, canonical_host=f"localhost:{port}")
    app = build_remote_app(_RemoteSpyApp(), config, readiness=None)
    server = tls_server(app, config)

    async def run() -> None:
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(server.serve)
            await _await_startup(server)
            context = ssl.create_default_context(cafile=str(other_certfile))
            async with httpx.AsyncClient(verify=context) as client:
                with pytest.raises(httpx.ConnectError):
                    await client.post(f"https://localhost:{port}/mcp", content=b"{}")
            server.should_exit = True

    anyio.run(run)


def test_remote_client_rejects_a_wrong_hostname(
    certificate: tuple[Path, Path],
    tls_server: Callable[[Any, RemoteMCPConfig], Any],
) -> None:
    """The contract is client SAN verification, not server-side SNI enforcement."""

    certfile, _ = certificate
    port = _free_port()
    config = _workload_config(certificate, bind_port=port, canonical_host=f"localhost:{port}")
    app = build_remote_app(_RemoteSpyApp(), config, readiness=None)
    server = tls_server(app, config)

    async def run() -> None:
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(server.serve)
            await _await_startup(server)
            context = ssl.create_default_context(cafile=str(certfile))
            async with httpx.AsyncClient(verify=context) as client:
                # 127.0.0.1 is not a SAN of the localhost-only fixture certificate.
                with pytest.raises(httpx.ConnectError):
                    await client.post(f"https://127.0.0.1:{port}/mcp", content=b"{}")
            server.should_exit = True

    anyio.run(run)


def test_remote_expired_certificate_is_refused_by_the_client(
    tmp_path: Path,
    tls_server: Callable[[Any, RemoteMCPConfig], Any],
) -> None:
    expired = tmp_path / "expired"
    expired.mkdir()
    certfile, keyfile = _issue_fixture_certificate(expired, lifetime=timedelta(seconds=-1))
    port = _free_port()
    config = RemoteMCPConfig(
        canonical_host=f"localhost:{port}",
        allowed_origins=(_ALLOWED_ORIGIN,),
        certfile=certfile,
        keyfile=keyfile,
        bind_port=port,
    )
    app = build_remote_app(_RemoteSpyApp(), config, readiness=None)
    server = tls_server(app, config)

    async def run() -> None:
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(server.serve)
            await _await_startup(server)
            context = ssl.create_default_context(cafile=str(certfile))
            async with httpx.AsyncClient(verify=context) as client:
                with pytest.raises(httpx.ConnectError):
                    await client.post(f"https://localhost:{port}/mcp", content=b"{}")
            server.should_exit = True

    anyio.run(run)


def test_remote_guard_forwards_lifespan_to_the_real_mcp_app(
    certificate: tuple[Path, Path],
    tmp_path: Path,
    tls_server: Callable[[Any, RemoteMCPConfig], Any],
) -> None:
    """The MCP session manager owns a task group started by its lifespan.

    A guard that swallows the lifespan scope leaves every request failing with
    "Task group is not initialized", which no spy-app test can catch.
    """

    from gove_zone.mcp_reference import create_reference_runtime
    from gove_zone.mcp_runtime import build_mcp_server, build_streamable_http_app

    port = _free_port()
    config = _workload_config(certificate, bind_port=port, canonical_host=f"localhost:{port}")
    certfile, _ = certificate

    async def run() -> None:

        runtime = await create_reference_runtime(
            tmp_path / "remote-lifespan-state",
            inbound_token=_TOKEN,
            session_id=_SESSION,
        )
        try:
            inner = build_streamable_http_app(
                build_mcp_server(runtime.gateway),
                allowed_hosts=[config.canonical_host],
                allowed_origins=[],
            )
            app = build_remote_app(inner, config, readiness=None)
            server = tls_server(app, config)
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(server.serve)
                await _await_startup(server)
                context = ssl.create_default_context(cafile=str(certfile))
                async with httpx.AsyncClient(verify=context) as client:
                    response = await client.post(
                        f"https://localhost:{port}/mcp",
                        headers={
                            "Authorization": f"Bearer {_TOKEN}",
                            "Content-Type": "application/json",
                            "Accept": "application/json, text/event-stream",
                        },
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "probe", "version": "1"},
                            },
                        },
                    )
                    # 500 here means the lifespan never reached the session manager.
                    assert response.status_code == 200, response.text
                    assert "serverInfo" in response.text
                server.should_exit = True
        finally:
            await runtime.aclose()

    anyio.run(run)


# ==========================================================================
# Actual CLI process, remote mode: the real `gove_zone.cli mcp serve-http
# --remote` entrypoint over a real TLS socket with an official streamable
# HTTP client and a real asymmetric EdDSA-JWS workload identity.
# ==========================================================================


def _mint_actual_cli_remote_jws(
    *,
    signer: Any,
    kid: str,
    issuer: str,
    audience: str,
    resource: str,
    session_id: str,
    scope: str,
) -> str:
    """Mint one compact EdDSA JWS matching the reference runtime's fixed identity.

    The reference runtime (``create_reference_runtime``) hardcodes the trusted
    issuer/audience/resource and the allowed client/tenant/role regardless of
    the CLI's own ``--identity-*`` flags, so the claims below pin those exact
    fixture-identity constants; only the signing key and expected-host/port are
    test-local.
    """

    def _b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    header = {"alg": "EdDSA", "typ": "at+jwt", "kid": kid}
    now = int(datetime.now(UTC).timestamp())
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": "fixture-agent",
        "client_id": "fixture-agent-client",
        "user_id": "fixture-agent",
        "tenant_id": "fixture-tenant",
        "role": "automation-agent",
        "authority": "mcp.tools.call",
        "scope": scope,
        "resource": resource,
        "sid": session_id,
        "jti": f"actual-cli-remote-{kid}",
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + 600,
    }
    header_segment = _b64(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_segment = _b64(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signed = f"{header_segment}.{payload_segment}".encode("ascii")
    signature = bytes.fromhex(signer.sign(signed))
    return f"{header_segment}.{payload_segment}.{_b64(signature)}"


def test_actual_cli_remote_governs_the_streamable_http_tool_and_exits_cleanly(
    tmp_path: Path,
    certificate: tuple[Path, Path],
) -> None:
    """The real `mcp serve-http --remote` subprocess, an official client, and SIGTERM.

    No in-process app or `tls_server` fixture: this drives the actual CLI
    entrypoint over loopback TLS with a real asymmetric EdDSA-JWS token, then
    proves the process shuts down cleanly on SIGTERM.
    """

    from gove_zone.signing import Ed25519Signer

    async def run() -> None:
        certfile, keyfile = certificate
        state = tmp_path / "actual-cli-remote-state"
        port = _free_port()
        canonical_host = f"localhost:{port}"

        issuer = "https://identity.fixture.invalid"
        audience = "acgs-mcp-gateway"
        resource = "mcp://fixture-server"
        kid = "actual-cli-remote-authority-1"
        authority = Ed25519Signer.generate(kid)
        trust_file = tmp_path / "trust.json"
        trust_file.write_text(
            json.dumps(
                {
                    kid: base64.urlsafe_b64encode(authority.public_bytes())
                    .decode("ascii")
                    .rstrip("=")
                }
            ),
            encoding="utf-8",
        )
        token = _mint_actual_cli_remote_jws(
            signer=authority,
            kid=kid,
            issuer=issuer,
            audience=audience,
            resource=resource,
            session_id=_SESSION,
            scope="tools:list fixture:catalog fixture:read fixture:write",
        )

        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "gove_zone.cli",
                "mcp",
                "serve-http",
                "--remote",
                "--state-dir",
                str(state),
                "--token-file",
                str(_token_file(tmp_path)),
                "--session-id",
                _SESSION,
                "--port",
                str(port),
                "--cert-file",
                str(certfile),
                "--key-file",
                str(keyfile),
                "--expected-host",
                canonical_host,
                "--allow-absent-origin",
                "--identity-trust-file",
                str(trust_file),
                "--identity-issuer",
                issuer,
                "--identity-audience",
                audience,
                "--identity-resource",
                resource,
                "--limit-concurrency",
                "8",
                "--timeout-graceful-shutdown",
                "5",
            ],
            cwd=Path.cwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            try:
                await _wait_for_port(port, process)
            except RuntimeError:
                stdout, stderr = process.communicate(timeout=5)
                raise RuntimeError(
                    "actual CLI `mcp serve-http --remote` failed to start: "
                    f"stdout={stdout!r} stderr={stderr!r}"
                ) from None

            context = ssl.create_default_context(cafile=str(certfile))
            async with (
                httpx.AsyncClient(
                    headers={
                        "Authorization": f"Bearer {token}",
                        "X-ACGS-Session-ID": _SESSION,
                    },
                    verify=context,
                ) as client,
                streamable_http_client(
                    f"https://localhost:{port}/mcp",
                    http_client=client,
                ) as streams,
                ClientSession(streams[0], streams[1]) as session,
            ):
                await session.initialize()
                tools = await session.list_tools()
                assert "fixture.write_once" in {tool.name for tool in tools.tools}

                allowed = await session.call_tool(
                    "fixture.write_once",
                    {"record": "actual-cli-remote-allowed"},
                    meta=_authorization("nonce-actual-cli-remote", "idempotency-actual-cli-remote"),
                )
                assert allowed.isError is False
                assert allowed.meta is not None
                decision = allowed.meta["io.acgs/decision"]
                assert decision["status"] == "succeeded"
                assert decision["receipt"]["decision"] == "allow"
                assert _ledger(state) == [{"record": "actual-cli-remote-allowed"}]

                denied = await session.call_tool(
                    "fixture.write_once",
                    {"record": "actual-cli-remote-denied"},
                )
                assert denied.isError is True
                assert denied.meta is not None
                refusal = denied.meta["io.acgs/decision"]
                assert refusal["decision"] == "deny"
                assert _ledger(state) == [{"record": "actual-cli-remote-allowed"}]

            # Client and session are closed by the `with` block above; only now
            # does the graceful-shutdown probe begin.
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=10)
                raise AssertionError(
                    "actual CLI `mcp serve-http --remote` did not exit within the "
                    f"graceful-shutdown timeout after SIGTERM; stderr:\n{stderr}"
                ) from None
            # Uvicorn's Server.capture_signals() runs its graceful shutdown to
            # completion and only then re-raises the captured SIGTERM against
            # the restored default handler, so a clean shutdown is reported by
            # POSIX as signal-terminated (-SIGTERM), not exit code 0.  A hung
            # shutdown falling through to the `kill()` branch above would
            # instead surface -SIGKILL, which this distinguishes from.
            assert process.returncode == -signal.SIGTERM, (
                "actual CLI `mcp serve-http --remote` did not shut down via a clean "
                f"re-raised SIGTERM; returncode={process.returncode} "
                f"stdout:\n{stdout}\nstderr:\n{stderr}"
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    anyio.run(run)
