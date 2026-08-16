"""Focused security tests for the fixed Remote MCP HTTP transport."""

from __future__ import annotations

import gzip
import json
import socket
import ssl
import threading
import zlib
from collections.abc import Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

import anyio
import httpcore
import httpx
import pytest

from gove_zone.mcp_gateway import MCPDownstreamCredential, MCPDownstreamTransport
from gove_zone.mcp_http_transport import (
    MCPFixedHTTPTransport,
    MCPHTTPTransportConfig,
    MCPHTTPTransportError,
    _PinnedHTTPXTransport,
    _PinnedNetworkBackend,
)
from gove_zone.mcp_security import MCPOriginError, MCPOriginValidator
from gove_zone.side_effect_kernel import AdapterOutcomeStatus


@dataclass
class _State:
    authorization: list[str] = field(default_factory=list)
    bodies: list[dict[str, Any]] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    call_count: int = 0
    redirect: bool = False
    drop_call: bool = False
    encoded_method: str | None = None
    response_encoding: str | None = None
    set_cookie_method: str | None = None
    cookies: list[str] = field(default_factory=list)
    sse_method: str | None = None
    sse_open: bool = False
    sse_payload_override: bytes | None = None
    sse_started: threading.Event = field(default_factory=threading.Event)
    sse_release: threading.Event = field(default_factory=threading.Event)


class _Server(ThreadingHTTPServer):
    state: _State


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        server = cast(_Server, self.server)
        state = server.state
        state.paths.append(self.path)
        state.authorization.append(self.headers.get("Authorization", ""))
        state.cookies.append(self.headers.get("Cookie", ""))
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        request = cast(dict[str, Any], json.loads(raw))
        state.bodies.append(request)
        if state.redirect:
            self.send_response(307)
            self.send_header("Location", f"http://localhost:{server.server_port}/redirected")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        method = request.get("method")
        if method == "tools/call":
            state.call_count += 1
            if state.drop_call:
                self.close_connection = True
                with suppress(OSError):
                    self.connection.shutdown(socket.SHUT_RDWR)
                return
        if "id" not in request:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        if method == "initialize":
            params = cast(dict[str, Any], request["params"])
            result: dict[str, Any] = {
                "protocolVersion": params["protocolVersion"],
                "capabilities": {},
                "serverInfo": {"name": "fixed-fixture", "version": "1.0"},
            }
        elif method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "safe.echo",
                        "description": "Fixed test tool",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"value": {"type": "string"}},
                            "required": ["value"],
                            "additionalProperties": False,
                        },
                    }
                ]
            }
        elif method == "tools/call":
            result = {
                "content": [{"type": "text", "text": "ok"}],
                "isError": False,
                "structuredContent": {"accepted": True},
            }
        else:
            self._json_response(
                {
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "error": {"code": -32601, "message": "denied"},
                },
                cast(str, method),
            )
            return
        self._json_response(
            {"jsonrpc": "2.0", "id": request["id"], "result": result},
            cast(str, method),
        )

    def _json_response(self, payload: dict[str, Any], method: str) -> None:
        state = cast(_Server, self.server).state
        body = json.dumps(payload, separators=(",", ":")).encode()
        if state.sse_method == method:
            body = state.sse_payload_override or (b"event: message\ndata: " + body + b"\n\n")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            if not state.sse_open:
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
            state.sse_started.set()
            if state.sse_open:
                state.sse_release.wait(timeout=5)
            return
        if state.encoded_method == method and state.response_encoding is not None:
            decoded = body + (b" " * 65_536)
            body = (
                gzip.compress(decoded)
                if state.response_encoding == "gzip"
                else zlib.compress(decoded)
            )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if state.encoded_method == method and state.response_encoding is not None:
            self.send_header("Content-Encoding", state.response_encoding)
        if state.set_cookie_method == method:
            self.send_header("Set-Cookie", "forbidden=authority; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class _FakeStream(httpcore.AsyncNetworkStream):
    def __init__(self, peer: object) -> None:
        self.peer = peer
        self.closed = False
        self.tls_hostname: str | None = None

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return b""

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        return

    async def aclose(self) -> None:
        self.closed = True

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.tls_hostname = server_hostname
        return self

    def get_extra_info(self, info: str) -> object:
        return self.peer if info == "server_addr" else None


class _RecordingBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, stream: _FakeStream) -> None:
        self.stream = stream
        self.hosts: list[str] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.hosts.append(host)
        return self.stream

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise AssertionError("Unix sockets must never be used")

    async def sleep(self, seconds: float) -> None:
        return


class _ChunkedOversizeStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.chunks_seen = 0
        self.closed = False

    async def __aiter__(self) -> Any:
        for chunk in (b"123", b"456", b"must-not-be-read"):
            self.chunks_seen += 1
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


@contextmanager
def _fixture() -> Iterator[tuple[_Server, _State]]:
    state = _State()
    server = _Server(("127.0.0.1", 0), _Handler)
    server.state = state
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _credential(secret: str = "fixed-downstream-secret") -> MCPDownstreamCredential:
    now = datetime.now(UTC)
    return MCPDownstreamCredential(
        credential_type="bearer",
        credential_id="fixture-credential",
        tenant_id="tenant-a",
        server_id="fixture-server",
        audience="mcp://fixture-server",
        scopes=("tools:list", "tools:execute"),
        issued_at=(now - timedelta(minutes=1)).isoformat(),
        expires_at=(now + timedelta(minutes=10)).isoformat(),
        secret=secret,
    )


def _target(server: _Server, answers: list[str]) -> tuple[MCPOriginValidator, Any]:
    validator = MCPOriginValidator(resolver=lambda _host, _port: list(answers))
    origin = validator.validate(
        server_id="fixture-server",
        url=f"http://localhost:{server.server_port}/mcp",
        allow_test_local=True,
    )
    return validator, origin


def test_fixed_http_transport_lists_and_calls_without_credential_passthrough() -> None:
    with _fixture() as (server, state):
        answers = ["127.0.0.1"]
        validator, origin = _target(server, answers)
        credential = _credential()
        transport = MCPFixedHTTPTransport(
            validator=validator,
            origin=origin,
            credential=credential,
        )
        assert isinstance(transport, MCPDownstreamTransport)

        async def scenario() -> None:
            async with transport:
                listed = await anyio.to_thread.run_sync(transport.list_tools, origin, credential)
                called = await anyio.to_thread.run_sync(
                    transport.call_tool,
                    origin,
                    credential,
                    "safe.echo",
                    {"value": "inbound-token-must-remain-an-argument"},
                )
                assert [tool.name for tool in listed.tools] == ["safe.echo"]
                assert listed.peer_address == "127.0.0.1"
                assert called.status is AdapterOutcomeStatus.CONFIRMED_SUCCEEDED
                assert called.peer_address == "127.0.0.1"
            await transport.aclose()

        anyio.run(scenario)
        assert state.call_count == 1
        assert state.authorization
        assert set(state.authorization) == {"Bearer fixed-downstream-secret"}
        assert all("fixed-downstream-secret" not in json.dumps(body) for body in state.bodies)
        call_body = next(body for body in state.bodies if body.get("method") == "tools/call")
        assert call_body["params"]["arguments"]["value"] == "inbound-token-must-remain-an-argument"


@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
def test_encoded_response_bomb_is_rejected_before_decoding(encoding: str) -> None:
    with _fixture() as (server, state):
        state.encoded_method = "tools/list"
        state.response_encoding = encoding
        validator, origin = _target(server, ["127.0.0.1"])
        credential = _credential()
        config = MCPHTTPTransportConfig(origin=origin, max_response_bytes=1024)
        transport = MCPFixedHTTPTransport.from_config(
            config,
            validator=validator,
            credential=credential,
        )

        async def scenario() -> None:
            async with transport:
                with pytest.raises(MCPHTTPTransportError):
                    await anyio.to_thread.run_sync(
                        transport.list_tools,
                        origin,
                        credential,
                    )

        anyio.run(scenario)
        assert state.call_count == 0


@pytest.mark.parametrize("open_stream", [False, True])
def test_post_sse_delivers_first_jsonrpc_event_before_close(open_stream: bool) -> None:
    with _fixture() as (server, state):
        state.sse_method = "tools/list"
        state.sse_open = open_stream
        validator, origin = _target(server, ["127.0.0.1"])
        credential = _credential()
        transport = MCPFixedHTTPTransport(
            validator=validator,
            origin=origin,
            credential=credential,
        )

        async def scenario() -> None:
            async with transport:
                listed = await anyio.to_thread.run_sync(
                    transport.list_tools,
                    origin,
                    credential,
                )
                assert [tool.name for tool in listed.tools] == ["safe.echo"]
                assert state.sse_started.is_set()
                if open_stream:
                    assert not state.sse_release.is_set()
                    state.sse_release.set()

        anyio.run(scenario)


def test_open_initialize_sse_completes_before_connection_close() -> None:
    with _fixture() as (server, state):
        state.sse_method = "initialize"
        state.sse_open = True
        validator, origin = _target(server, ["127.0.0.1"])
        transport = MCPFixedHTTPTransport(
            validator=validator,
            origin=origin,
            credential=_credential(),
            timeout_seconds=1,
        )

        async def scenario() -> None:
            try:
                await transport.start()
                assert state.sse_started.is_set()
                assert not state.sse_release.is_set()
            finally:
                state.sse_release.set()
                await transport.aclose()

        anyio.run(scenario)


def test_open_initialize_sse_without_valid_event_times_out_fail_closed() -> None:
    with _fixture() as (server, state):
        state.sse_method = "initialize"
        state.sse_open = True
        state.sse_payload_override = b": keepalive\n\n"
        validator, origin = _target(server, ["127.0.0.1"])
        transport = MCPFixedHTTPTransport(
            validator=validator,
            origin=origin,
            credential=_credential(),
            timeout_seconds=0.2,
        )

        async def scenario() -> None:
            try:
                with pytest.raises(TimeoutError):
                    await transport.start()
                assert state.sse_started.is_set()
            finally:
                state.sse_release.set()
                await transport.aclose()

        anyio.run(scenario)


def test_root_explicit_and_wildcard_exports_include_remote_http_transport() -> None:
    import gove_zone
    from gove_zone import (
        MCPFixedHTTPTransport as ExportedTransport,
    )
    from gove_zone import (
        MCPHTTPTransportConfig as ExportedConfig,
    )
    from gove_zone import (
        MCPHTTPTransportError as ExportedError,
    )

    expected = {
        "MCPFixedHTTPTransport",
        "MCPHTTPTransportConfig",
        "MCPHTTPTransportError",
    }
    assert expected.issubset(gove_zone.__all__)
    assert ExportedTransport is MCPFixedHTTPTransport
    assert ExportedConfig is MCPHTTPTransportConfig
    assert ExportedError is MCPHTTPTransportError


def test_chunked_and_declared_oversize_requests_stop_before_network_dispatch() -> None:
    with _fixture() as (server, state):
        validator, origin = _target(server, ["127.0.0.1"])
        transport = _PinnedHTTPXTransport(
            target=origin,
            validator=validator,
            authorization="Bearer fixed",
            max_request_bytes=5,
            max_response_bytes=1024,
        )
        stream = _ChunkedOversizeStream()

        async def scenario() -> None:
            chunked = httpx.Request(
                "POST",
                origin.url,
                headers={
                    "Authorization": "Bearer fixed",
                    "Accept-Encoding": "identity",
                },
                stream=stream,
            )
            with pytest.raises(MCPHTTPTransportError):
                await transport.handle_async_request(chunked)
            declared = httpx.Request(
                "POST",
                origin.url,
                headers={
                    "Authorization": "Bearer fixed",
                    "Accept-Encoding": "identity",
                    "Content-Length": "999",
                },
                stream=_ChunkedOversizeStream(),
            )
            with pytest.raises(MCPHTTPTransportError):
                await transport.handle_async_request(declared)
            await transport.aclose()

        anyio.run(scenario)
        assert stream.chunks_seen == 2
        assert stream.closed is True
        assert state.paths == []


def test_set_cookie_is_rejected_and_never_stored_or_replayed() -> None:
    with _fixture() as (server, state):
        state.set_cookie_method = "initialize"
        validator, origin = _target(server, ["127.0.0.1"])
        transport = _PinnedHTTPXTransport(
            target=origin,
            validator=validator,
            authorization="Bearer fixed",
            max_request_bytes=4096,
            max_response_bytes=4096,
        )
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        }

        async def scenario() -> None:
            cookie_request = httpx.Request(
                "POST",
                origin.url,
                headers={
                    "Authorization": "Bearer fixed",
                    "Accept-Encoding": "identity",
                    "Cookie": "inbound=forbidden",
                },
                json=payload,
            )
            with pytest.raises(MCPHTTPTransportError):
                await transport.handle_async_request(cookie_request)
            assert state.paths == []
            async with httpx.AsyncClient(
                transport=transport,
                headers={
                    "Authorization": "Bearer fixed",
                    "Accept-Encoding": "identity",
                },
                trust_env=False,
            ) as client:
                first = await client.post(origin.url, json=payload)
                assert "set-cookie" not in first.headers
                assert not client.cookies
                state.set_cookie_method = None
                await client.post(origin.url, json=payload)

        anyio.run(scenario)
        assert state.cookies == ["", ""]


def test_network_backend_connects_to_pin_and_preserves_original_tls_hostname() -> None:
    with _fixture() as (server, _state):
        _validator, origin = _target(server, ["127.0.0.1"])
        stream = _FakeStream(("127.0.0.1", server.server_port))
        inner = _RecordingBackend(stream)
        backend = _PinnedNetworkBackend(inner)

        async def scenario() -> None:
            token = backend.activate(origin)
            try:
                connected = await backend.connect_tcp(origin.hostname, origin.port)
                await connected.start_tls(ssl.create_default_context(), origin.hostname)
            finally:
                backend.deactivate(token)

        anyio.run(scenario)
        assert inner.hosts == ["127.0.0.1"]
        assert stream.tls_hostname == "localhost"


@pytest.mark.parametrize("peer", [None, ("127.0.0.2", 1)])
def test_network_backend_denies_missing_or_mismatched_actual_peer(peer: object) -> None:
    with _fixture() as (server, _state):
        _validator, origin = _target(server, ["127.0.0.1"])
        if isinstance(peer, tuple):
            peer = (peer[0], server.server_port)
        stream = _FakeStream(peer)
        backend = _PinnedNetworkBackend(_RecordingBackend(stream))

        async def scenario() -> None:
            token = backend.activate(origin)
            try:
                with pytest.raises(MCPHTTPTransportError):
                    await backend.connect_tcp(origin.hostname, origin.port)
            finally:
                backend.deactivate(token)

        anyio.run(scenario)
        assert stream.closed is True


def test_dns_change_and_fixed_context_fail_before_new_connection() -> None:
    with _fixture() as (server, state):
        answers = ["127.0.0.1"]
        validator, origin = _target(server, answers)
        credential = _credential()
        transport = MCPFixedHTTPTransport(validator=validator, origin=origin, credential=credential)

        async def scenario() -> None:
            await transport.start()
            before = len(state.bodies)
            answers[:] = ["127.0.0.2"]
            with pytest.raises(MCPOriginError):
                await anyio.to_thread.run_sync(transport.list_tools, origin, credential)
            assert len(state.bodies) == before
            with pytest.raises(MCPHTTPTransportError):
                await anyio.to_thread.run_sync(
                    transport.list_tools,
                    origin,
                    _credential("different-secret"),
                )
            assert len(state.bodies) == before
            await transport.aclose()

        anyio.run(scenario)


def test_redirect_is_not_followed_and_proxy_environment_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _fixture() as (server, state):
        state.redirect = True
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        validator, origin = _target(server, ["127.0.0.1"])
        transport = MCPFixedHTTPTransport(
            validator=validator,
            origin=origin,
            credential=_credential(),
        )

        async def scenario() -> None:
            with pytest.raises(MCPHTTPTransportError):
                await transport.start()
            await transport.aclose()

        anyio.run(scenario)
        assert state.paths == ["/mcp"]


def test_drop_after_recorded_call_is_unknown_and_never_retried() -> None:
    with _fixture() as (server, state):
        state.drop_call = True
        validator, origin = _target(server, ["127.0.0.1"])
        credential = _credential()
        transport = MCPFixedHTTPTransport(
            validator=validator,
            origin=origin,
            credential=credential,
            timeout_seconds=1,
        )

        async def scenario() -> None:
            async with transport:
                result = await anyio.to_thread.run_sync(
                    transport.call_tool,
                    origin,
                    credential,
                    "safe.echo",
                    {"value": "once"},
                )
                assert result.status is AdapterOutcomeStatus.UNKNOWN

        anyio.run(scenario)
        assert state.call_count == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/mcp",
        "http://127.0.0.1/mcp",
        "https://10.0.0.1/mcp",
    ],
)
def test_production_origin_defaults_deny_private_and_metadata_addresses(url: str) -> None:
    validator = MCPOriginValidator(resolver=lambda host, _port: [host])
    with pytest.raises(MCPOriginError):
        validator.validate(server_id="forbidden", url=url)
