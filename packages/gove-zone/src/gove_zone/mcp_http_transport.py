"""Pinned, no-redirect Streamable HTTP transport for the MCP action gateway."""

from __future__ import annotations

import ipaddress
import json
import secrets
import ssl
from collections.abc import AsyncIterator, Iterable, Mapping
from contextlib import AsyncExitStack
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import anyio
import httpcore
import httpx
from anyio.lowlevel import EventLoopToken
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from gove_zone.mcp_gateway import (
    MCPDownstreamCredential,
    MCPDownstreamToolList,
    MCPDownstreamToolResult,
    MCPToolDefinition,
)
from gove_zone.mcp_security import MCPOriginValidator, ValidatedMCPOrigin, ValidatedMCPStdioTarget
from gove_zone.mcp_transport_codec import safe_call_result
from gove_zone.side_effect_kernel import AdapterOutcomeStatus


class MCPHTTPTransportError(RuntimeError):
    """A fail-closed transport invariant violation."""


@dataclass(frozen=True, slots=True)
class MCPHTTPTransportConfig:
    """Secret-free fixed transport configuration for one gateway-owned origin."""

    origin: ValidatedMCPOrigin
    timeout_seconds: float = 5.0
    max_request_bytes: int = 1_048_576
    max_response_bytes: int = 4_194_304

    def __post_init__(self) -> None:
        if not isinstance(self.origin, ValidatedMCPOrigin):
            raise TypeError("origin must be a ValidatedMCPOrigin")
        if type(self.timeout_seconds) not in (int, float) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        for name in ("max_request_bytes", "max_response_bytes"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


def _contains_http_transport_error(exc: BaseException) -> bool:
    if isinstance(exc, BaseExceptionGroup):
        return any(_contains_http_transport_error(item) for item in exc.exceptions)
    return isinstance(exc, MCPHTTPTransportError)


def _peer_address(stream: httpcore.AsyncNetworkStream) -> tuple[str, int]:
    raw = stream.get_extra_info("server_addr")
    if not isinstance(raw, tuple) or len(raw) < 2:
        raise MCPHTTPTransportError("trustworthy downstream peer is unavailable")
    try:
        address = ipaddress.ip_address(str(raw[0])).compressed
        port = int(raw[1])
    except (TypeError, ValueError):
        raise MCPHTTPTransportError("trustworthy downstream peer is unavailable") from None
    return address, port


class _PinnedNetworkStream(httpcore.AsyncNetworkStream):
    def __init__(
        self,
        stream: httpcore.AsyncNetworkStream,
        target: ValidatedMCPOrigin,
        backend: _PinnedNetworkBackend,
    ) -> None:
        self._stream = stream
        self._target = target
        self._backend = backend

    async def validate(self) -> None:
        try:
            address, port = _peer_address(self._stream)
            if address not in self._target.pinned_addresses or port != self._target.port:
                raise MCPHTTPTransportError("downstream peer does not match the pinned target")
        except BaseException:
            await self._stream.aclose()
            raise
        self._backend.record_connected_peer(address)

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._stream.read(max_bytes, timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._stream.write(buffer, timeout)

    async def aclose(self) -> None:
        await self._stream.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if server_hostname != self._target.hostname:
            await self._stream.aclose()
            raise MCPHTTPTransportError("TLS server identity does not match the fixed target")
        stream = await self._stream.start_tls(ssl_context, server_hostname, timeout)
        wrapped = _PinnedNetworkStream(stream, self._target, self._backend)
        await wrapped.validate()
        return wrapped

    def get_extra_info(self, info: str) -> Any:
        return self._stream.get_extra_info(info)


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Resolve policy outside HTTPCore, then connect to one exact pinned IP."""

    def __init__(self, inner: httpcore.AsyncNetworkBackend | None = None) -> None:
        self._inner = inner or httpcore.AnyIOBackend()
        self._target: ContextVar[ValidatedMCPOrigin | None] = ContextVar(
            "acgs_mcp_http_target",
            default=None,
        )
        self._last_peer: str | None = None
        self._connected_count = 0

    @property
    def last_peer(self) -> str | None:
        return self._last_peer

    @property
    def connected_count(self) -> int:
        return self._connected_count

    def activate(self, target: ValidatedMCPOrigin) -> Token[ValidatedMCPOrigin | None]:
        return self._target.set(target)

    def deactivate(self, token: Token[ValidatedMCPOrigin | None]) -> None:
        self._target.reset(token)

    def record_connected_peer(self, address: str) -> None:
        self._last_peer = address
        self._connected_count += 1

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        target = self._target.get()
        if target is None or host != target.hostname or port != target.port:
            raise MCPHTTPTransportError("network connect is outside the fixed target")
        stream = await self._inner.connect_tcp(
            target.pinned_addresses[0],
            target.port,
            timeout,
            local_address,
            socket_options,
        )
        wrapped = _PinnedNetworkStream(stream, target, self)
        await wrapped.validate()
        return wrapped

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise MCPHTTPTransportError("Unix sockets are forbidden for remote MCP")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class _PinnedHTTPXTransport(httpx.AsyncBaseTransport):
    def __init__(
        self,
        *,
        target: ValidatedMCPOrigin,
        validator: MCPOriginValidator,
        authorization: str,
        max_request_bytes: int,
        max_response_bytes: int,
    ) -> None:
        self._target = target
        self._validator = validator
        self._authorization = authorization
        self._max_request_bytes = max_request_bytes
        self._max_response_bytes = max_response_bytes
        self._backend = _PinnedNetworkBackend()
        self._pool = httpcore.AsyncConnectionPool(
            network_backend=self._backend,
            max_connections=4,
            max_keepalive_connections=0,
            http2=False,
            retries=0,
        )

    @property
    def last_peer(self) -> str | None:
        return self._backend.last_peer

    @property
    def connected_count(self) -> int:
        return self._backend.connected_count

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        current = self._validator.reconcile(self._target)
        if str(request.url) != current.url or request.method not in {"POST", "GET", "DELETE"}:
            raise MCPHTTPTransportError("outbound request is outside the fixed MCP endpoint")
        raw_authority = [
            value for name, value in request.headers.raw if name.lower() == b"authorization"
        ]
        if len(raw_authority) != 1 or not secrets.compare_digest(
            raw_authority[0],
            self._authorization.encode("utf-8"),
        ):
            raise MCPHTTPTransportError("downstream credential binding mismatch")
        if any(name.lower() == b"proxy-authorization" for name, _ in request.headers.raw):
            raise MCPHTTPTransportError("proxy credential passthrough is forbidden")
        if any(name.lower() == b"cookie" for name, _ in request.headers.raw):
            raise MCPHTTPTransportError("outbound cookies are forbidden for remote MCP")
        accept_encoding = [
            value.strip().lower()
            for name, value in request.headers.raw
            if name.lower() == b"accept-encoding"
        ]
        if accept_encoding != [b"identity"]:
            raise MCPHTTPTransportError("remote MCP requires identity response encoding")
        body = await _read_bounded_request(request, self._max_request_bytes)
        headers = [
            (name, value) for name, value in request.headers.raw if name.lower() != b"connection"
        ]
        headers.append((b"connection", b"close"))
        connected_before = self._backend.connected_count
        token = self._backend.activate(current)
        try:
            try:
                response = await self._pool.handle_async_request(
                    httpcore.Request(
                        request.method,
                        str(request.url),
                        headers=headers,
                        content=body,
                        extensions=dict(request.extensions),
                    )
                )
            except Exception:
                if self._backend.connected_count > connected_before:
                    ambiguous = _ambiguous_call_response(request, body)
                    if ambiguous is not None:
                        return ambiguous
                raise
        finally:
            self._backend.deactivate(token)
        try:
            if 300 <= response.status < 400:
                raise MCPHTTPTransportError("redirects are forbidden for remote MCP")
            if _forbidden_response_encoding(response.headers):
                await response.aclose()
                return _protocol_error_response(
                    request,
                    body,
                    "encoded downstream responses are forbidden",
                )
            if any(name.lower() == b"set-cookie" for name, _ in response.headers):
                await response.aclose()
                return _protocol_error_response(
                    request,
                    body,
                    "downstream cookies are forbidden",
                )
            if response.status not in {202, 204} and not _valid_mcp_content_type(response.headers):
                await response.aclose()
                return _protocol_error_response(
                    request,
                    body,
                    "MCP response content type is invalid",
                )
            if self._backend.last_peer is None:
                raise MCPHTTPTransportError("trustworthy downstream peer is unavailable")
            return httpx.Response(
                response.status,
                headers=response.headers,
                stream=_BoundedCoreResponseStream(response, self._max_response_bytes),
                request=request,
            )
        except BaseException:
            await response.aclose()
            raise

    async def aclose(self) -> None:
        await self._pool.aclose()


def _valid_mcp_content_type(headers: list[tuple[bytes, bytes]]) -> bool:
    values = [value for name, value in headers if name.lower() == b"content-type"]
    if len(values) != 1:
        return False
    media_type = values[0].split(b";", 1)[0].strip().lower()
    return media_type in {b"application/json", b"text/event-stream"}


def _forbidden_response_encoding(headers: list[tuple[bytes, bytes]]) -> bool:
    values = [
        value.strip().lower() for name, value in headers if name.lower() == b"content-encoding"
    ]
    return bool(values) and values != [b"identity"]


async def _read_bounded_request(request: httpx.Request, limit: int) -> bytes:
    stream = request.stream
    if not isinstance(stream, httpx.AsyncByteStream):
        stream.close()
        raise MCPHTTPTransportError("asynchronous MCP request stream is required")
    lengths = [value for name, value in request.headers.raw if name.lower() == b"content-length"]
    if lengths:
        if len(lengths) != 1:
            await stream.aclose()
            raise MCPHTTPTransportError("MCP request Content-Length is ambiguous")
        try:
            declared = int(lengths[0])
        except ValueError:
            await stream.aclose()
            raise MCPHTTPTransportError("MCP request Content-Length is invalid") from None
        if declared < 0 or declared > limit:
            await stream.aclose()
            raise MCPHTTPTransportError("MCP request exceeds the configured bound")
    chunks: list[bytes] = []
    total = 0
    async for chunk in stream:
        total += len(chunk)
        if total > limit:
            await stream.aclose()
            raise MCPHTTPTransportError("MCP request exceeds the configured bound")
        chunks.append(chunk)
    await stream.aclose()
    return b"".join(chunks)


class _BoundedCoreResponseStream(httpx.AsyncByteStream):
    def __init__(self, response: httpcore.Response, limit: int) -> None:
        self._response = response
        self._limit = limit
        self._total = 0
        self._closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            async for chunk in self._response.aiter_stream():
                self._total += len(chunk)
                if self._total > self._limit:
                    await self.aclose()
                    raise MCPHTTPTransportError("MCP response exceeds the configured bound")
                yield chunk
        except BaseException:
            await self.aclose()
            raise

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            await self._response.aclose()


def _protocol_error_response(
    request: httpx.Request,
    body: bytes,
    message: str,
) -> httpx.Response:
    response = _jsonrpc_error_response(request, body, message)
    if response is None:
        raise MCPHTTPTransportError(message)
    return response


def _ambiguous_call_response(request: httpx.Request, body: bytes) -> httpx.Response | None:
    """Keep the SDK task alive while preserving an UNKNOWN tool-call outcome."""

    response = _jsonrpc_error_response(request, body, "downstream outcome unknown")
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        return None
    if type(payload) is not dict or payload.get("method") != "tools/call":
        return None
    return response


def _jsonrpc_error_response(
    request: httpx.Request,
    body: bytes,
    message: str,
) -> httpx.Response | None:
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        return None
    if type(payload) is not dict or "id" not in payload:
        return None
    response = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": payload["id"],
            "error": {"code": -32001, "message": message},
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return httpx.Response(
        200,
        headers={"Content-Type": "application/json", "Connection": "close"},
        content=response,
        request=request,
    )


class MCPFixedHTTPTransport:
    """One fixed origin and credential, with no redirect, proxy, or retry path."""

    def __init__(
        self,
        *,
        validator: MCPOriginValidator,
        origin: ValidatedMCPOrigin,
        credential: MCPDownstreamCredential,
        timeout_seconds: float = 5.0,
        max_request_bytes: int = 1_048_576,
        max_response_bytes: int = 4_194_304,
    ) -> None:
        if not isinstance(validator, MCPOriginValidator):
            raise TypeError("validator must be an MCPOriginValidator")
        if not isinstance(origin, ValidatedMCPOrigin):
            raise TypeError("origin must be a ValidatedMCPOrigin")
        if not isinstance(credential, MCPDownstreamCredential):
            raise TypeError("credential must be an MCPDownstreamCredential")
        if credential.server_id != origin.server_id:
            raise MCPHTTPTransportError("credential server does not match the fixed target")
        if type(timeout_seconds) not in (int, float) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if type(max_request_bytes) is not int or max_request_bytes <= 0:
            raise ValueError("max_request_bytes must be a positive integer")
        if type(max_response_bytes) is not int or max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be a positive integer")
        self._validator = validator
        self._origin = origin
        self._credential = credential
        self._timeout_seconds = float(timeout_seconds)
        self._max_request_bytes = max_request_bytes
        self._max_response_bytes = max_response_bytes
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None
        self._http_transport: _PinnedHTTPXTransport | None = None
        self._token: EventLoopToken | None = None
        self._lock: anyio.Lock | None = None
        self._closed = False

    @classmethod
    def from_config(
        cls,
        config: MCPHTTPTransportConfig,
        *,
        validator: MCPOriginValidator,
        credential: MCPDownstreamCredential,
    ) -> MCPFixedHTTPTransport:
        """Build the sole configured transport; no fallback is accepted."""

        if not isinstance(config, MCPHTTPTransportConfig):
            raise TypeError("config must be an MCPHTTPTransportConfig")
        return cls(
            validator=validator,
            origin=config.origin,
            credential=credential,
            timeout_seconds=config.timeout_seconds,
            max_request_bytes=config.max_request_bytes,
            max_response_bytes=config.max_response_bytes,
        )

    @property
    def origin(self) -> ValidatedMCPOrigin:
        return self._origin

    async def start(self) -> ValidatedMCPOrigin:
        if self._stack is not None or self._closed:
            raise RuntimeError("HTTP transport is single-use")
        target = self._validator.reconcile(self._origin)
        authorization = f"Bearer {self._credential.secret}"
        transport = _PinnedHTTPXTransport(
            target=target,
            validator=self._validator,
            authorization=authorization,
            max_request_bytes=self._max_request_bytes,
            max_response_bytes=self._max_response_bytes,
        )
        stack = AsyncExitStack()
        try:
            client = await stack.enter_async_context(
                httpx.AsyncClient(
                    headers={
                        "Authorization": authorization,
                        "Accept-Encoding": "identity",
                        "Connection": "close",
                    },
                    timeout=httpx.Timeout(self._timeout_seconds),
                    follow_redirects=False,
                    trust_env=False,
                    transport=transport,
                )
            )
            streams = await stack.enter_async_context(
                streamable_http_client(target.url, http_client=client, terminate_on_close=True)
            )
            session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
            with anyio.fail_after(self._timeout_seconds):
                await session.initialize()
        except BaseException as exc:
            failure = exc
            try:
                await stack.aclose()
            except BaseException as close_exc:
                failure = close_exc
            if _contains_http_transport_error(failure):
                raise MCPHTTPTransportError("remote MCP session failed closed") from None
            raise failure from None
        self._stack = stack
        self._session = session
        self._http_transport = transport
        self._token = anyio.lowlevel.current_token()
        self._lock = anyio.Lock()
        return target

    async def aclose(self) -> None:
        stack = self._stack
        self._closed = True
        self._session = None
        self._http_transport = None
        self._stack = None
        if stack is not None:
            await stack.aclose()

    async def __aenter__(self) -> MCPFixedHTTPTransport:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    def list_tools(
        self,
        origin: ValidatedMCPOrigin | ValidatedMCPStdioTarget,
        credential: MCPDownstreamCredential,
    ) -> MCPDownstreamToolList:
        target = self._exact_context(origin, credential)
        return anyio.from_thread.run(
            self._list_tools,
            target,
            credential,
            token=self._event_loop_token(),
        )

    def call_tool(
        self,
        origin: ValidatedMCPOrigin | ValidatedMCPStdioTarget,
        credential: MCPDownstreamCredential,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> MCPDownstreamToolResult:
        target = self._exact_context(origin, credential)
        return anyio.from_thread.run(
            self._call_tool,
            target,
            credential,
            tool_name,
            dict(arguments),
            token=self._event_loop_token(),
        )

    def _event_loop_token(self) -> EventLoopToken:
        if self._token is None or self._closed:
            raise RuntimeError("HTTP MCP session is unavailable before send")
        return self._token

    def _exact_context(
        self,
        origin: ValidatedMCPOrigin | ValidatedMCPStdioTarget,
        credential: MCPDownstreamCredential,
    ) -> ValidatedMCPOrigin:
        if not isinstance(origin, ValidatedMCPOrigin) or origin != self._origin:
            raise MCPHTTPTransportError("request target does not match the fixed origin")
        if (
            not isinstance(credential, MCPDownstreamCredential)
            or not secrets.compare_digest(credential.binding_hash, self._credential.binding_hash)
            or not secrets.compare_digest(credential.secret, self._credential.secret)
        ):
            raise MCPHTTPTransportError("request credential does not match the fixed authority")
        return self._validator.reconcile(origin)

    def _active(self) -> tuple[ClientSession, anyio.Lock, _PinnedHTTPXTransport]:
        if (
            self._session is None
            or self._lock is None
            or self._http_transport is None
            or self._closed
        ):
            raise RuntimeError("HTTP MCP session is unavailable before send")
        return self._session, self._lock, self._http_transport

    async def _list_tools(
        self,
        target: ValidatedMCPOrigin,
        credential: MCPDownstreamCredential,
    ) -> MCPDownstreamToolList:
        session, lock, transport = self._active()
        async with lock:
            self._validator.reconcile(target)
            try:
                with anyio.fail_after(self._timeout_seconds):
                    result = await session.list_tools()
            except BaseException as exc:
                if isinstance(exc, anyio.get_cancelled_exc_class()):
                    raise
                raise MCPHTTPTransportError("downstream catalog is unavailable") from None
        peer = transport.last_peer
        if peer is None:
            raise MCPHTTPTransportError("trustworthy downstream peer is unavailable")
        return MCPDownstreamToolList(
            tuple(
                MCPToolDefinition(
                    name=tool.name,
                    description=tool.description or "",
                    input_schema=tool.inputSchema,
                )
                for tool in result.tools
            ),
            response_origin=target.url,
            peer_address=peer,
        )

    async def _call_tool(
        self,
        target: ValidatedMCPOrigin,
        credential: MCPDownstreamCredential,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> MCPDownstreamToolResult:
        session, lock, transport = self._active()
        async with lock:
            self._validator.reconcile(target)
            connected_before = transport.connected_count
            try:
                with anyio.fail_after(self._timeout_seconds):
                    result = await session.call_tool(
                        tool_name,
                        arguments,
                        read_timeout_seconds=timedelta(seconds=self._timeout_seconds),
                    )
            except BaseException as exc:
                if isinstance(exc, anyio.get_cancelled_exc_class()):
                    raise
                peer = transport.last_peer
                if transport.connected_count <= connected_before or peer is None:
                    raise MCPHTTPTransportError("downstream call failed before dispatch") from None
                return MCPDownstreamToolResult(
                    AdapterOutcomeStatus.UNKNOWN,
                    None,
                    response_origin=target.url,
                    peer_address=peer,
                )
        peer = transport.last_peer
        if peer is None:
            raise MCPHTTPTransportError("trustworthy downstream peer is unavailable")
        if result.isError:
            return MCPDownstreamToolResult(
                AdapterOutcomeStatus.UNKNOWN,
                None,
                response_origin=target.url,
                peer_address=peer,
            )
        payload = safe_call_result(result, credential)
        if payload is None:
            return MCPDownstreamToolResult(
                AdapterOutcomeStatus.UNKNOWN,
                None,
                response_origin=target.url,
                peer_address=peer,
            )
        return MCPDownstreamToolResult(
            AdapterOutcomeStatus.CONFIRMED_SUCCEEDED,
            payload,
            response_origin=target.url,
            peer_address=peer,
        )


__all__ = ["MCPFixedHTTPTransport", "MCPHTTPTransportConfig", "MCPHTTPTransportError"]
