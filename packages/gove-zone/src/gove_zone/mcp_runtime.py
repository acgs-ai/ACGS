"""Official MCP protocol adapters for the shared P1 action gateway core."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shutil
import stat
import tempfile
import threading
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

import anyio
from mcp import ClientSession, types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import McpError
from mcp.shared.message import SessionMessage
from starlette.applications import Starlette
from starlette.routing import Route

from gove_zone.authorization import EvidenceRef, deep_thaw_json, validate_strict_json_budget
from gove_zone.mcp_gateway import (
    MCPActionGateway,
    MCPGatewayResponse,
    MCPGatewayStatus,
    MCPToolListResponse,
)

AUTHORIZATION_META_KEY = "io.acgs/authorization"
DECISION_META_KEY = "io.acgs/decision"
SESSION_HEADER = "x-acgs-session-id"
_AUTH_KEYS = frozenset({"nonce", "idempotencyKey", "requestedAt", "evidence", "goal"})
_EVIDENCE_KEYS = frozenset(
    {"evidenceId", "evidenceType", "digest", "issuer", "issuedAt", "expiresAt"}
)
_MAX_TOKEN_BYTES = 8192
_MAX_REQUEST_ID_BYTES = 4096


def read_secret_file(path: Path) -> str:
    """Read a bounded operator-owned token from one no-follow descriptor."""

    nofollow = getattr(os, "O_NOFOLLOW", None)
    cloexec = getattr(os, "O_CLOEXEC", None)
    if nofollow is None or cloexec is None:
        raise ValueError("platform lacks secure token-file open flags")
    flags = os.O_RDONLY | cloexec | nofollow
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ValueError("token file must be a private owner regular file") from None
    try:
        info = os.fstat(descriptor)
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or mode not in {0o400, 0o600}
            or info.st_size > _MAX_TOKEN_BYTES
        ):
            raise ValueError("token file must be owner-owned with mode 0600 or stricter")
        payload = bytearray()
        while chunk := os.read(descriptor, min(4096, _MAX_TOKEN_BYTES + 1 - len(payload))):
            payload.extend(chunk)
            if len(payload) > _MAX_TOKEN_BYTES:
                raise ValueError("token file exceeds the bounded size")
        try:
            decoded = bytes(payload).decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise ValueError("token file must contain strict UTF-8") from None
    finally:
        os.close(descriptor)
    value = decoded.removesuffix("\n")
    if not value or "\n" in value or "\r" in value:
        raise ValueError("token file must contain exactly one non-empty token")
    return value


def _require_same_file(descriptor: int, expected: os.stat_result) -> None:
    """Fail closed when the opened file was swapped underneath the descriptor."""

    current = os.fstat(descriptor)
    if (
        current.st_ino != expected.st_ino
        or current.st_dev != expected.st_dev
        or current.st_nlink != expected.st_nlink
        or current.st_uid != expected.st_uid
        or stat.S_IMODE(current.st_mode) != stat.S_IMODE(expected.st_mode)
    ):
        raise ValueError("secret file was replaced while it was being read")


def _iso_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _request_id(session_id: str, protocol_request_id: int | str) -> str:
    if type(session_id) is not str:
        raise TypeError("session ID must be a string")
    session_bytes = session_id.encode("utf-8", errors="strict")
    if len(session_bytes) > _MAX_REQUEST_ID_BYTES:
        raise ValueError("session ID is oversized")
    if type(protocol_request_id) is int:
        request_type = "integer"
        request_value = str(protocol_request_id)
    elif type(protocol_request_id) is str:
        request_type = "string"
        request_value = protocol_request_id
    else:
        raise TypeError("protocol request ID must be an integer or string")
    if len(request_value.encode("utf-8", errors="strict")) > _MAX_REQUEST_ID_BYTES:
        raise ValueError("protocol request ID is oversized")
    encoded = json.dumps(
        {
            "domain": "gove-zone.mcp-request.v2",
            "protocol_request_id": {"type": request_type, "value": request_value},
            "session_id": {"type": "string", "value": session_id},
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    return f"mcp-{digest[:32]}"


def _handler_request_id(session_id: str, protocol_request_id: object) -> str:
    try:
        return _request_id(session_id, cast(int | str, protocol_request_id))
    except (TypeError, ValueError, UnicodeError):
        return ""


def _meta_mapping(server: Server[Any]) -> dict[str, Any]:
    meta = server.request_context.meta
    if meta is None:
        return {}
    value = meta.model_dump(mode="json", by_alias=True, exclude_none=True)
    if type(value) is not dict:
        return {}
    validate_strict_json_budget(value)
    return value


def _inbound_identity(
    server: Server[Any],
    *,
    stdio_token: str | None,
    stdio_session_id: str | None,
) -> tuple[str, str]:
    request = server.request_context.request
    if request is None:
        if stdio_token is None or stdio_session_id is None:
            return "", ""
        return stdio_token, stdio_session_id
    headers = request.headers
    authorization = headers.get("authorization", "")
    prefix = "Bearer "
    token = authorization[len(prefix) :] if authorization.startswith(prefix) else ""
    return token, headers.get(SESSION_HEADER, "")


def _evidence(value: object) -> tuple[EvidenceRef, ...]:
    if type(value) is not list:
        raise ValueError("evidence must be a list")
    result: list[EvidenceRef] = []
    for item in value:
        if type(item) is not dict or set(item) != _EVIDENCE_KEYS:
            raise ValueError("evidence entry is malformed")
        result.append(
            EvidenceRef(
                evidence_id=item["evidenceId"],
                evidence_type=item["evidenceType"],
                digest=item["digest"],
                issuer=item["issuer"],
                issued_at=item["issuedAt"],
                expires_at=item["expiresAt"],
            )
        )
    return tuple(result)


def _call_params(name: str, arguments: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    authorization = meta.get(AUTHORIZATION_META_KEY)
    if type(authorization) is not dict or set(authorization) != _AUTH_KEYS:
        return {"name": name, "arguments": arguments, "malformed_authorization": True}
    validate_strict_json_budget(authorization)
    try:
        evidence = _evidence(authorization["evidence"])
    except (KeyError, TypeError, ValueError, RecursionError):
        return {"name": name, "arguments": arguments, "malformed_authorization": True}
    return {
        "name": name,
        "arguments": arguments,
        "nonce": authorization["nonce"],
        "idempotency_key": authorization["idempotencyKey"],
        "requested_at": authorization["requestedAt"],
        "observed_at": _iso_now(),
        "evidence": evidence,
        "goal": authorization["goal"],
    }


def _governance_meta(response: MCPGatewayResponse) -> dict[str, Any]:
    value: dict[str, Any] = {
        "requestId": response.request_id,
        "decision": response.decision.value,
        "status": response.status.value,
        "reasonCodes": list(response.reason_codes),
        "auditEventId": response.audit_event_id or None,
        "executed": response.executed,
        "retryable": response.retryable,
        "outcomeUnknown": response.outcome_unknown,
    }
    if response.receipt is not None:
        value["receipt"] = response.receipt.to_dict()
    if response.refusal_evidence is not None:
        value["refusalEvidence"] = response.refusal_evidence.to_dict()
    if response.execution_refusal_evidence is not None:
        # The execution gate's proof travels the wire in full, and stays separate
        # from the authorization fields above: ``auditEventId``/``refusalEvidence``
        # answer "was this request authorized?", these answer "did this receipted
        # attempt run?". The two audit ids belong to different records, so they are
        # never conflated — a consumer verifies this evidence against the exact
        # attempt, and ``audited``/``signed`` say which proofs actually survived
        # rather than asserting either one.
        value["executionRefusalEvidence"] = response.execution_refusal_evidence.to_dict()
        value["executionRefusalAuditEventId"] = response.execution_refusal_audit_event_id or None
        value["executionRefusalAudited"] = response.execution_refusal_audited
        value["executionRefusalSigned"] = response.execution_refusal_signed
    if response.pending_approval is not None:
        pending = response.pending_approval
        value["pendingApproval"] = {
            "pendingId": pending.pending_id,
            "requestId": pending.request_id,
            "tool": pending.tool,
            "actorId": pending.actor_id,
            "tenantId": pending.tenant_id,
            "auditHash": pending.audit_hash,
            "decisionRequestHash": pending.decision_request_hash,
        }
    return value


def _list_error_data(response: MCPToolListResponse) -> dict[str, Any]:
    value: dict[str, Any] = {
        "requestId": response.request_id,
        "decision": response.decision.value,
        "status": response.status.value,
        "reasonCodes": list(response.reason_codes),
        "auditEventId": response.audit_event_id or None,
        "retryable": response.retryable,
    }
    if response.refusal_evidence is not None:
        value["refusalEvidence"] = response.refusal_evidence.to_dict()
    return value


def build_mcp_server(
    gateway: MCPActionGateway,
    *,
    stdio_token: str | None = None,
    stdio_session_id: str | None = None,
) -> Server[Any]:
    """Register tools/list and tools/call against one authoritative gateway."""

    if not isinstance(gateway, MCPActionGateway):
        raise TypeError("gateway must be an MCPActionGateway")
    if (stdio_token is None) != (stdio_session_id is None):
        raise ValueError("stdio token and session must be configured together")
    server: Server[Any] = Server("acgs-mcp-action-gateway", version="1.0")

    @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
    async def list_tools() -> list[types.Tool]:
        token, session_id = _inbound_identity(
            server,
            stdio_token=stdio_token,
            stdio_session_id=stdio_session_id,
        )
        response = await anyio.to_thread.run_sync(
            lambda: gateway.list_tools(
                inbound_token=token,
                session_id=session_id,
                request_id=_handler_request_id(session_id, server.request_context.request_id),
            )
        )
        if response.status is not MCPGatewayStatus.LISTED:
            raise McpError(
                types.ErrorData(
                    code=-32001,
                    message="ACGS governance denied tools/list",
                    data=_list_error_data(response),
                )
            )
        return [
            types.Tool(
                name=item.name,
                description=item.description,
                inputSchema=cast(dict[str, Any], deep_thaw_json(item.input_schema)),
            )
            for item in response.tools
        ]

    async def call_tool(request: types.CallToolRequest) -> types.ServerResult:
        """Dispatch tools/call without the SDK's implicit tools/list cache lookup."""

        name = request.params.name
        arguments = request.params.arguments or {}
        token, session_id = _inbound_identity(
            server,
            stdio_token=stdio_token,
            stdio_session_id=stdio_session_id,
        )
        request_id = _handler_request_id(session_id, server.request_context.request_id)
        try:
            params = _call_params(name, arguments, _meta_mapping(server))
        except (TypeError, ValueError, RecursionError):
            params = {"name": name, "arguments": arguments, "malformed_authorization": True}
        response = await anyio.to_thread.run_sync(
            lambda: gateway.dispatch(
                "tools/call",
                inbound_token=token,
                session_id=session_id,
                request_id=request_id,
                params=params,
            )
        )
        if not isinstance(response, MCPGatewayResponse):
            raise RuntimeError("gateway returned an invalid tools/call response")
        governance = _governance_meta(response)
        if response.status is MCPGatewayStatus.SUCCEEDED:
            payload = response.payload
            if type(payload) is dict:
                try:
                    downstream = types.CallToolResult.model_validate(payload)
                except Exception:
                    downstream = None
                if downstream is not None:
                    return types.ServerResult(
                        types.CallToolResult(
                            content=downstream.content,
                            structuredContent=downstream.structuredContent,
                            isError=downstream.isError,
                            _meta={DECISION_META_KEY: governance},
                        )
                    )
            return types.ServerResult(
                types.CallToolResult(
                    content=[
                        types.TextContent(type="text", text=json.dumps(payload, sort_keys=True))
                    ],
                    _meta={DECISION_META_KEY: governance},
                )
            )
        return types.ServerResult(
            types.CallToolResult(
                content=[
                    types.TextContent(type="text", text="ACGS governance blocked the tool call")
                ],
                isError=True,
                _meta={DECISION_META_KEY: governance},
            )
        )

    # Deliberately register the low-level request handler directly.  The SDK's
    # ``Server.call_tool`` decorator asks tools/list for an input/output schema
    # before invoking the handler.  That extra lookup would turn a poisoned
    # tools/call into a generic list failure and would append a second denial.
    server.request_handlers[types.CallToolRequest] = call_tool
    return server


@asynccontextmanager
async def _in_process_client_session(
    server: Server[Any],
) -> AsyncIterator[ClientSession]:
    """Initialize one official client over bounded in-memory MCP streams."""

    if not isinstance(server, Server):
        raise TypeError("server must be an MCP low-level Server")
    client_send, server_receive = anyio.create_memory_object_stream[SessionMessage](16)
    server_send, client_receive = anyio.create_memory_object_stream[SessionMessage | Exception](16)
    async with anyio.create_task_group() as tasks:
        tasks.start_soon(
            server.run,
            server_receive,
            server_send,
            server.create_initialization_options(),
            True,
        )
        try:
            async with ClientSession(client_receive, client_send) as session:
                await session.initialize()
                yield session
        finally:
            await client_send.aclose()
            await server_receive.aclose()
            await server_send.aclose()
            await client_receive.aclose()
            tasks.cancel_scope.cancel()


def build_streamable_http_app(
    server: Server[Any],
    *,
    allowed_hosts: list[str],
    allowed_origins: list[str],
) -> Starlette:
    """Build one stateless /mcp ASGI endpoint with exact Host/Origin policy."""

    if not allowed_hosts:
        raise ValueError("at least one exact Host header is required")
    if any(item.endswith(":*") for item in [*allowed_hosts, *allowed_origins]):
        raise ValueError("wildcard Host/Origin patterns are not accepted")
    manager = StreamableHTTPSessionManager(
        server,
        # Stateless JSON-response mode is the whole remote-mode transport
        # contract: no server-side session to resume and no SSE stream to hold
        # open.  The guard's GET/session-ID rejections are only coherent because
        # of these two flags, so they are asserted, not assumed.
        json_response=True,
        stateless=True,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
        ),
    )

    class _ASGIEndpoint:
        #: Exposed so the transport mode can be verified without reflection.
        session_manager = manager

        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            await manager.handle_request(scope, receive, send)

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with manager.run():
            yield

    app = Starlette(routes=[Route("/mcp", endpoint=_ASGIEndpoint())], lifespan=lifespan)
    app.state.session_manager = manager
    return app


async def run_stdio_server(server: Server[Any]) -> None:
    """Serve the same low-level MCP handlers over process stdio."""

    async with stdio_server() as streams:
        read_stream, write_stream = streams
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
            raise_exceptions=False,
        )


class RemoteMCPConfigError(ValueError):
    """A remote-mode startup invariant was not satisfied."""


def _reject(message: str) -> RemoteMCPConfigError:
    return RemoteMCPConfigError(message)


def _printable_ascii(value: str, name: str) -> str:
    """Require canonical, unambiguous ASCII: no control characters, no spaces."""

    if type(value) is not str or not value:
        raise _reject(f"{name} must be a non-empty string")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError:
        raise _reject(f"{name} must be ASCII; IDNA names must be canonical A-labels") from None
    if any(byte <= 0x20 or byte == 0x7F for byte in raw):
        raise _reject(f"{name} must not contain control characters or whitespace")
    if "*" in value:
        raise _reject(f"{name} must not contain a wildcard")
    if value != value.lower():
        raise _reject(f"{name} must be lowercase canonical form")
    return value


def _canonical_port(value: str, name: str) -> int:
    if not value.isdigit() or (len(value) > 1 and value.startswith("0")):
        raise _reject(f"{name} must carry a canonical decimal port")
    port = int(value)
    if not 1 <= port <= 65535:
        raise _reject(f"{name} port is out of range")
    return port


def _canonical_authority(value: str, name: str) -> str:
    """Validate one exact ``host:port`` authority in a single canonical form."""

    text = _printable_ascii(value, name)
    if text.startswith("["):
        host, separator, port_text = text.partition("]:")
        if not separator:
            raise _reject(f"{name} must be an exact host:port authority")
        literal = host[1:]
        try:
            address = ipaddress.IPv6Address(literal)
        except ValueError:
            raise _reject(f"{name} has an invalid IPv6 literal") from None
        if address.compressed != literal:
            raise _reject(f"{name} must use the canonical compressed IPv6 form")
        _canonical_port(port_text, name)
        return text
    host, separator, port_text = text.rpartition(":")
    if not separator or not host:
        raise _reject(f"{name} must be an exact host:port authority")
    if ":" in host:
        raise _reject(f"{name} must bracket an IPv6 literal to be unambiguous")
    _canonical_port(port_text, name)
    if host.endswith("."):
        raise _reject(f"{name} must not use a trailing-dot host")
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if any(not label or len(label) > 63 for label in labels):
            raise _reject(f"{name} has an invalid DNS label") from None
        if any(label.startswith("-") or label.endswith("-") for label in labels):
            raise _reject(f"{name} has an invalid DNS label") from None
        return text
    if host_ip.compressed != host:
        raise _reject(f"{name} must use the canonical IP form")
    return text


def _split_origin_authority(remainder: str, name: str) -> tuple[str, str | None]:
    """Split an origin authority into its host part and any explicit port.

    RFC 6454/3986 allow an explicit port on a serialized origin, so
    ``https://console.example:8443`` is a legal authority that must be
    representable.  IPv6 stays strict: the literal must be bracketed, because an
    unbracketed ``::1`` cannot be split from its port unambiguously.
    """

    if remainder.startswith("["):
        closing = remainder.find("]")
        if closing == -1:
            raise _reject(f"{name} has an unterminated IPv6 literal")
        tail = remainder[closing + 1 :]
        if not tail:
            return remainder, None
        if not tail.startswith(":"):
            raise _reject(f"{name} must be an exact host:port authority")
        return remainder[: closing + 1], tail[1:]
    host, separator, port_text = remainder.rpartition(":")
    if not separator:
        return remainder, None
    if not host or not port_text.isdigit():
        # A colon that does not introduce a decimal port is either an
        # unbracketed IPv6 literal or a malformed authority.  Both are
        # ambiguous, and an ambiguous origin is an allowlist bypass.
        raise _reject(f"{name} must bracket an IPv6 literal to be unambiguous")
    return host, port_text


def _canonical_origin(value: str, name: str = "allowed origin") -> str:
    text = _printable_ascii(value, name)
    if text == "null":
        raise _reject("a null origin is never allowed")
    scheme, separator, remainder = text.partition("://")
    if not separator or scheme not in {"http", "https"}:
        raise _reject(f"{name} must be an exact http(s) origin")
    if "/" in remainder or not remainder:
        raise _reject(f"{name} must not carry a path")
    host_part, port_text = _split_origin_authority(remainder, name)
    default_port = "443" if scheme == "https" else "80"
    if port_text is None:
        # A default-port origin is canonical without an explicit port.
        _canonical_authority(f"{host_part}:{default_port}", name)
        return f"{scheme}://{host_part}"
    if port_text == default_port:
        # A browser serializes ``https://h:443`` as ``https://h``, so accepting
        # both would put one origin in the allowlist under two spellings while
        # only one can ever be compared against.
        raise _reject(f"{name} must omit the scheme default port")
    _canonical_authority(remainder, name)
    return f"{scheme}://{remainder}"


def _loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


_MAX_TLS_MATERIAL_BYTES = 1_048_576


def _secure_secret_file(path: Path, name: str) -> bytes:
    """Validate and read key material through exactly one descriptor.

    The bytes are returned, not just the path.  Validating a path and then
    handing that path to the TLS layer to re-open is a check/use split: whatever
    is at the path at open time is what gets served, regardless of what was
    validated.  Reading through the same validated descriptor removes the second
    open entirely, so there is no window to swap.
    """

    if not isinstance(path, Path):
        raise _reject(f"{name} must be a path")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise _reject("platform lacks the no-follow open flag required for secret files")
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow | os.O_CLOEXEC)
    except OSError:
        raise _reject(f"{name} must be an existing, non-symlink regular file") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise _reject(f"{name} must be a regular file")
        if info.st_uid != os.geteuid():
            raise _reject(f"{name} must be owned by the runtime user")
        if stat.S_IMODE(info.st_mode) not in {0o400, 0o600}:
            raise _reject(f"{name} must be owner-only (0400 or 0600)")
        # A second name for the key is a second place it can be observed or
        # swapped, so nlink must be exactly 1.
        if info.st_nlink != 1:
            raise _reject(f"{name} must have exactly one link")
        payload = bytearray()
        while chunk := os.read(descriptor, 65_536):
            payload.extend(chunk)
            if len(payload) > _MAX_TLS_MATERIAL_BYTES:
                raise _reject(f"{name} exceeds the bounded size")
        # Re-stat the same descriptor.  A rename-over during validation means the
        # bytes just read may not be the file that was validated, so refuse the
        # ambiguity rather than trust a stale identity.
        try:
            _require_same_file(descriptor, info)
        except ValueError as exc:
            raise _reject(f"{name} was replaced while it was being validated") from exc
    except OSError:
        raise _reject(f"{name} could not be read") from None
    finally:
        os.close(descriptor)
    if not payload:
        raise _reject(f"{name} must not be empty")
    return bytes(payload)


def _public_file(path: Path, name: str) -> bytes:
    """Validate and read public material through exactly one descriptor."""

    if not isinstance(path, Path):
        raise _reject(f"{name} must be a path")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise _reject("platform lacks the no-follow open flag required for TLS material")
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow | os.O_CLOEXEC)
    except OSError:
        raise _reject(f"{name} must be an existing, non-symlink regular file") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise _reject(f"{name} must be a regular file")
        payload = bytearray()
        while chunk := os.read(descriptor, 65_536):
            payload.extend(chunk)
            if len(payload) > _MAX_TLS_MATERIAL_BYTES:
                raise _reject(f"{name} exceeds the bounded size")
        try:
            _require_same_file(descriptor, info)
        except ValueError as exc:
            raise _reject(f"{name} was replaced while it was being validated") from exc
    except OSError:
        raise _reject(f"{name} could not be read") from None
    finally:
        os.close(descriptor)
    if not payload:
        raise _reject(f"{name} must not be empty")
    return bytes(payload)


@dataclass(frozen=True, slots=True)
class RemoteMCPBudgets:
    """Fail-closed resource ceilings applied before any MCP dispatch."""

    max_body_bytes: int = 1_048_576
    max_header_bytes: int = 16_384
    max_header_count: int = 64
    limit_concurrency: int = 32
    backlog: int = 64
    timeout_keep_alive: int = 5
    timeout_graceful_shutdown: int = 10
    limit_max_requests: int = 10_000

    def __post_init__(self) -> None:
        for name in (
            "max_body_bytes",
            "max_header_bytes",
            "max_header_count",
            "limit_concurrency",
            "backlog",
            "timeout_keep_alive",
            "timeout_graceful_shutdown",
            "limit_max_requests",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise _reject(f"{name} must be a positive integer")


class RemoteIdentityTrust(StrEnum):
    """How this listener authenticates the inbound workload identity."""

    #: A pinned Ed25519 trust snapshot verifies a compact JWS before any claim
    #: is read.  This is the only trust model a public listener may use.
    ASYMMETRIC_JWS = "asymmetric-jws"
    #: A hard-coded local fixture string.  It proves nothing about the caller
    #: and exists only so the loopback proof path can run without a signer.
    FIXTURE_STATIC = "fixture-static"


@dataclass(frozen=True, slots=True)
class RemoteMCPConfig:
    """One hostname, one certificate, one listener.

    Remote mode has no plaintext fallback and no proxy trust: TLS terminates in
    Uvicorn and the raw ``Host`` header is validated against exactly one
    configured canonical authority.
    """

    canonical_host: str
    allowed_origins: tuple[str, ...]
    certfile: Path
    keyfile: Path
    bind_host: str = "127.0.0.1"
    bind_port: int = 8443
    allow_non_loopback: bool = False
    allow_absent_origin: bool = False
    identity_trust: RemoteIdentityTrust = RemoteIdentityTrust.FIXTURE_STATIC
    budgets: RemoteMCPBudgets = field(default_factory=RemoteMCPBudgets)
    certificate_expiry_margin_seconds: int = 604_800
    # The validated bytes, captured once.  ``repr``/``compare`` are off so the
    # private key can never be printed by an incidental repr or log line.
    certificate_pem: bytes = field(init=False, repr=False, compare=False, default=b"")
    private_key_pem: bytes = field(init=False, repr=False, compare=False, default=b"")

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "canonical_host",
            _canonical_authority(self.canonical_host, "canonical_host"),
        )
        if type(self.allowed_origins) is not tuple:
            raise _reject("allowed_origins must be a tuple")
        origins = tuple(_canonical_origin(item) for item in self.allowed_origins)
        if len(set(origins)) != len(origins):
            raise _reject("allowed_origins must be unique")
        object.__setattr__(self, "allowed_origins", origins)
        certfile = Path(self.certfile)
        keyfile = Path(self.keyfile)
        # Read through the validating descriptor and keep the bytes.  The paths
        # are retained only as provenance; nothing downstream re-opens them, so
        # replacing or mutating the source after this point cannot change what is
        # served.
        object.__setattr__(self, "certificate_pem", _public_file(certfile, "certfile"))
        object.__setattr__(self, "private_key_pem", _secure_secret_file(keyfile, "keyfile"))
        object.__setattr__(self, "certfile", certfile)
        object.__setattr__(self, "keyfile", keyfile)
        if type(self.bind_port) is not int or not 1 <= self.bind_port <= 65535:
            raise _reject("bind_port is out of range")
        _printable_ascii(self.bind_host, "bind_host")
        for name in ("allow_non_loopback", "allow_absent_origin"):
            if type(getattr(self, name)) is not bool:
                raise _reject(f"{name} must be a boolean")
        if not isinstance(self.identity_trust, RemoteIdentityTrust):
            raise _reject("identity_trust must be a RemoteIdentityTrust")
        if not _loopback(self.bind_host) and not self.allow_non_loopback:
            raise _reject(
                "publishing beyond loopback requires an explicit remote opt-in "
                "(allow_non_loopback=True)"
            )
        asymmetric = self.identity_trust is RemoteIdentityTrust.ASYMMETRIC_JWS
        if self.allow_non_loopback and not asymmetric:
            # A public listener authenticated by a fixture string authenticates
            # nobody.  This is the invariant that keeps the fixture verifier a
            # local proof aid rather than a shipped credential.
            raise _reject(
                "a public bind requires the asymmetric JWS identity verifier; the fixture "
                "static verifier is refused beyond loopback"
            )
        if self.allow_absent_origin and not asymmetric:
            # Without an Origin there is no browser-supplied provenance at all,
            # so the only thing standing between the caller and the downstream is
            # the identity verifier.  A fixture string is not one.
            raise _reject(
                "allow_absent_origin requires the asymmetric JWS identity verifier; a "
                "bearer-shaped string is not authentication"
            )
        if not self.allowed_origins and not self.allow_absent_origin:
            raise _reject(
                "remote mode requires at least one allowed origin, or an explicit "
                "allow_absent_origin opt-in for non-browser workload clients"
            )
        if not isinstance(self.budgets, RemoteMCPBudgets):
            raise _reject("budgets must be a RemoteMCPBudgets")
        if (
            type(self.certificate_expiry_margin_seconds) is not int
            or self.certificate_expiry_margin_seconds < 0
        ):
            raise _reject("certificate_expiry_margin_seconds must be a non-negative integer")


def certificate_expiry(certfile: Path) -> datetime:
    """Read a certificate's notAfter so expiry can gate readiness."""

    from cryptography import x509

    return x509.load_pem_x509_certificate(
        _public_file(Path(certfile), "certfile")
    ).not_valid_after_utc


def config_certificate_expiry(config: RemoteMCPConfig) -> datetime:
    """Read notAfter from the snapshotted bytes, not from the source path."""

    from cryptography import x509

    if not isinstance(config, RemoteMCPConfig):
        raise TypeError("config must be a RemoteMCPConfig")
    return x509.load_pem_x509_certificate(config.certificate_pem).not_valid_after_utc


@contextmanager
def remote_tls_snapshot(config: RemoteMCPConfig) -> Iterator[tuple[Path, Path]]:
    """Materialize the validated TLS bytes into a process-private snapshot.

    Uvicorn takes ``ssl_certfile``/``ssl_keyfile`` as paths and opens them
    itself, so pointing it at the operator's source paths would reintroduce the
    check/use split the config just removed.  Instead the already-validated
    bytes are written into a fresh 0700 directory as 0600 files that only this
    process knows about, and Uvicorn is pointed only at those.  The directory is
    removed on exit so no key material outlives the listener.
    """

    if not isinstance(config, RemoteMCPConfig):
        raise TypeError("config must be a RemoteMCPConfig")
    directory = Path(tempfile.mkdtemp(prefix="gove-zone-tls-"))
    try:
        os.chmod(directory, 0o700)
        certfile = directory / "server.crt"
        keyfile = directory / "server.key"
        _write_private(certfile, config.certificate_pem)
        _write_private(keyfile, config.private_key_pem)
        yield certfile, keyfile
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _write_private(path: Path, payload: bytes) -> None:
    """Create one owner-only file that cannot pre-exist or be a symlink."""

    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)


class RemoteReadiness:
    """Cached readiness with a serialized, rate-limited probe.

    Public readiness never triggers work: an anonymous ``/readyz`` flood must not
    become a credential-bearing proxy to the downstream server.  The probe runs
    under a dedicated tools:list-only identity that cannot reach tools/call.
    """

    def __init__(
        self,
        *,
        probe: Callable[[], Sequence[str]],
        expected_tools: Sequence[str],
        certificate_expiry: datetime,
        expiry_margin_seconds: int = 604_800,
        min_interval_seconds: float = 0.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(probe):
            raise TypeError("probe must be callable")
        if not isinstance(certificate_expiry, datetime) or certificate_expiry.tzinfo is None:
            raise TypeError("certificate_expiry must be an aware datetime")
        self._probe = probe
        self._expected = frozenset(expected_tools)
        if not self._expected:
            raise ValueError("expected_tools must not be empty")
        self._expiry = certificate_expiry
        self._margin = float(expiry_margin_seconds)
        self._min_interval = float(min_interval_seconds)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._ready = False
        self._checked_at: datetime | None = None
        self._last_attempt: datetime | None = None

    def refresh(self) -> None:
        """Probe at most once per interval; concurrent callers collapse to one."""

        with self._lock:
            now = self._clock()
            if (
                self._last_attempt is not None
                and (now - self._last_attempt).total_seconds() < self._min_interval
            ):
                return
            self._last_attempt = now
            self._ready = self._evaluate(now)
            self._checked_at = now

    def _evaluate(self, now: datetime) -> bool:
        if (self._expiry - now).total_seconds() <= self._margin:
            return False
        try:
            tools = self._probe()
        except Exception:
            # Downstream/catalog failure means unready.  There is no fallback and
            # no error detail may reach a public caller.
            return False
        try:
            names = tuple(tools)
        except TypeError:
            return False
        if any(type(name) is not str for name in names):
            return False
        if not names or len(set(names)) != len(names):
            return False
        return set(names) == set(self._expected)

    @property
    def ready(self) -> bool:
        with self._lock:
            return self._ready

    def public_state(self) -> dict[str, Any]:
        """Expose only liveness facts: never a catalog, token, or error string."""

        with self._lock:
            checked_at = self._checked_at
            ready = self._ready
            age = None if checked_at is None else (self._clock() - checked_at).total_seconds()
        return {
            "ready": ready,
            "checked_at": None if checked_at is None else _iso(checked_at),
            "age_seconds": None if age is None else round(age, 3),
        }


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@asynccontextmanager
async def run_readiness_probe(
    readiness: RemoteReadiness,
    *,
    interval_seconds: float = 15.0,
) -> AsyncIterator[None]:
    """Refresh readiness on one serialized background task for the app's lifetime.

    The probe runs here and nowhere else.  Doing it per ``/readyz`` request would
    let an anonymous flood drive downstream traffic; doing it lazily would make
    the first caller pay for a downstream round trip.  ``refresh`` is blocking
    and internally rate-limited, so it runs on a worker thread and cannot
    stampede.
    """

    if not isinstance(readiness, RemoteReadiness):
        raise TypeError("readiness must be a RemoteReadiness")
    if type(interval_seconds) not in (int, float) or interval_seconds <= 0:
        raise ValueError("interval_seconds must be a positive number")

    async def loop() -> None:
        while True:
            await anyio.to_thread.run_sync(readiness.refresh)
            await anyio.sleep(interval_seconds)

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(loop)
        try:
            yield
        finally:
            tasks.cancel_scope.cancel()


_FORWARDED_HEADERS = frozenset({b"forwarded"})
_FORWARDED_PREFIX = b"x-forwarded-"


class _RemoteGuard:
    """Reject ambiguous or oversized remote requests before MCP dispatch."""

    def __init__(
        self,
        app: Any,
        config: RemoteMCPConfig,
        readiness: RemoteReadiness | None,
    ) -> None:
        self._app = app
        self._config = config
        self._readiness = readiness
        self._host = config.canonical_host.encode("ascii")
        self._origins = frozenset(item.encode("ascii") for item in config.allowed_origins)
        # An in-process ceiling on concurrent child dispatches.  Uvicorn's
        # limit_concurrency bounds accepted connections; this bounds how many of
        # them may be inside the governed MCP dispatch at once, which is the
        # resource that actually reaches the downstream server.
        self._slots = anyio.Semaphore(config.budgets.limit_concurrency)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") == "lifespan":
            # The inner app owns the MCP session manager's task group, so its
            # lifespan must reach it.  Swallowing this leaves every request
            # failing with an uninitialized task group.
            await self._app(scope, receive, send)
            return
        if scope.get("type") != "http":
            raise RuntimeError("remote mode serves HTTP only")
        headers: list[tuple[bytes, bytes]] = list(scope.get("headers") or [])
        rejection = self._screen(scope, headers)
        if rejection is not None:
            status, reason = rejection
            await _json_error(send, status, reason)
            return
        body = await _read_bounded_body(receive, self._config.budgets.max_body_bytes)
        if body is None:
            await _json_error(send, 413, "request body exceeds the configured budget")
            return
        path = scope.get("path", "")
        if path == "/healthz":
            await _json_body(send, 200, {"process": "ok"})
            return
        if path == "/readyz":
            await self._readyz(scope, send)
            return
        # Fail fast rather than queue: a saturated gateway that keeps accepting
        # work turns into an unbounded queue in front of the downstream server.
        if self._slots.value == 0:
            await _json_error(send, 503, "the listener concurrency budget is exhausted")
            return
        async with self._slots:
            await self._app(scope, _replay(body), send)

    async def _readyz(self, scope: Any, send: Any) -> None:
        """Serve readiness to an operator peer only.

        Readiness is an operational signal, so it is only for the operator's own
        peer (loopback, which in the compose topology means the container's own
        healthcheck).  A public caller learns nothing, not even ready/unready.
        """

        if not _peer_is_loopback(scope):
            await _json_error(send, 404, "not found")
            return
        if self._readiness is None:
            # No configured probe means nothing is known, and "unknown" is not
            # "ready".  Claiming ready here would make the route decorative.
            await _json_body(send, 503, {"ready": False, "checked_at": None, "age_seconds": None})
            return
        state = self._readiness.public_state()
        await _json_body(send, 200 if state["ready"] else 503, state)

    def _screen(
        self,
        scope: Any,
        headers: list[tuple[bytes, bytes]],
        # noqa: C901 - one flat rejection ladder is clearer than nested helpers
    ) -> tuple[int, str] | None:
        budgets = self._config.budgets
        if len(headers) > budgets.max_header_count:
            return 431, "too many request headers"
        total = sum(len(name) + len(value) + 4 for name, value in headers)
        if total > budgets.max_header_bytes:
            return 431, "request headers exceed the configured budget"
        for name, _ in headers:
            lowered = name.lower()
            if lowered in _FORWARDED_HEADERS or lowered.startswith(_FORWARDED_PREFIX):
                return 400, "forwarded headers are not accepted by this listener"
        hosts = [value for name, value in headers if name.lower() == b"host"]
        if len(hosts) != 1 or not _exact(hosts[0], self._host):
            return 400, "request Host does not match this listener"
        absolute = _absolute_form_authority(scope)
        if absolute is not None and not _exact(absolute, self._host):
            return 400, "absolute-form target does not match this listener"
        origins = [value for name, value in headers if name.lower() == b"origin"]
        if len(origins) > 1:
            return 403, "request Origin is ambiguous"
        if origins:
            if origins[0] not in self._origins:
                return 403, "request Origin is not allowed"
        elif not self._config.allow_absent_origin:
            # An absent Origin is a policy decision, not something a caller can
            # earn by presenting a bearer-shaped string.  Any string is
            # bearer-shaped; only the identity verifier behind this guard can say
            # whether it authenticates anyone, and the config invariant already
            # requires that verifier to be the asymmetric one before this flag
            # can be set at all.
            return 403, "an absent Origin is not accepted by this listener"
        if any(name.lower() == b"last-event-id" for name, _ in headers):
            return 400, "session resume is not accepted in remote mode"
        if any(name.lower() == b"mcp-session-id" for name, _ in headers):
            # Remote mode runs the SDK stateless: there is no server-side session
            # to resume, so a session ID can only be an attempt to bind to one.
            return 400, "session resume is not accepted in remote mode"
        path = scope.get("path", "")
        method = scope.get("method", "")
        if path == "/mcp":
            if method != "POST":
                # GET /mcp is the Streamable HTTP SSE subscription.  Stateless
                # JSON-response mode has no stream to subscribe to, and a
                # long-lived server-push channel is a resource this listener
                # deliberately does not offer.
                return 405, "this listener accepts only POST /mcp JSON requests"
            if not _accepts_json(headers):
                return 406, "this listener responds only with application/json"
        encodings = [
            value.strip().lower() for name, value in headers if name.lower() == b"content-encoding"
        ]
        if encodings and encodings != [b"identity"]:
            return 415, "compressed request bodies are not accepted"
        lengths = [value for name, value in headers if name.lower() == b"content-length"]
        if len(lengths) > 1:
            return 400, "request Content-Length is ambiguous"
        if lengths:
            try:
                declared = int(lengths[0])
            except ValueError:
                return 400, "request Content-Length is invalid"
            if declared < 0:
                return 400, "request Content-Length is invalid"
            if declared > budgets.max_body_bytes:
                return 413, "request body exceeds the configured budget"
        return None


def _exact(value: bytes, expected: bytes) -> bool:
    return value == expected


def _accepts_json(headers: list[tuple[bytes, bytes]]) -> bool:
    """Require that the caller can read the JSON response this listener returns.

    Remote mode runs the SDK in stateless JSON-response mode, so a client that
    advertises only ``text/event-stream`` is asking for a transport this
    listener refuses to speak.  Answering it with JSON anyway would leave the
    client waiting on a stream that never arrives; refusing is the honest reply.
    """

    values = [value for name, value in headers if name.lower() == b"accept"]
    if not values:
        return True
    media = [
        item.strip().partition(b";")[0].lower() for value in values for item in value.split(b",")
    ]
    return any(item in {b"application/json", b"*/*", b"application/*"} for item in media)


def _peer_is_loopback(scope: Any) -> bool:
    client = scope.get("client")
    if not isinstance(client, (tuple, list)) or len(client) != 2:
        return False
    host = client[0]
    if type(host) is not str:
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _absolute_form_authority(scope: Any) -> bytes | None:
    """Extract the authority when the client sent an absolute-form target."""

    raw = scope.get("raw_path")
    if not isinstance(raw, bytes):
        return None
    for prefix in (b"https://", b"http://"):
        if raw.lower().startswith(prefix):
            remainder = raw[len(prefix) :]
            authority, _, _ = remainder.partition(b"/")
            return authority
    return None


async def _read_bounded_body(receive: Any, limit: int) -> bytes | None:
    """Buffer at most ``limit`` bytes; a chunked flood is cut off, not absorbed."""

    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message.get("type") == "http.disconnect":
            return b""
        chunk = message.get("body", b"") or b""
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)


def _replay(body: bytes) -> Any:
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


async def _json_body(send: Any, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


async def _json_error(send: Any, status: int, reason: str) -> None:
    # The reason is a fixed operator-authored string.  No inbound header, token,
    # catalog entry, or downstream error is ever reflected back to the caller.
    await _json_body(send, status, {"error": reason})


def build_remote_app(
    app: Any,
    config: RemoteMCPConfig,
    *,
    readiness: RemoteReadiness | None,
) -> Any:
    """Wrap one MCP ASGI app in the remote-mode guard, health, and ready routes."""

    if not isinstance(config, RemoteMCPConfig):
        raise TypeError("config must be a RemoteMCPConfig")
    if readiness is not None and not isinstance(readiness, RemoteReadiness):
        raise TypeError("readiness must be a RemoteReadiness")
    return _RemoteGuard(app, config, readiness)


def build_remote_uvicorn_config(
    app: Any,
    config: RemoteMCPConfig,
    *,
    certfile: Path,
    keyfile: Path,
) -> Any:
    """Terminate TLS directly in Uvicorn and trust no proxy header.

    ``certfile``/``keyfile`` must come from :func:`remote_tls_snapshot`, not from
    the operator's source paths, so that the material Uvicorn opens is the
    material this process already validated.
    """

    import uvicorn

    if not isinstance(config, RemoteMCPConfig):
        raise TypeError("config must be a RemoteMCPConfig")
    if not isinstance(certfile, Path) or not isinstance(keyfile, Path):
        raise TypeError("certfile and keyfile must be snapshot paths")
    budgets = config.budgets
    return uvicorn.Config(
        app,
        host=config.bind_host,
        port=config.bind_port,
        log_level="warning",
        ssl_certfile=str(certfile),
        ssl_keyfile=str(keyfile),
        proxy_headers=False,
        forwarded_allow_ips=[],
        server_header=False,
        date_header=True,
        limit_concurrency=budgets.limit_concurrency,
        backlog=budgets.backlog,
        timeout_keep_alive=budgets.timeout_keep_alive,
        timeout_graceful_shutdown=budgets.timeout_graceful_shutdown,
        limit_max_requests=budgets.limit_max_requests,
    )


__all__ = [
    "AUTHORIZATION_META_KEY",
    "DECISION_META_KEY",
    "SESSION_HEADER",
    "RemoteIdentityTrust",
    "RemoteMCPBudgets",
    "RemoteMCPConfig",
    "RemoteMCPConfigError",
    "RemoteReadiness",
    "build_mcp_server",
    "build_remote_app",
    "build_remote_uvicorn_config",
    "build_streamable_http_app",
    "certificate_expiry",
    "config_certificate_expiry",
    "read_secret_file",
    "remote_tls_snapshot",
    "run_readiness_probe",
    "run_stdio_server",
]
