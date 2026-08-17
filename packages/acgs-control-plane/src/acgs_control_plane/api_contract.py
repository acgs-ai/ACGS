"""Request admission and redacted API error contracts."""

from __future__ import annotations

import re
import secrets
from collections.abc import Sequence
from http import HTTPStatus
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from acgs_control_plane.config import validate_max_request_body_bytes

REQUEST_ID_HEADER = "x-request-id"
REQUEST_ID_BYTES = 16
REQUEST_ID_RE = re.compile(r"^req_[0-9a-f]{32}$")

_JSON_HEADERS = [
    (b"content-type", b"application/json"),
    (b"cache-control", b"no-store"),
]


def new_request_id() -> str:
    """Return a bounded server-generated request ID."""

    return f"req_{secrets.token_hex(REQUEST_ID_BYTES)}"


def request_id_from_scope(scope: Scope) -> str:
    state = scope.setdefault("state", {})
    request_id = state.get("request_id")
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        request_id = new_request_id()
        state["request_id"] = request_id
    return request_id


def redacted_error(code: str, request_id: str, *, status: str = "error") -> dict[str, str]:
    return {"code": code, "status": status, "request_id": request_id}


def _content_length_values(scope: Scope) -> list[bytes]:
    return [
        value.strip()
        for name, value in scope.get("headers", [])
        if name.lower() == b"content-length"
    ]


def parse_content_length(
    scope: Scope, *, max_request_body_bytes: int
) -> tuple[int | None, str | None]:
    values = _content_length_values(scope)
    if not values:
        return None, None
    if len(values) != 1:
        return None, "invalid_content_length"
    raw = values[0]
    if not raw.isascii() or not raw.isdigit():
        return None, "invalid_content_length"
    if len(raw) > len(str(max_request_body_bytes)):
        return None, "request_body_too_large"
    return int(raw), None


class RequestAdmissionMiddleware:
    """Raw ASGI admission gate before FastAPI body parsing or route invocation."""

    def __init__(self, app: ASGIApp, *, max_request_body_bytes: int) -> None:
        self.app = app
        self.max_request_body_bytes = validate_max_request_body_bytes(max_request_body_bytes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = request_id_from_scope(scope)
        declared_length, length_error = parse_content_length(
            scope, max_request_body_bytes=self.max_request_body_bytes
        )
        if length_error is not None:
            status = (
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE
                if length_error == "request_body_too_large"
                else HTTPStatus.BAD_REQUEST
            )
            await _send_json(send, status, redacted_error(length_error, request_id))
            return
        if declared_length is not None and declared_length > self.max_request_body_bytes:
            await _send_json(
                send,
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                redacted_error("request_body_too_large", request_id),
            )
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                await _send_json(
                    send,
                    HTTPStatus.BAD_REQUEST,
                    redacted_error("invalid_request_stream", request_id),
                )
                return

            chunk = message.get("body", b"")
            append_result = append_bounded_body_chunk(
                body, chunk, max_request_body_bytes=self.max_request_body_bytes
            )
            if append_result == "too_large":
                await _send_json(
                    send,
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    redacted_error("request_body_too_large", request_id),
                )
                return
            if append_result == "invalid":
                await _send_json(
                    send,
                    HTTPStatus.BAD_REQUEST,
                    redacted_error("invalid_request_stream", request_id),
                )
                return

            if not message.get("more_body", False):
                break

        if declared_length is not None and declared_length != len(body):
            await _send_json(
                send,
                HTTPStatus.BAD_REQUEST,
                redacted_error("invalid_content_length", request_id),
            )
            return

        replayed = False
        admitted = bytes(body)

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": admitted, "more_body": False}
            return {"type": "http.disconnect"}

        async def add_request_id_header(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers = [(k, v) for k, v in headers if k.lower() != b"x-request-id"]
                headers.append((b"x-request-id", request_id.encode("ascii")))
                message["headers"] = headers
            await send(message)

        await self.app(scope, replay_receive, add_request_id_header)


async def _send_json(send: Send, status: HTTPStatus, content: dict[str, Any]) -> None:
    import json

    payload = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    headers = [
        *_JSON_HEADERS,
        (b"content-length", str(len(payload)).encode("ascii")),
        (b"x-request-id", str(content["request_id"]).encode("ascii")),
    ]
    await send({"type": "http.response.start", "status": int(status), "headers": headers})
    await send({"type": "http.response.body", "body": payload, "more_body": False})


def append_bounded_body_chunk(
    body: bytearray, chunk: object, *, max_request_body_bytes: int
) -> str:
    if not isinstance(chunk, bytes | bytearray | memoryview):
        return "invalid"
    chunk_length = len(chunk)
    if chunk_length > max_request_body_bytes - len(body):
        return "too_large"
    body.extend(chunk)
    return "ok"


def has_json_decode_error(errors: Sequence[Any]) -> bool:
    return any(str(error.get("type", "")).lower() == "json_invalid" for error in errors)
