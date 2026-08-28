import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from typing import Any

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class RequestBodyLimitMiddleware:
    """Bound HTTP request envelopes before framework body parsing or persistence."""

    def __init__(self, app: ASGIApp, max_bytes: int, timeout_seconds: float = 10) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.timeout_seconds = timeout_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        declared = self._declared_length(scope.get("headers", []))
        if declared is not None and declared > self.max_bytes:
            await self._reject(send)
            return
        consumed = 0
        buffered: list[Message] = []
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                async with asyncio.timeout_at(deadline):
                    message = await receive()
            except TimeoutError:
                await self._reject_timeout(send)
                return
            buffered.append(message)
            if message.get("type") != "http.request":
                break
            consumed += len(message.get("body", b""))
            if consumed > self.max_bytes:
                await self._reject(send)
                return
            if not message.get("more_body", False):
                break
        messages = iter(buffered)

        async def replay_receive() -> Message:
            try:
                return next(messages)
            except StopIteration:
                return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)

    @staticmethod
    def _declared_length(headers: list[tuple[bytes, bytes]]) -> int | None:
        values = [value for name, value in headers if name.lower() == b"content-length"]
        if not values:
            return None
        if len(values) != 1:
            return 2**63 - 1
        try:
            parsed = int(values[0].decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            return 2**63 - 1
        return parsed if parsed >= 0 else 2**63 - 1

    @staticmethod
    async def _reject(send: Send) -> None:
        body = json.dumps(
            {
                "code": "request_too_large",
                "title": "Request rejected",
                "detail": "The request exceeds the configured envelope limit.",
                "retryable": False,
            },
            separators=(",", ":"),
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    async def _reject_timeout(send: Send) -> None:
        body = json.dumps(
            {
                "code": "request_timeout",
                "title": "Request rejected",
                "detail": "The request body was not received within the configured deadline.",
                "retryable": True,
            },
            separators=(",", ":"),
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 408,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
