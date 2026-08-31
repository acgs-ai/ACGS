import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from httpx import ASGITransport, AsyncClient

from second_brain.app import create_app
from second_brain.config import Settings
from second_brain.request_limits import RequestBodyLimitMiddleware


async def _run_limiter(headers: list[tuple[bytes, bytes]], chunks: list[bytes]) -> tuple[int, int]:
    receives = 0
    messages = iter(
        [
            {
                "type": "http.request",
                "body": chunk,
                "more_body": index < len(chunks) - 1,
            }
            for index, chunk in enumerate(chunks)
        ]
    )
    status = 0

    async def receive() -> dict[str, Any]:
        nonlocal receives
        receives += 1
        return next(messages)

    async def send(message: dict[str, Any]) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = int(message["status"])

    async def downstream(scope: dict[str, Any], receive: Any, send: Any) -> None:
        while (await receive()).get("more_body", False):
            pass
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    limiter = RequestBodyLimitMiddleware(downstream, max_bytes=4)
    await limiter({"type": "http", "method": "POST", "headers": headers}, receive, send)
    return status, receives


async def test_declared_and_streamed_envelope_limits_fail_before_or_during_receive() -> None:
    assert await _run_limiter([(b"content-length", b"5")], [b"ignored"]) == (413, 0)
    assert await _run_limiter([], [b"12", b"345"]) == (413, 2)
    assert await _run_limiter([(b"content-length", b"2")], [b"12", b"345"]) == (413, 2)
    assert await _run_limiter([], [b"12", b"34"]) == (204, 2)


async def test_request_body_absolute_deadline_rejects_slow_trickle() -> None:
    status = 0

    async def receive() -> dict[str, Any]:
        await asyncio.sleep(0.03)
        return {"type": "http.request", "body": b"x", "more_body": True}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = int(message["status"])

    async def downstream(scope: dict[str, Any], receive: Any, send: Any) -> None:
        del scope, receive, send
        raise AssertionError("timed-out envelope reached the application")

    limiter = RequestBodyLimitMiddleware(downstream, max_bytes=100, timeout_seconds=0.02)
    await limiter({"type": "http", "method": "POST", "headers": []}, receive, send)
    assert status == 408


async def test_real_handler_rejects_chunked_envelope_without_persistence(
    database_urls: Any, tmp_path: Path
) -> None:
    settings = Settings(
        app_env="test",
        database_url=database_urls.app,
        storage_root=tmp_path / "objects",
        max_request_envelope_bytes=32,
    )
    app = create_app(settings)

    async def oversized() -> AsyncIterator[bytes]:
        yield b'{"title":"x","content":"'
        yield b"a" * 64
        yield b'"}'

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        response = await client.post(
            "/api/v1/captures/text",
            headers={
                "content-type": "application/json",
                "x-second-brain-owner-id": "00000000-0000-0000-0000-000000000001",
                "x-second-brain-workspace-id": "00000000-0000-0000-0000-000000000002",
            },
            content=oversized(),
        )
    assert response.status_code == 413
    assert "a" * 16 not in response.text
    assert not list((tmp_path / "objects").rglob("*"))
