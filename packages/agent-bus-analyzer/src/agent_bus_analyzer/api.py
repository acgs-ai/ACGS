"""FastAPI app factory — skeleton owned by Foundational (T069).

Endpoints are mounted per user story:
  - US1 mounts ``GET /api/bus/traces`` and ``GET /api/bus/traces/{id}``.
  - US2 mounts ``GET /api/bus/defects``.

The factory pattern keeps tests hermetic: each test instantiates a fresh app.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response

log = logging.getLogger("agent_bus_analyzer.api")


def create_app() -> FastAPI:
    app = FastAPI(
        title="agent-bus-analyzer",
        version="0.1.0",
        description="Observer-only analysis layer for the Enhanced Agent Bus.",
        docs_url="/api/bus/_docs",
        openapi_url="/api/bus/_openapi.json",
    )

    @app.middleware("http")
    async def log_requests(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        log.info(
            "method=%s path=%s status=%d elapsed_ms=%.1f",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        return response

    @app.get("/api/bus/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
