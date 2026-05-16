"""FastAPI app factory — Foundational (T069) + US1 endpoints (T070).

US1 mounts ``GET /api/bus/traces`` (list) and ``GET /api/bus/traces/{id}``.
Auth on every business endpoint via ``require_reviewer_role`` (T028).
Returns ``503`` on traces endpoints if the app was instantiated without a
TraceStore — used by Foundational tests where no store is wired.

US2 will mount ``GET /api/bus/defects`` via the same pattern (T043).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from typing import Annotated

from agent_bus_analyzer.auth import require_reviewer_role
from agent_bus_analyzer.models import SingleTrace, TraceList
from agent_bus_analyzer.store import TraceStore

log = logging.getLogger("agent_bus_analyzer.api")


def _get_store(request: Request) -> TraceStore:
    store: TraceStore | None = getattr(request.app.state, "store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Trace store not configured on this app instance",
        )
    return store


def create_app(store: TraceStore | None = None) -> FastAPI:
    app = FastAPI(
        title="agent-bus-analyzer",
        version="0.1.0",
        description="Observer-only analysis layer for the Enhanced Agent Bus.",
        docs_url="/api/bus/_docs",
        openapi_url="/api/bus/_openapi.json",
    )
    app.state.store = store

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

    @app.get(
        "/api/bus/traces",
        response_model=TraceList,
        dependencies=[Depends(require_reviewer_role)],
    )
    async def list_traces(
        request: Request,
        limit: Annotated[int, Query(gt=0, le=1000)] = 50,
    ) -> TraceList:
        return _get_store(request).list_traces(limit=limit)

    @app.get(
        "/api/bus/traces/{correlation_id}",
        response_model=SingleTrace,
        dependencies=[Depends(require_reviewer_role)],
    )
    async def get_trace(correlation_id: str, request: Request) -> SingleTrace:
        result = _get_store(request).get_trace(correlation_id)
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Trace not found: {correlation_id}",
            )
        return result

    return app
