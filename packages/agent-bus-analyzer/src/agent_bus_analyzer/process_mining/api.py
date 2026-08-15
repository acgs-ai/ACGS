"""Authenticated, tenant-scoped Process Intelligence query routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request, status

from agent_bus_analyzer.auth import ProcessPrincipal
from agent_bus_analyzer.process_mining.service import (
    ComplianceReport,
    ProcessDetail,
    ProcessIntelligenceService,
    ProcessList,
    VariantList,
)

VERSIONED_PROCESS_API_PREFIX = "/api/process-intelligence/v1"

Offset = Annotated[int, Query(ge=0)]
Limit = Annotated[int, Query(ge=1, le=200)]


def _get_engine(request: Request) -> ProcessIntelligenceService:
    engine = getattr(request.app.state, "process_engine", None)
    if not isinstance(engine, ProcessIntelligenceService):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Process Intelligence engine is not configured",
        )
    return engine


def _not_found() -> HTTPException:
    # Identical response whether an identifier is absent globally or belongs
    # to another tenant.  This prevents cross-tenant existence disclosure.
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Process not found",
    )


def build_process_router(
    *,
    prefix: str = "",
    operation_suffix: str = "root",
) -> APIRouter:
    """Build exact routes or versioned aliases with unique OpenAPI ids."""
    router = APIRouter(prefix=prefix, tags=["process-intelligence"])

    @router.get(
        "/processes",
        response_model=ProcessList,
        operation_id=f"list_processes_{operation_suffix}",
    )
    async def list_processes(
        request: Request,
        principal: ProcessPrincipal,
        offset: Offset = 0,
        limit: Limit = 50,
    ) -> ProcessList:
        return _get_engine(request).list_processes(
            tenant_id=principal.tenant_id,
            offset=offset,
            limit=limit,
        )

    @router.get(
        "/processes/{process_id}",
        response_model=ProcessDetail,
        operation_id=f"get_process_{operation_suffix}",
    )
    async def get_process(
        process_id: str,
        request: Request,
        principal: ProcessPrincipal,
    ) -> ProcessDetail:
        result = _get_engine(request).get_process(
            tenant_id=principal.tenant_id,
            process_id=process_id,
        )
        if result is None:
            raise _not_found()
        return result

    @router.get(
        "/processes/{process_id}/variants",
        response_model=VariantList,
        operation_id=f"get_process_variants_{operation_suffix}",
    )
    async def get_process_variants(
        process_id: str,
        request: Request,
        principal: ProcessPrincipal,
        offset: Offset = 0,
        limit: Limit = 50,
    ) -> VariantList:
        result = _get_engine(request).get_variants(
            tenant_id=principal.tenant_id,
            process_id=process_id,
            offset=offset,
            limit=limit,
        )
        if result is None:
            raise _not_found()
        return result

    @router.get(
        "/processes/{process_id}/compliance",
        response_model=ComplianceReport,
        operation_id=f"get_process_compliance_{operation_suffix}",
    )
    async def get_process_compliance(
        process_id: str,
        request: Request,
        principal: ProcessPrincipal,
    ) -> ComplianceReport:
        result = _get_engine(request).get_compliance(
            tenant_id=principal.tenant_id,
            process_id=process_id,
        )
        if result is None:
            raise _not_found()
        return result

    return router


def mount_process_intelligence(app: FastAPI) -> None:
    """Mount exact enterprise paths and explicitly versioned aliases."""
    app.include_router(build_process_router(operation_suffix="root"))
    app.include_router(
        build_process_router(
            prefix=VERSIONED_PROCESS_API_PREFIX,
            operation_suffix="v1",
        )
    )
