"""
Infrastructure API Endpoints
REST API for Infrastructure CRUD operations
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID
import logging
import math

from backend.database import get_db
from backend.services.infrastructure_service import InfrastructureService
from backend.schemas.infrastructure import (
    InfrastructureCreate,
    InfrastructureUpdate,
    InfrastructureResponse,
    InfrastructureFilter,
    PaginatedInfrastructureResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/", response_model=InfrastructureResponse, status_code=status.HTTP_201_CREATED
)
async def create_infrastructure(
    infra_data: InfrastructureCreate, db: AsyncSession = Depends(get_db)
):
    """Create a new infrastructure."""
    try:
        infra = await InfrastructureService.create_infrastructure(db, infra_data)
        logger.info(f"Created infrastructure: {infra.id}")
        return infra
    except Exception as e:
        logger.error(f"Failed to create infrastructure: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create infrastructure",
        )


@router.get("/{infra_id}", response_model=InfrastructureResponse)
async def get_infrastructure(infra_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get infrastructure by ID."""
    infra = await InfrastructureService.get_infrastructure(db, infra_id)
    if not infra:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Infrastructure {infra_id} not found",
        )
    return infra


@router.get("/", response_model=PaginatedInfrastructureResponse)
async def list_infrastructure(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    type_filter: Optional[str] = Query(None, alias="type"),
    status_filter: Optional[str] = Query(None, alias="status"),
    location: Optional[str] = Query(None),
    search: Optional[str] = Query(None, max_length=255),
    db: AsyncSession = Depends(get_db),
):
    """List infrastructure with filtering and pagination."""
    try:
        filters = InfrastructureFilter(
            type=type_filter, status=status_filter, location=location, search=search
        )

        items, total = await InfrastructureService.list_infrastructure(
            db, filters=filters, page=page, page_size=page_size
        )

        total_pages = math.ceil(total / page_size) if total > 0 else 0

        return PaginatedInfrastructureResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )
    except Exception as e:
        logger.error(f"Failed to list infrastructure: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list infrastructure",
        )


@router.put("/{infra_id}", response_model=InfrastructureResponse)
async def update_infrastructure(
    infra_id: UUID, infra_data: InfrastructureUpdate, db: AsyncSession = Depends(get_db)
):
    """Update infrastructure."""
    infra = await InfrastructureService.update_infrastructure(db, infra_id, infra_data)
    if not infra:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Infrastructure {infra_id} not found",
        )
    logger.info(f"Updated infrastructure: {infra_id}")
    return infra


@router.delete("/{infra_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_infrastructure(infra_id: UUID, db: AsyncSession = Depends(get_db)):
    """Delete infrastructure."""
    deleted = await InfrastructureService.delete_infrastructure(db, infra_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Infrastructure {infra_id} not found",
        )
    logger.info(f"Deleted infrastructure: {infra_id}")
