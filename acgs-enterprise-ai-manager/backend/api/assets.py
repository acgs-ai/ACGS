"""
IT Assets API Endpoints
REST API for IT Asset CRUD operations with filtering, pagination, and lifecycle tracking
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID
import logging
import math

from backend.database import get_db
from backend.services.asset_service import ITAssetService
from backend.schemas.asset import (
    ITAssetCreate,
    ITAssetUpdate,
    ITAssetResponse,
    ITAssetDetailResponse,
    ITAssetFilter,
    PaginatedITAssetResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/", response_model=ITAssetDetailResponse, status_code=status.HTTP_201_CREATED
)
async def create_asset(asset_data: ITAssetCreate, db: AsyncSession = Depends(get_db)):
    """
    Create a new IT asset.

    Args:
        asset_data: Asset creation data
        db: Database session

    Returns:
        Created asset with related entities
    """
    try:
        asset = await ITAssetService.create_asset(db, asset_data)
        logger.info(f"Created IT asset: {asset.id}")
        return asset
    except Exception as e:
        logger.error(f"Failed to create IT asset: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create IT asset",
        )


@router.get("/{asset_id}", response_model=ITAssetDetailResponse)
async def get_asset(asset_id: UUID, db: AsyncSession = Depends(get_db)):
    """
    Get an IT asset by ID with all related entities.

    Args:
        asset_id: Asset UUID
        db: Database session

    Returns:
        Asset details with related entities
    """
    asset = await ITAssetService.get_asset(db, asset_id, include_relations=True)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IT asset {asset_id} not found",
        )
    return asset


@router.get("/", response_model=PaginatedITAssetResponse)
async def list_assets(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    type_filter: Optional[str] = Query(None, alias="type"),
    status_filter: Optional[str] = Query(None, alias="status"),
    lifecycle_stage: Optional[str] = Query(None),
    owner_id: Optional[UUID] = Query(None),
    project_id: Optional[UUID] = Query(None),
    location: Optional[str] = Query(None, max_length=255),
    search: Optional[str] = Query(None, max_length=255),
    include_relations: bool = Query(False, description="Include related entities"),
    db: AsyncSession = Depends(get_db),
):
    """
    List IT assets with filtering and pagination.

    Args:
        page: Page number (1-indexed)
        page_size: Number of items per page (1-100)
        type_filter: Filter by asset type
        status_filter: Filter by status
        lifecycle_stage: Filter by lifecycle stage
        owner_id: Filter by owner
        project_id: Filter by project
        location: Filter by location (partial match)
        search: Search in name and location
        include_relations: Include related entities in response
        db: Database session

    Returns:
        Paginated list of IT assets
    """
    try:
        # Build filters
        filters = ITAssetFilter(
            type=type_filter,
            status=status_filter,
            lifecycle_stage=lifecycle_stage,
            owner_id=owner_id,
            project_id=project_id,
            location=location,
            search=search,
        )

        # Get assets
        assets, total = await ITAssetService.list_assets(
            db,
            filters=filters,
            page=page,
            page_size=page_size,
            include_relations=include_relations,
        )

        # Calculate total pages
        total_pages = math.ceil(total / page_size) if total > 0 else 0

        return PaginatedITAssetResponse(
            items=assets,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )
    except Exception as e:
        logger.error(f"Failed to list IT assets: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list IT assets",
        )


@router.put("/{asset_id}", response_model=ITAssetDetailResponse)
async def update_asset(
    asset_id: UUID, asset_data: ITAssetUpdate, db: AsyncSession = Depends(get_db)
):
    """
    Update an IT asset.

    Args:
        asset_id: Asset UUID
        asset_data: Asset update data
        db: Database session

    Returns:
        Updated asset with related entities
    """
    asset = await ITAssetService.update_asset(db, asset_id, asset_data)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IT asset {asset_id} not found",
        )
    logger.info(f"Updated IT asset: {asset_id}")
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(asset_id: UUID, db: AsyncSession = Depends(get_db)):
    """
    Delete an IT asset.

    Args:
        asset_id: Asset UUID
        db: Database session

    Returns:
        No content on success
    """
    deleted = await ITAssetService.delete_asset(db, asset_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IT asset {asset_id} not found",
        )
    logger.info(f"Deleted IT asset: {asset_id}")


@router.get("/project/{project_id}", response_model=PaginatedITAssetResponse)
async def get_project_assets(
    project_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """
    Get all IT assets for a specific project.

    Args:
        project_id: Project UUID
        page: Page number
        page_size: Items per page
        db: Database session

    Returns:
        Paginated list of IT assets for the project
    """
    filters = ITAssetFilter(project_id=project_id)
    assets, total = await ITAssetService.list_assets(
        db, filters=filters, page=page, page_size=page_size, include_relations=True
    )

    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return PaginatedITAssetResponse(
        items=assets,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/owner/{owner_id}", response_model=PaginatedITAssetResponse)
async def get_owner_assets(
    owner_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """
    Get all IT assets owned by a specific user.

    Args:
        owner_id: User UUID
        page: Page number
        page_size: Items per page
        db: Database session

    Returns:
        Paginated list of IT assets owned by the user
    """
    filters = ITAssetFilter(owner_id=owner_id)
    assets, total = await ITAssetService.list_assets(
        db, filters=filters, page=page, page_size=page_size, include_relations=True
    )

    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return PaginatedITAssetResponse(
        items=assets,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/lifecycle/{stage}", response_model=PaginatedITAssetResponse)
async def get_assets_by_lifecycle(
    stage: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """
    Get all IT assets in a specific lifecycle stage.

    Args:
        stage: Lifecycle stage (new, operational, aging, end_of_life)
        page: Page number
        page_size: Items per page
        db: Database session

    Returns:
        Paginated list of IT assets in the specified lifecycle stage
    """
    filters = ITAssetFilter(lifecycle_stage=stage)
    assets, total = await ITAssetService.list_assets(
        db, filters=filters, page=page, page_size=page_size, include_relations=True
    )

    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return PaginatedITAssetResponse(
        items=assets,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )
