"""
Projects API Endpoints
REST API for Project CRUD operations
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID
from datetime import date
import logging
import math

from backend.database import get_db
from backend.services.project_service import ProjectService
from backend.schemas.project import (
    ProjectCreate,
    ProjectUpdate,
    ProjectResponse,
    ProjectFilter,
    PaginatedProjectResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    project_data: ProjectCreate, db: AsyncSession = Depends(get_db)
):
    """Create a new project."""
    try:
        project = await ProjectService.create_project(db, project_data)
        logger.info(f"Created project: {project.id}")
        return project
    except Exception as e:
        logger.error(f"Failed to create project: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create project",
        )


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get project by ID."""
    project = await ProjectService.get_project(db, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found",
        )
    return project


@router.get("/", response_model=PaginatedProjectResponse)
async def list_projects(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    status_filter: Optional[str] = Query(None, alias="status"),
    owner_id: Optional[UUID] = Query(None),
    search: Optional[str] = Query(None, max_length=255),
    start_after: Optional[date] = Query(None),
    end_before: Optional[date] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """List projects with filtering and pagination."""
    try:
        filters = ProjectFilter(
            status=status_filter,
            owner_id=owner_id,
            search=search,
            start_after=start_after,
            end_before=end_before,
        )

        items, total = await ProjectService.list_projects(
            db, filters=filters, page=page, page_size=page_size
        )

        total_pages = math.ceil(total / page_size) if total > 0 else 0

        return PaginatedProjectResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )
    except Exception as e:
        logger.error(f"Failed to list projects: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list projects",
        )


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: UUID, project_data: ProjectUpdate, db: AsyncSession = Depends(get_db)
):
    """Update project."""
    project = await ProjectService.update_project(db, project_id, project_data)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found",
        )
    logger.info(f"Updated project: {project_id}")
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(project_id: UUID, db: AsyncSession = Depends(get_db)):
    """Delete project."""
    deleted = await ProjectService.delete_project(db, project_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found",
        )
    logger.info(f"Deleted project: {project_id}")
