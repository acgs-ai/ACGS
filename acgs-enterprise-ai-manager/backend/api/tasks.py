"""
Tasks API Endpoints
REST API for Task CRUD operations with filtering, pagination, and cross-domain linking
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID
import logging
import math

from backend.database import get_db
from backend.services.task_service import TaskService
from backend.schemas.task import (
    TaskCreate,
    TaskUpdate,
    TaskResponse,
    TaskDetailResponse,
    TaskFilter,
    PaginatedTaskResponse,
    TaskLinkRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/", response_model=TaskDetailResponse, status_code=status.HTTP_201_CREATED
)
async def create_task(task_data: TaskCreate, db: AsyncSession = Depends(get_db)):
    """
    Create a new task.

    Args:
        task_data: Task creation data
        db: Database session

    Returns:
        Created task with related entities
    """
    try:
        task = await TaskService.create_task(db, task_data)
        logger.info(f"Created task: {task.id}")
        return task
    except Exception as e:
        logger.error(f"Failed to create task: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create task",
        )


@router.get("/{task_id}", response_model=TaskDetailResponse)
async def get_task(task_id: UUID, db: AsyncSession = Depends(get_db)):
    """
    Get a task by ID with all related entities.

    Args:
        task_id: Task UUID
        db: Database session

    Returns:
        Task details with related entities
    """
    task = await TaskService.get_task(db, task_id, include_relations=True)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Task {task_id} not found"
        )
    return task


@router.get("/", response_model=PaginatedTaskResponse)
async def list_tasks(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    status_filter: Optional[str] = Query(None, alias="status"),
    priority: Optional[str] = Query(None),
    assignee_id: Optional[UUID] = Query(None),
    project_id: Optional[UUID] = Query(None),
    search: Optional[str] = Query(None, max_length=255),
    include_relations: bool = Query(False, description="Include related entities"),
    db: AsyncSession = Depends(get_db),
):
    """
    List tasks with filtering and pagination.

    Args:
        page: Page number (1-indexed)
        page_size: Number of items per page (1-100)
        status_filter: Filter by status
        priority: Filter by priority
        assignee_id: Filter by assignee
        project_id: Filter by project
        search: Search in title and description
        include_relations: Include related entities in response
        db: Database session

    Returns:
        Paginated list of tasks
    """
    try:
        # Build filters
        filters = TaskFilter(
            status=status_filter,
            priority=priority,
            assignee_id=assignee_id,
            project_id=project_id,
            search=search,
        )

        # Get tasks
        tasks, total = await TaskService.list_tasks(
            db,
            filters=filters,
            page=page,
            page_size=page_size,
            include_relations=include_relations,
        )

        # Calculate total pages
        total_pages = math.ceil(total / page_size) if total > 0 else 0

        return PaginatedTaskResponse(
            items=tasks,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )
    except Exception as e:
        logger.error(f"Failed to list tasks: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list tasks",
        )


@router.put("/{task_id}", response_model=TaskDetailResponse)
async def update_task(
    task_id: UUID, task_data: TaskUpdate, db: AsyncSession = Depends(get_db)
):
    """
    Update a task.

    Args:
        task_id: Task UUID
        task_data: Task update data
        db: Database session

    Returns:
        Updated task with related entities
    """
    task = await TaskService.update_task(db, task_id, task_data)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Task {task_id} not found"
        )
    logger.info(f"Updated task: {task_id}")
    return task


@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_task(task_id: UUID, db: AsyncSession = Depends(get_db)):
    """
    Delete a task.

    Args:
        task_id: Task UUID
        db: Database session

    Returns:
        No content on success
    """
    deleted = await TaskService.delete_task(db, task_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Task {task_id} not found"
        )
    logger.info(f"Deleted task: {task_id}")


@router.post("/{task_id}/assets", response_model=TaskDetailResponse)
async def link_asset_to_task(
    task_id: UUID, link_data: TaskLinkRequest, db: AsyncSession = Depends(get_db)
):
    """
    Link an IT asset to a task.

    Args:
        task_id: Task UUID
        link_data: Asset link data with entity_id and relationship_type
        db: Database session

    Returns:
        Updated task with linked asset
    """
    try:
        task = await TaskService.link_asset(db, task_id, link_data.entity_id)
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Task {task_id} not found",
            )
        logger.info(f"Linked asset {link_data.entity_id} to task {task_id}")
        return task
    except Exception as e:
        logger.error(f"Failed to link asset to task: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to link asset to task",
        )


@router.post("/{task_id}/infrastructure", response_model=TaskDetailResponse)
async def link_infrastructure_to_task(
    task_id: UUID, link_data: TaskLinkRequest, db: AsyncSession = Depends(get_db)
):
    """
    Link infrastructure to a task.

    Args:
        task_id: Task UUID
        link_data: Infrastructure link data with entity_id and relationship_type
        db: Database session

    Returns:
        Updated task with linked infrastructure
    """
    try:
        task = await TaskService.link_infrastructure(db, task_id, link_data.entity_id)
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Task {task_id} not found",
            )
        logger.info(f"Linked infrastructure {link_data.entity_id} to task {task_id}")
        return task
    except Exception as e:
        logger.error(f"Failed to link infrastructure to task: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to link infrastructure to task",
        )


@router.get("/project/{project_id}", response_model=PaginatedTaskResponse)
async def get_project_tasks(
    project_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """
    Get all tasks for a specific project.

    Args:
        project_id: Project UUID
        page: Page number
        page_size: Items per page
        db: Database session

    Returns:
        Paginated list of tasks for the project
    """
    filters = TaskFilter(project_id=project_id)
    tasks, total = await TaskService.list_tasks(
        db, filters=filters, page=page, page_size=page_size, include_relations=True
    )

    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return PaginatedTaskResponse(
        items=tasks,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/user/{user_id}", response_model=PaginatedTaskResponse)
async def get_user_tasks(
    user_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """
    Get all tasks assigned to a specific user.

    Args:
        user_id: User UUID
        page: Page number
        page_size: Items per page
        db: Database session

    Returns:
        Paginated list of tasks assigned to the user
    """
    filters = TaskFilter(assignee_id=user_id)
    tasks, total = await TaskService.list_tasks(
        db, filters=filters, page=page, page_size=page_size, include_relations=True
    )

    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return PaginatedTaskResponse(
        items=tasks,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )
