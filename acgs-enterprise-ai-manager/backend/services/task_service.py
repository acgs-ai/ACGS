"""
Task Service Layer
Business logic for Task CRUD operations with filtering, pagination, and search
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_
from sqlalchemy.orm import selectinload
from typing import Optional, List
from uuid import UUID
from datetime import datetime
from backend.utils.timeutil import utcnow

from backend.models.task import Task
from backend.schemas.task import TaskCreate, TaskUpdate, TaskFilter


class TaskService:
    """Service class for Task business logic."""

    @staticmethod
    async def create_task(db: AsyncSession, task_data: TaskCreate) -> Task:
        """
        Create a new task.

        Args:
            db: Database session
            task_data: Task creation data

        Returns:
            Created task instance
        """
        task = Task(**task_data.model_dump())
        db.add(task)
        await db.commit()
        await db.refresh(task)
        return task

    @staticmethod
    async def get_task(
        db: AsyncSession, task_id: UUID, include_relations: bool = False
    ) -> Optional[Task]:
        """
        Get a task by ID.

        Args:
            db: Database session
            task_id: Task UUID
            include_relations: Whether to load related entities

        Returns:
            Task instance or None if not found
        """
        query = select(Task).where(Task.id == task_id)

        if include_relations:
            query = query.options(
                selectinload(Task.assignee),
                selectinload(Task.project),
                selectinload(Task.assets),
                selectinload(Task.infrastructure),
            )

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def list_tasks(
        db: AsyncSession,
        filters: Optional[TaskFilter] = None,
        page: int = 1,
        page_size: int = 50,
        include_relations: bool = False,
    ) -> tuple[List[Task], int]:
        """
        List tasks with filtering and pagination.

        Args:
            db: Database session
            filters: Optional filter parameters
            page: Page number (1-indexed)
            page_size: Number of items per page
            include_relations: Whether to load related entities

        Returns:
            Tuple of (list of tasks, total count)
        """
        # Build base query
        query = select(Task)

        # Apply filters
        if filters:
            conditions = []

            if filters.status:
                conditions.append(Task.status == filters.status)

            if filters.priority:
                conditions.append(Task.priority == filters.priority)

            if filters.assignee_id:
                conditions.append(Task.assignee_id == filters.assignee_id)

            if filters.project_id:
                conditions.append(Task.project_id == filters.project_id)

            if filters.search:
                search_term = f"%{filters.search}%"
                conditions.append(
                    or_(
                        Task.title.ilike(search_term),
                        Task.description.ilike(search_term),
                    )
                )

            if filters.tags:
                # Filter by tags (JSONB contains)
                for tag in filters.tags:
                    conditions.append(Task.tags.contains([tag]))

            if filters.due_before:
                conditions.append(Task.due_date <= filters.due_before)

            if filters.due_after:
                conditions.append(Task.due_date >= filters.due_after)

            if conditions:
                query = query.where(and_(*conditions))

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar()

        # Apply pagination
        query = query.offset((page - 1) * page_size).limit(page_size)

        # Apply ordering (most recent first)
        query = query.order_by(Task.created_at.desc())

        # Load relations if requested
        if include_relations:
            query = query.options(
                selectinload(Task.assignee),
                selectinload(Task.project),
                selectinload(Task.assets),
                selectinload(Task.infrastructure),
            )

        # Execute query
        result = await db.execute(query)
        tasks = result.scalars().all()

        return list(tasks), total

    @staticmethod
    async def update_task(
        db: AsyncSession, task_id: UUID, task_data: TaskUpdate
    ) -> Optional[Task]:
        """
        Update a task.

        Args:
            db: Database session
            task_id: Task UUID
            task_data: Task update data

        Returns:
            Updated task instance or None if not found
        """
        task = await TaskService.get_task(db, task_id)
        if not task:
            return None

        # Update only provided fields
        update_data = task_data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(task, field, value)

        # Auto-set completed_at when status changes to 'done'
        if task_data.status == "done" and task.completed_at is None:
            task.completed_at = utcnow()

        task.updated_at = utcnow()

        await db.commit()
        await db.refresh(task)
        return task

    @staticmethod
    async def delete_task(db: AsyncSession, task_id: UUID) -> bool:
        """
        Delete a task.

        Args:
            db: Database session
            task_id: Task UUID

        Returns:
            True if deleted, False if not found
        """
        task = await TaskService.get_task(db, task_id)
        if not task:
            return False

        await db.delete(task)
        await db.commit()
        return True

    @staticmethod
    async def link_asset(
        db: AsyncSession, task_id: UUID, asset_id: UUID
    ) -> Optional[Task]:
        """
        Link an asset to a task.

        Args:
            db: Database session
            task_id: Task UUID
            asset_id: Asset UUID

        Returns:
            Updated task or None if not found
        """
        task = await TaskService.get_task(db, task_id, include_relations=True)
        if not task:
            return None

        # Import here to avoid circular dependency
        from backend.models.asset import ITAsset

        asset = await db.get(ITAsset, asset_id)
        if asset and asset not in task.assets:
            task.assets.append(asset)
            await db.commit()
            await db.refresh(task)

        return task

    @staticmethod
    async def link_infrastructure(
        db: AsyncSession, task_id: UUID, infrastructure_id: UUID
    ) -> Optional[Task]:
        """
        Link infrastructure to a task.

        Args:
            db: Database session
            task_id: Task UUID
            infrastructure_id: Infrastructure UUID

        Returns:
            Updated task or None if not found
        """
        task = await TaskService.get_task(db, task_id, include_relations=True)
        if not task:
            return None

        # Import here to avoid circular dependency
        from backend.models.infrastructure import Infrastructure

        infra = await db.get(Infrastructure, infrastructure_id)
        if infra and infra not in task.infrastructure:
            task.infrastructure.append(infra)
            await db.commit()
            await db.refresh(task)

        return task
