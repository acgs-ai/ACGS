"""
Project Service Layer
Business logic for Project CRUD operations with filtering and pagination
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_
from typing import Optional, List
from uuid import UUID

from backend.models.project import Project
from backend.schemas.project import ProjectCreate, ProjectUpdate, ProjectFilter


class ProjectService:
    """Service class for Project business logic."""

    @staticmethod
    async def create_project(db: AsyncSession, project_data: ProjectCreate) -> Project:
        """Create a new project."""
        project = Project(**project_data.model_dump())
        db.add(project)
        await db.commit()
        await db.refresh(project)
        return project

    @staticmethod
    async def get_project(db: AsyncSession, project_id: UUID) -> Optional[Project]:
        """Get project by ID."""
        result = await db.execute(select(Project).where(Project.id == project_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def list_projects(
        db: AsyncSession,
        filters: Optional[ProjectFilter] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[List[Project], int]:
        """List projects with filtering and pagination."""
        query = select(Project)

        if filters:
            conditions = []
            if filters.status:
                conditions.append(Project.status == filters.status)
            if filters.owner_id:
                conditions.append(Project.owner_id == filters.owner_id)
            if filters.search:
                search_term = f"%{filters.search}%"
                conditions.append(
                    or_(
                        Project.name.ilike(search_term),
                        Project.description.ilike(search_term),
                    )
                )
            if filters.start_after:
                conditions.append(Project.start_date >= filters.start_after)
            if filters.end_before:
                conditions.append(Project.end_date <= filters.end_before)
            if conditions:
                query = query.where(and_(*conditions))

        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar()

        query = query.offset((page - 1) * page_size).limit(page_size)
        query = query.order_by(Project.created_at.desc())

        result = await db.execute(query)
        items = result.scalars().all()
        return list(items), total

    @staticmethod
    async def update_project(
        db: AsyncSession, project_id: UUID, project_data: ProjectUpdate
    ) -> Optional[Project]:
        """Update project."""
        project = await ProjectService.get_project(db, project_id)
        if not project:
            return None

        update_data = project_data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(project, field, value)

        await db.commit()
        await db.refresh(project)
        return project

    @staticmethod
    async def delete_project(db: AsyncSession, project_id: UUID) -> bool:
        """Delete project."""
        project = await ProjectService.get_project(db, project_id)
        if not project:
            return False
        await db.delete(project)
        await db.commit()
        return True
