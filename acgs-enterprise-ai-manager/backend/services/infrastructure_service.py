"""
Infrastructure Service Layer
Business logic for Infrastructure CRUD operations with filtering and pagination
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_
from typing import Optional, List
from uuid import UUID

from backend.models.infrastructure import Infrastructure
from backend.schemas.infrastructure import (
    InfrastructureCreate,
    InfrastructureUpdate,
    InfrastructureFilter,
)


class InfrastructureService:
    """Service class for Infrastructure business logic."""

    @staticmethod
    async def create_infrastructure(
        db: AsyncSession, infra_data: InfrastructureCreate
    ) -> Infrastructure:
        """Create a new infrastructure."""
        infra = Infrastructure(**infra_data.model_dump())
        db.add(infra)
        await db.commit()
        await db.refresh(infra, ["tasks"])
        return infra

    @staticmethod
    async def get_infrastructure(
        db: AsyncSession, infra_id: UUID
    ) -> Optional[Infrastructure]:
        """Get infrastructure by ID."""
        result = await db.execute(
            select(Infrastructure).where(Infrastructure.id == infra_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def list_infrastructure(
        db: AsyncSession,
        filters: Optional[InfrastructureFilter] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[List[Infrastructure], int]:
        """List infrastructure with filtering and pagination."""
        query = select(Infrastructure)

        if filters:
            conditions = []
            if filters.type:
                conditions.append(Infrastructure.type == filters.type)
            if filters.status:
                conditions.append(Infrastructure.status == filters.status)
            if filters.location:
                conditions.append(
                    Infrastructure.location.ilike(f"%{filters.location}%")
                )
            if filters.search:
                search_term = f"%{filters.search}%"
                conditions.append(Infrastructure.name.ilike(search_term))
            if conditions:
                query = query.where(and_(*conditions))

        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar()

        query = query.offset((page - 1) * page_size).limit(page_size)
        query = query.order_by(Infrastructure.created_at.desc())

        result = await db.execute(query)
        items = result.scalars().all()
        return list(items), total

    @staticmethod
    async def update_infrastructure(
        db: AsyncSession, infra_id: UUID, infra_data: InfrastructureUpdate
    ) -> Optional[Infrastructure]:
        """Update infrastructure."""
        infra = await InfrastructureService.get_infrastructure(db, infra_id)
        if not infra:
            return None

        update_data = infra_data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(infra, field, value)

        await db.commit()
        await db.refresh(infra, ["tasks"])
        return infra

    @staticmethod
    async def delete_infrastructure(db: AsyncSession, infra_id: UUID) -> bool:
        """Delete infrastructure."""
        infra = await InfrastructureService.get_infrastructure(db, infra_id)
        if not infra:
            return False
        await db.delete(infra)
        await db.commit()
        return True
