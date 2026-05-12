"""
IT Asset Service Layer
Business logic for IT Asset CRUD operations with filtering, pagination, and search
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_
from sqlalchemy.orm import selectinload
from typing import Optional, List
from uuid import UUID
from datetime import datetime
from backend.utils.timeutil import utcnow

from backend.models.asset import ITAsset
from backend.schemas.asset import ITAssetCreate, ITAssetUpdate, ITAssetFilter


class ITAssetService:
    """Service class for IT Asset business logic."""

    @staticmethod
    async def create_asset(db: AsyncSession, asset_data: ITAssetCreate) -> ITAsset:
        """
        Create a new IT asset.

        Args:
            db: Database session
            asset_data: Asset creation data

        Returns:
            Created asset instance
        """
        asset = ITAsset(**asset_data.model_dump())
        db.add(asset)
        await db.commit()
        await db.refresh(asset, ["owner", "project", "tasks"])
        return asset

    @staticmethod
    async def get_asset(
        db: AsyncSession, asset_id: UUID, include_relations: bool = False
    ) -> Optional[ITAsset]:
        """
        Get an IT asset by ID.

        Args:
            db: Database session
            asset_id: Asset UUID
            include_relations: Whether to load related entities

        Returns:
            Asset instance or None if not found
        """
        query = select(ITAsset).where(ITAsset.id == asset_id)

        if include_relations:
            query = query.options(
                selectinload(ITAsset.owner),
                selectinload(ITAsset.project),
                selectinload(ITAsset.tasks),
            )

        result = await db.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def list_assets(
        db: AsyncSession,
        filters: Optional[ITAssetFilter] = None,
        page: int = 1,
        page_size: int = 50,
        include_relations: bool = False,
    ) -> tuple[List[ITAsset], int]:
        """
        List IT assets with filtering and pagination.

        Args:
            db: Database session
            filters: Optional filter parameters
            page: Page number (1-indexed)
            page_size: Number of items per page
            include_relations: Whether to load related entities

        Returns:
            Tuple of (list of assets, total count)
        """
        # Build base query
        query = select(ITAsset)

        # Apply filters
        if filters:
            conditions = []

            if filters.type:
                conditions.append(ITAsset.type == filters.type)

            if filters.status:
                conditions.append(ITAsset.status == filters.status)

            if filters.lifecycle_stage:
                conditions.append(ITAsset.lifecycle_stage == filters.lifecycle_stage)

            if filters.owner_id:
                conditions.append(ITAsset.owner_id == filters.owner_id)

            if filters.project_id:
                conditions.append(ITAsset.project_id == filters.project_id)

            if filters.location:
                conditions.append(ITAsset.location.ilike(f"%{filters.location}%"))

            if filters.search:
                search_term = f"%{filters.search}%"
                conditions.append(
                    or_(
                        ITAsset.name.ilike(search_term),
                        ITAsset.location.ilike(search_term),
                    )
                )

            if conditions:
                query = query.where(and_(*conditions))

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar()

        # Apply pagination
        query = query.offset((page - 1) * page_size).limit(page_size)

        # Apply ordering (most recent first)
        query = query.order_by(ITAsset.created_at.desc())

        # Load relations if requested
        if include_relations:
            query = query.options(
                selectinload(ITAsset.owner),
                selectinload(ITAsset.project),
                selectinload(ITAsset.tasks),
            )

        # Execute query
        result = await db.execute(query)
        assets = result.scalars().all()

        return list(assets), total

    @staticmethod
    async def update_asset(
        db: AsyncSession, asset_id: UUID, asset_data: ITAssetUpdate
    ) -> Optional[ITAsset]:
        """
        Update an IT asset.

        Args:
            db: Database session
            asset_id: Asset UUID
            asset_data: Asset update data

        Returns:
            Updated asset instance or None if not found
        """
        asset = await ITAssetService.get_asset(db, asset_id)
        if not asset:
            return None

        # Update only provided fields
        update_data = asset_data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(asset, field, value)

        asset.updated_at = utcnow()

        await db.commit()
        await db.refresh(asset)
        return asset

    @staticmethod
    async def delete_asset(db: AsyncSession, asset_id: UUID) -> bool:
        """
        Delete an IT asset.

        Args:
            db: Database session
            asset_id: Asset UUID

        Returns:
            True if deleted, False if not found
        """
        asset = await ITAssetService.get_asset(db, asset_id)
        if not asset:
            return False

        await db.delete(asset)
        await db.commit()
        return True
