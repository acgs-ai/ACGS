"""
Financial Service Layer
Business logic for Financial Record CRUD operations with approval workflow
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from typing import Optional, List
from uuid import UUID

from backend.models.financial_record import FinancialRecord
from backend.schemas.financial_record import (
    FinancialRecordCreate,
    FinancialRecordUpdate,
    FinancialRecordFilter,
)


class FinancialService:
    """Service class for Financial Record business logic."""

    @staticmethod
    async def create_financial_record(
        db: AsyncSession, record_data: FinancialRecordCreate
    ) -> FinancialRecord:
        """Create a new financial record."""
        record = FinancialRecord(**record_data.model_dump())
        db.add(record)
        await db.commit()
        await db.refresh(record, ["project", "approver"])
        return record

    @staticmethod
    async def get_financial_record(
        db: AsyncSession, record_id: UUID
    ) -> Optional[FinancialRecord]:
        """Get financial record by ID."""
        result = await db.execute(
            select(FinancialRecord).where(FinancialRecord.id == record_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def list_financial_records(
        db: AsyncSession,
        filters: Optional[FinancialRecordFilter] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[List[FinancialRecord], int]:
        """List financial records with filtering and pagination."""
        query = select(FinancialRecord)

        if filters:
            conditions = []
            if filters.type:
                conditions.append(FinancialRecord.type == filters.type)
            if filters.approval_status:
                conditions.append(
                    FinancialRecord.approval_status == filters.approval_status
                )
            if filters.project_id:
                conditions.append(FinancialRecord.project_id == filters.project_id)
            if filters.category:
                conditions.append(
                    FinancialRecord.category.ilike(f"%{filters.category}%")
                )
            if filters.date_from:
                conditions.append(FinancialRecord.date >= filters.date_from)
            if filters.date_to:
                conditions.append(FinancialRecord.date <= filters.date_to)
            if filters.min_amount is not None:
                conditions.append(FinancialRecord.amount >= filters.min_amount)
            if filters.max_amount is not None:
                conditions.append(FinancialRecord.amount <= filters.max_amount)
            if conditions:
                query = query.where(and_(*conditions))

        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar()

        query = query.offset((page - 1) * page_size).limit(page_size)
        query = query.order_by(FinancialRecord.date.desc())

        result = await db.execute(query)
        items = result.scalars().all()
        return list(items), total

    @staticmethod
    async def update_financial_record(
        db: AsyncSession, record_id: UUID, record_data: FinancialRecordUpdate
    ) -> Optional[FinancialRecord]:
        """Update financial record."""
        record = await FinancialService.get_financial_record(db, record_id)
        if not record:
            return None

        update_data = record_data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(record, field, value)

        await db.commit()
        await db.refresh(record, ["project", "approver"])
        return record

    @staticmethod
    async def delete_financial_record(db: AsyncSession, record_id: UUID) -> bool:
        """Delete financial record."""
        record = await FinancialService.get_financial_record(db, record_id)
        if not record:
            return False
        await db.delete(record)
        await db.commit()
        return True

    @staticmethod
    async def approve_financial_record(
        db: AsyncSession, record_id: UUID, approver_id: UUID
    ) -> Optional[FinancialRecord]:
        """Approve a financial record."""
        record = await FinancialService.get_financial_record(db, record_id)
        if not record:
            return None

        record.approval_status = "approved"
        record.approved_by = approver_id
        await db.commit()
        await db.refresh(record, ["project", "approver"])
        return record

    @staticmethod
    async def reject_financial_record(
        db: AsyncSession, record_id: UUID, approver_id: UUID
    ) -> Optional[FinancialRecord]:
        """Reject a financial record."""
        record = await FinancialService.get_financial_record(db, record_id)
        if not record:
            return None

        record.approval_status = "rejected"
        record.approved_by = approver_id
        await db.commit()
        await db.refresh(record, ["project", "approver"])
        return record
