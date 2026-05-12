"""
Document Metrics Calculator
Calculates document-related metrics for reporting dashboard
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from datetime import datetime, timedelta
from backend.utils.timeutil import utcnow
from typing import Dict, Any, Optional
import logging

from backend.models.document import Document

logger = logging.getLogger(__name__)


class DocumentMetrics:
    """Calculate document-related metrics for reporting."""

    @staticmethod
    async def get_activity_metrics(db: AsyncSession, days: int = 30) -> Dict[str, Any]:
        """
        Get document activity metrics.

        Args:
            db: Database session
            days: Number of days to analyze

        Returns:
            Dict with activity metrics
        """
        end_date = utcnow()
        start_date = end_date - timedelta(days=days)

        # Documents created in period
        created_query = select(func.count(Document.id)).where(
            and_(Document.created_date >= start_date, Document.created_date <= end_date)
        )

        result = await db.execute(created_query)
        created_count = result.scalar() or 0

        # Documents updated in period
        updated_query = select(func.count(Document.id)).where(
            and_(
                Document.updated_at >= start_date,
                Document.updated_at <= end_date,
                Document.updated_at != Document.created_date,
            )
        )

        result = await db.execute(updated_query)
        updated_count = result.scalar() or 0

        # Total documents
        total_query = select(func.count(Document.id))
        result = await db.execute(total_query)
        total_documents = result.scalar() or 0

        return {
            "period_days": days,
            "created": created_count,
            "updated": updated_count,
            "total_documents": total_documents,
            "activity_rate": (
                round((created_count + updated_count) / days, 2) if days > 0 else 0
            ),
        }

    @staticmethod
    async def get_type_distribution(db: AsyncSession) -> Dict[str, Any]:
        """
        Get distribution of documents by type.

        Args:
            db: Database session

        Returns:
            Dict with type distribution
        """
        query = select(
            Document.type, func.count(Document.id).label("count")
        ).group_by(Document.type)

        result = await db.execute(query)
        rows = result.all()

        distribution = {row.type: row.count for row in rows}

        return {"distribution": distribution, "total": sum(distribution.values())}

    @staticmethod
    async def get_storage_metrics(db: AsyncSession) -> Dict[str, Any]:
        """
        Get document storage metrics.

        Args:
            db: Database session

        Returns:
            Dict with storage metrics
        """
        # Total storage used
        storage_query = select(func.sum(Document.file_size).label("total_size"))

        result = await db.execute(storage_query)
        total_size = result.scalar() or 0

        # Storage by type
        type_storage_query = select(
            Document.type, func.sum(Document.file_size).label("size")
        ).group_by(Document.type)

        result = await db.execute(type_storage_query)
        rows = result.all()

        by_type = {row.type: int(row.size or 0) for row in rows}

        # Convert to MB
        total_size_mb = total_size / (1024 * 1024) if total_size else 0

        return {
            "total_size_bytes": int(total_size),
            "total_size_mb": round(total_size_mb, 2),
            "by_type_bytes": by_type,
        }

    @staticmethod
    async def get_access_metrics(db: AsyncSession, days: int = 30) -> Dict[str, Any]:
        """
        Get document access metrics.

        Args:
            db: Database session
            days: Number of days to analyze

        Returns:
            Dict with access metrics
        """
        end_date = utcnow()
        start_date = end_date - timedelta(days=days)

        # Documents accessed in period (based on updated_at as proxy)
        accessed_query = select(func.count(Document.id)).where(
            and_(Document.updated_at >= start_date, Document.updated_at <= end_date)
        )

        result = await db.execute(accessed_query)
        accessed_count = result.scalar() or 0

        return {
            "period_days": days,
            "accessed_documents": accessed_count,
            "average_daily_access": round(accessed_count / days, 2) if days > 0 else 0,
        }
