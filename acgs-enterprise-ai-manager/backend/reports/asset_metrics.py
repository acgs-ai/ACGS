"""
Asset Metrics Calculator
Calculates asset-related metrics for reporting dashboard
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, case
from datetime import datetime, timedelta
from backend.utils.timeutil import utcnow
from typing import Dict, Any, Optional
import logging

from backend.models.asset import ITAsset as Asset

logger = logging.getLogger(__name__)


class AssetMetrics:
    """Calculate asset-related metrics for reporting."""

    @staticmethod
    async def get_utilization_rate(
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Calculate asset utilization rate.

        Args:
            db: Database session
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dict with utilization metrics
        """
        filters = []
        if start_date:
            filters.append(Asset.created_at >= start_date)
        if end_date:
            filters.append(Asset.created_at <= end_date)

        # Get total assets
        total_query = select(func.count(Asset.id))
        if filters:
            total_query = total_query.where(and_(*filters))

        result = await db.execute(total_query)
        total_assets = result.scalar() or 0

        # Get assets by status
        status_filters = filters.copy()
        status_query = select(
            Asset.status, func.count(Asset.id).label("count")
        ).group_by(Asset.status)

        if status_filters:
            status_query = status_query.where(and_(*status_filters))

        result = await db.execute(status_query)
        rows = result.all()

        status_counts = {row.status: row.count for row in rows}

        # Calculate utilization (in_use / total)
        in_use = status_counts.get("in_use", 0)
        utilization_rate = (in_use / total_assets * 100) if total_assets > 0 else 0

        return {
            "total_assets": total_assets,
            "in_use": in_use,
            "available": status_counts.get("available", 0),
            "maintenance": status_counts.get("maintenance", 0),
            "retired": status_counts.get("retired", 0),
            "utilization_rate": round(utilization_rate, 2),
        }

    @staticmethod
    async def get_lifecycle_distribution(db: AsyncSession) -> Dict[str, Any]:
        """
        Get distribution of assets by lifecycle stage.

        Args:
            db: Database session

        Returns:
            Dict with lifecycle distribution
        """
        query = select(
            Asset.lifecycle_stage, func.count(Asset.id).label("count")
        ).group_by(Asset.lifecycle_stage)

        result = await db.execute(query)
        rows = result.all()

        distribution = {row.lifecycle_stage: row.count for row in rows}

        return {"distribution": distribution, "total": sum(distribution.values())}

    @staticmethod
    async def get_category_distribution(db: AsyncSession) -> Dict[str, Any]:
        """
        Get distribution of assets by category.

        Args:
            db: Database session

        Returns:
            Dict with category distribution
        """
        query = select(Asset.type, func.count(Asset.id).label("count")).group_by(
            Asset.type
        )

        result = await db.execute(query)
        rows = result.all()

        distribution = {row.type: row.count for row in rows}

        return {"distribution": distribution, "total": sum(distribution.values())}

    @staticmethod
    async def get_maintenance_metrics(
        db: AsyncSession, days: int = 30
    ) -> Dict[str, Any]:
        """
        Get asset maintenance metrics.

        Args:
            db: Database session
            days: Number of days to analyze

        Returns:
            Dict with maintenance metrics
        """
        now = utcnow()
        start_date = now - timedelta(days=days)

        # Assets in maintenance
        maintenance_query = select(func.count(Asset.id)).where(
            Asset.status == "maintenance"
        )

        result = await db.execute(maintenance_query)
        in_maintenance = result.scalar() or 0

        # `needs_maintenance` requires a per-asset maintenance-history field
        # (last_maintenance_date) which the ITAsset model does not yet expose.
        # Surface zero and a `schema_pending` flag rather than guessing from
        # purchase_date — date-of-purchase is not a substitute for
        # date-of-last-maintenance and would silently fabricate the metric.
        needs_maintenance = 0
        schema_pending = ["needs_maintenance"]

        return {
            "in_maintenance": in_maintenance,
            "needs_maintenance": needs_maintenance,
            "period_days": days,
            "schema_pending": schema_pending,
        }

    @staticmethod
    async def get_value_metrics(db: AsyncSession) -> Dict[str, Any]:
        """
        Get asset value metrics.

        Args:
            db: Database session

        Returns:
            Dict with value metrics
        """
        # Total asset value
        total_value_query = select(
            func.sum(Asset.purchase_cost).label("total_value")
        ).where(Asset.status != "retired")

        result = await db.execute(total_value_query)
        total_value = result.scalar() or 0

        # Value by category
        category_value_query = (
            select(Asset.type, func.sum(Asset.purchase_cost).label("value"))
            .where(Asset.status != "retired")
            .group_by(Asset.type)
        )

        result = await db.execute(category_value_query)
        rows = result.all()

        by_category = {row.type: float(row.value or 0) for row in rows}

        return {"total_value": float(total_value), "by_category": by_category}

    @staticmethod
    async def get_age_distribution(db: AsyncSession) -> Dict[str, Any]:
        """
        Get distribution of assets by age.

        Args:
            db: Database session

        Returns:
            Dict with age distribution
        """
        now = utcnow()

        # Calculate age in days and categorize
        query = (
            select(
                case(
                    (
                        func.extract("days", now - Asset.purchase_date) < 365,
                        "0-1 years",
                    ),
                    (
                        func.extract("days", now - Asset.purchase_date) < 730,
                        "1-2 years",
                    ),
                    (
                        func.extract("days", now - Asset.purchase_date) < 1095,
                        "2-3 years",
                    ),
                    (
                        func.extract("days", now - Asset.purchase_date) < 1825,
                        "3-5 years",
                    ),
                    else_="5+ years",
                ).label("age_range"),
                func.count(Asset.id).label("count"),
            )
            .where(Asset.status != "retired")
            .group_by("age_range")
        )

        result = await db.execute(query)
        rows = result.all()

        distribution = {row.age_range: row.count for row in rows}

        return {"distribution": distribution, "total": sum(distribution.values())}

    @staticmethod
    async def get_retirement_forecast(
        db: AsyncSession, months: int = 12
    ) -> Dict[str, Any]:
        """
        Forecast assets approaching retirement.

        Args:
            db: Database session
            months: Number of months to forecast

        Returns:
            Dict with retirement forecast
        """
        now = utcnow()
        forecast_date = now + timedelta(days=months * 30)

        # Assets older than 4 years (approaching 5-year retirement)
        approaching_retirement_query = select(func.count(Asset.id)).where(
            and_(
                func.extract("days", now - Asset.purchase_date) > 1460,  # 4 years
                func.extract("days", now - Asset.purchase_date) < 1825,  # 5 years
                Asset.status != "retired",
            )
        )

        result = await db.execute(approaching_retirement_query)
        approaching_retirement = result.scalar() or 0

        return {
            "approaching_retirement": approaching_retirement,
            "forecast_months": months,
            "forecast_date": forecast_date.isoformat(),
        }
