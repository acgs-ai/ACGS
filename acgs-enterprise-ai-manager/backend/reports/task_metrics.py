"""
Task Metrics Calculator
Calculates task-related metrics for reporting dashboard
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, case
from datetime import datetime, timedelta
from backend.utils.timeutil import utcnow
from typing import Dict, Any, Optional, List
import logging

from backend.models.task import Task

logger = logging.getLogger(__name__)


class TaskMetrics:
    """Calculate task-related metrics for reporting."""

    @staticmethod
    async def get_completion_rate(
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Calculate task completion rate.

        Args:
            db: Database session
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dict with completion metrics
        """
        # Build query filters
        filters = []
        if start_date:
            filters.append(Task.created_at >= start_date)
        if end_date:
            filters.append(Task.created_at <= end_date)

        # Get total tasks
        total_query = select(func.count(Task.id))
        if filters:
            total_query = total_query.where(and_(*filters))

        result = await db.execute(total_query)
        total_tasks = result.scalar() or 0

        # Get completed tasks
        completed_filters = filters + [Task.status == "completed"]
        completed_query = select(func.count(Task.id)).where(and_(*completed_filters))

        result = await db.execute(completed_query)
        completed_tasks = result.scalar() or 0

        # Calculate rate
        completion_rate = (
            (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
        )

        return {
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "in_progress_tasks": total_tasks - completed_tasks,
            "completion_rate": round(completion_rate, 2),
            "period": {
                "start": start_date.isoformat() if start_date else None,
                "end": end_date.isoformat() if end_date else None,
            },
        }

    @staticmethod
    async def get_status_distribution(
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get distribution of tasks by status.

        Args:
            db: Database session
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dict with status distribution
        """
        filters = []
        if start_date:
            filters.append(Task.created_at >= start_date)
        if end_date:
            filters.append(Task.created_at <= end_date)

        query = select(Task.status, func.count(Task.id).label("count")).group_by(
            Task.status
        )

        if filters:
            query = query.where(and_(*filters))

        result = await db.execute(query)
        rows = result.all()

        distribution = {row.status: row.count for row in rows}

        return {"distribution": distribution, "total": sum(distribution.values())}

    @staticmethod
    async def get_priority_distribution(
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get distribution of tasks by priority.

        Args:
            db: Database session
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dict with priority distribution
        """
        filters = []
        if start_date:
            filters.append(Task.created_at >= start_date)
        if end_date:
            filters.append(Task.created_at <= end_date)

        query = select(Task.priority, func.count(Task.id).label("count")).group_by(
            Task.priority
        )

        if filters:
            query = query.where(and_(*filters))

        result = await db.execute(query)
        rows = result.all()

        distribution = {row.priority: row.count for row in rows}

        return {"distribution": distribution, "total": sum(distribution.values())}

    @staticmethod
    async def get_overdue_tasks(db: AsyncSession) -> Dict[str, Any]:
        """
        Get count of overdue tasks.

        Args:
            db: Database session

        Returns:
            Dict with overdue task metrics
        """
        now = utcnow()

        # Count overdue tasks
        overdue_query = select(func.count(Task.id)).where(
            and_(Task.due_date < now, Task.status != "completed")
        )

        result = await db.execute(overdue_query)
        overdue_count = result.scalar() or 0

        # Get overdue tasks by priority
        priority_query = (
            select(Task.priority, func.count(Task.id).label("count"))
            .where(and_(Task.due_date < now, Task.status != "completed"))
            .group_by(Task.priority)
        )

        result = await db.execute(priority_query)
        rows = result.all()

        by_priority = {row.priority: row.count for row in rows}

        return {"overdue_count": overdue_count, "by_priority": by_priority}

    @staticmethod
    async def get_completion_trend(db: AsyncSession, days: int = 30) -> Dict[str, Any]:
        """
        Get task completion trend over time.

        Args:
            db: Database session
            days: Number of days to analyze

        Returns:
            Dict with completion trend data
        """
        end_date = utcnow()
        start_date = end_date - timedelta(days=days)

        # Get completed tasks grouped by date
        query = (
            select(
                func.date(Task.completed_at).label("date"),
                func.count(Task.id).label("count"),
            )
            .where(
                and_(
                    Task.completed_at >= start_date,
                    Task.completed_at <= end_date,
                    Task.status == "completed",
                )
            )
            .group_by(func.date(Task.completed_at))
            .order_by(func.date(Task.completed_at))
        )

        result = await db.execute(query)
        rows = result.all()

        trend_data = [
            {"date": row.date.isoformat() if row.date else None, "count": row.count}
            for row in rows
        ]

        return {
            "period_days": days,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "trend": trend_data,
            "total_completed": sum(item["count"] for item in trend_data),
        }

    @staticmethod
    async def get_average_completion_time(
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Calculate average time to complete tasks.

        Args:
            db: Database session
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dict with average completion time metrics
        """
        filters = [Task.status == "completed", Task.completed_at.isnot(None)]

        if start_date:
            filters.append(Task.created_at >= start_date)
        if end_date:
            filters.append(Task.created_at <= end_date)

        # Calculate average completion time in hours
        query = select(
            func.avg(
                func.extract("epoch", Task.completed_at - Task.created_at) / 3600
            ).label("avg_hours")
        ).where(and_(*filters))

        result = await db.execute(query)
        avg_hours = result.scalar() or 0

        return {
            "average_completion_hours": round(avg_hours, 2),
            "average_completion_days": round(avg_hours / 24, 2),
        }
