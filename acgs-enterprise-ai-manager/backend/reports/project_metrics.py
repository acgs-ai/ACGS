"""
Project Metrics Calculator
Calculates project-related metrics for reporting dashboard
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from datetime import datetime, timedelta
from backend.utils.timeutil import utcnow
from typing import Dict, Any, Optional
import logging

from backend.models.project import Project

logger = logging.getLogger(__name__)


class ProjectMetrics:
    """Calculate project-related metrics for reporting."""

    @staticmethod
    async def get_health_overview(db: AsyncSession) -> Dict[str, Any]:
        """
        Get overall project health overview.

        Args:
            db: Database session

        Returns:
            Dict with project health metrics
        """
        # Get projects by status
        status_query = select(
            Project.status, func.count(Project.id).label("count")
        ).group_by(Project.status)

        result = await db.execute(status_query)
        rows = result.all()

        by_status = {row.status: row.count for row in rows}

        # `by_health` / `health_rate` require a Project.health_status field
        # which is not yet on the ITAsset/Project models. Surface empty
        # distribution + zero rate with a `schema_pending` flag so callers
        # can distinguish "no data yet" from "metric not implemented" without
        # the endpoint 500ing.
        by_health: Dict[str, int] = {}
        health_rate = 0.0

        total_projects = sum(by_status.values())

        return {
            "total_projects": total_projects,
            "by_status": by_status,
            "by_health": by_health,
            "health_rate": health_rate,
            "schema_pending": ["by_health", "health_rate"],
        }

    @staticmethod
    async def get_completion_metrics(db: AsyncSession) -> Dict[str, Any]:
        """
        Get project completion metrics.

        Currently the Project model does not expose `completion_percentage`,
        so this returns a zeroed payload with `schema_pending` rather than
        500ing the report endpoint. Add a `completion_percentage` column
        (or compute it from task completion data) before treating this as
        live.
        """
        return {
            "average_completion": 0.0,
            "by_range": {},
            "schema_pending": ["average_completion", "by_range"],
        }

    @staticmethod
    async def get_timeline_metrics(db: AsyncSession) -> Dict[str, Any]:
        """
        Get project timeline metrics.

        Args:
            db: Database session

        Returns:
            Dict with timeline metrics
        """
        now = utcnow()

        # On-time projects
        on_time_query = select(func.count(Project.id)).where(
            and_(Project.end_date >= now, Project.status != "completed")
        )

        result = await db.execute(on_time_query)
        on_time = result.scalar() or 0

        # Overdue projects
        overdue_query = select(func.count(Project.id)).where(
            and_(Project.end_date < now, Project.status != "completed")
        )

        result = await db.execute(overdue_query)
        overdue = result.scalar() or 0

        # Completed projects
        completed_query = select(func.count(Project.id)).where(
            Project.status == "completed"
        )

        result = await db.execute(completed_query)
        completed = result.scalar() or 0

        total = on_time + overdue + completed
        on_time_rate = (on_time / total * 100) if total > 0 else 0

        return {
            "on_time": on_time,
            "overdue": overdue,
            "completed": completed,
            "on_time_rate": round(on_time_rate, 2),
        }

    @staticmethod
    async def get_budget_metrics(db: AsyncSession) -> Dict[str, Any]:
        """
        Get project budget metrics.

        Args:
            db: Database session

        Returns:
            Dict with budget metrics
        """
        # Total budget
        total_budget_query = select(
            func.sum(Project.budget).label("total_budget")
        ).where(Project.status != "completed")

        result = await db.execute(total_budget_query)
        total_budget = result.scalar() or 0

        # Total spent. The Project model exposes actual_cost; there is no
        # separate `spent` column.
        total_spent_query = select(
            func.sum(Project.actual_cost).label("total_spent")
        ).where(Project.status != "completed")

        result = await db.execute(total_spent_query)
        total_spent = result.scalar() or 0

        # Budget utilization
        budget_utilization = (
            (total_spent / total_budget * 100) if total_budget > 0 else 0
        )

        # Projects over budget
        over_budget_query = select(func.count(Project.id)).where(
            and_(
                Project.actual_cost > Project.budget,
                Project.status != "completed",
            )
        )

        result = await db.execute(over_budget_query)
        over_budget = result.scalar() or 0

        return {
            "total_budget": float(total_budget),
            "total_spent": float(total_spent),
            "remaining": float(total_budget - total_spent),
            "budget_utilization": round(budget_utilization, 2),
            "over_budget_count": over_budget,
        }

    @staticmethod
    async def get_risk_metrics(db: AsyncSession) -> Dict[str, Any]:
        """
        Get project risk metrics.

        Currently the Project model does not expose `risk_level`, so this
        returns a zeroed payload with `schema_pending` rather than 500ing
        the report endpoint. Add a `risk_level` column (or derive it from
        budget/timeline/health signals) before treating this as live.
        """
        return {
            "by_risk_level": {},
            "high_risk_count": 0,
            "high_risk_percentage": 0.0,
            "schema_pending": ["by_risk_level", "high_risk_count", "high_risk_percentage"],
        }
