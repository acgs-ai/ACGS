"""
Report Service
Aggregates metrics from all domains for unified reporting dashboard
"""

from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from backend.utils.timeutil import utcnow
from typing import Dict, Any, Optional, List
import logging

from backend.reports import (
    TaskMetrics,
    AssetMetrics,
    ProjectMetrics,
    FinancialMetrics,
    DocumentMetrics,
)

logger = logging.getLogger(__name__)


class ReportService:
    """Service for generating unified reports across all domains."""

    @staticmethod
    async def get_dashboard_overview(
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get comprehensive dashboard overview with metrics from all domains.

        Args:
            db: Database session
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dict containing metrics from all domains
        """
        logger.info("Generating dashboard overview")

        # Default to last 30 days if no dates provided
        if not end_date:
            end_date = utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        # Gather metrics from all domains
        dashboard_data = {
            "generated_at": utcnow().isoformat(),
            "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "tasks": await ReportService._get_task_summary(db, start_date, end_date),
            "assets": await ReportService._get_asset_summary(db, start_date, end_date),
            "projects": await ReportService._get_project_summary(db),
            "financial": await ReportService._get_financial_summary(
                db, start_date, end_date
            ),
            "documents": await ReportService._get_document_summary(db),
        }

        logger.info("Dashboard overview generated successfully")
        return dashboard_data

    @staticmethod
    async def _get_task_summary(
        db: AsyncSession, start_date: datetime, end_date: datetime
    ) -> Dict[str, Any]:
        """Get task metrics summary."""
        completion_rate = await TaskMetrics.get_completion_rate(
            db, start_date, end_date
        )
        status_dist = await TaskMetrics.get_status_distribution(
            db, start_date, end_date
        )
        overdue = await TaskMetrics.get_overdue_tasks(db)

        return {
            "completion_rate": completion_rate["completion_rate"],
            "total_tasks": completion_rate["total_tasks"],
            "completed_tasks": completion_rate["completed_tasks"],
            "in_progress_tasks": completion_rate["in_progress_tasks"],
            "overdue_tasks": overdue["overdue_count"],
            "status_distribution": status_dist["distribution"],
        }

    @staticmethod
    async def _get_asset_summary(
        db: AsyncSession, start_date: datetime, end_date: datetime
    ) -> Dict[str, Any]:
        """Get asset metrics summary."""
        utilization = await AssetMetrics.get_utilization_rate(db, start_date, end_date)
        maintenance = await AssetMetrics.get_maintenance_metrics(db)
        value = await AssetMetrics.get_value_metrics(db)

        return {
            "utilization_rate": utilization["utilization_rate"],
            "total_assets": utilization["total_assets"],
            "in_use": utilization["in_use"],
            "available": utilization["available"],
            "in_maintenance": maintenance["in_maintenance"],
            "needs_maintenance": maintenance["needs_maintenance"],
            "total_value": value["total_value"],
        }

    @staticmethod
    async def _get_project_summary(db: AsyncSession) -> Dict[str, Any]:
        """Get project metrics summary."""
        health = await ProjectMetrics.get_health_overview(db)
        timeline = await ProjectMetrics.get_timeline_metrics(db)
        budget = await ProjectMetrics.get_budget_metrics(db)

        return {
            "health_rate": health["health_rate"],
            "total_projects": health["total_projects"],
            "by_health": health["by_health"],
            "on_time": timeline["on_time"],
            "overdue": timeline["overdue"],
            "on_time_rate": timeline["on_time_rate"],
            "total_budget": budget["total_budget"],
            "total_spent": budget["total_spent"],
            "budget_utilization": budget["budget_utilization"],
        }

    @staticmethod
    async def _get_financial_summary(
        db: AsyncSession, start_date: datetime, end_date: datetime
    ) -> Dict[str, Any]:
        """Get financial metrics summary."""
        burn_rate = await FinancialMetrics.get_burn_rate(db, days=30)
        profit_loss = await FinancialMetrics.get_profit_loss(db, start_date, end_date)

        return {
            "daily_burn_rate": burn_rate["daily_burn_rate"],
            "monthly_burn_rate": burn_rate["monthly_burn_rate"],
            "total_income": profit_loss["total_income"],
            "total_expenses": profit_loss["total_expenses"],
            "profit_loss": profit_loss["profit_loss"],
            "profit_margin": profit_loss["profit_margin"],
            "is_profitable": profit_loss["is_profitable"],
        }

    @staticmethod
    async def _get_document_summary(db: AsyncSession) -> Dict[str, Any]:
        """Get document metrics summary."""
        activity = await DocumentMetrics.get_activity_metrics(db, days=30)
        storage = await DocumentMetrics.get_storage_metrics(db)

        return {
            "total_documents": activity["total_documents"],
            "created_last_30_days": activity["created"],
            "updated_last_30_days": activity["updated"],
            "activity_rate": activity["activity_rate"],
            "total_storage_mb": storage["total_size_mb"],
        }

    @staticmethod
    async def get_detailed_task_report(
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get detailed task report.

        Args:
            db: Database session
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Detailed task metrics
        """
        completion_rate = await TaskMetrics.get_completion_rate(
            db, start_date, end_date
        )
        status_dist = await TaskMetrics.get_status_distribution(
            db, start_date, end_date
        )
        priority_dist = await TaskMetrics.get_priority_distribution(
            db, start_date, end_date
        )
        overdue = await TaskMetrics.get_overdue_tasks(db)
        trend = await TaskMetrics.get_completion_trend(db, days=30)
        avg_time = await TaskMetrics.get_average_completion_time(
            db, start_date, end_date
        )

        return {
            "completion_metrics": completion_rate,
            "status_distribution": status_dist,
            "priority_distribution": priority_dist,
            "overdue_metrics": overdue,
            "completion_trend": trend,
            "average_completion_time": avg_time,
        }

    @staticmethod
    async def get_detailed_asset_report(
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get detailed asset report.

        Args:
            db: Database session
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Detailed asset metrics
        """
        utilization = await AssetMetrics.get_utilization_rate(db, start_date, end_date)
        lifecycle = await AssetMetrics.get_lifecycle_distribution(db)
        category = await AssetMetrics.get_category_distribution(db)
        maintenance = await AssetMetrics.get_maintenance_metrics(db)
        value = await AssetMetrics.get_value_metrics(db)
        age = await AssetMetrics.get_age_distribution(db)
        retirement = await AssetMetrics.get_retirement_forecast(db)

        return {
            "utilization_metrics": utilization,
            "lifecycle_distribution": lifecycle,
            "category_distribution": category,
            "maintenance_metrics": maintenance,
            "value_metrics": value,
            "age_distribution": age,
            "retirement_forecast": retirement,
        }

    @staticmethod
    async def get_detailed_project_report(db: AsyncSession) -> Dict[str, Any]:
        """
        Get detailed project report.

        Args:
            db: Database session

        Returns:
            Detailed project metrics
        """
        health = await ProjectMetrics.get_health_overview(db)
        completion = await ProjectMetrics.get_completion_metrics(db)
        timeline = await ProjectMetrics.get_timeline_metrics(db)
        budget = await ProjectMetrics.get_budget_metrics(db)
        risk = await ProjectMetrics.get_risk_metrics(db)

        return {
            "health_overview": health,
            "completion_metrics": completion,
            "timeline_metrics": timeline,
            "budget_metrics": budget,
            "risk_metrics": risk,
        }

    @staticmethod
    async def get_detailed_financial_report(
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get detailed financial report.

        Args:
            db: Database session
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Detailed financial metrics
        """
        burn_rate = await FinancialMetrics.get_burn_rate(db, days=30)
        revenue = await FinancialMetrics.get_revenue_metrics(db, start_date, end_date)
        expenses = await FinancialMetrics.get_expense_breakdown(
            db, start_date, end_date
        )
        profit_loss = await FinancialMetrics.get_profit_loss(db, start_date, end_date)
        cash_flow = await FinancialMetrics.get_cash_flow_trend(db, months=6)

        return {
            "burn_rate": burn_rate,
            "revenue_metrics": revenue,
            "expense_breakdown": expenses,
            "profit_loss": profit_loss,
            "cash_flow_trend": cash_flow,
        }

    @staticmethod
    async def get_detailed_document_report(db: AsyncSession) -> Dict[str, Any]:
        """
        Get detailed document report.

        Args:
            db: Database session

        Returns:
            Detailed document metrics
        """
        activity = await DocumentMetrics.get_activity_metrics(db, days=30)
        type_dist = await DocumentMetrics.get_type_distribution(db)
        storage = await DocumentMetrics.get_storage_metrics(db)
        access = await DocumentMetrics.get_access_metrics(db, days=30)

        return {
            "activity_metrics": activity,
            "type_distribution": type_dist,
            "storage_metrics": storage,
            "access_metrics": access,
        }

    @staticmethod
    async def get_executive_summary(db: AsyncSession) -> Dict[str, Any]:
        """
        Get executive summary with key metrics across all domains.

        Args:
            db: Database session

        Returns:
            Executive summary with KPIs
        """
        end_date = utcnow()
        start_date = end_date - timedelta(days=30)

        # Key metrics from each domain
        task_completion = await TaskMetrics.get_completion_rate(
            db, start_date, end_date
        )
        asset_utilization = await AssetMetrics.get_utilization_rate(
            db, start_date, end_date
        )
        project_health = await ProjectMetrics.get_health_overview(db)
        financial_pl = await FinancialMetrics.get_profit_loss(db, start_date, end_date)

        return {
            "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "key_metrics": {
                "task_completion_rate": task_completion["completion_rate"],
                "asset_utilization_rate": asset_utilization["utilization_rate"],
                "project_health_rate": project_health["health_rate"],
                "profit_margin": financial_pl["profit_margin"],
                "is_profitable": financial_pl["is_profitable"],
            },
            "summary": {
                "total_tasks": task_completion["total_tasks"],
                "total_assets": asset_utilization["total_assets"],
                "total_projects": project_health["total_projects"],
                "total_income": financial_pl["total_income"],
                "total_expenses": financial_pl["total_expenses"],
            },
        }
