"""
Reports API Endpoints
Provides unified reporting dashboard endpoints for multi-domain metrics
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from datetime import datetime, timedelta

from backend.database import get_db
from backend.services.report_service import ReportService

router = APIRouter(tags=["reports"])


@router.get("/dashboard")
async def get_dashboard_overview(
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get comprehensive dashboard overview with metrics from all domains.

    Returns metrics for:
    - Task completion rates
    - Asset utilization
    - Project health
    - Financial burn rate
    - Document activity
    """
    # Parse dates
    start = datetime.fromisoformat(start_date) if start_date else None
    end = datetime.fromisoformat(end_date) if end_date else None

    return await ReportService.get_dashboard_overview(db, start, end)


@router.get("/executive-summary")
async def get_executive_summary(db: AsyncSession = Depends(get_db)):
    """
    Get executive summary with key metrics across all domains.

    Returns high-level KPIs for executive decision-making.
    """
    return await ReportService.get_executive_summary(db)


@router.get("/tasks/detailed")
async def get_detailed_task_report(
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get detailed task report with comprehensive metrics.

    Includes:
    - Completion rates and trends
    - Status and priority distributions
    - Overdue task analysis
    - Average completion times
    """
    start = datetime.fromisoformat(start_date) if start_date else None
    end = datetime.fromisoformat(end_date) if end_date else None

    return await ReportService.get_detailed_task_report(db, start, end)


@router.get("/assets/detailed")
async def get_detailed_asset_report(
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get detailed asset report with comprehensive metrics.

    Includes:
    - Utilization rates
    - Lifecycle and category distributions
    - Maintenance metrics
    - Value analysis
    - Age distribution
    - Retirement forecast
    """
    start = datetime.fromisoformat(start_date) if start_date else None
    end = datetime.fromisoformat(end_date) if end_date else None

    return await ReportService.get_detailed_asset_report(db, start, end)


@router.get("/projects/detailed")
async def get_detailed_project_report(db: AsyncSession = Depends(get_db)):
    """
    Get detailed project report with comprehensive metrics.

    Includes:
    - Health overview
    - Completion metrics
    - Timeline analysis
    - Budget tracking
    - Risk assessment
    """
    return await ReportService.get_detailed_project_report(db)


@router.get("/financial/detailed")
async def get_detailed_financial_report(
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get detailed financial report with comprehensive metrics.

    Includes:
    - Burn rate analysis
    - Revenue metrics
    - Expense breakdown
    - Profit/loss statement
    - Cash flow trends
    """
    start = datetime.fromisoformat(start_date) if start_date else None
    end = datetime.fromisoformat(end_date) if end_date else None

    return await ReportService.get_detailed_financial_report(db, start, end)


@router.get("/documents/detailed")
async def get_detailed_document_report(db: AsyncSession = Depends(get_db)):
    """
    Get detailed document report with comprehensive metrics.

    Includes:
    - Activity metrics
    - Type distribution
    - Storage analysis
    - Access patterns
    """
    return await ReportService.get_detailed_document_report(db)


@router.get("/tasks/completion-trend")
async def get_task_completion_trend(
    days: int = Query(30, description="Number of days to analyze"),
    db: AsyncSession = Depends(get_db),
):
    """Get task completion trend over time."""
    from backend.reports import TaskMetrics

    return await TaskMetrics.get_completion_trend(db, days)


@router.get("/assets/utilization")
async def get_asset_utilization(
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Get asset utilization rate."""
    from backend.reports import AssetMetrics

    start = datetime.fromisoformat(start_date) if start_date else None
    end = datetime.fromisoformat(end_date) if end_date else None
    return await AssetMetrics.get_utilization_rate(db, start, end)


@router.get("/projects/health")
async def get_project_health(db: AsyncSession = Depends(get_db)):
    """Get project health overview."""
    from backend.reports import ProjectMetrics

    return await ProjectMetrics.get_health_overview(db)


@router.get("/financial/burn-rate")
async def get_financial_burn_rate(
    days: int = Query(30, description="Number of days to analyze"),
    db: AsyncSession = Depends(get_db),
):
    """Get financial burn rate."""
    from backend.reports import FinancialMetrics

    return await FinancialMetrics.get_burn_rate(db, days)


@router.get("/financial/cash-flow-trend")
async def get_cash_flow_trend(
    months: int = Query(6, description="Number of months to analyze"),
    db: AsyncSession = Depends(get_db),
):
    """Get cash flow trend over time."""
    from backend.reports import FinancialMetrics

    return await FinancialMetrics.get_cash_flow_trend(db, months)


@router.get("/documents/activity")
async def get_document_activity(
    days: int = Query(30, description="Number of days to analyze"),
    db: AsyncSession = Depends(get_db),
):
    """Get document activity metrics."""
    from backend.reports import DocumentMetrics

    return await DocumentMetrics.get_activity_metrics(db, days)
