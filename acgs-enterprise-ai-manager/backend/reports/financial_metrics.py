"""
Financial Metrics Calculator
Calculates financial-related metrics for reporting dashboard
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, case
from datetime import datetime, timedelta
from backend.utils.timeutil import utcnow
from typing import Dict, Any, Optional
import logging

from backend.models.financial_record import FinancialRecord

logger = logging.getLogger(__name__)


class FinancialMetrics:
    """Calculate financial-related metrics for reporting."""

    @staticmethod
    async def get_burn_rate(db: AsyncSession, days: int = 30) -> Dict[str, Any]:
        """
        Calculate financial burn rate.

        Args:
            db: Database session
            days: Number of days to analyze

        Returns:
            Dict with burn rate metrics
        """
        end_date = utcnow()
        start_date = end_date - timedelta(days=days)

        # Get total expenses in period
        expense_query = select(
            func.sum(FinancialRecord.amount).label("total_expenses")
        ).where(
            and_(
                FinancialRecord.type == "expense",
                FinancialRecord.date >= start_date,
                FinancialRecord.date <= end_date,
            )
        )

        result = await db.execute(expense_query)
        total_expenses = result.scalar() or 0

        # Calculate daily burn rate
        daily_burn_rate = total_expenses / days if days > 0 else 0
        monthly_burn_rate = daily_burn_rate * 30

        return {
            "period_days": days,
            "total_expenses": float(total_expenses),
            "daily_burn_rate": round(daily_burn_rate, 2),
            "monthly_burn_rate": round(monthly_burn_rate, 2),
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
        }

    @staticmethod
    async def get_revenue_metrics(
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get revenue metrics.

        Args:
            db: Database session
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dict with revenue metrics
        """
        filters = [FinancialRecord.type == "income"]

        if start_date:
            filters.append(FinancialRecord.date >= start_date)
        if end_date:
            filters.append(FinancialRecord.date <= end_date)

        # Total revenue
        revenue_query = select(
            func.sum(FinancialRecord.amount).label("total_revenue")
        ).where(and_(*filters))

        result = await db.execute(revenue_query)
        total_revenue = result.scalar() or 0

        # Revenue by category
        category_query = (
            select(
                FinancialRecord.category,
                func.sum(FinancialRecord.amount).label("amount"),
            )
            .where(and_(*filters))
            .group_by(FinancialRecord.category)
        )

        result = await db.execute(category_query)
        rows = result.all()

        by_category = {row.category: float(row.amount) for row in rows}

        return {"total_revenue": float(total_revenue), "by_category": by_category}

    @staticmethod
    async def get_expense_breakdown(
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get expense breakdown by category.

        Args:
            db: Database session
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dict with expense breakdown
        """
        filters = [FinancialRecord.type == "expense"]

        if start_date:
            filters.append(FinancialRecord.date >= start_date)
        if end_date:
            filters.append(FinancialRecord.date <= end_date)

        # Total expenses
        total_query = select(func.sum(FinancialRecord.amount).label("total")).where(
            and_(*filters)
        )

        result = await db.execute(total_query)
        total_expenses = result.scalar() or 0

        # Expenses by category
        category_query = (
            select(
                FinancialRecord.category,
                func.sum(FinancialRecord.amount).label("amount"),
            )
            .where(and_(*filters))
            .group_by(FinancialRecord.category)
        )

        result = await db.execute(category_query)
        rows = result.all()

        by_category = {row.category: float(row.amount) for row in rows}

        return {"total_expenses": float(total_expenses), "by_category": by_category}

    @staticmethod
    async def get_profit_loss(
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Calculate profit/loss.

        Args:
            db: Database session
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dict with profit/loss metrics
        """
        filters = []
        if start_date:
            filters.append(FinancialRecord.date >= start_date)
        if end_date:
            filters.append(FinancialRecord.date <= end_date)

        # Total income
        income_filters = filters + [FinancialRecord.type == "income"]
        income_query = select(
            func.sum(FinancialRecord.amount).label("total_income")
        ).where(and_(*income_filters))

        result = await db.execute(income_query)
        total_income = result.scalar() or 0

        # Total expenses
        expense_filters = filters + [FinancialRecord.type == "expense"]
        expense_query = select(
            func.sum(FinancialRecord.amount).label("total_expenses")
        ).where(and_(*expense_filters))

        result = await db.execute(expense_query)
        total_expenses = result.scalar() or 0

        # Calculate profit/loss
        profit_loss = total_income - total_expenses
        profit_margin = (profit_loss / total_income * 100) if total_income > 0 else 0

        return {
            "total_income": float(total_income),
            "total_expenses": float(total_expenses),
            "profit_loss": float(profit_loss),
            "profit_margin": round(profit_margin, 2),
            "is_profitable": profit_loss > 0,
        }

    @staticmethod
    async def get_cash_flow_trend(db: AsyncSession, months: int = 6) -> Dict[str, Any]:
        """
        Get cash flow trend over time.

        Args:
            db: Database session
            months: Number of months to analyze

        Returns:
            Dict with cash flow trend
        """
        end_date = utcnow()
        start_date = end_date - timedelta(days=months * 30)

        # Get monthly cash flow
        query = (
            select(
                func.date_trunc("month", FinancialRecord.date).label(
                    "month"
                ),
                FinancialRecord.type,
                func.sum(FinancialRecord.amount).label("amount"),
            )
            .where(
                and_(
                    FinancialRecord.date >= start_date,
                    FinancialRecord.date <= end_date,
                )
            )
            .group_by(
                func.date_trunc("month", FinancialRecord.date),
                FinancialRecord.type,
            )
            .order_by(func.date_trunc("month", FinancialRecord.date))
        )

        result = await db.execute(query)
        rows = result.all()

        # Organize by month
        monthly_data = {}
        for row in rows:
            month_key = row.month.strftime("%Y-%m") if row.month else "unknown"
            if month_key not in monthly_data:
                monthly_data[month_key] = {"income": 0, "expenses": 0}

            if row.type == "income":
                monthly_data[month_key]["income"] = float(row.amount)
            elif row.type == "expense":
                monthly_data[month_key]["expenses"] = float(row.amount)

        # Calculate net cash flow for each month
        trend_data = [
            {
                "month": month,
                "income": data["income"],
                "expenses": data["expenses"],
                "net_cash_flow": data["income"] - data["expenses"],
            }
            for month, data in sorted(monthly_data.items())
        ]

        return {
            "period_months": months,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "trend": trend_data,
        }

    @staticmethod
    async def get_budget_vs_actual(
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Compare budgeted vs actual expenses.

        Args:
            db: Database session
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dict with budget vs actual comparison
        """
        filters = [FinancialRecord.type == "expense"]

        if start_date:
            filters.append(FinancialRecord.date >= start_date)
        if end_date:
            filters.append(FinancialRecord.date <= end_date)

        # Actual expenses by category
        actual_query = (
            select(
                FinancialRecord.category,
                func.sum(FinancialRecord.amount).label("actual"),
            )
            .where(and_(*filters))
            .group_by(FinancialRecord.category)
        )

        result = await db.execute(actual_query)
        rows = result.all()

        by_category = {}
        for row in rows:
            by_category[row.category] = {
                "actual": float(row.actual),
                "budget": 0,  # Would come from budget table in real implementation
                "variance": 0,
            }

        return {
            "by_category": by_category,
            "total_actual": sum(cat["actual"] for cat in by_category.values()),
        }
