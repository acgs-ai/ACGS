"""Regression tests for backend.reports metric functions against the real
SQLAlchemy column set.

Codex adversarial-review finding #4: report metric queries referenced
columns that don't exist on the ORM models (Asset.last_maintenance_date,
Asset.purchase_price, Asset.acquisition_date, Asset.category;
FinancialRecord.transaction_type/transaction_date;
Document.document_type/created_at; Project.health_status,
completion_percentage, spent, risk_level). Every call from
/api/v1/reports/dashboard would 500.

These tests don't drive a database — they verify the queries can be
constructed and compiled (which fails fast if a column reference is wrong),
and that methods stubbed out for missing schema return safe zero payloads
with a `schema_pending` flag.
"""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-" + "x" * 16)


def _fake_session(results: list[Any]) -> AsyncMock:
    """Build an AsyncSession-like mock whose `.execute()` returns canned rows.

    Each call to `.execute()` pops the next preset from `results`. Each
    preset is itself a small object with `.scalar()` / `.all()` matching
    what the metric code calls.
    """
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=results)
    return session


def _scalar(value):
    r = MagicMock()
    r.scalar.return_value = value
    return r


def _rows(rows):
    r = MagicMock()
    r.all.return_value = rows
    return r


def _row(**fields):
    obj = MagicMock()
    for key, value in fields.items():
        setattr(obj, key, value)
    return obj


# ---------------------------------------------------------------------------
# asset_metrics
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_asset_value_metrics_uses_purchase_cost():
    from backend.reports.asset_metrics import AssetMetrics

    session = _fake_session(
        [
            _scalar(1234.5),
            _rows([_row(type="laptop", value=900), _row(type="server", value=334.5)]),
        ]
    )

    result = await AssetMetrics.get_value_metrics(session)

    assert result["total_value"] == pytest.approx(1234.5)
    assert result["by_category"] == {"laptop": 900.0, "server": 334.5}


@pytest.mark.asyncio
async def test_asset_category_distribution_uses_type_column():
    from backend.reports.asset_metrics import AssetMetrics

    session = _fake_session(
        [_rows([_row(type="laptop", count=3), _row(type="server", count=2)])]
    )

    result = await AssetMetrics.get_category_distribution(session)

    assert result == {"distribution": {"laptop": 3, "server": 2}, "total": 5}


@pytest.mark.asyncio
async def test_asset_maintenance_metrics_flags_missing_schema():
    from backend.reports.asset_metrics import AssetMetrics

    # Only the `in_maintenance` query runs now; needs_maintenance is stubbed.
    session = _fake_session([_scalar(4)])

    result = await AssetMetrics.get_maintenance_metrics(session, days=30)

    assert result["in_maintenance"] == 4
    assert result["needs_maintenance"] == 0
    assert "needs_maintenance" in result["schema_pending"]


@pytest.mark.asyncio
async def test_asset_age_distribution_compiles_against_purchase_date():
    """If the query still referenced Asset.acquisition_date this would raise
    AttributeError at query construction time."""
    from backend.reports.asset_metrics import AssetMetrics

    session = _fake_session([_rows([_row(age_range="0-1 years", count=2)])])

    result = await AssetMetrics.get_age_distribution(session)

    assert result["distribution"] == {"0-1 years": 2}


# ---------------------------------------------------------------------------
# financial_metrics
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_financial_burn_rate_uses_type_and_date():
    from backend.reports.financial_metrics import FinancialMetrics

    session = _fake_session([_scalar(900)])

    result = await FinancialMetrics.get_burn_rate(session, days=30)

    assert result["total_expenses"] == 900.0
    assert result["daily_burn_rate"] == pytest.approx(30.0)


@pytest.mark.asyncio
async def test_financial_profit_loss_compiles():
    from backend.reports.financial_metrics import FinancialMetrics

    session = _fake_session([_scalar(1000), _scalar(400)])

    result = await FinancialMetrics.get_profit_loss(session)

    assert result["total_income"] == 1000.0
    assert result["total_expenses"] == 400.0
    assert result["profit_loss"] == 600.0
    assert result["is_profitable"] is True


# ---------------------------------------------------------------------------
# document_metrics
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_document_activity_uses_created_date():
    from backend.reports.document_metrics import DocumentMetrics

    session = _fake_session([_scalar(5), _scalar(2), _scalar(10)])

    result = await DocumentMetrics.get_activity_metrics(session, days=30)

    assert result["created"] == 5
    assert result["updated"] == 2
    assert result["total_documents"] == 10


@pytest.mark.asyncio
async def test_document_type_distribution_uses_type_column():
    from backend.reports.document_metrics import DocumentMetrics

    session = _fake_session(
        [_rows([_row(type="policy", count=4), _row(type="report", count=1)])]
    )

    result = await DocumentMetrics.get_type_distribution(session)

    assert result == {"distribution": {"policy": 4, "report": 1}, "total": 5}


# ---------------------------------------------------------------------------
# project_metrics
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_project_health_overview_returns_zero_with_schema_pending():
    from backend.reports.project_metrics import ProjectMetrics

    session = _fake_session([_rows([_row(status="active", count=3)])])

    result = await ProjectMetrics.get_health_overview(session)

    assert result["total_projects"] == 3
    assert result["by_health"] == {}
    assert result["health_rate"] == 0.0
    assert "by_health" in result["schema_pending"]


@pytest.mark.asyncio
async def test_project_completion_metrics_stubbed():
    from backend.reports.project_metrics import ProjectMetrics

    # This method now returns immediately without hitting the session.
    session = _fake_session([])

    result = await ProjectMetrics.get_completion_metrics(session)

    assert result["average_completion"] == 0.0
    assert "average_completion" in result["schema_pending"]


@pytest.mark.asyncio
async def test_project_budget_metrics_uses_actual_cost():
    from backend.reports.project_metrics import ProjectMetrics

    session = _fake_session(
        [
            _scalar(1000),  # total_budget
            _scalar(400),  # total_spent (actual_cost)
            _scalar(1),  # over_budget count
        ]
    )

    result = await ProjectMetrics.get_budget_metrics(session)

    assert result["total_budget"] == 1000.0
    assert result["total_spent"] == 400.0
    assert result["budget_utilization"] == 40.0
    assert result["over_budget_count"] == 1


@pytest.mark.asyncio
async def test_project_risk_metrics_stubbed():
    from backend.reports.project_metrics import ProjectMetrics

    session = _fake_session([])

    result = await ProjectMetrics.get_risk_metrics(session)

    assert result["by_risk_level"] == {}
    assert result["high_risk_count"] == 0
    assert "by_risk_level" in result["schema_pending"]


@pytest.mark.asyncio
async def test_project_timeline_metrics_compiles():
    """timeline doesn't touch the schema-pending fields — must still run."""
    from backend.reports.project_metrics import ProjectMetrics

    session = _fake_session([_scalar(2), _scalar(1), _scalar(5)])

    result = await ProjectMetrics.get_timeline_metrics(session)

    assert result["on_time"] == 2
    assert result["overdue"] == 1
    assert result["completed"] == 5
    assert result["on_time_rate"] == pytest.approx(25.0)
