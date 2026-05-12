"""Regression tests for backend.api.financial approve/reject auth model.

Codex adversarial-review finding #1: the approve/reject endpoints used to
take an arbitrary `approver_id` query parameter and pass it straight to the
service, letting any authenticated caller approve as anyone. The fix wires
require_role("manager") and derives the approver from the JWT-resolved
current_user. These tests pin that behavior so it cannot silently regress.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import date, datetime
from backend.utils.timeutil import utcnow
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure the auth module is importable with a real secret before we import any
# downstream module that pulls it in.
os.environ.setdefault("SECRET_KEY", "test-secret-" + "x" * 16)


def _make_response_stub() -> SimpleNamespace:
    """Build an object FinancialRecordResponse can serialize via from_attributes."""
    now = utcnow()
    return SimpleNamespace(
        id=uuid4(),
        type="expense",
        amount=Decimal("100.00"),
        currency="USD",
        date=date(2026, 5, 12),
        category="ops",
        project_id=None,
        approval_status="approved",
        approved_by=uuid4(),
        description=None,
        additional_data=None,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def app(monkeypatch) -> FastAPI:
    """Build a minimal FastAPI app with only the financial router mounted."""
    from backend.api import financial
    from backend.auth.dependencies import get_current_user
    from backend.database import get_db

    response_stub = _make_response_stub()

    # Patch the service so we never touch a real DB; assertions inspect the
    # captured arguments.
    approve_mock = AsyncMock(return_value=response_stub)
    reject_mock = AsyncMock(return_value=response_stub)
    monkeypatch.setattr(
        "backend.api.financial.FinancialService.approve_financial_record",
        approve_mock,
    )
    monkeypatch.setattr(
        "backend.api.financial.FinancialService.reject_financial_record",
        reject_mock,
    )

    app = FastAPI()
    app.include_router(financial.router, prefix="/api/v1/financial")

    # Replace get_db with a no-op session yielder; the service is mocked so
    # the session is never actually used.
    async def _fake_db() -> AsyncIterator[object]:
        yield object()

    app.dependency_overrides[get_db] = _fake_db

    # Per-test override of get_current_user lets each test choose the role
    # claim it wants to exercise.
    app.dependency_overrides[get_current_user] = lambda: {
        "id": str(uuid4()),
        "email": "tester@example.com",
        "name": "Tester",
        "role": "viewer",
        "team": None,
        "permissions": [],
    }
    app.state.approve_mock = approve_mock
    app.state.reject_mock = reject_mock
    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


# Pydantic schema validation forces a structured response, so we ask the
# service mock to return a dict with only the fields the response model
# actually serializes. Building it once keeps each test focused on auth.
def _override_current_user(app: FastAPI, *, role: str, user_id: str | None = None):
    from backend.auth.dependencies import get_current_user

    resolved = user_id or str(uuid4())
    app.dependency_overrides[get_current_user] = lambda: {
        "id": resolved,
        "email": f"{role}@example.com",
        "name": role.title(),
        "role": role,
        "team": None,
        "permissions": [],
    }
    return resolved


def test_approve_rejects_non_manager(app: FastAPI, client: TestClient):
    _override_current_user(app, role="user")
    record_id = uuid4()

    resp = client.post(f"/api/v1/financial/{record_id}/approve")

    assert resp.status_code == 403, resp.text
    app.state.approve_mock.assert_not_awaited()


def test_reject_rejects_non_manager(app: FastAPI, client: TestClient):
    _override_current_user(app, role="user")
    record_id = uuid4()

    resp = client.post(f"/api/v1/financial/{record_id}/reject")

    assert resp.status_code == 403, resp.text
    app.state.reject_mock.assert_not_awaited()


def test_approve_uses_authenticated_user_not_query_param(
    app: FastAPI, client: TestClient
):
    user_id = _override_current_user(app, role="manager")
    record_id = uuid4()
    spoofed = uuid4()

    # Try to impersonate someone else via the legacy ?approver_id= path —
    # this must be ignored by the new handler signature.
    resp = client.post(
        f"/api/v1/financial/{record_id}/approve",
        params={"approver_id": str(spoofed)},
    )

    assert resp.status_code == 200, resp.text
    app.state.approve_mock.assert_awaited_once()
    _, called_record, called_approver = app.state.approve_mock.await_args.args
    assert called_record == record_id
    assert isinstance(called_approver, UUID)
    assert str(called_approver) == user_id  # NOT the spoofed UUID
    assert str(called_approver) != str(spoofed)


def test_reject_uses_authenticated_user_not_query_param(
    app: FastAPI, client: TestClient
):
    user_id = _override_current_user(app, role="admin")
    record_id = uuid4()
    spoofed = uuid4()

    resp = client.post(
        f"/api/v1/financial/{record_id}/reject",
        params={"approver_id": str(spoofed)},
    )

    assert resp.status_code == 200, resp.text
    app.state.reject_mock.assert_awaited_once()
    _, called_record, called_approver = app.state.reject_mock.await_args.args
    assert called_record == record_id
    assert isinstance(called_approver, UUID)
    assert str(called_approver) == user_id
    assert str(called_approver) != str(spoofed)
