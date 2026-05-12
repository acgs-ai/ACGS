"""Router smoke tests for backend.api.* endpoints.

These were placeholder stubs (each body was `pytest.skip("X API not yet
implemented")`) that predated the actual handler implementations. The
routers in backend/api/{tasks,assets,infrastructure,projects,financial,
documents}.py are now real.

A true DB-backed integration test requires an aiosqlite or postgres
fixture, which this venv does not currently provide. These tests cover
the next-best contract:

  - the route is mounted at the expected path
  - the router-level get_current_user gate is wired (401 without auth)
  - request bodies validate against the create/update schemas
  - the handler delegates to the documented service method with the
    right arguments
  - the response body serializes through the declared response model

If a future change adds a DB fixture, the service-mocking layer can be
swapped for a real DB without changing the test names.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import date, datetime
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("SECRET_KEY", "test-secret-" + "x" * 16)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


async def _fake_db() -> AsyncIterator[object]:
    yield object()


def _user_dict(role: str = "admin", user_id: str | None = None) -> dict:
    return {
        "id": user_id or str(uuid4()),
        "email": f"{role}@example.com",
        "name": role.title(),
        "role": role,
        "team": None,
        "permissions": [],
    }


def _build_app(router, prefix: str) -> FastAPI:
    """Mount one router with the same auth gate main.py uses."""
    from backend.auth.dependencies import get_current_user
    from backend.database import get_db

    app = FastAPI()
    app.include_router(router, prefix=prefix, dependencies=[Depends(get_current_user)])
    app.dependency_overrides[get_db] = _fake_db
    app.dependency_overrides[get_current_user] = _user_dict
    return app


# ---------------------------------------------------------------------------
# Response stubs (Pydantic from_attributes=True consumes these directly)
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime(2026, 5, 12, 12, 0, 0)


def _task_stub(**overrides):
    base = SimpleNamespace(
        id=uuid4(),
        title="Test task",
        description=None,
        status="todo",
        priority="medium",
        assignee_id=None,
        project_id=None,
        due_date=None,
        estimated_hours=None,
        actual_hours=None,
        tags=[],
        created_at=_now(),
        updated_at=_now(),
        completed_at=None,
        assignee=None,
        project=None,
        assets=[],
        infrastructure=[],
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


def _asset_stub(**overrides):
    base = SimpleNamespace(
        id=uuid4(),
        name="Test laptop",
        type="laptop",
        status="active",
        location=None,
        owner_id=None,
        project_id=None,
        purchase_date=None,
        purchase_cost=None,
        lifecycle_stage=None,
        warranty_expiry=None,
        specifications={},
        created_at=_now(),
        updated_at=_now(),
        owner=None,
        project=None,
        tasks=[],
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


def _infrastructure_stub(**overrides):
    base = SimpleNamespace(
        id=uuid4(),
        name="Test cluster",
        type="compute",
        status="operational",
        capacity=None,
        location=None,
        dependencies=[],
        configuration=None,
        created_at=_now(),
        updated_at=_now(),
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


def _project_stub(**overrides):
    base = SimpleNamespace(
        id=uuid4(),
        name="Test project",
        description=None,
        status="planning",
        start_date=None,
        end_date=None,
        budget=None,
        actual_cost=None,
        team=[],
        owner_id=None,
        created_at=_now(),
        updated_at=_now(),
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


def _financial_stub(**overrides):
    base = SimpleNamespace(
        id=uuid4(),
        type="expense",
        amount=Decimal("100.00"),
        currency="USD",
        date=date(2026, 5, 12),
        category="ops",
        project_id=None,
        approval_status="pending",
        approved_by=None,
        description=None,
        additional_data=None,
        created_at=_now(),
        updated_at=_now(),
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


def _document_stub(**overrides):
    base = SimpleNamespace(
        id=uuid4(),
        title="Test doc",
        content=None,
        type="report",
        tags=[],
        owner_id=None,
        version=1,
        file_path=None,
        file_size=None,
        mime_type=None,
        created_date=_now(),
        updated_at=_now(),
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


# ---------------------------------------------------------------------------
# Auth gate contract — runs once per router prefix to keep the test cheap
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_routers_reject_unauthenticated_requests():
    """All business routers must 401 when the auth dependency is not satisfied.

    This is the structural counterpart to test_p0_contract_hardening's
    test_business_routers_are_protected_and_system_routes_are_exempt: that
    one checks the route table, this one drives an actual request to confirm
    the wiring works at runtime for every router exercised below.
    """
    from backend.api import (
        assets,
        documents,
        financial,
        infrastructure,
        projects,
        tasks,
    )

    cases = [
        (tasks.router, "/api/v1/tasks", "/"),
        (assets.router, "/api/v1/assets", "/"),
        (infrastructure.router, "/api/v1/infrastructure", "/"),
        (projects.router, "/api/v1/projects", "/"),
        (financial.router, "/api/v1/financial", "/"),
        (documents.router, "/api/v1/documents", "/"),
    ]
    for router, prefix, path in cases:
        app = _build_app(router, prefix)
        # Drop the test-only override so the real get_current_user runs and
        # returns 401 for the missing Authorization header.
        from backend.auth.dependencies import get_current_user

        del app.dependency_overrides[get_current_user]
        client = TestClient(app)
        resp = client.get(f"{prefix}{path}")
        assert resp.status_code == 401, (
            f"{prefix}{path} returned {resp.status_code}, expected 401 — "
            "router-level auth gate may have regressed"
        )


# ===========================================================================
# Tasks API
# ===========================================================================


@pytest.mark.integration
class TestTasksAPI:
    """Smoke tests for Tasks domain API."""

    @pytest.fixture
    def app(self, monkeypatch):
        from backend.api import tasks

        return _build_app(tasks.router, "/api/v1/tasks")

    @pytest.fixture
    def client(self, app):
        return TestClient(app)

    def test_create_task(self, app, client, monkeypatch):
        stub = _task_stub(title="New task", status="in_progress", priority="high")
        mock = AsyncMock(return_value=stub)
        monkeypatch.setattr(
            "backend.api.tasks.TaskService.create_task", mock, raising=True
        )

        resp = client.post(
            "/api/v1/tasks/",
            json={"title": "New task", "status": "in_progress", "priority": "high"},
        )

        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["title"] == "New task"
        assert body["status"] == "in_progress"
        mock.assert_awaited_once()
        # Second positional arg is the validated TaskCreate.
        _, called_payload = mock.await_args.args
        assert called_payload.title == "New task"
        assert called_payload.priority == "high"

    def test_get_task(self, app, client, monkeypatch):
        task_id = uuid4()
        stub = _task_stub(id=task_id, title="Retrieve me")
        mock = AsyncMock(return_value=stub)
        monkeypatch.setattr(
            "backend.api.tasks.TaskService.get_task", mock, raising=True
        )

        resp = client.get(f"/api/v1/tasks/{task_id}")

        assert resp.status_code == 200, resp.text
        assert resp.json()["id"] == str(task_id)
        # include_relations=True is the documented contract on this endpoint.
        mock.assert_awaited_once()
        assert mock.await_args.kwargs.get("include_relations") is True

        # 404 path
        mock.return_value = None
        resp_missing = client.get(f"/api/v1/tasks/{uuid4()}")
        assert resp_missing.status_code == 404

    def test_update_task(self, app, client, monkeypatch):
        task_id = uuid4()
        stub = _task_stub(id=task_id, status="done", title="t")
        mock = AsyncMock(return_value=stub)
        monkeypatch.setattr(
            "backend.api.tasks.TaskService.update_task", mock, raising=True
        )

        resp = client.put(
            f"/api/v1/tasks/{task_id}",
            json={"status": "done"},
        )

        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "done"
        mock.assert_awaited_once()
        _, called_id, called_payload = mock.await_args.args
        assert called_id == task_id
        assert called_payload.status == "done"

    def test_delete_task(self, app, client, monkeypatch):
        task_id = uuid4()
        mock = AsyncMock(return_value=True)
        monkeypatch.setattr(
            "backend.api.tasks.TaskService.delete_task", mock, raising=True
        )

        resp = client.delete(f"/api/v1/tasks/{task_id}")

        assert resp.status_code == 204, resp.text
        mock.assert_awaited_once()

        # 404 path: service returns False for unknown id
        mock.return_value = False
        resp_missing = client.delete(f"/api/v1/tasks/{uuid4()}")
        assert resp_missing.status_code == 404

    def test_list_tasks(self, app, client, monkeypatch):
        stubs = [_task_stub(title="a"), _task_stub(title="b")]
        mock = AsyncMock(return_value=(stubs, 2))
        monkeypatch.setattr(
            "backend.api.tasks.TaskService.list_tasks", mock, raising=True
        )

        resp = client.get("/api/v1/tasks/?page=1&page_size=10")

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total"] == 2
        assert body["page"] == 1
        assert body["page_size"] == 10
        assert body["total_pages"] == 1
        assert [item["title"] for item in body["items"]] == ["a", "b"]


# ===========================================================================
# IT Assets API
# ===========================================================================


@pytest.mark.integration
class TestITAssetsAPI:
    """Smoke tests for IT Assets domain API."""

    @pytest.fixture
    def app(self, monkeypatch):
        from backend.api import assets

        return _build_app(assets.router, "/api/v1/assets")

    @pytest.fixture
    def client(self, app):
        return TestClient(app)

    def test_create_asset(self, app, client, monkeypatch):
        stub = _asset_stub(name="New laptop", type="laptop")
        mock = AsyncMock(return_value=stub)
        monkeypatch.setattr(
            "backend.api.assets.ITAssetService.create_asset", mock, raising=True
        )

        resp = client.post(
            "/api/v1/assets/",
            json={"name": "New laptop", "type": "laptop"},
        )

        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["name"] == "New laptop"
        assert body["type"] == "laptop"
        mock.assert_awaited_once()
        _, called_payload = mock.await_args.args
        assert called_payload.name == "New laptop"

    def test_get_asset(self, app, client, monkeypatch):
        asset_id = uuid4()
        stub = _asset_stub(id=asset_id, name="Existing server", type="server")
        mock = AsyncMock(return_value=stub)
        monkeypatch.setattr(
            "backend.api.assets.ITAssetService.get_asset", mock, raising=True
        )

        resp = client.get(f"/api/v1/assets/{asset_id}")

        assert resp.status_code == 200, resp.text
        assert resp.json()["id"] == str(asset_id)
        assert mock.await_args.kwargs.get("include_relations") is True

        # 404 path
        mock.return_value = None
        resp_missing = client.get(f"/api/v1/assets/{uuid4()}")
        assert resp_missing.status_code == 404

    def test_update_asset(self, app, client, monkeypatch):
        asset_id = uuid4()
        stub = _asset_stub(id=asset_id, status="maintenance", name="x", type="server")
        mock = AsyncMock(return_value=stub)
        monkeypatch.setattr(
            "backend.api.assets.ITAssetService.update_asset", mock, raising=True
        )

        resp = client.put(
            f"/api/v1/assets/{asset_id}",
            json={"status": "maintenance"},
        )

        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "maintenance"
        mock.assert_awaited_once()
        _, called_id, called_payload = mock.await_args.args
        assert called_id == asset_id
        assert called_payload.status == "maintenance"

    def test_delete_asset(self, app, client, monkeypatch):
        asset_id = uuid4()
        mock = AsyncMock(return_value=True)
        monkeypatch.setattr(
            "backend.api.assets.ITAssetService.delete_asset", mock, raising=True
        )

        resp = client.delete(f"/api/v1/assets/{asset_id}")

        assert resp.status_code == 204, resp.text
        mock.assert_awaited_once()

        mock.return_value = False
        resp_missing = client.delete(f"/api/v1/assets/{uuid4()}")
        assert resp_missing.status_code == 404


# ===========================================================================
# Infrastructure API
# ===========================================================================


@pytest.mark.integration
class TestInfrastructureAPI:
    """Smoke tests for Infrastructure domain API."""

    @pytest.fixture
    def app(self, monkeypatch):
        from backend.api import infrastructure

        return _build_app(infrastructure.router, "/api/v1/infrastructure")

    @pytest.fixture
    def client(self, app):
        return TestClient(app)

    def test_create_infrastructure(self, app, client, monkeypatch):
        stub = _infrastructure_stub(name="prod-cluster", type="compute")
        mock = AsyncMock(return_value=stub)
        monkeypatch.setattr(
            "backend.api.infrastructure.InfrastructureService.create_infrastructure",
            mock,
            raising=True,
        )

        resp = client.post(
            "/api/v1/infrastructure/",
            json={"name": "prod-cluster", "type": "compute"},
        )

        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["name"] == "prod-cluster"
        assert body["type"] == "compute"
        mock.assert_awaited_once()
        _, called_payload = mock.await_args.args
        assert called_payload.name == "prod-cluster"


# ===========================================================================
# Projects API
# ===========================================================================


@pytest.mark.integration
class TestProjectsAPI:
    """Smoke tests for Projects domain API."""

    @pytest.fixture
    def app(self, monkeypatch):
        from backend.api import projects

        return _build_app(projects.router, "/api/v1/projects")

    @pytest.fixture
    def client(self, app):
        return TestClient(app)

    def test_create_project(self, app, client, monkeypatch):
        stub = _project_stub(name="Migration", status="active")
        mock = AsyncMock(return_value=stub)
        monkeypatch.setattr(
            "backend.api.projects.ProjectService.create_project",
            mock,
            raising=True,
        )

        resp = client.post(
            "/api/v1/projects/",
            json={"name": "Migration", "status": "active"},
        )

        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["name"] == "Migration"
        assert body["status"] == "active"
        mock.assert_awaited_once()
        _, called_payload = mock.await_args.args
        assert called_payload.name == "Migration"


# ===========================================================================
# Financial API
# ===========================================================================


@pytest.mark.integration
class TestFinancialAPI:
    """Smoke tests for Financial domain API.

    Approval/rejection auth is exhaustively covered in
    tests/unit/test_financial_approver_auth.py; this test focuses on the
    create endpoint which the original stub targeted.
    """

    @pytest.fixture
    def app(self, monkeypatch):
        from backend.api import financial

        return _build_app(financial.router, "/api/v1/financial")

    @pytest.fixture
    def client(self, app):
        return TestClient(app)

    def test_create_financial_record(self, app, client, monkeypatch):
        stub = _financial_stub(type="expense", category="travel")
        mock = AsyncMock(return_value=stub)
        monkeypatch.setattr(
            "backend.api.financial.FinancialService.create_financial_record",
            mock,
            raising=True,
        )

        resp = client.post(
            "/api/v1/financial/",
            json={
                "type": "expense",
                "amount": "250.00",
                "currency": "USD",
                "date": "2026-05-12",
                "category": "travel",
            },
        )

        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["type"] == "expense"
        assert body["category"] == "travel"
        mock.assert_awaited_once()
        _, called_payload = mock.await_args.args
        assert called_payload.type == "expense"
        assert called_payload.amount == Decimal("250.00")


# ===========================================================================
# Documents API
# ===========================================================================


@pytest.mark.integration
class TestDocumentsAPI:
    """Smoke tests for Documents domain API."""

    @pytest.fixture
    def app(self, monkeypatch):
        from backend.api import documents

        return _build_app(documents.router, "/api/v1/documents")

    @pytest.fixture
    def client(self, app):
        return TestClient(app)

    def test_create_document(self, app, client, monkeypatch):
        stub = _document_stub(title="SOC2 report", type="report")
        mock = AsyncMock(return_value=stub)
        monkeypatch.setattr(
            "backend.api.documents.DocumentService.create_document",
            mock,
            raising=True,
        )

        resp = client.post(
            "/api/v1/documents/",
            json={"title": "SOC2 report", "type": "report"},
        )

        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["title"] == "SOC2 report"
        assert body["type"] == "report"
        mock.assert_awaited_once()
        _, called_payload = mock.await_args.args
        assert called_payload.title == "SOC2 report"
