import json
from datetime import datetime
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from backend.auth.dependencies import get_current_user
from backend.auth.router import _dev_bootstrap_user
from backend.database import get_db
from backend.governance.audit_logger import AuditLogger
from backend.governance.rules_engine import RulesEngine
from backend.middleware.governance_interceptor import GovernanceMiddleware


async def _fake_db():
    yield None


@pytest.mark.asyncio
async def test_auth_bootstrap_is_explicit_and_protected_routes_require_token(
    monkeypatch,
):
    from backend.main import app

    app.dependency_overrides[get_db] = _fake_db
    monkeypatch.delenv("ACGS_BOOTSTRAP_DEV_AUTH", raising=False)
    monkeypatch.setenv("ACGS_DEV_USER_EMAIL", "admin@example.com")
    monkeypatch.setenv("ACGS_DEV_USER_PASSWORD", "secret-password")

    assert _dev_bootstrap_user("admin@example.com", "secret-password") is None

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        unauthenticated = await client.get("/api/v1/search/domains")
        assert unauthenticated.status_code == 401

        monkeypatch.setenv("ACGS_BOOTSTRAP_DEV_AUTH", "1")
        login = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin@example.com", "password": "secret-password"},
        )
        assert login.status_code == 200
        token = login.json()["access_token"]

        authenticated = await client.get(
            "/api/v1/search/domains",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert authenticated.status_code == 200

    app.dependency_overrides.clear()


def test_business_routers_are_protected_and_system_routes_are_exempt():
    from backend.main import app

    protected_prefixes = {
        "/api/v1/tasks",
        "/api/v1/recommendations",
        "/api/v1/search",
        "/api/v1/projects",
        "/api/v1/assets",
        "/api/v1/infrastructure",
        "/api/v1/documents",
        "/api/v1/financial",
        "/api/v1/reports",
        "/api/v1/feedback",
    }
    exempt_paths = {"/", "/health", "/api/v1/auth/login"}

    route_dependencies = {
        route.path: {
            dependency.call
            for dependency in getattr(route, "dependant", ()).dependencies
        }
        for route in app.routes
        if hasattr(route, "dependant")
    }

    for prefix in protected_prefixes:
        matching_routes = [
            path for path in route_dependencies if path.startswith(prefix)
        ]
        assert matching_routes, f"missing route for {prefix}"
        assert any(
            get_current_user in route_dependencies[path] for path in matching_routes
        ), f"{prefix} is not protected"

    for path in exempt_paths:
        assert get_current_user not in route_dependencies.get(path, set())


@pytest.mark.asyncio
async def test_governance_middleware_replays_body_and_matches_body_text(monkeypatch):
    captured = {}

    class FakeGovernance:
        def validate_operation(self, operation, context, agent_id):
            captured["operation"] = operation
            captured["context"] = context
            return {"action": "ALLOW", "valid": True, "decision_id": "decision-1"}

    monkeypatch.setattr(
        "backend.middleware.governance_interceptor.get_governance",
        lambda: FakeGovernance(),
    )

    app = FastAPI()
    app.add_middleware(GovernanceMiddleware)

    @app.post("/api/v1/financial/")
    async def echo_body(request: Request):
        return await request.json()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/financial/",
            json={"type": "expense", "amount": 1500, "nested": {"api_key": "secret"}},
        )

    assert response.status_code == 200
    assert response.json()["amount"] == 1500
    assert captured["context"]["amount"] == 1500
    assert "amount=1500" in captured["context"]["operation_text"]
    assert "secret" not in captured["context"]["operation_text"]


def test_rules_engine_matches_body_derived_operation_text(tmp_path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        """
rules:
  - id: high-amount
    pattern: "amount=1500"
    severity: HIGH
    action: BLOCK
"""
    )

    engine = RulesEngine(str(rules_file))
    result = engine.validate(
        "POST /api/v1/financial", {"operation_text": "type=expense amount=1500"}
    )

    assert result["valid"] is False
    assert result["matched_rules"] == ["high-amount"]


def test_audit_logger_newest_first_redaction_and_per_file_genesis(tmp_path):
    logger = AuditLogger(str(tmp_path))

    def write_entry(path, timestamp, previous_hash="GENESIS"):
        entry = {
            "type": "DECISION",
            "timestamp": timestamp,
            "agent_id": "agent-1",
            "operation": "test",
            "context": {},
            "previous_hash": previous_hash,
        }
        entry["entry_hash"] = logger._compute_entry_hash(entry)
        path.write_text(json.dumps(entry) + "\n")
        return entry

    old_entry = write_entry(
        tmp_path / "audit_2026-01-01.jsonl", datetime(2026, 1, 1).isoformat()
    )
    new_entry = write_entry(
        tmp_path / "audit_2026-01-02.jsonl", datetime(2026, 1, 2).isoformat()
    )

    assert old_entry["previous_hash"] == "GENESIS"
    assert new_entry["previous_hash"] == "GENESIS"
    assert logger.verify_chain_integrity()["valid"] is True
    assert logger.query_audit_trail(limit=1)[0]["timestamp"] == new_entry["timestamp"]

    sanitized = logger._sanitize_context(
        {"request_body": {"user": "a", "nested": [{"token": "secret"}]}}
    )
    assert sanitized["request_body"]["nested"][0]["token"] == "***REDACTED***"


def test_frontend_views_use_backend_contracts():
    root = Path(__file__).resolve().parents[2]

    expected = {
        "frontend/src/views/Tasks.vue": [
            "listItems(response.data)",
            'value="todo"',
            'value="done"',
        ],
        "frontend/src/views/Assets.vue": [
            "listItems(response.data)",
            'value="software_license"',
        ],
        "frontend/src/views/Infrastructure.vue": [
            "listItems(response.data)",
            'value="compute"',
            'value="monitoring"',
        ],
        "frontend/src/views/Financial.vue": [
            "listItems(response.data)",
            'v-model="form.date"',
            'value="revenue"',
            'value="payment"',
        ],
        "frontend/src/views/Documents.vue": [
            "listItems(response.data)",
            "form.file_path",
            'value="specification"',
        ],
        "frontend/src/views/Dashboard.vue": [
            "totalItems(tasksRes.value.data)",
            "totalItems(infraRes.value.data)",
        ],
    }

    for relative_path, snippets in expected.items():
        source = (root / relative_path).read_text()
        for snippet in snippets:
            assert snippet in source, f"{relative_path} missing {snippet}"

    invalid_snippets = {
        "frontend/src/views/Tasks.vue": ['value="pending"', 'value="completed"'],
        "frontend/src/views/Assets.vue": ['value="hardware"', 'value="license"'],
        "frontend/src/views/Infrastructure.vue": ['value="server"', 'value="cloud"'],
        "frontend/src/views/Financial.vue": ['value="income"'],
        "frontend/src/views/Documents.vue": ["form.url"],
    }
    for relative_path, snippets in invalid_snippets.items():
        source = (root / relative_path).read_text()
        for snippet in snippets:
            assert snippet not in source, f"{relative_path} still contains {snippet}"


def test_frontend_auth_contract_restores_and_clears_sessions():
    root = Path(__file__).resolve().parents[2]

    auth_store = (root / "frontend/src/store/auth.js").read_text()
    assert "isAuthenticated: (state) => !!state.token && !!state.user" in auth_store
    assert "async restoreSession()" in auth_store
    assert "apiClient.get('/auth/me')" in auth_store
    assert "clearAuth()" in auth_store
    assert "localStorage.removeItem('auth_token')" in auth_store

    router = (root / "frontend/src/router/index.js").read_text()
    assert "beforeEach(async" in router
    assert "await authStore.restoreSession()" in router
    assert "query: { redirect: to.fullPath }" in router

    client = (root / "frontend/src/api/client.js").read_text()
    assert "new CustomEvent('auth:unauthorized')" in client
    assert "window.location.pathname !== '/login'" in client

    main = (root / "frontend/src/main.js").read_text()
    assert "window.addEventListener('auth:unauthorized'" in main
    assert "useAuthStore().clearAuth()" in main
