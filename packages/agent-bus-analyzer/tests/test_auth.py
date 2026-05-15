"""T028 — RBAC FastAPI dependency unit tests."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_bus_analyzer.auth import REVIEWER_ROLES, ReviewerRole, ValidatorFn, set_validator


def _make_app(validator: ValidatorFn) -> FastAPI:
    set_validator(validator)
    app = FastAPI()

    @app.get("/protected")
    async def protected(roles: ReviewerRole) -> dict[str, list[str]]:
        return {"roles": sorted(roles)}

    return app


def test_missing_bearer_yields_401() -> None:
    client = TestClient(_make_app(lambda _t: None))
    assert client.get("/protected").status_code == 401


def test_bad_token_yields_401() -> None:
    client = TestClient(_make_app(lambda _t: None))
    response = client.get("/protected", headers={"Authorization": "Bearer junk"})
    assert response.status_code == 401


def test_unauthorized_role_yields_403() -> None:
    client = TestClient(_make_app(lambda _t: frozenset({"random-other-role"})))
    response = client.get("/protected", headers={"Authorization": "Bearer ok"})
    assert response.status_code == 403


@pytest.mark.parametrize("role", sorted(REVIEWER_ROLES))
def test_authorized_role_yields_200(role: str) -> None:
    client = TestClient(_make_app(lambda _t: frozenset({role})))
    response = client.get("/protected", headers={"Authorization": "Bearer ok"})
    assert response.status_code == 200
    assert role in response.json()["roles"]
