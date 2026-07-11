"""P0 executable production-posture and future managed-contract gates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import acgs_control_plane.app as app_module
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.governance import (
    ROUTE_CONTRACTS,
    AuthenticatedRuntimeContext,
    ExecutionClass,
    ProductionPostureBlocked,
    SealedProviderStatus,
    managed_contract_stub,
)


class ReadyProvider:
    def __init__(self, component: str) -> None:
        self.component = component
        self.calls = 0

    def preflight(self) -> SealedProviderStatus:
        self.calls += 1
        return SealedProviderStatus.from_provider(self.component, True)


def _settings(tmp_path: Path, posture: RuntimePosture | None) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'must-not-exist.sqlite3'}",
        audit_dir=tmp_path / "audit",
        create_tables=True,
        runtime_posture=posture,
    )


def test_production_rejects_legacy_unsigned_routes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local = create_app(_settings(tmp_path, RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED))
    actual = {
        (method, route.path)
        for route in local.routes
        if isinstance(route, APIRoute)
        for method in route.methods or ()
    }
    expected = {(record.method, record.path) for record in ROUTE_CONTRACTS}
    assert actual == expected
    assert len(expected) == len(ROUTE_CONTRACTS)
    legacy = [
        r for r in ROUTE_CONTRACTS if r.execution_class is ExecutionClass.LEGACY_UNSIGNED_WRITE
    ]
    assert len(legacy) == 7
    assert TestClient(local).get("/healthz").status_code == 200
    ready = TestClient(local).get("/readyz")
    assert ready.status_code == 503
    assert ready.json()["status"] == "not-production-ready"
    local.state.engine.dispose()
    (tmp_path / "must-not-exist.sqlite3").unlink()

    calls = {"engine": 0}

    def forbidden_engine(_url: str) -> Any:
        calls["engine"] += 1
        raise AssertionError("persistence constructed before posture refusal")

    monkeypatch.setattr("acgs_control_plane.app.make_engine", forbidden_engine)
    with pytest.raises(ProductionPostureBlocked) as missing:
        create_app(_settings(tmp_path, None))
    assert missing.value.stage == "pre-persistence"
    assert calls == {"engine": 0}
    unknown_settings = _settings(tmp_path, None)
    object.__setattr__(unknown_settings, "runtime_posture", "mystery")
    with pytest.raises(ProductionPostureBlocked) as unknown:
        create_app(unknown_settings)
    assert unknown.value.blockers[0].code == "RUNTIME_POSTURE_UNKNOWN"

    providers = tuple(
        ReadyProvider(c)
        for c in ("signer-issuer", "trust-verifier", "durable-consumption-uow", "migration-head")
    )
    with pytest.raises(ProductionPostureBlocked) as blocked:
        create_app(_settings(tmp_path, RuntimePosture.PRODUCTION), production_providers=providers)
    assert calls == {"engine": 0}
    assert len([b for b in blocked.value.blockers if b.code == "LEGACY_UNSIGNED_WRITE"]) == 7
    assert all(provider.calls == 0 for provider in providers)
    assert not (tmp_path / "must-not-exist.sqlite3").exists()
    assert not (tmp_path / "audit").exists()

    original_register = app_module._register_routes

    def register_with_drift(app: Any) -> None:
        original_register(app)

        @app.get("/synthetic-later-route")
        def synthetic() -> dict[str, bool]:
            return {"unexpected": True}

    monkeypatch.setattr(app_module, "_register_routes", register_with_drift)
    with pytest.raises(ProductionPostureBlocked) as drifted:
        create_app(_settings(tmp_path, RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED))
    assert any(b.code == "UNCLASSIFIED_ROUTE" for b in drifted.value.blockers)
    assert calls == {"engine": 0}


def test_tenant_bootstrap_and_register_contract_stub_no_mutation() -> None:
    context = AuthenticatedRuntimeContext.from_server_provider(
        actor="invitee:1",
        tenant="tenant:prospective",
        project="project:default",
        environment="environment:default",
        authentication_method="oidc",
        authority_domain="platform",
        validated_at="2026-07-11T00:00:00Z",
    )
    providers = tuple(
        ReadyProvider(c)
        for c in ("signer-issuer", "trust-verifier", "durable-consumption-uow", "migration-head")
    )
    mutations = {"count": 0}

    def mutate() -> None:
        mutations["count"] += 1

    bindings = {
        "authority": "platform.provisioner/v1",
        "validator": "platform.bootstrap-policy/v1",
        "policy_id": "bootstrap",
        "policy_version": "1",
        "policy_hash": "a" * 64,
        "issued_at": "2026-07-11T00:00:00Z",
        "expires_at": "2026-07-11T00:01:00Z",
        "key_id": "key-1",
        "audit_anchor": "b" * 64,
        "idempotency_key": "op-1",
    }
    for decision in ("DENY", "ESCALATE", "ALLOW"):
        for contract, body in (
            ("tenant.bootstrap/v1", {"display_name": "Acme"}),
            (
                "agent.register/v1",
                {"name": "dispatcher", "configuration": {"mode": "strict"}},
            ),
        ):
            with pytest.raises(ProductionPostureBlocked) as stopped:
                managed_contract_stub(
                    contract,
                    body,
                    context,
                    providers=providers,
                    bindings=bindings,
                    decision=decision,
                    mutation=mutate,
                )
            assert stopped.value.blockers[0].code == "CANONICAL_PATH_NOT_ENABLED"
    assert mutations == {"count": 0}

    with pytest.raises(ValueError, match="caller-controlled"):
        managed_contract_stub(
            "agent.register/v1",
            {"name": "x", "tenant": "attacker"},
            context,
            providers=providers,
            bindings=bindings,
            decision="ALLOW",
            mutation=mutate,
        )
    assert mutations == {"count": 0}
