from __future__ import annotations

import re
from typing import Any

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from acgs_control_plane.auth import Principal
from acgs_control_plane.governance import ROUTE_CONTRACTS, ExecutionClass
from acgs_control_plane.mutation_inventory import (
    CANONICAL_MUTATION_DEFINITIONS,
    MutationDefinition,
    MutationEffectClass,
    verify_static_sql_atomic_safety,
)
from acgs_control_plane.tenant_bootstrap import BOOTSTRAP_IDEMPOTENCY_HEADER


def test_mutation_inventory_preserves_canonical_and_legacy_truth(client: TestClient) -> None:
    canonical_contracts = [
        contract
        for contract in ROUTE_CONTRACTS
        if contract.execution_class is ExecutionClass.CANONICAL_MANAGED_WRITE
    ]
    legacy_contracts = [
        contract
        for contract in ROUTE_CONTRACTS
        if contract.execution_class is ExecutionClass.LEGACY_UNSIGNED_WRITE
    ]

    # 6 unversioned canonical writes plus the 5 /v1 aliases (tenant bootstrap
    # is already served under /v1), and 6 legacy writes plus their /v1 aliases.
    assert len(canonical_contracts) == 11
    assert len(legacy_contracts) == 12
    assert {
        (definition.method, definition.path, definition.action, definition.effect_class)
        for definition in CANONICAL_MUTATION_DEFINITIONS
    } == {
        (contract.method, contract.path, contract.action, MutationEffectClass.SQL_ATOMIC)
        for contract in canonical_contracts
    }
    assert all(
        definition.effect_class is MutationEffectClass.SQL_ATOMIC
        for definition in CANONICAL_MUTATION_DEFINITIONS
    )
    assert {
        "agent.register",
        "agent.register.v1",
        "approval.vote",
        "approval.vote.v1",
        "approval.resume",
        "approval.resume.v1",
        "environment-policy.publish",
        "environment-policy.publish.v1",
        "environment-policy.activate",
        "environment-policy.activate.v1",
        "tenant-bootstrap.create",
    } == {definition.operation_id for definition in CANONICAL_MUTATION_DEFINITIONS}
    assert not [
        definition
        for definition in CANONICAL_MUTATION_DEFINITIONS
        if definition.effect_class
        in {MutationEffectClass.DURABLE_JOB_ENQUEUE, MutationEffectClass.EXTERNAL_ATTEMPT}
    ]
    assert (
        len(
            [
                blocker
                for blocker in client.app.state.readiness_blockers
                if blocker.code == "LEGACY_UNSIGNED_WRITE"
            ]
        )
        == 12
    )
    assert client.get("/healthz").status_code == 200


def test_late_route_added_after_app_creation_is_refused_before_handler(
    client: TestClient,
) -> None:
    reached = {"handler": False}

    @client.app.post("/synthetic-after-seal-write")
    def synthetic_after_seal_write() -> dict[str, bool]:
        reached["handler"] = True
        return {"mutated": True}

    response = client.post(
        "/synthetic-after-seal-write",
        json={"secret": "ACGS_SECRET_BODY_SHOULD_NOT_APPEAR"},
        headers={"X-Secret": "ACGS_SECRET_HEADER_SHOULD_NOT_APPEAR"},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "MUTATION_INVENTORY_DRIFT"
    assert reached == {"handler": False}
    assert "ACGS_SECRET_BODY_SHOULD_NOT_APPEAR" not in response.text
    assert "ACGS_SECRET_HEADER_SHOULD_NOT_APPEAR" not in response.text
    assert "synthetic_after_seal_write" not in response.text


def test_endpoint_swap_same_name_is_refused_before_managed_handler(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    reached = {"handler": False}
    route = _api_route(client, "POST", "/orgs/{org_id}/agents")

    def register_agent(*_args: Any, **_kwargs: Any) -> dict[str, bool]:
        reached["handler"] = True
        return {"mutated": True}

    assert register_agent.__name__ == route.endpoint.__name__
    route.endpoint = register_agent

    response = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={"name": "sealed-dispatcher"},
        headers={**admin_headers, BOOTSTRAP_IDEMPOTENCY_HEADER: "inventory-drift-agent-0001"},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "MUTATION_INVENTORY_DRIFT"
    assert reached == {"handler": False}
    assert "sealed-dispatcher" not in response.text
    assert "register_agent" not in response.text


def test_route_app_swap_is_refused_before_dispatched_asgi_app(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    reached = {"route_app": False}
    route = _api_route(client, "POST", "/orgs/{org_id}/agents")

    async def replacement_route_app(_scope: Any, _receive: Any, _send: Any) -> None:
        reached["route_app"] = True

    route.app = replacement_route_app

    response = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={"name": "route-app-drift-agent"},
        headers={**admin_headers, BOOTSTRAP_IDEMPOTENCY_HEADER: "inventory-route-app-0001"},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "MUTATION_INVENTORY_DRIFT"
    assert reached == {"route_app": False}
    assert "route-app-drift-agent" not in response.text


def test_dependant_call_swap_is_refused_before_replacement_call(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    reached = {"dependant": False}
    route = _api_route(client, "POST", "/orgs/{org_id}/agents")

    def register_agent(*_args: Any, **_kwargs: Any) -> dict[str, bool]:
        reached["dependant"] = True
        return {"mutated": True}

    route.dependant.call = register_agent

    response = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={"name": "dependant-drift-agent"},
        headers={**admin_headers, BOOTSTRAP_IDEMPOTENCY_HEADER: "inventory-dependant-0001"},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "MUTATION_INVENTORY_DRIFT"
    assert reached == {"dependant": False}
    assert "dependant-drift-agent" not in response.text


def test_dependency_rbac_drift_is_refused_before_managed_handler(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    route = _api_route(client, "POST", "/orgs/{org_id}/agents")
    removed = route.dependant.dependencies.pop()

    try:
        response = client.post(
            f"/orgs/{org['org_id']}/agents",
            json={"name": "rbac-drift-agent"},
            headers={**admin_headers, BOOTSTRAP_IDEMPOTENCY_HEADER: "inventory-rbac-agent-0001"},
        )
    finally:
        route.dependant.dependencies.append(removed)

    assert response.status_code == 503
    payload = response.json()
    assert payload["code"] == "MUTATION_INVENTORY_DRIFT"
    assert {
        detail["code"]
        for detail in payload["details"]
        if detail["operation_id"] == "agent.register"
    } >= {"RBAC_CONTRACT_DRIFT", "MANAGED_ROUTE_BINDING_DRIFT"}
    assert "rbac-drift-agent" not in response.text


def test_dependency_override_drift_refuses_before_auth_or_override(client: TestClient) -> None:
    reached = {"override": False}
    route = _api_route(client, "POST", "/orgs/{org_id}/agents")
    dependency_call = route.dependant.dependencies[-1].call

    def override() -> Principal:
        reached["override"] = True
        return Principal(user_id="u", org_id="o", name="n", role="org_admin")

    client.app.dependency_overrides[dependency_call] = override
    response = client.post(
        "/orgs/org-does-not-matter/agents",
        json={"name": "override-drift-agent"},
        headers={BOOTSTRAP_IDEMPOTENCY_HEADER: "inventory-override-0001"},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "MUTATION_INVENTORY_DRIFT"
    assert reached == {"override": False}
    assert "override-drift-agent" not in response.text


def test_service_instance_replacement_is_refused_before_service_call(
    client: TestClient, org: dict[str, Any], admin_headers: dict[str, str]
) -> None:
    reached = {"service": False}

    class ReplacementAgentRegistrationService:
        def register(self, *_args: Any, **_kwargs: Any) -> dict[str, bool]:
            reached["service"] = True
            return {"mutated": True}

    client.app.state.agent_registration_service = ReplacementAgentRegistrationService()

    response = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={"name": "replacement-service-agent"},
        headers={**admin_headers, BOOTSTRAP_IDEMPOTENCY_HEADER: "inventory-service-0001"},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "MUTATION_INVENTORY_DRIFT"
    assert reached == {"service": False}
    assert "replacement-service-agent" not in response.text


def test_service_method_monkeypatch_is_refused_before_method_call(
    client: TestClient,
    org: dict[str, Any],
    admin_headers: dict[str, str],
    monkeypatch: Any,
) -> None:
    reached = {"method": False}
    service_type = type(client.app.state.agent_registration_service)

    def replacement_register(self: Any, *_args: Any, **_kwargs: Any) -> dict[str, bool]:
        del self
        reached["method"] = True
        return {"mutated": True}

    monkeypatch.setattr(service_type, "register", replacement_register)

    response = client.post(
        f"/orgs/{org['org_id']}/agents",
        json={"name": "method-drift-agent"},
        headers={**admin_headers, BOOTSTRAP_IDEMPOTENCY_HEADER: "inventory-method-0001"},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "MUTATION_INVENTORY_DRIFT"
    assert reached == {"method": False}
    assert "method-drift-agent" not in response.text


def test_later_middleware_is_refused_before_middleware_side_effect(client: TestClient) -> None:
    reached = {"middleware": False}

    @client.app.middleware("http")
    async def later_middleware(_request: Any, call_next: Any) -> Any:
        reached["middleware"] = True
        return await call_next(_request)

    response = client.get("/healthz")

    assert response.status_code == 503
    assert response.json()["code"] == "MUTATION_INVENTORY_DRIFT"
    assert reached == {"middleware": False}
    assert "later_middleware" not in response.text


def test_middleware_dispatch_replacement_is_refused_before_side_effect(
    client: TestClient,
) -> None:
    reached = {"dispatch": False}
    middleware = next(iter(client.app.user_middleware))

    class ReplacementMiddleware:
        def __init__(self, app: Any, **_kwargs: Any) -> None:
            self.app = app

        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            reached["dispatch"] = True
            await self.app(scope, receive, send)

    middleware.cls = ReplacementMiddleware

    response = client.get("/healthz")

    assert response.status_code == 503
    assert response.json()["code"] == "MUTATION_INVENTORY_DRIFT"
    assert reached == {"dispatch": False}
    assert "ReplacementMiddleware" not in response.text


def test_legacy_route_regex_and_precedence_drift_executes_zero_legacy_handler(
    client: TestClient,
) -> None:
    reached = {"legacy": False}
    legacy_route = _api_route(client, "POST", "/orgs")
    canonical_route = _api_route(client, "POST", "/v1/tenant-bootstrap")

    async def legacy_route_app(_scope: Any, _receive: Any, _send: Any) -> None:
        reached["legacy"] = True

    legacy_route.app = legacy_route_app
    legacy_route.path_regex = re.compile("^/v1/tenant-bootstrap$")
    routes = list(client.app.router.routes)
    routes.remove(legacy_route)
    canonical_index = routes.index(canonical_route)
    routes.insert(canonical_index, legacy_route)
    client.app.router.routes[:] = routes

    response = client.post("/v1/tenant-bootstrap", json={"display_name": "Regex Drift"})

    assert response.status_code == 503
    assert response.json()["code"] == "MUTATION_INVENTORY_DRIFT"
    assert reached == {"legacy": False}
    assert "Regex Drift" not in response.text


def test_sql_atomic_static_guard_rejects_accidental_direct_side_effects() -> None:
    definition = MutationDefinition(
        operation_id="unsafe.probe",
        method="POST",
        path="/unsafe",
        action="unsafe.probe",
        effect_class=MutationEffectClass.SQL_ATOMIC,
        dispatcher="managed-mutation-uow.execute_with_receipt",
        service="tests.test_mutation_inventory",
        permission=None,
        scope="test",
        state_key="unsafe_service",
        service_method="run",
        static_symbols=(
            f"{__name__}:_unsafe_sql_atomic_static_probe",
            f"{__name__}:_unsafe_alias_static_probe",
        ),
    )

    blockers = verify_static_sql_atomic_safety((definition,))

    assert {blocker.code for blocker in blockers} == {
        "SQL_ATOMIC_FORBIDDEN_CALL",
        "SQL_ATOMIC_FORBIDDEN_METHOD",
    }
    assert {blocker.detail for blocker in blockers} >= {
        "filesystem",
        "direct-transaction-control",
        "subprocess",
    }


def test_static_guard_scans_registered_real_callback_surface() -> None:
    symbols = {
        symbol
        for definition in CANONICAL_MUTATION_DEFINITIONS
        for symbol in definition.static_symbols
    }

    assert "acgs_control_plane.tenant_bootstrap.TenantBootstrapService.bootstrap" in symbols
    assert "acgs_control_plane.tenant_bootstrap._execute_bootstrap_effect" in symbols
    assert "acgs_control_plane.agent_registration.AgentRegistrationService.register" in symbols
    assert "acgs_control_plane.approvals.create_agent_registration_approval_request" in symbols
    assert "acgs_control_plane.approvals.ApprovalService.vote" in symbols
    assert "acgs_control_plane.approvals.ApprovalService.resume" in symbols
    assert "acgs_control_plane.policy_registry.PolicyRegistryService.publish" in symbols
    assert "acgs_control_plane.policy_registry.PolicyRegistryService.activate" in symbols
    assert "acgs_control_plane.managed_mutations._execute_verified_operation" in symbols
    assert verify_static_sql_atomic_safety(CANONICAL_MUTATION_DEFINITIONS) == ()


def _api_route(client: TestClient, method: str, path: str) -> APIRoute:
    for route in client.app.routes:
        if isinstance(route, APIRoute) and route.path == path and method in (route.methods or ()):
            return route
    raise AssertionError(f"missing route {method} {path}")


def _unsafe_sql_atomic_static_probe(session: Any) -> None:
    session.commit()
    open("/tmp/acgs-unsafe-static-probe", "w").close()


def _unsafe_alias_static_probe() -> None:
    import subprocess as sp

    runner = sp.run
    runner(["true"])
