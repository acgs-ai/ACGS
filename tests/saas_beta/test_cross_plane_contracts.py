from __future__ import annotations

import inspect

import pytest
from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.governance import (
    ROUTE_CONTRACTS,
    ExecutionClass,
    ProductionPostureBlocked,
)
from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_AGENT_CREATE_ACTION,
    CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
    CONTROL_PLANE_POLICY_PUBLISH_ACTION,
    TENANT_BOOTSTRAP_ACTION,
    TENANT_BOOTSTRAP_EXECUTION_BOUNDARY,
    ManagedMutationUnitOfWork,
)
from acgs_control_plane.policy_registry import PolicyRegistryService
from acgs_control_plane.tenant_bootstrap import (
    BOOTSTRAP_AUTHORIZATION_HEADER,
    BOOTSTRAP_IDEMPOTENCY_HEADER,
    TENANT_BOOTSTRAP_AUTHORITY,
)
from fastapi.routing import APIRoute

from scripts.evidence import _common


def test_tenant_bootstrap_receipt_contract() -> None:
    matches = [
        route
        for route in ROUTE_CONTRACTS
        if (route.method, route.path) == ("POST", "/v1/tenant-bootstrap")
    ]
    assert len(matches) == 1
    route = matches[0]
    assert route.execution_class is ExecutionClass.CANONICAL_MANAGED_WRITE
    assert route.action == TENANT_BOOTSTRAP_ACTION == "tenant.bootstrap"
    assert route.permits_persistent_effect is True
    assert route.permits_filesystem_effect is False
    assert route.permits_external_effect is False
    assert TENANT_BOOTSTRAP_EXECUTION_BOUNDARY == "control-plane:tenant.bootstrap/v1"
    assert TENANT_BOOTSTRAP_AUTHORITY == "platform.provisioner/v1"
    assert BOOTSTRAP_AUTHORIZATION_HEADER == "Authorization"
    assert BOOTSTRAP_IDEMPOTENCY_HEADER == "Idempotency-Key"
    assert not any(
        candidate.path == "/v1/tenant-bootstrap"
        and candidate.execution_class is ExecutionClass.LEGACY_UNSIGNED_WRITE
        for candidate in ROUTE_CONTRACTS
    )

    assert _common.P2_TENANT_BOOTSTRAP_CP_SELECTORS == (
        "tests/integration/test_tenant_bootstrap_vertical.py::"
        "test_real_api_postgres_bootstrap_allow_atomic",
        "tests/integration/test_tenant_bootstrap_vertical.py::"
        "test_real_api_postgres_bootstrap_refusal_matrix",
        "tests/integration/test_tenant_bootstrap_vertical.py::"
        "test_100_request_multiprocess_bootstrap_once",
    )
    assert _common.P2_TENANT_BOOTSTRAP_ROOT_SELECTOR == (
        "tests/saas_beta/test_cross_plane_contracts.py::test_tenant_bootstrap_receipt_contract"
    )
    assert _common.P2_VERTICAL_GATE_ROOT_SELECTORS == (
        "tests/saas_beta/test_cross_plane_contracts.py::test_tenant_bootstrap_receipt_contract",
        "tests/saas_beta/test_cross_plane_contracts.py::"
        "test_vertical_gate_contract_locks_managed_routes_and_production_blockers",
    )
    assert _common.EXPECTED_BOOTSTRAP_MAP["P2-TENANT-BOOTSTRAP-000"] == "EVID+CP+GZ"


def test_vertical_gate_contract_locks_managed_routes_and_production_blockers(
    tmp_path,
) -> None:
    managed = {
        (route.method, route.path): route
        for route in ROUTE_CONTRACTS
        if route.execution_class is ExecutionClass.CANONICAL_MANAGED_WRITE
    }
    assert set(managed) == {
        ("POST", "/v1/tenant-bootstrap"),
        ("POST", "/orgs/{org_id}/agents"),
        ("POST", "/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies"),
        (
            "POST",
            "/orgs/{org_id}/projects/{project_id}/environments/{environment_id}"
            "/policies/{policy_version_id}/activate",
        ),
    }
    assert managed[("POST", "/v1/tenant-bootstrap")].action == TENANT_BOOTSTRAP_ACTION
    assert managed[("POST", "/orgs/{org_id}/agents")].action == CONTROL_PLANE_AGENT_CREATE_ACTION
    assert (
        managed[
            ("POST", "/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies")
        ].action
        == CONTROL_PLANE_POLICY_PUBLISH_ACTION
    )
    assert (
        managed[
            (
                "POST",
                "/orgs/{org_id}/projects/{project_id}/environments/{environment_id}"
                "/policies/{policy_version_id}/activate",
            )
        ].action
        == CONTROL_PLANE_POLICY_ACTIVATE_ACTION
    )
    assert all(route.permits_persistent_effect for route in managed.values())
    assert not any(route.permits_external_effect for route in managed.values())

    legacy_writes = [
        route
        for route in ROUTE_CONTRACTS
        if route.execution_class is ExecutionClass.LEGACY_UNSIGNED_WRITE
    ]
    assert [(route.method, route.path, route.action) for route in legacy_writes] == [
        ("POST", "/orgs", "org.create"),
        ("POST", "/orgs/{org_id}/users", "user.create"),
        ("PATCH", "/orgs/{org_id}/agents/{agent_id}/status", "agent.set_status"),
        ("POST", "/orgs/{org_id}/policies", "policy.publish"),
        ("POST", "/orgs/{org_id}/policies/{bundle_id}/activate", "policy.activate"),
        ("POST", "/orgs/{org_id}/exports", "export.generate"),
    ]

    with pytest.raises(ProductionPostureBlocked) as blocked:
        create_app(
            Settings(
                database_url="sqlite:///:memory:",
                audit_dir=tmp_path / "audit",
                create_tables=False,
                runtime_posture=RuntimePosture.PRODUCTION,
            ),
            production_providers=(),
        )
    blockers = [blocker.to_dict() for blocker in blocked.value.blockers]
    legacy_blockers = [
        blocker for blocker in blockers if blocker["code"] == "LEGACY_UNSIGNED_WRITE"
    ]
    assert len(legacy_blockers) == 6
    assert {blocker["route"] for blocker in legacy_blockers} == {
        f"{route.method} {route.path}" for route in legacy_writes
    }
    assert {
        blocker["component"]
        for blocker in blockers
        if blocker["code"] == "PROVIDER_PREFLIGHT_SKIPPED"
    } == {
        "durable-consumption-uow",
        "migration-head",
        "signer-issuer",
        "trust-verifier",
    }


def test_policy_registry_contract_locks_managed_routes_negative_oracles_and_local_posture(
    tmp_path,
) -> None:
    managed_routes = {
        (route.method, route.path): route
        for route in ROUTE_CONTRACTS
        if route.execution_class is ExecutionClass.CANONICAL_MANAGED_WRITE
    }
    publish_key = (
        "POST",
        "/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies",
    )
    activate_key = (
        "POST",
        "/orgs/{org_id}/projects/{project_id}/environments/{environment_id}"
        "/policies/{policy_version_id}/activate",
    )
    assert managed_routes[publish_key].action == CONTROL_PLANE_POLICY_PUBLISH_ACTION
    assert managed_routes[activate_key].action == CONTROL_PLANE_POLICY_ACTIVATE_ACTION
    assert {
        (route.method, route.path, route.action)
        for route in managed_routes.values()
        if route.action
        in {
            CONTROL_PLANE_POLICY_PUBLISH_ACTION,
            CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
        }
    } == {
        (*publish_key, CONTROL_PLANE_POLICY_PUBLISH_ACTION),
        (*activate_key, CONTROL_PLANE_POLICY_ACTIVATE_ACTION),
    }

    app = create_app(
        Settings(
            database_url="sqlite:///:memory:",
            audit_dir=tmp_path / "audit",
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )
    active_http_routes = {
        (next(iter(route.methods - {"HEAD"})), route.path): route.endpoint
        for route in app.routes
        if isinstance(route, APIRoute) and route.methods
    }
    publish_source = inspect.getsource(active_http_routes[publish_key])
    activate_source = inspect.getsource(active_http_routes[activate_key])
    for source, method_name in (
        (publish_source, ".publish("),
        (activate_source, ".activate("),
    ):
        assert "request.app.state.policy_registry_service" in source
        assert f"service{method_name}" in source
    assert isinstance(app.state.policy_registry_service, PolicyRegistryService)

    service_source = inspect.getsource(PolicyRegistryService)
    uow_source = inspect.getsource(ManagedMutationUnitOfWork)
    assert "ManagedMutationUnitOfWork(" in service_source
    assert service_source.count("uow.execute(") >= 2
    assert "execute_with_receipt(" in uow_source
    assert "expected_action=context.action" in uow_source
    assert "expected_project_id=context.project_id" in uow_source
    assert "expected_environment_id=context.environment_id" in uow_source

    assert _common.P3_POLICY_CP_SELECTORS == (
        "tests/integration/test_managed_policy_lifecycle_postgres.py::"
        "test_pg_publish_immutable_version_without_head",
        "tests/integration/test_managed_policy_lifecycle_postgres.py::"
        "test_pg_activate_advances_exactly_one_head",
        "tests/integration/test_managed_policy_lifecycle_postgres.py::"
        "test_pg_concurrent_candidates_have_one_generation_winner",
        "tests/integration/test_managed_policy_lifecycle_postgres.py::"
        "test_pg_publish_idempotent_replay_is_one_terminal_effect",
        "tests/integration/test_managed_policy_lifecycle_postgres.py::"
        "test_pg_idempotency_conflict_has_zero_delta",
        "tests/integration/test_managed_policy_lifecycle_postgres.py::"
        "test_pg_activation_revalidates_trust_and_rolls_back_before_effect",
    )
    assert _common.P3_POLICY_ROOT_SELECTORS == (
        "tests/saas_beta/test_cross_plane_contracts.py::"
        "test_policy_registry_contract_locks_managed_routes_negative_oracles_and_local_posture",
    )
    assert _common.EXPECTED_BOOTSTRAP_MAP["P3-POLICY-001"] == "EVID+CP"

    negative_zero_effect_oracles = {
        "tests/test_policy_registry_managed.py::"
        "test_managed_policy_activate_advances_head_once_and_stale_is_zero_effect",
        "tests/test_policy_registry_managed.py::"
        "test_managed_policy_publish_denial_records_evidence_without_policy_state",
        "tests/test_policy_registry_managed.py::"
        "test_managed_policy_activate_escalation_records_evidence_without_head_change",
        "tests/test_policy_registry_managed.py::"
        "test_managed_policy_rejects_nonfinite_json_before_persistence",
        "tests/test_policy_registry_managed.py::"
        "test_managed_policy_cross_environment_envelope_transplant_fails_before_effect",
        "tests/test_policy_registry_managed.py::"
        "test_managed_policy_wrong_environment_fails_before_effect",
    }
    assert all(
        selector.startswith("tests/test_policy_registry_managed.py::")
        for selector in negative_zero_effect_oracles
    )

    with pytest.raises(ProductionPostureBlocked) as blocked:
        create_app(
            Settings(
                database_url="sqlite:///:memory:",
                audit_dir=tmp_path / "prod-audit",
                create_tables=False,
                runtime_posture=RuntimePosture.PRODUCTION,
            ),
            production_providers=(),
        )
    blockers = [blocker.to_dict() for blocker in blocked.value.blockers]
    assert {
        blocker["component"]
        for blocker in blockers
        if blocker["code"] == "PROVIDER_PREFLIGHT_SKIPPED"
    } == {
        "durable-consumption-uow",
        "migration-head",
        "signer-issuer",
        "trust-verifier",
    }
    assert {
        blocker["route"] for blocker in blockers if blocker["code"] == "LEGACY_UNSIGNED_WRITE"
    } == {
        "POST /orgs",
        "POST /orgs/{org_id}/users",
        "PATCH /orgs/{org_id}/agents/{agent_id}/status",
        "POST /orgs/{org_id}/policies",
        "POST /orgs/{org_id}/policies/{bundle_id}/activate",
        "POST /orgs/{org_id}/exports",
    }
