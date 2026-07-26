from __future__ import annotations

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
    TENANT_BOOTSTRAP_ACTION,
    TENANT_BOOTSTRAP_EXECUTION_BOUNDARY,
)
from acgs_control_plane.tenant_bootstrap import (
    BOOTSTRAP_AUTHORIZATION_HEADER,
    BOOTSTRAP_IDEMPOTENCY_HEADER,
    TENANT_BOOTSTRAP_AUTHORITY,
)

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
        ("POST", "/v1/orgs/{org_id}/agents"),
    }
    assert managed[("POST", "/v1/tenant-bootstrap")].action == TENANT_BOOTSTRAP_ACTION
    assert managed[("POST", "/orgs/{org_id}/agents")].action == CONTROL_PLANE_AGENT_CREATE_ACTION
    assert managed[("POST", "/v1/orgs/{org_id}/agents")].action == CONTROL_PLANE_AGENT_CREATE_ACTION
    assert all(route.permits_persistent_effect for route in managed.values())
    assert not any(route.permits_external_effect for route in managed.values())

    legacy_writes = [
        route
        for route in ROUTE_CONTRACTS
        if route.execution_class is ExecutionClass.LEGACY_UNSIGNED_WRITE
    ]
    # Every legacy write is aliased under /v1, so the registry carries each
    # remaining unsigned route twice: the unversioned path and its /v1 alias.
    legacy_actions = [
        ("POST", "/orgs", "org.create"),
        ("POST", "/orgs/{org_id}/users", "user.create"),
        ("PATCH", "/orgs/{org_id}/agents/{agent_id}/status", "agent.set_status"),
        ("POST", "/orgs/{org_id}/policies", "policy.publish"),
        ("POST", "/orgs/{org_id}/policies/{bundle_id}/activate", "policy.activate"),
        ("POST", "/orgs/{org_id}/exports", "export.generate"),
    ]
    assert [(route.method, route.path, route.action) for route in legacy_writes] == [
        *legacy_actions,
        *[(method, f"/v1{path}", action) for method, path, action in legacy_actions],
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
    assert len(legacy_blockers) == 12
    assert {blocker["route"] for blocker in legacy_blockers} == {
        f"{route.method} {route.path}" for route in legacy_writes
    }
    assert {
        blocker["component"]
        for blocker in blockers
        if blocker["code"] == "PROVIDER_PREFLIGHT_SKIPPED"
    } == {
        "cursor-aead-keyring",
        "durable-consumption-uow",
        "migration-head",
        "signer-issuer",
        "trust-verifier",
    }
