from __future__ import annotations

from acgs_control_plane.governance import ROUTE_CONTRACTS, ExecutionClass
from acgs_control_plane.managed_mutations import (
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
    assert _common.EXPECTED_BOOTSTRAP_MAP["P2-TENANT-BOOTSTRAP-000"] == "EVID+CP+GZ"
