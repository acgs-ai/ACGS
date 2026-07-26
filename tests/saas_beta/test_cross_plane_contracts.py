from __future__ import annotations

import inspect

import acgs_control_plane.approvals as approvals_module
import pytest
from acgs_control_plane.app import create_app
from acgs_control_plane.approvals import ApprovalService
from acgs_control_plane.config import RuntimePosture, Settings
from acgs_control_plane.governance import (
    ROUTE_CONTRACTS,
    ExecutionClass,
    ProductionPostureBlocked,
)
from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_AGENT_CREATE_ACTION,
    CONTROL_PLANE_APPROVAL_VOTE_ACTION,
    CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
    CONTROL_PLANE_POLICY_PUBLISH_ACTION,
    TENANT_BOOTSTRAP_ACTION,
    TENANT_BOOTSTRAP_EXECUTION_BOUNDARY,
    ManagedMutationUnitOfWork,
)
from acgs_control_plane.mutation_inventory import (
    CANONICAL_MUTATION_DEFINITIONS,
    MutationEffectClass,
    MutationGuardedFastAPI,
    verify_static_sql_atomic_safety,
)
from acgs_control_plane.policy_registry import PolicyRegistryService
from acgs_control_plane.rbac import Permission
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
        ("POST", "/v1/orgs/{org_id}/agents"),
        ("POST", "/orgs/{org_id}/approvals/{approval_request_id}/votes"),
        ("POST", "/v1/orgs/{org_id}/approvals/{approval_request_id}/votes"),
        ("POST", "/orgs/{org_id}/approvals/{approval_request_id}/resume"),
        ("POST", "/v1/orgs/{org_id}/approvals/{approval_request_id}/resume"),
        ("POST", "/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies"),
        (
            "POST",
            "/v1/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies",
        ),
        (
            "POST",
            "/orgs/{org_id}/projects/{project_id}/environments/{environment_id}"
            "/policies/{policy_version_id}/activate",
        ),
        (
            "POST",
            "/v1/orgs/{org_id}/projects/{project_id}/environments/{environment_id}"
            "/policies/{policy_version_id}/activate",
        ),
    }
    assert managed[("POST", "/v1/tenant-bootstrap")].action == TENANT_BOOTSTRAP_ACTION
    assert managed[("POST", "/orgs/{org_id}/agents")].action == CONTROL_PLANE_AGENT_CREATE_ACTION
    assert managed[("POST", "/v1/orgs/{org_id}/agents")].action == CONTROL_PLANE_AGENT_CREATE_ACTION
    assert (
        managed[("POST", "/orgs/{org_id}/approvals/{approval_request_id}/votes")].action
        == CONTROL_PLANE_APPROVAL_VOTE_ACTION
    )
    assert (
        managed[("POST", "/v1/orgs/{org_id}/approvals/{approval_request_id}/votes")].action
        == CONTROL_PLANE_APPROVAL_VOTE_ACTION
    )
    assert (
        managed[("POST", "/orgs/{org_id}/approvals/{approval_request_id}/resume")].action
        == CONTROL_PLANE_AGENT_CREATE_ACTION
    )
    assert (
        managed[("POST", "/v1/orgs/{org_id}/approvals/{approval_request_id}/resume")].action
        == CONTROL_PLANE_AGENT_CREATE_ACTION
    )
    for prefix in ("", "/v1"):
        assert (
            managed[
                (
                    "POST",
                    f"{prefix}/orgs/{{org_id}}/projects/{{project_id}}"
                    "/environments/{environment_id}/policies",
                )
            ].action
            == CONTROL_PLANE_POLICY_PUBLISH_ACTION
        )
        assert (
            managed[
                (
                    "POST",
                    f"{prefix}/orgs/{{org_id}}/projects/{{project_id}}"
                    "/environments/{environment_id}"
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


def test_policy_registry_contract_locks_managed_routes_negative_oracles_and_local_posture(
    tmp_path,
) -> None:
    managed_routes = {
        (route.method, route.path): route
        for route in ROUTE_CONTRACTS
        if route.execution_class is ExecutionClass.CANONICAL_MANAGED_WRITE
    }
    publish_keys = tuple(
        (
            "POST",
            f"{prefix}/orgs/{{org_id}}/projects/{{project_id}}"
            "/environments/{environment_id}/policies",
        )
        for prefix in ("", "/v1")
    )
    activate_keys = tuple(
        (
            "POST",
            f"{prefix}/orgs/{{org_id}}/projects/{{project_id}}"
            "/environments/{environment_id}/policies/{policy_version_id}/activate",
        )
        for prefix in ("", "/v1")
    )
    for publish_key in publish_keys:
        assert managed_routes[publish_key].action == CONTROL_PLANE_POLICY_PUBLISH_ACTION
    for activate_key in activate_keys:
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
        *[(*key, CONTROL_PLANE_POLICY_PUBLISH_ACTION) for key in publish_keys],
        *[(*key, CONTROL_PLANE_POLICY_ACTIVATE_ACTION) for key in activate_keys],
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
        "cursor-aead-keyring",
        "durable-consumption-uow",
        "migration-head",
        "signer-issuer",
        "trust-verifier",
    }
    legacy_unsigned_writes = {
        ("POST", "/orgs"),
        ("POST", "/orgs/{org_id}/users"),
        ("PATCH", "/orgs/{org_id}/agents/{agent_id}/status"),
        ("POST", "/orgs/{org_id}/policies"),
        ("POST", "/orgs/{org_id}/policies/{bundle_id}/activate"),
        ("POST", "/orgs/{org_id}/exports"),
    }
    assert {
        blocker["route"] for blocker in blockers if blocker["code"] == "LEGACY_UNSIGNED_WRITE"
    } == {
        f"{method} {prefix}{path}"
        for method, path in legacy_unsigned_writes
        for prefix in ("", "/v1")
    }


def test_mutation_inventory_contract_locks_registry_and_actual_routing(tmp_path) -> None:
    definitions = {
        definition.operation_id: definition for definition in CANONICAL_MUTATION_DEFINITIONS
    }
    assert set(definitions) == {
        "tenant-bootstrap.create",
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
    }
    assert all(
        definition.effect_class is MutationEffectClass.SQL_ATOMIC
        for definition in definitions.values()
    )
    assert not any(
        definition.effect_class
        in {MutationEffectClass.DURABLE_JOB_ENQUEUE, MutationEffectClass.EXTERNAL_ATTEMPT}
        for definition in definitions.values()
    )
    assert verify_static_sql_atomic_safety(CANONICAL_MUTATION_DEFINITIONS) == ()
    assert definitions["agent.register"].action == CONTROL_PLANE_AGENT_CREATE_ACTION
    assert definitions["agent.register"].permission == Permission.AGENT_REGISTER.value
    assert definitions["approval.vote"].action == CONTROL_PLANE_APPROVAL_VOTE_ACTION
    assert definitions["approval.vote"].permission == Permission.APPROVAL_VOTE.value
    assert definitions["approval.resume"].action == CONTROL_PLANE_AGENT_CREATE_ACTION
    assert definitions["approval.resume"].permission == Permission.APPROVAL_RESUME.value
    assert definitions["environment-policy.publish"].action == CONTROL_PLANE_POLICY_PUBLISH_ACTION
    assert definitions["environment-policy.activate"].action == CONTROL_PLANE_POLICY_ACTIVATE_ACTION
    assert definitions["tenant-bootstrap.create"].action == TENANT_BOOTSTRAP_ACTION

    app = create_app(
        Settings(
            database_url="sqlite:///:memory:",
            audit_dir=tmp_path / "audit",
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )
    assert isinstance(app, MutationGuardedFastAPI)
    assert set(app.state.mutation_inventory_seal.definitions) == set(definitions)
    assert set(app.state.mutation_inventory_seal.route_hashes) == set(definitions)
    assert len(app.state.mutation_inventory_seal.surface_hash) == 64

    active_http_routes = {
        (method, route.path): route
        for route in app.routes
        if isinstance(route, APIRoute) and route.methods
        for method in route.methods
        if method != "HEAD"
    }
    for definition in definitions.values():
        route = active_http_routes[(definition.method, definition.path)]
        source = inspect.getsource(route.endpoint)
        assert f"request.app.state.{definition.state_key}" in source
        assert f"service.{definition.service_method}(" in source
        assert definition.operation_id in app.state.mutation_inventory_seal.route_hashes

    assert _common.P3_MUTATIONS_CP_SELECTORS == (
        "tests/integration/test_mutation_inventory_postgres.py::"
        "test_pg_agent_register_commits_one_sql_atomic_managed_mutation",
        "tests/integration/test_mutation_inventory_postgres.py::"
        "test_pg_route_app_drift_refuses_before_replacement_and_preserves_sql_counts",
        "tests/integration/test_mutation_inventory_postgres.py::"
        "test_pg_service_binding_drift_preserves_sql_counts_and_legacy_blockers",
        "tests/integration/test_mutation_inventory_postgres.py::"
        "test_pg_legacy_regex_precedence_drift_preserves_sql_counts_before_bootstrap",
    )
    assert _common.P3_MUTATIONS_ROOT_SELECTORS == (
        "tests/saas_beta/test_cross_plane_contracts.py::"
        "test_mutation_inventory_contract_locks_registry_and_actual_routing",
    )
    assert _common.EXPECTED_BOOTSTRAP_MAP["P3-MUTATIONS-002"] == "EVID+CP"


def test_approval_contract_locks_vote_and_resume_assurance(tmp_path) -> None:
    managed = {
        (route.method, route.path): route
        for route in ROUTE_CONTRACTS
        if route.execution_class is ExecutionClass.CANONICAL_MANAGED_WRITE
    }
    vote_key = ("POST", "/orgs/{org_id}/approvals/{approval_request_id}/votes")
    resume_key = ("POST", "/orgs/{org_id}/approvals/{approval_request_id}/resume")
    assert managed[vote_key].action == CONTROL_PLANE_APPROVAL_VOTE_ACTION
    assert managed[resume_key].action == CONTROL_PLANE_AGENT_CREATE_ACTION
    assert managed[vote_key].permits_persistent_effect is True
    assert managed[resume_key].permits_persistent_effect is True
    assert managed[vote_key].permits_external_effect is False
    assert managed[resume_key].permits_external_effect is False

    definitions = {
        definition.operation_id: definition for definition in CANONICAL_MUTATION_DEFINITIONS
    }
    assert definitions["approval.vote"].action == CONTROL_PLANE_APPROVAL_VOTE_ACTION
    assert definitions["approval.resume"].action == CONTROL_PLANE_AGENT_CREATE_ACTION
    assert definitions["approval.vote"].permission == Permission.APPROVAL_VOTE.value
    assert definitions["approval.resume"].permission == Permission.APPROVAL_RESUME.value

    app = create_app(
        Settings(
            database_url="sqlite:///:memory:",
            audit_dir=tmp_path / "approval-audit",
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )
    active_http_routes = {
        (method, route.path): route.endpoint
        for route in app.routes
        if isinstance(route, APIRoute) and route.methods
        for method in route.methods
        if method != "HEAD"
    }
    for key, method_name in ((vote_key, ".vote("), (resume_key, ".resume(")):
        source = inspect.getsource(active_http_routes[key])
        assert "request.app.state.approval_service" in source
        assert f"service{method_name}" in source
    assert isinstance(app.state.approval_service, ApprovalService)

    approval_source = inspect.getsource(approvals_module)
    service_source = inspect.getsource(ApprovalService)
    uow_source = inspect.getsource(ManagedMutationUnitOfWork)
    assert "ManagedMutationUnitOfWork(" in service_source
    assert "approval_chain_hash=sha256_json(receipt.approval_chain_summary)" in approval_source
    assert "CONTROL_PLANE_APPROVAL_VOTE_ACTION" in service_source
    assert "CONTROL_PLANE_AGENT_CREATE_ACTION" in approval_source
    assert "execute_with_receipt(" in uow_source
    assert "ASSURANCE_CLASS_NATIVE" in uow_source
    assert "expected_action=context.action" in uow_source
    assert "expected_project_id=context.project_id" in uow_source
    assert "expected_environment_id=context.environment_id" in uow_source

    assert _common.P3_APPROVAL_CP_SELECTORS == (
        "tests/integration/test_approval_resume_postgres.py::"
        "test_pg_escalate_creates_scoped_pending_without_agent_or_consumption",
        "tests/integration/test_approval_resume_postgres.py::"
        "test_pg_self_and_wrong_role_approval_are_non_executable",
        "tests/integration/test_approval_resume_postgres.py::"
        "test_pg_resume_before_required_vote_is_non_executable",
        "tests/integration/test_approval_resume_postgres.py::"
        "test_pg_approved_resume_executes_once_and_replay_is_stable",
        "tests/integration/test_approval_resume_postgres.py::"
        "test_pg_rejected_and_expired_requests_resume_zero_side_effects",
        "tests/integration/test_approval_resume_postgres.py::"
        "test_pg_stale_policy_trust_and_requester_resume_zero_side_effects",
        "tests/integration/test_approval_resume_postgres.py::"
        "test_pg_tampered_sealed_payload_resume_zero_side_effects",
        "tests/integration/test_approval_resume_postgres.py::"
        "test_pg_multiprocess_resume_race_authorizes_one_agent",
        "tests/integration/test_approval_resume_postgres.py::"
        "test_pg_approval_composite_constraints_reject_cross_scope_rows",
    )
    assert _common.P3_APPROVAL_GZ_SELECTORS == (
        "packages/gove-zone/tests/test_mcp_gateway_conformance.py::"
        "test_escalate_approve_resume_single_use",
        "packages/gove-zone/tests/test_mcp_gateway_conformance.py::test_cross_pending_reuse",
        "packages/gove-zone/tests/test_receipt_consumption.py::"
        "test_resume_replay_blocked_with_ledger",
        "packages/gove-zone/tests/test_receipt_consumption.py::"
        "test_concurrent_consumers_single_winner",
    )
    assert _common.P3_APPROVAL_ROOT_SELECTORS == (
        "tests/saas_beta/test_cross_plane_contracts.py::"
        "test_approval_contract_locks_vote_and_resume_assurance",
    )
    assert _common.EXPECTED_BOOTSTRAP_MAP["P3-APPROVAL-003"] == "EVID+CP+GZ"
