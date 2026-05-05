from __future__ import annotations

import pytest

from governance.gates import AuthorityGate
from governance.models import ActionRequest, Principal


def test_legalops_can_redline_contract_scope(roles_bundle):
    gate = AuthorityGate(roles_bundle)
    request = ActionRequest(
        actor=Principal(id="agent-legal-1", role="LegalOps"),
        intent="Redline supplier agreement",
        action_type="contract.redline",
        resource="contracts/supplier-123",
        inputs_hash="sha256:test",
    )

    result = gate.validate(request)

    assert result.allowed is True
    assert "AUTH_ALLOWED" in result.reason_codes


def test_marketingops_cannot_approve_contract(roles_bundle):
    gate = AuthorityGate(roles_bundle)
    request = ActionRequest(
        actor=Principal(id="agent-mkt-1", role="MarketingOps"),
        intent="Approve supplier agreement",
        action_type="contract.approve",
        resource="contracts/supplier-123",
        inputs_hash="sha256:test",
    )

    result = gate.validate(request)

    assert result.allowed is False
    assert "AUTH_ACTION_DENIED" in result.reason_codes


@pytest.mark.regression(
    pr="codex-investigate (no upstream PR)",
    severity="HIGH",
    issue="codex_tenant_spoof",
    coverage_angle="actor_cannot_spoof_request_tenant",
)
def test_actor_cannot_spoof_request_tenant(roles_bundle):
    gate = AuthorityGate(roles_bundle)
    request = ActionRequest(
        actor=Principal(id="agent-legal-1", role="LegalOps", tenant="acme"),
        intent="Redline supplier agreement",
        action_type="contract.redline",
        resource="contracts/supplier-123",
        inputs_hash="sha256:test",
        tenant="globex",
    )

    result = gate.validate(request)

    assert result.allowed is False
    assert "AUTH_TENANT_MISMATCH" in result.reason_codes
    assert result.evidence["actor_tenant"] == "acme"
    assert result.evidence["request_tenant"] == "globex"


def test_cross_tenant_delegation_metadata_permits_mismatch(roles_bundle):
    gate = AuthorityGate(roles_bundle)
    request = ActionRequest(
        actor=Principal(id="agent-legal-1", role="LegalOps", tenant="acme"),
        intent="Redline supplier agreement",
        action_type="contract.redline",
        resource="contracts/supplier-123",
        inputs_hash="sha256:test",
        tenant="globex",
        metadata={"cross_tenant_delegation": True},
    )

    result = gate.validate(request)

    assert result.allowed is True
    assert "AUTH_ALLOWED" in result.reason_codes


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_fnmatch_path_traversal",
    coverage_angle="scope_rejects_traversal",
)
def test_scope_rejects_path_traversal(roles_bundle):
    gate = AuthorityGate(roles_bundle)
    request = ActionRequest(
        actor=Principal(id="agent-legal-1", role="LegalOps"),
        intent="Redline supplier agreement",
        action_type="contract.redline",
        resource="contracts/../../etc/passwd",
        inputs_hash="sha256:test",
    )

    result = gate.validate(request)

    assert result.allowed is False
    assert "AUTH_RESOURCE_INVALID" in result.reason_codes


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_fnmatch_path_traversal",
    coverage_angle="scope_rejects_double_dot",
)
def test_scope_rejects_double_dot_segment(roles_bundle):
    gate = AuthorityGate(roles_bundle)
    request = ActionRequest(
        actor=Principal(id="agent-legal-1", role="LegalOps"),
        intent="Redline supplier agreement",
        action_type="contract.redline",
        resource="contracts/../supplier-456",
        inputs_hash="sha256:test",
    )

    result = gate.validate(request)

    assert result.allowed is False
    assert "AUTH_RESOURCE_INVALID" in result.reason_codes


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_fnmatch_path_traversal",
    coverage_angle="scope_rejects_absolute",
)
def test_scope_rejects_absolute_path(roles_bundle):
    gate = AuthorityGate(roles_bundle)
    request = ActionRequest(
        actor=Principal(id="agent-legal-1", role="LegalOps"),
        intent="Redline supplier agreement",
        action_type="contract.redline",
        resource="/etc/passwd",
        inputs_hash="sha256:test",
    )

    result = gate.validate(request)

    assert result.allowed is False
    assert "AUTH_RESOURCE_INVALID" in result.reason_codes


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_fnmatch_path_traversal",
    coverage_angle="normal_scope_positive_case",
)
def test_normal_scope_still_works(roles_bundle):
    gate = AuthorityGate(roles_bundle)
    request = ActionRequest(
        actor=Principal(id="agent-legal-1", role="LegalOps"),
        intent="Redline supplier agreement",
        action_type="contract.redline",
        resource="contracts/supplier-123",
        inputs_hash="sha256:test",
    )

    result = gate.validate(request)

    assert result.allowed is True
    assert "AUTH_ALLOWED" in result.reason_codes
