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


def _legalops_request(resource: str) -> ActionRequest:
    return ActionRequest(
        actor=Principal(id="agent-legal-1", role="LegalOps"),
        intent="Redline supplier agreement",
        action_type="contract.redline",
        resource=resource,
        inputs_hash="sha256:test",
    )


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_fnmatch_path_traversal",
    coverage_angle="scope_rejects_url_encoded_traversal",
)
def test_scope_rejects_url_encoded_traversal(roles_bundle):
    """Percent-encoded traversal sequences must not be decoded into a literal '..'
    that bypasses the scope check. Each variant must deny."""
    gate = AuthorityGate(roles_bundle)
    encoded_variants = [
        "%2e%2e/contracts/x",
        "%2e%2e%2fcontracts%2fx",
        "secrets/%2e%2e/etc",
        "%2fetc/passwd",
    ]
    for resource in encoded_variants:
        result = gate.validate(_legalops_request(resource))
        assert result.allowed is False, (
            f"url-encoded traversal must be denied: {resource!r} got reasons={result.reason_codes}"
        )


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_fnmatch_path_traversal",
    coverage_angle="scope_rejects_nul_byte_injection",
)
def test_scope_rejects_nul_byte_injection(roles_bundle):
    """Embedded NUL bytes must not truncate the resource string in a way that
    fools fnmatch/realpath into matching a permitted prefix."""
    gate = AuthorityGate(roles_bundle)
    nul_variants = [
        "secrets\x00contracts/legit",
        "etc/passwd\x00",
        "\x00contracts/supplier-123",
        "../etc\x00/passwd",
    ]
    for resource in nul_variants:
        result = gate.validate(_legalops_request(resource))
        assert result.allowed is False, (
            f"nul-byte injection must be denied: {resource!r} got reasons={result.reason_codes}"
        )


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_fnmatch_path_traversal",
    coverage_angle="scope_rejects_backslash_traversal_on_posix",
)
def test_scope_rejects_backslash_traversal_on_posix(roles_bundle):
    """Backslash-separated traversal sequences are literal characters on POSIX
    and must not match an fnmatch scope ending in '/*'."""
    gate = AuthorityGate(roles_bundle)
    backslash_variants = [
        "contracts\\..\\secrets",
        "contracts\\..\\..\\etc\\passwd",
        "..\\contracts\\x",
    ]
    for resource in backslash_variants:
        result = gate.validate(_legalops_request(resource))
        assert result.allowed is False, (
            f"backslash traversal must be denied: {resource!r} got reasons={result.reason_codes}"
        )


@pytest.mark.regression(
    pr="fix/governance-eng-autofix",
    severity="HIGH",
    issue="autofix_fnmatch_path_traversal",
    coverage_angle="scope_rejects_unicode_dotdot_lookalike",
)
def test_scope_rejects_unicode_dotdot_lookalike(roles_bundle):
    """Unicode codepoints that look like '.' or '/' must not be NFKC-folded into
    a literal traversal that the gate would otherwise accept."""
    gate = AuthorityGate(roles_bundle)
    unicode_variants = [
        "．．/contracts/x",            # FULLWIDTH FULL STOP as traversal prefix
        "secrets∕contracts",          # DIVISION SLASH (not real '/')
        "contracts⁄supplier-123",     # FRACTION SLASH (not real '/')
        "ｃｏｎｔｒａｃｔｓ/secrets",       # FULLWIDTH letters (lookalike prefix)
    ]
    for resource in unicode_variants:
        result = gate.validate(_legalops_request(resource))
        assert result.allowed is False, (
            f"unicode lookalike traversal must be denied: {resource!r} got reasons={result.reason_codes}"
        )
