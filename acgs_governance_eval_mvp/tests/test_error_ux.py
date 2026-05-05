from __future__ import annotations

import pytest

from governance.adapters.tools import GovernedToolAdapter
from governance.audit import ChainHashAuditStore
from governance.gates import AuthorityGate, PolicyRecallGate
from governance.models import (
    ActionRequest,
    DecisionRecord,
    GovernanceDeniedError,
    Principal,
)


def _payload(**overrides):
    base = {
        "actor": {"id": "agent-mkt-1", "role": "MarketingOps"},
        "intent": "Approve supplier agreement",
        "action_type": "contract.approve",
        "resource": "contracts/supplier-123",
        "inputs_hash": "sha256:test",
        "tool_input": {"contract_id": "supplier-123"},
        "metadata": {},
    }
    base.update(overrides)
    return base


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#7",
    severity="MEDIUM",
    issue="pr7_governance_denied_error",
    coverage_angle="denied_error_carries_full_decision",
)
def test_guard_raises_governance_denied_error_carrying_full_decision(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)

    with pytest.raises(GovernanceDeniedError) as excinfo:
        adapter.guard(_payload(), lambda effective: "should_not_execute")

    err = excinfo.value
    assert isinstance(err.decision, DecisionRecord)
    assert err.decision.allow is False
    assert "AUTH_ACTION_DENIED" in err.decision.reason_codes
    # str(err) is still the joined-reasons message used by today's catches.
    assert str(err) == "; ".join(err.decision.reasons)


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#7",
    severity="MEDIUM",
    issue="pr7_governance_denied_error",
    coverage_angle="denied_error_subclasses_permissionerror",
)
def test_governance_denied_error_is_subclass_of_permissionerror(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)

    raised: PermissionError | None = None
    try:
        adapter.guard(_payload(), lambda effective: "noop")
    except PermissionError as exc:
        raised = exc

    assert raised is not None
    assert isinstance(raised, GovernanceDeniedError)
    # Existing `except PermissionError` catches must still work.
    assert isinstance(raised, PermissionError)


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#7",
    severity="MEDIUM",
    issue="pr7_governance_denied_error",
    coverage_angle="authority_deny_remediation_hint",
)
def test_authority_deny_carries_remediation_hint(roles_bundle):
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
    assert result.remediation == (
        "Use a role that lists this action_type, or add it to the role's actions"
    )


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#7",
    severity="MEDIUM",
    issue="pr7_governance_denied_error",
    coverage_angle="policy_deny_remediation_hint",
)
def test_policy_deny_carries_remediation_hint(policy_bundle):
    gate = PolicyRecallGate(policy_bundle)
    request = ActionRequest(
        actor=Principal(id="agent-legal-1", role="LegalOps"),
        intent="Redline supplier agreement",
        action_type="contract.redline",
        resource="contracts/supplier-123",
        inputs_hash="sha256:test",
        metadata={},
    )

    result = gate.validate(request)

    assert result.allowed is False
    assert "POLICY_CITATION_MISSING" in result.reason_codes
    assert result.remediation == (
        "Add the missing policy id(s) (or matching obligation ids) to metadata.policy_citations"
    )
