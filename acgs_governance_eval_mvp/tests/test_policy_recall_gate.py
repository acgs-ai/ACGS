from __future__ import annotations

from governance.gates import PolicyRecallGate
from governance.models import ActionRequest, Principal


def test_contract_action_requires_policy_citation(policy_bundle):
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


def test_contract_action_passes_with_policy_citation(policy_bundle):
    gate = PolicyRecallGate(policy_bundle)
    request = ActionRequest(
        actor=Principal(id="agent-legal-1", role="LegalOps"),
        intent="Redline supplier agreement",
        action_type="contract.redline",
        resource="contracts/supplier-123",
        inputs_hash="sha256:test",
        metadata={"policy_citations": ["CONTRACT-AUTHORITY-001"]},
    )

    result = gate.validate(request)

    assert result.allowed is True
    assert "POLICY_RECALL_OK" in result.reason_codes


def test_ontario_marketing_inducement_is_denied(policy_bundle):
    gate = PolicyRecallGate(policy_bundle)
    request = ActionRequest(
        actor=Principal(id="agent-mkt-1", role="MarketingOps"),
        intent="Publish Ontario promo page",
        action_type="marketing.publish",
        resource="public/ontario/homepage",
        inputs_hash="sha256:test",
        metadata={
            "content_flags": ["bonus_offer"],
            "policy_citations": ["MKT-PUBLICATION-TRACE-002"],
        },
    )

    result = gate.validate(request)

    assert result.allowed is False
    assert "POLICY_DENY_MATCH" in result.reason_codes
    assert "MKT-ONTARIO-NO-INDUCEMENT-001" in result.rule_ids
