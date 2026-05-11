from __future__ import annotations

import pytest
from governance.adapters.tools import GovernedToolAdapter
from governance.audit import ChainHashAuditStore
from governance.replay import replay_event


def test_adapter_denies_without_policy_citation(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)

    decision = adapter.validate(
        {
            "actor": {"id": "agent-legal-1", "role": "LegalOps"},
            "intent": "Redline supplier agreement",
            "action_type": "contract.redline",
            "resource": "contracts/supplier-123",
            "inputs_hash": "sha256:test",
            "metadata": {},
        }
    )

    assert decision.allow is False
    assert "POLICY_CITATION_MISSING" in decision.reason_codes


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#4",
    severity="MEDIUM",
    issue="pr4_replay_same_versions_invariant",
    coverage_angle="replay_same_versions_byte_identical",
)
def test_replay_same_versions_matches(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)

    decision = adapter.validate(
        {
            "actor": {"id": "agent-legal-1", "role": "LegalOps"},
            "intent": "Redline supplier agreement",
            "action_type": "contract.redline",
            "resource": "contracts/supplier-123",
            "inputs_hash": "sha256:test",
            "metadata": {"policy_citations": ["CONTRACT-AUTHORITY-001"]},
        }
    )

    stored_event = store.query(event_id=decision.event_id, limit=1)[0]
    result = replay_event(stored_event, roles_bundle=roles_bundle, policy_bundle=policy_bundle)

    assert result["same_allow"] is True
    assert result["same_reason_codes"] is True


@pytest.mark.regression(
    pr="codex-investigate (no upstream PR)",
    severity="HIGH",
    issue="codex_no_audit_guard",
    coverage_angle="guard_refuses_no_audit_store",
)
def test_guard_refuses_when_audit_store_missing(roles_bundle, policy_bundle):
    adapter = GovernedToolAdapter(
        roles_bundle=roles_bundle,
        policy_bundle=policy_bundle,
        audit_store=None,
    )
    side_effect_called = False

    def side_effect():
        nonlocal side_effect_called
        side_effect_called = True
        return "executed"

    payload = {
        "actor": {"id": "agent-legal-1", "role": "LegalOps"},
        "intent": "Redline supplier agreement",
        "action_type": "contract.redline",
        "resource": "contracts/supplier-123",
        "inputs_hash": "sha256:test",
        "metadata": {"policy_citations": ["CONTRACT-AUTHORITY-001"]},
    }

    raised: RuntimeError | None = None
    try:
        adapter.guard(payload, side_effect)
    except RuntimeError as exc:
        raised = exc

    assert raised is not None
    assert "audit_store" in str(raised)
    assert side_effect_called is False
