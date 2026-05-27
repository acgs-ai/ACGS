from __future__ import annotations

import pytest
from governance.adapters.tools import GovernedToolAdapter
from governance.audit import ChainHashAuditStore, InMemoryAuditStore
from governance.models import ActionRequest
from governance.testing import governance_test_harness, make_request


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#5",
    severity="MEDIUM",
    issue="pr5_in_memory_audit_store",
    coverage_angle="in_memory_chain_validity_two_events",
)
def test_in_memory_chain_valid_for_two_events(roles_bundle, policy_bundle):
    store = InMemoryAuditStore()
    adapter = GovernedToolAdapter(
        roles_bundle=roles_bundle,
        policy_bundle=policy_bundle,
        audit_store=store,
    )

    first = adapter.validate(make_request(resource="contracts/a"))
    second = adapter.validate(make_request(resource="contracts/b"))

    result = store.verify_chain()
    assert first.allow is True
    assert second.allow is True
    assert second.previous_hash == first.event_hash
    assert result["valid"] is True
    assert result["checked"] == 2


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#5",
    severity="MEDIUM",
    issue="pr5_in_memory_audit_store",
    coverage_angle="in_memory_chain_tamper_detection",
)
def test_in_memory_chain_detects_tamper(roles_bundle, policy_bundle):
    store = InMemoryAuditStore()
    adapter = GovernedToolAdapter(
        roles_bundle=roles_bundle,
        policy_bundle=policy_bundle,
        audit_store=store,
    )
    adapter.validate(make_request())

    # Mutate the stored event behind the store's back; verify_chain must catch it.
    store._events[0]["allow"] = False

    assert store.verify_chain()["valid"] is False


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#5",
    severity="MEDIUM",
    issue="pr5_in_memory_audit_store",
    coverage_angle="memory_disk_event_hash_parity",
)
def test_in_memory_audit_store_produces_same_event_hash_as_disk(tmp_path, roles_bundle, policy_bundle):
    # Build one DecisionRecord without a store, then append the SAME record to
    # both backends. Identical payloads + identical previous_hash (genesis) must
    # produce identical event_hash, which is what makes the in-memory store
    # interchangeable with the disk store for chain verification logic.
    adapter = GovernedToolAdapter(
        roles_bundle=roles_bundle,
        policy_bundle=policy_bundle,
        audit_store=None,
    )
    decision = adapter.validate(make_request())

    disk_store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    mem_store = InMemoryAuditStore()

    disk_payload = disk_store.append(decision)
    mem_payload = mem_store.append(decision)

    assert disk_payload["event_hash"] == mem_payload["event_hash"]
    assert disk_payload["previous_hash"] == mem_payload["previous_hash"]
    assert disk_store.last_hash() == mem_store.last_hash()


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#5",
    severity="MEDIUM",
    issue="pr5_in_memory_audit_store",
    coverage_angle="test_harness_yields_adapter",
)
def test_governance_test_harness_yields_working_adapter():
    with governance_test_harness() as adapter:
        decision = adapter.validate(make_request())

        assert decision.allow is True
        assert decision.event_hash is not None
        assert adapter.audit_store is not None
        assert adapter.audit_store.last_hash() == decision.event_hash
        assert adapter.audit_store.verify_chain()["valid"] is True


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#5",
    severity="MEDIUM",
    issue="pr5_in_memory_audit_store",
    coverage_angle="make_request_helper_validity",
)
def test_make_request_helper_produces_valid_actionrequest_dict():
    payload = make_request()
    request = ActionRequest.from_dict(payload)

    assert request.actor.role == "LegalOps"
    assert request.action_type == "contract.redline"
    assert request.resource == "contracts/test"
    assert request.tool_input is not None
    assert request.inputs_hash != ""  # derived from tool_input by from_dict
