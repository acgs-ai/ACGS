from __future__ import annotations

import importlib
import sys

import pytest

from governance.audit import InMemoryAuditStore
from governance.dspy import (
    DSPyProgramRecord,
    DSPyProgramRegistry,
    EvidenceToClaimMapper,
)
from governance.dspy.governance_wrapper import (
    DSPyProgramInactiveError,
    MACIRoleViolation,
)
from governance.models import ActionRequest, DecisionRecord, Principal, sha256_json
from governance.replay import replay_event


class CountingEngine:
    def __init__(self, output=None, exc: Exception | None = None):
        self.output = output or {
            "verdict": "supported",
            "evidence_refs": ["audit:event"],
            "missing_evidence": [],
            "scope_boundary": "audit_events",
            "safer_claim_text": None,
        }
        self.exc = exc
        self.call_count = 0

    def __call__(self, inputs):
        self.call_count += 1
        if self.exc is not None:
            raise self.exc
        return self.output


def active_program(version: str = "v1") -> DSPyProgramRecord:
    return DSPyProgramRecord(
        program_id="evidence-to-claim",
        version=version,
        signature_hash=f"sig-{version}",
        weights_hash=f"weights-{version}",
        maci_role=EvidenceToClaimMapper.MACI_ROLE,
        status="active",
        eval_report_hash=f"eval-{version}",
    )


def draft_program(version: str) -> DSPyProgramRecord:
    return DSPyProgramRecord(
        program_id="evidence-to-claim",
        version=version,
        signature_hash=f"sig-{version}",
        weights_hash=f"weights-{version}",
        maci_role=EvidenceToClaimMapper.MACI_ROLE,
        status="draft",
    )


def append_evidence_event(
    store: InMemoryAuditStore,
    *,
    tenant: str = "tenant-a",
    integrity_status: str = "pass",
) -> dict:
    request = ActionRequest(
        action_type="contract.redline",
        resource="contracts/supplier-123",
        actor=Principal(id="agent-legal-1", role="LegalOps", tenant=tenant),
        intent="Redline supplier agreement",
        inputs_hash=sha256_json({"resource": "contracts/supplier-123"}),
        tenant=tenant,
        metadata={"integrity_status": integrity_status},
        tool_input={"resource": "contracts/supplier-123"},
    )
    decision = DecisionRecord(
        event_id=request.event_id,
        tenant=tenant,
        allow=True,
        reasons=["seed evidence"],
        reason_codes=["SEED_EVIDENCE"],
        rule_ids=[],
        checks=[],
        request=request,
        policy_version="test-policy",
        role_version="test-role",
        decision_state="allow",
        effective_tool_input=request.tool_input,
    )
    return store.append(decision)


def mapper_with(store: InMemoryAuditStore, engine: CountingEngine, program=None) -> EvidenceToClaimMapper:
    return EvidenceToClaimMapper(
        program_record=program or active_program(),
        engine=engine,
        audit_store=store,
    )


def test_supported_verdict_from_existing_evidence():
    store = InMemoryAuditStore()
    evidence = append_evidence_event(store)
    engine = CountingEngine()

    entry = mapper_with(store, engine).map_claim(
        tenant="tenant-a",
        claim_text="The contract was redlined with authority.",
        audit_event_ids=[evidence["event_id"]],
        evidence_refs=["audit:event"],
        calling_maci_role="claim_reviewer",
    )

    assert entry.verdict == "supported"
    assert entry.missing_evidence == []
    assert engine.call_count == 1


def test_invalidated_on_integrity_fail_over_supported_engine():
    store = InMemoryAuditStore()
    evidence = append_evidence_event(store, integrity_status="fail")

    entry = mapper_with(store, CountingEngine()).map_claim(
        tenant="tenant-a",
        claim_text="The integrity-failed evidence supports the claim.",
        audit_event_ids=[evidence["event_id"]],
        evidence_refs=["audit:event"],
        calling_maci_role="claim_reviewer",
    )

    assert entry.verdict == "invalidated"


def test_partial_on_missing_evidence_over_supported_engine():
    store = InMemoryAuditStore()

    entry = mapper_with(store, CountingEngine()).map_claim(
        tenant="tenant-a",
        claim_text="Missing evidence still supports the claim.",
        audit_event_ids=["missing-event"],
        evidence_refs=["audit:missing-event"],
        calling_maci_role="claim_reviewer",
    )

    assert entry.verdict == "partial"
    assert entry.missing_evidence == ["missing-event"]


def test_unknown_engine_verdict_is_undecidable():
    store = InMemoryAuditStore()
    evidence = append_evidence_event(store)
    engine = CountingEngine({"verdict": "maybe", "missing_evidence": [], "scope_boundary": "audit_events"})

    entry = mapper_with(store, engine).map_claim(
        tenant="tenant-a",
        claim_text="The engine returned an unknown verdict.",
        audit_event_ids=[evidence["event_id"]],
        evidence_refs=["audit:event"],
        calling_maci_role="claim_reviewer",
    )

    assert entry.verdict == "undecidable"


def test_maci_self_validate_blocked_before_engine_call():
    store = InMemoryAuditStore()
    engine = CountingEngine()

    with pytest.raises(MACIRoleViolation):
        mapper_with(store, engine).map_claim(
            tenant="tenant-a",
            claim_text="Self validation should be blocked.",
            audit_event_ids=[],
            evidence_refs=[],
            calling_maci_role=EvidenceToClaimMapper.MACI_ROLE,
        )

    assert engine.call_count == 0
    assert list(store.iter_events()) == []


def test_ledger_appended_once_and_chain_valid():
    store = InMemoryAuditStore()
    evidence = append_evidence_event(store)

    entry = mapper_with(store, CountingEngine()).map_claim(
        tenant="tenant-a",
        claim_text="The ledger should be persisted once.",
        audit_event_ids=[evidence["event_id"]],
        evidence_refs=["audit:event"],
        calling_maci_role="claim_reviewer",
    )

    events = list(store.iter_events())
    stored_event = events[-1]
    stored_ledger = stored_event["request"]["metadata"]["claim_ledger"]
    assert len(events) == 2
    assert stored_event["request"]["action_type"] == "dspy.claim_mapping"
    assert stored_ledger["event_hash"] is None
    assert stored_ledger["previous_hash"] is None
    assert entry.event_hash == stored_event["event_hash"]
    assert entry.previous_hash == stored_event["previous_hash"]
    assert store.verify_chain()["valid"] is True


def test_engine_error_yields_one_undecidable_audit_event():
    store = InMemoryAuditStore()
    engine = CountingEngine(exc=RuntimeError("boom"))

    entry = mapper_with(store, engine).map_claim(
        tenant="tenant-a",
        claim_text="Engine failure should be audited.",
        audit_event_ids=[],
        evidence_refs=[],
        calling_maci_role="claim_reviewer",
    )

    assert entry.verdict == "undecidable"
    assert entry.invocation.engine_error_msg is not None
    assert "boom" in entry.invocation.engine_error_msg
    assert len(list(store.iter_events())) == 1


def test_inactive_program_raises_without_ledger_entry():
    store = InMemoryAuditStore()
    engine = CountingEngine()
    program = DSPyProgramRecord(
        program_id="evidence-to-claim",
        version="retired",
        signature_hash="sig",
        weights_hash="weights",
        maci_role=EvidenceToClaimMapper.MACI_ROLE,
        status="retired",
    )

    with pytest.raises(DSPyProgramInactiveError):
        mapper_with(store, engine, program).map_claim(
            tenant="tenant-a",
            claim_text="Inactive programs cannot map claims.",
            audit_event_ids=[],
            evidence_refs=[],
            calling_maci_role="claim_reviewer",
        )

    assert engine.call_count == 0
    assert list(store.iter_events()) == []


def test_registry_promote_demotes_previous_and_writes_two_audit_events():
    store = InMemoryAuditStore()
    registry = DSPyProgramRegistry(store)
    registry.register(draft_program("v1"))
    registry.register(draft_program("v2"))

    registry.promote("evidence-to-claim", "v1", eval_report_hash="eval-v1")
    active = registry.promote("evidence-to-claim", "v2", eval_report_hash="eval-v2")

    records = {record.version: record for record in registry.list_programs("evidence-to-claim")}
    assert active.version == "v2"
    assert records["v1"].status == "retired"
    assert records["v2"].status == "active"
    assert len(list(store.iter_events())) == 2


def test_registry_rollback_writes_third_event_and_chain_valid():
    store = InMemoryAuditStore()
    registry = DSPyProgramRegistry(store)
    registry.register(draft_program("v1"))
    registry.register(draft_program("v2"))

    registry.promote("evidence-to-claim", "v1", eval_report_hash="eval-v1")
    registry.promote("evidence-to-claim", "v2", eval_report_hash="eval-v2")
    active = registry.rollback("evidence-to-claim", to_version="v1")

    assert active.version == "v1"
    assert active.status == "active"
    assert len(list(store.iter_events())) == 3
    assert store.verify_chain()["valid"] is True


def test_no_dspy_install_required_for_module_imports():
    sys.modules.pop("dspy", None)

    importlib.import_module("governance.dspy.claim_mapper")
    importlib.import_module("governance.dspy.governance_wrapper")

    assert "dspy" not in sys.modules


def test_cross_tenant_evidence_invalidated_and_tagged():
    store = InMemoryAuditStore()
    evidence = append_evidence_event(store, tenant="tenant-b")

    entry = mapper_with(store, CountingEngine()).map_claim(
        tenant="tenant-a",
        claim_text="Foreign tenant evidence cannot support this claim.",
        audit_event_ids=[evidence["event_id"]],
        evidence_refs=["audit:event"],
        calling_maci_role="claim_reviewer",
    )

    assert entry.verdict == "invalidated"
    assert f"FOREIGN_TENANT_EVIDENCE:{evidence['event_id']}" in entry.missing_evidence


def test_engine_invalidated_passes_through_without_clobbering():
    store = InMemoryAuditStore()
    evidence = append_evidence_event(store)
    engine = CountingEngine(
        {
            "verdict": "invalidated",
            "evidence_refs": ["audit:event"],
            "missing_evidence": [],
            "scope_boundary": "audit_events",
            "safer_claim_text": "Narrower claim",
        }
    )

    entry = mapper_with(store, engine).map_claim(
        tenant="tenant-a",
        claim_text="The engine may invalidate a clean-evidence claim.",
        audit_event_ids=[evidence["event_id"]],
        evidence_refs=["audit:event"],
        calling_maci_role="claim_reviewer",
    )

    assert entry.verdict == "invalidated"
    assert entry.safer_claim_text == "Narrower claim"


def test_registry_requires_audit_store():
    with pytest.raises(TypeError):
        DSPyProgramRegistry(None)  # type: ignore[arg-type]


def test_replay_skips_dspy_audit_events(roles_bundle, policy_bundle):
    event = {
        "event_id": "dspy-event-1",
        "request": {
            "action_type": "dspy.claim_mapping",
            "resource": "dspy/claims/evidence-to-claim/v1",
            "actor": {"id": "evidence-to-claim", "role": "evidence_mapper", "tenant": "tenant-a"},
            "intent": "Map evidence to claim verdict",
            "inputs_hash": "hash",
            "tenant": "tenant-a",
            "metadata": {},
        },
    }

    result = replay_event(event, roles_bundle=roles_bundle, policy_bundle=policy_bundle)

    assert result == {"event_id": "dspy-event-1", "kind": "dspy_audit_event", "skipped": True}
