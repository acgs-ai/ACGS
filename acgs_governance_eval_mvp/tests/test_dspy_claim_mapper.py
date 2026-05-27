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


# ---------------------------------------------------------------------------
# governance_wrapper.py — secret scrubbing in engine error messages
# ---------------------------------------------------------------------------


def _make_error_mapper(exc: Exception) -> EvidenceToClaimMapper:
    store = InMemoryAuditStore()
    return EvidenceToClaimMapper(
        program_record=active_program(),
        engine=CountingEngine(exc=exc),
        audit_store=store,
    )


@pytest.mark.parametrize(
    "secret_fragment,expected_redacted",
    [
        ("sk-abc123XYZ", "sk-<redacted>"),
        ("Bearer supersecrettoken", "Bearer <redacted>"),
        ("password=hunter2", "password=<redacted>"),
        ("api_key=MY_SECRET_KEY", "api_key=<redacted>"),
        ("token=eyJhbGciOiJSUzI1NiJ9", "token=<redacted>"),
    ],
)
def test_engine_error_secret_patterns_are_redacted(secret_fragment, expected_redacted):
    store = InMemoryAuditStore()
    engine = CountingEngine(exc=RuntimeError(secret_fragment))
    mapper = EvidenceToClaimMapper(
        program_record=active_program(),
        engine=engine,
        audit_store=store,
    )

    entry = mapper.map_claim(
        tenant="tenant-a",
        claim_text="Secret in error message should be scrubbed.",
        audit_event_ids=[],
        evidence_refs=[],
        calling_maci_role="claim_reviewer",
    )

    assert entry.invocation.engine_error_msg is not None
    assert expected_redacted in entry.invocation.engine_error_msg
    # The raw secret must not appear in the stored error message.
    raw_secret = secret_fragment.split("=", 1)[-1].split(" ", 1)[-1]
    assert raw_secret not in entry.invocation.engine_error_msg


# ---------------------------------------------------------------------------
# program_registry.py — retire()
# ---------------------------------------------------------------------------


def test_registry_retire_marks_record_retired_and_removes_active():
    store = InMemoryAuditStore()
    registry = DSPyProgramRegistry(store)
    registry.register(draft_program("v1"))
    registry.promote("evidence-to-claim", "v1", eval_report_hash="eval-v1")

    registry.retire("evidence-to-claim", "v1")

    records = {r.version: r for r in registry.list_programs("evidence-to-claim")}
    assert records["v1"].status == "retired"
    assert registry.get_active("evidence-to-claim") is None


def test_registry_retire_appends_audit_event():
    store = InMemoryAuditStore()
    registry = DSPyProgramRegistry(store)
    registry.register(draft_program("v1"))
    registry.promote("evidence-to-claim", "v1", eval_report_hash="eval-v1")
    events_before = len(list(store.iter_events()))

    registry.retire("evidence-to-claim", "v1")

    assert len(list(store.iter_events())) == events_before + 1


def test_registry_retire_unknown_version_raises():
    store = InMemoryAuditStore()
    registry = DSPyProgramRegistry(store)

    with pytest.raises(ValueError, match="unknown DSPy program"):
        registry.retire("evidence-to-claim", "v99")


# ---------------------------------------------------------------------------
# program_registry.py — register() error paths
# ---------------------------------------------------------------------------


def test_registry_register_duplicate_raises():
    store = InMemoryAuditStore()
    registry = DSPyProgramRegistry(store)
    registry.register(draft_program("v1"))

    with pytest.raises(ValueError, match="duplicate"):
        registry.register(draft_program("v1"))


def test_registry_register_active_status_raises():
    store = InMemoryAuditStore()
    registry = DSPyProgramRegistry(store)
    active = DSPyProgramRecord(
        program_id="evidence-to-claim",
        version="v1",
        signature_hash="sig-v1",
        weights_hash="weights-v1",
        maci_role=EvidenceToClaimMapper.MACI_ROLE,
        status="active",
    )

    with pytest.raises(ValueError, match="promote"):
        registry.register(active)


# ---------------------------------------------------------------------------
# program_registry.py — promote() error paths
# ---------------------------------------------------------------------------


def test_registry_promote_empty_eval_report_hash_raises():
    store = InMemoryAuditStore()
    registry = DSPyProgramRegistry(store)
    registry.register(draft_program("v1"))

    with pytest.raises(ValueError, match="eval_report_hash"):
        registry.promote("evidence-to-claim", "v1", eval_report_hash="")


def test_registry_promote_unknown_program_raises():
    store = InMemoryAuditStore()
    registry = DSPyProgramRegistry(store)

    with pytest.raises(ValueError, match="unknown DSPy program"):
        registry.promote("evidence-to-claim", "v99", eval_report_hash="eval-v99")


# ---------------------------------------------------------------------------
# program_registry.py — rollback() never-promoted rejection
# ---------------------------------------------------------------------------


def test_registry_rollback_never_promoted_raises():
    store = InMemoryAuditStore()
    registry = DSPyProgramRegistry(store)
    registry.register(draft_program("v1"))
    registry.register(draft_program("v2"))
    registry.promote("evidence-to-claim", "v1", eval_report_hash="eval-v1")
    # v2 was registered but never promoted — rollback must refuse it.

    with pytest.raises(ValueError, match="never-promoted"):
        registry.rollback("evidence-to-claim", to_version="v2")


# ---------------------------------------------------------------------------
# program_registry.py — get_active() returns None when no active version
# ---------------------------------------------------------------------------


def test_registry_get_active_returns_none_when_no_active():
    store = InMemoryAuditStore()
    registry = DSPyProgramRegistry(store)
    registry.register(draft_program("v1"))

    assert registry.get_active("evidence-to-claim") is None


def test_registry_get_active_returns_none_for_unknown_program():
    store = InMemoryAuditStore()
    registry = DSPyProgramRegistry(store)

    assert registry.get_active("completely-unknown") is None


# ---------------------------------------------------------------------------
# program_registry.py — list_programs() with no filter returns all programs
# ---------------------------------------------------------------------------


def test_registry_list_programs_no_filter_returns_all():
    store = InMemoryAuditStore()
    registry = DSPyProgramRegistry(store)
    p1 = DSPyProgramRecord(
        program_id="prog-a",
        version="v1",
        signature_hash="s",
        weights_hash="w",
        maci_role="mapper",
    )
    p2 = DSPyProgramRecord(
        program_id="prog-b",
        version="v1",
        signature_hash="s",
        weights_hash="w",
        maci_role="mapper",
    )
    registry.register(p1)
    registry.register(p2)

    all_programs = registry.list_programs()

    program_ids = {r.program_id for r in all_programs}
    assert "prog-a" in program_ids
    assert "prog-b" in program_ids
    assert len(all_programs) == 2


# ---------------------------------------------------------------------------
# claim_mapper.py — _integrity_failed top-level event field (not nested in metadata)
# ---------------------------------------------------------------------------


def test_integrity_fail_detected_via_top_level_event_field():
    """integrity_status on the event dict itself (not nested under request.metadata)
    must still trigger the invalidated verdict."""
    store = InMemoryAuditStore()
    # Append a legitimate event, then surgically add top-level integrity_status=fail.
    stored = append_evidence_event(store, integrity_status="pass")
    # Find and mutate the stored event to set top-level integrity_status.
    for ev in store._events:
        if ev.get("event_id") == stored["event_id"]:
            ev["integrity_status"] = "fail"
            # Clear the metadata path so only the top-level branch fires.
            ev.get("request", {}).get("metadata", {}).pop("integrity_status", None)
            break

    entry = mapper_with(store, CountingEngine()).map_claim(
        tenant="tenant-a",
        claim_text="Top-level integrity_status fail must invalidate.",
        audit_event_ids=[stored["event_id"]],
        evidence_refs=["audit:event"],
        calling_maci_role="claim_reviewer",
    )

    assert entry.verdict == "invalidated"


# ---------------------------------------------------------------------------
# governance_wrapper.py — pre_validate and post_validate hooks
# ---------------------------------------------------------------------------


def test_governed_module_pre_validate_called_and_can_abort():
    from governance.dspy.governance_wrapper import GovernedDSPyModule

    engine = CountingEngine()
    record = active_program()

    def pre_validate(inputs: dict) -> None:
        raise ValueError("pre_validate rejected inputs")

    module = GovernedDSPyModule(
        program_record=record,
        engine=engine,
        maci_role="claim_reviewer",
        pre_validate=pre_validate,
    )

    with pytest.raises(ValueError, match="pre_validate rejected"):
        module.invoke({"some": "input"}, calling_maci_role="other_role")

    assert engine.call_count == 0


def test_governed_module_post_validate_called_after_successful_engine():
    from governance.dspy.governance_wrapper import GovernedDSPyModule

    post_calls: list[tuple] = []

    def post_validate(inputs: dict, outputs: dict) -> None:
        post_calls.append((inputs, outputs))

    record = active_program()
    raw_output = {
        "verdict": "supported",
        "evidence_refs": [],
        "missing_evidence": [],
        "scope_boundary": "audit_events",
        "safer_claim_text": None,
    }
    engine = CountingEngine(output=raw_output)

    module = GovernedDSPyModule(
        program_record=record,
        engine=engine,
        maci_role="claim_reviewer",
        post_validate=post_validate,
    )

    outputs, evidence = module.invoke({"input": "data"}, calling_maci_role="other_role")

    assert len(post_calls) == 1
    assert post_calls[0][1] == raw_output
    assert evidence.engine_error_msg is None


def test_governed_module_post_validate_skipped_on_engine_error():
    from governance.dspy.governance_wrapper import GovernedDSPyModule

    post_calls: list = []

    def post_validate(inputs: dict, outputs: dict) -> None:
        post_calls.append(outputs)

    record = active_program()
    engine = CountingEngine(exc=RuntimeError("boom"))

    module = GovernedDSPyModule(
        program_record=record,
        engine=engine,
        maci_role="claim_reviewer",
        post_validate=post_validate,
    )

    outputs, evidence = module.invoke({"input": "data"}, calling_maci_role="other_role")

    assert outputs is None
    assert evidence.engine_error_msg is not None
    assert post_calls == []  # post_validate must NOT be called when engine raised
