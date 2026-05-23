from __future__ import annotations

import json
from multiprocessing import Barrier, Process
from pathlib import Path

import pytest

from governance.audit import AuthorizationTraceIntegrityError, ChainHashAuditStore, extract_trace
from governance.models import (
    ActionRequest,
    AuthorizationTrace,
    DecisionReceiptRef,
    DecisionRecord,
    EvaluationPolicy,
    Principal,
    sha256_json,
)


def _trace(evaluation_policy: EvaluationPolicy = "access-time") -> AuthorizationTrace:
    return AuthorizationTrace(
        trace_id="trace-r5-r6",
        workflow_id="workflow-r5-r6",
        parent_workflow_id=None,
        principal_chain=(
            {
                "principal_id": "codex:gpt-5",
                "role": "implementation-agent",
                "tenant": "default",
                "delegated_at": "2026-05-22T00:00:00+00:00",
                "delegation_evidence_hash": "sha256:root-delegation",
            },
            {
                "principal_id": "codex:gpt-5-worker",
                "role": "receipt-verifier",
                "tenant": "default",
                "delegated_at": "2026-05-22T00:01:00+00:00",
                "delegation_evidence_hash": "sha256:worker-delegation",
            },
        ),
        evaluation_policy=evaluation_policy,
    )


def _decision() -> DecisionRecord:
    actor = Principal(id="codex:gpt-5", role="implementation-agent", tenant="default")
    request = ActionRequest(
        action_type="governance.receipt.verify",
        resource="workflow-r5-r6",
        actor=actor,
        intent="Verify authorization trace receipt",
        inputs_hash="sha256:trace-test",
    )
    return DecisionRecord(
        event_id="event-r5-r6",
        tenant="default",
        allow=True,
        reasons=[],
        reason_codes=[],
        rule_ids=[],
        checks=[],
        request=request,
        policy_version="policy-test/v1",
        role_version="roles-test/v1",
        decision_state="allow",
    )


def _append_decision_process(path: str, index: int, barrier: Barrier) -> None:
    store = ChainHashAuditStore(path)
    decision = DecisionRecord(
        event_id=f"event-r5-r6-{index}",
        tenant="default",
        allow=True,
        reasons=[],
        reason_codes=[],
        rule_ids=[],
        checks=[],
        request=ActionRequest(
            action_type="governance.receipt.verify",
            resource=f"workflow-r5-r6-{index}",
            actor=Principal(id="codex:gpt-5", role="implementation-agent", tenant="default"),
            intent="Verify authorization trace receipt",
            inputs_hash=f"sha256:trace-test-{index}",
        ),
        policy_version="policy-test/v1",
        role_version="roles-test/v1",
        decision_state="allow",
    )
    store.append(decision)
    barrier.wait(timeout=10)
    second = DecisionRecord(
        event_id=f"event-r5-r6-{index}-second",
        tenant="default",
        allow=True,
        reasons=[],
        reason_codes=[],
        rule_ids=[],
        checks=[],
        request=ActionRequest(
            action_type="governance.receipt.verify",
            resource=f"workflow-r5-r6-{index}-second",
            actor=Principal(id="codex:gpt-5", role="implementation-agent", tenant="default"),
            intent="Verify authorization trace receipt",
            inputs_hash=f"sha256:trace-test-{index}-second",
        ),
        policy_version="policy-test/v1",
        role_version="roles-test/v1",
        decision_state="allow",
    )
    store.append(second)


def _read_event(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8").splitlines()[0])


def _write_event(path: Path, event: dict[str, object]) -> None:
    path.write_text(json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n")


def _rehash_event(event: dict[str, object]) -> None:
    payload = dict(event)
    payload.pop("event_hash", None)
    event["event_hash"] = sha256_json(payload)


def _draft7_validator():
    """Skip schema-validation coverage when optional jsonschema is absent from the sealed package deps."""
    jsonschema = pytest.importorskip("jsonschema")
    return jsonschema.Draft7Validator


def test_trace_tamper_detected_on_disk(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    store.append(_decision(), authorization_trace=_trace())
    event = _read_event(path)
    trace_payload = dict(event["authorization_trace"])
    workflow_scope = dict(trace_payload["workflow_scope"])
    principal_chain = [dict(entry) for entry in workflow_scope["principal_chain"]]
    principal_chain[0]["principal_id"] = "different-agent"
    workflow_scope["principal_chain"] = principal_chain
    trace_payload["workflow_scope"] = workflow_scope
    event["authorization_trace"] = trace_payload
    _write_event(path, event)

    mutated_event = _read_event(path)
    with pytest.raises(AuthorizationTraceIntegrityError):
        extract_trace(mutated_event)


def test_missing_trace_hash_fails_closed(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    store.append(_decision(), authorization_trace=_trace())
    event = _read_event(path)
    trace_payload = dict(event["authorization_trace"])
    receipt = dict(trace_payload["receipt"])
    receipt["receipt_hash"] = "0" * 64
    trace_payload["receipt"] = receipt
    event["authorization_trace"] = trace_payload
    _rehash_event(event)
    _write_event(path, event)

    with pytest.raises(AuthorizationTraceIntegrityError):
        ChainHashAuditStore(path).verify_chain()


def test_mismatched_trace_principal_chain_fails_closed(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    store.append(_decision(), authorization_trace=_trace())
    event = _read_event(path)
    trace_payload = dict(event["authorization_trace"])
    workflow_scope = dict(trace_payload["workflow_scope"])
    principal_chain = [dict(entry) for entry in workflow_scope["principal_chain"]]
    principal_chain[0]["principal_id"] = "different-agent"
    workflow_scope["principal_chain"] = principal_chain
    trace_payload["workflow_scope"] = workflow_scope
    receipt = dict(trace_payload["receipt"])
    receipt["receipt_hash"] = sha256_json(
        {
            "workflow_scope": workflow_scope,
            "evaluation_policy": trace_payload["evaluation_policy"],
            "receipt": {
                "trace_id": receipt["trace_id"],
                "schema_version": receipt["schema_version"],
            },
        }
    )
    trace_payload["receipt"] = receipt
    event["authorization_trace"] = trace_payload
    _rehash_event(event)
    _write_event(path, event)

    with pytest.raises(AuthorizationTraceIntegrityError):
        ChainHashAuditStore(path).verify_chain()


def test_receipt_round_trip(tmp_path):
    path = tmp_path / "audit.jsonl"
    original = _trace()
    payload = ChainHashAuditStore(path).append(_decision(), authorization_trace=original)
    event = _read_event(path)

    receipt = DecisionReceiptRef(
        receipt_hash=sha256_json(
            {
                "audit_event_hash": payload["event_hash"],
                "trace_id": original.trace_id,
                "principal_chain": [entry["principal_id"] for entry in original.principal_chain],
            }
        ),
        audit_event_hash=str(payload["event_hash"]),
        trace_id=original.trace_id,
    )

    assert DecisionReceiptRef.from_dict(receipt.to_dict()) == receipt
    assert extract_trace(event) == original


@pytest.mark.parametrize("evaluation_policy", ["initiation-time", "access-time", "completion-time"])
def test_evaluation_policy_round_trip(tmp_path, evaluation_policy: EvaluationPolicy):
    path = tmp_path / f"audit-{evaluation_policy}.jsonl"
    trace = _trace(evaluation_policy)
    ChainHashAuditStore(path).append(_decision(), authorization_trace=trace)
    event = _read_event(path)

    assert event["authorization_trace"]["evaluation_policy"] == evaluation_policy
    assert extract_trace(event) == trace


def test_schema_fixture_validates():
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "governance/schema/authorization_trace.schema.json").read_text(encoding="utf-8"))
    fixture = json.loads((root / "tests/fixtures/authorization_trace_minimal.json").read_text(encoding="utf-8"))
    draft7_validator = _draft7_validator()

    draft7_validator.check_schema(schema)
    draft7_validator(schema).validate(fixture)
    assert AuthorizationTrace.from_dict(fixture).trace_id == "trace-2026-05-22-r5-r6"


def test_authorization_trace_to_dict_validates_against_schema():
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "governance/schema/authorization_trace.schema.json").read_text(encoding="utf-8"))
    draft7_validator = _draft7_validator()

    draft7_validator.check_schema(schema)
    draft7_validator(schema).validate(_trace().to_dict())


def test_authorization_trace_round_trip_from_to_dict():
    trace = _trace()

    assert AuthorizationTrace.from_dict(trace.to_dict()) == trace


def test_multiprocess_concurrent_appends_preserve_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    barrier = Barrier(4)
    processes = [Process(target=_append_decision_process, args=(str(path), i, barrier)) for i in range(4)]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)

    assert all(process.exitcode == 0 for process in processes)

    verification = ChainHashAuditStore(path).verify_chain()
    assert verification["valid"] is True, verification["failures"]
    assert verification["checked"] == 8
    previous_hashes = [event["previous_hash"] for event in ChainHashAuditStore(path).iter_events()]
    assert len(previous_hashes) == len(set(previous_hashes))
