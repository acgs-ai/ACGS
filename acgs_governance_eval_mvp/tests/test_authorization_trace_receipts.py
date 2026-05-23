from __future__ import annotations

import inspect
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
    LegacyUnsignedTraceError,
    Principal,
    sha256_json,
)

from _phase2_helpers import HopSpec, MintedTrace, mint_signed_trace


def _minted(tmp_path: Path, evaluation_policy: EvaluationPolicy = "access-time") -> MintedTrace:
    return mint_signed_trace(
        tmp_path,
        evaluation_policy=evaluation_policy,
        hops=[
            HopSpec(principal_id="codex:gpt-5", role="implementation-agent"),
            HopSpec(principal_id="codex:gpt-5-worker", role="receipt-verifier"),
        ],
    )


def _trace(tmp_path: Path, evaluation_policy: EvaluationPolicy = "access-time") -> AuthorizationTrace:
    return _minted(tmp_path, evaluation_policy).trace


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
    trace = _trace(tmp_path)
    store.append(_decision(), authorization_trace=trace)
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


def test_extract_trace_integrity_failure_is_handled_by_caller(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    store.append(_decision(), authorization_trace=_trace(tmp_path))
    event = _read_event(path)
    trace_payload = dict(event["authorization_trace"])
    receipt = dict(trace_payload["receipt"])
    receipt["trace_hash"] = "0" * 64
    trace_payload["receipt"] = receipt
    event["authorization_trace"] = trace_payload

    with pytest.raises(AuthorizationTraceIntegrityError):
        extract_trace(event)

    try:
        extract_trace(event)
    except AuthorizationTraceIntegrityError:
        handled = True
    else:
        handled = False

    assert handled is True


def test_extract_trace_has_single_integrity_behavior():
    assert "strict" not in inspect.signature(extract_trace).parameters


def test_missing_trace_hash_fails_closed(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    store.append(_decision(), authorization_trace=_trace(tmp_path))
    event = _read_event(path)
    trace_payload = dict(event["authorization_trace"])
    receipt = dict(trace_payload["receipt"])
    receipt.pop("trace_hash")
    trace_payload["receipt"] = receipt
    event["authorization_trace"] = trace_payload
    _rehash_event(event)
    _write_event(path, event)

    with pytest.raises(AuthorizationTraceIntegrityError):
        ChainHashAuditStore(path).verify_chain()


def test_mismatched_trace_principal_chain_fails_closed(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    trace = _trace(tmp_path)
    store.append(_decision(), authorization_trace=trace)
    event = _read_event(path)
    trace_payload = dict(event["authorization_trace"])
    workflow_scope = dict(trace_payload["workflow_scope"])
    principal_chain = [dict(entry) for entry in workflow_scope["principal_chain"]]
    principal_chain[0]["principal_id"] = "different-agent"
    workflow_scope["principal_chain"] = principal_chain
    receipt = dict(trace_payload["receipt"])
    receipt["trace_hash"] = sha256_json(
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
    original = _trace(tmp_path)
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


def test_authorization_trace_from_valid_nested_wire_payload_passes(tmp_path):
    minted = _minted(tmp_path)
    payload = minted.trace.to_dict()

    assert AuthorizationTrace.from_dict(payload) == minted.trace


def test_authorization_trace_missing_trace_hash_raises(tmp_path):
    payload = _trace(tmp_path).to_dict()
    receipt = dict(payload["receipt"])
    receipt.pop("trace_hash")
    payload["receipt"] = receipt

    with pytest.raises(AuthorizationTraceIntegrityError):
        AuthorizationTrace.from_dict(payload)


def test_authorization_trace_wrong_trace_hash_raises(tmp_path):
    payload = _trace(tmp_path).to_dict()
    receipt = dict(payload["receipt"])
    receipt["trace_hash"] = "0" * 64
    payload["receipt"] = receipt

    with pytest.raises(AuthorizationTraceIntegrityError):
        AuthorizationTrace.from_dict(payload)


def test_authorization_trace_legacy_flat_shape_raises_value_error(tmp_path):
    trace = _trace(tmp_path)
    payload = {
        "trace_id": trace.trace_id,
        "workflow_id": trace.workflow_id,
        "parent_workflow_id": None,
        "principal_chain": list(trace.principal_chain),
        "evaluation_policy": "access-time",
        "schema_version": "v1",
        "trace_hash": trace.trace_hash(),
    }

    with pytest.raises(ValueError):
        AuthorizationTrace.from_dict(payload)


def test_legacy_unsigned_trace_payload_raises(tmp_path):
    """Phase 1 unsigned wire payload (no signatures, no action_binding,
    no hop_signatures_version) is rejected with LegacyUnsignedTraceError."""
    legacy_payload = {
        "workflow_scope": {
            "workflow_id": "workflow-legacy",
            "parent_workflow_id": None,
            "principal_chain": [
                {
                    "principal_id": "codex:gpt-5",
                    "role": "implementation-agent",
                    "tenant": "default",
                    "delegated_at": "2026-05-22T00:00:00+00:00",
                    "delegation_evidence_hash": "sha256:root-delegation",
                }
            ],
        },
        "evaluation_policy": "access-time",
        "receipt": {
            "trace_hash": "0" * 64,
            "audit_event_hash": "0" * 64,
            "trace_id": "trace-legacy",
            "schema_version": "v1",
        },
    }

    with pytest.raises(LegacyUnsignedTraceError):
        AuthorizationTrace.from_dict(legacy_payload)


@pytest.mark.parametrize("evaluation_policy", ["initiation-time", "access-time", "completion-time"])
def test_evaluation_policy_round_trip(tmp_path, evaluation_policy: EvaluationPolicy):
    path = tmp_path / f"audit-{evaluation_policy}.jsonl"
    trace = _trace(tmp_path, evaluation_policy)
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


def test_authorization_trace_to_dict_validates_against_schema(tmp_path):
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "governance/schema/authorization_trace.schema.json").read_text(encoding="utf-8"))
    draft7_validator = _draft7_validator()

    draft7_validator.check_schema(schema)
    draft7_validator(schema).validate(_trace(tmp_path).to_dict())


def test_authorization_trace_round_trip_from_to_dict(tmp_path):
    trace = _trace(tmp_path)

    assert AuthorizationTrace.from_dict(trace.to_dict()) == trace


def _append_loop_process(path: str, index: int, count: int, barrier: Barrier) -> None:
    store = ChainHashAuditStore(path)
    barrier.wait(timeout=10)
    for i in range(count):
        decision = DecisionRecord(
            event_id=f"event-loop-{index}-{i}",
            tenant="default",
            allow=True,
            reasons=[],
            reason_codes=[],
            rule_ids=[],
            checks=[],
            request=ActionRequest(
                action_type="governance.receipt.verify",
                resource=f"workflow-loop-{index}-{i}",
                actor=Principal(id="codex:gpt-5", role="implementation-agent", tenant="default"),
                intent="Verify authorization trace receipt",
                inputs_hash=f"sha256:trace-loop-{index}-{i}",
            ),
            policy_version="policy-test/v1",
            role_version="roles-test/v1",
            decision_state="allow",
        )
        store.append(decision)


def _verify_loop_process(path: str, iterations: int, barrier: Barrier, result_path: str) -> None:
    store = ChainHashAuditStore(path)
    barrier.wait(timeout=10)
    errors: list[str] = []
    for _ in range(iterations):
        try:
            store.verify_chain()
        except Exception as exc:  # noqa: BLE001 - record any read-side crash
            errors.append(f"{type(exc).__name__}: {exc}")
            break
    Path(result_path).write_text(json.dumps(errors), encoding="utf-8")


def test_verify_chain_safe_during_concurrent_appends(tmp_path):
    path = tmp_path / "audit.jsonl"
    result_paths = [tmp_path / f"verify-{i}.json" for i in range(2)]
    barrier = Barrier(4)

    writers = [Process(target=_append_loop_process, args=(str(path), i, 20, barrier)) for i in range(2)]
    verifiers = [
        Process(
            target=_verify_loop_process,
            args=(str(path), 40, barrier, str(result_paths[i])),
        )
        for i in range(2)
    ]

    for proc in writers + verifiers:
        proc.start()
    for proc in writers + verifiers:
        proc.join(timeout=20)

    assert all(proc.exitcode == 0 for proc in writers + verifiers)
    for result_path in result_paths:
        assert json.loads(result_path.read_text(encoding="utf-8")) == []

    final = ChainHashAuditStore(path).verify_chain()
    assert final["valid"] is True, final["failures"]
    assert final["checked"] == 40


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
