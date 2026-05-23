from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

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


def _read_event(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8").splitlines()[0])


def _write_event(path: Path, event: dict[str, object]) -> None:
    path.write_text(json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n")


def _rehash_event(event: dict[str, object]) -> None:
    payload = dict(event)
    payload.pop("event_hash", None)
    event["event_hash"] = sha256_json(payload)


def test_trace_is_anchored_in_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    payload = store.append(_decision(), authorization_trace=_trace())

    trace_payload = dict(payload["authorization_trace"])
    trace_payload["evaluation_policy"] = "completion-time"
    mutated = dict(payload)
    mutated["authorization_trace"] = trace_payload
    mutated.pop("event_hash", None)

    assert sha256_json(mutated) != payload["event_hash"]
    assert store.verify_chain()["valid"] is True


def test_missing_trace_hash_fails_closed(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    store.append(_decision(), authorization_trace=_trace())
    event = _read_event(path)
    trace_payload = dict(event["authorization_trace"])
    trace_payload["trace_hash"] = "0" * 64
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
    principal_chain = [dict(entry) for entry in trace_payload["principal_chain"]]
    principal_chain[0]["principal_id"] = "different-agent"
    trace_payload["principal_chain"] = principal_chain
    trace_payload["trace_hash"] = sha256_json(
        {key: value for key, value in trace_payload.items() if key != "trace_hash"}
    )
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

    Draft7Validator.check_schema(schema)
    Draft7Validator(schema).validate(fixture)
