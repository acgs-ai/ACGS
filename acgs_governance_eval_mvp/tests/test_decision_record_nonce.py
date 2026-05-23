"""DecisionRecord.nonce_consumed embedded-tombstone field.

Phase 2 §nonce-store contract: the durable tombstone is embedded
inside the authorized DecisionRecord, not a separate audit event.
See docs/design/phase2-trace-crypto.md.

This file covers shape + event_hash coverage; the audit-chain
verifier flow (truncation detection, replay detection) is the next
commit's scope.
"""

from __future__ import annotations

from governance.audit import ChainHashAuditStore
from governance.models import (
    ActionRequest,
    DecisionRecord,
    Principal,
    sha256_json,
)


def _decision(*, nonce_consumed: dict[str, str] | None = None) -> DecisionRecord:
    actor = Principal(id="codex:gpt-5", role="implementation-agent", tenant="default")
    request = ActionRequest(
        action_type="governance.receipt.verify",
        resource="workflow-nonce",
        actor=actor,
        intent="verify nonce-consumed embedding",
        inputs_hash="sha256:trace-test",
    )
    return DecisionRecord(
        event_id="event-nonce-1",
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
        nonce_consumed=nonce_consumed,
    )


def test_nonce_consumed_defaults_to_none_and_is_omitted():
    decision = _decision()
    payload = decision.to_dict()
    assert decision.nonce_consumed is None
    assert "nonce_consumed" not in payload


def test_nonce_consumed_appears_in_to_dict_when_set():
    nonce = {"trace_id": "trace-1", "session_nonce": "AAAAAAAAAAAAAAAAAAAAAA"}
    decision = _decision(nonce_consumed=nonce)
    payload = decision.to_dict()
    assert payload["nonce_consumed"] == nonce


def test_nonce_consumed_changes_event_hash_when_set(tmp_path):
    """If nonce_consumed is part of the canonical payload, two events
    with different nonces must produce different audit event hashes."""
    nonce_a = {"trace_id": "trace-a", "session_nonce": "AAAAAAAAAAAAAAAAAAAAAA"}
    nonce_b = {"trace_id": "trace-b", "session_nonce": "BBBBBBBBBBBBBBBBBBBBBB"}

    hash_a = sha256_json({**_decision(nonce_consumed=nonce_a).to_dict(), "previous_hash": "0" * 64})
    hash_b = sha256_json({**_decision(nonce_consumed=nonce_b).to_dict(), "previous_hash": "0" * 64})
    hash_none = sha256_json({**_decision().to_dict(), "previous_hash": "0" * 64})

    assert hash_a != hash_b
    assert hash_a != hash_none
    assert hash_b != hash_none


def test_nonce_consumed_survives_audit_chain_append(tmp_path):
    """Append a DecisionRecord with nonce_consumed; the on-disk event
    must contain the field and the chain hash must verify."""
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    nonce = {"trace_id": "trace-1", "session_nonce": "AAAAAAAAAAAAAAAAAAAAAA"}
    appended = store.append(_decision(nonce_consumed=nonce))

    assert appended["nonce_consumed"] == nonce
    result = store.verify_chain()
    assert result["valid"], result["failures"]


def test_nonce_consumed_tamper_breaks_event_hash(tmp_path):
    """If the on-disk nonce_consumed is mutated post-append, verify_chain
    must report the event_hash mismatch (durable tombstone integrity)."""
    import json

    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    nonce = {"trace_id": "trace-1", "session_nonce": "AAAAAAAAAAAAAAAAAAAAAA"}
    store.append(_decision(nonce_consumed=nonce))

    line = path.read_text(encoding="utf-8").splitlines()[0]
    event = json.loads(line)
    event["nonce_consumed"] = {"trace_id": "trace-2", "session_nonce": "ZZZZZZZZZZZZZZZZZZZZZZ"}
    path.write_text(
        json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    result = ChainHashAuditStore(path).verify_chain()
    assert not result["valid"]
    assert any(f["type"] == "event_hash_mismatch" for f in result["failures"])
