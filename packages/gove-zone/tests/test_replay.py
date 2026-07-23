"""Receipt + replay tests.

Proves the third MVP acceptance criterion: *every decision records goal,
action, tool, argument hash, policy version, matched rules, decision,
reason, timestamp, and audit hash. Receipts are replayable.*
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from gove_zone import (
    BoundaryPolicy,
    ChainHashAuditStore,
    Decision,
    Kernel,
    ToolEffect,
    find_event,
    replay_call,
    replay_event,
)
from gove_zone.authorization import (
    ExecutionReasonCode,
    ExecutionRefusalEvidence,
    ExecutionRefusalPhase,
    strict_json_hash,
)
from gove_zone.decision import DecisionRecord, RecordKind
from gove_zone.replay import execution_refusal_error, replay_from_side_store
from gove_zone.replay_store import ReplaySideStore
from gove_zone.signing import Ed25519Signer
from gove_zone.tool import ToolCall


def _kernel(tmp_path: Path) -> Kernel:
    return Kernel(
        policy=BoundaryPolicy(forbidden_keywords=["~/.ssh"]),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
    )


def test_receipt_records_every_required_field(tmp_path: Path) -> None:
    k = _kernel(tmp_path)

    @k.tool("write_file", effect=ToolEffect.PURE_READ_ONLY)
    def write_file(path: str, content: str) -> int:
        return len(content)

    _, receipt = k.dispatch("write_file", {"path": "/tmp/x", "content": "abc"})
    d = receipt.to_dict()

    # Required-by-MVP fields:
    for field in (
        "decision",
        "tool",
        "argument_hash",
        "policy_version",
        "matched_rules",
        "reason",
        "timestamp_iso",
        "audit_hash",
        "event_id",
        "goal",
    ):
        assert field in d, f"receipt missing required field: {field}"


def test_dispatch_preserves_goal_in_receipt_and_audit(tmp_path: Path) -> None:
    """The goal passed to dispatch round-trips through receipt and audit."""
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    k = Kernel(
        policy=BoundaryPolicy(forbidden_keywords=["~/.ssh"]),
        audit=audit,
    )

    @k.tool("ping", effect=ToolEffect.PURE_READ_ONLY)
    def ping() -> str:
        return "pong"

    _, receipt = k.dispatch("ping", goal="seed demo")
    assert receipt.record.goal == "seed demo"

    events = list(audit.iter_events())
    assert events[0]["goal"] == "seed demo"


def test_replay_call_matches_when_policy_unchanged(tmp_path: Path) -> None:
    """Re-evaluating the same call with the same policy reproduces the decision."""
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k = Kernel(
        policy=policy,
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
    )

    @k.tool("send", effect=ToolEffect.PURE_READ_ONLY)
    def send(body: str) -> None:
        return None

    _, receipt = k.dispatch("send", {"body": "hello"})

    replayed = replay_call(
        ToolCall(name="send", args={"body": "hello"}),
        expected_decision=Decision.ALLOW,
        policy=policy,
        expected_policy_version=receipt.record.policy_version,
    )
    assert replayed.matches is True
    assert replayed.replayed_decision is Decision.ALLOW
    assert replayed.policy_version_match is True
    assert replayed.argument_hash_match is True


def test_replay_call_diverges_when_args_change(tmp_path: Path) -> None:
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    # Replay against args that NOW trip the policy — receipt was ALLOW
    replayed = replay_call(
        ToolCall(name="send", args={"body": "now this is secret"}),
        expected_decision=Decision.ALLOW,
        policy=policy,
    )
    assert replayed.matches is False
    assert replayed.replayed_decision is Decision.DENY


def test_replay_event_uses_audit_only(tmp_path: Path) -> None:
    """When raw args are not available, replay can only confirm policy version."""
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k = Kernel(policy=policy, audit=audit)

    @k.tool("touch", effect=ToolEffect.PURE_READ_ONLY)
    def touch() -> None:
        return None

    _, receipt = k.dispatch("touch")
    event = find_event(audit, receipt.record.event_id)
    assert event is not None
    result = replay_event(event, policy)
    assert result.policy_version_match is True

    # Different policy → version mismatch
    other = BoundaryPolicy(forbidden_keywords=["different"])
    assert replay_event(event, other).policy_version_match is False


def test_find_event_returns_none_for_missing(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    assert find_event(audit, "ev_does_not_exist") is None


def _seed(tmp_path: Path, policy: BoundaryPolicy, args: dict[str, object]) -> tuple[Kernel, str]:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    side_store = ReplaySideStore(tmp_path / "replay.jsonl")
    k = Kernel(policy=policy, audit=audit, side_store=side_store)

    @k.tool("send", effect=ToolEffect.PURE_READ_ONLY)
    def send(**kwargs: object) -> None:
        return None

    try:
        _, receipt = k.dispatch("send", args)
        return k, receipt.record.event_id
    except Exception as exc:  # DeniedError carries the record
        return k, exc.record.event_id  # type: ignore[attr-defined]


def test_side_store_happy_rederivation(tmp_path: Path) -> None:
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k, event_id = _seed(tmp_path, policy, {"body": "hello"})
    event = find_event(k.audit, event_id)
    side = k.side_store.get(event_id)  # type: ignore[union-attr]
    assert event is not None and side is not None

    result = replay_from_side_store(event, side, policy)
    assert result.matches is True
    assert result.replayed_decision is Decision.ALLOW
    assert result.argument_hash_match is True
    assert result.policy_version_match is True
    assert result.event_id == event_id


def test_side_store_deny_rederivation(tmp_path: Path) -> None:
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k, event_id = _seed(tmp_path, policy, {"body": "this is secret"})
    event = find_event(k.audit, event_id)
    side = k.side_store.get(event_id)  # type: ignore[union-attr]
    assert event is not None and side is not None

    result = replay_from_side_store(event, side, policy)
    assert result.matches is True
    assert result.replayed_decision is Decision.DENY


def test_side_store_tamper_cross_check(tmp_path: Path) -> None:
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k, event_id = _seed(tmp_path, policy, {"body": "hello"})
    event = find_event(k.audit, event_id)
    side = k.side_store.get(event_id)  # type: ignore[union-attr]
    assert event is not None and side is not None

    side["args"] = {"body": "tampered"}  # corrupt the side record only
    result = replay_from_side_store(event, side, policy)
    assert result.matches is False
    assert result.argument_hash_match is False
    assert "argument_hash" in result.reason


def test_side_store_policy_version_mismatch(tmp_path: Path) -> None:
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k, event_id = _seed(tmp_path, policy, {"body": "hello"})
    event = find_event(k.audit, event_id)
    side = k.side_store.get(event_id)  # type: ignore[union-attr]
    assert event is not None and side is not None

    other = BoundaryPolicy(forbidden_keywords=["different"])
    result = replay_from_side_store(event, side, other)
    assert result.policy_version_match is False
    assert result.matches is False


def test_side_store_args_now_trip_changed_policy(tmp_path: Path) -> None:
    """A changed policy that would now DENY surfaces a non-matching re-derivation."""
    policy = BoundaryPolicy(forbidden_keywords=["never-matches"])
    k, event_id = _seed(tmp_path, policy, {"body": "danger"})
    event = find_event(k.audit, event_id)
    side = k.side_store.get(event_id)  # type: ignore[union-attr]
    assert event is not None and side is not None

    changed = BoundaryPolicy(forbidden_keywords=["danger"])
    result = replay_from_side_store(event, side, changed)
    assert result.matches is False
    assert result.replayed_decision is Decision.DENY


def test_side_store_allow_rederives_under_original_policy(tmp_path: Path) -> None:
    policy = BoundaryPolicy(forbidden_keywords=["secret"])
    k, event_id = _seed(tmp_path, policy, {"body": "safe text"})
    event = find_event(k.audit, event_id)
    side = k.side_store.get(event_id)  # type: ignore[union-attr]
    assert event is not None and side is not None

    result = replay_from_side_store(event, side, policy)
    assert result.matches is True
    assert result.replayed_decision is Decision.ALLOW


def _refusal_evidence(**changes: object) -> ExecutionRefusalEvidence:
    digest = "a" * 64
    fields: dict[str, object] = {
        "request_id_digest": digest,
        "receipt_id_digest": "b" * 64,
        "receipt_hash": "c" * 64,
        "tenant_digest": "d" * 64,
        "execution_boundary_digest": "e" * 64,
        "adapter_id_digest": "f" * 64,
        "authorization_audit_digest": "1" * 64,
        "binding_hash": "2" * 64,
        "argument_hash": "3" * 64,
        "reason_code": ExecutionReasonCode.REPLAY,
        "phase": ExecutionRefusalPhase.AUTHORIZATION_GATE,
        "audited": False,
    }
    fields.update(changes)
    return ExecutionRefusalEvidence(**fields)  # type: ignore[arg-type]


def _refusal_event(evidence: ExecutionRefusalEvidence) -> dict[str, object]:
    record = DecisionRecord(
        decision=Decision.DENY,
        tool="release.deploy",
        argument_hash=evidence.argument_hash,
        policy_version="fixture-policy/v1",
        event_id="ev_refusal_fixture",
        matched_rules=(evidence.reason_code.value,),
        reason=evidence.reason_code.value,
        actor="release-agent",
        state_hash=strict_json_hash(evidence._audit_state_dict()),
        record_kind=RecordKind.EXECUTION_REFUSAL,
        execution_evidence=evidence.audit_evidence(),
    )
    return record.to_dict()


def test_canonical_execution_refusal_record_passes_the_shared_contract() -> None:
    assert execution_refusal_error(_refusal_event(_refusal_evidence())) is None


def test_execution_refusal_contract_rejects_every_bound_field_mutation() -> None:
    baseline = _refusal_event(_refusal_evidence())

    # A refusal that claims the adapter ran is not a refusal.
    forged = dict(baseline)
    evidence = dict(baseline["execution_evidence"])  # type: ignore[arg-type]
    evidence["adapter_invoked"] = "true"
    forged["execution_evidence"] = evidence
    assert execution_refusal_error(forged) == "execution_refusal_evidence_schema_mismatch"

    # Phase, reason and every bound digest are committed by state_hash.
    for field_name, replacement in (
        ("phase", ExecutionRefusalPhase.RESERVATION.value),
        ("reason_code", ExecutionReasonCode.REVOKED.value),
        ("receipt_id_digest", "9" * 64),
        ("binding_hash", "9" * 64),
        ("authorization_audit_digest", "9" * 64),
        ("attempt_id_digest", "9" * 64),
    ):
        mutated = dict(baseline)
        evidence = dict(baseline["execution_evidence"])  # type: ignore[arg-type]
        evidence[field_name] = replacement
        mutated["execution_evidence"] = evidence
        assert execution_refusal_error(mutated) is not None, field_name

    # A refusal record may never claim an executable decision.
    allowed = dict(baseline)
    allowed["decision"] = Decision.ALLOW.value
    assert execution_refusal_error(allowed) == "execution_refusal_decision_mismatch"

    # Reason and matched_rules must agree with the evidence.
    relabelled = dict(baseline)
    relabelled["reason"] = ExecutionReasonCode.REVOKED.value
    assert execution_refusal_error(relabelled) == "execution_refusal_reason_mismatch"

    # A refusal never borrows the lifecycle attestation of a real execution.
    attested = dict(baseline)
    attested["lifecycle_attestation"] = {"authority_id": "forged"}
    assert execution_refusal_error(attested) == "execution_refusal_attestation_present"

    # The audit state hash binds the whole claim set.
    restated = dict(baseline)
    restated["state_hash"] = "0" * 64
    assert execution_refusal_error(restated) == "execution_refusal_state_hash_mismatch"


def test_execution_refusal_evidence_cannot_represent_an_invoked_adapter() -> None:
    with pytest.raises(ValueError, match="cannot claim adapter invocation"):
        _refusal_evidence(adapter_invoked=True)
    with pytest.raises(ValueError, match="does not prove the adapter was never entered"):
        _refusal_evidence(reason_code=ExecutionReasonCode.SUCCEEDED)
    with pytest.raises(ValueError, match="post-reservation"):
        _refusal_evidence(attempt_id_digest="7" * 64)


def test_from_audit_evidence_rejects_non_string_reason_code_and_phase() -> None:
    # Missing or non-string enum-selector evidence must fail closed with a clear
    # TypeError *before* enum construction — never be coerced into a rebuilt
    # refusal that a caller could round-trip as if it were valid.
    baseline = _refusal_evidence().audit_evidence()

    missing_reason = dict(baseline)
    del missing_reason["reason_code"]
    with pytest.raises(TypeError, match="reason_code must be a string"):
        ExecutionRefusalEvidence.from_audit_evidence(missing_reason)

    non_string_reason = dict(baseline)
    non_string_reason["reason_code"] = 123  # type: ignore[assignment]
    with pytest.raises(TypeError, match="reason_code must be a string"):
        ExecutionRefusalEvidence.from_audit_evidence(non_string_reason)

    missing_phase = dict(baseline)
    del missing_phase["phase"]
    with pytest.raises(TypeError, match="phase must be a string"):
        ExecutionRefusalEvidence.from_audit_evidence(missing_phase)

    non_string_phase = dict(baseline)
    non_string_phase["phase"] = 456  # type: ignore[assignment]
    with pytest.raises(TypeError, match="phase must be a string"):
        ExecutionRefusalEvidence.from_audit_evidence(non_string_phase)


def test_refusal_signature_and_audit_claims_are_not_interchangeable() -> None:
    signer = Ed25519Signer.generate("refusal-key")
    unsigned = _refusal_evidence(
        signing_key_id=signer.key_id,
        signature_algorithm=signer.algorithm,
    )
    signed = dataclasses.replace(
        unsigned,
        signed=True,
        signature=signer.sign(unsigned.payload_hash.encode("utf-8")),
    )
    assert signed.verify_signature(signer) is True

    # A signature over a different payload never transfers.
    other = _refusal_evidence(
        reason_code=ExecutionReasonCode.REVOKED,
        signing_key_id=signer.key_id,
        signature_algorithm=signer.algorithm,
    )
    transplanted = dataclasses.replace(other, signed=True, signature=signed.signature)
    assert transplanted.verify_signature(signer) is False
    # An unsigned refusal cannot smuggle a signature.
    with pytest.raises(ValueError, match="unsigned execution refusal"):
        dataclasses.replace(unsigned, signature=signed.signature)
    # Claiming audit identifiers without an audit is refused.
    with pytest.raises(ValueError, match="unaudited execution refusal"):
        _refusal_evidence(audit_event_id="ev_forged")
