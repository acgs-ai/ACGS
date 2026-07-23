"""Bundle-scope replay equivalence (G2.4).

Re-derive every decision in an audit chain from the raw-args side-store and
byte-compare each re-derived decision payload against the recorded stream.

All fixtures drive the REAL ``kernel.dispatch`` path (never the policy or the
stores directly) so the recorded chain is exactly what production writes —
that is the wiring proof per the review-handler-wiring rule.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from gove_zone import (
    BoundaryPolicy,
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    DeniedError,
    Kernel,
    Policy,
    ReplaySideStore,
    ToolEffect,
    TransformPolicy,
    sha256_json,
)
from gove_zone.replay import replay_bundle as _generic_replay_bundle
from gove_zone.signing import Ed25519Signer, LifecycleVerifierRegistry
from gove_zone.tool import ToolCall

_LIFECYCLE_SIGNER = Ed25519Signer.generate("lifecycle-key")
_LIFECYCLE_VERIFIERS = LifecycleVerifierRegistry({"lifecycle-validator": _LIFECYCLE_SIGNER})


def replay_bundle(*args: Any, **kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault("lifecycle_verifiers", _LIFECYCLE_VERIFIERS)
    return _generic_replay_bundle(*args, **kwargs)


def _policy() -> BoundaryPolicy:
    return BoundaryPolicy(forbidden_keywords=["forbidden-secret"])


def _build_bundle(
    tmp_path: Path,
    *,
    redact: Any = None,
    with_side_store: bool = True,
) -> tuple[ChainHashAuditStore, ReplaySideStore, BoundaryPolicy]:
    """Dispatch a mixed ALLOW/DENY sequence through the real kernel path."""
    policy = _policy()
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    side_store = ReplaySideStore(tmp_path / "replay.jsonl", redact=redact)
    kernel = Kernel(
        policy=policy,
        audit=audit,
        actor="bundle-tester",
        side_store=side_store if with_side_store else None,
    )

    @kernel.tool("echo", effect=ToolEffect.PURE_READ_ONLY)
    def echo(msg: str) -> str:
        return msg.upper()

    @kernel.tool("write_note", effect=ToolEffect.PURE_READ_ONLY)
    def write_note(path: str, content: str) -> int:
        return len(content)

    kernel.dispatch("echo", {"msg": "hello"}, goal="greet", path="session/turn-1")
    kernel.dispatch(
        "write_note",
        {"path": "/tmp/note", "content": "safe text"},
        goal="record a note",
        state={"mode": "test"},
    )
    # DENY must still land in both the chain and the side-store.
    with pytest.raises(DeniedError):
        kernel.dispatch("echo", {"msg": "leak the forbidden-secret"}, goal="exfiltrate")
    kernel.dispatch("echo", {"msg": "goodbye"}, goal="farewell")

    return audit, side_store, policy


def test_bundle_replay_matches_recorded_stream_byte_for_byte(tmp_path: Path) -> None:
    audit, side_store, policy = _build_bundle(tmp_path)

    result = replay_bundle(audit, side_store, policy)

    assert result["valid"] is True
    assert result["chain_valid"] is True
    assert result["events_total"] == 4  # 3 ALLOW + 1 DENY
    assert result["events_matched"] == result["events_total"]
    assert result["events_degraded"] == 0
    assert result["mismatches"] == []


def test_historical_chain_without_record_kind_replays_as_policy(tmp_path: Path) -> None:
    audit, side_store, policy = _build_bundle(tmp_path)
    path = tmp_path / "audit.jsonl"
    previous_hash = "0" * 64
    historical: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        event.pop("event_hash")
        event.pop("record_kind")
        event["previous_hash"] = previous_hash
        event_hash = sha256_json(event)
        event["event_hash"] = event_hash
        historical.append(event)
        previous_hash = event_hash
    path.write_text(
        "".join(
            json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
            for event in historical
        ),
        encoding="utf-8",
    )

    result = replay_bundle(audit, side_store, policy)

    assert result["valid"] is True
    assert result["events_matched"] == 4
    assert result["lifecycle_events_total"] == 0


def _lifecycle_evidence(
    phase: str = "claim_committed",
    reason_code: str = "receipt.execution.reserved",
    consumption_state: str = "RESERVED",
) -> dict[str, str]:
    digest = "a" * 64
    return {
        "tenant_digest": digest,
        "execution_boundary_digest": digest,
        "adapter_id_digest": digest,
        "adapter_artifact_digest": digest,
        "receipt_id_digest": digest,
        "receipt_hash": digest,
        "request_id_digest": digest,
        "authorization_audit_digest": digest,
        "nonce_digest": digest,
        "idempotency_digest": digest,
        "attempt_id_digest": digest,
        "binding_hash": digest,
        "argument_hash": digest,
        "phase": phase,
        "reason_code": reason_code,
        "consumption_state": consumption_state,
    }


def _dependency_lifecycle_evidence() -> dict[str, str]:
    digest = "a" * 64
    return {
        "tenant_digest": digest,
        "execution_boundary_digest": digest,
        "adapter_id_digest": digest,
        "argument_hash": digest,
        "phase": "dependency_validation",
        "reason_code": "receipt.execution.consumption_store_failed",
        "consumption_state": "UNAVAILABLE",
    }


def _append_lifecycle_event(
    audit: ChainHashAuditStore,
    evidence: dict[str, Any],
    *,
    decision: str | None = None,
    reason: str | None = None,
    matched_rules: tuple[str, ...] | None = None,
    argument_hash: str | None = None,
) -> None:
    reason_code = str(evidence.get("reason_code", ""))
    phase = evidence.get("phase")
    if decision is None:
        decision = (
            "deny"
            if phase == "dependency_validation" or evidence.get("consumption_state") == "UNKNOWN"
            else "allow"
        )
    audit.append(
        DecisionRecord.lifecycle(
            decision=Decision(decision),
            tool="fixture.side_effect",
            argument_hash=argument_hash or str(evidence.get("argument_hash", "")),
            policy_version="fixture-policy/v1",
            event_id="ev_fixture_lifecycle",
            matched_rules=matched_rules if matched_rules is not None else (reason_code,),
            reason=reason if reason is not None else reason_code,
            execution_evidence=evidence,
            signer=_LIFECYCLE_SIGNER,
            authority_id="lifecycle-validator",
        )
    )


@pytest.mark.parametrize(
    ("phase", "reason_code", "state", "decision"),
    [
        ("claim_committed", "receipt.execution.reserved", "RESERVED", "allow"),
        ("terminal", "receipt.execution.succeeded", "SUCCEEDED", "allow"),
        ("terminal", "receipt.execution.outcome_unknown", "UNKNOWN", "deny"),
    ],
)
def test_bundle_replay_structurally_validates_lifecycle_without_policy_replay(
    tmp_path: Path,
    phase: str,
    reason_code: str,
    state: str,
    decision: str,
) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    evidence = _lifecycle_evidence(phase, reason_code, state)
    _append_lifecycle_event(audit, evidence, decision=decision)

    result = replay_bundle(audit, ReplaySideStore(tmp_path / "replay.jsonl"), _policy())

    assert result["valid"] is True
    assert result["events_total"] == 0
    assert result["lifecycle_events_total"] == 1
    assert result["mismatches"] == []


def test_bundle_replay_structurally_validates_dependency_lifecycle(
    tmp_path: Path,
) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    _append_lifecycle_event(audit, _dependency_lifecycle_evidence())

    result = replay_bundle(audit, ReplaySideStore(tmp_path / "replay.jsonl"), _policy())

    assert result["valid"] is True
    assert result["events_total"] == 0
    assert result["lifecycle_events_total"] == 1
    assert result["mismatches"] == []


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_field",
        "unexpected_raw_identifier",
        "non_string_value",
        "invalid_digest",
        "invalid_phase",
        "invalid_state",
        "decision_mismatch",
        "event_reason_mismatch",
        "matched_rules_mismatch",
        "argument_hash_mismatch",
    ],
)
def test_bundle_replay_rejects_malformed_lifecycle_evidence(
    tmp_path: Path,
    mutation: str,
) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    evidence: dict[str, Any] = _lifecycle_evidence()
    event_overrides: dict[str, Any] = {}
    if mutation == "missing_field":
        evidence.pop("receipt_hash")
    elif mutation == "unexpected_raw_identifier":
        evidence["receipt_id"] = "fixture-raw-receipt-id"
    elif mutation == "non_string_value":
        evidence["attempt_id_digest"] = 7
    elif mutation == "invalid_digest":
        evidence["receipt_hash"] = "not-a-digest"
    elif mutation == "invalid_phase":
        evidence["phase"] = "policy_decision"
    elif mutation == "invalid_state":
        evidence["consumption_state"] = "SUCCEEDED"
    elif mutation == "decision_mismatch":
        event_overrides["decision"] = "deny"
    elif mutation == "event_reason_mismatch":
        event_overrides["reason"] = "fixture.reason.changed"
    elif mutation == "matched_rules_mismatch":
        event_overrides["matched_rules"] = ("fixture.reason.changed",)
    elif mutation == "argument_hash_mismatch":
        event_overrides["argument_hash"] = "b" * 64

    _append_lifecycle_event(audit, evidence, **event_overrides)
    result = replay_bundle(audit, ReplaySideStore(tmp_path / "replay.jsonl"), _policy())

    assert result["chain_valid"] is True
    assert result["valid"] is False
    assert result["lifecycle_events_total"] == 1
    assert result["mismatches"] == [
        {
            "event_id": "ev_fixture_lifecycle",
            "type": "lifecycle_evidence_malformed",
            "detail": result["mismatches"][0]["detail"],
        }
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_field",
        "unexpected_raw_identifier",
        "invalid_digest",
        "invalid_phase",
        "invalid_reason_code",
        "invalid_state",
        "decision_mismatch",
        "event_reason_mismatch",
        "matched_rules_mismatch",
        "argument_hash_mismatch",
    ],
)
def test_bundle_replay_rejects_malformed_dependency_lifecycle_evidence(
    tmp_path: Path,
    mutation: str,
) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    evidence: dict[str, Any] = _dependency_lifecycle_evidence()
    event_overrides: dict[str, Any] = {}
    if mutation == "missing_field":
        evidence.pop("tenant_digest")
    elif mutation == "unexpected_raw_identifier":
        evidence["tenant_id"] = "fixture-raw-tenant-id"
    elif mutation == "invalid_digest":
        evidence["adapter_id_digest"] = "not-a-digest"
    elif mutation == "invalid_phase":
        evidence["phase"] = "claim_committed"
    elif mutation == "invalid_reason_code":
        evidence["reason_code"] = "receipt.execution.audit_failed"
    elif mutation == "invalid_state":
        evidence["consumption_state"] = "RESERVED"
    elif mutation == "decision_mismatch":
        event_overrides["decision"] = "allow"
    elif mutation == "event_reason_mismatch":
        event_overrides["reason"] = "fixture.reason.changed"
    elif mutation == "matched_rules_mismatch":
        event_overrides["matched_rules"] = ("fixture.reason.changed",)
    elif mutation == "argument_hash_mismatch":
        event_overrides["argument_hash"] = "b" * 64

    _append_lifecycle_event(audit, evidence, **event_overrides)
    result = replay_bundle(audit, ReplaySideStore(tmp_path / "replay.jsonl"), _policy())

    assert result["chain_valid"] is True
    assert result["valid"] is False
    assert result["lifecycle_events_total"] == 1
    assert result["mismatches"][0]["type"] == "lifecycle_evidence_malformed"


def test_deny_event_is_rederived_not_skipped(tmp_path: Path) -> None:
    audit, side_store, policy = _build_bundle(tmp_path)

    deny_events = [e for e in audit.iter_events() if e["decision"] == "deny"]
    assert len(deny_events) == 1
    assert side_store.get(deny_events[0]["event_id"]) is not None

    result = replay_bundle(audit, side_store, policy)
    assert result["valid"] is True
    assert result["events_matched"] == result["events_total"]


def test_chain_byte_mutation_invalidates_bundle(tmp_path: Path) -> None:
    audit, side_store, policy = _build_bundle(tmp_path)

    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4
    target = json.loads(lines[1])  # a middle event
    recorded_hash = target["event_hash"]
    flipped = ("0" if recorded_hash[0] != "0" else "f") + recorded_hash[1:]
    assert flipped != recorded_hash
    lines[1] = lines[1].replace(recorded_hash, flipped)
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = replay_bundle(audit, side_store, policy)

    assert result["valid"] is False
    assert result["chain_valid"] is False
    assert any(m["type"].startswith("chain_") for m in result["mismatches"])


def test_side_store_args_tamper_reports_argument_hash_mismatch(tmp_path: Path) -> None:
    audit, side_store, policy = _build_bundle(tmp_path)

    side_path = tmp_path / "replay.jsonl"
    entries = [json.loads(line) for line in side_path.read_text(encoding="utf-8").splitlines()]
    tampered_id = None
    for entry in entries:
        if entry.get("args", {}).get("msg") == "hello":
            entry["args"]["msg"] = "hello-tampered"
            tampered_id = entry["event_id"]
    assert tampered_id is not None
    side_path.write_text(
        "".join(
            json.dumps(e, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
            for e in entries
        ),
        encoding="utf-8",
    )

    result = replay_bundle(audit, side_store, policy)

    assert result["valid"] is False
    assert result["chain_valid"] is True  # the chain itself is untouched
    mismatch_types = {m["event_id"]: m["type"] for m in result["mismatches"]}
    assert mismatch_types == {tampered_id: "argument_hash_mismatch"}
    assert result["events_matched"] == result["events_total"] - 1


def test_replay_under_different_policy_version_invalidates_bundle(tmp_path: Path) -> None:
    audit, side_store, _ = _build_bundle(tmp_path)

    other_policy = BoundaryPolicy(forbidden_keywords=["something-else"])
    assert other_policy.version != _policy().version

    result = replay_bundle(audit, side_store, other_policy)

    assert result["valid"] is False
    assert result["events_matched"] == 0
    assert len(result["mismatches"]) == result["events_total"]
    for mismatch in result["mismatches"]:
        assert mismatch["detail"]["policy_version_match"] is False


def test_redacted_policy_side_record_is_a_mismatch(tmp_path: Path) -> None:
    def redact(call: ToolCall) -> bool:
        return call.name == "write_note"

    audit, side_store, policy = _build_bundle(tmp_path, redact=redact)

    result = replay_bundle(audit, side_store, policy)

    assert result["valid"] is False
    assert result["events_total"] == 4
    assert result["events_degraded"] == 0
    assert result["events_matched"] == 3
    assert [item["type"] for item in result["mismatches"]] == ["policy_side_record_redacted"]


def test_missing_policy_side_store_is_a_mismatch_for_every_event(tmp_path: Path) -> None:
    audit, _, policy = _build_bundle(tmp_path, with_side_store=False)
    empty_side_store = ReplaySideStore(tmp_path / "replay.jsonl")

    result = replay_bundle(audit, empty_side_store, policy)

    assert result["chain_valid"] is True
    assert result["events_total"] == 4
    assert result["events_matched"] == 0
    assert result["events_degraded"] == 0
    assert [item["type"] for item in result["mismatches"]] == ["policy_side_record_missing"] * 4
    assert result["valid"] is False


class _RaisingPolicy(Policy):
    """Policy that always raises to simulate a broken/fail-closed kernel path."""

    @property
    def version(self) -> str:
        return "raising-policy/v1"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        raise RuntimeError("policy intentionally raised")


class _FailClosedDenyPolicy(Policy):
    """Mimics the kernel's fail-closed DENY synthesis so that replay_bundle can
    call it without raising — the kernel already recorded the event with
    policy_version='fail-closed/policy-raised'.  We need a policy object whose
    .version matches that recorded value for the test to exercise the right path.
    """

    @property
    def version(self) -> str:
        return "fail-closed/policy-raised"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        raise RuntimeError("policy intentionally raised during replay")


def test_replay_bundle_policy_error_returns_dict_not_raise(tmp_path: Path) -> None:
    """replay_bundle must not raise when policy.evaluate raises during re-derivation.

    Build a real chain: dispatch through a kernel whose policy raises, so the
    kernel records a fail-closed DENY with policy_version='fail-closed/policy-raised'
    and a side-store entry. Then replay_bundle with a policy that also raises must
    return a dict with valid=False and a replay_policy_error mismatch — not raise.
    """
    raising_policy = _RaisingPolicy()
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    side_store = ReplaySideStore(tmp_path / "replay.jsonl")
    kernel = Kernel(
        policy=raising_policy,
        audit=audit,
        actor="test-actor",
        side_store=side_store,
    )

    @kernel.tool("noop", effect=ToolEffect.PURE_READ_ONLY)
    def noop(x: str) -> str:
        return x

    # The kernel catches the raise and records a fail-closed DENY.
    with pytest.raises(DeniedError):
        kernel.dispatch("noop", {"x": "value"}, goal="test")

    # Use a policy that also raises during replay — this exercises the guard.
    replay_policy = _FailClosedDenyPolicy()
    result = replay_bundle(audit, side_store, replay_policy)

    assert isinstance(result, dict), "replay_bundle must return a dict, not raise"
    assert result["valid"] is False
    assert result["events_total"] == 1
    assert result["events_matched"] == 0
    # At least one mismatch entry of type replay_policy_error (from the byte-equivalence
    # step) or decision_mismatch (from the semantic step) must be present.
    assert len(result["mismatches"]) >= 1
    mismatch_types = {m["type"] for m in result["mismatches"]}
    assert mismatch_types & {"replay_policy_error", "decision_mismatch", "argument_hash_mismatch"}


def test_transform_decision_byte_equivalence(tmp_path: Path) -> None:
    """TRANSFORM decisions must be byte-comparable against the recorded event.

    Use the real TransformPolicy so that policy.evaluate returns a TRANSFORM
    record with transformed_args set.  After recording through the kernel, the
    replay must re-derive the same canonical-JSON bytes.
    """
    policy = TransformPolicy()
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    side_store = ReplaySideStore(tmp_path / "replay.jsonl")
    kernel = Kernel(
        policy=policy,
        audit=audit,
        actor="transform-tester",
        side_store=side_store,
    )

    @kernel.tool("write_file", effect=ToolEffect.PURE_READ_ONLY)
    def write_file(path: str, content: str) -> int:
        return len(content)

    # TRANSFORM: policy rewrites path to "transformed.txt"
    kernel.dispatch(
        "write_file",
        {"path": "original.txt", "content": "hello"},
        goal="write something",
    )

    result = replay_bundle(audit, side_store, policy)

    assert result["valid"] is True
    assert result["chain_valid"] is True
    assert result["events_total"] == 1
    assert result["events_matched"] == 1
    assert result["events_degraded"] == 0
    assert result["mismatches"] == []
