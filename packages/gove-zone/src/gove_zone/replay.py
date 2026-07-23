"""Replay — re-evaluate a recorded decision against a policy.

A receipt is *replayable* when running its policy against its captured
arguments produces the same decision. Replay is the integrity check between
"what we said happened" (the audit chain) and "what the policy says should
have happened given these arguments."
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from gove_zone.audit import ChainHashAuditStore
from gove_zone.authorization import ExecutionRefusalEvidence, strict_json_hash
from gove_zone.decision import Decision, DecisionRecord, RecordKind, canonical_json, sha256_json
from gove_zone.errors import AuditError
from gove_zone.policy import Policy
from gove_zone.replay_store import ReplaySideStore
from gove_zone.signing import LifecycleAttestation, LifecycleVerifierRegistry
from gove_zone.tool import ToolCall

_EXECUTION_EVIDENCE_DIGEST_FIELDS = frozenset(
    {
        "tenant_digest",
        "execution_boundary_digest",
        "adapter_id_digest",
        "adapter_artifact_digest",
        "receipt_id_digest",
        "receipt_hash",
        "request_id_digest",
        "authorization_audit_digest",
        "nonce_digest",
        "idempotency_digest",
        "attempt_id_digest",
        "binding_hash",
        "argument_hash",
    }
)
_EXECUTION_EVIDENCE_KEYS = _EXECUTION_EVIDENCE_DIGEST_FIELDS | {
    "phase",
    "reason_code",
    "consumption_state",
}
_DEPENDENCY_EVIDENCE_DIGEST_FIELDS = frozenset(
    {"tenant_digest", "execution_boundary_digest", "adapter_id_digest", "argument_hash"}
)
_DEPENDENCY_EVIDENCE_KEYS = _DEPENDENCY_EVIDENCE_DIGEST_FIELDS | {
    "phase",
    "reason_code",
    "consumption_state",
}
_EXECUTION_LIFECYCLE_CONTRACTS = {
    ("claim_committed", "receipt.execution.reserved", "RESERVED"): "allow",
    ("terminal", "receipt.execution.succeeded", "SUCCEEDED"): "allow",
    ("terminal", "receipt.execution.outcome_unknown", "UNKNOWN"): "deny",
}
_DEPENDENCY_LIFECYCLE_CONTRACT = (
    "dependency_validation",
    "receipt.execution.consumption_store_failed",
    "UNAVAILABLE",
)


def _is_sha256_hex(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _execution_evidence_error(event: dict[str, Any]) -> str | None:
    """Return a stable error code for malformed execution lifecycle evidence."""

    evidence = event.get("execution_evidence")
    if type(evidence) is not dict:
        return "execution_evidence_not_object"
    if any(type(key) is not str or type(value) is not str for key, value in evidence.items()):
        return "execution_evidence_non_string_field"

    keys = set(evidence)
    if keys == _EXECUTION_EVIDENCE_KEYS:
        digest_fields = _EXECUTION_EVIDENCE_DIGEST_FIELDS
        contract = (
            evidence["phase"],
            evidence["reason_code"],
            evidence["consumption_state"],
        )
        expected_decision = _EXECUTION_LIFECYCLE_CONTRACTS.get(contract)
        if expected_decision is None:
            return "execution_evidence_phase_contract_mismatch"
    elif keys == _DEPENDENCY_EVIDENCE_KEYS:
        digest_fields = _DEPENDENCY_EVIDENCE_DIGEST_FIELDS
        contract = (
            evidence["phase"],
            evidence["reason_code"],
            evidence["consumption_state"],
        )
        if contract != _DEPENDENCY_LIFECYCLE_CONTRACT:
            return "execution_evidence_dependency_contract_mismatch"
        expected_decision = "deny"
    else:
        return "execution_evidence_schema_mismatch"

    if any(not _is_sha256_hex(evidence[field]) for field in digest_fields):
        return "execution_evidence_digest_invalid"
    reason_code = evidence["reason_code"]
    if event.get("decision") != expected_decision:
        return "execution_evidence_decision_mismatch"
    if event.get("reason") != reason_code or event.get("matched_rules") != [reason_code]:
        return "execution_evidence_reason_mismatch"
    if event.get("argument_hash") != evidence["argument_hash"]:
        return "execution_evidence_argument_hash_mismatch"
    return None


def execution_refusal_error(event: dict[str, Any]) -> str | None:
    """Return a stable error code for a malformed execution refusal record.

    This is the single refusal contract: every verifier (bundle replay, release
    proof pack, product gates) must agree on exactly what a refusal record may
    say. A record passes only when it re-serializes byte-identically from its
    own claims, provably denies, and provably never entered an adapter.
    """

    if event.get("decision") != Decision.DENY.value:
        return "execution_refusal_decision_mismatch"
    if "lifecycle_attestation" in event:
        return "execution_refusal_attestation_present"
    evidence = event.get("execution_evidence")
    if type(evidence) is not dict:
        return "execution_refusal_evidence_not_object"
    if any(type(key) is not str or type(value) is not str for key, value in evidence.items()):
        return "execution_refusal_evidence_non_string_field"
    try:
        rebuilt = ExecutionRefusalEvidence.from_audit_evidence(evidence)
    except Exception:
        return "execution_refusal_evidence_schema_mismatch"
    # Round-trip equality proves the exact key set, the exact "false" literal,
    # every digest's shape, and the phase/attempt coupling in one comparison.
    if rebuilt.audit_evidence() != evidence:
        return "execution_refusal_evidence_schema_mismatch"
    if rebuilt.adapter_invoked:
        return "execution_refusal_claims_adapter_invocation"
    reason_code = rebuilt.reason_code.value
    if event.get("reason") != reason_code or event.get("matched_rules") != [reason_code]:
        return "execution_refusal_reason_mismatch"
    if event.get("argument_hash") != rebuilt.argument_hash:
        return "execution_refusal_argument_hash_mismatch"
    if event.get("state_hash") != strict_json_hash(rebuilt._audit_state_dict()):
        return "execution_refusal_state_hash_mismatch"
    if event.get("transformed_args") is not None:
        return "execution_refusal_transform_present"
    return None


def _record_kind(event: dict[str, Any]) -> tuple[RecordKind | None, str | None]:
    raw = event.get("record_kind", RecordKind.POLICY_DECISION.value)
    if type(raw) is not str:
        return None, "record_kind_not_string"
    try:
        return RecordKind(raw), None
    except ValueError:
        return None, "record_kind_unknown"


@dataclass(frozen=True)
class ReplayResult:
    """Outcome of replaying a recorded decision."""

    event_id: str
    matches: bool  # original decision == replayed decision
    original_decision: Decision
    replayed_decision: Decision
    policy_version_match: bool  # exact version string match
    argument_hash_match: bool  # original argument_hash == replayed
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "matches": self.matches,
            "original_decision": self.original_decision.value,
            "replayed_decision": self.replayed_decision.value,
            "policy_version_match": self.policy_version_match,
            "argument_hash_match": self.argument_hash_match,
            "reason": self.reason,
        }


def replay_event(event: dict[str, Any], policy: Policy) -> ReplayResult:
    """Replay a single audit event against *policy*.

    Note: the audit event records only the *argument_hash*, not the raw
    arguments. Without the raw args, replay cannot rerun the policy. Replay
    against an event-only record can therefore only confirm the policy
    version match; for full replay, callers should retain the original args
    alongside the audit event (e.g. via a side-store).
    """
    original = Decision(event["decision"])
    return ReplayResult(
        event_id=str(event.get("event_id", "")),
        matches=event.get("policy_version") == policy.version,
        original_decision=original,
        replayed_decision=original,  # cannot re-derive without raw args
        policy_version_match=event.get("policy_version") == policy.version,
        argument_hash_match=True,  # cannot recompute
        reason="policy-version-only replay; raw args not in audit event",
    )


def replay_call(
    call: ToolCall,
    expected_decision: Decision,
    policy: Policy,
    expected_policy_version: str | None = None,
) -> ReplayResult:
    """Replay by re-running *policy* against the actual *call*.

    This is the strong form: caller supplies both the raw args (which the
    kernel hashed but did not store in the audit) and the expected decision
    from the original receipt.
    """
    record = policy.evaluate(call)
    pv_match = expected_policy_version is None or record.policy_version == expected_policy_version
    arg_hash = sha256_json(dict(call.args))
    matches = record.decision is expected_decision and pv_match and record.argument_hash == arg_hash
    return ReplayResult(
        event_id=record.event_id,
        matches=matches,
        original_decision=expected_decision,
        replayed_decision=record.decision,
        policy_version_match=pv_match,
        argument_hash_match=record.argument_hash == arg_hash,
        reason=record.reason,
    )


def _call_from_side_record(event: dict[str, Any], side_record: dict[str, Any]) -> ToolCall:
    """Reconstruct the original :class:`ToolCall` from an audit *event* plus
    its raw-args *side_record*.

    The tool name comes from the tamper-evident audit event; everything the
    chain deliberately does not retain (raw args, state, path, actor, goal)
    comes from the side-store record.
    """
    return ToolCall(
        name=str(event.get("tool", "")),
        args=dict(side_record.get("args", {})),
        goal=str(side_record.get("goal", "")),
        actor=str(side_record.get("actor", "")),
        path=tuple(side_record.get("path", ()) or ()),
        state=dict(side_record.get("state", {})),
    )


def replay_from_side_store(
    event: dict[str, Any],
    side_record: dict[str, Any],
    policy: Policy,
) -> ReplayResult:
    """Re-derive a decision from an audit *event* + its raw-args *side_record*.

    Reconstructs the original :class:`~gove_zone.tool.ToolCall` from the
    side-store record, then:

    1. **Tamper cross-check (R4):** the reconstructed call must hash to the
       *audit event's* recorded ``argument_hash`` — the chain, not the side
       record, is the source of truth. A mismatch means the side-store drifted
       from the chain and is reported as a failed re-derivation.
    2. **Re-derivation (R3, R5):** delegate to :func:`replay_call`, which re-runs
       *policy* against the call and confirms the decision and policy version
       match what the chain recorded.

    Callers must not pass a redacted/tombstone ``side_record`` (it carries no raw
    args); those fall back to :func:`replay_event` instead.
    """
    event_id = str(event.get("event_id", ""))
    original = Decision(event["decision"])
    call = _call_from_side_record(event, side_record)

    if call.argument_hash() != event.get("argument_hash"):
        return ReplayResult(
            event_id=event_id,
            matches=False,
            original_decision=original,
            replayed_decision=original,
            policy_version_match=event.get("policy_version") == policy.version,
            argument_hash_match=False,
            reason="side-store argument_hash does not match audit chain",
        )

    try:
        result = replay_call(
            call,
            expected_decision=original,
            policy=policy,
            expected_policy_version=event.get("policy_version"),
        )
    except Exception as exc:
        return ReplayResult(
            event_id=event_id,
            matches=False,
            original_decision=original,
            replayed_decision=original,
            policy_version_match=False,
            argument_hash_match=True,
            reason=f"policy re-derivation raised: {exc}",
        )
    return replace(result, event_id=event_id)


def replay_bundle(
    store: ChainHashAuditStore,
    side_store: ReplaySideStore,
    policy: Policy,
    *,
    lifecycle_verifiers: LifecycleVerifierRegistry | None = None,
    forbidden_lifecycle_key_ids: frozenset[str] = frozenset(),
    forbidden_lifecycle_authority_ids: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Bundle-scope replay equivalence over an entire audit chain.

    Re-derives **every policy decision** in *store* (in chain order) from the raw
    arguments retained in *side_store*, and byte-compares each re-derived
    decision payload against what the chain recorded. This is the strongest
    offline integrity artifact the kernel offers: chain integrity (hash links),
    side-store/chain consistency (argument-hash cross-check), and full policy
    re-derivation (decision + canonical-JSON byte equivalence) in one verdict.

    Authenticated ``record_kind`` is the only classification input. Execution
    lifecycle records remain covered by full-chain hash and checkpoint
    verification, are structurally validated and counted separately, and are
    never sent back through the policy engine. Evidence presence alone never
    changes classification. Product verifiers remain responsible for
    cross-event lifecycle ordering and binding semantics.

    Per policy event:

    1. Fetch the side record. Missing or redacted/tombstone records cannot be
       re-derived; they fall back to :func:`replay_event` (policy-version-only)
       and are counted as *degraded*, never as *matched*.
    2. Cross-check + semantic re-derivation via :func:`replay_from_side_store`
       (argument-hash against the chain, decision + policy version re-run).
    3. Byte equivalence: re-run ``policy.evaluate`` on the reconstructed call,
       re-attach the kernel-owned context exactly as ``Kernel.dispatch`` does
       (goal/actor/path/state_hash/decision_request_hash), pin the two
       nondeterministic identity fields (``event_id``, ``timestamp_iso``) to
       the recorded values, then require ``canonical_json`` of the re-derived
       record to be byte-identical to the recorded event payload (the event
       minus its chain fields ``previous_hash``/``event_hash``).

    Returns a dict with ``valid`` (bool), ``chain_valid`` (bool),
    ``events_total``, ``events_matched``, ``events_degraded`` (ints), and
    ``mismatches`` (list of per-event detail dicts). Fail-closed: an invalid
    chain, an unreadable chain, or any single mismatch makes ``valid`` False.
    """
    mismatches: list[dict[str, Any]] = []
    events_total = 0
    events_matched = 0
    events_degraded = 0
    lifecycle_events_total = 0
    refusal_events_total = 0

    try:
        chain = store.verify_chain()
        events = list(store.iter_events())
    except AuditError as exc:
        return {
            "valid": False,
            "chain_valid": False,
            "events_total": 0,
            "events_matched": 0,
            "events_degraded": 0,
            "mismatches": [{"event_id": None, "type": "chain_unreadable", "detail": str(exc)}],
        }

    chain_valid = bool(chain["valid"])
    for failure in chain["failures"]:
        mismatches.append(
            {
                "event_id": failure.get("event_id"),
                "type": f"chain_{failure.get('type', 'failure')}",
                "detail": failure,
            }
        )

    for event in events:
        event_id = str(event.get("event_id", ""))
        side_record = side_store.get(event_id)
        kind, kind_error = _record_kind(event)
        if kind_error is not None:
            mismatches.append(
                {
                    "event_id": event_id,
                    "type": "record_kind_invalid",
                    "detail": kind_error,
                }
            )
            continue
        if kind is RecordKind.EXECUTION_REFUSAL:
            refusal_events_total += 1
            if side_record is not None:
                mismatches.append(
                    {
                        "event_id": event_id,
                        "type": "refusal_side_record_present",
                        "detail": "execution refusal must not have a policy side-record",
                    }
                )
            refusal_error = execution_refusal_error(event)
            if refusal_error is not None:
                mismatches.append(
                    {
                        "event_id": event_id,
                        "type": "refusal_evidence_malformed",
                        "detail": refusal_error,
                    }
                )
            continue
        if kind is RecordKind.EXECUTION_LIFECYCLE:
            lifecycle_events_total += 1
            if side_record is not None:
                mismatches.append(
                    {
                        "event_id": event_id,
                        "type": "lifecycle_side_record_present",
                        "detail": "execution lifecycle must not have a policy side-record",
                    }
                )
            evidence_error = _execution_evidence_error(event)
            if evidence_error is not None:
                mismatches.append(
                    {
                        "event_id": event_id,
                        "type": "lifecycle_evidence_malformed",
                        "detail": evidence_error,
                    }
                )
            try:
                parsed = DecisionRecord.from_dict(
                    {
                        key: value
                        for key, value in event.items()
                        if key
                        not in (
                            "previous_hash",
                            "event_hash",
                            "_audit_checkpoint_parent_hash",
                        )
                    }
                )
                attestation = parsed.lifecycle_attestation
                attestation_valid = (
                    lifecycle_verifiers is not None
                    and type(attestation) is LifecycleAttestation
                    and lifecycle_verifiers.verify(
                        attestation,
                        parsed.lifecycle_signing_payload(),
                        forbidden_key_ids=forbidden_lifecycle_key_ids,
                        forbidden_authority_ids=forbidden_lifecycle_authority_ids,
                    )
                )
            except Exception:
                attestation_valid = False
            if not attestation_valid:
                mismatches.append(
                    {
                        "event_id": event_id,
                        "type": "lifecycle_attestation_invalid",
                        "detail": "trusted lifecycle authorization proof is unavailable or invalid",
                    }
                )
            continue
        events_total += 1
        if "execution_evidence" in event:
            mismatches.append(
                {
                    "event_id": event_id,
                    "type": "policy_execution_evidence_present",
                    "detail": "policy decision cannot contain execution_evidence",
                }
            )
            continue

        if side_record is None:
            mismatches.append(
                {
                    "event_id": event_id,
                    "type": "policy_side_record_missing",
                    "detail": "policy decision requires its replay side-record",
                }
            )
            continue
        if side_record.get("redacted"):
            mismatches.append(
                {
                    "event_id": event_id,
                    "type": "policy_side_record_redacted",
                    "detail": "redacted policy side-record cannot be re-derived",
                }
            )
            continue

        semantic = replay_from_side_store(event, side_record, policy)
        if not semantic.matches:
            mismatches.append(
                {
                    "event_id": event_id,
                    "type": (
                        "argument_hash_mismatch"
                        if not semantic.argument_hash_match
                        else "decision_mismatch"
                    ),
                    "detail": semantic.to_dict(),
                }
            )
            continue

        # Byte equivalence: re-derive the full DecisionRecord the way the
        # kernel produced it, normalize only the nondeterministic identity
        # fields to the recorded values, and compare canonical JSON bytes.
        call = _call_from_side_record(event, side_record)
        try:
            fresh = policy.evaluate(call)
        except Exception as exc:
            mismatches.append(
                {
                    "event_id": event_id,
                    "type": "replay_policy_error",
                    "detail": str(exc),
                }
            )
            continue
        if (
            fresh.record_kind is not RecordKind.POLICY_DECISION
            or fresh.execution_evidence is not None
        ):
            mismatches.append(
                {
                    "event_id": event_id,
                    "type": "rederived_policy_schema_confusion",
                    "detail": "policy evaluation returned a non-policy record schema",
                }
            )
            continue
        fresh = replace(
            fresh,
            goal=call.goal,
            actor=call.actor,
            path=call.path,
            state_hash=call.state_hash(),
            decision_request_hash=call.decision_request_hash(),
            event_id=event_id,
            timestamp_iso=str(event.get("timestamp_iso", "")),
        )
        recorded_payload = {
            k: v
            for k, v in event.items()
            if k
            not in (
                "previous_hash",
                "event_hash",
                "_audit_checkpoint_parent_hash",
            )
        }
        recorded_bytes = canonical_json(recorded_payload).encode("utf-8")
        rederived_payload = fresh.to_dict()
        if "record_kind" not in recorded_payload:
            rederived_payload.pop("record_kind")
        rederived_bytes = canonical_json(rederived_payload).encode("utf-8")
        if rederived_bytes != recorded_bytes:
            mismatches.append(
                {
                    "event_id": event_id,
                    "type": "byte_mismatch",
                    "detail": {
                        "recorded": recorded_payload,
                        "rederived": fresh.to_dict(),
                    },
                }
            )
            continue

        events_matched += 1

    return {
        "valid": chain_valid and not mismatches and events_matched == events_total,
        "chain_valid": chain_valid,
        "events_total": events_total,
        "events_matched": events_matched,
        "events_degraded": events_degraded,
        "lifecycle_events_total": lifecycle_events_total,
        "refusal_events_total": refusal_events_total,
        "mismatches": mismatches,
    }


def replay_checkpointed_bundle(
    store: ChainHashAuditStore,
    side_store: ReplaySideStore,
    policy: Policy,
    *,
    lifecycle_verifiers: LifecycleVerifierRegistry | None = None,
) -> dict[str, Any]:
    """Strict replay requiring a signed external audit checkpoint.

    This additive surface never upgrades the legacy local hash-chain mode. If
    the trusted checkpoint is missing, unavailable, malformed, or diverges
    from local bytes, policy replay is not attempted and the result is invalid.
    """
    try:
        checkpoint = store.verify_checkpointed_chain()
    except AuditError as exc:
        return {
            "valid": False,
            "chain_valid": False,
            "checkpoint_valid": False,
            "strict": True,
            "events_total": 0,
            "events_matched": 0,
            "events_degraded": 0,
            "mismatches": [
                {
                    "event_id": None,
                    "type": "checkpoint_unreadable",
                    "detail": str(exc),
                }
            ],
        }
    if not checkpoint["valid"]:
        return {
            "valid": False,
            "chain_valid": bool(checkpoint.get("chain_valid", False)),
            "checkpoint_valid": False,
            "strict": bool(checkpoint.get("strict", False)),
            "events_total": int(checkpoint.get("checked", 0)),
            "events_matched": 0,
            "events_degraded": 0,
            "mismatches": [
                {
                    "event_id": None,
                    "type": "checkpoint_verification_failed",
                    "detail": checkpoint.get("failures", []),
                }
            ],
        }

    checkpoint_data = checkpoint.get("checkpoint")
    checkpoint_key_id = checkpoint_data.get("key_id") if type(checkpoint_data) is dict else None
    checkpoint_namespace = (
        checkpoint_data.get("namespace") if type(checkpoint_data) is dict else None
    )
    replay = replay_bundle(
        store,
        side_store,
        policy,
        lifecycle_verifiers=lifecycle_verifiers,
        forbidden_lifecycle_key_ids=(
            frozenset({checkpoint_key_id}) if type(checkpoint_key_id) is str else frozenset()
        ),
        forbidden_lifecycle_authority_ids=(
            frozenset({"audit-checkpoint", f"audit-checkpoint:{checkpoint_namespace}"})
            if type(checkpoint_namespace) is str
            else frozenset({"audit-checkpoint"})
        ),
    )
    try:
        checkpoint_after = store.verify_checkpointed_chain()
    except AuditError as exc:
        return {
            **replay,
            "valid": False,
            "checkpoint_valid": False,
            "strict": True,
            "mismatches": [
                *replay["mismatches"],
                {
                    "event_id": None,
                    "type": "checkpoint_changed_during_replay",
                    "detail": str(exc),
                },
            ],
        }
    if not checkpoint_after["valid"] or checkpoint_after.get("checkpoint") != checkpoint.get(
        "checkpoint"
    ):
        return {
            **replay,
            "valid": False,
            "checkpoint_valid": False,
            "strict": True,
            "mismatches": [
                *replay["mismatches"],
                {
                    "event_id": None,
                    "type": "checkpoint_changed_during_replay",
                    "detail": checkpoint_after.get("failures", []),
                },
            ],
        }
    return {
        **replay,
        "valid": bool(replay["valid"]),
        "checkpoint_valid": True,
        "strict": True,
        "checkpoint": checkpoint["checkpoint"],
    }


def find_event(store: ChainHashAuditStore, event_id: str) -> dict[str, Any] | None:
    """Locate an event in the audit store by id."""
    events = store.query(where=lambda e: e.get("event_id") == event_id, limit=1)
    return events[0] if events else None
