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
from gove_zone.decision import Decision, DecisionRecord, canonical_json, sha256_json
from gove_zone.errors import AuditError
from gove_zone.policy import Policy
from gove_zone.replay_store import ReplaySideStore
from gove_zone.tool import ToolCall


@dataclass(frozen=True)
class ReplayResult:
    """Outcome of replaying a recorded decision."""

    event_id: str
    # Decision-equality signal, but its STRENGTH depends on ``re_derived``:
    # when ``re_derived`` is True (replay_call / replay_from_side_store) it means
    # the policy was re-run and the original decision was reproduced; when
    # ``re_derived`` is False (event-only replay) the policy was NOT re-run, so
    # this only reflects a recorded-vs-current policy *version* match, not a true
    # re-derivation. Never read ``matches`` as "decision reproduced" without also
    # checking ``re_derived`` and the ``*_match`` flags.
    matches: bool
    original_decision: Decision
    replayed_decision: Decision
    policy_version_match: bool  # exact version string match
    argument_hash_match: bool  # original argument_hash == replayed
    reason: str
    # True ONLY when the policy was actually re-run against the original raw
    # args (replay_call / replay_from_side_store). False for event-only replay,
    # which can confirm the policy *version* but cannot re-derive the decision.
    # Callers must not read ``matches`` as "decision reproduced" without also
    # checking ``re_derived`` — an event-only ``matches`` is a version match.
    re_derived: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "matches": self.matches,
            "original_decision": self.original_decision.value,
            "replayed_decision": self.replayed_decision.value,
            "policy_version_match": self.policy_version_match,
            "argument_hash_match": self.argument_hash_match,
            "reason": self.reason,
            "re_derived": self.re_derived,
        }


def replay_event(event: dict[str, Any], policy: Policy) -> ReplayResult:
    """Replay a single audit event against *policy* (policy-version check only).

    .. warning::
       This is the **weak** replay form. The audit event records only the
       *argument_hash*, not the raw arguments, so this function CANNOT re-derive
       the decision. ``re_derived`` is ``False`` and ``argument_hash_match`` is
       ``False`` (the hash is not recomputed here, so a match cannot be
       claimed). ``matches`` reflects the *policy version* only — do not read it
       as "decision reproduced".

       For real integrity replay, retain the raw args in a side-store and use
       :func:`replay_from_side_store` (or :func:`replay_call` when you already
       hold the :class:`~gove_zone.tool.ToolCall`). Those set
       ``re_derived=True`` only after the policy is actually re-run.
    """
    original = Decision(event["decision"])
    return ReplayResult(
        event_id=str(event.get("event_id", "")),
        matches=event.get("policy_version") == policy.version,
        original_decision=original,
        replayed_decision=original,  # cannot re-derive without raw args
        policy_version_match=event.get("policy_version") == policy.version,
        argument_hash_match=False,  # not recomputed here — cannot claim a match
        reason="policy-version-only replay; raw args not in audit event",
        re_derived=False,
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
        re_derived=True,
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


def _rederive_from_side_store(
    event: dict[str, Any],
    side_record: dict[str, Any],
    policy: Policy,
) -> tuple[ReplayResult, DecisionRecord | None, ToolCall | None]:
    """Shared re-derivation engine for :func:`replay_from_side_store` and
    :func:`replay_bundle`.

    Performs the chain cross-check, then re-runs *policy* exactly **once**,
    returning ``(result, fresh_record, call)`` so bundle-scope callers can
    reuse the same evaluation for the byte-equivalence check instead of
    evaluating the policy a second time. ``fresh_record``/``call`` are ``None``
    when the cross-check failed or the policy raised.
    """
    event_id = str(event.get("event_id", ""))
    original = Decision(event["decision"])
    call = _call_from_side_record(event, side_record)

    if call.argument_hash() != event.get("argument_hash"):
        return (
            ReplayResult(
                event_id=event_id,
                matches=False,
                original_decision=original,
                replayed_decision=original,
                policy_version_match=event.get("policy_version") == policy.version,
                argument_hash_match=False,
                reason="side-store argument_hash does not match audit chain",
                re_derived=False,
            ),
            None,
            None,
        )

    try:
        fresh = policy.evaluate(call)
    except Exception as exc:
        return (
            ReplayResult(
                event_id=event_id,
                matches=False,
                original_decision=original,
                replayed_decision=original,
                policy_version_match=False,
                argument_hash_match=True,
                reason=f"policy re-derivation raised: {exc}",
                re_derived=False,
            ),
            None,
            None,
        )

    # Same acceptance rules as replay_call: decision, policy version (absent
    # recorded version passes, as before), and argument hash must all agree.
    expected_pv = event.get("policy_version")
    pv_match = expected_pv is None or fresh.policy_version == expected_pv
    arg_hash = call.argument_hash()
    arg_match = fresh.argument_hash == arg_hash
    result = ReplayResult(
        event_id=event_id,
        matches=fresh.decision is original and pv_match and arg_match,
        original_decision=original,
        replayed_decision=fresh.decision,
        policy_version_match=pv_match,
        argument_hash_match=arg_match,
        reason=fresh.reason,
        re_derived=True,
    )
    return result, fresh, call


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
    2. **Re-derivation (R3, R5):** re-run *policy* against the call and confirm
       the decision and policy version match what the chain recorded (same
       acceptance rules as :func:`replay_call`).

    Callers must not pass a redacted/tombstone ``side_record`` (it carries no raw
    args); those fall back to :func:`replay_event` instead.
    """
    result, _fresh, _call = _rederive_from_side_store(event, side_record, policy)
    return result


def replay_bundle(
    store: ChainHashAuditStore,
    side_store: ReplaySideStore,
    policy: Policy,
) -> dict[str, Any]:
    """Bundle-scope replay equivalence over an entire audit chain.

    Re-derives **every** decision in *store* (in chain order) from the raw
    arguments retained in *side_store*, and byte-compares each re-derived
    decision payload against what the chain recorded. This is the strongest
    offline integrity artifact the kernel offers: chain integrity (hash links),
    side-store/chain consistency (argument-hash cross-check), and full policy
    re-derivation (decision + canonical-JSON byte equivalence) in one verdict.

    Per event:

    1. Fetch the side record. Missing or redacted/tombstone records cannot be
       re-derived; they fall back to :func:`replay_event` (policy-version-only)
       and are counted as *degraded*, never as *matched*.
    2. Cross-check + semantic re-derivation via :func:`replay_from_side_store`
       (argument-hash against the chain, decision + policy version re-run).
    3. Byte equivalence: take the re-derived record from that same single
       ``policy.evaluate`` run, re-attach the kernel-owned context exactly as
       ``Kernel.dispatch`` does (goal/actor/path/state_hash/
       decision_request_hash), pin the two nondeterministic identity fields
       (``event_id``, ``timestamp_iso``) to the recorded values, then require
       ``canonical_json`` of the re-derived record to be byte-identical to the
       recorded event payload (the event minus its chain fields
       ``previous_hash``/``event_hash``).

    Returns a dict with ``valid`` (bool), ``chain_valid`` (bool),
    ``events_total``, ``events_matched``, ``events_degraded`` (ints), and
    ``mismatches`` (list of per-event detail dicts). Fail-closed: an invalid
    chain, an unreadable chain, or any single mismatch makes ``valid`` False.
    """
    mismatches: list[dict[str, Any]] = []
    events_total = 0
    events_matched = 0
    events_degraded = 0

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

    # Index the side-store once (last record per event_id wins, matching
    # ReplaySideStore.get) instead of rescanning the whole JSONL file per
    # event — the per-event get() made bundle replay O(events²).
    side_index: dict[str, dict[str, Any]] = {}
    for entry in side_store.iter_records():
        entry_id = entry.get("event_id")
        if isinstance(entry_id, str):
            side_index[entry_id] = entry

    for event in events:
        events_total += 1
        event_id = str(event.get("event_id", ""))
        side_record = side_index.get(event_id)

        if side_record is None or side_record.get("redacted"):
            # Honest degradation: no raw args retained, so only the
            # policy-version check is possible. Never counted as matched.
            fallback = replay_event(event, policy)
            if fallback.matches:
                events_degraded += 1
            else:
                mismatches.append(
                    {
                        "event_id": event_id,
                        "type": "degraded_policy_version_mismatch",
                        "detail": fallback.to_dict(),
                    }
                )
            continue

        semantic, fresh, call = _rederive_from_side_store(event, side_record, policy)
        if not semantic.matches or fresh is None or call is None:
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

        # Byte equivalence: reuse the SAME policy evaluation as the semantic
        # check above (one policy run per event), re-attach the kernel-owned
        # context exactly as Kernel.dispatch does, normalize only the
        # nondeterministic identity fields to the recorded values, and compare
        # canonical JSON bytes.
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
            k: v for k, v in event.items() if k not in ("previous_hash", "event_hash")
        }
        recorded_bytes = canonical_json(recorded_payload).encode("utf-8")
        rederived_bytes = canonical_json(fresh.to_dict()).encode("utf-8")
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
        "mismatches": mismatches,
    }


def find_event(store: ChainHashAuditStore, event_id: str) -> dict[str, Any] | None:
    """Locate an event in the audit store by id."""
    events = store.query(where=lambda e: e.get("event_id") == event_id, limit=1)
    return events[0] if events else None
