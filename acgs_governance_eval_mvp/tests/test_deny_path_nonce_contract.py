"""Phase 2 G003: deny-path nonce contract tests.

Covers design test #26 (denied_action_does_not_burn_nonce) with four
distinct scenarios to fully specify the contract:

1. A denied append with nonce_consumed does not burn the nonce — a
   subsequent allow append with the same nonce succeeds.
2. An allowed append burns the nonce — a second allow with the same
   nonce raises NonceReplayError (sanity / setup soundness).
3. Two consecutive denies with the same nonce both succeed and leave
   the nonce unburned (a follow-up allow then works).
4. The on-disk JSONL record for a denied event does not carry a
   nonce_consumed key.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from governance.audit import ChainHashAuditStore, NonceReplayError
from governance.models import ActionRequest, DecisionRecord, Principal


def _decision(
    *,
    event_id: str,
    trace_id: str = "trace-G003",
    session_nonce: str = "nonce-G003-AAA",
    embed_nonce: bool = True,
    allow: bool = True,
    resource: str = "workflow-G003",
    inputs_hash: str = "sha256:G003-test",
) -> DecisionRecord:
    actor = Principal(id="codex:gpt-5", role="implementation-agent", tenant="default")
    request = ActionRequest(
        action_type="governance.receipt.verify",
        resource=resource,
        actor=actor,
        intent="Phase 2 G003 deny-path nonce contract test",
        inputs_hash=inputs_hash,
    )
    return DecisionRecord(
        event_id=event_id,
        tenant="default",
        allow=allow,
        reasons=[] if allow else ["policy denied"],
        reason_codes=[] if allow else ["POLICY_DENY"],
        rule_ids=[],
        checks=[],
        request=request,
        policy_version="policy-test/v1",
        role_version="roles-test/v1",
        decision_state="allow" if allow else "deny",
        nonce_consumed={"trace_id": trace_id, "session_nonce": session_nonce} if embed_nonce else None,
    )


# ---------------------------------------------------------------------------
# 1. Denied append does not burn nonce — allow with same nonce succeeds.
# ---------------------------------------------------------------------------


def test_denied_action_does_not_burn_nonce(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)

    # Deny with nonce_consumed set — must NOT register the nonce.
    denied = store.append(_decision(event_id="deny-1", allow=False, session_nonce="N26-a"))
    assert "nonce_consumed" not in denied

    # Allow with the SAME nonce — must succeed (nonce was not burned).
    allowed = store.append(_decision(event_id="allow-1", allow=True, session_nonce="N26-a"))
    assert allowed["nonce_consumed"] == {"trace_id": "trace-G003", "session_nonce": "N26-a"}

    # Walk events: deny event must lack nonce_consumed, allow must have it.
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    deny_record = json.loads(lines[0])
    allow_record = json.loads(lines[1])
    assert "nonce_consumed" not in deny_record
    assert allow_record["nonce_consumed"] == {"trace_id": "trace-G003", "session_nonce": "N26-a"}

    # Chain integrity is preserved.
    verify = store.verify_chain()
    assert verify["valid"] is True
    assert verify["checked"] == 2


# ---------------------------------------------------------------------------
# 2. Sanity: allow burns nonce — second allow with same nonce raises.
# ---------------------------------------------------------------------------


def test_allow_then_replay_with_same_nonce_raises(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)

    # First allow: nonce is burned.
    store.append(_decision(event_id="allow-1", allow=True, session_nonce="N26-b"))

    # Second allow with the same nonce must raise NonceReplayError.
    with pytest.raises(NonceReplayError):
        store.append(
            _decision(
                event_id="allow-2",
                allow=True,
                session_nonce="N26-b",
                resource="workflow-G003-replay",
            )
        )

    # Only one event written.
    verify = store.verify_chain()
    assert verify["valid"] is True
    assert verify["checked"] == 1


# ---------------------------------------------------------------------------
# 3. Two consecutive denies with the same nonce both succeed; nonce remains
#    unburned; a follow-up allow with that nonce then succeeds too.
# ---------------------------------------------------------------------------


def test_two_consecutive_denies_with_same_nonce_both_succeed(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)

    first = store.append(_decision(event_id="deny-1", allow=False, session_nonce="N26-c"))
    second = store.append(
        _decision(
            event_id="deny-2",
            allow=False,
            session_nonce="N26-c",
            resource="workflow-G003-deny-retry",
        )
    )

    assert "nonce_consumed" not in first
    assert "nonce_consumed" not in second
    # Nonce index must still be empty — nothing was burned.
    assert store._nonce_index == set()

    # A subsequent allow with the same nonce must succeed.
    allowed = store.append(
        _decision(
            event_id="allow-1",
            allow=True,
            session_nonce="N26-c",
            resource="workflow-G003-final-allow",
        )
    )
    assert allowed["nonce_consumed"] == {"trace_id": "trace-G003", "session_nonce": "N26-c"}

    verify = store.verify_chain()
    assert verify["valid"] is True
    assert verify["checked"] == 3


# ---------------------------------------------------------------------------
# 4. On-disk JSONL record for a denied event does not contain nonce_consumed.
# ---------------------------------------------------------------------------


def test_denied_event_persists_without_nonce_field(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)

    store.append(_decision(event_id="deny-1", allow=False, session_nonce="N26-d"))

    raw = path.read_text(encoding="utf-8").strip()
    on_disk = json.loads(raw)
    assert "nonce_consumed" not in on_disk
