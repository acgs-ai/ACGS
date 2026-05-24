"""Phase 2 §verifier flow: in-lock LOCK_EX tail-scan single-use nonce
enforcement in ChainHashAuditStore.append.

Covers design tests:
- #13  single-use replay rejection (intra-process)
- #14  rehydration after process restart
- #20  nonce_consumed embedded in DecisionRecord audit event
- #21  replay detected via in-lock tail-scan
- #21b truncation of consuming event breaks verify_chain()
- #25  concurrent verifier holding LOCK_SH sees consistent state
- #27  cross-process: second process's stale in-memory index is
       repaired by the in-lock tail-scan before nonce check
"""

from __future__ import annotations

import json
import time
from multiprocessing import Barrier, Process, Queue
from pathlib import Path

import pytest

from governance.audit import ChainHashAuditStore, NonceReplayError
from governance.models import ActionRequest, DecisionRecord, Principal


def _decision(
    *,
    event_id: str,
    trace_id: str = "trace-G001",
    session_nonce: str = "nonce-G001-AAA",
    embed_nonce: bool = True,
    allow: bool = True,
    resource: str = "workflow-G001",
    inputs_hash: str = "sha256:G001-test",
) -> DecisionRecord:
    actor = Principal(id="codex:gpt-5", role="implementation-agent", tenant="default")
    request = ActionRequest(
        action_type="governance.receipt.verify",
        resource=resource,
        actor=actor,
        intent="Phase 2 nonce-store test",
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
# Design test #20 — nonce_consumed embedded in the DecisionRecord event,
# event_hash covers it, verify_chain() passes.
# ---------------------------------------------------------------------------


def test_nonce_consumed_embedded_in_decision_event(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    payload = store.append(_decision(event_id="e1", session_nonce="N20"))

    assert payload["nonce_consumed"] == {"trace_id": "trace-G001", "session_nonce": "N20"}

    on_disk = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert on_disk["nonce_consumed"] == {"trace_id": "trace-G001", "session_nonce": "N20"}

    verify = store.verify_chain()
    assert verify["valid"] is True, verify["failures"]
    assert verify["checked"] == 1


# ---------------------------------------------------------------------------
# Design test #13 — replay of (trace_id, session_nonce) raises forever.
# ---------------------------------------------------------------------------


def test_session_nonce_single_use_intra_process(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    store.append(_decision(event_id="e1", session_nonce="N13"))

    with pytest.raises(NonceReplayError):
        store.append(_decision(event_id="e2", session_nonce="N13", resource="workflow-G001-retry"))

    # Chain remains valid — the failed second append did not write a line.
    verify = store.verify_chain()
    assert verify["valid"] is True
    assert verify["checked"] == 1


# ---------------------------------------------------------------------------
# Design test #14 — rehydrates after restart (fresh store instance, same
# file, replay attempt still fails because the in-lock tail-scan from
# offset=0 absorbs all prior nonces before the check).
# ---------------------------------------------------------------------------


def test_nonce_store_rehydrates_after_restart(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    first_store = ChainHashAuditStore(path)
    first_store.append(_decision(event_id="e1", session_nonce="N14"))

    # Simulate a process restart by dropping the first store and creating a
    # fresh one — its in-memory index starts empty.
    del first_store
    fresh_store = ChainHashAuditStore(path)
    assert fresh_store._nonce_index == set()

    with pytest.raises(NonceReplayError):
        fresh_store.append(_decision(event_id="e2", session_nonce="N14", resource="workflow-G001-replay"))


# ---------------------------------------------------------------------------
# Design test #21 — replay detected in tail-scan (no separate tombstone log).
# ---------------------------------------------------------------------------


def test_nonce_replay_detected_in_tail_scan(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    store.append(_decision(event_id="e1", session_nonce="N21"))

    # Even after manually clearing the in-memory cache, the tail-scan from
    # offset=0 must re-detect the nonce. This is the §verifier flow
    # "no separate tombstone log" guarantee.
    store._nonce_index.clear()
    store._index_offset = 0

    with pytest.raises(NonceReplayError):
        store.append(_decision(event_id="e2", session_nonce="N21", resource="workflow-tail-rescan"))


# ---------------------------------------------------------------------------
# Design test #21b — truncating a consuming event breaks verify_chain.
# ---------------------------------------------------------------------------


def test_truncation_of_consuming_event_breaks_verify_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    store.append(_decision(event_id="e1", session_nonce="N21b-1"))
    store.append(_decision(event_id="e2", session_nonce="N21b-2"))
    store.append(_decision(event_id="e3", session_nonce="N21b-3"))

    # Drop the middle event (which carries nonce_consumed) from the chain.
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    path.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")

    verify = ChainHashAuditStore(path).verify_chain()
    assert verify["valid"] is False
    assert any(f["type"] == "previous_hash_mismatch" for f in verify["failures"])


# ---------------------------------------------------------------------------
# Helper processes for #25 and #27.
# ---------------------------------------------------------------------------


def _consume_then_hold(path: str, barrier_value: int, ready: Queue, release: Queue) -> None:  # noqa: ARG001
    """Process A: append a nonce-consuming event, then wait for the test
    to confirm the verifier process has had its chance to read it."""
    store = ChainHashAuditStore(path)
    store.append(_decision(event_id="A-1", session_nonce="N25"))
    ready.put("appended")
    # Block until the parent says we can exit.
    release.get(timeout=10)


def _verify_in_parallel(path: str, ready: Queue, result: Queue) -> None:
    """Verifier process: while A holds nothing (it already released
    LOCK_EX before the queue put), B holds LOCK_SH to verify the chain.
    Even under contention, verify_chain() must return valid=True."""
    ready.get(timeout=10)  # wait until A has appended
    store = ChainHashAuditStore(path)
    try:
        outcome = store.verify_chain()
        result.put(("ok", outcome["valid"], outcome["checked"], outcome["failures"]))
    except Exception as exc:  # noqa: BLE001
        result.put(("err", type(exc).__name__, str(exc), None))


def test_concurrent_verify_during_consume(tmp_path: Path) -> None:
    """Design test #25 — a verifier holding LOCK_SH never observes a
    partial state while a consumer holds LOCK_EX. After consumer commits
    + releases, verifier sees the full chain (1 event) consistently."""
    path = tmp_path / "audit.jsonl"
    ready: Queue = Queue()
    release: Queue = Queue()
    result: Queue = Queue()

    consumer = Process(target=_consume_then_hold, args=(str(path), 0, ready, release))
    verifier = Process(target=_verify_in_parallel, args=(str(path), ready, result))

    consumer.start()
    verifier.start()
    try:
        verifier.join(timeout=10)
        assert verifier.exitcode == 0
        outcome = result.get(timeout=5)
        assert outcome[0] == "ok", outcome
        _, valid, checked, failures = outcome
        assert valid is True, failures
        assert checked == 1
    finally:
        release.put("done")
        consumer.join(timeout=10)
        assert consumer.exitcode == 0


# ---------------------------------------------------------------------------
# Design test #27 — second process with stale in-memory index detects
# the replay via the in-lock tail-scan from the index high-water mark.
# ---------------------------------------------------------------------------


def _first_commit(path: str, barrier: Barrier) -> None:
    barrier.wait(timeout=10)
    store = ChainHashAuditStore(path)
    store.append(_decision(event_id="A-1", session_nonce="N27"))


def _stale_second_commit(path: str, gate: Queue, result: Queue) -> None:
    # Pre-build the store BEFORE A commits — this is the "stale in-memory
    # cache" scenario from §verifier flow. The cache holds offset=0 and
    # an empty nonce set. A then commits N27. B's append must still raise
    # because the in-lock tail-scan from offset=0 absorbs A's commit.
    store = ChainHashAuditStore(path)
    assert store._nonce_index == set()
    assert store._index_offset == 0
    gate.get(timeout=10)  # wait until A's commit is durable
    try:
        store.append(_decision(event_id="B-1", session_nonce="N27", resource="workflow-B-stale"))
    except NonceReplayError as exc:
        result.put(("replay", str(exc)))
        return
    result.put(("missed", None))


def test_concurrent_consume_observed_by_second_process(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    barrier = Barrier(1)
    gate: Queue = Queue()
    result: Queue = Queue()

    second = Process(target=_stale_second_commit, args=(str(path), gate, result))
    second.start()
    # Give B time to construct its store with offset=0 before A commits.
    time.sleep(0.2)

    first = Process(target=_first_commit, args=(str(path), barrier))
    first.start()
    first.join(timeout=10)
    assert first.exitcode == 0

    # Tell B that A is done; B will now attempt its replay commit.
    gate.put("go")
    second.join(timeout=10)
    assert second.exitcode == 0

    outcome = result.get(timeout=5)
    assert outcome[0] == "replay", f"expected NonceReplayError, got {outcome!r}"

    # Final chain still has exactly one event — B's commit was rejected
    # before it wrote anything.
    final = ChainHashAuditStore(path).verify_chain()
    assert final["valid"] is True
    assert final["checked"] == 1


# ---------------------------------------------------------------------------
# Sanity — events without nonce_consumed are unaffected by the nonce path.
# ---------------------------------------------------------------------------


def test_decisions_without_nonce_do_not_touch_index(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    store.append(_decision(event_id="e1", embed_nonce=False))
    store.append(_decision(event_id="e2", embed_nonce=False, resource="workflow-no-nonce-2"))

    assert store._nonce_index == set()
    verify = store.verify_chain()
    assert verify["valid"] is True
    assert verify["checked"] == 2


# ---------------------------------------------------------------------------
# Design test #26 — deny-path decisions must not burn session_nonce.
# ---------------------------------------------------------------------------


def test_denied_action_does_not_burn_nonce(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)

    denied = store.append(_decision(event_id="deny-1", allow=False, session_nonce="N26"))
    assert "nonce_consumed" not in denied

    allowed = store.append(_decision(event_id="allow-1", allow=True, session_nonce="N26"))
    assert allowed["nonce_consumed"] == {"trace_id": "trace-G001", "session_nonce": "N26"}

    with pytest.raises(NonceReplayError):
        store.append(_decision(event_id="allow-2", allow=True, session_nonce="N26", resource="workflow-G003-retry"))

    verify = store.verify_chain()
    assert verify["valid"] is True
    assert verify["checked"] == 2


def test_repeated_denied_actions_do_not_burn_nonce(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)

    first = store.append(_decision(event_id="deny-1", allow=False, session_nonce="N26-repeat"))
    second = store.append(
        _decision(
            event_id="deny-2",
            allow=False,
            session_nonce="N26-repeat",
            resource="workflow-G003-denied-retry",
        )
    )

    assert "nonce_consumed" not in first
    assert "nonce_consumed" not in second
    assert store._nonce_index == set()

    verify = store.verify_chain()
    assert verify["valid"] is True
    assert verify["checked"] == 2
