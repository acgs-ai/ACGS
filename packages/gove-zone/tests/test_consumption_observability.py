"""Observability for the consumption ledger's security-negative events.

Replay refusal (``ReceiptAlreadyUsedError``) and integrity-check failures
(``verify_ledger`` / ``reconcile``) are the ledger's load-bearing security
signals — but #114-#122 surfaced them only as a raised exception or a returned
report. An operator running a fleet has no way to *count* how often a burned
receipt was re-presented, or to feed a SIEM when the ledger fails verification.

This adds a side-channel — never on the enforcement path:

* a process-logger (``gove_zone.consumption``) that emits a WARNING on each
  blocked replay, failed ``verify_ledger``, and failed ``reconcile`` (the SIEM /
  stderr integration point, matching ``gove_zone.integration``); and
* a per-instance counter snapshot via ``observability()`` for in-process
  scraping and assertions.

Hard invariant under test: observability is a side effect of the security
decision, never a gate on it. A blocked replay still raises
``ReceiptAlreadyUsedError`` with its structured fields intact; verify/reconcile
still return their reports unchanged.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import threading

import pytest

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    LedgerObservability,
    ReceiptAlreadyUsedError,
    ReceiptConsumptionLedger,
    sha256_json,
)

_LOGGER_NAME = "gove_zone.consumption"


@dataclasses.dataclass
class _FakeReceipt:
    audit_event_hash: str
    request_id: str = "req-1"
    tenant_id: str = "tenant-acme"
    actor: str = "agent-x"
    proposed_action: str = "write_file"

    def compute_hash(self) -> str:
        return "receipt-hash-" + self.audit_event_hash[:8]


def _anchor(label: str) -> str:
    return (label * 64)[:64]


# --- counters ----------------------------------------------------------------


def test_observability_starts_at_zero(tmp_path):
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    obs = ledger.observability()
    assert isinstance(obs, LedgerObservability)
    assert (obs.consumed, obs.replays_blocked, obs.verify_failures, obs.reconcile_unmatched) == (
        0,
        0,
        0,
        0,
    )


def test_consumed_counter_increments_per_burn(tmp_path):
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ledger.consume(_FakeReceipt(_anchor("a")))
    ledger.consume(_FakeReceipt(_anchor("b")))
    obs = ledger.observability()
    assert obs.consumed == 2
    assert obs.replays_blocked == 0


def test_replay_blocked_counter_and_still_raises(tmp_path):
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ledger.consume(_FakeReceipt(_anchor("a")))
    with pytest.raises(ReceiptAlreadyUsedError) as exc:
        ledger.consume(_FakeReceipt(_anchor("a")))
    # The security decision is unchanged: the error carries its structured fields.
    assert exc.value.audit_event_hash == _anchor("a")
    obs = ledger.observability()
    assert obs.replays_blocked == 1
    assert obs.consumed == 1  # the blocked attempt did NOT count as a burn


def test_snapshot_is_immutable_and_independent(tmp_path):
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    first = ledger.observability()
    ledger.consume(_FakeReceipt(_anchor("a")))
    second = ledger.observability()
    # frozen dataclass — cannot be mutated to corrupt a later read
    with pytest.raises(dataclasses.FrozenInstanceError):
        first.consumed = 99  # type: ignore[misc]
    # the earlier snapshot is a point-in-time copy, not a live view
    assert first.consumed == 0
    assert second.consumed == 1


# --- structured logging ------------------------------------------------------


def test_replay_blocked_emits_warning(tmp_path, caplog):
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ledger.consume(_FakeReceipt(_anchor("a")))
    with (
        caplog.at_level(logging.WARNING, logger=_LOGGER_NAME),
        pytest.raises(ReceiptAlreadyUsedError),
    ):
        ledger.consume(_FakeReceipt(_anchor("a")))
    records = [r for r in caplog.records if r.name == _LOGGER_NAME and r.levelno == logging.WARNING]
    assert len(records) == 1
    msg = records[0].getMessage()
    assert "BLOCKED" in msg
    assert _anchor("a") in msg


def test_successful_consume_does_not_warn(tmp_path, caplog):
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        ledger.consume(_FakeReceipt(_anchor("a")))
    assert [
        r for r in caplog.records if r.name == _LOGGER_NAME and r.levelno >= logging.WARNING
    ] == []


# --- verify_ledger failures --------------------------------------------------


def _seed_chained(path, n):
    ledger = ReceiptConsumptionLedger(path)
    for i in range(n):
        ledger.consume(_FakeReceipt(_anchor(chr(ord("a") + i))))
    return ledger


def test_verify_failure_counts_and_warns(tmp_path, caplog):
    path = tmp_path / "consumed.jsonl"
    ledger = _seed_chained(path, 3)
    # Delete an interior line -> previous_hash_mismatch.
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    del records[1]
    path.write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in records), encoding="utf-8"
    )
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        report = ledger.verify_ledger()
    assert report["valid"] is False  # report unchanged by observability
    assert ledger.observability().verify_failures == 1
    warnings = [
        r for r in caplog.records if r.name == _LOGGER_NAME and r.levelno == logging.WARNING
    ]
    assert len(warnings) == 1
    assert "verify" in warnings[0].getMessage().lower()


def test_clean_verify_does_not_count_or_warn(tmp_path, caplog):
    path = tmp_path / "consumed.jsonl"
    ledger = _seed_chained(path, 2)
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        report = ledger.verify_ledger()
    assert report["valid"] is True
    assert ledger.observability().verify_failures == 0
    assert [r for r in caplog.records if r.name == _LOGGER_NAME] == []


# --- reconcile failures ------------------------------------------------------


def _audit_with_events(tmp_path, n):
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    hashes = []
    for i in range(n):
        record = DecisionRecord(
            decision=Decision.ALLOW,
            tool="write_file",
            argument_hash=sha256_json({"i": i}),
            policy_version="v0",
            event_id=f"e{i}",
        )
        hashes.append(str(audit.append(record)["event_hash"]))
    return audit, hashes


def test_reconcile_unmatched_counts_and_warns(tmp_path, caplog):
    audit, hashes = _audit_with_events(tmp_path, 1)
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ledger.consume(_FakeReceipt(hashes[0]))
    ledger.consume(_FakeReceipt(_anchor("f")))  # forged
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        report = ledger.reconcile(audit)
    assert report["valid"] is False
    assert ledger.observability().reconcile_unmatched == 1
    warnings = [
        r for r in caplog.records if r.name == _LOGGER_NAME and r.levelno == logging.WARNING
    ]
    assert len(warnings) == 1
    assert "reconcile" in warnings[0].getMessage().lower()


def test_clean_reconcile_does_not_count_or_warn(tmp_path, caplog):
    audit, hashes = _audit_with_events(tmp_path, 2)
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    for h in hashes:
        ledger.consume(_FakeReceipt(h))
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        report = ledger.reconcile(audit)
    assert report["valid"] is True
    assert ledger.observability().reconcile_unmatched == 0
    assert [r for r in caplog.records if r.name == _LOGGER_NAME] == []


# --- thread-safety -----------------------------------------------------------


def test_concurrent_burns_count_exactly(tmp_path):
    # The counter is touched outside the file lock (verify/reconcile run lock-free),
    # so its mutation must itself be guarded. N threads each burn a DISTINCT key;
    # the final consumed count must be exact under contention.
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    n = 24
    keys = [f"{i:064d}" for i in range(n)]  # 24 distinct 64-char anchors
    barrier = threading.Barrier(n)

    def _burn(k):
        barrier.wait()
        ledger.consume(_FakeReceipt(k))

    threads = [threading.Thread(target=_burn, args=(k,)) for k in keys]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert ledger.observability().consumed == n


# --- fail-closed hardening ----------------------------------------------------


def test_throwing_log_handler_does_not_swallow_replay_error(tmp_path):
    # Hardening the side-channel invariant: even a misbehaving logging handler
    # must NOT mask the fail-closed ReceiptAlreadyUsedError. stdlib logging
    # swallows handler emit() errors (logging.raiseExceptions only prints to
    # stderr), so the security exception still escapes and the replay still
    # counts. Also confirms the log is emitted off the file lock (handler runs
    # in the except clause after the lock is released).
    class _BoomHandler(logging.Handler):
        def emit(self, record):
            raise RuntimeError("logging handler blew up")

    logger = logging.getLogger(_LOGGER_NAME)
    handler = _BoomHandler()
    logger.addHandler(handler)
    try:
        ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
        ledger.consume(_FakeReceipt(_anchor("a")))
        with pytest.raises(ReceiptAlreadyUsedError):
            ledger.consume(_FakeReceipt(_anchor("a")))
        # Counted despite the handler exploding (counter bumped inside the lock,
        # before the log is even attempted).
        assert ledger.observability().replays_blocked == 1
        assert ledger.observability().consumed == 1
    finally:
        logger.removeHandler(handler)
