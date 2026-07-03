"""TTL-prune tests for the consumption ledger.

``test_consumption_tamper.py`` proves the chain integrity; this file proves
:meth:`~gove_zone.consumption.ReceiptConsumptionLedger.prune` bounds the file
*without weakening fail-closed replay protection*:

* an unexpired (or no-expiry) burn is never pruned and stays blocked;
* an expired burn is removed, re-chained, watermarked;
* the prune time-watermark defeats the clock-rollback replay that a naive prune
  would reopen (the load-bearing security case);
* a corrupt ledger / naive ``now`` fails closed and prunes nothing.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gove_zone import (
    ConsumptionLedgerError,
    ReceiptAlreadyUsedError,
    ReceiptConsumptionLedger,
)
from gove_zone.cli import main

# Fixed instants so prune verdicts are deterministic. PRUNE_NOW sits between the
# "past" expiries (already expired ⇒ prunable) and FUTURE (still valid ⇒ kept).
PAST_A = "2020-01-01T00:00:00+00:00"
PAST_B = "2023-01-01T00:00:00+00:00"
FUTURE = "2099-01-01T00:00:00+00:00"
PRUNE_NOW = datetime(2025, 1, 1, tzinfo=UTC)


@dataclasses.dataclass
class _FakeReceipt:
    """Minimal stand-in exposing only what ``consume`` reads, incl. ``expires_at``."""

    audit_event_hash: str
    expires_at: str = ""
    request_id: str = "req-1"
    tenant_id: str = "tenant-acme"
    actor: str = "agent-x"
    proposed_action: str = "write_file"

    def compute_hash(self) -> str:
        return "receipt-hash-" + self.audit_event_hash[:8]


def _anchor(label: str) -> str:
    return (label * 64)[:64]


def _lines(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


# --- core prune semantics -----------------------------------------------------


def test_unexpired_consumed_receipt_still_blocked_after_prune(tmp_path: Path) -> None:
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    r = _FakeReceipt(_anchor("a"), expires_at=FUTURE)
    ledger.consume(r)

    report = ledger.prune(now=PRUNE_NOW)
    assert report["pruned"] == 0
    assert report["kept"] == 1

    # The freshness record survives, so the replay is still refused.
    with pytest.raises(ReceiptAlreadyUsedError):
        ledger.consume(r)


def test_expired_consumed_entry_removed_by_prune(tmp_path: Path) -> None:
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path)
    r = _FakeReceipt(_anchor("a"), expires_at=PAST_A)
    ledger.consume(r)

    report = ledger.prune(now=PRUNE_NOW)
    assert report["pruned"] == 1
    assert report["kept"] == 0
    assert _lines(path) == []
    assert not ledger.is_consumed(r.audit_event_hash)


def test_no_expiry_entries_are_never_pruned(tmp_path: Path) -> None:
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    # A receipt with no expiry never expires; reopening it would allow replay
    # forever, so it must never be pruned regardless of how far `now` advances.
    ledger.consume(_FakeReceipt(_anchor("a"), expires_at=""))
    report = ledger.prune(now=datetime(9999, 1, 1, tzinfo=UTC))
    assert report["pruned"] == 0
    assert ledger.is_consumed(_anchor("a"))


def test_unparseable_expiry_is_kept(tmp_path: Path) -> None:
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    # Cannot be proven expired ⇒ fail-safe keep (could still pass verify).
    ledger.consume(_FakeReceipt(_anchor("a"), expires_at="not-a-timestamp"))
    report = ledger.prune(now=PRUNE_NOW)
    assert report["pruned"] == 0
    assert ledger.is_consumed(_anchor("a"))


def test_naive_expiry_is_kept(tmp_path: Path) -> None:
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    # Offset-naive expiry compares ambiguously and could fail open ⇒ keep.
    ledger.consume(_FakeReceipt(_anchor("a"), expires_at="2020-01-01T00:00:00"))
    report = ledger.prune(now=PRUNE_NOW)
    assert report["pruned"] == 0
    assert ledger.is_consumed(_anchor("a"))


def test_prune_keeps_unexpired_and_noexpiry_removes_only_expired(tmp_path: Path) -> None:
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ledger.consume(_FakeReceipt(_anchor("a"), expires_at=PAST_A))  # expired
    ledger.consume(_FakeReceipt(_anchor("b"), expires_at=""))  # no expiry
    ledger.consume(_FakeReceipt(_anchor("c"), expires_at=FUTURE))  # still valid

    report = ledger.prune(now=PRUNE_NOW)
    assert report["pruned"] == 1
    assert report["kept"] == 2
    assert not ledger.is_consumed(_anchor("a"))
    assert ledger.is_consumed(_anchor("b"))
    assert ledger.is_consumed(_anchor("c"))


def test_prune_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path)
    ledger.consume(_FakeReceipt(_anchor("a"), expires_at=PAST_A))
    ledger.consume(_FakeReceipt(_anchor("b"), expires_at=FUTURE))

    first = ledger.prune(now=PRUNE_NOW)
    after_first = path.read_text(encoding="utf-8")
    second = ledger.prune(now=PRUNE_NOW)

    assert first["pruned"] == 1
    assert second["pruned"] == 0
    assert second["kept"] == 1
    # A no-op prune leaves the file byte-for-byte untouched.
    assert path.read_text(encoding="utf-8") == after_first


def test_prune_now_must_be_timezone_aware(tmp_path: Path) -> None:
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ledger.consume(_FakeReceipt(_anchor("a"), expires_at=PAST_A))
    with pytest.raises(ConsumptionLedgerError):
        ledger.prune(now=datetime(2025, 1, 1))  # noqa: DTZ001 — naive on purpose


# --- the clock-rollback replay defense (load-bearing) -------------------------


def test_clock_rollback_after_prune_is_blocked_by_watermark(tmp_path: Path) -> None:
    """A naive prune reopens this replay; the watermark must close it.

    Burn R (expires PAST_B), prune at a correct clock (PRUNE_NOW > PAST_B) so the
    entry is removed and the anchor reads un-burned. Now the clock is rolled back
    below PAST_B, so ``receipt.verify`` check 13 would pass again — re-presenting
    R must NOT silently re-burn (that is the replay). The persisted prune
    watermark refuses it fail-closed.
    """
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    r = _FakeReceipt(_anchor("a"), expires_at=PAST_B)
    ledger.consume(r)

    report = ledger.prune(now=PRUNE_NOW)
    assert report["pruned"] == 1
    assert not ledger.is_consumed(r.audit_event_hash)  # entry physically gone

    with pytest.raises(ConsumptionLedgerError):
        ledger.consume(r)  # would have been a fresh (replay) burn without the watermark


def test_watermark_advances_to_max_pruned_and_gates_consume(tmp_path: Path) -> None:
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ledger.consume(_FakeReceipt(_anchor("a"), expires_at=PAST_A))
    ledger.consume(_FakeReceipt(_anchor("b"), expires_at=PAST_B))

    report = ledger.prune(now=PRUNE_NOW)
    assert report["pruned"] == 2
    assert report["watermark"] == PAST_B  # the latest expiry removed
    assert ledger.prune_watermark() == PAST_B

    # A receipt expiring at/under the watermark cannot be proven fresh ⇒ refused…
    with pytest.raises(ConsumptionLedgerError):
        ledger.consume(_FakeReceipt(_anchor("c"), expires_at="2022-06-01T00:00:00+00:00"))
    # …but one expiring after the watermark still burns normally.
    entry = ledger.consume(_FakeReceipt(_anchor("d"), expires_at=FUTURE))
    assert entry["consumed_key"] == _anchor("d")


def test_watermark_never_moves_backwards(tmp_path: Path) -> None:
    # The monotonic guard: pruning an entry whose expiry is OLDER than an
    # already-higher persisted watermark must not lower it. (The normal consume
    # path can't even create this state — a receipt expiring at/under the
    # watermark is refused — so seed the sidecar directly to exercise the guard.)
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path)
    ledger.consume(_FakeReceipt(_anchor("a"), expires_at=PAST_A))
    path.with_suffix(path.suffix + ".pwm").write_text(PAST_B + "\n", encoding="utf-8")

    ledger.prune(now=PRUNE_NOW)  # removes the PAST_A entry
    assert ledger.prune_watermark() == PAST_B  # not lowered to PAST_A


# --- re-chaining + HWM consistency --------------------------------------------


def test_survivors_rechained_and_verify_valid_after_prune(tmp_path: Path) -> None:
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl")
    ledger.consume(_FakeReceipt(_anchor("a"), expires_at=PAST_A))  # pruned
    ledger.consume(_FakeReceipt(_anchor("b"), expires_at=FUTURE))
    ledger.consume(_FakeReceipt(_anchor("c"), expires_at=FUTURE))

    report = ledger.prune(now=PRUNE_NOW)
    assert report["pruned"] == 1
    assert report["kept"] == 2

    verdict = ledger.verify_ledger()
    assert verdict["valid"], verdict["failures"]
    assert ledger.is_consumed(_anchor("b"))
    assert ledger.is_consumed(_anchor("c"))


def test_checkpoint_hwm_advances_with_prune(tmp_path: Path) -> None:
    ledger = ReceiptConsumptionLedger(tmp_path / "consumed.jsonl", checkpoint=True)
    ledger.consume(_FakeReceipt(_anchor("a"), expires_at=PAST_A))  # pruned (was the tail-1)
    ledger.consume(_FakeReceipt(_anchor("b"), expires_at=FUTURE))

    report = ledger.prune(now=PRUNE_NOW)
    assert report["pruned"] == 1
    # HWM tracks the re-chained tail, so scans/verify do not fail closed.
    assert ledger.checkpoint_hash() == report["last_hash"]
    assert ledger.is_consumed(_anchor("b"))
    assert ledger.verify_ledger()["valid"]


def test_corrupt_ledger_fails_closed_on_prune(tmp_path: Path) -> None:
    path = tmp_path / "consumed.jsonl"
    path.write_text("{not valid json\n", encoding="utf-8")
    ledger = ReceiptConsumptionLedger(path)

    with pytest.raises(ConsumptionLedgerError):
        ledger.prune(now=PRUNE_NOW)
    # Original file left intact (prunes nothing on a ledger it cannot read).
    assert path.read_text(encoding="utf-8") == "{not valid json\n"


def test_prune_all_under_checkpoint_does_not_brick_ledger(tmp_path: Path) -> None:
    # Pruning every entry leaves a GENESIS high-water-mark; a fresh receipt must
    # still burn afterwards, not be permanently refused by the deletion guard.
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path, checkpoint=True)
    ledger.consume(_FakeReceipt(_anchor("a"), expires_at=PAST_A))  # the only entry

    report = ledger.prune(now=PRUNE_NOW)
    assert report["pruned"] == 1
    assert report["kept"] == 0

    entry = ledger.consume(_FakeReceipt(_anchor("b"), expires_at=FUTURE))
    assert entry["consumed_key"] == _anchor("b")
    assert ledger.is_consumed(_anchor("b"))
    assert ledger.verify_ledger()["valid"]


def test_corrupt_watermark_fails_closed_on_consume(tmp_path: Path) -> None:
    # A present-but-unparseable .pwm is tamper of the rollback defense; consume
    # must refuse rather than skip the guard (which would reopen a pruned receipt).
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path)
    path.with_suffix(path.suffix + ".pwm").write_text("not-a-timestamp\n", encoding="utf-8")
    with pytest.raises(ConsumptionLedgerError):
        ledger.consume(_FakeReceipt(_anchor("a"), expires_at=FUTURE))


def test_corrupt_watermark_fails_closed_on_prune(tmp_path: Path) -> None:
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path)
    ledger.consume(_FakeReceipt(_anchor("a"), expires_at=PAST_A))  # allowed (no .pwm yet)
    path.with_suffix(path.suffix + ".pwm").write_text("garbage\n", encoding="utf-8")

    with pytest.raises(ConsumptionLedgerError):
        ledger.prune(now=PRUNE_NOW)
    # Prune refused before deleting anything against a corrupt watermark.
    assert ledger.is_consumed(_anchor("a"))


# --- CLI surface --------------------------------------------------------------


def test_cli_prune_ledger_happy_path(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path)
    ledger.consume(_FakeReceipt(_anchor("a"), expires_at=PAST_A))
    ledger.consume(_FakeReceipt(_anchor("b"), expires_at=FUTURE))

    rc = main(["prune-ledger", "--ledger", str(path), "--now", "2025-01-01T00:00:00+00:00"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["pruned"] == 1
    assert out["kept"] == 1
    assert out["watermark"] == PAST_A


def test_cli_prune_ledger_corrupt_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "consumed.jsonl"
    path.write_text("{bad\n", encoding="utf-8")
    rc = main(["prune-ledger", "--ledger", str(path)])
    assert rc == 2
    assert "prune-ledger" in capsys.readouterr().err
