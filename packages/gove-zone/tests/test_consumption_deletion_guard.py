"""Enforcement-time fail-closed guard against ledger deletion / truncation.

Before this guard, ``consume()`` / ``is_consumed()`` read a *missing or
truncated* ledger as "nothing consumed" (``_iter_records`` returns nothing when
the file is absent), so deleting ``consumed.jsonl`` silently reopened every
previously-burned receipt for replay — a fail-OPEN on the anti-replay control.

When checkpointing is on, the durable ``<ledger>.hwm`` sidecar proves the ledger
*had* a committed tail. The enforcement path now refuses (fail-closed) when that
high-water-mark entry is absent from the current file (deletion / truncation
below the HWM), instead of reopening. It tolerates the documented one-entry HWM
lag after a crash (HWM behind the ledger → its hash is still present), and is a
no-op when checkpointing is off (opt-in contract unchanged; deleting *both*
files remains the documented shared-storage residual).
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from gove_zone import ConsumptionLedgerError, ReceiptConsumptionLedger


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


def _entry_hash_at(path, index: int) -> str:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return json.loads(lines[index])["entry_hash"]


def test_deleted_ledger_with_checkpoint_refuses_replay(tmp_path):
    # Burn "a", then delete the ledger file but keep the .hwm sidecar (the
    # classic "wipe the freshness record" attack). Re-presenting "a" must NOT
    # silently re-burn (replay); it must fail closed.
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path, checkpoint=True)
    ledger.consume(_FakeReceipt(_anchor("a")))
    path.unlink()  # delete the ledger; .hwm sidecar remains
    assert (tmp_path / "consumed.jsonl.hwm").exists()
    with pytest.raises(ConsumptionLedgerError):
        ledger.consume(_FakeReceipt(_anchor("a")))
    # The refusal must not have re-created/re-burned the ledger.
    assert not path.exists()


def test_deleted_ledger_with_checkpoint_refuses_fresh_receipt(tmp_path):
    # A broken (truncated) ledger cannot prove ANY receipt fresh — even a
    # never-seen one — so a fresh anchor must also fail closed, not be admitted.
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path, checkpoint=True)
    ledger.consume(_FakeReceipt(_anchor("a")))
    path.unlink()
    with pytest.raises(ConsumptionLedgerError):
        ledger.consume(_FakeReceipt(_anchor("c")))


def test_truncated_below_hwm_refuses(tmp_path):
    # Burn a, b (HWM -> hash(b)); strip the last line so the HWM entry is gone.
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path, checkpoint=True)
    ledger.consume(_FakeReceipt(_anchor("a")))
    ledger.consume(_FakeReceipt(_anchor("b")))
    first_line = path.read_text(encoding="utf-8").splitlines()[0]
    path.write_text(first_line + "\n", encoding="utf-8")  # drop b; HWM still hash(b)
    with pytest.raises(ConsumptionLedgerError):
        ledger.consume(_FakeReceipt(_anchor("c")))


def test_benign_hwm_lag_still_consumes(tmp_path):
    # The documented crash window leaves the HWM one entry BEHIND the ledger
    # (its hash is still present). That must NOT trip the guard.
    path = tmp_path / "consumed.jsonl"
    hwm_path = tmp_path / "consumed.jsonl.hwm"
    ledger = ReceiptConsumptionLedger(path, checkpoint=True)
    ledger.consume(_FakeReceipt(_anchor("a")))
    ledger.consume(_FakeReceipt(_anchor("b")))
    hwm_path.write_text(_entry_hash_at(path, 0) + "\n", encoding="utf-8")  # roll HWM back to a
    entry = ledger.consume(_FakeReceipt(_anchor("c")))  # must succeed
    assert entry["consumed_key"] == _anchor("c")


def test_checkpoint_disabled_deletion_is_unchanged(tmp_path):
    # Opt-in contract: with checkpointing OFF there is no HWM to compare against,
    # so deletion behaves exactly as before (documented limitation). Pinning this
    # ensures the guard never changes behavior for non-checkpointed ledgers.
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path, checkpoint=False)
    ledger.consume(_FakeReceipt(_anchor("a")))
    path.unlink()
    entry = ledger.consume(_FakeReceipt(_anchor("a")))  # no HWM -> no guard -> re-burns
    assert entry["consumed_key"] == _anchor("a")


def test_is_consumed_refuses_on_truncation_with_checkpoint(tmp_path):
    # The read-only helper must surface the same fail-closed signal as consume().
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path, checkpoint=True)
    ledger.consume(_FakeReceipt(_anchor("a")))
    path.unlink()
    with pytest.raises(ConsumptionLedgerError):
        ledger.is_consumed(_anchor("a"))


def test_interior_deletion_caught_by_verify_not_by_consume(tmp_path):
    # Documents the enforcement gate's SCOPE: it checks HWM/tail *presence*, not
    # full chain *linkage*. Deleting an INTERIOR (non-tail) burned entry while the
    # HWM tail survives is NOT caught by consume() (the deleted receipt reopens) —
    # only the out-of-band verify_ledger() chain check flags it. Pinned so that a
    # future change closing this gap at enforcement time is a deliberate,
    # visible behavior change rather than a silent one.
    path = tmp_path / "consumed.jsonl"
    ledger = ReceiptConsumptionLedger(path, checkpoint=True)
    ledger.consume(_FakeReceipt(_anchor("a")))
    ledger.consume(_FakeReceipt(_anchor("b")))
    ledger.consume(_FakeReceipt(_anchor("c")))  # tail "c" == HWM
    lines = path.read_text(encoding="utf-8").splitlines()
    # drop the interior "a" entry; the tail ("c") and the HWM stay intact
    path.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")

    # Out-of-band integrity check DOES catch the broken chain.
    assert ledger.verify_ledger()["valid"] is False

    # consume() does NOT (the HWM tail is still present) — the deleted receipt
    # reopens. Asserting the CURRENT documented limitation, not endorsing it.
    entry = ledger.consume(_FakeReceipt(_anchor("a")))
    assert entry["consumed_key"] == _anchor("a")
