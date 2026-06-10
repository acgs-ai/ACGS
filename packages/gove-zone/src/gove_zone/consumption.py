"""Single-use receipt consumption ledger ("approve once, run once").

:meth:`~gove_zone.receipt.DecisionReceipt.verify` is stateless: it proves a
receipt is *valid*, not that it is *fresh*. Without external state, one valid
ALLOW receipt authorizes N executions — replaying the same receipt at
:func:`~gove_zone.executor.execute_with_receipt` re-runs the side effect every
time. This module supplies the missing state: a durable, process-safe ledger of
consumed receipts that the gate checks-and-burns *after* verification passes and
*before* the side effect runs.

Consumption key
---------------

The key is ``receipt.audit_event_hash`` — the chain hash of the audit event
that anchored the deciding :class:`~gove_zone.decision.DecisionRecord`. Every
:meth:`~gove_zone.audit.ChainHashAuditStore.append` produces a unique
``event_hash`` (the payload hashes over ``previous_hash``, so even identical
records at different chain positions differ), which gives the ledger its
semantics: **one audit-anchored decision authorizes at most one execution.**
Re-minting a second receipt from the same approval event (same anchor,
different ``expires_at``/``subject``/signature) does not grant a second run —
the anchor is already burned. A signed receipt cannot be re-keyed by an
attacker: ``audit_event_hash`` is part of the signed payload.

Fail-closed properties
----------------------

* **Burn-before-execute.** The ledger entry is fsync'd to disk under an
  exclusive cross-process lock before the tool runs. Two concurrent presenters
  of the same receipt serialize on the lock; exactly one proceeds, the other
  gets :class:`~gove_zone.errors.ReceiptAlreadyUsedError` before any side
  effect.
* **At-most-once, not exactly-once.** If the tool raises — or the process
  crashes between burn and execution — the receipt stays consumed. Recovery is
  a fresh approval, never a silent replay window.
* **Verification failures do not burn.** The gate consumes only after
  ``receipt.verify`` passes, so presenting a receipt with mismatched args or
  the wrong tenant cannot waste the approval (the deny path burns nothing —
  same contract as the eval-mvp nonce design, ADR-0007).
* **An unreadable or corrupt ledger refuses execution.** If the ledger cannot
  prove a receipt is fresh, the gate does not run the tool
  (:class:`~gove_zone.errors.ConsumptionLedgerError`).

The ledger is **opt-in** at the gate (``consumption_ledger=...``): existing
deployments are unchanged until they pass one. It is an enforcement-side
freshness record, not part of the audit chain — the chain stays the single
tamper-evident decision history, and a ledger entry references its anchoring
``event_hash`` rather than duplicating the record.

Scalability note: ``consume`` re-reads the whole ledger file under the lock on
every call. That is deliberate for v1 — it is immune to stale-cache races
across processes and the file grows by one line per *governed execution*, which
is low-volume by construction. Swap in an indexed store behind the same method
contract if a deployment outgrows it.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from gove_zone._locking import _exclusive_file_lock
from gove_zone.errors import (
    ConsumptionLedgerError,
    ReceiptAlreadyUsedError,
    ReceiptValidationError,
)

if TYPE_CHECKING:
    from gove_zone.receipt import DecisionReceipt

__all__ = ["ReceiptConsumptionLedger"]


class ReceiptConsumptionLedger:
    """Durable, process-safe single-use ledger for decision receipts.

    Usage::

        ledger = ReceiptConsumptionLedger("/var/lib/gove-zone/consumed.jsonl")
        executor = GovernedExecutor(..., consumption_ledger=ledger)
        executor.execute(action, args, receipt)   # runs, burns the receipt
        executor.execute(action, args, receipt)   # ReceiptAlreadyUsedError

    Storage is append-only JSONL beside a ``.lock`` sidecar, serialized with
    the same standard-library file-lock primitive as
    :class:`~gove_zone.audit.ChainHashAuditStore` (``fcntl.flock`` on POSIX,
    ``msvcrt.locking`` on Windows) — no runtime dependency added.

    Durability matches the audit store: entry bytes are fsync'd before the
    lock is released, which survives *process* crashes. On a brand-new ledger
    file the parent **directory entry** is not fsync'd, so a whole-machine
    power loss immediately after the very first burn can lose the file. Treat
    the ledger with the same placement and permissions as the audit chain —
    its entries carry the same decision metadata (actor, action, tenant).
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def consume(self, receipt: DecisionReceipt) -> dict[str, Any]:
        """Atomically burn *receipt*; raise if it was already burned.

        Returns the persisted ledger entry. Raises
        :class:`~gove_zone.errors.ReceiptAlreadyUsedError` if the receipt's
        audit anchor is already in the ledger,
        :class:`~gove_zone.errors.ReceiptValidationError` if the receipt
        carries no audit anchor to key on, and
        :class:`~gove_zone.errors.ConsumptionLedgerError` if the ledger cannot
        be read or written — all three refuse execution at the gate.

        The check-then-append runs under an exclusive cross-process lock and
        the entry is fsync'd before the lock is released, so concurrent
        presenters of the same receipt cannot both pass.
        """
        key = receipt.audit_event_hash
        if not isinstance(key, str) or not key.strip():
            raise ReceiptValidationError(
                "receipt has no audit_event_hash to key single-use consumption "
                "on; refusing execution (fail-closed)"
            )

        entry = {
            "consumed_key": key,
            "receipt_hash": receipt.compute_hash(),
            "request_id": receipt.request_id,
            "tenant_id": receipt.tenant_id,
            "actor": receipt.actor,
            "proposed_action": receipt.proposed_action,
            "consumed_at": datetime.now(UTC).isoformat(),
        }

        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        try:
            with lock_path.open("a+") as lock_fh, _exclusive_file_lock(lock_fh):
                if self._scan_consumed(key):
                    raise ReceiptAlreadyUsedError(key, str(self.path))
                line = (
                    json.dumps(entry, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                    + "\n"
                )
                try:
                    with self.path.open("a", encoding="utf-8") as fh:
                        fh.write(line)
                        fh.flush()
                        os.fsync(fh.fileno())
                except OSError as exc:
                    raise ConsumptionLedgerError(
                        f"could not record receipt consumption in {self.path}: {exc}; "
                        "refusing execution (fail-closed)"
                    ) from exc
        except ReceiptValidationError:
            raise  # ReceiptAlreadyUsedError / ConsumptionLedgerError pass through
        except OSError as exc:
            # Opening or locking the sidecar failed (e.g. flock ENOLCK, Windows
            # lock contention timeout): same taxonomy as any other ledger fault.
            raise ConsumptionLedgerError(
                f"could not acquire the consumption ledger lock {lock_path}: {exc}; "
                "refusing execution (fail-closed)"
            ) from exc
        return entry

    def is_consumed(self, audit_event_hash: str) -> bool:
        """Read-only check whether an audit anchor was already burned.

        Point-in-time only: a concurrent :meth:`consume` may land immediately
        after this returns ``False``. Gates must rely on :meth:`consume` —
        which re-checks under the exclusive lock — never on this helper. The
        read is unlocked, so a torn read of an in-flight append can also
        surface as a transient :class:`~gove_zone.errors.ConsumptionLedgerError`.
        """
        return self._scan_consumed(audit_event_hash)

    def _scan_consumed(self, key: str) -> bool:
        """Scan the ledger for *key*; fail closed on any unreadable state."""
        if not self.path.exists():
            return False
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                for line_number, line in enumerate(fh, start=1):
                    clean = line.strip()
                    if not clean:
                        continue
                    try:
                        record = json.loads(clean)
                    except json.JSONDecodeError as exc:
                        raise ConsumptionLedgerError(
                            f"consumption ledger line {line_number} in {self.path} "
                            f"is not valid JSON: {exc}; cannot prove receipt "
                            "freshness, refusing execution (fail-closed)"
                        ) from exc
                    if not isinstance(record, dict):
                        raise ConsumptionLedgerError(
                            f"consumption ledger line {line_number} in {self.path} "
                            "is not a JSON object; cannot prove receipt freshness, "
                            "refusing execution (fail-closed)"
                        )
                    if record.get("consumed_key") == key:
                        return True
        except OSError as exc:
            raise ConsumptionLedgerError(
                f"could not read consumption ledger {self.path}: {exc}; "
                "cannot prove receipt freshness, refusing execution (fail-closed)"
            ) from exc
        return False
