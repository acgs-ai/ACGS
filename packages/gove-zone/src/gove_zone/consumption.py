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
* **A ledger deleted or truncated below its checkpoint refuses execution.**
  With checkpointing on (``checkpoint=True``), a wiped or below-HWM ledger no
  longer reads as "nothing consumed" — which would silently reopen every burned
  receipt for replay. The persisted ``<ledger>.hwm`` proves a committed tail
  existed; if that high-water-mark ``entry_hash`` is absent from the current file
  the gate fails closed. **Scope of this enforcement-time check (read carefully):**
  it tests HWM/tail *presence*, not full chain *linkage*. It catches **wholesale
  deletion** and **tail truncation below the HWM**, but NOT deletion of an
  *interior* (non-tail) burned entry while the HWM tail stays intact — that
  reopens the deleted entry's receipt at ``consume()`` and is caught only by the
  out-of-band :meth:`verify_ledger` chain check (``previous_hash_mismatch``).
  Interior deletion needs only ledger write, not a sidecar rewrite. Without
  checkpointing (the default) there is no HWM, so no deletion is caught — enable
  ``checkpoint=True`` (ideally with the sidecar on more-protected/append-only
  storage), and run :meth:`verify_ledger` periodically for full tamper coverage.

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

import contextlib
import json
import logging
import os
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from gove_zone._locking import _exclusive_file_lock
from gove_zone.audit import GENESIS_HASH
from gove_zone.decision import sha256_json
from gove_zone.errors import (
    ConsumptionLedgerError,
    ReceiptAlreadyUsedError,
    ReceiptValidationError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from gove_zone.audit import ChainHashAuditStore
    from gove_zone.receipt import DecisionReceipt

__all__ = ["LedgerObservability", "ReceiptConsumptionLedger"]

# Process-logger for the ledger's security-negative events (blocked replays,
# failed verify/reconcile). Mirrors ``gove_zone.integration`` — a *logger record
# only*, never appended to the audit chain — and is the SIEM / stderr
# integration point (WARNING surfaces via logging's last-resort handler even
# with no configured handler). Quiet by default; zero behavior change.
_LOGGER = logging.getLogger("gove_zone.consumption")


@dataclass(frozen=True)
class LedgerObservability:
    """Immutable point-in-time snapshot of a ledger's security counters.

    Returned by :meth:`ReceiptConsumptionLedger.observability`. ``consumed`` is
    the denominator (successful burns); the other three count the
    security-negative events the ledger is meant to surface. Frozen so a caller
    holding an old snapshot cannot corrupt a later read.
    """

    consumed: int = 0
    replays_blocked: int = 0
    verify_failures: int = 0
    reconcile_unmatched: int = 0


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

    def __init__(self, path: str | Path, *, checkpoint: bool = False) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Opt-in durable high-water-mark: when True, every burn advances a
        # ``<ledger>.hwm`` sidecar holding the latest ``entry_hash`` so
        # :meth:`verify_ledger` can detect tail truncation without an
        # externally-supplied ``expected_last_hash``. Off by default — no sidecar
        # is written and behavior is unchanged.
        self.checkpoint = checkpoint
        self._hwm_path = self.path.with_suffix(self.path.suffix + ".hwm")
        # In-process security counters (a side channel for scraping/assertions,
        # never on the enforcement path). Guarded by their own lock because
        # ``verify_ledger``/``reconcile`` run lock-free and may race a concurrent
        # ``consume``; this lock is always acquired alone or *inside* the file
        # lock (never the reverse), so it introduces no lock-ordering cycle.
        self._obs_lock = threading.Lock()
        self._consumed = 0
        self._replays_blocked = 0
        self._verify_failures = 0
        self._reconcile_unmatched = 0

    def observability(self) -> LedgerObservability:
        """Return an immutable snapshot of this instance's security counters.

        Per-instance and process-local: a fresh ledger over the same file starts
        at zero (the durable, fleet-wide surface is the ``gove_zone.consumption``
        logger, which a SIEM consumes). Cheap and lock-guarded; safe to scrape
        concurrently with burns.
        """
        with self._obs_lock:
            return LedgerObservability(
                consumed=self._consumed,
                replays_blocked=self._replays_blocked,
                verify_failures=self._verify_failures,
                reconcile_unmatched=self._reconcile_unmatched,
            )

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
                # One locked scan does both jobs: detect replay AND capture the
                # tail's entry_hash to chain onto — mirroring
                # ``ChainHashAuditStore.append`` reading the last hash inside its
                # own lock so concurrent burns never fork the chain.
                already, last_hash = self._scan_for_consume(key)
                if already:
                    # Count the blocked replay inside the lock (cheap, no I/O),
                    # then raise. The WARNING is emitted AFTER the file lock is
                    # released (the ``except ReceiptAlreadyUsedError`` below) so a
                    # slow/blocking logging handler can never amplify lock-hold
                    # time for other presenters. Counting/logging is a side
                    # effect of the refusal — it never replaces or suppresses it.
                    with self._obs_lock:
                        self._replays_blocked += 1
                    raise ReceiptAlreadyUsedError(key, str(self.path))
                entry["previous_hash"] = last_hash
                # Hash over the entry WITHOUT ``entry_hash`` (it is not present
                # yet), so ``consumed_key`` and every other field — including the
                # chain link — is bound into the digest.
                entry["entry_hash"] = sha256_json(entry)
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
                # Advance the high-water-mark inside the same lock, after the
                # entry is durable. A crash in the tiny window between the two
                # fsyncs leaves the sidecar one entry behind, which verify reports
                # as a conservative last_hash_mismatch. The only undetected case
                # is a truncation that lands exactly on the lagged entry — already
                # subsumed by the shared-storage caveat in the class docstring.
                if self.checkpoint:
                    self._write_checkpoint(str(entry["entry_hash"]))
        except ReceiptAlreadyUsedError as exc:
            # File lock already released by the with-exit before this runs, so
            # the WARNING I/O is off the hot path. The error still escapes
            # unchanged — fail-closed is preserved.
            self._log_replay_blocked(exc.audit_event_hash)
            raise
        except ReceiptValidationError:
            raise  # ConsumptionLedgerError / bare ReceiptValidationError pass through
        except OSError as exc:
            # Opening or locking the sidecar failed (e.g. flock ENOLCK, Windows
            # lock contention timeout): same taxonomy as any other ledger fault.
            raise ConsumptionLedgerError(
                f"could not acquire the consumption ledger lock {lock_path}: {exc}; "
                "refusing execution (fail-closed)"
            ) from exc
        # Count only a fully committed burn (entry durable, lock released cleanly).
        with self._obs_lock:
            self._consumed += 1
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

    @staticmethod
    def _safe_warning(msg: str, *args: object) -> None:
        """Emit a WARNING that can NEVER propagate into the enforcement path.

        Observability is a side channel. stdlib does not wrap a custom handler's
        ``emit()`` (only built-in handlers self-guard via ``handleError``), so a
        misbehaving handler whose ``emit`` raises would otherwise escape and
        *replace* the fail-closed security exception (e.g. turn a clean
        ``ReceiptAlreadyUsedError`` into an unhandled ``RuntimeError``). Swallow
        it here — ``Exception`` only, so ``KeyboardInterrupt``/``SystemExit``
        still propagate.
        """
        with contextlib.suppress(Exception):
            _LOGGER.warning(msg, *args)

    def _log_replay_blocked(self, key: str) -> None:
        """Log a blocked replay. Side channel only — emitted after the file lock
        is released so handler I/O never amplifies lock-hold time; the counter is
        bumped separately inside the lock (see :meth:`consume`)."""
        self._safe_warning(
            "gove-zone consumption replay BLOCKED: audit anchor %s is already "
            "burned in %s (one approval authorizes at most one execution)",
            key,
            self.path,
        )

    def _record_verify_failures(self, failures: list[dict[str, Any]]) -> None:
        """Count + log a failed ``verify_ledger``. Called only when failures > 0."""
        with self._obs_lock:
            self._verify_failures += 1
        self._safe_warning(
            "gove-zone consumption ledger verify FAILED: %d finding(s) %s in %s",
            len(failures),
            sorted({str(f.get("type")) for f in failures}),
            self.path,
        )

    def _record_reconcile_unmatched(self, unmatched: list[dict[str, Any]]) -> None:
        """Count + log a failed ``reconcile``. Called only when unmatched > 0."""
        with self._obs_lock:
            self._reconcile_unmatched += 1
        self._safe_warning(
            "gove-zone consumption ledger reconcile FAILED: %d forged/orphan "
            "burn(s) (consumed_key matches no audit event) in %s",
            len(unmatched),
            self.path,
        )

    def _iter_records(self) -> Iterator[tuple[int, dict[str, Any]]]:
        """Yield ``(line_number, record)`` for each entry; fail closed on any
        unreadable or malformed state.

        Single parse path shared by :meth:`_scan_consumed`,
        :meth:`_scan_for_consume`, :meth:`verify_ledger`, and :meth:`seal`, so
        every reader surfaces the same :class:`~gove_zone.errors.ConsumptionLedgerError`
        taxonomy on a corrupt ledger rather than leaking a raw decode error.
        """
        if not self.path.exists():
            return
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
                    yield line_number, record
        except OSError as exc:
            raise ConsumptionLedgerError(
                f"could not read consumption ledger {self.path}: {exc}; "
                "cannot prove receipt freshness, refusing execution (fail-closed)"
            ) from exc

    def _assert_checkpoint_present(self, hwm: str | None, hwm_seen: bool) -> None:
        """Fail closed when a persisted high-water-mark points at an entry the
        ledger no longer contains.

        Closes the deletion/truncation fail-OPEN: a missing or below-HWM ledger
        used to read as "nothing consumed", silently reopening every burned
        receipt for replay. When checkpointing is on, the ``<ledger>.hwm`` sidecar
        proves a committed tail existed; if its ``entry_hash`` is absent from the
        current file, the ledger was truncated or deleted below the high-water-mark
        and cannot prove receipt freshness — refuse rather than reopen. Tolerant of
        the documented one-entry HWM lag after a crash (the HWM is BEHIND the
        ledger, so its hash is still present).

        This is a *presence* check, not a chain-linkage check: it catches wholesale
        deletion and tail-truncation-below-HWM, but NOT deletion of an interior
        (non-tail) burned entry while the HWM tail survives (that needs only a
        ledger write and is caught only by the out-of-band :meth:`verify_ledger`
        ``previous_hash_mismatch``). A no-op when checkpointing is off (no HWM) —
        the opt-in contract is unchanged.
        """
        if hwm is not None and not hwm_seen:
            raise ConsumptionLedgerError(
                f"consumption ledger {self.path} no longer contains its checkpointed "
                f"high-water-mark entry {hwm[:12]}...; it was truncated or deleted "
                "below the high-water-mark and cannot prove receipt freshness; "
                "refusing execution (fail-closed)"
            )

    def _scan_consumed(self, key: str) -> bool:
        """Scan the ledger for *key*; fail closed on any unreadable state or on a
        ledger truncated below its high-water-mark."""
        hwm = self.checkpoint_hash() if self.checkpoint else None
        found = False
        hwm_seen = False
        for _line_number, record in self._iter_records():
            if record.get("consumed_key") == key:
                found = True
            if hwm is not None and record.get("entry_hash") == hwm:
                hwm_seen = True
        self._assert_checkpoint_present(hwm, hwm_seen)
        return found

    def _scan_for_consume(self, key: str) -> tuple[bool, str]:
        """Single locked scan: return ``(already_consumed, tail_entry_hash)``.

        ``tail_entry_hash`` is the last entry's ``entry_hash`` to chain the next
        burn onto, or :data:`~gove_zone.audit.GENESIS_HASH` when the file is
        empty or its final entry is a pre-chaining legacy line (no
        ``entry_hash``). Mirrors ``ChainHashAuditStore._read_last_hash_from_disk``
        but folds the replay check into the same pass the lock already requires.
        Fails closed (via :meth:`_assert_checkpoint_present`) if the ledger has
        been truncated/deleted below its persisted high-water-mark.
        """
        hwm = self.checkpoint_hash() if self.checkpoint else None
        already = False
        hwm_seen = False
        last_hash = GENESIS_HASH
        for _line_number, record in self._iter_records():
            if record.get("consumed_key") == key:
                already = True
            entry_hash = record.get("entry_hash")
            last_hash = entry_hash if isinstance(entry_hash, str) and entry_hash else GENESIS_HASH
            if hwm is not None and entry_hash == hwm:
                hwm_seen = True
        self._assert_checkpoint_present(hwm, hwm_seen)
        return already, last_hash

    def _write_checkpoint(self, entry_hash: str) -> None:
        """Atomically advance the ``<ledger>.hwm`` sidecar to *entry_hash*.

        Temp write + ``os.replace`` + fsync, so a crash can never leave a
        half-written high-water-mark. Called only from inside the burn/seal lock.
        """
        tmp_path = self._hwm_path.with_suffix(self._hwm_path.suffix + ".tmp")
        try:
            with tmp_path.open("w", encoding="utf-8") as fh:
                fh.write(entry_hash + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, self._hwm_path)
        except OSError as exc:
            tmp_path.unlink(missing_ok=True)
            raise ConsumptionLedgerError(
                f"could not write consumption high-water-mark {self._hwm_path}: {exc}; "
                "refusing execution (fail-closed)"
            ) from exc

    def checkpoint_hash(self) -> str | None:
        """Return the persisted high-water-mark ``entry_hash``, or ``None``.

        ``None`` when no ``<ledger>.hwm`` sidecar exists (checkpointing was never
        enabled, or nothing has been burned yet). :meth:`verify_ledger` consults
        this automatically when no explicit ``expected_last_hash`` is passed.
        """
        try:
            value = self._hwm_path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            # No checkpoint written yet (or removed between calls). Treat a missing
            # sidecar as "no high-water-mark" without a TOCTOU exists()/read race.
            return None
        except OSError as exc:
            raise ConsumptionLedgerError(
                f"could not read consumption high-water-mark {self._hwm_path}: {exc}"
            ) from exc
        return value or None

    def verify_ledger(self, expected_last_hash: str | None = None) -> dict[str, Any]:
        """Re-walk the ledger and report tamper-evidence integrity.

        Twin of :meth:`~gove_zone.audit.ChainHashAuditStore.verify_chain`,
        adapted for in-place migration: leading pre-chaining entries (no
        ``entry_hash``) are counted as ``unverified_legacy`` and skipped, then
        the chained tail is verified link-by-link. Returns::

            {valid, checked, failures, last_hash, unverified_legacy}

        ``failures`` are typed dicts: ``previous_hash_mismatch`` (delete /
        reorder), ``entry_hash_mismatch`` (content tamper),
        ``legacy_after_chain`` (an unchained line interleaved into the chained
        tail), and — when *expected_last_hash* is supplied —
        ``last_hash_mismatch`` (tail truncation against an external
        high-water-mark; chaining alone cannot detect a shorter valid tail).

        A finding, not a gate: this returns a report and never raises on tamper.
        An unreadable / corrupt-JSON ledger still raises
        :class:`~gove_zone.errors.ConsumptionLedgerError` (same contract as
        :meth:`_scan_consumed`).
        """
        previous = GENESIS_HASH
        checked = 0
        unverified_legacy = 0
        failures: list[dict[str, Any]] = []
        seen_chained = False

        for line_number, record in self._iter_records():
            entry_hash = record.get("entry_hash")
            if not isinstance(entry_hash, str) or not entry_hash:
                if seen_chained:
                    failures.append(
                        {
                            "type": "legacy_after_chain",
                            "line": line_number,
                            "consumed_key": record.get("consumed_key"),
                        }
                    )
                else:
                    unverified_legacy += 1
                continue

            seen_chained = True
            checked += 1
            claimed_previous = record.get("previous_hash")
            if claimed_previous != previous:
                failures.append(
                    {
                        "type": "previous_hash_mismatch",
                        "consumed_key": record.get("consumed_key"),
                        "expected": previous,
                        "actual": claimed_previous,
                    }
                )

            payload = {k: v for k, v in record.items() if k != "entry_hash"}
            recomputed = sha256_json(payload)
            if entry_hash != recomputed:
                failures.append(
                    {
                        "type": "entry_hash_mismatch",
                        "consumed_key": record.get("consumed_key"),
                        "expected": recomputed,
                        "actual": entry_hash,
                    }
                )

            previous = entry_hash

        # An explicit argument wins; otherwise fall back to the persisted
        # high-water-mark so tail truncation is caught with no external state.
        effective_expected = (
            expected_last_hash if expected_last_hash is not None else self.checkpoint_hash()
        )
        if effective_expected is not None and previous != effective_expected:
            failures.append(
                {
                    "type": "last_hash_mismatch",
                    "expected": effective_expected,
                    "actual": previous,
                }
            )

        if failures:
            self._record_verify_failures(failures)

        return {
            "valid": len(failures) == 0,
            "checked": checked,
            "failures": failures,
            "last_hash": previous,
            "unverified_legacy": unverified_legacy,
            "checkpoint": effective_expected,
        }

    def reconcile(self, audit_store: ChainHashAuditStore) -> dict[str, Any]:
        """Cross-check every burn against the audit chain (forged-burn detection).

        Hash-chaining proves the ledger was not edited *internally*, but not that
        a ``consumed_key`` was ever a *real* decision. This walks the ledger and
        confirms each ``consumed_key`` is an ``event_hash`` actually present in
        *audit_store* — catching an **orphan / forged burn**: an entry keyed on a
        hash that anchors no audit event (e.g. a fabricated burn written to deny a
        legitimate receipt, or a burn whose audit event was dropped).

        *audit_store* is duck-typed — any object exposing
        ``iter_events()`` yielding dicts with an ``event_hash`` works (the kernel
        passes a :class:`~gove_zone.audit.ChainHashAuditStore`). It is supplied
        per call rather than held on the ledger, so reconciliation stays an
        explicit operator/periodic check and adds no constructor coupling.

        Returns ``{valid, checked, unmatched, audit_events}`` — a report, not a
        gate (mirrors :meth:`verify_ledger`). ``unmatched`` lists the offending
        ``consumed_key``s. An unreadable / corrupt ledger still raises
        :class:`~gove_zone.errors.ConsumptionLedgerError`.

        Limitation: this proves a burn maps to a real audit event; it does not
        prove the *reverse* (that every authorized decision was burned), nor does
        it detect tail truncation — those remain the high-water-mark's job.
        """
        valid_hashes = {
            event["event_hash"]
            for event in audit_store.iter_events()
            if isinstance(event.get("event_hash"), str)
        }

        checked = 0
        unmatched: list[dict[str, Any]] = []
        for line_number, record in self._iter_records():
            checked += 1
            key = record.get("consumed_key")
            if key not in valid_hashes:
                unmatched.append(
                    {
                        "consumed_key": key,
                        "line": line_number,
                        "receipt_hash": record.get("receipt_hash"),
                    }
                )

        if unmatched:
            self._record_reconcile_unmatched(unmatched)

        return {
            "valid": len(unmatched) == 0,
            "checked": checked,
            "unmatched": unmatched,
            "audit_events": len(valid_hashes),
        }

    def seal(self) -> dict[str, Any]:
        """Establish a full hash chain over an existing ledger's contents.

        One-time, operator-invoked migration for ledgers that predate chaining
        (or mix legacy and chained lines): reads every entry in file order under
        the exclusive lock, strips any existing chain fields, and recomputes a
        fresh chain (``previous_hash``/``entry_hash``) over the current content,
        then atomically replaces the file (temp write + ``os.replace`` + fsync)
        so a crash mid-seal cannot leave a partial file. Never called by
        :meth:`consume`; idempotent (re-sealing a sealed ledger reproduces the
        same chain). Returns ``{sealed, last_hash}``.

        Note: ``seal`` establishes tamper-evidence over *current* contents — it
        cannot retroactively prove entries weren't deleted before it ran.
        """
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        try:
            with lock_path.open("a+") as lock_fh, _exclusive_file_lock(lock_fh):
                previous = GENESIS_HASH
                sealed_lines: list[str] = []
                for _line_number, record in self._iter_records():
                    payload = {
                        k: v for k, v in record.items() if k not in ("previous_hash", "entry_hash")
                    }
                    payload["previous_hash"] = previous
                    payload["entry_hash"] = sha256_json(payload)
                    previous = payload["entry_hash"]
                    sealed_lines.append(
                        json.dumps(
                            payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
                        )
                    )

                tmp_path = self.path.with_suffix(self.path.suffix + ".seal-tmp")
                try:
                    with tmp_path.open("w", encoding="utf-8") as fh:
                        for line in sealed_lines:
                            fh.write(line + "\n")
                        fh.flush()
                        os.fsync(fh.fileno())
                    os.replace(tmp_path, self.path)
                except OSError as exc:
                    # os.replace is atomic: on failure the original file is
                    # untouched. Remove the orphan temp so a retry is clean.
                    tmp_path.unlink(missing_ok=True)
                    raise ConsumptionLedgerError(
                        f"could not seal consumption ledger {self.path}: {exc}; "
                        "original ledger left intact"
                    ) from exc
                # Keep the high-water-mark consistent with the freshly sealed tail.
                if self.checkpoint:
                    self._write_checkpoint(previous)
        except ConsumptionLedgerError:
            raise
        except OSError as exc:
            raise ConsumptionLedgerError(
                f"could not acquire the consumption ledger lock {lock_path}: {exc}; seal aborted"
            ) from exc
        return {"sealed": len(sealed_lines), "last_hash": previous}
