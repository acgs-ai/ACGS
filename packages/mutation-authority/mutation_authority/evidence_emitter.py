"""Evidence graph emission.

One evidence record per COMMITTED mutation, appended to
``evidence_graph.jsonl`` and cross-linked to the ledger COMMIT event that
authorized it. Evidence is a projection of the ledger: if the two ever
disagree, the ledger wins and the CI gate fails closed.

No silent mutation events: ``ci_gate`` enforces a bijection between
ledger COMMIT events and evidence records.
"""

from __future__ import annotations

import fcntl
import json
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .canonical import hash_obj, hmac_sign, hmac_verify
from .ledger import EVENT_COMMIT, AuditLedger, LedgerEvent
from .receipt import MutationDecisionReceipt
from .root import GovernanceRoot, RootIntegrityError

POLICY_FILE_KEY = "policy.json"

# Domain-separation label: the evidence-signing key is derived from the root
# key rather than the root key being used directly, so evidence signatures and
# receipt signatures never share key material (defense in depth; cheap).
_EVIDENCE_KEY_LABEL = "mutation-authority/evidence-signing/v1"


def _evidence_key(root: GovernanceRoot) -> bytes:
    return bytes.fromhex(hmac_sign(root.root_key(), _EVIDENCE_KEY_LABEL))


class EvidenceError(Exception):
    """Evidence could not be emitted or resolved. Fail closed."""


def policy_version(root: GovernanceRoot) -> str:
    """Version of the sealed policy = its hash from the signed root manifest."""
    files = root.manifest.get("files", {})
    version = files.get(POLICY_FILE_KEY)
    if not isinstance(version, str):
        raise RootIntegrityError("root manifest carries no policy hash")
    return version


class EvidenceEmitter:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def _write_lock(self) -> Iterator[None]:
        """Exclusive cross-process lock serializing every evidence writer over
        its whole read-check-append sequence. Emission and recovery both
        decide what to append from a snapshot of the evidence file; two
        writers (e.g. gateways committing mutations on different resources)
        that snapshot the same file could both find the same COMMIT records
        missing and append duplicates, which the CI gate's COMMIT-to-evidence
        bijection then rejects. The lock lives in a sidecar file (never the
        evidence file itself, so locking cannot create or truncate it), is
        keyed by the evidence path so it serializes across emitter instances
        and processes, and releases on close (and on process death). On-disk
        state must be re-read while holding the lock."""
        lock_path = self.path.with_name(self.path.name + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            yield

    # -- emission ---------------------------------------------------------

    def emit_for_receipt(
        self,
        root: GovernanceRoot,
        ledger: AuditLedger,
        receipt: MutationDecisionReceipt,
    ) -> dict[str, Any]:
        """Emit the evidence record for a receipt's COMMIT event.

        Looks the COMMIT event up in the ledger (never trusts caller-supplied
        hashes) so the record is guaranteed to describe an effect that the
        audit chain actually contains. Idempotent: if the record already
        exists (e.g. re-emitted by ``recover_missing``), the existing record
        is returned instead of appending a duplicate.
        """
        commit = self._commit_event_for(ledger, receipt.receipt_id)
        if commit is None:
            raise EvidenceError(
                f"no COMMIT event for receipt {receipt.receipt_id}; refusing to fabricate evidence"
            )
        record = self._record_for_commit(root, commit)
        with self._write_lock():
            # Re-read under the lock: another emitter may have appended this
            # record between our snapshot and acquiring the lock.
            for existing in self.records():
                if existing.get("evidence_id") == record["evidence_id"]:
                    return existing
            self._append(record)
        return record

    def recover_missing(self, root: GovernanceRoot, ledger: AuditLedger) -> list[dict[str, Any]]:
        """Re-emit evidence for committed mutations whose records are missing.

        Evidence is a deterministic projection of the ledger (every body field
        and the signature derive from the COMMIT event and the root key), so a
        record whose append failed AFTER the COMMIT succeeded — a full or
        read-only evidence filesystem, for example — is recoverable at any
        later time without re-running the effect. Restores the mandatory
        COMMIT-to-evidence bijection the CI gate enforces."""
        recovered: list[dict[str, Any]] = []
        with self._write_lock():
            # The gap scan and the appends are one serialized operation, and
            # the on-disk state is read while holding the lock: two gateways
            # recovering concurrently must not both decide the same COMMIT
            # records are missing and append duplicates.
            existing = {r.get("receipt_id") for r in self.records()}
            for event in ledger.events():
                if event.type == EVENT_COMMIT and event.payload.get("receipt_id") not in existing:
                    record = self._record_for_commit(root, event)
                    self._append(record)
                    recovered.append(record)
        return recovered

    @staticmethod
    def _record_for_commit(root: GovernanceRoot, commit: LedgerEvent) -> dict[str, Any]:
        body = {
            "actor": commit.payload["actor"],
            "resource": commit.payload["resource"],
            "previous_hash": commit.payload["before_hash"],
            "new_hash": commit.payload["after_hash"],
            "decision": commit.payload["decision"],
            "receipt_id": commit.payload["receipt_id"],
            "policy_version": policy_version(root),
            "authority_chain_ref": {
                "ledger_seq": commit.seq,
                "ledger_event_hash": commit.event_hash,
            },
            "timestamp": commit.timestamp,
        }
        # Root-key HMAC over the body: an attacker with evidence-file write
        # access but no keystore access cannot forge a record for any COMMIT,
        # even though every body field is public ledger data. evidence_id is
        # the (unsecret) content hash for referencing; signature is the
        # authenticity anchor the CI gate actually trusts.
        evidence_id = hash_obj(body)
        signature = hmac_sign(_evidence_key(root), evidence_id)
        return {**body, "evidence_id": evidence_id, "signature": signature}

    def _open_no_follow(self, flags: int) -> int:
        """Open the evidence file relative to a pinned parent-directory fd,
        refusing symlinks (O_NOFOLLOW) and non-regular files.

        The evidence path is attacker-adjacent state: if the projection file
        is swapped for a symlink, a plain ``open(path)`` would follow it and
        write signed evidence records into (or read forged ones from) an
        arbitrary file outside the governed store. Raises OSError on any
        identity failure; callers fail closed.
        """
        parent_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fd = os.open(self.path.name, flags | os.O_NOFOLLOW, 0o644, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(f"evidence file is not a regular file: {self.path}")
        except OSError:
            os.close(fd)
            raise
        return fd

    def _append(self, record: dict[str, Any]) -> None:
        fd = self._open_no_follow(os.O_WRONLY | os.O_APPEND | os.O_CREAT)
        try:
            data = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
        finally:
            os.close(fd)

    @staticmethod
    def verify_record(root: GovernanceRoot, record: dict[str, Any]) -> bool:
        """True iff record body hashes to its evidence_id AND the root-key
        signature over that id verifies. Recomputation, no stored trust."""
        body = {k: v for k, v in record.items() if k not in ("evidence_id", "signature")}
        evidence_id = record.get("evidence_id")
        signature = record.get("signature")
        if not isinstance(evidence_id, str) or not isinstance(signature, str):
            return False
        if hash_obj(body) != evidence_id:
            return False
        return hmac_verify(_evidence_key(root), evidence_id, signature)

    # -- reading ----------------------------------------------------------

    def records(self) -> list[dict[str, Any]]:
        try:
            fd = self._open_no_follow(os.O_RDONLY)
        except FileNotFoundError:
            return []
        try:
            raw = os.pread(fd, os.fstat(fd).st_size, 0)
        finally:
            os.close(fd)
        out: list[dict[str, Any]] = []
        for raw_line in raw.splitlines():
            line = raw_line.strip()
            if line:
                out.append(json.loads(line.decode("utf-8")))
        return out

    @staticmethod
    def _commit_event_for(ledger: AuditLedger, receipt_id: str) -> LedgerEvent | None:
        for event in ledger.events():
            if event.type == EVENT_COMMIT and event.payload.get("receipt_id") == receipt_id:
                return event
        return None
