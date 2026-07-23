"""Append-only JSONL audit store with hash chaining.

Ported from ``acgs_governance_eval_mvp/governance/audit/jsonl_chain.py``.
Process-safe via ``fcntl.flock`` when that lock primitive is available. Importing
the package does not require ``fcntl``; append support on platforms without a
safe lock primitive remains deferred.

Chain rules:

- ``previous_hash`` of event N links to ``event_hash`` of event N-1.
- The first event's ``previous_hash`` is :data:`GENESIS_HASH` (64 zeros).
- ``event_hash`` is ``sha256(canonical_json(payload))`` where ``payload`` is
  the full event dict minus ``event_hash`` itself.

Concurrent writers are serialized through an exclusive lock on a sidecar
``.lock`` file so two appends never produce sibling events that share a
``previous_hash``.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Generator, Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TextIO, TypeGuard, TypeVar, runtime_checkable

from gove_zone.decision import DecisionRecord, canonical_json, sha256_json
from gove_zone.errors import AuditError
from gove_zone.path_capability import (
    AttestedDirectory,
    is_proc_fd_path,
    require_attested_directory,
    validate_direct_file_path,
)
from gove_zone.signing import ReceiptSigner

GENESIS_HASH = "0" * 64
GENESIS_CHECKPOINT_HASH = GENESIS_HASH
_CHECKPOINT_DOMAIN = b"gove-zone:audit-checkpoint:v1\x00"
_CHECKPOINT_PARENT_FIELD = "_audit_checkpoint_parent_hash"
_T = TypeVar("_T")


class AuditChainError(AuditError):
    """Raised when the persisted audit chain tail is corrupt or unreadable."""


@dataclass(frozen=True, slots=True)
class AuditCheckpoint:
    """Signed external commitment to one exact audit-chain generation."""

    namespace: str
    generation: int
    head_hash: str
    previous_checkpoint_hash: str
    key_id: str
    algorithm: str
    signature: str

    def signing_payload(self) -> bytes:
        """Return the domain-separated canonical bytes covered by the signature."""
        return _CHECKPOINT_DOMAIN + canonical_json(self._unsigned_dict()).encode("utf-8")

    @property
    def checkpoint_hash(self) -> str:
        """Content hash used to link the next signed checkpoint."""
        return sha256_json(self.to_dict())

    def _unsigned_dict(self) -> dict[str, str | int]:
        return {
            "namespace": self.namespace,
            "generation": self.generation,
            "head_hash": self.head_hash,
            "previous_checkpoint_hash": self.previous_checkpoint_hash,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
        }

    def to_dict(self) -> dict[str, str | int]:
        return {**self._unsigned_dict(), "signature": self.signature}


@dataclass(frozen=True, slots=True)
class AuditCommit:
    """Proof that one exact event was fsync'd and externally checkpointed."""

    event_id: str
    event_hash: str
    event: dict[str, Any]
    checkpoint: AuditCheckpoint


@dataclass(frozen=True, slots=True)
class _AuditCommitSnapshot:
    """Deep canonical, immutable view of caller-owned commit material."""

    event_id: str
    event_hash: str
    embedded_event_hash: object
    canonical_event: str
    canonical_event_body: bytes
    checkpoint: AuditCheckpoint


def _snapshot_audit_commit(commit: AuditCommit) -> _AuditCommitSnapshot:
    if type(commit) is not AuditCommit:
        raise AuditChainError("invalid audit commit object")
    try:
        canonical_snapshot = canonical_json(
            {
                "event_id": commit.event_id,
                "event_hash": commit.event_hash,
                "event": commit.event,
                "checkpoint": commit.checkpoint.to_dict(),
            }
        )
        decoded = json.loads(canonical_snapshot)
        if type(decoded) is not dict or set(decoded) != {
            "event_id",
            "event_hash",
            "event",
            "checkpoint",
        }:
            raise ValueError("invalid audit commit snapshot shape")
        event = decoded["event"]
        checkpoint_data = decoded["checkpoint"]
        if type(event) is not dict or type(checkpoint_data) is not dict:
            raise ValueError("invalid audit commit nested snapshot shape")
        if set(checkpoint_data) != {
            "namespace",
            "generation",
            "head_hash",
            "previous_checkpoint_hash",
            "key_id",
            "algorithm",
            "signature",
        }:
            raise ValueError("invalid audit checkpoint snapshot shape")
        event_without_hash = dict(event)
        embedded_event_hash = event_without_hash.pop("event_hash", None)
        checkpoint = AuditCheckpoint(
            namespace=checkpoint_data["namespace"],
            generation=checkpoint_data["generation"],
            head_hash=checkpoint_data["head_hash"],
            previous_checkpoint_hash=checkpoint_data["previous_checkpoint_hash"],
            key_id=checkpoint_data["key_id"],
            algorithm=checkpoint_data["algorithm"],
            signature=checkpoint_data["signature"],
        )
        return _AuditCommitSnapshot(
            event_id=decoded["event_id"],
            event_hash=decoded["event_hash"],
            embedded_event_hash=embedded_event_hash,
            canonical_event=canonical_json(event),
            canonical_event_body=canonical_json(event_without_hash).encode("utf-8"),
            checkpoint=checkpoint,
        )
    except Exception as exc:
        raise AuditChainError("audit commit canonical snapshot failed") from exc


@runtime_checkable
class AuditCheckpointAnchor(Protocol):
    """Trusted monotonic store for signed audit checkpoints.

    JSONL append and anchor publication cannot be atomic. Implementations must
    durably reject rollback of their own state. Any false or indeterminate CAS
    result therefore poisons the writer instead of being auto-reconciled.
    """

    def read(self, namespace: str) -> AuditCheckpoint | None: ...

    def compare_and_swap(
        self,
        namespace: str,
        expected: AuditCheckpoint | None,
        replacement: AuditCheckpoint,
    ) -> bool: ...


@contextmanager
def _exclusive_file_lock(lock_fh: TextIO) -> Generator[None, None, None]:
    """Hold an exclusive process lock for platforms with ``fcntl`` support."""
    try:
        import fcntl
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "ChainHashAuditStore append requires a platform file-lock primitive; "
            "fcntl is unavailable on this host, so audit append support is deferred."
        ) from exc

    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


class ChainHashAuditStore:
    """Append-only JSONL audit store with cryptographic chain hashing.

    Usage::

        store = ChainHashAuditStore("/var/log/gove-zone/audit.jsonl")
        store.append(decision_record)
        result = store.verify_chain()
        assert result["valid"]
    """

    def __init__(
        self,
        path: str | Path,
        *,
        checkpoint_anchor: AuditCheckpointAnchor | None = None,
        checkpoint_namespace: str | None = None,
        checkpoint_signer: ReceiptSigner | None = None,
        checkpoint_verifier: ReceiptSigner | Mapping[str, ReceiptSigner] | None = None,
        require_trusted_checkpoint: bool = False,
        _attested_directory: AttestedDirectory | None = None,
        _attested_relative: str | None = None,
    ) -> None:
        self.path = Path(path)
        self._attested_directory = _attested_directory
        self._attested_relative = _attested_relative
        if _attested_directory is None:
            self.path = validate_direct_file_path(
                self.path,
                error_type=AuditChainError,
                create_parent=True,
            )
        else:
            require_attested_directory(_attested_directory, error_type=AuditChainError)
            _attested_directory.checkpoint()
        self._last_hash: str | None = None
        self._checkpoint_anchor = checkpoint_anchor
        self._checkpoint_namespace = checkpoint_namespace
        self._checkpoint_signer = checkpoint_signer
        self._checkpoint_verifier = (
            checkpoint_verifier if checkpoint_verifier is not None else checkpoint_signer
        )
        self._require_trusted_checkpoint = require_trusted_checkpoint
        self._checkpoint_poisoned = False

        if checkpoint_anchor is None:
            if require_trusted_checkpoint:
                raise AuditChainError("trusted audit checkpoint is required but not configured")
            if checkpoint_namespace is not None or checkpoint_signer is not None:
                raise AuditChainError(
                    "checkpoint namespace or signer configured without an external anchor"
                )
            if checkpoint_verifier is not None:
                raise AuditChainError("checkpoint verifier configured without an external anchor")
            return

        if not isinstance(checkpoint_anchor, AuditCheckpointAnchor):
            raise AuditChainError("checkpoint_anchor does not implement the anchor protocol")
        self._checkpoint_namespace = _validated_text(
            checkpoint_namespace,
            "checkpoint_namespace",
        )
        if self._checkpoint_verifier is None:
            raise AuditChainError("checkpoint verifier is required with an external anchor")
        if checkpoint_signer is not None:
            _validated_signer(checkpoint_signer)
        self._initialize_checkpoint_mode()

    @classmethod
    def from_attested(
        cls,
        directory: AttestedDirectory,
        relative: str,
        **kwargs: Any,
    ) -> ChainHashAuditStore:
        """Borrow *directory* and bind this store to one relative audit file."""
        require_attested_directory(directory, error_type=AuditChainError)
        directory.checkpoint()
        directory.proc_path(relative)
        return cls(
            directory.display_path / relative,
            _attested_directory=directory,
            _attested_relative=relative,
            **kwargs,
        )

    def _storage_path(self) -> Path:
        directory = self._attested_directory
        relative = self._attested_relative
        if directory is None or relative is None:
            return validate_direct_file_path(
                self.path,
                error_type=AuditChainError,
                create_parent=False,
            )
        require_attested_directory(directory, error_type=AuditChainError)
        directory.checkpoint()
        return directory.proc_path(relative)

    def _lock_path(self) -> Path:
        directory = self._attested_directory
        relative = self._attested_relative
        if directory is None or relative is None:
            path = self._storage_path()
            return validate_direct_file_path(
                path.with_suffix(path.suffix + ".lock"),
                error_type=AuditChainError,
                create_parent=False,
            )
        require_attested_directory(directory, error_type=AuditChainError)
        directory.checkpoint()
        return directory.proc_path(relative + ".lock")

    def append(self, decision: DecisionRecord) -> dict[str, Any]:
        """Append *decision* and return the persisted event dict.

        Serializes read-then-write under an exclusive platform file lock so
        concurrent callers never produce sibling events pointing at the same
        ``previous_hash``. Writes are fsync'd before the lock is released.
        """
        if self._checkpoint_anchor is not None:
            return dict(self.append_committed(decision).event)

        lock_path = self._lock_path()
        with lock_path.open("a+") as lock_fh, _exclusive_file_lock(lock_fh):
            # Always re-read while holding the lock. This instance may
            # have appended earlier, then another store/process may have
            # advanced the chain before this append.
            previous_hash = self._read_last_hash_from_disk()
            payload = decision.to_dict()
            payload["previous_hash"] = previous_hash
            payload.pop("event_hash", None)
            payload["event_hash"] = sha256_json(payload)

            line = (
                json.dumps(
                    payload,
                    sort_keys=True,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )
            with self._storage_path().open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
            self._last_hash = str(payload["event_hash"])
        return payload

    def append_committed(self, decision: DecisionRecord) -> AuditCommit:
        """Fsync one event and publish its signed external checkpoint.

        The file append necessarily precedes external CAS. A false or unknown
        CAS outcome leaves disk ahead of the anchor and permanently fail-stops
        this store instance. The method never rewrites or silently repairs that
        split-brain state.
        """
        if self._checkpoint_anchor is None:
            raise AuditChainError("append_committed requires a trusted checkpoint anchor")
        signer = self._checkpoint_signer
        if signer is None:
            raise AuditChainError("checkpoint signer is required for committed append")

        lock_path = self._lock_path()
        with lock_path.open("a+") as lock_fh, _exclusive_file_lock(lock_fh):
            current = self._assert_checkpoint_state_locked()
            payload = decision.to_dict()
            payload["previous_hash"] = current.head_hash
            payload[_CHECKPOINT_PARENT_FIELD] = current.checkpoint_hash
            payload.pop("event_hash", None)
            payload["event_hash"] = sha256_json(payload)
            event_hash = _validated_sha256(payload["event_hash"], "event_hash")
            event_id = _validated_text(payload.get("event_id"), "event_id")
            replacement = self._signed_checkpoint(
                generation=current.generation + 1,
                head_hash=event_hash,
                previous_checkpoint_hash=current.checkpoint_hash,
            )

            try:
                self._write_event_locked(payload)
            except Exception as exc:
                self._checkpoint_poisoned = True
                raise AuditChainError(
                    "audit append durability outcome is unknown; store is fail-stopped"
                ) from exc
            self._publish_checkpoint(current, replacement)
            self._last_hash = event_hash
            return AuditCommit(
                event_id=event_id,
                event_hash=event_hash,
                event=dict(payload),
                checkpoint=replacement,
            )

    def run_if_committed(self, commit: AuditCommit, callback: Callable[[], _T]) -> _T:
        """Run *callback* only for an exact signed commit in the trusted chain.

        Current full-chain verification, signed-anchor verification, exact
        generation-indexed event matching, and the callback occur under the
        same sidecar lock. A later append leaves an exact signed ancestor valid
        while never racing between final verification and the guarded callback.
        """
        if not callable(callback):
            raise AuditChainError("committed audit callback must be callable")
        snapshot = _snapshot_audit_commit(commit)
        _validated_text(snapshot.event_id, "commit.event_id")
        _validated_sha256(snapshot.event_hash, "commit.event_hash")

        lock_path = self._lock_path()
        with lock_path.open("a+") as lock_fh, _exclusive_file_lock(lock_fh):
            current = self._assert_checkpoint_state_locked()
            self._validate_checkpoint(snapshot.checkpoint)
            snapshot_event_hash = hashlib.sha256(snapshot.canonical_event_body).hexdigest()
            generation = snapshot.checkpoint.generation
            if generation < 1 or generation > current.generation:
                raise AuditChainError("audit commit generation is outside the trusted chain")
            if generation == current.generation and snapshot.checkpoint != current:
                raise AuditChainError("current-head audit checkpoint does not match the anchor")
            events = list(self.iter_events())
            if len(events) != current.generation:
                raise AuditChainError("trusted audit generation does not match persisted events")
            persisted = events[generation - 1]
            expected_previous_hash = (
                GENESIS_HASH
                if generation == 1
                else _validated_sha256(
                    events[generation - 2].get("event_hash"),
                    "previous event_hash",
                )
            )
            persisted_without_hash = dict(persisted)
            persisted_hash = persisted_without_hash.pop("event_hash", None)
            try:
                canonical_persisted = canonical_json(persisted)
                recomputed_hash = sha256_json(persisted_without_hash)
            except (TypeError, ValueError) as exc:
                raise AuditChainError("persisted audit event is not canonical JSON") from exc
            persisted_checkpoint_parent = persisted.get(_CHECKPOINT_PARENT_FIELD)
            if persisted_checkpoint_parent is not None:
                _validated_sha256(
                    persisted_checkpoint_parent,
                    "persisted checkpoint parent hash",
                )
            lineage_linked = generation == current.generation
            if generation < current.generation:
                next_checkpoint_parent = events[generation].get(_CHECKPOINT_PARENT_FIELD)
                lineage_linked = _is_sha256(next_checkpoint_parent) and _constant_time_equal(
                    next_checkpoint_parent, snapshot.checkpoint.checkpoint_hash
                )
            if (
                persisted.get("event_id") != snapshot.event_id
                or persisted_hash != snapshot.event_hash
                or snapshot.embedded_event_hash != snapshot.event_hash
                or snapshot_event_hash != snapshot.event_hash
                or snapshot.checkpoint.head_hash != snapshot.event_hash
                or snapshot.checkpoint.generation != generation
                or persisted.get("previous_hash") != expected_previous_hash
                or recomputed_hash != persisted_hash
                or canonical_persisted != snapshot.canonical_event
                or not lineage_linked
                or (
                    persisted_checkpoint_parent is not None
                    and persisted_checkpoint_parent != snapshot.checkpoint.previous_checkpoint_hash
                )
            ):
                raise AuditChainError("audit commit does not match the exact persisted event")
            return callback()

    @property
    def trusted_checkpoint_required(self) -> bool:
        """Whether construction required an externally trusted checkpoint."""
        return self._require_trusted_checkpoint

    @property
    def strict_integrity_ready(self) -> bool:
        """Return true only when local bytes exactly match a signed trusted head."""
        if self._checkpoint_anchor is None:
            return False
        return bool(self.verify_checkpointed_chain()["valid"])

    @property
    def integrity_scope(self) -> str:
        """Describe the proven boundary without upgrading legacy local chains."""
        if self._checkpoint_anchor is None:
            return "local-hash-chain-no-external-checkpoint"
        return "signed-external-checkpoint"

    def verify_checkpointed_chain(self) -> dict[str, Any]:
        """Verify the full local chain against the signed external checkpoint.

        Legacy stores intentionally return ``valid=False`` and ``strict=False``;
        :meth:`verify_chain` remains the compatible local-only verifier.
        """
        if self._checkpoint_anchor is None:
            chain = self.verify_chain()
            return {
                **chain,
                "valid": False,
                "chain_valid": bool(chain["valid"]),
                "checkpoint_valid": False,
                "strict": False,
                "checkpoint": None,
                "failures": [
                    *chain["failures"],
                    {"type": "trusted_checkpoint_unavailable"},
                ],
            }

        lock_path = self._lock_path()
        with lock_path.open("a+") as lock_fh, _exclusive_file_lock(lock_fh):
            try:
                checkpoint = self._assert_checkpoint_state_locked()
            except AuditChainError as exc:
                try:
                    chain = self.verify_chain()
                except AuditError:
                    chain = {
                        "valid": False,
                        "checked": 0,
                        "failures": [{"type": "chain_unreadable"}],
                        "last_hash": GENESIS_HASH,
                    }
                return {
                    **chain,
                    "valid": False,
                    "chain_valid": bool(chain["valid"]),
                    "checkpoint_valid": False,
                    "strict": True,
                    "checkpoint": None,
                    "failures": [
                        *chain["failures"],
                        {"type": "checkpoint_failure", "detail": str(exc)},
                    ],
                }
            chain = self.verify_chain()
            return {
                **chain,
                "valid": True,
                "chain_valid": True,
                "checkpoint_valid": True,
                "strict": True,
                "checkpoint": checkpoint.to_dict(),
            }

    def _initialize_checkpoint_mode(self) -> None:
        lock_path = self._lock_path()
        with lock_path.open("a+") as lock_fh, _exclusive_file_lock(lock_fh):
            if self._checkpoint_poisoned:
                raise AuditChainError("audit checkpoint store is fail-stopped")
            chain = self.verify_chain()
            if not chain["valid"]:
                raise AuditChainError("cannot initialize checkpoints for an invalid audit chain")
            anchored = self._read_checkpoint()
            if anchored is None:
                if int(chain["checked"]) != 0:
                    raise AuditChainError(
                        "non-empty legacy audit chain cannot be silently checkpointed"
                    )
                initial = self._signed_checkpoint(
                    generation=0,
                    head_hash=GENESIS_HASH,
                    previous_checkpoint_hash=GENESIS_CHECKPOINT_HASH,
                )
                self._publish_checkpoint(None, initial)
                return
            self._assert_checkpoint_matches_chain(anchored, chain)

    def _assert_checkpoint_state_locked(self) -> AuditCheckpoint:
        if self._checkpoint_poisoned:
            raise AuditChainError(
                "audit checkpoint store is fail-stopped after an indeterminate publication"
            )
        if self._checkpoint_anchor is None:
            raise AuditChainError("trusted audit checkpoint anchor is unavailable")
        chain = self.verify_chain()
        if not chain["valid"]:
            raise AuditChainError("local audit chain integrity verification failed")
        anchored = self._read_checkpoint()
        if anchored is None:
            raise AuditChainError("trusted audit checkpoint is missing")
        self._assert_checkpoint_matches_chain(anchored, chain)
        return anchored

    def _assert_checkpoint_matches_chain(
        self,
        checkpoint: AuditCheckpoint,
        chain: Mapping[str, Any],
    ) -> None:
        self._validate_checkpoint(checkpoint)
        checked = chain.get("checked")
        last_hash = chain.get("last_hash")
        if type(checked) is not int or not _is_sha256(last_hash):
            raise AuditChainError("local audit-chain verification returned malformed state")
        if checked > checkpoint.generation:
            raise AuditChainError("audit disk is ahead of its trusted checkpoint")
        if checked < checkpoint.generation:
            raise AuditChainError("trusted audit checkpoint is ahead of local disk")
        if not _constant_time_equal(last_hash, checkpoint.head_hash):
            raise AuditChainError("audit chain and trusted checkpoint have diverged")
        if checkpoint.generation == 0 and (
            checkpoint.head_hash != GENESIS_HASH
            or checkpoint.previous_checkpoint_hash != GENESIS_CHECKPOINT_HASH
        ):
            raise AuditChainError("initial audit checkpoint is incompatible")
        if checkpoint.generation > 0 and (
            checkpoint.head_hash == GENESIS_HASH
            or checkpoint.previous_checkpoint_hash == GENESIS_CHECKPOINT_HASH
        ):
            raise AuditChainError("non-initial audit checkpoint is incompatible")

    def _signed_checkpoint(
        self,
        *,
        generation: int,
        head_hash: str,
        previous_checkpoint_hash: str,
    ) -> AuditCheckpoint:
        signer = self._checkpoint_signer
        if signer is None:
            raise AuditChainError("checkpoint signer is unavailable")
        signer = _validated_signer(signer)
        namespace = _validated_text(self._checkpoint_namespace, "checkpoint_namespace")
        unsigned = AuditCheckpoint(
            namespace=namespace,
            generation=generation,
            head_hash=_validated_sha256(head_hash, "checkpoint.head_hash"),
            previous_checkpoint_hash=_validated_sha256(
                previous_checkpoint_hash,
                "checkpoint.previous_checkpoint_hash",
            ),
            key_id=_validated_text(signer.key_id, "checkpoint.key_id"),
            algorithm=_validated_text(signer.algorithm, "checkpoint.algorithm"),
            signature="pending",
        )
        try:
            signature = signer.sign(unsigned.signing_payload())
        except Exception as exc:
            raise AuditChainError("audit checkpoint signing failed") from exc
        checkpoint = AuditCheckpoint(
            namespace=unsigned.namespace,
            generation=unsigned.generation,
            head_hash=unsigned.head_hash,
            previous_checkpoint_hash=unsigned.previous_checkpoint_hash,
            key_id=unsigned.key_id,
            algorithm=unsigned.algorithm,
            signature=_validated_text(signature, "checkpoint.signature"),
        )
        self._validate_checkpoint(checkpoint)
        return checkpoint

    def _validate_checkpoint(self, checkpoint: AuditCheckpoint) -> None:
        if type(checkpoint) is not AuditCheckpoint:
            raise AuditChainError("trusted audit anchor returned a malformed checkpoint")
        namespace = _validated_text(self._checkpoint_namespace, "checkpoint_namespace")
        if checkpoint.namespace != namespace:
            raise AuditChainError("audit checkpoint namespace mismatch")
        if type(checkpoint.generation) is not int or checkpoint.generation < 0:
            raise AuditChainError("audit checkpoint generation is invalid")
        _validated_sha256(checkpoint.head_hash, "checkpoint.head_hash")
        _validated_sha256(
            checkpoint.previous_checkpoint_hash,
            "checkpoint.previous_checkpoint_hash",
        )
        _validated_text(checkpoint.key_id, "checkpoint.key_id")
        _validated_text(checkpoint.algorithm, "checkpoint.algorithm")
        _validated_text(checkpoint.signature, "checkpoint.signature")
        if checkpoint.algorithm == "none":
            raise AuditChainError("unsigned audit checkpoint is not trusted")

        verifier_config = self._checkpoint_verifier
        if isinstance(verifier_config, Mapping):
            verifier = verifier_config.get(checkpoint.key_id)
        else:
            verifier = verifier_config
        if verifier is None or not isinstance(verifier, ReceiptSigner):
            raise AuditChainError("audit checkpoint key id is not trusted")
        if verifier.key_id != checkpoint.key_id:
            raise AuditChainError("audit checkpoint key id does not match verifier")
        if verifier.algorithm != checkpoint.algorithm:
            raise AuditChainError("audit checkpoint algorithm does not match verifier")
        try:
            verified = verifier.verify(checkpoint.signing_payload(), checkpoint.signature)
        except Exception as exc:
            raise AuditChainError("audit checkpoint signature verification failed") from exc
        if verified is not True:
            raise AuditChainError("audit checkpoint signature is invalid")

    def _read_checkpoint(self) -> AuditCheckpoint | None:
        anchor = self._checkpoint_anchor
        namespace = _validated_text(self._checkpoint_namespace, "checkpoint_namespace")
        if anchor is None:
            return None
        try:
            checkpoint = anchor.read(namespace)
        except Exception as exc:
            raise AuditChainError("trusted audit checkpoint anchor is unavailable") from exc
        if checkpoint is None:
            return None
        self._validate_checkpoint(checkpoint)
        return checkpoint

    def _publish_checkpoint(
        self,
        expected: AuditCheckpoint | None,
        replacement: AuditCheckpoint,
    ) -> None:
        anchor = self._checkpoint_anchor
        namespace = _validated_text(self._checkpoint_namespace, "checkpoint_namespace")
        if anchor is None:
            raise AuditChainError("trusted audit checkpoint anchor is unavailable")
        try:
            updated = anchor.compare_and_swap(namespace, expected, replacement)
        except Exception as exc:
            self._checkpoint_poisoned = True
            raise AuditChainError(
                "trusted checkpoint CAS outcome is unknown; audit store is fail-stopped"
            ) from exc
        if updated is not True:
            self._checkpoint_poisoned = True
            raise AuditChainError("trusted checkpoint CAS failed; audit store is fail-stopped")

    def _write_event_locked(self, payload: Mapping[str, Any]) -> None:
        try:
            line = (
                json.dumps(
                    payload,
                    sort_keys=True,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                )
                + "\n"
            )
            with self._storage_path().open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        except (OSError, TypeError, ValueError) as exc:
            raise AuditChainError("could not durably append audit event") from exc

    def last_hash(self) -> str:
        """Return the event_hash of the most recent event, or genesis."""
        self._last_hash = self._read_last_hash_from_disk()
        return self._last_hash

    def _read_last_hash_from_disk(self) -> str:
        storage_path = self._storage_path()
        if not storage_path.exists():
            return GENESIS_HASH
        try:
            size = storage_path.stat().st_size
        except OSError as exc:
            raise AuditChainError(f"could not stat audit chain {self.path}: {exc}") from exc
        if size == 0:
            return GENESIS_HASH

        last_line: str | None = None
        try:
            with self._storage_path().open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                # Tail-read in chunks until the newline preceding the final
                # record, so we never load the whole file.
                chunk = 4096
                buf = b""
                pos = size
                while pos > 0:
                    read = min(chunk, pos)
                    pos -= read
                    fh.seek(pos)
                    buf = fh.read(read) + buf
                    stripped = buf.rstrip(b"\n")
                    nl = stripped.rfind(b"\n")
                    if nl != -1:
                        last_line = stripped[nl + 1 :].decode("utf-8")
                        break
                    if pos == 0:
                        last_line = stripped.decode("utf-8")
                        break
        except (OSError, UnicodeDecodeError) as exc:
            raise AuditChainError(
                f"could not read audit chain tail from {self.path}: {exc}"
            ) from exc

        if not last_line:
            raise AuditChainError(f"audit chain tail is blank in non-empty file {self.path}")
        try:
            event = json.loads(last_line)
        except json.JSONDecodeError as exc:
            raise AuditChainError(
                f"audit chain tail is not valid JSON in {self.path}: {exc}"
            ) from exc
        if not isinstance(event, dict):
            raise AuditChainError(f"audit chain tail is not a JSON object in {self.path}")
        event_hash = event.get("event_hash")
        if not isinstance(event_hash, str):
            raise AuditChainError(f"audit chain tail has invalid event_hash in {self.path}")
        return event_hash

    def iter_events(self) -> Iterable[dict[str, Any]]:
        """Yield every persisted event dict in chain order.

        Raises :class:`AuditChainError` on any malformed line so callers
        such as :meth:`verify_chain` surface the same exception type as
        :meth:`append` instead of leaking a raw ``json.JSONDecodeError``.
        """
        storage_path = self._storage_path()
        if not storage_path.exists():
            return
        with self._storage_path().open("r", encoding="utf-8") as fh:
            for line_number, line in enumerate(fh, start=1):
                clean = line.strip()
                if not clean:
                    continue
                try:
                    event = json.loads(clean)
                except json.JSONDecodeError as exc:
                    raise AuditChainError(
                        f"audit chain line {line_number} in {self.path} is not valid JSON: {exc}"
                    ) from exc
                if not isinstance(event, dict):
                    raise AuditChainError(
                        f"audit chain line {line_number} in {self.path} is not a JSON object"
                    )
                yield event

    def query(
        self,
        *,
        where: Callable[[dict[str, Any]], bool] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Filter events by an arbitrary predicate.

        Domain-specific filters (by tool, rule_id, tenant, etc.) compose on
        top of this — the kernel ships only the generic predicate hook.
        """
        out: list[dict[str, Any]] = []
        for event in self.iter_events():
            if where is not None and not where(event):
                continue
            out.append(event)
            if len(out) >= limit:
                break
        return out

    def verify_chain(self) -> dict[str, Any]:
        """Re-walk the chain and report integrity.

        Returns a dict with:
            ``valid`` (bool): True iff every event hash matches and every
              ``previous_hash`` matches the prior ``event_hash``.
            ``checked`` (int): number of events walked.
            ``failures`` (list): per-failure detail dicts.
            ``last_hash`` (str): final ``event_hash`` walked, or genesis.
        """
        previous = GENESIS_HASH
        checked = 0
        failures: list[dict[str, Any]] = []

        for event in self.iter_events():
            checked += 1
            expected_previous = event.get("previous_hash")
            if expected_previous != previous:
                failures.append(
                    {
                        "event_id": event.get("event_id"),
                        "type": "previous_hash_mismatch",
                        "expected": previous,
                        "actual": expected_previous,
                    }
                )

            claimed_hash = event.get("event_hash")
            payload = dict(event)
            payload.pop("event_hash", None)
            recomputed = sha256_json(payload)
            if claimed_hash != recomputed:
                failures.append(
                    {
                        "event_id": event.get("event_id"),
                        "type": "event_hash_mismatch",
                        "expected": recomputed,
                        "actual": claimed_hash,
                    }
                )

            previous = str(claimed_hash)

        return {
            "valid": len(failures) == 0,
            "checked": checked,
            "failures": failures,
            "last_hash": previous,
        }


def _is_proc_descriptor_alias(path: Path) -> bool:
    if is_proc_fd_path(path):
        return True
    parts = Path(os.path.abspath(os.fspath(path))).parts
    return (
        len(parts) >= 5
        and parts[:2] == ("/", "proc")
        and (parts[2].isdecimal() or parts[2] == "thread-self")
        and parts[3] == "fd"
        and parts[4].isdecimal()
    )


def _validated_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuditChainError(f"{field_name} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AuditChainError(f"{field_name} must be valid UTF-8") from exc
    return value


def _is_sha256(value: object) -> TypeGuard[str]:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validated_sha256(value: object, field_name: str) -> str:
    if not _is_sha256(value):
        raise AuditChainError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _validated_signer(signer: ReceiptSigner) -> ReceiptSigner:
    if not isinstance(signer, ReceiptSigner):
        raise AuditChainError("checkpoint signer does not implement the signing protocol")
    _validated_text(signer.key_id, "checkpoint signer key_id")
    algorithm = _validated_text(signer.algorithm, "checkpoint signer algorithm")
    if algorithm == "none":
        raise AuditChainError("unsigned checkpoint signer is not trusted")
    return signer


def _constant_time_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)
