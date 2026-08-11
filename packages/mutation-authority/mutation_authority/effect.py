"""Effect binding: the only code path that writes to the governed repository.

No Valid Mutation Decision Receipt, No Repository State Change.

A commit re-verifies everything at effect time: root integrity, chain
integrity, receipt signature, issuance-in-this-chain, single use, expiry,
and — critically — that the resource on disk still matches the receipt's
previous_state_hash. Approval does not survive a post-approval change to
the file (Attack F) or a second use of the same receipt (Attack E).
"""

from __future__ import annotations

import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from .canonical import ABSENT, sha256_hex, state_mode_suffix
from .engine import SECURE_CREATE_MODE, _verify_chain_root_binding
from .ledger import EVENT_COMMIT, EVENT_GENESIS, AuditLedger
from .receipt import MutationDecisionReceipt
from .root import GovernanceRoot

ACCEPTED = "ACCEPTED"
REJECTED = "REJECTED"


class EffectRecordingError(Exception):
    """The filesystem effect could not be bound into the audit chain.

    The effect has been rolled back: an applied-but-unrecorded side effect
    would be an unaudited state change, which violates the core invariant.
    """


def _open_bound_ancestor(
    repo_dir: Path, receipt: MutationDecisionReceipt
) -> tuple[int, str, tuple[str, ...]]:
    """Open and verify the exact ancestor identity signed into the receipt."""
    resource_parts = Path(receipt.resource).parts
    if not resource_parts or any(part in ("", ".", "..") for part in resource_parts):
        raise OSError("resource path is not a canonical relative path")
    ancestor_parts = (
        Path(receipt.parent_ancestor_path).parts if receipt.parent_ancestor_path else ()
    )
    parent_parts = resource_parts[:-1]
    if (
        any(part in ("", ".", "..") for part in ancestor_parts)
        or len(ancestor_parts) > len(parent_parts)
        or tuple(parent_parts[: len(ancestor_parts)]) != tuple(ancestor_parts)
    ):
        raise OSError("receipt ancestor path is not a parent of the resource")

    fd = os.open(repo_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in ancestor_parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        pinned = os.fstat(fd)
        if (pinned.st_dev, pinned.st_ino) != (
            receipt.parent_ancestor_device,
            receipt.parent_ancestor_inode,
        ):
            raise OSError("receipt ancestor identity changed")
        return fd, resource_parts[-1], tuple(parent_parts[len(ancestor_parts) :])
    except Exception:
        os.close(fd)
        raise


def _create_missing_parents(
    ancestor_fd: int, missing_parts: tuple[str, ...]
) -> tuple[int, list[tuple[int, str]]]:
    """Create receipt-authorized missing parents through the pinned ancestor."""
    current_fd = os.dup(ancestor_fd)
    created: list[tuple[int, str]] = []
    try:
        for part in missing_parts:
            parent_ref = os.dup(current_fd)
            made_directory = False
            try:
                os.mkdir(part, mode=0o755, dir_fd=current_fd)
                made_directory = True
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=current_fd,
                )
            except Exception:
                if made_directory:
                    os.rmdir(part, dir_fd=current_fd)
                os.close(parent_ref)
                raise
            created.append((parent_ref, part))
            os.close(current_fd)
            current_fd = child
        return current_fd, created
    except Exception:
        os.close(current_fd)
        _remove_created_parents(created)
        raise


def _remove_created_parents(created: list[tuple[int, str]]) -> None:
    """Remove newly created empty parents in reverse order and close refs."""
    first_error: OSError | None = None
    for parent_fd, name in reversed(created):
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError as exc:
            first_error = first_error or exc
        finally:
            os.close(parent_fd)
    created.clear()
    if first_error is not None:
        raise first_error


def _close_created_parent_refs(created: list[tuple[int, str]]) -> None:
    for parent_fd, _name in created:
        os.close(parent_fd)
    created.clear()


def _read_state_at(parent_fd: int, name: str) -> tuple[bytes | None, str, int]:
    """Read a regular file without following it or reopening its pathname."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except FileNotFoundError:
        # Absent state carries the fixed secure CREATE mode. Never probe the
        # process umask here: os.umask(0) would momentarily widen file
        # creation for every other thread in an embedding process.
        return None, ABSENT, SECURE_CREATE_MODE
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("resource is not a regular file")
        chunks = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        digest = sha256_hex(data) + state_mode_suffix(st.st_mode)
        return data, digest, stat.S_IMODE(st.st_mode)
    finally:
        os.close(fd)


def _atomic_replace_at(parent_fd: int, name: str, content: bytes, mode: int) -> None:
    """Replace name via a unique, non-followed file in parent_fd."""
    tmp_name = f".{name}.mutation-authority.{secrets.token_hex(16)}.tmp"
    fd = os.open(
        tmp_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
        dir_fd=parent_fd,
    )
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write to mutation temporary file")
            view = view[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
        os.replace(tmp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    except Exception:
        try:
            os.unlink(tmp_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(fd)


def _atomic_create_at(parent_fd: int, name: str, content: bytes, mode: int) -> None:
    """Publish a fully written CREATE without replacing a concurrent target."""
    tmp_name = f".{name}.mutation-authority.{secrets.token_hex(16)}.tmp"
    fd = os.open(
        tmp_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
        dir_fd=parent_fd,
    )
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write to mutation temporary file")
            view = view[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
        os.link(
            tmp_name,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except Exception:
        try:
            os.unlink(tmp_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(fd)
    # The link above PUBLISHED the target. From here on, a failure must not
    # propagate as an ordinary OSError: the caller maps that to REJECTED,
    # which would leave the published target on disk as an unaudited side
    # effect. If the temporary cannot be removed, unpublish the target and
    # re-raise; if even unpublishing fails, escalate loudly.
    try:
        os.unlink(tmp_name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass
    except OSError as exc:
        try:
            os.unlink(name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        except OSError as rollback_exc:
            raise EffectRecordingError(
                "CREATE temporary cleanup failed and the published target could not be unpublished"
            ) from rollback_exc
        raise exc


def _parent_matches_path(parent_fd: int, parent_path: Path) -> bool:
    """Return whether the pinned directory is still the authorized path."""
    try:
        pinned = os.fstat(parent_fd)
        named = os.stat(parent_path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(named.st_mode) and (
        pinned.st_dev,
        pinned.st_ino,
    ) == (named.st_dev, named.st_ino)


def _rollback_at(parent_fd: int, name: str, prior_bytes: bytes | None, prior_mode: int) -> None:
    """Restore the pre-effect state through the already-pinned parent fd."""
    if prior_bytes is None:
        try:
            os.unlink(name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
    else:
        _atomic_replace_at(parent_fd, name, prior_bytes, prior_mode)


def _rollback_transaction(
    parent_fd: int,
    target_name: str,
    prior_bytes: bytes | None,
    prior_mode: int,
    created_parents: list[tuple[int, str]],
) -> None:
    """Restore the target and remove directories created by this attempt."""
    first_error: OSError | None = None
    try:
        _rollback_at(parent_fd, target_name, prior_bytes, prior_mode)
    except OSError as exc:
        first_error = exc
    try:
        _remove_created_parents(created_parents)
    except OSError as exc:
        first_error = first_error or exc
    if first_error is not None:
        raise first_error


@dataclass(frozen=True)
class CommitResult:
    status: str  # ACCEPTED | REJECTED
    reason: str
    before_hash: str | None = None
    after_hash: str | None = None


class EffectBinder:
    def __init__(self, root: GovernanceRoot, ledger: AuditLedger, repo_dir: Path):
        self.root = root
        self.ledger = ledger
        self.repo_dir = repo_dir

    def commit(
        self,
        receipt: MutationDecisionReceipt,
        new_content: bytes | None,
        now: int,
    ) -> CommitResult:
        # The whole commit is one ledger transaction: the consumed-receipt
        # check (step 3) reads ledger state that the COMMIT append below
        # extends, so two concurrent commits of the same receipt must not
        # both observe "not yet consumed", both apply the filesystem effect,
        # and both append COMMIT events — that would break the single-use
        # guarantee (concurrent replay). Holding the ledger write lock from
        # the consumption check through the append makes check + effect +
        # record atomic across threads and processes.
        with self.ledger.transaction():
            return self._commit_locked(receipt, new_content, now)

    def _commit_locked(
        self,
        receipt: MutationDecisionReceipt,
        new_content: bytes | None,
        now: int,
    ) -> CommitResult:
        # Fail closed on any governance-layer tamper.
        self.root.verify_integrity()
        self.ledger.verify_chain()
        _verify_chain_root_binding(self.ledger, self.root)

        # 1. Receipt authenticity: signed by the governance root.
        if not receipt.verify_signature(self.root.root_key()):
            return CommitResult(REJECTED, "receipt signature invalid")

        # 2. Receipt provenance: issued by THIS ledger's decision engine.
        issued = self.ledger.issued_receipts().get(receipt.receipt_id)
        if issued != receipt.to_dict():
            return CommitResult(REJECTED, "receipt was not issued by this audit chain")

        # 3. Single use: a receipt authorizes exactly one state change.
        if receipt.receipt_id in self.ledger.committed_receipt_ids():
            return CommitResult(REJECTED, "receipt already consumed (replay rejected)")

        # 4. Expiry. `now` is caller-supplied, so clamp it against the audit
        #    chain's own clock: time never runs backwards past the newest
        #    committed effect, so a caller cannot resurrect an expired receipt
        #    by passing a backdated `now`. Only GENESIS/COMMIT timestamps are
        #    trusted here — COMMIT times are themselves receipt-gated by this
        #    check, whereas DECISION events can carry attacker-injected
        #    timestamps (a direct decide() DENY still appends one) and must
        #    not be able to expire live receipts (clock-skew DoS, Attack H).
        chain_now = max(
            (e.timestamp for e in self.ledger.events() if e.type in (EVENT_GENESIS, EVENT_COMMIT)),
            default=now,
        )
        effective_now = max(now, chain_now)
        if effective_now > receipt.expiry:
            return CommitResult(REJECTED, "receipt expired")

        # 5. Content/operation coherence.
        if receipt.operation == "DELETE" and new_content is not None:
            return CommitResult(REJECTED, "DELETE receipt cannot carry new content")
        if receipt.operation != "DELETE" and new_content is None:
            return CommitResult(REJECTED, f"{receipt.operation} requires new content")
        requested_state_hash = (
            ABSENT
            if new_content is None
            else sha256_hex(new_content) + state_mode_suffix(receipt.expected_state_mode)
        )
        if requested_state_hash != receipt.expected_state_hash:
            return CommitResult(REJECTED, "requested content is not authorized by receipt")

        # 6. Open the signed ancestor and require the exact device/inode
        #    captured by the decision engine before reading or creating state.
        try:
            ancestor_fd, target_name, missing_parents = _open_bound_ancestor(self.repo_dir, receipt)
        except OSError:
            return CommitResult(REJECTED, "receipt parent ancestor identity changed")

        parent_fd: int | None = None
        created_parents: list[tuple[int, str]] = []
        try:
            repo_root = self.repo_dir.resolve()
            lexical = Path(os.path.normpath(repo_root / receipt.resource))
            ancestor_path = (
                repo_root / receipt.parent_ancestor_path
                if receipt.parent_ancestor_path
                else repo_root
            )
            try:
                rel = lexical.relative_to(repo_root).as_posix()
            except ValueError:
                return CommitResult(REJECTED, "resource resolves outside the governed repository")
            root_dir = self.root.root_dir.resolve()
            if lexical == root_dir or lexical.is_relative_to(root_dir):
                return CommitResult(REJECTED, "resource resolves into the governance root")
            for prefix in self.root.protected_prefixes():
                if rel == prefix or rel.startswith(prefix.rstrip("/") + "/"):
                    return CommitResult(REJECTED, "resource resolves into a protected prefix")
            if not _parent_matches_path(ancestor_fd, ancestor_path):
                return CommitResult(REJECTED, "receipt parent ancestor path changed")

            if missing_parents:
                if receipt.operation != "CREATE":
                    return CommitResult(REJECTED, "non-CREATE receipt has missing parent state")
                prior_bytes, before_hash, prior_mode = (
                    None,
                    ABSENT,
                    receipt.expected_state_mode,
                )
            else:
                parent_fd = os.dup(ancestor_fd)
                if not _parent_matches_path(parent_fd, lexical.parent):
                    return CommitResult(REJECTED, "resource parent changed at effect time")
                try:
                    prior_bytes, before_hash, prior_mode = _read_state_at(parent_fd, target_name)
                except OSError:
                    return CommitResult(REJECTED, "resource is not a verified regular file")

            if before_hash != receipt.previous_state_hash:
                return CommitResult(
                    REJECTED,
                    "resource changed after approval (pre-state hash mismatch)",
                    before_hash=before_hash,
                )
            if receipt.operation == "UPDATE" and prior_mode != receipt.expected_state_mode:
                return CommitResult(REJECTED, "resource mode changed after approval")

            if missing_parents:
                if not _parent_matches_path(ancestor_fd, ancestor_path):
                    return CommitResult(REJECTED, "receipt parent ancestor changed before CREATE")
                try:
                    parent_fd, created_parents = _create_missing_parents(
                        ancestor_fd, missing_parents
                    )
                except OSError:
                    return CommitResult(
                        REJECTED, "receipt-authorized parent directories could not be created"
                    )
                if not _parent_matches_path(parent_fd, lexical.parent):
                    _remove_created_parents(created_parents)
                    return CommitResult(REJECTED, "created resource parent path changed")
                try:
                    prior_bytes, current_hash, _current_mode = _read_state_at(
                        parent_fd, target_name
                    )
                except OSError:
                    _remove_created_parents(created_parents)
                    return CommitResult(REJECTED, "CREATE target state could not be verified")
                if current_hash != ABSENT:
                    _remove_created_parents(created_parents)
                    return CommitResult(REJECTED, "CREATE target appeared after approval")

            assert parent_fd is not None
            # 7. Apply the effect atomically. Snapshot the prior bytes and metadata
            #    so an unrecordable effect can be rolled back completely.
            try:
                if receipt.operation == "DELETE":
                    os.unlink(target_name, dir_fd=parent_fd)
                else:
                    assert new_content is not None
                    if receipt.operation == "CREATE":
                        _atomic_create_at(
                            parent_fd,
                            target_name,
                            new_content,
                            receipt.expected_state_mode,
                        )
                    else:
                        _atomic_replace_at(
                            parent_fd,
                            target_name,
                            new_content,
                            receipt.expected_state_mode,
                        )
            except OSError:
                _remove_created_parents(created_parents)
                return CommitResult(REJECTED, "secure temporary effect file could not be created")
            try:
                _after_bytes, after_hash, after_mode = _read_state_at(parent_fd, target_name)
            except OSError:
                _rollback_transaction(
                    parent_fd,
                    target_name,
                    prior_bytes,
                    prior_mode,
                    created_parents,
                )
                return CommitResult(REJECTED, "effect after-state could not be verified")
            if after_hash != receipt.expected_state_hash or (
                after_hash != ABSENT and after_mode != receipt.expected_state_mode
            ):
                _rollback_transaction(
                    parent_fd,
                    target_name,
                    prior_bytes,
                    prior_mode,
                    created_parents,
                )
                return CommitResult(
                    REJECTED,
                    "effect after-state does not match receipt authorization",
                )

            # Retain both the signed ancestor and final parent pins through the
            # mutation and audit append boundaries.
            if not _parent_matches_path(ancestor_fd, ancestor_path) or not _parent_matches_path(
                parent_fd, lexical.parent
            ):
                try:
                    _rollback_transaction(
                        parent_fd,
                        target_name,
                        prior_bytes,
                        prior_mode,
                        created_parents,
                    )
                except OSError as exc:
                    raise EffectRecordingError(
                        "resource ancestor changed and rollback through pinned fds failed"
                    ) from exc
                return CommitResult(REJECTED, "resource ancestor changed during effect")

            # 8. Bind the effect into the audit chain. If the append fails, the
            #    effect and any newly created parent directories are rolled back.
            try:
                commit_event = self.ledger.append(
                    EVENT_COMMIT,
                    {
                        "receipt_id": receipt.receipt_id,
                        "actor": receipt.actor,
                        "resource": receipt.resource,
                        "before_hash": before_hash,
                        "after_hash": after_hash,
                        "decision": "ALLOW",
                    },
                    effective_now,
                )
            except Exception as exc:
                _rollback_transaction(
                    parent_fd,
                    target_name,
                    prior_bytes,
                    prior_mode,
                    created_parents,
                )
                raise EffectRecordingError(
                    "effect could not be bound to the audit chain; filesystem change rolled back"
                ) from exc

            if not _parent_matches_path(ancestor_fd, ancestor_path) or not _parent_matches_path(
                parent_fd, lexical.parent
            ):
                try:
                    _rollback_transaction(
                        parent_fd,
                        target_name,
                        prior_bytes,
                        prior_mode,
                        created_parents,
                    )
                    self.ledger.rollback_last(commit_event)
                except Exception as exc:
                    raise EffectRecordingError(
                        "resource ancestor changed at audit append and the effect "
                        "transaction could not be rolled back"
                    ) from exc
                return CommitResult(REJECTED, "resource ancestor changed during audit append")

            _close_created_parent_refs(created_parents)
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
            os.close(ancestor_fd)
        return CommitResult(
            ACCEPTED, "effect bound", before_hash=before_hash, after_hash=after_hash
        )
