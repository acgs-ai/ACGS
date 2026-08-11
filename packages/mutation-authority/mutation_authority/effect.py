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

from .canonical import ABSENT, hash_file, sha256_hex
from .engine import _verify_chain_root_binding
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


def _open_parent_dir(repo_dir: Path, resource: str) -> tuple[int, str]:
    """Open the resource parent without following any directory symlink."""
    parts = Path(resource).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise OSError("resource path is not a canonical relative path")
    fd = os.open(repo_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, mode=0o755, dir_fd=fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, parts[-1]
    except Exception:
        os.close(fd)
        raise


def _read_state_at(parent_fd: int, name: str) -> tuple[bytes | None, str, int]:
    """Read a regular file without following it or reopening its pathname."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except FileNotFoundError:
        # CREATE follows the process umask just like an ordinary 0666 file;
        # never widen a restrictive caller policy to a fixed 0644.
        current_umask = os.umask(0)
        os.umask(current_umask)
        return None, ABSENT, 0o666 & ~current_umask
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
        digest = sha256_hex(data) + (":exec" if st.st_mode & 0o111 else "")
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

        # 6. Pre-state binding: the file must still be exactly the state
        #    the decision was made against. Re-check containment at effect
        #    time too: a symlink introduced after approval must not let the
        #    write land outside the governed repository.
        target = self.repo_dir / receipt.resource
        repo_root = self.repo_dir.resolve()
        resolved = target.resolve()
        if resolved != repo_root and not resolved.is_relative_to(repo_root):
            return CommitResult(
                REJECTED, "resource resolves outside the governed repository (symlink escape)"
            )
        # The governance root and protected prefixes are rechecked against the
        # RESOLVED path too: a symlink that stays inside the repository but
        # lands on governance material must not bypass the policy decision.
        root_dir = self.root.root_dir.resolve()
        if resolved == root_dir or resolved.is_relative_to(root_dir):
            return CommitResult(
                REJECTED, "resource resolves into the governance root (symlink escape)"
            )
        rel = resolved.relative_to(repo_root).as_posix()
        for prefix in self.root.protected_prefixes():
            if rel == prefix or rel.startswith(prefix.rstrip("/") + "/"):
                return CommitResult(
                    REJECTED,
                    "resource resolves into a protected prefix (symlink escape)",
                )
        # Governed-prefix and actor-scope authorization ran against the
        # LEXICAL receipt.resource only. A symlink that stays inside the
        # repository (and off protected prefixes) could still redirect the
        # write to a file the actor was never authorized to touch, so the
        # resolved target must be exactly the authorized path — symlinked
        # resources are rejected rather than re-authorized here.
        lexical = Path(os.path.normpath(repo_root / receipt.resource))
        if resolved != lexical:
            return CommitResult(
                REJECTED,
                "resource path traverses a symlink; resolved target is not the authorized path",
            )
        before_hash = hash_file(target)
        if before_hash != receipt.previous_state_hash:
            return CommitResult(
                REJECTED,
                "resource changed after approval (pre-state hash mismatch)",
                before_hash=before_hash,
            )

        # 7. Apply the effect atomically. Snapshot the prior bytes and metadata
        #    so an unrecordable effect can be rolled back completely.
        try:
            parent_fd, target_name = _open_parent_dir(self.repo_dir, receipt.resource)
        except OSError:
            return CommitResult(REJECTED, "resource parent is not a verified directory")
        try:
            try:
                if not _parent_matches_path(parent_fd, resolved.parent):
                    return CommitResult(REJECTED, "resource parent changed at effect time")
                prior_bytes, secured_before_hash, prior_mode = _read_state_at(
                    parent_fd, target_name
                )
            except OSError:
                return CommitResult(REJECTED, "resource is not a verified regular file")
            if secured_before_hash != receipt.previous_state_hash:
                return CommitResult(
                    REJECTED,
                    "resource changed after approval (pre-state hash mismatch)",
                    before_hash=secured_before_hash,
                )
            if receipt.operation == "DELETE":
                os.unlink(target_name, dir_fd=parent_fd)
                after_hash = ABSENT
            else:
                assert new_content is not None
                try:
                    _atomic_replace_at(parent_fd, target_name, new_content, prior_mode)
                except OSError:
                    return CommitResult(
                        REJECTED, "secure temporary effect file could not be created"
                    )
                try:
                    _after_bytes, after_hash, _after_mode = _read_state_at(parent_fd, target_name)
                except OSError:
                    _rollback_at(parent_fd, target_name, prior_bytes, prior_mode)
                    return CommitResult(REJECTED, "effect after-state could not be verified")

            # A validated ancestor can be renamed/replaced while the pinned fd
            # remains usable. Revalidate immediately before recording COMMIT;
            # rollback only through the pinned fd if the lexical path changed.
            if not _parent_matches_path(parent_fd, resolved.parent):
                try:
                    _rollback_at(parent_fd, target_name, prior_bytes, prior_mode)
                except OSError as exc:
                    raise EffectRecordingError(
                        "resource parent changed and rollback through the pinned directory failed"
                    ) from exc
                return CommitResult(REJECTED, "resource parent changed during effect")

            # 8. Bind the effect into the audit chain. If the append fails, the
            #    effect must not persist: roll the file back and fail loudly.
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
                _rollback_at(parent_fd, target_name, prior_bytes, prior_mode)
                raise EffectRecordingError(
                    "effect could not be bound to the audit chain; filesystem change rolled back"
                ) from exc

            # append() is an attacker-observable boundary. If the authorized
            # ancestor was exchanged while COMMIT was being recorded, rewind
            # both sides of the transaction before returning to the caller.
            if not _parent_matches_path(parent_fd, resolved.parent):
                try:
                    _rollback_at(parent_fd, target_name, prior_bytes, prior_mode)
                    self.ledger.rollback_last(commit_event)
                except Exception as exc:
                    raise EffectRecordingError(
                        "resource parent changed at audit append and the effect "
                        "transaction could not be rolled back"
                    ) from exc
                return CommitResult(REJECTED, "resource parent changed during audit append")
        finally:
            os.close(parent_fd)
        return CommitResult(
            ACCEPTED, "effect bound", before_hash=before_hash, after_hash=after_hash
        )
