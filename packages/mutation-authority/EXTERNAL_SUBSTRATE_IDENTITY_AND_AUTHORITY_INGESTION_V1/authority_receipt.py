"""Authority-transition receipts — deterministic, verifiable, single-use.

Every governed authority-state transition (ROUTING_REQUIRED -> ROUTING_RESOLVED
-> READY_TO_SEND) and every evidence ingestion binds a receipt. The receipt_id
is the hash of the canonical decision inputs, so a receipt is intrinsically
bound to exactly one (request, transition, evidence, evidence bytes, scope,
substrate identity). Reusing it for a different request, evidence object,
scope, or substrate version yields a different required receipt_id and fails
verification; a ReplayLedger additionally enforces at-most-once.

No wall-clock: ``created_at`` is the caller-supplied logical decision instant,
so receipts are reproducible.
"""

from __future__ import annotations

import fcntl
import os
import secrets
import stat
from pathlib import Path
from typing import Any

from _canonical import canonical_json, hash_obj, hmac_sign, hmac_verify

RECEIPT_SCHEMA = "acgs_authority_transition_receipt/v2"
POLICY_VERSION = "external-substrate-authority-ingestion/v1"


class ReceiptError(RuntimeError):
    """Receipt invalid, replayed, or bound to different inputs — fail closed."""


def substrate_binding_valid(identity: Any, critical_set_digest: Any) -> bool:
    """Both current-substrate bindings must be non-empty strings."""
    return (
        isinstance(identity, str)
        and bool(identity.strip())
        and isinstance(critical_set_digest, str)
        and bool(critical_set_digest.strip())
    )


def require_substrate_binding(identity: Any, critical_set_digest: Any) -> None:
    if not substrate_binding_valid(identity, critical_set_digest):
        raise ReceiptError("substrate identity and critical-set digest must be non-empty strings")


def _read_secure_key(parent_fd: int, name: str, display: Path) -> bytes:
    """Read raw key bytes verbatim through a no-follow, pinned parent fd."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as exc:
        raise ReceiptError(f"cannot securely open keystore {display}: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ReceiptError(f"keystore is not a regular file: {display}")
        if st.st_uid != os.geteuid():
            raise ReceiptError(f"keystore is not owned by the current user: {display}")
        if stat.S_IMODE(st.st_mode) != 0o600:
            raise ReceiptError(f"keystore permissions must be exactly 0600: {display}")
        chunks = []
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        if len(data) < 32:
            raise ReceiptError(f"keystore exists but holds no usable key: {display}")
        return data
    finally:
        os.close(fd)


def _open_trusted_parent(keystore: Path) -> tuple[int, str, Path]:
    """Pin a non-symlinked, current-user-owned, non-writable parent path.

    The parent must already exist.  Traversing every component with
    O_NOFOLLOW prevents an ancestor symlink from redirecting key access.
    """
    absolute = keystore.absolute()
    if absolute.name in ("", ".", ".."):
        raise ReceiptError(f"invalid keystore path: {keystore}")
    parent = absolute.parent
    parts = parent.parts
    try:
        fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
    except OSError as exc:
        try:
            os.close(fd)
        except (NameError, OSError):
            pass
        raise ReceiptError(
            f"keystore parent has a missing or symlinked component: {parent}"
        ) from exc
    try:
        st = os.fstat(fd)
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o022:
            raise ReceiptError(
                "keystore parent must be owned by the current user and not "
                f"group/other-writable: {parent}"
            )
        _validate_pinned_parent(fd, parent)
        return fd, absolute.name, parent
    except Exception:
        os.close(fd)
        raise


def _validate_pinned_parent(parent_fd: int, parent: Path) -> None:
    try:
        pinned = os.fstat(parent_fd)
        named = os.stat(parent, follow_symlinks=False)
    except OSError as exc:
        raise ReceiptError(f"keystore parent changed during access: {parent}") from exc
    if not stat.S_ISDIR(named.st_mode) or (
        pinned.st_dev,
        pinned.st_ino,
    ) != (named.st_dev, named.st_ino):
        raise ReceiptError(f"keystore parent changed during access: {parent}")


def load_key(keystore: Path) -> bytes | None:
    """Securely load an existing key without minting one during verification."""
    parent_fd, name, parent = _open_trusted_parent(keystore)
    try:
        try:
            data = _read_secure_key(parent_fd, name, keystore)
        except ReceiptError:
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            raise
        _validate_pinned_parent(parent_fd, parent)
        return data
    finally:
        os.close(parent_fd)


def load_or_create_key(keystore: Path) -> bytes:
    """Securely load or atomically create an owner-only regular key file."""
    parent_fd, name, parent = _open_trusted_parent(keystore)
    created = False
    try:
        try:
            data = _read_secure_key(parent_fd, name, keystore)
            _validate_pinned_parent(parent_fd, parent)
            return data
        except ReceiptError:
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise

        key = secrets.token_bytes(32)
        try:
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            created = True
        except FileExistsError:
            data = _read_secure_key(parent_fd, name, keystore)
            _validate_pinned_parent(parent_fd, parent)
            return data
        except OSError as exc:
            raise ReceiptError(
                f"cannot create keystore with owner-only permissions: {exc}"
            ) from exc
        try:
            st = os.fstat(fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_uid != os.geteuid()
                or stat.S_IMODE(st.st_mode) != 0o600
            ):
                raise ReceiptError("new keystore failed owner/regular/mode verification")
            view = memoryview(key)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise ReceiptError("short write while creating keystore")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            _validate_pinned_parent(parent_fd, parent)
        except ReceiptError:
            if created:
                try:
                    os.unlink(name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
            raise
        return key
    finally:
        os.close(parent_fd)


def _decision_inputs(
    *,
    request_id: str,
    prior_state: str,
    new_state: str,
    authority_subject: str,
    authority_evidence_id: str,
    evidence_digest: str,
    authority_scope: Any,
    substrate_identity: str,
    substrate_critical_set_digest: str,
    decision: str,
    decision_reason: str,
) -> dict[str, Any]:
    return {
        "authority_evidence_id": authority_evidence_id,
        "authority_subject": authority_subject,
        "authority_scope_digest": hash_obj(authority_scope),
        "decision": decision,
        "decision_reason": decision_reason,
        "evidence_digest": evidence_digest,
        "new_state": new_state,
        "policy_version": POLICY_VERSION,
        "prior_state": prior_state,
        "request_id": request_id,
        "substrate_identity": substrate_identity,
        "substrate_critical_set_digest": substrate_critical_set_digest,
    }


def mint_receipt(
    key: bytes,
    *,
    request_id: str,
    prior_state: str,
    new_state: str,
    authority_subject: str,
    authority_evidence_id: str,
    evidence_digest: str,
    authority_scope: Any,
    substrate_identity: str,
    substrate_critical_set_digest: str,
    decision: str,
    decision_reason: str,
    created_at: str,
) -> dict[str, Any]:
    """Mint a signed receipt. created_at is a logical instant, not wall time."""
    require_substrate_binding(substrate_identity, substrate_critical_set_digest)
    inputs = _decision_inputs(
        request_id=request_id,
        prior_state=prior_state,
        new_state=new_state,
        authority_subject=authority_subject,
        authority_evidence_id=authority_evidence_id,
        evidence_digest=evidence_digest,
        authority_scope=authority_scope,
        substrate_identity=substrate_identity,
        substrate_critical_set_digest=substrate_critical_set_digest,
        decision=decision,
        decision_reason=decision_reason,
    )
    decision_inputs_digest = hash_obj(inputs)
    receipt_id = hash_obj({"decision_inputs_digest": decision_inputs_digest})
    body = {
        "schema": RECEIPT_SCHEMA,
        "receipt_id": receipt_id,
        "request_id": request_id,
        "prior_state": prior_state,
        "new_state": new_state,
        "authority_subject": authority_subject,
        "authority_evidence_id": authority_evidence_id,
        "authority_scope": authority_scope,
        "evidence_digest": evidence_digest,
        "substrate_identity": substrate_identity,
        "substrate_critical_set_digest": substrate_critical_set_digest,
        "decision_inputs_digest": decision_inputs_digest,
        "policy_version": POLICY_VERSION,
        "decision": decision,
        "decision_reason": decision_reason,
        "created_at": created_at,
    }
    body["signature"] = hmac_sign(key, canonical_json(body))
    return body


def verify_receipt(key: bytes, receipt: dict[str, Any]) -> bool:
    """Recompute the signature, the decision-inputs digest, and the receipt_id.
    Any mismatch — including a body field altered after minting — returns
    False. Fail closed on a malformed receipt."""
    try:
        if receipt.get("schema") != RECEIPT_SCHEMA:
            return False
        if not substrate_binding_valid(
            receipt.get("substrate_identity"),
            receipt.get("substrate_critical_set_digest"),
        ):
            return False
        sig = receipt["signature"]
        body = {k: v for k, v in receipt.items() if k != "signature"}
        if not hmac_verify(key, canonical_json(body), sig):
            return False
        inputs = _decision_inputs(
            request_id=receipt["request_id"],
            prior_state=receipt["prior_state"],
            new_state=receipt["new_state"],
            authority_subject=receipt["authority_subject"],
            authority_evidence_id=receipt["authority_evidence_id"],
            evidence_digest=receipt["evidence_digest"],
            authority_scope=receipt["authority_scope"],
            substrate_identity=receipt["substrate_identity"],
            substrate_critical_set_digest=receipt["substrate_critical_set_digest"],
            decision=receipt["decision"],
            decision_reason=receipt["decision_reason"],
        )
        digest = hash_obj(inputs)
        if digest != receipt["decision_inputs_digest"]:
            return False
        expected_id = hash_obj({"decision_inputs_digest": digest})
        return expected_id == receipt["receipt_id"]
    except (KeyError, TypeError):
        return False


class ReplayLedger:
    """At-most-once guard over receipt_ids. A receipt_id may be consumed once.

    By default the ledger is in-memory, which is what deterministic
    *verification* needs: recomputing the same evaluation must reproduce the
    same receipts, and an in-memory ledger still catches duplicates within one
    evaluation. An *execution* context — anything that acts on a receipt —
    must pass ``path`` so consumed ids persist across process restarts;
    otherwise a restart would forget every consumed receipt and replays of old
    receipts would be accepted."""

    def __init__(self, path: Path | None = None) -> None:
        self._seen: set[str] = set()
        self._path = path
        if path is not None and os.path.lexists(path):
            fd = self._open_pinned_ledger(os.O_RDONLY)
            if fd is not None:
                with os.fdopen(fd, "r", encoding="utf-8") as fh:
                    self._seen.update(self._parse_ledger(fh.read()))

    def _parse_ledger(self, content: str) -> set[str]:
        """Parse ledger content, REFUSING broken framing (fail closed).

        An unterminated tail — e.g. after an interrupted prior append — must
        never be silently accepted: the fragment would be loaded as a bogus
        id while the receipt id it truncated is forgotten, and the next
        append would concatenate a fresh id onto the fragment, permanently
        recording it as `fragment<receipt_id>`. Either way the persistent
        single-use guarantee is erased for a real, already-consumed receipt
        id, so a crash must surface as an explicit error, not as replay
        acceptance."""
        if content and not content.endswith("\n"):
            raise ReceiptError(
                f"replay ledger has an unterminated final line (interrupted "
                f"append?) — refusing to trust or extend it: {self._path}"
            )
        return {line.strip() for line in content.splitlines() if line.strip()}

    def _open_pinned_ledger(self, flags: int) -> int | None:
        """Open the persistent ledger with no-follow, regular-file checks.

        A replay path replaced by a symlink (or reached through a symlinked
        ancestor) must be refused: following it would read prior ids from —
        and append consumed ids into — an arbitrary writable target while the
        replay guard reports success. Returns None only when the ledger does
        not exist and O_CREAT was not requested."""
        assert self._path is not None
        parent_fd, name, parent = _open_trusted_parent(self._path)
        try:
            try:
                fd = os.open(name, flags | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise ReceiptError(
                    f"cannot securely open replay ledger {self._path}: {exc}"
                ) from exc
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ReceiptError(f"replay ledger is not a regular file: {self._path}")
                _validate_pinned_parent(parent_fd, parent)
            except Exception:
                os.close(fd)
                raise
            return fd
        finally:
            os.close(parent_fd)

    def consume(self, receipt_id: str) -> None:
        self.consume_many([receipt_id])

    def consume_many(self, receipt_ids: list[str]) -> None:
        """Consume a batch of receipt_ids as ONE atomic operation: either every
        id is recorded or none is. A multi-receipt transition (e.g. the paired
        ROUTING_REQUIRED->ROUTING_RESOLVED->READY_TO_SEND receipts for one
        request) must not be able to half-consume — two racing evaluations
        checking then appending id-by-id could interleave and each consume one
        receipt of the pair, leaving both requests half-advanced."""
        if len(set(receipt_ids)) != len(receipt_ids):
            raise ReceiptError("receipt replay: duplicate receipt_id within one batch")
        for rid in receipt_ids:
            if rid in self._seen:
                raise ReceiptError(f"receipt replay: {rid} already consumed")
        if self._path is not None:
            # The uniqueness check and the append must be ONE atomic
            # operation across processes: two ReplayLedger instances loaded
            # before either consumed would otherwise both pass a process-
            # local check and both append the same id. An exclusive file
            # lock serializes consumers; the on-disk state is re-read under
            # the lock so any id another process consumed since load is seen,
            # and the whole batch is checked and written under that one lock.
            self._path.absolute().parent.mkdir(parents=True, exist_ok=True)
            fd = self._open_pinned_ledger(os.O_RDWR | os.O_CREAT)
            assert fd is not None
            with os.fdopen(fd, "r+", encoding="utf-8") as fh:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                fh.seek(0)
                # Framing is validated UNDER the lock, before appending: an
                # unterminated tail from a crashed writer must abort the
                # consume instead of concatenating this batch's first id
                # onto the fragment.
                self._seen.update(self._parse_ledger(fh.read()))
                for rid in receipt_ids:
                    if rid in self._seen:
                        raise ReceiptError(f"receipt replay: {rid} already consumed")
                fh.seek(0, os.SEEK_END)
                fh.write("".join(rid + "\n" for rid in receipt_ids))
                fh.flush()
                os.fsync(fh.fileno())
                # flock releases on close
        self._seen.update(receipt_ids)

    def has(self, receipt_id: str) -> bool:
        return receipt_id in self._seen
