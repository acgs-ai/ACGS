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
from pathlib import Path
from typing import Any

from _canonical import canonical_json, hash_obj, hmac_sign, hmac_verify

RECEIPT_SCHEMA = "acgs_authority_transition_receipt/v1"
POLICY_VERSION = "external-substrate-authority-ingestion/v1"


class ReceiptError(RuntimeError):
    """Receipt invalid, replayed, or bound to different inputs — fail closed."""


def load_or_create_key(keystore: Path) -> bytes:
    """Load the HMAC key from a keystore outside the substrate, creating it on
    first use. The keystore lives in this package (gitignored), never in the
    read-only substrate.

    Creation is atomic and owner-only: the file is opened with
    O_CREAT|O_EXCL and mode 0600, so the key bytes are never observable
    through a world-readable window and a failure to restrict permissions
    fails closed instead of leaving a readable keystore behind.

    The key is raw random bytes and is read back verbatim — never
    whitespace-stripped. Stripping would reject (or worse, silently alter)
    a key whose first or last byte happens to be a whitespace byte, making
    load nondeterministically disagree with the key returned at creation."""
    if keystore.exists():
        if keystore.is_file():
            data = keystore.read_bytes()
            if len(data) >= 32:
                return data
        raise ReceiptError(f"keystore exists but holds no usable key: {keystore}")
    key = secrets.token_bytes(32)
    keystore.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(keystore, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        data = keystore.read_bytes()
        if len(data) >= 32:
            return data
        raise ReceiptError(f"keystore exists but holds no usable key: {keystore}") from None
    except OSError as exc:
        raise ReceiptError(f"cannot create keystore with owner-only permissions: {exc}") from exc
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def _decision_inputs(
    *,
    request_id: str,
    prior_state: str,
    new_state: str,
    authority_evidence_id: str,
    evidence_digest: str,
    authority_scope: Any,
    substrate_critical_set_digest: str,
) -> dict[str, Any]:
    return {
        "authority_evidence_id": authority_evidence_id,
        "authority_scope_digest": hash_obj(authority_scope),
        "evidence_digest": evidence_digest,
        "new_state": new_state,
        "policy_version": POLICY_VERSION,
        "prior_state": prior_state,
        "request_id": request_id,
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
    substrate_critical_set_digest: str,
    decision: str,
    decision_reason: str,
    created_at: str,
) -> dict[str, Any]:
    """Mint a signed receipt. created_at is a logical instant, not wall time."""
    inputs = _decision_inputs(
        request_id=request_id,
        prior_state=prior_state,
        new_state=new_state,
        authority_evidence_id=authority_evidence_id,
        evidence_digest=evidence_digest,
        authority_scope=authority_scope,
        substrate_critical_set_digest=substrate_critical_set_digest,
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
        "substrate_identity": substrate_critical_set_digest,
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
        sig = receipt["signature"]
        body = {k: v for k, v in receipt.items() if k != "signature"}
        if not hmac_verify(key, canonical_json(body), sig):
            return False
        inputs = _decision_inputs(
            request_id=receipt["request_id"],
            prior_state=receipt["prior_state"],
            new_state=receipt["new_state"],
            authority_evidence_id=receipt["authority_evidence_id"],
            evidence_digest=receipt["evidence_digest"],
            authority_scope=receipt["authority_scope"],
            substrate_critical_set_digest=receipt["substrate_identity"],
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
        if path is not None and path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                rid = line.strip()
                if rid:
                    self._seen.add(rid)

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
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a+", encoding="utf-8") as fh:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                fh.seek(0)
                for line in fh.read().splitlines():
                    rid = line.strip()
                    if rid:
                        self._seen.add(rid)
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
