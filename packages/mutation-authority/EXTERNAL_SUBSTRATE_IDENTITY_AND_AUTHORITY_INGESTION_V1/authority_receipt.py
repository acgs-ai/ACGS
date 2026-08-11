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
    read-only substrate."""
    if keystore.is_file():
        data = keystore.read_bytes().strip()
        if len(data) >= 32:
            return data
    key = secrets.token_bytes(32)
    keystore.parent.mkdir(parents=True, exist_ok=True)
    keystore.write_bytes(key)
    try:
        os.chmod(keystore, 0o600)
    except OSError:
        pass
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
        if receipt_id in self._seen:
            raise ReceiptError(f"receipt replay: {receipt_id} already consumed")
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(receipt_id + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        self._seen.add(receipt_id)

    def has(self, receipt_id: str) -> bool:
        return receipt_id in self._seen
