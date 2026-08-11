"""Evidence graph emission.

One evidence record per COMMITTED mutation, appended to
``evidence_graph.jsonl`` and cross-linked to the ledger COMMIT event that
authorized it. Evidence is a projection of the ledger: if the two ever
disagree, the ledger wins and the CI gate fails closed.

No silent mutation events: ``ci_gate`` enforces a bijection between
ledger COMMIT events and evidence records.
"""

from __future__ import annotations

import json
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
        audit chain actually contains.
        """
        commit = self._commit_event_for(ledger, receipt.receipt_id)
        if commit is None:
            raise EvidenceError(
                f"no COMMIT event for receipt {receipt.receipt_id}; refusing to fabricate evidence"
            )
        body = {
            "actor": commit.payload["actor"],
            "resource": commit.payload["resource"],
            "previous_hash": commit.payload["before_hash"],
            "new_hash": commit.payload["after_hash"],
            "decision": commit.payload["decision"],
            "receipt_id": receipt.receipt_id,
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
        record = {**body, "evidence_id": evidence_id, "signature": signature}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return record

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
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    @staticmethod
    def _commit_event_for(ledger: AuditLedger, receipt_id: str) -> LedgerEvent | None:
        for event in ledger.events():
            if event.type == EVENT_COMMIT and event.payload.get("receipt_id") == receipt_id:
                return event
        return None
