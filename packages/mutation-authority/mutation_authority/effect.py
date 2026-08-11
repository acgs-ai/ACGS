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
from dataclasses import dataclass
from pathlib import Path

from .canonical import ABSENT, hash_file, sha256_hex
from .engine import _verify_chain_root_binding
from .ledger import EVENT_COMMIT, AuditLedger
from .receipt import MutationDecisionReceipt
from .root import GovernanceRoot

ACCEPTED = "ACCEPTED"
REJECTED = "REJECTED"


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

        # 4. Expiry.
        if now > receipt.expiry:
            return CommitResult(REJECTED, "receipt expired")

        # 5. Content/operation coherence.
        if receipt.operation == "DELETE" and new_content is not None:
            return CommitResult(REJECTED, "DELETE receipt cannot carry new content")
        if receipt.operation != "DELETE" and new_content is None:
            return CommitResult(REJECTED, f"{receipt.operation} requires new content")

        # 6. Pre-state binding: the file must still be exactly the state
        #    the decision was made against.
        target = self.repo_dir / receipt.resource
        before_hash = hash_file(target)
        if before_hash != receipt.previous_state_hash:
            return CommitResult(
                REJECTED,
                "resource changed after approval (pre-state hash mismatch)",
                before_hash=before_hash,
            )

        # 7. Apply the effect atomically.
        if receipt.operation == "DELETE":
            target.unlink()
            after_hash = ABSENT
        else:
            assert new_content is not None
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_name(target.name + ".mutation-authority.tmp")
            tmp.write_bytes(new_content)
            os.replace(tmp, target)
            after_hash = sha256_hex(new_content)

        # 8. Bind the effect into the audit chain.
        self.ledger.append(
            EVENT_COMMIT,
            {
                "receipt_id": receipt.receipt_id,
                "actor": receipt.actor,
                "resource": receipt.resource,
                "before_hash": before_hash,
                "after_hash": after_hash,
                "decision": "ALLOW",
            },
            now,
        )
        return CommitResult(
            ACCEPTED, "effect bound", before_hash=before_hash, after_hash=after_hash
        )
