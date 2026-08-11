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
import stat
from dataclasses import dataclass
from pathlib import Path

from .canonical import ABSENT, hash_file
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
            (
                e.timestamp
                for e in self.ledger.events()
                if e.type in (EVENT_GENESIS, EVENT_COMMIT)
            ),
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
        before_hash = hash_file(target)
        if before_hash != receipt.previous_state_hash:
            return CommitResult(
                REJECTED,
                "resource changed after approval (pre-state hash mismatch)",
                before_hash=before_hash,
            )

        # 7. Apply the effect atomically. Snapshot the prior bytes first so
        #    an effect that cannot be recorded (step 8) can be rolled back.
        prior_bytes = target.read_bytes() if before_hash != ABSENT else None
        if receipt.operation == "DELETE":
            target.unlink()
            after_hash = ABSENT
        else:
            assert new_content is not None
            resolved.parent.mkdir(parents=True, exist_ok=True)
            tmp = resolved.with_name(resolved.name + ".mutation-authority.tmp")
            tmp.write_bytes(new_content)
            if before_hash != ABSENT:
                # An UPDATE replaces content, not file metadata: preserve the
                # pre-existing permission bits (e.g. the executable bit) that
                # os.replace with a fresh temp file would silently drop.
                os.chmod(tmp, stat.S_IMODE(os.stat(resolved).st_mode))
            os.replace(tmp, resolved)
            # Re-hash from disk (not from the input bytes) so the recorded
            # after-state binds exactly what the repository now contains,
            # including file-metadata state (symlink/exec) — never a value
            # the on-disk state could silently diverge from.
            after_hash = hash_file(target)

        # 8. Bind the effect into the audit chain. If the append fails, the
        #    effect must not persist: roll the file back and fail loudly —
        #    an applied-but-unaudited mutation is indistinguishable from an
        #    unauthorized out-of-band write.
        try:
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
                effective_now,
            )
        except Exception as exc:
            if prior_bytes is None:
                target.unlink(missing_ok=True)
            else:
                target.write_bytes(prior_bytes)
            raise EffectRecordingError(
                "effect could not be bound to the audit chain; "
                "filesystem change rolled back"
            ) from exc
        return CommitResult(
            ACCEPTED, "effect bound", before_hash=before_hash, after_hash=after_hash
        )
