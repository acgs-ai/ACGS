"""Runtime mutation gateway.

Converts a runtime mutation request into the governed pipeline:

    AuthorityContext -> MutationIntent -> DecisionEngine -> Receipt
                     -> EffectBinder -> ledger COMMIT -> evidence record

The gateway itself NEVER writes repository state. Its only write path is
``EffectBinder.commit``, which demands a valid, issued, unconsumed,
unexpired, pre-state-bound receipt. A request without a resolvable
authority context is rejected before an intent is even constructed.

Determinism: logical time is derived from the ledger head (max event
timestamp + 1); nonces are hashes of (actor, resource, chain head, tick).
No wall clock, no randomness.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..canonical import hash_file, hash_obj
from ..effect import ACCEPTED, EffectBinder
from ..engine import ALLOW, DecisionEngine
from ..evidence_emitter import EvidenceEmitter
from ..intent import OPERATIONS, MutationIntent, SignedIntent
from ..ledger import AuditLedger
from ..receipt import MutationDecisionReceipt
from ..root import GovernanceRoot

APPLIED = "APPLIED"
DENIED = "DENIED"
REJECTED = "REJECTED"


@dataclass(frozen=True)
class AuthorityContext:
    """Identity + authority carried by every runtime mutation request."""

    actor_id: str
    actor_key: bytes
    task_reference: str


@dataclass(frozen=True)
class GatewayResult:
    status: str  # APPLIED | DENIED | REJECTED
    reason: str
    receipt: MutationDecisionReceipt | None = None
    evidence_id: str | None = None
    after_hash: str | None = None


class MutationGateway:
    def __init__(
        self,
        root: GovernanceRoot,
        ledger: AuditLedger,
        repo_dir: Path,
        evidence: EvidenceEmitter,
    ):
        self.root = root
        self.ledger = ledger
        self.repo_dir = repo_dir
        self.evidence = evidence
        self.engine = DecisionEngine(root, ledger, repo_dir)
        self.binder = EffectBinder(root, ledger, repo_dir)

    # -- public API -------------------------------------------------------

    def request_mutation(
        self,
        context: AuthorityContext | None,
        resource_path: str,
        operation: str,
        new_content: bytes | None,
    ) -> GatewayResult:
        # 1. Authority context is mandatory and must resolve. Rejected
        #    before any intent exists — nothing is signed, nothing appended.
        context_error = self._context_error(context)
        if context_error is not None:
            return GatewayResult(REJECTED, context_error)
        assert context is not None

        if operation not in OPERATIONS:
            return GatewayResult(REJECTED, f"unknown operation: {operation}")

        # 2. Build + sign the intent (CAS read of current pre-state).
        now = self._next_tick()
        intent = MutationIntent(
            actor_identity=context.actor_id,
            resource_path=resource_path,
            operation=operation,
            expected_pre_hash=hash_file(self.repo_dir / resource_path),
            requested_change_scope=resource_path,
            timestamp=now,
            task_reference=context.task_reference,
            nonce=hash_obj(
                {
                    "actor": context.actor_id,
                    "resource": resource_path,
                    "chain_head": self.ledger.head_hash(),
                    "tick": now,
                }
            ),
        )
        signed = SignedIntent.create(intent, context.actor_key)

        # 3. Authority decision.
        decision = self.engine.decide(signed, now)
        if decision.decision != ALLOW or decision.receipt is None:
            return GatewayResult(DENIED, decision.reason)

        # 4. Effect binding — the ONLY state-changing call in this class.
        result = self.binder.commit(decision.receipt, new_content, self._next_tick())
        if result.status != ACCEPTED:
            return GatewayResult(REJECTED, result.reason, receipt=decision.receipt)

        # 5. Evidence emission, cross-linked to the ledger COMMIT event.
        #    The effect and its COMMIT are already durable at this point, so
        #    an evidence-file write failure (full/read-only filesystem) must
        #    not surface as a failed mutation: evidence is a deterministic
        #    projection of the ledger and is re-emitted from it — here on the
        #    next successful request, or explicitly via
        #    EvidenceEmitter.recover_missing — restoring the COMMIT-to-
        #    evidence bijection the CI gate enforces.
        try:
            # Heal any earlier deferred emissions first, then emit this one.
            self.evidence.recover_missing(self.root, self.ledger)
            record = self.evidence.emit_for_receipt(self.root, self.ledger, decision.receipt)
        except OSError:
            return GatewayResult(
                APPLIED,
                "mutation applied under receipt; evidence emission deferred "
                "(recoverable from the committed ledger via "
                "EvidenceEmitter.recover_missing)",
                receipt=decision.receipt,
                evidence_id=None,
                after_hash=result.after_hash,
            )
        return GatewayResult(
            APPLIED,
            "mutation applied under receipt",
            receipt=decision.receipt,
            evidence_id=record["evidence_id"],
            after_hash=result.after_hash,
        )

    # -- helpers ----------------------------------------------------------

    def _context_error(self, context: AuthorityContext | None) -> str | None:
        if context is None:
            return "missing authority context"
        if not context.actor_id or not context.actor_key:
            return "incomplete authority context (actor id and key required)"
        if not context.task_reference:
            return "incomplete authority context (task_reference required)"
        record = self.root.actor_record(context.actor_id)
        if record is None or record.get("status") != "active":
            return "authority context does not resolve to an active registered actor"
        return None

    def _next_tick(self) -> int:
        """Logical clock = ledger event count, NOT max(event.timestamp).

        Event timestamps are caller-supplied and the kernel records a
        DECISION event even for an unauthenticated DENY, so trusting
        max(timestamp) let any uncredentialed caller inject a huge value
        and instantly expire every other agent's live receipt (a DoS on
        the concurrency invariant). Event count is monotonic and advances
        by exactly one per appended event, so a spam DENY costs one tick,
        is attributable, and cannot leap the clock forward.

        Structural safety: verify the chain (anchor-checked) BEFORE counting,
        so a truncated/rewritten ledger cannot yield a shrunken tick value —
        the safety is enforced here, not left to the caller's convention of
        calling verify_chain first.
        """
        self.ledger.verify_chain()
        return sum(1 for _ in self.ledger.events())
