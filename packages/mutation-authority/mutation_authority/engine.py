"""Mutation Decision Engine.

Deterministic verifier: SignedIntent in, ALLOW/DENY out. ALLOW produces a
signed MutationDecisionReceipt. Every decision — including every DENY —
is appended to the audit chain.

Check order is fixed and documented; the same intent against the same
repository/ledger state always yields the same decision and the same
decision_hash.
"""

from __future__ import annotations

import os
import posixpath
import stat
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from .canonical import ABSENT, hash_file, hash_obj, hmac_verify, sha256_hex
from .intent import OPERATIONS, SignedIntent
from .ledger import EVENT_DECISION, AuditLedger, LedgerIntegrityError
from .receipt import MutationDecisionReceipt
from .root import GovernanceRoot, UnknownActorError
from .state import governed_match

ALLOW = "ALLOW"
DENY = "DENY"


@dataclass(frozen=True)
class Decision:
    decision: str  # ALLOW | DENY
    reason: str
    intent_hash: str
    decision_hash: str
    receipt: MutationDecisionReceipt | None


def _verify_chain_root_binding(ledger: AuditLedger, root: GovernanceRoot) -> None:
    """The genesis event must name THIS governance root's manifest hash.

    Prevents pairing an engine/binder with a ledger that was initialized
    against a different (or attacker-fabricated) governance root.
    """
    recorded = ledger.genesis().payload.get("root_manifest_hash")
    if recorded != root.manifest_hash():
        raise LedgerIntegrityError(
            f"audit chain is not bound to this governance root (genesis={recorded!r})"
        )


def _normalized(resource_path: str) -> str | None:
    """Normalize a governed path; None if it escapes the repository."""
    if not resource_path or resource_path.startswith(("/", "\\")):
        return None
    norm = posixpath.normpath(resource_path)
    if norm.startswith("..") or norm == "." or "\\" in norm:
        return None
    return norm


def _capture_parent_precondition(repo_dir: Path, resource: str) -> tuple[dict[str, Any], str]:
    """Pin the nearest existing parent ancestor and hash state through its fd."""
    parts = Path(resource).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise OSError("resource path is not canonical")
    fd = os.open(repo_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    traversed: list[str] = []
    parent_missing = False
    try:
        for part in parts[:-1]:
            try:
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
            except FileNotFoundError:
                parent_missing = True
                break
            os.close(fd)
            fd = child
            traversed.append(part)

        ancestor = os.fstat(fd)
        binding: dict[str, Any] = {
            "path": "/".join(traversed),
            "device": ancestor.st_dev,
            "inode": ancestor.st_ino,
        }
        if parent_missing:
            return binding, ABSENT

        try:
            target_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        except FileNotFoundError:
            return binding, ABSENT
        try:
            target_stat = os.fstat(target_fd)
            if not stat.S_ISREG(target_stat.st_mode):
                raise OSError("resource is not a regular file")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(target_fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            digest = sha256_hex(b"".join(chunks))
            if target_stat.st_mode & 0o111:
                digest += ":exec"
            return binding, digest
        finally:
            os.close(target_fd)
    finally:
        os.close(fd)


class DecisionEngine:
    def __init__(self, root: GovernanceRoot, ledger: AuditLedger, repo_dir: Path):
        self.root = root
        self.ledger = ledger
        self.repo_dir = repo_dir

    def decide(self, signed: SignedIntent, now: int) -> Decision:
        # Fail closed: a tampered governance root refuses ALL decisions.
        self.root.verify_integrity()
        self.ledger.verify_chain()
        _verify_chain_root_binding(self.ledger, self.root)

        intent = signed.intent
        intent_hash = intent.intent_hash()

        deny_reason = self._first_violation(signed, now)
        parent_precondition: dict[str, Any] | None = None
        if deny_reason is None:
            resource = _normalized(intent.resource_path)
            assert resource is not None
            try:
                parent_precondition, secured_hash = _capture_parent_precondition(
                    self.repo_dir, resource
                )
            except OSError:
                deny_reason = "resource parent/state could not be securely pinned"
            else:
                authorized = self.ledger.authorized_state(resource)
                if secured_hash != authorized:
                    deny_reason = (
                        "resource state diverged from audit chain "
                        "(unauthorized out-of-band mutation detected)"
                    )
                elif intent.expected_pre_hash != secured_hash:
                    deny_reason = "expected_pre_hash does not match current resource state"
                elif intent.operation == "CREATE" and secured_hash != ABSENT:
                    deny_reason = "CREATE on a resource that already exists"
                elif intent.operation in ("UPDATE", "DELETE") and secured_hash == ABSENT:
                    deny_reason = f"{intent.operation} on a resource that does not exist"

        if deny_reason is not None:
            return self._record(DENY, deny_reason, intent_hash, intent, now)
        return self._record(
            ALLOW,
            "all checks passed",
            intent_hash,
            intent,
            now,
            parent_precondition=parent_precondition,
        )

    # -- checks (fixed order, first violation wins) -----------------------

    def _first_violation(self, signed: SignedIntent, now: int) -> str | None:
        intent = signed.intent

        # 1. Actor identity: registered, active, signature verifies.
        record = self.root.actor_record(intent.actor_identity)
        if record is None or record.get("status") != "active":
            return "actor not registered or inactive"
        try:
            actor_key = self.root.actor_key(intent.actor_identity)
        except UnknownActorError:
            return "actor has no registered key"
        if not hmac_verify(actor_key, intent.intent_hash(), signed.signature):
            return "intent signature invalid"

        # 2. Structural validity.
        if intent.operation not in OPERATIONS:
            return f"unknown operation: {intent.operation}"
        resource = _normalized(intent.resource_path)
        if resource is None:
            return "resource path escapes governed repository"

        # 3. Containment: the RESOLVED path (symlinks followed) must stay
        #    inside the governed repository. String normalization alone
        #    cannot see a symlinked directory that points outside the repo,
        #    so a lexically clean path could otherwise write anywhere the
        #    process can. Fail closed on any escape.
        resolved = (self.repo_dir / resource).resolve()
        repo_root = self.repo_dir.resolve()
        if resolved != repo_root and not resolved.is_relative_to(repo_root):
            return "resource resolves outside the governed repository (symlink escape)"

        # 4. Governance root is never mutable through the mutation path.
        #    Structural check first: independent of policy authoring, any
        #    path resolving under root_dir is refused.
        root_dir = self.root.root_dir.resolve()
        if resolved == root_dir or root_dir in resolved.parents:
            return "resource is inside the immutable governance root"
        for prefix in self.root.protected_prefixes():
            if resource == prefix or resource.startswith(prefix.rstrip("/") + "/"):
                return "resource is inside the immutable governance root"

        # 5. Resource must be governed at all. governed_match is the SAME
        #    predicate the repository scan (state.repository_violations)
        #    applies, so what is gated on write is exactly what verification
        #    watches on disk.
        if not governed_match(resource, self.root.governed_prefixes()):
            return "resource is outside every governed prefix"

        # 6. Scope permission: requested scope must cover the resource AND
        #    be within the actor's allowed scopes (ownership). fnmatchcase:
        #    scope semantics must not vary with platform case-folding.
        if not fnmatchcase(resource, intent.requested_change_scope):
            return "requested_change_scope does not cover the resource"
        allowed_scopes = record.get("scopes", [])
        if not any(fnmatchcase(resource, scope) for scope in allowed_scopes):
            return "actor scope does not permit this resource"

        # 7. Task authority: the referenced task must grant this actor.
        if not self._task_authorized(intent.task_reference, intent.actor_identity):
            return "task_reference does not authorize this actor"

        # 8. Pre-state binding: disk must match BOTH the ledger-derived
        #    authorized state (detects out-of-band mutation — Attack A is
        #    not launderable) and the intent's expected_pre_hash.
        disk_hash = hash_file(self.repo_dir / resource)
        authorized = self.ledger.authorized_state(resource)
        if disk_hash != authorized:
            return (
                "resource state diverged from audit chain "
                "(unauthorized out-of-band mutation detected)"
            )
        if intent.expected_pre_hash != disk_hash:
            return "expected_pre_hash does not match current resource state"
        if intent.operation == "CREATE" and disk_hash != ABSENT:
            return "CREATE on a resource that already exists"
        if intent.operation in ("UPDATE", "DELETE") and disk_hash == ABSENT:
            return f"{intent.operation} on a resource that does not exist"

        # 9. Concurrency: exactly one live receipt per resource.
        if self.ledger.open_receipts_for(resource, now):
            return "conflicting mutation in flight for this resource"

        return None

    def _task_authorized(self, task_reference: str, actor: str) -> bool:
        for pattern, actors in self.root.task_authorities().items():
            if fnmatchcase(task_reference, pattern):
                return actor in actors
        return False

    # -- recording --------------------------------------------------------

    def _record(
        self,
        decision: str,
        reason: str,
        intent_hash: str,
        intent: Any,
        now: int,
        *,
        parent_precondition: dict[str, Any] | None = None,
    ) -> Decision:
        decision_body = {
            "decision": decision,
            "reason": reason,
            "intent_hash": intent_hash,
            "chain_head": self.ledger.head_hash(),
            "timestamp": now,
            "parent_precondition": parent_precondition,
        }
        decision_hash = hash_obj(decision_body)

        receipt: MutationDecisionReceipt | None = None
        payload: dict[str, Any] = {
            "decision": decision,
            "reason": reason,
            "intent_hash": intent_hash,
            "decision_hash": decision_hash,
            "actor": intent.actor_identity,
            "resource": intent.resource_path,
        }
        if decision == ALLOW:
            resource = _normalized(intent.resource_path)
            assert resource is not None  # already validated
            assert parent_precondition is not None
            body = {
                "receipt_id": hash_obj({"intent": intent_hash, "decision": decision_hash}),
                "intent_hash": intent_hash,
                "decision_hash": decision_hash,
                "actor": intent.actor_identity,
                "resource": resource,
                "operation": intent.operation,
                "allowed_scope": intent.requested_change_scope,
                "issued_at": now,
                "expiry": now + self.root.receipt_ttl(),
                "previous_state_hash": intent.expected_pre_hash,
                "parent_ancestor_path": parent_precondition["path"],
                "parent_ancestor_device": parent_precondition["device"],
                "parent_ancestor_inode": parent_precondition["inode"],
            }
            receipt = MutationDecisionReceipt.issue(body, self.root.root_key())
            payload["receipt"] = receipt.to_dict()

        self.ledger.append(EVENT_DECISION, payload, now)
        return Decision(
            decision=decision,
            reason=reason,
            intent_hash=intent_hash,
            decision_hash=decision_hash,
            receipt=receipt,
        )
