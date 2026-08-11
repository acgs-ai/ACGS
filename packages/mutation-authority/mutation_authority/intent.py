"""Mutation Intent model.

No agent writes to the governed repository directly. Every critical write
is first expressed as a MutationIntent, signed with the actor's identity
key, and submitted to the decision engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import hash_obj, hmac_sign

OPERATIONS = ("CREATE", "UPDATE", "DELETE")


@dataclass(frozen=True)
class MutationIntent:
    actor_identity: str
    resource_path: str
    operation: str  # CREATE | UPDATE | DELETE
    expected_pre_hash: str  # sha256 of current content, or ABSENT for CREATE
    expected_post_hash: str  # sha256 of requested bytes, or ABSENT for DELETE
    requested_change_scope: str  # glob the mutation claims to stay inside
    timestamp: int  # logical clock tick
    task_reference: str
    nonce: str  # uniqueness salt so identical intents hash apart

    def payload(self) -> dict[str, Any]:
        return {
            "actor_identity": self.actor_identity,
            "resource_path": self.resource_path,
            "operation": self.operation,
            "expected_pre_hash": self.expected_pre_hash,
            "expected_post_hash": self.expected_post_hash,
            "requested_change_scope": self.requested_change_scope,
            "timestamp": self.timestamp,
            "task_reference": self.task_reference,
            "nonce": self.nonce,
        }

    def intent_hash(self) -> str:
        return hash_obj(self.payload())


@dataclass(frozen=True)
class SignedIntent:
    intent: MutationIntent
    signature: str  # HMAC(actor_key, intent_hash)

    @classmethod
    def create(cls, intent: MutationIntent, actor_key: bytes) -> SignedIntent:
        return cls(intent=intent, signature=hmac_sign(actor_key, intent.intent_hash()))
