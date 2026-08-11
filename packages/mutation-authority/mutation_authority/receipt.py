"""Mutation Decision Receipt.

A receipt is the only object that authorizes a filesystem effect. It is
signed by the governance root key, bound to the exact pre-state hash of
the resource, single-use, and expiring.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import hash_obj, hmac_sign, hmac_verify


@dataclass(frozen=True)
class MutationDecisionReceipt:
    receipt_id: str
    intent_hash: str
    decision_hash: str
    actor: str
    resource: str
    operation: str
    allowed_scope: str
    issued_at: int  # logical clock tick
    expiry: int  # last logical tick at which the receipt may be committed
    previous_state_hash: str
    signature: str  # HMAC(root_key, hash of all fields above)

    def body(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "intent_hash": self.intent_hash,
            "decision_hash": self.decision_hash,
            "actor": self.actor,
            "resource": self.resource,
            "operation": self.operation,
            "allowed_scope": self.allowed_scope,
            "issued_at": self.issued_at,
            "expiry": self.expiry,
            "previous_state_hash": self.previous_state_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "signature": self.signature}

    @classmethod
    def issue(cls, body: dict[str, Any], root_key: bytes) -> MutationDecisionReceipt:
        signature = hmac_sign(root_key, hash_obj(body))
        return cls(**body, signature=signature)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MutationDecisionReceipt:
        return cls(**data)

    def verify_signature(self, root_key: bytes) -> bool:
        return hmac_verify(root_key, hash_obj(self.body()), self.signature)
