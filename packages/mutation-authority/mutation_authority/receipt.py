"""Versioned, root-signed authorization for one filesystem effect."""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any

from .canonical import hash_obj, hmac_sign, hmac_verify

MUTATION_RECEIPT_SCHEMA = "acgs_mutation_decision_receipt/v2"


class ReceiptFormatError(ValueError):
    """A persisted receipt is legacy, malformed, or unsupported."""


@dataclass(frozen=True)
class MutationDecisionReceipt:
    schema: str
    receipt_id: str
    intent_hash: str
    decision_hash: str
    actor: str
    resource: str
    operation: str
    allowed_scope: str
    issued_at: int
    expiry: int
    previous_state_hash: str
    expected_state_hash: str
    expected_state_mode: int
    parent_ancestor_path: str
    parent_ancestor_device: int
    parent_ancestor_inode: int
    signature: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
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
            "expected_state_hash": self.expected_state_hash,
            "expected_state_mode": self.expected_state_mode,
            "parent_ancestor_path": self.parent_ancestor_path,
            "parent_ancestor_device": self.parent_ancestor_device,
            "parent_ancestor_inode": self.parent_ancestor_inode,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "signature": self.signature}

    @classmethod
    def issue(cls, body: dict[str, Any], root_key: bytes) -> MutationDecisionReceipt:
        if body.get("schema") != MUTATION_RECEIPT_SCHEMA:
            raise ReceiptFormatError("mutation receipt issuer requires schema v2")
        signature = hmac_sign(root_key, hash_obj(body))
        return cls.from_dict({**body, "signature": signature})

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MutationDecisionReceipt:
        if not isinstance(data, dict):
            raise ReceiptFormatError("mutation receipt must be an object")
        schema = data.get("schema")
        if schema is None:
            raise ReceiptFormatError(
                "legacy unversioned mutation receipt rejected: ancestor and "
                "authorized after-state bindings cannot be recovered safely"
            )
        if schema != MUTATION_RECEIPT_SCHEMA:
            raise ReceiptFormatError(f"unsupported mutation receipt schema: {schema!r}")
        expected = {item.name for item in fields(cls)}
        missing = sorted(expected - data.keys())
        extra = sorted(data.keys() - expected)
        if missing or extra:
            raise ReceiptFormatError(
                f"malformed mutation receipt fields: missing={missing}, extra={extra}"
            )
        string_fields = expected - {
            "issued_at",
            "expiry",
            "expected_state_mode",
            "parent_ancestor_device",
            "parent_ancestor_inode",
        }
        if any(not isinstance(data[name], str) for name in string_fields):
            raise ReceiptFormatError("mutation receipt string field has invalid type")
        for name in expected - string_fields:
            if isinstance(data[name], bool) or not isinstance(data[name], int):
                raise ReceiptFormatError(f"mutation receipt {name} must be an integer")
        if not 0 <= data["expected_state_mode"] <= 0o7777:
            raise ReceiptFormatError("mutation receipt expected_state_mode is invalid")
        return cls(**data)

    def verify_signature(self, root_key: bytes) -> bool:
        return self.schema == MUTATION_RECEIPT_SCHEMA and hmac_verify(
            root_key, hash_obj(self.body()), self.signature
        )
