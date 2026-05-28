"""Receipt — the full proof-of-decision artifact for one dispatch.

A :class:`Receipt` is what the kernel returns alongside a successful tool
result. It packages the :class:`~gove_zone.decision.DecisionRecord`, the
audit chain hash, the actor identity, and a digest of the result. Receipts
are the unit of replay (see :mod:`gove_zone.replay`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from gove_zone.decision import DecisionRecord, sha256_json


def safe_result_hash(value: Any) -> str:
    """Hash *value* deterministically.

    Falls back to ``repr(value)[:512]`` for non-JSON-serializable values so
    the receipt always carries a hash even when a tool returns objects we
    cannot canonicalize.
    """
    try:
        json.dumps(value, sort_keys=True, default=str)
        return sha256_json(value)
    except (TypeError, ValueError):
        return sha256_json({"_repr": repr(value)[:512]})


@dataclass(frozen=True)
class Receipt:
    """Proof-of-decision: the decision, the audit anchor, and the outcome.

    Attributes:
        record: the policy's frozen :class:`DecisionRecord`.
        audit_hash: ``event_hash`` returned by the audit store on append.
        actor: opaque identity string ("anonymous" by default).
        result_hash: SHA-256 of the canonical-JSON of the tool result, or
            ``None`` if the dispatch did not execute (DENY/ESCALATE).
        error_class: class name of the exception raised by tool execution,
            or ``None`` if execution succeeded or never ran.
    """

    record: DecisionRecord
    audit_hash: str
    actor: str = "anonymous"
    result_hash: str | None = None
    error_class: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.record.to_dict(),
            "audit_hash": self.audit_hash,
            "actor": self.actor,
            "result_hash": self.result_hash,
            "error_class": self.error_class,
        }


@dataclass(frozen=True)
class DecisionReceipt:
    """Canonical public Decision Receipt schema for AI-agent execution.

    Designed for deterministic serialisation, canonical hashing, and fail-closed validation.
    """

    receipt_id: str
    request_id: str
    tenant_id: str
    actor: str
    proposed_action: str
    declared_goal: str
    execution_boundary: str
    policy_bundle_id: str
    policy_version: str
    policy_hash: str
    decision: str
    matched_rules: list[str]
    constraints: dict[str, Any]
    transformations: list[dict[str, Any]]
    approval_chain_summary: dict[str, Any]
    timestamp: str
    previous_audit_hash: str
    audit_event_hash: str
    subject: str = ""
    receipt_hash: str = ""
    signature: str = "unsigned_local"

    def to_dict(self) -> dict[str, Any]:
        transformations_list: Any = []
        if isinstance(self.transformations, list):
            for t in self.transformations:
                if isinstance(t, dict):
                    transformations_list.append(dict(t))
                else:
                    transformations_list.append(t)
        else:
            transformations_list = self.transformations

        return {
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "actor": self.actor,
            "subject": self.subject,
            "proposed_action": self.proposed_action,
            "declared_goal": self.declared_goal,
            "execution_boundary": self.execution_boundary,
            "policy_bundle_id": self.policy_bundle_id,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "decision": self.decision,
            "matched_rules": list(self.matched_rules),
            "constraints": (
                dict(self.constraints) if isinstance(self.constraints, dict) else self.constraints
            ),
            "transformations": transformations_list,
            "approval_chain_summary": (
                dict(self.approval_chain_summary)
                if isinstance(self.approval_chain_summary, dict)
                else self.approval_chain_summary
            ),
            "timestamp": self.timestamp,
            "previous_audit_hash": self.previous_audit_hash,
            "audit_event_hash": self.audit_event_hash,
            "receipt_hash": self.receipt_hash,
            "signature": self.signature,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DecisionReceipt:
        return cls(
            receipt_id=d["receipt_id"],
            request_id=d["request_id"],
            tenant_id=d["tenant_id"],
            actor=d["actor"],
            subject=d.get("subject", ""),
            proposed_action=d["proposed_action"],
            declared_goal=d["declared_goal"],
            execution_boundary=d["execution_boundary"],
            policy_bundle_id=d["policy_bundle_id"],
            policy_version=d["policy_version"],
            policy_hash=d["policy_hash"],
            decision=d["decision"],
            matched_rules=list(d["matched_rules"]),
            constraints=dict(d.get("constraints", {})),
            transformations=[dict(t) for t in d.get("transformations", [])],
            approval_chain_summary=dict(d.get("approval_chain_summary", {})),
            timestamp=d["timestamp"],
            previous_audit_hash=d["previous_audit_hash"],
            audit_event_hash=d["audit_event_hash"],
            receipt_hash=d.get("receipt_hash", ""),
            signature=d.get("signature", "unsigned_local"),
        )

    @classmethod
    def from_json(cls, text: str) -> DecisionReceipt:
        return cls.from_dict(json.loads(text))

    def compute_hash(self) -> str:
        d = self.to_dict()
        d.pop("receipt_hash", None)
        d.pop("signature", None)
        return sha256_json(d)

    @classmethod
    def from_record(
        cls,
        record: DecisionRecord,
        audit_hash: str,
        previous_audit_hash: str,
        tenant_id: str,
        execution_boundary: str,
        policy_bundle_id: str,
        policy_hash: str,
        request_id: str,
        subject: str = "",
        constraints: dict[str, Any] | None = None,
        approval_chain_summary: dict[str, Any] | None = None,
    ) -> DecisionReceipt:
        transformations: list[dict[str, Any]] = []
        if record.transformed_args:
            for k, v in record.transformed_args.items():
                transformations.append({"field": k, "value": v})

        import dataclasses

        receipt = cls(
            receipt_id=record.event_id,
            request_id=request_id,
            tenant_id=tenant_id,
            actor=record.actor or "anonymous",
            subject=subject,
            proposed_action=record.tool,
            declared_goal=record.goal or "",
            execution_boundary=execution_boundary,
            policy_bundle_id=policy_bundle_id,
            policy_version=record.policy_version,
            policy_hash=policy_hash,
            decision=record.decision.value,
            matched_rules=list(record.matched_rules),
            constraints=constraints or {},
            transformations=transformations,
            approval_chain_summary=approval_chain_summary or {},
            timestamp=record.timestamp_iso,
            previous_audit_hash=previous_audit_hash,
            audit_event_hash=audit_hash,
        )
        h = receipt.compute_hash()
        return dataclasses.replace(receipt, receipt_hash=h)

    def verify(
        self,
        *,
        expected_tenant_id: str | None = None,
        expected_execution_boundary: str | None = None,
        expected_audit_hash: str | None = None,
        expected_args: dict[str, Any] | None = None,
        expected_action: str | None = None,
        expected_policy_hash: str | None = None,
        expected_policy_bundle_id: str | None = None,
    ) -> None:
        from gove_zone.decision import Decision
        from gove_zone.errors import ReceiptValidationError

        # 1. Missing fields
        required_fields = [
            "receipt_id",
            "request_id",
            "tenant_id",
            "actor",
            "proposed_action",
            "execution_boundary",
            "policy_bundle_id",
            "policy_version",
            "policy_hash",
            "decision",
            "timestamp",
            "previous_audit_hash",
            "audit_event_hash",
        ]
        for field_name in required_fields:
            val = getattr(self, field_name)
            if val is None or val == "":
                raise ReceiptValidationError(f"Missing or empty required field: {field_name}")

        # 2. Check receipt hash (reject altered fields or invalid hash)
        if not self.receipt_hash:
            raise ReceiptValidationError("receipt_hash is missing")
        expected_hash = self.compute_hash()
        if self.receipt_hash != expected_hash:
            raise ReceiptValidationError(
                f"Altered field or invalid hash: receipt_hash mismatch. "
                f"Expected {expected_hash}, got {self.receipt_hash}"
            )

        # 3. Unknown decisions
        try:
            Decision(self.decision)
        except ValueError as err:
            raise ReceiptValidationError(f"Unknown decision: {self.decision}") from err

        # 4. Denied and escalated receipts
        if self.decision == Decision.DENY:
            raise ReceiptValidationError("Denied receipt cannot authorize execution")
        if self.decision == Decision.ESCALATE:
            raise ReceiptValidationError("Escalated receipt cannot authorize execution")

        # 5. Wrong tenant
        if expected_tenant_id is not None and self.tenant_id != expected_tenant_id:
            raise ReceiptValidationError(
                f"Tenant mismatch: expected {expected_tenant_id}, got {self.tenant_id}"
            )

        # 6. Wrong execution boundary
        if (
            expected_execution_boundary is not None
            and self.execution_boundary != expected_execution_boundary
        ):
            raise ReceiptValidationError(
                f"Execution boundary mismatch: expected {expected_execution_boundary}, "
                f"got {self.execution_boundary}"
            )

        # 7. Action mismatch
        if expected_action is not None and self.proposed_action != expected_action:
            raise ReceiptValidationError(
                f"Action mismatch: expected {expected_action}, got {self.proposed_action}"
            )

        # 8. Audit hash mismatch
        if expected_audit_hash is not None and self.audit_event_hash != expected_audit_hash:
            raise ReceiptValidationError(
                f"Audit hash mismatch: expected {expected_audit_hash}, got {self.audit_event_hash}"
            )

        # 9. Malformed transformations
        if not isinstance(self.transformations, list):
            raise ReceiptValidationError("transformations must be a list")
        for tx in self.transformations:
            if not isinstance(tx, dict):
                raise ReceiptValidationError("each transformation must be a dictionary")
            if "field" not in tx or "value" not in tx:
                raise ReceiptValidationError(
                    "transformation dictionary must contain 'field' and 'value' keys"
                )
            if not isinstance(tx["field"], str):
                raise ReceiptValidationError("transformation 'field' key must be a string")

        # 10. Transform mismatch
        if self.decision == Decision.TRANSFORM.value and expected_args is not None:
            for tx in self.transformations:
                f = tx["field"]
                val = tx["value"]
                if f not in expected_args:
                    raise ReceiptValidationError(
                        f"Transform mismatch: field '{f}' is missing from arguments"
                    )
                if expected_args[f] != val:
                    raise ReceiptValidationError(
                        f"Transform mismatch: field '{f}' expected '{val}', "
                        f"got '{expected_args[f]}'"
                    )

        # 11. Policy hash mismatch
        if expected_policy_hash is not None and self.policy_hash != expected_policy_hash:
            raise ReceiptValidationError(
                f"Policy hash mismatch: expected {expected_policy_hash}, got {self.policy_hash}"
            )

        # 12. Policy bundle ID mismatch
        if (
            expected_policy_bundle_id is not None
            and self.policy_bundle_id != expected_policy_bundle_id
        ):
            raise ReceiptValidationError(
                f"Policy bundle ID mismatch: expected {expected_policy_bundle_id}, "
                f"got {self.policy_bundle_id}"
            )
