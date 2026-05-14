"""Frontend contract helpers for the Gove Zone console.

The runtime's canonical artifact is still the audit-chained
``DecisionRecord``/``Receipt`` pair. This module only projects that proof into
the small JSON shape the React console needs to answer:

- what the agent tried to do,
- what governance decided,
- why it decided that,
- which receipt/audit hash proves it, and
- how to replay the evidence.
"""

from __future__ import annotations

from typing import Any, Literal

from gove_zone.decision import Decision, DecisionRecord, canonical_json
from gove_zone.receipt import Receipt

Outcome = Literal["allowed", "denied", "transformed", "escalated"]
Posture = Literal["confirmed", "partial", "blocked", "privileged"]


def _outcome(decision: Decision) -> Outcome:
    return {
        Decision.ALLOW: "allowed",
        Decision.DENY: "denied",
        Decision.TRANSFORM: "transformed",
        Decision.ESCALATE: "escalated",
    }[decision]


def _posture(decision: Decision) -> Posture:
    return {
        Decision.ALLOW: "confirmed",
        Decision.DENY: "blocked",
        Decision.TRANSFORM: "privileged",
        Decision.ESCALATE: "partial",
    }[decision]


def record_to_governed_action(
    record: DecisionRecord,
    *,
    audit_hash: str,
    args_before: dict[str, Any],
    actor: str = "anonymous",
    result_hash: str | None = None,
) -> dict[str, Any]:
    """Project a governed decision into the frontend action-console shape.

    This is intentionally deterministic and dependency-free so API gateways,
    file exporters, or tests can all use the same adapter. ``args_before`` is
    required because the audit event stores only ``argument_hash``; retaining
    the raw attempted payload is what makes the frontend's before/after and
    strong replay story understandable.
    """
    outcome = _outcome(record.decision)
    executed = record.decision in {Decision.ALLOW, Decision.TRANSFORM}
    after: dict[str, Any] = {
        "status": outcome,
        "tool_executed": executed,
        "decision": record.decision.value,
    }
    if record.transformed_args is not None:
        after["transformed_args"] = record.transformed_args
    if result_hash is not None:
        after["result_hash"] = result_hash

    return {
        "id": record.event_id,
        "agent": actor,
        "action": record.tool,
        "target": record.goal or record.tool,
        "attemptedAt": record.timestamp_iso,
        "outcome": outcome,
        "plainReason": record.reason or "No policy reason recorded.",
        "receiptId": record.event_id,
        "receiptHash": audit_hash,
        "traceId": record.event_id,
        "replayCommand": (
            f"gove-zone replay --event {record.event_id} "
            f"--audit-hash {audit_hash}"
        ),
        "auditEventId": record.event_id,
        "checks": [
            {
                "id": rule,
                "label": rule.replace("_", " ").replace(":", " · "),
                "posture": _posture(record.decision),
                "reason": record.reason or "Policy matched this rule.",
            }
            for rule in record.matched_rules
        ]
        or [
            {
                "id": record.policy_version,
                "label": "Policy evaluation",
                "posture": _posture(record.decision),
                "reason": record.reason or "Policy returned this decision.",
            }
        ],
        "before": canonical_json(args_before),
        "after": canonical_json(after),
    }


def receipt_to_governed_action(
    receipt: Receipt,
    *,
    args_before: dict[str, Any],
) -> dict[str, Any]:
    """Project a successful kernel receipt into the console contract."""
    return record_to_governed_action(
        receipt.record,
        audit_hash=receipt.audit_hash,
        args_before=args_before,
        actor=receipt.actor,
        result_hash=receipt.result_hash,
    )
