"""Machine-readable rejection envelopes for governed tool calls.

When the kernel denies or escalates a dispatch it raises a typed error
(:class:`~gove_zone.errors.DeniedError` / :class:`~gove_zone.errors.EscalateError`)
carrying the deciding :class:`~gove_zone.decision.DecisionRecord`. This module
projects that record into a small, stable JSON envelope a *calling agent* can
read to self-correct — the agent-facing twin of
:func:`gove_zone.frontend_contract.record_to_governed_action`, which targets the
human console. It is pure projection: it makes no decision and mutates nothing.

Fail-closed posture: the envelope only *reads* an already-decided record. It
carries ``argument_hash`` indirectly (via ``decision_request_hash``) but never
raw arguments, no ``state_hash``, and no ``transformed_args``. The only
free-text field is the policy-authored ``reason`` — keep policy reasons
non-sensitive.
"""

from __future__ import annotations

from typing import Any

from gove_zone.decision import Decision, DecisionRecord

_OUTCOME: dict[Decision, str] = {
    Decision.DENY: "denied",
    Decision.ESCALATE: "escalated",
}

#: Resolution hints — how the agent can move forward from each verdict.
REVISE_AND_RETRY = "revise_and_retry"
HUMAN_APPROVAL = "human_approval"


def rejection_dict(
    record: DecisionRecord,
    audit_hash: str,
    *,
    resumable: bool,
    resolution: str,
    approval: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Project a non-ALLOW decision into the agent-facing rejection envelope.

    Deterministic and dependency-free so adapters, gateways, and tests share one
    shape.

    Fail-closed: only ``DENY`` and ``ESCALATE`` records are projectable; an
    ``ALLOW``/``TRANSFORM`` record raises :class:`ValueError` rather than
    silently producing a "rejection" for an allowed call.

    ``allowed_alternatives`` is provisional: ``[]`` means *"not yet computed"*,
    to be populated by the PR-2 ``simulate`` capability-discovery primitive — it
    is NOT a claim that no alternative is permitted.
    """
    if record.decision not in _OUTCOME:
        raise ValueError(
            "rejection_dict only projects DENY/ESCALATE records, "
            f"got {record.decision!r}"
        )
    payload: dict[str, Any] = {
        "status": record.decision.value,
        "outcome": _OUTCOME[record.decision],
        "tool": record.tool,
        "actor": record.actor,
        "reason": record.reason,
        "matched_rules": list(record.matched_rules),
        "policy_version": record.policy_version,
        "decision_request_hash": record.decision_request_hash,
        "audit_hash": audit_hash,
        "resumable": resumable,
        "resolution": resolution,
        "allowed_alternatives": [],  # provisional: [] == "not yet computed" (PR-2)
    }
    if approval is not None:
        payload["approval"] = approval
    return payload
