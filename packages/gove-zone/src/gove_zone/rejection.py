"""Machine-readable rejection envelopes for governed tool calls.

When the kernel denies or escalates a dispatch it raises a typed error
(:class:`~gove_zone.errors.DeniedError` / :class:`~gove_zone.errors.EscalateError`)
carrying the deciding :class:`~gove_zone.decision.DecisionRecord`. This module
projects that record into a small, stable JSON envelope a *calling agent* can
read to self-correct — the agent-facing twin of
:func:`gove_zone.frontend_contract.record_to_governed_action`, which targets the
human console. It is pure projection: it makes no decision and mutates nothing.

Fail-closed leak posture: the envelope only *reads* an already-decided record. It
carries ``decision_request_hash`` / ``audit_hash`` (non-reversible commitments)
but never raw arguments, no ``state_hash``, and no ``transformed_args``.

The ``reason`` field has two provenances and is handled accordingly:

- On a **policy** verdict (a policy returned DENY/ESCALATE), ``reason`` is
  *policy-authored* free text and is surfaced verbatim — keep policy reason
  strings non-sensitive (they also reach the audit chain and the console).
- On a **fail-closed fallback** verdict (``policy_version`` starts with
  ``fail-closed/`` — the kernel synthesized a DENY because the policy raised or
  timed out), ``reason`` is derived from the raising exception's message and may
  echo raw arguments. The envelope **redacts** it to a fixed safe summary; the
  error class is still conveyed via ``matched_rules`` (``POLICY_ERROR:<type>``),
  and the full reason is retained in the ``DecisionRecord`` / audit chain for
  forensics. So the agent-facing channel is leak-safe by construction, not by
  policy-author discipline.
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

#: ``policy_version`` prefix the kernel stamps on a synthesized fail-closed DENY
#: (policy raised / timed out). Such records carry an exception-derived ``reason``.
_FAIL_CLOSED_PREFIX = "fail-closed/"

#: Envelope ``reason`` substituted for fail-closed records so the exception
#: message (which may echo raw arguments) never reaches the calling agent. The
#: error class stays available via ``matched_rules``; full detail in the audit chain.
_FAIL_CLOSED_REASON = (
    "policy evaluation failed under fail-closed fallback; "
    "see matched_rules for the error class and the audit chain for full detail"
)


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

    ``reason`` is redacted for fail-closed-fallback records (see module docstring)
    so an exception-derived reason cannot leak raw arguments to the caller.

    ``allowed_alternatives`` is **omitted** until a capability-discovery primitive
    (PR-2 ``simulate``) computes it. Absence therefore means *"not computed"*; a
    present list (possibly empty) will unambiguously mean *"computed"* — so the
    key never carries an in-band ambiguity between those two states.
    """
    if record.decision not in _OUTCOME:
        raise ValueError(
            "rejection_dict only projects DENY/ESCALATE records, "
            f"got {record.decision!r}"
        )
    reason = record.reason
    if record.policy_version.startswith(_FAIL_CLOSED_PREFIX):
        reason = _FAIL_CLOSED_REASON
    payload: dict[str, Any] = {
        "status": record.decision.value,
        "outcome": _OUTCOME[record.decision],
        "tool": record.tool,
        "actor": record.actor,
        "reason": reason,
        "matched_rules": list(record.matched_rules),
        "policy_version": record.policy_version,
        "decision_request_hash": record.decision_request_hash,
        "audit_hash": audit_hash,
        "resumable": resumable,
        "resolution": resolution,
    }
    if approval is not None:
        payload["approval"] = approval
    return payload
