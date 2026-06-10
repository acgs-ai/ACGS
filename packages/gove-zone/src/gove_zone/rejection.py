"""Machine-readable rejection envelopes for governed tool calls.

When the kernel denies or escalates a dispatch it raises a typed error
(:class:`~gove_zone.errors.DeniedError` / :class:`~gove_zone.errors.EscalateError`)
carrying the deciding :class:`~gove_zone.decision.DecisionRecord`. This module
projects that record into a small, stable JSON envelope a *calling agent* can
read to self-correct — the agent-facing twin of
:func:`gove_zone.frontend_contract.record_to_governed_action`, which targets the
human console. The envelope builders are pure projection: they make no decision
and mutate nothing. :func:`discover_alternatives` additionally drives the
read-only :meth:`~gove_zone.kernel.Kernel.simulate` primitive to fill
``allowed_alternatives`` — still no execution and no audit mutation.

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

from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Protocol

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

#: Decisions that make a simulated candidate an *available* alternative.
_ALTERNATIVE_OUTCOMES = (Decision.ALLOW, Decision.TRANSFORM)

#: Keys an ``allowed_alternatives`` entry must never carry — raw inputs would
#: break the envelope's leak-safe-by-construction posture.
_ALTERNATIVE_FORBIDDEN_KEYS = ("args", "transformed_args", "state")


class SupportsSimulate(Protocol):
    """Structural type for :func:`discover_alternatives` — anything exposing the
    read-only :meth:`gove_zone.kernel.Kernel.simulate` signature qualifies.

    Declared structurally (not as ``Kernel``) so this module keeps importing
    only :mod:`gove_zone.decision`: ``errors`` imports this module and
    ``kernel`` imports ``errors``, so a nominal ``Kernel`` import would cycle.
    """

    def simulate(
        self,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        *,
        goal: str = "",
        path: str | Sequence[str] | None = None,
        state: Mapping[str, Any] | None = None,
    ) -> DecisionRecord: ...


def rejection_dict(
    record: DecisionRecord,
    audit_hash: str,
    *,
    resumable: bool,
    resolution: str,
    approval: dict[str, Any] | None = None,
    allowed_alternatives: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Project a non-ALLOW decision into the agent-facing rejection envelope.

    Deterministic and dependency-free so adapters, gateways, and tests share one
    shape.

    Fail-closed: only ``DENY`` and ``ESCALATE`` records are projectable; an
    ``ALLOW``/``TRANSFORM`` record raises :class:`ValueError` rather than
    silently producing a "rejection" for an allowed call.

    ``reason`` is redacted for fail-closed-fallback records (see module docstring)
    so an exception-derived reason cannot leak raw arguments to the caller.

    ``allowed_alternatives`` keeps its tri-state contract: when the caller has
    not computed alternatives (``None``, the default) the key is **omitted** —
    absence means *"not computed"*. A passed list (possibly empty) is included
    verbatim and unambiguously means *"computed"* (empty == "none permitted").
    Entries are expected to come from :func:`alternative_from_record` /
    :func:`discover_alternatives`; entries carrying raw inputs (``args``,
    ``transformed_args``, ``state``) raise :class:`ValueError` so the envelope's
    leak posture holds by construction, not by caller discipline.
    """
    if record.decision not in _OUTCOME:
        raise ValueError(
            f"rejection_dict only projects DENY/ESCALATE records, got {record.decision!r}"
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
    if allowed_alternatives is not None:
        alternatives = [dict(alternative) for alternative in allowed_alternatives]
        for alternative in alternatives:
            leaked = [key for key in _ALTERNATIVE_FORBIDDEN_KEYS if key in alternative]
            if leaked:
                raise ValueError(
                    "allowed_alternatives entries must not carry raw inputs "
                    f"(forbidden keys: {leaked}); pass "
                    "alternative_from_record(...) projections instead"
                )
        payload["allowed_alternatives"] = alternatives
    return payload


def alternative_from_record(record: DecisionRecord) -> dict[str, Any]:
    """Project an ALLOW/TRANSFORM :class:`DecisionRecord` (typically returned by
    :meth:`~gove_zone.kernel.Kernel.simulate`) into an ``allowed_alternatives``
    entry.

    Fail-closed twin of :func:`rejection_dict`'s guard: only ``ALLOW`` /
    ``TRANSFORM`` records project; a ``DENY``/``ESCALATE`` record raises
    :class:`ValueError` rather than silently advertising a rejected call as an
    available alternative.

    Leak posture matches the envelope: the entry carries the tool name, the
    predicted decision, non-reversible commitments (``argument_hash``,
    ``decision_request_hash``) and ``policy_version`` — never raw arguments and
    never ``transformed_args``.
    """
    if record.decision not in _ALTERNATIVE_OUTCOMES:
        raise ValueError(
            "alternative_from_record only projects ALLOW/TRANSFORM records, "
            f"got {record.decision!r}"
        )
    return {
        "tool": record.tool,
        "decision": record.decision.value,
        "argument_hash": record.argument_hash,
        "decision_request_hash": record.decision_request_hash,
        "policy_version": record.policy_version,
    }


def discover_alternatives(
    kernel: SupportsSimulate,
    candidates: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Simulate candidate call variants and collect the ones that would pass.

    For each candidate — a mapping with ``tool`` (required) and optionally
    ``args`` / ``goal`` / ``path`` / ``state``, mirroring
    :meth:`~gove_zone.kernel.Kernel.simulate` — runs a read-only simulation and
    keeps the candidates whose predicted decision is ``ALLOW`` or ``TRANSFORM``.
    Each kept entry is :func:`alternative_from_record` plus ``candidate_index``
    (the candidate's position) so the caller can map a verdict back to the
    variant it supplied without the envelope echoing raw arguments.

    Read-only at the kernel level (inherits :meth:`simulate`'s guarantee): no
    tool executes and the audit chain is unchanged. The result is a
    *prediction* under the current policy, not authorization — execution still
    requires a real :meth:`dispatch` and its receipt.

    Unregistered tools propagate :class:`~gove_zone.errors.UnknownToolError`
    (mirroring ``simulate``) rather than being silently dropped, so a typo'd
    candidate surfaces instead of vanishing from the allowed set.
    """
    alternatives: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        record = kernel.simulate(
            str(candidate["tool"]),
            candidate.get("args"),
            goal=str(candidate.get("goal", "")),
            path=candidate.get("path"),
            state=candidate.get("state"),
        )
        if record.decision in _ALTERNATIVE_OUTCOMES:
            entry = alternative_from_record(record)
            entry["candidate_index"] = index
            alternatives.append(entry)
    return alternatives
