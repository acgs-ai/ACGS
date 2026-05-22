"""Replay verifier for Admission Gate v0.1.

Two entry points:

:func:`verify_decision`
    Pure receipt verification. Given a request, decision, and policy bundle,
    confirms that ``decision.receipt`` is internally consistent (request_hash,
    decision_hash, policy_bundle_hash all reproduce). Catches tampering and
    policy-bundle drift.

:func:`verify_decision_with_execution`
    Adds the four governed-execution invariants on top of receipt
    verification:

    - ``deny`` decisions MUST NOT have any execution event afterward.
    - ``transform`` decisions MUST have a ``transformed_boundary`` AND any
      execution event must declare it ran inside that boundary.
    - ``require_review`` decisions MUST have a valid human-review receipt
      before any execution event is accepted.
    - ``allow`` is always accepted.

This is the canonical object the workflow Proof Pack will iterate on for
multi-event chain verification later.
"""

from __future__ import annotations

from typing import Any

from governance.admission.policy import PolicyBundle, policy_bundle_hash
from governance.models import sha256_json


class ReplayError(Exception):
    """Raised when a replay attempt fails verification.

    The ``code`` attribute is a stable identifier ('tampered_receipt',
    'missing_receipt', 'policy_version_drift', etc.) suitable for CI
    assertions.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def verify_decision(
    *,
    request: dict[str, Any],
    decision: dict[str, Any],
    policy_bundle: PolicyBundle | dict[str, Any],
) -> dict[str, Any]:
    """Verify that a decision's receipt reproduces.

    Returns a structured report. Raises :class:`ReplayError` on any failure.
    """
    receipt = decision.get("receipt")
    if not receipt:
        raise ReplayError("missing_receipt", "decision has no 'receipt' field")
    if not isinstance(receipt, dict):
        raise ReplayError("missing_receipt", "decision.receipt is not an object")

    # request_hash check
    actual_req = sha256_json(request)
    if receipt.get("request_hash") != actual_req:
        raise ReplayError(
            "tampered_receipt",
            f"request_hash mismatch: receipt={receipt.get('request_hash')!r} actual={actual_req!r}",
        )

    # decision_hash check (over body excluding the receipt itself)
    body_only = {k: v for k, v in decision.items() if k != "receipt"}
    actual_dec = sha256_json(body_only)
    if receipt.get("decision_hash") != actual_dec:
        raise ReplayError(
            "tampered_receipt",
            f"decision_hash mismatch: receipt={receipt.get('decision_hash')!r} actual={actual_dec!r}",
        )

    # policy_bundle_hash check
    actual_pol = policy_bundle_hash(policy_bundle)
    if receipt.get("policy_bundle_hash") != actual_pol:
        raise ReplayError(
            "policy_bundle_hash_drift",
            f"policy_bundle_hash mismatch: receipt={receipt.get('policy_bundle_hash')!r} actual={actual_pol!r}",
        )

    # policy_version check (must match what request asked AND what bundle says)
    req_version = request.get("policy_context", {}).get("policy_version")
    bundle_version = policy_bundle.version if isinstance(policy_bundle, PolicyBundle) else policy_bundle.get("version")
    if receipt.get("policy_version") != bundle_version:
        raise ReplayError(
            "policy_version_drift",
            f"receipt.policy_version={receipt.get('policy_version')!r} != bundle.version={bundle_version!r}",
        )
    if req_version and receipt.get("policy_version") != req_version:
        raise ReplayError(
            "policy_version_drift",
            f"receipt.policy_version={receipt.get('policy_version')!r} != request.policy_context.policy_version={req_version!r}",
        )

    return {
        "ok": True,
        "decision": decision.get("decision"),
        "request_hash": actual_req,
        "decision_hash": actual_dec,
        "policy_bundle_hash": actual_pol,
        "policy_version": receipt.get("policy_version"),
    }


def verify_decision_with_execution(
    *,
    request: dict[str, Any],
    decision: dict[str, Any],
    policy_bundle: PolicyBundle | dict[str, Any],
    execution_events: list[dict[str, Any]] | None = None,
    human_review_receipts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Verify a decision PLUS the governed-execution invariants.

    ``execution_events`` is a list of dicts each with at least::

        {"kind": "tool_call" | "external_send" | "final_output" | ...,
         "boundary": {"allowed_outputs": [...], "disallowed_outputs": [...]}}

    ``human_review_receipts`` is a list of dicts each with at least::

        {"request_id": "...", "reviewer_role": "...", "approved": bool}
    """
    report = verify_decision(request=request, decision=decision, policy_bundle=policy_bundle)
    events = execution_events or []
    reviews = human_review_receipts or []
    action = decision.get("decision")

    if action == "deny":
        if events:
            raise ReplayError(
                "denied_action_executed",
                f"deny decision must have zero execution events; got {len(events)}",
            )
    elif action == "transform":
        tb = (decision.get("transform") or {}).get("transformed_boundary")
        if not tb:
            raise ReplayError(
                "transform_missing_boundary",
                "transform decision lacks transformed_boundary",
            )
        allowed = set(tb.get("allowed_outputs", []))
        disallowed = set(tb.get("disallowed_outputs", []))
        for i, ev in enumerate(events):
            ev_b = ev.get("boundary") or {}
            ev_allowed = set(ev_b.get("allowed_outputs", []))
            ev_disallowed = set(ev_b.get("disallowed_outputs", []))
            if ev_allowed != allowed or ev_disallowed != disallowed:
                raise ReplayError(
                    "execution_outside_transformed_boundary",
                    f"event[{i}] boundary != transform.transformed_boundary",
                )
    elif action == "require_review":
        required_role = (decision.get("review") or {}).get("reviewer_role")
        matching = [
            r
            for r in reviews
            if r.get("request_id") == request.get("request_id")
            and r.get("approved") is True
            and (required_role is None or r.get("reviewer_role") == required_role)
        ]
        if events and not matching:
            raise ReplayError(
                "missing_human_review_receipt",
                "require_review decision has execution events without an approved human-review "
                f"receipt from reviewer_role={required_role!r}",
            )
        report["human_review_satisfied"] = bool(matching)
        report["required_reviewer_role"] = required_role
    elif action == "allow":
        pass
    else:
        raise ReplayError("unknown_decision", f"unknown decision value: {action!r}")

    report["execution_events"] = len(events)
    report["human_review_receipts"] = len(reviews)
    return report
