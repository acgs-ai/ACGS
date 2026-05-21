"""Core admission decision engine for the v0.1 gate.

:func:`decide` consumes a validated admission request + a :class:`PolicyBundle`
and returns the admission decision dict. The returned dict is what a
deterministic workflow engine (Conductor, shell, CI) routes on::

    decision == allow    -> proceed inside execution_boundary
    decision == deny     -> stop; any later execution event fails replay
    decision == transform -> only the transformed boundary may run
    decision == require_review -> pause until a valid human-review receipt

Hashing is canonical (``sha256_json`` from governance.models). The receipt
binds: request bytes, decision bytes (excluding the receipt itself), and the
policy-bundle bytes. Any drift in any of these is detectable at replay.
"""

from __future__ import annotations

import os
import secrets
import uuid
from typing import Any

from governance.admission.policy import PolicyBundle, policy_bundle_hash
from governance.models import sha256_json, utc_now_iso

SCHEMA_VERSION = "admission_gate/0.1"

_PRECEDENCE = {"deny": 3, "require_review": 2, "transform": 1, "allow": 0}


def decide(
    request: dict[str, Any],
    *,
    policy_bundle: PolicyBundle,
    now: str | None = None,
    decision_id: str | None = None,
    receipt_id: str | None = None,
) -> dict[str, Any]:
    """Evaluate an admission request against a policy bundle.

    Returns a dict that conforms to ``admission_decision.schema.json``.
    """
    _require_request_shape(request)
    if request["policy_context"]["policy_bundle_id"] != policy_bundle.bundle_id:
        # Fail closed: request asked for a different bundle than we loaded.
        return _deny(
            request,
            policy_bundle,
            reason_code="policy_violation",
            reason=(
                f"requested policy_bundle_id={request['policy_context']['policy_bundle_id']!r} "
                f"!= loaded bundle_id={policy_bundle.bundle_id!r}"
            ),
            now=now,
            decision_id=decision_id,
            receipt_id=receipt_id,
        )

    fired: list[dict[str, Any]] = []
    for rule in policy_bundle.rules:
        if _rule_matches(rule.get("when", {}), request):
            fired.append(rule)

    if not fired:
        return _build_decision(
            request=request,
            policy_bundle=policy_bundle,
            decision="allow",
            reason_code="allowed_with_constraints",
            reason="no policy rule matched; default allow inside declared boundary",
            matched_constraints=[],
            transform={"applied": False, "description": None, "transformed_method": None, "transformed_boundary": None},
            review={"required": False, "reviewer_role": None, "reason": None},
            effective_permissions=list(request.get("requested_capabilities", [])),
            required_controls=[],
            blocked_capabilities=[],
            now=now,
            decision_id=decision_id,
            receipt_id=receipt_id,
        )

    fired.sort(key=lambda r: _PRECEDENCE[r["action"]], reverse=True)
    top = fired[0]
    action = top["action"]
    matched = [r.get("matched_constraint", r["id"]) for r in fired]

    transform = {"applied": False, "description": None, "transformed_method": None, "transformed_boundary": None}
    review = {"required": False, "reviewer_role": None, "reason": None}
    effective_permissions = list(request.get("requested_capabilities", []))
    required_controls: list[str] = []
    blocked_capabilities: list[str] = []

    if action == "deny":
        effective_permissions = []
        blocked_capabilities = list(request.get("requested_capabilities", []))
    elif action == "transform":
        tb = top.get("transformed_boundary") or {}
        transform = {
            "applied": True,
            "description": top.get("description", "policy-transformed execution boundary"),
            "transformed_method": top.get("transformed_method"),
            "transformed_boundary": {
                "allowed_outputs": list(tb.get("allowed_outputs", [])),
                "disallowed_outputs": list(tb.get("disallowed_outputs", [])),
            },
        }
        required_controls = list(top.get("required_controls", []))
        blocked_capabilities = list(top.get("blocked_capabilities", []))
    elif action == "require_review":
        review = {
            "required": True,
            "reviewer_role": top.get("reviewer_role", "compliance_officer"),
            "reason": top.get("review_reason", top.get("description", "review_required")),
        }
        required_controls = list(top.get("required_controls", []))

    return _build_decision(
        request=request,
        policy_bundle=policy_bundle,
        decision=action,
        reason_code=top["reason_code"],
        reason=top.get("description"),
        matched_constraints=matched,
        transform=transform,
        review=review,
        effective_permissions=effective_permissions,
        required_controls=required_controls,
        blocked_capabilities=blocked_capabilities,
        now=now,
        decision_id=decision_id,
        receipt_id=receipt_id,
    )


def make_receipt(
    *,
    request: dict[str, Any],
    decision_body: dict[str, Any],
    policy_bundle: PolicyBundle | dict[str, Any],
    now: str | None = None,
    receipt_id: str | None = None,
    previous_receipt_hash: str | None = None,
) -> dict[str, Any]:
    """Build a canonical receipt for an already-constructed decision body.

    ``decision_body`` MUST NOT yet contain a ``receipt`` field; this function
    hashes the body as-is so the receipt is reproducible at replay time.
    """
    if "receipt" in decision_body:
        raise ValueError("make_receipt: decision_body must not contain a 'receipt' field")
    pol_hash = policy_bundle_hash(policy_bundle)
    pol_version = (
        policy_bundle.version if isinstance(policy_bundle, PolicyBundle) else str(policy_bundle.get("version", ""))
    )
    return {
        "receipt_id": receipt_id or _new_receipt_id(),
        "hash_alg": "sha256",
        "request_hash": sha256_json(request),
        "decision_hash": sha256_json(decision_body),
        "policy_bundle_hash": pol_hash,
        "policy_version": pol_version,
        "created_at": now or utc_now_iso(),
        "previous_receipt_hash": previous_receipt_hash,
    }


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------


def _require_request_shape(request: dict[str, Any]) -> None:
    required = (
        "schema_version",
        "request_id",
        "workflow_id",
        "run_id",
        "phase",
        "actor",
        "declared_goal",
        "proposed_method",
        "risk_class",
        "requested_capabilities",
        "execution_boundary",
        "policy_context",
        "inputs_manifest",
    )
    missing = [k for k in required if k not in request]
    if missing:
        raise ValueError(f"admission request missing required keys: {missing}")
    if request["schema_version"] != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported admission request schema_version: {request['schema_version']!r}; expected {SCHEMA_VERSION!r}"
        )


def _rule_matches(when: dict[str, Any], request: dict[str, Any]) -> bool:
    """Tiny matcher for v0.1. Supported keys:

    - ``risk_class``: list of risk classes; ANY match
    - ``phase``: list of phases; ANY match
    - ``requested_capabilities_any``: list; match if any present
    - ``requested_capabilities_all``: list; match only if all present
    - ``disallowed_outputs_contains_any``: list; match against request execution_boundary.disallowed_outputs
    - ``allowed_outputs_contains_any``: list; match against request execution_boundary.allowed_outputs
    - ``environment``: list of environments; ANY match
    """
    if "risk_class" in when:
        if request.get("risk_class") not in when["risk_class"]:
            return False
    if "phase" in when:
        if request.get("phase") not in when["phase"]:
            return False
    if "environment" in when:
        env = request.get("execution_boundary", {}).get("environment")
        if env not in when["environment"]:
            return False
    caps = set(request.get("requested_capabilities", []))
    if "requested_capabilities_any" in when:
        if not (caps & set(when["requested_capabilities_any"])):
            return False
    if "requested_capabilities_all" in when:
        if not set(when["requested_capabilities_all"]).issubset(caps):
            return False
    if "allowed_outputs_contains_any" in when:
        allowed = set(request.get("execution_boundary", {}).get("allowed_outputs", []))
        if not (allowed & set(when["allowed_outputs_contains_any"])):
            return False
    if "disallowed_outputs_contains_any" in when:
        disallowed = set(request.get("execution_boundary", {}).get("disallowed_outputs", []))
        if not (disallowed & set(when["disallowed_outputs_contains_any"])):
            return False
    return True


def _deny(
    request: dict[str, Any],
    policy_bundle: PolicyBundle,
    *,
    reason_code: str,
    reason: str,
    now: str | None,
    decision_id: str | None,
    receipt_id: str | None,
) -> dict[str, Any]:
    return _build_decision(
        request=request,
        policy_bundle=policy_bundle,
        decision="deny",
        reason_code=reason_code,
        reason=reason,
        matched_constraints=["bundle_mismatch"],
        transform={"applied": False, "description": None, "transformed_method": None, "transformed_boundary": None},
        review={"required": False, "reviewer_role": None, "reason": None},
        effective_permissions=[],
        required_controls=[],
        blocked_capabilities=list(request.get("requested_capabilities", [])),
        now=now,
        decision_id=decision_id,
        receipt_id=receipt_id,
    )


def _build_decision(
    *,
    request: dict[str, Any],
    policy_bundle: PolicyBundle,
    decision: str,
    reason_code: str,
    reason: str | None,
    matched_constraints: list[str],
    transform: dict[str, Any],
    review: dict[str, Any],
    effective_permissions: list[str],
    required_controls: list[str],
    blocked_capabilities: list[str],
    now: str | None,
    decision_id: str | None,
    receipt_id: str | None,
) -> dict[str, Any]:
    body = {
        "schema_version": SCHEMA_VERSION,
        "request_id": request["request_id"],
        "decision_id": decision_id or _new_decision_id(),
        "decision": decision,
        "reason_code": reason_code,
        "policy_version": policy_bundle.version,
        "matched_constraints": matched_constraints,
        "execution_boundary": {
            "effective_permissions": effective_permissions,
            "required_controls": required_controls,
            "blocked_capabilities": blocked_capabilities,
        },
        "transform": transform,
        "review": review,
    }
    if reason is not None:
        body["reason"] = reason
    receipt = make_receipt(
        request=request,
        decision_body=body,
        policy_bundle=policy_bundle,
        now=now,
        receipt_id=receipt_id,
    )
    body["receipt"] = receipt
    return body


def _new_decision_id() -> str:
    return "dec_" + _short_id()


def _new_receipt_id() -> str:
    return "rcpt_" + _short_id()


def _short_id() -> str:
    # Deterministic if the caller passes their own id; otherwise uuid4 short form.
    rand = os.environ.get("ACGS_ADMISSION_TEST_ID_SEED")
    if rand:
        # Allow tests to inject a reproducible counter via env var.
        token = secrets.token_hex(4)
        return f"{rand}_{token}"
    return uuid.uuid4().hex[:16]
