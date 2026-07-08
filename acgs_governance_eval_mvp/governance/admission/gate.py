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

import uuid
from typing import Any

from governance.admission.policy import PolicyBundle, policy_bundle_hash
from governance.models import sha256_json, utc_now_iso

SCHEMA_VERSION = "admission_gate/0.1"

# Sentinel stored in receipt hash fields when canonical hashing itself failed.
# A replay verifier can never reproduce it from real bytes, so a degraded
# receipt always fails receipt verification — fail-closed at replay too.
HASH_UNAVAILABLE = "unavailable:canonicalization_failure"

_PRECEDENCE = {"deny": 3, "require_review": 2, "transform": 1, "allow": 0}

_ENUMS: dict[str, tuple[str, ...]] = {
    "phase": ("workflow_admission", "step_admission", "final_output"),
    "risk_class": ("low", "medium", "high", "critical"),
    "actor_role": ("agent", "human", "system"),
    "environment": ("local", "ci", "hosted", "production"),
}


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
        return _build_decision(
            request=request,
            policy_bundle=policy_bundle,
            decision="deny",
            reason_code="policy_violation",
            reason=(
                f"requested policy_bundle_id={request['policy_context']['policy_bundle_id']!r} "
                f"!= loaded bundle_id={policy_bundle.bundle_id!r}"
            ),
            matched_constraints=["bundle_mismatch"],
            transform=_empty_transform(),
            review=_empty_review(),
            effective_permissions=[],
            required_controls=[],
            blocked_capabilities=list(request.get("requested_capabilities", [])),
            now=now,
            decision_id=decision_id,
            receipt_id=receipt_id,
        )

    fired = [rule for rule in policy_bundle.rules if _rule_matches(rule.get("when", {}), request)]
    if not fired:
        return _no_match_decision(
            request=request,
            policy_bundle=policy_bundle,
            now=now,
            decision_id=decision_id,
            receipt_id=receipt_id,
        )

    fired.sort(key=lambda r: _PRECEDENCE[r["action"]], reverse=True)
    top = fired[0]
    action = top["action"]
    matched = [r.get("matched_constraint", r["id"]) for r in fired]

    # Union required_controls across every fired rule — secondary obligations
    # from lower-precedence rules (e.g. citation requirements from a
    # require_review rule that lost to a deny rule) must not silently drop.
    required_controls: list[str] = []
    seen_controls: set[str] = set()
    for r in fired:
        for c in r.get("required_controls", []) or []:
            if c not in seen_controls:
                required_controls.append(c)
                seen_controls.add(c)

    transform = _empty_transform()
    review = _empty_review()
    effective_permissions = list(request.get("requested_capabilities", []))
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
        blocked_capabilities = list(top.get("blocked_capabilities", []))
    elif action == "require_review":
        review = {
            "required": True,
            "reviewer_role": top.get("reviewer_role", "compliance_officer"),
            "reason": top.get("review_reason", top.get("description", "review_required")),
        }

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
) -> dict[str, Any]:
    """Build a canonical receipt for an already-constructed decision body.

    ``decision_body`` MUST NOT yet contain a ``receipt`` field; this function
    hashes the body as-is so the receipt is reproducible at replay time.
    """
    if "receipt" in decision_body:
        raise ValueError("make_receipt: decision_body must not contain a 'receipt' field")
    pol_version = (
        policy_bundle.version if isinstance(policy_bundle, PolicyBundle) else str(policy_bundle.get("version", ""))
    )
    return {
        "receipt_id": receipt_id or _new_receipt_id(),
        "hash_alg": "sha256",
        "request_hash": sha256_json(request),
        "decision_hash": sha256_json(decision_body),
        "policy_bundle_hash": policy_bundle_hash(policy_bundle),
        "policy_version": pol_version,
        "created_at": now or utc_now_iso(),
    }


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------


def _empty_transform() -> dict[str, Any]:
    return {
        "applied": False,
        "description": None,
        "transformed_method": None,
        "transformed_boundary": None,
    }


def _empty_review() -> dict[str, Any]:
    return {"required": False, "reviewer_role": None, "reason": None}


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

    # Fail closed on out-of-enum values. Without this an unknown risk_class
    # (e.g. "potato") matches no rule and would route to the no-match path.
    if request["phase"] not in _ENUMS["phase"]:
        raise ValueError(f"admission request.phase invalid: {request['phase']!r}")
    if request["risk_class"] not in _ENUMS["risk_class"]:
        raise ValueError(f"admission request.risk_class invalid: {request['risk_class']!r}")
    actor = request["actor"]
    if not isinstance(actor, dict) or "role" not in actor:
        raise ValueError("admission request.actor missing required 'role'")
    if actor["role"] not in _ENUMS["actor_role"]:
        raise ValueError(f"admission request.actor.role invalid: {actor['role']!r}")
    eb = request["execution_boundary"]
    if not isinstance(eb, dict) or "environment" not in eb:
        raise ValueError("admission request.execution_boundary missing required 'environment'")
    if eb["environment"] not in _ENUMS["environment"]:
        raise ValueError(f"admission request.execution_boundary.environment invalid: {eb['environment']!r}")
    if not isinstance(request.get("requested_capabilities"), list):
        raise ValueError("admission request.requested_capabilities must be a list")


def _rule_matches(when: dict[str, Any], request: dict[str, Any]) -> bool:
    """Tiny matcher for v0.1. Supported keys:

    - ``risk_class``: list of risk classes; ANY match
    - ``phase``: list of phases; ANY match
    - ``requested_capabilities_any``: list; match if any present
    - ``requested_capabilities_all``: list; match only if all present
    - ``requested_capabilities_subset_of``: list; match only if request's
      capabilities are entirely contained in the safelist (use this to mark
      a request as obviously-safe and exempt from the fail-closed default)
    - ``disallowed_outputs_contains_any``: list; match against request execution_boundary.disallowed_outputs
    - ``allowed_outputs_contains_any``: list; match against request execution_boundary.allowed_outputs
    - ``environment``: list of environments; ANY match
    """
    if "risk_class" in when and request.get("risk_class") not in when["risk_class"]:
        return False
    if "phase" in when and request.get("phase") not in when["phase"]:
        return False
    if "environment" in when:
        env = request.get("execution_boundary", {}).get("environment")
        if env not in when["environment"]:
            return False
    caps = set(request.get("requested_capabilities", []))
    if "requested_capabilities_any" in when and not (caps & set(when["requested_capabilities_any"])):
        return False
    if "requested_capabilities_all" in when and not set(when["requested_capabilities_all"]).issubset(caps):
        return False
    if "requested_capabilities_subset_of" in when and not caps.issubset(set(when["requested_capabilities_subset_of"])):
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


def _no_match_decision(
    *,
    request: dict[str, Any],
    policy_bundle: PolicyBundle,
    now: str | None,
    decision_id: str | None,
    receipt_id: str | None,
) -> dict[str, Any]:
    """Build the decision used when no rule matches.

    The action comes from ``policy_bundle.default_action`` (defaulting to
    ``deny``). The previous v0.1 prototype hard-coded ``allow`` here, which
    was a fail-OPEN default; the bundle now controls this explicitly and the
    receipt hash captures the choice.
    """
    action = policy_bundle.default_action
    review = _empty_review()
    requested = list(request.get("requested_capabilities", []))

    if action == "allow":
        decision = "allow"
        reason_code = "allowed_with_constraints"
        reason = "no rule matched; bundle.default_action='allow'"
        matched: list[str] = []
        effective = requested
        blocked: list[str] = []
    elif action == "require_review":
        decision = "require_review"
        reason_code = "no_matching_policy"
        reason = "no rule matched; bundle.default_action='require_review'"
        matched = ["no_matching_policy"]
        effective = requested
        blocked = []
        review = {
            "required": True,
            "reviewer_role": "compliance_officer",
            "reason": "no_matching_policy",
        }
    else:  # "deny" — the safe default
        decision = "deny"
        reason_code = "no_matching_policy"
        reason = "no rule matched; bundle.default_action='deny' (fail-closed)"
        matched = ["no_matching_policy"]
        effective = []
        blocked = requested

    return _build_decision(
        request=request,
        policy_bundle=policy_bundle,
        decision=decision,
        reason_code=reason_code,
        reason=reason,
        matched_constraints=matched,
        transform=_empty_transform(),
        review=review,
        effective_permissions=effective,
        required_controls=[],
        blocked_capabilities=blocked,
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
    try:
        body["receipt"] = make_receipt(
            request=request,
            decision_body=body,
            policy_bundle=policy_bundle,
            now=now,
            receipt_id=receipt_id,
        )
    except Exception as exc:
        # Fail closed: if the canonical hash of the request/decision cannot be
        # produced, no decision built here is executable. Replace whatever
        # action was computed (including allow) with a deny that carries a
        # degraded, non-reproducible receipt.
        return _canonicalization_failure_decision(
            request=request,
            policy_bundle=policy_bundle,
            error=exc,
            now=now,
            decision_id=decision_id,
            receipt_id=receipt_id,
        )
    return body


def _safe_str(value: Any) -> str:
    """str() that cannot raise — the fallback deny path must never fail."""
    try:
        return str(value)
    except Exception:
        return f"<unrepresentable {type(value).__name__}>"


def _canonicalization_failure_decision(
    *,
    request: dict[str, Any],
    policy_bundle: PolicyBundle,
    error: Exception,
    now: str | None,
    decision_id: str | None,
    receipt_id: str | None,
) -> dict[str, Any]:
    """Fail-closed deny used when canonical hashing raised mid-decision.

    Every field is built from safe coercions so this constructor cannot itself
    raise. Receipt hash fields are computed best-effort per field; any hash
    that cannot be produced is set to :data:`HASH_UNAVAILABLE`, which no
    replay verifier can reproduce — so the degraded receipt also fails closed
    at verification time.
    """
    requested = request.get("requested_capabilities", [])
    blocked = [_safe_str(c) for c in requested] if isinstance(requested, list) else []
    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "request_id": _safe_str(request.get("request_id", "")),
        "decision_id": decision_id or _new_decision_id(),
        "decision": "deny",
        "reason_code": "canonicalization_failure",
        "policy_version": _safe_str(policy_bundle.version),
        "matched_constraints": ["canonicalization_failure"],
        "execution_boundary": {
            "effective_permissions": [],
            "required_controls": [],
            "blocked_capabilities": blocked,
        },
        "transform": _empty_transform(),
        "review": _empty_review(),
        "reason": (
            "fail-closed deny: canonicalization/hash failure while building the "
            f"decision receipt: {type(error).__name__}: {_safe_str(error)}"
        ),
    }
    hashes: dict[str, str] = {}
    for field, compute in (
        ("request_hash", lambda: sha256_json(request)),
        ("decision_hash", lambda: sha256_json(body)),
        ("policy_bundle_hash", lambda: policy_bundle_hash(policy_bundle)),
    ):
        try:
            hashes[field] = compute()
        except Exception:
            hashes[field] = HASH_UNAVAILABLE
    body["receipt"] = {
        "receipt_id": receipt_id or _new_receipt_id(),
        "hash_alg": "sha256",
        **hashes,
        "policy_version": _safe_str(policy_bundle.version),
        "created_at": now or utc_now_iso(),
    }
    return body


def _new_decision_id() -> str:
    return "dec_" + uuid.uuid4().hex[:16]


def _new_receipt_id() -> str:
    return "rcpt_" + uuid.uuid4().hex[:16]
