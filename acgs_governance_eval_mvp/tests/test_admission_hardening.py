"""Hardening tests for Admission Gate v0.1 (post-review).

Covers the CRITICAL + HIGH + cheap-MEDIUM findings from the independent
code review of PR #50:

CRITICAL #1 — fail-closed default
    Empty / non-matching policy bundle MUST NOT default-allow with all
    requested capabilities. Default is deny; permissive bundles must opt in.

CRITICAL #2 — enum validation
    Out-of-enum values for risk_class, phase, environment, actor.role must
    raise before reaching the rule engine.

HIGH — reviewer_role match
    require_review decisions require a human-review receipt whose
    reviewer_role matches what the decision demanded.

MEDIUM — required_controls union
    Secondary obligations from non-top-precedence rules must not silently
    drop from the receipt.

MEDIUM — make_receipt is no longer in the public surface.

MEDIUM — schema else-clauses forbid forged transform.applied / review.required.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from governance.admission import (
    PolicyBundle,
    ReplayError,
    decide,
    load_policy_bundle,
    verify_decision_with_execution,
)
from governance.admission.policy import policy_bundle_from_dict

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "admission_gate_v0_1"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture()
def bundle() -> PolicyBundle:
    return load_policy_bundle(FIXTURES / "policy_bundle.json")


# ---------------------------------------------------------------------------
# CRITICAL #1 — fail-closed default action
# ---------------------------------------------------------------------------


def test_empty_bundle_default_action_is_deny() -> None:
    empty = policy_bundle_from_dict({"bundle_id": "legalguard_ca", "version": "1.2.0", "rules": []})
    assert empty.default_action == "deny"
    req = _load("allow_request.json")
    dec = decide(req, policy_bundle=empty)
    assert dec["decision"] == "deny"
    assert dec["reason_code"] == "no_matching_policy"
    assert dec["execution_boundary"]["effective_permissions"] == []
    assert set(dec["execution_boundary"]["blocked_capabilities"]) == set(req["requested_capabilities"])


def test_unmatched_high_risk_request_denies_when_default_deny() -> None:
    """The advisor's canonical exploit case: legal_analysis @ low risk
    matches none of the original 3 rules. With default_action=deny, this
    must fail closed.
    """
    sparse = policy_bundle_from_dict(
        {
            "bundle_id": "legalguard_ca",
            "version": "1.2.0",
            "default_action": "deny",
            "rules": [
                {
                    "id": "prohibited_client_facing_advice",
                    "when": {"requested_capabilities_any": ["client_facing_legal_advice"]},
                    "action": "deny",
                    "reason_code": "prohibited_output",
                }
            ],
        }
    )
    req = copy.deepcopy(_load("allow_request.json"))
    req["request_id"] = "req_exploit_001"
    req["requested_capabilities"] = ["legal_analysis"]
    req["risk_class"] = "low"
    dec = decide(req, policy_bundle=sparse)
    assert dec["decision"] == "deny"
    assert dec["reason_code"] == "no_matching_policy"


def test_explicit_default_action_allow_is_opt_in() -> None:
    permissive = policy_bundle_from_dict(
        {
            "bundle_id": "legalguard_ca",
            "version": "1.2.0",
            "default_action": "allow",
            "rules": [],
        }
    )
    assert permissive.default_action == "allow"
    req = _load("allow_request.json")
    dec = decide(req, policy_bundle=permissive)
    assert dec["decision"] == "allow"
    assert dec["reason_code"] == "allowed_with_constraints"


def test_default_action_require_review_routes_to_human() -> None:
    bundle = policy_bundle_from_dict(
        {
            "bundle_id": "legalguard_ca",
            "version": "1.2.0",
            "default_action": "require_review",
            "rules": [],
        }
    )
    req = _load("allow_request.json")
    dec = decide(req, policy_bundle=bundle)
    assert dec["decision"] == "require_review"
    assert dec["reason_code"] == "no_matching_policy"
    assert dec["review"]["required"] is True


def test_bundle_rejects_invalid_default_action() -> None:
    with pytest.raises(ValueError, match="default_action"):
        policy_bundle_from_dict(
            {
                "bundle_id": "legalguard_ca",
                "version": "1.2.0",
                "default_action": "passthrough",
                "rules": [],
            }
        )


# ---------------------------------------------------------------------------
# CP2 — policy ``when`` schema validation at load time
# ---------------------------------------------------------------------------


def test_policy_bundle_rejects_unknown_when_key_with_rule_id() -> None:
    with pytest.raises(ValueError, match=r"typo_rule.*requested_capabilites_any"):
        policy_bundle_from_dict(
            {
                "bundle_id": "legalguard_ca",
                "version": "1.2.0",
                "rules": [
                    {
                        "id": "typo_rule",
                        "when": {"requested_capabilites_any": ["legal_analysis"]},
                        "action": "deny",
                        "reason_code": "prohibited_output",
                    }
                ],
            }
        )


def test_policy_bundle_rejects_string_when_value() -> None:
    with pytest.raises(ValueError, match=r"risk_class.*list\[str\]"):
        policy_bundle_from_dict(
            {
                "bundle_id": "legalguard_ca",
                "version": "1.2.0",
                "rules": [
                    {
                        "id": "string_risk_class",
                        "when": {"risk_class": "high"},
                        "action": "deny",
                        "reason_code": "prohibited_output",
                    }
                ],
            }
        )


def test_policy_bundle_rejects_invalid_when_enum_value() -> None:
    with pytest.raises(ValueError, match=r"risk_class.*catastrophic_unknown"):
        policy_bundle_from_dict(
            {
                "bundle_id": "legalguard_ca",
                "version": "1.2.0",
                "rules": [
                    {
                        "id": "bad_risk_class",
                        "when": {"risk_class": ["catastrophic_unknown"]},
                        "action": "deny",
                        "reason_code": "prohibited_output",
                    }
                ],
            }
        )


def test_policy_bundle_fixture_loads_with_when_schema_validation() -> None:
    load_policy_bundle(FIXTURES / "policy_bundle.json")


# ---------------------------------------------------------------------------
# CRITICAL #2 — enum validation in decide()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field, bad_value, message_fragment",
    [
        ("risk_class", "potato", "risk_class"),
        ("phase", "garbage", "phase"),
    ],
)
def test_decide_rejects_invalid_top_level_enum(
    bundle: PolicyBundle, field: str, bad_value: str, message_fragment: str
) -> None:
    req = _load("allow_request.json")
    req[field] = bad_value
    with pytest.raises(ValueError, match=message_fragment):
        decide(req, policy_bundle=bundle)


def test_decide_rejects_invalid_actor_role(bundle: PolicyBundle) -> None:
    req = _load("allow_request.json")
    req["actor"]["role"] = "superuser"
    with pytest.raises(ValueError, match="actor.role"):
        decide(req, policy_bundle=bundle)


def test_decide_rejects_invalid_environment(bundle: PolicyBundle) -> None:
    req = _load("allow_request.json")
    req["execution_boundary"]["environment"] = "kubernetes_dev"
    with pytest.raises(ValueError, match="environment"):
        decide(req, policy_bundle=bundle)


def test_decide_rejects_missing_actor_role(bundle: PolicyBundle) -> None:
    req = _load("allow_request.json")
    del req["actor"]["role"]
    with pytest.raises(ValueError, match=r"actor.*role"):
        decide(req, policy_bundle=bundle)


# ---------------------------------------------------------------------------
# HIGH — reviewer_role match
# ---------------------------------------------------------------------------


def test_require_review_rejects_wrong_reviewer_role(bundle: PolicyBundle) -> None:
    req = _load("require_review_request.json")
    dec = decide(req, policy_bundle=bundle)
    assert dec["review"]["reviewer_role"] == "licensed_lawyer"

    # Intern approval must NOT satisfy a licensed_lawyer requirement.
    intern_review = {
        "request_id": req["request_id"],
        "reviewer_role": "intern",
        "approved": True,
    }
    with pytest.raises(ReplayError) as exc:
        verify_decision_with_execution(
            request=req,
            decision=dec,
            policy_bundle=bundle,
            execution_events=[{"kind": "tool_call", "boundary": {}}],
            human_review_receipts=[intern_review],
        )
    assert exc.value.code == "missing_human_review_receipt"


def test_require_review_accepts_correct_reviewer_role(bundle: PolicyBundle) -> None:
    req = _load("require_review_request.json")
    dec = decide(req, policy_bundle=bundle)
    lawyer_review = {
        "request_id": req["request_id"],
        "reviewer_role": "licensed_lawyer",
        "approved": True,
    }
    report = verify_decision_with_execution(
        request=req,
        decision=dec,
        policy_bundle=bundle,
        execution_events=[{"kind": "tool_call", "boundary": {}}],
        human_review_receipts=[lawyer_review],
    )
    assert report["ok"] is True
    assert report["required_reviewer_role"] == "licensed_lawyer"
    assert report["human_review_satisfied"] is True


# ---------------------------------------------------------------------------
# MEDIUM — required_controls union across all fired rules
# ---------------------------------------------------------------------------


def test_required_controls_unions_across_fired_rules() -> None:
    """When a deny rule wins over a require_review rule, the review rule's
    required_controls (e.g. citation_required) must still surface."""
    bundle = policy_bundle_from_dict(
        {
            "bundle_id": "legalguard_ca",
            "version": "1.2.0",
            "default_action": "deny",
            "rules": [
                {
                    "id": "prohibited",
                    "when": {"requested_capabilities_any": ["client_facing_legal_advice"]},
                    "action": "deny",
                    "reason_code": "prohibited_output",
                    "required_controls": ["audit_log_immutable"],
                },
                {
                    "id": "lawyer_required",
                    "when": {"requested_capabilities_any": ["legal_analysis"]},
                    "action": "require_review",
                    "reason_code": "review_required",
                    "reviewer_role": "licensed_lawyer",
                    "required_controls": ["source_citation_required"],
                },
            ],
        }
    )
    req = _load("deny_request.json")
    dec = decide(req, policy_bundle=bundle)
    assert dec["decision"] == "deny"
    controls = dec["execution_boundary"]["required_controls"]
    assert "audit_log_immutable" in controls
    assert "source_citation_required" in controls


# ---------------------------------------------------------------------------
# MEDIUM — make_receipt is no longer publicly exported
# ---------------------------------------------------------------------------


def test_make_receipt_not_in_public_api() -> None:
    import governance.admission as admission

    assert "make_receipt" not in admission.__all__
    # Still reachable for advanced callers via the submodule.
    from governance.admission.gate import make_receipt  # noqa: F401


# ---------------------------------------------------------------------------
# MEDIUM — schema else-clauses
# ---------------------------------------------------------------------------


def test_decision_schema_else_clauses_present() -> None:
    body = json.loads(
        (REPO_ROOT / "governance" / "schema" / "admission_decision.schema.json").read_text(encoding="utf-8")
    )
    branches = body["allOf"]
    assert len(branches) == 2
    transform_clause = next(b for b in branches if b["if"]["properties"]["decision"]["const"] == "transform")
    review_clause = next(b for b in branches if b["if"]["properties"]["decision"]["const"] == "require_review")
    assert "else" in transform_clause
    assert "else" in review_clause
    # In the else branch, transform.applied / review.required must be const false.
    assert transform_clause["else"]["properties"]["transform"]["properties"]["applied"]["const"] is False
    assert review_clause["else"]["properties"]["review"]["properties"]["required"]["const"] is False


# ---------------------------------------------------------------------------
# Matcher coverage — requested_capabilities_subset_of
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "request_caps, safelist, expect_match",
    [
        # Subset of safelist → match (request safely contained in allow-list)
        (["read_file"], ["read_file", "summarize"], True),
        (["read_file", "summarize"], ["read_file", "summarize"], True),
        (["summarize"], ["read_file", "summarize"], True),
        # Empty request capabilities → trivially a subset → match
        ([], ["read_file", "summarize"], True),
        # Capability outside safelist → no match (the canonical fail-closed case)
        (["read_file", "legal_analysis"], ["read_file", "summarize"], False),
        # Entirely disjoint → no match
        (["legal_analysis"], ["read_file", "summarize"], False),
    ],
)
def test_requested_capabilities_subset_of_matcher(request_caps, safelist, expect_match) -> None:
    """The subset_of matcher is what lets a bundle carve out an obviously-safe
    allow path on top of an otherwise fail-closed default. Cover it directly
    (the fixture bundle only exercises the True path)."""
    bundle = policy_bundle_from_dict(
        {
            "bundle_id": "legalguard_ca",
            "version": "1.2.0",
            "default_action": "deny",
            "rules": [
                {
                    "id": "safelist_only",
                    "when": {
                        "risk_class": ["low"],
                        "requested_capabilities_subset_of": safelist,
                    },
                    "action": "allow",
                    "reason_code": "allowed_with_constraints",
                }
            ],
        }
    )
    req = _load("allow_request.json")
    req = {**req, "requested_capabilities": request_caps, "risk_class": "low"}
    dec = decide(req, policy_bundle=bundle)
    if expect_match:
        assert dec["decision"] == "allow"
        assert dec["reason_code"] == "allowed_with_constraints"
    else:
        # No rule matches → fail-closed default fires
        assert dec["decision"] == "deny"
        assert dec["reason_code"] == "no_matching_policy"


# ---------------------------------------------------------------------------
# Cleanup invariants — dead-code removal must not regress behavior
# ---------------------------------------------------------------------------


def test_receipt_has_no_previous_receipt_hash_field() -> None:
    """v0.1 ships a single-event receipt only. ``previous_receipt_hash``
    (chained-receipt placeholder) was removed in cleanup because it was
    never set by ``decide()``. v0.2 may re-add it when receipt-chaining
    actually lands."""
    bundle = load_policy_bundle(FIXTURES / "policy_bundle.json")
    dec = decide(_load("allow_request.json"), policy_bundle=bundle)
    assert "previous_receipt_hash" not in dec["receipt"]


def test_receipt_schema_has_no_previous_receipt_hash() -> None:
    schema = json.loads(
        (REPO_ROOT / "governance" / "schema" / "decision_receipt.schema.json").read_text(encoding="utf-8")
    )
    assert "previous_receipt_hash" not in schema["properties"]
