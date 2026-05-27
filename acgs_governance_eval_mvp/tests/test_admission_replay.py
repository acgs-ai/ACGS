"""The seven required negative tests for Admission Gate v0.1 replay.

Each test maps 1:1 to the goal's verification list:

1. denied action cannot execute                 -> denied_action_executed
2. missing receipt fails replay                 -> missing_receipt
3. tampered receipt fails replay                -> tampered_receipt
4. changed policy version is detected           -> policy_version_drift
5. changed policy bundle hash is detected       -> policy_bundle_hash_drift
6. transform without transformed boundary fails -> transform_missing_boundary
7. require_review without human-review receipt  -> missing_human_review_receipt
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from governance.admission import (
    ReplayError,
    decide,
    load_policy_bundle,
    verify_decision,
    verify_decision_with_execution,
)
from governance.admission.policy import policy_bundle_from_dict

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "admission_gate_v0_1"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture()
def bundle():
    return load_policy_bundle(FIXTURES / "policy_bundle.json")


# ---------------------------------------------------------------------------
# 1. denied action cannot execute
# ---------------------------------------------------------------------------


def test_denied_action_cannot_execute(bundle) -> None:
    req = _load("deny_request.json")
    dec = decide(req, policy_bundle=bundle)
    assert dec["decision"] == "deny"

    # zero events: replay must pass
    report = verify_decision_with_execution(
        request=req,
        decision=dec,
        policy_bundle=bundle,
        execution_events=[],
    )
    assert report["ok"] is True

    # any event after deny: replay must FAIL
    with pytest.raises(ReplayError) as exc:
        verify_decision_with_execution(
            request=req,
            decision=dec,
            policy_bundle=bundle,
            execution_events=[{"kind": "tool_call", "boundary": {}}],
        )
    assert exc.value.code == "denied_action_executed"


# ---------------------------------------------------------------------------
# 2. missing receipt fails replay
# ---------------------------------------------------------------------------


def test_missing_receipt_fails_replay(bundle) -> None:
    req = _load("allow_request.json")
    dec = decide(req, policy_bundle=bundle)
    stripped = {k: v for k, v in dec.items() if k != "receipt"}
    with pytest.raises(ReplayError) as exc:
        verify_decision(request=req, decision=stripped, policy_bundle=bundle)
    assert exc.value.code == "missing_receipt"


# ---------------------------------------------------------------------------
# 3. tampered receipt fails replay
# ---------------------------------------------------------------------------


def test_tampered_receipt_request_hash(bundle) -> None:
    req = _load("allow_request.json")
    dec = decide(req, policy_bundle=bundle)
    dec["receipt"]["request_hash"] = "0" * 64
    with pytest.raises(ReplayError) as exc:
        verify_decision(request=req, decision=dec, policy_bundle=bundle)
    assert exc.value.code == "tampered_receipt"


def test_tampered_decision_body_detected_via_decision_hash(bundle) -> None:
    """Editing the decision body without re-issuing the receipt is rejected."""
    req = _load("allow_request.json")
    dec = decide(req, policy_bundle=bundle)
    # silently downgrade "deny" → "allow" on a deny decision would be the
    # attack here; we simulate by mutating a non-receipt field
    dec["reason_code"] = "allowed_with_constraints"
    dec["matched_constraints"] = ["forged"]
    with pytest.raises(ReplayError) as exc:
        verify_decision(request=req, decision=dec, policy_bundle=bundle)
    assert exc.value.code == "tampered_receipt"


# ---------------------------------------------------------------------------
# 4. changed policy version is detected
# ---------------------------------------------------------------------------


def test_changed_policy_version_detected(bundle) -> None:
    req = _load("allow_request.json")
    dec = decide(req, policy_bundle=bundle)
    # swap to a bundle with same hash inputs but different version → must
    # produce a different bundle hash AND a version-drift error
    drifted_raw = copy.deepcopy(bundle.raw)
    drifted_raw["version"] = "1.2.1"
    drifted = policy_bundle_from_dict(drifted_raw)
    with pytest.raises(ReplayError) as exc:
        verify_decision(request=req, decision=dec, policy_bundle=drifted)
    # policy_bundle_hash trips first because changing version changes hash;
    # the version-drift code is the explicit secondary detector when the
    # caller forces a matching hash (covered by next test).
    assert exc.value.code in {"policy_bundle_hash_drift", "policy_version_drift"}


def test_policy_version_drift_explicit(bundle) -> None:
    """If a forged decision claims a different policy_version than the
    loaded bundle, replay must surface it as version drift."""
    req = _load("allow_request.json")
    dec = decide(req, policy_bundle=bundle)
    dec["receipt"]["policy_version"] = "9.9.9"
    with pytest.raises(ReplayError) as exc:
        verify_decision(request=req, decision=dec, policy_bundle=bundle)
    assert exc.value.code == "policy_version_drift"


# ---------------------------------------------------------------------------
# 5. changed policy bundle hash is detected
# ---------------------------------------------------------------------------


def test_changed_policy_bundle_hash_detected(bundle) -> None:
    req = _load("allow_request.json")
    dec = decide(req, policy_bundle=bundle)
    mutated_raw = copy.deepcopy(bundle.raw)
    mutated_raw["rules"].append(
        {
            "id": "smuggled_rule",
            "when": {},
            "action": "allow",
            "reason_code": "allowed_with_constraints",
        }
    )
    mutated = policy_bundle_from_dict(mutated_raw)
    with pytest.raises(ReplayError) as exc:
        verify_decision(request=req, decision=dec, policy_bundle=mutated)
    assert exc.value.code == "policy_bundle_hash_drift"


# ---------------------------------------------------------------------------
# 6. transform without transformed boundary fails replay
# ---------------------------------------------------------------------------


def test_transform_without_transformed_boundary(bundle) -> None:
    req = _load("transform_request.json")
    dec = decide(req, policy_bundle=bundle)
    assert dec["decision"] == "transform"

    # strip the boundary, re-sign the receipt to keep hashes consistent so
    # the structural check (not the tamper check) is what fires
    dec["transform"]["transformed_boundary"] = None
    body_only = {k: v for k, v in dec.items() if k != "receipt"}
    from governance.models import sha256_json

    dec["receipt"]["decision_hash"] = sha256_json(body_only)

    with pytest.raises(ReplayError) as exc:
        verify_decision_with_execution(
            request=req,
            decision=dec,
            policy_bundle=bundle,
            execution_events=[
                {"kind": "tool_call", "boundary": {"allowed_outputs": ["internal_draft"], "disallowed_outputs": []}}
            ],
        )
    assert exc.value.code == "transform_missing_boundary"


def test_transform_execution_outside_boundary(bundle) -> None:
    """A transform decision plus an execution event whose boundary differs
    from the transformed boundary must fail replay."""
    req = _load("transform_request.json")
    dec = decide(req, policy_bundle=bundle)
    bad_event = {
        "kind": "tool_call",
        "boundary": {
            "allowed_outputs": ["client_facing_legal_advice"],  # not the transformed one
            "disallowed_outputs": [],
        },
    }
    with pytest.raises(ReplayError) as exc:
        verify_decision_with_execution(
            request=req,
            decision=dec,
            policy_bundle=bundle,
            execution_events=[bad_event],
        )
    assert exc.value.code == "execution_outside_transformed_boundary"


# ---------------------------------------------------------------------------
# 7. require_review without human-review receipt fails replay
# ---------------------------------------------------------------------------


def test_require_review_without_human_review_receipt(bundle) -> None:
    req = _load("require_review_request.json")
    dec = decide(req, policy_bundle=bundle)
    assert dec["decision"] == "require_review"

    # zero events, no reviews: ok (pending)
    report = verify_decision_with_execution(
        request=req,
        decision=dec,
        policy_bundle=bundle,
        execution_events=[],
        human_review_receipts=[],
    )
    assert report["ok"] is True
    assert report["human_review_satisfied"] is False

    # one event, no review: must fail
    with pytest.raises(ReplayError) as exc:
        verify_decision_with_execution(
            request=req,
            decision=dec,
            policy_bundle=bundle,
            execution_events=[{"kind": "tool_call", "boundary": {}}],
            human_review_receipts=[],
        )
    assert exc.value.code == "missing_human_review_receipt"

    # one event WITH a valid approved review: must pass
    review = {"request_id": req["request_id"], "reviewer_role": "licensed_lawyer", "approved": True}
    report = verify_decision_with_execution(
        request=req,
        decision=dec,
        policy_bundle=bundle,
        execution_events=[{"kind": "tool_call", "boundary": {}}],
        human_review_receipts=[review],
    )
    assert report["ok"] is True
    assert report["human_review_satisfied"] is True


# ---------------------------------------------------------------------------
# positive control: clean allow round-trips
# ---------------------------------------------------------------------------


def test_clean_allow_round_trips(bundle) -> None:
    req = _load("allow_request.json")
    dec = decide(req, policy_bundle=bundle)
    report = verify_decision(request=req, decision=dec, policy_bundle=bundle)
    assert report["ok"] is True
    assert report["decision"] == "allow"
