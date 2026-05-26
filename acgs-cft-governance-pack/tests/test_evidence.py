from __future__ import annotations

from datetime import datetime, timezone

from acgs_cft_governance_pack.evidence import build_evidence_event


def test_build_evidence_event_adds_decision_reason_hashes_and_timestamp() -> None:
    event = build_evidence_event(
        plan_hash="sha256:plan",
        policies=["policy-a", "policy-b"],
        control_results=[
            {
                "policy_id": "policy-a",
                "control_id": "control-a",
                "status": "pass",
                "violations": [],
            },
            {
                "policy_id": "policy-b",
                "control_id": "control-b",
                "status": "fail",
                "violations": [{"address": "x", "message": "denied"}],
            },
        ],
        actor_id="platform-ci",
        actor_role="validator",
        tenant="cft",
        now=datetime(2026, 5, 26, 12, 0, tzinfo=timezone.utc),
    )

    assert event["schema"] == "acgs.cft.evidence.v1"
    assert event["event_type"] == "terraform_plan_evaluation"
    assert event["timestamp"] == "2026-05-26T12:00:00Z"
    assert event["tenant"] == "cft"
    assert event["actor"] == {"id": "platform-ci", "role": "validator"}
    assert event["decision"] == "deny"
    assert event["reason"] == "Denied by 1 governance controls"
    assert event["plan_hash"] == "sha256:plan"
    assert event["policies"] == ["policy-a", "policy-b"]
    assert event["control_results"][1]["control_id"] == "control-b"
    assert event["merkle_root"].startswith("sha256:")
