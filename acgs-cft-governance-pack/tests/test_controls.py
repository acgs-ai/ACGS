from __future__ import annotations

import pytest

from acgs_cft_governance_pack.controls import evaluate_control


def test_evaluate_control_reports_forbidden_api_violation() -> None:
    plan = {
        "resource_changes": [
            {
                "address": "google_project_service.bad",
                "type": "google_project_service",
                "change": {"actions": ["create"], "after": {"service": "sqladmin.googleapis.com"}},
            },
        ],
    }
    control = {
        "id": "deny-sqladmin",
        "severity": "high",
        "rule": {
            "kind": "forbidden_apis",
            "resource_types": ["google_project_service"],
            "services": ["sqladmin.googleapis.com"],
        },
    }

    result = evaluate_control(plan, "project-policy", control)

    assert result["status"] == "fail"
    assert result["violations"] == [
        {
            "address": "google_project_service.bad",
            "type": "google_project_service",
            "message": "Forbidden API enabled: sqladmin.googleapis.com",
        },
    ]


def test_evaluate_control_rejects_unknown_rule_kind() -> None:
    control = {"id": "unknown", "rule": {"kind": "not_a_rule"}}

    with pytest.raises(ValueError, match="Unknown rule kind: not_a_rule"):
        evaluate_control({"resource_changes": []}, "project-policy", control)
