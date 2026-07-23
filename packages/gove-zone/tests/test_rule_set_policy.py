"""Declarative path/state policy tests.

The roadmap's next kernel step after raw path-boundary checks is a richer,
replayable policy surface over path + organization state + trust tier. These
regressions keep that DSL deterministic and pre-execution.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gove_zone import ChainHashAuditStore, DeniedError, Kernel, RuleSetPolicy, ToolEffect


def _privileged_notes_policy() -> RuleSetPolicy:
    return RuleSetPolicy.from_dict(
        {
            "id": "legal-privilege/v1",
            "rules": [
                {
                    "id": "PRIVILEGED_NOTES_REVIEW",
                    "effect": "deny",
                    "tools": ["matter.fetch"],
                    "path_prefix": "tenant-7/matter-9821/private-notes",
                    "state_equals": {"matter_status": "privileged"},
                    "state_contains": {
                        "org_controls": "human_review_required_for_privileged_notes"
                    },
                    "allow": {
                        "actors": ["review-lead"],
                        "trust_tiers": ["reviewer", "admin"],
                    },
                    "reason": "privileged matter notes require reviewer trust",
                }
            ],
        }
    )


def test_rule_set_policy_denies_matching_path_state_and_low_trust_actor(
    tmp_path: Path,
) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(policy=_privileged_notes_policy(), audit=audit, actor="analyst-12")
    executed: list[str] = []

    @kernel.tool("matter.fetch", effect=ToolEffect.PURE_READ_ONLY)
    def fetch(matter_id: str) -> str:
        executed.append(matter_id)
        return matter_id

    with pytest.raises(DeniedError) as exc_info:
        kernel.dispatch(
            "matter.fetch",
            {"matter_id": "Matter-9821"},
            goal="Read privileged notes",
            path="tenant-7/matter-9821/private-notes",
            state={
                "matter_status": "privileged",
                "org_controls": ["human_review_required_for_privileged_notes"],
                "trust_tier": "analyst",
            },
        )

    assert executed == []
    assert exc_info.value.record.matched_rules == ("PRIVILEGED_NOTES_REVIEW",)
    assert "reviewer trust" in exc_info.value.record.reason

    [event] = list(audit.iter_events())
    assert event["policy_version"].startswith("ruleset/legal-privilege/v1/")
    assert event["actor"] == "analyst-12"
    assert event["path"] == ["tenant-7", "matter-9821", "private-notes"]
    assert event["state_hash"]
    assert event["decision_request_hash"]


def test_rule_set_policy_allows_matching_rule_when_trust_tier_is_allowed(
    tmp_path: Path,
) -> None:
    kernel = Kernel(
        policy=_privileged_notes_policy(),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        actor="analyst-12",
    )

    @kernel.tool("matter.fetch", effect=ToolEffect.PURE_READ_ONLY)
    def fetch(matter_id: str) -> str:
        return f"ok:{matter_id}"

    result, receipt = kernel.dispatch(
        "matter.fetch",
        {"matter_id": "Matter-9821"},
        goal="Read privileged notes after escalation",
        path=("tenant-7", "matter-9821", "private-notes"),
        state={
            "matter_status": "privileged",
            "org_controls": ["human_review_required_for_privileged_notes"],
            "trust_tier": "reviewer",
        },
    )

    assert result == "ok:Matter-9821"
    assert receipt.record.matched_rules == ("PRIVILEGED_NOTES_REVIEW:allow:trust_tier",)
    assert receipt.record.state_hash
    assert receipt.record.decision_request_hash


def test_rule_set_policy_version_changes_with_rule_contract() -> None:
    baseline = _privileged_notes_policy()
    tightened = RuleSetPolicy.from_dict(
        {
            "id": "legal-privilege/v1",
            "rules": [
                {
                    "id": "PRIVILEGED_NOTES_REVIEW",
                    "effect": "deny",
                    "path_prefix": "tenant-7/matter-9821/private-notes",
                    "state_equals": {"matter_status": "privileged"},
                    "allow": {"trust_tiers": ["admin"]},
                }
            ],
        }
    )

    assert baseline.version != tightened.version
