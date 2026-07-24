"""Declarative path/state policy tests.

The roadmap's next kernel step after raw path-boundary checks is a richer,
replayable policy surface over path + organization state + trust tier. These
regressions keep that DSL deterministic and pre-execution.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gove_zone import ChainHashAuditStore, Decision, DeniedError, Kernel, RuleSetPolicy, ToolCall


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

    @kernel.tool("matter.fetch")
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

    @kernel.tool("matter.fetch")
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


def test_rule_set_policy_allows_when_args_match_trusted_state_binding() -> None:
    policy = RuleSetPolicy.from_dict(
        {
            "id": "arg-binding/v1",
            "rules": [
                {
                    "id": "TENANT_MISMATCH",
                    "effect": "deny",
                    "tools": ["tenant.write"],
                    "args_bound_to": {"tenant_id": "tenant_id"},
                }
            ],
        }
    )

    record = policy.evaluate(
        ToolCall(
            name="tenant.write",
            args={"tenant_id": "tenant-7"},
            state={"tenant_id": "tenant-7"},
        )
    )

    assert record.decision is Decision.ALLOW
    assert record.matched_rules == ()
    assert record.reason == "no rules matched"


def test_rule_set_policy_denies_when_arg_binding_mismatches_trusted_state() -> None:
    policy = RuleSetPolicy.from_dict(
        {
            "id": "arg-binding/v1",
            "rules": [
                {
                    "id": "TENANT_MISMATCH",
                    "effect": "deny",
                    "tools": ["tenant.write"],
                    "args_bound_to": {"tenant_id": "tenant_id"},
                    "reason": "tenant id must match trusted runner state",
                }
            ],
        }
    )

    record = policy.evaluate(
        ToolCall(
            name="tenant.write",
            args={"tenant_id": "tenant-8"},
            state={"tenant_id": "tenant-7"},
        )
    )

    assert record.decision is Decision.DENY
    assert record.matched_rules == ("TENANT_MISMATCH",)
    assert "trusted runner state" in record.reason


def test_rule_set_policy_denies_when_arg_binding_state_is_missing() -> None:
    policy = RuleSetPolicy.from_dict(
        {
            "id": "arg-binding/v1",
            "rules": [
                {
                    "id": "TENANT_MISSING",
                    "effect": "deny",
                    "tools": ["tenant.write"],
                    "args_bound_to": {"tenant_id": "tenant_id"},
                }
            ],
        }
    )

    record = policy.evaluate(
        ToolCall(
            name="tenant.write",
            args={"tenant_id": "tenant-7"},
            state={},
        )
    )

    assert record.decision is Decision.DENY
    assert record.matched_rules == ("TENANT_MISSING",)


def test_rule_set_policy_arg_binding_empty_payload_preserves_version_compatibility() -> None:
    direct = RuleSetPolicy.from_dict(
        {
            "id": "arg-binding/v1",
            "rules": [
                {
                    "id": "EMPTY_BINDING",
                    "effect": "deny",
                    "tools": ["tenant.write"],
                    "args_bound_to": {},
                }
            ],
        }
    )
    omitted = RuleSetPolicy.from_dict(
        {
            "id": "arg-binding/v1",
            "rules": [
                {
                    "id": "EMPTY_BINDING",
                    "effect": "deny",
                    "tools": ["tenant.write"],
                }
            ],
        }
    )

    assert "args_bound_to" not in direct.rules[0].version_payload()
    assert "args_bound_to" not in direct.rules[0].to_dict()
    assert direct.version == omitted.version


def test_agent_cannot_self_authorize_bound_argument_from_raw_args() -> None:
    # The trusted side of an args_bound_to binding lives in ToolCall.state
    # (runner-injected). An untrusted caller must not be able to authorize
    # itself by smuggling the binding target into the tool arguments: the
    # matcher reads call.state, never call.args, for the trusted value. A DENY
    # decision at the policy gate is the point at which the side effect is
    # refused.
    policy = RuleSetPolicy.from_dict(
        {
            "id": "arg-binding/v1",
            "rules": [
                {
                    "id": "TENANT_BINDING",
                    "effect": "deny",
                    "tools": ["tenant.write"],
                    "args_bound_to": {"tenant_id": "tenant_id"},
                    "reason": "tenant id must match trusted runner state",
                }
            ],
        }
    )

    # Caller puts the target in args AND smuggles a "state" mapping into args,
    # but the trusted ToolCall.state is absent -> fail closed (DENY).
    smuggled_missing_state = policy.evaluate(
        ToolCall(
            name="tenant.write",
            args={"tenant_id": "tenant-9", "state": {"tenant_id": "tenant-9"}},
            state={},
        )
    )
    assert smuggled_missing_state.decision is Decision.DENY
    assert smuggled_missing_state.matched_rules == ("TENANT_BINDING",)

    # Caller's args disagree with the trusted state -> DENY (args cannot
    # override the runner-established binding).
    args_override_attempt = policy.evaluate(
        ToolCall(
            name="tenant.write",
            args={"tenant_id": "tenant-9"},
            state={"tenant_id": "tenant-7"},
        )
    )
    assert args_override_attempt.decision is Decision.DENY
    assert args_override_attempt.matched_rules == ("TENANT_BINDING",)
