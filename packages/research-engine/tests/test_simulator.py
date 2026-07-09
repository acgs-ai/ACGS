"""Tests for delve's policy simulator, loophole critic, and reporter."""

from __future__ import annotations

from gove_zone.decision import Decision  # type: ignore[import-untyped]
from gove_zone.policy import PolicyRule, RuleSetPolicy  # type: ignore[import-untyped]

from delve.simulator import (
    LivingComplianceReporter,
    LoopholeIdentificationCritic,
    PolicyStressSimulator,
)


def test_stress_simulator() -> None:
    # Set up a policy rule that denies tool-1 if vendor is not approved
    rule = PolicyRule(
        rule_id="deny-unapproved-vendor",
        effect=Decision.DENY,
        tools=frozenset(["tool-1"]),
        state_equals={"vendor_approved": False},
    )
    policy = RuleSetPolicy(policy_id="p-perf", rules=[rule])

    simulator = PolicyStressSimulator(policy)

    # Mutated inputs: index 0 should match policy DENY, index 1 should bypass (ALLOW)
    mutations = [
        {"args": {"val": 1}, "state": {"vendor_approved": False}},
        {"args": {"val": 2}, "state": {"vendor_approved": True}},
    ]

    results = simulator.stress_test_tool("tool-1", {}, mutations)
    assert len(results) == 2
    assert results[0]["decision"] == "deny"
    assert results[1]["decision"] == "allow"


def test_critic_find_loopholes() -> None:
    critic = LoopholeIdentificationCritic()
    policy_dict = {
        "rules": [
            {"id": "unsafe-rule", "effect": "deny", "allow": {"actors": ["anonymous"]}},
            {"id": "broad-rule", "effect": "deny", "tools": ["t1"]},
        ]
    }

    loopholes = critic.find_loopholes(policy_dict)
    assert len(loopholes) == 3

    types = [lh["type"] for lh in loopholes]
    assert "PERMISSIVE_ACTOR" in types
    assert "BROAD_MATCH" in types


def test_compliance_reporter() -> None:
    reporter = LivingComplianceReporter()
    loopholes = [
        {
            "severity": "CRITICAL",
            "rule_id": "rule-1",
            "type": "PERMISSIVE_ACTOR",
            "description": "Allows anonymous",
        }
    ]
    sim_results = [{"mutation_index": 0, "args": {}, "state": {}, "decision": "allow"}]

    brief = reporter.generate_brief(loopholes, sim_results)
    assert "GPA-Control Living Compliance Brief" in brief
    assert "Vulnerability" in brief or "Loophole" in brief
    assert "anonymous" in brief

    patch = reporter.suggest_patch(loopholes[0])
    assert patch["action"] == "modify_rule"
    assert patch["rule_id"] == "rule-1"
    assert patch["patch"]["allow"]["actors"] == ["authorized-agent"]
