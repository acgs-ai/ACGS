"""Tests for the PQL compiler, graph transpiler, and static verifier."""

from __future__ import annotations

import pytest

from gove_zone.decision import Decision
from gove_zone.pql_compiler import (
    CelonisOCPMAdapter,
    GraphPreservationTranspiler,
    IngestionAdapterError,
    SignavioInsightsAdapter,
    StaticVerificationError,
    TranspilationError,
    compile_pql_to_ruleset,
)


def test_celonis_adapter_success() -> None:
    adapter = CelonisOCPMAdapter()
    raw = {
        "limits": [
            {
                "id": "limit-1",
                "action": "escalate",
                "tools": ["sap.invoice.approve"],
                "state_equals": {"vendor_type": "restricted"},
                "reason": "Restricted vendor",
            }
        ]
    }
    rules = adapter.ingest_limits(raw)
    assert len(rules) == 1
    assert rules[0]["id"] == "limit-1"
    assert rules[0]["effect"] == Decision.ESCALATE.value
    assert rules[0]["tools"] == ["sap.invoice.approve"]
    assert rules[0]["state_equals"] == {"vendor_type": "restricted"}


def test_celonis_adapter_invalid_data() -> None:
    adapter = CelonisOCPMAdapter()
    with pytest.raises(IngestionAdapterError):
        adapter.ingest_limits("not-json")


def test_signavio_adapter_success() -> None:
    adapter = SignavioInsightsAdapter()
    raw = {
        "insights": [
            {
                "id": "insight-1",
                "severity": "deny",
                "actions": ["sap.payment.send"],
                "description": "High value payment breach",
            }
        ]
    }
    rules = adapter.ingest_insights(raw)
    assert len(rules) == 1
    assert rules[0]["id"] == "insight-1"
    assert rules[0]["effect"] == Decision.DENY.value


def test_transpiler_success() -> None:
    transpiler = GraphPreservationTranspiler()
    spec = {
        "id": "order-to-cash",
        "nodes": [
            {"id": "create-order", "object": "sales_order", "tool": "sap.order.create"},
            {
                "id": "release-delivery",
                "object": "delivery",
                "tool": "sap.delivery.release",
                "depends_on": "create-order",
            },
        ],
    }
    ast = transpiler.transpile(spec)
    assert ast["id"] == "gpa-order-to-cash"
    rules = ast["rules"]
    assert len(rules) == 2

    # Check that OCPM parent-child dependency is preserved in state_equals
    delivery_rule = next(r for r in rules if r["id"] == "gpa-rule-release-delivery")
    assert delivery_rule["state_equals"] == {"parent_sales_order_id": "bound_create-order"}
    assert delivery_rule["tools"] == ["sap.delivery.release"]


def test_transpiler_invalid() -> None:
    transpiler = GraphPreservationTranspiler()
    with pytest.raises(TranspilationError):
        transpiler.transpile([])  # Must be dict


def test_verifier_duplicate_id() -> None:
    # Create a policy with duplicate rule IDs using the compiler helper
    raw_sources = [
        {
            "type": "celonis",
            "limits": [
                {"id": "duplicate-id", "tools": ["t1"]},
                {"id": "duplicate-id", "tools": ["t2"]},
            ],
        }
    ]
    with pytest.raises(StaticVerificationError):
        compile_pql_to_ruleset("p-test", raw_sources)


def test_compile_pql_to_ruleset() -> None:
    sources = [
        {"type": "celonis", "limits": [{"id": "rule-celonis", "tools": ["t1"]}]},
        {"type": "signavio", "insights": [{"id": "rule-signavio", "actions": ["t2"]}]},
    ]
    graph_spec = {"id": "po-flow", "nodes": [{"id": "n1", "object": "po", "tool": "t3"}]}

    policy = compile_pql_to_ruleset("p-complete", sources, graph_spec)
    assert policy.policy_id == "p-complete"
    assert len(policy.rules) == 3
    rule_ids = [r.rule_id for r in policy.rules]
    assert "rule-celonis" in rule_ids
    assert "rule-signavio" in rule_ids
    assert "gpa-rule-n1" in rule_ids
