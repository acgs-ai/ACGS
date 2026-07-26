"""Adversarial regression tests for PQL/GPA empty-feed fail-closed behavior."""

from __future__ import annotations

import pytest

from gove_zone.decision import Decision
from gove_zone.pql_compiler import (
    IngestionAdapterError,
    StaticVerificationError,
    TranspilationError,
    compile_pql_to_ruleset,
)
from gove_zone.tool import ToolCall


def test_empty_raw_sources_rejected_without_phantom_policy() -> None:
    with pytest.raises(StaticVerificationError, match="zero governance rules"):
        compile_pql_to_ruleset("p-empty", [])


def test_supported_but_empty_vendor_feed_rejected() -> None:
    with pytest.raises(IngestionAdapterError, match="produced zero rules"):
        compile_pql_to_ruleset("p-empty-celonis", [{"type": "celonis", "limits": []}])


def test_unknown_source_type_rejected() -> None:
    with pytest.raises(IngestionAdapterError, match="Unsupported PQL source type"):
        compile_pql_to_ruleset("p-unknown", [{"type": "celoniss", "limits": []}])


def test_missing_source_type_rejected() -> None:
    with pytest.raises(IngestionAdapterError, match="missing a supported 'type'"):
        compile_pql_to_ruleset("p-missing-type", [{"limits": []}])


def test_empty_graph_rejected_without_invalid_tool_fallback() -> None:
    with pytest.raises(TranspilationError, match="zero rules"):
        compile_pql_to_ruleset("p-empty-graph", [], {"id": "empty-flow", "nodes": []})


def test_empty_vendor_source_plus_valid_graph_still_rejected() -> None:
    with pytest.raises(IngestionAdapterError, match="produced zero rules"):
        compile_pql_to_ruleset(
            "p-empty-source-valid-graph",
            [{"type": "celonis", "limits": []}],
            {
                "id": "valid-flow",
                "nodes": [{"id": "approve-invoice", "tool": "sap.invoice.approve"}],
            },
        )


def test_empty_vendor_source_plus_valid_second_source_still_rejected() -> None:
    with pytest.raises(IngestionAdapterError, match="produced zero rules"):
        compile_pql_to_ruleset(
            "p-empty-source-valid-second-source",
            [
                {"type": "celonis", "limits": []},
                {"type": "signavio", "insights": [{"id": "valid-rule", "actions": ["sap.pay"]}]},
            ],
        )


def test_renamed_vendor_key_plus_valid_second_source_still_rejected() -> None:
    with pytest.raises(IngestionAdapterError, match="produced zero rules"):
        compile_pql_to_ruleset(
            "p-renamed-key-valid-second-source",
            [
                {"type": "signavio", "renamed_insights": [{"id": "lost-rule"}]},
                {"type": "celonis", "limits": [{"id": "valid-rule", "tools": ["sap.pay"]}]},
            ],
        )


def test_empty_graph_plus_valid_vendor_source_still_rejected() -> None:
    with pytest.raises(TranspilationError, match="zero rules"):
        compile_pql_to_ruleset(
            "p-empty-graph-valid-source",
            [{"type": "celonis", "limits": [{"id": "valid-rule", "tools": ["sap.pay"]}]}],
            {"id": "empty-flow", "nodes": []},
        )


def test_graph_only_policy_remains_supported_for_real_rule() -> None:
    policy = compile_pql_to_ruleset(
        "p-graph-only",
        [],
        {"id": "po-flow", "nodes": [{"id": "approve-invoice", "tool": "sap.invoice.approve"}]},
    )

    assert [rule.rule_id for rule in policy.rules] == ["gpa-rule-approve-invoice"]
    assert policy.evaluate(ToolCall(name="sap.invoice.approve")).decision is Decision.DENY
    assert all("gpa.invalid.tool" not in rule.tools for rule in policy.rules)


def test_valid_mixed_vendor_and_graph_policy_stays_supported() -> None:
    policy = compile_pql_to_ruleset(
        "p-valid-mixed",
        [{"type": "celonis", "limits": [{"id": "vendor-rule", "tools": ["sap.pay"]}]}],
        {"id": "po-flow", "nodes": [{"id": "approve-invoice", "tool": "sap.invoice.approve"}]},
    )

    assert [rule.rule_id for rule in policy.rules] == ["vendor-rule", "gpa-rule-approve-invoice"]
    assert policy.evaluate(ToolCall(name="sap.pay")).decision is Decision.DENY
    assert policy.evaluate(ToolCall(name="sap.invoice.approve")).decision is Decision.DENY
