"""Adversary class: POLICY BYPASS via PQL/GPA compiler silent fail-open.

``compile_pql_to_ruleset`` silently skips unrecognized ``source_type`` and, when the
compiled rule set is empty, injects a placeholder deny for a tool that is never called
(``gpa.invalid.tool``) purely to satisfy RuleSetPolicy's ">= 1 rule" constructor guard.
The result is a bundle that is functionally ``AllowAllPolicy`` while LOOKING like a
populated governance bundle. No error is raised — an empty or malformed upstream vendor
feed (Celonis/Signavio) becomes a functional allow-all with no operator-visible signal
and no integrator misconfiguration.

See threat-model-v2.md §2a. This is more severe than the opt-in policy-hash gap because
it requires only an upstream data-quality fault.
"""

from __future__ import annotations

from gove_zone import Decision
from gove_zone.pql_compiler import compile_pql_to_ruleset
from gove_zone.tool import ToolCall


def test_empty_vendor_feed_compiles_to_allow_all_KNOWN_GAP() -> None:
    """An empty feed compiles without error to a policy that permits a real payment tool."""
    policy = compile_pql_to_ruleset("prod-governance", [])

    record = policy.evaluate(
        ToolCall(name="sap.payment.send", args={"amount": 1_000_000}, actor="agent")
    )

    assert record.decision is Decision.ALLOW, (
        "empty vendor feed -> phantom deny for gpa.invalid.tool -> everything else ALLOWed. "
        "If this fails, the compiler now raises on empty input (good — update the manifest)."
    )
    assert record.matched_rules == ()


def test_unrecognized_source_type_silently_skipped_KNOWN_GAP() -> None:
    """A typo'd/renamed source type is silently dropped, again yielding allow-all."""
    policy = compile_pql_to_ruleset(
        "prod-governance",
        [{"type": "CELONIS_TYPO", "limits": [{"tools": ["sap.payment.send"]}]}],
    )

    record = policy.evaluate(
        ToolCall(name="sap.payment.send", args={"amount": 1_000_000}, actor="agent")
    )
    assert record.decision is Decision.ALLOW
