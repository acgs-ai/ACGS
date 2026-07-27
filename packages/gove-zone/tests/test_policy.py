"""Policy correctness tests."""

from __future__ import annotations

import pytest

from gove_zone import (
    AllowAllPolicy,
    BoundaryPolicy,
    CompositePolicy,
    Decision,
    DenyAllPolicy,
)
from gove_zone.tool import ToolCall


def _call(name: str = "write_file", **args: object) -> ToolCall:
    return ToolCall(name=name, args=dict(args))


def test_allow_all_policy_returns_allow() -> None:
    record = AllowAllPolicy().evaluate(_call())
    assert record.decision is Decision.ALLOW
    assert record.policy_version == "allow-all/v0"


def test_deny_all_policy_returns_deny() -> None:
    record = DenyAllPolicy(reason="kill switch").evaluate(_call())
    assert record.decision is Decision.DENY
    assert "kill switch" in record.reason
    assert record.matched_rules == ("DENY_ALL",)


def test_boundary_policy_denies_on_forbidden_keyword() -> None:
    p = BoundaryPolicy(forbidden_keywords=["~/.ssh", "/etc/shadow"])
    record = p.evaluate(_call(path="~/.ssh/id_rsa"))
    assert record.decision is Decision.DENY
    assert any("~/.ssh" in r for r in record.matched_rules)


def test_boundary_policy_denies_on_forbidden_pattern() -> None:
    p = BoundaryPolicy(forbidden_patterns=[r"\b4[0-9]{12}(?:[0-9]{3})?\b"])
    record = p.evaluate(_call(card="4111111111111111"))
    assert record.decision is Decision.DENY
    assert any("4[0-9]" in r for r in record.matched_rules)


def test_boundary_policy_allows_clean_input() -> None:
    p = BoundaryPolicy(forbidden_keywords=["~/.ssh"])
    record = p.evaluate(_call(path="/tmp/safe"))
    assert record.decision is Decision.ALLOW
    assert record.matched_rules == ()


def test_boundary_policy_scoped_to_only_tools() -> None:
    p = BoundaryPolicy(
        forbidden_keywords=["secret"],
        only_tools=["http_post"],
    )
    # Scoped tool — boundary fires
    deny_record = p.evaluate(_call(name="http_post", body="secret payload"))
    assert deny_record.decision is Decision.DENY
    # Out-of-scope tool — boundary skips even when args contain "secret"
    allow_record = p.evaluate(_call(name="write_file", content="secret data"))
    assert allow_record.decision is Decision.ALLOW
    assert "out of scope" in allow_record.reason


def test_boundary_policy_version_changes_when_rules_change() -> None:
    p1 = BoundaryPolicy(forbidden_keywords=["a"])
    p2 = BoundaryPolicy(forbidden_keywords=["b"])
    p1_dup = BoundaryPolicy(forbidden_keywords=["a"])
    assert p1.version != p2.version
    assert p1.version == p1_dup.version  # determinism


def test_composite_policy_first_non_allow_wins() -> None:
    composite = CompositePolicy(
        [
            AllowAllPolicy(),
            DenyAllPolicy(reason="rule 2"),
            AllowAllPolicy(),
        ]
    )
    record = composite.evaluate(_call())
    assert record.decision is Decision.DENY
    assert "rule 2" in record.reason
    # Version reflects the composite, not the member's
    assert record.policy_version.startswith("composite/")


def test_composite_policy_allows_when_all_members_allow() -> None:
    composite = CompositePolicy([AllowAllPolicy(), BoundaryPolicy(forbidden_keywords=["~/.ssh"])])
    record = composite.evaluate(_call(path="/tmp/ok"))
    assert record.decision is Decision.ALLOW
    assert record.policy_version.startswith("composite/")


def test_composite_policy_rejects_empty() -> None:
    with pytest.raises(ValueError):
        CompositePolicy([])
