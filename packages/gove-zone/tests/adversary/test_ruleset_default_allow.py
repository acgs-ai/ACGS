"""Adversary class: POLICY BYPASS via RuleSetPolicy allow-by-default.

``RuleSetPolicy`` is a deny/escalate-only overlay: a call matching NO rule falls through
to ALLOW (policy.py evaluate). That is by design — positive authorization is meant to be
composed under a deny-by-default base via ``CompositePolicy``. The foot-gun: nothing stops
a bare ``RuleSetPolicy`` (or ``YAMLPolicy``) from being THE terminal kernel policy in
production, where any unanticipated action (new tool, path typo, novel arg shape) is
silently permitted.

See threat-model-v2.md §2b.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gove_zone import (
    ChainHashAuditStore,
    CompositePolicy,
    Decision,
    DeniedError,
    DenyAllPolicy,
    Kernel,
    RuleSetPolicy,
)


def _deny_delete_only() -> RuleSetPolicy:
    return RuleSetPolicy.from_dict(
        {
            "id": "deny-delete/v1",
            "rules": [{"id": "BLOCK_DELETE", "effect": "deny", "tools": ["fs.delete"]}],
        }
    )


def test_unmatched_action_falls_through_to_allow_KNOWN_GAP(tmp_path: Path) -> None:
    """A tool matching no rule is executed with an empty matched-rules set — allow by
    default. The attack (invoke an un-modeled action) succeeds today."""
    kernel = Kernel(
        policy=_deny_delete_only(),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        actor="agent",
    )
    ran: list[str] = []

    @kernel.tool("fs.write")
    def write(path: str = "x") -> str:
        ran.append(path)
        return "wrote"

    result, receipt = kernel.dispatch("fs.write", {"path": "/etc/shadow"})

    assert result == "wrote"
    assert ran == ["/etc/shadow"]
    assert receipt.record.decision is Decision.ALLOW
    assert receipt.record.matched_rules == ()


def test_composite_deny_base_closes_the_gap_HELD(tmp_path: Path) -> None:
    """Composing the overlay above a DenyAllPolicy base closes the fall-through: an
    unmatched action is denied. This is the intended safe construction."""
    policy = CompositePolicy([_deny_delete_only(), DenyAllPolicy()])
    kernel = Kernel(
        policy=policy,
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        actor="agent",
    )
    ran: list[str] = []

    @kernel.tool("fs.write")
    def write(path: str = "x") -> str:
        ran.append(path)
        return "wrote"

    with pytest.raises(DeniedError):
        kernel.dispatch("fs.write", {"path": "/etc/shadow"})
    assert ran == []
