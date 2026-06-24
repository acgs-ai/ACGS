"""Fail-closed audit-sink tests (B20).

The governance kernel must never run a tool when its decision cannot be
anchored: if the audit sink is unwritable, dispatch fails closed (raises
``AuditError`` *before* the tool body runs). The durable, operator-configured
sink and the append-time fail-closed behavior already exist; these tests lock
that contract as a dispatcher-level regression guard so it cannot silently
regress to fail-open.

Root-safe by design: ``chmod`` is unreliable here (root bypasses file
permissions), so an unwritable sink is simulated by forcing ``append`` to raise
(dispatch-time) and by a structural parent-is-a-file error (construction-time),
neither of which depends on permission bits.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gove_zone import (
    AllowAllPolicy,
    AuditError,
    ChainHashAuditStore,
    Kernel,
)


def test_unwritable_sink_fails_closed_and_tool_never_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Append failure (dead/unwritable sink) -> dispatch raises ``AuditError``
    and the tool body never executes. The decision cannot be anchored, so the
    side effect must not happen."""
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    k = Kernel(policy=AllowAllPolicy(), audit=audit)
    ran: list[str] = []

    @k.tool("side_effect")
    def side_effect() -> None:
        ran.append("ran")

    def _boom(_record: object) -> dict[str, object]:
        raise OSError("sink unwritable")

    monkeypatch.setattr(audit, "append", _boom)

    with pytest.raises(AuditError):
        k.dispatch("side_effect")

    assert ran == []  # fail-closed: no side effect when the decision can't be anchored


def test_sink_under_a_file_parent_raises_at_construction(tmp_path: Path) -> None:
    """A sink whose parent path is a regular file cannot be created; the store
    surfaces the error at construction rather than silently proceeding. Uses a
    structural (not permission) error, so it holds even when running as root."""
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory", encoding="utf-8")

    with pytest.raises(OSError):
        ChainHashAuditStore(blocker / "audit.jsonl")
