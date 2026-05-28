"""Path-aware governance tests.

The market roadmap's "policies on paths" requirement is stronger than a
tool-name or argument-only boundary: the kernel must thread actor, path, and
state context into the pre-execution policy decision and persist that context
in the audit chain.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gove_zone import ChainHashAuditStore, DeniedError, Kernel, PathBoundaryPolicy


def test_path_boundary_denies_before_tool_execution_and_records_context(tmp_path: Path) -> None:
    audit = ChainHashAuditStore(tmp_path / "audit.jsonl")
    kernel = Kernel(
        policy=PathBoundaryPolicy(
            blocked_prefixes=["tenant-7/matter-9821/private-notes"],
            allowed_actors=["review-lead"],
        ),
        audit=audit,
        actor="analyst-12",
    )
    executed: list[str] = []

    @kernel.tool("matter.fetch")
    def fetch(matter_id: str) -> str:
        executed.append(matter_id)
        return matter_id

    with pytest.raises(DeniedError) as exc_info:
        kernel.dispatch(
            "matter.fetch",
            {"matter_id": "Matter-9821"},
            goal="Review matter private notes",
            path=("tenant-7", "matter-9821", "private-notes"),
            state={"matter_status": "privileged", "ticket": "IR-17"},
        )

    assert executed == []
    assert "PATH_BOUNDARY" in exc_info.value.record.matched_rules[0]

    events = list(audit.iter_events())
    assert len(events) == 1
    event = events[0]
    assert event["actor"] == "analyst-12"
    assert event["path"] == ["tenant-7", "matter-9821", "private-notes"]
    assert event["state_hash"]
    assert event["decision_request_hash"]


def test_path_boundary_allows_authorized_actor_and_preserves_receipt_context(
    tmp_path: Path,
) -> None:
    kernel = Kernel(
        policy=PathBoundaryPolicy(
            blocked_prefixes=["tenant-7/matter-9821/private-notes"],
            allowed_actors=["review-lead"],
        ),
        audit=ChainHashAuditStore(tmp_path / "audit.jsonl"),
        actor="review-lead",
    )

    @kernel.tool("matter.fetch")
    def fetch(matter_id: str) -> str:
        return f"ok:{matter_id}"

    result, receipt = kernel.dispatch(
        "matter.fetch",
        {"matter_id": "Matter-9821"},
        goal="Review matter private notes",
        path="tenant-7/matter-9821/private-notes",
        state={"matter_status": "privileged"},
    )

    assert result == "ok:Matter-9821"
    assert receipt.record.actor == "review-lead"
    assert receipt.record.path == ("tenant-7", "matter-9821", "private-notes")
    assert receipt.record.state_hash
    assert receipt.record.decision_request_hash
