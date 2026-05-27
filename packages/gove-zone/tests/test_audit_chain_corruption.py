"""Corrupt audit-tail handling tests.

The audit store may treat missing and empty files as a new chain, but any
non-empty unreadable or malformed tail must fail closed before appending.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gove_zone import (
    GENESIS_HASH,
    AllowAllPolicy,
    AuditChainError,
    AuditError,
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    Kernel,
    sha256_json,
)


def _record(event_id: str) -> DecisionRecord:
    return DecisionRecord(
        decision=Decision.ALLOW,
        tool="write_file",
        argument_hash=sha256_json({"id": event_id}),
        policy_version="v0",
        event_id=event_id,
    )


def test_append_rejects_corrupt_final_jsonl_line_without_writing(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    store.append(_record("e1"))
    before_valid_lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(path.read_text(encoding="utf-8") + '{"event_id":"broken"\n', encoding="utf-8")
    before = path.read_text(encoding="utf-8")

    with pytest.raises(AuditChainError, match="not valid JSON"):
        store.append(_record("e2"))

    assert path.read_text(encoding="utf-8") == before
    assert path.read_text(encoding="utf-8").splitlines() == [
        *before_valid_lines,
        '{"event_id":"broken"',
    ]


def test_append_rejects_truncated_final_event_hash(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text(
        json.dumps(
            {"event_id": "broken", "previous_hash": GENESIS_HASH},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(AuditChainError, match="invalid event_hash"):
        ChainHashAuditStore(path).append(_record("e2"))


def test_append_rejects_non_string_final_event_hash(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text(
        json.dumps(
            {"event_id": "broken", "event_hash": 42, "previous_hash": GENESIS_HASH},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(AuditChainError, match="invalid event_hash"):
        ChainHashAuditStore(path).append(_record("e2"))


def test_empty_audit_file_starts_from_genesis(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")

    payload = ChainHashAuditStore(path).append(_record("e1"))

    assert payload["previous_hash"] == GENESIS_HASH
    assert payload["event_hash"] != GENESIS_HASH


def test_dispatch_does_not_invoke_tool_when_audit_tail_is_corrupt(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text('{"event_id":"broken"\n', encoding="utf-8")
    kernel = Kernel(policy=AllowAllPolicy(), audit=ChainHashAuditStore(path))
    invocations: list[str] = []

    @kernel.tool("side_effect")
    def side_effect() -> None:
        invocations.append("ran")

    with pytest.raises(AuditError) as exc_info:
        kernel.dispatch("side_effect")

    assert isinstance(exc_info.value.__cause__, AuditChainError)
    assert invocations == []
    assert path.read_text(encoding="utf-8") == '{"event_id":"broken"\n'


def test_verify_chain_raises_audit_chain_error_on_malformed_line(tmp_path: Path) -> None:
    """verify_chain must surface AuditChainError, not raw JSONDecodeError.

    Callers that catch AuditError around append also expect the same type
    from verify_chain; a leaked json.JSONDecodeError forces them to widen
    the except clause and breaks the symmetric audit-chain contract.
    """
    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    store.append(_record("e1"))
    path.write_text(path.read_text(encoding="utf-8") + "{not-json\n", encoding="utf-8")

    with pytest.raises(AuditChainError, match="not valid JSON"):
        store.verify_chain()


def test_verify_chain_raises_audit_chain_error_on_non_object_line(tmp_path: Path) -> None:
    """A line that parses to a non-dict (e.g. a JSON list) is also corruption."""
    path = tmp_path / "audit.jsonl"
    path.write_text("[1, 2, 3]\n", encoding="utf-8")

    with pytest.raises(AuditChainError, match="not a JSON object"):
        ChainHashAuditStore(path).verify_chain()
