from __future__ import annotations

from acgs_trajectory import secrets_scan
from acgs_trajectory.adapter import SourceAdapter, read_jsonl
from acgs_trajectory.validate import (
    load_schema,
    v1_causal_graph,
    v2_block_integrity,
    v6_schema,
)


def parse(read_fixture, name):
    return SourceAdapter().parse(read_jsonl(read_fixture(name)))


def test_v1_clean_on_complete(read_fixture):
    assert v1_causal_graph(parse(read_fixture, "complete_session.jsonl")) == []


def test_v1_orphan_detected(read_fixture):
    reasons = v1_causal_graph(parse(read_fixture, "missing_parent_session.jsonl"))
    assert any(r.startswith("V1:orphan") for r in reasons)


def test_v1_broken_tool_ref(read_fixture):
    reasons = v1_causal_graph(parse(read_fixture, "broken_tool_ref_session.jsonl"))
    assert any("broken_tool_ref" in r for r in reasons)


def test_v1_sidechain_linked(read_fixture):
    # the subagent sidechain has a resolvable parent -> no unlink reason
    reasons = v1_causal_graph(parse(read_fixture, "subagent_session.jsonl"))
    assert not any("sidechain_unlinked" in r for r in reasons)


def test_v2_block_integrity_clean(read_fixture):
    assert v2_block_integrity(parse(read_fixture, "complete_session.jsonl")) == []


def test_v5_secret_detection():
    findings = secrets_scan.scan_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    assert findings
    # value is never stored in the finding
    for f in findings:
        assert "AKIA" not in f.as_reason()


def test_v5_git_sha_whitelisted():
    # 40-char hex must not trip the scanner (known FP)
    assert secrets_scan.scan_text("commit 1234567890abcdef1234567890abcdef12345678") == []


def test_v6_schema_loads_and_is_draft2020():
    schema = load_schema()
    assert schema["title"] == "governance_trajectory/v2"


def test_v6_rejects_derived_values():
    # a record with a non-null derived field must fail schema (raw/derived lock)
    minimal = {
        "schema_version": "governance_trajectory/v2",
        "trajectory_id": "0" * 64,
        "provenance": {"raw_ref": {"uri": "u", "sha256": "a" * 64, "byte_len": 1, "record_count": 1},
                       "captured_at": "2026-08-06T00:00:00Z", "collector_version": "0.1.0",
                       "source": "claude-code",
                       "registry_ref": {"entry_sha256": "b" * 64, "prev_entry_sha256": None}},
        "environment": {"session_id": "s", "model": "m", "claude_code_version": "2.1.170",
                        "entrypoint": "cli", "cwd": "/x", "host": None,
                        "git": {"branch": "m", "head_sha": "a" * 40, "dirty": False}},
        "human_intent": {"prompts": []},
        "trajectory": {"nodes": [], "edges": [], "root_uuids": [], "leaf_uuid": None},
        "tool_events": [], "hook_events": [], "code_changes": None,
        "derived": {"scores": {"trajectory_score": 1.0}, "labels": None, "tier": None, "outcome": None},
        "integrity": {"normalized_sha256": "c" * 64, "status": "complete", "reasons": []},
    }
    reasons = v6_schema(minimal)
    assert any(r.startswith("V6:derived") for r in reasons)
