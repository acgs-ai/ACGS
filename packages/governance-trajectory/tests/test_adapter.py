from __future__ import annotations

import pytest

from acgs_trajectory.adapter import SourceAdapter, read_jsonl, version_supported
from acgs_trajectory.errors import ParseError


def parse(read_fixture, name):
    return SourceAdapter().parse(read_jsonl(read_fixture(name)))


def test_version_boundary():
    assert version_supported("2.1.170")
    assert not version_supported("9.9.9")
    assert not version_supported(None)


def test_read_jsonl_preserves_line_indices(read_fixture):
    recs = read_jsonl(read_fixture("complete_session.jsonl"))
    assert [r.line_no for r in recs] == list(range(len(recs)))
    # raw text preserved verbatim
    assert all(r.raw_text for r in recs)


def test_malformed_line_raises(read_fixture):
    with pytest.raises(ParseError) as ei:
        read_jsonl(read_fixture("malformed_session.jsonl"))
    assert ei.value.line_no == 1


def test_block_separation_thinking_text_tooluse(read_fixture):
    p = parse(read_fixture, "complete_session.jsonl")
    kinds = {(n.type, n.content_kind) for n in p.nodes}
    assert ("assistant", "thinking") in kinds
    assert ("assistant", "text") in kinds
    assert ("tool_use", "tool_use") in kinds
    assert ("tool_result", "tool_result") in kinds
    assert ("hook", None) in kinds
    assert ("attachment", None) in kinds


def test_tool_use_result_linkage(read_fixture):
    p = parse(read_fixture, "complete_session.jsonl")
    ev = [t for t in p.tool_events if t.tool_use_id == "toolu_A1"][0]
    assert ev.name == "Bash"
    assert ev.input_ref is not None and ev.result_ref is not None
    assert ev.is_error is False


def test_token_usage_extracted(read_fixture):
    p = parse(read_fixture, "complete_session.jsonl")
    assert p.usage.input_tokens > 0
    assert p.usage.output_tokens > 0


def test_hook_events_from_system_records(read_fixture):
    p = parse(read_fixture, "hook_prevented_session.jsonl")
    assert len(p.hook_events) == 1
    h = p.hook_events[0]
    assert h.prevented_continuation is True
    assert "blocked-op-escalation-guard" in h.hook_names
    assert h.tool_use_id == "toolu_BLK"


def test_subagent_relationship_and_edges(read_fixture):
    p = parse(read_fixture, "subagent_session.jsonl")
    # sidechain node present and its spawn edge attaches to the Task tool_use
    spawn = [e for e in p.edges if e.kind == "sidechain_spawn"]
    assert spawn and spawn[0].parent_uuid == "a1"
    # a subagent tool event is flagged
    assert any(t.subagent for t in p.tool_events)


def test_environment_and_leaf(read_fixture):
    p = parse(read_fixture, "complete_session.jsonl")
    assert p.environment["session_id"] == "sess-0001"
    assert p.environment["model"] == "claude-opus-4-8"
    assert p.environment["claude_code_version"] == "2.1.170"
    assert p.leaf_uuid == "a3"
    assert p.version_ok is True


def test_queue_operation_not_a_node_but_in_raw(read_fixture):
    recs = read_jsonl(read_fixture("complete_session.jsonl"))
    assert any(r.type == "queue-operation" for r in recs)
    p = SourceAdapter().parse(recs)
    assert all(n.type != "queue-operation" for n in p.nodes)
