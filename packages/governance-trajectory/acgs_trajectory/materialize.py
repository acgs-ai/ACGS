"""Trajectory materialization (Phase 1, section 3).

raw JSONL  ->  governance_trajectory/v2 object.

No evaluation, labels, scoring, or ranking. ``derived.*`` is emitted null and
structurally locked by the schema. The normalized object references raw bytes
by pointer; it never copies authoritative content (ADR 0002 D6).
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .adapter import ParsedSession
from .canonical import canonical_bytes, sha256_hex
from .raw_store import RawRef

SCHEMA_VERSION = "governance_trajectory/v2"


def _git_env(parsed_env: dict[str, Any], repo_git: dict[str, Any] | None) -> dict[str, Any]:
    """Environment.git: branch from transcript, head_sha/dirty from repo join (D5)."""
    repo_git = repo_git or {}
    return {
        "branch": parsed_env.get("git_branch"),
        "head_sha": repo_git.get("head_sha"),
        "dirty": bool(repo_git.get("dirty")) if "dirty" in repo_git else None,
        "remote": repo_git.get("remote"),
    }


def materialize(
    parsed: ParsedSession,
    raw_ref: RawRef,
    *,
    captured_at: str,
    collector_version: str,
    repo_git: dict[str, Any] | None = None,
    registry_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a governance_trajectory/v2 dict (integrity filled in later by validators)."""
    env = parsed.environment
    session_id = env.get("session_id") or ""
    trajectory_id = sha256_hex(raw_ref.sha256 + session_id)

    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "trajectory_id": trajectory_id,
        "provenance": {
            "raw_ref": asdict(raw_ref),
            "captured_at": captured_at,
            "collector_version": collector_version,
            "source": "claude-code",
            "registry_ref": registry_ref
            or {"entry_sha256": "0" * 64, "prev_entry_sha256": None},
        },
        "environment": {
            "session_id": env.get("session_id"),
            "model": env.get("model"),
            "claude_code_version": env.get("claude_code_version"),
            "entrypoint": env.get("entrypoint"),
            "cwd": env.get("cwd"),
            "host": None,
            "git": _git_env(env, repo_git),
        },
        "human_intent": {"prompts": parsed.intents},
        "trajectory": {
            "nodes": [_node(n) for n in parsed.nodes],
            "edges": [asdict(e) for e in parsed.edges],
            "root_uuids": parsed.root_uuids,
            "leaf_uuid": parsed.leaf_uuid,
        },
        "tool_events": [_tool_event(t) for t in parsed.tool_events],
        "hook_events": [_hook_event(h) for h in parsed.hook_events],
        "code_changes": _code_changes(repo_git),
        "derived": {"scores": None, "labels": None, "tier": None, "outcome": None},
        "integrity": {
            # placeholder; validators finalize status + reasons, then we stamp the digest.
            "normalized_sha256": "0" * 64,
            "status": "incomplete",
            "reasons": [],
        },
    }
    return record


def stamp_normalized_digest(record: dict[str, Any]) -> dict[str, Any]:
    """Compute integrity.normalized_sha256 over the record with the digest field
    zeroed, so the hash is stable and self-excluding (deterministic, R6)."""
    clone = _deep_copy(record)
    clone["integrity"]["normalized_sha256"] = "0" * 64
    digest = sha256_hex(canonical_bytes(clone))
    record["integrity"]["normalized_sha256"] = digest
    return record


def _deep_copy(obj: Any) -> Any:
    import copy

    return copy.deepcopy(obj)


def _node(n) -> dict[str, Any]:
    d = asdict(n)
    # schema field names
    return {
        "uuid": d["uuid"],
        "parent_uuid": d["parent_uuid"],
        "seq": d["seq"],
        "type": d["type"],
        "role": d["role"],
        "is_sidechain": d["is_sidechain"],
        "content_kind": d["content_kind"],
        "raw_line": d["raw_line"],
        "block_index": d["block_index"],
        "digest": d["digest"],
        "ts": d["ts"],
    }


def _tool_event(t) -> dict[str, Any]:
    d = asdict(t)
    return {
        "use_uuid": d["use_uuid"],
        "tool_use_id": d["tool_use_id"],
        "name": d["name"],
        "caller": d["caller"],
        "input_ref": d["input_ref"],
        "result_ref": d["result_ref"],
        "is_error": d["is_error"],
        "ts_call": d["ts_call"],
        "ts_return": d["ts_return"],
        "subagent": d["subagent"],
    }


def _hook_event(h) -> dict[str, Any]:
    return asdict(h)


def _code_changes(repo_git: dict[str, Any] | None) -> dict[str, Any] | None:
    if not repo_git:
        return None
    diff_ref = None
    if repo_git.get("diff_sha256") and repo_git.get("diff_uri"):
        diff_ref = {"uri": repo_git["diff_uri"], "sha256": repo_git["diff_sha256"]}
    files = repo_git.get("files")
    if diff_ref is None and files is None:
        return None
    return {"diff_ref": diff_ref, "files": files}
