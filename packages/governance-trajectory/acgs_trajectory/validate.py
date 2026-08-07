"""Deterministic validation gates V1-V6 (Phase 1, section 4).

Every check is a pure function of its inputs (no LLM, no network) and returns a
list of failure reason strings. Empty list == pass. All failures are fail-closed:
they degrade ``integrity.status``; they never grant ``complete`` by absence.

V1 causal graph integrity   parentUuid resolution, sidechain linkage, tool linkage
V2 block integrity          valid block types, valid references
V3 provenance completeness  session identity, source digest, environment metadata
V4 tamper detection         raw digest mismatch fails
V5 secret boundary          detect + quarantine (never redacts authoritative raw)
V6 schema validation        governance_trajectory/v2 compliance
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

from .adapter import ParsedSession, session_ids
from .canonical import sha256_hex

REQUIRED_ENV_FIELDS = ("session_id", "model", "claude_code_version", "entrypoint", "cwd")


# ---- V1: causal graph integrity --------------------------------------------


def v1_causal_graph(parsed: ParsedSession) -> list[str]:
    reasons: list[str] = []
    known = {n.uuid for n in parsed.nodes if n.uuid}

    # parentUuid resolution (roots may have no parent)
    for n in parsed.nodes:
        if n.parent_uuid and n.parent_uuid not in known:
            reasons.append(f"V1:orphan:{n.uuid}->{n.parent_uuid}")

    # sidechain linkage: a sidechain node must have a resolvable parent
    for n in parsed.nodes:
        if n.is_sidechain and (n.parent_uuid is None or n.parent_uuid not in known):
            reasons.append(f"V1:sidechain_unlinked:{n.uuid}")

    # tool_use / tool_result linkage: every result must reference a real use
    for t in parsed.tool_events:
        if t.result_ref is not None and t.use_uuid is None:
            reasons.append(f"V1:broken_tool_ref:{t.tool_use_id}")

    # ordering: a tool_result must not precede its tool_use in the raw stream (H2)
    for t in parsed.tool_events:
        if t.input_ref is not None and t.result_ref is not None:
            if t.result_ref["raw_line"] < t.input_ref["raw_line"]:
                reasons.append(f"V1:tool_result_before_use:{t.tool_use_id}")

    # cycle detection over parentUuid links (H2 adversarial)
    parent = {n.uuid: n.parent_uuid for n in parsed.nodes if n.uuid}
    if _has_any_cycle(parent):
        reasons.append("V1:cycle")

    return reasons


def _has_any_cycle(parent: dict[str, str | None]) -> bool:
    """True if following parent pointers revisits a node. O(V): each node has at
    most one parent (functional graph), so a chain-walk with color marking visits
    every node once (GRAY = on current chain, BLACK = finished-acyclic)."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {n: WHITE for n in parent}
    for root in parent:
        if color[root] != WHITE:
            continue
        chain: list[str] = []
        node: str | None = root
        while node in parent and color.get(node) == WHITE:
            color[node] = GRAY
            chain.append(node)
            node = parent[node]
        cyclic = node in parent and color.get(node) == GRAY
        for n in chain:
            color[n] = BLACK
        if cyclic:
            return True
    return False


# ---- V2: block integrity ----------------------------------------------------


def v2_block_integrity(parsed: ParsedSession) -> list[str]:
    reasons: list[str] = []
    # unknown block types / malformed references were collected during parse
    for issue in parsed.block_issues:
        reasons.append(f"V2:{issue}")
    # confirm every tool node maps to a tool_event with a valid reference
    for t in parsed.tool_events:
        if t.input_ref is None and t.result_ref is None:
            reasons.append(f"V2:tool_event_no_ref:{t.tool_use_id}")
    return reasons


# ---- V3: provenance completeness -------------------------------------------


def v3_provenance(record: dict[str, Any], parsed: ParsedSession) -> list[str]:
    reasons: list[str] = []

    # single session identity
    sids = session_ids(parsed.records)
    if len(sids) == 0:
        reasons.append("V3:missing_session_id")
    elif len(sids) > 1:
        reasons.append(f"V3:multiple_session_ids:{len(sids)}")

    # source digest present + well-formed
    raw_ref = record.get("provenance", {}).get("raw_ref", {})
    if not _is_sha256(raw_ref.get("sha256")):
        reasons.append("V3:missing_source_digest")

    # environment metadata
    env = record.get("environment", {})
    for f in REQUIRED_ENV_FIELDS:
        if not env.get(f):
            reasons.append(f"V3:missing_env:{f}")
    if env.get("git", {}).get("head_sha") in (None, ""):
        # git head is required for a complete record but joined externally;
        # its absence caps the tier at C later — still a fail-closed reason.
        reasons.append("V3:missing_git_head_sha")

    return reasons


# ---- V4: tamper detection ---------------------------------------------------


def v4_tamper(record: dict[str, Any], raw_bytes: bytes) -> list[str]:
    claimed = record.get("provenance", {}).get("raw_ref", {}).get("sha256")
    actual = sha256_hex(raw_bytes)
    if claimed != actual:
        return [f"V4:raw_digest_mismatch"]
    return []


# ---- V5: secret boundary (detection performed at ingestion edge) -----------


def v5_secret(findings: list[Any]) -> list[str]:
    return [f.as_reason() if hasattr(f, "as_reason") else f"V5:{f}" for f in findings]


# ---- V6: schema validation --------------------------------------------------


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    text = resources.files("acgs_trajectory.schemas").joinpath(
        "governance_trajectory_v2.schema.json"
    ).read_text(encoding="utf-8")
    return json.loads(text)


def v6_schema(record: dict[str, Any]) -> list[str]:
    from jsonschema import Draft202012Validator

    validator = Draft202012Validator(load_schema())
    reasons: list[str] = []
    for err in sorted(validator.iter_errors(record), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in err.path) or "<root>"
        reasons.append(f"V6:{loc}:{err.message}")
    return reasons


def _is_sha256(v: Any) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)
