"""Claude Code JSONL source adapter (Phase 1, section 1).

Reads a Claude Code session transcript and extracts the causal graph, tool
events, hook events, token usage and environment WITHOUT semantic
interpretation. The raw records are preserved verbatim; everything produced
here references them by line index (see ADR 0002 D6).

Verified against Claude Code version 2.1.170 (ADR 0002 D1-D5).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .canonical import sha256_hex
from .errors import ParseError

# ---- version-aware parsing boundary (ADR 0002 D5, risk R1) ------------------

# Version families whose block layout matches the D1-D5 findings. Unknown
# versions are NOT silently parsed as if identical — they are surfaced so the
# caller can quarantine (fail closed).
SUPPORTED_VERSION_PREFIXES: tuple[str, ...] = ("2.",)

# Raw record types we understand (ADR 0002 D1).
KNOWN_RECORD_TYPES = frozenset(
    {"user", "assistant", "system", "attachment", "queue-operation", "last-prompt"}
)
# Content block types we understand (D1/D3).
KNOWN_BLOCK_TYPES = frozenset({"text", "thinking", "tool_use", "tool_result", "image"})
# Record types that do not become trajectory nodes but stay in raw.
NON_NODE_TYPES = frozenset({"queue-operation", "last-prompt"})


def version_supported(version: object, prefixes: tuple[str, ...] = SUPPORTED_VERSION_PREFIXES) -> bool:
    # non-string / absent / empty / malformed version metadata -> unsupported (H3, fail closed)
    return isinstance(version, str) and any(version.startswith(p) for p in prefixes)


# ---- data structures --------------------------------------------------------


@dataclass(frozen=True)
class RawRecord:
    """One line of the source JSONL, preserved verbatim plus its line index."""

    line_no: int  # 0-based index into the raw archive
    obj: dict[str, Any]
    raw_text: str

    @property
    def type(self) -> str | None:
        return self.obj.get("type")

    @property
    def uuid(self) -> str | None:
        return self.obj.get("uuid")

    @property
    def parent_uuid(self) -> str | None:
        return self.obj.get("parentUuid")

    @property
    def is_sidechain(self) -> bool:
        return bool(self.obj.get("isSidechain"))

    @property
    def timestamp(self) -> str | None:
        return self.obj.get("timestamp")

    @property
    def message(self) -> dict[str, Any] | None:
        m = self.obj.get("message")
        return m if isinstance(m, dict) else None

    def blocks(self) -> list[Any]:
        m = self.message
        if not m:
            return []
        c = m.get("content")
        if isinstance(c, list):
            return c
        if isinstance(c, str):
            return [{"type": "text", "text": c}]
        return []


@dataclass
class Node:
    uuid: str | None
    parent_uuid: str | None
    seq: int
    type: str  # user | assistant | tool_use | tool_result | hook | attachment
    role: str | None
    is_sidechain: bool
    content_kind: str | None  # text | thinking | tool_use | tool_result | None
    raw_line: int
    block_index: int | None
    digest: str
    ts: str | None


@dataclass
class Edge:
    parent_uuid: str
    child_uuid: str
    kind: str  # reply | tool_call | tool_return | sidechain_spawn


@dataclass
class ToolEvent:
    use_uuid: str | None
    tool_use_id: str
    name: str
    caller: str | None
    input_ref: dict[str, Any] | None
    result_ref: dict[str, Any] | None
    is_error: bool | None
    ts_call: str | None
    ts_return: str | None
    subagent: bool


@dataclass
class HookEvent:
    uuid: str | None
    subtype: str | None
    hook_names: list[str]
    hook_errors: list[str]
    prevented_continuation: bool | None
    stop_reason: str | None
    tool_use_id: str | None
    ts: str | None


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0


@dataclass
class ParsedSession:
    records: list[RawRecord]
    nodes: list[Node]
    edges: list[Edge]
    tool_events: list[ToolEvent]
    hook_events: list[HookEvent]
    intents: list[dict[str, Any]]
    leaf_uuid: str | None
    root_uuids: list[str]
    environment: dict[str, Any]
    usage: Usage
    version: str | None
    version_ok: bool
    block_issues: list[str] = field(default_factory=list)
    unknown_types: list[str] = field(default_factory=list)


# ---- reader -----------------------------------------------------------------


def read_jsonl(text: str) -> list[RawRecord]:
    """Parse raw JSONL text into ordered RawRecords, preserving line indices.

    Blank lines are skipped but still consume a line index so ``raw_line`` maps
    back to the true source position. A malformed line raises ParseError.
    """
    records: list[RawRecord] = []
    for i, line in enumerate(text.splitlines()):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ParseError(i, f"invalid JSON: {exc.msg}") from exc
        if not isinstance(obj, dict):
            raise ParseError(i, "top-level JSON is not an object")
        records.append(RawRecord(line_no=i, obj=obj, raw_text=line))
    return records


# ---- adapter ----------------------------------------------------------------


def _block_digest(block: Any) -> str:
    return sha256_hex(json.dumps(block, sort_keys=True, ensure_ascii=False))


def _node_type_for(record_type: str, block_type: str | None) -> tuple[str, str | None]:
    """Map (raw record type, primary block type) to a normalized node type."""
    if record_type == "system":
        return "hook", None
    if record_type == "attachment":
        return "attachment", None
    if block_type == "tool_use":
        return "tool_use", "tool_use"
    if block_type == "tool_result":
        return "tool_result", "tool_result"
    if record_type == "assistant":
        return "assistant", (block_type or "text")
    # default: user
    return "user", (block_type or "text")


class SourceAdapter:
    """Version-aware, non-interpreting parser of Claude Code transcripts."""

    def __init__(self, supported_prefixes: tuple[str, ...] = SUPPORTED_VERSION_PREFIXES) -> None:
        self.supported_prefixes = supported_prefixes

    def parse(self, records: list[RawRecord]) -> ParsedSession:
        version = next((r.obj.get("version") for r in records if r.obj.get("version")), None)
        version_ok = version_supported(version, self.supported_prefixes)

        nodes: list[Node] = []
        edges: list[Edge] = []
        tool_events: list[ToolEvent] = []
        hook_events: list[HookEvent] = []
        intents: list[dict[str, Any]] = []
        unknown_types: list[str] = []
        block_issues: list[str] = []
        usage = Usage()

        # tool_use blocks by id -> (record, block) ; tool_result by tool_use_id
        pending_use: dict[str, tuple[RawRecord, dict[str, Any], int]] = {}
        results: dict[str, tuple[RawRecord, dict[str, Any], int]] = {}

        seq = 0
        for rec in records:
            rtype = rec.type
            if rtype and rtype not in KNOWN_RECORD_TYPES:
                unknown_types.append(rtype)
            if rtype in NON_NODE_TYPES or rtype not in KNOWN_RECORD_TYPES:
                # last-prompt still contributes the leaf pointer; handled below.
                continue

            blocks = rec.blocks()
            # token usage (assistant only, D5)
            if rtype == "assistant" and rec.message:
                u = rec.message.get("usage") or {}
                usage.input_tokens += int(u.get("input_tokens") or 0)
                usage.output_tokens += int(u.get("output_tokens") or 0)
                usage.cache_read_input_tokens += int(u.get("cache_read_input_tokens") or 0)
                usage.cache_creation_input_tokens += int(u.get("cache_creation_input_tokens") or 0)

            # hook events (system records, D4)
            if rtype == "system":
                hook_events.append(
                    HookEvent(
                        uuid=rec.uuid,
                        subtype=rec.obj.get("subtype"),
                        hook_names=_hook_names(rec.obj),
                        hook_errors=list(rec.obj.get("hookErrors") or []),
                        prevented_continuation=rec.obj.get("preventedContinuation"),
                        stop_reason=rec.obj.get("stopReason"),
                        tool_use_id=rec.obj.get("toolUseID"),
                        ts=rec.timestamp,
                    )
                )

            role = rec.message.get("role") if rec.message else None
            primary_block = blocks[0] if blocks else None
            primary_type = primary_block.get("type") if isinstance(primary_block, dict) else None

            # validate + collect tool events across ALL blocks (D3)
            for bi, block in enumerate(blocks):
                if not isinstance(block, dict):
                    block_issues.append(f"line {rec.line_no}: non-object block")
                    continue
                btype = block.get("type")
                if btype and btype not in KNOWN_BLOCK_TYPES:
                    block_issues.append(f"line {rec.line_no}: unknown block type {btype!r}")
                if btype == "tool_use":
                    tid = block.get("id")
                    if not tid or not block.get("name") or "input" not in block:
                        block_issues.append(f"line {rec.line_no}: malformed tool_use block")
                    if tid:
                        pending_use[tid] = (rec, block, bi)
                elif btype == "tool_result":
                    ref = block.get("tool_use_id")
                    if not ref:
                        block_issues.append(f"line {rec.line_no}: tool_result missing tool_use_id")
                    else:
                        results[ref] = (rec, block, bi)

            # node (one per record; D2 keeps uuid unique)
            node_type, content_kind = _node_type_for(rtype, primary_type)
            nodes.append(
                Node(
                    uuid=rec.uuid,
                    parent_uuid=rec.parent_uuid,
                    seq=seq,
                    type=node_type,
                    role=role,
                    is_sidechain=rec.is_sidechain,
                    content_kind=content_kind,
                    raw_line=rec.line_no,
                    block_index=0 if blocks else None,
                    digest=_block_digest(primary_block) if primary_block is not None else sha256_hex(rec.raw_text),
                    ts=rec.timestamp,
                )
            )
            seq += 1

            # human intent = root-ish user text prompts
            if rtype == "user" and primary_type == "text" and not rec.is_sidechain:
                text = primary_block.get("text", "") if isinstance(primary_block, dict) else ""
                intents.append({"uuid": rec.uuid, "ts": rec.timestamp, "text": text})

        # join tool events (D3)
        for tid, (rec, block, bi) in pending_use.items():
            res = results.get(tid)
            res_rec, res_block, res_bi = res if res else (None, None, None)
            tool_events.append(
                ToolEvent(
                    use_uuid=rec.uuid,
                    tool_use_id=tid,
                    name=block.get("name", ""),
                    caller=block.get("caller"),
                    input_ref={"raw_line": rec.line_no, "block_index": bi, "digest": _block_digest(block)},
                    result_ref=(
                        {"raw_line": res_rec.line_no, "block_index": res_bi, "digest": _block_digest(res_block)}
                        if res
                        else None
                    ),
                    is_error=(bool(res_block.get("is_error")) if res else None),
                    ts_call=rec.timestamp,
                    ts_return=(res_rec.timestamp if res else None),
                    subagent=_is_subagent(rec.is_sidechain, block.get("caller")),
                )
            )
        # tool_results referencing an unknown use id -> broken tool reference (V1)
        for tid, (rec, block, bi) in results.items():
            if tid not in pending_use:
                tool_events.append(
                    ToolEvent(
                        use_uuid=None,
                        tool_use_id=tid,
                        name="",
                        caller=None,
                        input_ref=None,
                        result_ref={"raw_line": rec.line_no, "block_index": bi, "digest": _block_digest(block)},
                        is_error=bool(block.get("is_error")),
                        ts_call=None,
                        ts_return=rec.timestamp,
                        subagent=bool(rec.is_sidechain),
                    )
                )

        # edges + roots
        known_uuids = {n.uuid for n in nodes if n.uuid}
        node_by_uuid = {n.uuid: n for n in nodes if n.uuid}
        root_uuids: list[str] = []
        tool_result_uuids = {r.uuid for r in records if _has_block_type(r, "tool_result")}
        tool_use_uuids = {r.uuid for r in records if _has_block_type(r, "tool_use")}
        for n in nodes:
            if not n.parent_uuid:
                if n.uuid:
                    root_uuids.append(n.uuid)
                continue
            edges.append(Edge(parent_uuid=n.parent_uuid, child_uuid=n.uuid or "", kind=_edge_kind(n, node_by_uuid, tool_use_uuids, tool_result_uuids)))

        leaf_uuid = _leaf_uuid(records)

        environment = _environment(records, version)

        return ParsedSession(
            records=records,
            nodes=nodes,
            edges=edges,
            tool_events=tool_events,
            hook_events=hook_events,
            intents=intents,
            leaf_uuid=leaf_uuid,
            root_uuids=root_uuids,
            environment=environment,
            usage=usage,
            version=version,
            version_ok=version_ok,
            block_issues=block_issues,
            unknown_types=sorted(set(unknown_types)),
        )


def _is_subagent(is_sidechain: bool, caller: Any) -> bool:
    """Subagent origin. ``caller`` is a structured object in real transcripts
    (e.g. {"type": "direct"} for main-loop calls, ADR 0002 D3). We do not
    interpret it beyond distinguishing direct/main from anything else."""
    if is_sidechain:
        return True
    if isinstance(caller, dict):
        return caller.get("type") not in (None, "direct")
    if isinstance(caller, str):
        return caller not in ("", "main", "direct")
    return False


def _hook_names(obj: dict[str, Any]) -> list[str]:
    infos = obj.get("hookInfos")
    names: list[str] = []
    if isinstance(infos, list):
        for h in infos:
            if isinstance(h, dict):
                names.append(str(h.get("name") or h.get("hookName") or h.get("type") or "hook"))
            else:
                names.append(str(h))
    return names


def _has_block_type(rec: RawRecord, btype: str) -> bool:
    return any(isinstance(b, dict) and b.get("type") == btype for b in rec.blocks())


def _edge_kind(node: Node, node_by_uuid: dict[str, Node], tool_use_uuids: set, tool_result_uuids: set) -> str:
    parent = node_by_uuid.get(node.parent_uuid or "")
    if node.is_sidechain and (parent is None or not parent.is_sidechain):
        return "sidechain_spawn"
    if node.type == "tool_result" or node.uuid in tool_result_uuids:
        return "tool_return"
    if node.type == "tool_use" or node.uuid in tool_use_uuids:
        return "tool_call"
    return "reply"


def _leaf_uuid(records: list[RawRecord]) -> str | None:
    for rec in records:
        if rec.type == "last-prompt":
            return rec.obj.get("leafUuid")
    # fallback: last node-bearing record's uuid
    for rec in reversed(records):
        if rec.uuid and rec.type in KNOWN_RECORD_TYPES - NON_NODE_TYPES:
            return rec.uuid
    return None


def _environment(records: list[RawRecord], version: str | None) -> dict[str, Any]:
    def first(key: str) -> Any:
        return next((r.obj.get(key) for r in records if r.obj.get(key) is not None), None)

    model = next(
        (r.message.get("model") for r in records if r.message and r.message.get("model")),
        None,
    )
    return {
        "session_id": first("sessionId"),
        "model": model,
        "claude_code_version": version,
        "entrypoint": first("entrypoint"),
        "cwd": first("cwd"),
        "git_branch": first("gitBranch"),
    }


def session_ids(records: list[RawRecord]) -> set[str]:
    return {r.obj.get("sessionId") for r in records if r.obj.get("sessionId")}
