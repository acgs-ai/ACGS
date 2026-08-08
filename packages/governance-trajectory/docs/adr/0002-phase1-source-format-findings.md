# ADR 0002 — Phase 1 Source-Format Findings & Design Decisions

- **Status:** Proposed (Phase 1 design, awaiting approval)
- **Date:** 2026-08-06
- **Supersedes:** nothing; extends ADR 0001 §3 with verified detail
- **Basis:** direct inspection of a live Claude Code session JSONL (block-level)

This ADR records the *load-bearing format facts* that the `governance_trajectory/v2` schema
depends on. If any fact here is wrong, the schema is wrong — so each is stated as verified-observed,
not assumed.

## D1 — Record types and their governance role

| Raw `type` | Carries | Maps to v2 as |
|---|---|---|
| `user` | `message.content` = `text` blocks (human intent) **or** `tool_result` blocks | intent node / tool_result node |
| `assistant` | `message.content` = one of `text` \| `thinking` \| `tool_use` (blocks split per kind, one kind per record) | reasoning / action node |
| `system` | hook execution: `subtype, hookInfos, hookErrors, hookAdditionalContext, preventedContinuation, stopReason, toolUseID` | **hook_event** (governance evidence — see D4) |
| `attachment` | `attachment` payload (injected context/files) | attachment node |
| `queue-operation` | ephemeral queue bookkeeping | dropped from trajectory, retained in raw |
| `last-prompt` | `lastPrompt`, `leafUuid` = active DAG leaf | trajectory `leaf_uuid` pointer |

## D2 — Causal DAG reconstruction

- Every node has `uuid`; children reference `parentUuid`. This is a tree/DAG, **not** a flat list.
- `isSidechain: true` marks subagent branches. Subagent trajectories are **nested**, not inlined.
- `tool_use` blocks carry `caller` — distinguishes main-loop vs subagent-issued calls.
- **Decision:** normalize into `{nodes[], edges[]}` where `edges` = parent→child with a `kind`
  (`reply` | `tool_call` | `tool_return` | `sidechain_spawn`). Sidechain roots attach to the
  spawning `tool_use`, never orphaned to the session root.

## D3 — Tool call ↔ result linkage

- `tool_use` block: `{type, id, name, input, caller}`. **`caller` is a structured object**, not a
  string — observed value `{"type": "direct"}` for main-loop calls (verified on v2.1.170). Preserved
  verbatim; `subagent` is derived from `caller.type != "direct"` OR `isSidechain` (no interpretation
  beyond direct-vs-not). Schema therefore accepts `caller` as object|string|null.
- `tool_result` block: `{type, tool_use_id, content, is_error}`.
- **Decision:** `tool_events[]` join `tool_use.id == tool_result.tool_use_id`. `is_error` is
  preserved verbatim — it is primary evidence for the evaluator later (do not normalize it away).
- A `tool_use` with no matching `tool_result` = **dangling call** → ordering check flags it (V2).

## D4 — Hook/`system` records are first-class governance evidence

The `system` records capture when policy hooks fired (scope-gate, blocked-op, secret guard, etc.),
including `hookErrors`, `preventedContinuation`, and `stopReason`. This is **direct, in-stream,
fail-closed enforcement evidence** — exactly the ACGS signal we are trying to capture.

- **Decision:** `hook_events[]` is a top-level v2 array, preserved from `system` records, keyed by
  `toolUseID` so a blocked/allowed decision links to the tool call it governed. It is raw evidence,
  never a derived label.

## D5 — Environment provenance fields exist per-record

Every substantive record carries `sessionId, cwd, gitBranch, version` (Claude Code version),
`entrypoint`, `timestamp`. Assistant records carry `model` (`claude-opus-4-8` observed) and full
`usage` token accounting.

- **Decision:** environment is asserted **consistent across the session**; the normalizer verifies
  all records agree on `sessionId`/`version` and flags divergence (a session file mixing sessionIds
  is quarantined). `git.head_sha` and working-tree `diff` are **joined from the repo at capture
  time** — they are *not* in the JSONL and are the one external dependency of capture.

## D6 — Raw is authoritative; normalized references it, never copies it

- **Decision:** normalized nodes store a **pointer** `{raw_line, block_index}` + a content
  `digest`, not a copy of the content. The immutable raw archive holds the bytes. Replay reads raw.
  This gives a single source of truth and makes the raw/derived separation structural, not a
  convention.

## D7 — Content that may contain secrets

Tool inputs/outputs and diffs may contain `.env` content, tokens, keys.

- **Decision:** secret scanning runs at the **ingestion edge, before** anything is written to the
  shared raw archive. A hit quarantines the record (retained in a restricted quarantine store,
  flagged, incident-logged) and blocks promotion. Detection-before-archive is a hard boundary.
