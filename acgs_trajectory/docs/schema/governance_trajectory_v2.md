# Specification — `governance_trajectory/v2`

- **Status:** Phase 1 design, awaiting approval
- **Companion contract:** `governance_trajectory_v2.schema.json` (machine-checkable, authoritative)
- **Design basis:** ADR 0001 (scope), ADR 0002 (verified source-format facts D1–D7)

This document specifies the record produced by Phase 1 ingestion. It is a **contract**, not an
implementation. The JSON Schema file is the enforceable form; this prose explains intent and the
fail-closed rules the schema alone cannot express.

## 1. Design invariants

1. **Raw is authoritative.** Normalized/derived data references raw by `{raw_line, block_index}` +
   `digest`; it never becomes the source of truth (D6).
2. **Derived is separated and rebuildable.** Everything under `derived` can be deleted and
   recomputed from `raw` + schema. Deleting `raw` is the only irreversible act.
3. **Fail closed.** Any missing required evidence sets `integrity.status` to `incomplete` or
   `quarantined` and caps the (Phase-2) tier at C. Absence never upgrades.
4. **Evidence, not judgment, in v2.** `derived.*` is present but `null` in Phase 1. No scores, no
   labels, no outcome. Those are Phase 2/3 and must remain structurally separated.

## 2. Top-level structure

```
governance_trajectory/v2
├── schema_version         "governance_trajectory/v2"     (const)
├── trajectory_id          derived id = sha256(raw_sha256 + session_id)
├── provenance             immutable-source reference + registry linkage
├── environment            session identity + git state (D5)
├── human_intent           root user request(s)
├── trajectory             normalized causal DAG: nodes[] + edges[]
├── tool_events[]          tool_use ↔ tool_result joins (D3)
├── hook_events[]          governance/policy enforcement evidence (D4)
├── code_changes           git diff join (nullable in P1 if repo state absent)
├── derived                scores/labels/tier/outcome — ALL null in P1 (separated)
└── integrity              status + normalized digest + fail-closed reasons
```

### 2.1 `provenance`
- `raw_ref`: `{uri, sha256, byte_len, record_count}` — the immutable archive object.
- `captured_at`, `collector_version`, `source` (`"claude-code"`).
- `registry_ref`: `{entry_sha256, prev_entry_sha256}` — position in the hash-chained manifest
  (§ Storage). This is what makes silent modification detectable.

### 2.2 `environment` (D5)
Required: `session_id`, `model`, `claude_code_version`, `entrypoint`, `cwd`,
`git: { branch, head_sha, dirty }`. Optional: `git.remote`, `host`.
Missing any *required* field → `integrity.status = incomplete`.

### 2.3 `human_intent`
`prompts[]` = `{uuid, ts, text}` for each root `user` text request (the causal roots).

### 2.4 `trajectory` — normalized causal DAG (D2)
- `nodes[]`, each: `{uuid, parent_uuid, seq, type, role, is_sidechain, content_kind,
  raw_line, block_index, digest, ts}`.
  - `type` ∈ `user | assistant | tool_use | tool_result | hook | attachment`.
  - `content_kind` ∈ `text | thinking | tool_use | tool_result | null`.
  - `raw_line`/`block_index`/`digest` = pointer to authoritative raw bytes (D6). No content copy.
- `edges[]`: `{parent_uuid, child_uuid, kind}`, `kind` ∈
  `reply | tool_call | tool_return | sidechain_spawn`.
- `root_uuids[]`, `leaf_uuid` (from `last-prompt.leafUuid`, D1).

### 2.5 `tool_events[]` (D3)
`{use_uuid, tool_use_id, name, caller, input_ref, result_ref, is_error, ts_call, ts_return, subagent}`.
- `input_ref`/`result_ref` are `{raw_line, block_index, digest}` pointers, not inlined payloads.
- `is_error` preserved verbatim (evaluator input; never normalized away).
- A row with `result_ref = null` = dangling call (V2 flags it).

### 2.6 `hook_events[]` (D4 — governance evidence)
`{uuid, subtype, hook_names[], hook_errors[], prevented_continuation, stop_reason, tool_use_id, ts}`.
Preserved from `system` records. Raw evidence of policy enforcement; never a derived label.

### 2.7 `code_changes`
`{ diff_ref: {uri, sha256} | null, files: [{path, change_kind, adds, dels}] | null }`.
Joined from repo git state at capture (D5). Null-allowed in P1; null caps tier at B (Phase 3).

### 2.8 `derived` (separated, all null in P1)
`{ scores: null, labels: null, tier: null, outcome: null }`. Present for schema stability;
populating any of these is out of Phase 1 scope by explicit exclusion.

### 2.9 `integrity`
`{ normalized_sha256, status, reasons[] }`, `status` ∈ `complete | incomplete | quarantined`.
`reasons[]` enumerates every fail-closed trigger (missing field, dangling call, secret hit, unknown
type). Empty reasons ⇔ `complete`.

## 3. Fail-closed status resolution (deterministic)

```
if secret_detected(raw|diff):                      status = quarantined
elif unknown_record_type or version_unsupported:   status = quarantined
elif any required env field missing
     or orphan_nodes > 0
     or ordering_violation
     or hash_mismatch:                             status = incomplete
else:                                              status = complete
```
`quarantined` ⇒ not written to the shared raw archive (restricted store only).
`incomplete` ⇒ archived, but Phase-2 tier ceiling = C.
Only `complete` records are eligible for higher tiers later.

## 4. Explicitly NOT in this schema version

No evaluator scores, governance labels, tier assignment, outcome grounding, annotation, packaging,
or benchmark fields carry values. Their *slots* exist (`derived`) and stay `null`. This preserves
raw/derived separation and lets Phase 2 extend without a schema break.
