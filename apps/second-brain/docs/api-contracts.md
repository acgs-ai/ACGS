# API and trust contracts

The implemented base path is `/api/v1`. IDs are opaque UUIDs and timestamps are
UTC ISO 8601. The FastAPI routes and Pydantic contracts are authoritative; this
document explains the stable trust and provenance behavior around them.

## Authentication, sessions, authorization, and CSRF

- `dev/test`: a deterministic identity provider is permitted only when explicitly
  enabled and the service listens on loopback. It refuses non-loopback binds.
- `production`: startup refuses to run without a configured trusted identity
  verifier. There is no client-trusted principal-header mode.
- A successful verifier creates an opaque `Secure`, `HttpOnly`, `SameSite=Lax`
  session cookie. Session identifiers rotate on authentication and privilege
  changes and have absolute and idle expiry.
- State-changing methods require a same-origin `Origin`/`Host` check and a CSRF
  token bound to the session. `GET`/`HEAD` remain side-effect free.
- In trusted-proxy mode, owner and active workspace come only from the verified
  server-side session. Browser-supplied principal headers and identity body
  fields are rejected. Development headers are a separate loopback-only mode.
- Every database transaction runs `SET LOCAL app.owner_id = ...` and
  `SET LOCAL app.workspace_id = ...` before scoped SQL. Missing settings,
  membership failure, verifier failure, or transaction reuse fails closed.
- Required negative tests cover spoofed headers, tampered/expired cookies,
  missing/mismatched CSRF, workspace switching without membership, dev identity
  on non-loopback, and production startup without a verifier.

Authorization responses are `401` for absent/invalid identity and `403` for an
authenticated principal lacking workspace membership. Resource lookups may use
a scope-preserving `404` so they do not disclose whether an inaccessible object
exists.

## Runtime and bootstrap configuration boundary

`.env` is the API runtime input and contains the restricted `second_brain_app`
database URL plus implemented API settings only. The worker intentionally does
not load that file; separately permissioned `SECOND_BRAIN_WORKER_*` settings
provide its content and dispatcher URLs, storage, limits, and embedding profile.
Database-owner passwords, application-role bootstrap passwords, and Compose
port overrides are interpolation inputs used before the service starts. Local
inline defaults may be overridden through an untracked `.env.compose.local`
supplied explicitly to Compose; that file must never be sourced, exported, or
loaded by the API or worker. The local boundary check must prove the path is
Git-ignored before other product-surface checks execute.

## Common types and failure behavior

Safe errors are:

```text
ErrorResponse {
  code: string,
  title: string,
  detail: string,
  retryable: boolean,
  trace_id: string,
  field_errors?: [{field: string, code: string}]
}
```

Raw source content, provider secrets, parser tracebacks, internal paths, and
cross-scope identifiers are excluded. Mutation endpoints accept an
`Idempotency-Key` header. Reuse with the same request fingerprint returns the
original response; reuse with different input returns `409 idempotency_conflict`.

## Sources and jobs

- `POST /captures/text` — `{title, content, source_type: note|markdown, project_id?, tag_ids?, idempotency_key?}`.
- `POST /captures/upload` — multipart `{file, title, project_id?, tag_ids?, idempotency_key?}`.
- `POST /captures/url` — `{url, title, project_id?, tag_ids?, idempotency_key?}`.
- `GET /sources` — processing-state/project/tag/type/date/query filters and limit.
- `GET /sources/{source_id}` — metadata, versions, chunks, and job history.
- `GET /sources/{source_id}/content` — current extracted text.
- `GET /sources/{source_id}/context/{chunk_id}` — exact chunk plus bounded context.
- `POST /sources/{source_id}/purge`; `GET /purges/{operation_id}`.
- `GET /jobs/{job_id}`.

```text
SourceRecord {
  source_id, workspace_id, owner_id: UUID,
  source_type: note|markdown|txt|pdf|docx|url,
  display_title: string,
  original_uri?: string,
  uploaded_object_ref?: string,
  ingested_at: datetime,
  original_content_sha256?: hex64,
  normalized_dedup_sha256: hex64,
  mime_type: string,
  parser_name: string,
  parser_version: string,
  processing_state: queued|processing|ready|failed|purge_pending,
  processing_error?: SafeProcessingError,
  project_id?: UUID,
  tag_ids: UUID[]
}

SourceVersion {
  source_version_id, source_id: UUID,
  version_number: integer,
  content_sha256: hex64,
  parser_name, parser_version, chunker_name, chunker_version: string,
  created_at: datetime
}

IngestionJob {
  job_id, source_id, source_version_id: UUID,
  state: queued|processing|ready|failed|retrying|dead,
  attempts: integer,
  error_code?: string,
  error_message?: string
}
```

For notes and uploads, `original_content_sha256` hashes the exact accepted bytes
and `normalized_dedup_sha256` hashes the documented normalized content. For URL
capture, the initial source row may have no byte hash or object reference;
`normalized_dedup_sha256` instead hashes the normalized URI for scoped capture
idempotency. After processing, the exact fetched-byte hash and object key are
authoritative on the append-only source version and URL-fetch provenance,
together with final URI, redirects, and peer binding. A normalized URI hash is
never presented as a fetched-content hash. A duplicate in the same
owner/workspace returns the existing lineage and `duplicate: true`.

## Search

`GET /search?q&project_id&tag_id&source_type&date_from&date_to&limit`
uses limit `1..50`. A successful response always uses this envelope, including
when no passages match:

```text
SearchResponse {
  results: SearchResult[],
  semantic_status: available|unavailable
}
```

`semantic_status=available` means semantic retrieval completed, even when it
returned no candidates. `semantic_status=unavailable` means the semantic channel
failed while PostgreSQL lexical retrieval remained available; lexical results
may therefore still be present. The status appears only on the response envelope,
never on individual results. A whitespace-only query is rejected with the normal
structured `422 validation_error` response.

Each `SearchResult` contains stable source/chunk IDs, title, excerpt,
`{page?,section?,paragraph?,char_start,char_end}`, lexical rank/score?, semantic
rank/score?, fused rank/score, project/tags, source date, and parser/chunker
versions. Candidate pools are 50+50; RRF uses `k=60` and stable chunk-ID
tie-breaking.

## Ask

`POST /answers` accepts `{query, conversation_id?, filters?, retrieval_config?, idempotency_key?}`
and persists retrieval before generation. The response is:

```text
AnswerRecord {
  answer_id, retrieval_run_id, conversation_id?: UUID,
  query: string,
  status: grounded|insufficient_evidence|validation_failed|provider_unavailable,
  sufficiency: {sufficient: boolean, reason_code: string},
  evidence_supported_statements: [{
    statement_id: UUID,
    text: string,
    citations: [{citation_id, chunk_id, source_id, char_start, char_end}]
  }],
  system_commentary?: string,
  extractive_fallback?: [{text, citation}],
  retrieval_config: {lexical_k, semantic_k, rrf_k, evidence_chunk_limit, evidence_char_limit},
  retrieved_results: [{source_id, chunk_id, lexical_rank?, semantic_rank?, fused_rank}],
  model_provider, model_identifier, prompt_template_version: string,
  semantic_status: available|unavailable,
  provider_status: available|unavailable|not_called,
  created_at: datetime
}
```

Every evidence-supported statement requires a non-empty independently validated
citation set. System commentary is stored separately and cannot present source
facts. `insufficient_evidence` contains no unsupported statements.
Every grounded or fallback citation must match a persisted retrieval result on
owner, workspace, `source_id`, and `chunk_id`, and that source/chunk pair must
remain accessible in the current scoped transaction. An inaccessible source or
any scope/source/chunk mismatch produces `validation_failed` and suppresses all
generated statements. Only a bounded extractive fallback whose passages each
carry independently revalidated citations could be added without weakening the
contract. v0.1 returns no extractive fallback; the failure is explicit.

Evidence adequacy is evaluated before generation. Any selected lexical result
is adequate for this gate. Semantic-only selected evidence requires at least
one finite semantic score at or above the configured
`SECOND_BRAIN_ANSWER_MIN_SIMILARITY`, and the API configuration must exactly
match the append-only embedding profile's provider, model, dimensions, profile
version, and threshold. An unset threshold, below-threshold score, or profile
drift returns `insufficient_evidence` with `provider_status=not_called`.
Embedding outages preserve lexical retrieval. A generation transport outage
returns `provider_unavailable`; it does not become an ungrounded answer.

## Memory

- `GET /memory-proposals`
- `POST /memory-proposals/{id}/approve`
- `POST /memory-proposals/{id}/reject`
- `POST /memory-proposals/{id}/edit-and-approve`
- `GET /memories`
- `POST /memories/{id}/revise|supersede|archive|purge`

```text
MemoryProposal {
  proposal_id, workspace_id, owner_id: UUID,
  normalized_statement: string,
  category: preference|commitment|project_fact|person_fact|reference|other,
  source_chunk_ids: UUID[],
  confidence: number[0,1],
  evidence_quality: low|medium|high,
  status: proposed|approved|rejected,
  proposed_at: datetime,
  decided_at?: datetime
}

ApprovedMemory {
  memory_id, proposal_id, current_revision_id, workspace_id, owner_id: UUID,
  status: active|superseded|archived|purge_pending|purged,
  approved_at: datetime,
  supersedes_memory_id?: UUID,
  superseded_by_memory_id?: UUID
}

MemoryRevision {
  revision_id, memory_id: UUID,
  revision_number: integer,
  normalized_statement: string,
  category: MemoryCategory,
  source_chunk_ids: UUID[],
  confidence: number[0,1],
  evidence_quality: low|medium|high,
  created_at: datetime,
  created_by: UUID
}
```

Generation cannot invoke an approval transition. Revision numbers are monotonic
and previous revisions remain readable until an authorized purge.

## Organization, Today, and status

Required application routes are `/inbox`, `/library`,
`/library/:sourceId`, `/search`, `/ask`, `/memories`, `/memories/review`,
`/today`, and `/settings`.

`GET /today` returns these deterministic sections:

1. `recent_captures`: five sources by `ingested_at DESC, source_id ASC`.
2. `failed_jobs`: five unresolved failures by `finished_at DESC, job_id ASC`.
3. `recent_approved_memories`: five by `approved_at DESC, memory_id ASC`.
4. `active_project_sources`: at most five ready sources, one newest source per
   active project, ordered `project.updated_at DESC, source.ingested_at DESC,
   source_id ASC`.
5. `resurfacing`: three active approved memories not resurfaced in seven days,
   ordered by SHA-256 of `owner_id|workspace_id|UTC-date|memory_id`, then
   `memory_id ASC`.

Sections are not backfilled with model output. Their empty states are respectively
`No recent captures`, `No failed processing jobs`, `No approved memories yet`,
`No active-project sources`, and `Nothing scheduled to resurface today`.

Provider status exposes no secrets. The future ACGS port may add a veto but never
establishes identity, ownership, citation validity, or approval.

## Future local ACGS policy-decision interface

The product defines a local port but no v0.1 decision engine or remote
governance dependency:

```text
interface PolicyDecisionPort {
  evaluate(context: PolicyContext) -> PolicyResult
}

PolicyContext {
  request_id: UUID,
  action: capture_source|generate_answer|approve_memory|purge_source|purge_memory,
  actor_id, workspace_id: UUID,
  resource_type: source|answer|memory|workspace,
  resource_id?: UUID,
  source_type?: note|markdown|txt|pdf|docx|url,
  mime_type?: string,
  byte_count?, chunk_count?, retrieval_result_count?, citation_count?: integer,
  memory_category?: MemoryCategory,
  native_checks: pass|fail,
  occurred_at: datetime
}

PolicyResult {
  decision: pass|veto|unavailable,
  reason_code: string,
  policy_id?: string,
  policy_version?: string,
  audit_id?: string,
  evaluated_at: datetime
}
```

`reason_code` and `evaluated_at` are always present. When an enabled adapter
evaluates a concrete policy, it also returns the applicable `policy_id`,
`policy_version`, and `audit_id`; absence of required result metadata is
treated as `unavailable`, never as `pass`.

Context is bounded metadata only. It excludes raw/original/extracted content,
chunks, queries, generated answers, memory statements, prompts, cookies, CSRF
tokens, credentials, object paths, and provider bodies.

- Disabled/absent integration means “no additional veto”; native authorization,
  citation, purge, and explicit memory-activation checks still execute.
- Enabled integration returning `unavailable`, timing out, or erroring fails
  closed visibly for the protected operation.
- `pass` cannot turn a failed native check into success or grant any authority.
- Contract tests combine `pass`, `veto`, and `unavailable` with failed ownership,
  citation, purge, and memory-activation checks and prove no bypass.
