import type {
  ApprovedMemoryStatus,
  CaptureResult,
  CitationContext,
  EvidenceQuality,
  IngestionJob,
  MemoryCategory,
  MemoryDetail,
  MemoryMutationResult,
  MemoryProposal,
  MemorySummary,
  Project,
  PurgeRequestResult,
  PurgeState,
  PurgeStatus,
  ResurfaceResult,
  SearchResponse,
  SearchResult,
  SemanticState,
  ServiceStatusPayload,
  SourceDetail,
  SourceOrganization,
  SourceState,
  SourceSummary,
  SourceType,
  Tag,
  TodayPayload,
} from "./product-contracts";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UTC_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/;
const SHA256 = /^[0-9a-f]{64}$/i;
const SOURCE_TYPES = ["note", "markdown", "txt", "pdf", "docx", "url"] as const;
const SOURCE_STATES = ["queued", "processing", "ready", "failed", "purge_pending"] as const;
const SEMANTIC_STATES = ["pending", "available", "unavailable"] as const;
const JOB_STATES = ["queued", "processing", "ready", "failed", "dead"] as const;
const CATEGORIES = [
  "preference",
  "commitment",
  "project_fact",
  "person_fact",
  "reference",
  "other",
] as const;
const EVIDENCE = ["low", "medium", "high"] as const;
const PROPOSAL_STATES = ["proposed", "approved", "rejected"] as const;
const MEMORY_STATES = ["active", "superseded", "archived", "purge_pending"] as const;
const PURGE_STATES = ["queued", "processing", "complete", "dead"] as const;

type RecordValue = Record<string, unknown>;

function object(value: unknown, field = "response"): RecordValue {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${field} must be an object`);
  }
  return value as RecordValue;
}

function list(value: unknown, field: string, maximum = 1000): unknown[] {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new TypeError(`${field} must be a bounded list`);
  }
  return value;
}

function string(value: unknown, field: string, maximum = 100_000): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new TypeError(`${field} must be a bounded string`);
  }
  return value;
}

function nullableString(value: unknown, field: string, maximum = 100_000): string | null {
  return value === null ? null : string(value, field, maximum);
}

function uuid(value: unknown, field: string): string {
  const parsed = string(value, field, 36);
  if (!UUID.test(parsed)) throw new TypeError(`${field} must be a UUID`);
  return parsed;
}

function nullableUuid(value: unknown, field: string): string | null {
  return value === null ? null : uuid(value, field);
}

function integer(
  value: unknown,
  field: string,
  minimum = 0,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new TypeError(`${field} must be an integer in range`);
  }
  return value as number;
}

function finite(value: unknown, field: string, minimum?: number, maximum?: number): number {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    (minimum !== undefined && value < minimum) ||
    (maximum !== undefined && value > maximum)
  ) {
    throw new TypeError(`${field} must be a finite number in range`);
  }
  return value;
}

function nullableFinite(value: unknown, field: string): number | null {
  return value === null ? null : finite(value, field);
}

function boolean(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") throw new TypeError(`${field} must be a boolean`);
  return value;
}

function enumeration<const T extends readonly string[]>(
  value: unknown,
  field: string,
  choices: T,
): T[number] {
  if (typeof value !== "string" || !choices.includes(value)) {
    throw new TypeError(`${field} has an unsupported value`);
  }
  return value as T[number];
}

function utc(value: unknown, field: string): string {
  const parsed = string(value, field, 40);
  if (!UTC_DATE.test(parsed) || !Number.isFinite(Date.parse(parsed))) {
    throw new TypeError(`${field} must be a UTC timestamp`);
  }
  return parsed;
}

function nullableUtc(value: unknown, field: string): string | null {
  return value === null ? null : utc(value, field);
}

function nullableRecord(value: unknown, field: string): RecordValue | null {
  return value === null ? null : object(value, field);
}

function nullableInteger(value: unknown, field: string, minimum = 0): number | null {
  return value === null ? null : integer(value, field, minimum);
}

function uuidList(value: unknown, field: string): string[] {
  const values = list(value, field, 500).map((item) => uuid(item, field));
  if (new Set(values).size !== values.length) throw new TypeError(`${field} contains duplicates`);
  return values;
}

function tag(value: unknown): Tag {
  const input = object(value, "tag");
  return { tag_id: uuid(input.tag_id, "tag_id"), name: string(input.name, "tag.name", 200) };
}

export function parseTag(value: unknown): Tag {
  return tag(value);
}

export function parseTags(value: unknown): Tag[] {
  return list(value, "tags", 500).map(tag);
}

export function parseProject(value: unknown): Project {
  const input = object(value, "project");
  return {
    project_id: uuid(input.project_id, "project_id"),
    name: string(input.name, "project.name", 200),
    is_active: boolean(input.is_active, "project.is_active"),
  };
}

export function parseProjects(value: unknown): Project[] {
  return list(value, "projects", 500).map(parseProject);
}

export function parseCaptureResult(value: unknown): CaptureResult {
  const input = object(value);
  return {
    source_id: uuid(input.source_id, "source_id"),
    source_version_id: nullableUuid(input.source_version_id, "source_version_id"),
    job_id: uuid(input.job_id, "job_id"),
    state: enumeration(input.state, "state", ["queued", "processing", "ready", "failed"]),
    duplicate: boolean(input.duplicate, "duplicate"),
  };
}

export function parseIngestionJob(value: unknown): IngestionJob {
  const input = object(value);
  return {
    id: uuid(input.id, "job.id"),
    source_id: uuid(input.source_id, "job.source_id"),
    state: enumeration(input.state, "job.state", JOB_STATES),
    attempts: integer(input.attempts, "job.attempts", 0, 1000),
    error_code: nullableString(input.error_code, "job.error_code", 200),
    error_message: nullableString(input.error_message, "job.error_message", 2000),
  };
}

function sourceType(value: unknown, field: string): SourceType {
  return enumeration(value, field, SOURCE_TYPES);
}

function sourceState(value: unknown, field: string): SourceState {
  return enumeration(value, field, SOURCE_STATES);
}

function semanticState(value: unknown, field: string): SemanticState {
  return enumeration(value, field, SEMANTIC_STATES);
}

export function parseSourceSummary(value: unknown): SourceSummary {
  const input = object(value, "source");
  return {
    source_id: uuid(input.source_id, "source_id"),
    display_title: string(input.display_title, "display_title", 500),
    source_type: sourceType(input.source_type, "source_type"),
    processing_state: sourceState(input.processing_state, "processing_state"),
    project_id: nullableUuid(input.project_id, "project_id"),
    project_name: nullableString(input.project_name, "project_name", 200),
    tag_ids: uuidList(input.tag_ids, "tag_ids"),
    ingested_at: utc(input.ingested_at, "ingested_at"),
  };
}

export function parseSourceSummaries(value: unknown): SourceSummary[] {
  return list(value, "sources", 500).map(parseSourceSummary);
}

function parseVersion(value: unknown): SourceDetail["versions"][number] {
  const input = object(value, "source_version");
  const hash = string(input.content_sha256, "version.content_sha256", 64);
  if (!SHA256.test(hash)) throw new TypeError("version.content_sha256 is invalid");
  return {
    source_version_id: uuid(input.source_version_id, "version.source_version_id"),
    version_number: integer(input.version_number, "version.version_number", 1),
    parser_name: string(input.parser_name, "version.parser_name", 200),
    parser_version: string(input.parser_version, "version.parser_version", 100),
    parser_mime_type: nullableString(input.parser_mime_type, "version.parser_mime_type", 200),
    fetcher_version: nullableString(input.fetcher_version, "version.fetcher_version", 100),
    chunker_version: string(input.chunker_version, "version.chunker_version", 100),
    content_sha256: hash,
    created_at: utc(input.created_at, "version.created_at"),
  };
}

function parseDocument(value: unknown): SourceDetail["documents"][number] {
  const input = object(value, "document");
  return {
    document_id: uuid(input.document_id, "document.document_id"),
    source_version_id: uuid(input.source_version_id, "document.source_version_id"),
    extracted_text: string(input.extracted_text, "document.extracted_text", 10_000_000),
    character_count: integer(input.character_count, "document.character_count", 0, 10_000_000),
    created_at: utc(input.created_at, "document.created_at"),
  };
}

function parseChunk(value: unknown): SourceDetail["chunks"][number] {
  const input = object(value, "chunk");
  const start = integer(input.char_start, "chunk.char_start");
  const end = integer(input.char_end, "chunk.char_end", 1);
  if (end <= start) throw new TypeError("chunk offsets are invalid");
  return {
    chunk_id: uuid(input.chunk_id, "chunk.chunk_id"),
    source_version_id: uuid(input.source_version_id, "chunk.source_version_id"),
    ordinal: integer(input.ordinal, "chunk.ordinal"),
    chunk_text: string(input.chunk_text, "chunk.chunk_text", 1_000_000),
    char_start: start,
    char_end: end,
    page_number: nullableInteger(input.page_number, "chunk.page_number", 1),
    section: nullableString(input.section, "chunk.section", 1000),
    paragraph_number: nullableInteger(input.paragraph_number, "chunk.paragraph_number", 1),
    location: nullableRecord(input.location, "chunk.location"),
    chunker_version: string(input.chunker_version, "chunk.chunker_version", 100),
  };
}

function parseSourceJob(value: unknown): SourceDetail["jobs"][number] {
  const input = object(value, "job");
  return {
    job_id: uuid(input.job_id, "job.job_id"),
    source_version_id: nullableUuid(input.source_version_id, "job.source_version_id"),
    state: enumeration(input.state, "job.state", JOB_STATES),
    attempts: integer(input.attempts, "job.attempts", 0, 1000),
    pipeline_checkpoint: nullableString(input.pipeline_checkpoint, "job.pipeline_checkpoint", 200),
    semantic_state:
      input.semantic_state === null
        ? null
        : semanticState(input.semantic_state, "job.semantic_state"),
    semantic_error_class: nullableString(
      input.semantic_error_class,
      "job.semantic_error_class",
      200,
    ),
    error_code: nullableString(input.error_code, "job.error_code", 200),
    error_message: nullableString(input.error_message, "job.error_message", 2000),
    created_at: utc(input.created_at, "job.created_at"),
    updated_at: utc(input.updated_at, "job.updated_at"),
  };
}

function parseHistory(value: unknown): SourceDetail["ingestion_history"][number] {
  const input = object(value, "ingestion_history");
  return {
    job_id: uuid(input.job_id, "history.job_id"),
    attempt: integer(input.attempt, "history.attempt", 0, 1000),
    from_state:
      input.from_state === null
        ? null
        : enumeration(input.from_state, "history.from_state", JOB_STATES),
    to_state: enumeration(input.to_state, "history.to_state", JOB_STATES),
    reason_class: string(input.reason_class, "history.reason_class", 200),
    occurred_at: utc(input.occurred_at, "history.occurred_at"),
  };
}

export function parseSourceDetail(value: unknown): SourceDetail {
  const input = object(value, "source_detail");
  const hash = string(input.content_sha256, "content_sha256", 64);
  if (!SHA256.test(hash)) throw new TypeError("content_sha256 is invalid");
  return {
    source_id: uuid(input.source_id, "source_id"),
    display_title: string(input.display_title, "display_title", 500),
    source_type: sourceType(input.source_type, "source_type"),
    processing_state: sourceState(input.processing_state, "processing_state"),
    project_id: nullableUuid(input.project_id, "project_id"),
    ingested_at: utc(input.ingested_at, "ingested_at"),
    original_uri: nullableString(input.original_uri, "original_uri", 4000),
    object_key: nullableString(input.object_key, "object_key", 2000),
    original_filename: nullableString(input.original_filename, "original_filename", 500),
    source_metadata: nullableRecord(input.source_metadata, "source_metadata"),
    content_sha256: hash,
    mime_type: string(input.mime_type, "mime_type", 200),
    semantic_state: semanticState(input.semantic_state, "semantic_state"),
    processing_error_code: nullableString(
      input.processing_error_code,
      "processing_error_code",
      200,
    ),
    processing_error_message: nullableString(
      input.processing_error_message,
      "processing_error_message",
      2000,
    ),
    tags: parseTags(input.tags),
    versions: list(input.versions, "versions", 100).map(parseVersion),
    documents: list(input.documents, "documents", 100).map(parseDocument),
    chunks: list(input.chunks, "chunks", 10_000).map(parseChunk),
    jobs: list(input.jobs, "jobs", 1000).map(parseSourceJob),
    ingestion_history: list(input.ingestion_history, "ingestion_history", 10_000).map(parseHistory),
  };
}

export function parseCitationContext(value: unknown): CitationContext {
  const input = object(value, "citation_context");
  const charStart = integer(input.char_start, "char_start");
  const charEnd = integer(input.char_end, "char_end", 1);
  const contextStart = integer(input.context_char_start, "context_char_start");
  const contextEnd = integer(input.context_char_end, "context_char_end", 1);
  if (charEnd <= charStart || contextEnd <= contextStart)
    throw new TypeError("Citation offsets are invalid");
  if (charStart < contextStart || charEnd > contextEnd) {
    throw new TypeError("Citation range is outside its context");
  }
  return {
    source_id: uuid(input.source_id, "source_id"),
    display_title: string(input.display_title, "display_title", 500),
    source_version_id: uuid(input.source_version_id, "source_version_id"),
    version_number: integer(input.version_number, "version_number", 1),
    chunk_id: uuid(input.chunk_id, "chunk_id"),
    chunk_text: string(input.chunk_text, "chunk_text", 1_000_000),
    char_start: charStart,
    char_end: charEnd,
    page_number: nullableInteger(input.page_number, "page_number", 1),
    section: nullableString(input.section, "section", 1000),
    paragraph_number: nullableInteger(input.paragraph_number, "paragraph_number", 1),
    location: nullableRecord(input.location, "location"),
    chunker_version: string(input.chunker_version, "chunker_version", 100),
    context_text: string(input.context_text, "context_text", 2_000_000),
    context_char_start: contextStart,
    context_char_end: contextEnd,
  };
}

function parseSearchResult(value: unknown): SearchResult {
  const input = object(value, "search_result");
  const start = integer(input.char_start, "search.char_start");
  const end = integer(input.char_end, "search.char_end", 1);
  if (end <= start) throw new TypeError("Search offsets are invalid");
  return {
    chunk_id: uuid(input.chunk_id, "search.chunk_id"),
    source_id: uuid(input.source_id, "search.source_id"),
    display_title: string(input.display_title, "search.display_title", 500),
    source_type: sourceType(input.source_type, "search.source_type"),
    excerpt: string(input.excerpt, "search.excerpt", 100_000),
    char_start: start,
    char_end: end,
    page_number: nullableInteger(input.page_number, "search.page_number", 1),
    section: nullableString(input.section, "search.section", 1000),
    paragraph_number: nullableInteger(input.paragraph_number, "search.paragraph_number", 1),
    location: nullableRecord(input.location, "search.location"),
    project_id: nullableUuid(input.project_id, "search.project_id"),
    tags: parseTags(input.tags),
    ingested_at: utc(input.ingested_at, "search.ingested_at"),
    lexical_rank: nullableInteger(input.lexical_rank, "search.lexical_rank", 1),
    lexical_score: nullableFinite(input.lexical_score, "search.lexical_score"),
    semantic_rank: nullableInteger(input.semantic_rank, "search.semantic_rank", 1),
    semantic_score: nullableFinite(input.semantic_score, "search.semantic_score"),
    fused_rank: integer(input.fused_rank, "search.fused_rank", 1),
    fused_score: finite(input.fused_score, "search.fused_score", 0),
  };
}

export function parseSearchResponse(value: unknown): SearchResponse {
  const input = object(value, "search_response");
  return {
    results: list(input.results, "search_results", 500).map(parseSearchResult),
    semantic_status: enumeration(input.semantic_status, "search.semantic_status", [
      "available",
      "unavailable",
    ]),
  };
}

function memoryCategory(value: unknown, field: string): MemoryCategory {
  return enumeration(value, field, CATEGORIES);
}

function evidenceQuality(value: unknown, field: string): EvidenceQuality {
  return enumeration(value, field, EVIDENCE);
}

export function parseMemoryProposal(value: unknown): MemoryProposal {
  const input = object(value, "memory_proposal");
  return {
    proposal_id: uuid(input.proposal_id, "proposal_id"),
    statement: string(input.statement, "proposal.statement", 5000),
    category: memoryCategory(input.category, "proposal.category"),
    confidence: finite(input.confidence, "proposal.confidence", 0, 1),
    evidence_quality: evidenceQuality(input.evidence_quality, "proposal.evidence_quality"),
    status: enumeration(input.status, "proposal.status", PROPOSAL_STATES),
    proposed_at: utc(input.proposed_at, "proposal.proposed_at"),
    decided_at: nullableUtc(input.decided_at, "proposal.decided_at"),
    source_chunk_ids: uuidList(input.source_chunk_ids, "proposal.source_chunk_ids"),
  };
}

export function parseMemoryProposals(value: unknown): MemoryProposal[] {
  return list(value, "memory_proposals", 500).map(parseMemoryProposal);
}

export function parseAnswerMemoryProposal(value: unknown): MemoryProposal {
  const input = object(value, "answer.proposed_memory");
  const evidence = list(input.evidence, "proposal.evidence", 500).map((value) => {
    const item = object(value, "proposal.evidence_item");
    return {
      chunk_id: uuid(item.chunk_id, "proposal.evidence.chunk_id"),
      source_id: uuid(item.source_id, "proposal.evidence.source_id"),
      source_version_id: uuid(item.source_version_id, "proposal.evidence.source_version_id"),
    };
  });
  if (evidence.length === 0) throw new TypeError("proposal.evidence must not be empty");
  const parsed: MemoryProposal = {
    proposal_id: uuid(input.proposal_id, "proposal_id"),
    statement: string(input.statement, "proposal.statement", 5000),
    category: memoryCategory(input.category, "proposal.category"),
    confidence: finite(input.confidence, "proposal.confidence", 0, 1),
    evidence_quality: evidenceQuality(input.evidence_quality, "proposal.evidence_quality"),
    status: enumeration(input.status, "proposal.status", ["proposed"]),
    proposed_at: utc(input.proposed_at, "proposal.proposed_at"),
    decided_at: nullableUtc(input.decided_at, "proposal.decided_at"),
    source_chunk_ids: evidence.map((item) => item.chunk_id),
  };
  if (parsed.decided_at !== null || new Set(parsed.source_chunk_ids).size !== evidence.length) {
    throw new TypeError("Proposed memory lifecycle or evidence is invalid");
  }
  return parsed;
}

export function parseMemoryProposalMutation(value: unknown): MemoryProposal {
  const input = object(value, "memory_proposal_mutation");
  const evidence = list(input.evidence, "proposal.evidence", 500).map((value) => {
    const item = object(value, "proposal.evidence_item");
    return uuid(item.chunk_id, "proposal.evidence.chunk_id");
  });
  const status = enumeration(input.status, "proposal.status", PROPOSAL_STATES);
  const decidedAt = nullableUtc(input.decided_at, "proposal.decided_at");
  if ((status === "proposed") !== (decidedAt === null)) {
    throw new TypeError("Proposal lifecycle is inconsistent");
  }
  return {
    proposal_id: uuid(input.proposal_id, "proposal_id"),
    statement: string(input.statement, "proposal.statement", 5000),
    category: memoryCategory(input.category, "proposal.category"),
    confidence: finite(input.confidence, "proposal.confidence", 0, 1),
    evidence_quality: evidenceQuality(input.evidence_quality, "proposal.evidence_quality"),
    status,
    proposed_at: utc(input.proposed_at, "proposal.proposed_at"),
    decided_at: decidedAt,
    source_chunk_ids: evidence,
  };
}

function memoryStatus(value: unknown, field: string): ApprovedMemoryStatus {
  return enumeration(value, field, MEMORY_STATES);
}

export function parseMemorySummary(value: unknown): MemorySummary {
  const input = object(value, "memory");
  return {
    memory_id: uuid(input.memory_id, "memory_id"),
    status: memoryStatus(input.status, "memory.status"),
    approved_at: utc(input.approved_at, "memory.approved_at"),
    supersedes_memory_id: nullableUuid(input.supersedes_memory_id, "memory.supersedes_memory_id"),
    superseded_by_id: nullableUuid(input.superseded_by_id, "memory.superseded_by_id"),
    revision_id: uuid(input.revision_id, "memory.revision_id"),
    revision_number: integer(input.revision_number, "memory.revision_number", 1),
    statement: string(input.statement, "memory.statement", 5000),
    category: memoryCategory(input.category, "memory.category"),
    confidence: finite(input.confidence, "memory.confidence", 0, 1),
    evidence_quality: evidenceQuality(input.evidence_quality, "memory.evidence_quality"),
  };
}

export function parseMemorySummaries(value: unknown): MemorySummary[] {
  return list(value, "memories", 500).map(parseMemorySummary);
}

export function parseMemoryDetail(value: unknown): MemoryDetail {
  const input = object(value, "memory_detail");
  return {
    memory_id: uuid(input.memory_id, "memory_id"),
    proposal_id: uuid(input.proposal_id, "proposal_id"),
    status: memoryStatus(input.status, "memory.status"),
    approved_at: utc(input.approved_at, "memory.approved_at"),
    supersedes_memory_id: nullableUuid(input.supersedes_memory_id, "memory.supersedes_memory_id"),
    superseded_by_id: nullableUuid(input.superseded_by_id, "memory.superseded_by_id"),
    revisions: list(input.revisions, "memory.revisions", 1000).map((value) => {
      const revision = object(value, "memory_revision");
      return {
        revision_id: uuid(revision.revision_id, "revision.revision_id"),
        revision_number: integer(revision.revision_number, "revision.revision_number", 1),
        statement: string(revision.statement, "revision.statement", 5000),
        category: memoryCategory(revision.category, "revision.category"),
        confidence: finite(revision.confidence, "revision.confidence", 0, 1),
        evidence_quality: evidenceQuality(revision.evidence_quality, "revision.evidence_quality"),
        created_at: utc(revision.created_at, "revision.created_at"),
        source_chunk_ids: uuidList(revision.source_chunk_ids, "revision.source_chunk_ids"),
      };
    }),
  };
}

export function parseMemoryMutation(value: unknown): MemoryMutationResult {
  const input = object(value, "memory_mutation");
  return {
    memory_id: uuid(input.memory_id, "memory_id"),
    proposal_id: uuid(input.proposal_id, "proposal_id"),
    status: memoryStatus(input.status, "memory.status"),
    approved_at: utc(input.approved_at, "memory.approved_at"),
    supersedes_memory_id: nullableUuid(input.supersedes_memory_id, "memory.supersedes_memory_id"),
    superseded_by_id: nullableUuid(input.superseded_by_id, "memory.superseded_by_id"),
    revision_id: uuid(input.revision_id, "revision_id"),
    revision_number: integer(input.revision_number, "revision_number", 1),
    normalized_statement: string(input.normalized_statement, "normalized_statement", 5000),
    category: memoryCategory(input.category, "category"),
    confidence: finite(input.confidence, "confidence", 0, 1),
    evidence_quality_label: evidenceQuality(input.evidence_quality_label, "evidence_quality_label"),
  };
}

export function parseSourceOrganization(value: unknown): SourceOrganization {
  const input = object(value, "source_organization");
  return {
    source_id: uuid(input.source_id, "source_id"),
    project_id: nullableUuid(input.project_id, "project_id"),
    tag_ids: uuidList(input.tag_ids, "tag_ids"),
  };
}

export function parseResurfaceResult(value: unknown): ResurfaceResult {
  const input = object(value, "resurface_result");
  return {
    memory_id: uuid(input.memory_id, "memory_id"),
    recorded: boolean(input.recorded, "recorded"),
  };
}

function purgeState(value: unknown, field: string): PurgeState {
  return enumeration(value, field, PURGE_STATES);
}

export function parsePurgeRequest(value: unknown): PurgeRequestResult {
  const input = object(value, "purge_request");
  return {
    operation_id: uuid(input.operation_id, "operation_id"),
    state: purgeState(input.state, "purge.state"),
  };
}

export function parsePurgeStatus(value: unknown): PurgeStatus {
  const input = object(value, "purge_status");
  const state = purgeState(input.state, "purge.state");
  const finishedAt = nullableUtc(input.finished_at, "purge.finished_at");
  if ((state === "complete" || state === "dead") !== (finishedAt !== null)) {
    throw new TypeError("Purge terminal state and finished_at disagree");
  }
  return {
    operation_id: uuid(input.operation_id, "operation_id"),
    resource_type: enumeration(input.resource_type, "resource_type", ["source", "memory"]),
    resource_id: uuid(input.resource_id, "resource_id"),
    state,
    attempts: integer(input.attempts, "purge.attempts", 0, 1000),
    error_class: nullableString(input.error_class, "purge.error_class", 200),
    created_at: utc(input.created_at, "purge.created_at"),
    finished_at: finishedAt,
    events: list(input.events, "purge.events", 1000).map((value) => {
      const event = object(value, "purge_event");
      return {
        attempt: integer(event.attempt, "purge_event.attempt", 0, 1000),
        from_state:
          event.from_state === null ? null : purgeState(event.from_state, "purge_event.from_state"),
        to_state: purgeState(event.to_state, "purge_event.to_state"),
        reason_class: string(event.reason_class, "purge_event.reason_class", 200),
        occurred_at: utc(event.occurred_at, "purge_event.occurred_at"),
      };
    }),
  };
}

export function parseBoundPurgeStatus(
  value: unknown,
  expected: {
    operationId: string;
    resourceType: PurgeStatus["resource_type"];
    resourceId: string;
  },
): PurgeStatus {
  const status = parsePurgeStatus(value);
  if (
    status.operation_id !== expected.operationId ||
    status.resource_type !== expected.resourceType ||
    status.resource_id !== expected.resourceId
  ) {
    throw new TypeError("Purge status identity does not match the requested operation");
  }
  return status;
}

function section<T>(
  value: unknown,
  field: string,
  parser: (value: unknown) => T,
): { items: T[]; empty_message: string | null } {
  const input = object(value, field);
  const items = list(input.items, `${field}.items`, 100).map(parser);
  const emptyMessage = nullableString(input.empty_message, `${field}.empty_message`, 500);
  if ((items.length === 0) !== (emptyMessage !== null)) {
    throw new TypeError(`${field} empty state is inconsistent`);
  }
  return { items, empty_message: emptyMessage };
}

export function parseToday(value: unknown): TodayPayload {
  const input = object(value, "today");
  return {
    as_of: utc(input.as_of, "today.as_of"),
    recent_captures: section(input.recent_captures, "recent_captures", (value) => {
      const item = object(value);
      return {
        source_id: uuid(item.source_id, "source_id"),
        display_title: string(item.display_title, "display_title", 500),
        source_type: sourceType(item.source_type, "source_type"),
        processing_state: sourceState(item.processing_state, "processing_state"),
        project_id: nullableUuid(item.project_id, "project_id"),
        ingested_at: utc(item.ingested_at, "ingested_at"),
      };
    }),
    failed_jobs: section(input.failed_jobs, "failed_jobs", (value) => {
      const item = object(value);
      return {
        job_id: uuid(item.job_id, "job_id"),
        source_id: uuid(item.source_id, "source_id"),
        display_title: string(item.display_title, "display_title", 500),
        state: enumeration(item.state, "state", ["failed", "dead"]),
        error_code: nullableString(item.error_code, "error_code", 200),
        finished_at: utc(item.finished_at, "finished_at"),
      };
    }),
    recent_approved_memories: section(
      input.recent_approved_memories,
      "recent_approved_memories",
      (value) => {
        const item = object(value);
        return {
          memory_id: uuid(item.memory_id, "memory_id"),
          status: memoryStatus(item.status, "status"),
          approved_at: utc(item.approved_at, "approved_at"),
          normalized_statement: string(item.normalized_statement, "normalized_statement", 5000),
          revision_number: integer(item.revision_number, "revision_number", 1),
        };
      },
    ),
    active_project_sources: section(
      input.active_project_sources,
      "active_project_sources",
      (value) => {
        const item = object(value);
        return {
          project_id: uuid(item.project_id, "project_id"),
          project_name: string(item.project_name, "project_name", 200),
          source_id: uuid(item.source_id, "source_id"),
          display_title: string(item.display_title, "display_title", 500),
          source_type: sourceType(item.source_type, "source_type"),
          ingested_at: utc(item.ingested_at, "ingested_at"),
        };
      },
    ),
    resurfacing: section(input.resurfacing, "resurfacing", (value) => {
      const item = object(value);
      return {
        memory_id: uuid(item.memory_id, "memory_id"),
        normalized_statement: string(item.normalized_statement, "normalized_statement", 5000),
        revision_number: integer(item.revision_number, "revision_number", 1),
        approved_at: utc(item.approved_at, "approved_at"),
      };
    }),
  };
}

export function parseServiceStatus(value: unknown): ServiceStatusPayload {
  const input = object(value, "status");
  return {
    service: string(input.service, "status.service", 100),
    status: enumeration(input.status, "status.status", ["ready"]),
    database: string(input.database, "status.database", 100),
    storage: string(input.storage, "status.storage", 100),
    model_provider: string(input.model_provider, "status.model_provider", 200),
    embedding_provider_status: enumeration(input.embedding_provider_status, "status.embedding", [
      "available",
      "unavailable",
    ]),
    generation_provider_status: enumeration(input.generation_provider_status, "status.generation", [
      "available",
      "unavailable",
    ]),
    provider_status_scope: enumeration(
      input.provider_status_scope,
      "status.provider_status_scope",
      ["local_adapter_state_not_remote_health"],
    ),
    max_upload_bytes: integer(input.max_upload_bytes, "status.max_upload_bytes", 1),
    max_extracted_chars: integer(input.max_extracted_chars, "status.max_extracted_chars", 1),
    max_chunks: integer(input.max_chunks, "status.max_chunks", 1),
    max_processing_seconds: integer(
      input.max_processing_seconds,
      "status.max_processing_seconds",
      1,
    ),
  };
}

export function parseSession(value: unknown): { csrf_token: string } {
  const input = object(value, "session");
  return { csrf_token: string(input.csrf_token, "session.csrf_token", 512) };
}

export function parseNoContent(value: unknown): undefined {
  if (value !== null && value !== undefined) throw new TypeError("Response must be empty");
  return undefined;
}
