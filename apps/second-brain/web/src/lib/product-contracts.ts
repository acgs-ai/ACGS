export interface Project {
  project_id: string;
  name: string;
  is_active: boolean;
}

export interface Tag {
  tag_id: string;
  name: string;
}

export type SourceType = "note" | "markdown" | "txt" | "pdf" | "docx" | "url";
export type SourceState = "queued" | "processing" | "ready" | "failed" | "purge_pending";
export type SemanticState = "pending" | "available" | "unavailable";
export type MemoryCategory =
  | "preference"
  | "commitment"
  | "project_fact"
  | "person_fact"
  | "reference"
  | "other";
export type EvidenceQuality = "low" | "medium" | "high";
export type ApprovedMemoryStatus = "active" | "superseded" | "archived" | "purge_pending";
export type PurgeState = "queued" | "processing" | "complete" | "dead";

export interface CaptureResult {
  source_id: string;
  source_version_id: string | null;
  job_id: string;
  state: "queued" | "processing" | "ready" | "failed";
  duplicate: boolean;
}

export interface IngestionJob {
  id: string;
  source_id: string;
  state: "queued" | "processing" | "ready" | "failed" | "dead";
  attempts: number;
  error_code: string | null;
  error_message: string | null;
}

export interface SourceSummary {
  source_id: string;
  display_title: string;
  source_type: SourceType;
  processing_state: SourceState;
  project_id: string | null;
  project_name: string | null;
  tag_ids: string[];
  ingested_at: string;
}

export interface SourceDetail extends Omit<SourceSummary, "project_name" | "tag_ids"> {
  original_uri: string | null;
  object_key: string | null;
  original_filename: string | null;
  source_metadata: Record<string, unknown> | null;
  content_sha256: string;
  mime_type: string;
  semantic_state: SemanticState;
  processing_error_code: string | null;
  processing_error_message: string | null;
  tags: Tag[];
  versions: Array<{
    source_version_id: string;
    version_number: number;
    parser_name: string;
    parser_version: string;
    parser_mime_type: string | null;
    fetcher_version: string | null;
    chunker_version: string;
    content_sha256: string;
    created_at: string;
  }>;
  documents: Array<{
    document_id: string;
    source_version_id: string;
    extracted_text: string;
    character_count: number;
    created_at: string;
  }>;
  chunks: Array<{
    chunk_id: string;
    source_version_id: string;
    ordinal: number;
    chunk_text: string;
    char_start: number;
    char_end: number;
    page_number: number | null;
    section: string | null;
    paragraph_number: number | null;
    location: Record<string, unknown> | null;
    chunker_version: string;
  }>;
  jobs: Array<{
    job_id: string;
    source_version_id: string | null;
    state: "queued" | "processing" | "ready" | "failed" | "dead";
    attempts: number;
    pipeline_checkpoint: string | null;
    semantic_state: SemanticState | null;
    semantic_error_class: string | null;
    error_code: string | null;
    error_message: string | null;
    created_at: string;
    updated_at: string;
  }>;
  ingestion_history: Array<{
    job_id: string;
    attempt: number;
    from_state: string | null;
    to_state: "queued" | "processing" | "ready" | "failed" | "dead";
    reason_class: string;
    occurred_at: string;
  }>;
}

export interface CitationContext {
  source_id: string;
  display_title: string;
  source_version_id: string;
  version_number: number;
  chunk_id: string;
  chunk_text: string;
  char_start: number;
  char_end: number;
  page_number: number | null;
  section: string | null;
  paragraph_number: number | null;
  location: Record<string, unknown> | null;
  chunker_version: string;
  context_text: string;
  context_char_start: number;
  context_char_end: number;
}

export interface SearchResult {
  chunk_id: string;
  source_id: string;
  display_title: string;
  source_type: SourceType;
  excerpt: string;
  char_start: number;
  char_end: number;
  page_number: number | null;
  section: string | null;
  paragraph_number: number | null;
  location: Record<string, unknown> | null;
  project_id: string | null;
  tags: Tag[];
  ingested_at: string;
  lexical_rank: number | null;
  lexical_score: number | null;
  semantic_rank: number | null;
  semantic_score: number | null;
  fused_rank: number;
  fused_score: number;
}

export interface SearchResponse {
  results: SearchResult[];
  semantic_status: "available" | "unavailable";
}

export interface MemoryProposal {
  proposal_id: string;
  statement: string;
  category: MemoryCategory;
  confidence: number;
  evidence_quality: EvidenceQuality;
  status: "proposed" | "approved" | "rejected";
  proposed_at: string;
  decided_at: string | null;
  source_chunk_ids: string[];
}

export interface MemorySummary {
  memory_id: string;
  status: ApprovedMemoryStatus;
  approved_at: string;
  supersedes_memory_id: string | null;
  superseded_by_id: string | null;
  revision_id: string;
  revision_number: number;
  statement: string;
  category: MemoryCategory;
  confidence: number;
  evidence_quality: EvidenceQuality;
}

export interface MemoryDetail {
  memory_id: string;
  proposal_id: string;
  status: ApprovedMemoryStatus;
  approved_at: string;
  supersedes_memory_id: string | null;
  superseded_by_id: string | null;
  revisions: Array<{
    revision_id: string;
    revision_number: number;
    statement: string;
    category: MemoryCategory;
    confidence: number;
    evidence_quality: EvidenceQuality;
    created_at: string;
    source_chunk_ids: string[];
  }>;
}

export interface TodayPayload {
  as_of: string;
  recent_captures: {
    items: Array<{
      source_id: string;
      display_title: string;
      source_type: SourceType;
      processing_state: SourceState;
      project_id: string | null;
      ingested_at: string;
    }>;
    empty_message: string | null;
  };
  failed_jobs: {
    items: Array<{
      job_id: string;
      source_id: string;
      display_title: string;
      state: "failed" | "dead";
      error_code: string | null;
      finished_at: string;
    }>;
    empty_message: string | null;
  };
  recent_approved_memories: {
    items: Array<{
      memory_id: string;
      status: ApprovedMemoryStatus;
      approved_at: string;
      normalized_statement: string;
      revision_number: number;
    }>;
    empty_message: string | null;
  };
  active_project_sources: {
    items: Array<{
      project_id: string;
      project_name: string;
      source_id: string;
      display_title: string;
      source_type: SourceType;
      ingested_at: string;
    }>;
    empty_message: string | null;
  };
  resurfacing: {
    items: Array<{
      memory_id: string;
      normalized_statement: string;
      revision_number: number;
      approved_at: string;
    }>;
    empty_message: string | null;
  };
}

export interface SourceOrganization {
  source_id: string;
  project_id: string | null;
  tag_ids: string[];
}

export interface ResurfaceResult {
  memory_id: string;
  recorded: boolean;
}

export interface PurgeRequestResult {
  operation_id: string;
  state: PurgeState;
}

export interface PurgeStatus extends PurgeRequestResult {
  resource_type: "source" | "memory";
  resource_id: string;
  attempts: number;
  error_class: string | null;
  created_at: string;
  finished_at: string | null;
  events: Array<{
    attempt: number;
    from_state: PurgeState | null;
    to_state: PurgeState;
    reason_class: string;
    occurred_at: string;
  }>;
}

export interface MemoryMutationResult {
  memory_id: string;
  proposal_id: string;
  status: ApprovedMemoryStatus;
  approved_at: string;
  supersedes_memory_id: string | null;
  superseded_by_id: string | null;
  revision_id: string;
  revision_number: number;
  normalized_statement: string;
  category: MemoryCategory;
  confidence: number;
  evidence_quality_label: EvidenceQuality;
}

export interface ServiceStatusPayload {
  service: string;
  status: "ready";
  database: string;
  storage: string;
  model_provider: string;
  embedding_provider_status: "available" | "unavailable";
  generation_provider_status: "available" | "unavailable";
  provider_status_scope: "local_adapter_state_not_remote_health";
  max_upload_bytes: number;
  max_extracted_chars: number;
  max_chunks: number;
  max_processing_seconds: number;
}
