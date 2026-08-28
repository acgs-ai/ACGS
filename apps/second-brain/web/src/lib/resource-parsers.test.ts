import { describe, expect, it } from "vitest";

import {
  parseBoundPurgeStatus,
  parseCaptureResult,
  parseCitationContext,
  parseIngestionJob,
  parseMemoryDetail,
  parseMemoryMutation,
  parseMemoryProposal,
  parseMemoryProposals,
  parseMemorySummaries,
  parseProject,
  parseProjects,
  parsePurgeRequest,
  parsePurgeStatus,
  parseResurfaceResult,
  parseSearchResponse,
  parseServiceStatus,
  parseSourceDetail,
  parseSourceOrganization,
  parseSourceSummaries,
  parseSourceSummary,
  parseTags,
  parseToday,
} from "./resource-parsers";

const UUID_A = "00000000-0000-4000-8000-000000000001";
const UUID_B = "00000000-0000-4000-8000-000000000002";
const NOW = "2026-08-27T00:00:00Z";

describe("resource response parsers", () => {
  it("accepts the backend-null parser MIME type for a failed source version", () => {
    const source = parseSourceDetail({
      source_id: UUID_A,
      display_title: "Failed PDF",
      source_type: "pdf",
      processing_state: "failed",
      project_id: null,
      ingested_at: NOW,
      original_uri: null,
      object_key: "objects/source.pdf",
      original_filename: "source.pdf",
      source_metadata: {},
      content_sha256: "a".repeat(64),
      mime_type: "application/pdf",
      semantic_state: "pending",
      processing_error_code: "parse_failure",
      processing_error_message: "PDF parser rejected the source.",
      tags: [],
      versions: [
        {
          source_version_id: UUID_B,
          version_number: 1,
          parser_name: "pdf",
          parser_version: "parser-v1",
          parser_mime_type: null,
          fetcher_version: null,
          chunker_version: "chunker-v1",
          content_sha256: "a".repeat(64),
          created_at: NOW,
        },
      ],
      documents: [],
      chunks: [],
      jobs: [],
      ingestion_history: [],
    });

    expect(source.versions[0]?.parser_mime_type).toBeNull();
  });

  it.each([
    ["project collection", parseProjects],
    ["tag collection", parseTags],
    ["capture", parseCaptureResult],
    ["job", parseIngestionJob],
    ["source collection", parseSourceSummaries],
    ["source detail", parseSourceDetail],
    ["context", parseCitationContext],
    ["search", parseSearchResponse],
    ["proposal collection", parseMemoryProposals],
    ["memory collection", parseMemorySummaries],
    ["memory detail", parseMemoryDetail],
    ["memory mutation", parseMemoryMutation],
    ["source organization", parseSourceOrganization],
    ["resurface", parseResurfaceResult],
    ["purge request", parsePurgeRequest],
    ["purge status", parsePurgeStatus],
    ["Today", parseToday],
    ["status", parseServiceStatus],
  ])("rejects a malformed successful %s response", (_name, parser) => {
    expect(() => parser(null)).toThrow();
  });

  it("rejects malformed identifiers and exact status/category fields", () => {
    expect(() =>
      parseProject({ project_id: "not-a-uuid", name: "Project", is_active: true }),
    ).toThrow();
    expect(() =>
      parseSourceSummary({
        source_id: UUID_A,
        display_title: "Source",
        source_type: "email",
        processing_state: "ready",
        project_id: null,
        project_name: null,
        tag_ids: [],
        ingested_at: "2026-08-27T00:00:00Z",
      }),
    ).toThrow();
    expect(() =>
      parseMemoryProposal({
        proposal_id: UUID_A,
        statement: "Statement",
        category: "secret",
        confidence: 0.8,
        evidence_quality: "high",
        status: "proposed",
        proposed_at: "2026-08-27T00:00:00Z",
        decided_at: null,
        source_chunk_ids: [UUID_B],
      }),
    ).toThrow();
  });

  it("rejects invalid search ranks and citation context ranges", () => {
    expect(() =>
      parseSearchResponse({
        semantic_status: "available",
        results: [
          {
            chunk_id: UUID_A,
            source_id: UUID_B,
            display_title: "Source",
            source_type: "note",
            excerpt: "Evidence",
            char_start: 0,
            char_end: 8,
            page_number: null,
            section: null,
            paragraph_number: null,
            location: null,
            project_id: null,
            tags: [],
            ingested_at: "2026-08-27T00:00:00Z",
            lexical_rank: 0,
            lexical_score: 1,
            semantic_rank: null,
            semantic_score: null,
            semantic_status: "available",
            fused_rank: 1,
            fused_score: 1,
          },
        ],
      }),
    ).toThrow();
    expect(() =>
      parseCitationContext({
        source_id: UUID_A,
        display_title: "Source",
        source_version_id: UUID_B,
        version_number: 1,
        chunk_id: UUID_A,
        chunk_text: "Evidence",
        char_start: 10,
        char_end: 18,
        page_number: null,
        section: null,
        paragraph_number: null,
        location: null,
        chunker_version: "chunk-v1",
        context_text: "Evidence",
        context_char_start: 11,
        context_char_end: 19,
      }),
    ).toThrow("Citation range is outside its context");
  });

  it("parses only the canonical search envelope and rejects legacy arrays", () => {
    expect(parseSearchResponse({ results: [], semantic_status: "unavailable" })).toEqual({
      results: [],
      semantic_status: "unavailable",
    });
    expect(() => parseSearchResponse([])).toThrow("search_response must be an object");
  });

  it("rejects malformed purge state transitions", () => {
    expect(() =>
      parsePurgeStatus({
        operation_id: UUID_A,
        resource_type: "source",
        resource_id: UUID_B,
        state: "complete-ish",
        attempts: 1,
        error_class: null,
        created_at: "2026-08-27T00:00:00Z",
        finished_at: null,
        events: [],
      }),
    ).toThrow();
  });

  it.each([
    ["operation", { operation_id: UUID_B }],
    ["resource type", { resource_type: "memory" }],
    ["resource", { resource_id: UUID_A }],
  ])("rejects purge status whose %s identity does not match the request", (_, override) => {
    expect(() =>
      parseBoundPurgeStatus(
        {
          operation_id: UUID_A,
          resource_type: "source",
          resource_id: UUID_B,
          state: "complete",
          attempts: 1,
          error_class: null,
          created_at: NOW,
          finished_at: NOW,
          events: [],
          ...override,
        },
        { operationId: UUID_A, resourceType: "source", resourceId: UUID_B },
      ),
    ).toThrow("Purge status identity does not match the requested operation");
  });
});
