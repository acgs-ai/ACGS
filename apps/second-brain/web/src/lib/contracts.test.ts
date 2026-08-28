import { describe, expect, expectTypeOf, it } from "vitest";
import { parseAnswerPayload, parseAnswerRecord } from "./answer-parser";
import { type AnswerRecord, type Citation, getRenderableAnswer } from "./contracts";

const citation: Citation = {
  citation_id: crypto.randomUUID(),
  chunk_id: crypto.randomUUID(),
  source_id: crypto.randomUUID(),
  char_start: 0,
  char_end: 18,
};

describe("answer contracts", () => {
  it("exposes validated statements only for grounded answers", () => {
    const answer = parseAnswerRecord({
      status: "grounded",
      answer_id: crypto.randomUUID(),
      retrieval_run_id: crypto.randomUUID(),
      query: "What did the source say?",
      sufficiency: { sufficient: true, reason_code: "evidence_available" },
      evidence_supported_statements: [
        {
          statement_id: crypto.randomUUID(),
          text: "The source supports this.",
          citations: [citation],
        },
      ],
      retrieved_results: [
        { chunk_id: citation.chunk_id, source_id: citation.source_id, fused_rank: 1 },
      ],
      retrieval_config: {
        lexical_k: 50,
        semantic_k: 50,
        rrf_k: 60,
        evidence_chunk_limit: 8,
        evidence_char_limit: 12000,
      },
      model_provider: "fake",
      model_identifier: "deterministic",
      prompt_template_version: "v1",
      provider_status: "available",
      semantic_status: "available",
      created_at: new Date().toISOString(),
    });

    expect(answer.status).toBe("grounded");
    if (answer.status !== "grounded") throw new Error("Expected grounded answer");
    expect(getRenderableAnswer(answer)).toEqual({
      kind: "grounded",
      statements: answer.evidence_supported_statements,
      commentary: undefined,
    });
    expectTypeOf(answer).toMatchTypeOf<AnswerRecord>();
  });

  it("suppresses generated text when citation validation failed", () => {
    const answer = parseAnswerRecord({
      status: "validation_failed",
      answer_id: crypto.randomUUID(),
      retrieval_run_id: crypto.randomUUID(),
      query: "Unsupported answer",
      sufficiency: { sufficient: false, reason_code: "citation_invalid" },
      evidence_supported_statements: [
        { statement_id: crypto.randomUUID(), text: "Fabricated text", citations: [citation] },
      ],
      retrieved_results: [],
      retrieval_config: {
        lexical_k: 50,
        semantic_k: 50,
        rrf_k: 60,
        evidence_chunk_limit: 8,
        evidence_char_limit: 12000,
      },
      model_provider: "fake",
      model_identifier: "deterministic",
      prompt_template_version: "v1",
      provider_status: "available",
      semantic_status: "available",
      created_at: new Date().toISOString(),
    });

    expect(getRenderableAnswer(answer)).toEqual({
      kind: "validation_failed",
      message: "The generated answer could not be validated against the retrieved evidence.",
      fallback: [],
    });
    expect("evidence_supported_statements" in answer).toBe(false);
  });

  it("rejects grounded statements without citations", () => {
    const payload = {
      status: "grounded",
      answer_id: crypto.randomUUID(),
      retrieval_run_id: crypto.randomUUID(),
      query: "question",
      sufficiency: { sufficient: true, reason_code: "claimed" },
      retrieved_results: [
        { chunk_id: citation.chunk_id, source_id: citation.source_id, fused_rank: 1 },
      ],
      retrieval_config: {
        lexical_k: 50,
        semantic_k: 50,
        rrf_k: 60,
        evidence_chunk_limit: 8,
        evidence_char_limit: 12000,
      },
      model_provider: "fake",
      model_identifier: "deterministic",
      prompt_template_version: "v1",
      provider_status: "available",
      semantic_status: "available",
      created_at: new Date().toISOString(),
    };

    expect(() =>
      parseAnswerRecord({
        ...payload,
        evidence_supported_statements: [
          { statement_id: crypto.randomUUID(), text: "No evidence", citations: [] },
        ],
      }),
    ).toThrow("Grounded statements require at least one validated citation");
  });

  it("rejects inconsistent sufficiency and unretrieved citations", () => {
    const base = {
      status: "grounded",
      answer_id: crypto.randomUUID(),
      retrieval_run_id: crypto.randomUUID(),
      query: "question",
      sufficiency: { sufficient: false, reason_code: "inconsistent" },
      evidence_supported_statements: [
        { statement_id: crypto.randomUUID(), text: "claim", citations: [citation] },
      ],
      retrieved_results: [
        { chunk_id: crypto.randomUUID(), source_id: citation.source_id, fused_rank: 1 },
      ],
      retrieval_config: {
        lexical_k: 50,
        semantic_k: 50,
        rrf_k: 60,
        evidence_chunk_limit: 8,
        evidence_char_limit: 12000,
      },
      model_provider: "fake",
      model_identifier: "deterministic",
      prompt_template_version: "v1",
      provider_status: "available",
      semantic_status: "available",
      created_at: new Date().toISOString(),
    };

    expect(() => parseAnswerRecord(base)).toThrow(
      "Grounded status requires sufficient retrieved evidence",
    );
    expect(() =>
      parseAnswerRecord({ ...base, sufficiency: { sufficient: true, reason_code: "claimed" } }),
    ).toThrow("Citation is not present in retrieved evidence");
    expect(() =>
      parseAnswerRecord({
        ...base,
        sufficiency: { sufficient: true, reason_code: "claimed" },
        retrieved_results: [
          { chunk_id: citation.chunk_id, source_id: crypto.randomUUID(), fused_rank: 1 },
        ],
      }),
    ).toThrow("Citation is not present in retrieved evidence");
    expect(() =>
      parseAnswerRecord({
        ...base,
        sufficiency: { sufficient: true, reason_code: "claimed" },
        retrieved_results: [],
      }),
    ).toThrow("Grounded status requires sufficient retrieved evidence");
    expect(() =>
      parseAnswerRecord({
        ...base,
        status: "insufficient_evidence",
        sufficiency: { sufficient: true, reason_code: "inconsistent" },
        evidence_supported_statements: [],
      }),
    ).toThrow("Insufficient evidence cannot be sufficient");
    expect(() =>
      parseAnswerRecord({
        ...base,
        status: "validation_failed",
        sufficiency: { sufficient: true, reason_code: "inconsistent" },
      }),
    ).toThrow("Validation failure cannot be sufficient");
  });

  it("rejects malformed identifiers, dates, and fallback evidence", () => {
    const invalid = {
      status: "validation_failed",
      answer_id: "../../outside",
      retrieval_run_id: crypto.randomUUID(),
      query: "question",
      sufficiency: { sufficient: false, reason_code: "citation_invalid" },
      retrieved_results: [],
      retrieval_config: {
        lexical_k: 50,
        semantic_k: 50,
        rrf_k: 60,
        evidence_chunk_limit: 8,
        evidence_char_limit: 12000,
      },
      model_provider: "fake",
      model_identifier: "deterministic",
      prompt_template_version: "v1",
      provider_status: "available",
      semantic_status: "available",
      created_at: "not-a-date",
    };

    expect(() => parseAnswerRecord(invalid)).toThrow("answer_id must be a UUID");
    expect(() => parseAnswerRecord({ ...invalid, answer_id: crypto.randomUUID() })).toThrow(
      "created_at must be a valid UTC date",
    );
    expect(() =>
      parseAnswerRecord({
        ...invalid,
        answer_id: crypto.randomUUID(),
        created_at: "2026-02-31T12:00:00Z",
      }),
    ).toThrow("created_at must be a valid UTC date");
    expect(() =>
      parseAnswerRecord({
        ...invalid,
        answer_id: crypto.randomUUID(),
        created_at: new Date().toISOString(),
        extractive_fallback: [{ text: "passage", citation }],
      }),
    ).toThrow("Citation is not present in retrieved evidence");
  });

  it("accepts explicit provider outage and nullable backend fields", () => {
    const answer = parseAnswerRecord({
      status: "provider_unavailable",
      answer_id: crypto.randomUUID(),
      retrieval_run_id: crypto.randomUUID(),
      conversation_id: null,
      query: "What did the source say?",
      sufficiency: { sufficient: false, reason_code: "provider_unavailable" },
      evidence_supported_statements: [],
      retrieved_results: [
        {
          chunk_id: citation.chunk_id,
          source_id: citation.source_id,
          lexical_rank: 1,
          semantic_rank: null,
          fused_rank: 1,
        },
      ],
      retrieval_config: {
        lexical_k: 50,
        semantic_k: 50,
        rrf_k: 60,
        evidence_chunk_limit: 8,
        evidence_char_limit: 12000,
      },
      model_provider: "UnavailableGenerationProvider",
      model_identifier: "unavailable",
      prompt_template_version: "grounded-answer-v1",
      provider_status: "unavailable",
      semantic_status: "available",
      system_commentary: null,
      extractive_fallback: null,
      created_at: new Date().toISOString(),
    });

    expect(getRenderableAnswer(answer)).toEqual({
      kind: "provider_unavailable",
      message: "The generation provider is unavailable. Your sources remain searchable.",
      commentary: undefined,
    });
  });

  it("rejects a real chunk paired with the wrong source", () => {
    const otherSource = crypto.randomUUID();
    expect(() =>
      parseAnswerRecord({
        status: "grounded",
        answer_id: crypto.randomUUID(),
        retrieval_run_id: crypto.randomUUID(),
        query: "question",
        sufficiency: { sufficient: true, reason_code: "evidence_available" },
        evidence_supported_statements: [
          {
            statement_id: crypto.randomUUID(),
            text: "Unsupported pair",
            citations: [{ ...citation, source_id: otherSource }],
          },
        ],
        retrieved_results: [
          { chunk_id: citation.chunk_id, source_id: citation.source_id, fused_rank: 1 },
        ],
        retrieval_config: {
          lexical_k: 50,
          semantic_k: 50,
          rrf_k: 60,
          evidence_chunk_limit: 8,
          evidence_char_limit: 12000,
        },
        model_provider: "fake",
        model_identifier: "deterministic",
        prompt_template_version: "v1",
        provider_status: "available",
        semantic_status: "available",
        created_at: new Date().toISOString(),
      }),
    ).toThrow("Citation is not present in retrieved evidence");
  });

  it("rejects an otherwise grounded answer when its attached proposal is malformed", () => {
    const base = {
      status: "grounded",
      answer_id: crypto.randomUUID(),
      retrieval_run_id: crypto.randomUUID(),
      query: "question",
      sufficiency: { sufficient: true, reason_code: "evidence_available" },
      evidence_supported_statements: [
        { statement_id: crypto.randomUUID(), text: "claim", citations: [citation] },
      ],
      retrieved_results: [
        { chunk_id: citation.chunk_id, source_id: citation.source_id, fused_rank: 1 },
      ],
      retrieval_config: {
        lexical_k: 50,
        semantic_k: 50,
        rrf_k: 60,
        evidence_chunk_limit: 8,
        evidence_char_limit: 12000,
      },
      model_provider: "fake",
      model_identifier: "deterministic",
      prompt_template_version: "v1",
      provider_status: "available",
      semantic_status: "available",
      created_at: new Date().toISOString(),
    };
    expect(
      parseAnswerPayload({
        ...base,
        proposed_memory: null,
      }).proposed_memory,
    ).toBeNull();
    expect(() =>
      parseAnswerPayload({
        ...base,
        proposed_memory: {
          proposal_id: crypto.randomUUID(),
          statement: "proposal",
          category: "reference",
          confidence: 1,
          evidence_quality: "high",
          status: "approved",
          proposed_at: new Date().toISOString(),
          decided_at: null,
          evidence: [
            {
              chunk_id: "fabricated",
              source_id: citation.source_id,
              source_version_id: crypto.randomUUID(),
            },
          ],
        },
      }),
    ).toThrow();
  });

  it("accepts a proposed memory whose evidence pair belongs to the answer retrieval", () => {
    const base = {
      status: "grounded",
      answer_id: crypto.randomUUID(),
      retrieval_run_id: crypto.randomUUID(),
      query: "question",
      sufficiency: { sufficient: true, reason_code: "evidence_available" },
      evidence_supported_statements: [
        { statement_id: crypto.randomUUID(), text: "claim", citations: [citation] },
      ],
      retrieved_results: [
        { chunk_id: citation.chunk_id, source_id: citation.source_id, fused_rank: 1 },
      ],
      retrieval_config: {
        lexical_k: 50,
        semantic_k: 50,
        rrf_k: 60,
        evidence_chunk_limit: 8,
        evidence_char_limit: 12000,
      },
      model_provider: "fake",
      model_identifier: "deterministic",
      prompt_template_version: "v1",
      provider_status: "available",
      semantic_status: "available",
      created_at: new Date().toISOString(),
    };

    const parsed = parseAnswerPayload({
      ...base,
      proposed_memory: {
        proposal_id: crypto.randomUUID(),
        statement: "proposal",
        category: "reference",
        confidence: 1,
        evidence_quality: "high",
        status: "proposed",
        proposed_at: new Date().toISOString(),
        decided_at: null,
        evidence: [
          {
            chunk_id: citation.chunk_id,
            source_id: citation.source_id,
            source_version_id: crypto.randomUUID(),
          },
        ],
      },
    });

    expect(parsed.proposed_memory?.source_chunk_ids).toEqual([citation.chunk_id]);
  });

  it("rejects a proposed memory whose valid evidence pair was not retrieved for the answer", () => {
    const base = {
      status: "grounded",
      answer_id: crypto.randomUUID(),
      retrieval_run_id: crypto.randomUUID(),
      query: "question",
      sufficiency: { sufficient: true, reason_code: "evidence_available" },
      evidence_supported_statements: [
        { statement_id: crypto.randomUUID(), text: "claim", citations: [citation] },
      ],
      retrieved_results: [
        { chunk_id: citation.chunk_id, source_id: citation.source_id, fused_rank: 1 },
      ],
      retrieval_config: {
        lexical_k: 50,
        semantic_k: 50,
        rrf_k: 60,
        evidence_chunk_limit: 8,
        evidence_char_limit: 12000,
      },
      model_provider: "fake",
      model_identifier: "deterministic",
      prompt_template_version: "v1",
      provider_status: "available",
      semantic_status: "available",
      created_at: new Date().toISOString(),
    };

    expect(() =>
      parseAnswerPayload({
        ...base,
        proposed_memory: {
          proposal_id: crypto.randomUUID(),
          statement: "proposal",
          category: "reference",
          confidence: 1,
          evidence_quality: "high",
          status: "proposed",
          proposed_at: new Date().toISOString(),
          decided_at: null,
          evidence: [
            {
              chunk_id: citation.chunk_id,
              source_id: crypto.randomUUID(),
              source_version_id: crypto.randomUUID(),
            },
          ],
        },
      }),
    ).toThrow("Proposed memory evidence is not present in retrieved evidence");
  });
});
