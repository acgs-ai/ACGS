export type UUID = string;

export interface Citation {
  citation_id: UUID;
  chunk_id: UUID;
  source_id: UUID;
  char_start: number;
  char_end: number;
}

export interface EvidenceStatement {
  statement_id: UUID;
  text: string;
  citations: Citation[];
}

export interface ExtractiveFallback {
  text: string;
  citation: Citation;
}

export interface RetrievedResult {
  chunk_id: UUID;
  source_id: UUID;
  lexical_rank?: number;
  semantic_rank?: number;
  fused_rank: number;
}

export interface AnswerBase {
  answer_id: UUID;
  retrieval_run_id: UUID;
  conversation_id?: UUID;
  query: string;
  sufficiency: { sufficient: boolean; reason_code: string };
  retrieval_config: {
    lexical_k: number;
    semantic_k: number;
    rrf_k: number;
    evidence_chunk_limit: number;
    evidence_char_limit: number;
  };
  retrieved_results: RetrievedResult[];
  model_provider: string;
  model_identifier: string;
  prompt_template_version: string;
  provider_status: "available" | "unavailable" | "not_called";
  semantic_status: "available" | "unavailable";
  created_at: string;
}

export interface GroundedAnswer extends AnswerBase {
  status: "grounded";
  evidence_supported_statements: EvidenceStatement[];
  system_commentary?: string;
}

export interface InsufficientEvidenceAnswer extends AnswerBase {
  status: "insufficient_evidence";
  evidence_supported_statements: [];
  system_commentary?: string;
}

export interface ValidationFailedAnswer extends AnswerBase {
  status: "validation_failed";
  extractive_fallback: ExtractiveFallback[];
}

export interface ProviderUnavailableAnswer extends AnswerBase {
  status: "provider_unavailable";
  evidence_supported_statements: [];
  system_commentary?: string;
}

export type AnswerRecord =
  | GroundedAnswer
  | InsufficientEvidenceAnswer
  | ValidationFailedAnswer
  | ProviderUnavailableAnswer;

export type RenderableAnswer =
  | { kind: "grounded"; statements: EvidenceStatement[]; commentary: string | undefined }
  | { kind: "insufficient_evidence"; message: string; commentary: string | undefined }
  | { kind: "validation_failed"; message: string; fallback: ExtractiveFallback[] }
  | { kind: "provider_unavailable"; message: string; commentary: string | undefined };

export function getRenderableAnswer(answer: AnswerRecord): RenderableAnswer {
  if (answer.status === "grounded") {
    return {
      kind: "grounded",
      statements: answer.evidence_supported_statements,
      commentary: answer.system_commentary,
    };
  }
  if (answer.status === "insufficient_evidence") {
    return {
      kind: "insufficient_evidence",
      message: "The available sources do not provide enough evidence to answer this question.",
      commentary: answer.system_commentary,
    };
  }
  if (answer.status === "provider_unavailable") {
    return {
      kind: "provider_unavailable",
      message: "The generation provider is unavailable. Your sources remain searchable.",
      commentary: answer.system_commentary,
    };
  }
  return {
    kind: "validation_failed",
    message: "The generated answer could not be validated against the retrieved evidence.",
    fallback: answer.extractive_fallback,
  };
}
