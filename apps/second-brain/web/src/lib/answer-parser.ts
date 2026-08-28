import type {
  AnswerBase,
  AnswerRecord,
  Citation,
  EvidenceStatement,
  ExtractiveFallback,
  RetrievedResult,
} from "./contracts";
import type { MemoryProposal } from "./product-contracts";
import { parseAnswerMemoryProposal } from "./resource-parsers";

export type AnswerPayload = AnswerRecord & { proposed_memory: MemoryProposal | null };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UTC_DATE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(?:Z|\+00:00)$/;

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Answer payload must be an object");
  }
  return value as Record<string, unknown>;
}

function text(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${field} is required`);
  }
  return value;
}

function uuid(value: unknown, field: string): string {
  const parsed = text(value, field);
  if (!UUID.test(parsed)) throw new TypeError(`${field} must be a UUID`);
  return parsed;
}

function integer(value: unknown, field: string, minimum = 0): number {
  if (!Number.isInteger(value) || (value as number) < minimum) {
    throw new TypeError(`${field} is invalid`);
  }
  return value as number;
}

function list(value: unknown, field: string): unknown[] {
  if (!Array.isArray(value)) throw new TypeError(`${field} must be a list`);
  return value;
}

function utcDate(value: unknown): string {
  const parsed = text(value, "created_at");
  const parts = UTC_DATE.exec(parsed);
  if (!parts) {
    throw new TypeError("created_at must be a valid UTC date");
  }
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = parts;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    daysInMonth === undefined ||
    day > daysInMonth ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    !Number.isFinite(Date.parse(parsed))
  ) {
    throw new TypeError("created_at must be a valid UTC date");
  }
  return parsed;
}

function parseRetrieved(value: unknown): RetrievedResult {
  const input = object(value);
  return {
    chunk_id: uuid(input.chunk_id, "retrieved chunk_id"),
    source_id: uuid(input.source_id, "retrieved source_id"),
    fused_rank: integer(input.fused_rank, "fused_rank", 1),
    ...(input.lexical_rank === undefined || input.lexical_rank === null
      ? {}
      : { lexical_rank: integer(input.lexical_rank, "lexical_rank", 1) }),
    ...(input.semantic_rank === undefined || input.semantic_rank === null
      ? {}
      : { semantic_rank: integer(input.semantic_rank, "semantic_rank", 1) }),
  };
}

function parseBase(input: Record<string, unknown>): AnswerBase {
  const sufficiency = object(input.sufficiency);
  const config = object(input.retrieval_config);
  if (typeof sufficiency.sufficient !== "boolean") {
    throw new TypeError("sufficiency.sufficient is invalid");
  }
  return {
    answer_id: uuid(input.answer_id, "answer_id"),
    retrieval_run_id: uuid(input.retrieval_run_id, "retrieval_run_id"),
    ...(input.conversation_id === undefined || input.conversation_id === null
      ? {}
      : { conversation_id: uuid(input.conversation_id, "conversation_id") }),
    query: text(input.query, "query"),
    sufficiency: {
      sufficient: sufficiency.sufficient,
      reason_code: text(sufficiency.reason_code, "sufficiency.reason_code"),
    },
    retrieval_config: {
      lexical_k: integer(config.lexical_k, "lexical_k"),
      semantic_k: integer(config.semantic_k, "semantic_k"),
      rrf_k: integer(config.rrf_k, "rrf_k", 1),
      evidence_chunk_limit: integer(config.evidence_chunk_limit, "evidence_chunk_limit", 1),
      evidence_char_limit: integer(config.evidence_char_limit, "evidence_char_limit", 1),
    },
    retrieved_results: list(input.retrieved_results, "retrieved_results").map(parseRetrieved),
    model_provider: text(input.model_provider, "model_provider"),
    model_identifier: text(input.model_identifier, "model_identifier"),
    prompt_template_version: text(input.prompt_template_version, "prompt_template_version"),
    provider_status: enumeration(input.provider_status, "provider_status", [
      "available",
      "unavailable",
      "not_called",
    ]),
    semantic_status: enumeration(input.semantic_status, "semantic_status", [
      "available",
      "unavailable",
    ]),
    created_at: utcDate(input.created_at),
  };
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

function parseCitation(value: unknown): Citation {
  const input = object(value);
  const charStart = integer(input.char_start, "char_start");
  const charEnd = integer(input.char_end, "char_end", 1);
  if (charEnd <= charStart) throw new TypeError("Citation offsets are invalid");
  return {
    citation_id: uuid(input.citation_id, "citation_id"),
    chunk_id: uuid(input.chunk_id, "chunk_id"),
    source_id: uuid(input.source_id, "source_id"),
    char_start: charStart,
    char_end: charEnd,
  };
}

type EvidenceIdentity = Pick<RetrievedResult, "chunk_id" | "source_id">;

function isRetrieved(evidence: EvidenceIdentity, retrieved: RetrievedResult[]): boolean {
  return retrieved.some(
    (result) => result.chunk_id === evidence.chunk_id && result.source_id === evidence.source_id,
  );
}

function assertRetrieved(citation: Citation, retrieved: RetrievedResult[]): void {
  if (!isRetrieved(citation, retrieved)) {
    throw new TypeError("Citation is not present in retrieved evidence");
  }
}

function parseProposalEvidence(value: unknown): EvidenceIdentity[] {
  const input = object(value);
  return list(input.evidence, "proposal.evidence").map((item) => {
    const evidence = object(item);
    return {
      chunk_id: uuid(evidence.chunk_id, "proposal.evidence.chunk_id"),
      source_id: uuid(evidence.source_id, "proposal.evidence.source_id"),
    };
  });
}

function parseStatements(value: unknown, retrieved: RetrievedResult[]): EvidenceStatement[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new TypeError("Grounded answer requires cited statements");
  }
  return value.map((item) => {
    const input = object(item);
    const citations = Array.isArray(input.citations) ? input.citations.map(parseCitation) : [];
    if (citations.length === 0) {
      throw new TypeError("Grounded statements require at least one validated citation");
    }
    for (const citation of citations) assertRetrieved(citation, retrieved);
    return {
      statement_id: uuid(input.statement_id, "statement_id"),
      text: text(input.text, "statement text"),
      citations,
    };
  });
}

function parseFallback(value: unknown, retrieved: RetrievedResult[]): ExtractiveFallback[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new TypeError("extractive_fallback must be a list");
  return value.map((item) => {
    const input = object(item);
    const citation = parseCitation(input.citation);
    assertRetrieved(citation, retrieved);
    return { text: text(input.text, "fallback text"), citation };
  });
}

function commentary(input: Record<string, unknown>): { system_commentary?: string } {
  if (input.system_commentary === undefined || input.system_commentary === null) return {};
  return { system_commentary: text(input.system_commentary, "system_commentary") };
}

export function parseAnswerRecord(value: unknown): AnswerRecord {
  const input = object(value);
  const status = text(input.status, "status");
  const base = parseBase(input);
  if (status === "grounded") {
    if (!base.sufficiency.sufficient || base.retrieved_results.length === 0) {
      throw new TypeError("Grounded status requires sufficient retrieved evidence");
    }
    return {
      ...base,
      status,
      evidence_supported_statements: parseStatements(
        input.evidence_supported_statements,
        base.retrieved_results,
      ),
      ...commentary(input),
    };
  }
  if (status === "insufficient_evidence") {
    if (base.sufficiency.sufficient)
      throw new TypeError("Insufficient evidence cannot be sufficient");
    if (!Array.isArray(input.evidence_supported_statements)) {
      throw new TypeError("Insufficient evidence requires an empty statements list");
    }
    if (input.evidence_supported_statements.length) {
      throw new TypeError("Insufficient evidence cannot contain generated statements");
    }
    return { ...base, status, evidence_supported_statements: [], ...commentary(input) };
  }
  if (status === "validation_failed") {
    if (base.sufficiency.sufficient) throw new TypeError("Validation failure cannot be sufficient");
    return {
      ...base,
      status,
      extractive_fallback: parseFallback(input.extractive_fallback, base.retrieved_results),
    };
  }
  if (status === "provider_unavailable") {
    if (base.sufficiency.sufficient)
      throw new TypeError("Provider unavailable cannot be sufficient");
    if (
      !Array.isArray(input.evidence_supported_statements) ||
      input.evidence_supported_statements.length > 0
    ) {
      throw new TypeError("Provider unavailable cannot contain generated statements");
    }
    return { ...base, status, evidence_supported_statements: [], ...commentary(input) };
  }
  throw new TypeError("Answer status is invalid");
}

export function safeParseAnswerRecord(value: unknown): AnswerRecord | null {
  try {
    return parseAnswerRecord(value);
  } catch {
    return null;
  }
}

export function parseAnswerPayload(value: unknown): AnswerPayload {
  const input = object(value);
  const answer = parseAnswerRecord(input);
  const parsedProposal =
    input.proposed_memory === null
      ? null
      : {
          memory: parseAnswerMemoryProposal(input.proposed_memory),
          evidence: parseProposalEvidence(input.proposed_memory),
        };
  const proposal = parsedProposal?.memory ?? null;
  if (answer.status !== "grounded" && proposal !== null) {
    throw new TypeError("Only a grounded answer may include a proposed memory");
  }
  if (
    parsedProposal?.evidence.some((evidence) => !isRetrieved(evidence, answer.retrieved_results))
  ) {
    throw new TypeError("Proposed memory evidence is not present in retrieved evidence");
  }
  return { ...answer, proposed_memory: proposal };
}
