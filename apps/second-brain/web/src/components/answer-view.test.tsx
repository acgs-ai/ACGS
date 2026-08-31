import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AnswerView } from "./answer-view";

describe("AnswerView", () => {
  it("does not render generated statements from a validation-failed payload", () => {
    const answer = {
      status: "validation_failed",
      answer_id: crypto.randomUUID(),
      retrieval_run_id: crypto.randomUUID(),
      query: "question",
      sufficiency: { sufficient: false, reason_code: "citation_invalid" },
      evidence_supported_statements: [
        { statement_id: crypto.randomUUID(), text: "Unvalidated generated claim", citations: [] },
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
    };

    render(<AnswerView answer={answer} />);

    expect(screen.getByText("Citation validation failed")).toBeInTheDocument();
    expect(screen.queryByText("Unvalidated generated claim")).not.toBeInTheDocument();
  });

  it("fails closed for fabricated, unretrieved, and traversal-shaped citations", () => {
    const sourceId = "../../outside";
    const chunkId = crypto.randomUUID();
    const view = render(
      <AnswerView
        answer={{
          status: "grounded",
          answer_id: crypto.randomUUID(),
          retrieval_run_id: crypto.randomUUID(),
          query: "question",
          sufficiency: { sufficient: true, reason_code: "claimed" },
          evidence_supported_statements: [
            {
              statement_id: crypto.randomUUID(),
              text: "Fabricated claim",
              citations: [
                {
                  citation_id: crypto.randomUUID(),
                  chunk_id: chunkId,
                  source_id: sourceId,
                  char_start: 0,
                  char_end: 10,
                },
              ],
            },
          ],
          retrieved_results: [
            { chunk_id: crypto.randomUUID(), source_id: crypto.randomUUID(), fused_rank: 1 },
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
        }}
      />,
    );

    const rejected = within(view.container);
    expect(rejected.getByText("Answer contract rejected")).toBeInTheDocument();
    expect(rejected.getByText("Citation unavailable")).toBeInTheDocument();
    expect(rejected.queryByText("Fabricated claim")).not.toBeInTheDocument();
    expect(rejected.queryByRole("link", { name: "Inspect evidence" })).not.toBeInTheDocument();
  });

  it("labels provider outage without presenting a generated answer", () => {
    render(
      <AnswerView
        answer={{
          status: "provider_unavailable",
          answer_id: crypto.randomUUID(),
          retrieval_run_id: crypto.randomUUID(),
          conversation_id: null,
          query: "question",
          sufficiency: { sufficient: false, reason_code: "provider_unavailable" },
          evidence_supported_statements: [],
          retrieved_results: [],
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
          system_commentary: "The generation provider is unavailable.",
          extractive_fallback: null,
          created_at: new Date().toISOString(),
        }}
      />,
    );

    expect(screen.getByText("Provider unavailable")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Answer generation unavailable" })).toBeVisible();
    expect(screen.queryByText("Grounded answer")).not.toBeInTheDocument();
  });
});
