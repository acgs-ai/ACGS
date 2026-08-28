import { fireEvent, render, screen } from "@testing-library/react";
import { axe } from "jest-axe";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AskView } from "./ask-view";

describe("AskView", () => {
  afterEach(() => vi.restoreAllMocks());

  it("renders grounded statements, exact citations, and an inactive proposal", async () => {
    const sourceId = crypto.randomUUID();
    const chunkId = crypto.randomUUID();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/projects") || url.endsWith("/tags"))
        return new Response("[]", { status: 200 });
      return new Response(
        JSON.stringify({
          status: "grounded",
          answer_id: crypto.randomUUID(),
          retrieval_run_id: crypto.randomUUID(),
          conversation_id: null,
          query: "What?",
          sufficiency: { sufficient: true, reason_code: "evidence_available" },
          evidence_supported_statements: [
            {
              statement_id: crypto.randomUUID(),
              text: "The evidence supports this.",
              citations: [
                {
                  citation_id: crypto.randomUUID(),
                  chunk_id: chunkId,
                  source_id: sourceId,
                  char_start: 0,
                  char_end: 12,
                },
              ],
            },
          ],
          retrieved_results: [
            {
              chunk_id: chunkId,
              source_id: sourceId,
              lexical_rank: 1,
              semantic_rank: 1,
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
          model_provider: "FakeGenerationProvider",
          model_identifier: "deterministic",
          prompt_template_version: "grounded-answer-v1",
          provider_status: "available",
          semantic_status: "available",
          system_commentary: null,
          extractive_fallback: null,
          created_at: new Date().toISOString(),
          proposed_memory: {
            proposal_id: crypto.randomUUID(),
            statement: "Durable evidence statement",
            category: "reference",
            confidence: 1,
            evidence_quality: "high",
            status: "proposed",
            proposed_at: new Date().toISOString(),
            decided_at: null,
            evidence: [
              {
                chunk_id: chunkId,
                source_id: sourceId,
                source_version_id: crypto.randomUUID(),
              },
            ],
          },
        }),
        { status: 200 },
      );
    });

    const { container } = render(<AskView />);
    fireEvent.change(screen.getByLabelText("Question"), { target: { value: "What?" } });
    fireEvent.click(screen.getByRole("button", { name: "Ask from sources" }));
    expect(await screen.findByText("The evidence supports this.")).toBeVisible();
    expect(screen.getByRole("link", { name: "Inspect evidence" })).toHaveAttribute(
      "href",
      `/library/${sourceId}?chunk=${chunkId}&start=0&end=12`,
    );
    expect(screen.getByText("Proposed memory · inactive")).toBeVisible();
    expect((await axe(container)).violations).toEqual([]);
  });
});
