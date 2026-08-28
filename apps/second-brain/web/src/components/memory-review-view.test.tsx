import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { axe } from "jest-axe";
import { afterEach, describe, expect, it, vi } from "vitest";

import { MemoryReviewView } from "./memory-review-view";

describe("MemoryReviewView", () => {
  afterEach(() => vi.restoreAllMocks());

  it("keeps proposals inactive until explicit approval", async () => {
    const proposalId = crypto.randomUUID();
    const memoryId = crypto.randomUUID();
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      if (init?.method === "POST")
        return new Response(
          JSON.stringify({
            memory_id: memoryId,
            proposal_id: proposalId,
            status: "active",
            approved_at: new Date().toISOString(),
            supersedes_memory_id: null,
            superseded_by_id: null,
            revision_id: crypto.randomUUID(),
            revision_number: 1,
            normalized_statement: "Review this evidence",
            category: "reference",
            confidence: 1,
            evidence_quality_label: "high",
          }),
          { status: 200 },
        );
      return new Response(
        JSON.stringify([
          {
            proposal_id: proposalId,
            statement: "Review this evidence",
            category: "reference",
            confidence: 1,
            evidence_quality: "high",
            status: "proposed",
            proposed_at: new Date().toISOString(),
            decided_at: null,
            source_chunk_ids: [crypto.randomUUID()],
          },
        ]),
        { status: 200 },
      );
    });

    const { container } = render(<MemoryReviewView />);
    expect(await screen.findByText("Proposed memory · inactive")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(screen.getByText("Proposed memory approved.")).toBeVisible());
    expect(
      fetchMock.mock.calls.some(([url]) =>
        String(url).endsWith(`/memory-proposals/${proposalId}/approve`),
      ),
    ).toBe(true);
    expect((await axe(container)).violations).toEqual([]);
  });
});
