import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { axe } from "jest-axe";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SearchView } from "./search-view";

describe("SearchView", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("shows lexical fallback and stable evidence links", async () => {
    const sourceId = crypto.randomUUID();
    const chunkId = crypto.randomUUID();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/projects") || url.endsWith("/tags"))
        return new Response("[]", { status: 200 });
      return new Response(
        JSON.stringify({
          semantic_status: "unavailable",
          results: [
            {
              chunk_id: chunkId,
              source_id: sourceId,
              display_title: "Evidence source",
              source_type: "txt",
              excerpt: "matching evidence",
              char_start: 12,
              char_end: 29,
              page_number: null,
              section: null,
              paragraph_number: 1,
              location: {},
              project_id: null,
              tags: [],
              ingested_at: new Date().toISOString(),
              lexical_rank: 1,
              lexical_score: 0.9,
              semantic_rank: null,
              semantic_score: null,
              fused_rank: 1,
              fused_score: 0.016,
            },
          ],
        }),
        { status: 200 },
      );
    });

    const { container } = render(<SearchView />);
    fireEvent.change(screen.getByLabelText("Search evidence"), { target: { value: "matching" } });
    fireEvent.click(screen.getByRole("button", { name: "Search sources" }));
    expect(await screen.findByText(/Semantic retrieval is unavailable/)).toBeVisible();
    expect(screen.getByRole("link", { name: "Evidence source" })).toHaveAttribute(
      "href",
      `/library/${sourceId}?chunk=${chunkId}&start=12&end=29`,
    );
    expect(screen.getByText("matching evidence")).toBeVisible();
    expect((await axe(container)).violations).toEqual([]);
  });

  it("fails closed for a legacy bare-list search response", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/projects") || url.endsWith("/tags")) {
        return new Response("[]", { status: 200 });
      }
      return new Response("[]", { status: 200 });
    });

    render(<SearchView />);
    fireEvent.change(screen.getByLabelText("Search evidence"), { target: { value: "missing" } });
    fireEvent.click(screen.getByRole("button", { name: "Search sources" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The service returned an invalid response.",
    );
    expect(screen.queryByText("No source passages matched.")).not.toBeInTheDocument();
  });
});
