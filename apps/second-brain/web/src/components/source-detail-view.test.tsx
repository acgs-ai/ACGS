import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { axe } from "jest-axe";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SourceDetailView } from "./source-detail-view";

describe("SourceDetailView", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  function mockSourceDetail({
    sourceId,
    chunkId,
    contextSourceId = sourceId,
    contextChunkId = chunkId,
  }: {
    sourceId: string;
    chunkId: string;
    contextSourceId?: string;
    contextChunkId?: string;
  }) {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/projects") || url.endsWith("/tags"))
        return new Response("[]", { status: 200 });
      if (url.includes("/context/"))
        return new Response(
          JSON.stringify({
            source_id: contextSourceId,
            display_title: "Source",
            source_version_id: crypto.randomUUID(),
            version_number: 1,
            chunk_id: contextChunkId,
            chunk_text: "support",
            char_start: 107,
            char_end: 114,
            page_number: null,
            section: null,
            paragraph_number: 1,
            location: {},
            chunker_version: "v1",
            context_text: "before support after",
            context_char_start: 100,
            context_char_end: 120,
          }),
          { status: 200 },
        );
      return new Response(
        JSON.stringify({
          source_id: sourceId,
          display_title: "Source",
          source_type: "note",
          processing_state: "ready",
          project_id: null,
          project_name: null,
          tag_ids: [],
          ingested_at: new Date().toISOString(),
          original_uri: null,
          object_key: null,
          original_filename: null,
          source_metadata: {},
          content_sha256: "a".repeat(64),
          mime_type: "text/plain",
          semantic_state: "available",
          processing_error_code: null,
          processing_error_message: null,
          tags: [],
          versions: [],
          documents: [
            {
              document_id: crypto.randomUUID(),
              source_version_id: crypto.randomUUID(),
              extracted_text: "before support after",
              character_count: 20,
              created_at: new Date().toISOString(),
            },
          ],
          chunks: [
            {
              chunk_id: chunkId,
              source_version_id: crypto.randomUUID(),
              ordinal: 0,
              chunk_text: "support",
              char_start: 107,
              char_end: 114,
              page_number: null,
              section: null,
              paragraph_number: 1,
              location: {},
              chunker_version: "v1",
            },
          ],
          jobs: [],
          ingestion_history: [],
        }),
        { status: 200 },
      );
    });
  }

  it("opens and focuses exact bounded citation context", async () => {
    const sourceId = crypto.randomUUID();
    const chunkId = crypto.randomUUID();
    mockSourceDetail({ sourceId, chunkId });

    const { container } = render(
      <SourceDetailView
        selectedChunkId={chunkId}
        selectedEnd={114}
        selectedStart={107}
        sourceId={sourceId}
      />,
    );
    const evidence = await screen.findByText("support", { selector: "mark" });
    expect(evidence.tagName).toBe("MARK");
    await waitFor(() => expect(evidence).toHaveFocus());
    expect(
      within(evidence.closest("section") as HTMLElement).getByText(/before/),
    ).toHaveTextContent("before support after");
    expect((await axe(container)).violations).toEqual([]);
  });

  it.each([
    ["source", { contextSourceId: crypto.randomUUID() }],
    ["chunk", { contextChunkId: crypto.randomUUID() }],
  ])("rejects context whose %s identity does not match the requested citation", async (_, ids) => {
    const sourceId = crypto.randomUUID();
    const chunkId = crypto.randomUUID();
    mockSourceDetail({ sourceId, chunkId, ...ids });

    render(
      <SourceDetailView
        selectedChunkId={chunkId}
        selectedEnd={114}
        selectedStart={107}
        sourceId={sourceId}
      />,
    );

    expect(await screen.findByText("Citation unavailable")).toBeVisible();
    expect(screen.queryByText("support", { selector: "mark" })).not.toBeInTheDocument();
  });
});
