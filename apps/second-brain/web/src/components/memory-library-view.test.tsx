import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { axe } from "jest-axe";
import { afterEach, describe, expect, it, vi } from "vitest";

import { MemoryLibraryView } from "./memory-library-view";

describe("MemoryLibraryView", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  function memoryPayload(memoryId: string, proposalId: string, revisionId: string) {
    return {
      memory_id: memoryId,
      status: "active",
      approved_at: new Date().toISOString(),
      supersedes_memory_id: null,
      superseded_by_id: null,
      revision_id: revisionId,
      revision_number: 1,
      statement: "Approved evidence",
      category: "reference",
      confidence: 1,
      evidence_quality: "high",
      proposal_id: proposalId,
    };
  }

  function memoryDetail(memoryId: string, proposalId: string, revisionId: string) {
    return {
      memory_id: memoryId,
      proposal_id: proposalId,
      status: "active",
      approved_at: new Date().toISOString(),
      supersedes_memory_id: null,
      superseded_by_id: null,
      revisions: [
        {
          revision_id: revisionId,
          revision_number: 1,
          statement: "Approved evidence",
          category: "reference",
          confidence: 1,
          evidence_quality: "high",
          created_at: new Date().toISOString(),
          source_chunk_ids: [crypto.randomUUID()],
        },
      ],
    };
  }

  function terminalPurge(operationId: string, memoryId: string) {
    const now = new Date().toISOString();
    return {
      operation_id: operationId,
      resource_type: "memory",
      resource_id: memoryId,
      state: "complete",
      attempts: 1,
      error_class: null,
      created_at: now,
      finished_at: now,
      events: [],
    };
  }

  it("shows lineage and creates append-only revisions", async () => {
    const memoryId = crypto.randomUUID();
    const proposalId = crypto.randomUUID();
    const revisionId = crypto.randomUUID();
    const chunkId = crypto.randomUUID();
    const purgeOperationId = crypto.randomUUID();
    let revised = false;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      if (init?.method === "POST" && url.endsWith("/purge")) {
        return new Response(JSON.stringify({ operation_id: purgeOperationId, state: "queued" }), {
          status: 202,
        });
      }
      if (init?.method === "POST") {
        revised = true;
        return new Response(
          JSON.stringify({
            memory_id: memoryId,
            proposal_id: proposalId,
            status: "active",
            approved_at: new Date().toISOString(),
            supersedes_memory_id: null,
            superseded_by_id: null,
            revision_id: revisionId,
            revision_number: 2,
            normalized_statement: "Revised evidence",
            category: "reference",
            confidence: 1,
            evidence_quality_label: "high",
          }),
          { status: 200 },
        );
      }
      if (url.endsWith(`/memories/${memoryId}`))
        return new Response(
          JSON.stringify({
            memory_id: memoryId,
            proposal_id: proposalId,
            status: "active",
            approved_at: new Date().toISOString(),
            supersedes_memory_id: null,
            superseded_by_id: null,
            revisions: [
              {
                revision_id: revisionId,
                revision_number: revised ? 2 : 1,
                statement: revised ? "Revised evidence" : "Approved evidence",
                category: "reference",
                confidence: 1,
                evidence_quality: "high",
                created_at: new Date().toISOString(),
                source_chunk_ids: [chunkId],
              },
            ],
          }),
          { status: 200 },
        );
      return new Response(
        JSON.stringify([
          {
            memory_id: memoryId,
            status: "active",
            approved_at: new Date().toISOString(),
            supersedes_memory_id: null,
            superseded_by_id: null,
            revision_id: revisionId,
            revision_number: revised ? 2 : 1,
            statement: revised ? "Revised evidence" : "Approved evidence",
            category: "reference",
            confidence: 1,
            evidence_quality: "high",
          },
        ]),
        { status: 200 },
      );
    });

    const { container } = render(<MemoryLibraryView />);
    await screen.findByRole("heading", { name: "Approved evidence" });
    fireEvent.click(screen.getByText("Add revision", { selector: "summary" }));
    fireEvent.change(screen.getByLabelText("Statement"), { target: { value: "Revised evidence" } });
    fireEvent.click(screen.getByRole("button", { name: "Add revision" }));
    await waitFor(() => expect(screen.getByText("Approved memory revision added.")).toBeVisible());
    fireEvent.click(screen.getByText("Revision and source lineage", { selector: "summary" }));
    expect(screen.getByText(chunkId)).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Request purge" }));
    expect(screen.getByRole("alertdialog")).toHaveAccessibleName(
      "Confirm purge of memory Revised evidence",
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm purge Revised evidence" }));
    expect(await screen.findByText(/Purge queued/)).toHaveTextContent(purgeOperationId);
    expect((await axe(container)).violations).toEqual([]);
  });

  it("fails closed when terminal purge identity does not match the memory", async () => {
    const memoryId = crypto.randomUUID();
    const proposalId = crypto.randomUUID();
    const revisionId = crypto.randomUUID();
    const operationId = crypto.randomUUID();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      if (init?.method === "POST")
        return new Response(JSON.stringify({ operation_id: operationId, state: "complete" }), {
          status: 202,
        });
      if (url.endsWith(`/purges/${operationId}`))
        return new Response(JSON.stringify(terminalPurge(operationId, crypto.randomUUID())), {
          status: 200,
        });
      if (url.endsWith(`/memories/${memoryId}`))
        return new Response(JSON.stringify(memoryDetail(memoryId, proposalId, revisionId)), {
          status: 200,
        });
      return new Response(JSON.stringify([memoryPayload(memoryId, proposalId, revisionId)]), {
        status: 200,
      });
    });

    render(<MemoryLibraryView />);
    await screen.findByRole("heading", { name: "Approved evidence" });
    fireEvent.click(screen.getByRole("button", { name: "Request purge" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm purge Approved evidence" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The service returned an invalid response.",
    );
    expect(screen.getByRole("heading", { name: "Approved evidence" })).toBeVisible();
  });

  it("resolves and applies an immediate terminal memory purge replay", async () => {
    const memoryId = crypto.randomUUID();
    const proposalId = crypto.randomUUID();
    const revisionId = crypto.randomUUID();
    const operationId = crypto.randomUUID();
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      if (init?.method === "POST")
        return new Response(JSON.stringify({ operation_id: operationId, state: "complete" }), {
          status: 202,
        });
      if (url.endsWith(`/purges/${operationId}`))
        return new Response(JSON.stringify(terminalPurge(operationId, memoryId)), { status: 200 });
      if (url.endsWith(`/memories/${memoryId}`))
        return new Response(JSON.stringify(memoryDetail(memoryId, proposalId, revisionId)), {
          status: 200,
        });
      return new Response(JSON.stringify([memoryPayload(memoryId, proposalId, revisionId)]), {
        status: 200,
      });
    });

    render(<MemoryLibraryView />);
    await screen.findByRole("heading", { name: "Approved evidence" });
    fireEvent.click(screen.getByRole("button", { name: "Request purge" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm purge Approved evidence" }));

    await waitFor(() =>
      expect(screen.queryByRole("heading", { name: "Approved evidence" })).not.toBeInTheDocument(),
    );
    expect(
      fetchMock.mock.calls.some(([url]) => String(url).endsWith(`/purges/${operationId}`)),
    ).toBe(true);
  });

  it("restores memory purge-button focus after Escape and Cancel", async () => {
    const memoryId = crypto.randomUUID();
    const proposalId = crypto.randomUUID();
    const revisionId = crypto.randomUUID();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith(`/memories/${memoryId}`))
        return new Response(JSON.stringify(memoryDetail(memoryId, proposalId, revisionId)), {
          status: 200,
        });
      return new Response(JSON.stringify([memoryPayload(memoryId, proposalId, revisionId)]), {
        status: 200,
      });
    });

    render(<MemoryLibraryView />);
    const requestPurge = await screen.findByRole("button", { name: "Request purge" });
    fireEvent.click(requestPurge);
    const dialog = screen.getByRole("alertdialog");
    expect(screen.getByRole("button", { name: "Confirm purge Approved evidence" })).toHaveFocus();

    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Request purge" })).toHaveFocus(),
    );

    fireEvent.click(screen.getByRole("button", { name: "Request purge" }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Request purge" })).toHaveFocus(),
    );
  });
});
