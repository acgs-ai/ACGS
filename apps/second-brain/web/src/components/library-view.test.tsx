import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { axe } from "jest-axe";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { LibraryView } from "./library-view";

describe("LibraryView", () => {
  beforeEach(() => {
    cleanup();
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  function source(sourceId: string) {
    return {
      source_id: sourceId,
      display_title: "Evidence note",
      source_type: "note",
      processing_state: "ready",
      project_id: null,
      project_name: null,
      tag_ids: [],
      ingested_at: new Date().toISOString(),
    };
  }

  function terminalStatus(operationId: string, sourceId: string) {
    const now = new Date().toISOString();
    return {
      operation_id: operationId,
      resource_type: "source",
      resource_id: sourceId,
      state: "complete",
      attempts: 1,
      error_class: null,
      created_at: now,
      finished_at: now,
      events: [],
    };
  }

  it("lists scoped sources and requests purge explicitly", async () => {
    const sourceId = crypto.randomUUID();
    const operationId = crypto.randomUUID();
    let finishStatus: ((response: Response) => void) | undefined;
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("/projects") || url.endsWith("/tags"))
        return new Response("[]", { status: 200 });
      if (url.endsWith("/purge"))
        return new Response(JSON.stringify({ operation_id: operationId, state: "queued" }), {
          status: 202,
        });
      if (url.endsWith(`/purges/${operationId}`))
        return new Promise<Response>((resolve) => {
          finishStatus = resolve;
        });
      return new Response(JSON.stringify([source(sourceId)]), { status: 200 });
    });

    const { container } = render(<LibraryView />);
    await screen.findByRole("link", { name: "Evidence note" });
    fireEvent.click(screen.getByRole("button", { name: "Request purge" }));
    expect(screen.getByRole("alertdialog")).toHaveTextContent("Evidence note");
    fireEvent.click(screen.getByRole("button", { name: "Confirm purge Evidence note" }));
    expect(await screen.findByText(/Purge queued/)).toHaveTextContent(operationId);
    expect(screen.getByRole("link", { name: "Evidence note" })).toBeVisible();
    await waitFor(() => expect(finishStatus).toBeTypeOf("function"));
    finishStatus?.(
      new Response(
        JSON.stringify({
          operation_id: operationId,
          resource_type: "source",
          resource_id: sourceId,
          state: "complete",
          attempts: 1,
          error_class: null,
          created_at: new Date().toISOString(),
          finished_at: new Date().toISOString(),
          events: [
            {
              attempt: 1,
              from_state: "processing",
              to_state: "complete",
              reason_class: "purge_completed",
              occurred_at: new Date().toISOString(),
            },
          ],
        }),
        { status: 200 },
      ),
    );
    await waitFor(() =>
      expect(screen.queryByRole("link", { name: "Evidence note" })).not.toBeInTheDocument(),
    );
    expect(
      fetchMock.mock.calls.some(([url]) => String(url).endsWith(`/sources/${sourceId}/purge`)),
    ).toBe(true);
    expect((await axe(container)).violations).toEqual([]);
  });

  it("fails closed when polled purge identity does not match the source operation", async () => {
    const sourceId = crypto.randomUUID();
    const operationId = crypto.randomUUID();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith("/projects") || url.endsWith("/tags"))
        return new Response("[]", { status: 200 });
      if (init?.method === "POST")
        return new Response(JSON.stringify({ operation_id: operationId, state: "queued" }), {
          status: 202,
        });
      if (url.endsWith(`/purges/${operationId}`))
        return new Response(JSON.stringify(terminalStatus(operationId, crypto.randomUUID())), {
          status: 200,
        });
      return new Response(JSON.stringify([source(sourceId)]), { status: 200 });
    });

    render(<LibraryView />);
    await screen.findByRole("link", { name: "Evidence note" });
    fireEvent.click(screen.getByRole("button", { name: "Request purge" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm purge Evidence note" }));

    expect(await screen.findByText(/Purge status polling interrupted/)).toBeVisible();
    expect(screen.getByRole("link", { name: "Evidence note" })).toBeVisible();
  });

  it("resolves and applies an immediate terminal purge replay", async () => {
    const sourceId = crypto.randomUUID();
    const operationId = crypto.randomUUID();
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.endsWith("/projects") || url.endsWith("/tags"))
        return new Response("[]", { status: 200 });
      if (init?.method === "POST")
        return new Response(JSON.stringify({ operation_id: operationId, state: "complete" }), {
          status: 202,
        });
      if (url.endsWith(`/purges/${operationId}`))
        return new Response(JSON.stringify(terminalStatus(operationId, sourceId)), { status: 200 });
      return new Response(JSON.stringify([source(sourceId)]), { status: 200 });
    });

    render(<LibraryView />);
    await screen.findByRole("link", { name: "Evidence note" });
    fireEvent.click(screen.getByRole("button", { name: "Request purge" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm purge Evidence note" }));

    await waitFor(() =>
      expect(screen.queryByRole("link", { name: "Evidence note" })).not.toBeInTheDocument(),
    );
    expect(
      fetchMock.mock.calls.some(([url]) => String(url).endsWith(`/purges/${operationId}`)),
    ).toBe(true);
  });

  it("restores purge-button focus after Escape and Cancel", async () => {
    const sourceId = crypto.randomUUID();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/projects") || url.endsWith("/tags"))
        return new Response("[]", { status: 200 });
      return new Response(JSON.stringify([source(sourceId)]), { status: 200 });
    });

    render(<LibraryView />);
    const requestPurge = await screen.findByRole("button", { name: "Request purge" });
    fireEvent.click(requestPurge);
    const dialog = screen.getByRole("alertdialog");
    expect(screen.getByRole("button", { name: "Confirm purge Evidence note" })).toHaveFocus();

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
