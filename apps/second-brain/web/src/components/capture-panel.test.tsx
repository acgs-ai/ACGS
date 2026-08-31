import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { axe } from "jest-axe";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { CapturePanel } from "./capture-panel";

describe("CapturePanel", () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it("captures a note and exposes the durable job state", async () => {
    const sourceId = crypto.randomUUID();
    const jobId = crypto.randomUUID();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/projects?active_only=true") || url.endsWith("/tags")) {
        return new Response("[]", { status: 200 });
      }
      if (url.endsWith("/captures/text")) {
        return new Response(
          JSON.stringify({
            source_id: sourceId,
            source_version_id: null,
            job_id: jobId,
            state: "queued",
            duplicate: false,
          }),
          { status: 202 },
        );
      }
      return new Response(
        JSON.stringify({
          id: jobId,
          source_id: sourceId,
          state: "ready",
          attempts: 1,
          error_code: null,
          error_message: null,
        }),
        { status: 200 },
      );
    });

    const { container } = render(<CapturePanel />);
    fireEvent.change(screen.getByLabelText("Display title"), { target: { value: "Project note" } });
    fireEvent.change(screen.getByLabelText("Source content"), {
      target: { value: "Grounded evidence" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Capture source" }));

    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Source queued" })).toBeVisible(),
    );
    expect(screen.getByRole("link", { name: "Open source" })).toHaveAttribute(
      "href",
      `/library/${sourceId}`,
    );
    expect((await axe(container)).violations).toEqual([]);
  });
});
