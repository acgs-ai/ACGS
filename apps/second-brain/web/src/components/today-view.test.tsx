import { render, screen } from "@testing-library/react";
import { axe } from "jest-axe";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TodayView } from "./today-view";

describe("TodayView", () => {
  afterEach(() => vi.restoreAllMocks());

  it("renders exactly the five deterministic sections", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          as_of: new Date().toISOString(),
          recent_captures: { items: [], empty_message: "No recent captures" },
          failed_jobs: { items: [], empty_message: "No failed processing jobs" },
          recent_approved_memories: { items: [], empty_message: "No approved memories yet" },
          active_project_sources: { items: [], empty_message: "No active-project sources" },
          resurfacing: { items: [], empty_message: "Nothing scheduled to resurface today" },
        }),
        { status: 200 },
      ),
    );
    const { container } = render(<TodayView />);
    await screen.findByText("No recent captures");
    for (const heading of [
      "Sources added lately",
      "Jobs requiring attention",
      "Durable memories",
      "Relevant sources",
      "Review set",
    ])
      expect(screen.getByRole("heading", { name: heading })).toBeVisible();
    expect(screen.getAllByRole("heading", { level: 2 })).toHaveLength(5);
    expect((await axe(container)).violations).toEqual([]);
  });
});
