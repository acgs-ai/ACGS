import { render, screen } from "@testing-library/react";
import { axe } from "jest-axe";
import { describe, expect, it } from "vitest";

import { AppNavigation, ProductPage } from "./page-content";

describe("application shell", () => {
  it("provides every primary destination with accessible names", async () => {
    const { container } = render(<AppNavigation />);

    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
    for (const label of [
      "Today",
      "Inbox",
      "Library",
      "Search",
      "Ask",
      "Memories",
      "Memory review",
      "Settings",
    ]) {
      expect(screen.getByRole("link", { name: label })).toBeInTheDocument();
    }
    expect((await axe(container)).violations).toEqual([]);
  });

  it("labels unavailable capabilities without implying empty persisted data", async () => {
    const { container } = render(
      <ProductPage
        title="Inbox"
        eyebrow="Capture"
        description="Preserve source material and provenance."
        state={{
          label: "Capture unavailable",
          detail: "The capture endpoint is not implemented yet.",
        }}
      />,
    );

    expect(screen.getByRole("heading", { level: 1, name: "Inbox" })).toBeInTheDocument();
    expect(screen.getByText("Capture unavailable")).toBeInTheDocument();
    expect(screen.queryByText(/no sources/i)).not.toBeInTheDocument();
    expect((await axe(container)).violations).toEqual([]);
  });
});
