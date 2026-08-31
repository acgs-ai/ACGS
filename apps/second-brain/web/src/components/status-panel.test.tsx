import { render, screen } from "@testing-library/react";
import { axe } from "jest-axe";
import { describe, expect, it } from "vitest";

import { StatusPanel } from "./status-panel";

describe("StatusPanel", () => {
  it("shows safe provider metadata when the service is ready", async () => {
    const { container } = render(
      <StatusPanel
        status={{
          kind: "available",
          service: "second-brain",
          database: "available",
          storage: "filesystem",
          modelProvider: "fake",
          embeddingProviderStatus: "available",
          generationProviderStatus: "unavailable",
          maxUploadBytes: 10_000_000,
          maxExtractedChars: 2_000_000,
          maxChunks: 5_000,
          maxProcessingSeconds: 30,
        }}
      />,
    );

    expect(screen.getByText("Service ready")).toBeInTheDocument();
    expect(screen.getByText("filesystem")).toBeInTheDocument();
    expect(screen.getByText("fake")).toBeInTheDocument();
    expect(screen.getByText("10,000,000 bytes")).toBeInTheDocument();
    expect(screen.getByText("unavailable")).toBeInTheDocument();
    expect(screen.getByText(/local adapter state, not remote health/i)).toBeInTheDocument();
    expect((await axe(container)).violations).toEqual([]);
  });

  it("reports an explicit outage without rendering raw upstream details", () => {
    render(<StatusPanel status={{ kind: "unavailable", reason: "service_unavailable" }} />);

    expect(screen.getByText("Service unavailable")).toBeInTheDocument();
    expect(
      screen.getByText(/Capture, retrieval, Ask, and memory actions remain unavailable/),
    ).toBeInTheDocument();
  });
});
