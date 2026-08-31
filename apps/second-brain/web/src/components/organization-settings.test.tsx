import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { axe } from "jest-axe";
import { afterEach, describe, expect, it, vi } from "vitest";

import { OrganizationSettings } from "./organization-settings";

describe("OrganizationSettings", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("creates projects without exposing configuration secrets", async () => {
    let projectCreated = false;
    const projectId = crypto.randomUUID();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      if (init?.method === "DELETE") {
        projectCreated = false;
        return new Response(null, { status: 204 });
      }
      if (init?.method === "POST") {
        projectCreated = true;
        return new Response(
          JSON.stringify({ project_id: projectId, name: "Research", is_active: true }),
          { status: 201 },
        );
      }
      if (url.endsWith("/tags")) return new Response("[]", { status: 200 });
      return new Response(
        JSON.stringify(
          projectCreated ? [{ project_id: projectId, name: "Research", is_active: true }] : [],
        ),
        { status: 200 },
      );
    });
    const { container } = render(<OrganizationSettings />);
    fireEvent.change(screen.getByLabelText("New project name"), { target: { value: "Research" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    await waitFor(() => expect(screen.getByText("Project created.")).toBeVisible());
    expect(screen.getByDisplayValue("Research")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Delete project" }));
    expect(screen.getByRole("alertdialog")).toHaveAccessibleName(
      "Confirm deletion of project Research",
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm delete project Research" }));
    await waitFor(() => expect(screen.getByText("Project deleted.")).toBeVisible());
    expect(container.textContent).not.toMatch(/password|api[_ -]?key|secret/i);
    expect((await axe(container)).violations).toEqual([]);
  });

  it("restores project and tag delete-button focus after Escape and Cancel", async () => {
    const projectId = crypto.randomUUID();
    const tagId = crypto.randomUUID();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/tags")) {
        return new Response(JSON.stringify([{ tag_id: tagId, name: "Evidence" }]), {
          status: 200,
        });
      }
      return new Response(
        JSON.stringify([{ project_id: projectId, name: "Research", is_active: true }]),
        { status: 200 },
      );
    });

    render(<OrganizationSettings />);
    const projectDelete = await screen.findByRole("button", { name: "Delete project" });
    fireEvent.click(projectDelete);
    const projectDialog = screen.getByRole("alertdialog", {
      name: "Confirm deletion of project Research",
    });
    expect(screen.getByRole("button", { name: "Confirm delete project Research" })).toHaveFocus();

    fireEvent.keyDown(projectDialog, { key: "Escape" });
    await waitFor(() => expect(projectDelete).toHaveFocus());

    const tagDelete = screen.getByRole("button", { name: "Delete tag" });
    fireEvent.click(tagDelete);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(tagDelete).toHaveFocus());
  });
});
