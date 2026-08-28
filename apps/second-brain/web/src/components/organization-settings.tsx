"use client";

import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";

import { apiRequest, formatApiError } from "@/lib/browser-api";
import type { Project, Tag } from "@/lib/product-contracts";
import {
  parseNoContent,
  parseProject,
  parseProjects,
  parseTag,
  parseTags,
} from "@/lib/resource-parsers";

export function OrganizationSettings() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [confirmation, setConfirmation] = useState<{
    kind: "projects" | "tags";
    id: string;
    name: string;
  } | null>(null);
  const confirmButtonRef = useRef<HTMLButtonElement>(null);
  const deleteButtonRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const restoreFocusKey = useRef<string | null>(null);

  const load = useCallback(async () => {
    const [nextProjects, nextTags] = await Promise.all([
      apiRequest("/projects", { parse: parseProjects }),
      apiRequest("/tags", { parse: parseTags }),
    ]);
    setProjects(nextProjects);
    setTags(nextTags);
  }, []);

  useEffect(() => {
    load().catch((caught) => setError(formatApiError(caught)));
  }, [load]);

  useEffect(() => {
    if (confirmation) {
      confirmButtonRef.current?.focus();
      const handleEscape = (event: KeyboardEvent) => {
        if (event.key === "Escape") {
          event.preventDefault();
          restoreFocusKey.current = `${confirmation.kind}:${confirmation.id}`;
          setConfirmation(null);
        }
      };
      document.addEventListener("keydown", handleEscape);
      return () => document.removeEventListener("keydown", handleEscape);
    }
    const key = restoreFocusKey.current;
    if (key) {
      deleteButtonRefs.current[key]?.focus();
      restoreFocusKey.current = null;
    }
  }, [confirmation]);

  function closeConfirmation() {
    restoreFocusKey.current = confirmation ? `${confirmation.kind}:${confirmation.id}` : null;
    setConfirmation(null);
  }

  async function submitCreate(event: FormEvent<HTMLFormElement>, kind: "projects" | "tags") {
    event.preventDefault();
    const form = event.currentTarget;
    const name = String(new FormData(form).get("name") ?? "");
    try {
      await apiRequest(`/${kind}`, {
        method: "POST",
        body: { name },
        parse: (value) => (kind === "projects" ? parseProject(value) : parseTag(value)),
      });
      form.reset();
      setNotice(kind === "projects" ? "Project created." : "Tag created.");
      await load();
    } catch (caught) {
      setError(formatApiError(caught));
    }
  }

  async function updateProject(project: Project, form: HTMLFormElement) {
    const data = new FormData(form);
    try {
      await apiRequest(`/projects/${project.project_id}`, {
        method: "PATCH",
        body: { name: String(data.get("name")), is_active: data.get("is_active") === "on" },
        parse: parseProject,
      });
      setNotice("Project updated.");
      await load();
    } catch (caught) {
      setError(formatApiError(caught));
    }
  }

  async function renameTag(tag: Tag, form: HTMLFormElement) {
    try {
      await apiRequest(`/tags/${tag.tag_id}`, {
        method: "PATCH",
        body: { name: String(new FormData(form).get("name")) },
        parse: parseTag,
      });
      setNotice("Tag updated.");
      await load();
    } catch (caught) {
      setError(formatApiError(caught));
    }
  }

  async function remove(kind: "projects" | "tags", id: string) {
    try {
      await apiRequest(`/${kind}/${id}`, { method: "DELETE", parse: parseNoContent });
      setConfirmation(null);
      setNotice(kind === "projects" ? "Project deleted." : "Tag deleted.");
      await load();
    } catch (caught) {
      setError(formatApiError(caught));
    }
  }

  return (
    <div className="settings-grid">
      {error ? (
        <p className="error-message" role="alert">
          {error}
        </p>
      ) : null}
      {notice ? <p role="status">{notice}</p> : null}
      <section className="detail-panel" aria-labelledby="projects-heading">
        <h2 id="projects-heading">Projects</h2>
        <form className="inline-form" onSubmit={(event) => void submitCreate(event, "projects")}>
          <label>
            New project name
            <input maxLength={200} name="name" required />
          </label>
          <button type="submit">Create project</button>
        </form>
        <ul className="settings-list">
          {projects.map((project) => (
            <li key={project.project_id}>
              <form
                className="inline-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  void updateProject(project, event.currentTarget);
                }}
              >
                <label>
                  Project name
                  <input defaultValue={project.name} maxLength={200} name="name" required />
                </label>
                <label className="checkbox-label">
                  <input defaultChecked={project.is_active} name="is_active" type="checkbox" />
                  Active
                </label>
                <div className="button-row">
                  <button type="submit">Save project</button>
                  <button
                    className="danger-button"
                    onClick={() =>
                      setConfirmation({
                        kind: "projects",
                        id: project.project_id,
                        name: project.name,
                      })
                    }
                    ref={(node) => {
                      deleteButtonRefs.current[`projects:${project.project_id}`] = node;
                    }}
                    type="button"
                  >
                    Delete project
                  </button>
                </div>
              </form>
              {confirmation?.kind === "projects" && confirmation.id === project.project_id ? (
                <dialog
                  aria-label={`Confirm deletion of project ${project.name}`}
                  open
                  role="alertdialog"
                >
                  <p>Delete project “{project.name}”?</p>
                  <button
                    className="danger-button"
                    onClick={() => void remove("projects", project.project_id)}
                    ref={confirmButtonRef}
                    type="button"
                  >
                    Confirm delete project {project.name}
                  </button>
                  <button onClick={closeConfirmation} type="button">
                    Cancel
                  </button>
                </dialog>
              ) : null}
            </li>
          ))}
        </ul>
      </section>
      <section className="detail-panel" aria-labelledby="tags-heading">
        <h2 id="tags-heading">Tags</h2>
        <form className="inline-form" onSubmit={(event) => void submitCreate(event, "tags")}>
          <label>
            New tag name
            <input maxLength={200} name="name" required />
          </label>
          <button type="submit">Create tag</button>
        </form>
        <ul className="settings-list">
          {tags.map((tag) => (
            <li key={tag.tag_id}>
              <form
                className="inline-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  void renameTag(tag, event.currentTarget);
                }}
              >
                <label>
                  Tag name
                  <input defaultValue={tag.name} maxLength={200} name="name" required />
                </label>
                <div className="button-row">
                  <button type="submit">Save tag</button>
                  <button
                    className="danger-button"
                    onClick={() =>
                      setConfirmation({ kind: "tags", id: tag.tag_id, name: tag.name })
                    }
                    ref={(node) => {
                      deleteButtonRefs.current[`tags:${tag.tag_id}`] = node;
                    }}
                    type="button"
                  >
                    Delete tag
                  </button>
                </div>
              </form>
              {confirmation?.kind === "tags" && confirmation.id === tag.tag_id ? (
                <dialog aria-label={`Confirm deletion of tag ${tag.name}`} open role="alertdialog">
                  <p>Delete tag “{tag.name}”?</p>
                  <button
                    className="danger-button"
                    onClick={() => void remove("tags", tag.tag_id)}
                    ref={confirmButtonRef}
                    type="button"
                  >
                    Confirm delete tag {tag.name}
                  </button>
                  <button onClick={closeConfirmation} type="button">
                    Cancel
                  </button>
                </dialog>
              ) : null}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
