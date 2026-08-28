"use client";

import Link from "next/link";
import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";

import { apiRequest, formatApiError } from "@/lib/browser-api";
import type {
  Project,
  PurgeRequestResult,
  PurgeStatus,
  SourceSummary,
  Tag,
} from "@/lib/product-contracts";
import {
  parseBoundPurgeStatus,
  parseProjects,
  parsePurgeRequest,
  parseSourceSummaries,
  parseTags,
} from "@/lib/resource-parsers";

export function LibraryView() {
  const [sources, setSources] = useState<SourceSummary[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [purges, setPurges] = useState<Record<string, PurgeStatus | PurgeRequestResult>>({});
  const confirmButtonRef = useRef<HTMLButtonElement>(null);
  const purgeButtonRefs = useRef<Record<string, HTMLButtonElement>>({});
  const restoreFocusId = useRef<string | null>(null);

  const load = useCallback(async (query = "") => {
    setLoading(true);
    setError("");
    try {
      const [nextSources, nextProjects, nextTags] = await Promise.all([
        apiRequest(`/sources${query}`, { parse: parseSourceSummaries }),
        apiRequest("/projects", { parse: parseProjects }),
        apiRequest("/tags", { parse: parseTags }),
      ]);
      setSources(nextSources);
      setProjects(nextProjects);
      setTags(nextTags);
    } catch (caught) {
      setError(formatApiError(caught));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (confirmingId) {
      confirmButtonRef.current?.focus();
      const handleEscape = (event: KeyboardEvent) => {
        if (event.key === "Escape") {
          event.preventDefault();
          restoreFocusId.current = confirmingId;
          setConfirmingId(null);
        }
      };
      document.addEventListener("keydown", handleEscape);
      return () => document.removeEventListener("keydown", handleEscape);
    }
    const sourceId = restoreFocusId.current;
    if (sourceId) {
      purgeButtonRefs.current[sourceId]?.focus();
      restoreFocusId.current = null;
    }
  }, [confirmingId]);

  function closeConfirmation(): void {
    restoreFocusId.current = confirmingId;
    setConfirmingId(null);
  }

  useEffect(() => {
    const active = Object.entries(purges).filter(([, operation]) =>
      ["queued", "processing"].includes(operation.state),
    );
    if (active.length === 0) return;
    let mounted = true;
    const timer = window.setInterval(() => {
      for (const [sourceId, operation] of active) {
        apiRequest(`/purges/${operation.operation_id}`, {
          parse: (value) =>
            parseBoundPurgeStatus(value, {
              operationId: operation.operation_id,
              resourceType: "source",
              resourceId: sourceId,
            }),
        })
          .then((status) => {
            if (!mounted) return;
            setPurges((current) => ({ ...current, [sourceId]: status }));
            if (status.state === "complete") {
              setSources((current) => current.filter((item) => item.source_id !== sourceId));
            }
          })
          .catch((caught) => {
            if (mounted) {
              window.clearInterval(timer);
              setError(`Purge status polling interrupted. ${formatApiError(caught)}`);
            }
          });
      }
    }, 500);
    return () => {
      mounted = false;
      window.clearInterval(timer);
    };
  }, [purges]);

  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const params = new URLSearchParams();
    for (const key of [
      "query",
      "processing_state",
      "project_id",
      "tag_id",
      "source_type",
      "date_from",
      "date_to",
    ]) {
      const value = data.get(key);
      if (typeof value === "string" && value) params.set(key, value);
    }
    void load(params.size ? `?${params}` : "");
  }

  async function purge(source: SourceSummary) {
    setError("");
    try {
      const operation = await apiRequest(`/sources/${source.source_id}/purge`, {
        method: "POST",
        body: { reason_code: "user_requested" },
        idempotencyAction: `purge:source:${source.source_id}`,
        parse: parsePurgeRequest,
      });
      setSources((current) =>
        current.map((item) =>
          item.source_id === source.source_id
            ? { ...item, processing_state: "purge_pending" }
            : item,
        ),
      );
      setPurges((current) => ({ ...current, [source.source_id]: operation }));
      setConfirmingId(null);
      if (operation.state === "complete" || operation.state === "dead") {
        const status = await apiRequest(`/purges/${operation.operation_id}`, {
          parse: (value) =>
            parseBoundPurgeStatus(value, {
              operationId: operation.operation_id,
              resourceType: "source",
              resourceId: source.source_id,
            }),
        });
        setPurges((current) => ({ ...current, [source.source_id]: status }));
        if (status.state === "complete") {
          setSources((current) => current.filter((item) => item.source_id !== source.source_id));
        }
      }
    } catch (caught) {
      setError(formatApiError(caught));
    }
  }

  return (
    <div className="page-stack compact-stack">
      <form className="filter-panel" onSubmit={filter}>
        <label>
          Search library
          <input name="query" type="search" />
        </label>
        <label>
          State
          <select name="processing_state">
            <option value="">All states</option>
            {["queued", "processing", "ready", "failed", "purge_pending"].map((state) => (
              <option key={state}>{state}</option>
            ))}
          </select>
        </label>
        <label>
          Project
          <select name="project_id">
            <option value="">All projects</option>
            {projects.map((project) => (
              <option key={project.project_id} value={project.project_id}>
                {project.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Tag
          <select name="tag_id">
            <option value="">All tags</option>
            {tags.map((tag) => (
              <option key={tag.tag_id} value={tag.tag_id}>
                {tag.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Source type
          <select name="source_type">
            <option value="">All types</option>
            {["note", "markdown", "txt", "pdf", "docx", "url"].map((type) => (
              <option key={type}>{type}</option>
            ))}
          </select>
        </label>
        <label>
          From
          <input name="date_from" type="date" />
        </label>
        <label>
          To
          <input name="date_to" type="date" />
        </label>
        <button type="submit">Apply filters</button>
      </form>
      {error ? (
        <p className="error-message" role="alert">
          {error}
        </p>
      ) : null}
      {loading ? <p role="status">Loading sources…</p> : null}
      {!loading && sources.length === 0 && !error ? (
        <p className="empty-state">No sources match these filters.</p>
      ) : null}
      <ul className="record-list" aria-label="Sources">
        {sources.map((source) => {
          const operation = purges[source.source_id];
          return (
            <li key={source.source_id}>
              <div>
                <p className="status-label">
                  {source.source_type} · {source.processing_state}
                </p>
                <h2>
                  <Link href={`/library/${source.source_id}`}>{source.display_title}</Link>
                </h2>
                <p>
                  {source.project_name ?? "No project"} · Captured{" "}
                  {new Date(source.ingested_at).toLocaleDateString()}
                </p>
              </div>
              <div>
                {operation ? (
                  <p className="helper-text" role="status">
                    Purge {operation.state} · operation {operation.operation_id}
                    {"error_class" in operation && operation.error_class
                      ? ` · ${operation.error_class}`
                      : ""}
                  </p>
                ) : null}
                {confirmingId === source.source_id ? (
                  <dialog aria-labelledby={`confirm-${source.source_id}`} open role="alertdialog">
                    <p id={`confirm-${source.source_id}`}>
                      Confirm purge for “{source.display_title}”? Searchable text, embeddings, and
                      the stored original will be removed.
                    </p>
                    <div className="button-row">
                      <button
                        className="danger-button"
                        onClick={() => void purge(source)}
                        ref={confirmButtonRef}
                        type="button"
                      >
                        Confirm purge {source.display_title}
                      </button>
                      <button onClick={closeConfirmation} type="button">
                        Cancel
                      </button>
                    </div>
                  </dialog>
                ) : (
                  <button
                    className="danger-button"
                    disabled={source.processing_state === "purge_pending"}
                    onClick={() => setConfirmingId(source.source_id)}
                    ref={(node) => {
                      if (node) purgeButtonRefs.current[source.source_id] = node;
                      else delete purgeButtonRefs.current[source.source_id];
                    }}
                    type="button"
                  >
                    Request purge
                  </button>
                )}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
