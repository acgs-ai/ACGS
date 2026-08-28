"use client";

import { useEffect, useRef, useState } from "react";

import { apiRequest, formatApiError } from "@/lib/browser-api";
import type { CitationContext, Project, SourceDetail, Tag } from "@/lib/product-contracts";
import {
  parseCitationContext,
  parseProjects,
  parseSourceDetail,
  parseSourceOrganization,
  parseTags,
} from "@/lib/resource-parsers";

export function SourceDetailView({
  sourceId,
  selectedChunkId,
  selectedStart,
  selectedEnd,
}: {
  sourceId: string;
  selectedChunkId?: string;
  selectedStart?: number;
  selectedEnd?: number;
}) {
  const [source, setSource] = useState<SourceDetail | null>(null);
  const [context, setContext] = useState<CitationContext | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const evidenceRef = useRef<HTMLElement>(null);

  useEffect(() => {
    Promise.all([
      apiRequest(`/sources/${sourceId}`, { parse: parseSourceDetail }),
      apiRequest("/projects", { parse: parseProjects }),
      apiRequest("/tags", { parse: parseTags }),
      selectedChunkId
        ? apiRequest(`/sources/${sourceId}/context/${selectedChunkId}`, {
            parse: parseCitationContext,
          })
        : Promise.resolve(null),
    ])
      .then(([nextSource, nextProjects, nextTags, nextContext]) => {
        setSource(nextSource);
        setProjects(nextProjects);
        setTags(nextTags);
        setContext(nextContext);
      })
      .catch((caught) => setError(formatApiError(caught)));
  }, [selectedChunkId, sourceId]);

  useEffect(() => {
    if (context) evidenceRef.current?.focus();
  }, [context]);

  async function organize(form: HTMLFormElement) {
    const data = new FormData(form);
    const projectId = String(data.get("project_id") ?? "");
    const selectedTags = data.getAll("tag_ids").map(String);
    try {
      await apiRequest(`/sources/${sourceId}/organization`, {
        method: "PUT",
        body: { project_id: projectId || null, tag_ids: selectedTags },
        parse: parseSourceOrganization,
      });
      setNotice("Organization updated.");
    } catch (caught) {
      setError(formatApiError(caught));
    }
  }

  if (error && !source)
    return (
      <p className="error-message" role="alert">
        Citation unavailable: {error}
      </p>
    );
  if (!source) return <p role="status">Loading source…</p>;

  const citationStart = selectedStart ?? context?.char_start;
  const citationEnd = selectedEnd ?? context?.char_end;
  const citationRangeValid =
    context !== null &&
    context.source_id === sourceId &&
    context.chunk_id === selectedChunkId &&
    citationStart !== undefined &&
    citationEnd !== undefined &&
    Number.isSafeInteger(citationStart) &&
    Number.isSafeInteger(citationEnd) &&
    citationStart >= context.char_start &&
    citationEnd <= context.char_end &&
    citationStart >= context.context_char_start &&
    citationEnd <= context.context_char_end &&
    citationEnd > citationStart;
  const contextCharacters = context ? Array.from(context.context_text) : [];
  const localStart = citationRangeValid ? citationStart - context.context_char_start : 0;
  const localEnd = citationRangeValid ? citationEnd - context.context_char_start : 0;
  const selectedText = citationRangeValid
    ? contextCharacters.slice(localStart, localEnd).join("")
    : "";

  return (
    <div className="page-stack compact-stack">
      {error ? (
        <p className="error-message" role="alert">
          {error}
        </p>
      ) : null}
      {context && citationRangeValid && selectedText ? (
        <section className="evidence-focus" aria-labelledby="selected-evidence-heading">
          <p className="status-label">Evidence</p>
          <h2 id="selected-evidence-heading">Selected supporting passage</h2>
          <p>
            {contextCharacters.slice(0, localStart).join("")}
            <mark ref={evidenceRef} tabIndex={-1}>
              {selectedText}
            </mark>
            {contextCharacters.slice(localEnd).join("")}
          </p>
          <p className="helper-text">
            Chunk {context.chunk_id} · characters {context.char_start}–{context.char_end}
          </p>
        </section>
      ) : selectedChunkId ? (
        <section className="state-panel" role="alert">
          <p className="status-label">Citation unavailable</p>
          <h2>Citation range could not be validated</h2>
          <p>The requested offsets are not contained in the accessible source chunk.</p>
        </section>
      ) : null}
      <section className="detail-panel" aria-labelledby="metadata-heading">
        <p className="status-label">Original metadata</p>
        <h2 id="metadata-heading">{source.display_title}</h2>
        <dl className="metadata-list">
          <div>
            <dt>Source ID</dt>
            <dd>{source.source_id}</dd>
          </div>
          <div>
            <dt>Type</dt>
            <dd>{source.source_type}</dd>
          </div>
          <div>
            <dt>MIME type</dt>
            <dd>{source.mime_type}</dd>
          </div>
          <div>
            <dt>State</dt>
            <dd>{source.processing_state}</dd>
          </div>
          <div>
            <dt>Semantic retrieval</dt>
            <dd>{source.semantic_state}</dd>
          </div>
          <div>
            <dt>Captured</dt>
            <dd>{new Date(source.ingested_at).toLocaleString()}</dd>
          </div>
          <div>
            <dt>SHA-256</dt>
            <dd className="code-value">{source.content_sha256}</dd>
          </div>
          <div>
            <dt>Original filename or URI</dt>
            <dd>{source.original_filename ?? source.original_uri ?? "Direct note"}</dd>
          </div>
        </dl>
      </section>
      {source.processing_error_code || source.processing_error_message ? (
        <section className="state-panel" aria-labelledby="processing-failure-heading">
          <p className="status-label">Processing failed</p>
          <h2 id="processing-failure-heading">Source processing details</h2>
          {source.processing_error_code ? <p>Error code: {source.processing_error_code}</p> : null}
          {source.processing_error_message ? <p>{source.processing_error_message}</p> : null}
        </section>
      ) : null}
      <section className="detail-panel" aria-labelledby="organization-heading">
        <h2 id="organization-heading">Organization</h2>
        <form
          className="inline-form"
          onSubmit={(event) => {
            event.preventDefault();
            void organize(event.currentTarget);
          }}
        >
          <label>
            Project
            <select defaultValue={source.project_id ?? ""} name="project_id">
              <option value="">No project</option>
              {projects.map((project) => (
                <option key={project.project_id} value={project.project_id}>
                  {project.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Tags
            <select defaultValue={source.tags.map((tag) => tag.tag_id)} multiple name="tag_ids">
              {tags.map((tag) => (
                <option key={tag.tag_id} value={tag.tag_id}>
                  {tag.name}
                </option>
              ))}
            </select>
          </label>
          <button type="submit">Save organization</button>
        </form>
        {notice ? <p role="status">{notice}</p> : null}
      </section>
      <section className="detail-panel" aria-labelledby="extracted-heading">
        <p className="status-label">Extracted content</p>
        <h2 id="extracted-heading">Current document text</h2>
        <pre className="source-text">
          {source.documents[0]?.extracted_text ?? "Extracted content unavailable."}
        </pre>
      </section>
      <section aria-labelledby="chunks-heading">
        <h2 id="chunks-heading">Chunk boundaries</h2>
        <ol className="chunk-list">
          {source.chunks.map((chunk) => (
            <li id={`chunk-${chunk.chunk_id}`} key={chunk.chunk_id}>
              <p className="status-label">
                Chunk {chunk.ordinal} · {chunk.char_start}–{chunk.char_end}
              </p>
              <p>{chunk.chunk_text}</p>
              <small>
                {chunk.page_number ? `Page ${chunk.page_number}` : "No page"}
                {chunk.section ? ` · ${chunk.section}` : ""}
              </small>
            </li>
          ))}
        </ol>
      </section>
      <section aria-labelledby="history-heading">
        <h2 id="history-heading">Ingestion history</h2>
        <ol className="timeline">
          {source.ingestion_history.map((event) => (
            <li key={`${event.job_id}-${event.attempt}-${event.to_state}-${event.occurred_at}`}>
              <strong>{event.to_state}</strong> · {event.reason_class} ·{" "}
              {new Date(event.occurred_at).toLocaleString()}
            </li>
          ))}
        </ol>
        {source.jobs.map((job) =>
          job.error_code || job.error_message || job.semantic_error_class ? (
            <div className="state-panel" key={job.job_id}>
              <p className="status-label">Job {job.state}</p>
              <p>
                {[job.error_code, job.error_message, job.semantic_error_class]
                  .filter(Boolean)
                  .join(" · ")}
              </p>
            </div>
          ) : null,
        )}
      </section>
    </div>
  );
}
