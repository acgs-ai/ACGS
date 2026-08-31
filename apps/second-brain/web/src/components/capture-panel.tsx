"use client";

import Link from "next/link";
import { type FormEvent, useEffect, useState } from "react";

import { apiRequest, formatApiError } from "@/lib/browser-api";
import type { CaptureResult, IngestionJob, Project, Tag } from "@/lib/product-contracts";
import {
  parseCaptureResult,
  parseIngestionJob,
  parseProjects,
  parseTags,
} from "@/lib/resource-parsers";

type CaptureMode = "note" | "markdown" | "upload" | "url";

export function CapturePanel() {
  const [mode, setMode] = useState<CaptureMode>("note");
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [projectId, setProjectId] = useState("");
  const [tagIds, setTagIds] = useState<string[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [result, setResult] = useState<CaptureResult | null>(null);
  const [job, setJob] = useState<IngestionJob | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [pollingError, setPollingError] = useState("");

  useEffect(() => {
    Promise.all([
      apiRequest("/projects?active_only=true", { parse: parseProjects }),
      apiRequest("/tags", { parse: parseTags }),
    ])
      .then(([loadedProjects, loadedTags]) => {
        setProjects(loadedProjects);
        setTags(loadedTags);
      })
      .catch((caught) => setError(formatApiError(caught)));
  }, []);

  useEffect(() => {
    if (!result || job?.state === "ready" || job?.state === "failed" || job?.state === "dead") {
      return;
    }
    let active = true;
    const timer = window.setInterval(() => {
      apiRequest(`/jobs/${result.job_id}`, { parse: parseIngestionJob })
        .then((next) => {
          if (active) {
            setJob(next);
            setPollingError("");
          }
        })
        .catch((caught) => {
          if (active) setPollingError(`Job status polling interrupted. ${formatApiError(caught)}`);
        });
    }, 500);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [job?.state, result]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setPollingError("");
    try {
      const action = `capture:${mode}:${title}`;
      let captured: CaptureResult;
      if (mode === "upload") {
        if (!file) throw new Error("Choose a supported file.");
        const body = new FormData();
        body.set("title", title);
        body.set("file", file);
        if (projectId) body.set("project_id", projectId);
        for (const tagId of tagIds) body.append("tag_ids", tagId);
        captured = await apiRequest<CaptureResult>("/captures/upload", {
          method: "POST",
          body,
          idempotencyAction: action,
          parse: parseCaptureResult,
        });
      } else {
        captured = await apiRequest<CaptureResult>(
          mode === "url" ? "/captures/url" : "/captures/text",
          {
            method: "POST",
            body:
              mode === "url"
                ? { title, url: content, project_id: projectId || null, tag_ids: tagIds }
                : {
                    title,
                    content,
                    source_type: mode,
                    project_id: projectId || null,
                    tag_ids: tagIds,
                  },
            idempotencyAction: action,
            parse: parseCaptureResult,
          },
        );
      }
      setResult(captured);
      setJob({
        id: captured.job_id,
        source_id: captured.source_id,
        state: captured.state,
        attempts: 0,
        error_code: null,
        error_message: null,
      });
    } catch (caught) {
      setError(
        caught instanceof Error && caught.message === "Choose a supported file."
          ? caught.message
          : formatApiError(caught),
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="work-grid">
      <form className="form-panel" onSubmit={submit}>
        <fieldset className="choice-row">
          <legend>Source type</legend>
          {(["note", "markdown", "upload", "url"] as const).map((value) => (
            <label key={value}>
              <input
                checked={mode === value}
                name="capture-mode"
                onChange={() => setMode(value)}
                type="radio"
              />
              {value === "upload" ? "Document" : value === "url" ? "Public URL" : value}
            </label>
          ))}
        </fieldset>
        <label>
          Display title
          <input
            maxLength={300}
            onChange={(event) => setTitle(event.target.value)}
            required
            value={title}
          />
        </label>
        {mode === "upload" ? (
          <label>
            Supported document
            <input
              accept=".md,.txt,.pdf,.docx,text/markdown,text/plain,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document"
              onChange={(event) => setFile(event.target.files?.[0] ?? null)}
              required
              type="file"
            />
          </label>
        ) : (
          <div className="field-group">
            <label htmlFor="capture-content">
              {mode === "url" ? "Safe public HTTP or HTTPS URL" : "Source content"}
            </label>
            {mode === "url" ? (
              <input
                id="capture-content"
                inputMode="url"
                maxLength={2048}
                onChange={(event) => setContent(event.target.value)}
                required
                type="url"
                value={content}
              />
            ) : (
              <textarea
                id="capture-content"
                onChange={(event) => setContent(event.target.value)}
                required
                rows={10}
                value={content}
              />
            )}
          </div>
        )}
        <label>
          Project
          <select onChange={(event) => setProjectId(event.target.value)} value={projectId}>
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
          <select
            multiple
            onChange={(event) =>
              setTagIds([...event.target.selectedOptions].map((item) => item.value))
            }
            value={tagIds}
          >
            {tags.map((tag) => (
              <option key={tag.tag_id} value={tag.tag_id}>
                {tag.name}
              </option>
            ))}
          </select>
        </label>
        <p className="helper-text">
          Uploads are limited to Markdown, TXT, extractable PDF, and DOCX.
        </p>
        <button disabled={busy} type="submit">
          {busy ? "Submitting…" : "Capture source"}
        </button>
        {error ? (
          <p className="error-message" role="alert">
            {error}
          </p>
        ) : null}
      </form>
      <section className="detail-panel" aria-live="polite" aria-labelledby="capture-status-heading">
        <p className="status-label">Processing job</p>
        <h2 id="capture-status-heading">{job ? `Source ${job.state}` : "No active submission"}</h2>
        {job ? (
          <>
            <dl className="metadata-list">
              <div>
                <dt>State</dt>
                <dd>{job.state}</dd>
              </div>
              <div>
                <dt>Attempts</dt>
                <dd>{job.attempts}</dd>
              </div>
              <div>
                <dt>Duplicate</dt>
                <dd>{result?.duplicate ? "Existing source reused" : "No"}</dd>
              </div>
            </dl>
            {job.error_message ? (
              <p className="error-message">Processing failed: {job.error_message}</p>
            ) : null}
            {job.error_code ? <p className="helper-text">Error code: {job.error_code}</p> : null}
            {pollingError ? (
              <p className="warning-message" role="alert">
                {pollingError}
              </p>
            ) : null}
            <Link href={`/library/${job.source_id}`}>Open source</Link>
          </>
        ) : (
          <p>Submit a source to create an immutable record and a visible queued job.</p>
        )}
      </section>
    </div>
  );
}
