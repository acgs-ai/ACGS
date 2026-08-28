"use client";

import { type FormEvent, useEffect, useState } from "react";

import { type AnswerPayload, parseAnswerPayload } from "@/lib/answer-parser";
import { apiRequest, formatApiError } from "@/lib/browser-api";
import type { Project, Tag } from "@/lib/product-contracts";
import { parseProjects, parseTags } from "@/lib/resource-parsers";

import { AnswerView } from "./answer-view";

export function AskView() {
  const [answer, setAnswer] = useState<AnswerPayload | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      apiRequest("/projects", { parse: parseProjects }),
      apiRequest("/tags", { parse: parseTags }),
    ])
      .then(([nextProjects, nextTags]) => {
        setProjects(nextProjects);
        setTags(nextTags);
      })
      .catch((caught) => setError(formatApiError(caught)));
  }, []);

  async function ask(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setBusy(true);
    setError("");
    setAnswer(null);
    try {
      const body = {
        query: String(data.get("query") ?? ""),
        filters: {
          project_id: String(data.get("project_id") ?? "") || null,
          tag_id: String(data.get("tag_id") ?? "") || null,
          source_type: String(data.get("source_type") ?? "") || null,
        },
      };
      const response = await apiRequest("/answers", {
        method: "POST",
        body,
        idempotencyAction: `answer:${JSON.stringify(body)}`,
        parse: parseAnswerPayload,
      });
      setAnswer(response);
    } catch (caught) {
      setError(formatApiError(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="work-grid">
      <form className="form-panel" onSubmit={ask}>
        <label>
          Question
          <textarea maxLength={2000} name="query" required rows={6} />
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
        <p className="helper-text">
          Answers use at most eight retrieved chunks and 12,000 evidence characters.
        </p>
        <button disabled={busy} type="submit">
          {busy ? "Retrieving evidence…" : "Ask from sources"}
        </button>
        {error ? (
          <p className="error-message" role="alert">
            {error}
          </p>
        ) : null}
      </form>
      <div aria-live="polite">
        {answer ? (
          <AnswerView answer={answer} />
        ) : (
          <section className="detail-panel">
            <p className="status-label">Answer provenance</p>
            <h2>No question submitted</h2>
            <p>Ask a question to retrieve bounded evidence and validate every returned citation.</p>
          </section>
        )}
        {answer?.proposed_memory ? (
          <section className="proposal-panel" aria-labelledby="proposal-heading">
            <p className="status-label">Proposed memory · inactive</p>
            <h2 id="proposal-heading">Review required</h2>
            <p>{answer.proposed_memory.statement}</p>
            <p className="helper-text">
              This proposal is not active until you approve it in Memory review.
            </p>
          </section>
        ) : null}
      </div>
    </div>
  );
}
