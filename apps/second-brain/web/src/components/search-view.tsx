"use client";

import Link from "next/link";
import { type FormEvent, useEffect, useState } from "react";

import { apiRequest, formatApiError } from "@/lib/browser-api";
import { inclusiveDateQueryValue } from "@/lib/date-query";
import type { Project, SearchResult, Tag } from "@/lib/product-contracts";
import { parseProjects, parseSearchResponse, parseTags } from "@/lib/resource-parsers";

function score(value: number | null): string {
  return value === null ? "Not returned" : value.toFixed(4);
}

export function SearchView() {
  const [results, setResults] = useState<SearchResult[]>([]);
  const [semanticStatus, setSemanticStatus] = useState<"available" | "unavailable" | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
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

  async function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const params = new URLSearchParams();
    for (const [key, raw] of data.entries()) {
      const value = String(raw);
      if (value) params.set(key, inclusiveDateQueryValue(key, value));
    }
    setSubmitted(true);
    setLoading(true);
    setError("");
    try {
      const response = await apiRequest(`/search?${params}`, { parse: parseSearchResponse });
      setResults(response.results);
      setSemanticStatus(response.semantic_status);
    } catch (caught) {
      setError(formatApiError(caught));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page-stack compact-stack">
      <form className="filter-panel" onSubmit={search}>
        <label className="wide-field">
          Search evidence
          <input name="q" required type="search" />
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
        <button type="submit">Search sources</button>
      </form>
      {loading ? <p role="status">Searching lexical and semantic indexes…</p> : null}
      {error ? (
        <p className="error-message" role="alert">
          {error}
        </p>
      ) : null}
      {!loading && submitted && results.length === 0 && !error ? (
        <p className="empty-state">No source passages matched.</p>
      ) : null}
      {semanticStatus === "unavailable" ? (
        <p className="warning-message" role="status">
          Semantic retrieval is unavailable. Results use PostgreSQL lexical search.
        </p>
      ) : null}
      <ol className="search-results" aria-label="Search results">
        {results.map((result) => (
          <li key={result.chunk_id}>
            <p className="status-label">
              Fused rank {result.fused_rank} · {result.source_type}
            </p>
            <h2>
              <Link
                href={`/library/${result.source_id}?chunk=${result.chunk_id}&start=${result.char_start}&end=${result.char_end}`}
              >
                {result.display_title}
              </Link>
            </h2>
            <p className="source-excerpt">{result.excerpt}</p>
            <dl className="rank-grid">
              <div>
                <dt>Lexical</dt>
                <dd>
                  {result.lexical_rank ?? "—"} · {score(result.lexical_score)}
                </dd>
              </div>
              <div>
                <dt>Semantic</dt>
                <dd>
                  {result.semantic_rank ?? "—"} · {score(result.semantic_score)}
                </dd>
              </div>
              <div>
                <dt>Fused score</dt>
                <dd>{result.fused_score.toFixed(4)}</dd>
              </div>
              <div>
                <dt>Location</dt>
                <dd>
                  {result.page_number
                    ? `Page ${result.page_number}`
                    : `Characters ${result.char_start}–${result.char_end}`}
                </dd>
              </div>
            </dl>
            <p className="helper-text">
              {result.tags.map((tag) => tag.name).join(", ") || "No tags"} ·{" "}
              {new Date(result.ingested_at).toLocaleDateString()} · Chunk {result.chunk_id}
            </p>
          </li>
        ))}
      </ol>
    </div>
  );
}
