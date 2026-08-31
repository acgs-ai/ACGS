"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { apiRequest, formatApiError } from "@/lib/browser-api";
import type { TodayPayload } from "@/lib/product-contracts";
import { parseResurfaceResult, parseToday } from "@/lib/resource-parsers";

export function TodayView() {
  const [today, setToday] = useState<TodayPayload | null>(null);
  const [error, setError] = useState("");
  const [recorded, setRecorded] = useState<string[]>([]);

  useEffect(() => {
    apiRequest("/today", { parse: parseToday })
      .then(setToday)
      .catch((caught) => setError(formatApiError(caught)));
  }, []);

  async function resurface(memoryId: string) {
    try {
      await apiRequest(`/memories/${memoryId}/resurface`, {
        method: "POST",
        body: {},
        parse: parseResurfaceResult,
      });
      setRecorded((current) => [...current, memoryId]);
    } catch (caught) {
      setError(formatApiError(caught));
    }
  }

  if (error && !today)
    return (
      <p className="error-message" role="alert">
        {error}
      </p>
    );
  if (!today) return <p role="status">Loading Today…</p>;
  return (
    <div className="dashboard-grid">
      {error ? (
        <p className="error-message" role="alert">
          {error}
        </p>
      ) : null}
      <section>
        <p className="status-label">Recent captures</p>
        <h2>Sources added lately</h2>
        {today.recent_captures.empty_message ? (
          <p>{today.recent_captures.empty_message}</p>
        ) : (
          <ul>
            {today.recent_captures.items.map((item) => (
              <li key={item.source_id}>
                <Link href={`/library/${item.source_id}`}>{item.display_title}</Link>
                <small>
                  {item.source_type} · {item.processing_state}
                </small>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <p className="status-label">Processing failed</p>
        <h2>Jobs requiring attention</h2>
        {today.failed_jobs.empty_message ? (
          <p>{today.failed_jobs.empty_message}</p>
        ) : (
          <ul>
            {today.failed_jobs.items.map((item) => (
              <li key={item.job_id}>
                <Link href={`/library/${item.source_id}`}>{item.display_title}</Link>
                <small>{item.error_code ?? item.state}</small>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <p className="status-label">Recently approved</p>
        <h2>Durable memories</h2>
        {today.recent_approved_memories.empty_message ? (
          <p>{today.recent_approved_memories.empty_message}</p>
        ) : (
          <ul>
            {today.recent_approved_memories.items.map((item) => (
              <li key={item.memory_id}>
                {item.normalized_statement}
                <small>
                  Revision {item.revision_number} · {item.status}
                </small>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <p className="status-label">Active projects</p>
        <h2>Relevant sources</h2>
        {today.active_project_sources.empty_message ? (
          <p>{today.active_project_sources.empty_message}</p>
        ) : (
          <ul>
            {today.active_project_sources.items.map((item) => (
              <li key={item.source_id}>
                <Link href={`/library/${item.source_id}`}>{item.display_title}</Link>
                <small>{item.project_name}</small>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <p className="status-label">Deterministic resurfacing</p>
        <h2>Review set</h2>
        {today.resurfacing.empty_message ? (
          <p>{today.resurfacing.empty_message}</p>
        ) : (
          <ul>
            {today.resurfacing.items.map((item) => (
              <li key={item.memory_id}>
                <p>{item.normalized_statement}</p>
                <button
                  disabled={recorded.includes(item.memory_id)}
                  onClick={() => void resurface(item.memory_id)}
                  type="button"
                >
                  {recorded.includes(item.memory_id) ? "Reviewed today" : "Mark reviewed"}
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
