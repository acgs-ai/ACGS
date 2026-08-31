"use client";

import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";

import { apiRequest, formatApiError } from "@/lib/browser-api";
import type {
  MemoryDetail,
  MemorySummary,
  PurgeRequestResult,
  PurgeStatus,
} from "@/lib/product-contracts";
import {
  parseBoundPurgeStatus,
  parseMemoryDetail,
  parseMemoryMutation,
  parseMemorySummaries,
  parsePurgeRequest,
} from "@/lib/resource-parsers";

export function MemoryLibraryView() {
  const [memories, setMemories] = useState<MemorySummary[]>([]);
  const [details, setDetails] = useState<Record<string, MemoryDetail>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [purges, setPurges] = useState<Record<string, PurgeRequestResult | PurgeStatus>>({});
  const confirmButtonRef = useRef<HTMLButtonElement>(null);
  const purgeButtonRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const restoreFocusId = useRef<string | null>(null);

  const load = useCallback(async () => {
    const next = await apiRequest("/memories", { parse: parseMemorySummaries });
    const detailRows = await Promise.all(
      next.map((memory) =>
        apiRequest(`/memories/${memory.memory_id}`, { parse: parseMemoryDetail }),
      ),
    );
    setMemories(next);
    setDetails(Object.fromEntries(detailRows.map((detail) => [detail.memory_id, detail])));
  }, []);

  useEffect(() => {
    load()
      .catch((caught) => setError(formatApiError(caught)))
      .finally(() => setLoading(false));
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
    const memoryId = restoreFocusId.current;
    if (memoryId) {
      purgeButtonRefs.current[memoryId]?.focus();
      restoreFocusId.current = null;
    }
  }, [confirmingId]);

  function closeConfirmation() {
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
      for (const [memoryId, operation] of active) {
        apiRequest(`/purges/${operation.operation_id}`, {
          parse: (value) =>
            parseBoundPurgeStatus(value, {
              operationId: operation.operation_id,
              resourceType: "memory",
              resourceId: memoryId,
            }),
        })
          .then((status) => {
            if (!mounted) return;
            setPurges((current) => ({ ...current, [memoryId]: status }));
            if (status.state === "complete") {
              setMemories((current) => current.filter((item) => item.memory_id !== memoryId));
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

  async function mutate(
    memory: MemorySummary,
    action: "revise" | "supersede" | "archive" | "purge",
    form?: HTMLFormElement,
  ) {
    setError("");
    setNotice("");
    const data = form ? new FormData(form) : null;
    const current = details[memory.memory_id]?.revisions.at(-1);
    let body: Record<string, unknown> = {};
    if (action === "revise") {
      body = {
        statement: String(data?.get("statement") ?? ""),
        category: String(data?.get("category") ?? memory.category),
        confidence: Number(data?.get("confidence") ?? memory.confidence),
        evidence_quality: String(data?.get("evidence_quality") ?? memory.evidence_quality),
        source_chunk_ids: current?.source_chunk_ids ?? [],
      };
    } else if (action === "supersede") {
      body = { superseding_memory_id: String(data?.get("superseding_memory_id") ?? "") };
    } else if (action === "purge") {
      body = { reason_code: "user_requested" };
    }
    try {
      const result = await apiRequest(`/memories/${memory.memory_id}/${action}`, {
        method: "POST",
        body,
        idempotencyAction: `memory:${memory.memory_id}:${action}:${current?.revision_number ?? 0}`,
        parse: (value) =>
          action === "purge" ? parsePurgeRequest(value) : parseMemoryMutation(value),
      });
      setNotice(
        action === "revise" ? "Approved memory revision added." : `Memory ${action} requested.`,
      );
      if (action === "purge") {
        if (!("operation_id" in result)) throw new TypeError("Purge response was not returned");
        setMemories((current) =>
          current.map((item) =>
            item.memory_id === memory.memory_id ? { ...item, status: "purge_pending" } : item,
          ),
        );
        setPurges((currentPurges) => ({ ...currentPurges, [memory.memory_id]: result }));
        setConfirmingId(null);
        if (result.state === "complete" || result.state === "dead") {
          const status = await apiRequest(`/purges/${result.operation_id}`, {
            parse: (value) =>
              parseBoundPurgeStatus(value, {
                operationId: result.operation_id,
                resourceType: "memory",
                resourceId: memory.memory_id,
              }),
          });
          setPurges((currentPurges) => ({ ...currentPurges, [memory.memory_id]: status }));
          if (status.state === "complete") {
            setMemories((currentMemories) =>
              currentMemories.filter((item) => item.memory_id !== memory.memory_id),
            );
          }
        }
      } else {
        await load();
      }
    } catch (caught) {
      setError(formatApiError(caught));
    }
  }

  if (loading) return <p role="status">Loading approved memories…</p>;
  return (
    <div className="page-stack compact-stack">
      {error ? (
        <p className="error-message" role="alert">
          {error}
        </p>
      ) : null}
      {notice ? <p role="status">{notice}</p> : null}
      {memories.length === 0 && !error ? (
        <p className="empty-state">No approved memories yet.</p>
      ) : null}
      <ul className="memory-list" aria-label="Approved memories">
        {memories.map((memory) => {
          const detail = details[memory.memory_id];
          const purge = purges[memory.memory_id];
          return (
            <li key={memory.memory_id}>
              <p className="status-label">Approved memory · {memory.status}</p>
              <h2>{memory.statement}</h2>
              <p>
                {memory.category} · revision {memory.revision_number} · {memory.evidence_quality}{" "}
                evidence
              </p>
              <details>
                <summary>Revision and source lineage</summary>
                <ol className="timeline">
                  {detail?.revisions.map((revision) => (
                    <li key={revision.revision_id}>
                      <strong>Revision {revision.revision_number}</strong>
                      <p>{revision.statement}</p>
                      <ul>
                        {revision.source_chunk_ids.map((chunkId) => (
                          <li className="code-value" key={chunkId}>
                            {chunkId}
                          </li>
                        ))}
                      </ul>
                    </li>
                  ))}
                </ol>
              </details>
              {memory.status === "active" ? (
                <>
                  <details>
                    <summary>Add revision</summary>
                    <form
                      className="inline-form"
                      onSubmit={(event: FormEvent<HTMLFormElement>) => {
                        event.preventDefault();
                        void mutate(memory, "revise", event.currentTarget);
                      }}
                    >
                      <label>
                        Statement
                        <textarea
                          defaultValue={memory.statement}
                          maxLength={4000}
                          name="statement"
                          required
                          rows={4}
                        />
                      </label>
                      <label>
                        Category
                        <select defaultValue={memory.category} name="category">
                          {[
                            "preference",
                            "commitment",
                            "project_fact",
                            "person_fact",
                            "reference",
                            "other",
                          ].map((category) => (
                            <option key={category}>{category}</option>
                          ))}
                        </select>
                      </label>
                      <label>
                        Confidence
                        <input
                          defaultValue={memory.confidence}
                          max="1"
                          min="0"
                          name="confidence"
                          step="0.01"
                          type="number"
                        />
                      </label>
                      <label>
                        Evidence quality
                        <select defaultValue={memory.evidence_quality} name="evidence_quality">
                          <option>low</option>
                          <option>medium</option>
                          <option>high</option>
                        </select>
                      </label>
                      <button type="submit">Add revision</button>
                    </form>
                  </details>
                  <details>
                    <summary>Supersede with another approved memory</summary>
                    <form
                      className="inline-form"
                      onSubmit={(event) => {
                        event.preventDefault();
                        void mutate(memory, "supersede", event.currentTarget);
                      }}
                    >
                      <label>
                        Superseding memory
                        <select name="superseding_memory_id" required>
                          <option value="">Choose memory</option>
                          {memories
                            .filter(
                              (item) =>
                                item.memory_id !== memory.memory_id && item.status === "active",
                            )
                            .map((item) => (
                              <option key={item.memory_id} value={item.memory_id}>
                                {item.statement}
                              </option>
                            ))}
                        </select>
                      </label>
                      <button type="submit">Supersede</button>
                    </form>
                  </details>
                  <div className="button-row">
                    <button
                      className="secondary-button"
                      onClick={() => void mutate(memory, "archive")}
                      type="button"
                    >
                      Archive
                    </button>
                    <button
                      className="danger-button"
                      onClick={() => setConfirmingId(memory.memory_id)}
                      ref={(node) => {
                        purgeButtonRefs.current[memory.memory_id] = node;
                      }}
                      type="button"
                    >
                      Request purge
                    </button>
                  </div>
                  {confirmingId === memory.memory_id ? (
                    <dialog
                      aria-label={`Confirm purge of memory ${memory.statement}`}
                      open
                      role="alertdialog"
                    >
                      <p>Confirm purge for “{memory.statement}”?</p>
                      <button
                        className="danger-button"
                        onClick={() => void mutate(memory, "purge")}
                        ref={confirmButtonRef}
                        type="button"
                      >
                        Confirm purge {memory.statement}
                      </button>
                      <button onClick={closeConfirmation} type="button">
                        Cancel
                      </button>
                    </dialog>
                  ) : null}
                </>
              ) : null}
              {purge ? (
                <p className="helper-text" role="status">
                  Purge {purge.state} · operation {purge.operation_id}
                  {"error_class" in purge && purge.error_class ? ` · ${purge.error_class}` : ""}
                </p>
              ) : null}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
