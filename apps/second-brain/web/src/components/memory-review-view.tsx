"use client";

import { type FormEvent, useEffect, useState } from "react";

import { apiRequest, formatApiError } from "@/lib/browser-api";
import type { MemoryProposal } from "@/lib/product-contracts";
import {
  parseMemoryMutation,
  parseMemoryProposalMutation,
  parseMemoryProposals,
} from "@/lib/resource-parsers";

export function MemoryReviewView() {
  const [proposals, setProposals] = useState<MemoryProposal[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    apiRequest("/memory-proposals?status=proposed", { parse: parseMemoryProposals })
      .then(setProposals)
      .catch((caught) => setError(formatApiError(caught)))
      .finally(() => setLoading(false));
  }, []);

  async function decide(
    proposal: MemoryProposal,
    action: "approve" | "reject" | "edit-and-approve",
    form?: HTMLFormElement,
  ) {
    setError("");
    setNotice("");
    let body: Record<string, unknown> = {};
    if (action === "edit-and-approve" && form) {
      const data = new FormData(form);
      body = {
        statement: String(data.get("statement") ?? ""),
        category: String(data.get("category") ?? "other"),
        confidence: Number(data.get("confidence")),
        evidence_quality: String(data.get("evidence_quality") ?? "medium"),
      };
    }
    try {
      await apiRequest(`/memory-proposals/${proposal.proposal_id}/${action}`, {
        method: "POST",
        body,
        idempotencyAction: `proposal:${proposal.proposal_id}:${action}`,
        parse: (value) =>
          action === "reject" ? parseMemoryProposalMutation(value) : parseMemoryMutation(value),
      });
      setProposals((current) =>
        current.filter((item) => item.proposal_id !== proposal.proposal_id),
      );
      setNotice(action === "reject" ? "Proposed memory rejected." : "Proposed memory approved.");
    } catch (caught) {
      setError(formatApiError(caught));
    }
  }

  if (loading) return <p role="status">Loading proposed memories…</p>;
  return (
    <div className="page-stack compact-stack">
      {error ? (
        <p className="error-message" role="alert">
          {error}
        </p>
      ) : null}
      {notice ? <p role="status">{notice}</p> : null}
      {proposals.length === 0 && !error ? (
        <p className="empty-state">No proposed memories require review.</p>
      ) : null}
      <ul className="memory-review-list" aria-label="Proposed memories">
        {proposals.map((proposal) => (
          <li key={proposal.proposal_id}>
            <p className="status-label">Proposed memory · inactive</p>
            <h2>{proposal.statement}</h2>
            <p>
              {proposal.category} · {proposal.evidence_quality} evidence · confidence{" "}
              {proposal.confidence.toFixed(2)}
            </p>
            <details>
              <summary>Inspect evidence lineage</summary>
              <ul>
                {proposal.source_chunk_ids.map((chunkId) => (
                  <li className="code-value" key={chunkId}>
                    {chunkId}
                  </li>
                ))}
              </ul>
            </details>
            <div className="button-row">
              <button onClick={() => void decide(proposal, "approve")} type="button">
                Approve
              </button>
              <button
                className="secondary-button"
                onClick={() => void decide(proposal, "reject")}
                type="button"
              >
                Reject
              </button>
            </div>
            <details>
              <summary>Edit before approval</summary>
              <form
                className="inline-form"
                onSubmit={(event: FormEvent<HTMLFormElement>) => {
                  event.preventDefault();
                  void decide(proposal, "edit-and-approve", event.currentTarget);
                }}
              >
                <label>
                  Statement
                  <textarea
                    defaultValue={proposal.statement}
                    maxLength={4000}
                    name="statement"
                    required
                    rows={4}
                  />
                </label>
                <label>
                  Category
                  <select defaultValue={proposal.category} name="category">
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
                    defaultValue={proposal.confidence}
                    max="1"
                    min="0"
                    name="confidence"
                    step="0.01"
                    type="number"
                  />
                </label>
                <label>
                  Evidence quality
                  <select defaultValue={proposal.evidence_quality} name="evidence_quality">
                    <option>low</option>
                    <option>medium</option>
                    <option>high</option>
                  </select>
                </label>
                <button type="submit">Save and approve</button>
              </form>
            </details>
          </li>
        ))}
      </ul>
    </div>
  );
}
