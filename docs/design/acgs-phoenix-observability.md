# ACGS × Arize Phoenix — Observability Adjunct Architecture

Status: Proposed
Supersedes: none
Supplements: `docs/adr/0001-in-context-procedure-execution-external-runtime-governance.md`
Drivers: runtime observability for governed LLM/tool calls; EU AI Act Article 12
(record-keeping) and Article 15 (accuracy/robustness monitoring) evidence
coverage; debugging latency/token/cost regressions; LLM-as-a-judge evaluation
pipeline under governance control.

## Context

ACGS emits chain-hashed JSONL evidence for every governed action via two
independent writers:

- `acgs_governance_eval_mvp/governance/adapters/hermes/evidence_writer.py::ChainEvidenceWriter` — hook-level
  events (`pre_tool`, `post_tool`, `final_check`) with canonical-JSON SHA-256
  hashing, `prev_hash` linkage, `event_hash`, Merkle root computation, and
  cross-process fcntl-locked append.
- `acgs_governance_eval_mvp/governance/audit/jsonl_chain.py` — gate-level
  decisions (Authority, PolicyRecall, GovernanceRecall) with the same
  chain-hash discipline.

These chains are the **authoritative audit artifact** — tamper-evident,
replayable, and independent of any external infrastructure. ADR-0001
codifies the principle that "runtime governance is authoritative; prompt-level
governance is advisory." The evidence chain is the durable record of that
authority being exercised.

What the chains do **not** provide:

- Per-call latency, tokens-consumed, and cost metrics.
- Full prompt and full model response capture with side-by-side visual diff.
- LLM-as-a-judge evaluation results (hallucination, faithfulness, toxicity,
  relevance) anchored to specific traces.
- A triage UI for engineers and CISOs to slice by tool, tenant, session, or
  policy violation over time.

Arize Phoenix is an OpenTelemetry-native, self-hostable, open-source LLM
observability backend that provides exactly those missing capabilities without
sending data off-host. Released under ELv2 but free to self-host with no feature
gating.

## Decision

Adopt Arize Phoenix as an **observability adjunct** to the ACGS chain-hashed
audit trail. Phoenix is explicitly NOT an audit replacement. The two surfaces
are linked by a narrow, deterministic contract — neither owns the other's data,
and the chain remains authoritative for every governance decision.

### Authoritativeness rule

| Question                                         | Authoritative source                          |
|--------------------------------------------------|-----------------------------------------------|
| Was this tool call allowed? Denied? Why?         | ACGS chain (`decision`, `reasons`, `policy_ids`) |
| Has the evidence been tampered with?             | ACGS chain (`event_hash`, `prev_hash`, Merkle) |
| What prompt and response did the model produce?  | Phoenix span (authoritative for wire content) |
| How long did the call take? How many tokens?     | Phoenix span                                  |
| Did an LLM-as-a-judge eval pass or fail?         | Phoenix eval row                              |
| Was the judge's result binding on the decision?  | ACGS chain — evals are advisory inputs only   |

If the two disagree on a shared field, the ACGS chain wins by definition. The
Phoenix trace is presumed contemporaneous evidence of what the wire carried,
but the chain's `input_hash` of the tool call payload is the binding commitment.

### Cross-link contract

Every ACGS evidence row whose hook fires inside an active OpenTelemetry span
carries two new optional keys in `metadata`:

```json
{
  "metadata": {
    "trace_id": "0af7651916cd43dd8448eb211c80319c",
    "span_id":  "b7ad6b7169203331",
    "...": "existing keys unchanged"
  }
}
```

The same span is enriched with two OpenInference-compatible attributes:

```text
acgs.event_hash = <64-char sha256 from the evidence row>
acgs.decision   = "ALLOW" | "DENY" | "REQUIRE_HUMAN" | "REWRITE" | "REDACT" | "SOFT_BLOCK_WITH_EXPLANATION"
```

Both directions are best-effort and no-op when the other side is absent:

- If `opentelemetry.trace` is not imported, or no span is active, the ACGS
  evidence row is written exactly as today (no new metadata keys).
- If Phoenix is unreachable, the span cannot be exported, but the middleware
  still writes the evidence row and the chain still verifies — governance is
  unaffected.

The cross-link is inserted in `HermesACGSMiddleware._audit()` only. The
`ChainEvidenceWriter` is not modified; its hashing surface is unchanged. This
preserves hash stability for all pre-existing evidence.

### Evals are advisory, not authoritative

A future deliverable (D3, not in this ADR) will let `GovernanceRecallGate`
consume Phoenix eval rows as policy inputs. That ADR will separately decide:

1. Whether missing Phoenix evals force `DENY` (hard fail-closed) or produce a
   `DEGRADED_ALLOW` audit event (soft fail-closed).
2. Which eval schemas are considered binding inputs versus advisory context.
3. How the chain captures the eval-row hashes so audit is self-contained if
   Phoenix data is later wiped.

Until D3 is ratified, Phoenix evals have no load-bearing role in any gate
decision.

### Retention asymmetry is documented, not hidden

Phoenix traces are typically retained 7–90 days depending on operator policy
and disk budget. The ACGS chain is retained for the regulatory lifetime of
the governed activity (often 7+ years). A missing or expired Phoenix trace is
**not** destroyed evidence — the authoritative binding data (`event_hash`,
`input_hash`, `prev_hash`, `event_hash` Merkle root) all live in the JSONL
chain and are reproducible from it.

This is reflected in the Evidence Panel UI: if a Phoenix deep-link 404s, the
panel shows "trace expired (retention policy: Nd)" rather than "evidence
missing."

## Alternatives considered

### Extend ChainEvidenceWriter to capture prompts, tokens, latency itself

Rejected. Would duplicate OTEL semantic conventions, couple governance code
to model-provider SDKs, and bloat the chain with high-volume observability
data that doesn't need chain-hash discipline. ACGS's discipline is expensive
(canonical JSON, fsync, fcntl); applying it to token counters is wasteful.
Phoenix already solves this with vendor-standard semantics via OpenInference.

### Use LangSmith, Helicone, or Datadog LLM Observability

Considered. All three are viable as observability backends but each requires
data to leave the host (LangSmith, Helicone) or introduces a commercial
agent/license surface (Datadog). Phoenix is the only mainstream option that
is OSS, self-hostable, air-gap compatible, and natively OpenInference/OTEL
without a collector sidecar. For a governance-first stack the blast-radius
surface area matters more than feature completeness.

### Make Phoenix a hard ACGS dependency

Rejected. Coupling governance to an observability backend inverts the trust
model: the authoritative audit would depend on a non-authoritative process
being up. Phoenix is additive. ACGS functions with Phoenix down, and the
chain-verify semantics do not reference Phoenix at all.

### Put Phoenix in the ACGS gate package

Rejected. The instrumentation belongs at the **edge** where the LLM/tool call
is actually made (Hermes agent, calling app, adapter). Keeping
`acgs_governance_eval_mvp/governance/` free of `phoenix`/`openinference`
imports preserves its posture as a deterministic, minimal-dep evaluator.
`acgs_governance_eval_mvp/governance/adapters/hermes/` already spans the edge and is the right seam.

## Consequences

### Positive

- Observability debt is repaid without rewriting ACGS hashing, schema, or
  invariants.
- EU AI Act Article 12 (record-keeping) and Article 15 (accuracy/robustness
  monitoring) get evidence surfaces without a parallel audit system.
- The Evidence Panel can deep-link to any governed call's full prompt,
  response, latency, token cost, and eval scores — dramatically better
  triage without loosening the authoritative chain.
- Open-source, self-hostable, air-gap-friendly: no data leaves the host; no
  commercial license dependency.
- Cross-link is minimal-surface: two metadata keys in ACGS, two span
  attributes on the Phoenix side. Fully reversible.

### Negative

- A second process to run, monitor, back up, and version-pin. Docker-compose
  pattern in `acgs_governance_eval_mvp/examples/phoenix/` contains the operational footprint.
- New dependency on the OpenTelemetry Python SDK at the edge (not the gate).
  Optional: middleware no-ops cleanly when absent.
- Retention asymmetry must be clearly communicated to auditors to prevent
  "Phoenix shows nothing, therefore no trace exists" being misread as a
  chain-of-custody gap. Mitigated by the ACGS-authoritative rule above and
  the Evidence Panel UI treatment.

### Neutral

- Phoenix's own playground / PXI feature surface should be kept disabled or
  network-restricted in governed environments. The self-hosting hardening in
  `acgs_governance_eval_mvp/examples/phoenix/docker-compose.yml` and the 15.2+ SSRF fix are
  the baseline; air-gapped sites should additionally block outbound model
  APIs at the egress.

## Testing implications

- Existing chain-verify tests must continue to pass with and without OTEL
  installed. The new metadata keys are present only when spans are active.
- New tests cover three paths:
  1. OTEL not importable → middleware behaves as today, chain verifies.
  2. OTEL importable but no active span → middleware behaves as today.
  3. OTEL importable with an active in-memory span (test SDK) → evidence row
     has `trace_id`/`span_id`; span carries `acgs.event_hash`/`acgs.decision`;
     chain verifies.
- A Phoenix integration smoke test (docker-compose + OTLP export) is marked
  `integration` and skipped by default in the unit suite.

## References

- ADR-0001: In-Context Procedure Execution with External Runtime Governance
- `acgs_governance_eval_mvp/examples/phoenix/docker-compose.yml` — hardened self-host
- `acgs_governance_eval_mvp/examples/phoenix/README.md` — operator runbook
- Phoenix releases: https://github.com/Arize-ai/phoenix/releases (verified v15.4.0, 2026-05-05)
- Phoenix self-hosting: https://arize.com/docs/phoenix/self-hosting
- OpenInference semantic conventions: https://github.com/Arize-ai/openinference
- EU AI Act Article 12 / 15 — record-keeping and accuracy/robustness
