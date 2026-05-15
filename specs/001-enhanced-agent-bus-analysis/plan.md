# Implementation Plan: Enhanced Agent Bus Analysis

**Branch**: `001-enhanced-agent-bus-analysis` | **Date**: 2026-05-14 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-enhanced-agent-bus-analysis/spec.md`

## Summary

Build an **observer-only** analysis layer that subscribes to the existing `EnhancedAgentBus` (`ACGS/packages/enhanced_agent_bus/`) and the per-tool `Kernel.dispatch()` audit stream from `packages/gove-zone/`, producing a hash-chained trace store and a privileged console view for governance reviewers. The feature does not introduce a new bus, a new decision type, or a new auth path — it consumes the dispatch events and `Decision` receipts that already flow through the platform and renders them as causally-ordered, tamper-evident traces with constitutional-hash provenance.

Primary surfaces delivered:

- **`packages/agent-bus-analyzer/`** (new Python package): observer subscription, in-process capture queue with backpressure, append-only hash-chained trace store, classifier, query API.
- **`acgi-ai/src/routes/console/BusAnalysis.tsx`** (new console page): trace list, single-trace inspector, wiring-defect summary.
- **Trace contract** in `packages/agent-bus-analyzer/contracts/` (Pydantic models + JSON Schema) shared between the Python store and the TypeScript console.

## Technical Context

**Language/Version**: Python 3.11 (workspace floor; matches `gove-zone`, ACGS bus); TypeScript 5.x via Vite + React 19 for the console (matches `acgi-ai/`).

**Primary Dependencies**:
- Python: `pydantic>=2` (already in `acgs-lite`), `gove_zone.audit.ChainHashAuditStore` (reuse — do not fork the chain logic), `enhanced_agent_bus` (subscribe via its existing observer/handler registration surface; no fork).
- Frontend: React 19, Tailwind 4, the existing console data-fetching pattern used by `acgi-ai/src/routes/console/Audit.tsx` (extend, do not introduce a new client).

**Storage**:
- **Primary** — append-only JSONL trace store with per-event SHA-256 chain hash (`ChainHashAuditStore` pattern from `packages/gove-zone/src/gove_zone/audit.py`). Default path `var/agent-bus-analyzer/traces/<YYYY-MM-DD>.jsonl`, configurable.
- **Secondary (derived)** — SQLite index keyed by `(correlation_id, causal_index)` for fast trace lookup. The SQLite index is **not** on the integrity path; it is rebuildable from the JSONL.

**Testing**: `pytest` (workspace standard) with dispatcher-level integration tests as required by Constitution Principle III. Frontend: `vitest` + `@testing-library/react`, plus a Playwright smoke against the local console build.

**Target Platform**: Linux server (Python package deployed alongside the existing ACGS bus host); modern browser for the console (Chromium-class, matching `acgi-ai/` baseline).

**Project Type**: web (Python backend package + TypeScript frontend page).

**Performance Goals**:
- Capture path adds ≤5% end-to-end bus dispatch latency (SC-005).
- Trace inspector renders in ≤60s for 99% of runs at floor scale (SC-001).
- Wiring-defect summary refresh ≤60s (SC-003).

**Constraints**:
- Read-only on the bus and on the gove-zone audit chain (Spec FR-003, FR-010).
- Fail-closed on integrity-store unavailability (FR-008, SC-004).
- 90-day retention default (FR-012); expired traces surface "expired" status, not 404.
- Backpressure recorded as "ingest gap" markers, never bus-blocking (FR-013).

**Scale/Scope**:
- Floor: 10K captured events/day → ~900K events at 90-day retention.
- Trace inspector lookup p95 ≤200ms at floor scale (derived from SC-001).
- Designed to horizontally partition by date file; not required to support 1M+ events/day in v1.

## Constitution Check

*Gate: must pass before Phase 0 research. Re-checked after Phase 1 design.*

| Principle | Verdict | Justification |
|---|---|---|
| **I. Constitutional Hash Integrity** | PASS | Feature reads `CONSTITUTIONAL_HASH` from `ACGS/src/core/shared/constants.py` (or env override) as a record field. No sealed file is modified. Trace records embed the active hash as data; they do not mint a new hash. |
| **II. Subproject Boundary Isolation** | PASS | New code is contained in `packages/agent-bus-analyzer/` (workspace member, not a submodule) and `acgi-ai/src/routes/console/BusAnalysis.tsx`. Submodules (`acgs-lite`, `clinicalguard`, `Acgs-Swarm`) are not touched. The ACGS bus package is consumed via its public observer surface, not patched. |
| **III. Fail-Closed Governance** | PASS | Feature is observer-only — not on any authorization path (FR-010). The capture path fails closed if the integrity store is unreachable (FR-008). Wiring tests run at dispatcher level (mirror `packages/gove-zone/tests/test_kernel_dispatch.py`): we exercise `EnhancedAgentBus.publish()` and verify a trace event lands, not just call the observer function directly. |
| **IV. Receipt-Backed Auditability** | PASS | Trace events are SHA-256 hash-chained per trace (mirrors `gove_zone.audit.ChainHashAuditStore`). Receipts reference the gove-zone audit receipt hash where one exists, joining the two chains for cross-validation. Replay is verifiable offline by re-hashing the JSONL. |
| **V. Privileged Surface Containment** | PASS | New console page lives under `acgi-ai/src/routes/console/` (privileged origin). CSP stays `style-src 'self'` — no inline styles, no CDN fonts, no third-party scripts. Routing plumbing for the page lands in the same commit (no orphan page). Reads go through the existing console identity layer; no new auth surface. |

**Gate**: PASS. No violations require `Complexity Tracking` entries.

## Project Structure

### Documentation (this feature)

```text
specs/001-enhanced-agent-bus-analysis/
├── spec.md              # Feature specification (already authored)
├── plan.md              # This file
├── research.md          # Phase 0 — decisions + alternatives
├── data-model.md        # Phase 1 — entity definitions
├── contracts/
│   ├── trace-event.schema.json   # JSON Schema for one captured event
│   ├── trace-query.schema.json   # JSON Schema for the query response
│   └── observer-interface.md     # Python observer contract (read-only)
├── quickstart.md        # Phase 1 — how to run the observer against a local bus
├── checklists/
│   └── requirements.md  # Spec quality checklist (already authored, passing)
└── tasks.md             # Phase 2 — generated by /speckit-tasks
```

### Source Code (repository root)

```text
packages/agent-bus-analyzer/                 # NEW workspace package (not a submodule)
├── pyproject.toml
├── src/agent_bus_analyzer/
│   ├── __init__.py
│   ├── observer.py        # Subscribes to EnhancedAgentBus + gove-zone audit tail
│   ├── capture.py         # In-process queue, backpressure, ingest-gap markers
│   ├── store.py           # Hash-chained JSONL append + SQLite derived index
│   ├── classifier.py      # Status classification (completed / policy-violation / ...)
│   ├── wiring.py          # Handler registry snapshot + wiring-defect detection
│   ├── query.py           # Public query API consumed by the console
│   ├── models.py          # Pydantic models (Trace, Event, WiringDefectFinding, ...)
│   └── cli.py             # `python -m agent_bus_analyzer verify <trace-id>` integrity check
└── tests/
    ├── test_capture_readonly.py        # Proves observer never mutates a bus event
    ├── test_chain_integrity.py         # Tampering detection round-trip
    ├── test_backpressure_gap_marker.py # Ingest-gap behavior under burst
    ├── test_wiring_defect_detection.py # Declared-but-not-routed handler surfaces
    ├── test_bus_dispatch_capture.py    # DISPATCHER-LEVEL: publish() -> trace landed
    └── test_classifier.py              # Status classification accuracy

acgi-ai/src/routes/console/
├── BusAnalysis.tsx        # NEW page — trace list + inspector + defect summary
├── BusAnalysis.test.tsx   # Component tests
└── (existing pages)       # Audit.tsx, Agents.tsx, etc. unchanged

acgi-ai/src/lib/
└── bus-analysis-client.ts # NEW — typed wrapper over query API; mirrors trace-event.schema.json

acgi-ai/src/router.tsx
                            # MODIFIED to register /console/bus route — landed in same commit (Principle V.3)
```

**Structure Decision**: New Python package under `packages/agent-bus-analyzer/` (workspace member, not a submodule) plus a privileged-console page under `acgi-ai/src/routes/console/BusAnalysis.tsx`. The Python package is the source of truth for trace records and integrity verification; the console page is a read-only viewer. No changes to `packages/gove-zone/`, no changes to `ACGS/packages/enhanced_agent_bus/`, no new submodules.

## Complexity Tracking

> Filled only when Constitution Check has violations. **No violations recorded.**
