# Phase 0 — Research: Enhanced Agent Bus Analysis

**Branch**: `001-enhanced-agent-bus-analysis` | **Date**: 2026-05-14

Each section follows the format: **Decision** / **Rationale** / **Alternatives considered**.

---

## R1. Where do trace events come from?

**Decision**: Subscribe to two existing surfaces — (a) `EnhancedAgentBus` message publish/handle events in `ACGS/packages/enhanced_agent_bus/`, and (b) the `gove-zone` audit-receipt tail produced by `Kernel.dispatch()` in `packages/gove-zone/src/gove_zone/audit.py`. Merge both streams keyed by correlation identifier.

**Rationale**: The spec talks about a single conceptual "inter-agent bus," but the repo splits coordination across two layers: ACGS handles inter-agent message routing (Kafka / Redis / local backends), and gove-zone governs per-tool dispatch and emits `Decision` receipts. A reviewer needs both views to answer "did handler X receive event Y and what did it decide?" — message-only or receipt-only is insufficient.

**Alternatives considered**:
- *Bus-only*: simpler, but loses the `Decision` verdict; reviewers can't see why a step was denied. Rejected.
- *Audit-only*: misses bus dispatches that never reached the kernel (the exact "unwired handler" case Story 2 requires). Rejected.
- *Patch the bus to emit a unified stream*: invasive, would couple the bus package to a new dependency, and violates the "read-only on the bus" constraint (FR-003). Rejected.

---

## R2. How is the trace store made tamper-evident?

**Decision**: Reuse `gove_zone.audit.ChainHashAuditStore` pattern: append-only JSONL, each event carries `event_hash = SHA-256(canonical_json(event_payload + prev_hash))`. The trace store is a sibling instance with its own file path, not a shared writer to gove-zone's audit log.

**Rationale**: The pattern is already battle-tested in this repo, the chain-verification CLI already exists conceptually (we'll add a `agent_bus_analyzer verify` entry point that calls into the same canonical-JSON + SHA-256 primitives), and reusing it preserves Constitution Principle IV (Receipt-Backed Auditability) without introducing a second integrity model the team has to learn.

**Alternatives considered**:
- *Merkle tree per trace*: stronger inclusion proofs, but our use case is "verify the whole trace at read time," which a linear chain satisfies for far less complexity. Rejected.
- *Cryptographic signatures per event*: requires a key-management story we don't need; tamper-evidence (not non-repudiation against an internal actor) is the actual requirement. Deferred to a future spec.
- *External WORM store (S3 Object Lock)*: viable for production deploys, out of scope for v1; the JSONL layout is the format such a store would hold anyway.

---

## R3. Capture-path latency budget

**Decision**: Observer enqueues onto an in-process `asyncio.Queue` of bounded capacity (default 10,000). Persistence runs on a separate writer task. The bus publish call returns the moment the event is enqueued; if the queue is full, the observer drops the event and emits an `ingest-gap` marker covering the gap window.

**Rationale**: SC-005 caps capture-induced latency at 5%. A synchronous fsync-per-event design would blow that budget under burst. Bounded queue + async writer gives us a worst-case "enqueue or skip" decision in microseconds, with no bus blocking ever (FR-013).

**Alternatives considered**:
- *Synchronous write*: simplest, but trivially exceeds the 5% budget under load. Rejected.
- *Unbounded queue*: removes the visible failure mode but turns it into an invisible memory leak. Rejected.
- *Disk-spilled queue (e.g., aiokafka local sink)*: more complex than the floor scale (10K events/day) needs. Deferred.

---

## R4. Query backing store

**Decision**: JSONL files are the source of truth; a SQLite database is built as a derived secondary index keyed by `(correlation_id, causal_index)`. The console queries SQLite for trace lists and looks up the JSONL when rendering a specific trace.

**Rationale**: JSONL alone forces full-file scans for trace lookup, breaking SC-001 (60s p99 inspector load). SQLite gives O(log n) lookup, is trivially rebuildable from JSONL (no separate backup), and is already a workspace-friendly storage choice (zero infra). Crucially, the SQLite index is **not** on the integrity path — a corrupted or missing SQLite file is recoverable from the JSONL.

**Alternatives considered**:
- *Postgres*: heavier than floor scale needs; introduces an infra dependency the rest of `gove-zone` doesn't have. Deferred for higher scale.
- *Single JSONL with linear scan*: violates SC-001 latency target above ~50K events. Rejected.
- *Embedded LMDB / RocksDB*: no clear win over SQLite for our access patterns; adds an unfamiliar dependency. Rejected.

---

## R5. Agent identity model

**Decision**: Extend the existing `actor: str` field used by `gove-zone` (`packages/gove-zone/src/gove_zone/receipt.py:48`) with a non-breaking convention: identifiers follow `<role>:<instance>` (e.g., `claude:worker-03`, `codex:eval-12`, `gemini:eval-07`, `acgs:handler/policy-evaluator`). The analyzer does not introduce a new enum; instead it parses the colon-delimited role for grouping in the wiring-defect view.

**Rationale**: The repo treats `actor` as opaque on purpose — a fixed enum would couple every future agent worker to a release of `gove-zone`. The colon-prefix convention gives us groupable identity for free without imposing schema migration on existing code paths. Where an event lacks the prefix (legacy `actor="anonymous"`), the analyzer classifies it under role `unknown` rather than dropping it.

**Alternatives considered**:
- *Introduce an `AgentRole` enum in gove-zone*: changes a shared package for a feature-local need. Rejected.
- *Map role server-side from a config file*: hidden coupling between deploy config and trace classification. Rejected.
- *Require explicit role field on every emitter*: forces changes to ACGS bus and every worker codebase. Rejected as out of scope.

---

## R6. Constitutional-hash anchoring at capture time

**Decision**: Read `CONSTITUTIONAL_HASH` from the environment, falling back to `ACGS.src.core.shared.constants.CONSTITUTIONAL_HASH`. Record the hash on **every event**, not just the trace header — because the spec edge case "hash rotates mid-run" requires us to identify the exact event index of the rotation.

**Rationale**: Per-event recording costs ~16 bytes per record (the hash is 16 chars in the existing constant); the trace store is already JSONL-heavy with similar per-event overhead. Per-trace recording would silently mask a mid-run rotation, which is a privileged-surface red flag we explicitly committed to surface (Spec Edge Cases).

**Alternatives considered**:
- *Per-trace header only*: cheaper, but loses rotation detection. Rejected per spec edge case.
- *Compute hash from constitution file contents at boot*: changes the existing trust model where the constant is already canonical. Rejected.

---

## R7. Frontend page placement and data-fetching pattern

**Decision**: New page at `acgi-ai/src/routes/console/BusAnalysis.tsx`, routed at `/console/bus`. Data fetching mirrors `Audit.tsx`'s existing `useAudit()` hook pattern (custom hook over a typed REST client) rather than introducing a new query library. The route is registered in `acgi-ai/src/router.tsx` in the same commit that adds the page (Principle V.3 — no orphan routes).

**Rationale**: The console already has a working pattern for fetched governance data; reusing it preserves the privileged-surface CSP and existing identity flow. Introducing a new query library would expand the privileged surface's attack surface for no gain.

**Alternatives considered**:
- *Standalone observability micro-frontend*: privilege-leak risk; the console origin is already the right home. Rejected.
- *Reuse `Audit.tsx` itself with a tab*: tempting, but the data shapes diverge (audit is per-decision, bus is per-trace-tree); cleaner separation is a separate page. Rejected.

---

## R8. Test strategy for handler-wiring detection (Story 2 / Constitution Principle III)

**Decision**: Add a **dispatcher-level** integration test (`tests/test_bus_dispatch_capture.py`) that:

1. Boots a local `EnhancedAgentBus` (its `local_bus.py` backend),
2. Registers an observer via the analyzer's `observer.attach(bus)`,
3. Calls `bus.publish(...)` with a payload destined for a non-existent handler,
4. Asserts that within the configured detection window, the analyzer's store contains an event with status `unwired-handler` and the expected handler name.

**Rationale**: A unit test that imports the classifier and feeds it a synthetic event does NOT prove the bus subscription is wired — exactly the failure mode `~/.claude/rules/review-handler-wiring.md` warns about. The constitution's Principle III demands dispatcher-level verification; we satisfy it by sending real traffic through the real subscription path.

**Alternatives considered**:
- *Unit test only*: violates Principle III. Rejected.
- *End-to-end test against a running ACGS deployment*: too heavy for CI; the local bus backend covers the dispatcher path adequately. Deferred to staging.

---

## R9. Retention enforcement mechanism

**Decision**: A daily maintenance task (invoked via cron, systemd timer, or the deploy host's scheduler — chosen at deploy time, not in code) calls `agent_bus_analyzer.store.expire_older_than(days=90)`. Expiry rewrites the SQLite index but **never** mutates JSONL files. Files older than the retention boundary are moved to an `expired/` subdirectory and indexed as `status=expired` in SQLite.

**Rationale**: Mutating JSONL would defeat the tamper-evidence model. Moving expired files preserves the chain artifacts if a regulator later asks for them, while making them invisible to default queries. The `status=expired` response on query satisfies FR-012 explicitly.

**Alternatives considered**:
- *Delete expired JSONL outright*: irreversibly destroys evidence; conflicts with the spirit of the audit-trail constitution. Rejected.
- *Mark expired in JSONL via an appended marker*: complicates chain verification. Rejected.
