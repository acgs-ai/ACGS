# Feature Specification: Enhanced Agent Bus Analysis

**Feature Branch**: `001-enhanced-agent-bus-analysis`

**Created**: 2026-05-14

**Status**: Draft

**Input**: User description: "Build an observability and analysis layer over the inter-agent message bus used in govern-zone's multi-agent runtime. Capture every dispatch/response across agents (Claude, Codex, Gemini workers + ACGS governance handlers), persist structured traces with constitutional-hash provenance, and surface a queryable view that flags policy violations, dispatch failures, and unwired handlers. Read-only on the bus itself; the analysis layer must be fail-closed against tampering and must not weaken existing governance gates."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Investigate a Suspect Run (Priority: P1)

A governance reviewer is told a multi-agent run produced an output that may have violated policy. They open the analysis view, filter by the run's correlation identifier, and walk every dispatch/response in order — seeing which agent received which message, which handler responded, what governance verdicts fired, and which (if any) constraints were tripped.

**Why this priority**: Without trace reconstruction, post-hoc governance review is guesswork. This is the load-bearing capability that makes everything else in the feature defensible — it is the difference between "we believe the run was compliant" and "we can prove what happened."

**Independent Test**: Trigger a known multi-agent run, then load the analysis view filtered to that run's correlation ID. The view must list every dispatch and response in causal order, name the responding handler, and show the governance verdict attached to each step. Pass = a reviewer can answer "did handler X receive event Y and what did it decide?" without reading raw logs.

**Acceptance Scenarios**:

1. **Given** a completed run with correlation ID R, **When** the reviewer opens the analysis view and filters to R, **Then** every dispatch/response pair from that run appears in causal order with timestamp, source agent, target handler, and governance verdict.
2. **Given** a run that included a policy-flagged response, **When** the reviewer opens that run, **Then** the flagged step is visibly marked with the rule that fired and a link to the constitutional-hash version under which the rule was evaluated.
3. **Given** a run that completed without violations, **When** the reviewer opens that run, **Then** the trace is marked "clean" with the constitutional-hash provenance shown for the entire trace.

---

### User Story 2 - Catch Wiring Defects Before They Reach Production (Priority: P2)

An operator deploys a new agent handler or governance rule. The analysis layer detects events that were dispatched but never received by any registered handler ("unwired handlers"), and dispatches that failed (timeouts, rejections, exceptions). The operator can see these defects within minutes of the deploy, before the next governance review cycle.

**Why this priority**: Unwired handlers are a recurring failure mode in this codebase — a function is defined and tests pass, but the dispatcher never routes traffic to it. This story turns that silent failure into a loud one.

**Independent Test**: Intentionally register a handler in source but omit it from the dispatcher's routing table, then send the event it expects. The analysis layer must surface an "unwired handler" finding within one minute, naming the expected handler and the event that had no destination.

**Acceptance Scenarios**:

1. **Given** an event was dispatched on the bus, **When** no handler responded within the configured timeout, **Then** the analysis layer marks that event as a "dispatch failure" with the expected handler (if known from registration metadata) and the timeout reason.
2. **Given** a handler is declared in source code but missing from the dispatcher's runtime registry, **When** an event matching its signature is dispatched, **Then** the analysis layer marks the event as "unwired" and surfaces the declared-but-unregistered handler name in the daily wiring-defect summary.
3. **Given** a dispatcher exception during routing, **When** the operator opens the analysis view, **Then** the failed dispatch is visible with its exception class, message, and the responsible dispatcher entry point.

---

### User Story 3 - Prove the Audit Trail Has Not Been Tampered With (Priority: P3)

A compliance reviewer needs to attest that the trace history they are reviewing has not been altered since the run completed. They open any trace and see a constitutional-hash chain that ties each event to the governance version that was active when the event was recorded, plus an integrity check that confirms the trace has not been modified after the fact.

**Why this priority**: Tamper-evident audit trails are the difference between an observability tool and a governance-grade analysis layer. Without this, a malicious or careless actor could erase evidence of a violation. P3 because P1 and P2 deliver value immediately, while this story makes the artifact admissible.

**Independent Test**: Capture a trace, then attempt to modify a recorded event in storage. The integrity check on the analysis view must show "tampering detected" with the specific event identified. Pass = the system refuses to display a tampered trace as "clean."

**Acceptance Scenarios**:

1. **Given** a recorded trace, **When** the reviewer opens it, **Then** the view displays the constitutional-hash version active during the run and an integrity status (intact / tampered / unknown).
2. **Given** a trace whose stored events have been modified after the fact, **When** the reviewer opens it, **Then** the view shows "tampering detected" and refuses to mark the trace clean even if no policy violation is otherwise recorded.
3. **Given** the constitutional-hash chain cannot be verified (e.g., missing predecessor hash), **When** the reviewer opens the trace, **Then** the view marks integrity as "unknown" rather than silently passing it as intact.

---

### Edge Cases

- A dispatch is recorded but the corresponding response is never recorded (the recording process crashed mid-pair). The trace must mark the pair as "incomplete" rather than dropping the dispatch or fabricating a response.
- A burst exceeds the analysis layer's ingest capacity. The bus itself must remain unaffected; the analysis layer must drop into a backpressure mode that records "ingest gap from T1 to T2" rather than silently losing events.
- An agent emits a response with no corresponding prior dispatch (orphan response). The trace records the orphan and the analysis surface flags it for review.
- The constitutional hash rotates mid-run. The trace records both the old and new hash and shows the exact event index at which the rotation occurred.
- A reviewer queries a trace that has aged past the retention boundary. The view returns "expired" with the retention policy under which the trace was purged, rather than not-found.
- The analysis layer's own integrity store becomes unreachable. The capture path must fail closed (refuse to record new events) rather than write events that cannot be hash-chained.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST capture every dispatch and every response that flows across the inter-agent bus, with no sampling, for runs the operator has marked as governance-relevant. The "governance-relevant marking" mechanism is controlled by the `BUS_ANALYZER_CAPTURE_MODE` env var: `all` (default — capture every event without per-run opt-in) or `marked-only` (capture only events whose `correlation_id` is registered via the operator-marking API). Precedence: env var > deployment config file > per-tenant override. Unset = `all`.
- **FR-002**: System MUST record, for each captured event: the source agent identity, the target handler identity (declared and resolved), the event payload reference, a causal-order index, the wall-clock timestamp, and the constitutional-hash version active at capture time.
- **FR-003**: System MUST be read-only with respect to the inter-agent bus. The act of capturing an event MUST NOT alter the event, delay its delivery beyond an agreed budget, or change the response any handler would have produced.
- **FR-004**: System MUST persist captured events to a tamper-evident store, where every event references the hash of its predecessor in the same trace so any after-the-fact modification is detectable.
- **FR-005**: System MUST provide a query surface where an operator can retrieve all events belonging to a single run by correlation identifier, ordered by causal index.
- **FR-006**: System MUST automatically classify each recorded event into one of the following statuses: completed, policy-violation, dispatch-failure, unwired-handler, orphan-response, or incomplete-pair. Ingest-gap rows are recorded with `status="ingest-gap"` and are excluded from both the hash chain and SC-002 classification accuracy metrics (see `data-model.md` chain rules and the `_verify_chain` implementation in `store.py`).
- **FR-007**: System MUST detect "unwired handler" conditions by comparing the set of declared handlers (from the runtime registry) against the set of events that were dispatched without any responder, and surface unresolved entries in a wiring-defect summary refreshed at least every 60 seconds.
- **FR-008**: System MUST fail closed if its own integrity store is unavailable: new events MUST NOT be recorded in a non-hash-chained form, and the operator surface MUST display the degraded state.
- **FR-009**: System MUST display, for any trace, the constitutional-hash version under which it was recorded, and an integrity status of intact, tampered, or unknown.
- **FR-010**: System MUST NOT weaken any existing governance gate. Capture and analysis paths MUST run on the read side of bus events and MUST NOT be in the authorization path for any action.
- **FR-011**: System MUST enforce role-based access on the query surface so that only authorized reviewers (governance reviewers, operators, compliance) can read traces. Unauthorized reads MUST be rejected and themselves recorded as audit events.
- **FR-012**: System MUST retain captured traces for a configurable retention window; the default is 90 days from run completion, with no hard minimum floor — deployments may tighten or extend retention to satisfy tenant or regulatory requirements (confirm against `packages/clinicalguard/` tenant requirements before onboarding any clinical tenant). Expired traces MUST return an explicit "expired" status on query, not a generic not-found.
- **FR-013**: System MUST handle ingest backpressure by recording explicit "ingest gap" markers covering the affected time window, rather than silently dropping events or blocking the bus.

### Key Entities

- **Trace**: A complete record of one governance-relevant run. Owns a correlation identifier, a constitutional-hash version, an ordered sequence of Events, and an integrity status.
- **Event**: A single dispatch-or-response observation on the bus. Carries source agent, target handler, payload reference, causal index, timestamp, predecessor hash, status classification, and (where applicable) the rule that flagged it.
- **Handler Registry Snapshot**: The set of handlers known to the runtime at a point in time, used to compute "unwired handler" findings by comparison against observed responders.
- **Wiring Defect Finding**: A derived record identifying an event that was dispatched but had no live handler, or a handler that was declared but received no traffic for events it was registered to handle.
- **Constitutional Hash Anchor**: A reference to the version of the governance constitution that was active when a trace or event was recorded.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For 99% of governance-relevant runs, a reviewer can reconstruct the full causal sequence of dispatch/response pairs within 60 seconds of opening the trace view.
- **SC-002**: Across a 30-day window, the analysis layer correctly classifies at least 95% of captured events into one of the defined statuses (completed, policy-violation, dispatch-failure, unwired-handler, orphan-response, incomplete-pair), measured against a sampled human review.
- **SC-003**: A wiring defect (handler declared but not routed) is surfaced in the wiring-defect summary within 60 seconds of the first event it should have received.
- **SC-004**: 100% of stored traces display either an intact or a tampered/unknown integrity status — no trace renders as "clean" without an underlying integrity verification.
- **SC-005**: Bus dispatch latency, measured end-to-end across all agents, does not regress by more than 5% after the capture path is enabled, versus a pre-feature baseline.
- **SC-006**: Zero recorded incidents in which a governance gate fails open because the analysis layer was unavailable, degraded, or producing errors. The analysis layer is never on the authorization path.

## Assumptions

- **Inter-agent bus exists and is observable.** The govern-zone runtime already exposes a dispatch/response model across Claude/Codex/Gemini workers and ACGS governance handlers from which an observer can subscribe without becoming part of the authorization path. If no such observation point exists, that subscription point must be created as a precondition, not as part of this feature.
- **Constitutional hash is an existing, queryable artifact.** The repo already maintains a `Constitutional Hash:` marker on sealed governance artifacts; this feature uses that hash as the anchor for trace provenance rather than minting a new identifier.
- **Retention default of 90 days.** Aligns with standard audit-trail practice for governance evidence and gives a clear default in the absence of an explicit policy. Retention may be tightened or extended per deployment.
- **Backpressure is preferred over bus-blocking.** Recording an "ingest gap" marker is acceptable; pausing or slowing the actual inter-agent bus is not. The bus is the production path; the analysis layer is the observer.
- **Reviewers are authenticated and authorized through the existing console identity surface.** This feature does not introduce a new identity system; it relies on the privileged console origin's existing auth (see `acgi-ai/CLAUDE.md` and console CSP rules).
- **Initial volume target.** First production deployments are scoped to lab/internal workloads — order of 10,000 captured events per day. The design must accommodate horizontal scale but is not required to support million-event/day workloads in this first version.
- **Out of scope for v1.** Real-time alerting to external systems (Slack, PagerDuty), automated remediation of wiring defects, and replay/re-execution of recorded traces. These are deferred to subsequent specs.
