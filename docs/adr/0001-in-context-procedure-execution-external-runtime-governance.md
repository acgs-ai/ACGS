# ADR: In-Context Procedure Execution with External Runtime Governance

## Context

When a defined procedure fits within a frontier model's context window, the model can self-orchestrate the procedure from a system prompt: making local decisions, asking follow-up questions, branching on user input, all without external node routing in the LangGraph, CrewAI, or OpenAI Agents SDK style. This eliminates a class of overhead (extra LLM calls per node, mid-conversation graph state, framework coupling) for procedures that don't otherwise need external routing. It does not eliminate the need for runtime control over what side effects the model is allowed to cause.

External orchestration retains a role for multi-model pipelines, tool use with external state, non-procedural or open-ended tasks, and smaller models, plus any procedure that cannot fit in context. ACGS should be agnostic to whether the agent self-orchestrates in context or routes through an external graph. It governs execution boundaries, not flow.

The repo already contains governance-runtime building blocks:

- `hermes_acgs_bundle/hermes_acgs_middleware.py` defines fail-closed pre-tool, post-tool, and final-answer checks with actions including `ALLOW`, `DENY`, `REQUIRE_HUMAN`, `REWRITE`, `REDACT`, and `SOFT_BLOCK_WITH_EXPLANATION`.
- `hermes_acgs_bundle/evidence_writer.py` defines hash-linked JSONL governance evidence with `input_hash`, `decision`, `policy_ids`, `prev_hash`, and `event_hash`.
- `ACGS/packages/acgs-lite/src/acgs_lite/integrations/hermes.py` defines `HermesGovernor.evaluate(tool_name, tool_input, session_meta)`, blocks denied actions by raising `GovernanceViolationError`, and fails closed on evaluation or audit errors.
- `ACGS/.hermes/governance/hermes.constitution.yaml` defines HRM-001 through HRM-008 for shell confirmation, workspace write boundaries, secret denial, destructive patterns, network allowlisting, read audit, protected governance assets, and required tool names.
- `acgs_governance_eval_mvp/governance/adapters/tools.py` and `acgs_governance_eval_mvp/governance/models.py` define gate-based validation, role and policy versioning, and chain-hash decision records.
- `ACGS/packages/acgs-lite/src/acgs_lite/traces/schema.py` defines `GovernedTraceBundle` for replayable, hash-linked governed action evidence.

## Decision

Adopt in-context procedure execution as the default Hermes reasoning model for defined procedural tasks, and keep ACGS as an external runtime governance boundary for every side-effectful action.

Hermes should self-orchestrate procedural reasoning in context when the procedure fits the model context and the task is a defined procedural conversation. ACGS should not compete with LangGraph, CrewAI, or the OpenAI Agents SDK as a default workflow orchestration engine. ACGS should instead govern execution boundaries: tool calls, API calls, file writes, shell commands, permissions, policy checks, separation-of-duties, audit trails, and verifiable evidence.

Prompt-level governance is advisory. Runtime governance is authoritative. A model may explain the policy, but it must not decide by self-attestation that a side effect is safe, approved, or compliant. The runtime gate must make and record the decision before execution.

## Alternatives considered

### Pure external node routing as the default

Rejected: pure external node routing as the default. For defined procedural conversations with a frontier model, in-context procedure execution can match the task quality of external graph routing without the per-node call overhead. External routing remains useful for specific cases such as multi-model pipelines, tool use with external state, open-ended tasks, smaller models, and procedures too large for context. But it should not be ACGS's default product position, since governing execution is independent from how the agent reaches a tool-call decision.

### Prompt-only compliance as sufficient

Rejected: prompt-only compliance as sufficient. Prompt instructions can shape reasoning and conversation flow, but they are not an authoritative control boundary for tool calls, shell commands, file writes, network access, data access, permissions, audit, or evidence. Prompt-only compliance cannot prove denied actions did not execute and cannot produce tamper-evident runtime records by itself.

### Agent self-reporting as an audit mechanism

Rejected: agent self-reporting as an audit mechanism. Model-generated summaries are useful context, not audit evidence. Audit-supporting evidence must be produced by the runtime: input hashes, policy IDs, decisions, role and policy versions, previous hash, event hash, execution status, result hash, and replay metadata. The agent can describe the evidence, but the runtime must create it.

### Build a complex workflow engine

Rejected as a default direction. ACGS should avoid becoming a general workflow orchestrator unless a future benchmark shows that a specific class of tasks needs external routing. The immediate value is policy-governed execution control around Hermes autonomy.

## Consequences

Positive consequences:

- Hermes can use frontier-model strengths for procedural reasoning without unnecessary external routing.
- ACGS has a clearer product boundary: execution control, auditability, role authority, and replayable evidence.
- Denied actions can be prevented before execution.
- Every governance decision can be recorded as hash-linked or otherwise tamper-evident evidence.
- Policy bundles and role bundles can be versioned independently from prompts.
- The benchmark can show ACGS value where orchestration does not: safe execution, audit completeness, false allow reduction, false deny tracking, and recovery after denial.

Tradeoffs:

- In-context procedures may increase token cost because the procedure is repeated in context.
- Runtime governance adds latency and decision overhead that must be measured.
- Human approval triggers need clear identity and authorization handling.
- Replayable evidence may require careful redaction and hash-only retention for sensitive inputs.

## Risks

- Overgeneralizing in-context procedure execution as a universal replacement for orchestration.
- Treating prompt instructions as enough for compliance-supporting controls.
- Allowing side-effectful tools to bypass the runtime gate.
- Creating audit logs that cannot be verified or replayed.
- Storing raw sensitive data in evidence.
- Failing open when policy evaluation or audit persistence fails.
- Introducing excessive latency without measurement.
- Making role separation symbolic by accepting model self-attestation.

## Non-goals

- Do not build a complex workflow engine unless necessary.
- Do not overfit to LangGraph.
- Do not claim orchestration is useless for all tasks.
- Do not claim prompt instructions are sufficient for compliance.
- Do not bury governance inside the LLM context only.
- Do not rely on the model to self-attest safety.
- Do not create unverifiable audit logs.
- Do not introduce excessive latency without measuring it.
- Do not provide legal, regulatory, or compliance guarantees. The system should produce compliance-supporting, audit-supporting, evidence-ready records.

## Migration path

1. Repo inspection.
   - Inventory existing Hermes middleware, evidence writer, acgs-lite integration, HRM constitution, gate models, and trace bundle schema.
   - Produce a gap list without behavior changes.

2. Passive observation.
   - Capture Hermes proposed tool calls and final checks.
   - Write hash-linked audit events without blocking execution.
   - Establish baseline audit completeness and latency.

3. Advisory governance.
   - Return policy decisions and explanations while running in dry-run or advisory mode.
   - Add policy and role version fields to decision records.
   - Measure false allows and false denies before enforcement.

4. Enforced governance.
   - Intercept every side-effectful action before execution.
   - Execute only after `ALLOW` or approved rewrite.
   - Ensure `DENY` and failed governance evaluation prevent execution.
   - Fail closed when audit persistence fails.

5. Evidence pack.
   - Export replayable governed trace bundles with policy snapshot hash, decision, execution status, execution result hash, previous bundle hash, bundle hash, replay metadata, and verifier results.
   - Verify audit chains and evidence completeness.

6. Benchmark.
   - Compare Mode 1 traditional external procedural orchestration, Mode 2 full procedure in system prompt without runtime governance, and Mode 3 full procedure in system prompt plus ACGS runtime governance.
   - Report task success, information accuracy, consistency, graceful handling, tool-call safety, policy violation rate, false allow rate, false deny rate, audit completeness, latency, token cost, number of LLM calls, number of governance decisions, and recovery after denial.
