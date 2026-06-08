# Glossary

> **Core invariant: No valid Decision Receipt, no side effect.**


**ACGS** — Agentic Constitutional Governance System; in this repo, the broader governance platform and documentation spine.

**gove-zone** — The governed-runtime kernel package at `packages/gove-zone/`, Python module `gove_zone`.

**Decision Receipt** — A verifiable proof-of-decision artifact binding actor, action, arguments, policy, validator, authority, audit anchor, expiry, hash, and optional signature.

**Side effect** — Any operation that changes external state or causes real-world impact: file write, API call, database update, email, payment, deployment, shell command, MCP tool call, etc.

**Fail-closed** — Refuse execution when governance cannot prove authorization. Errors, missing receipts, malformed evidence, audit failure, or policy failure do not become implicit allow.

**Executor** — The component that would run the side effect. In ACGS, it must verify a Decision Receipt first.

**Actor** — The principal proposing the action, usually the agent or runtime caller. Must be supplied from trusted runtime context at the gate.

**Validator** — The authority principal that issues the governance decision. Must be distinct from the actor/proposer.

**Policy bundle** — Versioned and hash-bound policy material used to decide whether an action is allowed, denied, transformed, or escalated.

**Authority** — The grant or basis under which a validator may authorize the action.

**Audit replay** — Re-checking recorded evidence against policy/audit context to confirm the original decision still matches or to detect tampering/drift.

**Proof pack** — Exported local evidence bundle containing receipts, audit JSONL, verification output, conformance results, manifest, and limitations.

**MCP** — Model Context Protocol; a protocol for connecting models/agents to tools. MCP connects tools; ACGS governs whether tool calls may execute.

**Guardrail** — A system that constrains model content, outputs, prompts, or behavior. Guardrails complement ACGS but do not replace side-effect authorization.

**Orchestration** — Framework logic that routes, schedules, plans, retries, or composes agent work. ACGS authorizes side effects inside/under orchestration.

**Receipt-gated execution** — Execution pattern where a tool runs only if a Decision Receipt verifies against the exact execution context.

**Tamper-evident evidence** — Evidence that reveals modification through hashes, signatures, or chain links; not necessarily immutable storage.
