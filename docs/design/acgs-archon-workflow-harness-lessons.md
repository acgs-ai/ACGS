# ACGS Archon Workflow Harness Lessons

Status: Proposed
Supplements: `docs/adr/0001-in-context-procedure-execution-external-runtime-governance.md`
Source reviewed: `https://github.com/coleam00/Archon` on 2026-05-11

## Context

Archon is an AI coding workflow engine. Its useful contribution is not another
model prompt, but a harness around agent execution: YAML workflow definitions,
DAG nodes, reusable command prompts, deterministic subprocess nodes, approval
gates, worktree isolation, workflow run state, and event streams for UI or
operator review.

ACGS already has a narrower strategic boundary. ADR-0001 says ACGS should not
become a general workflow orchestrator by default. ACGS governs side effects,
policy checks, role authority, audit trails, and replayable evidence. The
Archon reference is useful only where it strengthens that boundary.

## Current Checkout Boundary

This note is grounded in the current `ACGS/govern-zone` checkout. The local
anchors are:

- `docs/adr/0001-in-context-procedure-execution-external-runtime-governance.md`
  for the runtime-governance boundary.
- `docs/design/acgs-phoenix-observability.md` for the pattern of using external
  systems as adjuncts rather than authoritative controls.
- `tests/test_monorepo_invariants.py` for lightweight repo-shape checks.

`packages/enhanced_agent_bus` is not present in this checkout. Any future
implementation note that depends on that package must first re-check the actual
local tree and add package-local tests in the same change.

## Adoptable Patterns

| Archon pattern | ACGS interpretation | Why it matters |
| --- | --- | --- |
| YAML DAG workflow definitions | Use as an optional harness format around governed procedures, not as the core governance engine. | Gives operators repeatable runbooks without making prompt instructions authoritative. |
| Command and prompt nodes | Treat as reusable procedure prompts that still require runtime gates before side effects. | Separates procedure guidance from authorization. |
| Bash and script nodes | Keep deterministic verification outside the model where possible. | Makes build, lint, hash, and evidence checks reproducible. |
| Approval nodes | Represent human approval as runtime state with identity and audit evidence. | Avoids model self-attestation as approval. |
| Worktree isolation | Run implementation workflows away from the privileged checkout by default. | Reduces blast radius for agent edits and parallel work. |
| Workflow run persistence | Persist run status, working path, current gate, and resume metadata. | Enables recovery without relying on chat transcript memory. |
| Workflow event stream | Emit structured events for node starts, completions, denials, approvals, and artifacts. | Gives UI and operators a stable observability contract. |
| Provider capability flags | Declare which agent backends support tools, sandboxing, structured output, cost caps, or resume. | Prevents silent degradation when a workflow uses unsupported controls. |

## Non-Goals

1. Do not position ACGS as a LangGraph, CrewAI, OpenAI Agents SDK, or Archon
   replacement.
2. Do not make prompt-level workflow success equivalent to governance approval.
3. Do not claim legal, regulatory, or compliance certification.
4. Do not require a workflow engine for simple in-context Hermes procedures.
5. Do not bypass fail-closed runtime gates for command, file, API, network, or
   shell side effects.

## Minimal ACGS Harness Contract

An ACGS workflow harness should be small enough to wrap an existing governed
procedure:

```yaml
name: governed-change
description: bounded implementation with runtime governance
nodes:
  - id: plan
    prompt: create a scoped implementation plan
    side_effects: none

  - id: implement
    depends_on: [plan]
    prompt: implement the approved plan
    side_effects: file_write
    governance:
      pre_tool_gate: required
      audit_event: required

  - id: verify
    depends_on: [implement]
    bash: make verify
    side_effects: shell_command
    governance:
      pre_tool_gate: required
      audit_event: required

  - id: approval
    depends_on: [verify]
    approval:
      role: reviewer
      capture_response: true
```

This is a harness contract, not a new authorization source. Any side-effectful
node must still pass the same policy, role, and audit gates described in
ADR-0001.

## Recommended Implementation Path

1. Start with a read-only schema for a local workflow descriptor.
2. Validate DAG shape: unique node IDs, dependency references, no cycles, and no
   unknown `$node.output` references.
3. Add a dry-run planner that emits the node order and required governance gates.
4. Only then add an executor for deterministic nodes such as `bash` or `script`.
5. Add AI provider execution last, after gate and audit contracts are locked.

The first implementation should not include a Web UI, marketplace of providers,
or remote bot adapters. Those are useful platform features in Archon, but they
are not the ACGS differentiator.

## Acceptance Criteria For A Future PR

1. Read-only workflow validation rejects cycles and unknown dependencies.
2. Side-effectful nodes cannot be executed without a pre-execution gate decision.
3. Denied nodes do not execute.
4. Human approval writes identity, role, timestamp, decision, and evidence hash.
5. Every node transition emits a structured event.
6. Resume state is stored outside the model transcript.
7. Provider capability mismatches fail closed or block before execution.
8. Tests prove that governance decisions remain authoritative over workflow
   status text.

## Decision

Use Archon as a reference for workflow harness mechanics, not as a product positioning template.
ACGS should borrow the repeatability and observability patterns while keeping runtime governance,
fail-closed denial, role separation, and tamper-evident evidence as the authoritative system
boundary.
