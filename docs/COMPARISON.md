# Honest comparison

> **Core invariant: No valid Decision Receipt, no side effect.**


ACGS / gove-zone is not trying to replace the surrounding ecosystem. It fills a narrower gap: side-effect authorization with verifiable receipts.

| System | What it does | What ACGS adds | Non-attack summary |
|---|---|---|---|
| MCP | Connects models/agents to tools through a protocol. | Governs whether a specific `tools/call` may execute. | MCP connects tools; ACGS governs whether tools may execute. |
| OpenAI Agents SDK-style runtimes | Orchestrate model/tool interactions and agent loops. | Receipt gate at the tool wrapper/executor boundary. | Agent frameworks orchestrate work; ACGS authorizes side effects. |
| LangGraph | Builds graph workflows with nodes, state, and tool calls. | Receipt verification before side-effect nodes/tools. | LangGraph routes execution; ACGS decides if a side effect is legitimate. |
| Guardrails systems | Moderate/shape model text, structured output, prompts, or content. | Enforces actor/action/argument/policy/audit legitimacy before execution. | Guardrails moderate content; ACGS enforces execution legitimacy. |
| Sandboxing | Contains execution in a restricted environment. | Decides whether execution is authorized before it begins. | Sandboxes contain execution; ACGS decides whether execution is authorized. |
| IAM/RBAC | Authenticates users/services and grants broad permissions. | Binds actor, action, arguments, policy, validator, authority, receipt, and audit evidence to one decision. | IAM authenticates principals; ACGS proves a specific side-effect decision. |
| Audit logs | Record what happened. | Requires policy/receipt evidence before execution and records denials too. | Audit logs observe; ACGS gates and audits. |
| Policy engines | Evaluate rules. | Connects policy verdicts to Decision Receipts, executor validation, audit chain, and replay. | Policy engines decide; ACGS packages the decision into an execution membrane. |

## Core distinction

Most agent tooling focuses on making actions possible. ACGS focuses on proving whether actions are legitimate.

## What to combine

A production-adjacent stack should combine:

- IAM for authenticated caller identity;
- ACGS for receipt-gated authorization of exact side effects;
- sandboxing for containment;
- content guardrails for text/model behavior;
- MCP or framework adapters for tool connectivity;
- SIEM/WORM storage for durable audit retention;
- key management/PKI for signing keys;
- monitoring and incident response for operations.

ACGS is the execution legitimacy layer, not the whole safety stack.
