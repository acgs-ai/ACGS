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

## Microsoft agent governance

Microsoft ships several agent-governance products. They are largely
*complementary* to a receipt-gated execution layer — each answers a different
question — so this is a layer comparison, not a head-to-head. Product details
move quickly; entries are dated to when they were verified.

| Microsoft offering | Layer | Governs | First-class portable per-decision receipt? |
|---|---|---|---|
| Entra Agent ID | Identity / lifecycle | Agent authentication, authorization, conditional access, lifecycle | No — identity/activity logs |
| Purview for AI (DSPM for AI) | Data governance / compliance | Sensitivity labels, DLP, eDiscovery, retention, audit of AI interactions | No — unified audit log, not portable per-decision |
| Copilot Control System | Admin deployment control plane | Tenant approve/publish/deploy/block of agents (pre-deployment) | No — admin audit events |
| Azure AI Foundry Guardrails | Content-safety execution gate | Content-safety categories at input / tool-call / tool-response / output (tool-call & response are Preview; Foundry Agent Service only) | No — Azure Monitor events |
| Agent Governance Toolkit (AGT) | Runtime policy-enforcement middleware | Pre/post tool-call policy (Cedar/OPA), fail-closed, Merkle-chained audit, 15+ frameworks | Partial — see below |

The first four operate at the identity, data-governance, deployment, and
content-safety layers respectively. None decides whether one specific tool-call
side effect may execute against an arbitrary business policy, and none emits a
portable per-decision artifact; they sit alongside a receipt gate rather than in
place of it. (Foundry Guardrails is the closest of the four to a runtime gate,
but it covers content-safety categories and applies only to agents built in
Azure Foundry Agent Service.)

**Agent Governance Toolkit (AGT)** is the structurally nearest comparison, and
deserves a fair one. It is open-source (MIT), framework-agnostic across 15+
runtimes, explicitly fail-closed, and keeps a SHA-256 Merkle-chained audit log
with external inclusion proofs (`get_proof()`) — genuinely strong engineering,
and broader in framework coverage than this alpha project is today. The
evidenced difference is *receipt-centric vs audit-centric*: per AGT's own
audit-and-compliance documentation, its chain is built for forensics and
compliance reporting after the fact, and it has no first-class **decision
receipt** — no pre-execution, sealed, self-contained artifact, signed before the
side effect fires, that a relying party *outside* the enforcement runtime can
independently verify before accepting the action, and no receipt lifecycle
(expiry / revocation / delegation). ACGS / gove-zone's narrower bet is exactly
that artifact: a Decision Receipt issued before execution and verifiable on its
own (hash-bound, optionally Ed25519-signed), vendor-neutral by format — with
cross-host reference validators still on the roadmap (see
[`CLAIMS.md`](CLAIMS.md) and [`ROADMAP.md`](ROADMAP.md)). This is a contrast by
evidence, not a knock: AGT and a receipt gate could even compose.

Sources, verified as of June 2026:

- Entra Agent ID — <https://learn.microsoft.com/en-us/entra/agent-id/identity-professional/microsoft-entra-agent-identities-for-ai-agents>
- Purview for AI — <https://learn.microsoft.com/en-us/purview/ai-microsoft-purview>
- Copilot Control System — <https://learn.microsoft.com/en-us/microsoft-365/copilot/copilot-control-system/security-governance>
- Azure AI Foundry Guardrails — <https://learn.microsoft.com/en-us/azure/foundry/guardrails/guardrails-overview>
- Agent Governance Toolkit — <https://github.com/microsoft/agent-governance-toolkit> and <https://microsoft.github.io/agent-governance-toolkit/tutorials/04-audit-and-compliance/>
