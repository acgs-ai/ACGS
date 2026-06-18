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

## Collaboration platforms with built-in compliance (e.g. Mattermost)

Team-collaboration platforms increasingly ship governance suites *and* AI agents.
Mattermost is a representative, open-source example. Its governance is largely
*complementary* to a receipt gate: it operates at a different point on the action
timeline. Entries dated to when they were verified (June 2026); most features are
Enterprise/Enterprise-Advanced-gated, not in the MIT Team Edition.

| Mattermost capability | Layer | Governs | First-class portable per-decision receipt? |
|---|---|---|---|
| Audit logging (Beta) | Observability | Records API/mmctl events to file/syslog/TCP | No — JSON log entries, not per-decision |
| Compliance export / e-discovery | Archive | Daily export to CSV / Actiance / Global Relay for downstream supervision | No — message archive, not authorization |
| Data retention + Legal Hold | Lifecycle | Preserve/expire data; Legal Hold *Secret* verifies file authenticity | No — preserves data; Secret proves files, not decisions |
| RBAC + ABAC (Ent. Advanced) | Authorization | Roles/schemes; attribute-based channel + some action gating | No — grants access, no decision artifact |
| Mattermost Agents — MCP tool policy | Agent execution gate | Per-tool **allow / require-approval / disable** + inherited user RBAC | No — token-usage logs + OTel traces |

The compliance stack (audit, export, retention, legal hold) is **archive-centric
and after-the-fact** — it records and preserves; it does not authorize a side
effect before it runs, and there is no fail-closed gate on human or agent actions.
The one genuine pre-execution control is **Mattermost Agents' per-MCP-tool
approval policy** — admins set each tool to allow, require approval, or disable.
That is real human-in-the-loop gating and deserves acknowledgement as prior art.
The evidenced difference is *resolution and artifact*: it is a coarse per-*tool*
toggle, not evaluation of the specific action **plus arguments** against a policy
bundle; it has no fail-closed default (MCP can't be globally disabled from the
console); and it produces no signed, portable decision receipt a relying party can
verify before accepting the action. ACGS / gove-zone's narrower bet is exactly
that finer-grained, fail-closed, receipt-emitting gate at the `tools/call`
boundary — which is also a natural composition seam: the same Mattermost Agents
MCP surface is a candidate reference integration for the gate (see
[`ROADMAP.md`](ROADMAP.md)). Contrast by evidence, not a knock — a receipt gate
and Mattermost's compliance suite stack cleanly.

Sources, verified as of June 2026:

- Audit logging — <https://docs.mattermost.com/administration-guide/manage/logging.html>
- Compliance export / e-discovery — <https://docs.mattermost.com/administration-guide/comply/compliance-export.html>
- Data retention — <https://docs.mattermost.com/administration-guide/comply/data-retention-policy.html>
- Legal hold — <https://docs.mattermost.com/administration-guide/comply/legal-hold.html>
- Advanced permissions / ABAC — <https://docs.mattermost.com/administration-guide/manage/admin/attribute-based-access-control.html>
- Mattermost Agents (MCP tool approval) — <https://docs.mattermost.com/agents/docs/admin_guide.html>

## Agent sandbox frameworks (e.g. flue)

A newer category packages the *sandbox itself* as the agent framework — give the
agent an isolated workspace to read, write, and execute in, and treat that
containment as the safety story. flue (by Astro / `withastro`, Apache-2.0) is a
representative, fast-rising example. Its governance is *complementary* to a
receipt gate: it bounds the environment an agent runs in; it does not authorize
the specific side effects that cross out of that environment. Entries verified
June 2026; flue is moving quickly.

| flue capability | Layer | Governs | First-class portable per-decision receipt? |
|---|---|---|---|
| Virtual sandbox (default) | In-memory workspace | `just-bash` filesystem/exec scratch space; **not** an OS or network-isolation boundary (its docs note generated runtimes permit network access) | No |
| Local sandbox | Host process | Direct host filesystem + shell; for trusted scenarios, no isolation | No |
| Remote sandbox (Daytona, Cloudflare Sandbox) | Provider-managed VM/container | Container-backed Linux environment off the application host | No |
| Observability | Telemetry | Export traces/metrics via OpenTelemetry, Braintrust, or Sentry | No — telemetry, not a per-decision artifact |

flue's safety primitive is **containment**: confine *where* an agent operates so
that runaway execution or filesystem damage stays bounded. That is real and
useful, and it composes with a receipt gate rather than competing with it. The
evidenced difference is *containment vs authorization-plus-non-repudiation*: a
sandbox bounds the room, but it does not decide which doors may open, nor leave a
portable proof of who opened them. Two gaps follow directly from flue's own
documentation. First, its default virtual sandbox is **not a network-isolation
boundary** (egress is permitted), so an agent inside it can still exfiltrate data
or call a destructive API — the sandbox confines the filesystem, not the
*semantics* of an outbound action. Second, its action record is
OpenTelemetry-style **observability** — operator-trusted and mutable — not a
signed, sealed, per-decision artifact a relying party *outside* the runtime can
verify *before* accepting the action; and its published sandbox and tools guides
document no policy-decision or per-action approval gate and no fail-closed default
on outbound side effects. ACGS / gove-zone's narrower bet sits exactly at that
egress boundary: receipt-gate the side effects that leave the sandbox (network,
payments, writes to production), fail closed without a valid Decision Receipt, and
emit an independently verifiable artifact. The natural composition is
defense-in-depth — sandbox the workspace with flue, receipt-gate what crosses out
of it. Contrast by evidence, not a knock.

Sources, verified as of June 2026:

- flue — <https://github.com/withastro/flue>
- flue sandboxes guide — <https://flueframework.com/docs/guide/sandboxes/>
