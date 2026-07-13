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

## Governance postures and evidence boundaries

Products at the agent action boundary can observe events, enforce a policy
before an action, or aim to provide a portable authorization artifact. These
are overlapping capabilities rather than a ranking of products:

| Posture | Boundary | Examples / claim boundary |
|---|---|---|
| **Observed evidence** | Records or reconstructs events after they occur. | Logs, traces, and audit systems; useful for investigation, but not pre-execution authorization proof. |
| **Enforcement-capable** | Evaluates or blocks a proposed action at a configured pre-execution boundary. | AWS AgentCore Policy in `ENFORCE` mode, Microsoft ACS/AGT, Galileo Agent Control, and configured NeMo Guardrails surfaces each publish enforcement capabilities within their respective scopes. |
| **Portable receipt target (ACGS beta)** | Target contract: an executor-verifiable authorization artifact binds the specific decision before the side effect. | ACGS's target is exact action/argument/actor/policy/scope binding, bounded expiry, single-use semantics, provenance preservation, and independently anchored evidence where the named evidence gates are met. |

ACGS does not claim to be the only option that enforces before an action. Its
target distinction is portable executor-verifiable Decision Receipt semantics
and provenance-preserving assurance, not a claim that other enforcement systems
only observe harm. Current local capability and configuration limits remain in
[CLAIMS.md](CLAIMS.md) and [SECURITY_MODEL.md](SECURITY_MODEL.md). This is a
technical membrane discussion, not a compliance certification. See
[AGENT_STACK_GOVERNANCE.md](AGENT_STACK_GOVERNANCE.md) for where each adapter
plugs into the agent stack.

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

| Microsoft offering | Layer | Published boundary relevant to this comparison |
|---|---|---|
| Entra Agent ID | Identity / lifecycle | Agent identity, authorization, conditional access, and lifecycle controls. |
| Purview for AI (DSPM for AI) | Data governance / compliance | Sensitivity, DLP, eDiscovery, retention, and audit controls for AI interactions. |
| Copilot Control System | Admin deployment control plane | Tenant approval, publishing, deployment, and blocking controls for agents. |
| Azure AI Foundry Guardrails | Content-safety and tool-call controls | Guardrails at input, tool-call, tool-response, and output boundaries, subject to the product's documented scope. |
| Agent Governance Toolkit (AGT) / Agent Control Specification (ACS) | Runtime policy-enforcement middleware | Published deterministic, fail-closed policy intervention around tool calls, escalation semantics, and audit/evidence capabilities. |

The offerings operate at different layers and may be composed. This comparison
does not assert a feature-completeness verdict or infer the absence of an
unlisted capability from any provider. In particular, it does not treat
runtime enforcement as merely post-hoc logging.

**Agent Governance Toolkit (AGT)** and its Agent Control Specification (ACS)
are the structurally nearest governance comparison. Their published materials
describe pre-tool-call intervention, deterministic fail-closed behavior,
escalation, and evidence/audit integrity capabilities. ACGS does not describe
AGT as audit-only, does not claim it cannot issue or verify an artifact, and
does not claim exclusive ownership of fail-closed enforcement. The ACGS beta
target is a separately testable portable executor-verifiable Decision Receipt
contract with exact action/argument/actor/policy/scope binding, bounded expiry,
single-use semantics, provenance-preserving adapter evidence, and independent
evidence anchoring. That distinction remains a target until the named
conformance and evidence gates pass; AGT and an ACGS receipt gate may compose.

Other published enforcement-capable systems are also complementary: AWS
AgentCore Policy documents gateway interception and `ENFORCE` default-deny/
forbid-wins semantics; Galileo Agent Control documents an open-source runtime
control plane; and NVIDIA NeMo Guardrails documents configured tool/action
validation boundaries. Adapter profiles for those systems are roadmap work, not
shipped interoperability claims.

Sources, verified as of 2026-07-13:

- Entra Agent ID — <https://learn.microsoft.com/en-us/entra/agent-id/identity-professional/microsoft-entra-agent-identities-for-ai-agents>
- Purview for AI — <https://learn.microsoft.com/en-us/purview/ai-microsoft-purview>
- Copilot Control System — <https://learn.microsoft.com/en-us/microsoft-365/copilot/copilot-control-system/security-governance>
- Azure AI Foundry Guardrails — <https://learn.microsoft.com/en-us/azure/foundry/guardrails/guardrails-overview>
- Agent Governance Toolkit / Agent Control Specification — <https://github.com/microsoft/agent-governance-toolkit>, <https://microsoft.github.io/agent-governance-toolkit/packages/agent-control-specification/>, and <https://microsoft.github.io/agent-governance-toolkit/tutorials/04-audit-and-compliance/>
- AWS AgentCore Policy — <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-getting-started.html>
- Galileo Agent Control — <https://docs.galileo.ai/release-notes>
- NVIDIA NeMo Guardrails tool calling — <https://docs.nvidia.com/nemo/guardrails/configure-guardrails/guardrail-catalog/tool-calling>

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
| Remote sandbox (Daytona, Cloudflare Sandbox) | Provider-managed VM/container | Container-backed Linux environment off the application host (Cloudflare: a full Linux container per Durable Object) | No |
| Cloudflare outbound Worker (`outboundByHost`) | Egress proxy | Intercepts the container's HTTP requests **per host**; injects credentials at the Worker so the container never sees raw secrets | No — credential mediation + routing, no decision artifact |
| Observability | Telemetry | Export traces/metrics via OpenTelemetry, Braintrust, or Sentry | No — telemetry, not a per-decision artifact |

flue's safety primitive is **containment**: confine *where* an agent operates so
that runaway execution or filesystem damage stays bounded. That is real and
useful, and it composes with a receipt gate rather than competing with it. The
evidenced difference is *containment vs authorization-plus-non-repudiation*: a
sandbox bounds the room, but it does not decide which doors may open, nor leave a
portable proof of who opened them. The isolation strength varies sharply by
tier: the default virtual sandbox is, by flue's own docs, **not a
network-isolation boundary** (egress is permitted), so an agent inside it can
still exfiltrate data or call a destructive API. The **Cloudflare Sandbox** tier
raises that floor considerably — a full Linux container per Durable Object, plus
an **outbound Worker** (`outboundByHost`) that intercepts the container's HTTP
requests per host and injects credentials at the Worker so the container never
sees raw secrets (Cloudflare calls this a "zero-trust" model). That egress
mediation is genuine prior art and deserves acknowledgement, not a knock.

The evidenced difference is *resolution and artifact*, the same axis on which the
AGT and Mattermost entries above turn. The outbound Worker keys on **hostname**,
not on the specific action **plus its arguments** evaluated against a policy
bundle; it is an imperative routing/credential hook, not a declarative
`DENY` / `ESCALATE` / `ALLOW` verdict, and it has no stated fail-closed default
for unconfigured hosts. Crucially it protects the *secret* (the container never
sees the key), not the *action*: an agent can still trigger an
authorized-credential call to a destructive endpoint on an allowed host — the
proxy dutifully injects the token and forwards the request — and the record left
behind is OpenTelemetry-style **observability** (operator-trusted, mutable), not a
signed, sealed, per-decision artifact a relying party *outside* the runtime can
verify *before* accepting the action. ACGS / gove-zone's narrower bet sits exactly
at that boundary: evaluate the action-and-arguments, fail closed without a valid
Decision Receipt, and emit an independently verifiable artifact. The composition
is concrete rather than hand-wavy — flue's `outboundByHost` callback is a natural
mount point for a receipt gate: call the kernel, forward only on `ALLOW` with the
signed receipt attached, fail closed on `DENY`. Sandbox the workspace with flue;
receipt-gate what crosses out of it. Contrast by evidence, not a knock.

Sources, verified as of June 2026:

- flue — <https://github.com/withastro/flue>
- flue sandboxes guide — <https://flueframework.com/docs/guide/sandboxes/>
- flue Cloudflare deploy guide (`outboundByHost`) — <https://flueframework.com/docs/ecosystem/deploy/cloudflare/>
- Cloudflare Sandbox SDK (Beta, Apache-2.0) — <https://github.com/cloudflare/sandbox-sdk> and <https://developers.cloudflare.com/sandbox/>

## How the nearest comparisons relate (different axes)

The two structurally-closest projects above sit near gove-zone on *different
axes* — they are not interchangeable "same competitor" rivals:

- **Microsoft AGT / ACS** is the nearest *governance-paradigm* analogue. Its
  published pre-tool-call, fail-closed, escalation, and integrity-evidence
  capabilities share the authorization axis. This repository does not frame it
  as audit-only. The comparison is a target evidence-boundary distinction:
  portable executor-verifiable receipt semantics and assurance provenance must
  be demonstrated by ACGS conformance/evidence gates rather than presumed from
  a product label.
- **flue** is a *containment-paradigm* tool. It bounds **where** an agent runs,
  not **which action-plus-arguments** may execute; even its strongest egress
  mediation (`outboundByHost`) keys on hostname and protects the secret, not the
  action. The difference here is one of *paradigm* (authorization versus
  containment), not merely artifact resolution.

So "closest competitor" means two different things: AGT shares the axis and
differs on the artifact; flue differs on the axis itself. A receipt gate
composes with both rather than replacing either.
