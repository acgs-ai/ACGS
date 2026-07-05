# External Research — Market, Competitors, Standards

> Platform-reconstruction program, document 2 of 6.
> Web research performed 2026-07-05. Each claim carries its source URL; claims are
> marked **[verified]** (stated in cited source) or **[inferred]** (synthesis).
> Read together with `01-internal-audit.md` (what we have) — this document is
> "what the world has."

## 1. Competitor landscape

The market splits into three camps. Receipt-gated **pre-execution** enforcement sits
in a thin — and now contested — slice of camp C.

### Camp A — Content/output guardrails (prompt/response-level)

NVIDIA NeMo Guardrails, Guardrails AI, Lakera Guard, Llama Guard, OpenAI Moderation.
These filter model inputs/outputs (toxicity, jailbreaks, PII). They do **not** decide
whether a side-effecting tool call is permitted and emit no signed authorization
artifact. **[verified]**
- https://generalanalysis.com/guides/best-ai-guardrails
- https://galileo.ai/blog/best-ai-guardrails-platforms
- https://www.deepinspect.ai/blog/nemo-guardrails-alternatives

### Camp B — GRC / documentation governance (post-hoc, org-level)

Credo AI, Holistic AI, IBM watsonx.governance, Modulos, Trustible. They document and
attest governance and monitor models across clouds. A buyer's guide states plainly:
"Credo AI documents governance requirements but **does not enforce them at the
execution layer**." **[verified]**
- https://www.modulos.ai/best-ai-governance-platforms/
- https://www.truefoundry.com/blog/best-ai-governance-tools

Pricing signals **[verified]**: Credo AI $30K–$150K/yr (~$40K–$200K+ first year);
watsonx.governance enterprise-custom; category budgets $25K–$200K+/yr.
- https://co-aims.com/blog/credo-ai-review-2026-compliance-officers
- https://www.cloudzero.com/blog/ai-governance-tools/

### Camp C — Agent authorization / identity (pre-execution, action-level) — the direct set

- **Microsoft Entra Agent ID + "Agent Identity Perimeter"** (Build 2026): extends
  Conditional Access to agent-initiated actions; requires explicit human approval
  before high-risk operations (data deletion, external email, config changes,
  exports). Strongest incumbent threat. Identity-centric: it gates **access**, but
  produces no portable cryptographic per-action receipt. **[verified]**
  - https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id
  - https://windowsnews.ai/article/ai-agents-in-2026-microsoft-governance-identity-perimeter-and-email-risk.423028
- **Policy engines extending to agents**: Cerbos (markets "agentic authorization" —
  an AI gateway sends each request to Cerbos before routing upstream), Permit.io,
  Oso, OPA/Cedar. Architecturally the closest analog to receipt-gating, minus the
  signed-receipt-as-artifact and fail-closed-executor invariant. **[verified]**
  - https://www.cerbos.dev/features-benefits-and-use-cases/agentic-authorization
  - https://workos.com/blog/best-authorization-platforms-ai-agent-permissions-2026
- **Startups on the exact thesis**: aport.io ("pre-execution guardrails," Open Agent
  Passport, fail-closed DENY, signed decision events), Aembit (agent workload auth),
  Agent Trust Stack MCP, AgentSeal (SHA-256 hash-chain receipts). **[verified]**
  - https://aport.io/blog/ai-agent-authorization-complete-guide/
  - https://aembit.io/blog/secure-agentic-access-authentication-and-authorization-for-ai-agent-workloads/

### Differentiation read **[inferred]**

The "policy-before-execution → signed Decision Receipt → executor fails closed"
invariant is **no longer unique**, but the space is early and fragmented. gove-zone's
edge is a coherent, framework-adapter-wide kernel with a single receipt primitive,
versus (a) identity-gating that stops at access rather than per-action provenance
(Microsoft), (b) policy engines returning allow/deny that treat the signed,
offline-verifiable receipt as an afterthought (Cerbos/Permit), and (c) point
startups lacking multi-framework/MCP breadth.

## 2. Standards and regulation

### EU AI Act — the deadline moved, the evidence bar did not

GPAI obligations apply since 2 Aug 2025. The headline 2 Aug 2026 high-risk (Annex III)
date has **likely slipped**: the Digital Omnibus provisional agreement (7 May 2026,
pending formal adoption) defers Annex III obligations to **2 Dec 2027**. Fines up to
€35M / 7% turnover. **[verified]** Messaging consequence: tell buyers the cliff moved
but the evidence requirements didn't.
- https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/
- https://www.legiscope.com/blog/eu-ai-act-timeline-deadlines.html

### Frameworks

ISO/IEC 42001 is the certifiable, third-party-audited management standard; NIST AI RMF
is the risk overlay. **Singapore published the first agentic-AI governance framework
(Jan 2026)**; **NIST issued an RFI on AI Agent Security and a concept paper on AI
Agent Identity and Authorization (early 2026)**. **[verified]**
- https://gaicc.org/blog/ai-governance-comparison-eu-ai-act-nist-iso-42001/
- https://www.trustcloud.ai/ai/iso-42001-nist-ai-rmf-practical-steps-for-responsible-ai-governance/

### Agent-identity / receipt standards — strategically the most relevant

MCP, A2A, and ACP now sit under the Linux Foundation's **Agentic AI Foundation**
(co-founded by OpenAI, Anthropic, Google, Microsoft, AWS, Block; ~150 members).
MCP added OAuth 2.1 + mandatory PKCE (Jan 2026); **A2A v1.0 shipped April 2026**;
new controls require unique, **cryptographically verifiable agent identities**.
Directly overlapping standards work: **Agent Receipts** (Ed25519 + W3C Verifiable
Credentials), **Agent Enforcement Receipts (AERs)** — an IETF Internet-Draft targeting
**SCITT transparency logs** — plus academic protocols ("Before the Tool Call,"
"Proof-Carrying Agent Actions," "Notarized Agents"). **[verified]**
- https://zylos.ai/research/2026-03-26-agent-interoperability-protocols-mcp-a2a-acp-convergence/
- https://www.aiuc-1.com/research/2026-q2-standard-update
- https://arxiv.org/pdf/2606.04104

### What compliance evidence can a Decision Receipt satisfy? **[inferred from verified checklist]**

Tamper-evident, operation-level, attribution-complete, write-once audit logs
(hash-chained, independently signed) — the 2026 audit-trail checklist; substrate for
EU AI Act logging, GDPR Art. 22 automated-decision records, SOX/HIPAA controls.
Auditors in 2026 are reportedly instructed to **discount logs that cannot prove
non-alteration**.
- https://www.kiteworks.com/regulatory-compliance/ai-agent-audit-trail-siem-integration/

## 3. Market trends

- **Gartner**: 40% of enterprise apps will embed task-specific agents by end-2026
  (from <5% in 2025); **$234B** of enterprise-software spend "at risk" from agentic
  AI; **>40% of agentic projects cancelled by 2027**; 40% of enterprises will
  demote/decommission agents due to governance gaps found only after production
  incidents. **[verified]**
  - https://www.gartner.com/en/newsroom/press-releases/2026-07-01-gartner-says-us-dollars-234-billion-in-enterprise-application-software-spend-is-at-risk-from-agentic-artificial-intelligence
  - https://www.gartner.com/en/newsroom/press-releases/2025-06-25-gartner-predicts-over-40-percent-of-agentic-ai-projects-will-be-canceled-by-end-of-2027
- **Incidents driving demand [verified]**: 344 verified agent-inflicted-damage cases
  Sep 2023–May 2026 (188 with no external attacker); April 2026 PocketOS case — a
  coding agent deleted the production DB and backups, ignoring safety restrictions;
  an Alibaba-affiliated agent hijacked GPUs and opened a backdoor; 65–66% of firms
  hit by an agent-caused security incident in 2026.
  - https://www.cyera.com/research/agent-inflicted-damage-inside-the-real-world-failures-of-enterprise-ai-systems
  - https://www.kiteworks.com/cybersecurity-risk-management/ai-agent-security-incidents-2026/
  - https://www.infosecurity-magazine.com/news/unchecked-ai-agents-cause/
- **Adoption blockers [verified]**: evaluation/observability (64%), governance
  friction (57%), model reliability (51%); **88% of agent pilots never reach
  production**.
  - https://joget.com/ai-agent-adoption-in-2026-what-the-analysts-data-shows/
- **Analyst caution [verified]**: Gartner (26 May 2026) warns that **uniform
  governance across all agents will itself cause failure** — the platform must
  support risk-tiered, per-action policy, not a blanket gate.
  - https://www.gartner.com/en/newsroom/press-releases/2026-05-26-gartner-says-applying-uniform-governance-across-ai-agents-will-lead-to-enterprise-ai-agent-failure

## 4. Positioning whitespace **[inferred]**

1. **"Enforced, not documented."** GRC leaders explicitly don't enforce at the
   execution layer; guardrail vendors filter text, not actions. A receipt-gated
   executor that fails closed is the missing enforcement layer beneath both. The
   contrast is source-verified — lead with it.
2. **Portable, offline-verifiable receipt vs vendor-locked allow/deny.** Cerbos /
   Permit / Microsoft return decisions inside their own logs. A signed Decision
   Receipt any downstream executor or auditor can verify **without calling back** —
   aligned to SCITT / W3C-VC — is defensible. Align the receipt format with Agent
   Receipts (Ed25519/W3C-VC) and IETF AERs/SCITT now: ride the standard, don't fight it.
3. **Framework-agnostic kernel + MCP gateway.** Incumbents are identity-suite-bound
   (Microsoft) or SDK-bound (Oso). A kernel that slots under LangChain / CrewAI /
   AutoGen *and* the MCP tool-call boundary matches where sources say governance is
   moving: "from at-login to every tool call."
4. **Audit-grade evidence as the buyer wedge.** Auditors discount non-tamper-evident
   logs; EU AI Act logging obligations are live regardless of the high-risk deferral.
   Position the receipt chain as ready-made conformity evidence (Art. 22, ISO 42001,
   SOX/HIPAA) — converting a security feature into a compliance budget line item
   ($25K–$200K/yr category).
5. **Risk-tiered enforcement, not a blanket gate** — preempts the #1 analyst objection.

**Net:** the thesis is market-validated (funded startups + IETF/W3C standards +
analyst incident data all converging on pre-execution signed enforcement) but **no
longer uniquely owned**. The 12–18 month window favors whoever couples the fail-closed
executor to an emerging-standard-aligned, portable receipt sold as audit evidence —
before Microsoft's identity perimeter or Cerbos's gateway absorbs the category.
