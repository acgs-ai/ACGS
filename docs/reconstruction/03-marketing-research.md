# Marketing Research — ICP, Positioning, Pricing, GTM

> Platform-reconstruction program, document 3 of 6.
> Web research performed 2026-07-05. Claims marked **[verified]** (cited source) or
> **[inferred]** (synthesis from cited signals). Companion to
> `02-external-research.md`; this document answers *who buys, what frame, what price,
> what motion*.

**Bottom line:** the "pre-action authorization + signed proof" category this project
occupies is now real and contested — a near-identical competitor (APort) and
Microsoft's toolkit have staked the same frame. That validates the thesis but forces
sharper positioning (own the *verifiable receipt*, not the generic "governance
platform") and an integration-led motion.

## 1. ICP — who feels the pain first

**Signals [verified]:**

- AI-governance hiring is among the fastest-growing enterprise categories; Financial
  Services is the #1 *regulated* vertical in postings (~9% of 146 analyzed
  AI-governance roles; Professional Services 51%, Tech 15%).
  https://axialsearch.com/insights/ai-governance-jobs/ ,
  https://www.ziprecruiter.com/Jobs/Ai-Governance
- 65% of firms hit an AI-agent security incident in 2026; only **14.4%** of agents go
  live with full security/IT approval; 97% of AI-related breaches involved orgs
  lacking AI access controls (IBM).
  https://www.kiteworks.com/cybersecurity-risk-management/ai-agent-security-incidents-2026/ ,
  https://www.tierzero.ai/blog/ai-agent-security-over-privileged/
- Concrete irreversible-action incidents (strongest pain evidence): Step Finance DeFi
  agent moved $27–30M in SOL with no human approval; a Cursor agent deleted files
  after the user typed "DO NOT RUN ANYTHING"; a Meta internal agent auto-posted to a
  forum triggering a 2-hour data-exposure chain; the PocketOS agent destroyed a
  production DB in 9 seconds.
  https://beam.ai/agentic-insights/ai-agent-security-breaches-2026-lessons ,
  https://zenity.io/blog/current-events/ai-agent-database-deletion-pocketos

**ICP ranking [inferred]:**

1. **Fintech/DeFi and payments ops** — irreversible money movement is the cleanest
   "no receipt, no side effect" wedge; public dollar losses already exist.
2. **AI platform teams at mid-market regulated SaaS** — they deploy agents to prod,
   own the incident, and are technical enough to adopt an OSS Python core.
3. **Healthcare AI / clinical** — high impact, longer cycle; `clinicalguard` already
   targets this vertical.

Legal/insurance/MSPs are secondary (agent adoption lags). The buyer persona is the
**AI platform / security engineer who gets paged**, not the compliance officer.

**Regulatory-driver caveat:** one research lane cites EU AI Act high-risk obligations
enforceable 2 Aug 2026; the other found the Digital Omnibus provisional agreement
(7 May 2026, pending formal adoption) deferring Annex III to 2 Dec 2027 (see
`02-external-research.md` §2). Treat the Aug-2026 cliff as **uncertain** — do not
build messaging solely on the deadline; the logging/evidence obligations are the
durable driver either way.

## 2. Positioning — which frame fits Decision Receipts

| Frame | Who owns it | Fit |
|---|---|---|
| "Compliance automation" (SOC2 for agents) | Vanta, Drata | ❌ Crowded, audit-centric, not runtime |
| "Authorization as a service" | Oso — pivoted to "Oso for Agents" (https://www.osohq.com/) | ⚠️ Strong incumbent now in-lane |
| "Pre-action authorization / policy before the API call" | **APort** — "Passport. Policy. Proof.", signed audit trails, Apache-2.0 OAP spec (https://aport.io/blog/best-ai-agent-guardrails-2026-pre-action-authorization-compared/) | ⚠️ **Near-identical to this project** |
| "AI firewall" / runtime guardrails | Robust Intelligence, Arthur, CodeIntegrity ($5M seed) (https://www.geekwire.com/2026/codeintegrity-raises-4-8m-to-put-permanent-guardrails-on-unpredictable-ai-agents/) | ⚠️ Content/behavioral, not deterministic proof |
| "Attestation / notarized receipts" | Academic ("Notarized Agents" — see `02-external-research.md` §2 citations); provenance vendors | ✅ Least crowded, most differentiated |

**Recommendation [inferred]:** lead with the **verifiable Decision Receipt** as the
differentiator, wrapped in the category language buyers search for:
*"pre-execution policy enforcement with cryptographically verifiable receipts."*
Avoid "firewall" (implies content pattern-matching, which this is not) and pure
"SOC2 for agents" (commoditized). The defensible wedge APort/Oso/Microsoft do not
emphasize: **offline-verifiable, tamper-evident receipts + fail-closed executors** —
regulators increasingly expect "runtime proof, not logs" (EU AI Act Art. 12 /
Annex IV) **[inferred — single vendor analysis]**.
https://zylos.ai/research/2026-05-01-ai-agent-governance-compliance-2026/

**Threat [verified]:** APort has the same tagline structure plus an open spec.
Differentiate on verifiability/offline proof + Python-native OSS core +
regulated-domain packs (clinical, Terraform/infra) — or risk reading as a clone.
Validate APort's actual traction before committing messaging.

## 3. Pricing signals

- **Compliance-automation ACVs [verified]:** Vanta ~$10K (startup) → $30–50K
  (mid-market, multi-framework) → $80–120K+ (enterprise); Drata ~$7.5K → $15–25K
  typical. Priced by company size + framework count, not per-seat. Vanta's 30–50%
  renewal jumps are a known grievance — an opening for transparent pricing.
  https://www.secureleap.tech/blog/vanta-review-pricing-top-alternatives-for-compliance-automation ,
  https://www.complyjet.com/blog/drata-pricing-plans
- **Agentic-infra trend [verified]:** hybrid pricing (predictable base + usage
  metering on tokens/API calls/decisions) is the 2026 default; API-gateway benchmark
  ~$3.50/M calls.
  https://www.getmonetizely.com/blogs/the-2026-guide-to-saas-ai-and-agentic-pricing-models
- **Recommendation [inferred]:** open-core with **per-decision (per-receipt)
  metering** — the meter maps natively to "no receipt, no side effect"; the receipt
  is the product's atomic event. Design-partner pilots at **$0–15K for 2 quarters**
  (below Vanta entry) traded for logo + case study; convert to hybrid base+usage.

## 4. GTM motion — ranked for a solo/small OSS team

1. **Integration-led distribution through the agent stack (highest leverage).**
   LangChain/CrewAI/LangGraph/LlamaIndex now treat MCP as the default tool protocol —
   this project already has an MCP gateway pilot and framework adapters. Ship as an
   MCP server + framework hooks; list on MCP hubs / agent marketplaces (listings
   updated <30 days rank 2–3× higher).
   https://chatforest.com/guides/mcp-agent-framework-integrations/ ,
   https://www.digitalapplied.com/blog/ai-agent-marketplaces-2026-discovery-distribution
2. **OSS-to-PLG via PyPI/GitHub (the foundation).** The proven sequence (Supabase,
   Infisical, Cal.com): open core → earn trust → gate enterprise later. Sequential,
   not simultaneous. acgs-lite on PyPI is the existing top-of-funnel.
   https://www.productmarketingalliance.com/developer-marketing/open-source-to-plg/
3. **Content/SEO around regulatory evidence + incident post-mortems.** Teardowns of
   the Step Finance / Cursor / PocketOS incidents mapped to "a Decision Receipt would
   have blocked this," plus "runtime proof vs logs" explainers. Cheap, compounding,
   credibility-building. (Keep EU-deadline framing hedged per §1 caveat.)

Compliance-partner channel is real but slower — defer until PLG traction.

## 5. Naming / brand

- **[verified]** No web collision found for "govern-zone" or "acgs.ai" in
  AI-governance contexts.
- **[inferred]** "ACGS" is a heavily overloaded acronym (sports, government, academic
  systems) — weak for SEO/recall. "govern-zone" reads generic and will not own a
  search term. The distinctive, ownable product noun is **"Decision Receipts"** —
  anchor brand, SEO, and any trademark work on that, not on the ACGS/governance
  umbrella.

## 6. Marketing inputs handed to the blueprint and roadmap

1. Position the platform around the receipt primitive (supports blueprint decision to
   extract the evidence/receipt library as L0 and align it with Agent Receipts /
   IETF AER standards).
2. MCP gateway + framework adapters are the **distribution surface**, not just
   integrations — prioritize their packaging/listing in the roadmap.
3. Per-decision metering implies the control plane must count/attribute decisions per
   tenant — a concrete platform requirement (tenancy + consumption ledger already
   exist in the kernel).
4. Domain packs (clinicalguard, cft-pack) are positioning assets — "regulated-domain
   packs" — keep them visible in the platform story.
5. Watch-item: APort traction; revisit positioning quarterly.
