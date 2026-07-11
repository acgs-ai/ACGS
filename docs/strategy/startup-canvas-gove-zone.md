# Startup Canvas: ACGS / gove-zone platform

> Stress-test: [swot-gove-zone.md](swot-gove-zone.md)

> Product: vendor-neutral, receipt-gated governance layer for AI-agent side effects.
> Stage: alpha (`0.1.0a1`), kernel ~95% built, OSS on GitHub, `acgs-lite` published to PyPI, console (acgi-ai) deployed.
> Date: 2026-07-03

## Part 1: Product Strategy

### Vision

Every autonomous-agent side effect in production is provably authorized: **no valid Decision Receipt, no side effect.** When a regulator, auditor, or incident responder asks "was this agent allowed to do that?", the answer is a verifiable artifact, not a log-grep.

### Market Segments (JTBD)

| Segment | Job to be done |
|---|---|
| **First: platform/security engineering teams deploying agentic AI in regulated or high-blast-radius environments** (fintech, healthcare, security ops, infra automation) | "Prove to our risk/compliance function that agents cannot take unauthorized actions — before we're allowed to ship them." |
| Second: AI-agent framework adopters (LangGraph, MCP, OpenAI-SDK-style runtimes) hitting production review | "Pass security review without rewriting our agent stack." |
| Third: auditors / GRC teams | "Get evidence of control that survives tampering and works offline." |

Early adopters: teams that already lost a fight with their security review board, or run governed security agents (pentest/OSINT — VulnClaw, Maigret case studies).

### Value Proposition

- **What before:** Agents act; logs are advisory and post-hoc; guardrails moderate text, not execution; compliance cannot prove a specific action was authorized. Production approval blocked or faked.
- **How:** Execution membrane below any framework. Policy decides *before* execution; decision is bound (actor + action + arguments + policy + audit evidence) into a signed Decision Receipt; executors fail closed without a valid receipt; audit hash chain + replay + offline proof-pack verifier.
- **What after:** Every side effect — including denials and escalations — has a verifiable receipt. One receipt format across all frameworks. Evidence checkable offline by a third party.
- **Alternatives (and why not):**
  - *Microsoft AGT* — audit-centric, records what happened; ACGS gates before execution. Retrofitting pre-execution gating breaks the post-hoc model.
  - *Guardrails libs* — moderate content, bypassable at executor layer.
  - *Policy engines (OPA etc.)* — decide but don't bind verdict to receipt, executor validation, and audit chain.
  - *IAM/RBAC* — authenticates principals, grants broad permission; doesn't prove a specific side-effect decision.
  - *Homegrown logging* — no tamper evidence, no fail-closed enforcement.

### Trade-offs (what we won't do)

- Not an agent framework; never orchestrates. No conflict of interest — neutrality *is* the position.
- No prompt-level / content safety — combine with guardrails, don't replace them.
- No compliance-certification claims until externally evidenced (claim-safe docs discipline).
- Won't privilege one framework or cloud; adapters stay thin and tiered (integration matrix).
- Won't chase sandbox/containment — decide authorization, not contain execution.

### Key Metrics

- **North Star:** governed side effects per month (receipts issued *and* verified in enforcing, fail-closed mode).
- **OMTM (now):** number of external teams running the receipt gate fail-closed in a real pipeline (design partners), not stars or downloads.
- Supporting: PyPI installs of acgs-lite, adapter-in-production count per framework, proof-pack verifications by third parties, deny/escalate events actually enforced.

### Growth

- **Motion:** PLG bottom-up via OSS (zero-runtime-deps kernel, PyPI, one-command proof path), then sales-led for hosted console + managed signing/ledger.
- **Channels:** PyPI/GitHub; framework-adapter docs (MCP, LangGraph, A2A) placed where integrators search; security-community content (governed-pentest VulnClaw, OSINT case studies); AI-citation surfaces (llms.txt, agent discovery).
- **Wedge:** "governed security agents" — highest-stakes, most legible use case; a pentest agent that provably can't exceed scope sells the invariant in one demo.

### Capabilities

- **Build (core):** kernel, receipt spec, signing, audit chain, replay, offline verifier, executor gates, console.
- **Partner/integrate:** agent frameworks (adapters, not forks), cloud KMS/PKI for keys, SIEM/WORM for retention, sandboxes for containment.
- **Explicitly not build:** orchestration, model safety, IAM.

### Can't / Won't (defensibility)

- **Structural:** platform vendors (Microsoft, OpenAI, Google) governing their *own* agents have a conflict of interest ACGS doesn't — a neutral membrane below all frameworks is a position incumbents can't credibly occupy.
- **Architectural:** audit-centric incumbents must invert their model (post-hoc → pre-execution fail-closed) to copy; that breaks existing product contracts.
- **Honest weakness:** receipt spec itself is copyable. Real moat = neutrality + evidence-chain completeness (gate + receipt + chain + replay + offline verifier as one tested system) + head start becoming the reference format auditors accept.

## Part 2: Business Model

### Cost Structure

- **Fixed:** core engineering (OSS kernel + verifier + adapters), claim-safe docs/compliance content, security review overhead.
- **Variable (low):** console hosting (Cloud Run / Workers Assets — near-zero at current scale); managed ledger/signing scales with receipt volume.
- COGS structurally low: kernel runs in customer's process; heavy costs only enter with managed evidence retention.

### Revenue Streams (open-core)

| Tier | What | Pricing shape |
|---|---|---|
| OSS (free) | Kernel, receipt spec, local audit chain, offline verifier, adapters | Apache-2.0; adoption engine |
| Team | Hosted console, managed signing keys, receipt ledger with retention | Platform fee + usage (receipts/month) |
| Enterprise | SSO, multi-tenant policy control plane, WORM/SIEM export, SLAs, support | Annual contract, seat + volume |
| Services (early) | Design-partner integration, auditor-ready proof-pack packaging | Fixed-fee engagements funding roadmap |

Monetization principle: **the decision is free; durable, managed, auditor-grade evidence is paid.** Never paywall fail-closed enforcement itself (would poison the invariant and adoption).

## Strategy Coherence Check

- Neutrality (strategy) ⇄ vendor-neutral receipt format (product) ⇄ open-core with free enforcement (model): reinforcing.
- PLG wedge needs frictionless kernel → zero runtime deps + one-command proof path: aligned.
- North Star (verified governed side effects) directly drives paid tier (managed evidence volume): aligned.
- Tension to watch: claim-safe honesty ("alpha, not certified") vs. selling to compliance buyers who want certainty — bridged via design-partner services, not marketing claims.

## Riskiest Assumptions (ranked)

1. **Buyers require pre-execution gating.** If post-hoc audit (AGT-style) satisfies regulators, the core wedge collapses. → Test: 3–5 design-partner conversations with risk/compliance owners; ask what their auditor actually rejected.
2. **Receipts are auditor-acceptable evidence.** → Test: put proof pack + offline verifier in front of a real GRC/auditor; capture written reaction.
3. **Integration cost is acceptable.** Teams will wire executors through a membrane despite latency/complexity. → Test: time-to-first-governed-call metric on adapter quickstarts; target < 1 hour.
4. **Evidence retention is the monetizable unit.** Teams pay for managed ledger rather than self-hosting JSONL. → Test: offer paid pilot of managed ledger to OSS users; measure conversion intent.
5. **Neutrality matters to buyers** (vs. "we're all-in on one vendor anyway"). → Test: segment design partners by mono-vendor vs. multi-framework stacks; compare pull.

## Experiments to Run Next

- Design-partner program (n=3): fail-closed in one real pipeline each; instrument OMTM.
- Auditor validation sprint: one external auditor reviews a proof pack; publish (claim-safe) findings.
- Wedge content: governed-pentest demo → security-community distribution; measure PyPI + adapter-doc traffic.
