# Platform Reconstruction — Executive Summary & Roadmap

> Platform-reconstruction program, document 0 of 6 (read this first).
> Produced 2026-07-05 on branch `docs/platform-reconstruction` (base origin/master
> `34137f6`). Companion documents:
> `01-internal-audit.md` · `02-external-research.md` · `03-marketing-research.md` ·
> `04-platform-blueprint.md` · `05-production-deployment.md`.
> **Status: PROPOSAL.** Nothing here is a production or compliance claim; per
> `docs/CLAIMS.md` discipline, present-tense capability language describes targets.

## 1. The verdict in three sentences

The estate does **not** need a rebuild: a layered platform already exists de facto,
anchored by a clean, well-tested kernel (`gove-zone`: 634 tests, mypy-strict, zero
runtime deps, 90% coverage floor) — reconstruction means **formalizing layers,
consolidating ~4× duplicated evidence plumbing, hardening defaults, and
productionizing deployment**, not rewriting. The market has validated the thesis —
pre-execution enforcement with signed proof is now a real, contested category
(Microsoft Entra Agent ID, Cerbos, APort) — so the 12–18-month window rewards
shipping the **standard-aligned, offline-verifiable Decision Receipt** as the
differentiator rather than broad platform ambitions. The production gap is
operational, not architectural: one self-hosted CI runner as SPOF, no staging
environment, a possibly-unarmed production approval gate, and integrity features
(signing, single-use receipts) that are built but **off by default**.

## 2. What we have (from the internal audit)

- **Kernel (`packages/gove-zone/`)** — strongest asset; fail-closed policy → receipt
  → executor gate → hash-chained audit → replay; zero cross-package imports.
- **Published spine** — `acgs-lite` (PyPI v2.10.1) under `Acgs-Swarm`/`clinicalguard`
  (nested repos); a second receipt lineage with **no code-level link** to the kernel.
- **Working satellites** — eval-mvp (reference gate engine), agent-bus-analyzer
  (observability, deploy-ready), cft-pack + hermes (host adapters), acgi-ai console +
  marketing (the only two deployed surfaces).
- **Top defects** — evidence writers duplicated ~4×; signing/single-use opt-in;
  constitutional-hash CI gate guards an **empty** inventory (no-op control); 5
  readiness tests run in no CI; orphan Vue app un-gated; roadmap/plan sprawl with
  stale pointers.

## 3. What the world looks like (from external + marketing research)

- Three competitor camps: content guardrails (don't gate actions), GRC platforms
  (document, don't enforce), and the direct set — agent authorization (Microsoft,
  Cerbos, **APort — near-identical framing**). Whitespace: **"enforced, not
  documented"** + a **portable receipt** verifiable offline, aligned to emerging
  standards (Agent Receipts Ed25519/W3C-VC; IETF Agent Enforcement Receipts → SCITT).
- Regulatory driver is durable but the EU AI Act high-risk cliff is uncertain
  (Digital Omnibus deferral to Dec 2027 pending) — sell the **evidence obligations**,
  not the deadline.
- ICP: fintech/payments ops → AI platform teams at regulated mid-market SaaS →
  clinical. Buyer = the engineer who gets paged. Pricing: open-core, per-decision
  (per-receipt) metering; pilots $0–15K. GTM: integration-led via MCP + framework
  hooks, then OSS-PLG, then incident-teardown content. Brand: anchor on **"Decision
  Receipts"**, not the ACGS acronym.

## 4. Target platform (from the blueprint)

Organized layers with enforced boundary contracts:

```
L4 Experience      console + marketing + CLI
L3 Integrations    MCP gateway · framework adapters · cft-pack · hermes-as-adapter
L2 Control plane   policy mgmt · receipt-verification API · tenant · revocation
L1 Kernel          gove-zone (policy · decision · executor gate · audit · signing)
L0 Evidence        ONE shared receipt/evidence-chain lib (standards-aligned)
L5 Observability   agent-bus-analyzer · eval-mvp        (spans L1–L4)
```

Six decisions (blueprint §2): gove-zone = kernel of record with acgs-lite as
published SDK bound by a receipt-format contract (no repo merge); extract the single
L0 evidence library; fold hermes into eval-mvp; archive the orphan Vue app; **flip
signing + single-use receipts on by default** with explicit dev-mode; add risk-tiered
enforcement (answers the Gartner uniform-governance objection).

## 5. Phased roadmap (blueprint §3 + production plan §8, merged)

> Note: this table reconciles the two source phase plans into one sequence; a few
> items sit in a different phase here than in their source doc (e.g. readiness-test
> un-ignore, staging deploy). The source docs govern if this is turned into an
> execution plan.

| Phase | Theme | Highlights | Risk | Gate |
|---|---|---|---|---|
| **A — Hygiene** | Docs + CI truth | One roadmap of record + `docs/archive/`; fix stale pointers; archive orphan; normalize CI templates; version-string fix; fail-fast `test:all` grouping; un-ignore 5 readiness tests; write (unapplied) IaC | Green | Agent-preparable |
| **B — Consolidation + staging** | One evidence lib, binding defaults | Extract `acgs-evidence` (L0) behind kernel-test baseline; hermes fold-in; defaults flip (major-version note); populate-or-descope constitutional-hash gate; deploy staging from existing `service.staging.yaml`; hosted-twin verify lane (SPOF) | Yellow | Mixed |
| **C — Platformization** | Services + standards | Receipt-verification/control-plane API; agent-bus-analyzer deploy pipeline (`maxScale: 1` respected); align L0 to Agent Receipts / IETF AER + conformance suite; risk-tier policy surface; cross-lineage contract test | Yellow-red | Mixed |
| **D — Production trust** | Human gates armed | Arm `production` env + reviewers; env-scoped secrets; clinicalguard fail-closed + PAT scope; generalize PyPI Trusted Publishing; eval-mvp governed MCP pilot | — | **Human-gated** |

Standing invariant: **agents prepare, humans deploy/publish/arm-trust.** And the
product invariant is untouched throughout: **No valid Decision Receipt, no side
effect** — Phase B strengthens it by making it bind by default.

## 6. Top 10 actions (ordered)

1. Flip signing + single-use receipts to default-on with explicit dev profile
   (highest-leverage integrity change; blueprint §2e).
2. Extract the single L0 evidence/receipt library; reroute kernel + 3 hosts
   (blueprint §2b) — guard with the 634-test baseline.
3. Align the receipt format to Agent Receipts (Ed25519/W3C-VC) + IETF AER/SCITT —
   the standards window is the moat (research §4).
4. Deploy staging (`service.staging.yaml` exists unused) + extend post-deploy verify.
5. Kill the single-runner SPOF via hosted-twin verify lanes (pattern exists:
   `tests-root-hosted.yml`); deploys stay self-hosted.
6. Verify + arm the GitHub `production` environment with required reviewers
   (**human**).
7. Populate or descope the constitutional-hash parent gate; un-ignore the 5
   readiness tests (truth-in-CI items).
8. Add the agent-bus-analyzer deploy workflow; generalize gove-zone's PyPI
   Trusted-Publishing template to acgs-lite (**publish stays human**).
9. Estate hygiene: one roadmap of record, `docs/archive/`, archive the orphan Vue
   app, fix stale CLAUDE.md/PLAN pointers, normalize CI templates.
10. Reposition messaging on "pre-execution policy enforcement with cryptographically
    verifiable receipts"; package the MCP gateway + adapters as the distribution
    surface; monitor APort quarterly (marketing §2/§6).

## 7. Open decisions for the maintainer

1. L0 receipt-schema ownership between the gove-zone and acgs-lite lineages
   (needs acgs-lite source checkout to settle).
2. Standards timing: align now vs stable-internal-format-first (12–18-month window).
3. Defaults-flip rollout: major version vs one-cycle profile gate.
4. L2 control plane: deployed service vs embedded library (changes doc-05 scope).
5. Constitutional-hash gate: activate or descope — a no-op that reads as a control
   is the worst option.
