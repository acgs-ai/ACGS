---
version: alpha
name: ACGS GovernZone
description: Editorial constitutional governance for marketing, product atlases, privileged consoles, and evidence panels.
colors:
  primary: "#171310"
  secondary: "#57503F"
  tertiary: "#9E2B25"
  neutral: "#E9E5DA"
  paper: "#E9E5DA"
  paper-alt: "#F0EDE4"
  paper-deep: "#E2DDD0"
  card: "#F6F4EC"
  ink: "#171310"
  ink-secondary: "#26211B"
  ink-tertiary: "#3E3831"
  muted: "#57503F"
  muted-light: "#8A8170"
  line: "#171310"
  line-soft: "#C6BFAF"
  line-softer: "#D8D2C2"
  rust: "#9E2B25"
  rust-hover: "#7A1E1A"
  rust-soft: "#E8D5CD"
  gold: "#A5843B"
  gold-ink: "#6E5A25"
  parchment: "#F3EAD4"
  parchment-ink: "#5A4111"
  parchment-line: "#E3D5A8"
  risk-confirmed: "#3D6B4A"
  risk-partial: "#76520D"
  risk-blocked: "#C8432A"
typography:
  hero:
    fontFamily: Instrument Serif
    fontSize: 5rem
    fontWeight: 400
    lineHeight: 1
    letterSpacing: "-0.02em"
  h1:
    fontFamily: Instrument Serif
    fontSize: 3rem
    fontWeight: 400
    lineHeight: 1.05
    letterSpacing: "-0.02em"
  h2:
    fontFamily: Instrument Serif
    fontSize: 2.25rem
    fontWeight: 400
    lineHeight: 1.08
    letterSpacing: "-0.012em"
  body:
    fontFamily: IBM Plex Serif
    fontSize: 1rem
    fontWeight: 400
    lineHeight: 1.55
  body-large:
    fontFamily: IBM Plex Serif
    fontSize: 1.25rem
    fontWeight: 400
    lineHeight: 1.55
  ui:
    fontFamily: Instrument Sans
    fontSize: 0.9375rem
    fontWeight: 500
    lineHeight: 1.4
    letterSpacing: "-0.005em"
  runtime:
    fontFamily: Inter Tight
    fontSize: 0.875rem
    fontWeight: 500
    lineHeight: 1.45
    letterSpacing: "-0.005em"
  mono:
    fontFamily: JetBrains Mono
    fontSize: 0.6875rem
    fontWeight: 500
    lineHeight: 1.4
    letterSpacing: "0.08em"
spacing:
  2xs: 2px
  xs: 4px
  sm: 8px
  md: 12px
  lg: 16px
  xl: 20px
  2xl: 24px
  3xl: 32px
  4xl: 48px
  5xl: 64px
rounded:
  sm: 4px
  md: 6px
  lg: 8px
  pill: 999px
components:
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.paper}"
    typography: "{typography.ui}"
    rounded: "{rounded.sm}"
    padding: 12px
  button-primary-hover:
    backgroundColor: "{colors.ink-secondary}"
    textColor: "{colors.paper}"
    rounded: "{rounded.sm}"
    padding: 12px
  button-secondary:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    typography: "{typography.ui}"
    rounded: "{rounded.sm}"
    padding: 12px
  button-rust:
    backgroundColor: "{colors.rust}"
    textColor: "{colors.paper}"
    typography: "{typography.ui}"
    rounded: "{rounded.sm}"
    padding: 12px
  surface-card:
    backgroundColor: "{colors.paper-alt}"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
    padding: 24px
  surface-privilege:
    backgroundColor: "{colors.parchment}"
    textColor: "{colors.parchment-ink}"
    rounded: "{rounded.sm}"
    padding: 12px
  risk-confirmed-pill:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.risk-confirmed}"
    typography: "{typography.mono}"
    rounded: "{rounded.pill}"
    padding: 8px
  risk-partial-pill:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.risk-partial}"
    typography: "{typography.mono}"
    rounded: "{rounded.pill}"
    padding: 8px
  risk-blocked-pill:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.risk-blocked}"
    typography: "{typography.mono}"
    rounded: "{rounded.pill}"
    padding: 8px
---

## Overview

ACGS GovernZone is one design language for every product surface: the public marketing landing page, product reference atlas, LegalGuard, governance-eval, ACGS Lite, Hermes governed evidence, EU AI Act countdown, hackathon vault demo, login boundary, and privileged runtime console.

The aesthetic is editorial constitutional infrastructure: warm paper, strong black rules, rust as the only interaction accent, mono citations and hashes, and Instrument Serif emphasis. The surfaces should feel like a Federal Register supplement that runs in production, not a generic SaaS dashboard.

The design contract is product-wide:

- Marketing and product atlas pages explain the system with asymmetric editorial layouts.
- Console and workbench pages enforce privilege boundaries with compact, auditable runtime tables.
- LegalGuard and any matter-bearing product use parchment boundaries before privileged content.
- Evidence panels and eval dashboards use mono hashes, receipt rows, and replay language.
- All products inherit the same color, typography, spacing, radius, focus, and risk semantics from this file.

## Colors

- **Paper (#E9E5DA):** the default background across all products — bone drafting paper (2026-07-10 drafting-print revision; deepened from the legacy #FAFAF7 warm paper). It keeps legal/governance surfaces calm and archival.
- **Paper Alt (#F0EDE4):** cards, sidebars, code blocks, product atlas tiles, and console panels.
- **Ink (#171310):** primary copy, strong rules, and high-emphasis actions — warmed drafting ink.
- **Rust (#9E2B25):** the single brand accent for links, active states, asterisms, italic emphasis, and controlled approval actions — deepened to an oxide crimson in the drafting-print revision; normal-size accent text passes WCAG AA on paper (5.9:1).
- **Gold (#A5843B / ink #6E5A25):** the seal. Decorative drafting marks only — section rules, ticks, plate corners — at #A5843B (2.8:1, never body text); any text-bearing gold uses #6E5A25 (AA, 5.3:1). Gold never replaces rust as the interaction accent. Under `[data-theme="control-plane"]` both gold tokens remap to one dark-safe gold #C9A75C (8.4:1 on the near-black ground), mirroring the rust→brightened-rust remap.
- **Parchment (#F3EAD4):** privilege boundary surfaces, sign-in caveats, matter-bearing warnings, and no-advice disclaimers.
- **Risk colors:** forest for confirmed, mustard for partial, signal red for blocked. They are semantic status colors, never decorative accents.

Banned product-wide: purple/violet/indigo palettes, blue-to-teal SaaS gradients, neon glow, traffic-light status dots, and one-off hex literals outside the token declaration layer.

## Typography

Instrument Serif is the display face and carries one rust italic word per major title. Instrument Sans is the marketing and button UI face. Inter Tight is runtime console chrome. IBM Plex Serif is the editorial and explanatory body face. JetBrains Mono is reserved for hashes, citations, versions, event IDs, and compact status labels.

Use tabular numerals for all numeric columns, constitutional hashes, timestamps, versions, docket identifiers, and audit anchors. Do not use `system-ui` as a primary fallback because it changes brand voice per platform.

Title rule: each product or console H1 gets exactly one italic rust word. Examples: `constitutional governance`, `Legal AI that knows when to stop`, `Evidence, not logs`, `Constitution compile`, and `Privacy and provenance`.

## Layout

The base unit is 4px. Marketing and product atlas pages use a 1200px shell, asymmetric hero composition, editorial cards, and asterism section breaks. Console pages use a 276px sidebar, flexible main panel, and 280px status rail. Matter-bearing or privileged products place the parchment boundary before sensitive content.

### Ask surface carve-out (`/ask`)

The `/ask` route is the one explicit, owner-approved exception to the
asymmetric-hero rule. It is a conversational governance Q&A surface modeled on a
search-assistant layout: a left workspace rail, a **centered prompt hero**, and a
threaded answer view with sourced cards and follow-ups. This centered
composition is intentional and permitted **only on `/ask`** — do not propagate
it to the landing, product atlas, or console surfaces. It still obeys every
non-visual contract: ACGS tokens only (no hardcoded hex), no inline `style`,
self-hosted fonts, hairline borders instead of shadows, and the rust accent as
the single brand color. Answer copy is grounded in `docs/CLAIMS.md` public
wording so the surface never overclaims.

Spacing should feel compact and deliberate. Cards use 24px padding by default, tables use dense mono headers, and product evidence lists use grid lines rather than shadows. Border radius is restrained: 4px for buttons, 6px for inputs, 8px for cards, and pill radius only for semantic pills.

## Elevation & Depth

Use hairline borders and top rules instead of shadows. Depth comes from paper layering (`paper`, `paper-alt`, `paper-deep`, `card`) and black-rule hierarchy. Shadows, glows, glassmorphism, blur panels, and floating 3D forms are not part of the system.

## Shapes

Shapes are constitutional and editorial: rectangular panels, compact cards, strong horizontal rules, mono pills, and the asterism `⁂` as a typographic section marker. The asterism is not a general icon; use it for brand marks, section breaks, sidebar brand furniture, and product bullet marks only.

## Components

`button-primary` is the default high-emphasis action and should appear at most once per viewport. `button-secondary` is for alternate navigation. `button-rust` is reserved for approval or promotion actions where the user is affirming a governed decision. Ghost text actions may use rust on hover but must not look like primary calls to action.

`surface-privilege` is structural for authentication, legal disclaimers, and privileged console boundaries. It should not animate in, be hidden behind a feature flag, or be treated as decorative.

Risk pills are semantic and restricted to confirmed, partial, blocked, and privileged states. They must not be used as generic badges.

Product pages use the same primitives as marketing: product-nav, product-hero, product-docket, product-stat-grid, product-brief, and product-evidence-list. Console pages use c-side, c-banner, c-topbar, c-heartbeat, c-table, c-toolbar, c-receipt, and the same button primitives.

Six governance components live under `src/components/governance/` and are always imported directly from their component file — there is no barrel export. `DecisionBadge` (`gz-badge`) renders the runtime outcome of a governed action (ALLOW / DENY / REVIEW_REQUIRED / TRANSFORM / ERROR) using a dot-plus-label pattern; import `Decision` from the same file. `FeatureStatusBadge` (`gz-fstatus`) renders the maturity of a feature or claim (verified / partial / in-progress / roadmap / unverified / needs-review / not-supported / deprecated) as a pill with a shaped dot that distinguishes unproven states; import `FeatureStatus` from the same file. `ProofChip` (`gz-proofchip`) is a link to a proof artifact; when `href` is absent it renders a fail-closed "No proof artifact" state — never pass a page-internal anchor as `href`. `GovernedClaim` (`gz-claim`) wraps a product claim with a `FeatureStatusBadge` and a `ProofChip`; it passes `proofUrl` to `ProofChip` only when status is `verified` or `partial`. `ReceiptCard` (`gz-rcard`) is the core receipt object: actor, capability, decision, policy, reason, hash chain, and optional replay/export actions; import `ReceiptCardData` from the same file. `HashChainViewer` (`gz-chain`) renders previous → current → next hash links with a chain-verification status; a `broken` status renders a fail-closed warning. All six components are theme-adaptive: their CSS reads only `--gz-*` token aliases and the semantic status tokens (`--allow`, `--deny`, `--verified`, etc.), which resolve to warm-paper values on the editorial surface and to dark control-plane values under `[data-theme="control-plane"]` — no hardcoded hex in any component rule.

## Two aesthetic registers + status colours (§2.6)

> **Supersession (2026-06-07).** The earlier rule "do not use dark mode for the
> privileged console" is retired. The console (`/console/*`) and product runtime
> surfaces now use a dark **control-plane** register; the editorial marketing
> landing and the parchment login / privilege boundary stay warm paper. A
> deliberate hybrid, approved by the maintainer.

One system, two registers — they share every token, the five type families, the
asterism `⁂`, and the governance law (gate · default-deny · record · replay):

1. **Editorial (warm paper + rust)** — the default `:root`. Marketing landing,
   product atlas prose, login boundary.
2. **Control-plane (dark)** — opt-in via `data-theme="control-plane"` on a
   subtree (set on the console shell root in `Console.tsx`). Near-black
   cool-tinted slate, brightened rust, instrumented density.

Mechanism: components and surfaces read `--gz-*` semantic aliases (`--gz-bg`,
`--gz-surface`, `--gz-fg`, `--gz-brand`, …). Under `[data-theme="control-plane"]`
those flip to dark values, **and** the warm-paper base aliases (`--paper`,
`--ink`, `--line`, `--accent`) are remapped onto them — so the token-only,
hardcoded-hex-free console rules invert to dark with no per-rule changes. Two
intentional non-remaps: the parchment privilege boundary (`--boundary*`) stays a
warm structural strip on dark (§4.3), and `--accent-on` (text/icon on a rust
fill) stays light in both registers.

### Status colours — signal, not decoration

Decision and feature/claim status are semantic colour, tuned per register
(editorial values AA on paper; control-plane values bright on near-black):

| Token | Decision / state |
|---|---|
| `--allow` green | ALLOW · verified |
| `--deny` red | DENY · blocked |
| `--review` amber | REVIEW_REQUIRED · partial |
| `--transform` blue | TRANSFORM · in-progress |
| `--roadmap` purple | roadmap / planned — status-only |
| `--unverified` gray | unverified |
| `--deprecated` muted red-gray | deprecated / not-supported |

This is the ONE place a non-rust hue is allowed, and only as signal — rust
remains the single *brand* accent. Badges read `color: var(--allow|…)` with a
low-alpha `color-mix` fill so one rule adapts to either register. The legacy risk
pills (`--risk-*`) map to the bright `--allow/--review/--deny` under the
control-plane register.

> **Divergence from canonical.** Per `CLAUDE.md`, this file is downstream of
> `/home/martin/Downloads/govern-zone/ACGS/DESIGN.md`, which "wins for tokens."
> The two-register model, the `--gz-*` aliases, `--accent-on`, and the status
> colour system are a project-local superset added here on 2026-06-07. Fold them
> back into the canonical file when it is next revised.

## Platform UX blueprint

The leading-platform target is a visual workbench that makes agent governance easy to operate without hiding risk. The public marketing UI and `/console/workbench` use the same product principle: **work queue → trace graph → evaluation panel → human release gate → evidence room**.

Design requirements:

- Show work as a short, ordered path before exposing dense tables. Operators should understand the next safe action in one scan.
- Keep trace, evaluation, guardrail, release, and evidence concepts visually adjacent so risk is not split across disconnected tabs.
- Treat NIST AI RMF-style governance, OWASP GenAI risk controls, agent tracing, guardrails, evaluation, and human judgment as visible product objects.
- Add an operator quick-start checklist that stays in the same workbench UI: **Start here → Hold release → Export proof**. It should explain the next safe action, the reason to block, and the proof that can leave the product.
- Add a platform requirements rail in the same workbench UI: **Framework → control → proof**. It should translate current governance, regulatory, agent-security, observability, evaluation, and accessibility research into six text-first lanes: Govern, Regulate, Secure, Observe, Measure, and Use.
- Add a Framework integration rail in the same workbench UI: **Normalize → Gate → Receipt → Adopt**. It should show how Claude/Codex-style, MCP-style, OpenAI Responses, OpenAI Chat, LangChain-style, generic, and batched tool-call payloads move through `gove-zone` normalization, policy gating, receipt emission, and malformed-batch denial without claiming live third-party framework deployment proof.
- Add Agent framework starter kits in the same workbench UI: **Pick payload → run gate → attach receipt**. It should give OpenAI Responses, LangChain tool-call, MCP / Claude / Codex hook, and benchmark-fixture starters a visible payload shape, local `gove-zone` command, proof label, and next route before anyone treats local adapter proof as live framework deployment.
- Add a guided review path in the same workbench UI: **Choose → Trace → Check → Export**. It should show the first-minute sequence before dense tables: choose the case, follow the trace path, check evaluation/authority holds, and export bounded proof only with the claim boundary attached.
- Add an operator decision rail for first-time use: **Pick the case → Inspect the path → Decide and export**. It should sit between the visual board and dense proof so the next safe action is visible before table review.
- Add a launch proof ladder in the same UI: **Local → Live → Assured**. Operators should see which evidence is only local, which command proves live deployment, and which external assurance packet must replace blockers before production claims.
- Add a current cutover panel in the same proof ladder UI: **Current saved cutover state**. It should show `safeToClaimProduction=false`, the saved live-check delta, and separate Marketing origin, Console origin, Storybook proof, and Evidence validation lanes so local operators can act without reading generated JSON.
- Add a release blocker queue in the same proof ladder UI: **Release blocker queue**. It should turn every external blocker into an operator card with `blockerId`, owner, proof artifact, and the next unblock command so deployment work is visible without treating the blocker as resolved.
- Add a live verifier blocker map in the same proof ladder UI: **Live verifier blocker map**. It should show the current live blocker ids (`live-console-dns`, `live-storybook-dns`, `live-console-healthz`, `live-console-security-headers`, `live-storybook-https`, and `live-storybook-manifest`) with their proof checks and next routes without treating them as completed evidence.
- Add a production command rail in the same proof ladder UI: **Production command rail**. It should show `make production-blocker-evidence`, `verify:production-live`, `validate:production-evidence`, and `validate:hosted-storybook-proof` with their artifact paths so operators know which proof files to attach without treating local commands as deploy approval.
- Add a hosted Storybook runway in the same proof ladder UI: **Hosted Storybook runway**. It should show **Build local gallery → Enable Pages deploy → Build proof gap report → Verify live Storybook → Attach hosted proof** with `storybook:build`, `STORYBOOK_PAGES_ENABLED=true`, `hosted-storybook-proof-gap-report.json`, `storybook-manifest-live`, and `copyIntoProductionEvidence.hostedStorybook` labels so the hosted buyer-evidence path is easy to operate without implying live proof exists.
- Add an assurance proof intake panel in the same proof ladder UI: **Assurance proof intake**. It should show the external proof packets still needed for Production authority, Legal claim review, Security assessment, Manual accessibility, and Hosted buyer evidence without treating templates as completed proof.
- Use existing editorial primitives only: paper layers, black rules, mono stage labels, rust arrows/checks, and serif explanations. Do not add a dashboard color palette, heavy icons, shadows, or animation.
- Keep copy claim-safe. This is a research-backed product blueprint until deployment proof, legal signoff, and external assurance evidence exist.

## Route-by-route wire decisions (A7)

The console shell reads `CONSOLE_WIRE_DECISIONS` from `src/routes/console/wire-decisions.ts` so the same route contract drives H1 metadata and the right-rail `Route contract` evidence card. These are local wire-level decisions for the current Phase 1 console slice; production browser evidence, cursor-scale lists, and destructive mutation confirmations remain separate deploy gates.

| Route | Header anatomy | Primary action | Secondary actions | Density | Filter placement | Pagination / virtualization | Right-rail purpose | Receipt lifetime | Destructive confirmation |
|---|---|---|---|---|---|---|---|---|---|
| `/console` | Shell title with heartbeat metrics and overview sections for cases, queues, and refusals | Open governed actions for verification | Inline queue and audit drill-down links only | Dense summary cards plus compact table and queue grid | No free-text filter; heartbeat and sections are scan controls | No pagination; capped summary evidence | Live ledger, queue health, events, coverage, and route contract | No local receipts; links to action and audit evidence | No destructive actions |
| `/console/workbench` | Shell title, operator map, work queue cards, trace sketch, evidence panel | Open the next safe evidence route from each stage | Inspect actions, traces, policies, deliberations, and audit without local mutation | Visual flow map over a three-column board with compact evidence rows | No free-text filter; staged map and case cards are visual scan controls | No pagination; local blueprint capped to three cases and five stages | Ledger and route contract visible while the workbench explains the operator path | Mints no local receipts; points to route-local or persisted evidence | No destructive actions on local blueprint |
| `/console/agents` | Shell title, agent toolbar, registry table, selected agent evidence | Select an agent row for authority evidence | Search agents and open action history | Dense mono table plus compact evidence cards | SearchToolbar above registry table | No pagination; fixture-scale filtered table | Global ledger plus route contract while evidence changes inline | Read-only inspection has no local receipt | No destructive actions |
| `/console/actions` | Shell title, action search, governed action table, dry-run detail | Run Test action in dry-run mode | Select action row, inspect explanation, inspect receipt | Two-column detail grid with dense table | SearchToolbar above action table | No pagination; rows scoped to governance sample | Global status plus contract while dry-run receipts stay inline | Inline dry-run receipt remains until replaced | Dry run only; production side effects require confirmation |
| `/console/maci` | Shell title, separation lane cards, isolation evidence | Inspect lane separation evidence | Review obligation, approval, monitor, and incident cards | Compact lane cards with mono evidence rows | No filter; all four lanes remain visible | No pagination; fixed lane count | Live ledger context beside separation proof | Read-only inspection has no local receipt | No destructive actions |
| `/console/deliberations` | Shell title, deliberation search, review cards, inline receipt | Approve, escalate, or open evidence | Search matters and review counsel context | Card review queue with compact metadata | SearchToolbar above deliberation cards | No pagination; queue capped for operator review | Queue health beside local review receipt | Inline deliberation receipt remains until replaced | Reject or close style actions require explicit intent and production confirmation |
| `/console/incidents` | Shell title, incident toolbar, escalation table, selected detail | Inspect escalation and linked audit evidence | Search incidents and review severity, owner, next response | Dense incident table plus detail cards | SearchToolbar above incident list | No pagination; active escalations only | Queue health while detail explains escalation | Read-only incident review has no local receipt | No destructive actions |
| `/console/policies` | Shell title, policy toolbar, dense register, selected detail | Open policy detail row | Search policy identifiers and scan status pills | Dense register table with compact detail | SearchToolbar above policy table | No pagination; current register sample | Route contract and coverage beside policy details | Read-only policy inspection has no local receipt | Future policy retirement requires confirmation and receipt |
| `/console/compile` | Shell title, compile summary, draft table, promotion receipt | Promote a validated draft | Replay checks, discard local draft evidence, inspect rows | Metric cards over dense draft table | Status controls above change table | No pagination; active compile unit only | Ledger and queue context while receipts render inline | Compile receipt remains until promote, replay, or discard replaces it | Local discard only; production discard or deploy requires confirmation |
| `/console/audit` | Shell title, audit filters, immutable event list, selected evidence | Open audit event for hash and actor context | Filter by event type, matter, or hash | Dense audit rows with mono hashes and timestamps | Filters above immutable event list | No local pagination; production stream requires cursors | Current ledger context while audit stays immutable | Shows persisted receipts and mints none | No destructive actions on immutable evidence |
| `/console/bus` | Shell title, bus trace explorer, selected trace detail, back navigation | Open a trace for schema and latency evidence | Back to list or inspect bus payload details | Inspector trace list with compact detail panels | Inline route controls rather than global text filter | No local pagination; production traces require cursors | Global health while trace detail explains propagation | References persisted bus evidence only | No destructive actions |
| `/console/settings` | Shell title, settings search, parameter table, staged receipt | Stage a setting-change receipt | Defer parameter, search settings, inspect rationale | Dense parameter table with compact receipt panel | SearchToolbar above settings table | No pagination; bounded parameter list | Ledger context while staged receipts stay inline | Settings receipt remains until another local action replaces it | Production parameter changes require confirmation |
| `/console/tenants` | Shell title, tenant search, tenancy cards, active tenant receipt | Switch or inspect tenant context | Search tenants and review region, matters, posture | Compact tenant cards with dense metadata | SearchToolbar above tenant cards | No pagination; active operator scope only | Queue and coverage context during tenant switching | Tenant receipt remains until next switch or inspect action | Tenant switching is local; destructive tenant changes absent |
| `/console/account` | Shell title, identity card, session table, account receipts | Rotate identity evidence or revoke session receipt | Inspect session metadata and local account status | Compact identity cards with dense session table | No filter; account surface stays short | No pagination; active sessions in one table | Privileged status while personal receipts stay inline | Account receipt remains until another identity or session action replaces it | Local revocation queue only; production revoke requires confirmation |

## Do's and Don'ts

Do:

- Use token references and CSS custom properties instead of hardcoded colors.
- Self-host fonts for privileged or matter-bearing surfaces.
- Use citations, hashes, replay receipts, and audit anchors as visual evidence.
- Keep page titles editorial with one rust italic word.
- Validate contrast whenever changing token values.

Don't:

- Introduce a second accent color.
- Use purple/violet/indigo gradients or generic SaaS blue.
- Apply `[data-theme="control-plane"]` to the editorial landing or the parchment privilege boundary — it is the console and product surface register only.
- Hide or animate privilege boundaries.
- Replace legal/governance copy with vague trust-marketing language.
- Use large shadows, glossy cards, bubble radii, or decorative status colors.
