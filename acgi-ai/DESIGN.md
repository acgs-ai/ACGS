---
version: alpha
name: ACGS GovernZone
description: Editorial constitutional governance for marketing, product atlases, privileged consoles, and evidence panels.
colors:
  primary: "#1A1A1A"
  secondary: "#6B6B6B"
  tertiary: "#B8422E"
  neutral: "#FAFAF7"
  paper: "#FAFAF7"
  paper-alt: "#F2F1EC"
  paper-deep: "#EBEAE2"
  card: "#FFFFFF"
  ink: "#1A1A1A"
  ink-secondary: "#2B2B2B"
  ink-tertiary: "#424242"
  muted: "#6B6B6B"
  muted-light: "#999999"
  line: "#1A1A1A"
  line-soft: "#CFCFCF"
  line-softer: "#E5E5E5"
  rust: "#B8422E"
  rust-hover: "#8F361E"
  rust-soft: "#F4E2D8"
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

- **Paper (#FAFAF7):** the default background across all products. It keeps legal/governance surfaces calm and archival.
- **Paper Alt (#F2F1EC):** cards, sidebars, code blocks, product atlas tiles, and console panels.
- **Ink (#1A1A1A):** primary copy, strong rules, and high-emphasis actions.
- **Rust (#B8422E):** the single brand accent for links, active states, asterisms, italic emphasis, and controlled approval actions. It is darkened from the legacy decorative rust so normal-size rust text passes WCAG AA on paper.
- **Parchment (#F3EAD4):** privilege boundary surfaces, sign-in caveats, matter-bearing warnings, and no-advice disclaimers.
- **Risk colors:** forest for confirmed, mustard for partial, crimson for blocked. They are semantic status colors, never decorative accents.

Banned product-wide: purple/violet/indigo palettes, blue-to-teal SaaS gradients, neon glow, traffic-light status dots, and one-off hex literals outside the token declaration layer.

## Typography

Instrument Serif is the display face and carries one rust italic word per major title. Instrument Sans is the marketing and button UI face. Inter Tight is runtime console chrome. IBM Plex Serif is the editorial and explanatory body face. JetBrains Mono is reserved for hashes, citations, versions, event IDs, and compact status labels.

Use tabular numerals for all numeric columns, constitutional hashes, timestamps, versions, docket identifiers, and audit anchors. Do not use `system-ui` as a primary fallback because it changes brand voice per platform.

Title rule: each product or console H1 gets exactly one italic rust word. Examples: `constitutional governance`, `Legal AI that knows when to stop`, `Evidence, not logs`, `Constitution compile`, and `Privacy and provenance`.

## Layout

The base unit is 4px. Marketing and product atlas pages use a 1200px shell, asymmetric hero composition, editorial cards, and asterism section breaks. Console pages use a 276px sidebar, flexible main panel, and 280px status rail. Matter-bearing or privileged products place the parchment boundary before sensitive content.

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

## Platform UX blueprint

The leading-platform target is a visual workbench that makes agent governance easy to operate without hiding risk. The public marketing UI and `/console/workbench` use the same product principle: **work queue → trace graph → evaluation panel → human release gate → evidence room**.

Design requirements:

- Show work as a short, ordered path before exposing dense tables. Operators should understand the next safe action in one scan.
- Keep trace, evaluation, guardrail, release, and evidence concepts visually adjacent so risk is not split across disconnected tabs.
- Treat NIST AI RMF-style governance, OWASP GenAI risk controls, agent tracing, guardrails, evaluation, and human judgment as visible product objects.
- Add an operator quick-start checklist that stays in the same workbench UI: **Start here → Hold release → Export proof**. It should explain the next safe action, the reason to block, and the proof that can leave the product.
- Add a platform requirements rail in the same workbench UI: **Framework → control → proof**. It should translate current governance, regulatory, agent-security, observability, evaluation, and accessibility research into six text-first lanes: Govern, Regulate, Secure, Observe, Measure, and Use.
- Add a guided review path in the same workbench UI: **Choose → Trace → Check → Export**. It should show the first-minute sequence before dense tables: choose the case, follow the trace path, check evaluation/authority holds, and export bounded proof only with the claim boundary attached.
- Add an operator decision rail for first-time use: **Pick the case → Inspect the path → Decide and export**. It should sit between the visual board and dense proof so the next safe action is visible before table review.
- Add a launch proof ladder in the same UI: **Local → Live → Assured**. Operators should see which evidence is only local, which command proves live deployment, and which external assurance packet must replace blockers before production claims.
- Add a current cutover panel in the same proof ladder UI: **Current saved cutover state**. It should show `safeToClaimProduction=false`, the saved live-check delta, and separate Marketing origin, Console origin, Storybook proof, and Evidence validation lanes so local operators can act without reading generated JSON.
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
- Use dark mode for the privileged console.
- Hide or animate privilege boundaries.
- Replace legal/governance copy with vague trust-marketing language.
- Use large shadows, glossy cards, bubble radii, or decorative status colors.
