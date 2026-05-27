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
