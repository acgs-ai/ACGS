# Design System — ACGS Marketing + Console (acgi-ai)

> A monograph that runs in production.

This is the project-local design source-of-truth for the ACGS marketing landing
and governance console shipped from this React + Vite repository. It is
**downstream** of the canonical specification at
`/home/martin/Downloads/govern-zone/ACGS/DESIGN.md` (henceforth: *canonical*).
When the two disagree, the canonical wins. When this document specifies
something the canonical does not (e.g., React-specific surface mappings, route
shape, build settings), this document is authoritative for that detail.

Read this before changing anything visual in `acgi-ai/`. When the runtime code
references "DESIGN.md §X.Y", it is referring to **this** file.

---

## §1 Product Context

- **What this is:** Two React surfaces in one Vite app —
  - **Marketing landing** (`/`): editorial, 1200px max, asymmetric, sells the
    constitutional-governance thesis to compliance officers, governance leads,
    and engineering managers.
  - **Governance console** (`/console/*`): grid-disciplined, 276/···/280
    layout, MACI-aware, runs the operating constitution. Five sub-pages:
    Overview, Agents, MACI lanes, Policies, Audit, Deliberations.
- **Who it's for:**
  - Marketing audience: evaluators (regulated-AI buyers, lawyers, model-risk
    officers).
  - Console audience: governance leads and on-call counsel using the bus to
    enforce constitutional rules at runtime.
- **Industry:** AI safety / governance infrastructure, regulated AI, legal-tech
  adjacent.
- **Project type:** Hybrid web app — editorial marketing + privileged-feeling
  governance runtime. Both surfaces ship from the same Vite bundle.

**What we are not** — same anti-pattern list as canonical §1: no
navy-pinstripe-corporate, no Bloomberg-terminal cosplay, no Vercel-grid
sameness, no purple/violet/indigo SaaS gradients, no centered-everything
hero.

---

## §2 Tokens

All tokens are declared once in `src/index.css`. Hardcoded hex outside that
file is banned. Tokens follow canonical §2 verbatim; the React surface
expresses them as plain CSS custom properties (no Tailwind utility classes
in JSX, no oklch — hex is the runtime contract for this project).

### §2.1 Color

| Role | Hex | Use |
|---|---|---|
| `--paper`        | `#fafaf7` | Primary background — warm cream |
| `--paper-2`      | `#f2f1ec` | Cards, sidebars, code blocks |
| `--paper-3`      | `#ebeae2` | Pull-quotes, deep-warm surface |
| `--card`         | `#ffffff` | Pure white card on paper, sparingly |
| `--ink`          | `#1a1a1a` | Primary text — warm black |
| `--ink-2`        | `#2b2b2b` | Secondary text |
| `--ink-3`        | `#424242` | Tertiary / body |
| `--muted`        | `#6b6b6b` | Meta lines, captions |
| `--muted-2`      | `#999999` | Hint, placeholder |
| `--line`         | `#1a1a1a` | Strong rule (first viewport divider) |
| `--line-soft`    | `#cfcfcf` | Section dividers, table rules |
| `--line-softer`  | `#e5e5e5` | Card borders, inputs |
| `--accent`       | `#d97757` | Warm rust — single brand accent |
| `--accent-2`     | `#c96442` | Hover, active |
| `--accent-soft`  | `#f4e2d8` | Selection, focus echo |
| `--boundary`     | `#f3ead4` | Privilege parchment |
| `--boundary-ink` | `#7a5a1a` | Privilege text on parchment |
| `--boundary-line`| `#e3d5a8` | Privilege banner border |
| `--risk-lo`      | `#3d6b4a` | CONFIRMED / approved (forest) |
| `--risk-mid`     | `#b8842a` | PARTIAL / conditional (mustard) |
| `--risk-hi`      | `#c8432a` | BLOCKED / rejected (crimson) |

**Banned:** purple/violet/indigo for any role; pure traffic-light red/yellow/
green for risk; one-off hex literals; gradients between two ACGS tokens.

**Dark mode:** marketing only, deferred (see §7.2). Console stays light —
canonical §2.1 reasoning still applies (lawyers do not request dark mode;
the warm-paper aesthetic depends on it).

### §2.2 Typography

Five families, three roles, one bridge — same as canonical:

| Family | Variable | Role |
|---|---|---|
| Instrument Serif (400 / 400 italic) | `--font-display` | Display, hero, italic-rust emphasis |
| Instrument Sans (400 / 500 / 600 / 700) | `--font-sans` | Marketing UI, nav, CTAs, buttons |
| Inter Tight (400 / 500 / 600) | `--font-runtime` | Console UI chrome, table rows |
| IBM Plex Serif (400 / 500 / 600) | `--font-serif` | Editorial body, console prose |
| JetBrains Mono (400 / 500 / 700) | `--font-mono` | Code, hashes, citations, mono meta |

**Type scale** (anchor 16px body):

| Level | Size | Line | Where |
|---|---|---|---|
| Hero        | 56–96px (clamp) | 1.0  | Marketing top-of-page only |
| H1 (console)| 36px            | 1.05 | `c-topbar h1` |
| H2 (sec)    | 36–52px (clamp) | 1.05 | Marketing section heads |
| H3          | 22–28px         | 1.15 | Card heads, document titles |
| Body Lg     | 20px            | 1.55 | Marketing intro paragraph |
| Body        | 16px            | 1.55 | Default |
| Body Sm     | 13.5–15px       | 1.5  | Console table rows, console body |
| Meta        | 11–12px         | 1.4  | Mono labels, hashes, timestamps |

**Font features (always on):**
- Global: `font-feature-settings: "kern" 1, "liga" 1, "calt" 1;`
- Numeric columns / hash strings / version pills: add
  `font-variant-numeric: tabular-nums;`
- Console (Inter Tight): add `"ss01" 1, "ss03" 1, "cv11" 1` — technical
  letterforms.

**Italic policy:** Italic Instrument Serif is the brand's emphasis primitive.
Every page title in the console has exactly one italic-rust word
(*constitution*, *registry*, *separation*, *deliberations*, *escalations*,
*register*, *compile*, *trail*, *parameters*). Marketing hero has *governance*.
Do not italicize body text. Do not italicize buttons. Card-level headings
that mirror the page-title pattern (e.g., `delib-card h4`, `incident-row .title`)
follow the same rule: at most one italic-rust word, chosen for editorial
intent — never by word position.

**Font loading — critical privilege note:**
- The current implementation in `src/index.css` loads all five families from
  `fonts.googleapis.com` via `@import url(...)`. This is **acceptable for
  marketing** but **not for the privileged console** (matter / agent / tenant
  IDs in URL would leak via Referer to the CDN operator).
- The console currently shares the marketing import. **Before going to
  production with real tenant data, self-host WOFF2 subsets per §7.1.**
- The fallback stack in every `--font-*` declaration falls through to a named
  family stack (`Helvetica Neue`, `Arial`, `Georgia`), **not** `system-ui`.
  Do not regress to `system-ui` — it would silently swap brand voice per OS.

**Banned font primaries:** Inter, Roboto, Arial, Helvetica, Open Sans, Lato,
Montserrat, Poppins, Raleway, Clash Display, Space Grotesk, Geist (default),
Comic Sans, Papyrus, Lobster, Impact, Trajan, Courier New for body.

### §2.3 Spacing & Layout

**Base unit:** 4px. **Density:** compact.

Token vars in `src/index.css`:

```
--space-2xs: 2px   --space-xs: 4px    --space-sm: 8px    --space-md: 12px
--space-lg: 16px   --space-xl: 20px   --space-2xl: 24px  --space-3xl: 32px
--space-4xl: 48px  --space-5xl: 64px
```

**Border radius:**

| Element | Token | Px |
|---|---|---|
| Buttons | `--radius-sm` | 4 |
| Inputs  | `--radius-md` | 6 |
| Cards   | `--radius-lg` | 8 |
| Pills   | `--radius-pill` | 999 |

Bubble radius (>12px) is banned. Square 0 is reserved for hairline rules.

**Marketing layout** (canonical §2.3 / §5.1):
- Max content width: 1200px
- Hero: 2:1 asymmetric grid, text left, code/pull-quote right
- Section heads: 0.32fr / 1fr split (mono folio number left, display title right)
- Editorial cards: 3-column grid, `--paper-2` background, 2px black-rule top,
  folio number, serif title
- Asterism (`⁂`) section breaks: centered, italic Instrument Serif, rust accent

**Console layout** (canonical §5.2):
- `--console-sidebar: 276px`
- `--console-right-rail: 280px` (collapses below 1100px)
- `--doc-body-max: 64ch` for legal prose
- Privilege boundary banner (parchment) is **structural** — top edge of every
  console page, never animated, never gated on a feature flag (canonical §4.2).
- Topbar 24px / 32px padding, h1 36px Instrument Serif with one italic-rust
  word, two action buttons right.

### §2.4 Focus rings

Universal — exact spec from canonical §2.4:

```css
:focus-visible {
  outline: none;
  box-shadow:
    0 0 0 2px var(--paper),
    0 0 0 4px var(--accent);
  border-radius: 4px;
}
```

The double-ring works on cream paper, dark ink, and parchment surfaces alike.
Do **not** replace with a single rust outline (disappears on `--accent-soft`).

### §2.5 Motion

Minimal-functional only.

| Easing | Curve | Use |
|---|---|---|
| Enter | `ease-out`, 200ms | New element appears |
| Exit  | `ease-in`, 150ms  | Dismiss |
| Move  | `ease-in-out`, 250ms | Position transitions |

**Banned:** scroll-jacking, parallax, autoplaying video, "wow" hero animations,
3D primitives (no animated spheres / tetrahedra / waves), neon glow.

`prefers-reduced-motion: reduce` is honoured globally with `!important` on the
animation/transition resets. Biome flags this; the suppression comments in
`src/index.css` are spec-mandated and must remain.

---

## §3 Aesthetic Direction

**Aesthetic:** Editorial-Constitutional. Same as canonical §3.

**Mood:** Federal Register supplement, not SaaS dashboard. Empty space is part
of the composition. Every refusal is countersigned; every approval is signed.
The page is a poster, not a document.

**Reference brands** (descending fit):
1. Anthropic — warm-paper editorial, dark footer monolith
2. Stripe Press — oxblood, address-block footer, books as objects
3. Harvey AI — italic-serif gravitas (we are the *light* edition)

**Anti-references:** Credo AI, Holistic AI, "Geist on a Vercel grid", any
"Trusted by Gartner" badge wall.

**Voice:** First-person plural for the company; third-person for the product.
Cite primary sources by section (`§164.502(b)`, `EU AI Act §15(4)`,
`SR 11-7 §V`). The constitutional hash `608508a9bd224290` is brand furniture
— it appears in mono in the sidebar foot, the privilege banner, the audit
column, and the dark footer (in rust).

---

## §4 Components

### §4.1 Risk pills (canonical §4)

Border-and-text in the risk colour, transparent background, leading dot:

```
[● CONFIRMED]    border + text --risk-lo
[● PARTIAL]      border + text --risk-mid
[● BLOCKED]      border + text --risk-hi
[● PRIVILEGED]   parchment background + boundary-ink text
```

Mono 11px, letter-spacing 0.06em, radius 999px. Used in: agent registry,
MACI lane cards, audit timeline, deliberation cards, coverage right-rail.

These are **semantic, not decorative.** Do not use them for anything other
than these four states.

### §4.2 Buttons

| Variant | Background | Text | Border | Use |
|---|---|---|---|---|
| `btn-primary`   | `--ink`    | `--paper` | none | Default CTA. One per viewport. |
| `btn-secondary` | transparent| `--ink`   | `--line` | "Read the docs" / "Open the console" |
| `btn-ghost`     | transparent| `--ink`   | none | Tertiary; rust on hover |
| `btn-rust`      | `--accent` | `--paper` | none | Approval / confirmation in console (Approve in Deliberations) |
| (danger)        | `--risk-hi`| `--paper` | none | Reserved; not yet used |

Padding `12px 20px` (marketing), `~10px 18px` (console nav-cta), radius 4px,
weight 500, letter-spacing -0.005em.

### §4.3 Privilege banner (canonical §4.2)

The console's parchment banner is structural. `display: block` is
load-bearing — no `aria-hidden` toggle, no animate-in/out on route change,
no localization without legal review. Citation lives on the right; copy is
fixed.

### §4.4 Privilege boundary text

Custodial / matter-bearing rows render with `pill.privileged` (parchment
background, boundary ink text) instead of any of the three risk colours.

### §4.5 Folio glyph

The asterism `⁂` (U+2042) is the brand mark. Used in:
- Hero eyebrow (above the headline, in `--accent` italic)
- Section breaks between long-form blocks (centred row of three)
- Sidebar brand line in the console (after `acgs`, italic rust)
- Footer mark in the dark monolith
- Audit-trail closing caveat
- Bullet for pricing tier features (`li::before` content `⁂`)

It is a typographic device, not an icon. Do not use it as a logo or general
bullet.

### §4.6 Coverage table

Mono 13px, tabular-nums, three columns (Framework / Sections enforced /
Version). Border-top is the strong `--line`; all other rules `--line-softer`.
First column is sans-serif 14px (the human-readable name); second column is
mono ink-3 (the citation chain); third column is mono ink-3 right-aligned
(version pin).

### §4.7 Console table

`.c-table` — same column policy:
- Headers: mono 10.5px uppercase, `--line` border-bottom
- Body: 13.5px, `--line-softer` row borders, `:hover` `--paper-2`
- Mono columns flagged with `.mono` class, `tabular-nums` enabled

### §4.8 Pricing tiers

Three cards. Middle (Governed) is **inverted** — `--ink` background,
`--paper` text, rust CTA. Bullets use `⁂` in italic rust. No "compare features"
matrix; tiers are editorial, not check-mark grids.

### §4.9 Marketing footer

Dark address-block, four columns: brand (with monogram + address-style
prose), platform links, editions, reading-room. Bottom bar: version pin
(`v3.1.0 · Vol. I · MMXXVI`) on the left, `hash 608508a9bd224290` on the
right with the hash itself in `--accent`.

### §4.10 Code block (hero)

`.m-code` — `--paper-2` background, `--line-softer` border, mono 12.5px,
tabular-nums. Header row (caption + version + hash) in mono 11px uppercase
with bottom border. Token classes: `.k` (keyword) `--accent-2`, `.s`
(string) `--ink`, `.c` (comment) `--muted`. Renders the actual rule that
the bus would refuse.

---

## §5 Surface Mappings

### §5.1 Marketing — `src/routes/Marketing.tsx`

- Single file, single component
- Owns the asymmetric hero, three editorial cards (Constitutions that
  compile / Separation of powers / Fail closed), six-row coverage table,
  three-tier pricing, dark footer
- All copy lives in three module-level data structures: `capabilities`,
  `coverage`, `tiers`. Edit those, not the JSX

### §5.2 Console shell — `src/routes/Console.tsx`

- Hosts the 3-column `.console` grid
- Owns the sidebar (`acgs ⁂`, version pin, two nav groups Operate/Govern,
  constitutional-hash foot)
- Owns the privilege banner (always rendered, always visible)
- Owns the topbar (crumb + display-serif h1 with italic-rust word + two
  actions)
- Owns the right rail (Live Ledger / Recent Events / Coverage status pills)
- Dispatches to one of five sub-pages via `<PageBody path={path} />`

### §5.3 Console pages — `src/routes/console/*`

| File | Route | Section | Purpose |
|---|---|---|---|
| `Overview.tsx`     | `/console`               | Operate | Stat blocks + refusal-by-article table |
| `Agents.tsx`       | `/console/agents`        | Operate | 12-row agent registry |
| `Maci.tsx`         | `/console/maci`          | Operate | Three-column lane board |
| `Deliberations.tsx`| `/console/deliberations` | Operate | HITL queue with Approve/Hold/Refuse |
| `Incidents.tsx`    | `/console/incidents`     | Operate | Active escalations off the audit trail |
| `Policies.tsx`     | `/console/policies`      | Govern  | Rule list + diff editor |
| `Compile.tsx`      | `/console/compile`       | Govern  | Staged constitution amendments + hash diff |
| `Audit.tsx`        | `/console/audit`         | Govern  | Append-only timeline |
| `Settings.tsx`     | `/console/settings`      | Govern  | Operator parameters with constitution/operator/default tags |

Each page returns plain JSX. No Tailwind utility classes. Inline styles are
used **only** for one-off flexbox alignments inside otherwise-tokenized
sections (e.g., `style={{ marginLeft: 'auto' }}`); colors and font-families
inside style props always reference `var(--*)`.

Two component primitives extend §4 for these pages:

- **`.change-marker`** (Compile) — diff-style ASCII indicator (`+` / `~` /
  `−`) in mono with risk-colour leading character. Used in place of risk
  pills for change types so §4.1's "pills are semantic" contract holds.
- **`.tag`** (Settings) — flat mono uppercase label for source attribution
  (`Constitution` / `Operator` / `Default`). Visually distinct from posture
  pills: rectangular `--radius-sm`, no leading dot, no risk colour.

### §5.4 Routing — `src/App.tsx` + `src/lib/navigate.ts`

- Custom client-side router via `useState` + `popstate`
- `navigate(to)` performs `pushState` + dispatches a `popstate` so listeners
  rerender
- TanStack Router and React Query are in deps but **not yet used** — they
  are reserved for the next phase (data fetching, route loaders, search
  params)

### §5.5 Build / lint settings

- **Vite 8 + React 19 + TypeScript 6**
- Pure CSS with custom properties — Tailwind is in deps but the project does
  not use utility classes; Tailwind is reserved for future utility-only use
  cases
- **Biome** is the formatter and linter (combined under `pnpm lint` and
  `pnpm format`). ESLint is also wired but Biome is the primary check.
- The two `!important` declarations in the `prefers-reduced-motion` reset
  carry inline `biome-ignore` comments. They are spec-mandated; do not remove.

---

## §6 Allowed and Banned

### §6.1 Allowed

- Subtle SVG noise overlay on marketing (already in `App.css`,
  opacity ≤ 0.4, `mix-blend-mode: multiply`)
- Hairline rules (1px `--line-soft` / `--line-softer`)
- Folio glyph `⁂` and Roman numerals (I, II, III, IV) — folio numbers on
  section heads use Roman in the marketing layout
- Drop-cap-style folio numbers (`№ 01`, `№ 02`, `№ 03`) on editorial cards
- Dark monolith address-block footer (Stripe-Press inspired)

### §6.2 Banned

- Purple / violet / indigo gradients
- Linear blue→teal or pink→orange gradients
- 3D blob illustrations
- Glow effects, drop shadows >12% opacity, neon outlines
- Animated 3D primitives (sphere / tetrahedron / wave)
- 3-column icon-in-coloured-circle feature grids
- Centred-everything composition for hero / feature sections
- Generic stock photography ("professionals at laptops")
- Traffic-light window chrome on code blocks (red/yellow/green macOS dots)
  — use a folio number (`01`) or a hash instead
- Bubble-rounded buttons / cards (radius >12px)
- "Trusted by Gartner / IDC / Forrester" badge walls
- Hardcoded hex literals outside `src/index.css`
- External CDN font / script loads on the **console** (privileged surface)
  once the WOFF2 self-host ships (§7.1)
- `system-ui` as a typography fallback — silently swaps brand voice per OS

---

## §7 Roadmap

### §7.1 Self-host WOFF2 for the console (P0 before production)

The console is currently sharing the marketing-side Google Fonts CDN load.
Console URLs include `/console/agents`, `/console/policies`, etc.; once
real tenant or matter IDs ride those URLs, the CDN operator gets them via
`Referer`. Ship self-hosted WOFF2 subsets:

- Latin subset of Inter Tight 400/500/600, IBM Plex Serif 400/500,
  JetBrains Mono 400 served from same-origin `/static/fonts/`
- WOFF2 only, headers `public, max-age=31536000, immutable`
- Marketing may continue to use Google Fonts; the privilege concern is
  scoped to authenticated / privileged-data routes

### §7.2 Marketing dark mode

Dark mode tokens are scoped in canonical §2.1 but not yet wired here. When
shipped:
- Marketing only (console stays light per canonical §2.1)
- Inversion does **not** desaturate the rust accent — `--accent` stays at
  `#d97757` in both modes

### §7.3 TanStack Router migration

The current `App.tsx` uses a 14-line custom router. When data fetching,
route loaders, search-param decoding, or nested layouts are needed, migrate
to TanStack Router (already in deps). Keep `navigate()` as a thin wrapper
to avoid a churning rewrite of every link.

### §7.4 Form work (deliberations approve/hold/refuse)

Approve / Hold / Refuse are currently buttons with no handlers. When wired,
they must emit a constitutional-hash-attested receipt before the action
ships — the bus must refuse to dispatch a high-risk decision without the
receipt (canonical §4 humans-in-the-loop rule).

### §7.5 Real data wiring

Every list, table, and queue currently renders module-level fixture data.
The fixtures are realistic but not connected to the bus, the gateway, or
the worker. Wiring is out of scope for the design system; when it lands,
the API client must reuse `src/core/shared/` from the ACGS monorepo (auth,
rate limit, structured logging).

---

## §8 Decisions Log

| Date | Decision | Rationale |
|---|---|---|
| 2026-05-03 | DESIGN.md created | First project-local doc for `acgi-ai`. Derives from canonical ACGS/DESIGN.md. Captures the realized React+Vite surface, the routing structure, and the build/lint settings the canonical doc does not cover. |
| 2026-05-03 | Pure CSS with custom properties; no Tailwind utilities | Token-driven design is easier to audit against DESIGN.md. Tailwind stays in deps for future utility-only use. |
| 2026-05-03 | Custom 14-line router over TanStack Router | Seven routes, no data fetching, no nested layouts — TanStack Router boilerplate would have outweighed its benefits. Migration path noted in §7.3. |
| 2026-05-03 | Biome as primary lint+format; ESLint kept for `react-refresh/only-export-components` | Biome is faster and includes formatter; the only ESLint rule with practical leverage is the fast-refresh export check, satisfied by extracting `navigate` into `src/lib/navigate.ts`. |
| 2026-05-03 | Italic-rust emphasis word on every console h1 | Page identity primitive. Six pages, six emphasis words: *constitution*, *registry*, *separation*, *register*, *trail*, *deliberations*. Marketing hero adds *governance*. |
| 2026-05-03 | Marketing copy lives in module-level data, not JSX | `capabilities`, `coverage`, `tiers` arrays in `Marketing.tsx`. Editorial copy changes without touching layout. |
| 2026-05-03 | Privilege banner rendered structurally, never gated | Canonical §4.2 mandate: `display: block` is load-bearing on the parchment banner; no animation, no `aria-hidden` toggle, no feature flag. |
| 2026-05-03 | `biome-ignore` comments on `prefers-reduced-motion` `!important` | Canonical §2.5 mandates `!important` so user motion preference cannot be overridden. The two suppression comments in `src/index.css` are spec-mandated and must remain. |
| 2026-05-03 | Google Fonts CDN for both marketing and console (with TODO) | Acceptable for marketing; not for the privileged console once tenant IDs ride URLs. §7.1 tracks the WOFF2 self-host that must precede production. |
| 2026-05-03 | Card-level italic-rust rule (Deliberations, Incidents) | Same "exactly one italic word" pattern as page titles, chosen by editorial intent (e.g. *disclose*, *quorum*, *recipient*) rather than slice-by-position. Implemented via a per-record `emphasis` field + `renderTitle` helper. Replaces the prior `slice(2)` rendering that italicized 3-4 words per card. |
| 2026-05-03 | Three console pages added: Compile, Settings, Incidents | Compile wires up the previously dead "Compile constitution" topbar button (`/console/compile`); Settings exposes operator parameters with a constitution-vs-operator-vs-default source tag; Incidents surfaces escalations off the audit trail. Crumb numbering: I.V Incidents, II.II Compile, II.III Audit (renumbered from II.II), II.IV Settings. Tenants and Login deferred — multi-tenancy is not a primary surface in DESIGN.md, and auth needs its own visual paradigm. |
| 2026-05-03 | `.change-marker` and `.tag` primitives added rather than reusing risk pills | §4.1 says risk pills are semantic-only (CONFIRMED/PARTIAL/BLOCKED/PRIVILEGED). Compile change types and Settings source attribution are different semantics; mapping them to risk pills would have broken the contract. `.change-marker` uses ASCII +/~/− in risk colours; `.tag` is flat, rectangular, no leading dot. |

---

## §9 References

- Canonical: `/home/martin/Downloads/govern-zone/ACGS/DESIGN.md` (23K)
- Vertical sister: `/home/martin/Downloads/govern-zone/ACGS/packages/legalguard/DESIGN.md` (19K)
- Live preview: `pnpm dev` from this directory; pages at `/`, `/console`,
  `/console/agents`, `/console/maci`, `/console/policies`, `/console/audit`,
  `/console/deliberations`
- Constitutional hash (brand furniture): `608508a9bd224290`
