# ACGS GovernZone — build conventions

This design system ships **tokens + a hand-written CSS class system + self-hosted fonts** (no React component exports). Build UI with plain JSX styled by these classes and tokens. All styling truth lives in `styles.css` and its imports (`_ds_bundle.css` = the compiled app stylesheet, `fonts/fonts.css`) — read them before inventing anything. Never hardcode hex colors; every color must come from a `var(--*)` token.

## Root wrappers (required)

- Marketing/editorial surface: wrap the page in `<div className="marketing">` — sets bone-paper ground (`--paper`), warm ink, serif rhythm, SVG noise.
- Privileged console surface (dark "control plane"): set `data-theme="control-plane"` on the root **and** use console chrome classes (`.c-main`, `.c-banner`, `.rail-*`). The `--gz-*` token family remaps automatically under that attribute.

Without a wrapper, text renders on default white — always start from one.

## Tokens (the vocabulary)

- Surfaces: `--paper`, `--paper-2`, `--paper-3`, `--card`
- Ink: `--ink`, `--ink-2`, `--ink-3`, `--muted`, `--muted-2`
- Rules/borders: `--line`, `--line-soft`, `--line-softer`
- Accent (crimson = decision): `--accent`, `--accent-2`, `--accent-soft`, `--accent-on`; seal gold: `--gold`, `--gold-ink`
- Governance verdicts: `--allow`, `--deny`, `--review`, `--transform`
- Claim status: `--verified`, `--unverified`, `--partial`, `--missing`, `--deprecated`, `--roadmap`, `--notsupported`
- Risk: `--risk-lo`, `--risk-mid`, `--risk-hi`
- Type: `--font-display` (Instrument Serif), `--font-sans` (Instrument Sans), `--font-serif` (IBM Plex Serif), `--font-mono` (JetBrains Mono), `--font-runtime` (Inter Tight — console/runtime UI only)
- Space: `--space-2xs` … `--space-5xl` (4px base); radius: `--radius-sm/md/lg/pill`
- Dark console: `--gz-bg`, `--gz-fg`, `--gz-fg-2`, `--gz-surface`, `--gz-surface-2`, `--gz-line`, `--gz-brand`

## Class families (use these, don't invent parallel ones)

| Family | Use |
|---|---|
| `.m-*` | Marketing editorial: `.m-card`, `.m-cards`, `.m-brief`, `.m-code`, `.m-brand` |
| `.btn` + `.btn-primary` / `.btn-secondary` / `.btn-ghost` / `.btn-rust` / `.btn-sm` | Buttons |
| `.gz-badge` + `--allow` / `--deny` / `--review` / `--transform` / `--error` / `--sm` | Verdict badges (BEM `--` modifiers) |
| `.gz-chain*` | Receipt hash-chain visualization |
| `.ev-*` | Evidence/bento panels: `.ev-bento-cell`, `.ev-bento-cell-label`, `.ev-audit-section` |
| `.c-*`, `.rail-*` | Console chrome: `.c-main`, `.c-banner`, `.c-heartbeat`, `.rail-stat`, `.rail-event` |
| `.action-*` | Governed-action cards: `.action-card`, `.action-checks`, `.action-detail` |
| `.u-*` | Utilities: `.u-mono-cap` (mono smallcaps label), `.u-color-muted`, `.u-em-rust`, `.u-fw-600`, `.u-align-right` |

## Idiomatic snippet

```jsx
<div className="marketing" style={{ padding: "var(--space-3xl)" }}>
  <p className="u-mono-cap">Decision receipt</p>
  <h2 style={{ font: "600 2rem var(--font-display)", color: "var(--ink)" }}>
    Policy first, receipt always.
  </h2>
  <div className="m-card" style={{ borderColor: "var(--line-soft)" }}>
    <span className="gz-badge gz-badge--allow">ALLOW</span>
    <code style={{ fontFamily: "var(--font-mono)", color: "var(--muted)" }}>
      r_9f2c · sha256 bound
    </code>
  </div>
  <button className="btn btn-primary" type="button">Verify receipt</button>
</div>
```

Crimson (`--accent`) marks decisions; gold (`--gold`) marks seals/attestations — use them sparingly, never as large fills.
