# Deployment — ACGS Marketing + Console (acgi-ai)

> The deployment topology is the privilege boundary.

This is the project-local deployment design for `acgi-ai`. It pairs with
`DESIGN.md` (the visual + UX contract) and `CLAUDE.md` (the agent contract).
The visual privilege boundary in `DESIGN.md §4.3` only holds if the network
topology under it agrees. This document is what that agreement looks like.

When `DESIGN.md` and `DEPLOY.md` disagree, `DESIGN.md` wins for visual /
brand questions; `DEPLOY.md` wins for hosting, headers, CSP, and supply
chain. They overlap on the WOFF2 self-host (§7.1 there → §6 here).

---

## §1 Purpose & constraints

The repo ships a single Vite bundle that serves two surfaces:

- **Marketing landing** at `/` — public, evaluator-facing, editorial
- **Governance console** at `/console/*` — privileged, tenant + matter IDs
  ride the URL, audit trail material

These have different threat models, different audiences, and different
acceptable third parties in the request path. The deployment must reflect
that without doubling the operational surface area beyond what is justified.

**Hard constraints:**

1. `DESIGN.md §7.1` — fonts on the privileged console must be
   same-origin WOFF2 (CDN `Referer` would leak `/console/agents`,
   `/console/policies/P-1207`, etc. to the font CDN operator).
2. `DESIGN.md §4.3` — the structural privilege banner is a UI commitment
   the deployment must not silently undermine (e.g. by sticking a
   third-party analytics tag on the console origin).
3. The custom 14-line router (`src/lib/navigate.ts`) uses `pushState`. Any
   deep link into `/console/*` must fall back to `index.html` server-side.
4. There is no backend yet (`DESIGN.md §7.5`); the console renders fixture
   data. The deployment must be ready to grow an API at the same origin
   without a second migration.
5. The product brand is regulated-AI. Subprocessor list and access-log
   custody are buyer-visible artifacts. Treat them like product surface.

**Out of scope for this document:**

- The bus, gateway, and worker. Their deployment lives in the ACGS
  monorepo. This doc is the front-door only.
- Auth (SSO/OIDC). When it lands, it terminates at the console origin
  defined in §4 — that's the only constraint this doc sets.
- DR / multi-region. Single-region is fine for the marketing+demo phase;
  see §11.

---

## §2 Topology

**Two origins, one brand. Marketing on edge, console on operator-controlled
infrastructure.**

```
                     ┌──────────────────────────────┐
   acgs.ai           │  Vercel edge (or Netlify)    │
   www.acgs.ai  ───► │  static bundle, CDN-cached   │
                     │  marketing surface only       │
                     └──────────────────────────────┘

                     ┌──────────────────────────────┐
   console.acgs.ai   │  Cloud Run (or Fly.io)        │
                ───► │  Caddy/Nginx in a container   │
                     │  static bundle + same-origin  │
                     │  /api/* reverse proxy → bus   │
                     │  same-origin /static/fonts/   │
                     └──────────────────────────────┘
```

Why split, when the bundle is one file:

- **Privilege.** The marketing CDN provider sees marketing traffic only.
  The console CDN provider does not exist; the request path is end-to-end
  under operator control. This is the deployment-layer expression of
  `DESIGN.md §4.3`.
- **Subprocessor story.** "Vercel sees public marketing visitors; nothing
  third-party sits between a customer and `console.acgs.ai`." That is a
  one-line answer to a question every regulated-AI buyer asks.
- **Future API homing.** When the bus client lands (`DESIGN.md §7.5`), it
  calls `console.acgs.ai/api/*` — same origin, no CORS, no Referer
  cross-pollination, no separate cert. The proxy is already there.

Why not a single edge deploy:

- A single Vercel/Netlify deploy puts the edge provider on every console
  request. Their access logs would carry `/console/agents/A-07` etc.
  That is not a story this product wants to tell.

Why not a Cloudflare-in-front-of-origin single-domain plan:

- Cloudflare Enterprise with BAA is a defensible answer, but it is more
  expensive, more configuration-fragile (cache rules, header rewrites,
  `Referer` policy), and gives up the cleanest version of the
  subprocessor story. Reconsider in §11 when traffic justifies a WAF.

---

## §3 Marketing surface — `acgs.ai`, `www.acgs.ai`

**Provider:** Vercel (Hobby for staging, Pro for production). Netlify is an
acceptable substitute; the design is provider-agnostic at this layer.

**Build:**

```
pnpm install --frozen-lockfile
pnpm build
# output: dist/
```

**Routing config** (`vercel.json` at repo root, applied only to the
marketing project — see §7):

```jsonc
{
  "buildCommand": "pnpm build",
  "outputDirectory": "dist",
  "cleanUrls": true,
  "rewrites": [
    {
      "source": "/console/(.*)",
      "destination": "https://console.acgs.ai/console/$1"
    },
    { "source": "/(.*)", "destination": "/index.html" }
  ],
  "headers": [
    {
      "source": "/assets/(.*)",
      "headers": [
        { "key": "Cache-Control", "value": "public, max-age=31536000, immutable" }
      ]
    },
    {
      "source": "/(.*)",
      "headers": [
        { "key": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains; preload" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=(), interest-cohort=()" }
      ]
    }
  ]
}
```

**Notes on the marketing surface:**

- The `/console/*` rewrite is a hard redirect to the console origin so
  that an evaluator who clicks "Open the console" from a deep marketing
  link lands on the privileged origin, not on a marketing-side
  rendering. This means `Marketing.tsx`'s "Open the console" CTA must
  point at `https://console.acgs.ai/console`, not at a relative `/console`
  href, in the production build.
- Marketing analytics are acceptable here. Plausible / Fathom / Vercel
  Web Analytics — pick one. Do not deploy the same script bundle on the
  console origin (§4).
- Google Fonts CDN may continue to load on this origin
  (`DESIGN.md §2.2`). The privilege concern is scoped to the console.

---

## §4 Console surface — `console.acgs.ai`

**Provider:** Cloud Run (managed) or Fly.io. Pick by team operational
familiarity; the contract is identical. The container holds:

- Caddy (recommended) or Nginx — terminates TLS via Let's Encrypt /
  ACME, serves the static `dist/` bundle, applies the headers in §5,
  and reverse-proxies `/api/*` once the bus client lands.
- The compiled `dist/` from `pnpm build`, baked at image-build time.
- `/static/fonts/*.woff2` — see §6.

**Why a container, not Cloud Run "service" with object storage:**

- A container is the right primitive when the same origin needs to
  grow a reverse proxy. Object-storage hosting forces a second hop
  for `/api/*` (Cloud Run + GCS, or Fly + Tigris) which is operational
  rope for a marginal cost saving.

**Caddyfile sketch** (`infra/caddy/Caddyfile` when implemented):

```caddy
console.acgs.ai {
  encode gzip zstd

  # SPA fallback for the custom 14-line router
  try_files {path} /index.html

  # Static assets — long cache, hash-stable
  @assets path /assets/*
  header @assets Cache-Control "public, max-age=31536000, immutable"

  # Self-hosted fonts — DESIGN.md §7.1
  @fonts path /static/fonts/*.woff2
  header @fonts {
    Cache-Control "public, max-age=31536000, immutable"
    Access-Control-Allow-Origin "*"
  }

  # Privileged HTML — never cache the entry document
  @html path /index.html /
  header @html Cache-Control "no-store, no-cache, must-revalidate"

  # Security posture — see §5 for the full justification
  header {
    Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    X-Content-Type-Options    "nosniff"
    X-Frame-Options           "DENY"
    Referrer-Policy           "no-referrer"
    Permissions-Policy        "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    Cross-Origin-Opener-Policy   "same-origin"
    Cross-Origin-Resource-Policy "same-origin"
    Content-Security-Policy   "{$CSP}"
  }

  # API reverse proxy — wired when the bus client lands (DESIGN.md §7.5)
  # handle_path /api/* {
  #   reverse_proxy bus.internal:8080
  # }

  root * /srv/dist
  file_server
}
```

**Notes on the console surface:**

- **No third-party analytics ever.** The console is the audit trail; it
  cannot also be a Google Analytics property.
- **No third-party error tracking SDK loaded in-browser.** Sentry / Datadog
  RUM, etc., would put session URLs in their warehouse. If product
  decides it needs error telemetry, route it server-side via the bus.
- **No CDN edge cache for `/index.html` or any `/console/*` HTML
  response.** Static `/assets/*` (Vite's hashed bundle) is the only thing
  that may sit in caches.
- `Referrer-Policy: no-referrer` is stricter on the console than on
  marketing because the console may link out (docs, citations) and we do
  not want the console URL to leak in those navigations.
- `X-Frame-Options: DENY` is non-negotiable — the privileged surface
  must never be embeddable.

---

## §5 Headers & CSP

The marketing and console surfaces share a baseline; the console adds.

| Header | Marketing | Console | Notes |
|---|---|---|---|
| `Strict-Transport-Security` | preload, 2y | preload, 2y | Both apex-eligible |
| `X-Content-Type-Options` | nosniff | nosniff | |
| `X-Frame-Options` | SAMEORIGIN | **DENY** | §4 reasoning |
| `Referrer-Policy` | strict-origin-when-cross-origin | **no-referrer** | Console URLs leak meaning |
| `Permissions-Policy` | minimal | minimal | No camera/mic/geo on either |
| `Cross-Origin-Opener-Policy` | unsafe-none | **same-origin** | Console isolates |
| `Cross-Origin-Resource-Policy` | cross-origin | **same-origin** | Console isolates |
| `Content-Security-Policy` | report-only | **enforced** | See below |

**Console CSP (target, enforced):**

```
default-src 'self';
script-src  'self';
style-src   'self' 'unsafe-inline';   /* see note */
font-src    'self';
img-src     'self' data:;
connect-src 'self';
frame-ancestors 'none';
base-uri    'self';
form-action 'self';
upgrade-insecure-requests;
```

**`'unsafe-inline'` on `style-src` is a debt, not a permission.** The
React surface uses inline `style={{}}` for one-off flexbox alignments
(`DESIGN.md §5.3`). To remove the debt either (a) move every inline
style into a CSS class, or (b) ship a build-time nonce or hash list.
Option (a) is cheapest and matches the design contract better. Track
this as P0-before-real-tenants alongside the WOFF2 self-host.

**Marketing CSP (target, report-only):**

Marketing can keep `script-src 'self' https://*.googletagmanager.com`
(or whichever analytics is chosen) and `style-src` permissive while we
iterate. The cost of getting marketing CSP wrong is a broken third-party
analytics tag, not a privilege leak.

---

## §6 Build, fonts, and static assets

**Vite output:**

- `dist/index.html` — never cached
- `dist/assets/*.{js,css}` — hashed filenames, `immutable, max-age=1y`
- `dist/assets/*.{svg,png,woff2}` — same

**WOFF2 self-host** (`DESIGN.md §7.1`, landed):

- 5 families × {latin, latin-ext} subsets under
  `public/static/fonts/`, declared in `src/fonts.css`, served at
  `/static/fonts/*.woff2` by the Caddy `@fonts` matcher
  (`infra/Caddyfile`). 30 files / ~803KB total; latin loads first,
  latin-ext deferred via `unicode-range` so most sessions never request
  it. Cyrillic, Greek, Vietnamese subsets dropped — re-add only if a
  new tenant needs them.
- Source: Google Fonts CSS endpoint with a modern UA, then the
  `gstatic.com` WOFF2 binaries downloaded once at dev time. No runtime
  third-party fetch from either surface.
- Both surfaces use the same bundle. Marketing inherits the privilege
  story even though it doesn't strictly need to — one font story is
  easier to reason about than two.
- **TODO:** SIL Open Font License attribution at
  `public/static/fonts/OFL.txt` plus a marketing footer link in the
  "Reading room" column. Required before first real tenant.

**No bundle-time secrets.** This is a fully-static frontend. There is
no `VITE_*` env var that ever holds a credential. When the API client
lands (`DESIGN.md §7.5`), auth tokens come from the auth flow at runtime,
never the build.

---

## §7 CI/CD

**Repo layout for deploy artifacts** (when implemented):

```
.github/workflows/
  marketing.yml      # → Vercel marketing project
  console.yml        # → Cloud Run / Fly.io console project
infra/
  caddy/Caddyfile    # console origin config
  cloudrun/service.yaml  (or fly/fly.toml)
  Dockerfile.console
vercel.json          # marketing-only routing
```

**One PR, two deploy targets.** Both workflows trigger on PR + main.
Both run `pnpm lint && pnpm build` before deploying. PR previews:

- Marketing → Vercel preview URL (one per PR; transient)
- Console → Cloud Run preview revision behind a temporary
  `pr-{number}.console-staging.acgs.ai` hostname; gated behind the
  staging IAP / VPN

**Preview environments are fixture-data only.** No PR preview ever sees
real tenant data; that is enforced by §10 (production access logs +
synthetic-tenant-only banner on staging).

**Branch protection on `main`:**

1. Required check: `pnpm lint`
2. Required check: `pnpm build`
3. Required check: `marketing-deploy` (preview must succeed)
4. Required check: `console-deploy` (preview must succeed)
5. Required review: 1 maintainer approval

`main` deploys to production on merge. There is no manual promotion
step; manual promotion encourages drift. If a hotfix needs to skip
preview, that is a procedural exception with an incident record.

---

## §8 Environments

| Env | Marketing host | Console host | Constitution hash | Data |
|---|---|---|---|---|
| dev (local) | localhost:5173 | localhost:5173 | `608508a9bd224290` (fixture) | fixture |
| preview | `pr-{n}-acgi-ai.vercel.app` | `pr-{n}.console-staging.acgs.ai` | per-PR fixture | fixture |
| staging | `staging.acgs.ai` | `console-staging.acgs.ai` | rotating fixture | synthetic tenants |
| production | `acgs.ai`, `www.acgs.ai` | `console.acgs.ai` | the live canon | real |

Every non-production environment renders a banner in the privilege
strip (`DESIGN.md §4.3`'s parchment band) that says
`⁂ STAGING · synthetic data only` in `--boundary-ink` on
`--boundary`. This is structural, not a feature flag — same rules as
the production banner.

---

## §9 DNS, certificates, mail

**Zone:** `acgs.ai`, single registrar, DNSSEC on.

**Records:**

| Name | Type | Target | Notes |
|---|---|---|---|
| `acgs.ai` | A/AAAA | Vercel anycast | apex |
| `www.acgs.ai` | CNAME | `cname.vercel-dns.com` | |
| `console.acgs.ai` | CNAME | Cloud Run / Fly hostname | |
| `_acme-challenge.console` | TXT | rotated by ACME client | for cert issuance |
| MX | | Workspace / Fastmail | mail provider |
| TXT (apex) | SPF | `v=spf1 include:_spf.google.com -all` | mail policy |
| TXT (DKIM) | DKIM | provider-issued | mail policy |
| TXT (DMARC) | `v=DMARC1; p=reject; rua=mailto:dmarc@acgs.ai` | reject, not quarantine | regulated-AI brand |
| CAA (apex) | CAA | `0 issue "letsencrypt.org"` | restrict CAs |

**HSTS preload:** submit `acgs.ai` and `www.acgs.ai` after 60 days of
clean delivery. Console is preload-eligible via `includeSubDomains` on
the apex record.

**Certificates:** ACME via the deploy provider on each surface. No
manual cert handling.

---

## §10 Observability & audit

The deployment's observability matches the product's: append-only,
hash-anchored, operator-readable.

**Marketing:**

- Provider built-in access logs (Vercel / Netlify) + analytics product.
  Retention 90 days. This is enough — marketing access patterns are
  not constitutional artifacts.

**Console:**

- Caddy access log → JSON lines → forwarded to the same audit sink the
  bus uses (`DESIGN.md §7.5` — when the API client lands, this is
  `bus.internal/observe`). Until then, ship to a same-region log bucket
  with object-lock + WORM retention of 7 years (HIPAA / SR 11-7 floor).
- No third-party log shipper that introduces a subprocessor.
- Each request log line carries the constitutional hash currently being
  served by the static bundle. When the hash changes, the log carries
  both `served_hash` and `request_id` so a deliberation receipt can
  later be cross-referenced (`DESIGN.md §7.4`).
- `/healthz` returns `{ ok, served_hash, build_id }`. The right-rail
  "Constitution drift" stat in `Console.tsx` will eventually pull this.

**Alerting:**

- Console: 5xx rate over 1% in 5 min → page on-call.
- Console: cert expiry < 14 days → page on-call.
- Console: `served_hash` mismatch with bus-reported canonical hash →
  page maintainer (this maps directly to the product's incident class
  in `Incidents.tsx`'s `I-0431` fixture).
- Marketing: 5xx rate over 5% in 5 min → notify; not a page.

---

## §11 Roadmap

| Item | Trigger | Notes |
|---|---|---|
| OFL attribution (`public/static/fonts/OFL.txt` + marketing footer link) | Before any real tenant | Last loose end on the WOFF2 self-host (§6). |
| Strict CSP on console (`'unsafe-inline'` removed) | Before any real tenant URL | §5 of this doc. |
| API reverse proxy on console origin | When `src/core/shared/` lands | §4 Caddyfile already sketches it. |
| Cloudflare in front (single-domain) | If WAF / bot management becomes a buyer requirement | §2 weighed and deferred. |
| Multi-region failover | When availability SLO > 99.9% | Single-region is fine until then; pair primary with a warm passive in another region. |
| SSO / OIDC at the console edge | When auth lands | Terminates at the console origin defined in §4. |
| Subprocessor disclosure page | First regulated buyer | One marketing-side page that lists Vercel (marketing only), Cloud Run / Fly (console), Let's Encrypt (certs), font foundries — and explicitly states no third party touches `/console/*`. |

---

## §12 Decisions log

| Date | Decision | Rationale |
|---|---|---|
| 2026-05-04 | DEPLOY.md created | First project-local deployment design. Pairs with DESIGN.md as the network-layer expression of the privilege boundary. |
| 2026-05-04 | Split topology — marketing on edge CDN, console on operator-controlled container | The product brand is privilege; the deployment must mirror it. A single Vercel deploy would put the CDN provider on every privileged URL, which is not the subprocessor story this product can tell. |
| 2026-05-04 | Container with Caddy/Nginx for the console, not object-storage hosting | Same origin will grow a reverse proxy when the bus client lands; container is the primitive that handles both static + proxy without a second migration. |
| 2026-05-04 | Cloud Run (or Fly.io) over Cloudflare-fronted single-domain | Cloudflare Enterprise + BAA is defensible but more configuration-fragile; reconsider when traffic justifies a WAF (§11). |
| 2026-05-04 | Strict CSP on the console; permissive (report-only) on marketing | The cost of a marketing CSP miss is a broken analytics tag; the cost of a console CSP miss is a script with `Referer` access to privileged URLs. |
| 2026-05-04 | No third-party analytics / RUM / error tracking on the console origin, ever | The console is the audit trail. It cannot also be a Datadog property. Server-side telemetry (via the bus) replaces the in-browser SDKs when needed. |
| 2026-05-04 | `Referrer-Policy: no-referrer` on console; `strict-origin-when-cross-origin` on marketing | Console URLs carry meaning (`/console/policies/P-1207`, `/console/agents/A-07`). Even one outbound link could leak that to the destination. |
| 2026-05-04 | Staging environments render a structural `STAGING · synthetic data only` band in the privilege strip | Same structural rule as the production banner — never animated, never gated on a flag. The point of the banner is to be impossible to miss; staging needs that property too. |
| 2026-05-04 | Marketing's "Open the console" CTA is an absolute URL to `https://console.acgs.ai/console` in production builds | Forces the user across the privilege boundary at the network layer, not just at the React route layer. |
| 2026-05-04 | DMARC `p=reject`, not `quarantine` | Regulated-AI brand. Phishing using `acgs.ai` is a buyer-trust event. |

---

## §13 References

- `DESIGN.md` — visual + UX contract; the source of truth for the
  privilege boundary this document deploys.
- `CLAUDE.md` — agent contract; first-stop for future Claudes.
- Canonical: `/home/martin/Downloads/govern-zone/ACGS/DESIGN.md`.
- Constitutional hash (brand furniture): `608508a9bd224290`.
