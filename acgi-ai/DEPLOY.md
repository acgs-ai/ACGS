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
4. The React console still renders fixture data until the API client lands
   (`DESIGN.md §7.5`), but the console origin owns a same-origin `/api/*`
   reverse proxy now. It must fail closed when no governed bus upstream is
   configured.
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
- **API homing.** The bus client calls `console.acgs.ai/api/*` — same
  origin, no CORS, no Referer cross-pollination, no separate cert. The
  proxy is already there and stays fail-closed until `BUS_UPSTREAM` points
  at the governed bus/gateway.

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
pnpm build:marketing
# output: dist/
```

The marketing build is mode-specific: `vite --mode marketing` aliases the
React entry to `src/surfaces/marketing/App.tsx`. It must not embed the
privileged console route tree.

**Routing config** (`vercel.json` at repo root, applied only to the
marketing project — see §7):

```jsonc
{
  "buildCommand": "pnpm build:marketing",
  "outputDirectory": "dist",
  "cleanUrls": true,
  "routes": [
    {
      "src": "/(?:.*\/)?(?:AGENTS|CLAUDE|DESIGN|DEPLOY)\.md$",
      "status": 404
    },
    {
      "src": "/console",
      "status": 308,
      "headers": { "Location": "https://console.acgs.ai/console" }
    },
    {
      "src": "/console/(.*)",
      "status": 308,
      "headers": { "Location": "https://console.acgs.ai/console/$1" }
    },
    { "src": "/(.*)", "dest": "/" }
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

- The `/console` and `/console/*` Vercel routes are hard 308 redirects to the console origin so
  that an evaluator who clicks "Open the console" from a deep marketing
  link lands on the privileged origin, not on a marketing-side
  rendering. The internal-doc 404 route must stay before those redirects,
  and the SPA fallback must stay last. This means `Marketing.tsx`'s "Open the console" CTA must
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

- Caddy (recommended) or Nginx — terminates TLS via the platform load
  balancer or Let's Encrypt / ACME, serves the static `dist/` bundle,
  applies the headers in §5, and reverse-proxies `/api/*` to the governed
  bus/gateway named by `BUS_UPSTREAM`.
- The compiled `dist/` from `pnpm build:console`, baked at image-build
  time. The console build aliases the React entry to
  `src/surfaces/console/App.tsx`.
- `/static/fonts/*.woff2` — see §6.

**Why a container, not Cloud Run "service" with object storage:**

- A container is the right primitive when the same origin needs to
  grow a reverse proxy. Object-storage hosting forces a second hop
  for `/api/*` (Cloud Run + GCS, or Fly + Tigris) which is operational
  rope for a marginal cost saving.

**Caddyfile contract** (`infra/Caddyfile`):

```caddy
console.acgs.ai {
  encode gzip zstd

  # Static assets — long cache, hash-stable
  @assets path /assets/*
  header @assets Cache-Control "public, max-age=31536000, immutable"

  # Self-hosted fonts — DESIGN.md §7.1
  @fonts path /static/fonts/*.woff2
  header @fonts Cache-Control "public, max-age=31536000, immutable"

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

  root * /srv/dist

  # Preserve handler order so the SPA fallback never rewrites /api/*.
  route {
    handle /healthz {
      header Content-Type "application/json"
      respond `{"ok":true,"served_hash":"608508a9bd224290","build_id":"{$ACGI_BUILD_ID:local}","surface":"console"}` 200
    }

    # API reverse proxy — fail closed unless BUS_UPSTREAM is configured.
    # BUS_UPSTREAM is a full upstream address such as
    # https://bus.internal.example or http://10.0.0.12:8080.
    handle /api/* {
      reverse_proxy {$BUS_UPSTREAM:127.0.0.1:65535} {
        header_up X-ACGS-Schema-Version "{$ACGS_SCHEMA_VERSION:v1}"
        header_down X-ACGS-Schema-Version "{$ACGS_SCHEMA_VERSION:v1}"
      }
    }

    # SPA fallback for the custom 14-line router.
    handle {
      try_files {path} /index.html
      file_server
    }
  }
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
- **Bus proxy:** Cloud Run renders `BUS_UPSTREAM` from the
  `CONSOLE_BUS_UPSTREAM` GitHub secret at deploy time. If the secret is
  absent, the deploy workflow fails before rollout. If a local/staging
  container omits `BUS_UPSTREAM`, Caddy proxies to `127.0.0.1:65535`, a
  closed-port fallback that returns a proxy failure instead of silently
  serving fixture data. `ACGS_SCHEMA_VERSION` defaults to `v1`; Caddy sends
  and echoes `X-ACGS-Schema-Version` so post-deploy smoke checks can prove
  the same-origin contract.
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

**Console CSP (enforced):**

```
default-src 'self';
script-src  'self';
style-src   'self';
font-src    'self';
img-src     'self' data:;
connect-src 'self';
frame-ancestors 'none';
base-uri    'self';
form-action 'self';
upgrade-insecure-requests;
```

**Strict — no `'unsafe-inline'` anywhere.** Reaching this state required
eliminating every JSX `style={{}}` from the source tree, since CSP cannot
hash or nonce inline `style="..."` attributes. The replacements live in
`src/csp-utilities.css` (utility `.u-*` classes + component-scoped
classes). The design contract (CLAUDE.md) now bans inline styles on the
privileged surface.

**Marketing CSP (target, report-only):**

Marketing ships `Content-Security-Policy-Report-Only` from `vercel.json`
with the same-origin baseline below and a report sink at
`https://csp-report.acgs.ai/marketing`:

```
default-src 'self';
script-src  'self';
style-src   'self';
font-src    'self';
img-src     'self' data:;
connect-src 'self';
object-src  'none';
base-uri    'self';
frame-ancestors 'none';
form-action 'self';
report-uri  https://csp-report.acgs.ai/marketing;
```

`pnpm run test:marketing-csp` verifies that the header remains report-only
until the cutover plan lands. If analytics is added later, extend this
report-only allowlist deliberately and keep console CSP separate.

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
- `fonts.sha256` records the SHA-256 digest of every self-hosted WOFF2.
  `pnpm run test:font-manifest` verifies the manifest, the `src/fonts.css`
  references, and package-script wiring; `pnpm build` runs that gate before
  emitting console and marketing artifacts.
- Source: Google Fonts CSS endpoint with a modern UA, then the
  `gstatic.com` WOFF2 binaries downloaded once at dev time. No runtime
  third-party fetch from either surface.
- Both surfaces use the same bundle. Marketing inherits the privilege
  story even though it doesn't strictly need to — one font story is
  easier to reason about than two.
- License compliance: SIL Open Font License attribution lives at
  `public/static/fonts/OFL.txt` and is linked from the marketing footer's
  "Reading room" column.

**No bundle-time secrets.** This is a fully-static frontend. There is
no `VITE_*` env var that ever holds a credential. When the API client
lands (`DESIGN.md §7.5`), auth tokens come from the auth flow at runtime,
never the build.

`BUS_UPSTREAM` is deliberately a container runtime environment variable,
not a Vite value. It configures only Caddy's server-side proxy path and is
never embedded in `dist/`.

---

## §7 CI/CD

**Repo layout for deploy artifacts** (when implemented):

```
.github/workflows/
  marketing.yml      # → Vercel marketing project
  console.yml        # → Cloud Run / Fly.io console project
infra/
  Caddyfile          # console origin config
  cloudrun/service.preview.yaml
  cloudrun/service.staging.yaml
  cloudrun/service.production.yaml
  cloudrun/service.yaml  # render target produced from service.${DEPLOY_ENV}.yaml
  Dockerfile.console
vercel.json          # marketing-only routing
```

The console deploy workflow requires `CONSOLE_AUTH_UPSTREAM` and
`CONSOLE_BUS_UPSTREAM` alongside the Cloud Run/GCP secrets. It calls the
shared fail-closed renderer, `scripts/render-cloudrun-service.mjs`, to turn
`infra/cloudrun/service.${DEPLOY_ENV}.yaml` into
`infra/cloudrun/service.yaml`, rendering the image URI, `ACGI_BUILD_ID`, the
forward-auth upstream, and the governed bus upstream. The renderer refuses
missing/placeholder values, unsupported environments, non-HTTP upstreams, and
leftover `REPLACE_*` markers before `gcloud run services replace` can run.
`DEPLOY_ENV` defaults to `production` in the push deploy job.
Local infra verification uses:

```bash
pnpm run test:all
pnpm run test:ci-gates
pnpm run build:console
pnpm run test:bus-proxy
pnpm run test:cloudrun-templates
pnpm run test:cloudrun-renderer
pnpm run test:production-deploy-contract
pnpm run test:production-launch-handoff
pnpm run test:production-authority-packet
pnpm run test:production-evidence-template
pnpm run test:production-live-verifier
pnpm run test:production-blocker-report
pnpm run test:production-evidence-validator
pnpm run test:production-cutover-plan
pnpm run test:production-evidence-draft
pnpm run test:storybook-runtime-plan
pnpm run test:hosted-storybook-handoff
pnpm run test:hosted-storybook-proof-template
pnpm run test:hosted-storybook-proof-gap-report
pnpm run test:container-pins
pnpm run test:auth-boundary
pnpm run smoke:bus-proxy
```

`pnpm run test:ci-gates` statically checks that both deploy workflows run the
full `pnpm test:all` readiness suite before any credentialed deploy step. It
also keeps console path filters aligned with script/docs changes so readiness
gate edits cannot silently bypass the production-bound workflows.

`pnpm run test:production-deploy-contract` statically verifies production deploy
fail-closed behavior: marketing push runs must error when `VERCEL_TOKEN`,
`VERCEL_ORG_ID`, or `VERCEL_PROJECT_ID` is absent; console push runs remain WIF,
Cloud Run renderer, and postdeploy gated. Local readiness and build output are
not production deployment proof.

`pnpm run test:production-launch-handoff` verifies `PRODUCTION-LAUNCH.md`, the
production launch handoff. That handoff lists the exact Vercel/GCP/console
secrets, local preflight commands, live post-deploy command, external proof
artifacts, and rollback triggers needed before an operator can truthfully claim
production launch.

`pnpm run test:production-authority-packet` verifies
`production-authority.example.json`, the template-only operator authority packet
for deploy-owner, DNS-owner, auth-owner, and claim/legal-owner approvals. The
example stays `pending-external:deploy-owner-approval` and is not production
deployment proof; it prevents a green local readiness run from being confused
with authority to deploy, mutate DNS, enable Storybook Pages, or publish
stronger claims.

`pnpm run test:production-evidence-template` verifies
`production-evidence.example.json`, a machine-readable intake template for the
live proof an operator must attach after credentialed deploys. The template is
not live production proof; it keeps legal, SOC2, WCAG, pentest, browser, and
hosted Storybook fields as `pending-external` placeholders until external
evidence is attached.

`pnpm run test:production-live-verifier` verifies that the live verifier itself
is wired without executing external network checks in `test:all`. After a
credentialed deploy, operators run
`pnpm -F acgi-ai run verify:production-live -- --json --out ../dist-release-evidence/production-live-verification.json`
to save uncontaminated DNS, HTTPS, `/healthz`, security-header, and
`storybook.acgs.ai` manifest evidence even when the command exits non-zero for
remaining blockers. If an operator captured pnpm stdout instead of using
`--out`, the blocker-evidence wrapper canonicalizes the file only when it
contains exactly one `production-live-verification` object and rejects ambiguous
captures. The hosted Storybook proof includes
`storybook-manifest-live`, which fetches `/manifest.json` and requires the
expected buyer-evidence story ids, `publishTarget`, and conservative claim
boundary so a bare 200 response cannot satisfy buyer-evidence proof. That live
command may fail while DNS or hosted deploys are absent; a failing JSON output
is deployment-blocker evidence, not live production proof.
Its `blockedUntil` and `blockers[]` fields identify the exact live checks to
resolve; copy the `blockers[].blockerId` values into `productionLiveBlockers`
in the completed production evidence manifest.

`pnpm run test:production-blocker-report` verifies the local
`production-blocker-report` builder. After saving the live verifier JSON,
operators can run
`pnpm -F acgi-ai run build:production-blocker-report -- --live-output <verify-production-live.json> --out <production-blocker-report.json>`
to package `productionLiveStatus`, `productionLiveBlockers`, `blockedUntil`,
and `copyIntoProductionEvidence` handoff fields. The builder performs local
file I/O only; it does not deploy, fetch live origins, or create live
production proof.

`pnpm run test:production-cutover-plan` verifies the local
`production-cutover-plan` builder. After saving both the live verifier JSON and
blocker report, operators can run
`pnpm -F acgi-ai run build:production-cutover-plan -- --live-output <verify-production-live.json> --blocker-report <production-blocker-report.json> --out <production-cutover-plan.json>`
to package required GitHub secrets, DNS cutover records, remaining
`productionLiveBlockers`, `liveCheckSummary`, `cutoverDelta`, and
`copyIntoProductionEvidence` handoff fields. The builder performs local file I/O
only; it does not deploy, mutate DNS, fetch live origins, or create live
production proof.

`pnpm run test:production-evidence-validator` verifies the local validator for a
completed operator manifest. After filling the real production evidence JSON and
saving the `verify:production-live` JSON output, operators run
`pnpm -F acgi-ai run validate:production-evidence -- --manifest <completed-production-evidence.json> --live-output <verify-production-live.json>`
to create a `production-evidence-validation` artifact. The validator checks
`productionLiveStatus`, `productionLiveBlockers`, `productionEvidenceValidationCommand`,
`productionEvidenceValidationOutputRef`, `validatedProductionEvidence`, claim
boundaries, pending-external blockers, and live-output consistency without
deploying or performing network I/O. For `deployment-blocked` manifests it
allows explicit `pending-external:` refs for missing Cloud Run, Vercel, and
GitHub Actions run URLs so blocked evidence can validate without inventing live
proof. For `live-verified` or `--require-pass` manifests it rejects pending
external assurance until the operator supplies verified legal claim-matrix
reviewer / review timestamp / artifact ref, third-party pentest vendor and
report with `criticalFindingsOpen=0`, manual WCAG/screen-reader report covering
NVDA and VoiceOver, and browser screenshot or visual-diff bundle refs. The
validator is still intake validation only; it does not create legal, pentest,
WCAG, browser, or regulatory proof.

`pnpm run test:production-evidence-draft` verifies the local
`production-evidence-draft` builder. After saving the live verifier JSON,
blocker report, and cutover plan, operators can run
`pnpm -F acgi-ai run build:production-evidence-draft -- --live-output <verify-production-live.json> --blocker-report <production-blocker-report.json> --cutover-plan <production-cutover-plan.json> --out <production-evidence.deployment-blocked.json>`
to generate a validator-ready `deployment-blocked` production evidence draft
that copies `productionLiveStatus`, `productionLiveBlockers`,
`productionEvidenceValidationCommand`, `productionBlockerReport`, and
`productionCutoverPlan` while preserving `pending-external:` refs for missing
external proof. The builder performs local file I/O only; it does not deploy,
fetch live origins, mutate DNS, or create live production proof.

`make release-evidence` now includes a `productionEvidenceChain` snapshot in
`dist-release-evidence/manifest.json`. It compares the saved live verifier,
`production-blocker-report`, `production-cutover-plan`,
`production-evidence.deployment-blocked.json`,
`production-evidence-validation.deployment-blocked.json`, and
`hostedStorybookHandoff` blocker sets so stale `productionLiveBlockers` copying
is visible before operators attach external proof. This chain check is local
file comparison only; it is not live production proof.

`make production-launch-preflight` refreshes the release evidence bundle and
runs `scripts/production_launch_preflight.py` against
`dist-release-evidence/manifest.json`. The preflight emits a conservative
`production-launch-preflight` ready/blocked decision with `requiredActions`,
repository freshness, live verifier state, production evidence chain state,
validation state, `externalBlockerIds`, full `externalBlockers`, and
`proofIntakeArtifacts` that point each external blocker at the local proof
template or command to replace with signed/live evidence. Current local output
is expected to stay `blocked` until the release-evidence manifest was generated
from the current clean commit and external deploy authority, DNS/auth proof,
hosted Storybook proof, and assurance evidence are attached. The preflight does
not deploy, mutate DNS, approve release authority, or create live production
proof.

`make production-blocker-evidence` runs
`scripts/build_production_blocker_evidence.py`, the one-command operator wrapper
for refreshing a deployment-blocked production evidence packet. It builds the
buyer-evidence gallery with `storybook.acgs.ai` publication metadata, runs or
copies `verify:production-live` JSON, runs acgi-ai `pnpm` evidence commands
through the exact Node 24 gate in `scripts/run_acgi_node24_gate.sh`,
canonicalizes unambiguous wrapper-captured verifier transcripts, builds the
blocker report, cutover plan, hosted Storybook handoff, `dist-release-evidence/hosted-storybook-proof-gap-report.json`
Build proof gap report, deployment-blocked production-evidence draft and validator
output when live blockers remain, optionally writes
`dist-release-evidence/hosted-storybook-proof-validation.json` when
`--hosted-storybook-proof <hosted-storybook-proof.json>` is supplied, refreshes
`make release-evidence`,
and writes `dist-release-evidence/production-launch-preflight.json`. After
external Pages/DNS evidence is attached, operators validate the completed hosted
proof with `pnpm -F acgi-ai run validate:hosted-storybook-proof -- --proof <hosted-storybook-proof.json> --live-output <verify-production-live.json> --out ../dist-release-evidence/hosted-storybook-proof-validation.json --require-pass`. Its safe
local proof command is
`uv run python scripts/build_production_blocker_evidence.py --dry-run --json`;
the real operator command may perform live network checks but does not deploy,
mutate DNS, approve release authority, install dependencies, create hosted
Storybook proof, or create live production proof.

`pnpm run test:storybook-runtime-plan` verifies
`storybook-runtime.plan.json`, the pending official Storybook runtime dependency
plan. It keeps `@storybook/react-vite`, current official Storybook install/build
references, lockfile updates, all eight buyer-evidence story ids, and shim
replacement behind `pending-external:dependency-owner-approval`;
the plan is not official Storybook runtime proof, not hosted Storybook proof, and
not production deployment proof.

`pnpm run test:hosted-storybook-handoff` verifies the local
`hosted-storybook-handoff` builder. After saving a Pages-ready buyer-evidence
manifest and the live verifier JSON, operators can run
`pnpm -F acgi-ai run build:hosted-storybook-handoff -- --buyer-evidence-manifest <dist-buyer-evidence/manifest.json> --live-output <verify-production-live.json> --out <hosted-storybook-handoff.json>`
to package `storybook.acgs.ai`, `storybook-manifest-live`, remaining live
Storybook blockers, and `copyIntoProductionEvidence.hostedStorybook` fields.
Blocked output keeps `pending-external:storybook-pages-proof` and
`hosted-storybook-buyer-evidence` instead of claiming hosted proof. The builder
performs local file I/O only; it does not deploy, mutate DNS, fetch live
origins, install the official Storybook runtime, or create live production
proof.

`pnpm run test:hosted-storybook-proof-template` verifies
`hosted-storybook-proof.example.json`, the template-only intake packet for the
external Storybook Pages, DNS, manifest, and passing `verify:production-live`
evidence needed to remove `hosted-storybook-buyer-evidence`. It records the
required `storybook-manifest-live` checks, `pending-external:storybook-pages-proof`
placeholder, `pending-external:hosted-browser-qa-proof`, hosted browser
screenshot, automated accessibility, and visual-diff refs for all eight
buyer-evidence stories,
`build:hosted-storybook-handoff --require-live-clear`, and
`copyIntoProductionEvidence.hostedStorybook` fields. The template is not hosted
Storybook proof, not official Storybook runtime proof, not production
deployment proof, and not WCAG conformance proof.

`pnpm run test:hosted-storybook-proof-gap-report` verifies
`build:hosted-storybook-proof-gap-report`, the local Build proof gap report
command that reads `hosted-storybook-proof.example.json`, saved
`verify:production-live` JSON, and `hosted-storybook-handoff.json`, then writes
`hosted-storybook-proof-gap-report.json`. The report makes unresolved Pages run,
DNS, `storybook-manifest-live`, hosted manifest, hosted browser/a11y/visual-diff,
`copyIntoProductionEvidence.hostedStorybook`, and template-ref gaps visible; it
does not deploy, mutate DNS, fetch live origins, install Storybook, create hosted
Storybook proof, or create live production proof.

The console image build is pinned to `node:24-alpine` and the runtime image
is pinned to `caddy:2.10.2-alpine`; `pnpm run test:container-pins` keeps
those tags aligned with the Docker-backed bus-proxy smoke test and package
toolchain contract. From the monorepo root, `make verify-js-node24` activates
the repo's `fnm` Node 24 from `acgi-ai/.node-version`, verifies pnpm 9.15.4,
and runs `pnpm -F acgi-ai run test:all`; use that command for local
deploy-readiness evidence when the shell-default `node` is not Node 24.

**Auth boundary while OIDC is pending.** The product target is still OIDC or a
server-issued HttpOnly `SameSite=Strict` Secure cookie at the console origin.
Until that external provider/session layer is provisioned, the client-side
demo session helper is non-production-only: `hasSession()` returns `false` in
production, storage access is gated before `window` storage is touched, and
`test:auth-boundary` scans the built console bundle for demo-auth sentinels.
The production SPA route guard instead awaits the same-origin `/auth/status`
bridge. Caddy serves that JSON only after the same
`forward_auth {$AUTH_UPSTREAM:127.0.0.1:65535}` `/authorize` check used for
`/console` and `/console/*` has accepted the request, so a public marketing
SPA navigation cannot mint a console session in JavaScript. Every Cloud Run
template carries `AUTH_UPSTREAM`, and the shared `render-cloudrun-service.mjs`
path used by `console.yml` refuses to deploy until the
`CONSOLE_AUTH_UPSTREAM`-derived `AUTH_UPSTREAM` value is present. The localhost
fallback is a closed port so a missing authorizer fails closed before the SPA
fallback can serve privileged deep links or a positive `/auth/status` response.
This is a local fail-closed bridge, not a replacement for the Phase 5 OIDC
deployment gate or staged provider proof.

**Cloud Run service templates.** The three committed templates keep scaling
policy reviewable. The shared renderer performs the only deploy-time
substitution, so workflow edits cannot drift into ad-hoc `sed` overrides:

| Environment | Template | minScale | Concurrency | Memory | Cost note |
| --- | --- | ---: | ---: | ---: | --- |
| preview | `infra/cloudrun/service.preview.yaml` | 0 | 80 | 256Mi | No always-on instance; cold starts are allowed for ephemeral preview checks. |
| staging | `infra/cloudrun/service.staging.yaml` | 1 | 80 | 512Mi | Budget roughly `$15-25/mo per always-on instance` before traffic, region, and committed-use differences. |
| production | `infra/cloudrun/service.production.yaml` | 2 | 60 | 1Gi | Budget roughly `$30-50/mo` for two always-on instances using the same `$15-25/mo per always-on instance` estimate. |

Cold-start SLO coverage is still an external-deploy gate: run a synthetic
external pinger every 30s against the deployed console revision and a
Playwright assertion that p99 first-request latency under cold-start scenario
stays below 800ms. Local template checks only prove the intended Cloud Run
shape is present before deploy.

**One PR, two deploy targets.** Both workflows trigger on PR + main. Both run
the full `pnpm test:all` readiness suite before any credentialed deploy step;
marketing then runs `pnpm build:marketing`, while console runs
`pnpm build:console` before packaging/deploying the console image. Current PR
runs are readiness/lint/build only; preview deploys are disabled until
secrets, projects, and domains are configured. Pushes to `master` deploy
production, and missing production credentials fail closed rather than
green-skipping deploy.

**Preview environments are fixture-data only.** No PR preview ever sees
real tenant data; that is enforced by §10 (production access logs +
synthetic-tenant-only banner on staging).

**Branch protection on `main`:**

1. Required check: `pnpm test:all`
2. Required check: `pnpm run test:ci-gates` for workflow/deploy-contract edits
3. Required check: `pnpm run test:production-deploy-contract` for workflow/deploy-contract edits
4. Required check: `pnpm run test:production-launch-handoff` for workflow/deploy-contract edits
5. Required check: `pnpm build:marketing` / `pnpm build:console`
6. Required check: `pnpm test:claim-matrix` while any public compliance/security copy changes
7. Required check: `pnpm test:trust-surface` while trust, security, DPA, SOC2, subprocessor, or security-contact copy changes
8. Required check: `marketing-deploy` (production deploy must succeed on `master`)
9. Required check: `console-deploy` (production deploy must succeed on `master`)
10. Required review: 1 maintainer approval

`main` deploys to production on merge. There is no manual promotion
step; manual promotion encourages drift. If a hotfix needs to skip
preview, that is a procedural exception with an incident record.

**Claim honesty gate.** Engineering claim review lives in `claim-matrix.json` and
`pnpm test:claim-matrix`. The matrix is an engineering draft, not legal
signoff: every public compliance/security claim remains `publicDeployAllowed:
false` until legal review approves the evidence and exact wording. The gate
rejects known overclaim phrases such as `production-ready`, `auditor-ready`,
and certification language in public copy before that review exists.

**Trust/security publication gate.** A22 trust-center artifacts are local
publication scaffolding, not legal signoff. `pnpm test:trust-surface` verifies
that `/trust` and `/security` are routable on the marketing surface, that
`/.well-known/security.txt` publishes the security contact, and that
`/subprocessors.xml` publishes an engineering-draft subprocessor change RSS
feed. `/trust` may describe a DPA draft and SOC2 roadmap only as draft/roadmap
material; `/security` must keep OIDC/server-cookie auth, live deploy proof,
third-party pentest, and manual WCAG review as explicit gates before stronger
public claims.

**Accessibility foundation gate.** `pnpm test:a11y` is a local static
Accessibility foundation gate. It checks skip links, stable main-content
targets, visible focus, reduced-motion handling, conservative copy, and the
bounded `A11Y.md` contract. It is not a WCAG conformance statement; manual
NVDA, VoiceOver, axe/browser, touch-target, and visual-baseline evidence remain
external gates before stronger accessibility wording or production launch.

**Console state coverage gate.** `pnpm run test:state-coverage` is a local
static Console state coverage gate for the Phase 1 state foundation. It verifies
that shared console primitives cover loading, empty, error, partial-bus,
stale-while-revalidating, retry-in-flight, conflicted-mutation,
permission-denied, rate-limited, optimistic-pending, and expired-session; it
also locks the `emptyMeans` taxonomy and the non-production environment
indicator. This does not replace browser scenario tests against 401/403/429/5xx
responses, but it prevents the UI from regressing to blank or bespoke state
chrome before deploy workflows run.


**Polling hygiene gate.** `pnpm run test:polling-hygiene` is a local static
Polling hygiene gate for the Phase 1 bus-query foundation. It verifies that
live console queries use jittered 5-10s intervals, slower governance/settings
queries use jittered 30-60s intervals, interval refetching is disabled while
the page is hidden or in background tabs, and all polling consumers depend on
the shared `useBusHealth()` hook with adaptive failure backoff. This does not
replace deployed-browser request-volume evidence or backend load telemetry, but
it prevents fixed synchronized polling from shipping through readiness gates.


**Session sync gate.** `pnpm run test:session-sync` is a local static Session
sync gate for the non-production console demo-session path. It verifies that
demo sign-in/sign-out changes use a gated `localStorage` storage-event channel,
that console routes subscribe and invalidate TanStack Router after session
changes, and that QueryClient retries re-check `hasSession()` before retrying.
This does not replace the production OIDC/server-cookie gate; it only prevents
the temporary demo-session path from drifting into a single-tab-only or stale
retry state while production auth remains external.

**AppError boundary gate.** `pnpm run test:app-errors` is a local static
AppError boundary gate for the privileged console shell. It verifies that page
bodies are wrapped by a path-resetting `react-error-boundary`, that page and
root faults normalize through `toAppError()`, that the console error state
surfaces cause/fix/trace-ID details, and that route files do not throw bare
`Error` or string values. This does not replace browser scenario tests, but it
prevents a rendering fault from silently regressing to a blank privileged shell
before deploy workflows run.

**Login interstitial gate.** `pnpm run test:login-interstitial` is a local
static gate for the `/login` privilege-boundary handoff. It verifies that SSO
provider selection renders a parchment moment for at least 800ms, names the
operator, matter, and constitutional hash, accepts Enter as a dismissal request,
and does not mint a client-side console session. This does not replace OIDC or
server-cookie production auth; it only makes the first privileged transition
visible while the external provider layer remains a Phase 5 gate.

**Privilege banner gate.** `pnpm run test:privilege-banner` is a local static
gate for the console privilege banner and right-rail receipt foundation. It
verifies that the parchment boundary is a structural semantic region, that
mobile drawer/backdrop z-index tokens stay below it, that the right rail is a
polite live receipt region, and that console route pages do not introduce
toast/modal/FAB or fixed/sticky receipt overlays. This does not replace
Playwright intersection checks or manual responsive/browser evidence, but it
prevents route-local UI chrome from occluding the privilege boundary before
deploy workflows run.

**Wire decisions gate.** `pnpm run test:wire-decisions` is a local static gate
for the Phase 1 A7 console wire contract. It verifies that every in-scope
console route has a typed `CONSOLE_WIRE_DECISIONS` entry, that the shell uses
the registry for crumbs/titles and the right-rail route contract card, and that
`DESIGN.md` documents route-by-route header anatomy, actions, density, filters,
pagination, right-rail purpose, receipt lifetime, and destructive confirmation.
This does not replace browser layout or production cursor-scale evidence, but it
keeps route-level UI decisions explicit before deploy workflows run.


**Test surface foundation gate.** `pnpm run test:test-surface` is a local
static gate for the Phase 2/A15 script surface. It verifies `pnpm run test:e2e`
and `pnpm run test:visual` package wiring, records the E2E route/viewport
manifest and visual baseline target manifest, and keeps those commands inside
`pnpm test:all`. This is not Playwright execution, not axe execution, and not a
visual-diff artifact; browser screenshots, CSP event capture, accessibility
scans, and visual diff proof remain external Phase 2 evidence before stronger
launch claims.

**Local browser workbench evidence.** `pnpm run evidence:browser-workbench`
launches the marketing and console Vite surfaces separately, uses
Chrome/Chromium headless, checks expected DOM text, scrolls hash targets into
view before capture, rejects likely blank screenshots, and captures the
marketing workbench, `/console/workbench`,
`/console/workbench#operator-decision-rail`,
`/console/workbench#guided-review-path`,
`/console/workbench#framework-integration-rail`,
`/console/workbench#agent-framework-starter-kits`,
`/console/workbench#launch-proof-ladder`,
`/console/workbench#release-blocker-queue`,
`/console/workbench#live-verifier-blocker-map`,
`/console/workbench#production-command-rail`,
`/console/workbench#hosted-storybook-runway`, and
`/console/workbench#assurance-proof-intake` at the five visual baseline viewports.
It writes a `local-browser-workbench-evidence` manifest and screenshots under
`dist-browser-evidence/`; `pnpm run test:browser-evidence` verifies the command
contract, dry-run manifest shape, target-visible screenshot guards, docs, and
readiness wiring. This local browser evidence is not production deployment
proof, not hosted Storybook proof, not WCAG conformance proof, and not
legal/security assurance.

**Buyer evidence gallery gate.** `pnpm run evidence:build` produces the
dependency-free local buyer-evidence gallery under `dist-buyer-evidence/`.
`pnpm run test:buyer-evidence` rebuilds it in a scratch directory and verifies
the proof-story manifest, visual governance workbench story, hosted Storybook
runway proof points, conservative claim boundary, package-script wiring, and
documentation links. `pnpm run
storybook:build` currently aliases this
local gallery build so the planned Storybook proof command has a local
artifact. `pnpm run test:storybook-runtime-plan` verifies the
`storybook-runtime.plan.json` dependency plan and keeps official Storybook
runtime work behind `pending-external:dependency-owner-approval` until an owner
approves adding dependencies and replacing the shim. `pnpm run test:storybook-publication` verifies the gated
`.github/workflows/storybook.yml` publication scaffold: it builds the same
claim-safe gallery with `ACGI_EVIDENCE_CNAME=storybook.acgs.ai`, writes the
Pages `CNAME`, writes `.nojekyll`, includes a `/manifest.json` for the live
`storybook-manifest-live` check, records hosted-proof requirements in that
manifest, uploads the `buyer-evidence-storybook` artifact, and only enables GitHub Pages deployment when
`STORYBOOK_PAGES_ENABLED` is explicitly set. Before upload or deploy, the
Storybook workflow also runs `test:hosted-storybook-handoff`,
`test:hosted-storybook-proof-template`, and
`test:hosted-storybook-proof-gap-report` so the Pages path cannot drift from the
operator proof handoff or proof-intake contract. The console workflow also runs
`pnpm evidence:build` and uploads the
`buyer-evidence-gallery` artifact before any credentialed GCP/auth/deploy
step, giving reviewers a CI-retained proof bundle.
`pnpm run test:hosted-storybook-handoff` verifies the follow-up
`hosted-storybook-handoff` artifact shape, and
`build:hosted-storybook-handoff` writes `hosted-storybook-handoff.json` from the
local publication manifest plus saved `verify:production-live` JSON so operators
can copy `pending-external` or verified Storybook fields into production
evidence without overclaiming. `pnpm run test:hosted-storybook-proof-template`
guards `hosted-storybook-proof.example.json`, the external proof intake template
for the Pages run URL, DNS evidence, hosted `/manifest.json` evidence, absent
`live-storybook-*` blockers, hosted browser screenshot, automated
accessibility, and visual-diff refs for all eight buyer-evidence stories, plus
the `hosted-storybook-buyer-evidence`
blocker removal handoff. `build:hosted-storybook-proof-gap-report` then writes
`hosted-storybook-proof-gap-report.json` as the local gap checklist before proof
owners are asked to complete the packet. This is still not the official Storybook runtime; `storybook-runtime.plan.json`
is only a pending dependency plan and not official Storybook runtime proof,
not live `storybook.acgs.ai` proof, not live production proof, and not
WCAG conformance proof.

**Release evidence bundle.** `make release-evidence` at the repository root
writes `dist-release-evidence/manifest.json`, `platform-readiness.json`, and a
human README. The bundle packages the current platform-readiness snapshot,
buyer-evidence gallery metadata, required verification commands, git identity,
toolchain expectations, the `production-evidence.example.json` intake template,
the `verify:production-live` proof command slot, the
`build:production-blocker-report` handoff report slot, the
`build:production-cutover-plan` DNS/deploy cutover handoff slot, the
`build:production-evidence-draft` deployment-blocked manifest draft slot, the
`build:hosted-storybook-handoff` Storybook Pages handoff slot, the
`hosted-storybook-proof.example.json` external proof intake slot, the
`validate:production-evidence` validator command slot, and explicit external
blockers. This is a deploy handoff artifact only: it is not live production
proof, not legal signoff, not pentest evidence, and not a compliance
attestation.

**TTHW foundation gate.** `pnpm run test:tthw` is a local static gate for
`hello-world.sh`, package-script wiring, and `.github/workflows/tthw.yml`. The
scheduled workflow runs the clean-runner HTTP shell measurement on Node 24 with
a 300-second budget, while `pnpm run hello:world:local` is a bounded local smoke
that skips install and allows local Node drift. This is not a production deployment proof, not a headless browser proof, and not evidence that live
Vercel or Cloud Run domains are serving the latest build.

**Bus schema contract gate.** `contracts/bus.openapi.json` is the local
source of truth for the bus analyzer schema; `src/api/openapi.json` is a
compatibility mirror. `pnpm run test:bus-schema` regenerates
`src/api/bus.generated.ts`, checks drift, and verifies strict positive and
negative fixtures for unknown fields, missing required fields,
`X-ACGS-Schema-Version` skew, and machine-readable error envelopes. This is a
local schema/readiness gate, not proof that the live bus is deployed.

**Performance budget gate.** `pnpm run test:performance` builds marketing and
console artifacts into a temporary `.performance-check/` directory and enforces
the Phase 5 gzipped JS+CSS budgets from `PLAN.md`: marketing <= 200 KB and
console <= 350 KB. This gate does not replace Lighthouse or live latency
evidence, but it prevents local bundle growth from silently violating the deploy
contract.

**Post-deploy evidence.** The console deploy job must run the same local
evidence script operators can run by hand:

```bash
EXPECTED_BUILD_ID="$GITHUB_SHA" pnpm run verify:postdeploy -- https://console.acgs.ai
```

The script checks the live security headers, `/healthz` `{ ok, served_hash,
build_id }`, the entry document's live `/assets/*` references, and the built
`dist/assets` bundle. Both live and local assets are scanned for inline
`style=` attributes or unexpected third-party URL literals; live JS assets are
also scanned for demo-auth sentinels such as `sessionStorage` and the demo
session key. A green Cloud Run deploy without this evidence is a build/deploy
success, not production verification.

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
| `console.acgs.ai` | CNAME | Cloud Run / Fly hostname | locked in `production-cutover-plan` |
| `storybook.acgs.ai` | CNAME | GitHub Pages custom-domain target | required for buyer-evidence manifest proof |
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
  bus uses (`DESIGN.md §7.5`). Until that sink is live, ship to a same-region log bucket
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
| API client hook-up to bus | When `src/core/shared/` lands | §4 Caddyfile already proxies `/api/*`; remaining work is authenticated client/runtime integration. |
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
| 2026-05-04 | Internal docs are stripped from build output and denied at the deployment layer for `*AGENTS.md`, `*CLAUDE.md`, `*DESIGN.md`, `*DEPLOY.md` | Vite copies `public/` verbatim into `dist/`. Per-directory `AGENTS.md` files placed for in-repo agent navigation must never be web-reachable on either origin (privilege leak on console; brand-control on marketing). The Vite plugin removes them from `dist/`; Caddy and Vercel rules provide defense in depth if one slips through. |
| 2026-05-24 | Console `/api/*` is a fail-closed Caddy reverse proxy backed by `BUS_UPSTREAM` | The deploy boundary should be ready for a governed bus without ever serving fixture data as if it were live backend output. The workflow requires `CONSOLE_BUS_UPSTREAM`, and Caddy forwards/echoes `X-ACGS-Schema-Version` for contract evidence. |
| 2026-05-24 | Bus analyzer schema ownership is local and generated | `contracts/bus.openapi.json` is the vendored bus schema source of truth; `pnpm run test:bus-schema` guards codegen drift and fixture/error-envelope coverage before deploy workflows run. |
| 2026-05-24 | Bundle performance budgets are enforced locally | `pnpm run test:performance` enforces marketing <= 200 KB and console <= 350 KB gzipped JS+CSS budgets before CI/deploy gates can pass. |
| 2026-05-24 | Console state coverage has a local static gate | `pnpm run test:state-coverage` guards the Phase 1 11-state primitive set, `emptyMeans` taxonomy, and non-production environment indicator before CI/deploy gates can pass. |
| 2026-05-24 | Console polling hygiene has a local static gate | `pnpm run test:polling-hygiene` guards jittered live/slow intervals, visibility-aware polling, background interval suppression, and bus-health failure backoff before CI/deploy gates can pass. |
| 2026-05-25 | Cross-tab demo-session sync has a local static gate | `pnpm run test:session-sync` guards the temporary demo-session storage-event channel, console router invalidation, and retry-time `hasSession()` re-checks while production OIDC/server-cookie auth remains external. |
| 2026-05-25 | Console AppError boundary has a local static gate | `pnpm run test:app-errors` guards console page error-boundary wiring, typed AppError details, route throw hygiene, and package/security/CI wiring before deploy gates can pass. |
| 2026-05-25 | Login interstitial has a local static gate | `pnpm run test:login-interstitial` guards the Phase 1 parchment handoff, operator/matter/hash copy, Enter dismissal, and no client-side console grant before deploy gates can pass. |
| 2026-05-25 | Privilege banner has a local static gate | `pnpm run test:privilege-banner` guards the structural banner region, z-index token order, polite right-rail live region, and no route-local toast/modal/FAB or fixed/sticky receipt overlays before deploy gates can pass. |
| 2026-05-25 | Wire decisions have a local static gate | `pnpm run test:wire-decisions` guards the A7 typed per-route console wire registry, shell right-rail route contract, DESIGN appendix, and package/security/CI wiring before deploy gates can pass. |
| 2026-05-25 | Marketing production deploy fails closed when Vercel secrets are absent | A green push run must not mean a skipped deploy; `pnpm run test:production-deploy-contract` locks the production deploy fail-closed behavior while keeping local readiness distinct from live production proof. |
| 2026-05-25 | Production launch has a machine-verifiable handoff | `pnpm run test:production-launch-handoff` guards the required secrets, local preflights, live postdeploy command, evidence artifacts, and claim boundary in `PRODUCTION-LAUNCH.md` before an operator attempts the credentialed deploy. |
| 2026-05-25 | Production evidence intake is schema-checked before deploy | `pnpm run test:production-evidence-template` guards `production-evidence.example.json` as a template-only manifest for live deploy proof, with `pending-external` assurance placeholders, verified assurance detail fields, and an explicit not live production proof boundary. |
| 2026-05-25 | Production live verifier is locally gated but not auto-run | `pnpm run test:production-live-verifier` guards the `verify:production-live` DNS/HTTPS/healthz/header/Storybook checker, emits `blockedUntil`/`blockers`, and keeps it out of `test:all` as a live network proof command. |
| 2026-05-25 | Production authority has a local proof packet | `pnpm run test:production-authority-packet` guards `production-authority.example.json`, keeping deploy-owner/DNS/auth/claim approvals as `pending-external:deploy-owner-approval` style refs so local readiness is not confused with authority to deploy or claim production launch. |
| 2026-05-25 | Live verifier blockers have a local handoff report | `pnpm run test:production-blocker-report` guards `build:production-blocker-report`, which turns saved `verify:production-live` JSON into a `production-blocker-report` with `copyIntoProductionEvidence` fields while preserving the not live production proof boundary. |
| 2026-05-25 | Production cutover plan has a local builder | `pnpm run test:production-cutover-plan` guards `build:production-cutover-plan`, which turns saved live verifier and blocker-report JSON into a `production-cutover-plan` with required GitHub secrets, DNS cutover records, `productionLiveBlockers`, `liveCheckSummary`, `cutoverDelta`, and `copyIntoProductionEvidence` while preserving the not live production proof boundary. |
| 2026-05-25 | Completed production evidence has a local validator | `pnpm run test:production-evidence-validator` guards `validate:production-evidence`, the completed-manifest validator for `productionLiveStatus`, `productionLiveBlockers`, `productionEvidenceValidationCommand`, `productionEvidenceValidationOutputRef`, and `validatedProductionEvidence` consistency against the attached live verifier JSON, including explicit `pending-external:` refs for deployment-blocked Cloud Run/Vercel/GitHub run URLs and verified legal, pentest, manual WCAG/screen-reader, and browser assurance details before `--require-pass`. |
| 2026-05-25 | Deployment-blocked production evidence has a local draft builder | `pnpm run test:production-evidence-draft` guards `build:production-evidence-draft`, which turns saved live verifier, `production-blocker-report`, and `production-cutover-plan` JSON into a validator-ready `production-evidence.deployment-blocked.json` draft while preserving the not live production proof boundary. |
| 2026-05-25 | Storybook runtime dependency has a local approval plan | `pnpm run test:storybook-runtime-plan` guards `storybook-runtime.plan.json`, keeping `@storybook/react-vite`, `npx storybook@latest init`, lockfile updates, and shim replacement behind `pending-external:dependency-owner-approval`; the plan is not official Storybook runtime proof, not hosted Storybook proof, and not production deployment proof. |
| 2026-05-25 | Hosted Storybook proof has a local operator handoff | `pnpm run test:hosted-storybook-handoff` guards `build:hosted-storybook-handoff`, which turns a Pages-ready buyer-evidence manifest and saved live verifier JSON into `hosted-storybook-handoff.json` with `pending-external:storybook-pages-proof`, `storybook-manifest-live`, and `copyIntoProductionEvidence.hostedStorybook` fields while preserving the not live production proof boundary. |
| 2026-05-25 | Hosted Storybook proof intake is machine-verifiable before claim | `pnpm run test:hosted-storybook-proof-template` guards `hosted-storybook-proof.example.json`, keeping Storybook Pages run URL, DNS evidence, hosted manifest evidence, `storybook-manifest-live`, absent `live-storybook-*` blockers, and `copyIntoProductionEvidence.hostedStorybook` requirements explicit while preserving the not hosted Storybook proof boundary. |
| 2026-05-25 | Hosted Storybook proof gaps have a local checklist | `pnpm run test:hosted-storybook-proof-gap-report` guards `build:hosted-storybook-proof-gap-report`, which writes `hosted-storybook-proof-gap-report.json` from the proof template, live verifier output, and handoff so unresolved Pages, DNS, live verifier, hosted manifest, hosted browser, copy-field, and pending-ref gaps are visible without claiming hosted Storybook proof. |
| 2026-05-25 | Fixture fallback is network-only outside production | `withFixtureFallback` is disabled in production, rethrows `ApiError`/4xx/5xx and non-network errors, and only uses fixture data for explicit network-unavailable `TypeError` cases in non-production mock mode; `pnpm run test:security` and `pnpm run test:mvp` guard the boundary. |

---

## §13 References

- `DESIGN.md` — visual + UX contract; the source of truth for the
  privilege boundary this document deploys.
- `CLAUDE.md` — agent contract; first-stop for future Claudes.
- Canonical: `/home/martin/Downloads/govern-zone/ACGS/DESIGN.md`.
- Constitutional hash (brand furniture): `608508a9bd224290`.
