Status: Design note
Title: Console forward-auth with Google as the IdP — terminate at the edge, never in the SPA
Drivers: a real sign-in flow for the console origin that reuses the existing fail-closed `forward_auth` model and changes **zero** of the enforced CSP. Google is the identity provider; an `oauth2-proxy` service is the proposed `AUTH_UPSTREAM`. This note separates what the repo already wires (stated as fact) from what is proposed (labeled as such), and is written so the repo's own auth-boundary gate (`pnpm test:auth-boundary`) stays green without editing it.

## Context & decision

The console is the audit-trail surface. `/console/*` URLs carry matter and session IDs, and the enforced Content-Security-Policy is, verbatim from `acgi-ai/infra/Caddyfile`:

```
Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests"
```

`script-src 'self'` and `connect-src 'self'` forbid third-party in-browser scripts and cross-origin fetch/XHR. A client-side SPA auth library (Clerk, Firebase Auth, Auth0's browser SDK, Google's GIS JS) would require loading a third-party script and/or calling a third-party origin from the browser — both blocked by this CSP, and both would put session-bearing traffic and `Referer` leakage on the privileged origin. The console therefore authenticates at the **edge**, server-side, via the existing `forward_auth` model. The decision: keep auth below the SPA, at the same privileged origin, and add an `oauth2-proxy` upstream rather than any in-browser auth.

**This needs zero CSP change.** Google sign-in is a *top-level browser navigation* (a full-page redirect to `accounts.google.com` and back) plus a *server-side* token exchange that the browser never sees. CSP `connect-src`/`script-src` govern in-page `fetch`/XHR/script loads, not top-level document navigations, so they remain valid untouched. The browser's only same-origin interactions are the `/authorize/*` paths and the session cookie. Do **not** add `accounts.google.com` to `connect-src` — it is not needed, and adding it would be the exact pattern this origin refuses.

## The `/authorize` contract today (repo-verified)

The console already gates deep links at the edge. From `acgi-ai/infra/Caddyfile`, the console-routes handler:

```
@console_routes path /console /console/*

handle @console_routes {
  forward_auth {$AUTH_UPSTREAM:127.0.0.1:65535} {
    uri /authorize
    copy_headers X-ACGS-Operator X-ACGS-Tenant X-ACGS-Auth-Context
  }
  try_files {path} /index.html
  file_server
}
```

The same `forward_auth {$AUTH_UPSTREAM:127.0.0.1:65535}` `/authorize` check guards the `/auth/status` bridge.

Verified facts about this wiring:

- **`AUTH_UPSTREAM` is a container env var**, supplied at deploy time from the GitHub secret `CONSOLE_AUTH_UPSTREAM`. `.github/workflows/console.yml` sets `AUTH_UPSTREAM: ${{ secrets.CONSOLE_AUTH_UPSTREAM }}` and passes `--auth-upstream "${AUTH_UPSTREAM}"` into the Cloud Run service render; the templates under `acgi-ai/infra/cloudrun/*.yaml` carry `AUTH_UPSTREAM` with a `REPLACE_AUTH_UPSTREAM_AT_DEPLOY_TIME` placeholder (see also `acgi-ai/DEPLOY.md` §7 and its "Auth boundary" section).
- **Fail-closed by default.** The Caddy default `127.0.0.1:65535` is a dead localhost port. If `AUTH_UPSTREAM` is unset, `forward_auth` cannot get a 2xx, so `/console/*` and `/auth/status` are denied. Missing auth config fails closed, never open. `render-cloudrun-service.mjs`'s `requireUpstream('AUTH_UPSTREAM')` additionally refuses to render a deploy when the upstream is absent.
- **Route order is gated.** `acgi-ai/scripts/check-auth-boundary.mjs` asserts the handler order `healthz → auth/status → api → internal_docs → console_routes → SPA fallback`, and asserts that both `handle /auth/status` and `handle @console_routes` contain `forward_auth {$AUTH_UPSTREAM:127.0.0.1:65535}`, `uri /authorize`, and `copy_headers … X-ACGS-Operator`. Any proposal must keep those assertions true.
- The upstream "owns OIDC/server-cookie verification and returns 2xx only for authorized sessions" (Caddyfile comment). The repo does **not** ship that upstream — `AUTH_UPSTREAM` is an external service. Per `DEPLOY.md`, production OIDC/server-cookie auth is still pending and external.

## Proposed design — `oauth2-proxy` as the `AUTH_UPSTREAM`, Google as IdP

> Everything in this section is **proposed**, not present in the repo. The only secret name drawn from existing wiring is `CONSOLE_AUTH_UPSTREAM` (→ `AUTH_UPSTREAM`). The `oauth2-proxy` service, its env vars, the `__Host-` cookie, and the `/authorize/*` routes do not exist in this repository today.

Run an [`oauth2-proxy`](https://oauth2-proxy.github.io/oauth2-proxy/) instance at the console origin (same Cloud Run service as a sidecar, or a co-located service reachable only from Caddy). Point `CONSOLE_AUTH_UPSTREAM` (→ `AUTH_UPSTREAM`) at it. `oauth2-proxy` performs the Google OIDC dance server-side and answers Caddy's `forward_auth` sub-request with 2xx (authorized) / 401 (not).

### Conform to the `/authorize` + `X-ACGS-*` contract (do not break the gate)

This design takes the **conform-to-the-existing-contract** path, not the rewrite-the-gate path. It does **not** silently drop `/authorize` or the `X-ACGS-*` headers, and it does **not** require editing `check-auth-boundary.mjs`. Two concrete mechanisms:

1. **Serve oauth2-proxy under the `/authorize` prefix.** Set `OAUTH2_PROXY_PROXY_PREFIX=/authorize`. oauth2-proxy then serves its auth-check endpoint at `/authorize/auth` and the full sign-in / callback / sign-out dance natively under `/authorize/*` — same origin, no rewrite shim.
   - The Caddy `forward_auth` `uri` changes from `uri /authorize` to **`uri /authorize/auth`** in *both* the `@console_routes` and `/auth/status` blocks. This is a deliberate one-token change per block: bare `/authorize` is oauth2-proxy's prefix root, not an auth endpoint, so probing `/authorize` would 302-to-signin and `forward_auth` would never see a 2xx — denying *every* session, including valid ones. The auth-check endpoint is always `<prefix>/auth`.
   - The auth-boundary gate's `uri /authorize` assertion is a substring check (`/uri \/authorize[\s\S]*/`), so `uri /authorize/auth` still satisfies it. Verify this against the gate before relying on it.
2. **Emit the `X-ACGS-*` headers as response headers on the auth-check.** Caddy's `copy_headers` copies from the `forward_auth` *response*. oauth2-proxy must therefore emit `X-ACGS-Operator` / `X-ACGS-Tenant` / `X-ACGS-Auth-Context` as **response** headers on `/authorize/auth`, mapped from the Google identity claims. This is oauth2-proxy's alpha-config response-header injection (the `injectResponseHeaders` surface), **not** `--set-xauthrequest` (which only emits `X-Auth-Request-*` and would leave `copy_headers` copying nothing → operator identity silently dropped). Names and exact alpha-config schema are per oauth2-proxy's docs, not repo-verified — confirm against the pinned release before deploy.

Because the `copy_headers` line stays `copy_headers X-ACGS-Operator X-ACGS-Tenant X-ACGS-Auth-Context` verbatim, **no IdP access/refresh token is forwarded downstream** (see "Token surface" below), and the gate's `copy_headers … X-ACGS-Operator` assertion stays true with zero edits.

### `oauth2-proxy` config (env-based)

Names below are per oauth2-proxy's documented configuration, not repo-verified. Treat the whole block as the documented oauth2-proxy surface to confirm against its version docs before deploy.

```sh
# Google as the IdP
OAUTH2_PROXY_PROVIDER=google
OAUTH2_PROXY_CLIENT_ID=<google-oauth-client-id>          # from the operator's client_secret_*.json
OAUTH2_PROXY_CLIENT_SECRET=<google-oauth-client-secret>  # SERVER-SIDE ONLY — see "Where the secret lives"
OAUTH2_PROXY_REDIRECT_URL=https://console.acgs.ai/authorize/callback

# Restrict who may sign in (choose one or both, per oauth2-proxy docs):
OAUTH2_PROXY_EMAIL_DOMAINS=<allowed-domain>              # or an explicit allowlist file
# OAUTH2_PROXY_GOOGLE_GROUPS=...                         # if group-scoping is required

# Same-origin behaviour: oauth2-proxy serves its endpoints under /authorize/*
# so the Caddy forward_auth probe path (/authorize/auth) and the OAuth dance
# (/authorize/sign_in, /authorize/callback, /authorize/sign_out) share the
# existing /authorize contract — no rewrite shim, gate stays green.
OAUTH2_PROXY_PROXY_PREFIX=/authorize
OAUTH2_PROXY_REVERSE_PROXY=true                          # behind Caddy

# Emit the X-ACGS-* identity headers on the auth RESPONSE (alpha-config
# injectResponseHeaders), mapped from Google claims, so Caddy's copy_headers
# forwards real identity. Do NOT rely on --set-xauthrequest alone: it emits
# X-Auth-Request-* only, which the existing copy_headers line would ignore.

# Session cookie — see "Cookie & session security"
OAUTH2_PROXY_COOKIE_NAME=__Host-acgs_console_session
OAUTH2_PROXY_COOKIE_SECRET=<32-byte-random>              # SERVER-SIDE ONLY
OAUTH2_PROXY_COOKIE_SECURE=true
OAUTH2_PROXY_COOKIE_HTTPONLY=true
OAUTH2_PROXY_COOKIE_SAMESITE=<see "Cookie & session security">
OAUTH2_PROXY_COOKIE_PATH=/
```

Verify each flag name and default against the oauth2-proxy release you pin; this block is illustrative of the documented surface, not a tested config.

### Caddy `forward_auth` block (proposed change)

The only change to each existing handler is the `uri` line (`/authorize` → `/authorize/auth`). The `forward_auth` upstream, the dead-port fallback, and the `copy_headers X-ACGS-Operator X-ACGS-Tenant X-ACGS-Auth-Context` line are unchanged, so the route-order and header-contract assertions in `check-auth-boundary.mjs` stay green.

```
handle @console_routes {
  forward_auth {$AUTH_UPSTREAM:127.0.0.1:65535} {
    uri /authorize/auth                       # was: uri /authorize — oauth2-proxy serves the check at <prefix>/auth
    copy_headers X-ACGS-Operator X-ACGS-Tenant X-ACGS-Auth-Context
  }
  try_files {path} /index.html
  file_server
}
```

The `/auth/status` block changes identically (`uri /authorize` → `uri /authorize/auth`); everything else in that block — `header Cache-Control "no-store"`, the `forward-auth-status-bridge` response, the "client demo storage is not accepted" claim boundary — stays verbatim.

A new browser-facing handler serves the OAuth dance under the same prefix. It is inserted with the **same dead-port fallback** and placed so the gated route order (`healthz → auth/status → api → internal_docs → console_routes → SPA fallback`) is preserved — the route-order assertion pins the relative order of those six named handlers via `[\s\S]*` gaps, so an additional `handle /authorize/*` between them does not break it:

```
# oauth2-proxy's own endpoints (sign-in, callback, sign-out) — same origin,
# same /authorize prefix, same fail-closed dead-port fallback.
handle /authorize/* {
  reverse_proxy {$AUTH_UPSTREAM:127.0.0.1:65535}
}
```

Place this handler so it does not disturb the asserted order of `healthz`, `auth/status`, `api/*`, `@internal_docs`, `@console_routes`, and the final SPA `handle {}`. All of this is server-side, on the one privileged origin.

## Token surface — no IdP token leaves oauth2-proxy

The console gate needs **identity** (who is signed in), not the IdP **bearer token**. This design therefore copies only `X-ACGS-Operator` / `X-ACGS-Tenant` / `X-ACGS-Auth-Context` downstream and **never** copies a raw Google access/refresh token via `copy_headers`:

- Do **not** add `X-Auth-Request-Access-Token` (or any IdP token header) to `copy_headers`. Forwarding it would push a live bearer credential toward the bus and into the Caddy JSON access log (`infra/Caddyfile` log block), which `DEPLOY.md` §10 forwards into the same audit sink the bus uses — a credential-in-logs / blast-radius regression on the audit-trail origin.
- The access/refresh tokens stay inside oauth2-proxy's encrypted server-side session. The browser holds only the opaque `__Host-` cookie.
- If a downstream caller genuinely needs a token, **mint a scoped server-side token at the bus boundary** rather than forwarding Google's access token through Caddy.
- **Verify access-log redaction regardless.** Caddy logs request headers it is told to; confirm the access-log config does not capture forwarded auth headers (or any `X-ACGS-*` / token header), so identity attribution lands in the audit sink without leaking credentials or copying more than intended.

## Where the Google client_secret lives

Server-side **only**. The client secret is injected as `OAUTH2_PROXY_CLIENT_SECRET` through the same secret mechanism the console deploy already uses for `CONSOLE_AUTH_UPSTREAM` / `CONSOLE_BUS_UPSTREAM` — a GitHub Actions secret rendered into the container, and/or a Cloud Run secret. It is:

- **never committed** to the repo;
- **never sent to the browser** — the browser only ever receives the `__Host-` session cookie, never the client secret, the client_id-as-credential, or any access/refresh token in a URL or in JS.

The operator's local `client_secret_*.json` (the file Google's console hands out) is a **source to copy the `client_id` and `client_secret` *from*** into the secret store. That JSON does **not** belong in the repo and should not be committed.

## Cookie & session security

The product target in `acgi-ai/DEPLOY.md` (line 646) is "OIDC or a server-issued HttpOnly `SameSite=Strict` Secure cookie at the console origin." A stock oauth2-proxy session cookie defaults to `SameSite=Lax`, because the Google callback is a top-level cross-site navigation and `SameSite=Strict` can drop the cookie on that first return and break the callback. That is a **documented-contract divergence that must be reconciled, not asserted away.** Two acceptable resolutions — pick one before shipping:

- **Split-cookie model (preferred; needs no DEPLOY.md change).** Keep a `SameSite=Strict` long-lived session cookie at the console origin, and use a separate short-lived state cookie scoped only to the callback path (`Path=/authorize/callback`, `SameSite=Lax` or `None`) to survive the redirect-back. This honours the Strict target at line 646 for the session cookie while letting the OAuth handshake complete. Confirm oauth2-proxy's CSRF/state-cookie configuration supports a distinct attribute set for the state cookie on the pinned release.
- **Accept Lax as a required companion change.** If the single-cookie Lax model is chosen instead, `DEPLOY.md` line 646 **must be updated** in the same PR to state that `SameSite=Lax` is the accepted setting for the oauth2-proxy session cookie, with the redirect-back rationale. Do **not** ship a Lax cookie while the security doc still names Strict as the target. (This doc cannot edit `DEPLOY.md`; the edit is called out here as a required companion change.)

Independent of which model is chosen, these hold:

- **`__Host-` cookie-name prefix** — forces `Secure`, `Path=/`, and no `Domain` attribute, so the session cookie is bound to the exact console origin and cannot be scoped up to a parent domain or set over plain HTTP. (Note: `__Host-` requires `Path=/`; a path-scoped state cookie in the split model uses a distinct, non-`__Host-` name.)
- **`Secure`** + **`HttpOnly`** — TLS-only, unreadable by JS (consistent with `script-src 'self'`; no script needs it).
- **Single-origin scope** — the session cookie is never valid for the marketing origin. HSTS is `includeSubDomains; preload` (`DEPLOY.md` line 226/296), so a sibling subdomain is in-scope for TLS — another reason the cookie must stay pinned to the exact console host and the redirect must stay pinned to the exact origin (see "Fail-closed behavior").
- **`cookie-secret` is required** — `OAUTH2_PROXY_COOKIE_SECRET` must be a 32-byte random value, server-side only, treated like any other secret above. It encrypts/signs the session cookie; a missing or weak value is a session-forgery vector.

## Fail-closed behavior

- **oauth2-proxy down ⇒ `forward_auth` denies.** Caddy's auth sub-request gets no 2xx, so `/console/*` and `/auth/status` are denied — the same posture as the dead-port fallback, consistent with ACGS fail-closed.
- **No silent open.** An unset `AUTH_UPSTREAM` still resolves to `127.0.0.1:65535` (dead) on all three handlers (`@console_routes`, `/auth/status`, and the new `/authorize/*`), so misconfiguration denies rather than serves the SPA or the OAuth endpoints.
- **Open-redirect prevention — pin to the single exact origin.** Do **not** use oauth2-proxy's `whitelist-domain` at all: it has a documented history of wildcard/subdomain/leading-dot bypass (`.acgs.ai`, `evil.example#console.acgs.ai`-style parsing quirks), and with `includeSubDomains` HSTS a loosely-whitelisted sibling subdomain is in-scope for abuse. Rely on the exact `OAUTH2_PROXY_REDIRECT_URL=https://console.acgs.ai/authorize/callback` and reject any post-login `rd` target whose scheme+host+port is not exactly `https://console.acgs.ai`. An open redirect here could bounce an authenticated operator — and their matter/session-ID-bearing URL — off-origin.
- **No token in URL or JS** — the access/refresh tokens stay in the encrypted server-side session; the browser holds only the opaque `__Host-` cookie.

## Deploy secrets to set (operator runs these — human-gated)

These commands are run by the **operator**, not by an agent. `gh secret` and `gcloud` are human-gated in this repo; do not paste real secret values into any agent or chat. Placeholders only below.

```sh
# GitHub Actions secret feeding AUTH_UPSTREAM (already wired in console.yml).
# Point it at the oauth2-proxy address once it's deployed.
gh secret set CONSOLE_AUTH_UPSTREAM   # value: oauth2-proxy upstream addr — paste at the prompt, not on the CLI

# oauth2-proxy's own secrets. Prefer Cloud Run secrets (Secret Manager) for these
# rather than plaintext env on the service. Example with gcloud:
gcloud secrets create oauth2-proxy-client-secret --replication-policy=automatic   # then add a version
gcloud secrets create oauth2-proxy-cookie-secret --replication-policy=automatic   # then add a version
# ...and mount them into the service as OAUTH2_PROXY_CLIENT_SECRET / OAUTH2_PROXY_COOKIE_SECRET.
```

The exact secret names and whether they ride as GitHub secrets vs. Cloud Run secrets is the operator's call; the constraint is only that `OAUTH2_PROXY_CLIENT_SECRET` and `OAUTH2_PROXY_COOKIE_SECRET` are server-side and never committed. Confirm the render path (`render-cloudrun-service.mjs` / `console.yml`) actually injects any new env var before relying on it — adding a var to the Caddyfile or oauth2-proxy without wiring it through the deploy renderer leaves it unset (and therefore fail-closed).

## What this does NOT do / claim boundary

This authenticates *access to the console origin*. It is:

- **not** authorization or policy enforcement — whether a *proposed action* is permitted is the ACGS gate's job, recorded in receipts and audit events. Signing in does not authorize any side effect.
- **not** a compliance certification claim.
- **not** proof of production deployment. The `oauth2-proxy` service, Google client registration, the response-header claim→`X-ACGS-*` mapping, the cookie model, DNS/ACME, and the secrets above must all be provisioned and verified live before any "console auth is deployed" claim. Use deploy and health-check evidence, not this note.
- **not** a replacement for the governed bus (`BUS_UPSTREAM` / `CONSOLE_BUS_UPSTREAM`) — that path is separate and stays fail-closed independently.

Identity at the edge ≠ authorized action. Keep that line in any downstream copy.

## Verification hooks

- **Fail-closed, locally, no auth configured:** build the console image and start Caddy with `AUTH_UPSTREAM` unset; request `/console`, `/auth/status`, and `/authorize/sign_in`. All must return non-2xx (the dead-port fallback), never the SPA or an OAuth endpoint. This exercises the same `forward_auth` path the deploy uses.
- **Fail-closed, upstream down:** point `AUTH_UPSTREAM` at an address with nothing listening; confirm `/console/*` is denied, not served.
- **CSP/auth gates still green:** run the existing console gates from `acgi-ai/` — at minimum `pnpm lint`, `pnpm test:security`, `pnpm test:auth-boundary` (production bundle excludes client-side demo-session auth), and `pnpm test:all`. The `uri /authorize/auth` change must still satisfy the auth-boundary `uri /authorize` substring assertion and the unchanged `copy_headers … X-ACGS-Operator` assertion; the added `handle /authorize/*` must not perturb the asserted handler order. Capture literal command output before claiming the gates pass, and confirm no in-browser third-party script or cross-origin `connect-src` was introduced (that would fail the CSP/security invariants).
- **Allow path, identity headers populated:** once oauth2-proxy is wired, confirm an authorized Google session yields a 2xx from `/authorize/auth` **and** that the console receives `X-ACGS-Operator` / `X-ACGS-Tenant` / `X-ACGS-Auth-Context` populated with the mapped Google identity (not empty) — exercise it through Caddy (the `forward_auth` dispatcher), not by calling oauth2-proxy directly, so the wiring and the response-header mapping are what's tested. Confirm the downstream bus/audit consumer's expected header names match exactly, so attribution does not silently fail open.
- **Open-redirect negative test:** through Caddy, assert that `rd=https://evil.example/`, leading-dot (`rd=https://.acgs.ai/`), and sibling-subdomain (`rd=https://x.acgs.ai/`) targets are all refused and the flow only ever lands back on `https://console.acgs.ai`.
- **Access-log redaction:** confirm the Caddy JSON access log does not capture forwarded auth/identity headers or any IdP token, since `DEPLOY.md` §10 forwards those logs into the shared audit sink.
