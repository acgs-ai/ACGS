# Console Telemetry Design — PostHog Without Breaking the Privilege Boundary

Status: v2 DRAFT — revision after adversarial review (round 1: REQUEST CHANGES,
2 blockers + 4 majors, all addressed below). Code follows only after re-review.
Date: 2026-08-14. Context: PostHog Self-driving is live (project 551990); the
wizard's client instrumentation was reverted because it violated the console
CSP gate and DEPLOY.md §4. This design is the replacement.

## 0. Authorization — DEPLOY.md §4 amendment (required, approved)

Review round 1 established that DEPLOY.md §4's first console note ("No
third-party analytics ever...") is unconditional, and its server-side
carve-out covers **error telemetry only**. Product events to PostHog —
however bounded and relayed — therefore require amending the standing
commitment, not reinterpreting it.

**Decision (2026-08-14, approved by Martin in-session):** amend §4. The
amendment to land in DEPLOY.md (§4 note + §12 decision-log entry), verbatim:

> **§12 decision-log entry:** 2026-08-14 — Martin. Amended the console
> analytics ban: first-party-collected, server-relayed product events with an
> allowlist schema MAY be forwarded to a third-party analytics warehouse
> (PostHog project 551990). Unchanged and reaffirmed: no third-party
> analytics/RUM/error-tracking **SDK in the console browser**, no session
> replay of the console, no DOM/IP/free-text capture, enforced console CSP.
> The export surface is exactly the event names + bounded properties in the
> telemetry design doc's schema table, nothing else.

The §4 console-notes bullet itself is replaced (not merely annotated), so §4
and §12 cannot contradict each other. Replacement text for the first console
note, verbatim:

> - **No third-party analytics SDK in the browser, ever — and no session
>   replay of the console, ever.** The console is the audit trail; no
>   third-party script observes it from inside. The only analytics export
>   is first-party-collected, server-relayed events under the allowlist
>   schema in `docs/POSTHOG_CONSOLE_TELEMETRY_DESIGN.md` (§12 decision,
>   2026-08-14). Anything beyond that schema is banned exactly as before.

Process (review condition, round 2): the DEPLOY.md §4+§12 text change is its
own commit, approved explicitly by the commitment owner at PR review,
separate from the code diff — the amendment is a human decision with a named
owner, not something a squashed code approval absorbs.

Until this text lands in DEPLOY.md, no telemetry code lands anywhere.

## 1. Constraints

1. DEPLOY.md §4 as amended (§0): no in-browser third-party SDK, no replay,
   no DOM/IP/free-text export; bounded server-relayed events only.
2. **Console CSP is enforced and closed:** `connect-src 'self'`,
   `script-src 'self'` (DEPLOY.md §5). `scripts/check-console-csp-harness.mjs`
   scans the built console bundle (`scanBuiltConsoleArtifact`) and rejects
   URL literals outside its allowlist regex (w3.org / react.dev / localhost /
   127.0.0.1) — this existing gate already blocks any PostHog URL literal
   from shipping in the console bundle.
3. **Perf budgets** (`scripts/check-performance-budget.mjs` budgets table):
   marketing 225 KiB gzip, console 350 KiB gzip, lazy chunks summed. The
   emitter is dependency-free (~1 KiB) and fits the console budget with no
   budget change; full `posthog-js` on marketing remains out (separate
   design if ever wanted).
4. **Claim safety:** telemetry is not audit. Nothing here may be described
   as part of the governance evidence chain, and no governance evidence may
   depend on it.

## 2. Decision

**Console telemetry is first-party events relayed server-side. Session replay
never runs on the console origin.**

- The console browser emits allowlist events to the same-origin path
  `/api/telemetry`, which rides the existing Caddy `handle /api/*`
  reverse-proxy to `BUS_UPSTREAM` (DEPLOY.md §4 Caddyfile). No third-party
  SDK, no new origin, no CSP change.
- A server-side forwarder (bus side) holds the PostHog project key and ships
  accepted events to PostHog's capture API. The key never reaches a browser.
- PostHog Replay Vision scanners currently targeting console flows are
  disabled (§8) — replaying the privileged audit surface into a third-party
  warehouse stays rejected, with masking or without.

### Rejected alternatives

| Alternative | Why rejected |
|---|---|
| Full `posthog-js` on console behind a same-origin `/ingest` proxy | The proxy hides the origin, not the fact: a third-party SDK executing in the privileged surface, streaming DOM/session data outward. Violates §4 even as amended (in-browser SDK + replay stay banned). |
| `posthog-js-lite` (events only) on console | Still a third-party SDK in-browser on the privileged origin; §4 as amended still bans it. |
| Full `posthog-js` on marketing instead | Marketing budget 225 KiB with lazy chunks summed; the SDK does not fit without its own budget design. Out of scope. |
| Self-hosted PostHog | Removes the warehouse concern, not the in-browser SDK/CSP concern; adds an ops surface. Revisit only if console replay is ever wanted badly enough to own the storage. |

## 3. Architecture

```
console browser ──POST /api/telemetry (same-origin, CSP-clean)──▶ Caddy
    Caddy handle /api/* ──reverse_proxy {$BUS_UPSTREAM}──▶ bus: telemetry relay
        relay: validate (allowlist) → strip/deny → enqueue → 202 always
        forwarder (server-side): batch → PostHog /batch capture API
                                  (key from server secret store, never client)
```

- **Client emitter** (`src/surfaces/console/telemetry.ts`, ~1 KiB, no deps):
  `track(event, props)` → `navigator.sendBeacon('/api/telemetry', body)` with
  `fetch(..., {keepalive: true})` fallback. Fire-and-forget: failures are
  swallowed after one debug log; no retries; in-memory batch ≤20 events,
  flushed on a jittered interval (base 15 s + random 0–5 s, to decorrelate
  concurrent sessions) and on `visibilitychange` via sendBeacon.
- **Flag semantics (precise):** gated by build-time `VITE_CONSOLE_TELEMETRY`.
  When unset/off, `track()` is a no-op and **no telemetry network call is
  ever made**; the ~1 KiB emitter module itself may still ship in the bundle
  (call sites import it unconditionally). The guarantee is behavioral
  (zero network), not bundle-absence — and it is what the flag-off test
  asserts (§6).
- **Endpoint auth posture (stated plainly):** the Caddyfile's
  `handle /api/*` block has **no `forward_auth`** — `/api/telemetry` is not
  auth-gated at the Caddy layer, and cannot be universally, because
  `login_provider_selected` / `magic_link_requested` are pre-auth by nature.
  The session cookie rides along on same-origin requests when present
  (`src/api/client.ts` uses `credentials: 'same-origin'`); the relay MAY use
  it to attribute authenticated events but MUST accept (and 202-drop at its
  discretion) unauthenticated ones. Abuse posture: the endpoint is
  write-only, schema-allowlisted, 202-always, and lossy — a garbage flood
  costs the sender a request and the relay a validation; see the isolation
  paragraph below for why it cannot starve governed traffic.
- **Isolation from governed API traffic:** telemetry shares `BUS_UPSTREAM`
  with real `/api/*` calls. Required mitigations, in order of authority:
  (a) bus-side: the relay endpoint is cheap-validate-then-202 with a bounded
  internal queue that drops oldest on overflow — it never applies
  backpressure to the shared connection path; (b) Caddy: a dedicated
  `handle /api/telemetry` block placed before `handle /api/*`, so operators
  can disable telemetry at the edge without touching governed routes (v1
  ships the dedicated block with a conservative `request_body max_size 64KB`).
  Rate limiting at the Caddy layer is NOT an available fallback as pinned:
  it requires a non-standard Caddy module (custom build), and this repo pins
  `caddy:2.10.2-alpine` under `pnpm test:container-pins` — enabling it would
  be a pinned-image change with its own gate update, decided separately. The
  shipping abuse controls are the body cap, the edge kill-switch, and the
  bus-side drop-oldest queue; (c) client: small batches, jittered flush, no
  retries (already above).
- **Forwarder**: server-side batch POST to PostHog `/batch`.
  `distinct_id = HMAC-SHA256(actor_id, TELEMETRY_SALT)`.
  **Salt custody:** `TELEMETRY_SALT` is a server-side secret (secret
  manager / deploy-time env, same custody class as the PostHog key), global
  (not per-tenant) in v1, rotated by redeploy (rotation breaks distinct_id
  continuity; accepted). Claim discipline: distinct_ids are **pseudonymous
  under salt secrecy** — not claimed irreversible in the abstract; with a
  small actor space, whoever holds the salt can confirm guesses. PostHog
  never receives the raw actor id, the salt, the browser IP
  (server-relayed connection + explicit `$ip: null`), or user agent.

## 4. Event schema (v1 — allowlist, everything else rejected)

| Event | Properties (all enumerated/bounded) |
|---|---|
| `console_section_navigated` | `route_template` (see resolution table below) |
| `console_signed_out` | — |
| `login_provider_selected` | `provider_id` |
| `magic_link_requested` | — |
| `action_policy_test_run` | — (the `outcome` property was REMOVED from v1: review round 2 flagged that its multi-tenant aggregate disclosure question was never resolved; default-deny wins. Re-adding it requires its own review with per-tenant aggregation thresholds.) |
| `constitution_replay_started` | — |
| `constitution_promoted` | — |
| `constitution_compile_discarded` | — |
| `deliberation_action_taken` | `action_kind` ∈ bounded enum |
| `policy_rule_selected` | `rule_position` (integer index, not rule text) |

### Route-param resolution table (closes review blocker 2)

`route_template` is NEVER the resolved URL. Per route, exactly this:

| Console route | Emitted `route_template` value | Param handling |
|---|---|---|
| `/console/$section` | `/console/<section>` with `<section>` substituted **only if** the matched value is in the router's static section list (Actions, Policies, Deliberations, Compile, …); otherwise the literal `/console/$section` | `$section` resolves from a closed set — it is an enum, not user input |
| `/console/audit/$receiptId` | the literal string `/console/audit/$receiptId` | `$receiptId` NEVER resolves — a receipt id is governance-evidence content (§5) |
| any future route with a param | literal template until this table explicitly allowlists the param | default-deny |

The emitter implements this as a lookup table over the router's static route
ids; there is no code path from `useParams()`-style values into an event
property except through the section-enum check. A unit gate asserts the
table covers every route in the console route tree (fails closed when a new
route is added without a table entry).

**Payload hygiene rules (hard):** no free-text fields; no policy / receipt /
deliberation CONTENT ever; no resolved ids of any kind in v1; no URLs beyond
`route_template` above; no error messages or stack traces (server-side error
telemetry is the pre-existing §4 carve-out, a separate design). The client
enforces this by construction (typed event map; no arbitrary-props overload
exported). The relay re-enforces it server-side (§6 wiring caveat).

## 5. What this is NOT (claim boundary)

- Not audit, not evidence, not part of any receipt or chain. The governed
  bus path is used for transport/origin discipline only; telemetry events
  MUST NOT be written into the bus's audit artifacts, and no receipt may
  reference them.
- Lossy by design: dropped events are silent and acceptable. Any future
  "usage report" produced from PostHog data must be labeled analytics, not
  governance evidence.
- No compliance claim attaches to any part of this design.

## 6. Gates — lockstep changes

| Gate | Change |
|---|---|
| `check-console-csp-harness.mjs` | CSP posture: **none** (no new URL literals — the existing `scanBuiltConsoleArtifact` allowlist already blocks PostHog hosts). **Add** to its existing `walk()`-based source scan: fail on any `posthog` package import anywhere under `src/` (all of `src/`, `.ts` included — NOT just console dirs; review round 1 showed `Login.tsx` and shared modules sit outside `src/{surfaces,routes}/console/**`). This is the anti-wizard-re-run guard, placed in the script that already has a tree walker (`check-security-invariants.mjs` reads a fixed file list and is the wrong home). |
| Console CSP / DEPLOY.md §5 | None. `connect-src 'self'` covers `/api/telemetry`. |
| DEPLOY.md §4 + §12 | The §0 amendment text, landed in the same PR as the emitter — the doc change authorizes the code change; they are not separable. Plus the §4 note on the dedicated `/api/telemetry` Caddy block (§3 isolation). |
| Route-table coverage gate | New unit check: every route id in the console route tree has an entry in the §4 resolution table (fails closed on new routes). |
| Emitter tests (this repo, dispatcher-level where applicable) | Flag off ⇒ zero network calls (spy on fetch/sendBeacon through real user flows); flag on ⇒ beacon to `/api/telemetry` with schema-valid body; `route_template` for the audit route is the literal template (leak regression test). |
| Wiring | All new checks added to `pnpm test:all` AND enumerated in `check-ci-readiness-gates.mjs` in the same PR (an unwired check proves nothing). |
| Relay allowlist + audit-exclusion enforcement | **OPEN DEPENDENCY — unprovable from this repo.** Two bus-side MUSTs share this row: (a) the relay's event/prop allowlist; (b) §5's audit-exclusion rule — telemetry events MUST NOT produce bus audit artifacts and no receipt may reference them. Both live bus-side; 202-always makes both unobservable from the client, so no acgi-ai gate can prove either. Requirement carried to the bus package: dispatcher-level tests (through its HTTP surface) proving (a) unknown events/props are dropped and never logged raw, and (b) an accepted telemetry event produces zero audit-chain entries and zero receipt references, per the handler-wiring rule. Until both exist and are cited here, the server-side enforcement claims are UNVERIFIED and §8 step 3 may not proceed. |

## 7. PostHog-side reconciliation (web UI follow-ups, human)

- Replay Vision scanners targeting console flows: **disable** (no replay
  source will exist). Marketing replay would be its own budgeted design.
- Session Replay product toggle: leave OFF (the setup report's "follow-up
  required" is resolved as: do not enable).
- Scouts/signal sources keyed on events keep working — events arrive
  server-side with the same names the wizard configured.

## 8. Rollout

1. Land in one PR: §0 amendment in DEPLOY.md (§4 note + §12 entry), emitter
   (flag default off), route-table gate, posthog-import guard, test:all +
   ci-gates wiring.
2. Bus-side relay + forwarder land in the bus's own repo/package with their
   own review and the §6 dispatcher-level proof (holds the PostHog key +
   `TELEMETRY_SALT`; both in server secret custody).
3. Staging: `VITE_CONSOLE_TELEMETRY=1` build; verify events in PostHog show
   pseudonymous distinct_ids, `$ip` absent, only schema events/props.
   Blocked until §6's relay proof exists.
4. Production enable is a deploy-time human decision, reversible by flag,
   and independently killable at the edge via the dedicated Caddy block.

## 9. Open questions

- Bus endpoint placement (new bus route vs sidecar collector behind the same
  Caddy proxy): recommendation stands — bus route; but note it inherits the
  fail-closed `BUS_UPSTREAM` default ONLY (closed-port fallback), **not**
  auth (see §3 auth posture). Decided at bus-side design time.
- ~~Whether `action_policy_test_run.outcome` is too revealing in aggregate~~
  — RESOLVED (round 2): property dropped from v1, event kept; see §4.
