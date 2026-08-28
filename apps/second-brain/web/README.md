# Second Brain web

This package is the server-rendered web boundary for Second Brain v0.1. It
provides the complete private-workspace journey across Inbox, Library, source
detail, hybrid Search, grounded Ask, deliberate memory review, Today, and
Settings. The browser talks only to the same-origin proxy; persistent service
responses are treated as untrusted and parsed before they reach the UI.

These surfaces and their harness are implemented. Repository acceptance still
depends on executing the documented gates; implementation presence is not
itself a production-readiness claim.

## Product routes

- `/inbox` captures notes, Markdown, TXT, extractable PDF, DOCX, and safe public
  URLs while showing the durable ingestion job state.
- `/library` filters sources and retains purge-pending records until a durable
  purge operation reports completion.
- `/library/:sourceId` separates original metadata, extracted text, chunks,
  processing history, and exact citation context.
- `/search` accepts only the canonical `{results, semantic_status}` response,
  displays lexical and semantic retrieval evidence, and reports explicit
  semantic-provider outages even when no result rows exist.
- `/ask` displays only validated grounded, abstained, validation-failed, or
  provider-unavailable answer contracts. Proposed memories stay inactive.
- `/memories/review` and `/memories` implement explicit approval, revisions,
  lineage, supersession, archive, and confirmed purge.
- `/today` shows the five deterministic review sections; `/settings` shows safe
  provider status, limits, projects, and tags.

## Runtime contract

Use Node 24 and the nested lockfile:

```bash
fnm exec --using 24 pnpm install --frozen-lockfile
fnm exec --using 24 pnpm build
```

Every runtime requires:

- `SECOND_BRAIN_API_URL`: HTTP(S) service origin, without credentials, path,
  query, or fragment.
- `SECOND_BRAIN_PUBLIC_ORIGIN`: the browser-visible HTTP(S) origin. Production
  requires HTTPS.
- `SECOND_BRAIN_WEB_APP_ENV`: `development`, `test`, or `production`.
- `SECOND_BRAIN_WEB_AUTH_MODE`: `session` or `development_headers`.
- `SECOND_BRAIN_WEB_BIND_HOST`: an explicit IP address for `start`. `dev`
  defaults to `127.0.0.1`.
- `SECOND_BRAIN_WEB_PORT`: listener port, default `3000`.

`development_headers` additionally requires
`SECOND_BRAIN_WEB_DEV_OWNER_ID` and `SECOND_BRAIN_WEB_DEV_WORKSPACE_ID`. It is
rejected in production and unless the actual configured listener, API origin,
and public origin are all literal loopback IP addresses. Development identity variables are rejected
in session mode. `pnpm start` passes the validated bind address directly to
Next.js and exits before listening when validation fails.

HSTS is intentionally not emitted by this HTTP-capable process. Configure HSTS
only at the confirmed HTTPS reverse proxy or ingress termination boundary.

The same-origin proxy validates the route allowlist, removes browser identity
and `Host` headers, and sets the configured upstream host. The complete request
body is capped at 12,000,000 bytes and must arrive within one non-resetting
10-second deadline. Declared or streamed oversize bodies never reach the
service. A stalled body receives a structured retryable `408`; its reader is
cancelled after the response is committed so the HTTP socket can receive the
error. Accepted bodies use a bounded 0600 temporary spool, stream once to the
service, and are removed after the upstream request settles. Session cookies
returned by the trusted exchange are
reconstructed only when their name, expiry, maximum age, path, SameSite,
Secure, and HttpOnly attributes match the service contract.

The browser keeps CSRF material in memory and `sessionStorage`, never local
storage. Mutations use a request fingerprint and retained idempotency descriptor
so an ambiguous response can be retried after reload with the same key. A valid
success or conclusive client error clears the descriptor.

## Checks

```bash
fnm exec --using 24 pnpm lint
fnm exec --using 24 pnpm format:check
fnm exec --using 24 pnpm typecheck
fnm exec --using 24 pnpm test
fnm exec --using 24 pnpm build
fnm exec --using 24 pnpm test:e2e
fnm exec --using 24 pnpm test:e2e:real
fnm exec --using 24 pnpm audit --prod
```

`test:e2e` uses a bounded local upstream to verify the Next.js proxy dispatcher
and fail-closed status rendering. `test:e2e:real` requires the healthy local
pgvector development container on `127.0.0.1:55439`; it never uses the
persistent development database. The guarded harness creates a uniquely named
`second_brain_test_*` database and temporary object-storage directory, migrates
from empty, starts the real API and current production-built Next.js application
with offline fake providers, then drops only those exact disposable resources.
The browser's first capture is persisted while no worker is running. A separate
worker subprocess claims it and is killed; after its lease expires, a distinct
production worker CLI must reclaim and complete it exactly once. The harness
accepts only the ordered queued, claimed, reclaimed, and ready event history,
one document/chunk/embedding lineage, and no processing-retry event.
The harness exposes only a bounded recovery state on a dedicated loopback port.
The browser journey must observe terminal success from that endpoint before it
can pass; pending recovery remains non-success, and timeout or proof failure is
reported only as a content-free error code.
Migration and child-process output is retained in bounded buffers, emitted only
on harness failure, and scanned across read boundaries for the seeded private
source text after all child readers have terminated.

The real journey runs at desktop and 390×844 mobile viewports with retries
disabled. It covers note and TXT capture, a visible failed PDF parser job,
hybrid retrieval, exact citation context, grounded and abstained Ask, inactive
proposal approval and revision, source and memory purge, keyboard activation,
horizontal overflow checks, and axe analysis.

The package `test` target depends on the production build, so foundation
Playwright never starts from a clean checkout before the Next server artifact
exists. The persistence harness also joins its recovery-proof thread and rejects
an incomplete thread or recorded exception before cleanup, privacy scanning, or
a successful exit. Process registration and cleanup share one lock: once
cleanup begins, no later child process can be spawned. Teardown signals every
registered process group before waiting, escalates within one shared eight-second
deadline, and then joins recovery, status, and log-reader threads with the time
remaining. Database polling observes the same stop signal.

All harness records are synthetic and test-only. The fixed private marker exists
solely to prove that raw source content does not appear in child logs; it is
redacted before bounded failure logs are emitted. The reusable demonstration
payloads in `../examples/demo-sources.json` are a separate CC0-1.0 dataset and
are not read by the E2E harness.
