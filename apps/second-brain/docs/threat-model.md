# Second Brain v0.1 threat model

## Assets and boundaries

Assets include private originals, extracted text, chunks, embeddings, retrieval
history, answers, citations, memories, credentials, and deletion state. Trust
boundaries are browser/session, web/API principal, API/worker/PostgreSQL RLS,
object storage, public URL fetching, documents/model prompt, external providers,
and the optional future ACGS port.

| Threat | Required control | Required proof |
|---|---|---|
| Cross-scope leakage | forced RLS, composite scope keys, server principal | direct SQL and API denial tests |
| Database-owner credential leakage | runtime env contains only restricted app-role URL; bootstrap secrets use isolated Compose input | process-env test proves API/worker lack owner/bootstrap values |
| Principal/session spoofing | loopback-only dev auth; trusted production verifier; secure HttpOnly session; same-origin+CSRF; transaction `SET LOCAL` | spoofed headers/cookies, missing CSRF, verifier outage, and production startup denial tests |
| Document prompt injection | fixed contract, evidence delimiters, no tools, strict schema | malicious source cannot alter contract |
| Fabricated citations | retrieval membership, scope recheck, context lookup | unretrieved citation rejected |
| SSRF/rebinding | validate scheme, DNS and each redirect; block local/private/link-local/metadata; cap body/time | private, metadata, redirect, rebinding tests |
| Malicious upload | extension+MIME+signature allowlist, UUID key, extraction/time limits | traversal, mismatch, malformed fixtures |
| Content in logs | structured allowlist logging | seeded secret absent from API/worker logs |
| Stale deletion | transactional retrieval exclusion and physical purge | FTS/vector/object absence after purge |
| Duplicate ingestion | scoped normalized-hash uniqueness and idempotent stages | concurrent duplicate test |
| Lost/duplicated jobs | leases, attempts, `SKIP LOCKED`, recovery | termination/restart test |
| Unauthorized activation | inactive proposal state and explicit append transitions | model/policy/direct mutation denied |
| Provider outage | bounded retries and explicit unavailable state | lexical continues; Ask fails visibly |
| Uncalibrated semantic evidence | append-only profile threshold; exact API/worker profile match; fail-closed adequacy gate | NULL, drift, and below-threshold tests abstain before generation |
| Model evidence/privacy egress | default-deny egress; minimize to bounded selected evidence; exclude originals, unrelated chunks, credentials and hidden scope metadata | fake/local zero-socket test and remote request-capture allowlist test |
| Policy escalation | optional metadata-only `PolicyDecisionPort`; native checks always run | `pass` cannot bypass ownership, citation, purge, or memory-activation tests; enabled `unavailable` fails closed |

Defaults are 10,000,000 upload and URL-response bytes, a 12,000,000-byte request
envelope, 2,000,000 extracted characters, 5,000 chunks, three redirects, ten
seconds for request-body and URL-fetch deadlines, 30 seconds processing, eight
Ask chunks, and 12,000 evidence characters. Raising limits requires
resource/security tests.

Deferred residuals: production OIDC, concrete S3, OCR and hostile-renderer
isolation, ANN scale, compromised host/DB admin, live deployment, and external
penetration testing. Failure never degrades to unscoped retrieval, uncited trust,
automatic activation, or silent purge success.

Compose interpolation is not a service configuration channel. Database-owner
and application-role bootstrap passwords and port overrides remain local-only
inline defaults or values in an explicitly supplied, untracked
`.env.compose.local`. That file is never sourced into the API/worker
environment. `make check` verifies the path is Git-ignored before later
surface checks. The service receives only its restricted application-role URL;
owner credentials reaching a service process are a startup/test failure, not a
supported fallback. The worker does require its restricted dispatcher role in
addition to the content-role URL; it intentionally does not load the API `.env`.

## Future policy-port failure modes

The port is disabled by default and then acts as a no-op, not an implicit
approval: native checks remain mandatory. Once explicitly enabled, `veto`
denies, while timeout, exception, malformed output, or `unavailable` denies the
protected operation with a visible policy-unavailable error. `pass` is only the
absence of an additional veto. Inputs are the bounded metadata fields in
`api-contracts.md`; source text, answers, memory statements, prompts, secrets,
and storage paths are forbidden. Tests combine every decision with failed
ownership, citation, purge, and memory-activation checks to prove the adapter
cannot become an authorization bypass.

## Model egress rules

- Fake and local providers run with network egress disabled; the test intercepts
  socket creation and fails on any attempt.
- A remote provider is opt-in and receives only the query, versioned system
  contract, and already bounded selected evidence. It never receives the
  original object, unrelated chunks, session cookies, CSRF tokens, database
  keys, object-store paths, provider credentials, or owner/workspace identifiers
  unless a provider contract explicitly requires a pseudonymous request ID.
- Request/response bodies are excluded from normal logs. Provider errors are
  reduced to provider/model IDs, latency, counts, and safe error classes.
- Remote evidence egress is recorded as metadata in answer provenance. Provider
  outage or an egress-policy denial cannot expand the evidence set or trigger an
  unrestricted fallback.
