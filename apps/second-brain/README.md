# Second Brain v0.1

Second Brain is a private, provenance-first workspace for capturing sources,
retrieving evidence, asking source-grounded questions, and deliberately
promoting evidence into durable memory. It does not claim to remember
everything, execute autonomous actions, or treat generated text as source
material.

The service, worker, PostgreSQL/pgvector schema, filesystem object adapter, and
server-rendered Next.js product surfaces are implemented in this directory.
Backend Checkpoints A-D, web acceptance, and package-local
`make -C apps/second-brain verify` passed with independent evidence in
`docs/implementation-log.md`. The release-candidate audit reproduced the
package gate but found an unchanged root-workspace Ruff failure after supplying
Node 24, a patched temporary Turbo 2.10.12, and all three pinned submodules.
GitHub-hosted CI has not run. This README makes no committed-baseline,
deployment, or production-readiness claim.

## Product boundary

The v0.1 vertical slice includes:

- notes, Markdown, TXT, extractable-text PDF, DOCX, and safe public URLs;
- immutable source/version lineage and visible, durable processing jobs;
- PostgreSQL full-text and exact pgvector retrieval with deterministic RRF;
- bounded grounded Ask with validated stable chunk citations and abstention;
- proposed versus approved memory, append-only revisions, supersession,
  archive, and durable purge;
- Inbox, Library, source detail, Search, Ask, Memory Review, Today, and Settings;
- real PostgreSQL, pgvector, worker, and filesystem persistence in the browser
  acceptance harness, with offline deterministic providers.

The product routes are `/inbox`, `/library`, `/library/:sourceId`, `/search`,
`/ask`, `/memories`, `/memories/review`, `/today`, and `/settings`.

Explicit v0.1 deferrals include OCR, JavaScript-rendered pages, unbounded
crawling, production OIDC, a concrete S3 adapter, distributed workers, ANN
indexing, native mobile, browser extensions, knowledge graphs, autonomous
actions, automatic memory approval, and a remote ACGS adapter.

## Architecture and trust boundaries

The application is isolated from the existing ACGS governance console:

- `web/` is a Next.js 16 server-rendered UI and same-origin API proxy;
- `service/` is a FastAPI API plus a separately launched ingestion/purge worker;
- PostgreSQL 18 with pgvector stores lineage, lexical indexes, exact vectors,
  jobs, retrieval provenance, citations, memories, and content-free tombstones;
- `.second-brain-storage` stores originals behind server-generated object keys;
- deterministic fake and OpenAI-compatible model providers share typed
  boundaries without tying the product to one vendor.

Every scoped transaction sets owner and workspace before querying, and forced
row-level security plus composite constraints enforce that scope in PostgreSQL.
The API process uses `second_brain_app`. Job claiming uses the separately
permissioned `second_brain_worker` dispatcher connection. Development identity
is accepted only over a direct loopback connection. Production startup rejects
development headers and requires a bounded trusted-proxy verifier configuration.

Future ACGS integration is the optional metadata-only
`PolicyDecisionPort.evaluate(context) -> pass|veto|unavailable` seam. It is
disabled by default. When enabled, it may add a veto; `unavailable` fails the
protected operation closed, and `pass` cannot grant access, validate citations,
authorize purge, or activate memory. It is not a second policy engine and v0.1
does not depend on a remote governance service.

Design and trust details:

- `docs/adr/0001-second-brain-v01.md`
- `docs/invariants.md`
- `docs/api-contracts.md`
- `docs/threat-model.md`
- `tasks/plan.md`

## Prerequisites

- Podman with Compose support;
- Python 3.11, 3.12, or 3.13 and `uv`;
- Node.js 24 through `fnm`;
- pnpm 9.15.4 through the package manager declaration;
- the pinned dependencies in `service/uv.lock` and `web/pnpm-lock.yaml`.

All commands below run from `apps/second-brain` unless stated otherwise.

## Local setup

Install locked dependencies and start PostgreSQL:

```bash
cd service && uv sync --locked
cd ../web && fnm exec --using 24 pnpm install --frozen-lockfile
cd ..
cp .env.example .env
make db-up
make migrate
```

The default local database volume is development-only. Seed one deterministic
local principal before using development-header authentication:

```bash
podman compose -f compose.yaml exec -T postgres \
  psql -U second_brain_owner -d second_brain <<'SQL'
INSERT INTO users (id,email)
VALUES ('11111111-1111-4111-8111-111111111111','local@example.test')
ON CONFLICT DO NOTHING;
INSERT INTO workspaces (id,owner_id,name)
VALUES (
  '22222222-2222-4222-8222-222222222222',
  '11111111-1111-4111-8111-111111111111',
  'Local workspace'
)
ON CONFLICT DO NOTHING;
INSERT INTO workspace_memberships (workspace_id,user_id,role)
VALUES (
  '22222222-2222-4222-8222-222222222222',
  '11111111-1111-4111-8111-111111111111',
  'owner'
)
ON CONFLICT DO NOTHING;
SQL
```

Run the API and continuous worker in separate terminals:

```bash
make service-run
```

```bash
cd service
uv run python -m second_brain.worker --worker-id local-worker
```

Run the web application in a third terminal:

```bash
SECOND_BRAIN_API_URL=http://127.0.0.1:8000 \
SECOND_BRAIN_PUBLIC_ORIGIN=http://127.0.0.1:3000 \
SECOND_BRAIN_WEB_APP_ENV=development \
SECOND_BRAIN_WEB_AUTH_MODE=development_headers \
SECOND_BRAIN_WEB_BIND_HOST=127.0.0.1 \
SECOND_BRAIN_WEB_PORT=3000 \
SECOND_BRAIN_WEB_DEV_OWNER_ID=11111111-1111-4111-8111-111111111111 \
SECOND_BRAIN_WEB_DEV_WORKSPACE_ID=22222222-2222-4222-8222-222222222222 \
fnm exec --using 24 pnpm --dir web dev
```

Open `http://127.0.0.1:3000/inbox`. `make service-worker-once` is available for
one queued ingestion or purge operation. `make db-down` stops the container but
retains its development volume.

`service-run` is the supported launcher. It disables Uvicorn proxy-header
rewriting and raw access logs so authentication uses the immutable socket peer
and application logs retain allowlisted route templates only. Do not replace it
with a bare `uvicorn` command.

## Environment reference

`apps/second-brain/.env.example` is the canonical API template and `.env` is the
canonical untracked API file. `service/.env` must not become a second source of
truth. Worker settings use the `SECOND_BRAIN_WORKER_` prefix and are supplied
only to the worker process; the worker intentionally does not load `.env`.

### API settings

| Variable | Default / range | Purpose |
| --- | --- | --- |
| `SECOND_BRAIN_APP_ENV` | `development`; `development\|test\|production` | Runtime trust mode. |
| `SECOND_BRAIN_AUTH_MODE` | `development_headers`; `development_headers\|trusted_proxy` | Principal verification path. |
| `SECOND_BRAIN_BIND_HOST` / `SECOND_BRAIN_BIND_PORT` | `127.0.0.1` / `8000`; port `1..65535` | API listener. |
| `SECOND_BRAIN_DATABASE_URL` | restricted local app URL | Must authenticate exactly as `second_brain_app`. |
| `SECOND_BRAIN_STORAGE_BACKEND` / `SECOND_BRAIN_STORAGE_ROOT` | `filesystem` / `.second-brain-storage` | Original-object adapter and root. |
| `SECOND_BRAIN_MAX_UPLOAD_BYTES` | `10000000`; `1..100000000` | Upload and URL response-byte cap. |
| `SECOND_BRAIN_MAX_REQUEST_ENVELOPE_BYTES` | `12000000`; `1..120000000` | Whole request-body cap. |
| `SECOND_BRAIN_REQUEST_BODY_TIMEOUT_SECONDS` | `10`; `(0,120]` | Request-body deadline. |
| `SECOND_BRAIN_MAX_EXTRACTED_CHARS` | `2000000`; `1..20000000` | Extracted-text cap. |
| `SECOND_BRAIN_MAX_CHUNKS` | `5000`; `1..50000` | Per-version chunk cap. |
| `SECOND_BRAIN_MAX_PROCESSING_SECONDS` | `30`; `1..300` | Worker processing deadline. |
| `SECOND_BRAIN_URL_MAX_REDIRECTS` | `3`; `0..10` | Revalidated redirect cap. |
| `SECOND_BRAIN_URL_TIMEOUT_SECONDS` | `10`; `(0,60]` | Whole URL fetch deadline. |
| `SECOND_BRAIN_MODEL_PROVIDER` | `fake`; `fake\|openai_compatible` | Embedding and generation adapter family. |
| `SECOND_BRAIN_MODEL_BASE_URL` | `http://127.0.0.1:8001/v1` | OpenAI-compatible base URL. |
| `SECOND_BRAIN_EMBEDDING_MODEL` | `text-embedding` | Embedding model identifier. |
| `SECOND_BRAIN_EMBEDDING_DIMENSIONS` | `8`; `1..4096` | Exact vector dimensions. |
| `SECOND_BRAIN_EMBEDDING_PROFILE_VERSION` | `1`; `1..2147483647` | Append-only embedding/calibration version. |
| `SECOND_BRAIN_ANSWER_MIN_SIMILARITY` | unset/`NULL`; `[-1,1]` | Calibrated semantic-only answer threshold; unset abstains. |
| `SECOND_BRAIN_ANSWER_API_KEY` | unset | API-only OpenAI-compatible credential for embedding and generation. |
| `SECOND_BRAIN_ANSWER_GENERATION_MODEL` | `grounded-answer` | Generation model identifier. |
| `SECOND_BRAIN_POLICY_ENABLED` | `false` | Enables the local veto-only policy port. |

Production trusted-proxy, session, and exchange-rate settings are documented
inline in `.env.example` and validated by `service/src/second_brain/config.py`.
Unknown general API keys fail startup; answer-provider and worker prefixes are
parsed by their separate settings classes.

### Worker settings and profile calibration

The worker has separate content and dispatcher database URLs plus corresponding
storage, processing, URL, and embedding settings under
`SECOND_BRAIN_WORKER_*`. For OpenAI-compatible embeddings it uses
`SECOND_BRAIN_WORKER_MODEL_API_KEY`; the API-only answer credential is never
loaded through the worker settings class.

The API and worker values for embedding provider/base URL, model, dimensions,
`EMBEDDING_PROFILE_VERSION`, and `ANSWER_MIN_SIMILARITY` must describe the same
profile. The threshold is immutable after insertion. To change it:

1. Evaluate representative in-scope queries offline and choose a threshold in
   `[-1.0, 1.0]`; do not use a convenient test value as production calibration.
2. Increment both API and worker embedding profile versions.
3. Deploy the same model, dimensions, version, and threshold to both processes.
4. Re-ingest sources to create embeddings under the new append-only profile.
5. Verify above-threshold, below-threshold, provider-outage, and cross-scope
   behavior before enabling semantic-only answers.

If the threshold is unset, the stored profile differs from API configuration,
or the provider/model/version/dimensions differ, semantic-only Ask returns
`insufficient_evidence` without calling generation. Lexical evidence remains
usable, and ordinary lexical search continues during embedding outages.

## Source lifecycle

Note and upload capture creates an immutable source, source version, object
lineage record, and visible queued job. URL capture initially creates the source
and queued job; processing appends the fetched source version and object
lineage. A leased worker moves the job through `queued` → `processing` → `ready`
or a visible `failed`/retry/dead state. Parsing produces append-only documents
and deterministic `chars-v1` chunks of 1,200 characters with 120-character
overlap. Chunks retain stable IDs, character offsets, and available PDF page or
DOCX paragraph metadata. Parser or chunker upgrades create a new source version
rather than reinterpreting an old one.

Deduplication is scoped to owner, workspace, and normalized content hash.
Capture and worker stages are idempotent and restart-safe. When embeddings are
unavailable, a successfully parsed source remains lexical-ready with an
explicit semantic-unavailable state.

URL capture has a distinct provenance sequence. The initial source row records
the normalized public URI and may have no original-byte hash or object
reference. Its normalized-URI SHA-256 supplies tenant-scoped capture
idempotency. After a successful bounded fetch, the exact fetched bytes,
content SHA-256, stored object key, final URI, redirect lineage, and peer
binding are authoritative on the append-only source version and URL-fetch
provenance records; the URI hash is not presented as a content hash.

## Retrieval and citation contract

Search scopes PostgreSQL before ranking, selects lexical top 50 and semantic
top 50, and combines them with reciprocal-rank fusion using `k=60`. Equal fused
scores use stable chunk-ID ordering. Results expose source and chunk IDs,
excerpt, location, lexical and semantic channel details, source date, project,
tags, and provider status.

Ask persists the query, filters, fixed retrieval configuration, retrieved ranks,
selected evidence, provider/model identifiers, prompt version, final status,
and citations. It sends at most eight selected chunks and 12,000 evidence
characters to generation. Retrieved text is serialized as untrusted data under
a fixed no-tools JSON contract.

Semantic-only evidence must meet the calibrated profile threshold described
above. A selected lexical match is adequate without that semantic threshold.
No selected evidence, uncalibrated or below-threshold semantic-only evidence,
or profile drift returns `insufficient_evidence` before generation. Generation
outage returns `provider_unavailable`. Malformed output or inaccessible,
unretrieved, stale, or cross-scope citations returns `validation_failed` and no
generated statement is displayed as trusted. System commentary is stored and
rendered separately from source-supported statements.

Every displayed citation identifies a selected retrieval result, stable chunk,
source, source version, and evidence offsets. Source context rechecks current
accessibility and returns the exact passage with bounded surrounding context.

## Memory lifecycle

A grounded answer may create an inactive proposed memory. Only explicit
approval or edit-and-approve creates an active approved memory, preserving its
source-chunk evidence. Rejection leaves no active memory. Meaning changes append
a numbered revision; they never overwrite historical meaning. Supersession and
archive are explicit state transitions, and a policy result cannot activate a
memory.

## Deletion and purge

A purge request immediately changes the target to retrieval-ineligible
`purge_pending`, then creates a durable worker operation. Completion removes the
stored original, extracted text, chunks, full-text index entries, embeddings,
and permitted derived memory meaning. A content-free audit tombstone and bounded
reason/state metadata may remain. Until the operation reports `complete`, the UI
must not describe deletion as finished. Retry/dead states remain visible.

## Supported types and limits

| Capture | Accepted input | Important restrictions |
| --- | --- | --- |
| Note | `note` or `markdown` text | Non-empty; title at most 300 characters. |
| TXT | `.txt` + `text/plain` | Valid UTF-8; no NUL bytes. |
| Markdown | `.md` + `text/markdown` | Valid UTF-8; no NUL bytes. |
| PDF | `.pdf` + `application/pdf` | Structural signature required; extractable text only; no OCR. |
| DOCX | `.docx` + OOXML MIME | No macros, encryption, unsafe paths, external relationships, or unsafe expansion. |
| URL | public HTTP/HTTPS on default port | Revalidates DNS and peer on every redirect; no JavaScript rendering. |

Default limits are 10,000,000 upload/URL bytes, 12,000,000 request-envelope
bytes, 2,000,000 extracted characters, 5,000 chunks, three redirects, ten
seconds for request body and URL fetch, and 30 seconds for processing. URL
ingestion rejects loopback, private, link-local, multicast, unspecified,
reserved, metadata-service, unsafe-redirect, rebinding, compressed-response,
unsupported-MIME, and oversized targets.

## Backup and restore notes

There is no automated backup command in v0.1. A valid backup must capture a
transactionally consistent PostgreSQL dump and the filesystem storage root from
the same quiesced point, while API and worker mutations are stopped. Protect the
database dump, originals, configuration, and provider secrets as private data;
do not place them in normal logs or the repository.

Restore into a separately named database and empty storage root, run Alembic to
the application revision if required, and validate object hashes, source counts,
job states, lexical results, embedding profile compatibility, citation context,
and purge tombstones before directing a runtime at it. A database-only or
object-only restore is incomplete. Practice restore in an isolated environment;
the guarded migration and browser harnesses are not backup tools and never use
the persistent development database.

## Verification

The local targets are executable contracts, not placeholders:

```bash
make -C apps/second-brain check
make -C apps/second-brain lint
make -C apps/second-brain typecheck
make -C apps/second-brain test
make -C apps/second-brain build
make -C apps/second-brain migration
make -C apps/second-brain integration
make -C apps/second-brain restart-test
make -C apps/second-brain log-scan
make -C apps/second-brain accessibility
make -C apps/second-brain real-persistence
make -C apps/second-brain verify
```

`real-persistence` requires the healthy pinned pgvector container on
`127.0.0.1:55439`; the target builds the service and production web application
before starting acceptance. The harness creates a unique
`second_brain_test_*` database and temporary storage root, migrates from empty,
seeds synthetic test-only records, and starts the real API, worker, and web
application with offline fake providers. It drops only those exact disposable
resources. It never reads, migrates, resets, or treats the persistent
`second_brain` development database as acceptance evidence. Child logs are
bounded, shown only on failure, redacted, and scanned for the seeded private
marker.

The existing persistent development volume predates some unreleased migrations
and remains excluded from acceptance. If an operator deliberately chooses to
recreate it, that is a destructive local action performed outside verification;
automated gates never remove it.

## Demonstration data

`examples/demo-sources.json` contains two small synthetic capture payloads. It
contains no private or third-party licensed material and is dedicated to the
public domain under CC0-1.0; see `examples/README.md`. Submit each object to
`POST /api/v1/captures/text` or paste it through Inbox, then run the worker.

## Known limitations

- Exact vector search is intentionally scale-limited; no ANN index is present.
- The only implemented object adapter is local filesystem storage.
- PDF support requires extractable text; OCR and hostile-renderer isolation are
  absent.
- URL capture does not render JavaScript or crawl beyond bounded redirects.
- OpenAI compatibility covers `/embeddings` and `/chat/completions`; provider
  transport health is reported from local adapter state, not a remote probe.
- Semantic-only grounded answers require deployment-specific calibration and a
  profile-versioned re-ingestion.
- Proposed-memory evidence persists stable chunk, source, and source-version
  lineage, but v0.1 has no direct proposal foreign key to the originating answer
  or retrieval run.
- Source purge retains content-free audit tombstones, but memory detail does not
  expose those tombstones after the evidence content has been purged.
- A rare inverse lock order between capture-stage abandonment and the sweeper
  can deadlock (`stage -> job` versus `job -> stage`). PostgreSQL aborts one
  participant, so the failure is visible and retry/recovery remains available;
  eliminating the inversion is deferred.
- Production identity integration, deployment hardening, backup automation,
  S3, load testing, external penetration testing, and operational monitoring
  remain outside the verified v0.1 slice.
- Package-local independent acceptance and `make -C apps/second-brain verify`
  passed with 198 service tests, 88 web tests, 42 combined browser tests,
  20 accessibility tests, and the fresh-persistence harness. Root `make verify`
  ran with Node 24, temporary Turbo 2.10.12, and the three pinned submodules
  initialized; Second Brain JavaScript lint passed, then the root gate failed on
  116 Ruff errors in unchanged `acgs-cft-governance-pack` and
  `acgs_governance_eval_mvp` code. GitHub-hosted CI was not run.

Current verdict: **PARTIAL**. The implemented system is production-shaped, but
this is not a “production ready,” “secure,” or “complete” claim. Root-wide
verification is failing outside this package; hosted CI and production identity,
S3, deployment, operations, and external security validation remain unverified.
