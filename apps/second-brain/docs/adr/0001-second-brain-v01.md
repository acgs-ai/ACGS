# ADR-0001: Isolated provenance-first Second Brain vertical slice

## Status

Accepted and implemented incrementally. This ADR records the decision; runtime
claims still require the implementation and verification evidence cited in the
main README and implementation log.

## Date

2026-08-27

## Context

ACGS has no tracked Second Brain product. The repository is a mixed uv/pnpm
monorepo with an existing React/Vite governance console (`acgi-ai`), several
FastAPI packages, and a narrow fail-closed enforcement kernel (`gove-zone`). The
requested product is a private research and recall workspace, not a governance
console feature or an autonomous-agent execution surface.

The MVP must preserve immutable source provenance, survive worker restart,
retrieve lexically when models are unavailable, validate every answer citation,
require explicit memory activation, and fail closed across owner/workspace
boundaries. Its browser acceptance path must use real persistence.

## Decision

Create an isolated top-level application at `apps/second-brain/` with:

- a currently supported Next.js/React/TypeScript web app on Node 24 and pnpm 9;
- a FastAPI/Pydantic 2 service and ingestion worker on Python 3.11+ via uv;
- SQLAlchemy 2 and Alembic over PostgreSQL with pgvector;
- PostgreSQL FTS plus exact vector similarity, fused with reciprocal-rank fusion;
- a PostgreSQL durable job queue using leases and `FOR UPDATE SKIP LOCKED`;
- a filesystem object adapter for local proof and an S3-compatible interface;
- OpenAI-compatible embedding/generation transports and deterministic fakes;
- PostgreSQL row-level security and composite ownership constraints;
- loopback-only development/test identity, trusted-verifier production sessions,
  secure HttpOnly cookies, same-origin CSRF, and transaction-local DB scope;
- an optional future local ACGS seam,
  `PolicyDecisionPort.evaluate(context) -> pass|veto|unavailable`, that accepts
  bounded metadata only and can veto but never grant authority.

The deterministic retrieval contract is lexical top 50 plus semantic top 50,
RRF `k=60`, summed reciprocal ranks, and stable `chunk_id` tie-breaking. Ask is
bounded by default to eight chunks and 12,000 evidence characters.

## Alternatives considered

### Add routes to `acgi-ai`

Rejected. It would reuse React, TanStack Query, CSP-safe CSS, and API patterns,
but couples a private knowledge product to a governance console with a fixed
privilege banner, two-surface marketing/console build, governance navigation,
fixture history, and a different deployment contract. It also lacks the
requested server-rendered application shell.

### Put the product in `packages/gove-zone`

Rejected. `gove-zone` is the narrow enforcement membrane for side effects. A
personal knowledge product, retrieval engine, and memory lifecycle do not belong
inside that kernel and must not inherit its guarantees.

### Use Redis or an external queue

Rejected for v0.1. PostgreSQL already provides the required durable state,
locking, recovery, and transaction boundary. A second stateful service increases
operations and consistency risk without helping the first vertical slice.

### Add a vector database or knowledge graph

Rejected for v0.1. pgvector and PostgreSQL FTS satisfy the required hybrid
retrieval contract while keeping owner/workspace enforcement in one database.

## Consequences

- The product has its own frontend build and deployment boundary.
- The isolated app is registered in the root pnpm workspace and path-filtered
  Second Brain CI; those integrations preserve, rather than collapse, its own
  frontend and service boundary.
- The first implementation is larger than a demo because isolation, SSRF,
  citation validation, durable jobs, and purge are acceptance invariants.
- Exact vector search is intentionally scale-limited until a provider/dimension
  profile and ANN indexing strategy are proven.
- Production OIDC and S3 are explicit integration boundaries, not v0.1 claims.
- Production startup refuses missing trusted identity verification; no browser
  principal header is an authentication mechanism.
- API/worker runtime settings and Compose bootstrap values are separate input
  channels. The API receives only the restricted `second_brain_app` connection
  URL. The worker receives that content URL and a restricted
  `second_brain_worker` dispatcher URL. PostgreSQL owner/bootstrap secrets and
  the published local port remain in inline local-only Compose defaults or an
  explicitly passed, untracked `.env.compose.local`; they are never exported to
  or read by the API or worker. The local acceptance gate fails closed unless
  Git confirms that path is ignored.
- Semantic-only Ask requires a calibrated threshold attached to an immutable
  embedding profile. Provider/model/dimensions/version/threshold drift or a
  missing threshold abstains before generation. Recalibration increments the
  profile version and re-ingests rather than mutating profile meaning.
- The disabled ACGS seam is a no-op: native checks still run and there is no
  additional veto. When enabled, `veto` denies and `unavailable`, timeout, or
  error fails the protected operation closed with a visible state.
- `pass` is not authority. It cannot override failed ownership, citation, purge,
  or explicit memory-activation checks. The seam records bounded reason,
  policy-version, audit, and evaluation-time metadata and does not introduce a
  second decision engine or a `gove-zone` dependency.

## Revisit triggers

Write a superseding ADR before changing the frontend framework, database,
retrieval fusion contract, ownership enforcement layer, memory activation rule,
or ACGS privilege semantics.
