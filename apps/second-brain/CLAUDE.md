# Second Brain v0.1 — Local Guide

This guide supplements the root `CLAUDE.md`. `AGENTS.md` is the local operating
contract; the architecture and trust decisions live under `docs/`.

## Product language

Use precise labels: Source, Evidence, Proposed memory, Approved memory,
Insufficient evidence, Processing failed, and Citation unavailable. Keep
original content, extracted content, generated answers, memory states, and
system metadata visually and semantically distinct.

Avoid anthropomorphic claims such as "I remember everything", "I know you", or
"Your AI understands your life".

## Architecture boundary

The planned application is:

- `web/`: isolated Next.js private application;
- `service/`: FastAPI API and ingestion worker sharing domain modules;
- PostgreSQL/pgvector: system of record, FTS, vectors, and durable jobs;
- filesystem object adapter for local proof, with an S3-compatible boundary;
- OpenAI-compatible provider transports plus deterministic fake providers.

Do not add Second Brain routes to `acgi-ai`. Reuse its restrained visual,
same-origin, CSP, and accessibility conventions as patterns, not source-level
coupling.

## Verification intent

The local `Makefile` intentionally fails until the planned manifests, code,
migrations, and tests exist. A missing implementation surface is a visible
failure, never a skipped success.

Required end-state commands are documented in `README.md` and `tasks/plan.md`.
