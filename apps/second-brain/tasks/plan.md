# Implementation Plan: Second Brain v0.1

## Outcome and stop condition

Deliver one private, provenance-first vertical slice from capture through
grounded answer and explicit memory approval. Stop only when all 20 required
tests, real-persistence Playwright, empty-database migrations, package/root
gates, secret-log scan, and independent review pass. Otherwise report PARTIAL or
BLOCKED.

## Capability map

| Phase | Deliverable | Gate |
|---|---|---|
| 0 | baseline/topology and pre-existing failures | recorded HEAD/status/gates |
| 1 | ADR, invariants, API trust contract, threat model | independent rereview maps every invariant to proof |
| 2 | PostgreSQL/pgvector, Alembic, RLS, lineage | empty DB and cross-scope denial |
| 3 | all capture types, immutable storage, durable worker | idempotency, failure, restart, SSRF |
| 4 | FTS, vectors, deterministic RRF and filters | stable scoped retrieval and outage fallback |
| 5 | bounded Ask, citation validation, abstention | injection and fabricated-citation denial |
| 6 | proposal, approval, revision, supersession, purge | inactive-before-approval and deletion proof |
| 7 | Inbox, Library, Search, Ask, Memories, Today, Settings | keyboard/mobile real-persistence journey |
| 8 | logs, limits, migrations, build, docs, review | full verification matrix |

## Fixed slice and architecture

Use isolated `apps/second-brain/{web,service}`: currently supported Next.js on
Node 24/pnpm 9; FastAPI/Pydantic 2/SQLAlchemy 2/Alembic on Python 3.11+; real
PostgreSQL+pgvector; PostgreSQL durable jobs; local filesystem storage with an
S3 interface; OpenAI-compatible providers and deterministic fakes. Do not extend
`acgi-ai` or modify `gove-zone`. Future ACGS policy integration is the optional
local `PolicyDecisionPort.evaluate(context) -> pass|veto|unavailable` seam. It
accepts bounded metadata only; disabled is a no-op, enabled-unavailable fails
closed, and `pass` never overrides native checks.

Included inputs are note, Markdown, TXT, extractable PDF, DOCX, and one safe
public URL. Retrieval uses lexical and semantic top 50, RRF `k=60`, chunk-ID
tie-break. Ask defaults to eight chunks and 12,000 evidence characters.

Deferred: OCR, JS-rendered pages, crawling, production OIDC, concrete S3,
distributed workers, ANN indexing, mobile, extension, graph, autonomous actions,
automatic memory approval, live deployment, and remote ACGS adapter.

## Ordered tasks

Every task begins RED with its focused failing test/probe and ends GREEN with
that proof passing. No task may touch more than five files.

1. **Local operating boundary** — the five root-local scaffold files. RED: validator finds no local checks. GREEN: local instructions and visible-failure Makefile are detected.
2. **Architecture/trust records** — ADR, invariants, API contract, threat model, implementation log. RED: ownership/auth/citation/approval/purge/privacy rules unmapped. GREEN: every invariant names enforcement and proof, then a separate reviewer accepts the revision. This task remains incomplete until rereview.
3. **Workspace/dev wiring** — root `pyproject.toml`, `pnpm-workspace.yaml`, root `Makefile`, `compose.yaml`, service manifest. RED: packages unresolved. GREEN: uv/pnpm resolve and PostgreSQL+pgvector starts.
4. **FastAPI scaffold** — service init/config/api/errors/health test. RED: readiness absent. GREEN: safe database/storage/provider status.
5. **Identity/lineage migration** — Alembic config/env, first migration, DB module, migration test. RED: empty DB lacks any mandatory relation or policy. GREEN: the test independently asserts every mandatory relation, composite scope constraint, RLS policy, and append-only rule.
6. **Retrieval/memory migration** — content/retrieval/memory models, migration, constraint test. RED: invalid lineage accepted. GREEN: append-oriented constraints reject it.
7. **RLS principal scope** — principal, auth dependency, DB scope, RLS migration, isolation test. RED: spoofed headers/cookies, missing CSRF, production dev auth, or cross-scope SQL succeeds. GREEN: trusted verifier, secure session, CSRF, `SET LOCAL`, direct SQL, and API tests fail closed.
8. **Storage/hash contracts** — storage protocol/local adapter, ingestion contracts/hash, test. RED: traversal/hash drift. GREEN: UUID keys, streaming hash, atomic write/delete.
9. **Capture API** — source schema/service/router/app wiring/test. RED: note creates no lineage. GREEN: note/file/URL enqueue stable scoped records.
10. **Document parsers** — parser base/text/PDF/DOCX/test. RED: fixtures fail or exceed limits. GREEN: bounded extraction with locations.
11. **Safe URL ingestion** — URL policy/fetcher/HTML/error/test. RED: private/metadata/rebinding reachable. GREEN: every hop and limit validated.
12. **Chunking/job claims** — chunker, queue/contracts, lease migration, test. RED: drift/double claim. GREEN: stable offsets and `SKIP LOCKED` lease recovery.
13. **Model providers** — provider base/fake/OpenAI-compatible/status/test. RED: outage leaks, fake/local opens a socket, or remote sends excess evidence. GREEN: zero-egress local proof, remote allowlist capture, and bounded explicit unavailable behavior.
14. **Ingestion worker** — pipeline/worker/CLI/job route/test. RED: restart loses/duplicates. GREEN: idempotent resume and visible ready/failed state.
15. **Hybrid retrieval** — query/fusion/contracts/route/test. RED: unstable or cross-scope results. GREEN: scoped FTS/vector/RRF and lexical fallback.
16. **Source context** — context service/library route/schema/test. RED: citation cannot resolve. GREEN: exact passage plus bounded context and lineage.
17. **Ask evidence** — evidence/prompt/service/route/test. RED: injection changes contract, evidence is unbounded, or a factual statement lacks citations. GREEN: delimited bounded evidence, statement-level citation sets, separate commentary, sufficiency, and persisted run.
18. **Citation validation** — output contract/citations/fallback/service/test. RED: unretrieved citation or generated text on validation failure is accepted. GREEN: generation is suppressed and only independently cited bounded extractive fallback is allowed.
19. **Memory approval** — memory contracts/service/route/model/test. RED: proposal becomes active. GREEN: explicit approve/reject/edit with evidence.
20. **Revision and purge** — revisions/purge service/route/worker/test. RED: overwrite or stale retrieval. GREEN: append revision and complete purge.
21. **Organization and Today** — organize/today services/routes/test. RED: counts, ordering, ties, or empty states drift. GREEN: the five documented sections, counts, sort keys, hash selection, ties, and empty labels are exact.
22. **Policy port and logging** — port/contracts/hooks/logging/test. RED: `pass` bypasses ownership, citation, purge, or memory activation; enabled `unavailable` continues; or source appears in logs. GREEN: disabled no-op, enabled fail-closed veto/unavailable, native checks remain authoritative, and logs are content-free.
23. **Next.js scaffold** — package/config/tsconfig/layout/global CSS. RED: shell/build absent. GREEN: accessible SSR shell builds on Node 24.
24. **Web API/session** — API/types/session/provider status/test. RED: client selects trusted scope, bypasses CSRF, or swallows errors. GREEN: secure cookie session, same-origin CSRF, server scope, and explicit states.
25. **Inbox and Library** — pages/components/test. RED: capture/jobs inaccessible. GREEN: all capture modes and states work by keyboard.
26. **Source detail and Search** — pages/components/test. RED: ranks/context absent. GREEN: exact context and hybrid metadata visible.
27. **Ask and Memory UI** — pages/components/test. RED: invalid answer/proposal looks trusted. GREEN: statuses, citations, approval and lineage explicit.
28. **Today and Settings UI** — pages/nav/state/test. RED: required routes fail mobile/keyboard. GREEN: deterministic dashboard and provider/limit status.
29. **Real-persistence E2E** — Playwright config/journey, seed script/data/readme. RED: journey depends on mocks. GREEN: PostgreSQL, pgvector, worker, storage, fake models end to end.
30. **CI/full local gate** — workflow, local/root Makefiles, web/service manifests. RED: migration/security/E2E failure is non-gating. GREEN: all stacks and log scan gate.
31. **Product/trust docs** — README, environment, lifecycle, retrieval/citation, supported limits. RED: docs drift. GREEN: values match config/tests.
32. **Operations/limitations docs** — providers, deletion, backup/restore, limitations, ACGS boundary. RED: deferred systems implied implemented. GREEN: claims match evidence.
33. **Final independent verification** — no planned files. RED: any gate/review fails. GREEN: literal evidence, clean diff, correct boundaries, no overclaim.

## Required test mapping

1→9/12/14–16/29; 2→10/14/29; 3→8/9/14; 4→10/14/25;
5→13/15; 6→7/15; 7–8→7/15/18; 9→17; 10–11→18;
12–13→19; 14–15→20; 16→11; 17→12/14; 18→22/30;
19→5–7/30; 20→29.

## Verification commands

```bash
make -C apps/second-brain verify
make -C apps/second-brain migration
make -C apps/second-brain integration
make -C apps/second-brain restart-test
make -C apps/second-brain log-scan
make -C apps/second-brain accessibility
make -C apps/second-brain real-persistence
make -C apps/second-brain migration
cd apps/second-brain/service && uv run ruff check . && uv run ruff format --check .
cd apps/second-brain/service && uv run mypy src/second_brain && uv run pytest -q
fnm exec --using 24 pnpm --dir apps/second-brain/web lint
fnm exec --using 24 pnpm --dir apps/second-brain/web typecheck
fnm exec --using 24 pnpm --dir apps/second-brain/web test
fnm exec --using 24 pnpm --dir apps/second-brain/web build
fnm exec --using 24 pnpm --dir apps/second-brain/web exec playwright test
make verify
git diff --check
```

## Checkpoints

- After 1–7: contracts, migrations, and isolation pass before ingestion.
- After 8–14: one source is durable and restart-safe before retrieval.
- After 15–18: citation/abstention gates pass before memory work.
- After 19–22: memory and purge trust gates pass before UI.
- After 23–29: full primary journey passes with real persistence.
- After 30–33: all gates and independent review pass; otherwise stop with an honest non-PASS verdict.
