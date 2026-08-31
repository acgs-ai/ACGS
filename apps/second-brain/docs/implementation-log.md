# Implementation log

Append date, task, starting/ending HEAD, files, exact commands, literal results,
and unresolved failures. Separate pre-existing root failures from regressions.

## 2026-08-27 — Phase 1 architecture and plan scaffold

- Repository: `/home/martin/Documents/ACGS-wt/second-brain-v0.1`
- Branch: `feat/second-brain-v0.1`
- Starting HEAD: `cddf485a6c2558c06fe6fc46f576b17f7a3f55b9`
- Initial worktree: clean and equal to `origin/master`.
- Scope: documentation and local planning contract only.
- Product implementation: not started.
- Remote operations: none.
- Scope detector: `subdir-of-repo`, git root remained the isolated ACGS
  worktree, no sealed/generated files found in this new scope.
- Subproject validator: detected local `check`, `lint`, `typecheck`, `test`,
  `build`, and `verify` targets; no prohibited commands.
- `make -C apps/second-brain check`: expected non-zero result with
  `MISSING: service/pyproject.toml`; missing implementation is visible.
- `git diff --check -- apps/second-brain`: exit 0. Because the files remain
  untracked, a temporary-index attempt was made but the host returned
  `Disk quota exceeded`; a per-file `git diff --no-index --check` scan and
  trailing-whitespace scan then completed with no findings.

## 2026-08-27 — Independent review remediation

- Independent review did not accept Phase 1. Task 2 was reopened.
- Findings required concrete authentication modes, complete persistence/RLS
  gates, typed API and Ask contracts, privacy-preserving model egress, explicit
  product routes and Today ordering, and expanded local acceptance targets.
- Documentation and scaffold contracts were revised; backend and web runtime
  changes remained outside this writer lane.
- Phase 1 remains incomplete until a separate reviewer rereviews these changes.
- Per-file `git diff --no-index --check` and trailing-whitespace scans completed
  for the eleven writer-owned files with no findings.
- Local validation still detected the standard check/lint/typecheck/test/build/
  verify contract. The Makefile additionally defines migration, integration,
  restart, privacy-log, accessibility, and real-persistence targets.
- `make -C apps/second-brain check` exited 2 with
  `MISSING: web/package.json`; the backend manifest added by another lane was
  preserved and the absent web proof remains a visible failure.
- `git diff --check -- apps/second-brain` exited 0.

## 2026-08-27 — Tasks 3–7 backend foundation

- Added the pinned PostgreSQL 18/pgvector container, separate non-superuser
  runtime role, uv-locked FastAPI service, safe error/status routes, full minimum
  schema, composite lineage constraints, immutable provenance triggers, forced
  RLS, and loopback/signed principal verification.
- RED API probe: import failed because the service package did not exist. RED
  migration probe: required relations were absent. RED isolation probe: the
  registered source route did not exist. Each became GREEN after its increment.
- The migration test provisions only a guarded `second_brain_test_<uuid>` on
  loopback, checks exact tables/extensions/policies and up/down/up, then drops it.
  It does not downgrade the configured development database.
- `uv run ruff check .`: `All checks passed!`.
- `uv run ruff format --check .`: `10 files already formatted`.
- `uv run mypy src/second_brain`: `Success: no issues found in 5 source files`.
- `make service-verify`: ruff check/format, mypy, `13 passed in 1.09s`, and
  source/wheel build all passed against real PostgreSQL/pgvector.
- `make migration`: `1 passed in 0.62s`; no disposable test database remained.
- Live uvicorn smoke returned HTTP 200 with `status=ok` for health and
  `status=ready`, `database=available` for provider status.
- `make check`: expected non-zero result `MISSING: web/package.json`; Task 3 and
  the full-product gate remain incomplete until the web lane lands.
- Seeded private source content was absent from captured application access logs.
- No commit, push, deployment, or remote mutation was performed.
- P1 credential-boundary remediation removed all Compose/bootstrap credentials
  from runtime `Settings`. Owner-password keys now fail as unknown from both
  dotenv and process environment sources, and serialized settings expose only
  restricted service fields. Focused API/config tests passed `6 passed in
  0.28s`; final `make service-verify` passed ruff, formatting, mypy, `13 passed
  in 0.97s`, and both distribution builds.

## 2026-08-27 — Second Phase 1 documentation remediation

- Task 2 remains open pending a separate independent rereview.
- At that checkpoint, the canonical environment template was aligned to the
  then-implemented settings and Compose database role: development app
  environment, loopback-only
  development-header auth, `second_brain_app` on port 55439, filesystem
  storage, and fake models. Production secrets and unimplemented settings stay
  commented.
- The `migration` target calls only
  `cd service && uv run pytest -q tests/test_migrations.py`. The guarded harness
  requires a unique `second_brain_test_*` database on loopback and proves
  create, upgrade, assertions, downgrade, re-upgrade, assertions, and drop. No
  direct Alembic downgrade command remains in the local plan.
- The future local ACGS seam is now the concrete metadata-only
  `PolicyDecisionPort.evaluate(context) -> pass|veto|unavailable` contract.
  Disabled is a no-op, enabled-unavailable fails closed, and `pass` never
  overrides ownership, citation, purge, or memory-activation checks.
- No service, web, root, generated, sealed, commit, or remote state was changed
  by this writer remediation.
- Per-file `git diff --no-index --check` scan: `per-file no-index whitespace:
  PASS (12 files)`.
- Scope detector: `topology: subdir-of-repo`, git root
  `/home/martin/Documents/ACGS-wt/second-brain-v0.1`, and no sealed/generated
  files in this scope.
- Subproject validator detected local `make test`, `make lint`, `make check`,
  `make verify`, `make typecheck`, and `make build` commands.
- Direct migration downgrade scan: `direct migration downgrade command: absent`.
- `git diff --check -- apps/second-brain`: exit 0 with no output.
- `make -C apps/second-brain check`: exit 2 with
  `MISSING: web/package.json`; the intentionally incomplete web surface remains
  a visible failure and was not changed by this writer lane.
- Root `make lint-docs`: exit 0; governance stack index passed, 24 markdown
  links checked, and the AI governance hub validation passed for 26 files.

## 2026-08-27 — Compose secret-boundary remediation

- Task 2 remains open pending a separate independent rereview.
- Removed the Compose-only database-owner password, app-role bootstrap
  password, and published-port variables from the canonical service
  `.env.example`.
- Defined `.env` as the API runtime configuration containing only the
  restricted application-role URL and implemented API settings. Worker-only
  settings are now supplied separately under `SECOND_BRAIN_WORKER_*`; the
  worker intentionally does not load `.env`.
- Documented local-only inline Compose defaults and the optional untracked
  `.env.compose.local` override passed explicitly to Compose. It must never be
  sourced, exported, or read by the API or worker.
- No Compose, service, web, root, commit, or remote state was changed.
- Per-file no-index whitespace scan: `PASS (12 files)`.
- Compose-only runtime-key scan: `PASS`; `.env.example` contains none of
  `SECOND_BRAIN_DB_OWNER_PASSWORD`, `SECOND_BRAIN_DB_APP_PASSWORD`, or
  `SECOND_BRAIN_DB_PORT`.
- Subproject validator detected `make test`, `make lint`, `make check`,
  `make verify`, `make typecheck`, and `make build`.
- `git diff --check -- apps/second-brain`: exit 0 with no output.
- `make -C apps/second-brain check`: exit 2 with
  `MISSING: web/package.json`; the open web surface remains visible and Task 2
  remains pending rereview.

## 2026-08-27 — Compose ignore-boundary remediation

- Task 2 remains open pending one last independent rereview.
- Standardized the provisional Compose-local filename as `.env.compose.local`,
  which matches the repository `.env.*` ignore rule.
- Added `secret-boundary-check` as the first `check` prerequisite. It runs
  `git -C ../.. check-ignore -q apps/second-brain/.env.compose.local` and fails
  with a clear error before later missing-surface checks if the path is not
  ignored.
- No service, Compose, web, root, commit, or remote state was changed.
- Stale-name scan: `PASS`.
- `git check-ignore -v apps/second-brain/.env.compose.local` returned
  `.gitignore:3:.env.* apps/second-brain/.env.compose.local`.
- `make -C apps/second-brain secret-boundary-check`: exit 0 (`PASS`).
- Per-file no-index whitespace scan: `PASS (12 files)`; repository
  `git diff --check -- apps/second-brain` also exited 0 with no output.
- Subproject validator continued to detect the standard local test, lint,
  check, verify, typecheck, and build commands.
- `make -C apps/second-brain check` passed the ignore prerequisite, then exited
  2 at the later expected `MISSING: web/package.json` surface check.

## 2026-08-27 — Independent Phase 1 documentation approval

- Verdict: `APPROVE`; `P0=0`, `P1=0`.
- `secret-boundary-check` passed and proved `.env.compose.local` is Git-ignored.
- The reviewer confirmed the credential separation, guarded disposable-database
  migration contract, and metadata-only veto policy-port contract.
- Task 2 is complete. No other task status changed.

## 2026-08-27 — Fourth backend review remediation

- Corrected approved-memory revision semantics: proposal evidence remains
  anchored to immutable revision 1, while `current_revision_id` may advance to
  a later evidenced revision belonging to the same memory and tenant scope.
- Added app-role transaction coverage for activation through revision 1,
  advancement to revision 2, unchanged revision-1 lineage, and rejection of
  missing, foreign, mismatched, altered, or late evidence states.
- The existing persistent development volume contains an older unreleased
  `0001` shape. It was not changed, reset, migrated, or used as acceptance
  evidence. Manual development requires an explicit operator-authorized volume
  recreation; automated verification uses fresh guarded
  `second_brain_test_*` databases only.
- Checkpoint A remains open pending a fifth independent review. No commit,
  push, deployment, destructive volume operation, or remote mutation occurred.
- Focused revision-semantics RED probe failed because revision 2 was required
  to be revision 1; the corrected focused probe passed `1 passed in 0.40s`.
- `uv run ruff check .`: `All checks passed!`; formatting reported `16 files
  left unchanged`; full MyPy reported `Success: no issues found in 16 source
  files`; full Pytest reported `43 passed in 5.09s`.
- `make service-verify`: lint, formatting, complete MyPy, `43 passed in 5.13s`,
  source distribution, and wheel build all passed.
- `make migration`: the guarded fresh-database up/down/up proof reported
  `1 passed in 0.48s`; the real-socket launcher test separately reported
  `1 passed in 1.00s`.

## 2026-08-27 — Fifth backend review remediation

- Serialized proposal-evidence insertion against proposal decisions by locking
  the scoped proposal row `FOR SHARE` before checking that its status remains
  `proposed`. The lock conflicts with the approval update without weakening RLS
  or composite tenant constraints.
- A bounded two-connection PostgreSQL test covers both orderings. Evidence-first
  blocks approval until evidence commits; approval-first blocks evidence until
  approval commits, after which evidence observes `approved` and fails. The
  test also proves no decided proposal has committed evidence newer than its
  decision timestamp.
- Focused RED reproduced the race because approval completed before the open
  evidence transaction. Focused GREEN reported `1 passed in 0.84s`.
- Formatting reported `16 files left unchanged`; Ruff passed; complete MyPy
  reported no issues in 16 files; full Pytest reported `44 passed in 6.00s`.
- `make service-verify` passed lint, formatting, complete MyPy,
  `44 passed in 5.44s`, and both distribution builds. `make migration` reported
  `1 passed in 0.51s`; the live-socket launcher proof reported
  `1 passed in 1.00s`.
- The persistent development volume was not reset, migrated, or mutated. No
  commit, push, deployment, or remote mutation occurred. Checkpoint A remains
  open pending a sixth focused independent review.

## 2026-08-27 — Sixth backend review remediation

- Schema-qualified every application relation referenced by migration-defined
  invariant, trigger, and authentication functions. All ten functions now have
  catalog-audited `search_path=pg_catalog, public, pg_temp` configuration, with
  the temporary schema last.
- Upgrade revokes database `TEMPORARY` from both `PUBLIC` and
  `second_brain_app` using safely quoted dynamic SQL. Downgrade restores the
  PostgreSQL default `PUBLIC` grant, and the guarded up/down/up test proves the
  transition deterministically on a fresh disposable database.
- The migration test proves the application role cannot create a temporary
  shadow table, audits all function `proconfig` entries, and rejects any
  unqualified application-relation reference in function definitions.
- Focused fresh-migration plus two-order concurrency proof reported
  `2 passed in 1.29s`. Formatting left 16 files unchanged; Ruff passed; complete
  MyPy reported no issues in 16 files; full Pytest reported
  `44 passed in 5.45s`.
- `make service-verify` passed lint, formatting, complete MyPy,
  `44 passed in 5.60s`, and both distribution builds. `make migration` reported
  `1 passed in 0.52s`; the live-socket launcher test reported
  `1 passed in 1.01s`.
- The persistent development database and volume were not migrated, reset, or
  mutated. No commit, status change, push, deployment, or remote mutation
  occurred. Checkpoint A remains open pending a seventh independent review.

## 2026-08-27 — Task 17 shared citation-contract alignment

- Added stable `source_id` to each `retrieved_results` response entry.
- Required every grounded and extractive-fallback citation to match a persisted
  retrieval result on owner, workspace, source, and chunk and to remain
  accessible in the current scoped transaction.
- An inaccessible or mismatched citation now explicitly produces
  `validation_failed` and suppresses generated statements; only independently
  revalidated extractive passages may be returned as fallback.
- At this alignment point, Backend Task 17 still had to implement and test this
  contract; its final completion is recorded below. No service, web, root,
  task-status, commit, or remote state changed in this documentation pass.

## 2026-08-27 — Independent backend and web-foundation approvals

- Backend Tasks 4–7 and Checkpoint A received final independent `APPROVE` with
  `P0=0`, `P1=0`, `P2=0`, and `P3=0`.
- Backend evidence: complete MyPy over 16 source files, 44 passing tests, service
  lint/format/type/build verification, guarded migration proof, and live-socket
  launcher proof all passed.
- Web Tasks 23–24 received independent `APPROVE` with `P0=0`, `P1=0`, and one
  nonblocking `P2` for Task 17 citation membership. That dependency was later
  closed by completed Task 17, as recorded below.
- Web evidence: 25 unit tests, 38 Playwright tests, production build, and
  dependency audit passed.
- Task 3 remains incomplete because root pnpm workspace registration is not
  done. Tasks 25–29 remain incomplete because their product endpoints and
  real-persistence journey are unavailable.
- No service, web, root, commit, push, deployment, or remote state changed in
  this record-only pass.

## 2026-08-27 — Checkpoint B ingestion implementation handoff

- Implemented the review-stage backend ingestion increment without changing
  task or checkpoint status: opaque filesystem object storage; authenticated
  text, Markdown, upload, and URL capture; immutable source/version/job
  persistence; deterministic TXT/Markdown/PDF/DOCX/HTML extraction and
  location-aware chunking; PostgreSQL lexical indexing; model-provider
  boundaries; and a separate durable worker with skip-locked leases,
  heartbeat, retry/backoff, dead-letter, and restart reclaim behavior.
- Added offline URL controls for scheme/user-info/port validation, public-only
  DNS results, per-hop redirect revalidation, connection to the validated IP,
  peer binding, byte/type/time/redirect bounds, and private, loopback,
  link-local, metadata, redirect, and peer-mismatch rejection. No public
  network was used by the test suite.
- RED probes reproduced a PostgreSQL untyped-null idempotency bind failure,
  missing source `processing` transition, lost paragraph location for chunks,
  an uncaught malformed-PDF exception, and the new migration index assertion.
  Each focused probe passed after the corresponding fix.
- `make -C apps/second-brain service-verify` passed Ruff check and format,
  strict MyPy over `src`, `tests`, and `migrations`, `59 passed in 7.17s`, and
  source/wheel builds. `make -C apps/second-brain migration` passed the guarded
  fresh-database up/down/up proof (`1 passed in 0.54s`).
- The focused ingestion, URL, production-session, RLS, restart, launcher, and
  privacy set reported `33 passed in 3.62s`. The real-socket API plus one-shot
  worker smoke separately reported `1 passed in 1.42s` and verified persisted
  content without emitting its seeded private marker to API or worker logs.
- No-index whitespace validation passed for 89 nonignored Second Brain files.
  The final PostgreSQL query found no residual `second_brain_test_*` database,
  and the process query found no residual API or worker process. The existing
  persistent development database/volume was not migrated, reset, or mutated.
  No commit, push, deployment, or remote mutation occurred. At this handoff,
  Checkpoint B was pending independent review.

## 2026-08-27 — Checkpoint B final independent approval

- Tasks 8–14 and Checkpoint B received final independent `APPROVE` with
  `P0=0`, `P1=0`, `P2=0`, and `P3=0`. This approval supersedes the pending
  review status in the preceding implementation handoff.
- Capture stages now carry immutable, non-null `job_id` lineage constrained to
  the exact owner, workspace, source, and ingestion job. Reconciliation and
  abandonment act only on that job; they do not select another job by source.
- The focused review set reported `22 passed`. Its same-source regression proved
  that sweeping a stale stage for an old failed URL job abandons only that old
  stage while a newer queued job and its event history remain queued and
  unchanged.
- `make -C apps/second-brain service-verify` passed Ruff check and format,
  complete MyPy over 33 files, `124 passed`, and source/wheel builds.
  `make -C apps/second-brain migration` passed the guarded empty-database
  migration proof (`1 passed`).
- Final cleanup probes found no residual `second_brain_test_*` database and no
  residual API or worker process. The persistent development database and
  volume were not migrated, reset, or mutated.
- Repository and branch remained
  `/home/martin/Documents/ACGS-wt/second-brain-v0.1` and
  `feat/second-brain-v0.1`. Starting and ending HEAD were both
  `cddf485a6c2558c06fe6fc46f576b17f7a3f55b9`.
- No commit, push, deployment, or remote mutation occurred. At that approval
  point, Task 3, Tasks 15–22, and Tasks 25–33 remained incomplete; Tasks 23–24
  retained their earlier approved status.

## 2026-08-27 — Checkpoint C final independent approval

- Tasks 15–18 and Checkpoint C received final independent `APPROVE` with
  `P0=0`, `P1=0`, `P2=0`, and `P3=0`.
- The additive `0002_retrieval_answer_provenance.py` migration establishes
  database-enforced exact source-version, chunk-version, selected-evidence, and
  citation lineage without rewriting the approved `0001` foundation.
- Scoped lexical and exact-vector retrieval use deterministic RRF, and the
  source-context and Ask paths preserve bounded evidence, retrieval ranks, and
  validated source/chunk membership in real PostgreSQL persistence.
- Final remediation hardened explicit `provider_unavailable` results,
  server-owned system commentary, scoped answer idempotency, and embedding
  profile identity across provider, version, model, and dimensions.
- `make -C apps/second-brain service-verify` passed Ruff check and format,
  complete MyPy, `142 passed`, and source/wheel builds. The focused closure set
  reported `9 passed`.
- `make -C apps/second-brain migration` passed the guarded empty-database
  additive upgrade, full downgrade, and re-upgrade proof (`1 passed`).
- Final cleanup probes found no residual `second_brain_test_*` database and no
  residual API or worker process. The persistent development database and
  volume were not migrated, reset, or mutated.
- Repository and branch remained
  `/home/martin/Documents/ACGS-wt/second-brain-v0.1` and
  `feat/second-brain-v0.1`. Starting and ending HEAD were both
  `cddf485a6c2558c06fe6fc46f576b17f7a3f55b9`.
- No commit, push, deployment, or remote mutation occurred. At that approval
  point, Task 3, Tasks 19–22, and Tasks 25–33 remained incomplete; Tasks 23–24
  retained their earlier approved status.

## 2026-08-27 — Checkpoint D final independent approval

- Tasks 19–22 and Checkpoint D received final independent `APPROVE` with
  `P0=0`, `P1=0`, `P2=0`, and `P3=0`.
- The service wires project/tag organization, deterministic Today, proposed and
  approved memory lifecycle, source/memory purge, and purge-status routes.
  Proposed memory stays inactive until explicit approval, and meaning changes
  append revisions rather than overwriting history.
- Purge becomes retrieval-ineligible immediately, then a durable worker removes
  stored originals, extracted content, chunks, embeddings, and permitted memory
  meaning. Tests prove deterministic ordering for both approval-first and
  purge-first races and restart-safe completion without duplication or loss.
- The metadata-only policy port remains veto-only and fail-closed. Disabled
  policy is a no-op and creates no policy-decision audit row. When enabled,
  scoped append-only audit records preserve pass, veto, unavailable, and
  adapter-exception outcomes; `pass` cannot override native checks. Purge and
  logging reason codes are constrained to bounded allowlists, with legacy values
  safely normalized during migration.
- `make -C apps/second-brain service-verify` passed Ruff check and format,
  complete MyPy, `179 passed`, and source/wheel builds.
- `make -C apps/second-brain migration` reported `2 passed` for guarded
  empty-database up/down/up plus legacy-reason normalization. The dedicated
  `restart-test` reported `3 passed`, `log-scan` reported `9 passed`, and
  `makefile-regression` passed.
- Final cleanup probes found no residual `second_brain_test_*` database and no
  residual API or worker process. The persistent development database and
  volume were not migrated, reset, or mutated.
- Repository and branch remained
  `/home/martin/Documents/ACGS-wt/second-brain-v0.1` and
  `feat/second-brain-v0.1`. Starting and ending HEAD were both
  `cddf485a6c2558c06fe6fc46f576b17f7a3f55b9`.
- No commit, push, deployment, or remote mutation occurred. Task 3 and Tasks
  25–33 remain incomplete; Tasks 23–24 retain their earlier approved status.

## 2026-08-27 — Final documentation and environment alignment

- Reconciled the README, environment template, API contract, invariants, threat
  model, ADR status, web harness notes, and synthetic demonstration data with
  the implemented service, worker, web runtime, Makefile, and migrations.
- Removed the obsolete `SECOND_BRAIN_MODEL_API_KEY` example. The documented
  provider boundary now uses API-only `SECOND_BRAIN_ANSWER_API_KEY` and
  `SECOND_BRAIN_ANSWER_GENERATION_MODEL`, worker-only
  `SECOND_BRAIN_WORKER_MODEL_API_KEY`, and matching API/worker embedding profile
  version and semantic-answer threshold settings.
- Implementation inspection confirmed additive migration
  `0006_answer_adequacy`: the nullable `[-1,1]` semantic-only answer threshold is
  stored with an append-only embedding profile and is immutable after insert.
  Missing calibration, below-threshold evidence, or API/worker profile drift
  abstains before generation; recalibration requires a version bump and
  re-ingestion.
- Existing focused backend proofs cover crash recovery after retrieval and a
  concurrent same-idempotency-key race. PostgreSQL advisory locking allows an
  unrelated scoped search to proceed, invokes generation once, and makes the
  losing request reload the winner's answer ID. This documentation lane
  inspected those tests but did not rerun the database-backed suite.
- Root `make lint-docs` passed: governance stack index, 24 internal markdown
  files, and 26 AI-governance documentation files. A Second Brain-local link
  scan passed, the env/config consistency scan passed with no obsolete or
  unknown documented keys, and the two-record demo JSON validated.
- Make dry-runs resolved every documented service, migration, restart, logging,
  accessibility, real-persistence, and aggregate verification command. pnpm
  exposed each documented web script. Per-file no-index whitespace checks
  passed for the ten documentation/environment/example files.
- No full application gate, persistent database operation, process launch,
  commit, push, deployment, or remote mutation occurred. Tasks 25–29,
  Checkpoint E, and the remaining task states were not changed. Repository HEAD
  remained `cddf485a6c2558c06fe6fc46f576b17f7a3f55b9`.

## 2026-08-28 — Product UI, Checkpoint E, and closeout-task approvals

- Task 3, Tasks 25–32, and Checkpoint E received independent approval. Task 33
  remains open for the separate final verifier.
- Root pnpm workspace registration and the path-filtered Second Brain workflow
  were reviewed and approved. This is repository-local configuration evidence;
  no GitHub-hosted Actions run is claimed.
- Web review findings were remediated and approved across Inbox, Library, source
  detail, Search, Ask, Memory Review, Today, and Settings. The canonical Search
  contract remains one response envelope containing `results` and the
  envelope-level `semantic_status`.
- Three independent real-persistence browser runs each passed `6/6` without
  retries. These runs supplied Checkpoint E evidence for the desktop/mobile
  keyboard journey without mocked persistence.
- Review found a memory-purge router defect; the defect was fixed and the
  resulting route wiring was independently approved.
- An aggregate verification attempt failed before a leaking service test fixture
  was corrected. That failure is retained as intermediate defect evidence, not
  treated as final gate evidence. After the fixture fix, the complete service
  suite reported `193 passed`.
- The CI and documentation changes received independent rereview approval. No
  root-wide gate, clean-worktree state, commit, push, deployment, remote
  mutation, or GitHub-hosted CI result is claimed by this record.

## 2026-08-28 — Final independent verification

- Task 33 is complete. The final overall verdict is `PARTIAL`, not a product
  `PASS` or a production-readiness claim.
- `make -C apps/second-brain verify` passed. Its evidence included 193 service
  tests, 86 web tests, 40 browser tests, 2 migration tests, 3 restart tests,
  9 privacy-log tests, 20 accessibility tests, and 2 real-persistence tests,
  together with the required service/web builds and production dependency
  audit.
- Root `make verify` did not reach the Second Brain gate. It failed earlier on
  three uninitialized private nested repositories, the available Node 22
  runtime rather than the required Node 24 runtime, and a missing `turbo`
  executable. These root-workspace blockers prevent an overall `PASS`; they do
  not invalidate the passing package-local gate.
- The worktree remained dirty and uncommitted. Starting and ending HEAD were
  both `cddf485a6c2558c06fe6fc46f576b17f7a3f55b9`. No push, deployment, or
  other remote change was performed.

## 2026-08-28 — Release-candidate proxy and worker-recovery evidence

- The same-origin proxy request envelope was aligned with the service at
  12,000,000 bytes and one absolute 10-second deadline. A stalled request now
  returns the structured retryable `408 request_body_timeout` response before
  Next's post-response lifecycle cancels the reader; the temporary 0600 spool
  is removed and the request is never forwarded upstream.
- The focused RED run
  `fnm exec --using 24 pnpm --dir web test -- src/lib/bounded-body.test.ts`
  initially reported `2 failed, 4 passed`: the old 26,214,400-byte constant and
  the unbounded stalled reader. After the patch it reported `6 passed`.
- The real dispatcher probe
  `fnm exec --using 24 pnpm --dir web exec playwright test tests/foundation.spec.ts --grep 'times out a stalled'`
  reported `2 passed` across desktop and mobile with Playwright retries set to
  zero. The raw TCP request proved the 408 body, zero upstream mutations, and
  no residual proxy spool.
- The real-persistence harness now begins with no worker, observes the browser's
  persisted queued job, runs a separate claimant process, kills that process,
  waits for lease expiry, and starts a distinct production worker CLI. It
  verifies ordered queued/claimed/reclaimed/ready events, exactly one
  document/chunk/embedding lineage, two claims, and zero processing retries.
  The existing killed-claim subprocess regression is included in
  `make restart-test`; its focused run reported `1 passed in 4.98s`.
- The first new `make real-persistence` run correctly failed closed because the
  harness queried a nonexistent direct `documents.source_id` column. The
  harness-only assertion was corrected to follow `documents.source_version_id`
  through immutable source versions. A fresh rerun rebuilt service and web,
  migrated a new disposable database, used a new filesystem store, and reported
  `2 passed` for the desktop/mobile primary journey. This was a diagnosed
  harness correction, not a retry used to mask product flakiness.
- `make real-persistence` now depends on `build`, so a standalone acceptance run
  cannot silently reuse a stale Next production build. Web lint, type checking,
  the focused unit suite, and the production build passed after the changes.
- Independent rereview found that the recovery event's five-second wait result
  was ignored and that a clean `make verify` could reach foundation Playwright
  before the Next production build. Focused RED tests reproduced both gaps: the
  harness tests raised two missing-guard errors, and `make makefile-regression`
  reported `make verify does not build web before browser tests`.
- The harness now requires the recovery event, joins the coordinator thread,
  rejects a still-live coordinator, and propagates recorded coordinator errors
  before cleanup, privacy scanning, or a green exit. Its focused privacy and
  recovery suite reports `3 passed`.
- The package `test` target now depends on `build`. The Make regression inspects
  the authoritative dry-run and reported the production web build at line 20,
  before foundation Playwright at line 23. Standalone real persistence retains
  its build dependency.
- A new fresh `make real-persistence` run rebuilt service and web, migrated a
  new disposable database, created a new filesystem store, ran the joined
  killed-worker recovery proof, and reported `2 passed` across desktop and
  mobile with zero Playwright retries.
- Final rereview established that Playwright could ignore a nonzero web-server
  teardown exit. Focused RED tests reported two missing harness guards: no
  bounded recovery-status state and no cleanup-time spawn rejection.
- The harness now serves only `pending`, `success`, or a content-free error code
  from a dedicated loopback port. Success is published only after the recovery
  coordinator has terminated and its exact event/count assertions have passed.
  The primary browser journey explicitly awaits this status and fails
  immediately on terminal error, so teardown behavior cannot convert a failed
  recovery proof into green browser evidence.
- Recovery and status threads are non-daemon. Child registration and cleanup
  use one lock, cleanup freezes the registered process set, and later spawns are
  rejected. The focused harness suite reports `6 passed`; web lint and type
  checking pass.
- A fresh post-fix `make real-persistence` rebuilt the service and production
  web application, migrated another unique disposable database, used a new
  filesystem store, and reported `2 passed` across desktop and mobile in 23.3
  seconds with Playwright retries still zero.
- A final cleanup review found that the harness could spend 35 seconds joining
  recovery before terminating `start_new_session` children, exceeding
  Playwright's 15-second graceful-shutdown window. The focused RED regression
  failed because no bounded process-and-thread cleanup primitive existed.
- Cleanup now atomically freezes child registration, signals every registered
  process group first, escalates to `SIGKILL` after a shared grace period, and
  reaps processes plus recovery, status, and log-reader threads within one
  eight-second deadline. Database polling and startup URL waits are stop-aware,
  and any remaining process group or thread is reported as a cleanup failure.
- The new strong cleanup regression starts a real SIGTERM-ignoring subprocess
  with a loopback listener, proves the process group is killed and its port is
  released within the budget, and joins its output reader. The focused harness
  suite reports `7 passed`.
- A fresh `make real-persistence` run rebuilt both production artifacts and
  reported `2 passed` across desktop and mobile in 22.6 seconds with zero
  retries. After teardown, ports 3302, 3320, and 3321 were all closed.

## 2026-08-28 — Release-candidate independent audit, precommit evidence

- The authoritative precommit `make -C apps/second-brain verify` gate passed.
  It reported 198 service tests, 88 web unit tests, 42 default Playwright tests
  comprising 22 foundation and 20 accessibility tests, 2 migration tests,
  1 integration test, 4 restart tests, 9 privacy-log tests, 7 harness tests,
  and 2 separately executed real-persistence primary-journey browser tests. The
  production web dependency audit reported zero vulnerabilities, and Playwright
  used zero retries.
- A full locked Python dependency audit resolved `pydantic-settings==2.14.2`
  and `pytest==9.0.3` and reported zero known vulnerabilities.
- Root `make verify` was run with Node 24, a patched temporary Turbo 2.10.12,
  and the pinned `acgs-lite`, `Acgs-Swarm`, and `clinicalguard` submodules
  initialized. Second Brain JavaScript lint passed. The root gate then failed
  with 116 Ruff errors in unchanged `acgs-cft-governance-pack` and
  `acgs_governance_eval_mvp` paths. This is a root-integration failure, not a
  package-local acceptance failure.
- URL provenance documentation now matches persistence: a URL source may have
  a null exact-byte hash and object reference at capture while its normalized
  URI hash provides scoped idempotency. Successful processing binds the exact
  fetched bytes, hash, object, final URI, redirects, and peer to append-only
  source-version and URL-fetch provenance.
- The independent audit retained three nonblocking P2 limitations: proposed
  memory evidence has chunk/source/version lineage but no direct answer or
  retrieval-run foreign key; source-purge content-free tombstones are not
  exposed in memory detail; and the inverse `abandon_capture_stage`
  stage-to-job versus sweeper job-to-stage lock order can rarely deadlock.
  PostgreSQL makes that deadlock visible by aborting one participant, and the
  operation remains retryable/recoverable.
- GitHub-hosted CI was not run. Production readiness is not claimed. This
  precommit record does not claim a committed or clean baseline, and this
  documentation pass performed no staging, commit, push, deployment, or remote
  mutation.
- Documentation validation passed: `make test-docs` reported `122 passed,
  5 skipped` with one existing dynamic-swarm submodule warning, and
  `make lint-docs` passed the governance stack index plus 24-file internal-link
  and 26-file AI-governance documentation checks. The four-file documentation
  diff also passed `git diff --check`.
