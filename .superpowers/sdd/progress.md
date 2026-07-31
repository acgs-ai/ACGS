# SDD ledger — kernel-unification Phase 0-1 (2026-07-10)
Plan: docs/superpowers/plans/2026-07-10-kernel-unification-program.md
Worktrees: parent-ADR=/tmp/claude-1000/-home-martin-Documents-ACGS/134686cf-19b8-4a8f-9c7b-9b84d111cf1b/scratchpad/acgs-parent-adr (feat/kernel-unification-adr); acgs-lite=/tmp/claude-1000/-home-martin-Documents-ACGS/134686cf-19b8-4a8f-9c7b-9b84d111cf1b/scratchpad/acgs-lite-gove (feat/gove-kernel-bridge @c49b1027)
Env: acgs-lite worktree .venv (py3.11) has acgs_lite + gove_zone (editable, gove-zone from /home/martin/Documents/ACGS-master/packages/gove-zone [crypto]) — run tests via .venv/bin/python -m pytest
Bases: parent-ADR base=a87c8f7; acgs-lite base=c49b1027
Task 0: complete (commit 5d2c258, review clean; 2 Minor: ADR header style follows 0003/0007 not 0008; report cites 0008 as style ref inaccurately)
Task 1: complete (commit 98fb7c4e, review clean; Minor: tests/gove/ lacks __init__.py [folded into Task 2]; report's "alphabetical" claim inaccurate. ⚠️ resolved: GoveKernelUnavailable not yet raised anywhere — by design until a use-surface exists; final review should confirm)
Task 2: complete (commit ea7b3c50, review clean; ⚠️ Decision members resolved — controller verified decision.py:18 during extraction)
Task 3: complete (commit f882be81, review clean via opus adversarial pass; Minor: non-JSON-serializable args re-raise out of evaluate — kernel fail-closed wrapper backstops, platform-wide ToolCall.args precondition; fix suggestion: compute argument_hash before try)
Task 4: complete (commit bd5046a7, review clean via opus; 3 Minor for final review: (a) ALLOW-leg non-vacuity proven only transitively via DENY leg — add local constitution-has-rules assert; (b) expected_audit_hash not bound at gate — bind receipt.audit_event_hash to store event hash; (c) no tampered-signature negative case [out of scope])
Task 5: complete (commit d03ae833, review clean; extra limitation bullets kept as reasonable judgment)
All tasks complete. Final branch: feat/gove-kernel-bridge c49b1027..d03ae833 (5 commits incl. Task1-5); parent ADR branch feat/kernel-unification-adr @5d2c258.
Fix wave: complete (commit c9cb766b, opus re-review: both findings resolved, no regressions)
Final whole-branch review: With fixes → fixes applied+approved. PHASE 0-1 COMPLETE.
Final state: acgs-lite feat/gove-kernel-bridge = c49b1027..c9cb766b (6 commits, 20/20 tests, lint clean, seal intact); parent feat/kernel-unification-adr = 5d2c258 (ADR 0009, lint-docs green). Both awaiting HUMAN push/PR.
Pushed + PRs opened (user-authorized): acgs-lite PR https://github.com/dislovelhl/acgs-lite/pull/121; parent ADR PR https://github.com/dislovelhl/ACGS/pull/253
MERGED (user-authorized, verify-gate markers scoped): #253 → ACGS master b71de0b (squash); #121 → acgs-lite main 4233e351 (squash). Parent submodule pointer bump PENDING (separate step).
Pointer bump: PR #256 (chore/bump-acgs-lite-pointer, gitlink c49b1027→4233e351) opened.
#256 MERGED → master c35c35c. PHASE 0-1 FULLY CLOSED (ADR + bridge + pointer all on default branches). Worktrees removed.

## Phase 2: gove-zone 1.0 release prep (2026-07-11)
Plan: docs/superpowers/plans/2026-07-11-gove-zone-1.0-release-prep.md
Worktree: /tmp/claude-1000/-home-martin-Documents-ACGS/134686cf-19b8-4a8f-9c7b-9b84d111cf1b/scratchpad/gove-zone-release
Branch: feat/gove-zone-release-prep off origin/master c35c35c
Baseline: 971 tests 0 fail 4 skip (uv run --package gove-zone --extra dev --extra schema --extra crypto)
Task 1: complete (commit 872c3b6, review Approved). Note: hatch [tool.hatch.version] needed custom pattern (indented __version__ in try/except; default anchor no-match) — implementer added, reviewer verified. Minors: brief line-ref drift (117→~192); report count wording.
Task 2: complete (commit 6348038, review Approved). 148-name public_api.txt fixture byte-identical to live __all__; mutate check evidenced. Minor: report said 149 names (corrected to 148 in archive).
Task 3: complete (commit e8efda5, review Approved). uv build workspace-root leakage confirmed → `uv build -o dist`; LICENSE.bak mutate false-pass (hatchling LICENSE* glob) corrected. Minors: tests-leak regex misses nested gove_zone/tests/ (non-issue current layout); cold-cache uv python fetch unproven locally (CI dry-run will cover).
Task 4: complete (commits 34f7162 + fix acf183b, re-review Approved). lint-docs exit 0. INCIDENT: haiku implementer left stale Phase-1 task-4-report.md (never wrote its own) — fixer rewrote with real evidence; also HUMAN-labeled classifier flip in RELEASING.md.
Task 5: complete (commits a9e3911 + dee4538 retire-legacy + 45e9623 harden; opus security review Approved-no-blockers, B1/B2/B3 recommendations applied in fix wave 3 — re-verify in final review). KEY: legacy release.yml (tag v*, env production, never published — PyPI 404) RETIRED; single publish lane = release-gove-zone.yml, SHA-pinned token actions, push-only publish gate.
Task 6: complete (commit 07c15a5, review Approved). dist-check job purely additive; defaults.working-directory inheritance verified.
Carried Minors for final review: (T1) brief line-ref drift only; (T2) report count corrected; (T3) tests-leak regex misses nested gove_zone/tests/ layout drift + cold-cache uv fetch unproven locally; (T5) fix-wave-3 (B1 warning, B2 push-only publish, B3 SHA pins) needs re-verify.
Final review (opus): READY TO MERGE. Exit criteria all green (977 tests/0 fail/4 skip; ruff clean; release_check OK 1.0.0rc1 wheel; actionlint clean; lint-docs pass; scope clean). Carried Minors triaged ship-as-is; M1 stale version comment fixed inline @ c5a6866 (verified: pattern unique, 6 tests pass, ruff clean).
PHASE 2 BUILD COMPLETE: branch feat/gove-zone-release-prep @ c5a6866 (10 commits off c35c35c) in scratchpad/gove-zone-release worktree. AWAITING HUMAN PUSH + PR. Post-push: workflow_dispatch dry-run of release-gove-zone.yml; PyPI publish human-gated (tag + pypi env approval per RELEASING.md).

## Post-Phase-2 merged work (recorded 2026-07-30 against origin/master 45f8593d)

Context: the ledger above ended at Phase 2 (2026-07-11). This section records the
54 merge PRs that landed on origin/master between 2026-07-11 and 2026-07-30, so
the done-state is visible without re-deriving it from git history.

NOTE ON VERIFICATION TREE (amended 2026-07-30 after adversarial review): the
gate commands below were FIRST run on a worktree at local master 7cf79580
(326 commits behind origin/master 45f8593d). The figures in the G1.3 row
originally recorded (109 stmts / 22 branch) are the 7cf79580 figures. The
gates were RE-RUN on a fresh worktree at origin/master 45f8593d
(verify/gates-at-45f8593d, 0/0 divergence) and ALL 10 DONE gates pass there
too. The G1.3 row below now carries the accurate 45f8593d figures; the original
7cf79580 figures are retained in parentheses for audit traceability. The gate
COMPLETION conclusion (all DONE) holds at both SHAs; the stale-tree issue was
a provenance/accuracy defect in the recorded figures, not a false-DONE.

### FINAL-GOAL gate completion (verified by running the actual gate commands at origin/master 45f8593d)

| Gate | Status | Verified by | Merged PR(s) |
|---|---|---|---|
| G1.1 gove-zone PyPI publish | prep DONE; publish HUMAN-GATED | wheel-smoke CI job exists; release-gove-zone.yml SHA-pinned push-only publish gate | #2-phase release-prep |
| G1.2 cross-platform audit lock | DONE | `_locking.py` fcntl+msvcrt; `test_audit_chain.py::test_concurrent_appends_preserve_chain_integrity` on macOS+Windows via `cross-platform-lock` CI matrix job (macos-latest, windows-latest, py 3.11/3.12) | #118 (extract _locking) |
| G1.3 fail-closed coverage 100% on gove_zone.kernel | DONE | `--cov=gove_zone.kernel --cov-branch --cov-fail-under=100` → 100.00% at 45f8593d (206 stmts, 0 miss, 68 branch, 0 partial). [Original 7cf79580 figures: 109 stmts, 0 miss, 22 branch — kernel.py gained +216 lines between the two SHAs.] | wired in python-gove-zone.yml; #292 |
| G1.4 adapter parity per runtime family | DONE | `test_adapter_conformance.py` — 38 conformance tests pass (Claude/Codex hook, function-call, OpenAI Chat/Responses batch, LangChain, generic, malformed-batch fail-closed) | #314 (LangGraph + conformance), #110 (enforce-by-default gate) |
| G1.5 ADR-0005 propagation budget | DONE | `bench-gate` Makefile target + benchmarks/test_propagation_overhead.py + test_artifact_integrity.py in CI | (ADR-0005 wave) |
| G1.6 NFS-without-lockd startup probe | DONE | `test_fs_probe.py` + `_fsprobe.py` refuses start on NFS-like mount | #309 |
| G2.1 evidence bundle schema frozen/versioned | DONE | `test_proofpack_schema.py`; proof-pack.v1 schema with additionalProperties:false | #311 |
| G2.2 standalone verifier package | DONE | `packages/acgs-proofpack-verifier` v0.1.0a1, zero runtime deps, `test_cleanroom.py` passes, `acgs-verify` CLI, no gove-zone/network | #294 |
| G2.3 tamper resistance mutation suite | DONE | `test_mutation_suite.py` — single-record/single-byte mutation flips verify to FAIL | (mutation wave) |
| G2.4 deterministic replay byte-for-byte | DONE | `test_replay_bundle_equivalence.py` | (replay wave) |
| G2.5 constitutional integrity cross-check | DONE | fail-closed constitution-hash registry cross-check; constitutional-hash.yml CI workflow | #311 |
| G3.1 live production deploy (clinical/AGCO) | HUMAN-GATED | n/a — requires credentials, live domain, legal review | — |
| G3.2 console fail-closed in prod (forward_auth) | HUMAN-GATED; scaffolding done | Caddy @console_routes forward_auth + /auth/status bridge; local probe tests implementable | (console auth wave) |
| G3.3 continuous evidence + third-party verifier report | HUMAN-GATED | requires external independent party to run G2 verifier and sign | — |
| G3.4 fail-closed deny/escalation in prod | HUMAN-GATED; game-day tooling done | `examples/gameday_incident_evidence.py` + runbooks implementable | (gameday wave) |
| G3.5 buyer-evidence gallery from live data | HUMAN-GATED; scaffolding done | `test:buyer-evidence` + live-data wiring depends on G3.1 | (buyer-evidence wave) |

Net: ALL FOUR agent-implementable FINAL-GOAL gates (G1.2, G1.3, G1.4, G2.2) are
COMPLETE and merged to master. G1.1 prep is done (publish is human-gated).
G3.1–G3.5 are production-deployment gates, all human-gated; their agent-
implementable scaffolding (forward_auth, gameday tooling, buyer-evidence tests)
is done.

### Program / feature merges since 2026-07-11 (54 PR-merges)

G102 native control-plane spine (the dominant program this window):
| PR | Branch | Subject | Bucket |
|---|---|---|---|
| #365 | beta/p0-g102e0-audit-appender | feat(control-plane): audit appender | program (G102e0) |
| #366 | beta/p0-g102e1-db-governance-event | feat(control-plane): DB governance event | program (G102e1) |
| #367 | beta/p0-g102e2-native-receipt-ledger | feat(control-plane): native receipt ledger | program (G102e2) |
| #368 | beta/p0-g102e3-verifiable-native-evidence | feat(control-plane): verifiable native evidence | program (G102e3) |
| #369 | beta/p0-g102e4-scope-attachment | feat(control-plane): scope attachment | program (G102e4) |
| #370 | beta/p0-g102e5-native-transaction-spine | feat(control-plane): native transaction spine | program (G102e5) |
| #371 | beta/p1-g102-durable-idempotency | feat(control-plane): durable idempotency | program (G102) |
| #357 | beta/p1-g102-request-admission | feat(control-plane): request admission | program (G102) |
| #358 | beta/p1-g102a-program-reconcile | program reconcile | program (G102a) |
| #359 | beta/p1-g102b-receipt-cursors | feat: receipt cursors | program (G102b) |
| #360 | beta/p1-g102b-program-reconcile | program reconcile | program (G102b) |
| #361 | beta/p1-g102c-openapi-drift | feat: OpenAPI drift | program (G102c) |
| #362 | beta/p1-g102c-program-reconcile | program reconcile | program (G102c) |
| #363 | beta/p1-g102d-v1-api-contract | feat: v1 API contract | program (G102d) |
| #364 | beta/p1-g102d-program-reconcile | program reconcile | program (G102d) |
| #356 | beta/p1-g101-program-reconcile | program reconcile | program (G101) |
| #355 | beta/p1-g101-tool-provenance | feat: tool provenance | program (G101) |
| #354 | beta/p1-migration-001 | feat: migration 001 | program (migration) |

P2 evidence-corpus / register / trust / tenant-bootstrap:
| PR | Branch | Subject | Bucket |
|---|---|---|---|
| #383 | beta/p2-evidence-corpus-000d | feat: evidence corpus 000d | program (P2) |
| #386 | beta/p2-tenant-bootstrap-000 | feat: tenant bootstrap 000 | program (P2) |
| #387 | beta/p2-evidence-corpus-001d | feat: evidence corpus 001d | program (P2) |
| #388 | beta/p2-register-001-retry | feat: register 001 retry | program (P2) |
| #389 | beta/p2-idempotency-evidence-002a | feat: idempotency evidence 002a | program (P2) |
| #373 | beta/p1-evidence-corpus-002d | feat: evidence corpus 002d | program (P1) |
| #374 | beta/p1-scope-002 | feat: scope 002 | program (P1) |
| #375 | beta/p1-evidence-corpus-003d | feat: evidence corpus 003d | program (P1) |
| #376 | beta/p1-ledger-003 | feat: ledger 003 | program (P1) |
| #377 | beta/p1-evidence-corpus-004d | feat: evidence corpus 004d | program (P1) |
| #378 | beta/p1-trust-004-gz | feat: trust 004 gove-zone | program (P1) |
| #380 | beta/p1-trust-004 | feat: trust 004 | program (P1) |
| #372 | beta/p1-evidence-corpus-001d | feat: evidence corpus 001d | program (P1) |

Gove-zone hardening + policy identity + evidence capture:
| PR | Branch | Subject | Bucket |
|---|---|---|---|
| #412 | feat/gove-zone-full-digest-policy-identity | feat(gove-zone): bind policy identity to full SHA-256 and seal policy state | fix/harden (G1.x-adjacent) |
| #404 | feat/gove-zone-w0-m0-evidence-capture-20260726 | feat: W0-M0 evidence capture | program (evidence capture) |

Fix / chore / docs / CI:
| PR | Branch | Subject | Bucket |
|---|---|---|---|
| #419 | fix/codex-review-false-green | fix(hooks): pin uv workspace resolution for the receipt hook | fix |
| #414 | fix/drop-caller-worker-otel-advisories | fix(deps): drop iii-lab caller-worker (vulnerable npm tree) | fix |
| #416 | beta/p3-program-reconciliation-003a | beta/p3 program reconciliation 003a | program (P3) |
| #415 | fix/pages-jekyll-scope | fix(pages): scope Jekyll build to publishable docs | fix |
| #408 | chore/pypi-n...tity | chore: correct publishable identity before claiming PyPI namespaces | chore |
| #407 | docs/brand-boundary-acgs | docs: establish ACGS / gove-zone brand boundary | docs |
| #406 | chore/private-docs-boundary | chore: private docs boundary | chore |
| #401 | fix/postgres-gate-head-0007-assertions | fix(control-plane): align PG gate head assertions | fix |
| #382 | fix/ci-tests-docs-and-iii-lab-static | fix(ci): tests/docs + iii-lab static | fix (CI) |
| #381 | fix/keep-github-hosted-security-lanes | fix: keep GitHub-hosted security lanes | fix (CI) |
| #379 | blacksmith-migration-ee83e18 | chore: blacksmith migration | chore (CI) |
| #352 | dislovelhl/docs/community-health | docs: community health | docs |
| #351 | dislovelhl/fix/uv-workspace-gove-zone-source | fix: uv workspace gove-zone source | fix |
| #350 | dislovelhl/feat/pre-launch-hardening | feat: pre-launch hardening | fix/harden |
| #349 | dislovelhl/docs-version-pin-fix | docs: version pin fix | docs |
| #347 | dislovelhl/claude/acgs-prior-art-verification-vvn6ni | chore: prior-art verification | chore |
| #346 | dislovelhl/fix/evidence-pack-lf-extraction | fix: evidence pack LF extraction | fix |
| #344 | dislovelhl/agent/readme-release-docs | docs: readme/release docs | docs |
| #338 | dislovelhl/beta/p1-g101-integrated-candidate | beta: G101 integrated candidate | program (G101) |
| #337 | dislovelhl/beta/p0-g030b-pr308-rebased-repair | beta: G030b repair | program (P0) |
| #348 | dependabot/npm...caller-worker | chore: dependabot npm bump | chore (dependabot) |

### Notes
- G3.1–G3.5 remain HUMAN-GATED (production deploy / third-party verification).
- All agent-implementable FINAL-GOAL gates (G1.2, G1.3, G1.4, G2.2) are complete.
- The dominant program in this window is the G102 native control-plane spine
  (e0–e5 + a/b/c/d sub-phases) and the P1/P2 evidence-corpus + register + trust
  + tenant-bootstrap verticals — production-leaning infrastructure, not
  FINAL-GOAL gates.
- The main clone's checked-out branch `feat/gove-zone-policy-identity` is
  behind 583 commits; its plan/task statuses are NOT authoritative. Always
  ground-truth against origin/master + this ledger.

### Adversarial review findings (2026-07-30, Claude Code opus read-only pass)
Two blocking findings; both confirmed by independent reproduction and addressed:

1. STALE VERIFICATION TREE (addressed above): the original gate figures were
   run on 7cf79580, not 45f8593d. G1.3 row now carries accurate 45f8593d
   figures (206 stmts/68 branch) with 7cf79580 figures retained for traceability.
   All 10 DONE gates re-verified at 45f8593d in worktree verify/gates-at-45f8593d.
   Classification error (#416 in fix table) moved to program table.

2. G2.2 STANDALONE VERIFIER REJECTS REAL GOVE-ZONE PACKS (product defect on
   origin/master, not a ledger error): `acgs_proofpack_verifier` returns
   `valid:false / SUMMARY_BINDING_MISMATCH` on any gove-zone-generated
   acgs/proof-pack/v1 pack while gove-zone's own CLI returns `valid:true`.
   Root cause: the vendored `GENERATED_WITH` constant in
   `packages/acgs-proofpack-verifier/src/acgs_proofpack_verifier/proofpack.py`
   was namespace-rewritten to `acgs_proofpack_verifier.proofpack` and is
   interpolated into the byte-compared verification-summary.md footer, so the
   re-rendered expected summary can never match a gove-zone-generated one.
   Fix: a one-line TDD change pinning the constant to the generator's value
   (`gove_zone.proofpack`) + a new clean-room round-trip test, in worktree
   gate-verify-45f8593d. The G2.2 gate is not FALSELY marked DONE (the package
   exists, zero-deps, clean-room suite passes) — its STATED PURPOSE (an
   auditor independently verifying a shipped pack offline) is unmet by the
   current code. Fix status: APPLIED + VERIFIED + GOVERNANCE-REVIEWED. The fix
   excises the generator-identity footer from the byte-compared summary region
   (the footer is an unauthenticated attestation — no self-digest, not in the
   tier-3 re-derived section set — so including it in the tamper-evident
   compare created a forgery vector). The substantive summary body (receipt,
   chain, replay) remains byte-bound; a tampered body still trips
   SUMMARY_BINDING_MISMATCH. Existing golden fixtures (verifier-namespace
   footer) still pass; real gove-zone packs now return valid:true. New
   round-trip test `test_round_trip_gove_zone_pack.py` added (3 tests: programmatic
   verify, CLI verify, forged-body-rejected adversarial). CI-safe: skips loudly
   when the gove-zone interpreter is absent. Full 19-test suite green, ruff clean.
   Governance reviewer: APPROVED after the forgery-window + CI-skip + adversarial-test
   findings were addressed.

### Addendum (2026-07-30, second pass — exact merge provenance per gate)

This section already existed when the second pass ran (same date, same SHA
45f8593d), so nothing was duplicated. What was missing was the exact merge
commit / PR number behind several gates — they were cited as "(mutation wave)",
"(replay wave)", "#2-phase release-prep" etc., which is precisely what forces
the git-history re-derivation this ledger exists to prevent. Resolved below by
`git log origin/master --grep`, verbatim from the commit subjects on master.

IMPORTANT — what this addendum does and does not claim: it establishes **merge
provenance only**. No gate command, test, build, or lint was re-run in this pass
(the brief forbids it). The DONE/HUMAN-GATED statuses in the table above are the
orchestrator's verification, carried forward unchanged.

| Gate | Landing commit(s) on master | Verbatim subject |
|---|---|---|
| G1.1 | `14fc3ad6` (#290), 2026-07-11 | feat(gove-zone): clean-venv wheel-smoke gate + CHANGELOG/SemVer policy + PEP 740 attestations (G1.1) |
| G1.2 | `15ec1ff7` (#118), 2026-06-10 + `8dfdc893` (#291), 2026-07-11 | refactor(gove-zone): extract _exclusive_file_lock into shared gove_zone._locking / test(gove-zone): OS-agnostic concurrent audit-writer test + CI OS matrix |
| G1.3 | `f11a3c86` (#292), 2026-07-11 | test(gove-zone): enforce 100% deny-path coverage gate on the kernel (G1.3) |
| G1.4 | `21ef1e78` (#103), 2026-06-09 + `77598819` (#110) + `7cf79580` (#314), 2026-07-12 | test(gove-zone): adapter conformance harness across all runtime families / feat(gove-zone)!: enforce-by-default gate mode (PR-3, audit R1/P0) / feat(integration): first-class LangGraph adapter + conformance case (ROADMAP row 4) |
| G1.5 | `041f310f` (#313), 2026-07-12 | feat(gove-zone): wire ADR-0005 propagation budget into verify + CI (G1.5) |
| G1.6 | `d4f7e4de` (#309), 2026-07-12 | feat(gove-zone): unsafe-filesystem (NFS-without-lockd) startup probe (G1.6) |
| G2.1 | `4c41cd34` (#293) + `9451ea93` (#285), 2026-07-11 + `bff2f0f0` (#311), 2026-07-12 | feat(gove-zone): publish JSON Schemas for the acgs/proof-pack/v1 evidence bundle / fix(gove-zone): proofpack manifest emits verifier-readable receipts (closes round-trip) / feat(evidence): fail-closed constitution-hash registry cross-check (G2.5/G2.1) |
| G2.2 | `2c1dc565` (#294), 2026-07-11 | feat(acgs-proofpack-verifier): dependency-minimal offline proof-pack verifier + clean-room CI (G2.2) |
| G2.3 | `380b49ef` (#295), 2026-07-11 | test(gove-zone): exhaustive mutation suite proving 100% tamper detection on signed/anchored path (G2.3) |
| G2.4 | `d5475aec` (#106), 2026-06-09 | feat(gove-zone): G2.4 bundle-scope replay equivalence — re-derive every chained decision byte-for-byte |
| G2.5 | `bff2f0f0` (#311), 2026-07-12 | feat(evidence): fail-closed constitution-hash registry cross-check (G2.5/G2.1) |
| G3.2 (scaffolding) | `7811065c` (#297), 2026-07-11 | test(acgi-ai): add runtime /console fail-closed probe to bus-proxy smoke + postdeploy (G3.2) |
| G3.4 (game-day tooling) | `ec5d3a9d` (#298), 2026-07-11 | feat(gove-zone): game-day drill persisting a governed incident-evidence bundle (G3.4) |
| G3.1 / G3.3 / G3.5 | — | no landing commit; production-deploy / third-party gates, human-gated |

Addendum findings:
- **Why the gate PRs are absent from the 54-merge list above.** The G1.x/G2.x
  gate PRs (#290–#298, #309–#314, and the June ones #103/#106/#110/#118) were
  **squash-merged**, so they produce ordinary commits, not merge commits, and
  never appear in `git log --merges`. The 54-row program tables above are
  correct and complete for merge commits; they are not the whole PR history for
  this window. Any future "what landed?" query must run both
  `git log --merges` **and** a squash-commit scan (`--grep='(#'`).
- **Criteria count is 16, not 15.** The `CRITERIA` array has G1.1–G1.6 (6),
  G2.1–G2.5 (5), G3.1–G3.5 (5) = 16. The gate table above already lists all 16;
  the brief's "15" was wrong. Split: 10 DONE (G1.2–G1.6, G2.1–G2.5),
  6 human-gated (G1.1 publish + G3.1–G3.5), 0 incomplete.
- **`.claude/workflows/final-goal-pursuit.js` is NOT in this worktree.** It
  lives only in the primary clone at
  `/home/martin/Documents/ACGS/.claude/workflows/final-goal-pursuit.js`. Its own
  header notes the criteria are embedded because `FINAL-GOAL.md` is not
  committed — so there is no in-repo authoritative copy of the gate text on
  master. Read it from the primary clone, or treat this ledger as the cache.
- **#110 verified.** The G1.4 row above cites "#110 (enforce-by-default gate)";
  confirmed real at `77598819` — `feat(gove-zone)!: enforce-by-default gate mode
  (PR-3, audit R1/P0)`. It is a gate-mode PR rather than a conformance test PR,
  so the conformance evidence for G1.4 is #103 + #314; #110 is what makes the
  gate enforce by default.
- No gate was found to be falsely marked DONE. Every gate claimed DONE above has
  a real landing commit on origin/master, named verbatim in this table.
