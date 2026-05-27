# Codex `/goal` contract — Release-readiness hardening from ChatGPT review

> Created from the 2026-05-27 ChatGPT review of `govern-zone-master(1).zip`.
> Scope is bounded hardening only: make the repo reproducible, fail closed on
> malformed governance inputs, preserve audit-chain integrity, and remove the
> largest release blockers. Do not add product features or broaden public API
> surface unless a test proves the old boundary was already unusable.

## Working directory

```bash
/home/martin/Downloads/govern-zone/ACGS/govern-zone
```

If the repository is elsewhere, run the goal from that repository root.

## Branch

Create a new branch from the current reviewed branch unless one already exists:

```bash
git switch -c release-readiness-hardening-chatgpt-review
```

## Goal text (paste this)

```text
/goal Close the release-readiness blockers from the ChatGPT review of
`govern-zone-master(1).zip` with focused commits and no scope drift. Prioritize
fail-closed governance behavior, reproducible local/CI setup, and audit-chain
integrity. Stop on the stop condition.

READ FIRST:
- AGENTS.md and CLAUDE.md — hard constraints, submodule boundaries, explicit staging.
- MONOREPO.md, pyproject.toml, Makefile, pnpm-workspace.yaml, package.json.
- tests/test_monorepo_invariants.py, tests/test_hardening_report.py,
  scripts/hardening_report.py.
- acgs_governance_eval_mvp/governance/admission/policy.py and
  acgs_governance_eval_mvp/governance/admission/gate.py.
- acgs_governance_eval_mvp/tests/test_admission_hardening.py and
  acgs_governance_eval_mvp/tests/fixtures/admission_gate_v0_1/policy_bundle.json.
- packages/gove-zone/src/gove_zone/audit.py, packages/gove-zone/src/gove_zone/kernel.py,
  and packages/gove-zone/tests/.
- acgs_governance_eval_mvp/governed_mcp_v0/_io.py,
  acgs_governance_eval_mvp/governed_mcp_v0/server.py, and governed_mcp_v0 tests.
- acgi-ai/src/lib/session.ts, acgi-ai/src/App.tsx, acgi-ai/src/routes/Login.tsx,
  acgi-ai/src/api/client.ts, acgi-ai/infra/Caddyfile,
  acgi-ai/scripts/check-security-invariants.mjs, acgi-ai/tests/.
- .github/workflows/claude.yml, .github/workflows/claude-code-review.yml,
  .claude/settings.json.
- packages/agent-bus-analyzer/pyproject.toml and tests.
- hermes_acgs_bundle/tests/, hermes_acgs_bundle/hermes_acgs_middleware.py,
  hermes_acgs_bundle/evidence_writer.py.

BLOCKERS / CHECKPOINTS (fix in this order, one focused commit each):

1. MONOREPO REPRODUCIBILITY DRIFT.
   Problem: root workspace declarations, MONOREPO.md, tests, and
   scripts/hardening_report.py disagree about workspace members. The extracted
   release zip also lacks initialized submodule contents and .git metadata, so
   tests that call `git ls-tree HEAD` fail in archive form.

   Fix path:
   - Make the authoritative workspace-member set truthful and single-sourced
     where practical. It must include every package actually declared in
     pyproject.toml, plus hermes only if you intentionally add a hermes
     pyproject/workspace entry in checkpoint 7.
   - Update tests/test_monorepo_invariants.py and scripts/hardening_report.py
     so expected UV members match pyproject.toml and MONOREPO.md.
   - Make `_is_gitlink()` or its replacement archive-safe: non-git zip exports
     must not crash on `git ls-tree`. Prefer reading `.gitmodules` as a fallback
     to detect registered submodule paths; if the submodule path is empty in a
     release archive, skip with a precise message or fail with a precise release
     packaging error, but do not raise a raw CalledProcessError.
   - Add a regression test that simulates a non-git checkout/zip by monkeypatching
     subprocess.run to fail and proves the invariant test reports/skips cleanly.
   - Decide whether release archives must include submodule contents. If yes,
     add a documented packaging check. If no, update the invariant wording so
     missing submodule pyproject files are treated as lazy submodules, not broken
     parent-tracked packages.

   Evidence required:
   - `python -m pytest tests/test_monorepo_invariants.py tests/test_hardening_report.py -q`
     exits 0 in a normal git checkout.
   - If a zip/no-git simulation test is added, show its nodeid and passing output.

2. ADMISSION POLICY `when` VALIDATION FAIL-CLOSED.
   Problem: policy_bundle_from_dict validates top-level rule keys but not nested
   `when` keys. gate._rule_matches() ignores unknown `when` keys and then returns
   True, so a typo can silently create an overbroad rule.

   Fix path:
   - Define the exact v0.1 `when` schema in policy.py or a small helper module.
     Allowed keys are currently:
       risk_class, phase, environment,
       requested_capabilities_any, requested_capabilities_all,
       requested_capabilities_subset_of,
       disallowed_outputs_contains_any, allowed_outputs_contains_any.
   - Reject unknown `when` keys at policy-bundle load time with ValueError naming
     the rule id/index and key.
   - Validate value types. The current matcher expects lists for every supported
     key. Reject strings, dicts, nulls, and scalar values unless you explicitly
     update the matcher and tests.
   - Validate enum contents for risk_class, phase, and environment using the same
     enum universe as gate.py. Avoid circular imports; duplicate constants only
     if necessary and leave a comment that they must stay in sync.
   - Add regression tests:
       a) typo key such as `tool_nam` or `requested_capabilites_any` is rejected.
       b) string instead of list is rejected.
       c) invalid enum value is rejected.
       d) the existing admission fixture policy still loads and existing
          admission tests still pass.

   Evidence required:
   - `cd acgs_governance_eval_mvp && uv run --package acgs-governance-eval-mvp python -m pytest tests/test_admission_hardening.py tests/test_admission_gate_v0_1.py -q`
     exits 0.

3. GOVE-ZONE AUDIT TAIL CORRUPTION MUST NOT RESET TO GENESIS.
   Problem: packages/gove-zone/src/gove_zone/audit.py returns GENESIS_HASH when
   _read_last_hash_from_disk() hits OSError or JSONDecodeError. A corrupt or
   partially-written tail can therefore cause later appends to fork/restart the
   audit chain instead of failing closed.

   Fix path:
   - Introduce a specific exception, e.g. AuditChainError, for unreadable or
     malformed audit tails.
   - Keep the missing/empty-file case as GENESIS_HASH. Treat OSError,
     UnicodeDecodeError, JSONDecodeError, missing `event_hash`, and non-string
     event_hash in a non-empty file as hard failures.
   - Ensure Kernel.dispatch fails before side effects when audit append fails.
     If kernel.py currently suppresses audit write failures on error paths,
     either return explicit audit-write status in the receipt or fail closed when
     audit is mandatory. Do not silently drop audit evidence for a governed
     decision.
   - Add tests:
       a) corrupt final JSONL line causes append() to raise and does not append.
       b) unreadable tail or malformed event_hash raises.
       c) a normal empty audit file still starts from GENESIS_HASH.
       d) dispatch path does not execute the tool when audit append fails.

   Evidence required:
   - `cd packages/gove-zone && uv run --package gove-zone python -m pytest tests/test_audit.py tests/test_fail_closed.py tests/test_replay.py -q`
     exits 0. If file names differ, run the equivalent targeted tests plus full
     `python -m pytest tests/ -q`.

4. GOVERNED MCP RECEIPT/AUDIT WRITE MUST BE ATOMIC UNDER CONCURRENCY.
   Problem: governed_mcp_v0/server.py computes receipt index and previous audit
   hash without a shared lock, then writes receipt and audit rows separately.
   Concurrent admissions can choose the same receipt index or previous_hash.

   Fix path:
   - Add a shared evidence lock in governed_mcp_v0/_io.py or a small dedicated
     writer class. Under one lock: compute next receipt index, compute previous
     audit hash, write the receipt, append the audit event, flush/fsync both.
   - Use exclusive receipt creation (`open(..., "x")`) or an atomic temp-file +
     no-overwrite replace so duplicate indices cannot silently overwrite.
   - If audit append fails after receipt creation, fail closed and leave evidence
     in a diagnosable state. Do not report allow if either receipt or audit write
     failed.
   - Preserve existing receipt/audit schema unless a test proves it is already
     broken.
   - Add a concurrency regression test using ThreadPoolExecutor or multiprocessing:
       N guarded admissions produce N unique receipt paths and a linear audit
       chain with no duplicate previous_hash siblings.

   Evidence required:
   - `cd acgs_governance_eval_mvp && uv run --package acgs-governance-eval-mvp python -m pytest tests/test_governed_mcp_v0.py tests/test_audit_chain.py -q`
     exits 0, including the new concurrency test.

5. CONSOLE AUTH BOUNDARY MUST BE SERVER-BACKED OR EXPLICITLY FAIL-CLOSED.
   Problem: acgi-ai currently gates `/console` with client-side sessionStorage.
   `createSession()` is production-blocked, SSO buttons do not establish a real
   session, API calls use same-origin cookies only, and Caddy returns 503 for
   /api/*. This is safe as a demo blocker but not a release-ready auth path.

   Fix path:
   - Do not fake SSO and do not re-enable production createSession().
   - Introduce an explicit auth contract:
       `/api/auth/session` (or equivalent) returns authenticated session state
       from the server/gateway; production console route guards trust only that
       server-backed state.
   - sessionStorage may be used only for local development/test mocks, guarded by
     DEV or a clearly named test/mock mode. It must not grant production console
     access.
   - Mutating API calls must carry either CSRF protection for cookie sessions or
     an explicit bearer token injected by the auth boundary. Pick one and test it.
   - If the API gateway is still intentionally unwired, make the production build
     and/or deployment check fail loudly with an actionable message instead of
     shipping a console that appears authenticated but has 503 APIs.
   - Update Login.tsx so SSO buttons link/redirect only to configured backend
     auth start endpoints. If no endpoint is configured, keep the current
     no-grant error behavior.
   - Add tests:
       a) production-like environment ignores forged sessionStorage.
       b) `/console/*` redirects/renders login until server session is confirmed.
       c) unauthenticated API calls fail and do not fall back to fixture data.
       d) mutating API calls include the selected CSRF/bearer mechanism.

   Evidence required:
   - `cd acgi-ai && pnpm run test:security` exits 0.
   - `cd acgi-ai && pnpm run test:unit` exits 0.
   - If Playwright is available, run the targeted auth/deep-link test; otherwise
     state the skipped command and why.

6. AI WORKFLOW SECRET / SELF-HOSTED RUNNER HARDENING.
   Problem: .github/workflows/claude*.yml run Claude workflows on self-hosted
   runners with CLAUDE_CODE_OAUTH_TOKEN. Comment/PR triggers can be risky unless
   restricted to trusted actors. .claude/settings.json also allows broad
   `git -C packages/...:*`, which can bypass direct deny patterns.

   Fix path:
   - Restrict Claude comment/review triggers to trusted author associations
     (OWNER, MEMBER, COLLABORATOR) or to an explicit allowlist. Use clear GitHub
     expressions and comments.
   - Do not expose CLAUDE_CODE_OAUTH_TOKEN to untrusted fork PRs or first-time
     contributors. Prefer no-op with a clear log message over running.
   - Remove `id-token: write` unless the workflow actually uses OIDC. Keep
     `contents: read`, `pull-requests: read`, `issues: read`, and `actions: read`
     only where necessary.
   - Avoid self-hosted runners for untrusted PR contexts. If self-hosted must
     remain, make the trust guard mandatory.
   - Replace broad `.claude/settings.json` allow patterns such as
     `Bash(git -C packages/acgs-lite:*)` with read-only subcommands, or add deny
     patterns for `git -C ... push`, `add`, `reset --hard`, `clean -f`, checkout
     to protected branches, and equivalent destructive forms.
   - Add a small static test or script assertion so future edits cannot re-open
     broad self-hosted secret exposure.

   Evidence required:
   - The new/updated static test passes.
   - `python -m pytest tests/test_monorepo_invariants.py -q` or the equivalent
     workflow-security test exits 0.

7. LOCAL DEPENDENCY DECLARATIONS FOR AGENT-BUS-ANALYZER AND HERMES.
   Problem: packages/agent-bus-analyzer tests fail to collect when
   `enhanced_agent_bus` is absent. hermes_acgs_bundle tests require
   opentelemetry-sdk locally, while its dependency declaration is CI-only.

   Fix path:
   - For agent-bus-analyzer: either add the missing local source/package to the
     workspace, pin a resolvable dependency, or split tests so pure unit tests
     collect offline and integration tests use pytest.importorskip/markers with
     a clear message. Do not mask real failures behind broad skips.
   - For hermes_acgs_bundle: add a minimal pyproject.toml or requirements-test.txt
     that declares pytest, pyyaml, opentelemetry-api, and opentelemetry-sdk. If
     pyproject.toml is added, decide intentionally whether hermes joins the root
     uv workspace, MONOREPO.md, Makefile, and hardening-report expected set.
   - Align local commands, package metadata, and CI workflows. The same command
     that passes in CI should pass locally from a fresh checkout with documented
     dependency install steps.

   Evidence required:
   - `cd packages/agent-bus-analyzer && uv run --package agent-bus-analyzer python -m pytest -q`
     exits 0, or unit tests pass and integration skips are explicit and justified.
   - `cd hermes_acgs_bundle && uv run python -m pytest tests/ -q` exits 0, or the
     documented local requirements command followed by pytest exits 0.

STOP CONDITION (all must hold; paste literal evidence):
- All checkpoint-specific evidence commands above pass or have a precise,
  justified skip tied to an unavailable external/private dependency.
- Root `python -m pytest tests/test_monorepo_invariants.py tests/test_hardening_report.py -q` passes.
- `cd acgs_governance_eval_mvp && uv run --package acgs-governance-eval-mvp python -m pytest tests/ -q` passes.
- `cd packages/gove-zone && uv run --package gove-zone python -m pytest tests/ benchmarks/ -q` passes.
- `cd acgi-ai && pnpm run test:security && pnpm run test:unit` passes.
- `make lint-py` passes in an initialized checkout, or any remaining skip is
  directly caused by intentionally uninitialized private submodules and is
  documented in the final summary.
- `git diff --stat` shows only files needed for these seven checkpoints.
- No edits to sealed constitutional-hash files unless the hash is recomputed and
  the lock/update procedure is included in the same commit.
- No `git add -A` or `git add .`; stage files explicitly.
- Do not touch packages/Acgs-Swarm internals unless the task is explicitly
  narrowed to that submodule.

HARD CONSTRAINTS:
- No fake auth success path in production.
- Unknown governance policy keys must fail closed at load time.
- Audit corruption must never reset the parent hash to genesis for a non-empty
  file.
- Receipt/audit persistence failure must prevent governed side effects from
  reporting success.
- Do not broaden public API surfaces just to make tests pass.
- Do not silence failing tests with broad skips. Any skip must name the missing
  optional/private dependency and preserve unit-test coverage.
- Treat submodules as independent repos; commit inside them only if the fix
  genuinely belongs there, then bump the parent pointer explicitly.

PROGRESS LOG:
Append one line per checkpoint to:
.omc/state/release-readiness-hardening-progress.log

Format:
`<ISO-8601 UTC> CHECKPOINT <n> done: <summary> | sha=<short sha>`

COMMITS (conventional commits, one per checkpoint):
- test(monorepo): make workspace invariants archive-safe and truthful
- fix(eval-mvp): reject malformed admission policy conditions
- fix(gove-zone): fail closed on corrupt audit tails
- fix(eval-mvp): serialize governed MCP receipt and audit writes
- fix(console): require server-backed auth for production console access
- ci(security): restrict AI workflows to trusted actors
- build(monorepo): declare local test dependencies consistently

DO NOT MERGE. Emit final summary with: checkpoints closed, tests added,
commands run with literal output, skips/remaining blockers, and any file you
consider risky or worth a second review.
```

## Launch

Preferred: paste the **Goal text** block into an interactive Codex session from
this repository root so `/goal` durable-objective semantics are active.

Optional non-interactive extraction of the same text:

```bash
cd /home/martin/Downloads/govern-zone/ACGS/govern-zone
codex exec --dangerously-bypass-approvals-and-sandbox \
  "$(awk '/^## Goal text/{p=1;next} p && /^```text$/{q=1;next} q && /^```$/{exit} q' docs/codex-goals/release-readiness-hardening-chatgpt-review.md)"
```

`codex exec` may not preserve true interactive `/goal` behavior. Use the
interactive session when durability/resume behavior matters.

## Status hook

```bash
tail -f .omc/state/release-readiness-hardening-progress.log
```
