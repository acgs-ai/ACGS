export const meta = {
  name: 'acgs-lite-pep-closure-pursuit',
  description: 'Audit the acgs-lite PEP-closure final goal (G1-G7) against packages/acgs-lite, then implement + review + verify one increment per run',
  whenToUse: 'Each run = one verifiable increment toward docs/design/acgs-lite-pep-closure-final-goal.md. First run defaults to dryRun (scoreboard + plan only); resume with {dryRun:false} to execute. {maxItems:N} caps implemented items (default 2); {exclude:[...]} skips criteria in flight on unmerged branches.',
  phases: [
    { title: 'Audit' },
    { title: 'Prioritize' },
    { title: 'Implement' },
    { title: 'Review' },
    { title: 'Verify' },
  ],
}

// ---------------------------------------------------------------------------
// Config — inline constants (args have historically arrived undefined; every
// field has a safe default). Paths pinned absolutely: workflow sub-agents do
// NOT inherit the package cwd.
// ---------------------------------------------------------------------------
const REPO = '/home/martin/Documents/ACGS'
const PKG = '/home/martin/Documents/ACGS/packages/acgs-lite'
const WT_BASE = '/home/martin/Documents/ACGS-wt'
const GOAL_DOC = '/home/martin/Documents/ACGS/docs/design/acgs-lite-pep-closure-final-goal.md'

const input = typeof args === 'string'
  ? (() => { try { return JSON.parse(args) } catch { return {} } })()
  : (args ?? {})

// ---- Shell/prompt-safety for values embedded in sub-agent command snippets -
// Implement/review/verify sub-agents are handed PROMPTS containing example shell
// commands (`git -C <dir> worktree add <path> -b <branch> main`, `cd <worktree>`).
// Values flowing into those commands come from args (exclude list) or from an
// LLM planning step (criterionId -> slug). Taken raw they enable two failure modes:
//   1. SHELL injection — a value with a quote / ; / $() / backtick can break out
//      of the command a sub-agent is told to run.
//   2. PROMPT injection — a value with a newline can inject new instructions into
//      the sub-agent's prompt. Shell-quoting does NOT stop this.
// So: VALIDATE first (fail closed — refuse to run on anything outside a narrow
// allowlist, which also rejects control chars / newlines), shell-quote second
// (defense in depth) wherever a value is embedded in a command.
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`
function assertShellSafe(value, label, allowed) {
  const s = String(value)
  if (!allowed.test(s)) {
    throw new Error(
      `acgs-lite-pep-closure-pursuit: refusing to run — \`${label}\` = ${JSON.stringify(s)} ` +
        `contains characters unsafe to embed in a sub-agent command/prompt (allowed: ${allowed}). ` +
        `This gate fails closed rather than emit a command a sub-agent could be tricked into ` +
        `mis-running, or a prompt it could be tricked into mis-reading.`
    )
  }
}
// Allowlist regexes (mirrors review-branch-adversarial.js):
//   filesystem path : /^[A-Za-z0-9._/-]+$/
//   git ref         : /^[A-Za-z0-9._/@~^{}-]+$/
//   slug / criterion-id / branch-name component : /^[A-Za-z0-9._-]+$/
const RE_SLUG = /^[A-Za-z0-9._-]+$/
const RE_PATH = /^[A-Za-z0-9._/-]+$/
const RE_REF = /^[A-Za-z0-9._/@~^{}-]+$/

// validationCommand is an LLM-planner-produced free-form shell command that a
// sub-agent is explicitly told to "run exactly". A slug/path allowlist would
// over-restrict it (a legitimate gate command needs spaces, flags, quotes, e.g.
// `uv run pytest -k receipt`), and shq is wrong (the value IS the command, not
// an argument to quote). The real risk is PROMPT injection — a newline/control
// char lets a poisoned plan inject new instructions into the directive that
// surrounds it. So guard fail-closed against control chars + an absurd length,
// then interpolate the value verbatim. Returns the value so it can be inlined.
function assertCommandSafe(value, label) {
  const s = String(value)
  if (/[\r\n\x00-\x1f]/.test(s) || s.length > 512) {
    throw new Error(
      `acgs-lite-pep-closure-pursuit: refusing to run — \`${label}\` = ${JSON.stringify(s)} ` +
        `contains a newline/control char or is over-long (cap 512), so it is unsafe to embed ` +
        `verbatim in a "run this command exactly" directive (prompt-injection vector). ` +
        `This gate fails closed rather than emit a prompt a sub-agent could be tricked into mis-reading.`
    )
  }
  return s
}

const MAX_ITEMS = Number.isInteger(input?.maxItems) && input.maxItems > 0 ? Math.min(input.maxItems, 3) : 2
// Plan-only by default: implementation is dispatched through the codex EXT-C
// lane by the orchestrator (classifier-kill avoidance), so this workflow's
// job is audit + prioritize. Pass {dryRun:false} to use in-band implementers.
const DRY_RUN = input?.dryRun === false ? false : true
// Default exclusions: criteria already implemented on in-flight (unmerged)
// branches — final-goal/acgs-lite-{g1,g2,g3,g4,g6,g7} (2026-06-11). Hardcoded
// because args have historically arrived undefined. NOTE: G5 (the only
// remaining criterion) must wait for G1 to merge (governed.py overlap,
// planner-verified conflict) — re-run this workflow only after that merge.
const EXCLUDE = Array.isArray(input?.exclude) ? input.exclude : ['G1', 'G2', 'G3', 'G4', 'G6', 'G7']
// EXCLUDE elements are arg-derived and interpolated into prompt/log text via
// `EXCLUDE.join(', ')` (never into a shell command), so they need fail-closed
// validation against newlines/control chars (prompt injection) but no shq.
// A criterion id is a slug-shaped token (e.g. 'G1').
EXCLUDE.forEach((id, i) => assertShellSafe(id, `exclude[${i}]`, RE_SLUG))

// The 7 goal criteria, embedded from docs/design/acgs-lite-pep-closure-final-goal.md
// (auditors should still read that doc and prefer its current wording).
// Evidence anchors were verified 2026-06-10 against the live tree.
const CRITERIA = [
  {
    id: 'G1', title: 'Unified side-effect execution boundary',
    text: `GovernedAgent.run()/arun() must offer the same receipt gate as GovernedCallable (validate_receipt_for_execution, fail-closed). Verified gap: governed.py:318-396 run() has zero receipt references while GovernedCallable gates at governed.py:709-726 via legitimacy/invariants.py:122-153. Also: arun() (governed.py:528+) is missing the circuit-breaker step AND never calls _emit_cdp — sync/async must end up behaviorally identical.
CONSTRAINT (non-breaking): acgs-lite is published on PyPI (v2.10.0). The receipt gate on GovernedAgent must land as an OPT-IN parameter (e.g. require_receipt / receipt_gate=, default off) with a documented deprecation path; flipping the default is a human-gated v3 decision. Acceptance: with the gate enabled — no receipt -> deny, expired -> deny, wrong method/actor -> deny; with it disabled — existing behavior + DeprecationWarning-style guidance; arun parity tests (circuit breaker + CDP emission) pass.`,
  },
  {
    id: 'G2', title: 'Single-use receipt replay protection',
    text: `DecisionReceipt (legitimacy/receipt.py:32-48) has no nonce, no consumed state, no argument_hash; ExecutionBoundary.single_use exists but is a DEAD FIELD (only receipt.py:29, signing.py:260, selector.py:250,332 — validate_receipt_for_execution never reads it). Selector issues receipts with expires_at=None and single_use=False. Required: wire single_use into validation; add a consumed store with atomic consume; add nonce + argument_hash binding; selector defaults become single_use=True with a finite expires_at. Prior art to study (do not copy blindly): gove-zone consumption ledger merged as PR-4b (#114), keyed on audit_event_hash — see packages/gove-zone/src/gove_zone/replay_store.py and related tests. Acceptance: same receipt second execution fails closed; two concurrent executions -> exactly one succeeds; expired/None-expiry issuance covered by tests. Backward compat: consumption enforcement may need to key off single_use=True receipts only, so existing issued receipts keep working.`,
  },
  {
    id: 'G3', title: 'Constitution hash v2 (full enforcement semantics)',
    text: `constitution/constitution.py:119-123 hashes only id/text/severity/hardcoded/sorted-keywords and truncates to 16 hex. Excluded but enforcement-affecting: patterns, condition, workflow_action, enabled, valid_from/valid_until, category, subcategory, depends_on, deprecated/replaced_by, priority, metadata. Required: canonical JSON serialization over ALL enforcement-affecting Rule fields, full 64-hex SHA-256, versioned hash format (e.g. "v2:<hex>") with a back-compat marker so existing pinned hashes (AGENTS.md anchor 608508a9bd224290, production.py:105-109 pin check) keep verifying. Sealed artifacts and lock files must be regenerated via their generator path, never hand-edited. Acceptance: changing workflow_action/enabled/a pattern changes the hash; reordering non-semantic representation does not; v1 pins still verify against v1 hashes.`,
  },
  {
    id: 'G4', title: 'Audit chain hardening',
    text: `audit.py truncates entry and chain hashes to 16 hex (audit.py:260,370,576); default backend is in-memory with max_entries=10000 rolling drop; record() is fail-open (audit.py:336-342, fail-closed record_atomic exists at :383-525 but is opt-in); AuditLog.from_backend (:532-559) trusts persisted chain hashes without calling verify_chain(). Required: full-length SHA-256 chain hashes (versioned/back-compat for existing persisted chains), verify-on-load in from_backend (or an opt-out with loud warning), production profile (production.py) requires a durable backend and fail-closed writes (record_atomic as the production default). Keep the fast dev/demo mode, explicitly labeled. Acceptance: tampered persisted chain fails on load; production profile without durable audit backend fails its gate; dev mode unchanged.`,
  },
  {
    id: 'G5', title: 'Structured action proposal before side effects',
    text: `GovernedAgent.run() order is validate-input -> EXECUTE (governed.py:352 _execute_agent) -> validate-output, so output validation cannot block side effects; the retry loop (governed.py:390-391, 579-580) re-executes the agent BEFORE re-validating each round. Required: a pre-execution structured action proposal path (actor/tool/method/resource/arguments_hash/risk_level) that the gate validates before _execute_agent runs, and retry rounds re-enter the gate. This can build on G1's gate. Scope discipline: do not redesign the agent API — add the proposal hook opt-in alongside the existing flow. Acceptance: a denied proposal prevents _execute_agent from being called (assert via spy/mock); each retry round passes the gate again.`,
  },
  {
    id: 'G6', title: 'Authenticated principal -> MACI binding',
    text: `MACIEnforcer.check(agent_id, action) takes a bare string (maci.py:229-285); server.py:424 reads agent_id from the request body; the only HTTP auth is a shared X-API-Key (server.py:369-375) with zero binding to agent_id — any key holder can claim any agent_id and inherit its MACI role. Required: an authenticated-principal layer (JWT claims verification at minimum; design for mTLS/workload identity later) mapping principal -> agent_id; body agent_id becomes a claim that must match the authenticated principal or the request is denied; per-principal API keys as a fallback tier. Must stay backward compatible: unauthenticated/dev mode keeps working but is clearly labeled and off in the production profile. Acceptance: principal/agent_id mismatch -> deny; missing auth in production profile -> deny; dev mode regression tests unchanged.`,
  },
  {
    id: 'G7', title: 'Threat-model doc + red-team regression suite',
    text: `No consolidated threat model exists for acgs-lite; red-team tests exist only partially (tests/red_team/governance_fail_closed_cases.py). Required: a threat-model document (docs/ inside the package) plus a defensive red-team regression suite covering: receipt replay, argument substitution, validator/executor self-approval, audit write failure, audit chain tamper, constitution hash drift, keyword-boundary bypass, async/sync divergence, server fail-open integration, agent_id spoofing claims. Tests for not-yet-fixed gaps land as xfail(strict) so they flip to PASS as G1-G6 merge. Wire the suite into the package-local test gate. Acceptance: suite runs in the package gate; every listed threat has at least one test (passing or strict-xfail); threat-model doc cross-references test IDs.`,
  },
]

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------
const AUDIT_SCHEMA = {
  type: 'object',
  required: ['id', 'status', 'evidence', 'gapSummary', 'agentImplementable', 'nextAction', 'scope'],
  properties: {
    id: { type: 'string' },
    status: { type: 'string', enum: ['met', 'partial', 'unmet', 'blocked-human'] },
    evidence: { type: 'string', description: 'Concrete file paths, test names, command output observed in the repo' },
    gapSummary: { type: 'string' },
    agentImplementable: { type: 'boolean', description: 'true only if a coding agent can close (part of) the gap without publish/deploy/merge/secrets' },
    nextAction: { type: 'string', description: 'The single most valuable concrete next step' },
    scope: { type: 'string', enum: ['small', 'medium', 'large'] },
  },
}

const PLAN_SCHEMA = {
  type: 'object',
  required: ['items', 'rationale'],
  properties: {
    rationale: { type: 'string' },
    items: {
      type: 'array',
      items: {
        type: 'object',
        required: ['criterionId', 'title', 'plan', 'validationCommand'],
        properties: {
          criterionId: { type: 'string' },
          title: { type: 'string' },
          plan: { type: 'string', description: 'Concrete step-by-step plan with file paths relative to the acgs-lite repo root' },
          validationCommand: { type: 'string', description: 'The package-local gate command (runnable from inside an acgs-lite worktree) that proves the work' },
        },
      },
    },
  },
}

const IMPL_SCHEMA = {
  type: 'object',
  required: ['completed', 'branch', 'worktree', 'filesChanged', 'summary'],
  properties: {
    completed: { type: 'boolean' },
    branch: { type: 'string' },
    worktree: { type: 'string', description: 'Absolute path of the acgs-lite worktree the changes live in' },
    filesChanged: { type: 'array', items: { type: 'string' } },
    summary: { type: 'string' },
    blockers: { type: 'string' },
  },
}

const REVIEW_SCHEMA = {
  type: 'object',
  required: ['verdict', 'issues'],
  properties: {
    verdict: { type: 'string', enum: ['approve', 'request-changes', 'block'] },
    issues: { type: 'array', items: { type: 'string' } },
  },
}

const VERIFY_SCHEMA = {
  type: 'object',
  required: ['passed', 'command', 'outputTail'],
  properties: {
    passed: { type: 'boolean' },
    command: { type: 'string' },
    outputTail: { type: 'string', description: 'Last ~20 lines of literal command output' },
    notes: { type: 'string' },
  },
}

// ---------------------------------------------------------------------------
// Shared prompt fragments
// ---------------------------------------------------------------------------
const REPO_RULES = `
Package under work: ${PKG} — a NESTED git repository (its own .git, registered as a submodule of ${REPO}). Workflow agents do NOT start there — cd first.
Hard rules (non-negotiable):
- ALL git operations (branch, add, commit, worktree) happen INSIDE ${PKG} (or a worktree of it). NEVER stage acgs-lite paths from the parent repo; NEVER touch the parent's submodule pointer.
- acgs-lite is PUBLISHED on PyPI (v2.10.0). No breaking changes to the public API; published requires-python floor is >=3.10. New enforcement behavior must be opt-in with a deprecation path; default flips are human-gated.
- NEVER weaken fail-closed behavior, bypass receipt validation, or treat DENY/ESCALATE as executable.
- NEVER edit files carrying "Constitutional Hash:", "@generated", or "DO NOT EDIT" markers by hand; sealed hashes/locks are regenerated via their generator path only.
- NEVER run: git add -A, git add ., git stash, git reset --hard, git push --force, gh pr merge, gcloud, vercel, pip publish/twine, or anything touching secrets. PyPI publishing and production deploys are HUMAN-GATED.
- Read ${PKG}/CLAUDE.md and ${PKG}/AGENTS.md before editing and obey them over root assumptions.
- The goal definition with verified file:line evidence lives at ${GOAL_DOC} — read it and prefer its current wording.
`.trim()

// ---------------------------------------------------------------------------
// G6 audit — pre-supplied via the Codex EXT-C lane (2026-06-10). The in-band
// G6 audit agent was killed twice by a usage-policy classifier false positive
// (stop_details.type=refusal on run wf_8e2301e4-590), so we do NOT re-dispatch
// it; this verified external result stands in. Codex thread:
// 019eb3f9-c80f-7c40-a48e-fc1aa5979030 (read-only run).
// ---------------------------------------------------------------------------
const G6_AUDIT = {
  id: 'G6',
  status: 'unmet',
  evidence: 'Codex EXT-C re-verified 2026-06-10: maci.py:207-213 in-memory role dict keyed by supplied agent_id string; maci.py:242-247 self._roles.get(agent_id) defaulting to observer; DRIFT: package export also routes via maci/__init__.py:16 -> maci/enforcer.py:33-57 with the same bare-string lookup. server.py:353-375 single shared X-API-Key; server.py:418-436 /validate reads agent_id from JSON body (default "anonymous"); server.py:102-119 claude-code path same; server.py:556-579 deprecated /x402/check takes agent_id as query param. Identity-like building blocks exist but are NOT wired into MACI role resolution: autonoma.py:204-235 HMAC/JWT are Autonoma env refs only; constitution/delegation_token.py:1-6,145-185 offline delegation tooling; constitution/access_control.py:137-205 standalone in-memory principal RBAC not wired into server.py or MACIEnforcer; federation/transport.py:36-57 bearer token then accepts payload.agent_id. Tests cover shared-key auth (test_server_api_key_auth.py:34-66) and arbitrary agent_id propagation (test_server.py:113-132), not principal/agent_id consistency.',
  gapSummary: 'No authenticated-principal layer is wired into MACI role resolution. HTTP callers satisfying the shared endpoint credential can present any agent_id on /validate and integration routes; several identity building blocks (per-route bearer, HMAC/JWT refs, delegation tokens, standalone principal RBAC) exist but none binds the authenticated caller to the agent_id MACI consumes. No principal/agent_id consistency tests exist.',
  agentImplementable: true,
  nextAction: 'Add an opt-in principal binding layer to create_governance_app deriving the effective agent_id from per-principal credentials or a configured principal_to_agent_id map, rejecting mismatched body/query agent_id when enabled, keeping current dev/shared-key behavior unchanged by default; add server tests for allow, mismatch-deny, and production-profile-required modes.',
  scope: 'medium',
}

// ---------------------------------------------------------------------------
// Phase 1 — Audit (G6 excluded: pre-supplied above; single wave <=8)
// ---------------------------------------------------------------------------
phase('Audit')
log(`Auditing ${CRITERIA.length - 1} PEP-closure criteria against ${PKG} (G6 pre-supplied via Codex)`)

const auditResults = await parallel(CRITERIA.filter(c => c.id !== 'G6').map(c => () =>
  agent(
    `You are auditing ONE exit criterion of the acgs-lite PEP-closure final goal against the actual repository state. Report evidence, not optimism. This is defensive security review of our own library.

${REPO_RULES}

Criterion ${c.id}: ${c.title}
${c.text}

Procedure:
1. cd ${PKG}. Read ${GOAL_DOC} section for ${c.id} and prefer its current wording.
2. Search ${PKG}/src/acgs_lite for implementation and ${PKG}/tests for coverage relevant to this criterion (grep, read code, check CI config). The evidence anchors above were verified 2026-06-10 — re-check them; if the code has since changed, say so explicitly.
3. Where cheap and read-only, RUN targeted verification (a scoped pytest selection, a grep proving wiring). Do not run anything that mutates state, installs from the network, or takes >3 minutes.
4. Classify status: met / partial / unmet / blocked-human (blocked-human = remaining gap requires publish, deploy, merge, secrets, or an external party/major-version decision).
5. agentImplementable=true only if a coding agent could close part of the gap purely with local code/test/doc changes inside ${PKG}.
Be skeptical: a unit test importing a function directly does NOT prove the gate is wired into the execution path. Set id to "${c.id}".`,
    { label: `audit:${c.id}`, phase: 'Audit', schema: AUDIT_SCHEMA },
  )))

// Fail closed on missing lanes: a crashed audit agent (null / unstructured
// result) must stay visible as an explicit "unknown" for its criterion.
// Silently dropping it would shrink the scoreboard and could make "remaining
// gaps are human-gated" a statement about criteria that were never evaluated
// (with the default exclusions, a dropped G5 lane can empty `candidates`).
const auditedCriteria = CRITERIA.filter(c => c.id !== 'G6')
const audits = auditedCriteria.map((c, i) => {
  const r = auditResults[i]
  return r && r.id ? r : {
    id: c.id,
    status: 'unknown',
    evidence: '',
    gapSummary: 'audit lane crashed or returned no structured result: criterion NOT evaluated',
    agentImplementable: false,
    nextAction: 're-run this audit lane',
    scope: 'small',
  }
})
audits.push(G6_AUDIT)
const scoreboard = audits.map(a => ({ id: a.id, status: a.status, scope: a.scope, gap: a.gapSummary }))
const met = audits.filter(a => a.status === 'met').length
log(`Scoreboard: ${met}/${CRITERIA.length} met`)

// Every criterion must be accounted for before prioritization: ranking against
// an incomplete scoreboard can mislabel never-evaluated gaps as human-gated.
const unaudited = audits.filter(a => a.status === 'unknown')
if (unaudited.length > 0) {
  log(`STOPPING (fail-closed): ${unaudited.length} criteria produced no audit verdict: ${unaudited.map(a => a.id).join(', ')}`)
  return {
    scoreboard,
    selected: [],
    unaudited: unaudited.map(a => a.id),
    note: `Audit incomplete: ${unaudited.length}/${CRITERIA.length} criteria returned no verdict (crashed/empty audit lanes). Prioritization was NOT run, because an incomplete scoreboard cannot prove "remaining gaps are human-gated". Re-run the workflow.`,
  }
}

// ---------------------------------------------------------------------------
// Phase 2 — Prioritize (barrier is correct: ranking needs all 7 results)
// ---------------------------------------------------------------------------
phase('Prioritize')
const candidates = audits.filter(a => a.agentImplementable && a.status !== 'met' && !EXCLUDE.includes(a.id))
if (EXCLUDE.length) log(`Excluded (in flight on unmerged branches): ${EXCLUDE.join(', ')}`)

if (candidates.length === 0) {
  return { scoreboard, selected: [], note: 'No agent-implementable unmet criteria found — remaining gaps are human-gated.', humanGated: audits.filter(a => a.status === 'blocked-human') }
}

const plan = await agent(
  `You are the planning lane for the acgs-lite PEP-closure pursuit. From the audit results below, select the ${MAX_ITEMS} highest-leverage work items a coding agent can complete THIS RUN, and write a concrete plan for each.

${REPO_RULES}

Selection rules:
- Closure-dependency order matters: G1 (unified gate) unblocks G2 and G5; G7's xfail suite is valuable early because it locks the threat list. Prefer converting "partial" to "met" with bounded scope; prefer small/medium over large.
- AVOID selecting two items that edit the same hot file (governed.py is shared by G1 and G5) in the same run — they will conflict at merge. If both rank highest, pick one and the next non-conflicting item.
${EXCLUDE.length ? `- ALREADY IN FLIGHT (implemented on unmerged branches, do NOT select): ${EXCLUDE.join(', ')}. Avoid plans that conflict with those pending changes.` : ''}
- Each item must be completable locally: code + tests + a package-local validation command runnable from inside an acgs-lite worktree. No publishing, deploying, merging.
- Read ${PKG}/CLAUDE.md and ${PKG}/AGENTS.md and take the authoritative package gate command from there (do not invent one).

Audit results:
${JSON.stringify(candidates, null, 2)}

Full scoreboard for context:
${JSON.stringify(scoreboard, null, 2)}`,
  { label: 'prioritize', phase: 'Prioritize', schema: PLAN_SCHEMA },
)

const selected = (plan?.items ?? []).slice(0, MAX_ITEMS)
log(`Selected ${selected.length} work item(s): ${selected.map(s => s.criterionId).join(', ')}`)

if (DRY_RUN) {
  return {
    scoreboard,
    rationale: plan?.rationale,
    selected,
    note: 'dryRun (default) — audit + plan only, nothing implemented. Resume with {dryRun:false} to execute; the Audit/Prioritize phases will be served from cache.',
    humanGated: audits.filter(a => a.status === 'blocked-human').map(a => ({ id: a.id, gap: a.gapSummary })),
  }
}

// ---------------------------------------------------------------------------
// Phases 3-5 — Implement -> Review -> Verify, pipelined per item.
// NOTE: no isolation:'worktree' here — that would create a worktree of the
// PARENT repo where the acgs-lite submodule is not checked out. Implementers
// create their own worktree of the NESTED repo instead.
// ---------------------------------------------------------------------------
const outcomes = await pipeline(
  selected,
  // Stage 1 — implement, in a self-created worktree of the nested repo
  item => {
    if (budget.total && budget.remaining() < 80_000) {
      log(`Budget low — skipping implementation of ${item.criterionId}`)
      return null
    }
    // slug is LLM-produced (criterionId from the planning step) and flows into a
    // `git worktree add` shell command below — validate fail-closed, then shq it.
    const slug = item.criterionId.toLowerCase()
    assertShellSafe(slug, 'slug', RE_SLUG)
    return agent(
      `You are the implementation lane for ONE work item toward the acgs-lite PEP-closure goal.

${REPO_RULES}

Work item (criterion ${item.criterionId}): ${JSON.stringify(item.title)}

Plan:
${JSON.stringify(item.plan)}

Procedure:
1. Create an isolated worktree of the NESTED repo (not the parent):
   git -C ${PKG} worktree add ${shq(`${WT_BASE}/acgs-lite-${slug}`)} -b ${shq(`final-goal/acgs-lite-${slug}`)} main
   (Branch off "main" explicitly — the shared checkout sits on an unrelated improve/* branch; do not base on it. If the branch already exists, append a -2 suffix to both. If ${WT_BASE} does not exist, mkdir -p it.)
2. cd into that worktree. Read CLAUDE.md / AGENTS.md there first and obey them.
3. Make the smallest safe change that closes the gap, WITH tests (TDD where practical). Remember: opt-in + backward compatible; no new runtime deps unless the package already declares them.
4. Run the validation command locally from inside the worktree: ${assertCommandSafe(item.validationCommand, `items[${item.criterionId}].validationCommand`)}
5. Stage ONLY the files you changed (explicit paths, never -A), commit on the feature branch with a conventional message. Do NOT push. Do NOT touch the parent repo.
Report the absolute worktree path, branch name, and the files you changed. If you hit a hard blocker, set completed=false and explain in blockers.`,
      { label: `impl:${item.criterionId}`, phase: 'Implement', schema: IMPL_SCHEMA },
    )
  },
  // Stage 2 — independent review of the diff (separate agent from implementer)
  (impl, item) => {
    if (!impl || !impl.completed) return impl ? { impl, review: { verdict: 'block', issues: ['implementation incomplete: ' + (impl.blockers ?? 'unknown')] } } : null
    // impl.worktree/impl.branch are LLM-reported and flow into a `cd` command +
    // prompt text — validate fail-closed (path / git-ref allowlists also reject
    // newlines, blocking prompt injection), then shq the worktree where it lands
    // in a shell command. title/summary are free-form display text → JSON.stringify
    // to neutralize embedded newlines (matches the canonical reference's escaping).
    assertShellSafe(impl.worktree, 'impl.worktree', RE_PATH)
    assertShellSafe(impl.branch, 'impl.branch', RE_REF)
    return agent(
      `You are the review lane — you did NOT write this change. Review it adversarially against the repo's rules.

${REPO_RULES}

Change under review: criterion ${item.criterionId} — ${JSON.stringify(item.title)}
Worktree: ${shq(impl.worktree)}
Branch: ${impl.branch}
Files changed: ${JSON.stringify(impl.filesChanged)}
Implementer's summary: ${JSON.stringify(impl.summary)}

Procedure:
1. cd ${shq(impl.worktree)} && git log --oneline -5 && git diff $(git merge-base HEAD main 2>/dev/null || git merge-base HEAD master)...HEAD — review every hunk.
2. Check specifically:
   - fail-closed preserved? No path where a gate failure silently allows execution?
   - backward compatibility: is new enforcement opt-in? Does the default behavior of the published API stay identical (run the existing test suite mentally / spot-check)?
   - wiring: is the new gate actually reached from the public entry points (grep the new symbol OUTSIDE its own file — zero hits = not wired = block)? Do tests exercise the entry-point path, not just the function?
   - sealed/hash-marked files untouched by hand? No new runtime dependencies? Scope stayed inside the acgs-lite repo?
3. Verdict: approve / request-changes (fixable nits) / block (correctness, security, or boundary violation).`,
      { label: `review:${item.criterionId}`, phase: 'Review', schema: REVIEW_SCHEMA },
    ).then(review => ({ impl, review }))
  },
  // Stage 3 — verification with literal output
  (r, item) => {
    if (!r) return null
    if (r.review.verdict === 'block') return { item: item.criterionId, ...r, verify: { passed: false, command: '(skipped — review blocked)', outputTail: '' } }
    return agent(
      `You are the verification lane. Run the package-local gate and report LITERAL output — never summarize a result you did not run.

Worktree: ${shq(r.impl.worktree)} (cd there first; this is a worktree of the nested acgs-lite repo)
Validation command: ${assertCommandSafe(item.validationCommand, `items[${item.criterionId}].validationCommand`)}

Procedure:
1. Run the validation command exactly. Capture the last ~20 lines and the exit code.
2. Also run "git status --short" and confirm the worktree has no unintended drift outside ${JSON.stringify(r.impl.filesChanged)}.
3. passed=true ONLY if exit code is 0 and no drift.`,
      { label: `verify:${item.criterionId}`, phase: 'Verify', schema: VERIFY_SCHEMA },
    ).then(verify => ({ item: item.criterionId, ...r, verify }))
  },
)

// ---------------------------------------------------------------------------
// Final report
// ---------------------------------------------------------------------------
const done = outcomes.filter(Boolean)
const shipped = done.filter(o => o.verify?.passed && o.review?.verdict === 'approve')
log(`Run complete: ${shipped.length}/${selected.length} item(s) implemented, reviewed, and verified`)

return {
  scoreboard,
  metCount: `${met}/${CRITERIA.length}`,
  rationale: plan?.rationale,
  results: done.map(o => ({
    criterion: o.item,
    branch: o.impl?.branch,
    worktree: o.impl?.worktree,
    files: o.impl?.filesChanged,
    review: o.review?.verdict,
    reviewIssues: o.review?.issues,
    verified: o.verify?.passed,
    verifyOutput: o.verify?.outputTail,
  })),
  humanGated: audits.filter(a => a.status === 'blocked-human').map(a => ({ id: a.id, gap: a.gapSummary, nextAction: a.nextAction })),
  nextSteps: 'Verified branches live in worktrees of the NESTED acgs-lite repo — human reviews and merges/pushes from inside packages/acgs-lite (PyPI publish is human-gated). Re-run with {exclude:[...]} for the next increment; default run is dryRun scoreboard-only.',
}
