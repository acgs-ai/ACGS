export const meta = {
  name: 'final-goal-pursuit',
  description: 'Audit FINAL-GOAL.md gates G1/G2/G3 against the repo, pick the highest-leverage unmet criteria, then implement + review + verify one increment of progress',
  whenToUse: 'Each run produces one verifiable increment toward the ACGS project definition of done. Pass {dryRun:true} for scoreboard-only; {maxItems:N} to change how many criteria get implemented (default 2).',
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
// field has a safe default). Repo path is pinned absolutely because workflow
// sub-agents do NOT inherit the package cwd.
// ---------------------------------------------------------------------------
const REPO = '/home/martin/Documents/ACGS'

const input = typeof args === 'string'
  ? (() => { try { return JSON.parse(args) } catch { return {} } })()
  : (args ?? {})
const MAX_ITEMS = Number.isInteger(input?.maxItems) && input.maxItems > 0 ? Math.min(input.maxItems, 4) : 2
const DRY_RUN = input?.dryRun === true
// Criteria already implemented on in-flight (unmerged) branches — skip this run.
const EXCLUDE = Array.isArray(input?.exclude) ? input.exclude : []

// ---- Shell/prompt-safety for values embedded in sub-agent command snippets -
// Implementer / reviewer / verifier sub-agents are handed PROMPTS containing
// example shell commands (`cd <worktree>`, `git ... <branch>`, the validation
// command). Values that reach those snippets come from this workflow's args or
// from earlier sub-agents' (LLM-produced) structured output. Taken raw they
// enable two failure modes:
//   1. SHELL injection — a value with a quote / ; / $() / backtick can break
//      out of a command a sub-agent is told to run.
//   2. PROMPT injection — a value with a newline can inject new instructions
//      into the sub-agent's prompt. Shell-quoting does NOT stop this.
// So: VALIDATE first (fail closed — refuse on anything outside a narrow
// allowlist, which also rejects control chars / newlines), shell-quote second
// (defense in depth) wherever a value is embedded in a command.
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`
function assertShellSafe(value, label, allowed) {
  const s = String(value)
  if (!allowed.test(s)) {
    throw new Error(
      `final-goal-pursuit: refusing to run — \`${label}\` = ${JSON.stringify(s)} ` +
        `contains characters unsafe to embed in a sub-agent command/prompt (allowed: ${allowed}). ` +
        `This gate fails closed rather than emit a command a sub-agent could be tricked into ` +
        `mis-running, or a prompt it could be tricked into mis-reading.`
    )
  }
}
// Allowlists (mirrors review-branch-adversarial.js):
const RE_PATH = /^[A-Za-z0-9._/-]+$/ // filesystem path
const RE_REF = /^[A-Za-z0-9._/@~^{}-]+$/ // git ref / branch name
const RE_SLUG = /^[A-Za-z0-9._-]+$/ // slug / id component

// Nested git repositories registered in .gitmodules. In a worktree of the
// PARENT repo these paths are empty 160000 gitlinks, so work targeting them
// must be dispatched through a worktree of the nested repo itself.
const NESTED_REPOS = [
  'packages/acgs-lite',
  'packages/Acgs-Swarm',
  'packages/clinicalguard',
  'packages/ACGS-agency-agents',
  'packages/acgs-control-plane',
]

// Boundary containment for planner-produced packageDir values. RE_PATH only
// validates CHARACTERS: it still admits an arbitrary absolute path outside
// ${REPO} ("/tmp/evil") or a `..` escape, either of which would launch an
// implementation lane outside the git boundary this workflow governs. Fail
// closed on both, then report which nested repo (if any) owns the path so the
// dispatch site can create the worktree at the right repository.
function resolveBoundary(dir, label) {
  const s = String(dir)
  if (s.split('/').includes('..')) {
    throw new Error(`final-goal-pursuit: refusing to run: \`${label}\` = ${JSON.stringify(s)} contains a ".." segment (path escape).`)
  }
  // Normalize BEFORE containment and nested-owner matching: drop "." segments,
  // repeated slashes, and trailing slashes. A valid but noncanonical path such
  // as "packages/./acgs-lite" or "packages//acgs-lite" would otherwise pass
  // containment yet miss NESTED_REPOS and get dispatched through a parent
  // worktree, where the nested repo is only an empty gitlink.
  const segs = s.split('/').filter(seg => seg !== '' && seg !== '.')
  const joined = segs.join('/')
  const abs = s.startsWith('/') ? (joined ? `/${joined}` : '/') : (joined ? `${REPO}/${joined}` : REPO)
  if (abs !== REPO && !abs.startsWith(`${REPO}/`)) {
    throw new Error(`final-goal-pursuit: refusing to run: \`${label}\` = ${JSON.stringify(s)} resolves outside the repository boundary ${REPO}. Work outside the selected subproject cannot be reviewed or committed at the correct boundary.`)
  }
  const rel = abs === REPO ? '' : abs.slice(REPO.length + 1)
  const nested = NESTED_REPOS.find(n => rel === n || rel.startsWith(`${n}/`)) ?? null
  return { abs, nestedRepoDir: nested ? `${REPO}/${nested}` : null }
}

// EXCLUDE elements are arg-derived and appear in prompt/display text (newline =
// prompt injection). They are criterion ids like "G1.1" — validate fail-closed.
// (Display-only, never shell-interpolated, so no shq needed here.)
for (const id of EXCLUDE) assertShellSafe(id, 'exclude[]', RE_SLUG)

// The 16 gate criteria from FINAL-GOAL.md (embedded because the file is not
// yet committed; auditors should still read FINAL-GOAL.md at repo root if it
// exists and prefer its current wording).
const CRITERIA = [
  { id: 'G1.1', gate: 'G1', text: 'gove-zone >= 1.0.0 published to PyPI, semver discipline, signed releases. Verify: pip install gove-zone in clean venv; gove-zone smoke exits 0. NOTE: the actual PyPI publish is HUMAN-GATED; packaging/metadata/release-prep work is agent-implementable.' },
  { id: 'G1.2', gate: 'G1', text: 'Cross-platform audit locking: Linux, macOS, Windows (portable lock or platform-split implementation replacing bare fcntl). Verify: OS-matrix CI green incl. concurrent-writer test per OS. Constraint: gove-zone has ZERO runtime deps by design — use stdlib (fcntl POSIX + msvcrt Windows), never add filelock.' },
  { id: 'G1.3', gate: 'G1', text: 'Fail-closed coverage at 100% statement coverage on deny paths: disk/log exhaustion, policy runtime crash, watchdog timeout, malformed batch (runtime.malformed_batch), broker unavailable. Verify: fail-closed suite + coverage gate wired into make verify and CI.' },
  { id: 'G1.4', gate: 'G1', text: 'Adapter parity tested per runtime family: Claude/Codex hooks, MCP tools/call, function-call style, OpenAI Chat tool_calls, OpenAI Responses, LangChain, generic bridge, batched expansion. Verify: per-adapter conformance tests in make verify.' },
  { id: 'G1.5', gate: 'G1', text: 'Performance budget met on the ADR-0005 path (propagation: mean <=15%, p95 <=25%, tokens <=10%, heap <=5MB; or token-fallback equivalents). Verify: benchmark artifact committed under .benchmarks/.' },
  { id: 'G1.6', gate: 'G1', text: 'Unsafe-filesystem startup probe ships (NFS-without-lockd risk). Verify: probe test — audit path on NFS-like mount -> refuse to start, exit non-zero.' },
  { id: 'G2.1', gate: 'G2', text: 'Evidence bundle schema frozen and versioned: receipts, chain segments, constitution hash, identity trace (principal/tenant/role/delegation), replay inputs. Verify: published JSON Schema; bundle round-trips losslessly.' },
  { id: 'G2.2', gate: 'G2', text: 'Standalone verifier published as a separate dependency-minimal package validating a bundle WITHOUT gove-zone installed and without network access. Verify: clean-room machine verifies a published bundle, exit 0. (Publishing is human-gated; building the package is implementable.)' },
  { id: 'G2.3', gate: 'G2', text: 'Tamper resistance proven by mutation suite: any single-record or single-byte mutation across receipts/chain/constitution flips verification to FAIL. Verify: property-based mutation tests, 100% detection rate required.' },
  { id: 'G2.4', gate: 'G2', text: 'Deterministic replay: replaying a bundle reproduces identical decisions byte-for-byte. Verify: replay-equivalence test in CI.' },
  { id: 'G2.5', gate: 'G2', text: 'Constitutional integrity end-to-end: sealed-file hash CI blocks unsigned constitution changes; verifier cross-checks bundle constitution hash against the published registry. Verify: constitutional-hash workflow green + verifier cross-check test.' },
  { id: 'G3.1', gate: 'G3', text: 'At least 1 live production deployment governing a regulated workload (clinicalguard / Ontario healthcare; AGCO iGaming). HUMAN-GATED: deploy workflows and production claims are not agent-executable. Audit only: report readiness blockers.' },
  { id: 'G3.2', gate: 'G3', text: 'Console/admin surfaces fail closed in production: forward_auth upstream live, no SPA fallthrough on /console*. Production probe is HUMAN-GATED; local probe tests and config are implementable.' },
  { id: 'G3.3', gate: 'G3', text: 'Continuous evidence: production emits audit chains; an independent third party runs the G2 verifier on a production bundle and signs a verification report. HUMAN-GATED (requires external party).' },
  { id: 'G3.4', gate: 'G3', text: 'At least 1 deny/escalation handled fail-closed in production with governed incident evidence (organic or documented game-day). HUMAN-GATED for production; game-day tooling/runbooks are implementable.' },
  { id: 'G3.5', gate: 'G3', text: 'Buyer-evidence gallery served from live (not mocked) data for the deployed surface. Verify: pnpm -F acgi-ai run test:buyer-evidence against the production bundle source. Live-data wiring depends on G3.1; test scaffolding is implementable.' },
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
        required: ['criterionId', 'title', 'plan', 'packageDir', 'validationCommand'],
        properties: {
          criterionId: { type: 'string' },
          title: { type: 'string' },
          plan: { type: 'string', description: 'Concrete step-by-step plan with file paths' },
          packageDir: { type: 'string', description: 'The subproject directory the work lives in, absolute path' },
          validationCommand: { type: 'string', description: 'The package-local gate command that proves the work' },
        },
      },
    },
  },
}

const IMPL_SCHEMA = {
  type: 'object',
  required: ['completed', 'branch', 'baseRef', 'baseBranch', 'worktree', 'filesChanged', 'summary'],
  properties: {
    completed: { type: 'boolean' },
    noChangesNeeded: { type: 'boolean', description: 'true when the criterion is already satisfied and ZERO changes were made — then branch must be "" and filesChanged []' },
    branch: { type: 'string', description: 'git ref name only (e.g. final-goal/g1-2); empty string when noChangesNeeded — never prose' },
    baseRef: { type: 'string', description: 'the resolvable commit-ish the feature branch was actually created from, exactly as passed to git (e.g. origin/main when only the remote-tracking ref exists, or main when a local branch does); empty string when noChangesNeeded' },
    baseBranch: { type: 'string', description: 'short PR-facing base name with any origin/ prefix stripped (e.g. main); empty string when noChangesNeeded' },
    worktree: { type: 'string', description: 'Absolute path of the worktree the changes live in' },
    filesChanged: { type: 'array', items: { type: 'string' }, description: 'Changed file paths RELATIVE to the worktree root, matching git diff --name-only output' },
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
Repository: ${REPO} (run all commands from inside it; workflow agents do NOT start there — cd first).
Hard rules (non-negotiable):
- NEVER edit files carrying "Constitutional Hash:", "@generated", or "DO NOT EDIT" markers; never hand-edit docs/constitutional-hashes.lock.
- NEVER weaken fail-closed behavior, bypass receipt validation, or treat DENY/ESCALATE as executable.
- NEVER run: git add -A, git add ., git stash, git reset --hard, git push --force, gh pr merge, gcloud, vercel, or anything touching secrets. Publishing to PyPI and production deploys are HUMAN-GATED.
- packages/acgs-lite, packages/Acgs-Swarm, packages/clinicalguard are nested git repos — do not stage from the parent across that boundary.
- Before editing inside any subdirectory, read its local CLAUDE.md / AGENTS.md and obey them over root assumptions.
- gove-zone has dependencies=[] by design — stdlib or optional extras only, never new runtime deps.
`.trim()

// ---------------------------------------------------------------------------
// Phase 1 — Audit (fan-out in waves of <=8 to avoid 429 bursts)
// ---------------------------------------------------------------------------
phase('Audit')
log(`Auditing ${CRITERIA.length} gate criteria against ${REPO}`)

const audits = []
for (let i = 0; i < CRITERIA.length; i += 8) {
  const wave = CRITERIA.slice(i, i + 8)
  const results = await parallel(wave.map(c => () =>
    agent(
      `You are auditing ONE exit criterion of the ACGS project final goal against the actual repository state. Report evidence, not optimism.

${REPO_RULES}

Criterion ${c.id} (gate ${c.gate}):
${c.text}

Procedure:
1. cd ${REPO}. If FINAL-GOAL.md exists at the repo root, read the row for ${c.id} and prefer its current wording.
2. Search the repo for implementation, tests, CI workflows, and artifacts relevant to this criterion (grep, read code, check .github/workflows/, Makefile, package manifests).
3. Where cheap and read-only, RUN the verification (e.g. a targeted pytest, a make target) and cite literal output. Do not run anything that mutates state, installs from the network, deploys, or takes >3 minutes.
4. Classify status: met / partial / unmet / blocked-human (blocked-human = the remaining gap requires publish, deploy, merge, secrets, or an external party).
5. agentImplementable=true only if a coding agent could close part of the gap purely with local code/test/CI changes.
Be skeptical: a unit test that imports a handler directly does NOT prove wiring; local success is not production proof. Set id to "${c.id}".`,
      { label: `audit:${c.id}`, phase: 'Audit', schema: AUDIT_SCHEMA },
    )))
  // Fail closed on missing lanes: a crashed audit agent (null result) must stay
  // visible as an explicit "unknown" for its criterion — silently dropping it
  // would shrink the scoreboard and could make "no implementable gaps remain"
  // a statement about criteria that were never evaluated. Each lane must also
  // report the criterion it was asked to audit: a result with the wrong id
  // would duplicate one criterion while silently omitting another, so require
  // r.id === c.id.
  wave.forEach((c, j) => {
    const r = results[j]
    audits.push(r && r.id === c.id ? r : {
      id: c.id,
      status: 'unknown',
      evidence: '',
      gapSummary: 'audit lane crashed, returned no structured result, or reported a mismatched criterion id: criterion NOT evaluated',
      agentImplementable: false,
      nextAction: 're-run this audit lane',
      scope: 'small',
    })
  })
  log(`Audit wave done: ${audits.length}/${CRITERIA.length} criteria accounted for`)
}

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
    note: `Audit incomplete — ${unaudited.length}/${CRITERIA.length} criteria returned no verdict (crashed/empty audit lanes). Prioritization was NOT run: an incomplete scoreboard cannot prove "no implementable gaps remain". Re-run the workflow.`,
  }
}

// ---------------------------------------------------------------------------
// Phase 2 — Prioritize (barrier is correct: ranking needs all 16 results)
// ---------------------------------------------------------------------------
phase('Prioritize')
const candidates = audits.filter(a => a.agentImplementable && a.status !== 'met' && !EXCLUDE.includes(a.id))
if (EXCLUDE.length) log(`Excluded (in-flight on unmerged branches): ${EXCLUDE.join(', ')}`)

if (candidates.length === 0) {
  return { scoreboard, selected: [], note: 'No agent-implementable unmet criteria found — remaining gaps are human-gated.', humanGated: audits.filter(a => a.status === 'blocked-human') }
}

const plan = await agent(
  `You are the planning lane for the ACGS final-goal pursuit. From the audit results below, select the ${MAX_ITEMS} highest-leverage work items a coding agent can complete THIS RUN, and write a concrete plan for each.

${REPO_RULES}

Selection rules:
- Highest leverage = unblocks the most downstream gate rows, or converts a "partial" to "met" with bounded scope. Prefer small/medium scope over large.
${EXCLUDE.length ? `- ALREADY IN FLIGHT (implemented on unmerged branches, do NOT select): ${EXCLUDE.join(', ')}. Avoid plans that conflict with those pending changes.` : ''}
- Each item must be completable locally: code + tests + a package-local validation command. No publishing, deploying, merging.
- One item = one subproject directory. Name the absolute packageDir and the exact validationCommand (prefer commands documented in that package's Makefile/CLAUDE.md, e.g. "uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q").
- Read the relevant package's CLAUDE.md/AGENTS.md before finalizing each plan.

Audit results:
${JSON.stringify(candidates, null, 2)}

Full scoreboard for context:
${JSON.stringify(scoreboard, null, 2)}`,
  { label: 'prioritize', phase: 'Prioritize', schema: PLAN_SCHEMA },
)

const selected = (plan?.items ?? []).slice(0, MAX_ITEMS)
// criterionId and packageDir are LLM-produced (planner output) and flow into
// shell snippets in the implement/review/verify prompts (branch name derived
// from criterionId; packageDir into `cd`/scope checks). Validate fail-closed
// before any are embedded. A planner that emits an id/path with a quote, ;,
// $(), backtick, or newline is refused rather than handed to a sub-agent.
// validationCommand/plan/title (and impl.summary in Stage 2) are intentionally
// free-form command/prose meant to be run/shown verbatim, so they CANNOT be
// allowlisted or shell-quoted away — but a newline in them would inject new
// instructions into a sub-agent's prompt (prompt injection; the file header at
// the top names this exact threat). So they are JSON.stringify'd at each
// interpolation site, which escapes newlines/control chars to literal \n while
// preserving the content — neutralizing the injection without rejecting the
// (legitimately multi-line) values.
for (const it of selected) {
  assertShellSafe(it.criterionId, 'criterionId', RE_SLUG)
  assertShellSafe(it.packageDir, 'packageDir', RE_PATH)
  // Character validation is not containment: also require packageDir to live
  // inside ${REPO}, and record whether a nested repo owns it so Stage 1 can
  // create the worktree at that repository instead of the parent (where the
  // nested path is an empty gitlink and nothing can be committed).
  const boundary = resolveBoundary(it.packageDir, `items[${it.criterionId}].packageDir`)
  it.packageDir = boundary.abs
  it.nestedRepoDir = boundary.nestedRepoDir
}
log(`Selected ${selected.length} work item(s): ${selected.map(s => s.criterionId).join(', ')}`)

if (DRY_RUN) {
  return { scoreboard, rationale: plan?.rationale, selected, note: 'dryRun=true — audit + plan only, nothing implemented.', humanGated: audits.filter(a => a.status === 'blocked-human').map(a => ({ id: a.id, gap: a.gapSummary })) }
}

// ---------------------------------------------------------------------------
// Phases 3-5 — Implement -> Review -> Verify, pipelined per item.
// Worktree isolation: items mutate files concurrently without colliding.
// Reviewer is a SEPARATE agent from the implementer (hard repo rule).
// ---------------------------------------------------------------------------
const outcomes = await pipeline(
  selected,
  // Stage 1 — implement, isolated in its own worktree
  item => {
    if (budget.total && budget.remaining() < 80_000) {
      log(`Budget low — skipping implementation of ${item.criterionId}`)
      return null
    }
    const slug = item.criterionId.toLowerCase().replace('.', '-')
    // Nested-repo targets CANNOT use a parent worktree: the nested path is an
    // empty 160000 gitlink there, so the task is unperformable and nothing can
    // be committed at the correct boundary. Dispatch those through a worktree
    // of the nested repository itself (mirrors acgs-lite-pep-closure-pursuit).
    if (item.nestedRepoDir) {
      // The planner's packageDir (and any absolute paths inside its plan text)
      // point into the SHARED checkout, but the implementation happens in the
      // temporary worktree created in step 2. Hand the lane the package path
      // RELATIVE to the nested repo root so following it lands inside the
      // worktree, and mark the shared checkout as read-only: an implementer
      // following absolute plan paths would edit the original submodule while
      // the reviewer and verifier inspect the worktree.
      const nestedRel = item.packageDir === item.nestedRepoDir ? '.' : item.packageDir.slice(item.nestedRepoDir.length + 1)
      return agent(
        `You are the implementation lane for ONE work item toward the ACGS final goal. The work targets a NESTED git repository (${item.nestedRepoDir} has its own .git, registered as a submodule of ${REPO}); inside that repository the work lives at ${JSON.stringify(nestedRel)} relative to the repo root. A worktree of the parent repo records the nested repo as an empty gitlink, so you MUST create and work in a worktree of the nested repo itself.

${REPO_RULES}

Work item (criterion ${item.criterionId}): ${JSON.stringify(item.title)}

Plan (any absolute paths in it refer to the shared checkout; translate them to the same paths relative to YOUR worktree root before acting, and never follow them into the shared checkout):
${JSON.stringify(item.plan)}

Procedure:
1. Determine the nested repo's base explicitly (NEVER base on the shared checkout's current HEAD, which may sit on an unrelated in-flight branch). Resolve TWO values: base_ref, the resolvable commit-ish the worktree starts from, and base_branch, the short PR-facing name. A detached submodule checkout often has ONLY remote-tracking refs, and a short name that exists only under refs/remotes/ is NOT resolvable by "git worktree add", so never strip origin/ from the start ref. Resolve in this order:
   a. base_ref="$(git -C ${shq(item.nestedRepoDir)} symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null)" (e.g. origin/main). If non-empty: base_branch="\${base_ref#origin/}".
   b. Else the first name of main, master for which "git -C ${shq(item.nestedRepoDir)} show-ref --verify --quiet refs/heads/<name>" succeeds: base_ref=<name>, base_branch=<name>.
   c. Else the first name of main, master for which "git -C ${shq(item.nestedRepoDir)} show-ref --verify --quiet refs/remotes/origin/<name>" succeeds: base_ref=origin/<name>, base_branch=<name>.
   d. If none resolve, STOP: set completed=false and explain in blockers. Do not guess a ref.
2. Create an isolated worktree of the NESTED repo (not the parent), starting from that ref: git -C ${shq(item.nestedRepoDir)} worktree add "$(mktemp -d)/wt" -b ${shq(`final-goal/${slug}`)} "$base_ref" (if the branch already exists, append a -2 suffix).
3. cd into that worktree and do ALL reading, editing, running, and staging from inside it, addressing files by paths relative to its root (the work lives at ${JSON.stringify(nestedRel)}). The shared checkout at ${item.nestedRepoDir} is the source for "git worktree add" ONLY: never edit, run validation in, or stage files there. Read the package-local CLAUDE.md / AGENTS.md first and obey them.
4. Make the smallest safe change that closes the gap, WITH tests (TDD where practical).
5. Run the validation command locally from inside the worktree: ${JSON.stringify(item.validationCommand)}
6. Stage ONLY the files you changed (explicit paths, never -A), commit on the feature branch with a conventional message. Do NOT push. NEVER touch the parent repo or its submodule pointer.
Report the absolute worktree path, branch name, the base you resolved in step 1 (baseRef = the exact start ref you passed to git, e.g. origin/main; baseBranch = the short PR-facing name, e.g. main), and the files you changed as paths RELATIVE to the worktree root (matching git diff --name-only output). If you hit a hard blocker, set completed=false and explain in blockers.
If you determine the criterion is ALREADY satisfied and zero changes are required: set completed=true, noChangesNeeded=true, branch="" (empty — NEVER prose in the branch field), baseRef="", baseBranch="", filesChanged=[], and put the evidence in summary.`,
        { label: `impl:${item.criterionId}`, phase: 'Implement', schema: IMPL_SCHEMA },
      )
    }
    return agent(
      `You are the implementation lane for ONE work item toward the ACGS final goal. You are running in an isolated git worktree of ${REPO} — discover your worktree root with "git rev-parse --show-toplevel" and work there.

${REPO_RULES}

Work item (criterion ${item.criterionId}): ${JSON.stringify(item.title)}

Plan:
${JSON.stringify(item.plan)}

Package directory (relative to the worktree what ${item.packageDir} is to the main checkout): adjust the path to your worktree root.

Procedure:
1. Read the package-local CLAUDE.md / AGENTS.md first and obey them.
2. Resolve the repository's real base explicitly (NEVER report the branch the worktree happened to start on: isolation worktrees can begin on a generated transient branch or a detached HEAD, neither of which is a ref a PR can target). Resolve TWO values: base_ref, the resolvable commit-ish to branch from, and base_branch, the short PR-facing name. A checkout may expose the base ONLY as a remote-tracking ref, and a short name that exists only under refs/remotes/ is NOT resolvable, so never strip origin/ from the start ref. Resolve in this order:
   a. base_ref="$(git symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null)" (e.g. origin/master). If non-empty: base_branch="\${base_ref#origin/}".
   b. Else the first name of main, master for which "git show-ref --verify --quiet refs/heads/<name>" succeeds: base_ref=<name>, base_branch=<name>.
   c. Else the first name of main, master for which "git show-ref --verify --quiet refs/remotes/origin/<name>" succeeds: base_ref=origin/<name>, base_branch=<name>.
   d. If none resolve, STOP: set completed=false and explain in blockers. Do not guess a ref.
3. Create the feature branch FROM that ref: git switch -c ${shq(`final-goal/${slug}`)} "$base_ref" (if the branch already exists, append a -2 suffix).
4. Make the smallest safe change that closes the gap, WITH tests (TDD where practical).
5. Run the validation command locally: ${JSON.stringify(item.validationCommand)}
6. Stage ONLY the files you changed (explicit paths, never -A), commit on the feature branch with a conventional message. Do NOT push.
Report the absolute worktree path, branch name, the base you resolved in step 2 (baseRef = the exact start ref you passed to git, e.g. origin/master; baseBranch = the short PR-facing name, e.g. master), and the files you changed as paths RELATIVE to the worktree root (matching git diff --name-only output). If you hit a hard blocker, set completed=false and explain in blockers.
If you determine the criterion is ALREADY satisfied and zero changes are required: set completed=true, noChangesNeeded=true, branch="" (empty — NEVER prose in the branch field), baseRef="", baseBranch="", filesChanged=[], and put the evidence in summary.`,
      { label: `impl:${item.criterionId}`, phase: 'Implement', isolation: 'worktree', schema: IMPL_SCHEMA },
    )
  },
  // Stage 2 — independent review of the diff
  (impl, item) => {
    if (!impl || !impl.completed) return impl ? { impl, review: { verdict: 'block', issues: ['implementation incomplete: ' + (impl.blockers ?? 'unknown')] } } : null
    // Legitimate no-op: criterion already satisfied, zero changes made. Nothing
    // to review or verify, and impl.branch/worktree are never embedded in a
    // shell snippet on this path — short-circuit BEFORE the shell-safety gate.
    if (impl.noChangesNeeded === true || (impl.filesChanged ?? []).length === 0) {
      return { impl, review: { verdict: 'no-op', issues: [] }, noop: true }
    }
    // impl.worktree / impl.branch are LLM-produced (implementer output) and are
    // embedded in shell snippets (`cd <worktree>`, branch references) handed to
    // the reviewer/verifier. Validate fail-closed before embedding; a path/ref
    // carrying a quote, ;, $(), backtick, or newline is refused.
    // impl.summary is free-form prose (often multi-line) shown to the reviewer —
    // not allowlistable; it is JSON.stringify'd at its interpolation site below
    // to escape newlines/control chars (prompt-injection defense).
    assertShellSafe(impl.worktree, 'impl.worktree', RE_PATH)
    assertShellSafe(impl.branch, 'impl.branch', RE_REF)
    // Normalize reported filesChanged BEFORE the reviewer's diff preflight sees
    // them: the schema asks for worktree-relative paths but permits absolute
    // ones, and "git diff --name-only" emits repository-relative paths, so an
    // absolute entry like "<worktree>/src/foo.py" would fail the mandatory
    // inclusion check (and the verifier's drift check against "git status
    // --short") even when the diff covers every change. Strip the worktree
    // prefix from entries under the worktree; an absolute path NOT under the
    // worktree cannot appear in the reviewed diff at all, so block fail-closed
    // rather than hand the reviewer a list it can never satisfy. Mutating
    // impl.filesChanged keeps Stage 3 and the final report consistent.
    const wtPrefix = impl.worktree.endsWith('/') ? impl.worktree : `${impl.worktree}/`
    const normalizedFiles = []
    for (const f of impl.filesChanged ?? []) {
      const s = String(f)
      if (s.startsWith(wtPrefix)) normalizedFiles.push(s.slice(wtPrefix.length))
      else if (s.startsWith('/')) {
        return { impl, review: { verdict: 'block', issues: [`implementer reported changed file ${JSON.stringify(s)} outside its worktree ${JSON.stringify(impl.worktree)}: the file cannot be part of the reviewed diff, so the change cannot receive an effective review`] } }
      } else {
        normalizedFiles.push(s.replace(/^(\.\/)+/, ''))
      }
    }
    impl.filesChanged = normalizedFiles
    // The base the implementer branched from. The reviewer must diff against
    // impl.baseRef, the exact commit-ish the branch was created from: the
    // short baseBranch name can be UNRESOLVABLE in the worktree (a nested or
    // detached checkout often exposes only refs/remotes/origin/main, where
    // "main" does not resolve but "origin/main" does). No fallback: guessing
    // a ref makes the diff exit 128 and the change would sail through with no
    // effective review. A non-no-op result missing either field is blocked
    // fail-closed instead.
    if (!impl.baseRef || !impl.baseBranch) {
      return { impl, review: { verdict: 'block', issues: ['implementer reported no baseRef/baseBranch: the reviewer cannot diff against the ref the feature branch was created from, so the change cannot receive an effective review'] } }
    }
    const reviewBase = impl.baseRef
    assertShellSafe(reviewBase, 'impl.baseRef', RE_REF)
    assertShellSafe(impl.baseBranch, 'impl.baseBranch', RE_REF)
    // A syntactically valid baseRef can still be the WRONG ref: if the
    // implementer reports its own feature branch (or HEAD, or the feature
    // branch's remote-tracking ref) as the base, the instructed diff is empty
    // and the change would be approved with zero hunks reviewed. Refuse the
    // obvious self-references deterministically here; the remaining
    // properties (base resolves, is an ancestor, and the diff actually
    // covers the reported files) can only be proven inside the worktree, so
    // the reviewer preflights them below and blocks on failure.
    if (reviewBase === impl.branch || reviewBase === `origin/${impl.branch}` || reviewBase.toUpperCase() === 'HEAD' || reviewBase === '@') {
      return { impl, review: { verdict: 'block', issues: [`implementer reported baseRef=${JSON.stringify(reviewBase)}, which is the feature branch itself (or HEAD): diffing it against HEAD is empty, so the change cannot receive an effective review`] } }
    }
    return agent(
      `You are the review lane — you did NOT write this change. Review it adversarially against the repo's rules.

${REPO_RULES}

Change under review: criterion ${item.criterionId} — ${JSON.stringify(item.title)}
Worktree: ${impl.worktree}
Branch: ${impl.branch}
Base ref: ${reviewBase} (the exact commit-ish the feature branch was created from; PR-facing base name: ${impl.baseBranch})
Files changed: ${JSON.stringify(impl.filesChanged)}
Implementer's summary: ${JSON.stringify(impl.summary)}

Procedure:
1. cd ${shq(impl.worktree)}, then PREFLIGHT the diff basis before reviewing anything. The base ref above was reported by the implementation lane and may be wrong; verdict=block (do not review further) if ANY of these fails:
   a. git rev-parse --verify ${shq(`${reviewBase}^{commit}`)} succeeds, and its commit differs from "git rev-parse HEAD" (a base equal to the tip diffs empty: nothing would be reviewed).
   b. git merge-base --is-ancestor ${shq(reviewBase)} HEAD exits 0 (the base must be an ancestor of the feature branch).
   c. git diff --name-only ${shq(reviewBase)}...HEAD is non-empty and includes EVERY file in the "Files changed" list above (a diff that misses reported files means the base is wrong and hunks would silently escape review).
2. git diff ${shq(reviewBase)}...HEAD: review every hunk.
3. Check: fail-closed behavior preserved? sealed/hash-marked files untouched? handler actually WIRED into the dispatch path (grep the symbol outside its own file; zero hits = not wired = block)? tests exercise the registration path, not just the function? scope stayed inside ${item.packageDir}? no new runtime deps in gove-zone?
4. Verdict: approve / request-changes (fixable nits) / block (correctness, security, or boundary violation).`,
      { label: `review:${item.criterionId}`, phase: 'Review', schema: REVIEW_SCHEMA },
    ).then(review => ({ impl, review }))
  },
  // Stage 3 — verification with literal output
  (r, item) => {
    if (!r) return null
    if (r.noop) return { item: item.criterionId, ...r, verify: { passed: true, command: '(skipped — no changes required, criterion already satisfied)', outputTail: '' } }
    if (r.review.verdict === 'block') return { item: item.criterionId, ...r, verify: { passed: false, command: '(skipped — review blocked)', outputTail: '' } }
    // Re-validate before embedding in the verifier's `cd` snippet (additive /
    // defense-in-depth; already gated in Stage 2 on the same impl object).
    assertShellSafe(r.impl.worktree, 'impl.worktree', RE_PATH)
    return agent(
      `You are the verification lane. Run the package-local gate and report LITERAL output — never summarize a result you did not run.

Worktree: ${shq(r.impl.worktree)} (cd there first)
Validation command: ${JSON.stringify(item.validationCommand)}

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
const noops = done.filter(o => o.noop)
const shipped = done.filter(o => !o.noop && o.verify?.passed && o.review?.verdict === 'approve')
log(`Run complete: ${shipped.length}/${selected.length} item(s) implemented, reviewed, and verified${noops.length ? ` (+${noops.length} already-satisfied no-op)` : ''}`)

return {
  scoreboard,
  metCount: `${met}/${CRITERIA.length}`,
  rationale: plan?.rationale,
  results: done.map(o => ({
    criterion: o.item,
    noop: o.noop === true || undefined,
    branch: o.impl?.branch,
    // baseRef is the exact commit-ish the feature branch was created from
    // (possibly a remote-tracking ref like origin/main), as reported by the
    // implementer and preflighted by the reviewer. baseBranch is its short
    // PR-facing name. The PR handoff MUST target baseBranch: nested repos
    // expose main (not master), so assuming the parent repo's default branch
    // would open PRs against a base that does not exist.
    baseRef: o.impl?.baseRef,
    baseBranch: o.impl?.baseBranch,
    worktree: o.impl?.worktree,
    files: o.impl?.filesChanged,
    review: o.review?.verdict,
    reviewIssues: o.review?.issues,
    verified: o.verify?.passed,
    verifyOutput: o.verify?.outputTail,
  })),
  humanGated: audits.filter(a => a.status === 'blocked-human').map(a => ({ id: a.id, gap: a.gapSummary, nextAction: a.nextAction })),
  nextSteps: 'Verified branches live in their worktrees. A human opens each PR against that result\'s baseBranch (nested repos expose main, not master; never assume the parent repo\'s default branch). gh pr merge is human-gated. Re-run this workflow for the next increment; pass {dryRun:true} for scoreboard only.',
}
