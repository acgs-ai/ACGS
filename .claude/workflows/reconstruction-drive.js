export const meta = {
  name: 'reconstruction-drive',
  description:
    'Phase-parametrized dynamic driver for the platform-reconstruction roadmap: reads docs/reconstruction/ at origin/master at runtime, decomposes the selected phase into id-stable work items, prepares the agent-preparable ones in isolated worktrees, verifies with package-scoped gates, and reviews each with a distinct fresh-context reviewer. Human-gated items (merge/deploy/publish/secret/env-arm) are surfaced, never executed.',
  whenToUse:
    'Run with no args (or {phase:"A"}) for a read-only preview of the decomposed roadmap plus the exact human-gated actions. Pass {phase:"A"|"B"|"C"|"D", execute:true, items:["<id>",...]} to prepare ONLY the caller-named work items (drawn from a prior preview) on feature branches in isolated worktrees. execute:true with empty/absent items stays preview-only. To execute, RESUME the preview run (resumeFromRunId) rather than launching fresh — resuming replays the cached Survey manifest so the item ids stay pinned; a fresh run may re-slug them. Phase D is checklist-only forever. {maxItems:N} caps concurrent preparations (default 4, hard max 4).',
  phases: [
    { title: 'Survey', model: 'opus' },
    { title: 'Prepare' },
    { title: 'Verify', model: 'sonnet' },
    { title: 'Review', model: 'opus' },
  ],
}

// ---------------------------------------------------------------------------
// Config — inline constants with safe defaults. args have historically arrived
// undefined, as a JSON string, or as an object; an undefined/garbled args MUST
// degrade to the read-only preview, never to a mutating run. The repo root is
// pinned absolutely because workflow sub-agents do NOT inherit the package cwd.
// ---------------------------------------------------------------------------
const REPO = '/home/martin/Documents/ACGS'

const input =
  typeof args === 'string'
    ? (() => {
        try {
          return JSON.parse(args)
        } catch {
          return {}
        }
      })()
    : (args ?? {})

const PHASE = ['A', 'B', 'C', 'D'].includes(input?.phase) ? input.phase : 'A'
// Fail-closed default: preview only. Mutation requires an explicit literal true.
const EXECUTE = input?.execute === true
// Mutation operates ONLY on caller-named ids drawn from a prior preview.
const NAMED_IDS = Array.isArray(input?.items)
  ? input.items.filter((x) => typeof x === 'string' && x.trim()).map((x) => x.trim())
  : []
// Pacing cap lives in JS control flow only — never in a prompt string (embedding
// a variant value in prompt text breaks the resume/journal cache).
const MAX_ITEMS =
  Number.isInteger(input?.maxItems) && input.maxItems > 0 ? Math.min(input.maxItems, 4) : 4

// ---------------------------------------------------------------------------
// Shared prompt fragments (reused from aiops-dev-recovery.js — proven idioms)
// ---------------------------------------------------------------------------
const REPO_RULES = `
Repository: ${REPO} is the SHARED main checkout — it is live on another branch and OFF-LIMITS for any mutation; never cd into it to edit, commit, or branch. All git READ operations (git fetch, git show, git rev-parse) work from your OWN worktree because every worktree shares the same .git object store — run them where you already are, never from ${REPO}.
Hard rules (non-negotiable):
- NEVER edit files carrying "Constitutional Hash:", "@generated", or "DO NOT EDIT" markers; never hand-edit docs/constitutional-hashes.lock.
- NEVER weaken fail-closed behavior, bypass receipt validation, or treat DENY/ESCALATE as executable.
- NEVER run: git add -A, git add ., git stash, git reset --hard, git clean -f, git checkout master, git push, git push --force, gh pr merge, gh pr close, gh secret, gh release, gh workflow run, gcloud, vercel, sudo. Publishing and production deploys are HUMAN-GATED.
- If a command is refused by a permission deny-rule, do NOT retry it (not once, not with tweaked flags). Record it as a human-gated action and move on.
- packages/acgs-lite, packages/Acgs-Swarm, packages/clinicalguard are nested git repos — never stage across that boundary from the parent; commit from inside the nested repo only.
- Before editing inside any subdirectory, read its local CLAUDE.md / AGENTS.md and obey them over root assumptions.
- gove-zone has dependencies=[] by design — stdlib or optional extras only, never new runtime deps.
- The main checkout is SHARED with other live sessions and is dirty by design: treat files you did not create as someone else's work. All mutations happen in your own isolated worktree, never in ${REPO} itself.
- gh auth caveat: an expired keyring token makes public-repo READS silently fall back anonymous while writes 401 — "gh auth status" lies; trust "gh api user".
`.trim()

const EVIDENCE_RULES = `
VERIFICATION DISCIPLINE (non-negotiable): report ONLY what commands actually printed. Capture exit codes with echo "EXIT:$?" immediately after each command. Never claim a pass without the literal exit code you observed.`.trim()

// Reviewer charter — embedded inline so the graceful fallback (a plain default
// reviewer with no named agentType) carries the same rubric as the named ones.
const REVIEWER_CHARTER = `
You are the REVIEW lane and you did NOT author this change (author != reviewer). Review the prepared diff against the repo's local instructions and these checks:
- Fail-closed integrity: no weakening of DENY/ESCALATE handling, receipt validation, audit-chain append, or single-use enforcement.
- Sealed files: no edits to Constitutional-Hash / @generated / DO NOT EDIT files or the hash lock.
- Boundary discipline: no staging across a nested-repo boundary (packages/acgs-lite, packages/Acgs-Swarm, packages/clinicalguard); no unrelated cross-package edits.
- Handler wiring: a new handler/route/tool/command/middleware is INCOMPLETE unless it is registered in the runtime dispatch path AND exercised by a test that hits the dispatcher, not one that imports and calls it directly. If wiring cannot be traced end-to-end, set wired=false.
- Tests + evidence: the change carries tests where it is a code/test change, and the package-scoped gate is the proof.
Verdict: ALLOW only when every check passes; REQUEST_CHANGES for fixable gaps (missing wiring/tests/scope creep); BLOCK for a fail-closed, sealed-file, or boundary violation.`.trim()

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------
const WORKPLAN_SCHEMA = {
  type: 'object',
  required: ['roadmapSha', 'workItems'],
  properties: {
    roadmapSha: { type: 'string', description: 'The origin/master commit SHA the roadmap docs were read at' },
    workItems: {
      type: 'array',
      items: {
        type: 'object',
        required: [
          'id',
          'title',
          'phase',
          'theme',
          'agentPreparable',
          'remediation',
          'roadmapRef',
        ],
        properties: {
          id: {
            type: 'string',
            description:
              'Deterministic slug derived from roadmapRef (doc + section + item), lowercase kebab-case. Never an invented free-form slug.',
          },
          title: { type: 'string' },
          phase: { type: 'string', enum: ['A', 'B', 'C', 'D'] },
          theme: { type: 'string', description: 'Short area tag, e.g. evidence-lib, signing, hash-gate, brand, deploy' },
          agentPreparable: {
            type: 'boolean',
            description:
              'true ONLY for a local code/doc/config/test change — never merge, deploy, secrets, publish, or env/trust-arming. Phase D items are always false.',
          },
          packageDir: {
            type: 'string',
            description:
              'Subproject dir the change lives in, RELATIVE to the repo root (e.g. "acgi-ai", "packages/acgs-lite", or "." for the root). Never an absolute path — it is joined against each isolated worktree root at run time. Required when agentPreparable.',
          },
          remediation: {
            type: 'string',
            description:
              'Concrete file-level plan (agentPreparable) or the exact command/action a human must run (human-gated).',
          },
          validationCommand: {
            type: 'string',
            description:
              'Package-scoped gate command that proves the change, written RELATIVE to the repo root — no absolute paths and no cd into any specific checkout; it is executed from the root of an isolated worktree. Required when agentPreparable.',
          },
          dependsOn: { type: 'array', items: { type: 'string' }, description: 'Ids of work items that must land first' },
          humanAction: {
            type: 'string',
            description: 'For non-agentPreparable items: the exact human-gated command/step.',
          },
          roadmapRef: {
            type: 'string',
            description:
              'Traceable citation into roadmap section 5/6 of 00-EXECUTIVE-SUMMARY.md or section 8 of 05-production-deployment.md, e.g. "00#5:extract-l0-evidence-lib".',
          },
        },
      },
    },
    openDecisions: {
      type: 'array',
      items: {
        type: 'object',
        required: ['ref', 'question'],
        properties: {
          ref: { type: 'string', description: 'Citation into 00-EXECUTIVE-SUMMARY.md section 7' },
          question: { type: 'string' },
          blocksPhase: { type: 'string', description: 'Which phase (B/C) this decision gates, if any' },
        },
      },
    },
  },
}

const PREP_SCHEMA = {
  type: 'object',
  required: ['completed', 'branch', 'worktree', 'filesChanged', 'summary'],
  properties: {
    completed: { type: 'boolean' },
    branch: { type: 'string' },
    worktree: { type: 'string', description: 'Absolute worktree path the changes live in' },
    filesChanged: { type: 'array', items: { type: 'string' } },
    summary: { type: 'string' },
    blockers: { type: 'string' },
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

const REVIEW_SCHEMA = {
  type: 'object',
  required: ['verdict', 'findings', 'wired'],
  properties: {
    verdict: { type: 'string', enum: ['ALLOW', 'REQUEST_CHANGES', 'BLOCK'] },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['severity', 'detail'],
        properties: {
          severity: { type: 'string', enum: ['info', 'minor', 'major', 'blocker'] },
          detail: { type: 'string' },
        },
      },
    },
    wired: {
      type: 'boolean',
      description:
        'true only if any new handler/route/tool is registered in the runtime path AND exercised by a dispatcher-level test. false when there is no wiring to trace or it is not covered.',
    },
  },
}

// ---------------------------------------------------------------------------
// Phase 1 — Survey (single opus agent; reads the roadmap at runtime and
// decomposes it deterministically). The prompt is a pure function of the roadmap
// at origin/master — it references neither the selected phase nor execute/items/
// budget — so the same roadmap SHA yields a byte-identical manifest and the
// journal caches it for resume.
// ---------------------------------------------------------------------------
phase('Survey')
log(`reconstruction-drive: surveying roadmap at origin/master — phase=${PHASE}, execute=${EXECUTE}`)

const surveyPrompt = `You are the SURVEY lane. Decompose the merged platform-reconstruction roadmap into id-stable work items. Read only; change nothing.

${REPO_RULES}

Procedure:
1. git fetch origin master --quiet || true — run from your own worktree; all worktrees share the object store so this updates origin/master without touching the shared main checkout.
2. Capture the roadmap commit: git rev-parse origin/master — report it as roadmapSha.
3. Read the roadmap at that commit (never the working tree):
   - git show origin/master:docs/reconstruction/00-EXECUTIVE-SUMMARY.md — focus on section 5 (roadmap / workstreams), section 6 (execution), and section 7 (open decisions).
   - git show origin/master:docs/reconstruction/05-production-deployment.md — focus on section 8 (deployment / cutover).
4. Read current repo state for context only: git rev-parse --abbrev-ref HEAD ; git log --oneline -3 ; git status --short | head -20.

Emit workItems spanning ALL phases A-D found in the roadmap. For each item:
- id: derive it DETERMINISTICALLY from roadmapRef — slugify the doc number, section number, and the item's own heading into lowercase kebab-case (example: roadmapRef "00#5:extract-l0-evidence-lib" -> id "doc00-s5-extract-l0-evidence-lib"). Do NOT invent free-form slugs; two runs over the same roadmap text MUST produce the same id.
- roadmapRef: a citation traceable to section 5 or 6 of doc 00, or section 8 of doc 05. An item with no such traceable roadmapRef must be DROPPED, not emitted.
- phase: the roadmap phase (A/B/C/D) the item belongs to.
- theme: a short area tag.
- agentPreparable: true ONLY when a local code/doc/config/test change closes it. Set it false for anything requiring a merge, a deploy, publishing (PyPI/release), secrets, credential/token refresh, or arming trust/signing in an environment. ALL Phase D items are agentPreparable=false.
- When agentPreparable=true: give a packageDir RELATIVE to the repo root (e.g. "acgi-ai" or "." for the root — NEVER an absolute path), a concrete file-level remediation plan, and a package-scoped validationCommand that is ALSO relative to the repo root (no absolute paths, no cd into any specific checkout — it will be executed from the root of an isolated worktree). Prefer a command documented in that package's Makefile/CLAUDE.md; NEVER a whole-repo make verify.
- When agentPreparable=false: fill humanAction with the exact human-gated command/step; leave packageDir/validationCommand empty.
- dependsOn: ids of items that must land first (respect the roadmap ordering).

Also emit openDecisions: the unresolved decisions from doc 00 section 7, each with its ref and, where the roadmap says so, the phase (B/C) it gates.

Sort workItems ascending by id before returning.

${EVIDENCE_RULES}`

const survey = await agent(surveyPrompt, {
  label: 'survey',
  phase: 'Survey',
  model: 'opus',
  schema: WORKPLAN_SCHEMA,
})

// Defense in depth: enforce the traceability filter and the stable ordering in
// JS too, so the manifest is well-formed even if the model drifts. Sorting on a
// string key is deterministic (no clock, no randomness).
const workItems = (survey?.workItems ?? [])
  .filter((w) => w && typeof w.id === 'string' && w.roadmapRef && String(w.roadmapRef).trim())
  .slice()
  .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))

const droppedForTrace = (survey?.workItems ?? []).length - workItems.length
if (droppedForTrace > 0) {
  log(`Survey: dropped ${droppedForTrace} item(s) lacking a traceable roadmapRef`)
}

const openDecisions = Array.isArray(survey?.openDecisions) ? survey.openDecisions : []
const phaseItems = workItems.filter((w) => w.phase === PHASE)
const preparable = phaseItems.filter((w) => w.agentPreparable === true)
const humanGated = phaseItems.filter((w) => w.agentPreparable !== true)

log(
  `Survey complete: ${workItems.length} traceable item(s) total; phase ${PHASE} has ${phaseItems.length} (${preparable.length} agent-preparable, ${humanGated.length} human-gated)`,
)

// ---------------------------------------------------------------------------
// Helpers shared by the preview and the final report
// ---------------------------------------------------------------------------
const humanActionsFor = (items) =>
  items.map((i) => ({
    id: i.id,
    phase: i.phase,
    theme: i.theme,
    action: i.humanAction || i.remediation,
    roadmapRef: i.roadmapRef,
  }))

const previewOf = (items) =>
  items.map((i) => ({
    id: i.id,
    title: i.title,
    theme: i.theme,
    packageDir: i.packageDir,
    validationCommand: i.validationCommand,
    dependsOn: i.dependsOn ?? [],
    roadmapRef: i.roadmapRef,
  }))

const decisionsForPhase =
  PHASE === 'B' || PHASE === 'C'
    ? openDecisions.filter((d) => !d.blocksPhase || d.blocksPhase === PHASE)
    : openDecisions

const executeInvocation = preparable.length
  ? `Resume THIS run (pass resumeFromRunId from the launch output) with args {"phase":"${PHASE}","execute":true,"items":[${preparable
      .slice(0, MAX_ITEMS)
      .map((i) => JSON.stringify(i.id))
      .join(
        ',',
      )}]} — resuming replays the cached Survey manifest so the ids above stay pinned; a fresh invocation re-runs Survey live and may re-slug ids (unknown ids fail-safe to notRun).`
  : `Phase ${PHASE} has no agent-preparable items — every action is human-gated.`

// The caller-named, agent-preparable, in-manifest items — the ONLY mutation set.
const named = NAMED_IDS.length ? preparable.filter((w) => NAMED_IDS.includes(w.id)) : []
const unknownIds = NAMED_IDS.filter((id) => !preparable.some((w) => w.id === id))
if (unknownIds.length) {
  log(`Ignoring ${unknownIds.length} named id(s) not agent-preparable in phase ${PHASE}: ${unknownIds.join(', ')}`)
}

// ---------------------------------------------------------------------------
// Fail-closed gate. No mutation unless: execute:true AND phase is not D AND the
// caller named at least one in-manifest agent-preparable item AND the phase has
// agent-preparable work at all. Otherwise return a structured preview only.
// Phase D with execute:true still returns the human checklist — zero worktrees.
// ---------------------------------------------------------------------------
if (!EXECUTE || PHASE === 'D' || named.length === 0 || preparable.length === 0) {
  const reason = !EXECUTE
    ? 'preview (pass execute:true with a named items[] to prepare)'
    : PHASE === 'D'
      ? 'phase D is checklist-only — human-gated deployment/cutover, never agent-executed'
      : preparable.length === 0
        ? 'no agent-preparable items in this phase — everything is human-gated'
        : 'no in-manifest agent-preparable items were named in items[]'
  return {
    phase: PHASE,
    mode: reason,
    roadmapSha: survey?.roadmapSha ?? 'unknown',
    agentPreparable: previewOf(preparable),
    humanGated: humanActionsFor(humanGated),
    openDecisions: decisionsForPhase,
    notRun: unknownIds.map((id) => ({ id, reason: 'named but not an agent-preparable item in this phase' })),
    nextInvocation: executeInvocation,
  }
}

// ---------------------------------------------------------------------------
// Budget pacing. affordable = how many item budgets of ~300k tokens remain (or 2
// when the runtime reports no budget total). When affordable is 0 we prepare
// ZERO items and report every named item as notRun overflow — we never force an
// unaffordable item through (that would contradict fail-closed + no-silent-caps).
// Cap numbers stay OUT of every prompt string to keep the resume cache intact.
// ---------------------------------------------------------------------------
const affordable = budget.total ? Math.floor(budget.remaining() / 300_000) : 2
const cap = Math.min(MAX_ITEMS, affordable)
const selected = named.slice(0, cap)
const overflow = named.slice(cap)

if (affordable === 0) {
  log(`Budget exhausted — preparing 0 item(s); all ${named.length} named item(s) reported as notRun overflow`)
} else if (overflow.length) {
  log(`Pacing cap: preparing ${selected.length}/${named.length} named item(s) this run — re-run for the rest`)
}

// ---------------------------------------------------------------------------
// Prepare → Verify → Review pipeline over the selected slice. Prepare runs in an
// isolated worktree (mutations never touch the shared main checkout); Verify runs
// the item's package-scoped gate in that worktree; Review is a distinct
// fresh-context invocation routed to a specialized reviewer with a fallback.
// ---------------------------------------------------------------------------
const prepPrompt = (item) => `You are the PREPARE lane for ONE roadmap work item. You are in an isolated git worktree of ${REPO} — discover your root with "git rev-parse --show-toplevel" and work ONLY there.

${REPO_RULES}

Work item ${item.id} (phase ${item.phase}, theme ${item.theme}): ${item.title}
Roadmap reference: ${item.roadmapRef}
Package (relative to your worktree root): ${item.packageDir || '(read the remediation to locate it)'}

Remediation plan:
${item.remediation}

Procedure:
1. git fetch origin master --quiet — run from your own worktree (worktrees share the object store); you must branch off FRESH origin/master, never a stale local master.
2. In your worktree, create feature branch "reconstruct/${item.id}" from origin/master.
3. Read the package-local CLAUDE.md / AGENTS.md under "${item.packageDir || 'the touched package'}" (a path relative to your worktree root — join it against the worktree, never the shared main checkout) first and obey them over root assumptions.
4. Make the SMALLEST safe change that closes the item, WITH tests when it is a code/test change. Never edit sealed / Constitutional-Hash / @generated / DO NOT EDIT files. For a nested repo (packages/acgs-lite, packages/Acgs-Swarm, packages/clinicalguard) commit from INSIDE the nested repo only.
5. Run the package-scoped gate FROM YOUR WORKTREE ROOT (the command is written relative to the repo root): ${item.validationCommand || 'the package-local gate documented in its CLAUDE.md'} — then "ruff format" any Python you touched (CI checks formatting separately). A fresh worktree may need "--extra dev --extra crypto" on uv runs.
6. Stage ONLY files you changed (explicit paths, never git add -A / git add .), commit conventionally. Do NOT push, merge, deploy, or publish.
${EVIDENCE_RULES}
If hard-blocked, set completed=false and explain in blockers — never bypass a refusal.`

const verifyPrompt = (item, prep) => `You are the VERIFY lane. Run the package-scoped gate and report LITERAL output — never summarize a result you did not run. This is package-scoped by design; do NOT run a whole-repo make verify.

Worktree: ${prep.worktree} (cd there first — this is the item's ISOLATED worktree, never the shared main checkout)
Package (relative to the worktree root): ${item.packageDir || '(read the item CLAUDE.md to locate it)'}
Validation command (relative to the repo root, run from the worktree root): ${item.validationCommand || 'the package-local gate from the package CLAUDE.md'}

Procedure:
1. From the worktree root run the validation command exactly (it is written relative to the repo root; if it must run from inside the package, cd into "${prep.worktree}" joined with the relative package dir first). A fresh worktree may need "--extra dev --extra crypto" on uv runs. Capture the last ~20 lines and echo "EXIT:$?".
2. git status --short — confirm there is no drift outside ${JSON.stringify(prep.filesChanged)}.
3. passed=true ONLY if the exit code is 0 AND there is no drift outside the declared files.
${EVIDENCE_RULES}`

const reviewPrompt = (item, prep) => `You are reviewing ONE prepared roadmap work item in an isolated worktree. You are NOT its author.

${REVIEWER_CHARTER}

Work item ${item.id} (theme ${item.theme}): ${item.title}
Roadmap reference: ${item.roadmapRef}
Worktree: ${prep.worktree}
Files the author reports changing: ${JSON.stringify(prep.filesChanged)}

Procedure:
1. cd ${prep.worktree} && git diff origin/master...HEAD — read the actual diff, do not trust the summary.
2. Read the package-local CLAUDE.md / AGENTS.md for the touched package.
3. Apply every check in the charter above. For any new handler/route/tool, trace it from the runtime dispatch registration to a test that hits the dispatcher; if you cannot, set wired=false.
4. Return your verdict, findings, and wired. ALLOW only when every check passes.`

// Route the review to a specialized reviewer by the class of files touched.
// governance-reviewer and workspace-boundary-reviewer are both registered agent
// types in this repo; the try/catch degrades gracefully to a default reviewer
// carrying the same inline charter if a named type is ever unavailable.
const GOVERNANCE_RX = /(kernel|receipt|policy|audit|signing|sign|executor|fail.?closed|constitution)/i
const PACKAGE_RX = /(packages\/[^/]+|acgi-ai|acgs_governance_eval_mvp|acgs-cft-governance-pack|hermes_acgs_bundle|automation)/

const reviewerTypeFor = (item, prep) => {
  const files = Array.isArray(prep?.filesChanged) ? prep.filesChanged : []
  const haystack = `${item.theme} ${files.join(' ')}`
  if (GOVERNANCE_RX.test(haystack)) return 'governance-reviewer'
  const roots = new Set(
    files
      .map((f) => {
        const m = String(f).match(PACKAGE_RX)
        return m ? m[0] : null
      })
      .filter(Boolean),
  )
  if (roots.size > 1) return 'workspace-boundary-reviewer'
  return null
}

const runReview = async (item, prep) => {
  const prompt = reviewPrompt(item, prep)
  const type = reviewerTypeFor(item, prep)
  if (type) {
    try {
      return await agent(prompt, { label: `review:${item.id}`, phase: 'Review', agentType: type, schema: REVIEW_SCHEMA })
    } catch (e) {
      log(`review:${item.id}: agentType '${type}' unavailable → default reviewer fallback (${e?.message ?? e})`)
    }
  }
  return await agent(prompt, { label: `review:${item.id}`, phase: 'Review', model: 'opus', schema: REVIEW_SCHEMA })
}

const outcomes = await pipeline(
  selected,
  // Stage 1 — Prepare in an isolated worktree
  (item) => {
    if (budget.total && budget.remaining() < 100_000) {
      log(`Budget low — skipping ${item.id} (recorded as notRun)`)
      return { item, skipped: true }
    }
    return agent(prepPrompt(item), {
      label: `prep:${item.id}`,
      phase: 'Prepare',
      isolation: 'worktree',
      schema: PREP_SCHEMA,
    }).then((prep) => ({ item, prep }))
  },
  // Stage 2 — Verify with the package-scoped gate
  (r) => {
    if (!r || r.skipped) return r
    if (!r.prep?.completed) {
      return { ...r, verify: { passed: false, command: '(skipped — prepare incomplete)', outputTail: r.prep?.blockers ?? '' } }
    }
    return agent(verifyPrompt(r.item, r.prep), {
      label: `verify:${r.item.id}`,
      phase: 'Verify',
      model: 'sonnet',
      schema: VERIFY_SCHEMA,
    }).then((verify) => ({ ...r, verify }))
  },
  // Stage 3 — Review (distinct fresh-context invocation; wired=false downgrades)
  async (r) => {
    if (!r || r.skipped || !r.prep?.completed) return r
    const rev = await runReview(r.item, r.prep)
    let verdict = rev?.verdict
    // Handler-wiring rubric: an unwired change can never be ALLOW.
    if (rev?.wired === false && verdict === 'ALLOW') verdict = 'REQUEST_CHANGES'
    return { ...r, review: { ...(rev ?? {}), verdict } }
  },
)

// ---------------------------------------------------------------------------
// Final report. Every dropped/skipped/overflow item is surfaced in notRun with a
// reason — no silent caps. Human actions and open decisions travel with it.
// ---------------------------------------------------------------------------
const done = outcomes.filter(Boolean)
const executed = done.filter((o) => o.prep?.completed)
const skipped = done.filter((o) => o.skipped)
const blocked = done.filter((o) => o.prep && o.prep.completed !== true)

const notRun = [
  ...overflow.map((i) => ({ id: i.id, reason: 'budget/pacing overflow — re-run to prepare' })),
  ...skipped.map((o) => ({ id: o.item.id, reason: 'per-item budget guard skipped preparation' })),
  ...blocked.map((o) => ({ id: o.item.id, reason: `prepare incomplete: ${o.prep?.blockers || 'see worktree'}` })),
  ...unknownIds.map((id) => ({ id, reason: 'named but not an agent-preparable item in this phase' })),
]

log(
  `reconstruction-drive run complete: phase ${PHASE} — ${executed.length}/${selected.length} prepared, ${notRun.length} not run`,
)

return {
  phase: PHASE,
  roadmapSha: survey?.roadmapSha ?? 'unknown',
  executed: executed.map((o) => ({
    id: o.item.id,
    theme: o.item.theme,
    roadmapRef: o.item.roadmapRef,
    branch: o.prep?.branch,
    worktree: o.prep?.worktree,
    filesChanged: o.prep?.filesChanged,
    verify: { passed: o.verify?.passed ?? false, command: o.verify?.command, outputTail: o.verify?.outputTail },
    review: { verdict: o.review?.verdict, wired: o.review?.wired, findings: o.review?.findings ?? [] },
  })),
  notRun,
  humanActions: humanActionsFor(humanGated),
  openDecisions: decisionsForPhase,
  nextInvocation:
    'Prepared branches live in their isolated worktrees — a human reviews the verdicts, then opens PRs against master (merge, push, deploy, and publish are all human-gated). For overflow/skipped items, RESUME THIS run (resumeFromRunId from the launch output) with the same {phase, execute:true, items:[...]} so the cached Survey manifest replays and the ids stay pinned; a fresh invocation re-runs Survey live and may re-slug ids (unknown ids fail-safe to notRun).',
}
