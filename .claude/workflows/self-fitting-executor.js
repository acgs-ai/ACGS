export const meta = {
  name: 'self-fitting-executor',
  description: 'Discover the environment, classify + plan the task, then loop act -> verify -> adapt (separate implementer and verifier agents) until the gate passes or a hard cap stops it.',
  whenToUse: 'A self-contained coding task (modify / debug / feature / refactor / investigate) you want executed autonomously with checkpointed, verification-gated, resumable iterations.',
  phases: [
    { title: 'Discover', detail: '3 parallel probes -> capability map' },
    { title: 'Plan', detail: 'classify task type, decompose into verifiable steps' },
    { title: 'Execute', detail: 'one implementer agent per step, minimal diff' },
    { title: 'Verify', detail: 'independent verifier runs the gate, literal output only' },
    { title: 'Rescue', detail: 'strategy switch after 2 consecutive verified failures' },
  ],
}

// ---- Structured-output schemas -------------------------------------------

const PROBE = {
  type: 'object',
  required: ['findings', 'commands'],
  properties: {
    findings: { type: 'array', items: { type: 'string' } },
    commands: {
      type: 'array',
      items: {
        type: 'object',
        required: ['purpose', 'command'],
        properties: {
          purpose: { type: 'string' },
          command: { type: 'string' },
          cwd: { type: 'string' },
        },
      },
    },
  },
}

const PLAN = {
  type: 'object',
  required: ['taskType', 'targetDir', 'steps', 'verify', 'risks'],
  properties: {
    taskType: {
      type: 'string',
      enum: ['modify', 'debug', 'feature', 'refactor', 'investigate'],
    },
    targetDir: { type: 'string' },
    steps: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'description'],
        properties: {
          id: { type: 'string' },
          description: { type: 'string' },
          files: { type: 'array', items: { type: 'string' } },
          check: { type: 'string' }, // fast, narrow, repo-defined command proving THIS step
        },
      },
    },
    // The authoritative full gate for targetDir. Repo-defined only — never invented.
    verify: {
      type: 'array',
      items: {
        type: 'object',
        required: ['command'],
        properties: { command: { type: 'string' }, cwd: { type: 'string' } },
      },
    },
    risks: { type: 'array', items: { type: 'string' } },
    assumptions: { type: 'array', items: { type: 'string' } },
  },
}

const ACT = {
  type: 'object',
  required: ['status', 'summary', 'changedFiles'],
  properties: {
    status: { type: 'string', enum: ['completed', 'partial', 'blocked'] },
    summary: { type: 'string' },
    changedFiles: { type: 'array', items: { type: 'string' } },
    blockers: { type: 'array', items: { type: 'string' } },
  },
}

const VERDICT = {
  type: 'object',
  required: ['pass', 'evidence'],
  properties: {
    pass: { type: 'boolean' },
    evidence: { type: 'string' }, // LITERAL command output lines, never a paraphrase
    failures: { type: 'array', items: { type: 'string' } },
  },
}

const RESCUE_ADVICE = {
  type: 'object',
  required: ['diagnosis', 'revisedApproach'],
  properties: {
    diagnosis: { type: 'string' },
    revisedApproach: { type: 'string' },
  },
}

// ---- Args -----------------------------------------------------------------
// Workflow({ args: { task, maxIterations?, repoDir? } }) — or a plain string task.
const input =
  typeof args === 'string'
    ? (() => {
        try {
          return JSON.parse(args)
        } catch {
          return { task: args }
        }
      })()
    : (args ?? {})
const TASK = typeof input === 'string' ? input : (input.task ?? '')
if (!TASK) {
  return {
    ok: false,
    error: 'No task provided. Pass args as a task string or { task, maxIterations?, repoDir? }.',
  }
}
const MAX_ITER = Number.isInteger(input.maxIterations) && input.maxIterations > 0
  ? input.maxIterations
  : 8
const REPO = input.repoDir ?? '.'
// A repo path never legitimately needs a quote/space/;/$/backtick/newline —
// fail closed rather than embed an injectable value into sub-agent prompts.
if (!/^[A-Za-z0-9._/-]+$/.test(String(REPO))) {
  return { ok: false, error: `Unsafe repoDir ${JSON.stringify(REPO)} — refusing to embed it in sub-agent prompts.` }
}

// Pinned to every prompt so a sub-agent that greps/reads autonomously never
// drifts to the wrong checkout (the recurring worktree-vs-cwd failure mode).
const REPO_NOTE = `\n\nREPOSITORY (pin): all commands and file paths are relative to the repo at \`${REPO}\`. Run shell commands from there (or the stated cwd) and open files at \`${REPO}/<path>\` — never another checkout.`

const SAFETY_RULES = `- Obey the NEAREST CLAUDE.md / AGENTS.md for every directory you touch; they outrank these generic rules.
- Smallest safe diff. No drive-by refactors. Match local style and conventions.
- Never edit sealed/generated files (Constitutional Hash markers, @generated, DO NOT EDIT banners, lockfiles) — change the generator or stop and report.
- Trace dependencies before deleting anything.
- Never \`git add -A\` / \`git add .\`. Do not commit, push, or merge unless the task explicitly says so. Do not cross nested-repo/submodule boundaries.
- Do not weaken fail-closed behavior, auth, policy enforcement, or auditability.
- No silent breaking changes to public APIs; preserve build reproducibility.
- Do not bypass, skip, or weaken tests to make them pass.`

const trim = (s, n = 1200) => {
  const t = String(s ?? '')
  return t.length > n ? t.slice(0, n) + ' …[trimmed]' : t
}

// ---- STATE (spec §7) — maintained deterministically in the orchestrator ----
// Checkpointing/resumability comes from the workflow journal: re-running with
// resumeFromRunId replays every completed agent() call from cache.
const state = {
  goal: TASK,
  current_phase: 'discover',
  completed_steps: [],
  pending_steps: [],
  risks: [],
  decisions_log: [],
  test_results: [],
}

// ---- Phase 1: environment self-discovery (spec §3) — parallel probes ------
// Barrier justified: the planner genuinely needs the ENTIRE capability map.

const PROBES = [
  {
    key: 'toolchain',
    focus:
      'Map layout and toolchain: top-level structure, the subdirectory(ies) most relevant to the task, build systems, package managers, runtimes, and how to build/run. Put build/run commands in `commands`.',
  },
  {
    key: 'gates',
    focus:
      'Identify the authoritative validation gates: test, lint, type-check, and build commands, plus CI workflows that gate changes (.github/workflows). Package-local gates beat root gates for single-package work. Put each in `commands` with its cwd.',
  },
  {
    key: 'constraints',
    focus:
      'Identify constraints: nearest local instruction files (CLAUDE.md / AGENTS.md) and their hard rules, sealed/generated files (hash markers, @generated, DO NOT EDIT, lockfiles), nested git repos / submodule boundaries, and anything the task must not touch. `commands` may be empty.',
  },
]

log(`Discovering environment for task: ${trim(TASK, 120)}`)
const probeResults = await parallel(
  PROBES.map((p) => () =>
    agent(
      `You are the \`${p.key}\` discovery probe for an autonomous execution run in the repo at \`${REPO}\`.
TASK (for scoping discovery only — do NOT execute it): ${TASK}

${p.focus}

Prefer facts read from real files (Makefile, package.json, pyproject.toml, CI workflows, CLAUDE.md/AGENTS.md) over guesses. Keep findings short and factual. Return commands ONLY if the repo itself defines them — never invent validation commands.${REPO_NOTE}`,
      { label: `probe:${p.key}`, phase: 'Discover', schema: PROBE }
    )
  )
)
const capabilities = PROBES.map((p, i) => ({
  probe: p.key,
  ...(probeResults[i] ?? { findings: ['probe failed or was skipped'], commands: [] }),
}))

// ---- Phase 2: classify + plan (spec §4) ------------------------------------

state.current_phase = 'plan'
const plan = await agent(
  `You are the planning lane of an autonomous execution run. Classify the task and produce the smallest safe plan. Discover, don't assume — read code where the capability map is not enough.

TASK: ${TASK}

CAPABILITY MAP (from discovery):
${JSON.stringify(capabilities, null, 2)}

Rules:
- taskType strategy: 'modify' = locate modules -> map dependencies -> minimal diff. 'debug' = reproduce -> isolate failure domain -> root-cause -> patch. 'feature' = decompose into vertical slices, integrate incrementally, keep a runnable state. 'refactor' = define invariants first, behavior parity via tests, small reversible steps. 'investigate' = read-only analysis producing a report, no edits.
- targetDir: the directory whose local rules and gates govern this work ('.' if root-wide).
- steps: ordered, each independently completable AND verifiable; each step's optional \`check\` is a fast, narrow, repo-defined shell command proving that step. Fewer, well-scoped steps beat many vague ones.
- verify: the authoritative FULL gate for targetDir as repo-defined commands (from the capability map). Leave empty ONLY if the repo truly defines none — never invent commands.
- risks / assumptions: record anything that may break later (spec: minimal-assumption bias).${REPO_NOTE}`,
  { label: 'classify+plan', phase: 'Plan', schema: PLAN }
)
if (!plan) {
  return { ok: false, error: 'Planning agent failed or was skipped.', capabilities, state }
}
state.risks = plan.risks ?? []
state.pending_steps = plan.steps.map((s) => s.id)
state.decisions_log.push(
  `plan: taskType=${plan.taskType} targetDir=${plan.targetDir} steps=[${plan.steps.map((s) => s.id).join(', ')}] gate=${plan.verify.length} cmd(s)`
)
log(`Plan: ${plan.taskType} in ${plan.targetDir} — ${plan.steps.length} step(s), ${plan.verify.length} gate command(s)`)

// ---- Phase 3: the execution loop (spec §5) ---------------------------------
// OBSERVE/PLAN happened above; each iteration is ACT -> VERIFY -> EVALUATE ->
// ADAPT, with CHECKPOINT provided by the journal. Implementers run sequentially
// in the shared working tree ON PURPOSE (state must persist across iterations),
// so no worktree isolation.

const pending = [...plan.steps]
const rescuedSteps = new Set()
let iteration = 0
let failStreak = 0
let lastFeedback = ''
let rescueAdvice = ''
let finalVerdict = null
let aborted = null

const runVerifier = (cmds, context, label) =>
  agent(
    `You are the verification lane. You did NOT write the changes — trust nothing you did not run yourself.

Run each command below with Bash (from its \`cwd\` if given, else from \`${REPO}\`) and record its exit status:
${JSON.stringify(cmds, null, 2)}

Context (implementer's claim — verify it, don't trust it): ${context}

pass=true ONLY if every command exits 0. In \`evidence\`, paste the decisive LITERAL output lines (the test summary line, the exact error lines) — never a paraphrase. List each failing command with a one-line reason in \`failures\`.${REPO_NOTE}`,
    { label, phase: 'Verify', schema: VERDICT }
  )

state.current_phase = 'execute'
while (iteration < MAX_ITER) {
  if (budget.total && budget.remaining() < 40_000) {
    aborted = 'token budget floor reached'
    break
  }
  iteration++

  // All steps done -> run the authoritative full gate (spec §11: completion
  // criteria are the verifier's, not the implementer's).
  if (pending.length === 0) {
    if (plan.verify.length === 0) {
      state.decisions_log.push(`iter ${iteration}: no repo-defined gate — refusing to claim verified success`)
      break
    }
    log(`All steps done — running the full gate (iteration ${iteration}/${MAX_ITER})`)
    finalVerdict = await runVerifier(
      plan.verify,
      `all ${state.completed_steps.length} step(s) completed: ${state.completed_steps.map((s) => s.id).join(', ')}`,
      'final-gate'
    )
    state.test_results.push({ iteration, step: 'final-gate', pass: finalVerdict?.pass ?? false, evidence: trim(finalVerdict?.evidence) })
    if (finalVerdict?.pass) {
      state.decisions_log.push(`iter ${iteration}: final gate PASSED`)
      break
    }
    const failures = (finalVerdict?.failures ?? []).join('; ') || trim(finalVerdict?.evidence, 400)
    state.decisions_log.push(`iter ${iteration}: final gate FAILED -> queueing fix step`)
    pending.push({
      id: `fix-final-gate-${iteration}`,
      description: `The full verification gate failed after all planned steps. Fix ONLY these failures (isolate cause, correct, re-run only the affected scope): ${failures}`,
    })
    lastFeedback = trim(finalVerdict?.evidence)
    continue
  }

  const step = pending[0]

  // ACT — one implementer agent, one step, minimal diff (spec §5.3, §9).
  const act = await agent(
    // NOTE: MAX_ITER is deliberately NOT in this prompt — the advertised recovery
    // path is "resume with a higher maxIterations", which must not invalidate
    // cached act calls. (`iteration` is stable across a same-order replay.)
    `You are the implementation lane (iteration ${iteration}) of an autonomous execution run. Execute EXACTLY ONE step — do not start other steps.

TASK: ${TASK}
STEP \`${step.id}\`: ${step.description}${step.files?.length ? `\nLikely files: ${step.files.join(', ')}` : ''}
TASK TYPE: ${plan.taskType} · TARGET DIR: ${plan.targetDir}
STATE: ${JSON.stringify({ completed: state.completed_steps.map((s) => s.id), pending: pending.map((s) => s.id), recent_decisions: state.decisions_log.slice(-4) })}
${lastFeedback ? `\nPREVIOUS ATTEMPT FAILED VERIFICATION — address this first:\n${lastFeedback}\n` : ''}${rescueAdvice ? `\nSTRATEGY SWITCH (rescue diagnosis) — follow this revised approach instead of retrying the old one:\n${rescueAdvice}\n` : ''}
SAFETY RULES (non-negotiable):
${SAFETY_RULES}

Read the nearest CLAUDE.md/AGENTS.md before editing. Make the smallest change that completes the step. You may run quick checks while working, but do NOT claim the gate passes — a separate verifier runs it. Report honestly: status 'blocked' with blockers if you cannot proceed. Placeholder stubs, "fix later" markers, skipped tests, and unimplemented branches are NOT completion.${REPO_NOTE}`,
    { label: `act:${step.id}`, phase: 'Execute', schema: ACT }
  )
  if (!act) {
    aborted = `implementer for step ${step.id} failed or was skipped`
    break
  }
  state.decisions_log.push(`iter ${iteration}: act ${step.id} -> ${act.status} (${act.changedFiles.length} file(s))`)
  if (act.status === 'blocked') {
    aborted = `step ${step.id} blocked: ${(act.blockers ?? []).join('; ') || act.summary}`
    break
  }

  // VERIFY — independent agent runs the narrowest relevant check.
  const checkCmds = step.check
    ? [{ purpose: `check for step ${step.id}`, command: step.check, cwd: plan.targetDir }]
    : plan.verify
  if (checkCmds.length === 0) {
    // No repo-defined check exists: record the step but never claim it verified.
    state.completed_steps.push({ id: step.id, summary: act.summary, changedFiles: act.changedFiles, verified: false })
    state.decisions_log.push(`iter ${iteration}: ${step.id} completed GATELESS (no repo-defined check)`)
    pending.shift()
    failStreak = 0; lastFeedback = ''; rescueAdvice = ''
    continue
  }
  const verdict = await runVerifier(
    checkCmds,
    `step ${step.id}: ${act.summary} (changed: ${act.changedFiles.join(', ') || 'no files'})`,
    `verify:${step.id}`
  )
  const pass = verdict?.pass === true
  state.test_results.push({ iteration, step: step.id, pass, evidence: trim(verdict?.evidence ?? 'verifier produced no verdict') })

  // EVALUATE + ADAPT — deterministic (spec §5.5–5.6, §8).
  if (pass) {
    state.completed_steps.push({ id: step.id, summary: act.summary, changedFiles: act.changedFiles, verified: true })
    state.decisions_log.push(`iter ${iteration}: ${step.id} VERIFIED`)
    log(`✓ ${step.id} verified (${pending.length - 1} step(s) left)`)
    pending.shift()
    failStreak = 0; lastFeedback = ''; rescueAdvice = ''
    continue
  }

  failStreak++
  lastFeedback = trim(verdict?.evidence ?? 'verifier produced no verdict (skipped/crashed) — treated as NOT verified')
  state.decisions_log.push(`iter ${iteration}: ${step.id} FAILED verification (streak ${failStreak})`)
  log(`✗ ${step.id} failed verification (streak ${failStreak})`)

  if (failStreak >= 2) {
    if (rescuedSteps.has(step.id)) {
      aborted = `step ${step.id} failed verification twice more after a strategy switch — stopping rather than thrashing`
      break
    }
    // RESCUE — repeated failure means switch strategy, not retry harder (spec §8).
    rescuedSteps.add(step.id)
    const rescue = await agent(
      `You are the rescue lane. The SAME step has failed verification ${failStreak} times in a row. Do NOT retry harder — switch strategy: isolate the failure domain, build a minimal reproduction, find the root cause.

TASK: ${TASK}
STEP \`${step.id}\`: ${step.description}
FAILURE EVIDENCE (most recent):
${lastFeedback}
RECENT DECISIONS: ${JSON.stringify(state.decisions_log.slice(-6))}

Investigate the actual code and the failing commands with fresh eyes (read files, re-run the failing command, add temporary instrumentation if needed — then remove it). Return a concrete root-cause diagnosis and a revised approach the implementer can follow: which files to change differently, or a smaller intermediate step to take first.${REPO_NOTE}`,
      { label: `rescue:${step.id}`, phase: 'Rescue', schema: RESCUE_ADVICE }
    )
    if (rescue) {
      rescueAdvice = `Diagnosis: ${rescue.diagnosis}\nRevised approach: ${rescue.revisedApproach}`
      state.decisions_log.push(`iter ${iteration}: rescue diagnosis for ${step.id} — strategy switched`)
      failStreak = 0 // the revised approach gets a fresh (capped) chance
    } else {
      state.decisions_log.push(`iter ${iteration}: rescue for ${step.id} produced nothing`)
    }
  }
}

// ---- Report (spec §10/§11) — findings / actions / next steps ---------------

state.current_phase = 'done'
state.pending_steps = pending.map((s) => s.id)
const gateless = plan.verify.length === 0 && plan.steps.every((s) => !s.check)
const verified = finalVerdict?.pass === true
const ok = verified && pending.length === 0 && !aborted

if (!ok) {
  log(aborted ? `Stopped: ${aborted}` : verified ? 'Done' : 'Finished WITHOUT a passing full gate — do not treat as complete')
}

return {
  ok,
  task: TASK,
  taskType: plan.taskType,
  targetDir: plan.targetDir,
  iterations: iteration,
  maxIterations: MAX_ITER,
  verified,
  gateless: gateless
    ? 'No repo-defined checks were found — success is NOT claimed; ask the user for the right gate.'
    : false,
  stoppedBecause: aborted,
  findings: {
    capabilities: capabilities.map((c) => ({ probe: c.probe, findings: c.findings.slice(0, 8), commands: c.commands })),
    risks: state.risks,
    assumptions: plan.assumptions ?? [],
  },
  actions: state.completed_steps,
  test_results: state.test_results,
  next_steps: aborted
    ? [`Resolve: ${aborted}`, ...state.pending_steps.map((id) => `Then finish step ${id}`)]
    : state.pending_steps.length
      ? state.pending_steps.map((id) => `Finish step ${id} (iteration cap hit — resume with resumeFromRunId)`)
      : verified
        ? ['Review the diff, then commit (the workflow never commits)']
        : ['Run the full gate manually or re-run with a higher maxIterations'],
  decisions_log: state.decisions_log,
}
