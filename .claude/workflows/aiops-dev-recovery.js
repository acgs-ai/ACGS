export const meta = {
  name: 'aiops-dev-recovery',
  description:
    'AIOps closed loop for the ACGS monorepo: sense repo/CI/runtime health, diagnose incidents, remediate in isolated worktrees, escalate stuck fixes to Codex gpt-5.5 (advisory artifacts), verify with literal output',
  whenToUse:
    'Run with no args (or {execute:false}) for a read-only health sweep + incident report. Pass {execute:true} to let fix lanes implement remediations on feature branches in isolated worktrees. Pass {task:"..."} to inject a directed development item into the same pipeline. {maxIncidents:N} caps concurrent remediations (default 2, max 4).',
  phases: [
    { title: 'Sense' },
    { title: 'Diagnose', model: 'opus' },
    { title: 'Remediate' },
    { title: 'Rescue' },
    { title: 'Verify' },
  ],
}

// ---------------------------------------------------------------------------
// Config — inline constants with safe defaults (args have historically arrived
// undefined; an undefined args MUST degrade to the read-only sweep, never to a
// mutating run). Repo path is pinned absolutely because workflow sub-agents do
// NOT inherit the package cwd.
// ---------------------------------------------------------------------------
const REPO = '/home/martin/Documents/ACGS'
const ASK_ARTIFACTS = `${REPO}/.omc/artifacts/ask`

const input = typeof args === 'string'
  ? (() => { try { return JSON.parse(args) } catch { return {} } })()
  : (args ?? {})
// Fail-closed default: observe only. Mutation requires an explicit literal true.
const EXECUTE = input?.execute === true
const TASK = typeof input?.task === 'string' && input.task.trim() ? input.task.trim() : null
const MAX_INCIDENTS = Number.isInteger(input?.maxIncidents) && input.maxIncidents > 0
  ? Math.min(input.maxIncidents, 4)
  : 2

// ---------------------------------------------------------------------------
// Shared prompt fragments
// ---------------------------------------------------------------------------
const REPO_RULES = `
Repository: ${REPO} (workflow agents do NOT start there — cd first).
Hard rules (non-negotiable):
- NEVER edit files carrying "Constitutional Hash:", "@generated", or "DO NOT EDIT" markers; never hand-edit docs/constitutional-hashes.lock.
- NEVER weaken fail-closed behavior, bypass receipt validation, or treat DENY/ESCALATE as executable.
- NEVER run: git add -A, git add ., git stash, git reset --hard, git clean -f, git checkout master, git push --force, gh pr merge, gh pr close, gh secret, gh release, gh workflow run, gcloud, vercel, sudo. Publishing and production deploys are HUMAN-GATED.
- If a command is refused by a permission deny-rule, do NOT retry it (not once, not with tweaked flags). Record it as a human-gated action and move on.
- packages/acgs-lite, packages/Acgs-Swarm, packages/clinicalguard are nested git repos — never stage across that boundary from the parent.
- Before editing inside any subdirectory, read its local CLAUDE.md / AGENTS.md and obey them over root assumptions.
- gove-zone has dependencies=[] by design — stdlib or optional extras only, never new runtime deps.
- The main checkout is SHARED with other live sessions and is dirty by design: treat files you did not create as someone else's work. All mutations happen in your own isolated worktree, never in ${REPO} itself.
- gh auth caveat: an expired keyring token makes public-repo READS silently fall back anonymous while writes 401 — "gh auth status" lies; trust "gh api user".
`.trim()

const EVIDENCE_RULES = `
VERIFICATION DISCIPLINE (non-negotiable): report ONLY what commands actually printed. Capture exit codes with echo "EXIT:$?" immediately after each command. Never claim a pass without the literal exit code you observed.`.trim()

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------
const PROBE_SCHEMA = {
  type: 'object',
  required: ['probe', 'healthy', 'findings'],
  properties: {
    probe: { type: 'string' },
    healthy: { type: 'boolean' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['signal', 'severity', 'evidence'],
        properties: {
          signal: { type: 'string', description: 'One-line name of the anomaly or confirmation' },
          severity: { type: 'string', enum: ['info', 'warn', 'critical'] },
          evidence: { type: 'string', description: 'Literal command output lines proving the signal' },
        },
      },
    },
    notes: { type: 'string' },
  },
}

const DIAG_SCHEMA = {
  type: 'object',
  required: ['overallHealth', 'incidents'],
  properties: {
    overallHealth: { type: 'string', enum: ['green', 'yellow', 'red'] },
    incidents: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'title', 'kind', 'severity', 'evidence', 'agentFixable', 'remediation'],
        properties: {
          id: { type: 'string', description: 'Short slug, e.g. ci-master-red or task-directed-1' },
          title: { type: 'string' },
          kind: { type: 'string', enum: ['code-defect', 'test-failure', 'env-drift', 'ci-infra', 'auth-expiry', 'state-stale', 'directed-dev', 'human-gated'] },
          severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
          evidence: { type: 'string' },
          agentFixable: { type: 'boolean', description: 'true only if closable with local code/config/test changes — no merge, deploy, secrets, auth refresh, or external party' },
          packageDir: { type: 'string', description: 'Absolute subproject dir the fix lives in (when agentFixable)' },
          remediation: { type: 'string', description: 'Concrete fix plan with file paths (agentFixable) or the exact command/action a human must run (human-gated)' },
          validationCommand: { type: 'string', description: 'Package-local gate command proving the fix (when agentFixable)' },
        },
      },
    },
  },
}

const FIX_SCHEMA = {
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

const RESCUE_SCHEMA = {
  type: 'object',
  required: ['rescued', 'diagnosis', 'proposedFix'],
  properties: {
    rescued: { type: 'boolean', description: 'true if Codex produced a usable diagnosis/fix proposal' },
    diagnosis: { type: 'string' },
    proposedFix: { type: 'string', description: 'Concrete file-level change proposal extracted from the Codex artifact' },
    artifactPath: { type: 'string' },
  },
}

// ---------------------------------------------------------------------------
// Phase 1 — Sense (parallel read-only probes; each ≤3 min, mutates nothing)
// ---------------------------------------------------------------------------
phase('Sense')
log(`AIOps sweep of ${REPO} — execute=${EXECUTE}${TASK ? ' + directed task' : ''}`)

const PROBES = [
  {
    key: 'repo-state',
    prompt: `Probe the WORKING-TREE / TOPOLOGY health of the monorepo. Read-only.
Procedure:
1. cd ${REPO}
2. python3 /home/martin/.claude/scripts/scope-detect.py --json . 2>/dev/null || true — note topology + dirty subprojects.
3. git status --short | head -40 ; git rev-parse --abbrev-ref HEAD ; git log --oneline -3
4. git worktree list — flag worktrees whose paths no longer exist, but remember ~/Documents/ACGS-wt/* worktrees belong to OTHER live sessions (dirty there is intentional, severity=info).
5. git submodule status — a '+' prefix means pointer drift (warn, do not fix).
The shared checkout being dirty on a docs/* branch is the NORMAL state here (other sessions own it) — only flag signals that block work: merge conflicts, detached HEAD, lock files (.git/index.lock), broken submodule init.`,
  },
  {
    key: 'ci-health',
    prompt: `Probe CI / pipeline health on GitHub. Read-only.
Procedure:
1. cd ${REPO} && git remote get-url origin — derive owner/repo.
2. gh api user >/dev/null 2>&1; echo "AUTH_EXIT:$?" — nonzero means the gh token is expired/anonymous (reads still work rate-limited; report severity=warn signal "gh-auth-expired" because all writes will 401).
3. gh run list --branch master --limit 10 (table). Flag any failed/cancelled run on master as critical with the run name + URL.
4. For the latest master commit: gh api repos/{owner}/{repo}/commits/master/check-runs --jq '.check_runs[] | "\\(.name): \\(.status) \\(.conclusion)"' — flag non-success conclusions.
5. gh api repos/{owner}/{repo}/actions/runners --jq '.runners[] | "\\(.name): \\(.status)"' 2>/dev/null — this box IS the self-hosted runner the required "verify" check needs; offline = critical. A 401 here just means auth-expired (mark unknown, not offline).`,
  },
  {
    key: 'local-gates',
    prompt: `Probe LOCAL QUALITY GATES of the core runtime package. Read-only (run checks, change nothing, no installs/sync).
Procedure:
1. cd ${REPO}
2. uv run --package gove-zone ruff check packages/gove-zone/src packages/gove-zone/tests; echo "EXIT:$?"
3. uv run --package gove-zone ruff format --check packages/gove-zone/src packages/gove-zone/tests; echo "EXIT:$?"  (CI runs BOTH — format drift alone goes RED in CI)
4. uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q 2>&1 | tail -5; echo "EXIT:$?"
5. make lint-docs 2>&1 | tail -5; echo "EXIT:$?"
Any nonzero exit is a finding: include the failing lane, the literal tail output, severity=high for test failures, warn for lint/format drift. All green → healthy=true with the literal pass lines as evidence.`,
  },
  {
    key: 'runtime-health',
    prompt: `Probe AGENT-RUNTIME / OPS health of this development machine. Read-only.
Procedure:
1. cd ${REPO}
2. Governance hook interpreter: test -x .venv/bin/python; echo "VENV_EXIT:$?" — the .claude/settings.json receipt hook pins this interpreter and exits 2 (blocking ALL edits) when the venv is missing. Missing venv = critical, remediation = "uv sync".
3. Stale orchestration state: ls .omc/state/ 2>/dev/null | head; find .omc/state -name "cancel-signal*" -mmin +120 2>/dev/null — stale cancel signals strand future runs (warn).
4. Disk: df -h . | tail -1 — under 5% free = critical (audit chain appends + worktrees need space).
5. Lock debris: ls .git/index.lock 2>/dev/null && echo LOCKED — an index.lock with no live git process = warn (do NOT delete it; report only).
6. omc + codex rescue lane availability: which omc codex; echo "EXIT:$?" — missing = warn (escalation ladder degraded).`,
  },
]

const probes = (await parallel(PROBES.map(p => () =>
  agent(
    `You are ONE health probe in an AIOps sensing sweep. Mutate NOTHING — no edits, no commits, no installs, no deletes, no reruns.

${REPO_RULES}

${p.prompt}

${EVIDENCE_RULES}
Set probe to "${p.key}". healthy=true only when zero warn/critical findings.`,
    { label: `sense:${p.key}`, phase: 'Sense', model: 'sonnet', schema: PROBE_SCHEMA },
  )))).filter(Boolean)

const anomalies = probes.flatMap(p => p.findings.filter(f => f.severity !== 'info').map(f => ({ probe: p.probe, ...f })))
log(`Sense complete: ${probes.length}/${PROBES.length} probes, ${anomalies.length} non-info signal(s)`)

// ---------------------------------------------------------------------------
// Phase 2 — Diagnose (barrier is correct: correlation needs ALL probe results)
// ---------------------------------------------------------------------------
phase('Diagnose')
const diagnosis = await agent(
  `You are the diagnosis lane of an AIOps loop for this repo. Correlate the probe signals below into discrete INCIDENTS, deduplicating root causes (one expired token explains both a CI-read warning and a runner-status unknown — that is ONE auth-expiry incident, not three).

${REPO_RULES}

Probe results (verbatim from the sensing sweep):
${JSON.stringify(probes, null, 2)}
${TASK ? `
DIRECTED DEVELOPMENT TASK (inject as one incident with kind="directed-dev", agentFixable=true unless it requires merge/deploy/secrets):
${TASK}
` : ''}
Classification rules:
- agentFixable=true ONLY when local code/config/test changes close it: no gh auth refresh (human types the browser flow), no PyPI publish, no deploy, no merging, no secrets.
- auth-expiry, runner-offline, and anything needing "gh auth refresh" or infra credentials → agentFixable=false, kind accordingly, remediation = the EXACT command the human runs.
- For each agentFixable incident: name the absolute packageDir, a concrete file-level fix plan, and the package-local validationCommand that proves it (prefer commands documented in that package's Makefile/CLAUDE.md). Read the package's local instructions if needed (read-only).
- Do not invent incidents: zero anomalies → overallHealth=green with an empty or info-only incident list${TASK ? ' (plus the directed-dev incident)' : ''}.
- Severity honesty: a red master CI is critical; format drift is low.`,
  { label: 'diagnose', phase: 'Diagnose', model: 'opus', schema: DIAG_SCHEMA },
)

const incidents = diagnosis?.incidents ?? []
const fixable = incidents.filter(i => i.agentFixable)
const humanGated = incidents.filter(i => !i.agentFixable)
log(`Diagnosis: health=${diagnosis?.overallHealth} — ${incidents.length} incident(s), ${fixable.length} agent-fixable, ${humanGated.length} human-gated`)

if (!EXECUTE || fixable.length === 0) {
  return {
    mode: EXECUTE ? 'execute (nothing agent-fixable)' : 'read-only sweep (pass {execute:true} to remediate)',
    overallHealth: diagnosis?.overallHealth ?? 'unknown',
    probes: probes.map(p => ({ probe: p.probe, healthy: p.healthy, findings: p.findings })),
    incidents,
    humanActions: humanGated.map(i => ({ id: i.id, severity: i.severity, action: i.remediation })),
    nextInvocation: fixable.length
      ? `Workflow aiops-dev-recovery with args {"execute":true${TASK ? `,"task":${JSON.stringify(TASK)}` : ''}} remediates: ${fixable.map(i => i.id).join(', ')}`
      : 'No agent-fixable incidents — nothing to execute.',
  }
}

// ---------------------------------------------------------------------------
// Phases 3-5 — Remediate → Verify, with a single Codex gpt-5.5 rescue cycle
// when the first verified attempt fails (model-routing: stuck → EXT-C lane,
// artifacts only, Claude applies; rework cycles hard-capped at 2 attempts).
// Worktree isolation: fixes mutate files concurrently without colliding and
// never touch the shared main checkout.
// ---------------------------------------------------------------------------
const queue = fixable
  .sort((a, b) => ['critical', 'high', 'medium', 'low'].indexOf(a.severity) - ['critical', 'high', 'medium', 'low'].indexOf(b.severity))
  .slice(0, MAX_INCIDENTS)
if (fixable.length > queue.length) log(`Capacity cap: remediating ${queue.length}/${fixable.length} fixable incident(s) this run — re-run for the rest`)

const fixPrompt = (incident, rescueAdvice) => `You are the ${rescueAdvice ? 'RESCUE-APPLY' : 'remediation'} lane for ONE incident in an AIOps loop. You are in an isolated git worktree of ${REPO}${rescueAdvice ? '' : ' — discover your root with "git rev-parse --show-toplevel" and work ONLY there'}.

${REPO_RULES}

Incident ${incident.id} (${incident.kind}, ${incident.severity}): ${incident.title}
Evidence: ${incident.evidence}

Fix plan:
${incident.remediation}
${rescueAdvice ? `
A first attempt FAILED verification. Codex gpt-5.5 (independent advisory lane) diagnosed:
${rescueAdvice.diagnosis}

Proposed fix (advisory — verify it against the code before applying, you own correctness):
${rescueAdvice.proposedFix}
` : ''}
Procedure:
1. Read the package-local CLAUDE.md / AGENTS.md under ${incident.packageDir || 'the touched package'} first and obey them.
2. ${rescueAdvice ? 'Work on the existing branch in this worktree.' : `Create a feature branch "aiops/${incident.id}".`}
3. Make the smallest safe change WITH tests where the kind is code-defect/test-failure/directed-dev. env-drift/state-stale fixes must stay non-destructive (regenerate via documented generators, never delete files you did not create).
4. Run: ${incident.validationCommand || 'the package-local gate documented in its CLAUDE.md'} — then "ruff format" any Python you touched (CI checks formatting separately).
5. Stage ONLY files you changed (explicit paths, never -A), commit conventionally. Do NOT push.
${EVIDENCE_RULES}
If hard-blocked, set completed=false and explain in blockers — never bypass a refusal.`

const verifyPrompt = (incident, fix) => `You are the verification lane. Run the gate and report LITERAL output — never summarize a result you did not run.

Worktree: ${fix.worktree} (cd there first)
Validation command: ${incident.validationCommand || 'the package-local gate from the package CLAUDE.md'}

Procedure:
1. Run the validation command exactly; capture the last ~20 lines and echo "EXIT:$?".
2. git status --short — confirm no drift outside ${JSON.stringify(fix.filesChanged)}.
3. passed=true ONLY if exit code 0 and no drift.
${EVIDENCE_RULES}`

const outcomes = await pipeline(
  queue,
  // Stage 1 — first remediation attempt, isolated worktree
  incident => {
    if (budget.total && budget.remaining() < 80_000) {
      log(`Budget low — skipping ${incident.id}`)
      return null
    }
    return agent(fixPrompt(incident, null), {
      label: `fix:${incident.id}`, phase: 'Remediate', isolation: 'worktree', schema: FIX_SCHEMA,
    }).then(fix => ({ incident, fix }))
  },
  // Stage 2 — verify attempt 1
  r => {
    if (!r?.fix?.completed) return r ? { ...r, verify: { passed: false, command: '(skipped — fix incomplete)', outputTail: r.fix?.blockers ?? '' } } : null
    return agent(verifyPrompt(r.incident, r.fix), {
      label: `verify:${r.incident.id}`, phase: 'Verify', model: 'sonnet', schema: VERIFY_SCHEMA,
    }).then(verify => ({ ...r, verify }))
  },
  // Stage 3 — Codex gpt-5.5 rescue when attempt 1 failed (advisory artifact)
  r => {
    if (!r || r.verify.passed || !r.fix?.worktree) return r
    log(`${r.incident.id}: attempt 1 failed verification → Codex gpt-5.5 rescue lane`)
    return agent(
      `You operate the Codex gpt-5.5 ADVISORY rescue lane (EXT-C). A remediation attempt failed verification; obtain an independent diagnosis from Codex, artifacts only — Codex must NOT edit anything.

Failed incident ${r.incident.id}: ${r.incident.title}
Worktree with the failing attempt: ${r.fix.worktree}
Files changed so far: ${JSON.stringify(r.fix.filesChanged)}
Verification failure output:
${r.verify.outputTail}

Procedure:
1. cd ${r.fix.worktree} && git diff master...HEAD | head -300 — capture the attempted diff for context.
2. Build a self-contained prompt (failure output + relevant diff hunks + the goal: "${r.incident.title}"). Include concrete file paths. NEVER include secrets or tokens. WRITE the prompt to a temp FILE (e.g. "$(mktemp -d)/rescue-prompt.md") — verification output and diff hunks contain quotes/backticks/$ that break inline shell quoting and can hit argv limits; never hand-assemble an escaped one-liner.
3. Run: cd ${REPO} && timeout 600 omc ask codex "$(cat <promptfile>)" — command substitution inside double quotes passes arbitrary content safely (no re-evaluation); the artifact lands under ${ASK_ARTIFACTS}/. If omc exits nonzero or writes no artifact, do NOT retry it — fall back ONCE to stdin form: cd ${r.fix.worktree} && timeout 600 codex exec --sandbox read-only - < <promptfile>.
4. Read the artifact/stdout; extract the root-cause diagnosis and the concrete file-level fix proposal. Cite artifactPath when one exists.
5. rescued=false if both invocations fail or the output is unusable — in that case write your OWN best diagnosis from the diff and failure output instead (still fill diagnosis/proposedFix).
Treat Codex output as advisory: do not apply anything yourself.`,
      { label: `rescue:${r.incident.id}`, phase: 'Rescue', schema: RESCUE_SCHEMA },
    ).then(rescue => ({ ...r, rescue }))
  },
  // Stage 4 — apply rescue advice in the SAME worktree, then final verify
  async r => {
    if (!r || r.verify.passed || !r.rescue) return r
    const fix2 = await agent(fixPrompt(r.incident, r.rescue), {
      label: `apply:${r.incident.id}`, phase: 'Remediate', schema: FIX_SCHEMA,
    }, )
    if (!fix2?.completed) return { ...r, finalVerify: { passed: false, command: '(rescue apply incomplete)', outputTail: fix2?.blockers ?? '' } }
    const merged = { ...r.fix, filesChanged: [...new Set([...(r.fix.filesChanged ?? []), ...(fix2.filesChanged ?? [])])] }
    const finalVerify = await agent(verifyPrompt(r.incident, merged), {
      label: `verify2:${r.incident.id}`, phase: 'Verify', model: 'sonnet', schema: VERIFY_SCHEMA,
    })
    // Rework cycle cap reached (2 attempts): whatever this says is final.
    return { ...r, fix: merged, finalVerify }
  },
)

// ---------------------------------------------------------------------------
// Final report
// ---------------------------------------------------------------------------
const done = outcomes.filter(Boolean)
const resolved = done.filter(o => (o.finalVerify ?? o.verify)?.passed)
const stuck = done.filter(o => !(o.finalVerify ?? o.verify)?.passed)
log(`AIOps run complete: ${resolved.length}/${queue.length} incident(s) remediated+verified, ${stuck.length} stuck after the 2-attempt cap`)

return {
  overallHealth: diagnosis?.overallHealth,
  incidents: incidents.map(i => ({ id: i.id, kind: i.kind, severity: i.severity, agentFixable: i.agentFixable })),
  remediated: resolved.map(o => ({
    id: o.incident.id,
    branch: o.fix?.branch,
    worktree: o.fix?.worktree,
    files: o.fix?.filesChanged,
    rescuedByCodex: Boolean(o.rescue?.rescued),
    verifyOutput: (o.finalVerify ?? o.verify)?.outputTail,
  })),
  stuck: stuck.map(o => ({
    id: o.incident.id,
    worktree: o.fix?.worktree,
    lastFailure: (o.finalVerify ?? o.verify)?.outputTail,
    codexDiagnosis: o.rescue?.diagnosis,
    next: 'Both attempts (Claude + Codex-advised) failed — needs human triage; the worktree preserves the state.',
  })),
  humanActions: humanGated.map(i => ({ id: i.id, severity: i.severity, action: i.remediation })),
  notRun: fixable.length > queue.length ? fixable.slice(MAX_INCIDENTS).map(i => i.id) : [],
  nextSteps: 'Verified branches live in their worktrees — a human opens PRs against master (merge is human-gated). Re-run for capped/remaining incidents.',
}
