export const meta = {
  name: 'agency-agents-productization-pursuit',
  description: 'Systematically research market/runtime data (including smolagents as a candidate), decide the highest-leverage path for turning packages/ACGS-agency-agents into a hosted managed-agent product (智能代理.com), then implement + review + verify one increment per run',
  whenToUse: 'Meant to be re-run periodically (long-running pursuit) — each run refreshes market/runtime data, re-confirms or revises the build-path decision, and produces one verifiable increment. First run defaults to dryRun (research + decision + plan only); resume with {dryRun:false} to execute. Pass {asOf:"2026-08-01"} on a later run to force fresh (non-cached) research once you know the landscape has moved. {maxItems:N} caps implemented items (default 2); {exclude:[...]} skips items already in flight on unmerged branches.',
  phases: [
    { title: 'Research' },
    { title: 'Decide' },
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
const PKG = '/home/martin/Documents/ACGS/packages/ACGS-agency-agents'
const EXPERIMENTS = '/home/martin/Documents/ACGS/experiments'

const input = typeof args === 'string'
  ? (() => { try { return JSON.parse(args) } catch { return {} } })()
  : (args ?? {})

// ---- Shell/prompt-safety for values embedded in sub-agent command snippets -
// Implement/review/verify sub-agents are handed PROMPTS containing example
// shell commands (`git -C <dir> worktree add <path> -b <branch>`, `cd <dir>`).
// Values flowing into those commands come from args or from an LLM planning
// step (id -> slug, packageDir, worktree, branch). Taken raw they enable two
// failure modes:
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
      `agency-agents-productization-pursuit: refusing to run — \`${label}\` = ${JSON.stringify(s)} ` +
        `contains characters unsafe to embed in a sub-agent command/prompt (allowed: ${allowed}). ` +
        `This gate fails closed rather than emit a command a sub-agent could be tricked into ` +
        `mis-running, or a prompt it could be tricked into mis-reading.`
    )
  }
}
// Allowlists (mirrors review-branch-adversarial.js / final-goal-pursuit.js):
const RE_PATH = /^[A-Za-z0-9._/-]+$/ // filesystem path
const RE_REF = /^[A-Za-z0-9._/@~^{}-]+$/ // git ref / branch name
const RE_SLUG = /^[A-Za-z0-9._-]+$/ // slug / id component

// A short free-form cache-busting marker (e.g. a date or "run 3"). Interpolated
// into research prompts only — never into a shell command — but a newline
// would still inject new instructions into the prompt, so guard fail-closed
// against control chars and an absurd length rather than allowlist it away.
function assertPromptTextSafe(value, label, maxLen) {
  const s = String(value)
  if (/[\r\n\x00-\x1f]/.test(s) || s.length > maxLen) {
    throw new Error(
      `agency-agents-productization-pursuit: refusing to run — \`${label}\` = ${JSON.stringify(s)} ` +
        `contains a newline/control char or exceeds ${maxLen} chars, unsafe to embed verbatim in a prompt.`
    )
  }
  return s
}

const MAX_ITEMS = Number.isInteger(input?.maxItems) && input.maxItems > 0 ? Math.min(input.maxItems, 3) : 2
// Research + Decide + Prioritize only by default — implementation is opt-in so
// a freshly-scheduled long-running pursuit never silently starts editing code.
const DRY_RUN = input?.dryRun === false ? false : true
const EXCLUDE = Array.isArray(input?.exclude) ? input.exclude : []
EXCLUDE.forEach((id, i) => assertShellSafe(id, `exclude[${i}]`, RE_SLUG))
const AS_OF = typeof input?.asOf === 'string' && input.asOf.length > 0
  ? assertPromptTextSafe(input.asOf, 'asOf', 64)
  : null

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------
const RESEARCH_SCHEMA = {
  type: 'object',
  required: ['topic', 'findings', 'recommendation', 'confidence'],
  properties: {
    topic: { type: 'string' },
    findings: {
      type: 'array',
      items: { type: 'string' },
      description: 'Concrete, evidenced data points — cite file paths, repo names, URLs, or commands actually run',
    },
    recommendation: { type: 'string' },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
  },
}

const ADVOCATE_SCHEMA = {
  type: 'object',
  required: ['position', 'strongestArguments', 'weaknesses'],
  properties: {
    position: { type: 'string' },
    strongestArguments: { type: 'array', items: { type: 'string' } },
    weaknesses: {
      type: 'array',
      items: { type: 'string' },
      description: 'Honest weaknesses of your OWN position — do not omit these, a one-sided case is worthless here',
    },
  },
}

const DECISION_SCHEMA = {
  type: 'object',
  required: ['chosenPath', 'rationale', 'confidence'],
  properties: {
    chosenPath: { type: 'string', enum: ['extend-existing-foundation', 'adopt-smolagents', 'hybrid'] },
    rationale: { type: 'string' },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    keyCriteria: {
      type: 'array',
      items: {
        type: 'object',
        required: ['name', 'favors'],
        properties: {
          name: { type: 'string' },
          favors: { type: 'string', description: 'Which path this criterion favors and why, in one line' },
        },
      },
    },
    risks: { type: 'array', items: { type: 'string' } },
    unresolvedQuestions: {
      type: 'array',
      items: { type: 'string' },
      description: 'What this decision does NOT resolve — lead with this rather than false confidence',
    },
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
        required: ['id', 'title', 'plan', 'packageDir', 'validationCommand'],
        properties: {
          id: { type: 'string', description: 'Short slug, e.g. "smolagents-adapter-spike"' },
          title: { type: 'string' },
          plan: { type: 'string', description: 'Concrete step-by-step plan with file paths' },
          packageDir: { type: 'string', description: 'Absolute path: either the ACGS-agency-agents nested repo or an experiments/ subdirectory' },
          validationCommand: { type: 'string', description: 'The package-local gate command that proves the work (e.g. ./scripts/lint-agents.sh, ./scripts/check-divisions.sh, or a pytest invocation for new experiment code)' },
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
    worktree: { type: 'string', description: 'Absolute path of the worktree the changes live in' },
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
Parent repo: ${REPO}. Package under discussion: ${PKG} — a NESTED git repository
(its own .git, registered as a submodule of ${REPO} at packages/ACGS-agency-agents,
fork of https://github.com/msitarzewski/agency-agents). Experimental runtime
prototypes (e.g. a smolagents adapter spike) belong under ${EXPERIMENTS}/ in the
PARENT repo instead — that is the repo's documented convention for non-production,
path-filtered surfaces (see MONOREPO.md "Experimental surfaces").

Hard rules (non-negotiable):
- ALL git operations on ACGS-agency-agents content (branch, add, commit, worktree)
  happen INSIDE ${PKG} or a worktree of it. NEVER stage its paths from the parent
  repo; NEVER touch the parent's submodule pointer as a side effect of this work.
- ACGS-agency-agents is a content catalog: 217 persona .md files across 16
  divisions (see divisions.json), converted to 14 tool formats by scripts/convert.sh
  per tools.json, installed by scripts/install.sh. Adding/editing a persona means:
  respect the existing frontmatter schema (name/description/color/emoji/vibe),
  keep it inside an existing division directory (or add one only via
  divisions.json + scripts/convert.sh + scripts/lint-agents.sh AGENT_DIRS, per
  CONTRIBUTING.md), and run scripts/check-divisions.sh / scripts/check-tools.sh /
  scripts/lint-agents.sh as the validation gate — there is no pytest suite here.
- scripts/i18n/ currently only patches installed-copy frontmatter name/description
  to Chinese (agent-names-zh.json + localize-agents-zh.ps1) and does NOT translate
  persona body text. Any localization work should say explicitly whether it is
  extending that shallow patch or building the deeper full-body pipeline.
- NEVER weaken fail-closed behavior, bypass receipt validation, or treat
  DENY/ESCALATE as executable (applies if work touches anything in packages/gove-zone).
- NEVER edit files carrying "Constitutional Hash:", "@generated", or "DO NOT EDIT"
  markers by hand; sealed hashes/locks are regenerated via their generator path only.
- NEVER run: git add -A, git add ., git stash, git reset --hard, git push --force,
  gh pr merge, gcloud, vercel, or anything touching secrets. Publishing and
  production deploys are HUMAN-GATED.
- Read the local CLAUDE.md/AGENTS.md/CONTRIBUTING.md of whichever directory you
  are editing and obey it over root assumptions.
`.trim()

// ---------------------------------------------------------------------------
// Phase 1 — Research (fan-out, parallel is correct: Decide needs ALL of it)
// ---------------------------------------------------------------------------
phase('Research')
const asOfNote = AS_OF
  ? `As-of marker for this run: ${JSON.stringify(AS_OF)} — treat this as a cue to seek CURRENT information (recent commits, releases, pricing, star counts), not to recite stale training data.`
  : ''

const RESEARCH_QUESTIONS = [
  {
    key: 'foundation-state',
    prompt: `Audit the CURRENT state of ${PKG} as a candidate foundation for a hosted Chinese-language managed-agent product ("智能代理.com").
${asOfNote}
Report, with evidence (file paths, counts, git log):
1. How many persona .md files exist now, across how many divisions (compare to divisions.json) — has the catalog grown/shrunk since a prior audit would have seen 217 across 16 divisions?
2. What actually exists in scripts/i18n/ today — has full-body Chinese translation been started, or is it still only the frontmatter-name patch (agent-names-zh.json + localize-agents-zh.ps1)?
3. Does ANY web-facing catalog/browser exist yet in this repo or a sibling experiments/ directory (vs. only the CLI install.sh / desktop agencyagents.app flow)?
4. Does ANY execution runtime exist yet under experiments/ or elsewhere in this repo that actually RUNS a persona (as opposed to just rendering it into a static config file for a local tool)?
Be skeptical — a translated frontmatter field is not "localization done"; a rendered SKILL.md is not "hosted execution".`,
  },
  {
    key: 'smolagents-fit',
    prompt: `Research huggingface/smolagents (github.com/huggingface/smolagents) as a candidate execution runtime for turning ACGS-agency-agents personas into hosted, running agents.
${asOfNote}
Report, with evidence (repo stats, README/docs content, code structure):
1. What is smolagents — core abstractions (agent class, tool definition, code-vs-JSON action format), license, maturity (stars, release cadence, maintainer), minimum runtime requirements.
2. Model-provider flexibility: which LLM providers/backends does it support out of the box (OpenAI, Anthropic, HF Inference, local/Ollama, OpenAI-compatible endpoints) — could it reach Chinese models (Qwen/GLM/DeepSeek/Kimi) directly or only via an OpenAI-compatible shim?
3. Multi-agent support: does it have an equivalent of agency-swarm's Agency/communication_flows, or is it single-agent-per-instance (requiring you to hand-roll orchestration)?
4. Hosting story: is there any official/community "managed" or server-hosting pattern (comparable to Agencii for agency-swarm, or Anthropic's Managed Agents), or is it purely a local/embedded library?
5. How much would porting a persona .md file (frontmatter + system-prompt body) into a smolagents agent definition cost in engineering effort, concretely?
Cite the exact repo path/README section for every claim; do not guess at API shapes you have not verified.`,
  },
  {
    key: 'runtime-candidates-refresh',
    prompt: `Refresh-check the previously identified runtime candidates for ACGS-agency-agents, looking for drift since they were last evaluated.
${asOfNote}
Report on:
1. VRSEN/agency-swarm (github.com/VRSEN/agency-swarm) — any notable recent releases, breaking changes, or new integrations (especially anything touching hosting/multi-tenancy/OpenClaw/Agencii) since its most recent tagged release.
2. Anthropic Managed Agents (platform.claude.com/docs/en/managed-agents) — any change in beta status, pricing, or API surface (agents/sessions endpoints, permission policies, skills) since public beta.
3. Whether either has added anything resembling smolagents' code-action execution model or vice versa.
If you find nothing has materially changed, say so plainly rather than padding the report.`,
  },
  {
    key: 'market-signal-refresh',
    prompt: `Lightweight refresh-check on Chinese-market competitor signals relevant to prioritizing the next build increment for a managed-agent platform.
${asOfNote}
Report on: any notable recent feature launches, pricing changes, or star-count/momentum shifts for Coze Studio (github.com/coze-dev/coze-studio), Dify (github.com/langgenius/dify), and FastGPT (github.com/labring/FastGPT) — specifically anything that would change which feature is currently highest-leverage to build next (e.g. a new multi-agent/committee feature, a new China-cloud one-click deploy, a new free-tier model). If nothing material has changed, say so plainly.`,
  },
]

const findings = await parallel(RESEARCH_QUESTIONS.map(q => () =>
  agent(q.prompt, { label: `research:${q.key}`, phase: 'Research', schema: RESEARCH_SCHEMA })
    .then(r => (r ? { key: q.key, ...r } : null))
))
const cleanFindings = findings.filter(Boolean)
log(`Research complete: ${cleanFindings.length}/${RESEARCH_QUESTIONS.length} question(s) answered`)

// ---------------------------------------------------------------------------
// Phase 2 — Decide (barrier is correct: the decision needs every finding, and
// both advocate cases, in hand at once). Dialectic pattern: two advocates argue
// opposite ends, a synthesizer decides — mirrors the polarity-pair /
// dissent-quota approach this session studied in council-of-high-intelligence,
// applied here to a concrete build-vs-adopt decision rather than free debate.
// ---------------------------------------------------------------------------
phase('Decide')
const findingsJson = JSON.stringify(cleanFindings, null, 2)

const [forExisting, forSmolagents] = await parallel([
  () => agent(
    `You are the advocate for CONTINUING to extend the existing foundation (packages/ACGS-agency-agents content + a runtime built on VRSEN/agency-swarm and/or Anthropic Managed Agents, as previously researched). Make the strongest honest case for this path, using the research findings below. You must also list your own position's real weaknesses — do not hide them.

Research findings:
${findingsJson}`,
    { label: 'advocate:existing-foundation', phase: 'Decide', schema: ADVOCATE_SCHEMA },
  ),
  () => agent(
    `You are the advocate for ADOPTING smolagents (huggingface/smolagents) as the execution runtime instead, re-platforming the ACGS-agency-agents personas onto it. Make the strongest honest case for this path, using the research findings below. You must also list your own position's real weaknesses — do not hide them.

Research findings:
${findingsJson}`,
    { label: 'advocate:smolagents', phase: 'Decide', schema: ADVOCATE_SCHEMA },
  ),
])

const decision = await agent(
  `You are the synthesizer deciding the build path for turning ACGS-agency-agents into a hosted Chinese-language managed-agent product ("智能代理.com"). You have NOT written either case below — judge them on evidence, not confidence.

${REPO_RULES}

Case FOR continuing on the existing foundation (agency-swarm / Anthropic Managed Agents):
${JSON.stringify(forExisting, null, 2)}

Case FOR adopting smolagents:
${JSON.stringify(forSmolagents, null, 2)}

Raw research findings (for anything the advocates underweighted):
${findingsJson}

Decide chosenPath = "extend-existing-foundation" | "adopt-smolagents" | "hybrid" (hybrid = e.g. smolagents for lightweight single-agent tool-use personas, agency-swarm/Managed Agents for multi-agent "council" style features). Lead your rationale with what would change your mind, and put anything genuinely unresolved in unresolvedQuestions rather than forcing false confidence.`,
  { label: 'decide', phase: 'Decide', schema: DECISION_SCHEMA },
)
log(`Decision: ${decision?.chosenPath ?? 'undecided'} (confidence: ${decision?.confidence ?? 'unknown'})`)

// ---------------------------------------------------------------------------
// Phase 3 — Prioritize (barrier is correct: needs the decision + all findings)
// ---------------------------------------------------------------------------
phase('Prioritize')
const plan = await agent(
  `You are the planning lane. Given the decision below, select the ${MAX_ITEMS} highest-leverage work item(s) a coding agent can complete THIS RUN toward productizing ACGS-agency-agents, and write a concrete plan for each.

${REPO_RULES}

Decision: ${JSON.stringify(decision, null, 2)}

Selection rules:
- Every item must be completable locally: code/content + a package-local validation command. No publishing, deploying, merging, no network installs that take >3 minutes.
- If chosenPath involves smolagents, the FIRST such item should be a small, bounded spike under ${EXPERIMENTS}/ (e.g. port ONE persona to a working smolagents agent + a smoke test) — not a full re-platform in one run.
- If chosenPath is extend-existing-foundation or hybrid, prefer items that close a concretely-identified gap from the research findings (e.g. deepen i18n beyond frontmatter, or scaffold a minimal hosted-execution wrapper around one persona).
${EXCLUDE.length ? `- ALREADY IN FLIGHT (implemented on unmerged branches, do NOT re-select): ${EXCLUDE.join(', ')}.` : ''}
- Name the absolute packageDir (either inside ${PKG} or ${EXPERIMENTS}/<new-dir>) and the exact validationCommand. Read that directory's CLAUDE.md/AGENTS.md/CONTRIBUTING.md first and take the authoritative command from there — do not invent a pytest command for a directory that has no Python package yet; if you are creating one, its validationCommand should be the test command you are ALSO setting up in this same item.

Research findings for context:
${findingsJson}`,
  { label: 'prioritize', phase: 'Prioritize', schema: PLAN_SCHEMA },
)

const selected = (plan?.items ?? []).slice(0, MAX_ITEMS)
for (const it of selected) {
  assertShellSafe(it.id, 'id', RE_SLUG)
  assertShellSafe(it.packageDir, 'packageDir', RE_PATH)
}
log(`Selected ${selected.length} work item(s): ${selected.map(s => s.id).join(', ')}`)

if (DRY_RUN) {
  return {
    decision,
    findings: cleanFindings,
    rationale: plan?.rationale,
    selected,
    note: 'dryRun (default) — research + decision + plan only, nothing implemented. Resume with {dryRun:false} to execute; the Research/Decide/Prioritize phases will be served from cache unless you also pass a new {asOf:...}.',
  }
}

// ---------------------------------------------------------------------------
// Phases 4-6 — Implement -> Review -> Verify, pipelined per item.
// NOTE: no blanket isolation:'worktree' here — items may target either the
// NESTED ACGS-agency-agents repo or the PARENT repo's experiments/ dir, and a
// parent worktree does not check out nested submodules. The implementer is
// told which case applies and creates the correct worktree itself.
// ---------------------------------------------------------------------------
const outcomes = await pipeline(
  selected,
  // Stage 1 — implement, in a self-created worktree of the correct repo
  item => {
    if (budget.total && budget.remaining() < 80_000) {
      log(`Budget low — skipping implementation of ${item.id}`)
      return null
    }
    const inNestedPkg = item.packageDir.startsWith(PKG)
    return agent(
      `You are the implementation lane for ONE work item toward productizing ACGS-agency-agents. Work item: ${JSON.stringify(item.title)}

${REPO_RULES}

Target directory: ${item.packageDir}
${inNestedPkg
  ? `This is INSIDE the nested ACGS-agency-agents repo. Create your worktree of THAT repo: cd ${shq(PKG)} && git worktree add <path> -b "product/${item.id}" main (or its default branch — check with git branch --show-current first). All git operations (branch/add/commit) happen inside that worktree, never from the parent.`
  : `This is inside the PARENT repo's experiments/ tree. Create your worktree of the PARENT repo: cd ${shq(REPO)} && git worktree add <path> -b "product/${item.id}" master (or its default branch). Do not create/modify anything under packages/ACGS-agency-agents in this item.`}

Plan:
${JSON.stringify(item.plan)}

Procedure:
1. Read the relevant CLAUDE.md/AGENTS.md/CONTRIBUTING.md first and obey it.
2. Make the smallest safe change that delivers this item, with a smoke test or validation artifact where practical.
3. Run the validation command locally: ${JSON.stringify(item.validationCommand)}
4. Stage ONLY the files you changed (explicit paths, never -A), commit on the feature branch with a conventional message. Do NOT push.
Report the absolute worktree path, branch name, and the files you changed. If you hit a hard blocker, set completed=false and explain in blockers.`,
      { label: `impl:${item.id}`, phase: 'Implement', isolation: 'worktree', schema: IMPL_SCHEMA },
    )
  },
  // Stage 2 — independent review of the diff
  (impl, item) => {
    if (!impl || !impl.completed) return impl ? { impl, review: { verdict: 'block', issues: ['implementation incomplete: ' + (impl.blockers ?? 'unknown')] } } : null
    assertShellSafe(impl.worktree, 'impl.worktree', RE_PATH)
    assertShellSafe(impl.branch, 'impl.branch', RE_REF)
    return agent(
      `You are the review lane — you did NOT write this change. Review it adversarially against the repo's rules.

${REPO_RULES}

Change under review: ${item.id} — ${JSON.stringify(item.title)}
Worktree: ${impl.worktree}
Branch: ${impl.branch}
Files changed: ${JSON.stringify(impl.filesChanged)}
Implementer's summary: ${JSON.stringify(impl.summary)}

Procedure:
1. cd ${shq(impl.worktree)} && git diff <default-branch>...HEAD — review every hunk.
2. Check: scope stayed inside ${item.packageDir}? no hand-edited sealed/hash-marked files? no persona frontmatter schema drift? if this touches scripts/i18n/, does it honestly describe whether it deepened full-body translation or only extended the frontmatter patch? if this is a smolagents spike, does it actually run (not just import cleanly)?
3. Verdict: approve / request-changes (fixable nits) / block (correctness, security, or boundary violation).`,
      { label: `review:${item.id}`, phase: 'Review', schema: REVIEW_SCHEMA },
    ).then(review => ({ impl, review }))
  },
  // Stage 3 — verification with literal output
  (r, item) => {
    if (!r) return null
    if (r.review.verdict === 'block') return { item: item.id, ...r, verify: { passed: false, command: '(skipped — review blocked)', outputTail: '' } }
    assertShellSafe(r.impl.worktree, 'impl.worktree', RE_PATH)
    return agent(
      `You are the verification lane. Run the package-local gate and report LITERAL output — never summarize a result you did not run.

Worktree: ${shq(r.impl.worktree)} (cd there first)
Validation command: ${JSON.stringify(item.validationCommand)}

Procedure:
1. Run the validation command exactly. Capture the last ~20 lines and the exit code.
2. Also run "git status --short" and confirm the worktree has no unintended drift outside ${JSON.stringify(r.impl.filesChanged)}.
3. passed=true ONLY if exit code is 0 and no drift.`,
      { label: `verify:${item.id}`, phase: 'Verify', schema: VERIFY_SCHEMA },
    ).then(verify => ({ item: item.id, ...r, verify }))
  },
)

// ---------------------------------------------------------------------------
// Final report
// ---------------------------------------------------------------------------
const done = outcomes.filter(Boolean)
const shipped = done.filter(o => o.verify?.passed && o.review?.verdict === 'approve')
log(`Run complete: ${shipped.length}/${selected.length} item(s) implemented, reviewed, and verified`)

return {
  decision,
  findings: cleanFindings,
  rationale: plan?.rationale,
  results: done.map(o => ({
    item: o.item,
    branch: o.impl?.branch,
    worktree: o.impl?.worktree,
    files: o.impl?.filesChanged,
    review: o.review?.verdict,
    reviewIssues: o.review?.issues,
    verified: o.verify?.passed,
    verifyOutput: o.verify?.outputTail,
  })),
  nextSteps: 'Verified branches live in their worktrees — human opens PRs (gh pr merge is human-gated). Re-run this workflow for the next increment; pass a fresh {asOf:...} whenever you want the Research phase to re-check the landscape instead of replaying from cache.',
}
