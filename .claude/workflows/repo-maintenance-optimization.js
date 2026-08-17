export const meta = {
  name: 'repo-maintenance-optimization',
  description:
    'Dynamic, read-only maintenance & optimization audit: 9 discovery lanes sweep the live repo and emit findings + proposed fixes; each finding is adversarially verified and risk-classified against the hard constraints; output is a prioritized, safe-to-apply backlog.',
  whenToUse:
    'Periodic repo hygiene / optimization pass on the govern-zone monorepo. Read-only — produces a verified, risk-ranked maintenance plan (green=safe auto-fix, yellow=needs care, red=touches a sealed/boundary constraint). Scope with args:{lanes,packages,root}. Applying fixes is a human/isolated-worktree follow-up, never done here.',
  phases: [{ title: 'Discover' }, { title: 'Verify' }, { title: 'Synthesize' }],
}

// ════════════════════════════════════════════════════════════════════════════
// Configuration
// ════════════════════════════════════════════════════════════════════════════
// Repo root. Workflows run from the session cwd, but sub-agents can drift cwd
// (a known failure mode), so we PIN an absolute path into every prompt and pin
// every git command with `git -C`. Override with args.root.
const ROOT = '/home/martin/Documents/ACGS'

// Scope tool: DERIVES each subproject's lint/typecheck/test/build lanes from its
// own manifests and filters out any `NEVER run` / `DO NOT run` prohibitions.
const VALIDATE = '/home/martin/.claude/scripts/validate-subproject.py'

// Authoritative package list = root Makefile PYTHON_PACKAGES + the frontend.
// clinicalguard (private submodule, often uninitialized) and hermes_acgs_bundle
// (path-filtered) are excluded by default; add them via args.packages.
const DEFAULT_PACKAGES = [
  'packages/acgs-lite',
  'packages/Acgs-Swarm',
  'packages/gove-zone',
  'packages/agent-bus-analyzer',
  'packages/research-engine',
  'acgs_governance_eval_mvp',
  'acgs-cft-governance-pack',
  'acgi-ai',
]

// ════════════════════════════════════════════════════════════════════════════
// args normalization  (object → object, JSON string → parsed, else pass-through)
// ════════════════════════════════════════════════════════════════════════════
const input =
  typeof args === 'string'
    ? (() => {
        try {
          return JSON.parse(args)
        } catch {
          return args
        }
      })()
    : args

const root = input?.root ?? ROOT
const packages =
  Array.isArray(input?.packages) && input.packages.length > 0
    ? input.packages
    : DEFAULT_PACKAGES

// ════════════════════════════════════════════════════════════════════════════
// Shell / prompt-injection safety for values embedded in sub-agent command
// snippets. `root` and each `dir` are interpolated into example shell commands
// (`git -C "<root>"`, `python3 <validate> "<dir>"`). Raw, they enable (1) SHELL
// injection (a quote/;/$()/backtick breaks out of the command) and (2) PROMPT
// injection (a newline injects instructions). VALIDATE-first via a strict
// allowlist (also rejects control chars/newlines), shell-quote second.
// ════════════════════════════════════════════════════════════════════════════
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`
function assertShellSafe(value, label, allowed) {
  const s = String(value)
  if (!allowed.test(s)) {
    throw new Error(
      `repo-maintenance-optimization: refusing to run — \`${label}\` = ${JSON.stringify(s)} ` +
        `contains characters unsafe to embed in a command/prompt (allowed: ${allowed}). ` +
        `This gate fails closed rather than emit a command a sub-agent could be tricked into ` +
        `mis-running, or a prompt it could be tricked into mis-reading.`
    )
  }
}
const FS_PATH = /^[A-Za-z0-9._/-]+$/
assertShellSafe(root, 'root', FS_PATH)
for (const dir of packages) assertShellSafe(dir, 'package', FS_PATH)

const PKG_LIST = packages.join(', ')

// ════════════════════════════════════════════════════════════════════════════
// Shared risk-classification contract — the 5 HARD CONSTRAINTS of this repo.
// Embedded in every discovery AND verification prompt so risk classes are
// assigned consistently. A misclassified "green" that touches one of these is
// the single most dangerous output this workflow could produce.
// ════════════════════════════════════════════════════════════════════════════
const RISK_GUIDE = `RISK CLASSIFICATION (assign to every finding):
- "green"  = mechanically safe, auto-fixable, behavior-preserving, and touches
             NONE of the hard constraints below. Examples: \`ruff format\`,
             removing a provably-unused local import, fixing a broken relative
             doc link, deleting dead scratch files already git-ignored.
- "yellow" = a real improvement that needs human judgment or could change
             behavior: refactors, dependency bumps, added tests, perf changes,
             renaming, non-trivial dead-code removal.
- "red"    = touches a HARD CONSTRAINT and MUST NEVER be auto-applied:
   1. SEALED files — any file containing a "# Constitutional Hash:" marker, or
      docs/constitutional-hashes.lock. Changing them requires recomputing hashes.
   2. NESTED-REPO / SUBMODULE boundaries — packages/acgs-lite, packages/Acgs-Swarm,
      packages/clinicalguard are independent git repos. Never stage pointer drift
      from the parent; commits go inside the package.
   3. PUBLISHED API — packages/acgs-lite is on PyPI. Do not break its public API
      or its \`requires-python = ">=3.10"\` floor (INTENTIONALLY looser than the
      workspace 3.11 floor — that mismatch is NOT a bug).
   4. PRIVILEGED CONSOLE — acgi-ai/src/routes/console/** and its CSP. Never extend
      public-only patterns (CDN fonts, third-party scripts, anon endpoints) there.
   5. GENERATED / CI / SETTINGS — pnpm-lock.yaml, uv.lock, anything marked
      "@generated"/"DO NOT EDIT", .github/workflows/**, .claude/settings.json.

REPO-SPECIFIC LANDMINES (classify these as yellow/red, never green):
- Do NOT propose removing acgi-ai exports/symbols that check-*.mjs foundation
  gates assert by regex — an "unused export" autofix there BREAKS test:all.
- Root tests/*.py run in NO CI workflow; the tests-docs workflow is path-filtered
  (can go green while red). Flag coverage/gate gaps, don't assume CI catches them.
- acgi-ai marketing has a hard ~200 KiB gzip budget that sums ALL marketing
  assets — code-splitting does not help; a size regression is a real defect.`

const BOUNDARIES = `STRICT BOUNDARIES (this is a READ-ONLY audit):
- Make NO file edits, NO commits, NO git state changes.
- Do NOT install/sync/upgrade dependencies (no \`uv sync\`, no \`pnpm install\`,
  no \`--fix\`/\`--write\` autofix flags). Run only inspection/check/list commands.
- Pin every git command with \`git -C ${shq(root)}\`. When you read a file, open it
  at ${root}/<path> — never the default cwd or another checkout.
- Report ONLY what commands actually printed; never claim a count you did not see.`

// ════════════════════════════════════════════════════════════════════════════
// Structured-output contracts
// ════════════════════════════════════════════════════════════════════════════
const FINDINGS = {
  type: 'object',
  required: ['findings'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['title', 'package', 'path', 'severity', 'riskClass', 'remediation', 'evidence'],
        properties: {
          title: { type: 'string' },
          package: { type: 'string' }, // affected package dir, or 'root'
          path: { type: 'string' }, // file[:line] or glob the finding anchors to
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
          riskClass: { type: 'string', enum: ['green', 'yellow', 'red'] },
          autoFixable: { type: 'boolean' },
          remediation: { type: 'string' }, // concrete proposed action
          evidence: { type: 'string' }, // literal command output / file:line proof
        },
      },
    },
  },
}

const VERDICT = {
  type: 'object',
  required: ['isReal', 'riskClass', 'safeToAutoApply'],
  properties: {
    isReal: { type: 'boolean' }, // survives adversarial scrutiny (default false if unsure)
    riskClass: { type: 'string', enum: ['green', 'yellow', 'red'] }, // corrected classification
    safeToAutoApply: { type: 'boolean' }, // true ONLY if green AND respects all 5 constraints
    reason: { type: 'string' },
  },
}

// ════════════════════════════════════════════════════════════════════════════
// The 9 discovery lanes — a multi-modal sweep. Each lane is a DIFFERENT way of
// looking at the repo, blind to the others; together they surface what any one
// angle would miss. Each returns findings WITH a proposed remediation so the
// verifier has something concrete to attack.
// ════════════════════════════════════════════════════════════════════════════
const LANES = [
  {
    key: 'git-hygiene',
    title: 'Git & worktree hygiene',
    prompt: `Sweep GIT / WORKTREE HYGIENE for the monorepo at ${root}.
Inspect (read-only): \`git -C ${shq(root)} status --short --branch\`; local branches already
merged into master (\`git -C ${shq(root)} branch --merged master\`); stale per-agent worktrees
under ../ACGS-wt/* (\`git -C ${shq(root)} worktree list\`); submodule pointer drift
(\`git -C ${shq(root)} submodule status\` — a leading + means the parent points at a non-committed
submodule commit); and runtime/agent state that is tracked-but-should-be-ignored
(.omc/, .acgs-swarm/, __pycache__/, htmlcov/, .coverage, virtualenvs).
Report each as a finding with a concrete cleanup remediation. NEVER propose \`git clean\`,
\`git stash\`, branch deletion, or committing submodule pointer drift as green — those are
destructive/boundary-touching (yellow or red).`,
  },
  {
    key: 'lint-format-debt',
    title: 'Lint & format debt',
    prompt: `Quantify LINT & FORMAT DEBT per package (${PKG_LIST}).
For each Python package: get its lanes via \`python3 ${VALIDATE} <pkg> --json\`, then from inside
the package run the CHECK-ONLY forms through the workspace venv: \`uv run ruff check .\` and
\`uv run ruff format --check .\` (count violations; note how many ruff reports as auto-fixable).
For acgi-ai: \`pnpm -F acgi-ai run lint\` (biome) in check mode. Do NOT pass --fix/--write.
Report per-package debt with counts from the literal output. \`ruff format\` / biome-format
of NON-sealed source is typically green; a ruff rule that requires a manual code change is yellow.`,
  },
  {
    key: 'type-debt',
    title: 'Type-checking debt',
    prompt: `Survey TYPE-CHECKING DEBT across ${PKG_LIST}.
For each package with mypy configured, run \`uv run mypy\` (or \`uv run mypy src tests\`) from inside
it and count errors. Separately grep for accumulated \`# type: ignore\` and \`Any\` escape hatches
(\`git -C ${shq(root)} grep -n "type: ignore" -- <pkg>\`), and note any Python package that has NO
mypy configuration at all (a coverage gap). Report findings with counts and the specific files.
Adding types / removing ignores is yellow (behavior-adjacent); it is never green.`,
  },
  {
    key: 'dead-code-duplication',
    title: 'Dead code & duplication',
    prompt: `Find DEAD CODE and DUPLICATION.
Look for: unused imports/variables (ruff F401/F841 signal), modules imported nowhere, unreachable
branches, commented-out code blocks, and logic duplicated across packages that could share a helper.
Use \`git -C ${shq(root)} grep\` to prove a symbol has zero references outside its definition before
calling it dead.
CRITICAL: on acgi-ai, an "unused" export may be asserted by a check-*.mjs foundation gate via regex —
removing it BREAKS test:all. Before proposing removal of any acgi-ai export, grep the check-*.mjs
gates for its name; if matched, classify red and do NOT propose removal. Genuinely-unused local
symbols in non-gated Python are yellow (removal changes the module surface); never green unless the
symbol is provably unreferenced scratch.`,
  },
  {
    key: 'dependency-health',
    title: 'Dependency health',
    prompt: `Audit DEPENDENCY HEALTH (read-only; never install/upgrade).
JS: \`pnpm -F acgi-ai outdated\` and \`pnpm -F acgi-ai list --depth 0\`; note outdated/duplicate/
conflicting versions and any dep pulled in but unused. Python: inspect each package's pyproject.toml
for pinned/loose ranges and \`uv pip list --outdated\` in the workspace; note security-relevant
outdated packages.
Constraints to RESPECT (not flag as bugs): acgs-lite's \`requires-python = ">=3.10"\` is INTENTIONALLY
looser than the workspace 3.11 floor. Do not propose bumping the published acgs-lite floor. Lockfile
edits (pnpm-lock.yaml/uv.lock) are generated → red. A dep bump is yellow (needs test verification).`,
  },
  {
    key: 'test-health',
    title: 'Test suite health & coverage',
    prompt: `Assess TEST HEALTH and COVERAGE GAPS.
Look for: skipped/xfail tests (\`git -C ${shq(root)} grep -n "skip\\|xfail" -- '*test*.py'\`), \`.only\`
in JS specs, slow suites, and — most important for a governance kernel — enforcement/policy/handler
paths that LACK a NEGATIVE-PATH test (a gate that DENIES/BLOCKS must have a test proving it denies).
Also flag CI-visibility gaps: root tests/*.py run in NO workflow, and tests-docs is path-filtered
(can merge red). Report each gap with the file and what test is missing. Added tests are yellow.`,
  },
  {
    key: 'doc-rot',
    title: 'Documentation rot',
    prompt: `Find DOCUMENTATION ROT.
Run \`make -C ${shq(root)} lint-docs\` (governance-stack index + link validation) and report any failure.
Grep docs/ for broken relative links, references to files/symbols that no longer exist, and stale
claims that contradict current code (cross-check against docs/CLAIMS.md — every claim there names the
code/tests that back it). Check that examples/** and tests/docs/** still run. Fixing a broken relative
link or a stale path is green; rewording a capability CLAIM is red-adjacent (claims must stay
provable — verify against source before proposing any wording change) → classify yellow/red.`,
  },
  {
    key: 'perf-optimization',
    title: 'Performance & size optimization',
    prompt: `Find PERFORMANCE & SIZE optimization opportunities.
Frontend: build acgi-ai marketing in check mode if cheap, or inspect known bundle sizes; the marketing
gzip budget is a HARD ~200 KiB summed across ALL marketing assets — flag anything trending over.
Python: spot O(n^2)/repeated-work hotspots, redundant recomputation, and SEQUENTIAL independent LLM/IO
calls that should be batched with asyncio.gather (per the repo's LLM-integration patterns). Report each
with the file:line and the concrete optimization. Perf changes are yellow (need a before/after check);
they are never green.`,
  },
  {
    key: 'ci-workflow-health',
    title: 'CI & workflow health',
    prompt: `Audit CI & GITHUB-WORKFLOW health at ${root}/.github/workflows/.
List the workflows and check for: path-filter traps (a gate that can go green while the code it should
guard is red — e.g. tests-docs), packages whose gate runs in NO workflow (root tests/), redundant or
duplicated jobs, hardcoded stale action versions, and self-hosted-runner assumptions. Report each with
the workflow file and the gap. NOTE: .github/workflows/** is a dangerous edit zone → any proposed
change is red (human review required); this lane surfaces the gap, it does not green-light edits.`,
  },
]

// Optional lane subset via args.lanes (intersect with known keys — never trust
// raw strings into anything). Default = all lanes.
const laneFilter =
  Array.isArray(input?.lanes) && input.lanes.length > 0 ? new Set(input.lanes) : null
const activeLanes = laneFilter ? LANES.filter((l) => laneFilter.has(l.key)) : LANES
if (activeLanes.length === 0) {
  return { error: `No known lanes matched ${JSON.stringify(input?.lanes)}. Known: ${LANES.map((l) => l.key).join(', ')}` }
}

// ════════════════════════════════════════════════════════════════════════════
// Verification: one adversarial verifier per finding. It re-checks REALITY,
// re-derives the RISK CLASS from the hard constraints, and only sets
// safeToAutoApply=true when the finding is both real and genuinely green.
// (Single strict verifier — proportionate for maintenance findings, which are
// lower-stakes than the 3-lens security review used on code diffs.)
// ════════════════════════════════════════════════════════════════════════════
function verifyPrompt(f, laneKey) {
  return `Adversarially verify ONE maintenance finding. Assume it is WRONG or MIS-CLASSIFIED until the
real code/repo proves otherwise. This is READ-ONLY: inspect, do not change anything.

Finding (lane: ${laneKey}):
${JSON.stringify(
  {
    title: f.title,
    package: f.package,
    path: f.path,
    severity: f.severity,
    claimedRisk: f.riskClass,
    remediation: f.remediation,
    evidence: f.evidence,
  },
  null,
  2
)}

Check three things against the real repo at ${root} (use \`git -C ${shq(root)} ...\` and read files at
${root}/<path>):
1. IS IT REAL? Reproduce the evidence. If you cannot confirm the problem exists as described, set
   isReal=false. Default to false when uncertain.
2. WHAT IS THE TRUE RISK CLASS? Re-derive it yourself from the guide below — do not trust the finding's
   self-assessment. If the target file/path touches ANY hard constraint, it is red regardless of what
   the finding claimed.
3. IS IT SAFE TO AUTO-APPLY? Set safeToAutoApply=true ONLY if isReal AND your riskClass is "green" AND
   applying the exact proposed remediation cannot change behavior or touch a constrained surface.

${RISK_GUIDE}

Give a one-sentence reason. When genuinely unsure on any axis, choose the conservative answer
(isReal=false, higher risk, not auto-applyable).`
}

async function verifyFinding(f, laneKey) {
  const v = await agent(verifyPrompt(f, laneKey), {
    label: `verify:${laneKey}:${(f.path || f.title || '').slice(0, 32)}`,
    phase: 'Verify',
    schema: VERDICT,
  })
  if (!v) return { ...f, lane: laneKey, status: 'unverified' } // verifier crashed/skipped
  return {
    ...f,
    lane: laneKey,
    // The verifier's classification is authoritative over the discoverer's.
    riskClass: v.riskClass,
    safeToAutoApply: v.safeToAutoApply === true,
    verifyReason: v.reason,
    status: v.isReal ? 'confirmed' : 'rejected',
  }
}

// ════════════════════════════════════════════════════════════════════════════
// Orchestration — pipeline: each lane's findings start verifying the moment
// that lane's discovery returns (no barrier between discover and verify across
// lanes). The barrier is the final `await` before synthesis, which is correct:
// the prioritized plan genuinely needs every confirmed finding at once.
// ════════════════════════════════════════════════════════════════════════════
log(`repo-maintenance-optimization: ${activeLanes.length} lane(s) over ${packages.length} package(s) @ ${root}`)

const reviewed = await pipeline(
  activeLanes,
  (lane) =>
    agent(`${lane.prompt}\n\n${BOUNDARIES}\n\n${RISK_GUIDE}`, {
      label: `discover:${lane.key}`,
      phase: 'Discover',
      schema: FINDINGS,
    }),
  (found, lane) =>
    parallel((found?.findings ?? []).map((f) => () => verifyFinding(f, lane.key)))
)

// pipeline/parallel leave null holes for skipped/failed items.
const all = reviewed.flat().filter(Boolean)
const confirmed = all.filter((f) => f.status === 'confirmed')
const rejected = all.filter((f) => f.status === 'rejected')
const unverified = all.filter((f) => f.status === 'unverified')

// Bucket the confirmed backlog by actionability.
const green = confirmed.filter((f) => f.safeToAutoApply) // safe to auto-apply now
const yellow = confirmed.filter((f) => !f.safeToAutoApply && f.riskClass === 'yellow')
const red = confirmed.filter((f) => !f.safeToAutoApply && f.riskClass === 'red')

const sevRank = { critical: 0, high: 1, medium: 2, low: 3 }
const bySeverity = (a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9)
;[green, yellow, red, unverified].forEach((arr) => arr.sort(bySeverity))

const slim = (f) => ({
  lane: f.lane,
  severity: f.severity,
  risk: f.riskClass,
  title: f.title,
  package: f.package,
  path: f.path,
  remediation: f.remediation,
  reason: f.verifyReason,
})

log(
  `Discovered ${all.length} raw findings → ${confirmed.length} confirmed ` +
    `(${green.length} green / ${yellow.length} yellow / ${red.length} red), ` +
    `${rejected.length} rejected, ${unverified.length} unverified.`
)

// ════════════════════════════════════════════════════════════════════════════
// Synthesis — one agent turns the confirmed, risk-ranked backlog into a
// sequenced maintenance & optimization plan (cross-item reasoning: ordering,
// dependencies, and the safe follow-up path).
// ════════════════════════════════════════════════════════════════════════════
phase('Synthesize')
const report = await agent(
  `OUTPUT CONTRACT (read first): Your ENTIRE response is stored verbatim as the plan — it is data, not
a chat reply. Emit ONLY the finished Markdown plan. The FIRST character of your response must be \`#\`
(the title heading). Do NOT include any preamble, meta-commentary, reasoning, "Let me…" narration,
restatement of this task, or code fences around the whole document. No text before the title, none after
the last section. Do all your thinking silently; write only the plan.

Write a concise, prioritized MAINTENANCE & OPTIMIZATION plan for the govern-zone monorepo from the
verified backlog below. This audit was READ-ONLY; the plan tells a human what to do next.
Begin with the exact title line:  # govern-zone — Maintenance & Optimization Plan

Structure it as:
1. Executive summary (2-3 sentences: overall repo health + the single highest-leverage action).
2. "Safe to apply now" — the green items, grouped by package, as a checklist. Note that even these
   must be applied in an isolated per-agent worktree and committed by a human (this repo human-gates
   commits/pushes; submodules commit from inside; never \`git add -A\`).
3. "Needs care" — the yellow items, ordered by severity, each with the judgment call required.
4. "Constrained / human-decision" — the red items (sealed hashes, submodule boundaries, published API,
   console CSP, CI/generated files), each stating which constraint it touches and why it can't be
   auto-applied.
5. Suggested sequencing for the top 5 actions.

Confirmed backlog (JSON):
${JSON.stringify({ green: green.map(slim), yellow: yellow.map(slim), red: red.map(slim) }, null, 2)}

${unverified.length ? `Note: ${unverified.length} finding(s) were UNVERIFIED (the verifier produced no vote) — list them as "needs manual re-check", do not present them as clean.` : ''}

REMINDER: respond with the plan only — first character \`#\`, no preamble or trailing commentary.`,
  { label: 'synthesize:plan', phase: 'Synthesize' }
)

// Defensive strip: if a model still emits a monologue preamble before the title,
// keep only from the first Markdown H1 onward so the returned `report` is clean.
function stripPreamble(text) {
  if (typeof text !== 'string') return text
  const i = text.indexOf('\n# ')
  if (i >= 0) return text.slice(i + 1) // title wasn't the first line → drop preamble
  return text.startsWith('# ') ? text : text.trimStart()
}
const reportClean = stripPreamble(report)

return {
  mode: 'audit (read-only)',
  root,
  lanes: activeLanes.map((l) => l.key),
  packages,
  totals: {
    raw: all.length,
    confirmed: confirmed.length,
    green: green.length,
    yellow: yellow.length,
    red: red.length,
    rejected: rejected.length,
    unverified: unverified.length,
  },
  backlog: { green: green.map(slim), yellow: yellow.map(slim), red: red.map(slim) },
  unverified: unverified.map(slim),
  report: reportClean,
}
