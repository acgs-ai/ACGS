export const meta = {
  name: 'review-branch-adversarial',
  description: 'Review the branch diff (vs master) across 4 dimensions; verify each finding through 3 independent perspectives, keep only majority-confirmed findings.',
  whenToUse: 'Before opening a PR on a govern-zone feature branch — multi-dimension review + adversarial verification.',
  phases: [
    { title: 'Review' },
    { title: 'Verify' },
  ],
}

// ---- Structured-output schemas -------------------------------------------

const FINDINGS = {
  type: 'object',
  required: ['findings'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['title', 'file', 'severity', 'detail'],
        properties: {
          title: { type: 'string' },
          file: { type: 'string' },
          line: { type: 'integer' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
          detail: { type: 'string' },
        },
      },
    },
  },
}

const VERDICT = {
  type: 'object',
  required: ['isReal'],
  properties: {
    isReal: { type: 'boolean' },
    reason: { type: 'string' },
  },
}

// ---- What "the diff" means here ------------------------------------------
// Reviewers fetch the diff themselves (the orchestrator has no shell).
// Args (all optional): Workflow({ args: { base, paths, workingTree } })
//   base        — ref to diff against (default 'master'; pass 'origin/master'
//                 if the checkout only has it remotely).
//   paths       — pathspec to SCOPE the review, e.g. 'packages/gove-zone/'
//                 ('' = whole branch diff). Smaller scope = real per-agent coverage.
//   workingTree — true to include UNCOMMITTED changes (staged + unstaged) vs base,
//                 not just committed history. Untracked files still need a direct
//                 read (git diff never shows them) — the prompt instructs that.
const input =
  typeof args === 'string'
    ? (() => {
        try {
          return JSON.parse(args)
        } catch {
          return { base: args }
        }
      })()
    : args
const BASE = input?.base ?? 'master'
const PATHS = input?.paths ?? ''
const WORKING_TREE = input?.workingTree === true
const PATHSPEC = PATHS ? ` -- ${PATHS}` : ''
// committed-only → three-dot `<base>...HEAD` (changes since the merge base).
// working-tree   → two-dot `<base>` (base tip vs the working tree: commits + uncommitted).
const DIFF_CMD = WORKING_TREE
  ? `git diff ${BASE}${PATHSPEC}`
  : `git diff ${BASE}...HEAD${PATHSPEC}`
const SCOPE_NOTE = PATHS
  ? `SCOPE: review ONLY changes under \`${PATHS}\`. Ignore everything outside it.`
  : `SCOPE: the full branch diff.`
const UNTRACKED_NOTE = WORKING_TREE
  ? ` This run INCLUDES uncommitted work. Also run \`git status --short${PATHSPEC}\` and READ every untracked ("??") file in scope — they are brand-new and never appear in a diff.`
  : ''

// ---- The 4 review dimensions ---------------------------------------------

const DIMENSIONS = [
  {
    key: 'bugs',
    prompt: `You are reviewing a govern-zone feature branch for LOGIC CORRECTNESS bugs.
Run \`${DIFF_CMD}\` to see the changes (also \`${DIFF_CMD} --stat\` for the file list).
Read the changed files for full context where the diff alone is ambiguous.
Look for: incorrect control flow, off-by-one and boundary errors, unhandled error
paths, wrong/missing return values, broken invariants, mishandled None/empty cases,
and changes that silently alter existing behavior.
Report ONLY defects you can point to a specific file (and line where possible).
Do not report style or speculative concerns. If there are no real bugs, return an empty findings array.`,
  },
  {
    key: 'security',
    prompt: `You are reviewing a govern-zone feature branch for SECURITY issues.
Run \`${DIFF_CMD}\` and read the changed files.
govern-zone is a regulated-AI governance kernel — pay special attention to:
authorization/authn changes, secret or credential handling, injection vectors,
and especially any change that WEAKENS fail-closed behavior, auditability, or
policy enforcement (a governance gate that now fails open is critical).
Report ONLY concrete, file-anchored security defects. Empty array if none.`,
  },
  {
    key: 'wiring',
    prompt: `You are reviewing a govern-zone feature branch for HANDLER-WIRING gaps —
the failure class where a handler/route/tool/middleware/event-listener is DEFINED
but never registered in the runtime path that receives traffic (dead code; old path
still runs). See the project rule at ~/.claude/rules/review-handler-wiring.md.
Run \`${DIFF_CMD}\` and read the changed files.
For each new or modified handler: find its registration site and confirm it is
referenced by symbol name in the dispatcher/router/registry. Use grep, e.g.
\`git grep -n "<HandlerSymbol>" -- ':!<its own file>'\` — zero hits outside its own
file = NOT WIRED. Also flag a unit test that calls a handler directly as the only
"proof" of wiring (it isn't), and replaced handlers whose OLD registration was not deleted.
Report each unwired/duplicate-registered handler as a finding, file-anchored. Empty array if all are wired.`,
  },
  {
    key: 'governance',
    prompt: `You are reviewing a govern-zone feature branch for GOVERNANCE-CONSTRAINT and
TEST-COVERAGE violations.
Run \`${DIFF_CMD}\` and \`${DIFF_CMD} --stat\`; read the changed files.
Flag, file-anchored:
1. Any change to a file containing a "# Constitutional Hash:" marker where the hash
   was NOT recomputed (sealed files must not drift silently).
2. Unexpected submodule POINTER drift — the parent diff shows nested-repo
   (packages/acgs-lite, packages/Acgs-Swarm, packages/clinicalguard) commit-pointer
   changes, not their contents; flag pointer bumps that are not the stated task.
3. Changes to enforcement / policy / handler paths that lack tests — specifically
   MISSING NEGATIVE-PATH tests (a gate that blocks/denies must have a test proving it denies).
4. Weak or absent test coverage on the changed logic generally.
Empty array if none apply.`,
  },
]

// ---- Verification: 3 distinct perspectives per finding -------------------

const LENSES = [
  {
    key: 'correctness',
    instr: `Through a CORRECTNESS lens: read the cited file and surrounding code. Is the
described defect actually present in the code as written, or did the reviewer
misread control flow / a guard / a default? Default to isReal=false unless you can
trace the exact code path that produces the claimed problem.`,
  },
  {
    key: 'security',
    instr: `Through a SECURITY / impact lens: even if the code matches the description, does
it actually create exploitable or fail-open behavior, or is it defended elsewhere
(validated upstream, unreachable, already gated)? Default to isReal=false unless the
harmful path is genuinely reachable.`,
  },
  {
    key: 'repro',
    instr: `Through a REPRODUCIBILITY lens: could you write a concrete failing test or give a
concrete input/sequence that demonstrates this finding? If you cannot construct a
concrete reproduction from the actual code, treat it as not real (isReal=false).`,
  },
]

function verifyPrompt(f, dimKey, lens) {
  return `Adversarially verify ONE code-review finding. Your job is to REFUTE it — assume it
is wrong until the code proves otherwise.

Finding (dimension: ${dimKey}):
${JSON.stringify({ title: f.title, file: f.file, line: f.line, severity: f.severity, detail: f.detail }, null, 2)}

Inspect the real code: open ${f.file} (read the working-tree file for full context, and
\`git diff ${BASE}${WORKING_TREE ? '' : '...HEAD'} -- ${f.file}\` to see what changed). ${lens.instr}

Return isReal=true ONLY if the finding survives this scrutiny, with a one-sentence reason.`
}

async function verifyFinding(f, dimKey) {
  // Inherit the session model (omit `model`). The verify task — refuting a
  // fail-open/reachability claim against real code — needs genuine reasoning,
  // not a cheap mechanical pass; a small model also unreliably calls the forced
  // StructuredOutput tool and silently drops the vote.
  const votes = await parallel(
    LENSES.map((lens) => () =>
      agent(verifyPrompt(f, dimKey, lens), {
        label: `verify:${dimKey}:${lens.key}`,
        phase: 'Verify',
        schema: VERDICT,
      })
    )
  )
  const cast = votes.filter(Boolean) // nulls = verifier crashed / skipped
  const realVotes = cast.filter((v) => v.isReal).length
  // Honest tri-state: a finding with ZERO surviving votes was NOT rejected —
  // verification never happened. Never let that read as "clean".
  const status =
    cast.length === 0 ? 'unverified' : realVotes >= 2 ? 'confirmed' : 'rejected'
  return {
    ...f,
    dimension: dimKey,
    realVotes,
    totalVotes: cast.length,
    status,
    confirmed: status === 'confirmed',
  }
}

// ---- Orchestration: pipeline (review per dimension -> verify per finding) --
// No barrier: a dimension's findings start verifying the moment that dimension's
// review returns — `bugs` can be verifying while `governance` is still reviewing.

const reviewed = await pipeline(
  DIMENSIONS,
  (d) =>
    agent(`${d.prompt}\n\n${SCOPE_NOTE}${UNTRACKED_NOTE}`, {
      label: `review:${d.key}`,
      phase: 'Review',
      schema: FINDINGS,
    }),
  (review, dim) =>
    parallel((review?.findings ?? []).map((f) => () => verifyFinding(f, dim.key)))
)

// pipeline/parallel leave `null` holes for skipped/failed items — filter them out.
const all = reviewed.flat().filter(Boolean)
const confirmed = all.filter((f) => f.status === 'confirmed')
const rejected = all.filter((f) => f.status === 'rejected')
const unverified = all.filter((f) => f.status === 'unverified')

const sevRank = { critical: 0, high: 1, medium: 2, low: 3 }
const bySeverity = (a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9)
confirmed.sort(bySeverity)
unverified.sort(bySeverity)

log(
  `Reviewed ${DIMENSIONS.length} dimensions: ${all.length} raw findings → ` +
    `${confirmed.length} confirmed (≥2/3), ${rejected.length} rejected, ` +
    `${unverified.length} UNVERIFIED (verifier produced no vote — not a clean signal).`
)

const slim = (f) => ({
  dimension: f.dimension,
  severity: f.severity,
  title: f.title,
  file: f.file,
  line: f.line,
  detail: f.detail,
  realVotes: `${f.realVotes}/${f.totalVotes}`,
})

return {
  diff: DIFF_CMD,
  dimensions: DIMENSIONS.map((d) => d.key),
  totals: {
    raw: all.length,
    confirmed: confirmed.length,
    rejected: rejected.length,
    unverified: unverified.length,
  },
  confirmed: confirmed.map(slim),
  unverified: unverified.map(slim),
  rejected: rejected.map((f) => ({
    dimension: f.dimension,
    title: f.title,
    file: f.file,
    realVotes: `${f.realVotes}/${f.totalVotes}`,
  })),
}
