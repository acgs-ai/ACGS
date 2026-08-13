export const meta = {
  name: 'claim-verify-pipeline',
  description:
    'Verify the governance-hub claim substantiation: build the marketing surface, prove the agent-readable static artifacts shipped, run the full package gate, then adversarially audit (3 lenses) that the code actually substantiates the public claim and preserves the C5 baseline.',
  whenToUse:
    "Re-verify that 'the project works as the claim' on demand or before a PR. Defaults to the hub-claim worktree; after the branch merges pass args:{packageDir:'/home/martin/Documents/ACGS/acgi-ai'}. Set args:{base:'feat/marketing-governance-hub'} so the audit lenses diff against the right base.",
  phases: [{ title: 'Build' }, { title: 'Gate' }, { title: 'Audit' }],
}

// ── Configuration ────────────────────────────────────────────────────────────
// Where the hub-claim source currently lives. The Marketing.tsx interview, the
// governance-domains axis, and the asset generator exist ONLY on the
// feat/marketing-hub-claim-substantiation branch, materialized in this worktree.
// Once that branch merges into the hub branch / main, override via
// args:{packageDir:'/home/martin/Documents/ACGS/acgi-ai'}.
const PKG_DEFAULT = '/home/martin/Documents/ACGS-hub-claim/acgi-ai'
// Base ref the audit lenses diff the claim work against.
const BASE_DEFAULT = 'feat/marketing-governance-hub'

// ── args normalization ───────────────────────────────────────────────────────
// args may arrive as an object, a JSON string, plain text, or undefined. Parse
// ONLY when it is actually a string (an object stays an object).
const input =
  typeof args === 'string'
    ? (() => {
        try {
          return JSON.parse(args)
        } catch {
          return { packageDir: args }
        }
      })()
    : args

const PKG = input?.packageDir ?? PKG_DEFAULT
const BASE = input?.base ?? BASE_DEFAULT

// ── Shell/prompt-safety for values embedded in sub-agent command snippets ─────
// The build, gate, and audit sub-agents are handed PROMPTS containing example
// shell commands (`cd <PKG>`, `git -C <PKG> diff <BASE>...HEAD`). Those values
// come from this workflow's args. Taken raw they enable two failure modes:
//   1. SHELL injection — a value with a quote / ; / $() / backtick can break out
//      of a command a sub-agent is told to run.
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
      `claim-verify-pipeline: refusing to run — \`${label}\` = ${JSON.stringify(s)} ` +
        `contains characters unsafe to embed in a sub-agent command/prompt (allowed: ${allowed}). ` +
        `This gate fails closed rather than emit a command a sub-agent could be tricked into ` +
        `mis-running, or a prompt it could be tricked into mis-reading.`
    )
  }
}

// PKG is a filesystem path (default '/home/martin/Documents/ACGS-hub-claim/acgi-ai',
// or e.g. 'packages/gove-zone/') interpolated into `cd` and `git -C` commands and
// shown in markdown/log — a path never legitimately needs a quote/space/;/$/backtick/newline.
assertShellSafe(PKG, 'packageDir', /^[A-Za-z0-9._/-]+$/)
// BASE is a git ref (default 'feat/marketing-governance-hub') interpolated into the
// audit diff command — a ref never legitimately needs a quote/space/;/$/backtick/newline.
assertShellSafe(BASE, 'base', /^[A-Za-z0-9._/@~^{}-]+$/)

// ── structured-output contracts ──────────────────────────────────────────────
const BUILD_RESULT = {
  type: 'object',
  required: ['buildCommand', 'buildExit', 'artifacts', 'siblingBlockPresent'],
  properties: {
    buildCommand: { type: 'string' },
    buildExit: { type: 'integer' },
    siblingBlockPresent: { type: 'boolean' },
    artifacts: {
      type: 'array',
      items: {
        type: 'object',
        required: ['path', 'present', 'bytes', 'plainText'],
        properties: {
          path: { type: 'string' },
          present: { type: 'boolean' },
          bytes: { type: 'integer' },
          // Machine-readable content-sanity verdict: true ONLY if the file is
          // plain-text framework content, NOT HTML (an SPA fallback page).
          plainText: { type: 'boolean' },
          // A one-line content sanity note (e.g. "framework header found, no HTML").
          sanity: { type: 'string' },
        },
      },
    },
    failureSummary: { type: 'string' },
  },
}

const GATE_RESULT = {
  type: 'object',
  required: ['gateCommand', 'gateExit', 'unitTests'],
  properties: {
    gateCommand: { type: 'string' },
    gateExit: { type: 'integer' },
    unitTests: {
      type: 'object',
      required: ['ran'],
      properties: {
        ran: { type: 'boolean' },
        files: { type: 'integer' },
        passed: { type: 'integer' },
        failed: { type: 'integer' },
      },
    },
    failureSummary: { type: 'string' },
  },
}

const AUDIT_VERDICT = {
  type: 'object',
  required: ['lens', 'pass', 'blocking'],
  properties: {
    lens: { type: 'string' },
    // pass = the claim is genuinely substantiated for this lens, no blocker.
    pass: { type: 'boolean' },
    // Concrete, file-anchored blockers that mean the claim is NOT substantiated.
    blocking: {
      type: 'array',
      items: {
        type: 'object',
        required: ['title', 'file', 'detail'],
        properties: {
          title: { type: 'string' },
          file: { type: 'string' },
          line: { type: 'integer' },
          detail: { type: 'string' },
        },
      },
    },
    notes: { type: 'string' },
  },
}

// ── Stage 1: Build + prove the artifacts (single agent, sequential) ───────────
// CRITICAL ordering: build:marketing is what Vercel runs and what emits the
// agent-readable surface into dist/. The artifact check MUST happen in THIS agent
// immediately after build:marketing — a later `test:all` run ends in build:console
// which empties dist/, so checking afterward would spuriously read "missing".
const buildPrompt = `You are verifying the DEPLOY-PATH build of the govern-zone marketing surface and proving its agent-readable static artifacts actually shipped.

STRICT BOUNDARIES:
- READ + BUILD only. Make NO source edits, NO commits, NO git state changes. Do NOT run \`pnpm install\` / \`uv sync\`. Run only the build + inspection commands below.
- Operate ONLY inside: ${PKG}

PROCEDURE — follow exactly, capturing each exit code with  echo "EXIT:$?":
1. cd ${shq(PKG)}
2. Confirm the script exists:  pnpm run | grep -E 'build:marketing' || cat package.json
   The deploy build (what Vercel's buildCommand runs) is:  pnpm build:marketing
   (= tsc -b && vite build --mode marketing && node --experimental-strip-types scripts/gen-agent-assets.mjs)
3. Run it:  pnpm build:marketing   — record the exit code as buildExit.
4. IMMEDIATELY (before anything else can touch dist/) inspect the emitted surface:
   - ls -l dist/llms.txt dist/governance-framework.txt   (record bytes; present=false if absent)
   - For each: head it and confirm it is PLAIN-TEXT framework content, NOT HTML
     (no leading "<!doctype html>"); set plainText=true/false accordingly (an HTML
     SPA-fallback body is plainText=false) and note one sanity line per file.
   - grep -c 'id="agent-governance"' dist/index.html   → siblingBlockPresent = (count >= 1).
     This block must be a SIBLING of #root (createRoot wipes #root children on mount).
5. failureSummary: if buildExit != 0 OR any artifact missing/empty OR an artifact is HTML
   OR the sibling block is absent, give the package, the failing check, and the last ~25 lines
   of the relevant output. Empty string if the build is clean and all three artifacts are proven.

VERIFICATION DISCIPLINE (non-negotiable): report ONLY the exit codes and byte counts you literally observed. Never claim a build passed or an artifact shipped without the literal command output in front of you.`

// ── Stage 2: Full package gate (single agent, AFTER build) ────────────────────
// Sequential after build — never concurrent: two builds in one worktree corrupt
// the shared dist/.vite/tsbuildinfo. test:all is the package's authoritative
// gate (route/CSP/claim-matrix/security/agent-asset checks + the vitest unit
// suite). The unit suite carries the C3/C4/C5 substantiation tests, so a green
// test:all is what proves the capability — not just that it compiles.
const gatePrompt = `You are running the FULL authoritative gate for the govern-zone marketing package.

STRICT BOUNDARIES:
- READ-ONLY verification. NO edits, NO commits, NO git changes, NO dependency installs.
- Operate ONLY inside: ${PKG}

PROCEDURE — capture every exit code with  echo "EXIT:$?":
1. cd ${shq(PKG)}
2. Run the aggregate gate:  pnpm test:all
   (This chain includes the vercel-route check, marketing-CSP check, claim-matrix
   overclaim scan, security-invariant check, agent-asset equality check, AND the
   vitest unit suite via test:unit — the unit suite holds the domain-distinct,
   ingestion-diff, and C5-baseline substantiation tests.) Record exit as gateExit.
3. From the vitest portion of the output, extract the unit-test tallies
   ("Test Files … / Tests …"): set unitTests.ran=true with files/passed/failed.
   If the chain aborted before vitest ran, set ran=false and explain in failureSummary.
4. failureSummary: for any non-zero lane, give the lane name and the last ~30 lines
   (or the single key error). Empty string only if gateExit == 0 AND the unit suite ran with 0 failures.

VERIFICATION DISCIPLINE: a passing gate REQUIRES gateExit == 0 AND the unit suite actually executed. Do NOT infer a pass from "it should pass" — paste the exit code you saw.`

// ── Stage 3: Adversarial claim audit — 3 independent lenses ───────────────────
// This is the value beyond a plain `make verify`: a green build proves the code
// COMPILES and tests pass; these lenses prove the code SUBSTANTIATES THE CLAIM and
// introduces no privilege/overclaim regression. Each lens defaults to skepticism.
const LENSES = [
  {
    key: 'security',
    agentType: 'security-reviewer',
    instr: `Through a SECURITY / privilege lens, audit the claim-substantiation changes for any exploitable or fail-OPEN regression.
Focus on the W3 deployment-context ingestion path (the \`?ctx=\`/query-param parser \`parseDeploymentContext\` in src/routes/Marketing.tsx) and the static agent surface:
- Does any untrusted input (query string, ?ctx envelope) reach the DOM or the brief as an INSTRUCTION, or get eval'd / passed to Function? It must only coerce onto enums / clamped numbers / booleans and fail-closed (return {} on any error, never throw).
- Did any change extend a public-only pattern (CDN font, third-party script, anonymous endpoint) into a console/privileged surface, or relax the marketing CSP? The console origin must stay isolated.
- Is fail-closed behavior preserved end to end?
Report ONLY concrete, file-anchored blockers (pass=false with blocking[]). If the ingestion path is genuinely closed-schema and nothing weakens isolation, pass=true.`,
  },
  {
    key: 'capability',
    agentType: 'code-reviewer',
    instr: `Through a CAPABILITY-substantiation lens, audit whether the code ACTUALLY delivers what the public governance-hub claim promises — not just that it compiles. Diff the branch and read the changed files.
Confirm, file-anchored, each of these is REAL and not theater:
- C3 (domain-aware): src/lib/governance-domains.ts makes gdpr vs hipaa_phipa yield a MATERIALLY different brief (PHI handled distinctly from generic PII via signalOverrides/weightDeltas), and Marketing.tsx actually consumes it.
- C4 (deployment-context): the ingestion path changes the produced brief (warm vs cold), driven by supplied context rather than a hand-toggle.
- C2 (agent-readable surface): /llms.txt + /governance-framework.txt are FRAMEWORK-only (no live-data promise), generated from the shared modules (single source of truth, not copy-pasted), and route-ordered before the SPA catch-all.
- C5 (baseline preserved): the \`none\` domain is zero-delta — the substantive governance model (agentReadableRules / briefFormat / doNotAllow / stopConditions) is NOT regressed; a guard test asserts literal base strings.
Any of these missing, faked, or only unit-tested-in-isolation-without-wiring is a blocking finding. Empty blocking[] + pass=true only if all four hold.`,
  },
  {
    key: 'evidence',
    agentType: 'verifier',
    instr: `Through an EVIDENCE / no-overclaim lens, independently confirm the gate evidence is real and the PUBLIC copy stays claim-safe.
- Re-derive (do not trust prior claims) that the agent-readable artifacts are present and non-empty and that the unit substantiation tests exist in tests/** (not src/) and assert non-vacuously.
- Scan the public-facing copy (Marketing.tsx hero/subhead/CTA/interview) AND claim-matrix.json for overclaim phrases — "compliant", "certified", "guaranteed", "production-ready", "auditor-ready" — and for present-tense promises that depend on un-shipped ops (live-URL fetch, DNS cutover). Any such phrase in shippable copy is a blocking finding.
- Confirm claim-matrix.json still carries publicDeployAllowed:false / status pending legal for the regulated-positioning claims (the claim is NOT yet cleared to publish).
pass=true only if the evidence reproduces AND no overclaim leaked AND the publish gate is still closed.`,
  },
]

const auditPrompt = (lens) => `You are independently auditing whether a SHIPPED code change genuinely substantiates a regulated-AI governance product's PUBLIC marketing claim. Be adversarial: assume the claim is NOT substantiated until the code proves it.

Package under audit: ${PKG}
See the diff with:  git -C ${shq(PKG)} diff ${BASE}...HEAD   (and \`--stat\` for the file list). Read the changed files for full context; the diff alone is often ambiguous. Untracked ("??") files never show in a diff — run \`git -C ${shq(PKG)} status --short\` and READ any new files in scope.

${lens.instr}

STRICT BOUNDARIES: READ-ONLY. No edits, no commits, no builds (the build/gate already ran in prior stages). Point every blocker at a specific file (and line where possible). Set lens="${lens.key}".`

// ── Orchestration ─────────────────────────────────────────────────────────────
// Sequential build → gate (each a hard barrier: gate must not run while the build
// holds dist/, and the audit is meaningless if the build failed). Then the three
// read-only lenses run in PARALLEL — they only read files, so no artifact race.
log(`claim-verify-pipeline: package=${PKG} · audit base=${BASE}`)

phase('Build')
const build = await agent(buildPrompt, {
  label: 'build:marketing+artifacts',
  phase: 'Build',
  model: 'sonnet',
  schema: BUILD_RESULT,
})

const artifacts = build?.artifacts ?? []
// Proof requires the TWO EXPECTED artifacts by name (not "any two nonempty
// files"), each machine-verified as plain text (a zero-exit build can still
// emit an HTML SPA fallback), and an EMPTY failureSummary — the build agent's
// contract records content-sanity failures there, and ignoring it would let an
// explicitly-failed deploy-artifact check sail through to "substantiated".
const EXPECTED_ARTIFACTS = ['llms.txt', 'governance-framework.txt']
const artifactFor = (name) => artifacts.find((a) => (a.path ?? '').split('/').pop() === name)
const artifactsProven =
  !!build &&
  build.buildExit === 0 &&
  build.siblingBlockPresent === true &&
  (build.failureSummary ?? '').trim() === '' &&
  EXPECTED_ARTIFACTS.every((name) => {
    const a = artifactFor(name)
    return !!a && a.present && a.bytes > 0 && a.plainText === true
  })

phase('Gate')
// Only spend the (slow) full gate if the deploy build itself is sound.
const gate = artifactsProven
  ? await agent(gatePrompt, {
      label: 'pnpm test:all',
      phase: 'Gate',
      model: 'sonnet',
      schema: GATE_RESULT,
    })
  : null
if (!artifactsProven) {
  log('Build/artifact proof failed — skipping the full gate and audit (fail-closed).')
}

const gateGreen =
  !!gate && gate.gateExit === 0 && gate.unitTests?.ran === true && (gate.unitTests?.failed ?? 1) === 0

phase('Audit')
// Run the adversarial lenses only when the mechanical gates are green — auditing
// a red build wastes model tokens and muddies the verdict.
const audits = gateGreen
  ? (
      await parallel(
        LENSES.map((lens) => () =>
          agent(auditPrompt(lens), {
            label: `audit:${lens.key}`,
            phase: 'Audit',
            agentType: lens.agentType,
            schema: AUDIT_VERDICT,
          }).then((v) => (v ? { ...v, lens: v.lens || lens.key } : null)),
        ),
      )
    ).filter(Boolean)
  : []

// ── Verdict (honest tri-state) ────────────────────────────────────────────────
// "substantiated" requires: deploy build + artifacts proven, full gate green, and
// all three lenses ran AND passed with zero blockers. A lens that produced no
// verdict (crashed/skipped) is NOT a pass — never let absence read as clean.
const lensesRan = audits.length
const lensesPassed = audits.filter((a) => a.pass && (a.blocking?.length ?? 0) === 0).length
const auditClean = lensesRan === LENSES.length && lensesPassed === LENSES.length

const substantiated = artifactsProven && gateGreen && auditClean

const blockers = audits.flatMap((a) =>
  (a.blocking ?? []).map((b) => ({ lens: a.lens, ...b })),
)

log(
  `claim-verify: build=${artifactsProven ? 'proven' : 'FAILED'} · gate=${
    gate ? (gateGreen ? 'green' : 'red') : 'skipped'
  } · audit=${lensesPassed}/${LENSES.length} lenses clean (${LENSES.length - lensesRan} produced no verdict) → ${
    substantiated ? 'SUBSTANTIATED' : 'NOT substantiated'
  }`,
)

return {
  substantiated,
  packageDir: PKG,
  auditBase: BASE,
  build: build
    ? {
        buildExit: build.buildExit,
        siblingBlockPresent: build.siblingBlockPresent,
        artifacts,
        failureSummary: build.failureSummary || '',
      }
    : null,
  gate: gate
    ? {
        gateExit: gate.gateExit,
        unitTests: gate.unitTests,
        failureSummary: gate.failureSummary || '',
      }
    : { skipped: true, reason: 'build/artifact proof failed' },
  audit: {
    lensesExpected: LENSES.length,
    lensesRan,
    lensesPassed,
    verdicts: audits.map((a) => ({ lens: a.lens, pass: a.pass, notes: a.notes || '' })),
    blockers,
  },
}
