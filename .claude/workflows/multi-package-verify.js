export const meta = {
  name: 'multi-package-verify',
  description:
    "Run each govern-zone package's own local lint/typecheck/test/build gate in an isolated agent, then aggregate a pass/fail matrix",
  whenToUse:
    'Before merging a multi-package change, or to get a repo-wide gate matrix without running every suite into the main context. Pass args:{packages:[...]} to verify a subset.',
  phases: [{ title: 'Verify', model: 'sonnet' }],
}

// ── Configuration ────────────────────────────────────────────────────────────
// Repo root. Workflows run from the session cwd (this repo), but we pin it so
// agents can `cd` deterministically and so `args.root` can override it.
const ROOT = '/home/martin/Documents/govern-zone'

// Path to the scope tool that DERIVES each subproject's gate from its own
// manifests (Makefile / package.json / pyproject.toml ...) and filters out any
// `NEVER run` / `DO NOT run` prohibitions. We pin the absolute path rather than
// rely on `~` expansion inside subshells.
const VALIDATE = '/home/martin/.claude/scripts/validate-subproject.py'

// Authoritative default list = the root Makefile's PYTHON_PACKAGES + the
// frontend. Each entry is a path relative to ROOT. The list is the ONLY thing
// hardcoded here; every package's actual gate commands are auto-derived at run
// time by VALIDATE, so this stays correct even as gates change.
//
// Deliberately excluded by default (add via args.packages when you want them):
//   - packages/clinicalguard  → private submodule, often uninitialized locally
//   - hermes_acgs_bundle      → path-filtered; include when its tree changed
//   - acgs-enterprise-ai-manager/frontend → Vue app, separate toolchain
const DEFAULT_PACKAGES = [
  'packages/acgs-lite',
  'packages/Acgs-Swarm',
  'packages/gove-zone',
  'packages/agent-bus-analyzer',
  'acgs_governance_eval_mvp',
  'acgs-cft-governance-pack',
  'acgi-ai',
]

// ── args normalization ───────────────────────────────────────────────────────
// args may arrive as an object (object stays an object), a JSON string, plain
// text, or undefined. Parse ONLY when it is actually a string.
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

// ── structured-output contract ───────────────────────────────────────────────
const GATE_RESULT = {
  type: 'object',
  required: ['package', 'status', 'lanes'],
  properties: {
    package: { type: 'string' },
    status: {
      type: 'string',
      // pass: every lane exit 0 | fail: a real lint/type/test defect
      // error: lane could not run (missing deps / un-synced venv / toolchain)
      // no-checks: VALIDATE found no runnable lanes for this package
      enum: ['pass', 'fail', 'error', 'no-checks'],
    },
    lanes: {
      type: 'array',
      items: {
        type: 'object',
        required: ['lane', 'command', 'exitCode', 'passed'],
        properties: {
          lane: { type: 'string' },
          command: { type: 'string' },
          exitCode: { type: 'integer' },
          passed: { type: 'boolean' },
        },
      },
    },
    failureSummary: { type: 'string' },
  },
}

// ── prompt builder ────────────────────────────────────────────────────────────
// Invocation rule (empirically verified): this repo is a `uv` + `pnpm` workspace.
// `validate-subproject` derives bare `pytest` / `ruff check .` / `mypy .` by
// convention, but bare Python tools run OUTSIDE the workspace venv and fail with
// `ModuleNotFound` (the packages are editable-installed in the uv venv). Wrapping
// them in `uv run` resolves it. `make` / `pnpm` lanes manage their own env and run
// as-is. We also prefer each package's OWN documented command when more specific
// (e.g. Acgs-Swarm's AGENTS.md pins `pytest tests/ --import-mode=importlib`).
const gatePrompt = (dir) => `You are verifying ONE package's local gate inside the govern-zone monorepo (a \`uv\` + \`pnpm\` workspace).

STRICT BOUNDARIES:
- READ-ONLY verification. Make NO file edits, NO commits, NO git state changes, and do NOT install or sync dependencies (no \`uv sync\`, no \`pnpm install\`). Run only the gate commands themselves.
- Touch ONLY the package at: ${dir}. Do not run anything against any other package.

Repo root: ${root}
Package:   ${dir}

PROCEDURE — follow exactly:
1. cd "${root}"
2. Get the authoritative lane list:  python3 ${VALIDATE} "${dir}" --json
   It lists the lanes (lint / typecheck / test / build) derived from THIS package's own manifests, with any "NEVER run" / "DO NOT run" prohibitions already filtered out.
3. Pick the command for each lane, in this priority order:
   a. If the package's OWN local instructions (AGENTS.md / CLAUDE.md / README / Makefile under ${dir}) document a more specific command for that lane (e.g. a pytest invocation with \`--import-mode=importlib\` or an explicit testpath), PREFER that exact documented command — local instructions are authoritative.
   b. Otherwise use the command from the --json plan.
4. Choose how to INVOKE each command, by its kind:
   - A bare Python tool (\`pytest ...\`, \`ruff ...\`, \`mypy ...\`, \`python -m pytest ...\`): run it through the workspace venv as \`uv run <command>\` from inside ${dir}. Running the bare tool directly fails with \`ModuleNotFound\` because it uses the wrong interpreter. (Verified: bare \`pytest\` in a package dir raises \`ModuleNotFoundError\`; \`uv run pytest\` collects cleanly.)
   - A \`make ...\` target, or a \`pnpm\`/\`npm\` command: run it AS-IS from inside ${dir} — these manage their own environment.
5. If the plan has zero checks, return status "no-checks", an empty lanes array, and an empty failureSummary.
6. For EACH lane: cd "${root}/${dir}", run the chosen command, and immediately capture its exit code with  echo "EXIT:$?". Run ALL lanes — do NOT stop at the first failing lane (we need a complete matrix).
7. Report each lane: { lane, command, exitCode, passed: exitCode === 0 } using the exact command you ran and the exit code you literally observed.
8. Set status:
   - "pass"  if every lane exited 0
   - "fail"  if a lane returned non-zero from a real lint/type/test/build defect (assertion failures, type errors in source, lint violations)
   - "error" if a lane could not run for an ENVIRONMENT reason EVEN under the correct invocation above (a \`ModuleNotFound\` that persists under \`uv run\`, missing toolchain, an un-synced workspace) — setup, not a code defect
   When genuinely unsure between "fail" and "error", choose "fail".
9. failureSummary: for any failing/erroring lane, give the package, the lane, and the last ~25 lines of its output (or the single key error line). Empty string if everything passed.

VERIFICATION DISCIPLINE (non-negotiable): report ONLY what the commands actually printed. Never claim a pass without the literal exit code you saw. Do not summarize a suite as passing because it "should" pass.`

// ── run ───────────────────────────────────────────────────────────────────────
log(`multi-package-verify: ${packages.length} package(s) → ${packages.join(', ')}`)
phase('Verify')

const results = await parallel(
  packages.map((dir) => () =>
    agent(gatePrompt(dir), {
      label: `gate:${dir}`,
      phase: 'Verify',
      model: 'sonnet',
      schema: GATE_RESULT,
    }).then((r) => (r ? { ...r, package: r.package || dir } : null)),
  ),
)

// parallel() leaves a null in the slot of any thunk that threw or was skipped.
const matrix = results.filter(Boolean)
const dropped = results.length - matrix.length

const summary = {
  total: matrix.length,
  pass: matrix.filter((r) => r.status === 'pass').length,
  fail: matrix.filter((r) => r.status === 'fail').length,
  error: matrix.filter((r) => r.status === 'error').length,
  noChecks: matrix.filter((r) => r.status === 'no-checks').length,
  dropped,
}

// "Green" requires every requested package to have actually PASSED. A package
// with no derivable gate ("no-checks") or one that dropped is NOT verified, so it
// cannot count as green — mirroring validate-subproject's refusal to fake success.
const allGreen =
  dropped === 0 && matrix.length === packages.length && matrix.every((r) => r.status === 'pass')

if (dropped > 0) {
  log(`WARNING: ${dropped} package(s) produced no result (agent skipped or errored) — NOT counted as green.`)
}
log(
  `Verify matrix: ${summary.pass}/${summary.total} pass · ${summary.fail} fail · ${summary.error} env-error · ${summary.noChecks} no-checks` +
    (dropped ? ` · ${dropped} dropped` : ''),
)

return { allGreen, summary, matrix }
