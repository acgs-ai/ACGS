#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_PROOF_TEMPLATE = 'hosted-storybook-proof.example.json'
const DEFAULT_LIVE_OUTPUT = '../dist-release-evidence/production-live-verification.json'
const DEFAULT_HANDOFF = '../dist-release-evidence/hosted-storybook-handoff.json'
const DEFAULT_OUT = '../dist-release-evidence/hosted-storybook-proof-gap-report.json'
const STORYBOOK_TARGET = 'https://storybook.acgs.ai'
const REQUIRED_STORYBOOK_CHECK_IDS = [
  'storybook-dns-live',
  'storybook-https-live',
  'storybook-manifest-live',
]
const STORYBOOK_BLOCKER_IDS = [
  'live-storybook-dns',
  'live-storybook-https',
  'live-storybook-manifest',
]
const REQUIRED_BROWSER_FIELDS = ['screenshotRefs', 'automatedA11yReportRefs', 'visualDiffRefs']
const CLAIM_BOUNDARY =
  'Hosted Storybook proof gap report is a local operator checklist only; it does not deploy, mutate DNS, fetch live origins, install the official Storybook runtime, validate legal/SOC2/WCAG/pentest/regulatory claims, or create hosted Storybook proof; it is not live production proof.'
const COMMAND_TEMPLATE =
  'pnpm -F acgi-ai run build:hosted-storybook-proof-gap-report -- --proof-template <hosted-storybook-proof.example.json> --live-output <verify-production-live.json> --handoff <hosted-storybook-handoff.json> --out <hosted-storybook-proof-gap-report.json>'

function usage() {
  return `Usage: node scripts/build-hosted-storybook-proof-gap-report.mjs [options]

Builds a local gap report for the hosted Storybook proof packet. This command
reads the template, saved live-verifier output, and hosted Storybook handoff so
operators can see exactly which external evidence is still missing before they
try to remove hosted-storybook-buyer-evidence.

Options:
  --proof-template <path>  Hosted Storybook proof template/completed proof (default: ${DEFAULT_PROOF_TEMPLATE})
  --live-output <path>     Saved verify:production-live JSON (default: ${DEFAULT_LIVE_OUTPUT} when present)
  --handoff <path>         Hosted Storybook handoff JSON (default: ${DEFAULT_HANDOFF} when present)
  --out <path>             Write gap report JSON (default: ${DEFAULT_OUT})
  --json                   Print machine-readable JSON to stdout
  --help                   Show this help
`
}

function parseArgs(argv) {
  const options = {
    proofTemplatePath: DEFAULT_PROOF_TEMPLATE,
    liveOutputPath: DEFAULT_LIVE_OUTPUT,
    handoffPath: DEFAULT_HANDOFF,
    outPath: DEFAULT_OUT,
    json: false,
    help: false,
  }

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    const next = () => {
      index += 1
      if (index >= argv.length) throw new Error(`${arg} requires a value`)
      return argv[index]
    }

    if (arg === '--') continue
    else if (arg === '--proof-template') options.proofTemplatePath = next()
    else if (arg === '--live-output') options.liveOutputPath = next()
    else if (arg === '--handoff') options.handoffPath = next()
    else if (arg === '--out') options.outPath = next()
    else if (arg === '--json') options.json = true
    else if (arg === '--help' || arg === '-h') options.help = true
    else throw new Error(`Unknown option: ${arg}`)
  }
  return options
}

function readJson(path, label, { optional = false } = {}) {
  try {
    return JSON.parse(readFileSync(resolve(root, path), 'utf8'))
  } catch (error) {
    if (optional && error.code === 'ENOENT') return null
    throw new Error(`Could not read ${label} JSON ${path}: ${error.message}`)
  }
}

function writeJson(path, payload) {
  const outPath = resolve(root, path)
  mkdirSync(dirname(outPath), { recursive: true })
  writeFileSync(outPath, `${JSON.stringify(payload, null, 2)}\n`)
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0
}

function collectPendingRefs(value, path = '$', refs = []) {
  if (typeof value === 'string') {
    if (value.includes('REPLACE_WITH_') || value.startsWith('pending-external:')) {
      refs.push({ path, value })
    }
    return refs
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectPendingRefs(entry, `${path}[${index}]`, refs))
    return refs
  }
  if (value && typeof value === 'object') {
    for (const [key, entry] of Object.entries(value)) {
      collectPendingRefs(entry, `${path}.${key}`, refs)
    }
  }
  return refs
}

function findCheck(liveOutput, id) {
  const checks = Array.isArray(liveOutput?.checks) ? liveOutput.checks : []
  return checks.find((check) => check?.id === id) ?? null
}

function liveBlockerIds(liveOutput) {
  const blockers = Array.isArray(liveOutput?.blockers) ? liveOutput.blockers : []
  return blockers
    .map((blocker) => (typeof blocker === 'string' ? blocker : blocker?.blockerId))
    .filter(isNonEmptyString)
}

function storyIdsFrom(proof) {
  if (Array.isArray(proof?.target?.requiredStoryIds)) return proof.target.requiredStoryIds
  if (Array.isArray(proof?.manifestEvidence?.storyIds)) return proof.manifestEvidence.storyIds
  if (Array.isArray(proof?.browserEvidence?.storyIds)) return proof.browserEvidence.storyIds
  return []
}

function gap(id, title, status, evidence, nextAction) {
  return { id, title, status, evidence, nextAction }
}

function buildGapReport({ proof, liveOutput, handoff, options }) {
  const pendingRefs = collectPendingRefs(proof)
  const blockerIds = liveBlockerIds(liveOutput)
  const storyIds = storyIdsFrom(proof).filter(isNonEmptyString)
  const missingBrowserRefs = []
  const browserEvidence = proof.browserEvidence ?? {}
  for (const field of REQUIRED_BROWSER_FIELDS) {
    const refs = browserEvidence[field]
    const missingStoryIds = storyIds.filter((storyId) => !isNonEmptyString(refs?.[storyId]))
    if (missingStoryIds.length > 0) missingBrowserRefs.push({ field, missingStoryIds })
  }
  const liveChecks = REQUIRED_STORYBOOK_CHECK_IDS.map((id) => {
    const check = findCheck(liveOutput, id)
    return { id, status: check?.status ?? 'missing', error: check?.error ?? null }
  })
  const storybookBlockers = STORYBOOK_BLOCKER_IDS.filter((id) => blockerIds.includes(id))
  const workflow = proof.workflow ?? {}
  const dns = proof.dns ?? {}
  const manifestEvidence = proof.manifestEvidence ?? {}
  const hostedStorybook = proof.copyIntoProductionEvidence?.hostedStorybook ?? {}

  const gaps = [
    gap(
      'storybook-pages-run-evidence',
      'Attach successful Pages workflow run',
      isNonEmptyString(workflow.runUrl) && isNonEmptyString(workflow.pagesDeployUrl)
        ? 'ready'
        : 'missing-external-proof',
      { runUrl: workflow.runUrl ?? null, pagesDeployUrl: workflow.pagesDeployUrl ?? null },
      'Run buyer-evidence-storybook with STORYBOOK_PAGES_ENABLED=true and attach the workflow run plus Pages deploy URL.',
    ),
    gap(
      'storybook-dns-evidence',
      'Attach storybook.acgs.ai DNS evidence',
      isNonEmptyString(dns.configuredBy) && isNonEmptyString(dns.evidenceRef)
        ? 'ready'
        : 'missing-external-proof',
      {
        host: dns.host ?? null,
        configuredBy: dns.configuredBy ?? null,
        evidenceRef: dns.evidenceRef ?? null,
      },
      'Attach DNS owner/change evidence for storybook.acgs.ai CNAME before rerunning the live verifier.',
    ),
    gap(
      'storybook-live-verifier-pass',
      'Pass Storybook live verifier checks',
      liveOutput?.status === 'pass' && storybookBlockers.length === 0
        ? 'ready'
        : 'blocked-live-verifier',
      { liveStatus: liveOutput?.status ?? 'missing', storybookBlockers, liveChecks },
      'Rerun verify:production-live until storybook-dns-live, storybook-https-live, and storybook-manifest-live pass and live-storybook-* blockers are absent.',
    ),
    gap(
      'hosted-manifest-evidence',
      'Attach hosted manifest proof',
      isNonEmptyString(manifestEvidence.manifestJsonRef) &&
        isNonEmptyString(manifestEvidence.claimBoundaryRef)
        ? 'ready'
        : 'missing-external-proof',
      {
        publishTarget: manifestEvidence.publishTarget ?? null,
        manifestJsonRef: manifestEvidence.manifestJsonRef ?? null,
        claimBoundaryRef: manifestEvidence.claimBoundaryRef ?? null,
        storyIds,
      },
      'Attach hosted /manifest.json evidence proving publishTarget, story ids, and claim-boundary preservation.',
    ),
    gap(
      'hosted-browser-evidence',
      'Attach hosted browser, a11y, and visual-diff refs',
      browserEvidence.status === 'pass' && missingBrowserRefs.length === 0
        ? 'ready'
        : 'missing-external-proof',
      {
        status: browserEvidence.status ?? null,
        targetUrl: browserEvidence.targetUrl ?? null,
        viewportSet: browserEvidence.viewportSet ?? [],
        missingBrowserRefs,
      },
      'Attach hosted screenshot, automated accessibility, and visual-diff refs for every buyer-evidence story across the visual baseline viewports.',
    ),
    gap(
      'production-evidence-copy-field',
      'Prepare copyIntoProductionEvidence.hostedStorybook',
      hostedStorybook.status === 'verified' && isNonEmptyString(hostedStorybook.proofRef)
        ? 'ready'
        : 'missing-external-proof',
      { hostedStorybook },
      'Copy the verified hostedStorybook object into the completed production evidence manifest after live proof passes.',
    ),
    gap(
      'no-template-or-pending-refs',
      'Replace template and pending refs',
      pendingRefs.length === 0 ? 'ready' : 'missing-external-proof',
      { pendingRefCount: pendingRefs.length, pendingRefs: pendingRefs.slice(0, 80) },
      'Replace every REPLACE_WITH_* and pending-external:* value with signed external evidence before validation.',
    ),
  ]
  const openGaps = gaps.filter((entry) => entry.status !== 'ready')

  return {
    schemaVersion: 1,
    artifactKind: 'hosted-storybook-proof-gap-report',
    generatedAt: new Date().toISOString(),
    status: openGaps.length === 0 ? 'ready-for-validation' : 'blocked',
    claimBoundary: CLAIM_BOUNDARY,
    command: COMMAND_TEMPLATE,
    inputs: {
      proofTemplatePath: options.proofTemplatePath,
      liveOutputPath: options.liveOutputPath,
      handoffPath: options.handoffPath,
      proofArtifactKind: proof.artifactKind ?? null,
      liveOutputPresent: Boolean(liveOutput),
      handoffPresent: Boolean(handoff),
      handoffStatus: handoff?.status ?? null,
    },
    target: {
      url: STORYBOOK_TARGET,
      manifestUrl: `${STORYBOOK_TARGET}/manifest.json`,
      blockerToRemove: 'hosted-storybook-buyer-evidence',
    },
    summary: {
      totalGaps: gaps.length,
      openGapCount: openGaps.length,
      readyGapCount: gaps.length - openGaps.length,
      openGapIds: openGaps.map((entry) => entry.id),
      storyCount: storyIds.length,
      storybookBlockers,
    },
    gaps,
    operatorSequence: [
      'Build the buyer-evidence gallery and publish it through the gated buyer-evidence-storybook workflow.',
      'Attach Pages run, Pages deploy URL, and storybook.acgs.ai DNS evidence to the hosted proof packet.',
      'Rerun verify:production-live and require storybook-dns-live, storybook-https-live, and storybook-manifest-live to pass.',
      'Attach hosted manifest, hosted screenshots, automated accessibility, and visual-diff refs for every buyer-evidence story.',
      'Run validate:hosted-storybook-proof with --require-pass and copy the verified hostedStorybook object into production evidence.',
    ],
  }
}

function printHuman(report, outPath) {
  console.log(`Hosted Storybook proof gap report: ${report.status}`)
  console.log(CLAIM_BOUNDARY)
  if (outPath) console.log(`Wrote ${outPath}`)
  console.log(`Open gaps: ${report.summary.openGapIds.join(', ') || 'none'}`)
}

function main() {
  let options
  try {
    options = parseArgs(process.argv.slice(2))
    if (options.help) {
      console.log(usage())
      return
    }
    const proof = readJson(options.proofTemplatePath, 'hosted Storybook proof template')
    const liveOutput = readJson(options.liveOutputPath, 'live output', { optional: true })
    const handoff = readJson(options.handoffPath, 'hosted Storybook handoff', { optional: true })
    const report = buildGapReport({ proof, liveOutput, handoff, options })
    if (options.outPath) writeJson(options.outPath, report)
    if (options.json || !options.outPath)
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
    else printHuman(report, options.outPath)
  } catch (error) {
    if (options?.json) {
      process.stdout.write(
        `${JSON.stringify(
          {
            schemaVersion: 1,
            artifactKind: 'hosted-storybook-proof-gap-report-error',
            status: 'fail',
            error: error.message,
            claimBoundary: CLAIM_BOUNDARY,
          },
          null,
          2,
        )}\n`,
      )
    } else {
      console.error(error.message)
      console.error(usage())
    }
    process.exit(1)
  }
}

main()
