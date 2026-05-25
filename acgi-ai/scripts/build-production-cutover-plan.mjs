#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const COMMAND_TEMPLATE =
  'pnpm -F acgi-ai run build:production-cutover-plan -- --live-output <verify-production-live.json> --blocker-report <production-blocker-report.json> --out <production-cutover-plan.json>'
// Downstream evidence draft builder consumes this artifact: build:production-evidence-draft, test:production-evidence-draft, production-evidence-draft, production-evidence.deployment-blocked.json.
const CLAIM_BOUNDARY =
  'Production cutover plan is an operator handoff artifact generated from local files; it does not deploy, mutate DNS, fetch live origins, validate legal/SOC2/WCAG/pentest/regulatory claims, or create live production proof; it is not live production proof.'
const BLOCKED_UNTIL =
  'Resolve every listed productionLiveBlocker, rerun verify:production-live until all checks pass, then validate completed production evidence before making deployment claims.'

const REQUIRED_GITHUB_SECRETS = [
  'VERCEL_TOKEN',
  'VERCEL_ORG_ID',
  'VERCEL_PROJECT_ID',
  'GCP_PROJECT_ID',
  'GCP_REGION',
  'GCP_WORKLOAD_IDENTITY_PROVIDER',
  'GCP_SERVICE_ACCOUNT',
  'GCP_ARTIFACT_REGISTRY',
  'CONSOLE_AUTH_UPSTREAM',
  'CONSOLE_BUS_UPSTREAM',
]

const REQUIRED_GITHUB_VARIABLES = ['STORYBOOK_PAGES_ENABLED=true']

const DNS_RECORDS = [
  {
    host: 'acgs.ai',
    type: 'A/ALIAS or Vercel-managed apex',
    target: 'REPLACE_WITH_VERCEL_PRODUCTION_TARGET',
    proves: ['marketing-dns-live', 'marketing-https-live'],
  },
  {
    host: 'www.acgs.ai',
    type: 'CNAME',
    target: 'REPLACE_WITH_VERCEL_WWW_TARGET',
    proves: ['marketing redirect/canonical checks'],
  },
  {
    host: 'console.acgs.ai',
    type: 'CNAME',
    target: 'REPLACE_WITH_CLOUD_RUN_OR_FLY_HOSTNAME',
    proves: ['console-dns-live', 'console-healthz-live', 'console-security-headers-live'],
  },
  {
    host: 'storybook.acgs.ai',
    type: 'CNAME',
    target: 'REPLACE_WITH_GITHUB_PAGES_CNAME_TARGET',
    proves: ['storybook-dns-live', 'storybook-https-live', 'storybook-manifest-live'],
  },
]

const BLOCKER_ACTIONS = {
  'live-console-dns':
    'Create or repair the console.acgs.ai DNS record for the deployed console service.',
  'live-storybook-dns':
    'Create or repair the storybook.acgs.ai DNS record for the hosted buyer-evidence origin.',
  'live-console-healthz':
    'Deploy the console service and verify /healthz exposes ok=true plus the expected served_hash and build_id.',
  'live-console-security-headers':
    'Serve the console origin with HSTS, CSP, X-Frame-Options, and Referrer-Policy headers.',
  'live-storybook-https':
    'Publish the buyer-evidence artifact and verify storybook.acgs.ai returns a 2xx/3xx HTTPS response.',
  'live-storybook-manifest':
    'Publish the claim-safe buyer-evidence manifest to storybook.acgs.ai and verify expected story ids, publish target, and claim boundary.',
}

function usage() {
  return `Usage: node scripts/build-production-cutover-plan.mjs [options]

Builds a local production-cutover-plan artifact from saved live verifier and blocker-report JSON.
This command performs local file I/O only: it does not deploy, change DNS, fetch live origins, or create live production proof.

Options:
  --live-output <path>            Optional JSON from pnpm -F acgi-ai run verify:production-live -- --json
  --blocker-report <path>         Optional JSON from build:production-blocker-report
  --out <path>                    Write the cutover plan JSON to this path
  --json                          Print machine-readable JSON to stdout
  --require-clear                 Exit non-zero when live blockers remain
  --help                          Show this help
`
}

function parseArgs(argv) {
  const options = {
    liveOutputPath: null,
    blockerReportPath: null,
    outPath: null,
    json: false,
    requireClear: false,
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
    else if (arg === '--live-output') options.liveOutputPath = next()
    else if (arg === '--blocker-report') options.blockerReportPath = next()
    else if (arg === '--out') options.outPath = next()
    else if (arg === '--json') options.json = true
    else if (arg === '--require-clear') options.requireClear = true
    else if (arg === '--help' || arg === '-h') options.help = true
    else throw new Error(`Unknown option: ${arg}`)
  }

  return options
}

function readJson(path, label) {
  if (!path) return null
  try {
    return JSON.parse(readFileSync(resolve(root, path), 'utf8'))
  } catch (error) {
    throw new Error(`Could not read ${label} JSON ${path}: ${error.message}`)
  }
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0
}

function idsFromLiveOutput(liveOutput) {
  const blockers = Array.isArray(liveOutput?.blockers) ? liveOutput.blockers : []
  return blockers
    .map((blocker) => (typeof blocker === 'string' ? blocker : blocker?.blockerId))
    .filter(isNonEmptyString)
}

function idsFromBlockerReport(blockerReport) {
  return Array.isArray(blockerReport?.productionLiveBlockers)
    ? blockerReport.productionLiveBlockers.filter(isNonEmptyString)
    : []
}

function normalizeBlocker(id, liveOutput, blockerReport) {
  const detailSources = [
    ...(Array.isArray(blockerReport?.blockers) ? blockerReport.blockers : []),
    ...(Array.isArray(liveOutput?.blockers) ? liveOutput.blockers : []),
  ]
  const found = detailSources.find(
    (blocker) => blocker && typeof blocker === 'object' && blocker.blockerId === id,
  )
  return {
    blockerId: id,
    checkId: found?.checkId ?? null,
    area: found?.area ?? 'Production cutover',
    requiredAction:
      found?.requiredAction ??
      BLOCKER_ACTIONS[id] ??
      'Resolve the corresponding live verifier failure and rerun verify:production-live.',
    error: found?.error ?? null,
    claimBoundary:
      found?.claimBoundary ??
      'This blocker must be resolved and reverified before it can support live production proof.',
  }
}

function unique(values) {
  return [...new Set(values.filter(isNonEmptyString))]
}

function buildPlan({ liveOutput, blockerReport, options }) {
  if (liveOutput && liveOutput.artifactKind !== 'production-live-verification') {
    throw new Error('live output artifactKind must be production-live-verification')
  }
  if (blockerReport && blockerReport.artifactKind !== 'production-blocker-report') {
    throw new Error('blocker report artifactKind must be production-blocker-report')
  }

  const liveStatus = isNonEmptyString(liveOutput?.status) ? liveOutput.status : null
  const blockerReportStatus = isNonEmptyString(blockerReport?.status) ? blockerReport.status : null
  const productionLiveBlockers = unique([
    ...idsFromBlockerReport(blockerReport),
    ...idsFromLiveOutput(liveOutput),
  ])
  const failedCheckIds = unique(
    Array.isArray(blockerReport?.failedCheckIds)
      ? blockerReport.failedCheckIds
      : Array.isArray(liveOutput?.checks)
        ? liveOutput.checks.filter((check) => check?.status !== 'pass').map((check) => check?.id)
        : [],
  )
  const status =
    productionLiveBlockers.length > 0 || blockerReportStatus === 'blocked' || liveStatus === 'fail'
      ? 'blocked'
      : liveStatus === 'pass'
        ? 'ready-for-evidence-validation'
        : 'operator-preflight'

  return {
    schemaVersion: 1,
    artifactKind: 'production-cutover-plan',
    generatedAt: new Date().toISOString(),
    status,
    claimBoundary: CLAIM_BOUNDARY,
    command: COMMAND_TEMPLATE,
    inputs: {
      liveOutputPath: options.liveOutputPath,
      blockerReportPath: options.blockerReportPath,
      productionLiveStatus: liveStatus,
      blockerReportStatus,
    },
    requiredGitHubSecrets: REQUIRED_GITHUB_SECRETS,
    requiredGitHubVariables: REQUIRED_GITHUB_VARIABLES,
    dnsCutover: {
      claimBoundary:
        'DNS records are required operator actions, not proof until verify:production-live passes against the live origins.',
      records: DNS_RECORDS,
    },
    operatorSequence: [
      'Run make verify-js-node24, make platform-readiness, make release-evidence, and pnpm -F acgi-ai run test:production-cutover-plan.',
      'Confirm required GitHub secrets and STORYBOOK_PAGES_ENABLED=true only after DNS and Pages are ready.',
      'Push or merge to master and record marketing.yml, console.yml, and buyer-evidence-storybook run URLs.',
      'Record Vercel deployment URL, Cloud Run revision URL, image digest, EXPECTED_BUILD_ID, and console /healthz output.',
      'Run pnpm -F acgi-ai run verify:postdeploy -- https://console.acgs.ai.',
      'Run pnpm -F acgi-ai run verify:production-live -- --json and save the JSON artifact.',
      'If blocked, run build:production-blocker-report and build:production-cutover-plan from the saved JSON artifacts.',
      'Complete production-evidence.example.json, then run validate:production-evidence with the saved live output.',
      'Do not claim production deployment, hosted Storybook, legal, SOC2, WCAG, pentest, or regulatory proof until the matching external evidence is attached.',
    ],
    productionLiveBlockers,
    failedCheckIds,
    blockers: productionLiveBlockers.map((id) => normalizeBlocker(id, liveOutput, blockerReport)),
    blockedUntil:
      status === 'blocked'
        ? blockerReport?.blockedUntil || liveOutput?.blockedUntil || BLOCKED_UNTIL
        : null,
    copyIntoProductionEvidence: {
      verification: {
        productionLiveStatus: liveStatus ?? 'REPLACE_WITH_PASS_OR_FAIL_FROM_VERIFY_PRODUCTION_LIVE',
        productionLiveBlockers,
        productionEvidenceValidationCommand:
          'pnpm -F acgi-ai run validate:production-evidence -- --manifest <completed-production-evidence.json> --live-output <verify-production-live.json>',
      },
      artifacts: {
        verifyProductionLiveOutput: '<verify-production-live.json artifact or hash>',
        productionBlockerReport: '<production-blocker-report.json artifact or hash>',
        productionCutoverPlan: '<production-cutover-plan.json artifact or hash>',
        validatedProductionEvidence: '<validate-production-evidence JSON artifact or hash>',
      },
    },
  }
}

function printHuman(plan, outPath) {
  console.log(`Production cutover plan: ${plan.status}`)
  console.log(CLAIM_BOUNDARY)
  if (outPath) console.log(`Wrote ${outPath}`)
  if (plan.productionLiveBlockers.length > 0) {
    console.log(`Blocked until: ${plan.blockedUntil}`)
    for (const blocker of plan.blockers)
      console.log(`- ${blocker.blockerId}: ${blocker.requiredAction}`)
  } else {
    console.log(
      'No saved live blockers were reported. Validate live evidence before deployment claims.',
    )
  }
}

function main() {
  let options
  try {
    options = parseArgs(process.argv.slice(2))
    if (options.help) {
      console.log(usage())
      return
    }
    const liveOutput = readJson(options.liveOutputPath, 'live output')
    const blockerReport = readJson(options.blockerReportPath, 'blocker report')
    const plan = buildPlan({ liveOutput, blockerReport, options })
    const encoded = `${JSON.stringify(plan, null, 2)}\n`
    if (options.outPath) writeFileSync(resolve(root, options.outPath), encoded)
    if (options.json || !options.outPath) process.stdout.write(encoded)
    else printHuman(plan, options.outPath)
    if (options.requireClear && plan.status === 'blocked') process.exit(1)
  } catch (error) {
    if (options?.json) {
      process.stdout.write(
        `${JSON.stringify(
          {
            schemaVersion: 1,
            artifactKind: 'production-cutover-plan-error',
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
