#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const COMMAND_TEMPLATE =
  'pnpm -F acgi-ai run build:production-blocker-report -- --live-output <verify-production-live.json> --out <production-blocker-report.json>'
const VALIDATION_COMMAND_TEMPLATE =
  'pnpm -F acgi-ai run validate:production-evidence -- --manifest <completed-production-evidence.json> --live-output <verify-production-live.json>'
const CLAIM_BOUNDARY =
  'Production blocker report summarizes an attached verify:production-live JSON artifact; it does not deploy, fetch live origins, validate legal/SOC2/WCAG/pentest/regulatory claims, or create live production proof; it is not live production proof.'

function usage() {
  return `Usage: node scripts/build-production-blocker-report.mjs --live-output <path> [options]

Builds a local production-blocker-report artifact from verify:production-live JSON.
This command performs local file I/O only: it does not deploy, fetch live origins, or create live production proof; it is not live production proof.

Options:
  --live-output <path>           JSON output from pnpm -F acgi-ai run verify:production-live -- --json
  --out <path>                   Write the report JSON to this path
  --json                         Print machine-readable JSON to stdout
  --require-clear                Exit non-zero when live output still has blockers or non-passing checks
  --help                         Show this help
`
}

function parseArgs(argv) {
  const options = {
    liveOutputPath: null,
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
    else if (arg === '--out') options.outPath = next()
    else if (arg === '--json') options.json = true
    else if (arg === '--require-clear') options.requireClear = true
    else if (arg === '--help' || arg === '-h') options.help = true
    else if (!options.liveOutputPath) options.liveOutputPath = arg
    else throw new Error(`Unknown option: ${arg}`)
  }

  if (!options.help && !options.liveOutputPath) throw new Error('--live-output is required')
  return options
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(resolve(root, path), 'utf8'))
  } catch (error) {
    throw new Error(`Could not read JSON ${path}: ${error.message}`)
  }
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0
}

function normalizeBlocker(blocker, index) {
  if (!blocker || typeof blocker !== 'object') {
    throw new Error(`blockers[${index}] must be an object`)
  }
  if (!isNonEmptyString(blocker.blockerId)) {
    throw new Error(`blockers[${index}].blockerId must be present`)
  }

  return {
    blockerId: blocker.blockerId,
    checkId: isNonEmptyString(blocker.checkId) ? blocker.checkId : null,
    status: isNonEmptyString(blocker.status) ? blocker.status : 'fail',
    area: isNonEmptyString(blocker.area) ? blocker.area : 'Production live check',
    requiredAction: isNonEmptyString(blocker.requiredAction)
      ? blocker.requiredAction
      : 'Resolve the underlying live verifier failure and rerun verify:production-live.',
    error: isNonEmptyString(blocker.error) ? blocker.error : null,
    evidence: blocker.evidence && typeof blocker.evidence === 'object' ? blocker.evidence : {},
    claimBoundary: isNonEmptyString(blocker.claimBoundary)
      ? blocker.claimBoundary
      : 'This blocker is not live production proof until the live verifier passes.',
  }
}

function buildReport(liveOutput, options) {
  if (liveOutput?.artifactKind !== 'production-live-verification') {
    throw new Error('live output artifactKind must be production-live-verification')
  }

  const checks = Array.isArray(liveOutput.checks) ? liveOutput.checks : []
  const blockers = Array.isArray(liveOutput.blockers)
    ? liveOutput.blockers.map((blocker, index) => normalizeBlocker(blocker, index))
    : []
  const failedCheckIds = checks
    .filter((check) => check?.status !== 'pass')
    .map((check) => check?.id)
    .filter(Boolean)
  const productionLiveStatus = isNonEmptyString(liveOutput.status) ? liveOutput.status : 'unknown'
  const status = productionLiveStatus === 'pass' && blockers.length === 0 && failedCheckIds.length === 0
    ? 'clear'
    : 'blocked'
  const productionLiveBlockers = blockers.map((blocker) => blocker.blockerId)

  return {
    schemaVersion: 1,
    artifactKind: 'production-blocker-report',
    generatedAt: new Date().toISOString(),
    status,
    claimBoundary: CLAIM_BOUNDARY,
    command: COMMAND_TEMPLATE,
    liveOutputPath: options.liveOutputPath,
    productionLiveStatus,
    productionLiveBlockers,
    blockedUntil:
      status === 'clear'
        ? null
        : liveOutput.blockedUntil ||
          'Resolve every listed blocker and rerun verify:production-live until all checks pass.',
    failedCheckIds,
    blockers,
    copyIntoProductionEvidence: {
      verification: {
        productionLiveStatus,
        productionLiveBlockers,
        productionEvidenceValidationCommand: VALIDATION_COMMAND_TEMPLATE,
      },
      artifacts: {
        verifyProductionLiveOutput: '<verify-production-live.json artifact or hash>',
        validatedProductionEvidence: '<validate-production-evidence JSON artifact or hash>',
      },
    },
    operatorNextSteps:
      status === 'clear'
        ? [
            'Attach the passing verify:production-live JSON to the completed production evidence manifest.',
            'Run validate:production-evidence with --require-pass before making live deployment claims.',
          ]
        : [
            'Fix the listed DNS, HTTPS, /healthz, security-header, or hosted Storybook blockers.',
            'Rerun pnpm -F acgi-ai run verify:production-live -- --json after each fix.',
            'Copy productionLiveStatus and productionLiveBlockers into the completed production evidence manifest.',
            'Do not claim live production deployment proof until the live verifier is clear.',
          ],
  }
}

function printHuman(report, outPath) {
  console.log(`Production blocker report: ${report.status}`)
  console.log(CLAIM_BOUNDARY)
  if (outPath) console.log(`Wrote ${outPath}`)
  if (report.status === 'blocked') {
    console.log(`Blocked until: ${report.blockedUntil}`)
    for (const blocker of report.blockers) {
      console.log(`- ${blocker.blockerId}: ${blocker.requiredAction}`)
    }
  } else {
    console.log('No live verifier blockers were reported.')
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
    const liveOutput = readJson(options.liveOutputPath)
    const report = buildReport(liveOutput, options)
    const encoded = `${JSON.stringify(report, null, 2)}\n`
    if (options.outPath) writeFileSync(resolve(root, options.outPath), encoded)
    if (options.json || !options.outPath) process.stdout.write(encoded)
    else printHuman(report, options.outPath)
    if (options.requireClear && report.status !== 'clear') process.exit(1)
  } catch (error) {
    if (options?.json) {
      process.stdout.write(
        `${JSON.stringify(
          {
            schemaVersion: 1,
            artifactKind: 'production-blocker-report-error',
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
