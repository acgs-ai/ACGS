#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(root, '..')
const DEFAULT_TEMPLATE = 'production-evidence.example.json'
const DEFAULT_LIVE_OUTPUT = '../dist-release-evidence/production-live-verification.json'
const DEFAULT_BLOCKER_REPORT = '../dist-release-evidence/production-blocker-report.json'
const DEFAULT_CUTOVER_PLAN = '../dist-release-evidence/production-cutover-plan.json'
const DEFAULT_OUT = '../dist-release-evidence/production-evidence.deployment-blocked.json'
// Upstream source artifact builders: build:production-blocker-report and build:production-cutover-plan.
const COMMAND_TEMPLATE =
  'pnpm -F acgi-ai run build:production-evidence-draft -- --live-output <verify-production-live.json> --blocker-report <production-blocker-report.json> --cutover-plan <production-cutover-plan.json> --out <production-evidence.deployment-blocked.json>'
const CLAIM_BOUNDARY =
  'Deployment-blocked production evidence draft generated from saved local artifacts; it is not live production proof, not legal signoff, not SOC2 proof, not WCAG conformance proof, not pentest completion, and not regulatory compliance proof.'
const VALIDATION_OUTPUT_REF = 'pending-external:production-evidence-validation-output'
const POSTDEPLOY_OUTPUT_REF = 'pending-external:postdeploy-output'
const BASE_REMAINING_BLOCKERS = [
  'production-deployment',
  'frontend-production-auth',
  'legal-review-of-claim-matrix',
  'third-party-penetration-test',
  'full-wcag-manual-screen-reader-evidence',
  'hosted-storybook-buyer-evidence',
]

function usage() {
  return `Usage: node scripts/build-production-evidence-draft.mjs [options]

Builds a deployment-blocked production-evidence manifest draft from saved local artifacts.
This command performs local file I/O only: it does not deploy, fetch live origins, mutate DNS,
or create live production proof. The generated manifest must still be validated with
validate:production-evidence and remains blocked until live verifier blockers are resolved.

Options:
  --template <path>                 production-evidence.example.json path (default: ${DEFAULT_TEMPLATE})
  --live-output <path>              JSON output from pnpm -F acgi-ai run verify:production-live -- --json
                                    (default: ${DEFAULT_LIVE_OUTPUT})
  --blocker-report <path>           Optional production-blocker-report JSON (default: ${DEFAULT_BLOCKER_REPORT} when present)
  --cutover-plan <path>             Optional production-cutover-plan JSON (default: ${DEFAULT_CUTOVER_PLAN} when present)
  --out <path>                      Write the draft JSON to this path (default: ${DEFAULT_OUT})
  --cloud-run-revision-url <url>    Optional real Cloud Run revision URL; otherwise pending-external is recorded
  --cloudflare-url <url>            Optional real Cloudflare deployment URL; otherwise pending-external is recorded
  --marketing-run-url <url>         Optional real marketing workflow run URL; otherwise pending-external is recorded
  --console-run-url <url>           Optional real console workflow run URL; otherwise pending-external is recorded
  --storybook-run-url <url>         Optional real Storybook workflow run URL; otherwise pending-external is recorded
  --validation-output-ref <ref>     Validator output artifact/hash ref (default: ${VALIDATION_OUTPUT_REF})
  --postdeploy-output-ref <ref>     Postdeploy artifact/hash ref (default: ${POSTDEPLOY_OUTPUT_REF})
  --json                            Print machine-readable JSON to stdout
  --help                            Show this help
`
}

function parseArgs(argv) {
  const options = {
    templatePath: DEFAULT_TEMPLATE,
    liveOutputPath: DEFAULT_LIVE_OUTPUT,
    blockerReportPath: DEFAULT_BLOCKER_REPORT,
    cutoverPlanPath: DEFAULT_CUTOVER_PLAN,
    outPath: DEFAULT_OUT,
    cloudRunRevisionUrl: null,
    cloudflareUrl: null,
    marketingRunUrl: null,
    consoleRunUrl: null,
    storybookRunUrl: null,
    validationOutputRef: VALIDATION_OUTPUT_REF,
    postdeployOutputRef: POSTDEPLOY_OUTPUT_REF,
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
    else if (arg === '--template') options.templatePath = next()
    else if (arg === '--live-output') options.liveOutputPath = next()
    else if (arg === '--blocker-report') options.blockerReportPath = next()
    else if (arg === '--cutover-plan') options.cutoverPlanPath = next()
    else if (arg === '--out') options.outPath = next()
    else if (arg === '--cloud-run-revision-url') options.cloudRunRevisionUrl = next()
    else if (arg === '--cloudflare-url') options.cloudflareUrl = next()
    else if (arg === '--marketing-run-url') options.marketingRunUrl = next()
    else if (arg === '--console-run-url') options.consoleRunUrl = next()
    else if (arg === '--storybook-run-url') options.storybookRunUrl = next()
    else if (arg === '--validation-output-ref') options.validationOutputRef = next()
    else if (arg === '--postdeploy-output-ref') options.postdeployOutputRef = next()
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

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0
}

function pendingExternal(label) {
  return `pending-external:${label}`
}

function unique(values) {
  return [...new Set(values.filter(isNonEmptyString))]
}

function refPath(path) {
  if (!isNonEmptyString(path)) return null
  return relative(repoRoot, resolve(root, path)).replaceAll('\\', '/')
}

function idsFromLiveOutput(liveOutput) {
  const blockers = Array.isArray(liveOutput?.blockers) ? liveOutput.blockers : []
  return blockers
    .map((blocker) => (typeof blocker === 'string' ? blocker : blocker?.blockerId))
    .filter(isNonEmptyString)
}

function idsFromArtifact(artifact) {
  return Array.isArray(artifact?.productionLiveBlockers)
    ? artifact.productionLiveBlockers.filter(isNonEmptyString)
    : []
}

function findCheck(liveOutput, id) {
  return Array.isArray(liveOutput?.checks)
    ? liveOutput.checks.find((check) => check?.id === id)
    : null
}

function assertArtifactKind(payload, expected, label) {
  if (!payload) return
  if (payload.artifactKind !== expected) {
    throw new Error(`${label} artifactKind must be ${expected}`)
  }
}

function buildDraft({ template, liveOutput, blockerReport, cutoverPlan, options }) {
  assertArtifactKind(liveOutput, 'production-live-verification', 'live output')
  assertArtifactKind(blockerReport, 'production-blocker-report', 'blocker report')
  assertArtifactKind(cutoverPlan, 'production-cutover-plan', 'cutover plan')

  const productionLiveBlockers = unique([
    ...idsFromLiveOutput(liveOutput),
    ...idsFromArtifact(blockerReport),
    ...idsFromArtifact(cutoverPlan),
  ])
  const productionLiveStatus = liveOutput.status === 'pass' ? 'pass' : 'fail'
  if (productionLiveStatus !== 'fail' || productionLiveBlockers.length === 0) {
    throw new Error(
      'build-production-evidence-draft only creates deployment-blocked drafts from failing verify:production-live output with blockers; use production-evidence.example.json for live-verified evidence after deploy.',
    )
  }

  const targets = liveOutput.targets ?? {}
  const healthzCheck = findCheck(liveOutput, 'console-healthz-live')
  const storybookManifestCheck = findCheck(liveOutput, 'storybook-manifest-live')
  const liveOutputRef = refPath(options.liveOutputPath)
  const blockerReportRef = blockerReport ? refPath(options.blockerReportPath) : null
  const cutoverPlanRef = cutoverPlan ? refPath(options.cutoverPlanPath) : null
  const manifestRef = refPath(options.outPath) ?? DEFAULT_OUT.replace(/^\.\.\//, '')

  return {
    schemaVersion: 1,
    artifactKind: 'production-evidence',
    status: 'deployment-blocked',
    generatedAt: new Date().toISOString(),
    claimBoundary: CLAIM_BOUNDARY,
    deploy: {
      marketingUrl: targets.marketingUrl ?? template.deploy?.marketingUrl ?? 'https://acgs.ai',
      consoleUrl: targets.consoleUrl ?? template.deploy?.consoleUrl ?? 'https://console.acgs.ai',
      cloudRunRevisionUrl:
        options.cloudRunRevisionUrl ?? pendingExternal('cloud-run-revision-url'),
      cloudflareUrl: options.cloudflareUrl ?? pendingExternal('cloudflare-deployment-url'),
      githubActionsRunUrls: {
        marketing: options.marketingRunUrl ?? pendingExternal('marketing-workflow-run-url'),
        console: options.consoleRunUrl ?? pendingExternal('console-workflow-run-url'),
        storybook: options.storybookRunUrl ?? pendingExternal('storybook-workflow-run-url'),
      },
    },
    verification: {
      expectedBuildId:
        targets.expectedBuildId ?? healthzCheck?.evidence?.build_id ?? pendingExternal('expected-build-id'),
      healthz: {
        url:
          healthzCheck?.evidence?.url ??
          `${targets.consoleUrl ?? template.deploy?.consoleUrl ?? 'https://console.acgs.ai'}/healthz`,
        served_hash:
          healthzCheck?.evidence?.served_hash ??
          targets.expectedServedHash ??
          pendingExternal('healthz-served-hash'),
        build_id:
          healthzCheck?.evidence?.build_id ??
          targets.expectedBuildId ??
          pendingExternal('healthz-build-id'),
      },
      postdeployCommand: 'pnpm -F acgi-ai run verify:postdeploy -- https://console.acgs.ai',
      postdeployOutputRef: options.postdeployOutputRef,
      liveCheckedAt: liveOutput.generatedAt ?? new Date().toISOString(),
      productionLiveCommand: 'pnpm -F acgi-ai run verify:production-live -- --json',
      productionLiveOutputRef: liveOutputRef,
      productionLiveStatus,
      productionLiveBlockers,
      productionEvidenceValidationCommand:
        `pnpm -F acgi-ai run validate:production-evidence -- --manifest ${manifestRef} --live-output ${liveOutputRef}`,
      productionEvidenceValidationOutputRef: options.validationOutputRef,
    },
    hostedStorybook: {
      url: targets.storybookUrl ?? template.hostedStorybook?.url ?? 'https://storybook.acgs.ai',
      manifestUrl:
        storybookManifestCheck?.evidence?.url ??
        template.hostedStorybook?.manifestUrl ??
        'https://storybook.acgs.ai/manifest.json',
      status: 'pending',
      proofRef: pendingExternal('storybook-pages-proof'),
      claimBoundary: 'pending means this file does not prove hosted Storybook buyer evidence.',
    },
    assurance: {
      legalClaimMatrix: {
        status: 'pending-external',
        proofRef: pendingExternal('legal-review'),
        reviewer: pendingExternal('legal-or-claim-reviewer'),
        reviewedAt: pendingExternal('legal-review-timestamp'),
        claimMatrixRef: pendingExternal('legal-reviewed-claim-matrix'),
      },
      pentest: {
        status: 'pending-external',
        proofRef: pendingExternal('pentest'),
        vendor: pendingExternal('pentest-vendor'),
        completedAt: pendingExternal('pentest-completion-timestamp'),
        reportRef: pendingExternal('pentest-report'),
        criticalFindingsOpen: pendingExternal('zero-open-critical-findings-count'),
      },
      wcagManual: {
        status: 'pending-external',
        proofRef: pendingExternal('wcag-manual'),
        reviewer: pendingExternal('accessibility-reviewer'),
        reviewedAt: pendingExternal('manual-wcag-review-timestamp'),
        reportRef: pendingExternal('manual-wcag-report'),
        assistiveTech: [pendingExternal('nvda-evidence'), pendingExternal('voiceover-evidence')],
      },
      browserScreenshots: {
        status: 'pending-external',
        proofRef: pendingExternal('browser-screenshots'),
        capturedAt: pendingExternal('browser-screenshot-capture-timestamp'),
        bundleRef: pendingExternal('browser-screenshot-or-visual-diff-bundle'),
      },
    },
    artifacts: {
      releaseEvidenceManifest: 'dist-release-evidence/manifest.json',
      platformReadinessJson: 'dist-release-evidence/platform-readiness.json',
      buyerEvidenceGallery: 'buyer-evidence-gallery',
      consoleDist: 'console-dist',
      postdeployOutput: options.postdeployOutputRef,
      verifyProductionLiveOutput: liveOutputRef,
      productionBlockerReport: blockerReportRef ?? pendingExternal('production-blocker-report'),
      productionCutoverPlan: cutoverPlanRef ?? pendingExternal('production-cutover-plan'),
      productionEvidenceDraft: manifestRef,
      validatedProductionEvidence: options.validationOutputRef,
    },
    remainingBlockers: unique([...BASE_REMAINING_BLOCKERS, ...productionLiveBlockers]),
    sourceArtifacts: {
      liveOutputPath: liveOutputRef,
      blockerReportPath: blockerReportRef,
      cutoverPlanPath: cutoverPlanRef,
    },
    blockedUntil:
      cutoverPlan?.blockedUntil ??
      blockerReport?.blockedUntil ??
      liveOutput.blockedUntil ??
      'Resolve every listed productionLiveBlocker, rerun verify:production-live until all checks pass, then validate completed production evidence before making deployment claims.',
    operatorNextSteps: [
      'Resolve the listed productionLiveBlockers in DNS, deploy, security headers, /healthz, and hosted Storybook publication.',
      'Rerun pnpm -F acgi-ai run verify:production-live -- --json and rebuild blocker/cutover/draft artifacts from the saved JSON.',
      'Run pnpm -F acgi-ai run validate:production-evidence -- --manifest <completed-production-evidence.json> --live-output <verify-production-live.json>.',
      'Do not claim production deployment, hosted Storybook, legal, SOC2, WCAG, pentest, or regulatory proof until matching external evidence is attached.',
    ],
    command: COMMAND_TEMPLATE,
  }
}

function printHuman(draft, outPath) {
  console.log(`Production evidence draft: ${draft.status}`)
  console.log(CLAIM_BOUNDARY)
  if (outPath) console.log(`Wrote ${outPath}`)
  console.log(`productionLiveStatus: ${draft.verification.productionLiveStatus}`)
  console.log(`productionLiveBlockers: ${draft.verification.productionLiveBlockers.join(', ')}`)
  console.log(`blockedUntil: ${draft.blockedUntil}`)
}

function main() {
  let options
  try {
    options = parseArgs(process.argv.slice(2))
    if (options.help) {
      console.log(usage())
      return
    }
    const template = readJson(options.templatePath, 'production evidence template')
    const liveOutput = readJson(options.liveOutputPath, 'live output')
    const blockerReport = readJson(options.blockerReportPath, 'blocker report', { optional: true })
    const cutoverPlan = readJson(options.cutoverPlanPath, 'cutover plan', { optional: true })
    const draft = buildDraft({ template, liveOutput, blockerReport, cutoverPlan, options })
    const encoded = `${JSON.stringify(draft, null, 2)}\n`
    if (options.outPath) {
      const outputPath = resolve(root, options.outPath)
      mkdirSync(dirname(outputPath), { recursive: true })
      writeFileSync(outputPath, encoded)
    }
    if (options.json || !options.outPath) process.stdout.write(encoded)
    else printHuman(draft, options.outPath)
  } catch (error) {
    if (options?.json) {
      process.stdout.write(
        `${JSON.stringify(
          {
            schemaVersion: 1,
            artifactKind: 'production-evidence-draft-error',
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
