#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'

const STORYBOOK_TARGET = 'https://storybook.acgs.ai'
const STORYBOOK_MANIFEST_URL = 'https://storybook.acgs.ai/manifest.json'
const EXPECTED_STORY_IDS = [
  'receipt-proof-journey',
  'bus-owned-proof-source',
  'claim-safe-trust-surface',
  'deploy-readiness-boundary',
]
const REQUIRED_BROWSER_VIEWPORTS = [360, 768, 834, 1024, 1440]
const BROWSER_EVIDENCE_REF_FIELDS = [
  ['screenshotRefs', 'screenshot refs'],
  ['automatedA11yReportRefs', 'automated accessibility report refs'],
  ['visualDiffRefs', 'visual-diff refs'],
]
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
const CLAIM_BOUNDARY =
  'Hosted Storybook proof validation only checks operator-supplied files; it does not deploy, mutate DNS, fetch live origins, install the official Storybook runtime, or create legal/SOC2/WCAG/pentest/regulatory assurance.'

function usage() {
  return `Usage: node scripts/validate-hosted-storybook-proof.mjs --proof <path> --live-output <path> [options]

Validates a completed hosted Storybook buyer-evidence proof packet against saved verify:production-live JSON.
This command performs local file validation only; it does not deploy, mutate DNS, fetch live origins, install Storybook, or create hosted proof by itself.

Options:
  --proof <path>                 Completed hosted Storybook proof JSON
  --live-output <path>           JSON output from pnpm -F acgi-ai run verify:production-live -- --json
  --out <path>                   Save machine-readable validation JSON to a file
  --require-pass                 Require proof and live verifier to be fully verified/pass
  --json                         Print machine-readable JSON only
  --help                         Show this help
`
}

function parseArgs(argv) {
  const options = {
    proofPath: null,
    liveOutputPath: null,
    outPath: null,
    requirePass: false,
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
    else if (arg === '--proof') options.proofPath = next()
    else if (arg === '--live-output') options.liveOutputPath = next()
    else if (arg === '--out') options.outPath = next()
    else if (arg === '--require-pass') options.requirePass = true
    else if (arg === '--json') options.json = true
    else if (arg === '--help' || arg === '-h') options.help = true
    else if (!options.proofPath) options.proofPath = arg
    else throw new Error(`Unknown option: ${arg}`)
  }

  if (!options.help && !options.proofPath) throw new Error('--proof is required')
  if (!options.help && !options.liveOutputPath) throw new Error('--live-output is required')
  return options
}

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(resolve(path), 'utf8'))
  } catch (error) {
    throw new Error(`Could not read ${label} JSON ${path}: ${error.message}`)
  }
}

function writeJsonOutput(result, outPath) {
  if (!outPath) return
  const outputPath = resolve(outPath)
  mkdirSync(dirname(outputPath), { recursive: true })
  writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`)
}

function pass(id, evidence = {}) {
  return { id, status: 'pass', evidence }
}

function fail(id, error, evidence = {}) {
  return { id, status: 'fail', error, evidence }
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0
}

function isHttpsUrl(value) {
  if (!isNonEmptyString(value)) return false
  try {
    return new URL(value).protocol === 'https:'
  } catch {
    return false
  }
}

function includesAll(source, required) {
  const entries = Array.isArray(source) ? source : []
  return required.filter((entry) => !entries.includes(entry))
}

function missingBrowserEvidenceRefs(browserEvidence, field) {
  const refs = browserEvidence?.[field]
  if (!refs || typeof refs !== 'object' || Array.isArray(refs)) return EXPECTED_STORY_IDS
  return EXPECTED_STORY_IDS.filter((storyId) => !isNonEmptyString(refs[storyId]))
}

function findCheck(liveOutput, id) {
  return Array.isArray(liveOutput?.checks)
    ? liveOutput.checks.find((check) => check?.id === id)
    : null
}

function collectForbiddenRefs(value, path = '$', matches = []) {
  if (typeof value === 'string') {
    if (value.includes('REPLACE_WITH_') || value.startsWith('pending-external:')) matches.push(path)
    return matches
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectForbiddenRefs(entry, `${path}[${index}]`, matches))
    return matches
  }
  if (value && typeof value === 'object') {
    for (const [key, entry] of Object.entries(value)) {
      collectForbiddenRefs(entry, `${path}.${key}`, matches)
    }
  }
  return matches
}

function pushCheck(checks, condition, id, failMessage, evidence = {}) {
  checks.push(condition ? pass(id, evidence) : fail(id, failMessage, evidence))
}

function validateProof(proof, liveOutput, options) {
  const checks = []
  const forbiddenRefs = collectForbiddenRefs(proof)
  const target = proof.target ?? {}
  const workflow = proof.workflow ?? {}
  const dns = proof.dns ?? {}
  const liveVerification = proof.liveVerification ?? {}
  const manifestEvidence = proof.manifestEvidence ?? {}
  const browserEvidence = proof.browserEvidence ?? {}
  const copyIntoProductionEvidence = proof.copyIntoProductionEvidence ?? {}
  const hostedStorybook = copyIntoProductionEvidence.hostedStorybook ?? {}
  const liveBlockerIds = Array.isArray(liveOutput?.blockers)
    ? liveOutput.blockers.map((blocker) => blocker?.blockerId).filter(isNonEmptyString)
    : []
  const missingStoryIds = includesAll(manifestEvidence.storyIds, EXPECTED_STORY_IDS)
  const missingLiveCheckIds = includesAll(
    liveVerification.requiredPassingCheckIds,
    REQUIRED_STORYBOOK_CHECK_IDS,
  )
  const missingAbsentBlockerIds = includesAll(
    liveVerification.requiredAbsentBlockerIds,
    STORYBOOK_BLOCKER_IDS,
  )

  pushCheck(checks, proof.schemaVersion === 1, 'schema-version', 'schemaVersion must be 1')
  pushCheck(
    checks,
    proof.artifactKind === 'hosted-storybook-proof',
    'artifact-kind',
    'completed proof artifactKind must be hosted-storybook-proof, not hosted-storybook-proof-template',
    { actual: proof.artifactKind ?? null },
  )
  pushCheck(
    checks,
    proof.status === 'verified',
    'proof-status',
    'completed proof status must be verified',
    { actual: proof.status ?? null },
  )
  pushCheck(
    checks,
    forbiddenRefs.length === 0,
    'no-template-or-pending-refs',
    'completed hosted Storybook proof must not contain REPLACE_WITH_ placeholders or pending-external refs',
    { forbiddenRefPaths: forbiddenRefs },
  )
  pushCheck(
    checks,
    String(proof.claimBoundary ?? '').includes('not production deployment proof') &&
      String(proof.claimBoundary ?? '').includes('not legal signoff') &&
      String(proof.claimBoundary ?? '').includes('not SOC2 proof') &&
      String(proof.claimBoundary ?? '').includes('not WCAG conformance proof') &&
      String(proof.claimBoundary ?? '').includes('not pentest completion'),
    'claim-boundary-conservative',
    'claimBoundary must preserve production/legal/SOC2/WCAG/pentest limits',
    { claimBoundary: proof.claimBoundary ?? null },
  )

  pushCheck(checks, target.url === STORYBOOK_TARGET, 'target-url', 'target.url must match Storybook')
  pushCheck(
    checks,
    target.manifestUrl === STORYBOOK_MANIFEST_URL,
    'target-manifest-url',
    'target.manifestUrl must match Storybook manifest URL',
  )
  pushCheck(
    checks,
    target.expectedPublishTarget === STORYBOOK_TARGET,
    'target-publish-target',
    'target.expectedPublishTarget must match Storybook target',
  )
  pushCheck(
    checks,
    includesAll(target.requiredStoryIds, EXPECTED_STORY_IDS).length === 0,
    'target-required-stories',
    'target.requiredStoryIds must include every expected buyer-evidence story',
    { missingStoryIds: includesAll(target.requiredStoryIds, EXPECTED_STORY_IDS) },
  )
  pushCheck(
    checks,
    target.manifestClaimBoundaryMustInclude === 'not production deployment proof',
    'target-manifest-claim-boundary',
    'target must require the hosted manifest claim boundary',
  )

  pushCheck(checks, workflow.name === 'buyer-evidence-storybook', 'workflow-name', 'workflow.name must match')
  pushCheck(
    checks,
    workflow.file === '.github/workflows/storybook.yml',
    'workflow-file',
    'workflow.file must point to storybook.yml',
  )
  pushCheck(
    checks,
    workflow.artifactName === 'buyer-evidence-storybook',
    'workflow-artifact',
    'workflow.artifactName must match buyer-evidence-storybook',
  )
  pushCheck(
    checks,
    workflow.requiredRepoVariable === 'STORYBOOK_PAGES_ENABLED=true',
    'workflow-repo-variable',
    'workflow.requiredRepoVariable must require STORYBOOK_PAGES_ENABLED=true',
  )
  for (const key of ['runUrl', 'pagesDeployUrl']) {
    pushCheck(checks, isHttpsUrl(workflow[key]), `workflow-${key}`, `workflow.${key} must be an https URL`, {
      value: workflow[key] ?? null,
    })
  }
  pushCheck(
    checks,
    isNonEmptyString(workflow.buildOutputRef),
    'workflow-build-output-ref',
    'workflow.buildOutputRef must reference the uploaded buyer-evidence artifact or hash',
  )

  pushCheck(checks, dns.host === 'storybook.acgs.ai', 'dns-host', 'dns.host must match')
  pushCheck(checks, dns.recordType === 'CNAME', 'dns-record-type', 'dns.recordType must be CNAME')
  for (const key of ['configuredBy', 'evidenceRef']) {
    pushCheck(checks, isNonEmptyString(dns[key]), `dns-${key}`, `dns.${key} must be present`)
  }

  pushCheck(
    checks,
    liveVerification.command === 'pnpm -F acgi-ai run verify:production-live -- --json',
    'live-verification-command',
    'liveVerification.command must capture verify:production-live',
  )
  pushCheck(
    checks,
    isNonEmptyString(liveVerification.outputRef),
    'live-verification-output-ref',
    'liveVerification.outputRef must reference saved live verifier JSON',
  )
  pushCheck(
    checks,
    liveVerification.status === 'pass',
    'live-verification-status',
    'liveVerification.status must be pass for completed hosted proof',
    { actual: liveVerification.status ?? null },
  )
  pushCheck(
    checks,
    missingLiveCheckIds.length === 0,
    'required-passing-check-ids',
    'liveVerification.requiredPassingCheckIds must include every Storybook live check',
    { missingLiveCheckIds },
  )
  pushCheck(
    checks,
    missingAbsentBlockerIds.length === 0,
    'required-absent-blocker-ids',
    'liveVerification.requiredAbsentBlockerIds must include every Storybook blocker id',
    { missingAbsentBlockerIds },
  )

  pushCheck(
    checks,
    manifestEvidence.artifactKind === 'local-buyer-evidence-gallery',
    'manifest-artifact-kind',
    'manifestEvidence.artifactKind must match buyer evidence gallery',
  )
  pushCheck(
    checks,
    manifestEvidence.publishTarget === STORYBOOK_TARGET,
    'manifest-publish-target',
    'manifestEvidence.publishTarget must match Storybook target',
  )
  pushCheck(
    checks,
    isNonEmptyString(manifestEvidence.manifestJsonRef),
    'manifest-json-ref',
    'manifestEvidence.manifestJsonRef must reference hosted manifest evidence or hash',
  )
  pushCheck(
    checks,
    missingStoryIds.length === 0,
    'manifest-story-ids',
    'manifestEvidence.storyIds must include every expected buyer-evidence story',
    { missingStoryIds },
  )
  pushCheck(
    checks,
    isNonEmptyString(manifestEvidence.claimBoundaryRef),
    'manifest-claim-boundary-ref',
    'manifestEvidence.claimBoundaryRef must reference the hosted manifest claim boundary evidence',
  )

  pushCheck(
    checks,
    browserEvidence.status === 'pass',
    'browser-evidence-status',
    'browserEvidence.status must be pass for completed hosted proof',
    { actual: browserEvidence.status ?? null },
  )
  pushCheck(
    checks,
    browserEvidence.targetUrl === STORYBOOK_TARGET,
    'browser-evidence-target',
    'browserEvidence.targetUrl must match the hosted Storybook target',
    { actual: browserEvidence.targetUrl ?? null },
  )
  pushCheck(
    checks,
    includesAll(browserEvidence.storyIds, EXPECTED_STORY_IDS).length === 0,
    'browser-evidence-story-ids',
    'browserEvidence.storyIds must include every expected buyer-evidence story',
    { missingStoryIds: includesAll(browserEvidence.storyIds, EXPECTED_STORY_IDS) },
  )
  pushCheck(
    checks,
    includesAll(browserEvidence.viewportSet, REQUIRED_BROWSER_VIEWPORTS).length === 0,
    'browser-evidence-viewports',
    'browserEvidence.viewportSet must include the visual baseline viewport set',
    { missingViewports: includesAll(browserEvidence.viewportSet, REQUIRED_BROWSER_VIEWPORTS) },
  )
  for (const [field, label] of BROWSER_EVIDENCE_REF_FIELDS) {
    const missingRefs = missingBrowserEvidenceRefs(browserEvidence, field)
    pushCheck(
      checks,
      missingRefs.length === 0,
      `browser-evidence-${field}`,
      `browserEvidence.${field} must include ${label} for every expected story`,
      { missingStoryIds: missingRefs },
    )
  }
  pushCheck(
    checks,
    String(browserEvidence.claimBoundary ?? '').includes('not production deployment proof') &&
      String(browserEvidence.claimBoundary ?? '').includes('not WCAG conformance proof') &&
      String(browserEvidence.claimBoundary ?? '').includes('not manual screen-reader evidence') &&
      String(browserEvidence.claimBoundary ?? '').includes('not legal signoff') &&
      String(browserEvidence.claimBoundary ?? '').includes('not SOC2 proof') &&
      String(browserEvidence.claimBoundary ?? '').includes('not pentest completion'),
    'browser-evidence-claim-boundary',
    'browserEvidence.claimBoundary must preserve production/legal/SOC2/WCAG/manual/pentest limits',
    { claimBoundary: browserEvidence.claimBoundary ?? null },
  )

  pushCheck(
    checks,
    hostedStorybook.url === STORYBOOK_TARGET &&
      hostedStorybook.manifestUrl === STORYBOOK_MANIFEST_URL &&
      hostedStorybook.status === 'verified' &&
      isNonEmptyString(hostedStorybook.proofRef),
    'copy-hosted-storybook-verified',
    'copyIntoProductionEvidence.hostedStorybook must be verified and include proofRef',
    { hostedStorybook },
  )
  pushCheck(
    checks,
    copyIntoProductionEvidence.remainingBlockerToRemove === 'hosted-storybook-buyer-evidence',
    'remaining-blocker-to-remove',
    'copyIntoProductionEvidence must name hosted-storybook-buyer-evidence as the blocker to remove',
  )

  pushCheck(
    checks,
    liveOutput?.artifactKind === 'production-live-verification',
    'live-output-artifact-kind',
    'live output artifactKind must be production-live-verification',
    { actual: liveOutput?.artifactKind ?? null },
  )
  pushCheck(
    checks,
    liveOutput?.status === 'pass',
    'live-output-status',
    'live output status must be pass for completed hosted Storybook proof',
    { actual: liveOutput?.status ?? null },
  )
  pushCheck(
    checks,
    liveOutput?.targets?.storybookUrl === STORYBOOK_TARGET,
    'live-output-target',
    'live output targets.storybookUrl must match Storybook target',
    { actual: liveOutput?.targets?.storybookUrl ?? null },
  )
  pushCheck(
    checks,
    STORYBOOK_BLOCKER_IDS.every((blockerId) => !liveBlockerIds.includes(blockerId)),
    'live-output-absent-storybook-blockers',
    'live output must not include hosted Storybook blocker ids',
    { liveBlockerIds },
  )
  for (const checkId of REQUIRED_STORYBOOK_CHECK_IDS) {
    const check = findCheck(liveOutput, checkId)
    pushCheck(
      checks,
      check?.status === 'pass',
      `live-output-${checkId}`,
      `${checkId} must pass in live output`,
      { check: check ?? null },
    )
  }
  const manifestLiveCheck = findCheck(liveOutput, 'storybook-manifest-live')
  const manifestLiveEvidence = manifestLiveCheck?.evidence ?? {}
  pushCheck(
    checks,
    manifestLiveEvidence.artifactKind === 'local-buyer-evidence-gallery' &&
      manifestLiveEvidence.publishTarget === STORYBOOK_TARGET &&
      includesAll(manifestLiveEvidence.storyIds, EXPECTED_STORY_IDS).length === 0 &&
      manifestLiveEvidence.claimBoundaryPreserved === true,
    'live-output-manifest-evidence',
    'storybook-manifest-live evidence must prove hosted buyer-evidence manifest shape, stories, publish target, and claim boundary',
    { manifestLiveEvidence },
  )

  if (!options.requirePass) {
    checks.push(pass('require-pass-option', { skippedReason: '--require-pass not supplied' }))
  } else {
    pushCheck(
      checks,
      proof.status === 'verified' && liveOutput?.status === 'pass',
      'require-pass-option',
      '--require-pass requires verified proof and passing live output',
      { proofStatus: proof.status ?? null, liveStatus: liveOutput?.status ?? null },
    )
  }

  const hasFailures = checks.some((check) => check.status === 'fail')
  return {
    schemaVersion: 1,
    artifactKind: 'hosted-storybook-proof-validation',
    generatedAt: new Date().toISOString(),
    status: hasFailures ? 'fail' : 'pass',
    claimBoundary: CLAIM_BOUNDARY,
    proofPath: options.proofPath,
    liveOutputPath: options.liveOutputPath,
    checks,
  }
}

function renderHuman(result) {
  const lines = [
    `Hosted Storybook proof validation: ${result.status}`,
    `Claim boundary: ${result.claimBoundary}`,
  ]
  for (const check of result.checks) {
    const suffix = check.error ? ` — ${check.error}` : ''
    lines.push(`- ${check.status.toUpperCase()} ${check.id}${suffix}`)
  }
  return lines.join('\n')
}

try {
  const options = parseArgs(process.argv.slice(2))
  if (options.help) {
    console.log(usage())
    process.exit(0)
  }
  const proof = readJson(options.proofPath, 'hosted Storybook proof')
  const liveOutput = readJson(options.liveOutputPath, 'live output')
  const result = validateProof(proof, liveOutput, options)
  writeJsonOutput(result, options.outPath)
  if (options.json) console.log(JSON.stringify(result, null, 2))
  else {
    console.log(renderHuman(result))
    if (options.outPath) console.log(`Wrote ${options.outPath}`)
  }
  process.exit(result.status === 'pass' ? 0 : 1)
} catch (error) {
  const result = {
    schemaVersion: 1,
    artifactKind: 'hosted-storybook-proof-validation',
    generatedAt: new Date().toISOString(),
    status: 'fail',
    claimBoundary: CLAIM_BOUNDARY,
    checks: [fail('cli-or-json-parse', error.message)],
  }
  if (process.argv.includes('--json')) console.log(JSON.stringify(result, null, 2))
  else {
    console.error(error.message)
    console.error(usage())
  }
  process.exit(1)
}
