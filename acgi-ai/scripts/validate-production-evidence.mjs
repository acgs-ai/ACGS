#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'

const CLAIM_BOUNDARY =
  'Production evidence validation only checks operator-supplied artifacts; it is not legal signoff, not SOC2 proof, not WCAG conformance evidence, not pentest completion, and not regulatory compliance proof.'

function usage() {
  return `Usage: node scripts/validate-production-evidence.mjs --manifest <path> [options]

Validates a completed production evidence manifest and optional verify:production-live JSON output.
This command performs local file validation only; it does not deploy, fetch live origins, or create live production proof.

Options:
  --manifest <path>              Completed production evidence manifest JSON
  --live-output <path>           JSON output from pnpm -F acgi-ai run verify:production-live -- --json
  --out <path>                   Save machine-readable validation JSON to a file
  --require-pass                 Require manifest and live verifier statuses to be pass/live-verified
  --json                         Print machine-readable JSON only
  --help                         Show this help
`
}

function parseArgs(argv) {
  const options = {
    manifestPath: null,
    liveOutputPath: null,
    outPath: null,
    json: false,
    requirePass: false,
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
    else if (arg === '--manifest') options.manifestPath = next()
    else if (arg === '--live-output') options.liveOutputPath = next()
    else if (arg === '--out') options.outPath = next()
    else if (arg === '--json') options.json = true
    else if (arg === '--require-pass') options.requirePass = true
    else if (arg === '--help' || arg === '-h') options.help = true
    else if (!options.manifestPath) options.manifestPath = arg
    else throw new Error(`Unknown option: ${arg}`)
  }

  if (!options.help && !options.manifestPath) throw new Error('--manifest is required')
  return options
}

function writeJsonOutput(result, outPath) {
  if (!outPath) return
  const outputPath = resolve(outPath)
  mkdirSync(dirname(outputPath), { recursive: true })
  writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`)
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(resolve(path), 'utf8'))
  } catch (error) {
    throw new Error(`Could not read JSON ${path}: ${error.message}`)
  }
}

function pass(id, evidence = {}) {
  return { id, status: 'pass', evidence }
}

function fail(id, error, evidence = {}) {
  return { id, status: 'fail', error, evidence }
}

function hasReplacementPlaceholders(value, path = '$', matches = []) {
  if (typeof value === 'string') {
    if (value.includes('REPLACE_WITH_')) matches.push(path)
    return matches
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      hasReplacementPlaceholders(entry, `${path}[${index}]`, matches)
    })
    return matches
  }
  if (value && typeof value === 'object') {
    for (const [key, entry] of Object.entries(value)) {
      hasReplacementPlaceholders(entry, `${path}.${key}`, matches)
    }
  }
  return matches
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

function isBlockedPendingExternalRef(value, manifest) {
  return manifest.status === 'deployment-blocked' && String(value ?? '').startsWith('pending-external:')
}

function isPendingExternalRef(value) {
  return String(value ?? '').startsWith('pending-external:')
}

function isHttpsUrlOrBlockedPendingExternal(value, manifest, { allowPendingExternal = false } = {}) {
  return isHttpsUrl(value) || (allowPendingExternal && isBlockedPendingExternalRef(value, manifest))
}

function isCompletedOperatorRef(value) {
  const normalized = String(value ?? '').trim()
  return (
    normalized.length > 0 &&
    !normalized.includes('REPLACE_WITH_') &&
    !isPendingExternalRef(normalized)
  )
}

function isIsoTimestamp(value) {
  return isNonEmptyString(value) && !Number.isNaN(Date.parse(value))
}

function includesAll(source, fragments) {
  const normalized = String(source ?? '').toLowerCase()
  return fragments.filter((fragment) => !normalized.includes(fragment.toLowerCase()))
}

function pushCheck(checks, condition, id, failMessage, evidence = {}) {
  checks.push(condition ? pass(id, evidence) : fail(id, failMessage, evidence))
}

function findCheck(liveOutput, id) {
  return Array.isArray(liveOutput?.checks)
    ? liveOutput.checks.find((check) => check.id === id)
    : null
}

function validateManifest(manifest, options, liveOutput) {
  const checks = []
  const placeholders = hasReplacementPlaceholders(manifest)
  const deploy = manifest.deploy ?? {}
  const verification = manifest.verification ?? {}
  const artifacts = manifest.artifacts ?? {}
  const hostedStorybook = manifest.hostedStorybook ?? {}
  const assurance = manifest.assurance ?? {}
  const productionLiveBlockers = Array.isArray(verification.productionLiveBlockers)
    ? verification.productionLiveBlockers
    : []
  const remainingBlockers = Array.isArray(manifest.remainingBlockers)
    ? manifest.remainingBlockers
    : []
  const deploymentStatuses = new Set(['live-verified', 'deployment-blocked'])
  const productionLiveStatuses = new Set(['pass', 'fail'])

  pushCheck(checks, manifest.schemaVersion === 1, 'schema-version', 'schemaVersion must be 1')
  pushCheck(
    checks,
    manifest.artifactKind === 'production-evidence',
    'artifact-kind',
    'artifactKind must be production-evidence, not the template artifact kind',
    { actual: manifest.artifactKind },
  )
  pushCheck(
    checks,
    deploymentStatuses.has(manifest.status),
    'manifest-status',
    'status must be live-verified or deployment-blocked',
    { actual: manifest.status },
  )
  pushCheck(
    checks,
    placeholders.length === 0,
    'no-replace-placeholders',
    'completed production evidence must not contain REPLACE_WITH_ placeholders',
    { placeholderPaths: placeholders },
  )

  const missingClaimFragments = includesAll(manifest.claimBoundary, [
    'not legal',
    'SOC2',
    'WCAG',
    'pentest',
    'regulatory compliance',
  ])
  pushCheck(
    checks,
    missingClaimFragments.length === 0,
    'claim-boundary-conservative',
    'claimBoundary must preserve legal/SOC2/WCAG/pentest/regulatory limits',
    { missingClaimFragments },
  )

  for (const [key, label, allowPendingExternal] of [
    ['marketingUrl', 'marketing URL', false],
    ['consoleUrl', 'console URL', false],
    ['cloudRunRevisionUrl', 'Cloud Run revision URL', true],
    ['cloudflareUrl', 'Cloudflare deployment URL', true],
  ]) {
    pushCheck(
      checks,
      isHttpsUrlOrBlockedPendingExternal(deploy[key], manifest, { allowPendingExternal }),
      `deploy-${key}`,
      `${label} must be a non-placeholder https:// URL${
        allowPendingExternal ? ' or pending-external ref while deployment-blocked' : ''
      }`,
      {
        value: deploy[key] ?? null,
      },
    )
  }

  for (const key of ['marketing', 'console', 'storybook']) {
    pushCheck(
      checks,
      isHttpsUrlOrBlockedPendingExternal(deploy.githubActionsRunUrls?.[key], manifest, {
        allowPendingExternal: true,
      }),
      `github-actions-${key}`,
      `${key} GitHub Actions run URL must be a non-placeholder https:// URL or pending-external ref while deployment-blocked`,
      { value: deploy.githubActionsRunUrls?.[key] ?? null },
    )
  }

  pushCheck(
    checks,
    isNonEmptyString(verification.expectedBuildId),
    'expected-build-id',
    'verification.expectedBuildId must be present',
  )
  pushCheck(
    checks,
    isHttpsUrl(verification.healthz?.url),
    'healthz-url',
    'verification.healthz.url must be an https:// URL',
    { value: verification.healthz?.url ?? null },
  )
  for (const key of ['served_hash', 'build_id']) {
    pushCheck(
      checks,
      isNonEmptyString(verification.healthz?.[key]),
      `healthz-${key}`,
      `verification.healthz.${key} must be present`,
    )
  }
  pushCheck(
    checks,
    verification.postdeployCommand ===
      'pnpm -F acgi-ai run verify:postdeploy -- https://console.acgs.ai',
    'postdeploy-command',
    'verification.postdeployCommand must capture the console postdeploy verifier command',
    { actual: verification.postdeployCommand ?? null },
  )
  pushCheck(
    checks,
    isNonEmptyString(verification.postdeployOutputRef),
    'postdeploy-output-ref',
    'verification.postdeployOutputRef must reference the postdeploy artifact or hash',
  )
  pushCheck(
    checks,
    verification.productionLiveCommand === 'pnpm -F acgi-ai run verify:production-live -- --json',
    'production-live-command',
    'verification.productionLiveCommand must capture the live verifier command',
    { actual: verification.productionLiveCommand ?? null },
  )
  pushCheck(
    checks,
    isNonEmptyString(verification.productionLiveOutputRef),
    'production-live-output-ref',
    'verification.productionLiveOutputRef must reference the live verifier JSON artifact or hash',
  )
  pushCheck(
    checks,
    productionLiveStatuses.has(verification.productionLiveStatus),
    'production-live-status-field',
    'verification.productionLiveStatus must be pass or fail',
    { actual: verification.productionLiveStatus ?? null },
  )
  pushCheck(
    checks,
    Array.isArray(verification.productionLiveBlockers) &&
      verification.productionLiveBlockers.every(isNonEmptyString),
    'production-live-blockers-field',
    'verification.productionLiveBlockers must be an array of blocker ids from verify:production-live',
    { actual: verification.productionLiveBlockers ?? null },
  )
  pushCheck(
    checks,
    isNonEmptyString(verification.productionEvidenceValidationCommand) &&
      verification.productionEvidenceValidationCommand.includes('validate:production-evidence') &&
      verification.productionEvidenceValidationCommand.includes('--manifest') &&
      verification.productionEvidenceValidationCommand.includes('--live-output'),
    'production-evidence-validation-command',
    'verification.productionEvidenceValidationCommand must run validate:production-evidence with --manifest and --live-output',
    { actual: verification.productionEvidenceValidationCommand ?? null },
  )
  pushCheck(
    checks,
    isNonEmptyString(verification.productionEvidenceValidationOutputRef),
    'production-evidence-validation-output-ref',
    'verification.productionEvidenceValidationOutputRef must reference the validator JSON artifact or hash',
  )
  pushCheck(
    checks,
    !Number.isNaN(Date.parse(verification.liveCheckedAt ?? '')),
    'live-checked-at',
    'verification.liveCheckedAt must be an ISO-8601 timestamp',
    { actual: verification.liveCheckedAt ?? null },
  )
  pushCheck(
    checks,
    isNonEmptyString(artifacts.validatedProductionEvidence),
    'validated-production-evidence-artifact',
    'artifacts.validatedProductionEvidence must reference the validator JSON artifact or hash',
  )

  pushCheck(
    checks,
    hostedStorybook.url === 'https://storybook.acgs.ai',
    'hosted-storybook-url',
    'hostedStorybook.url must remain https://storybook.acgs.ai',
    { actual: hostedStorybook.url ?? null },
  )
  pushCheck(
    checks,
    hostedStorybook.manifestUrl === 'https://storybook.acgs.ai/manifest.json',
    'hosted-storybook-manifest-url',
    'hostedStorybook.manifestUrl must remain https://storybook.acgs.ai/manifest.json',
    { actual: hostedStorybook.manifestUrl ?? null },
  )
  if (hostedStorybook.status === 'pending') {
    pushCheck(
      checks,
      remainingBlockers.includes('hosted-storybook-buyer-evidence'),
      'hosted-storybook-pending-blocker',
      'pending hosted Storybook proof must keep hosted-storybook-buyer-evidence in remainingBlockers',
    )
  }

  const pendingAssuranceBlockers = {
    legalClaimMatrix: 'legal-review-of-claim-matrix',
    pentest: 'third-party-penetration-test',
    wcagManual: 'full-wcag-manual-screen-reader-evidence',
    browserScreenshots: 'hosted-storybook-buyer-evidence',
  }
  for (const [key, blocker] of Object.entries(pendingAssuranceBlockers)) {
    if (assurance[key]?.status !== 'pending-external') continue
    pushCheck(
      checks,
      isNonEmptyString(assurance[key]?.proofRef) && remainingBlockers.includes(blocker),
      `assurance-${key}-pending-blocker`,
      `assurance.${key} pending-external must keep ${blocker} in remainingBlockers and name a proofRef`,
      { proofRef: assurance[key]?.proofRef ?? null, remainingBlockers },
    )
  }
  if (manifest.status === 'live-verified' || options.requirePass) {
    const assuranceStatusCheckIds = {
      legalClaimMatrix: 'require-pass-assurance-legalClaimMatrix-verified',
      pentest: 'require-pass-assurance-pentest-verified',
      wcagManual: 'require-pass-assurance-wcagManual-verified',
      browserScreenshots: 'require-pass-assurance-browserScreenshots-verified',
    }
    const assuranceRequirements = {
      legalClaimMatrix: {
        requiredFields: {
          reviewer: (entry) => isNonEmptyString(entry?.reviewer),
          reviewedAt: (entry) => isIsoTimestamp(entry?.reviewedAt),
          claimMatrixRef: (entry) => isCompletedOperatorRef(entry?.claimMatrixRef),
        },
      },
      pentest: {
        requiredFields: {
          vendor: (entry) => isNonEmptyString(entry?.vendor),
          completedAt: (entry) => isIsoTimestamp(entry?.completedAt),
          reportRef: (entry) => isCompletedOperatorRef(entry?.reportRef),
          criticalFindingsOpen: (entry) => entry?.criticalFindingsOpen === 0,
        },
      },
      wcagManual: {
        requiredFields: {
          reviewer: (entry) => isNonEmptyString(entry?.reviewer),
          reviewedAt: (entry) => isIsoTimestamp(entry?.reviewedAt),
          reportRef: (entry) => isCompletedOperatorRef(entry?.reportRef),
          assistiveTech: (entry) =>
            Array.isArray(entry?.assistiveTech) &&
            ['NVDA', 'VoiceOver'].every((tool) => entry.assistiveTech.includes(tool)),
        },
      },
      browserScreenshots: {
        requiredFields: {
          capturedAt: (entry) => isIsoTimestamp(entry?.capturedAt),
          bundleRef: (entry) => isCompletedOperatorRef(entry?.bundleRef),
        },
      },
    }
    for (const [key, requirement] of Object.entries(assuranceRequirements)) {
      const entry = assurance[key] ?? {}
      pushCheck(
        checks,
        entry.status === 'verified',
        assuranceStatusCheckIds[key],
        `live-verified or --require-pass manifests require assurance.${key}.status=verified`,
        { status: entry.status ?? null },
      )
      pushCheck(
        checks,
        isCompletedOperatorRef(entry.proofRef),
        `require-pass-assurance-${key}-proof-ref`,
        `live-verified or --require-pass manifests require assurance.${key}.proofRef to reference attached external proof`,
        { proofRef: entry.proofRef ?? null },
      )
      for (const [field, predicate] of Object.entries(requirement.requiredFields)) {
        pushCheck(
          checks,
          predicate(entry),
          `require-pass-assurance-${key}-${field}`,
          `live-verified or --require-pass manifests require assurance.${key}.${field}`,
          { value: entry[field] ?? null },
        )
      }
    }
  }

  if (liveOutput) {
    pushCheck(
      checks,
      liveOutput.artifactKind === 'production-live-verification',
      'live-output-artifact-kind',
      'live output artifactKind must be production-live-verification',
      { actual: liveOutput.artifactKind ?? null },
    )
    pushCheck(
      checks,
      ['pass', 'fail'].includes(liveOutput.status),
      'live-output-status',
      'live output status must be pass or fail',
      { actual: liveOutput.status ?? null },
    )
    pushCheck(
      checks,
      liveOutput.targets?.marketingUrl === deploy.marketingUrl &&
        liveOutput.targets?.consoleUrl === deploy.consoleUrl &&
        liveOutput.targets?.storybookUrl === hostedStorybook.url,
      'live-output-targets-match-manifest',
      'live output targets must match manifest production origins',
      {
        liveTargets: liveOutput.targets ?? null,
        manifestTargets: {
          marketingUrl: deploy.marketingUrl ?? null,
          consoleUrl: deploy.consoleUrl ?? null,
          storybookUrl: hostedStorybook.url ?? null,
        },
      },
    )

    const liveOutputBlockers = Array.isArray(liveOutput.blockers) ? liveOutput.blockers : []
    const liveOutputBlockerIds = liveOutputBlockers
      .map((blocker) => blocker?.blockerId)
      .filter(isNonEmptyString)
    pushCheck(
      checks,
      Array.isArray(liveOutput.blockers) &&
        liveOutputBlockers.every(
          (blocker) =>
            isNonEmptyString(blocker?.blockerId) &&
            isNonEmptyString(blocker?.checkId) &&
            ['fail', 'pending'].includes(blocker?.status),
        ),
      'live-output-blockers-field',
      'live output must include blocker ids for failed or pending live checks',
      { blockers: liveOutput.blockers ?? null },
    )
    if (liveOutput.status === 'pass') {
      pushCheck(
        checks,
        liveOutputBlockerIds.length === 0,
        'pass-live-output-has-no-blockers',
        'passing live output must not contain production live blockers',
        { liveOutputBlockerIds },
      )
    }

    const healthzCheck = findCheck(liveOutput, 'console-healthz-live')
    const storybookManifestLiveCheck = findCheck(liveOutput, 'storybook-manifest-live')
    if (
      liveOutput.status === 'pass' ||
      manifest.status === 'live-verified' ||
      options.requirePass
    ) {
      pushCheck(
        checks,
        healthzCheck?.status === 'pass' &&
          healthzCheck.evidence?.served_hash === verification.healthz?.served_hash &&
          healthzCheck.evidence?.build_id === verification.healthz?.build_id,
        'live-output-healthz-matches-manifest',
        'console-healthz-live evidence must pass and match manifest served_hash/build_id',
        { healthzCheck: healthzCheck ?? null },
      )
    } else {
      checks.push(
        pass('live-output-healthz-matches-manifest', {
          skippedReason: 'deployment-blocked live output may fail before healthz proof exists',
          healthzCheck: healthzCheck ?? null,
        }),
      )
    }

    if (manifest.status === 'live-verified' || options.requirePass) {
      pushCheck(
        checks,
        liveOutput.status === 'pass' && verification.productionLiveStatus === 'pass',
        'live-verified-requires-pass-live-output',
        'live-verified or --require-pass manifests require pass live output and productionLiveStatus=pass',
        {
          manifestStatus: manifest.status,
          productionLiveStatus: verification.productionLiveStatus,
          liveStatus: liveOutput.status,
        },
      )
      pushCheck(
        checks,
        storybookManifestLiveCheck?.status === 'pass',
        'live-verified-requires-storybook-manifest',
        'live-verified or --require-pass manifests require the hosted Storybook manifest live check to pass',
        { storybookManifestLiveCheck: storybookManifestLiveCheck ?? null },
      )
    }
    if (manifest.status === 'deployment-blocked') {
      pushCheck(
        checks,
        verification.productionLiveStatus === 'fail' && remainingBlockers.length > 0,
        'deployment-blocked-requires-failed-live-output-ref',
        'deployment-blocked manifests must set productionLiveStatus=fail and keep remainingBlockers non-empty',
        { productionLiveStatus: verification.productionLiveStatus, remainingBlockers },
      )
      pushCheck(
        checks,
        liveOutputBlockerIds.length > 0 &&
          liveOutputBlockerIds.every((blockerId) =>
            productionLiveBlockers.includes(blockerId),
          ),
        'deployment-blocked-live-blockers-match',
        'deployment-blocked manifests must copy every live output blocker id into verification.productionLiveBlockers',
        { liveOutputBlockerIds, productionLiveBlockers },
      )
    }
  } else {
    pushCheck(
      checks,
      !options.requirePass,
      'live-output-required-for-require-pass',
      '--require-pass requires --live-output JSON evidence',
    )
  }

  const hasFailures = checks.some((check) => check.status === 'fail')
  return {
    schemaVersion: 1,
    artifactKind: 'production-evidence-validation',
    generatedAt: new Date().toISOString(),
    status: hasFailures ? 'fail' : 'pass',
    claimBoundary: CLAIM_BOUNDARY,
    manifestPath: options.manifestPath,
    liveOutputPath: options.liveOutputPath ?? null,
    checks,
  }
}

function renderHuman(result) {
  const lines = [
    `Production evidence validation: ${result.status}`,
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
  const manifest = readJson(options.manifestPath)
  const liveOutput = options.liveOutputPath ? readJson(options.liveOutputPath) : null
  const result = validateManifest(manifest, options, liveOutput)
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
    artifactKind: 'production-evidence-validation',
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
