#!/usr/bin/env node
import { lookup } from 'node:dns/promises'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const DEFAULTS = {
  marketingUrl: 'https://acgs.ai',
  consoleUrl: 'https://console.acgs.ai',
  storybookUrl: 'https://storybook.acgs.ai',
  timeoutMs: 10_000,
}
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')

const EXPECTED_SERVED_HASH = process.env.EXPECTED_SERVED_HASH ?? '608508a9bd224290'
const EXPECTED_BUILD_ID = process.env.EXPECTED_BUILD_ID ?? ''
const CLAIM_BOUNDARY =
  'Live verifier output is production evidence only when every required live check passes against the deployed origins; failures or pending Storybook checks remain deployment blockers and are not live production proof.'
const BLOCKER_CATALOG = {
  'marketing-dns-live': {
    blockerId: 'live-marketing-dns',
    area: 'Marketing DNS',
    requiredAction: 'Confirm acgs.ai DNS resolves before claiming the marketing origin is live.',
  },
  'console-dns-live': {
    blockerId: 'live-console-dns',
    area: 'Console DNS',
    requiredAction:
      'Create or repair the console.acgs.ai DNS record for the deployed console service.',
  },
  'storybook-dns-live': {
    blockerId: 'live-storybook-dns',
    area: 'Hosted Storybook DNS',
    requiredAction:
      'Create or repair the storybook.acgs.ai DNS record for the hosted buyer-evidence origin.',
  },
  'marketing-https-live': {
    blockerId: 'live-marketing-https',
    area: 'Marketing HTTPS',
    requiredAction: 'Verify the acgs.ai HTTPS endpoint returns a 2xx/3xx response.',
  },
  'console-healthz-live': {
    blockerId: 'live-console-healthz',
    area: 'Console /healthz',
    requiredAction:
      'Deploy the console service and verify /healthz exposes ok=true plus the expected served_hash and build_id.',
  },
  'console-security-headers-live': {
    blockerId: 'live-console-security-headers',
    area: 'Console security headers',
    requiredAction:
      'Serve the console origin with HSTS, CSP, X-Frame-Options, and Referrer-Policy headers.',
  },
  'storybook-https-live': {
    blockerId: 'live-storybook-https',
    area: 'Hosted Storybook HTTPS',
    requiredAction:
      'Publish the buyer-evidence artifact and verify storybook.acgs.ai returns a 2xx/3xx HTTPS response.',
  },
  'storybook-manifest-live': {
    blockerId: 'live-storybook-manifest',
    area: 'Hosted Storybook buyer-evidence manifest',
    requiredAction:
      'Publish the claim-safe buyer-evidence manifest to storybook.acgs.ai and verify the expected story ids, publish target, and claim boundary.',
  },
}

function usage() {
  return `Usage: node scripts/verify-production-live.mjs [options]

Runs live DNS, HTTPS, /healthz, security-header, and hosted Storybook manifest checks for the production origins.
This command performs network I/O and is intentionally not part of pnpm test:all.

Options:
  --json                         Print machine-readable JSON only
  --out <path>                   Save machine-readable JSON to a file, even when live checks fail
  --timeout-ms <ms>              Per-request timeout (default: ${DEFAULTS.timeoutMs})
  --marketing-url <url>          Marketing origin (default: ${DEFAULTS.marketingUrl})
  --console-url <url>            Console origin (default: ${DEFAULTS.consoleUrl})
  --storybook-url <url>          Hosted buyer-evidence origin (default: ${DEFAULTS.storybookUrl})
  --expected-build-id <id>       Expected /healthz build_id (or EXPECTED_BUILD_ID env)
  --allow-storybook-pending      Mark Storybook DNS/HTTP failures pending instead of failed
  --help                         Show this help

Environment:
  EXPECTED_SERVED_HASH           Expected /healthz served_hash (default: ${EXPECTED_SERVED_HASH})
  EXPECTED_BUILD_ID              Expected /healthz build_id when --expected-build-id is omitted
`
}

function parseArgs(argv) {
  const options = {
    ...DEFAULTS,
    json: false,
    expectedBuildId: EXPECTED_BUILD_ID,
    allowStorybookPending: false,
    outPath: null,
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
    else if (arg === '--json') options.json = true
    else if (arg === '--out') options.outPath = next()
    else if (arg === '--help' || arg === '-h') options.help = true
    else if (arg === '--timeout-ms') options.timeoutMs = Number.parseInt(next(), 10)
    else if (arg === '--marketing-url') options.marketingUrl = next()
    else if (arg === '--console-url') options.consoleUrl = next()
    else if (arg === '--storybook-url') options.storybookUrl = next()
    else if (arg === '--expected-build-id') options.expectedBuildId = next()
    else if (arg === '--allow-storybook-pending') options.allowStorybookPending = true
    else throw new Error(`Unknown option: ${arg}`)
  }

  if (!Number.isFinite(options.timeoutMs) || options.timeoutMs < 1) {
    throw new Error('--timeout-ms must be a positive integer')
  }

  for (const key of ['marketingUrl', 'consoleUrl', 'storybookUrl']) {
    const url = new URL(options[key])
    if (url.protocol !== 'https:') throw new Error(`${key} must use https://`)
  }

  return options
}

function writeJsonOutput(result, outPath) {
  if (!outPath) return
  const outputPath = resolve(root, outPath)
  mkdirSync(dirname(outputPath), { recursive: true })
  writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`)
}

function pass(id, evidence = {}) {
  return { id, status: 'pass', evidence }
}

function fail(id, error, evidence = {}) {
  return {
    id,
    status: 'fail',
    error: error instanceof Error ? error.message : String(error),
    evidence,
  }
}

function pending(id, error, evidence = {}) {
  return {
    id,
    status: 'pending',
    error: error instanceof Error ? error.message : String(error),
    evidence,
  }
}

async function dnsCheck(id, targetUrl) {
  const url = new URL(targetUrl)
  try {
    const result = await lookup(url.hostname)
    return pass(id, { hostname: url.hostname, address: result.address, family: result.family })
  } catch (error) {
    return fail(id, error, { hostname: url.hostname })
  }
}

async function fetchWithTimeout(url, options) {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs)
  try {
    return await fetch(url, {
      method: options.method ?? 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': 'acgi-ai-production-live-verifier/1.0',
      },
    })
  } finally {
    clearTimeout(timeout)
  }
}

async function fetchReachabilityCheck(id, targetUrl, options) {
  try {
    let response = await fetchWithTimeout(targetUrl, { ...options, method: 'HEAD' })
    let method = 'HEAD'
    if (response.status === 405) {
      response = await fetchWithTimeout(targetUrl, { ...options, method: 'GET' })
      method = 'GET'
    }
    const ok = response.status >= 200 && response.status < 400
    if (!ok) {
      return fail(id, `HTTP ${response.status}`, {
        url: response.url,
        method,
        status: response.status,
      })
    }
    return pass(id, {
      url: response.url,
      method,
      status: response.status,
    })
  } catch (error) {
    return fail(id, error, { url: targetUrl })
  }
}

async function fetchJson(url, options) {
  const response = await fetchWithTimeout(url, { ...options, method: 'GET' })
  const text = await response.text()
  let json = null
  try {
    json = JSON.parse(text)
  } catch (error) {
    throw new Error(`Invalid JSON from ${url}: ${error.message}`)
  }
  return { response, json }
}

async function consoleHealthzCheck(targetUrl, options) {
  const healthzUrl = new URL('/healthz', targetUrl).toString()
  try {
    const { response, json } = await fetchJson(healthzUrl, options)
    const failures = []
    if (response.status < 200 || response.status >= 400) failures.push(`HTTP ${response.status}`)
    if (json.ok !== true) failures.push('ok must be true')
    if (typeof json.build_id !== 'string' || json.build_id.length === 0) {
      failures.push('build_id must be non-empty')
    }
    if (json.build_id === 'local') failures.push('build_id must not be local')
    if (options.expectedBuildId && json.build_id !== options.expectedBuildId) {
      failures.push(`build_id must equal EXPECTED_BUILD_ID ${options.expectedBuildId}`)
    }
    if (json.served_hash !== EXPECTED_SERVED_HASH) {
      failures.push(`served_hash must equal EXPECTED_SERVED_HASH ${EXPECTED_SERVED_HASH}`)
    }

    const evidence = {
      url: healthzUrl,
      status: response.status,
      ok: json.ok,
      served_hash: json.served_hash,
      build_id: json.build_id,
      expectedServedHash: EXPECTED_SERVED_HASH,
      expectedBuildId: options.expectedBuildId || null,
    }

    return failures.length > 0
      ? fail('console-healthz-live', failures.join('; '), evidence)
      : pass('console-healthz-live', evidence)
  } catch (error) {
    return fail('console-healthz-live', error, { url: healthzUrl })
  }
}

async function consoleSecurityHeaderCheck(targetUrl, options) {
  try {
    let response = await fetchWithTimeout(targetUrl, { ...options, method: 'HEAD' })
    let method = 'HEAD'
    if (response.status === 405) {
      response = await fetchWithTimeout(targetUrl, { ...options, method: 'GET' })
      method = 'GET'
    }
    const requiredHeaders = [
      'Strict-Transport-Security',
      'Content-Security-Policy',
      'X-Frame-Options',
      'Referrer-Policy',
    ]
    const missingHeaders = requiredHeaders.filter((header) => !response.headers.get(header))
    const evidence = {
      url: response.url,
      method,
      status: response.status,
      requiredHeaders,
      presentHeaders: requiredHeaders.filter((header) => Boolean(response.headers.get(header))),
    }
    if (response.status < 200 || response.status >= 400 || missingHeaders.length > 0) {
      return fail(
        'console-security-headers-live',
        `HTTP ${response.status}; missing_headers=${missingHeaders.join(',') || 'none'}`,
        evidence,
      )
    }
    return pass('console-security-headers-live', evidence)
  } catch (error) {
    return fail('console-security-headers-live', error, { url: targetUrl })
  }
}

async function storybookManifestCheck(targetUrl, options) {
  const manifestUrl = new URL('/manifest.json', targetUrl).toString()
  try {
    const { response, json } = await fetchJson(manifestUrl, options)
    const expectedStoryIds = [
      'receipt-proof-journey',
      'bus-owned-proof-source',
      'claim-safe-trust-surface',
      'visual-governance-workbench',
      'operator-decision-rail',
      'launch-proof-ladder',
      'deploy-readiness-boundary',
    ]
    const storyIds = Array.isArray(json.stories)
      ? json.stories.map((story) => story?.id).filter(Boolean)
      : []
    const missingStoryIds = expectedStoryIds.filter((id) => !storyIds.includes(id))
    const expectedPublishTarget = new URL(targetUrl).toString().replace(/\/$/, '')
    const publishTarget = typeof json.publishTarget === 'string' ? json.publishTarget : ''
    const claimBoundary = typeof json.claimBoundary === 'string' ? json.claimBoundary : ''
    const failures = []

    if (response.status < 200 || response.status >= 400) failures.push(`HTTP ${response.status}`)
    if (json.artifactKind !== 'local-buyer-evidence-gallery') {
      failures.push('artifactKind must be local-buyer-evidence-gallery')
    }
    if (publishTarget.replace(/\/$/, '') !== expectedPublishTarget) {
      failures.push(`publishTarget must equal ${expectedPublishTarget}`)
    }
    if (!claimBoundary.includes('not production deployment proof')) {
      failures.push('claimBoundary must preserve the not production deployment proof boundary')
    }
    if (missingStoryIds.length > 0) {
      failures.push(`missing story ids: ${missingStoryIds.join(',')}`)
    }

    const evidence = {
      url: manifestUrl,
      status: response.status,
      artifactKind: json.artifactKind ?? null,
      publishTarget: publishTarget || null,
      expectedPublishTarget,
      storyIds,
      missingStoryIds,
      claimBoundaryPreserved: claimBoundary.includes('not production deployment proof'),
    }

    return failures.length > 0
      ? fail('storybook-manifest-live', failures.join('; '), evidence)
      : pass('storybook-manifest-live', evidence)
  } catch (error) {
    return fail('storybook-manifest-live', error, { url: manifestUrl })
  }
}

function applyStorybookPending(checks, allowStorybookPending) {
  if (!allowStorybookPending) return checks
  return checks.map((check) => {
    if (!check.id.startsWith('storybook-') || check.status !== 'fail') return check
    return pending(check.id, check.error, {
      ...check.evidence,
      claimBoundary: 'pending Storybook is not hosted Storybook proof',
    })
  })
}

function buildBlockers(checks) {
  return checks
    .filter((check) => check.status !== 'pass')
    .map((check) => {
      const catalog = BLOCKER_CATALOG[check.id] ?? {
        blockerId: `live-${check.id}`,
        area: check.id,
        requiredAction: 'Resolve the failed live verification check and rerun verify:production-live.',
      }
      return {
        blockerId: catalog.blockerId,
        checkId: check.id,
        status: check.status,
        area: catalog.area,
        requiredAction: catalog.requiredAction,
        error: check.error ?? null,
        evidence: check.evidence ?? {},
        claimBoundary:
          'This blocker must be resolved and reverified before it can support live production proof.',
      }
    })
}

async function run(options) {
  const checks = [
    await dnsCheck('marketing-dns-live', options.marketingUrl),
    await dnsCheck('console-dns-live', options.consoleUrl),
    await dnsCheck('storybook-dns-live', options.storybookUrl),
    await fetchReachabilityCheck('marketing-https-live', options.marketingUrl, options),
    await consoleHealthzCheck(options.consoleUrl, options),
    await consoleSecurityHeaderCheck(options.consoleUrl, options),
    await fetchReachabilityCheck('storybook-https-live', options.storybookUrl, options),
    await storybookManifestCheck(options.storybookUrl, options),
  ]
  const normalizedChecks = applyStorybookPending(checks, options.allowStorybookPending)
  const hasFailures = normalizedChecks.some((check) => check.status === 'fail')
  const blockers = buildBlockers(normalizedChecks)

  return {
    schemaVersion: 1,
    artifactKind: 'production-live-verification',
    generatedAt: new Date().toISOString(),
    status: hasFailures ? 'fail' : 'pass',
    claimBoundary: CLAIM_BOUNDARY,
    targets: {
      marketingUrl: options.marketingUrl,
      consoleUrl: options.consoleUrl,
      storybookUrl: options.storybookUrl,
      expectedServedHash: EXPECTED_SERVED_HASH,
      expectedBuildId: options.expectedBuildId || null,
      allowStorybookPending: options.allowStorybookPending,
    },
    blockedUntil:
      blockers.length > 0
        ? 'Resolve every listed blocker and rerun verify:production-live until all checks pass.'
        : null,
    blockers,
    checks: normalizedChecks,
  }
}

function renderHuman(result) {
  const lines = [
    `Production live verification: ${result.status}`,
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
  const result = await run(options)
  writeJsonOutput(result, options.outPath)
  if (options.json) console.log(JSON.stringify(result, null, 2))
  else {
    console.log(renderHuman(result))
    if (options.outPath) console.log(`Wrote ${options.outPath}`)
  }
  process.exit(result.status === 'pass' ? 0 : 1)
} catch (error) {
  if (process.argv.includes('--json')) {
    console.log(
      JSON.stringify(
        {
          schemaVersion: 1,
          artifactKind: 'production-live-verification',
          generatedAt: new Date().toISOString(),
          status: 'fail',
          claimBoundary: CLAIM_BOUNDARY,
          blockedUntil: 'Fix the CLI arguments and rerun verify:production-live.',
          blockers: [
            {
              blockerId: 'live-verifier-cli-arguments',
              checkId: 'cli-arguments',
              status: 'fail',
              area: 'Live verifier invocation',
              requiredAction: 'Fix the CLI arguments and rerun verify:production-live.',
              error: error.message,
              evidence: {},
              claimBoundary:
                'A malformed verifier invocation is not live production proof or deployment-blocker proof.',
            },
          ],
          checks: [fail('cli-arguments', error)],
        },
        null,
        2,
      ),
    )
  } else {
    console.error(error.message)
    console.error(usage())
  }
  process.exit(1)
}
