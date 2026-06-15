import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

function headerValue(headers, key) {
  return headers.find((header) => header.key.toLowerCase() === key.toLowerCase())?.value
}

const vercelJson = JSON.parse(read('vercel.json'))
const packageJson = JSON.parse(read('package.json'))
const catchAllHeaderBlock = vercelJson.headers?.find((entry) => entry.source === '/(.*)')
const headers = catchAllHeaderBlock?.headers ?? []
const reportOnlyCsp = headerValue(headers, 'Content-Security-Policy-Report-Only') ?? ''
const enforcedCsp = headerValue(headers, 'Content-Security-Policy') ?? ''
const requiredDirectives = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  'report-uri https://csp-report.acgs.ai/marketing',
]

check(Boolean(catchAllHeaderBlock), 'vercel.json must define a catch-all marketing header block.')
check(
  reportOnlyCsp.length > 0,
  'vercel.json must set Content-Security-Policy-Report-Only for marketing.',
)
check(
  enforcedCsp.length === 0,
  'marketing vercel.json must not enforce Content-Security-Policy before the cutover plan lands.',
)
for (const directive of requiredDirectives) {
  check(
    reportOnlyCsp.includes(directive),
    `marketing report-only CSP must include: ${directive}`,
  )
}
check(
  !reportOnlyCsp.includes("'unsafe-inline'"),
  'marketing report-only CSP must not normalize unsafe-inline.',
)
check(
  !/googleapis|gstatic/.test(reportOnlyCsp),
  'marketing report-only CSP must preserve the same-origin font story, not Google font CDNs.',
)
check(
  packageJson.scripts?.['test:marketing-csp'] === 'node scripts/check-marketing-csp.mjs',
  'package.json must expose test:marketing-csp.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:marketing-csp'),
  'package.json test:all must include test:marketing-csp.',
)

// --- Cloudflare Pages header parity (DEPLOY.md §3/§5) ---
// The Cloudflare deploy (marketing-cloudflare.yml) ships headers from
// acgi-ai/infra/cloudflare/_headers instead of vercel.json. Assert it carries the
// IDENTICAL report-only CSP so the two provider configs cannot silently drift.
const cfHeaders = read('infra/cloudflare/_headers')
// HTTP header names are case-insensitive — match accordingly so a re-cased header
// can't slip past parity (and the enforced-CSP guard below).
const cfReportOnlyMatch = cfHeaders.match(/^[ \t]*Content-Security-Policy-Report-Only:[ \t]*(.+)$/im)
const cfReportOnlyLine = cfReportOnlyMatch ? cfReportOnlyMatch[0] : ''
const cfCspValue = cfReportOnlyMatch ? cfReportOnlyMatch[1].trim() : ''
check(
  cfReportOnlyLine.length > 0,
  'infra/cloudflare/_headers must set Content-Security-Policy-Report-Only for marketing.',
)
check(
  // `Policy\s*:` only matches an ENFORCED header; the report-only line has
  // `-Report-Only` between "Policy" and the colon, so it is not caught here.
  !/^[ \t]*Content-Security-Policy[ \t]*:/im.test(cfHeaders),
  'infra/cloudflare/_headers must not enforce Content-Security-Policy before the cutover plan lands.',
)
check(
  cfCspValue === reportOnlyCsp.trim(),
  'Cloudflare _headers report-only CSP must be byte-identical to vercel.json (no drift).',
)
check(
  !cfReportOnlyLine.includes("'unsafe-inline'"),
  'Cloudflare _headers report-only CSP must not normalize unsafe-inline.',
)
check(
  !/googleapis|gstatic/.test(cfReportOnlyLine),
  'Cloudflare _headers report-only CSP must preserve the same-origin font story.',
)
for (const securityHeader of [
  'Strict-Transport-Security:',
  'X-Content-Type-Options: nosniff',
  'X-Frame-Options: SAMEORIGIN',
  'Referrer-Policy: strict-origin-when-cross-origin',
  'Permissions-Policy:',
]) {
  check(
    cfHeaders.includes(securityHeader),
    `Cloudflare _headers must include security header: ${securityHeader}`,
  )
}

if (failures.length > 0) {
  console.error('Marketing CSP check failed:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log('Marketing CSP report-only check passed.')
