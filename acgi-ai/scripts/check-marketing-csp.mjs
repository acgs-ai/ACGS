import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// Marketing CSP contract. Cloudflare Pages is the marketing deploy provider and
// acgi-ai/infra/cloudflare/_headers is the SINGLE SOURCE OF TRUTH for the
// marketing surface's security headers (DEPLOY.md §3/§5). Vercel has been
// removed; there is no longer a second provider config to keep in parity with.
// The CSP is REPORT-ONLY for marketing; the console CSP is ENFORCED and served
// by Caddy on the Cloud Run origin (§4) — it is NOT configured here.

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

const packageJson = JSON.parse(read('package.json'))

// --- Cloudflare Pages marketing headers (canonical source) ---
const cfHeaders = read('infra/cloudflare/_headers')
// HTTP header names are case-insensitive — match accordingly so a re-cased header
// can't slip past the directive/enforced-CSP guards below.
const cfReportOnlyMatch = cfHeaders.match(/^[ \t]*Content-Security-Policy-Report-Only:[ \t]*(.+)$/im)
const cfReportOnlyLine = cfReportOnlyMatch ? cfReportOnlyMatch[0] : ''
const reportOnlyCsp = cfReportOnlyMatch ? cfReportOnlyMatch[1].trim() : ''

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
for (const directive of requiredDirectives) {
  check(
    reportOnlyCsp.includes(directive),
    `marketing report-only CSP must include: ${directive}`,
  )
}
check(
  !cfReportOnlyLine.includes("'unsafe-inline'"),
  'marketing report-only CSP must not normalize unsafe-inline.',
)
check(
  !/googleapis|gstatic/.test(cfReportOnlyLine),
  'marketing report-only CSP must preserve the same-origin font story, not Google font CDNs.',
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
    `infra/cloudflare/_headers must include security header: ${securityHeader}`,
  )
}

// --- package.json wiring ---
check(
  packageJson.scripts?.['test:marketing-csp'] === 'node scripts/check-marketing-csp.mjs',
  'package.json must expose test:marketing-csp.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:marketing-csp'),
  'package.json test:all must include test:marketing-csp.',
)

if (failures.length > 0) {
  console.error('Marketing CSP check failed:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log('Marketing CSP report-only check passed.')
