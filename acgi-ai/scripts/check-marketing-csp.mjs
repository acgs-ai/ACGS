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

if (failures.length > 0) {
  console.error('Marketing CSP check failed:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log('Marketing CSP report-only check passed.')
