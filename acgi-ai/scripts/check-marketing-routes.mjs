import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// Marketing edge-route contract. Cloudflare Pages is the marketing deploy
// provider and acgi-ai/infra/cloudflare/_redirects is the single source of truth
// for marketing edge routing (DEPLOY.md §3). Vercel has been removed. This gate
// pins the privilege boundary: internal docs 404, /console crosses to the
// separate privileged console origin, and marketing SPA paths fall back to the
// shell — with the catch-all fallback LAST so it never shadows the boundary.

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function readIfExists(relativePath) {
  const path = resolve(root, relativePath)
  return existsSync(path) ? readFileSync(path, 'utf8') : ''
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

// Parse Cloudflare _redirects: each non-comment, non-blank line is
// `<from> <to> <status>` separated by whitespace. Order is significant
// (first match wins), so we keep the parsed rules in file order.
const redirectsText = read('infra/cloudflare/_redirects')
const rules = redirectsText
  .split('\n')
  .map((line) => line.trim())
  .filter((line) => line.length > 0 && !line.startsWith('#'))
  .map((line) => {
    const [from, to, status] = line.split(/\s+/)
    return { from, to, status: Number(status) }
  })

const packageJson = JSON.parse(read('package.json'))
const securityInvariants = read('scripts/check-security-invariants.mjs')
const deployDocs = read('DEPLOY.md')
const architecture = readIfExists('ARCHITECTURE.md')
const readinessMap = readIfExists('../docs/integration-readiness-task-map.md')

const ruleIndex = (predicate) => rules.findIndex(predicate)

const consoleExactIndex = ruleIndex(
  (r) => r.from === '/console' && r.status === 308,
)
const consoleWildcardIndex = ruleIndex(
  (r) => r.from === '/console/*' && r.status === 308,
)
const internalDocPaths = ['/AGENTS.md', '/CLAUDE.md', '/DESIGN.md', '/DEPLOY.md']
const denyIndices = internalDocPaths.map((p) =>
  ruleIndex((r) => r.from === p && r.status === 404),
)
const fallbackIndex = ruleIndex((r) => r.from === '/*' && r.status === 200)

check(rules.length > 0, '_redirects must define an ordered marketing edge route table.')
check(consoleExactIndex >= 0, '_redirects must include an exact /console 308 redirect.')
check(consoleWildcardIndex >= 0, '_redirects must include a /console/* 308 redirect.')
check(
  denyIndices.every((i) => i >= 0),
  '_redirects must 404 the internal docs (AGENTS/CLAUDE/DESIGN/DEPLOY), not fall through to the SPA shell.',
)
check(fallbackIndex >= 0, '_redirects must include the SPA fallback /* -> /index.html 200.')

// Privilege-boundary ordering: the /console crossings and internal-doc 404s must
// precede the catch-all SPA fallback, and the SPA fallback must be the LAST rule
// so it never shadows a more specific boundary route.
check(
  fallbackIndex === rules.length - 1,
  'SPA fallback (/* -> /index.html) must be the final _redirects rule.',
)
check(
  consoleExactIndex >= 0 && consoleExactIndex < fallbackIndex,
  'exact /console redirect must precede the SPA fallback.',
)
check(
  consoleWildcardIndex >= 0 && consoleWildcardIndex < fallbackIndex,
  '/console/* redirect must precede the SPA fallback.',
)
check(
  denyIndices.every((i) => i >= 0 && i < fallbackIndex),
  'internal-doc 404 rules must precede the SPA fallback.',
)

// Console-origin redirect targets (the privileged boundary). Cloudflare uses
// :splat for the wildcard tail.
check(
  rules[consoleExactIndex]?.to === 'https://console.acgs.ai/console',
  '/console must 308 redirect to https://console.acgs.ai/console.',
)
check(
  rules[consoleWildcardIndex]?.to === 'https://console.acgs.ai/console/:splat',
  '/console/* must 308 redirect to https://console.acgs.ai/console/:splat.',
)
// /consolefoo must NOT match the /console redirect — Cloudflare matches the
// literal /console and the /console/* prefix, so a bare /consolefoo stays a
// marketing SPA path handled by the fallback. Assert there is no rule that would
// capture it as a console crossing.
check(
  !rules.some((r) => r.from === '/console*' || r.from === '/consolefoo'),
  '_redirects must not over-capture /consolefoo as a console crossing; only /console and /console/* cross.',
)

// --- package.json wiring ---
check(
  packageJson.scripts?.['test:marketing-routes'] === 'node scripts/check-marketing-routes.mjs',
  'package.json must expose test:marketing-routes for marketing edge route verification.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:marketing-routes'),
  'package.json test:all must include test:marketing-routes.',
)

// --- guarded by the security-invariant check ---
check(
  securityInvariants.includes('check-marketing-routes.mjs') &&
    securityInvariants.includes('test:marketing-routes') &&
    securityInvariants.includes('https://console.acgs.ai/console'),
  'security invariant check must guard the marketing route verifier and console-origin redirect contract.',
)

// --- docs must document the live (Cloudflare _redirects) contract ---
check(
  /_redirects/.test(deployDocs) &&
    /\/console\b/.test(deployDocs) &&
    /308/.test(deployDocs) &&
    /https:\/\/console\.acgs\.ai\/console/.test(deployDocs),
  'DEPLOY.md must document the current Cloudflare _redirects console-redirect/deny contract.',
)
check(
  /marketing privileged redirect/.test(architecture) && /console\.acgs\.ai/.test(architecture),
  'ARCHITECTURE.md must document the marketing-to-console origin boundary.',
)
check(
  /Cloudflare marketing edge routing/.test(readinessMap) && /test:marketing-routes/.test(readinessMap),
  'docs/integration-readiness-task-map.md must map Cloudflare marketing route readiness to its gate.',
)

if (failures.length > 0) {
  console.error('Marketing route contract check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Marketing route contract check passed.')
