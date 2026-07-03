import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function maybeRead(relativePath) {
  const absolute = resolve(root, relativePath)
  return existsSync(absolute) ? readFileSync(absolute, 'utf8') : ''
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

function mustContain(source, needle, label) {
  check(source.includes(needle), `${label} must include ${JSON.stringify(needle)}.`)
}

// Footer links to privileged routes must wire same-surface SPA navigation on the
// SAME anchor as the href — not merely have the href and a navigate() call loose
// somewhere in the file. Accepts the internalNav('/x') factory (current form,
// optional after-hook arg) or an inline (param)=>{...navigate('/x')} handler
// (any arrow-parameter name, e.g. (e) or (event)).
// Anchor-scoped so a stray/commented handler can no longer satisfy a broken link
// (closes the MEDIUM finding from the 2026-06-13 dedup review).
function mustWireFooterRoute(source, path, label) {
  const p = path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const anchor = new RegExp(
    `<a\\s+href="${p}"\\s+onClick=\\{(?:internalNav\\('${p}'(?:,[^)]*)?\\)|\\(\\w+\\)\\s*=>\\s*\\{[^}]*navigate\\('${p}'\\)[^}]*\\})`,
  )
  check(
    anchor.test(source),
    `${label} <a href="${path}"> must wire SPA navigation on the same anchor via internalNav('${path}') or inline navigate('${path}').`,
  )
}

const packageJson = JSON.parse(read('package.json'))
const marketingApp = read('src/surfaces/marketing/App.tsx')
const marketing = read('src/routes/Marketing.tsx')
const privacy = read('src/routes/Privacy.tsx')
const claimMatrix = JSON.parse(read('claim-matrix.json'))
const deploy = read('DEPLOY.md')
const readiness = read('../docs/integration-readiness-task-map.md')
const trust = maybeRead('src/routes/Trust.tsx')
const security = maybeRead('src/routes/Security.tsx')
const securityTxt = maybeRead('public/.well-known/security.txt')
const subprocessorRss = maybeRead('public/subprocessors.xml')

check(existsSync(resolve(root, 'src/routes/Trust.tsx')), 'src/routes/Trust.tsx must exist.')
check(existsSync(resolve(root, 'src/routes/Security.tsx')), 'src/routes/Security.tsx must exist.')
check(
  existsSync(resolve(root, 'public/.well-known/security.txt')),
  'public/.well-known/security.txt must exist.',
)
check(existsSync(resolve(root, 'public/subprocessors.xml')), 'public/subprocessors.xml must exist.')

mustContain(marketingApp, "from '../../routes/Trust'", 'marketing App route table')
mustContain(marketingApp, "from '../../routes/Security'", 'marketing App route table')
mustContain(marketingApp, "path: '/trust'", 'marketing App route tree')
mustContain(marketingApp, 'component: Trust', 'marketing App route tree')
mustContain(marketingApp, "path: '/security'", 'marketing App route tree')
mustContain(marketingApp, 'component: Security', 'marketing App route tree')

mustContain(marketing, 'href="/trust"', 'marketing footer')
mustContain(marketing, 'href="/security"', 'marketing footer')
mustWireFooterRoute(marketing, '/trust', 'marketing footer')
mustWireFooterRoute(marketing, '/security', 'marketing footer')
mustContain(privacy, 'href="/subprocessors.xml"', 'privacy subprocessor disclosure')

mustContain(trust, 'Engineering draft pending legal review', 'Trust page')
mustContain(trust, 'DPA draft', 'Trust page')
mustContain(trust, 'SOC 2 roadmap', 'Trust page')
mustContain(trust, 'Subprocessor change feed', 'Trust page')
mustContain(trust, '/.well-known/security.txt', 'Trust page')
mustContain(trust, '/subprocessors.xml', 'Trust page')
check(
  !/SOC 2 (certified|compliant|attested)/i.test(trust),
  'Trust page must not imply SOC 2 certification/compliance/attestation.',
)
check(
  !/production[- ]validated/i.test(trust),
  'Trust page must not use production-validated language.',
)

mustContain(security, 'Engineering draft pending live deploy evidence', 'Security page')
mustContain(security, 'Security contact', 'Security page')
mustContain(security, 'Console CSP', 'Security page')
mustContain(security, 'OIDC or server-cookie auth remains a production gate', 'Security page')
mustContain(security, '/.well-known/security.txt', 'Security page')
check(
  !/penetration test complete/i.test(security),
  'Security page must not claim pentest completion.',
)
check(
  !/WCAG 2\.2 AA conformant/i.test(security),
  'Security page must not claim WCAG conformance without manual evidence.',
)

mustContain(securityTxt, 'Contact: mailto:security@acgs.ai', 'security.txt')
mustContain(securityTxt, 'Expires: 2027-06-30T23:59:59Z', 'security.txt')
mustContain(securityTxt, 'Policy: https://acgs.ai/security', 'security.txt')
mustContain(securityTxt, 'Preferred-Languages: en', 'security.txt')
check(
  !/TODO|TBD|example\.com/i.test(securityTxt),
  'security.txt must not contain placeholder TODO/TBD/example values.',
)

mustContain(subprocessorRss, '<rss version="2.0"', 'subprocessor RSS')
mustContain(subprocessorRss, '<title>ACGS subprocessor changes</title>', 'subprocessor RSS')
mustContain(subprocessorRss, '<link>https://acgs.ai/privacy</link>', 'subprocessor RSS')
mustContain(
  subprocessorRss,
  '<guid>acgs-subprocessors-engineering-draft-2026-05-25</guid>',
  'subprocessor RSS',
)
mustContain(subprocessorRss, 'Engineering draft pending legal review', 'subprocessor RSS')
check(
  !/TODO|TBD|example\.com/i.test(subprocessorRss),
  'subprocessor RSS must not contain placeholder TODO/TBD/example values.',
)

const claimIds = new Map(claimMatrix.claims.map((claim) => [claim.id, claim]))
check(
  claimIds.get('subprocessor-boundary')?.sourceFiles?.includes('public/subprocessors.xml'),
  'claim-matrix subprocessor-boundary must cite public/subprocessors.xml.',
)
check(
  claimIds.get('subprocessor-boundary')?.sourceFiles?.includes('src/routes/Trust.tsx'),
  'claim-matrix subprocessor-boundary must cite src/routes/Trust.tsx.',
)
check(
  claimIds.get('console-csp-and-headers')?.sourceFiles?.includes('src/routes/Security.tsx'),
  'claim-matrix console-csp-and-headers must cite src/routes/Security.tsx.',
)
check(
  claimIds.get('soc2-roadmap')?.sourceFiles?.includes('src/routes/Trust.tsx'),
  'claim-matrix soc2-roadmap must cite src/routes/Trust.tsx.',
)

check(
  packageJson.scripts?.['test:trust-surface'] === 'node scripts/check-trust-surface.mjs',
  'package.json must expose test:trust-surface.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:trust-surface'),
  'package.json test:all must include test:trust-surface.',
)
check(
  /test:trust-surface/.test(deploy) &&
    /\.well-known\/security\.txt/.test(deploy) &&
    /subprocessors\.xml/.test(deploy),
  'DEPLOY.md must document the trust/security publication gate and static disclosure files.',
)
check(
  /Trust and security pages/.test(readiness) &&
    /pnpm -F acgi-ai run test:trust-surface/.test(readiness),
  'integration readiness map must record the trust/security page gate and verification command.',
)

if (failures.length) {
  console.error('Trust/security surface check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Trust/security surface check passed.')
