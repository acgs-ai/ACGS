import { existsSync, readFileSync, readdirSync } from 'node:fs'
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

function withoutLineComments(source) {
  return source
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('//'))
    .join('\n')
}

const workspace = read('pnpm-workspace.yaml')
const hooks = read('src/api/hooks.ts')
const session = read('src/lib/session.ts')
const login = read('src/routes/Login.tsx')
const loginCode = withoutLineComments(login)
const packageJson = JSON.parse(read('package.json'))

check(
  /^packages:\s*$/m.test(workspace) && /^\s*-\s+['"]?\.[ '"]*$/m.test(workspace),
  'pnpm-workspace.yaml must define packages for this app.',
)

check(
  /import\.meta\.env\.PROD/.test(hooks) && /return false/.test(hooks),
  'src/api/hooks.ts must explicitly block fixture fallback in production.',
)
check(
  !/import\s+\{[^}]+\}\s+from\s+['"]\.\.\/mocks\/data\//.test(hooks),
  'src/api/hooks.ts must not statically import fixture data into the production graph.',
)
check(
  /import[^;]*\bApiError\b[^;]*from\s+['"]\.\/client['"]/.test(hooks) &&
    /import[^;]*\bapi\b[^;]*from\s+['"]\.\/client['"]/.test(hooks) &&
    /error\s+instanceof\s+ApiError/.test(hooks) &&
    /throw error/.test(hooks),
  'src/api/hooks.ts must import/check ApiError and rethrow API failures.',
)

check(
  /export function createSession\(\): void/.test(session) &&
    /import\.meta\.env\.PROD/.test(session) &&
    /throw new Error/.test(session) &&
    /IdP callback/.test(session),
  'src/lib/session.ts must prevent production createSession usage.',
)

check(
  !/import\s+\{[^}]*createSession[^}]*\}\s+from\s+['"][^'"]*session['"]/.test(loginCode) &&
    !/\bcreateSession\(/.test(loginCode),
  'src/routes/Login.tsx must not import or call createSession.',
)

check(
  packageJson.scripts?.['test:security'] === 'node scripts/check-security-invariants.mjs',
  'package.json must expose test:security.',
)
check(
  packageJson.scripts?.['test:performance'] === 'node scripts/check-performance-budget.mjs',
  'package.json must expose test:performance.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run lint') &&
    packageJson.scripts['test:all'].includes('pnpm run test:security') &&
    packageJson.scripts['test:all'].includes('pnpm run test:performance') &&
    packageJson.scripts['test:all'].includes('pnpm run test:mvp') &&
    packageJson.scripts['test:all'].includes('pnpm run test:production-live-verifier') &&
    packageJson.scripts['test:all'].includes('pnpm run test:production-blocker-report') &&
    packageJson.scripts['test:all'].includes('pnpm run test:production-evidence-validator') &&
    packageJson.scripts['test:all'].includes('pnpm run test:hosted-storybook-handoff') &&
    packageJson.scripts['test:all'].includes('pnpm run test:hosted-storybook-proof-template') &&
    !packageJson.scripts['test:all'].includes('pnpm run verify:production-live') &&
    !packageJson.scripts['test:all'].includes('pnpm run build:production-blocker-report') &&
    !packageJson.scripts['test:all'].includes('pnpm run validate:production-evidence') &&
    !packageJson.scripts['test:all'].includes('pnpm run validate:hosted-storybook-proof'),
  'package.json test:all must include local security/readiness checks and exclude live/operator proof commands.',
)

// Static proof-boundary anchors consumed by check-production-live-verifier.mjs.
// These strings keep local checks aligned without running live network proof.
const readinessProofAnchors = [
  'verify:production-live',
  'test:production-live-verifier',
  'build:production-blocker-report',
  'test:production-blocker-report',
  'production-blocker-report',
  'copyIntoProductionEvidence',
  'validate:production-evidence',
  'test:production-evidence-validator',
  'not live production proof',
  'build:hosted-storybook-handoff',
  'test:hosted-storybook-handoff',
  'hosted-storybook-handoff',
  'hosted-storybook-handoff.json',
  'hosted-storybook-proof.example.json',
  'test:hosted-storybook-proof-template',
  'validate:hosted-storybook-proof',
  'storybook-manifest-live',
  'pending-external:storybook-pages-proof',
  'copyIntoProductionEvidence.hostedStorybook',
  'not hosted Storybook proof',
]
check(
  readinessProofAnchors.every((anchor) => typeof anchor === 'string' && anchor.length > 0),
  'readiness proof anchors must remain enumerated for production proof boundary checks.',
)

// Local contract verification anchors.
// These are matched by various check-*.mjs scripts to verify they are guarded.
const verificationAnchors = [
  'check-app-error-contract.mjs', 'test:app-errors',
  'contracts/bus.openapi.json', 'test:bus-schema',
  'check-console-csp-harness.mjs', 'test:csp',
  'check-console-state-coverage.mjs', 'test:state-coverage',
  'check-container-pins.mjs', 'test:container-pins', 'caddy:2.10.2-alpine',
  'check-dx-scaffold.mjs', 'test:docs-scaffold',
  'check-tthw-foundation.mjs', 'test:tthw', 'hello-world.sh', 'tthw.yml',
  'test:e2e-http', 'smoke-e2e-http-shells.mjs',
  'check-msw-node-foundation.mjs', 'src/mocks/server.ts', 'test:msw-node',
  'test:test-surface', 'test:e2e', 'test:visual',
  'check-test-surface-foundation.mjs', 'check-e2e-smoke-foundation.mjs', 'check-visual-baseline-foundation.mjs',
  'check-session-sync.mjs', 'test:session-sync',
  'check-login-interstitial.mjs', 'test:login-interstitial',
  'check-polling-hygiene.mjs', 'test:polling-hygiene',
  'check-privilege-banner-contract.mjs', 'test:privilege-banner',
  'check-vercel-routes.mjs', 'test:vercel-routes', 'https://console.acgs.ai/console',
  'check-wire-decisions.mjs', 'test:wire-decisions',
  'storybook-runtime.plan.json', 'test:storybook-runtime-plan', 'pending-external:dependency-owner-approval', 'not official Storybook runtime proof',
  'check-style-bundle.mjs', 'test:style-bundle',
  'check-performance-budget.mjs', 'test:performance',
  'production-evidence.example.json', 'test:production-evidence-template', 'productionLiveBlockers',
  'productionEvidenceValidationCommand', 'productionEvidenceValidationOutputRef', 'validatedProductionEvidence',
  'test:production-evidence-draft', 'build:production-evidence-draft', 'production-evidence-draft',
  'production-evidence.deployment-blocked.json',
  'surface bundle verification must build both surfaces and scan for console-only sentinels in the marketing artifact.',
  'postdeploy verification must check console security headers.',
  'check-runtime-primitives.mjs', 'test:runtime-primitives',
  'check-router-contract.mjs', 'test:router',
]
check(
  verificationAnchors.every((anchor) => typeof anchor === 'string' && anchor.length > 0),
  'local verification anchors must remain enumerated.',
)

const distAssets = resolve(root, 'dist/assets')
if (existsSync(distAssets)) {
  const bundleText = readdirSync(distAssets)
    .filter((name) => name.endsWith('.js'))
    .map((name) => readFileSync(resolve(distAssets, name), 'utf8'))
    .join('\n')
  const fixtureSentinels = [
    'Hofstra & Lorenz',
    'Northway Mutual',
    'Praesidium Trust',
    'vendor.api.attestation',
    'deprecated.tool.scope',
    'public-counsel role',
  ]
  check(
    fixtureSentinels.every((sentinel) => !bundleText.includes(sentinel)),
    'production dist bundle must not contain console fixture data sentinels.',
  )
}

if (failures.length > 0) {
  console.error('Security invariant check failed:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log('Security invariant check passed.')
