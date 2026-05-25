import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []
// Artifact anchor: production-evidence.deployment-blocked.json.

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
const viteConfig = read('vite.config.ts')
const main = read('src/main.tsx')
const hooks = read('src/api/hooks.ts')
const session = read('src/lib/session.ts')
const login = read('src/routes/Login.tsx')
const loginCode = withoutLineComments(login)
const packageJson = JSON.parse(read('package.json'))
const vercelJson = JSON.parse(read('vercel.json'))
const caddyfile = read('infra/Caddyfile')
const cloudRunService = read('infra/cloudrun/service.yaml')
const consoleWorkflow = read('../.github/workflows/console.yml')
const marketingWorkflow = read('../.github/workflows/marketing.yml')
const postdeployPath = resolve(root, 'scripts/postdeploy-verify.sh')
const postdeploy = existsSync(postdeployPath) ? readFileSync(postdeployPath, 'utf8') : ''
const surfaceCheckPath = resolve(root, 'scripts/check-surface-bundles.mjs')
const surfaceCheck = existsSync(surfaceCheckPath) ? readFileSync(surfaceCheckPath, 'utf8') : ''
const performanceBudgetCheckPath = resolve(root, 'scripts/check-performance-budget.mjs')
const performanceBudgetCheck = existsSync(performanceBudgetCheckPath)
  ? readFileSync(performanceBudgetCheckPath, 'utf8')
  : ''
const busProxyCheckPath = resolve(root, 'scripts/check-bus-proxy-contract.mjs')
const busProxyCheck = existsSync(busProxyCheckPath) ? readFileSync(busProxyCheckPath, 'utf8') : ''
const busSchemaCheckPath = resolve(root, 'scripts/check-bus-schema-contract.mjs')
const busSchemaCheck = existsSync(busSchemaCheckPath)
  ? readFileSync(busSchemaCheckPath, 'utf8')
  : ''
const cloudRunTemplateCheckPath = resolve(root, 'scripts/check-cloudrun-templates.mjs')
const cloudRunTemplateCheck = existsSync(cloudRunTemplateCheckPath)
  ? readFileSync(cloudRunTemplateCheckPath, 'utf8')
  : ''
const cloudRunRendererPath = resolve(root, 'scripts/render-cloudrun-service.mjs')
const cloudRunRenderer = existsSync(cloudRunRendererPath)
  ? readFileSync(cloudRunRendererPath, 'utf8')
  : ''
const cloudRunRendererCheckPath = resolve(root, 'scripts/check-cloudrun-renderer.mjs')
const cloudRunRendererCheck = existsSync(cloudRunRendererCheckPath)
  ? readFileSync(cloudRunRendererCheckPath, 'utf8')
  : ''
const containerPinCheckPath = resolve(root, 'scripts/check-container-pins.mjs')
const containerPinCheck = existsSync(containerPinCheckPath)
  ? readFileSync(containerPinCheckPath, 'utf8')
  : ''
const authBoundaryCheckPath = resolve(root, 'scripts/check-auth-boundary.mjs')
const authBoundaryCheck = existsSync(authBoundaryCheckPath)
  ? readFileSync(authBoundaryCheckPath, 'utf8')
  : ''
const fontManifestCheckPath = resolve(root, 'scripts/check-font-manifest.mjs')
const fontManifestCheck = existsSync(fontManifestCheckPath)
  ? readFileSync(fontManifestCheckPath, 'utf8')
  : ''
const fontManifestPath = resolve(root, 'fonts.sha256')
const postdeployLiveAssetsCheckPath = resolve(root, 'scripts/check-postdeploy-live-assets.mjs')
const postdeployLiveAssetsCheck = existsSync(postdeployLiveAssetsCheckPath)
  ? readFileSync(postdeployLiveAssetsCheckPath, 'utf8')
  : ''
const claimMatrixPath = resolve(root, 'claim-matrix.json')
const claimMatrix = existsSync(claimMatrixPath) ? readFileSync(claimMatrixPath, 'utf8') : ''
const claimMatrixCheckPath = resolve(root, 'scripts/check-claim-matrix.mjs')
const claimMatrixCheck = existsSync(claimMatrixCheckPath)
  ? readFileSync(claimMatrixCheckPath, 'utf8')
  : ''
const marketingCspCheckPath = resolve(root, 'scripts/check-marketing-csp.mjs')
const marketingCspCheck = existsSync(marketingCspCheckPath)
  ? readFileSync(marketingCspCheckPath, 'utf8')
  : ''
const vercelRouteCheckPath = resolve(root, 'scripts/check-vercel-routes.mjs')
const vercelRouteCheck = existsSync(vercelRouteCheckPath)
  ? readFileSync(vercelRouteCheckPath, 'utf8')
  : ''
const ciReadinessGateCheckPath = resolve(root, 'scripts/check-ci-readiness-gates.mjs')
const ciReadinessGateCheck = existsSync(ciReadinessGateCheckPath)
  ? readFileSync(ciReadinessGateCheckPath, 'utf8')
  : ''
const productionAuthorityPacketPath = resolve(root, 'production-authority.example.json')
const productionAuthorityPacket = existsSync(productionAuthorityPacketPath)
  ? readFileSync(productionAuthorityPacketPath, 'utf8')
  : ''
const productionAuthorityPacketCheckPath = resolve(
  root,
  'scripts/check-production-authority-packet.mjs',
)
const productionAuthorityPacketCheck = existsSync(productionAuthorityPacketCheckPath)
  ? readFileSync(productionAuthorityPacketCheckPath, 'utf8')
  : ''
const productionEvidenceTemplatePath = resolve(root, 'production-evidence.example.json')
const productionEvidenceTemplate = existsSync(productionEvidenceTemplatePath)
  ? readFileSync(productionEvidenceTemplatePath, 'utf8')
  : ''
const productionEvidenceTemplateCheckPath = resolve(
  root,
  'scripts/check-production-evidence-template.mjs',
)
const productionEvidenceTemplateCheck = existsSync(productionEvidenceTemplateCheckPath)
  ? readFileSync(productionEvidenceTemplateCheckPath, 'utf8')
  : ''
const productionLiveVerifierPath = resolve(root, 'scripts/verify-production-live.mjs')
const productionLiveVerifier = existsSync(productionLiveVerifierPath)
  ? readFileSync(productionLiveVerifierPath, 'utf8')
  : ''
const productionLiveVerifierCheckPath = resolve(root, 'scripts/check-production-live-verifier.mjs')
const productionLiveVerifierCheck = existsSync(productionLiveVerifierCheckPath)
  ? readFileSync(productionLiveVerifierCheckPath, 'utf8')
  : ''
const productionBlockerReportPath = resolve(root, 'scripts/build-production-blocker-report.mjs')
const productionBlockerReport = existsSync(productionBlockerReportPath)
  ? readFileSync(productionBlockerReportPath, 'utf8')
  : ''
const productionBlockerReportCheckPath = resolve(
  root,
  'scripts/check-production-blocker-report.mjs',
)
const productionBlockerReportCheck = existsSync(productionBlockerReportCheckPath)
  ? readFileSync(productionBlockerReportCheckPath, 'utf8')
  : ''
const productionEvidenceValidatorPath = resolve(root, 'scripts/validate-production-evidence.mjs')
const productionEvidenceValidator = existsSync(productionEvidenceValidatorPath)
  ? readFileSync(productionEvidenceValidatorPath, 'utf8')
  : ''
const productionEvidenceValidatorCheckPath = resolve(
  root,
  'scripts/check-production-evidence-validator.mjs',
)
const productionEvidenceValidatorCheck = existsSync(productionEvidenceValidatorCheckPath)
  ? readFileSync(productionEvidenceValidatorCheckPath, 'utf8')
  : ''
const productionCutoverPlanPath = resolve(root, 'scripts/build-production-cutover-plan.mjs')
const productionCutoverPlan = existsSync(productionCutoverPlanPath)
  ? readFileSync(productionCutoverPlanPath, 'utf8')
  : ''
const productionCutoverPlanCheckPath = resolve(root, 'scripts/check-production-cutover-plan.mjs')
const productionCutoverPlanCheck = existsSync(productionCutoverPlanCheckPath)
  ? readFileSync(productionCutoverPlanCheckPath, 'utf8')
  : ''
const productionEvidenceDraftPath = resolve(root, 'scripts/build-production-evidence-draft.mjs')
const productionEvidenceDraft = existsSync(productionEvidenceDraftPath)
  ? readFileSync(productionEvidenceDraftPath, 'utf8')
  : ''
const productionEvidenceDraftCheckPath = resolve(
  root,
  'scripts/check-production-evidence-draft.mjs',
)
const productionEvidenceDraftCheck = existsSync(productionEvidenceDraftCheckPath)
  ? readFileSync(productionEvidenceDraftCheckPath, 'utf8')
  : ''
const hostedStorybookHandoffPath = resolve(root, 'scripts/build-hosted-storybook-handoff.mjs')
const hostedStorybookHandoff = existsSync(hostedStorybookHandoffPath)
  ? readFileSync(hostedStorybookHandoffPath, 'utf8')
  : ''
const hostedStorybookHandoffCheckPath = resolve(root, 'scripts/check-hosted-storybook-handoff.mjs')
const hostedStorybookHandoffCheck = existsSync(hostedStorybookHandoffCheckPath)
  ? readFileSync(hostedStorybookHandoffCheckPath, 'utf8')
  : ''
const hostedStorybookProofTemplatePath = resolve(root, 'hosted-storybook-proof.example.json')
const hostedStorybookProofTemplate = existsSync(hostedStorybookProofTemplatePath)
  ? readFileSync(hostedStorybookProofTemplatePath, 'utf8')
  : ''
const hostedStorybookProofTemplateCheckPath = resolve(
  root,
  'scripts/check-hosted-storybook-proof-template.mjs',
)
const hostedStorybookProofTemplateCheck = existsSync(hostedStorybookProofTemplateCheckPath)
  ? readFileSync(hostedStorybookProofTemplateCheckPath, 'utf8')
  : ''
const hostedStorybookProofValidatorPath = resolve(
  root,
  'scripts/validate-hosted-storybook-proof.mjs',
)
const hostedStorybookProofValidator = existsSync(hostedStorybookProofValidatorPath)
  ? readFileSync(hostedStorybookProofValidatorPath, 'utf8')
  : ''
const storybookRuntimePlanPath = resolve(root, 'storybook-runtime.plan.json')
const storybookRuntimePlan = existsSync(storybookRuntimePlanPath)
  ? readFileSync(storybookRuntimePlanPath, 'utf8')
  : ''
const storybookRuntimePlanCheckPath = resolve(root, 'scripts/check-storybook-runtime-plan.mjs')
const storybookRuntimePlanCheck = existsSync(storybookRuntimePlanCheckPath)
  ? readFileSync(storybookRuntimePlanCheckPath, 'utf8')
  : ''
const trustSurfaceCheckPath = resolve(root, 'scripts/check-trust-surface.mjs')
const trustSurfaceCheck = existsSync(trustSurfaceCheckPath)
  ? readFileSync(trustSurfaceCheckPath, 'utf8')
  : ''
const platformBlueprintCheckPath = resolve(root, 'scripts/check-platform-blueprint.mjs')
const platformBlueprintCheck = existsSync(platformBlueprintCheckPath)
  ? readFileSync(platformBlueprintCheckPath, 'utf8')
  : ''
const consoleStateCoverageCheckPath = resolve(root, 'scripts/check-console-state-coverage.mjs')
const consoleStateCoverageCheck = existsSync(consoleStateCoverageCheckPath)
  ? readFileSync(consoleStateCoverageCheckPath, 'utf8')
  : ''
const pollingHygieneCheckPath = resolve(root, 'scripts/check-polling-hygiene.mjs')
const pollingHygieneCheck = existsSync(pollingHygieneCheckPath)
  ? readFileSync(pollingHygieneCheckPath, 'utf8')
  : ''
const sessionSyncCheckPath = resolve(root, 'scripts/check-session-sync.mjs')
const sessionSyncCheck = existsSync(sessionSyncCheckPath)
  ? readFileSync(sessionSyncCheckPath, 'utf8')
  : ''
const appErrorContractCheckPath = resolve(root, 'scripts/check-app-error-contract.mjs')
const appErrorContractCheck = existsSync(appErrorContractCheckPath)
  ? readFileSync(appErrorContractCheckPath, 'utf8')
  : ''
const loginInterstitialCheckPath = resolve(root, 'scripts/check-login-interstitial.mjs')
const loginInterstitialCheck = existsSync(loginInterstitialCheckPath)
  ? readFileSync(loginInterstitialCheckPath, 'utf8')
  : ''
const privilegeBannerContractCheckPath = resolve(
  root,
  'scripts/check-privilege-banner-contract.mjs',
)
const privilegeBannerContractCheck = existsSync(privilegeBannerContractCheckPath)
  ? readFileSync(privilegeBannerContractCheckPath, 'utf8')
  : ''
const wireDecisionsCheckPath = resolve(root, 'scripts/check-wire-decisions.mjs')
const wireDecisionsCheck = existsSync(wireDecisionsCheckPath)
  ? readFileSync(wireDecisionsCheckPath, 'utf8')
  : ''
const testSurfaceFoundationCheckPath = resolve(root, 'scripts/check-test-surface-foundation.mjs')
const testSurfaceFoundationCheck = existsSync(testSurfaceFoundationCheckPath)
  ? readFileSync(testSurfaceFoundationCheckPath, 'utf8')
  : ''
const e2eSmokeFoundationCheckPath = resolve(root, 'scripts/check-e2e-smoke-foundation.mjs')
const e2eSmokeFoundationCheck = existsSync(e2eSmokeFoundationCheckPath)
  ? readFileSync(e2eSmokeFoundationCheckPath, 'utf8')
  : ''
const e2eHttpFoundationCheckPath = resolve(root, 'scripts/check-e2e-http-foundation.mjs')
const e2eHttpFoundationCheck = existsSync(e2eHttpFoundationCheckPath)
  ? readFileSync(e2eHttpFoundationCheckPath, 'utf8')
  : ''
const e2eHttpSmokePath = resolve(root, 'scripts/smoke-e2e-http-shells.mjs')
const e2eHttpSmoke = existsSync(e2eHttpSmokePath) ? readFileSync(e2eHttpSmokePath, 'utf8') : ''
const visualBaselineFoundationCheckPath = resolve(
  root,
  'scripts/check-visual-baseline-foundation.mjs',
)
const visualBaselineFoundationCheck = existsSync(visualBaselineFoundationCheckPath)
  ? readFileSync(visualBaselineFoundationCheckPath, 'utf8')
  : ''
const browserEvidenceCapturePath = resolve(root, 'scripts/capture-workbench-browser-evidence.mjs')
const browserEvidenceCapture = existsSync(browserEvidenceCapturePath)
  ? readFileSync(browserEvidenceCapturePath, 'utf8')
  : ''
const browserEvidenceFoundationCheckPath = resolve(
  root,
  'scripts/check-browser-evidence-foundation.mjs',
)
const browserEvidenceFoundationCheck = existsSync(browserEvidenceFoundationCheckPath)
  ? readFileSync(browserEvidenceFoundationCheckPath, 'utf8')
  : ''
const tthwFoundationCheckPath = resolve(root, 'scripts/check-tthw-foundation.mjs')
const tthwFoundationCheck = existsSync(tthwFoundationCheckPath)
  ? readFileSync(tthwFoundationCheckPath, 'utf8')
  : ''
const mswNodeFoundationCheckPath = resolve(root, 'scripts/check-msw-node-foundation.mjs')
const mswNodeFoundationCheck = existsSync(mswNodeFoundationCheckPath)
  ? readFileSync(mswNodeFoundationCheckPath, 'utf8')
  : ''
const mswNodeServerPath = resolve(root, 'src/mocks/server.ts')
const mswNodeServer = existsSync(mswNodeServerPath) ? readFileSync(mswNodeServerPath, 'utf8') : ''
const mswPolicyPath = resolve(root, 'src/mocks/policy.ts')
const mswPolicy = existsSync(mswPolicyPath) ? readFileSync(mswPolicyPath, 'utf8') : ''
const helloWorldCheckPath = resolve(root, 'scripts/hello-world.sh')
const helloWorldCheck = existsSync(helloWorldCheckPath)
  ? readFileSync(helloWorldCheckPath, 'utf8')
  : ''
const tthwWorkflowPath = resolve(root, '../.github/workflows/tthw.yml')
const tthwWorkflow = existsSync(tthwWorkflowPath) ? readFileSync(tthwWorkflowPath, 'utf8') : ''
const a11yFoundationCheckPath = resolve(root, 'scripts/check-a11y-foundation.mjs')
const a11yFoundationCheck = existsSync(a11yFoundationCheckPath)
  ? readFileSync(a11yFoundationCheckPath, 'utf8')
  : ''
const a11yDocPath = resolve(root, 'A11Y.md')
const a11yDoc = existsSync(a11yDocPath) ? readFileSync(a11yDocPath, 'utf8') : ''
const dxScaffoldCheckPath = resolve(root, 'scripts/check-dx-scaffold.mjs')
const dxScaffoldCheck = existsSync(dxScaffoldCheckPath)
  ? readFileSync(dxScaffoldCheckPath, 'utf8')
  : ''
const runtimePrimitivesCheckPath = resolve(root, 'scripts/check-runtime-primitives.mjs')
const runtimePrimitivesCheck = existsSync(runtimePrimitivesCheckPath)
  ? readFileSync(runtimePrimitivesCheckPath, 'utf8')
  : ''
const routerContractCheckPath = resolve(root, 'scripts/check-router-contract.mjs')
const routerContractCheck = existsSync(routerContractCheckPath)
  ? readFileSync(routerContractCheckPath, 'utf8')
  : ''
const styleBundleCheckPath = resolve(root, 'scripts/check-style-bundle.mjs')
const styleBundleCheck = existsSync(styleBundleCheckPath)
  ? readFileSync(styleBundleCheckPath, 'utf8')
  : ''
const consoleCspHarnessPath = resolve(root, 'scripts/check-console-csp-harness.mjs')
const consoleCspHarness = existsSync(consoleCspHarnessPath)
  ? readFileSync(consoleCspHarnessPath, 'utf8')
  : ''

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
    /function isNetworkUnavailable\(error: unknown\): boolean/.test(hooks) &&
    /error\s+instanceof\s+ApiError/.test(hooks) &&
    /error\s+instanceof\s+TypeError/.test(hooks) &&
    /failed to fetch/.test(hooks) &&
    /fetch failed/.test(hooks) &&
    /networkerror/.test(hooks) &&
    /network request failed/.test(hooks) &&
    /load failed/.test(hooks) &&
    /!isNetworkUnavailable\(error\)/.test(hooks) &&
    /throw error/.test(hooks),
  'src/api/hooks.ts must import/check ApiError and limit fixture fallback to network-unavailable errors.',
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
  packageJson.scripts?.['test:all'] ===
    'pnpm run lint && pnpm run build:console && pnpm run test:security && pnpm run test:mvp && pnpm run test:font-manifest && pnpm run test:surfaces && pnpm run test:performance && pnpm run test:bus-schema && pnpm run test:bus-proxy && pnpm run test:cloudrun-templates && pnpm run test:cloudrun-renderer && pnpm run test:production-deploy-contract && pnpm run test:production-launch-handoff && pnpm run test:production-authority-packet && pnpm run test:production-evidence-template && pnpm run test:production-live-verifier && pnpm run test:production-blocker-report && pnpm run test:production-evidence-validator && pnpm run test:production-cutover-plan && pnpm run test:production-evidence-draft && pnpm run test:container-pins && pnpm run test:auth-boundary && pnpm run test:postdeploy-live-assets && pnpm run test:claim-matrix && pnpm run test:trust-surface && pnpm run test:platform-blueprint && pnpm run test:state-coverage && pnpm run test:polling-hygiene && pnpm run test:session-sync && pnpm run test:app-errors && pnpm run test:login-interstitial && pnpm run test:privilege-banner && pnpm run test:wire-decisions && pnpm run test:test-surface && pnpm run test:buyer-evidence && pnpm run test:storybook-runtime-plan && pnpm run test:storybook-publication && pnpm run test:hosted-storybook-handoff && pnpm run test:hosted-storybook-proof-template && pnpm run test:e2e-http && pnpm run test:browser-evidence && pnpm run test:tthw && pnpm run test:msw-node && pnpm run test:a11y && pnpm run test:docs-scaffold && pnpm run test:runtime-primitives && pnpm run test:router && pnpm run test:marketing-csp && pnpm run test:vercel-routes && pnpm run test:ci-gates && pnpm run test:style-bundle && pnpm run test:csp',
  'package.json test:all must run lint, console build, security, MVP, font-manifest, surface-split, performance-budget, bus-schema, bus-proxy, Cloud Run template, Cloud Run renderer, production deploy fail-closed, production launch handoff, production authority packet, production evidence template, production live verifier, production blocker report, production evidence validator, production cutover plan, production evidence draft, hosted Storybook handoff, hosted Storybook proof template, container-pin, auth-boundary, postdeploy-live-asset, claim-matrix, trust-surface, platform-blueprint, console state coverage, polling/session-sync hygiene, AppError boundary, login interstitial, privilege banner, wire decisions, test surface foundation, buyer-evidence gallery, Storybook runtime plan, Storybook publication scaffold, hosted Storybook handoff, E2E HTTP shell smoke, browser evidence foundation, TTHW foundation, MSW node-mode foundation, a11y foundation, docs-scaffold, runtime-primitives, router, marketing-CSP, Vercel-route, CI readiness-gate, style-bundle, and console-CSP verification while excluding live/operator-specific proof commands.',
)
check(
  packageJson.scripts?.['verify:postdeploy'] === 'bash scripts/postdeploy-verify.sh',
  'package.json must expose verify:postdeploy for live console evidence checks.',
)
check(
  packageJson.scripts?.build ===
    'pnpm run test:font-manifest && pnpm run build:console && ACGI_OUT_DIR=dist-marketing pnpm run build:marketing',
  'package.json build must verify font provenance, then produce both console and marketing artifacts without overwriting console dist.',
)
check(
  packageJson.scripts?.['build:console'] === 'tsc -b && vite build --mode console',
  'package.json must expose an explicit console build profile.',
)
check(
  packageJson.scripts?.['build:marketing'] === 'tsc -b && vite build --mode marketing',
  'package.json must expose an explicit marketing build profile.',
)
check(
  packageJson.scripts?.['test:surfaces'] === 'node scripts/check-surface-bundles.mjs',
  'package.json must expose test:surfaces for marketing/console artifact split verification.',
)
check(
  packageJson.scripts?.['test:performance'] === 'node scripts/check-performance-budget.mjs',
  'package.json must expose test:performance for bundle budget verification.',
)
check(
  packageJson.scripts?.['test:bus-proxy'] === 'node scripts/check-bus-proxy-contract.mjs',
  'package.json must expose test:bus-proxy for console /api reverse-proxy readiness.',
)
check(
  packageJson.scripts?.['test:bus-schema'] === 'node scripts/check-bus-schema-contract.mjs',
  'package.json must expose test:bus-schema for schema ownership and codegen drift verification.',
)
check(
  packageJson.scripts?.['smoke:bus-proxy'] === 'node scripts/smoke-bus-proxy-contract.mjs',
  'package.json must expose smoke:bus-proxy for Docker-backed /api proxy verification.',
)
check(
  packageJson.scripts?.['test:cloudrun-templates'] === 'node scripts/check-cloudrun-templates.mjs',
  'package.json must expose test:cloudrun-templates for Cloud Run environment template verification.',
)
check(
  packageJson.scripts?.['render:cloudrun'] === 'node scripts/render-cloudrun-service.mjs',
  'package.json must expose render:cloudrun for deterministic Cloud Run manifest rendering.',
)
check(
  packageJson.scripts?.['test:cloudrun-renderer'] === 'node scripts/check-cloudrun-renderer.mjs',
  'package.json must expose test:cloudrun-renderer for deploy render fail-closed verification.',
)
check(
  packageJson.scripts?.['test:container-pins'] === 'node scripts/check-container-pins.mjs',
  'package.json must expose test:container-pins for deploy image/toolchain pin verification.',
)
check(
  packageJson.scripts?.['test:auth-boundary'] === 'node scripts/check-auth-boundary.mjs',
  'package.json must expose test:auth-boundary for production auth boundary verification.',
)
check(
  packageJson.scripts?.['test:font-manifest'] === 'node scripts/check-font-manifest.mjs',
  'package.json must expose test:font-manifest for self-hosted WOFF2 provenance verification.',
)
check(
  packageJson.scripts?.['test:postdeploy-live-assets'] ===
    'node scripts/check-postdeploy-live-assets.mjs',
  'package.json must expose test:postdeploy-live-assets for live deployed asset auth-sentinel verification.',
)
check(
  packageJson.scripts?.['test:claim-matrix'] === 'node scripts/check-claim-matrix.mjs',
  'package.json must expose test:claim-matrix for compliance/security claim honesty verification.',
)
check(
  packageJson.scripts?.['test:trust-surface'] === 'node scripts/check-trust-surface.mjs',
  'package.json must expose test:trust-surface for trust/security publication verification.',
)
check(
  packageJson.scripts?.['test:platform-blueprint'] === 'node scripts/check-platform-blueprint.mjs',
  'package.json must expose test:platform-blueprint for platform UI/UX blueprint verification.',
)
check(
  packageJson.scripts?.['test:state-coverage'] === 'node scripts/check-console-state-coverage.mjs',
  'package.json must expose test:state-coverage for console state coverage verification.',
)
check(
  packageJson.scripts?.['test:polling-hygiene'] === 'node scripts/check-polling-hygiene.mjs',
  'package.json must expose test:polling-hygiene for polling hygiene verification.',
)
check(
  packageJson.scripts?.['test:session-sync'] === 'node scripts/check-session-sync.mjs',
  'package.json must expose test:session-sync for cross-tab session sync verification.',
)
check(
  packageJson.scripts?.['test:app-errors'] === 'node scripts/check-app-error-contract.mjs',
  'package.json must expose test:app-errors for AppError boundary verification.',
)
check(
  packageJson.scripts?.['test:login-interstitial'] === 'node scripts/check-login-interstitial.mjs',
  'package.json must expose test:login-interstitial for login parchment handoff verification.',
)
check(
  packageJson.scripts?.['test:privilege-banner'] ===
    'node scripts/check-privilege-banner-contract.mjs',
  'package.json must expose test:privilege-banner for privilege banner and right-rail verification.',
)
check(
  packageJson.scripts?.['test:wire-decisions'] === 'node scripts/check-wire-decisions.mjs',
  'package.json must expose test:wire-decisions for route-level wire decision verification.',
)
check(
  packageJson.scripts?.['test:test-surface'] === 'node scripts/check-test-surface-foundation.mjs',
  'package.json must expose test:test-surface for Phase 2 test surface manifest verification.',
)
check(
  packageJson.scripts?.['test:tthw'] === 'node scripts/check-tthw-foundation.mjs',
  'package.json must expose test:tthw for the TTHW foundation verifier.',
)
check(
  packageJson.scripts?.['test:msw-node'] === 'node scripts/check-msw-node-foundation.mjs',
  'package.json must expose test:msw-node for the MSW node-mode foundation verifier.',
)
check(
  packageJson.scripts?.['test:e2e'] === 'node scripts/check-e2e-smoke-foundation.mjs',
  'package.json must expose test:e2e for the E2E smoke manifest gate.',
)
check(
  packageJson.scripts?.['test:e2e-http'] === 'node scripts/smoke-e2e-http-shells.mjs',
  'package.json must expose test:e2e-http for the E2E HTTP shell smoke.',
)
check(
  packageJson.scripts?.['test:visual'] === 'node scripts/check-visual-baseline-foundation.mjs',
  'package.json must expose test:visual for the visual baseline manifest gate.',
)
check(
  packageJson.scripts?.['evidence:browser-workbench'] ===
    'node scripts/capture-workbench-browser-evidence.mjs',
  'package.json must expose evidence:browser-workbench for local browser workbench screenshots.',
)
check(
  packageJson.scripts?.['test:browser-evidence'] ===
    'node scripts/check-browser-evidence-foundation.mjs',
  'package.json must expose test:browser-evidence for the local browser evidence verifier.',
)
check(
  packageJson.scripts?.['test:a11y'] === 'node scripts/check-a11y-foundation.mjs',
  'package.json must expose test:a11y for accessibility foundation verification.',
)
check(
  packageJson.scripts?.['test:docs-scaffold'] === 'node scripts/check-dx-scaffold.mjs',
  'package.json must expose test:docs-scaffold for DX architecture/integration docs verification.',
)
check(
  packageJson.scripts?.['test:runtime-primitives'] === 'node scripts/check-runtime-primitives.mjs',
  'package.json must expose test:runtime-primitives for typed flags and AppError taxonomy verification.',
)
check(
  packageJson.scripts?.['test:router'] === 'node scripts/check-router-contract.mjs',
  'package.json must expose test:router for TanStack Router route contract verification.',
)
check(
  packageJson.scripts?.['test:csp'] ===
    'pnpm run build:console && node scripts/check-console-csp-harness.mjs',
  'package.json must expose test:csp for strict console CSP/Tailwind verification.',
)
check(packageJson.scripts?.hello === 'node scripts/hello.mjs', 'package.json must expose hello.')
check(
  packageJson.scripts?.['hello:world'] === 'bash scripts/hello-world.sh',
  'package.json must expose hello:world for the clean-runner TTHW script.',
)
check(
  packageJson.scripts?.['hello:world:local'] ===
    'bash scripts/hello-world.sh --skip-install --allow-node-drift --http-only',
  'package.json must expose hello:world:local for the bounded local TTHW smoke.',
)
check(
  packageJson.scripts?.['dev:mock'] === 'VITE_USE_MOCKS=true vite',
  'package.json must expose dev:mock.',
)
check(
  packageJson.scripts?.['dev:live'] === 'VITE_USE_MOCKS=false vite',
  'package.json must expose dev:live.',
)
check(
  packageJson.scripts?.test === 'pnpm run test:all',
  'package.json must expose test as the local full gate.',
)
check(
  packageJson.scripts?.['test:contract'] ===
    'pnpm run test:bus-schema && pnpm run test:bus-proxy && pnpm run test:cloudrun-templates && pnpm run test:cloudrun-renderer && pnpm run test:production-deploy-contract && pnpm run test:auth-boundary',
  'package.json must expose test:contract for integration/deployment and production deploy fail-closed contract checks.',
)
check(
  packageJson.scripts?.['audit:eval'] ===
    'pnpm run test:claim-matrix && pnpm run test:trust-surface && pnpm run test:platform-blueprint',
  'package.json must expose audit:eval for public claim/trust evidence checks.',
)
check(
  packageJson.scripts?.['test:marketing-csp'] === 'node scripts/check-marketing-csp.mjs',
  'package.json must expose test:marketing-csp for marketing report-only CSP verification.',
)
check(
  packageJson.scripts?.['test:vercel-routes'] === 'node scripts/check-vercel-routes.mjs',
  'package.json must expose test:vercel-routes for marketing edge route verification.',
)
check(
  packageJson.scripts?.['test:ci-gates'] === 'node scripts/check-ci-readiness-gates.mjs',
  'package.json must expose test:ci-gates for deploy workflow readiness verification.',
)
check(
  packageJson.scripts?.['test:production-deploy-contract'] ===
    'node scripts/check-production-deploy-contract.mjs',
  'package.json must expose test:production-deploy-contract for fail-closed production deploy verification.',
)
check(
  packageJson.scripts?.['test:production-launch-handoff'] ===
    'node scripts/check-production-launch-handoff.mjs',
  'package.json must expose test:production-launch-handoff for production launch handoff verification.',
)
check(
  packageJson.scripts?.['test:production-authority-packet'] ===
    'node scripts/check-production-authority-packet.mjs',
  'package.json must expose test:production-authority-packet for production authority verification.',
)
check(
  packageJson.scripts?.['test:production-evidence-template'] ===
    'node scripts/check-production-evidence-template.mjs',
  'package.json must expose test:production-evidence-template for production evidence template verification.',
)
check(
  packageJson.scripts?.['verify:production-live'] === 'node scripts/verify-production-live.mjs',
  'package.json must expose verify:production-live for live production proof collection.',
)
check(
  packageJson.scripts?.['test:production-live-verifier'] ===
    'node scripts/check-production-live-verifier.mjs',
  'package.json must expose test:production-live-verifier for local live-verifier wiring verification.',
)
check(
  packageJson.scripts?.['build:production-blocker-report'] ===
    'node scripts/build-production-blocker-report.mjs',
  'package.json must expose build:production-blocker-report for operator blocker handoff reports.',
)
check(
  packageJson.scripts?.['test:production-blocker-report'] ===
    'node scripts/check-production-blocker-report.mjs',
  'package.json must expose test:production-blocker-report for local blocker report verification.',
)
check(
  packageJson.scripts?.['validate:production-evidence'] ===
    'node scripts/validate-production-evidence.mjs',
  'package.json must expose validate:production-evidence for operator-supplied production evidence validation.',
)
check(
  packageJson.scripts?.['test:production-evidence-validator'] ===
    'node scripts/check-production-evidence-validator.mjs',
  'package.json must expose test:production-evidence-validator for local production-evidence validator verification.',
)
check(
  packageJson.scripts?.['build:production-cutover-plan'] ===
    'node scripts/build-production-cutover-plan.mjs',
  'package.json must expose build:production-cutover-plan for local cutover handoff generation.',
)
check(
  packageJson.scripts?.['test:production-cutover-plan'] ===
    'node scripts/check-production-cutover-plan.mjs',
  'package.json must expose test:production-cutover-plan for local production cutover plan verification.',
)
check(
  packageJson.scripts?.['build:production-evidence-draft'] ===
    'node scripts/build-production-evidence-draft.mjs',
  'package.json must expose build:production-evidence-draft for local deployment-blocked manifest draft generation.',
)
check(
  packageJson.scripts?.['test:production-evidence-draft'] ===
    'node scripts/check-production-evidence-draft.mjs',
  'package.json must expose test:production-evidence-draft for local production evidence draft verification.',
)
check(
  packageJson.scripts?.['build:hosted-storybook-handoff'] ===
    'node scripts/build-hosted-storybook-handoff.mjs',
  'package.json must expose build:hosted-storybook-handoff for local hosted Storybook handoff generation.',
)
check(
  packageJson.scripts?.['test:hosted-storybook-handoff'] ===
    'node scripts/check-hosted-storybook-handoff.mjs',
  'package.json must expose test:hosted-storybook-handoff for local hosted Storybook handoff verification.',
)
check(
  packageJson.scripts?.['test:hosted-storybook-proof-template'] ===
    'node scripts/check-hosted-storybook-proof-template.mjs',
  'package.json must expose test:hosted-storybook-proof-template for hosted Storybook proof intake verification.',
)
check(
  packageJson.scripts?.['validate:hosted-storybook-proof'] ===
    'node scripts/validate-hosted-storybook-proof.mjs',
  'package.json must expose validate:hosted-storybook-proof for completed hosted Storybook proof validation.',
)
check(
  packageJson.scripts?.['test:storybook-runtime-plan'] ===
    'node scripts/check-storybook-runtime-plan.mjs',
  'package.json must expose test:storybook-runtime-plan for official Storybook runtime dependency plan verification.',
)
check(
  packageJson.scripts?.['test:style-bundle'] ===
    'pnpm run build:console && node scripts/check-style-bundle.mjs',
  'package.json must expose test:style-bundle for production style bundle integrity verification.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:font-manifest') &&
    packageJson.scripts['test:all'].includes('pnpm run test:surfaces') &&
    packageJson.scripts['test:all'].includes('pnpm run test:performance') &&
    packageJson.scripts['test:all'].includes('pnpm run test:bus-schema') &&
    packageJson.scripts['test:all'].includes('pnpm run test:bus-proxy') &&
    packageJson.scripts['test:all'].includes('pnpm run test:cloudrun-templates') &&
    packageJson.scripts['test:all'].includes('pnpm run test:cloudrun-renderer') &&
    packageJson.scripts['test:all'].includes('pnpm run test:production-deploy-contract') &&
    packageJson.scripts['test:all'].includes('pnpm run test:production-launch-handoff') &&
    packageJson.scripts['test:all'].includes('pnpm run test:production-authority-packet') &&
    packageJson.scripts['test:all'].includes('pnpm run test:production-evidence-template') &&
    packageJson.scripts['test:all'].includes('pnpm run test:production-live-verifier') &&
    packageJson.scripts['test:all'].includes('pnpm run test:production-blocker-report') &&
    packageJson.scripts['test:all'].includes('pnpm run test:production-evidence-validator') &&
    packageJson.scripts['test:all'].includes('pnpm run test:production-cutover-plan') &&
    packageJson.scripts['test:all'].includes('pnpm run test:production-evidence-draft') &&
    packageJson.scripts['test:all'].includes('pnpm run test:hosted-storybook-handoff') &&
    packageJson.scripts['test:all'].includes('pnpm run test:hosted-storybook-proof-template') &&
    !packageJson.scripts['test:all'].includes('pnpm run verify:production-live') &&
    !packageJson.scripts['test:all'].includes('pnpm run build:production-blocker-report') &&
    !packageJson.scripts['test:all'].includes('pnpm run build:production-cutover-plan') &&
    !packageJson.scripts['test:all'].includes('pnpm run build:production-evidence-draft') &&
    !packageJson.scripts['test:all'].includes('pnpm run build:hosted-storybook-handoff') &&
    !packageJson.scripts['test:all'].includes('pnpm run validate:production-evidence') &&
    !packageJson.scripts['test:all'].includes('pnpm run validate:hosted-storybook-proof') &&
    packageJson.scripts['test:all'].includes('pnpm run test:container-pins') &&
    packageJson.scripts['test:all'].includes('pnpm run test:auth-boundary') &&
    packageJson.scripts['test:all'].includes('pnpm run test:postdeploy-live-assets') &&
    packageJson.scripts['test:all'].includes('pnpm run test:claim-matrix') &&
    packageJson.scripts['test:all'].includes('pnpm run test:trust-surface') &&
    packageJson.scripts['test:all'].includes('pnpm run test:platform-blueprint') &&
    packageJson.scripts['test:all'].includes('pnpm run test:state-coverage') &&
    packageJson.scripts['test:all'].includes('pnpm run test:polling-hygiene') &&
    packageJson.scripts['test:all'].includes('pnpm run test:session-sync') &&
    packageJson.scripts['test:all'].includes('pnpm run test:app-errors') &&
    packageJson.scripts['test:all'].includes('pnpm run test:login-interstitial') &&
    packageJson.scripts['test:all'].includes('pnpm run test:privilege-banner') &&
    packageJson.scripts['test:all'].includes('pnpm run test:wire-decisions') &&
    packageJson.scripts['test:all'].includes('pnpm run test:test-surface') &&
    packageJson.scripts['test:all'].includes('pnpm run test:buyer-evidence') &&
    packageJson.scripts['test:all'].includes('pnpm run test:storybook-runtime-plan') &&
    packageJson.scripts['test:all'].includes('pnpm run test:storybook-publication') &&
    packageJson.scripts['test:all'].includes('pnpm run test:hosted-storybook-handoff') &&
    packageJson.scripts['test:all'].includes('pnpm run test:hosted-storybook-proof-template') &&
    packageJson.scripts['test:all'].includes('pnpm run test:e2e-http') &&
    packageJson.scripts['test:all'].includes('pnpm run test:browser-evidence') &&
    !packageJson.scripts['test:all'].includes('pnpm run evidence:browser-workbench') &&
    packageJson.scripts['test:all'].includes('pnpm run test:tthw') &&
    packageJson.scripts['test:all'].includes('pnpm run test:msw-node') &&
    packageJson.scripts['test:all'].includes('pnpm run test:a11y') &&
    packageJson.scripts['test:all'].includes('pnpm run test:docs-scaffold') &&
    packageJson.scripts['test:all'].includes('pnpm run test:runtime-primitives') &&
    packageJson.scripts['test:all'].includes('pnpm run test:router') &&
    packageJson.scripts['test:all'].includes('pnpm run test:marketing-csp') &&
    packageJson.scripts['test:all'].includes('pnpm run test:vercel-routes') &&
    packageJson.scripts['test:all'].includes('pnpm run test:ci-gates') &&
    packageJson.scripts['test:all'].includes('pnpm run test:style-bundle') &&
    packageJson.scripts['test:all'].includes('pnpm run test:csp'),
  'package.json test:all must include font-manifest, marketing/console surface, performance-budget, bus-schema, bus-proxy, Cloud Run template, Cloud Run renderer, production deploy fail-closed, production launch handoff, production authority packet, production evidence template, production live verifier, production blocker report, production evidence validator, production cutover plan, production evidence draft, hosted Storybook handoff, hosted Storybook proof template, container-pin, auth-boundary, postdeploy-live-asset, claim-matrix, trust-surface, platform-blueprint, console state coverage, polling/session-sync hygiene, AppError boundary, login interstitial, privilege banner, wire decisions, test surface foundation, buyer-evidence gallery, Storybook runtime plan, Storybook publication scaffold, hosted Storybook handoff, hosted Storybook proof template, E2E HTTP shell smoke, browser evidence foundation, TTHW foundation, MSW node-mode foundation, a11y foundation, docs-scaffold, runtime-primitives, router, marketing-CSP, Vercel-route, CI readiness-gate, style-bundle, and console-CSP verification.',
)
check(
  /@surface\/App/.test(main) && !/from ['"]\.\/App(?:\.tsx)?['"]/.test(main),
  'src/main.tsx must import the mode-specific surface app, not the combined legacy app.',
)
check(
  /VITE_ACGI_SURFACE/.test(viteConfig) &&
    /mode === 'marketing'/.test(viteConfig) &&
    /@surface\/App/.test(viteConfig) &&
    /surfaces\/marketing\/App\.tsx/.test(viteConfig) &&
    /surfaces\/console\/App\.tsx/.test(viteConfig),
  'vite.config.ts must alias @surface/App to explicit marketing or console entry modules.',
)
check(
  vercelJson.buildCommand === 'pnpm build:marketing',
  'vercel.json must build the marketing-only artifact, not the privileged console bundle.',
)
const vercelRoutes = Array.isArray(vercelJson.routes) ? vercelJson.routes : []
const internalDocRouteIndex = vercelRoutes.findIndex(
  (route) => route.status === 404 && /AGENTS\|CLAUDE\|DESIGN\|DEPLOY/.test(route.src ?? ''),
)
const consoleExactRouteIndex = vercelRoutes.findIndex(
  (route) =>
    route.src === '/console' &&
    route.status === 308 &&
    route.headers?.Location === 'https://console.acgs.ai/console',
)
const consoleWildcardRouteIndex = vercelRoutes.findIndex(
  (route) =>
    route.src === '/console/(.*)' &&
    route.status === 308 &&
    route.headers?.Location === 'https://console.acgs.ai/console/$1',
)
const spaFallbackRouteIndex = vercelRoutes.findIndex(
  (route) => route.src === '/(.*)' && route.dest === '/',
)
check(
  internalDocRouteIndex === 0 &&
    consoleExactRouteIndex > internalDocRouteIndex &&
    consoleWildcardRouteIndex > consoleExactRouteIndex &&
    spaFallbackRouteIndex === vercelRoutes.length - 1 &&
    (!Array.isArray(vercelJson.rewrites) || vercelJson.rewrites.length === 0),
  'vercel.json must deny internal docs first, 308 redirect /console paths to console.acgs.ai, and keep SPA fallback last.',
)
const marketingHeaders =
  vercelJson.headers?.find((entry) => entry.source === '/(.*)')?.headers ?? []
const marketingReportOnlyCsp =
  marketingHeaders.find((header) => header.key === 'Content-Security-Policy-Report-Only')?.value ??
  ''
check(
  marketingReportOnlyCsp.includes("default-src 'self'") &&
    marketingReportOnlyCsp.includes("script-src 'self'") &&
    marketingReportOnlyCsp.includes("font-src 'self'") &&
    marketingReportOnlyCsp.includes('report-uri https://csp-report.acgs.ai/marketing') &&
    !marketingHeaders.some((header) => header.key === 'Content-Security-Policy'),
  'vercel.json must set marketing Content-Security-Policy-Report-Only without enforcing CSP before cutover.',
)
check(
  /pnpm build:marketing/.test(marketingWorkflow),
  'marketing.yml must verify the marketing-only build profile.',
)
check(
  /pnpm build:console/.test(consoleWorkflow),
  'console.yml must verify the console-only build profile.',
)
check(
  /name:\s+Readiness gate[\s\S]*run:\s+pnpm test:all/.test(consoleWorkflow) &&
    consoleWorkflow.indexOf('pnpm test:all') < consoleWorkflow.indexOf('Auth to GCP via WIF') &&
    consoleWorkflow.indexOf('pnpm test:all') < consoleWorkflow.indexOf('Build & push image') &&
    consoleWorkflow.indexOf('pnpm test:all') < consoleWorkflow.indexOf('Deploy to Cloud Run'),
  'console.yml must run pnpm test:all before any credentialed image push or Cloud Run deploy step.',
)
check(
  /name:\s+Readiness gate[\s\S]*run:\s+pnpm test:all/.test(marketingWorkflow) &&
    marketingWorkflow.indexOf('pnpm test:all') <
      marketingWorkflow.indexOf('Check Vercel secrets present') &&
    marketingWorkflow.indexOf('pnpm test:all') <
      marketingWorkflow.indexOf('Pull Vercel environment') &&
    marketingWorkflow.indexOf('pnpm test:all') < marketingWorkflow.indexOf('Deploy'),
  'marketing.yml must run pnpm test:all before any credentialed Vercel deploy step.',
)
check(
  (consoleWorkflow.match(/acgi-ai\/scripts\/\*\*/g) ?? []).length >= 2 &&
    (consoleWorkflow.match(/acgi-ai\/DEPLOY\.md/g) ?? []).length >= 2 &&
    (consoleWorkflow.match(/acgi-ai\/hosted-storybook-proof\.example\.json/g) ?? []).length >= 2 &&
    (consoleWorkflow.match(/docs\/integration-readiness-task-map\.md/g) ?? []).length >= 2,
  'console.yml path filters must include readiness scripts, hosted Storybook proof template, and deploy/readiness docs for both PR and push triggers.',
)
check(
  !/paths-ignore:[\s\S]*acgi-ai\/DEPLOY\.md[\s\S]*concurrency:/.test(marketingWorkflow),
  'marketing.yml must not ignore acgi-ai/DEPLOY.md because deploy-contract edits must run the readiness gate.',
)
check(existsSync(surfaceCheckPath), 'scripts/check-surface-bundles.mjs must exist.')
check(
  /build:marketing/.test(surfaceCheck) &&
    /build:console/.test(surfaceCheck) &&
    /Action control/.test(surfaceCheck) &&
    /marketing artifact/i.test(surfaceCheck),
  'surface bundle verification must build both surfaces and scan for console-only sentinels in the marketing artifact.',
)
check(
  /handle \/healthz \{[\s\S]*"served_hash":"608508a9bd224290"[\s\S]*"build_id":"\{\$ACGI_BUILD_ID:local\}"/.test(
    caddyfile,
  ),
  'infra/Caddyfile /healthz must expose served_hash and env-backed build_id.',
)
check(
  /handle \/api\/\* \{[\s\S]*reverse_proxy\s+\{\$BUS_UPSTREAM:[^}]+\}[\s\S]*header_up\s+X-ACGS-Schema-Version\s+"\{\$ACGS_SCHEMA_VERSION:v1\}"[\s\S]*header_down\s+X-ACGS-Schema-Version\s+"\{\$ACGS_SCHEMA_VERSION:v1\}"/.test(
    caddyfile,
  ) && !/API not yet wired/.test(caddyfile),
  'infra/Caddyfile must proxy /api/* to BUS_UPSTREAM with X-ACGS-Schema-Version instead of static 503.',
)
check(
  /name:\s+ACGI_BUILD_ID[\s\S]*value:\s+"REPLACE_BUILD_ID_AT_DEPLOY_TIME"/.test(cloudRunService),
  'infra/cloudrun/service.yaml must carry an ACGI_BUILD_ID placeholder.',
)
check(
  /name:\s+BUS_UPSTREAM[\s\S]*value:\s+"REPLACE_BUS_UPSTREAM_AT_DEPLOY_TIME"/.test(
    cloudRunService,
  ) && /name:\s+ACGS_SCHEMA_VERSION[\s\S]*value:\s+"v1"/.test(cloudRunService),
  'infra/cloudrun/service.yaml must carry BUS_UPSTREAM and ACGS_SCHEMA_VERSION env wiring.',
)
check(
  /REPLACE_BUILD_ID_AT_DEPLOY_TIME/.test(cloudRunRenderer) &&
    /\$\{GITHUB_SHA::12\}/.test(consoleWorkflow) &&
    /--build-id "\$\{BUILD_ID\}"/.test(consoleWorkflow) &&
    /EXPECTED_BUILD_ID="\$BUILD_ID"/.test(consoleWorkflow),
  'console.yml must render build_id from the deployed git SHA and smoke-test it.',
)
check(
  /CONSOLE_BUS_UPSTREAM/.test(consoleWorkflow) &&
    /REPLACE_BUS_UPSTREAM_AT_DEPLOY_TIME/.test(cloudRunRenderer) &&
    /BUS_UPSTREAM/.test(consoleWorkflow) &&
    /--bus-upstream "\$\{BUS_UPSTREAM\}"/.test(consoleWorkflow),
  'console.yml must require and render CONSOLE_BUS_UPSTREAM into Cloud Run before deploy.',
)
check(
  /actions\/upload-artifact@v4/.test(consoleWorkflow) &&
    /actions\/download-artifact@v4/.test(consoleWorkflow) &&
    /postdeploy-verify\.sh/.test(consoleWorkflow),
  'console.yml must run scripts/postdeploy-verify.sh against the deployed revision with the built dist artifact.',
)
check(existsSync(postdeployPath), 'scripts/postdeploy-verify.sh must exist.')
if (existsSync(postdeployPath)) {
  check(
    (statSync(postdeployPath).mode & 0o111) !== 0,
    'scripts/postdeploy-verify.sh must be executable.',
  )
}
check(
  /EXPECTED_SERVED_HASH/.test(postdeploy) &&
    /EXPECTED_BUILD_ID/.test(postdeploy) &&
    /\/healthz/.test(postdeploy) &&
    /served_hash/.test(postdeploy) &&
    /build_id/.test(postdeploy),
  'postdeploy verification must check /healthz served_hash and build_id.',
)
check(
  /Strict-Transport-Security/.test(postdeploy) &&
    /Content-Security-Policy/.test(postdeploy) &&
    /X-Frame-Options/.test(postdeploy) &&
    /Referrer-Policy/.test(postdeploy),
  'postdeploy verification must check console security headers.',
)
check(
  /style=/.test(postdeploy) && /https?:\/\//.test(postdeploy) && /assets/.test(postdeploy),
  'postdeploy verification must scan built console assets for inline styles and third-party URLs.',
)
check(
  /live deployed asset contains demo auth sentinel/.test(postdeploy) &&
    /entry document did not reference live \/assets resources/.test(postdeploy) &&
    /live deployed assets contain unexpected third-party URLs/.test(postdeploy),
  'postdeploy verification must fetch live deployed assets and reject demo auth sentinels, missing assets, and unexpected third-party URLs.',
)
check(
  existsSync(postdeployLiveAssetsCheckPath),
  'scripts/check-postdeploy-live-assets.mjs must exist.',
)
check(
  /sessionStorage\.setItem/.test(postdeployLiveAssetsCheck) &&
    /acgs\.console\.session/.test(postdeployLiveAssetsCheck) &&
    /postdeploy verifier accepted a live deployed asset/.test(postdeployLiveAssetsCheck) &&
    /test-build/.test(postdeployLiveAssetsCheck),
  'postdeploy live asset contract check must simulate clean and demo-auth-contaminated deployed assets.',
)
check(existsSync(claimMatrixPath), 'claim-matrix.json must exist for public claim honesty.')
check(
  /engineering_draft_pending_legal/.test(claimMatrix) &&
    /subprocessor-boundary/.test(claimMatrix) &&
    /production-auth-boundary/.test(claimMatrix) &&
    /wcag-manual-evidence/.test(claimMatrix),
  'claim-matrix.json must keep an engineering-draft status and cover subprocessor, auth, and WCAG claim risks.',
)
check(existsSync(claimMatrixCheckPath), 'scripts/check-claim-matrix.mjs must exist.')
check(
  /forbiddenPublicPhrases/.test(claimMatrixCheck) &&
    /production-ready/.test(claimMatrixCheck) &&
    /auditor-ready/.test(claimMatrixCheck) &&
    /publicDeployAllowed/.test(claimMatrixCheck) &&
    /test:claim-matrix/.test(claimMatrixCheck),
  'claim matrix contract check must reject public overclaims and package wiring drift.',
)
check(existsSync(busProxyCheckPath), 'scripts/check-bus-proxy-contract.mjs must exist.')
check(
  /BUS_UPSTREAM/.test(busProxyCheck) &&
    /X-ACGS-Schema-Version/.test(busProxyCheck) &&
    /API not yet wired/.test(busProxyCheck),
  'bus proxy contract check must guard BUS_UPSTREAM, schema-version headers, and removal of static 503 copy.',
)
check(existsSync(performanceBudgetCheckPath), 'scripts/check-performance-budget.mjs must exist.')
check(
  /budgets\s*=\s*\{/.test(performanceBudgetCheck) &&
    /marketing:\s*200\s*\*\s*1024/.test(performanceBudgetCheck) &&
    /console:\s*350\s*\*\s*1024/.test(performanceBudgetCheck) &&
    /test:performance/.test(performanceBudgetCheck),
  'performance budget check must guard marketing/console gzipped bundle budgets and package wiring.',
)
check(existsSync(busSchemaCheckPath), 'scripts/check-bus-schema-contract.mjs must exist.')
check(
  existsSync(resolve(root, 'contracts/bus.openapi.json')),
  'contracts/bus.openapi.json must exist.',
)
check(
  /contracts\/bus\.openapi\.json/.test(busSchemaCheck) &&
    /test:bus-schema/.test(busSchemaCheck) &&
    /codegenMatchesContract/.test(busSchemaCheck) &&
    /schema-version-skew-error\.json/.test(busSchemaCheck),
  'bus schema contract check must guard schema ownership, generated type drift, fixtures, version skew, and package wiring.',
)
check(existsSync(cloudRunTemplateCheckPath), 'scripts/check-cloudrun-templates.mjs must exist.')
check(existsSync(cloudRunRendererPath), 'scripts/render-cloudrun-service.mjs must exist.')
check(existsSync(cloudRunRendererCheckPath), 'scripts/check-cloudrun-renderer.mjs must exist.')
check(existsSync(containerPinCheckPath), 'scripts/check-container-pins.mjs must exist.')
check(
  containerPinCheck.includes('node:24-alpine') &&
    containerPinCheck.includes('caddy:2.10.2-alpine') &&
    /test:container-pins/.test(containerPinCheck) &&
    /Dockerfile\.console/.test(containerPinCheck),
  'container pin contract check must guard Node, Caddy, package wiring, and production/smoke image parity.',
)
check(
  /preview:\s*\{[\s\S]*minScale:\s*'0'/.test(cloudRunTemplateCheck) &&
    /staging:\s*\{[\s\S]*minScale:\s*'1'/.test(cloudRunTemplateCheck) &&
    /production:\s*\{[\s\S]*minScale:\s*'2'/.test(cloudRunTemplateCheck) &&
    /infra\/cloudrun\/service\.\$\{environment\}\.yaml/.test(cloudRunTemplateCheck) &&
    /test:cloudrun-templates/.test(cloudRunTemplateCheck) &&
    /render-cloudrun-service\.mjs/.test(cloudRunTemplateCheck),
  'Cloud Run template contract check must guard preview/staging/production manifests, renderer usage, and package script wiring.',
)
check(
  /replaceExactlyOnce/.test(cloudRunRenderer) &&
    /must start with http:\/\/ or https:\/\//.test(cloudRunRenderer) &&
    /rendered service.yaml still contains REPLACE_\*/.test(cloudRunRenderer) &&
    /test:cloudrun-renderer/.test(cloudRunRendererCheck),
  'Cloud Run renderer must fail closed on missing placeholders/secrets and have a package-level verifier.',
)
check(existsSync(authBoundaryCheckPath), 'scripts/check-auth-boundary.mjs must exist.')
check(
  /hasSession\(\) must always return false for demo sessionStorage in production/.test(
    authBoundaryCheck,
  ) &&
    /\/auth\/status production session bridge/.test(authBoundaryCheck) &&
    /production console bundle must not contain demo auth sentinel/.test(authBoundaryCheck) &&
    /TanStack Router scroll restoration/.test(authBoundaryCheck) &&
    /test:auth-boundary/.test(authBoundaryCheck),
  'auth boundary contract check must guard demo-auth exclusion, /auth/status bridge wiring, TanStack scroll-storage allowance, and package script wiring.',
)
check(existsSync(fontManifestPath), 'fonts.sha256 must exist for self-hosted WOFF2 provenance.')
check(existsSync(fontManifestCheckPath), 'scripts/check-font-manifest.mjs must exist.')
check(
  /createHash\(['"]sha256['"]\)/.test(fontManifestCheck) &&
    /fonts\.sha256/.test(fontManifestCheck) &&
    /src\/fonts\.css/.test(fontManifestCheck) &&
    /public\/static\/fonts/.test(fontManifestCheck) &&
    /test:font-manifest/.test(fontManifestCheck),
  'font manifest contract check must verify WOFF2 hashes, CSS references, and package script wiring.',
)
check(existsSync(trustSurfaceCheckPath), 'scripts/check-trust-surface.mjs must exist.')
check(
  /src\/routes\/Trust\.tsx/.test(trustSurfaceCheck) &&
    /src\/routes\/Security\.tsx/.test(trustSurfaceCheck) &&
    /public\/\.well-known\/security\.txt/.test(trustSurfaceCheck) &&
    /public\/subprocessors\.xml/.test(trustSurfaceCheck) &&
    /test:trust-surface/.test(trustSurfaceCheck),
  'trust surface contract check must guard trust/security routes, security.txt, subprocessor RSS, and package wiring.',
)
check(existsSync(platformBlueprintCheckPath), 'scripts/check-platform-blueprint.mjs must exist.')
check(
  /src\/routes\/Marketing\.tsx/.test(platformBlueprintCheck) &&
    /DESIGN\.md/.test(platformBlueprintCheck) &&
    /platform-ui-ux-research\.md/.test(platformBlueprintCheck) &&
    /test:platform-blueprint/.test(platformBlueprintCheck),
  'platform blueprint contract check must guard the visual workbench, design source, research memo, and package wiring.',
)
check(
  existsSync(consoleStateCoverageCheckPath),
  'scripts/check-console-state-coverage.mjs must exist.',
)
check(
  /requiredStatePrimitives/.test(consoleStateCoverageCheck) &&
    /ConsoleLoading/.test(consoleStateCoverageCheck) &&
    /PartialBus/.test(consoleStateCoverageCheck) &&
    /ExpiredSession/.test(consoleStateCoverageCheck) &&
    /emptyMeans/.test(consoleStateCoverageCheck) &&
    /test:state-coverage/.test(consoleStateCoverageCheck),
  'console state coverage check must guard the 11 state primitives, emptyMeans taxonomy, env indicator, docs, and package wiring.',
)
check(existsSync(pollingHygieneCheckPath), 'scripts/check-polling-hygiene.mjs must exist.')
check(
  /POLL_WINDOWS/.test(pollingHygieneCheck) &&
    /jitteredRefetchInterval/.test(pollingHygieneCheck) &&
    /refetchIntervalInBackground/.test(pollingHygieneCheck) &&
    /useBusHealth/.test(pollingHygieneCheck) &&
    /test:polling-hygiene/.test(pollingHygieneCheck),
  'polling hygiene check must guard jittered intervals, visibility gating, background interval disablement, bus-health backoff, docs, and package wiring.',
)
check(existsSync(sessionSyncCheckPath), 'scripts/check-session-sync.mjs must exist.')
check(
  /SESSION_SYNC_KEY/.test(sessionSyncCheck) &&
    /localStorage/.test(sessionSyncCheck) &&
    /storage/.test(sessionSyncCheck) &&
    /subscribeToSessionSync/.test(sessionSyncCheck) &&
    /hasSession/.test(sessionSyncCheck) &&
    /test:session-sync/.test(sessionSyncCheck),
  'session sync check must guard localStorage broadcast/listener wiring, console subscription, query retry session recheck, docs, and package wiring.',
)
check(existsSync(appErrorContractCheckPath), 'scripts/check-app-error-contract.mjs must exist.')
check(
  /ConsolePageErrorFallback/.test(appErrorContractCheck) &&
    /toAppError/.test(appErrorContractCheck) &&
    /react-error-boundary/.test(appErrorContractCheck) &&
    /throw\\s\+new\\s\+Error/.test(appErrorContractCheck) &&
    /test:app-errors/.test(appErrorContractCheck),
  'AppError contract check must guard console ErrorBoundary wiring, typed error details, route throw hygiene, docs, and package wiring.',
)
check(existsSync(a11yFoundationCheckPath), 'scripts/check-a11y-foundation.mjs must exist.')
check(existsSync(a11yDocPath), 'A11Y.md must exist for the accessibility foundation contract.')
check(
  /src\/routes\/Console\.tsx/.test(a11yFoundationCheck) &&
    /className="skip-link"/.test(a11yFoundationCheck) &&
    /test:a11y/.test(a11yFoundationCheck) &&
    /A11Y\.md/.test(a11yFoundationCheck) &&
    /Accessibility foundation gate/.test(a11yFoundationCheck),
  'accessibility foundation check must guard skip links, console/main landmarks, A11Y.md, and package/docs wiring.',
)
check(
  /static accessibility foundation/.test(a11yDoc) &&
    /not a WCAG conformance statement/.test(a11yDoc) &&
    /manual NVDA/.test(a11yDoc) &&
    /VoiceOver/.test(a11yDoc),
  'A11Y.md must describe the static accessibility foundation without claiming conformance.',
)
check(existsSync(dxScaffoldCheckPath), 'scripts/check-dx-scaffold.mjs must exist.')
check(
  /ARCHITECTURE\.md/.test(dxScaffoldCheck) &&
    /INTEGRATING\.md/.test(dxScaffoldCheck) &&
    /GETTING_STARTED\.md/.test(dxScaffoldCheck) &&
    /test:docs-scaffold/.test(dxScaffoldCheck) &&
    /hello/.test(dxScaffoldCheck),
  'DX scaffold contract check must guard architecture/integration/onboarding docs and script wiring.',
)
check(existsSync(runtimePrimitivesCheckPath), 'scripts/check-runtime-primitives.mjs must exist.')
check(
  /src\/lib\/flags\.ts/.test(runtimePrimitivesCheck) &&
    /src\/lib\/errors\.ts/.test(runtimePrimitivesCheck) &&
    /VITE_EVAL_MODE/.test(runtimePrimitivesCheck) &&
    /AppErrorKind/.test(runtimePrimitivesCheck) &&
    /throw\\s\+new\\s\+Error/.test(runtimePrimitivesCheck) &&
    /test:runtime-primitives/.test(runtimePrimitivesCheck),
  'runtime primitives contract check must guard typed VITE flags, AppError taxonomy, route throw hygiene, and package wiring.',
)

check(existsSync(styleBundleCheckPath), 'scripts/check-style-bundle.mjs must exist.')
check(
  /App\.css/.test(styleBundleCheck) &&
    /test:style-bundle/.test(styleBundleCheck) &&
    /\.marketing/.test(styleBundleCheck) &&
    /\.console/.test(styleBundleCheck) &&
    /\.c-banner/.test(styleBundleCheck),
  'style bundle check must guard App.css import, package wiring, and production marketing/console selectors.',
)

check(existsSync(consoleCspHarnessPath), 'scripts/check-console-csp-harness.mjs must exist.')
check(
  /style=/.test(consoleCspHarness) &&
    /Content-Security-Policy/.test(consoleCspHarness) &&
    (consoleCspHarness.includes('@tailwindcss/vite') ||
      consoleCspHarness.includes('@tailwindcss\\/vite')) &&
    /test:csp/.test(consoleCspHarness) &&
    /mockServiceWorker/.test(viteConfig),
  'console CSP harness must guard strict CSP, inline styles, Tailwind plugin usage, package wiring, and production MSW exclusion.',
)
check(existsSync(routerContractCheckPath), 'scripts/check-router-contract.mjs must exist.')
check(
  /@tanstack\/react-router/.test(routerContractCheck) &&
    /products\/\$slug/.test(routerContractCheck) &&
    /console\/\$section/.test(routerContractCheck) &&
    /validateSearch/.test(routerContractCheck) &&
    /test:router/.test(routerContractCheck),
  'router contract check must guard TanStack Router, product params, console guards, login search params, and package wiring.',
)
check(existsSync(marketingCspCheckPath), 'scripts/check-marketing-csp.mjs must exist.')
check(existsSync(vercelRouteCheckPath), 'scripts/check-vercel-routes.mjs must exist.')
check(existsSync(ciReadinessGateCheckPath), 'scripts/check-ci-readiness-gates.mjs must exist.')
check(existsSync(productionEvidenceTemplatePath), 'production-evidence.example.json must exist.')
check(
  existsSync(productionEvidenceTemplateCheckPath),
  'scripts/check-production-evidence-template.mjs must exist.',
)
check(
  existsSync(hostedStorybookProofTemplatePath),
  'hosted-storybook-proof.example.json must exist.',
)
check(
  existsSync(hostedStorybookProofTemplateCheckPath),
  'scripts/check-hosted-storybook-proof-template.mjs must exist.',
)
check(
  existsSync(hostedStorybookProofValidatorPath),
  'scripts/validate-hosted-storybook-proof.mjs must exist.',
)
check(existsSync(productionLiveVerifierPath), 'scripts/verify-production-live.mjs must exist.')
check(
  existsSync(productionLiveVerifierCheckPath),
  'scripts/check-production-live-verifier.mjs must exist.',
)
check(
  existsSync(productionBlockerReportPath),
  'scripts/build-production-blocker-report.mjs must exist.',
)
check(
  existsSync(productionBlockerReportCheckPath),
  'scripts/check-production-blocker-report.mjs must exist.',
)
check(
  existsSync(productionEvidenceValidatorPath),
  'scripts/validate-production-evidence.mjs must exist.',
)
check(
  existsSync(productionEvidenceValidatorCheckPath),
  'scripts/check-production-evidence-validator.mjs must exist.',
)
check(existsSync(wireDecisionsCheckPath), 'scripts/check-wire-decisions.mjs must exist.')
check(
  existsSync(testSurfaceFoundationCheckPath),
  'scripts/check-test-surface-foundation.mjs must exist.',
)
check(existsSync(e2eHttpFoundationCheckPath), 'scripts/check-e2e-http-foundation.mjs must exist.')
check(existsSync(e2eHttpSmokePath), 'scripts/smoke-e2e-http-shells.mjs must exist.')
check(existsSync(tthwFoundationCheckPath), 'scripts/check-tthw-foundation.mjs must exist.')
check(existsSync(mswNodeFoundationCheckPath), 'scripts/check-msw-node-foundation.mjs must exist.')
check(existsSync(mswNodeServerPath), 'src/mocks/server.ts must exist.')
check(existsSync(mswPolicyPath), 'src/mocks/policy.ts must exist.')
check(existsSync(helloWorldCheckPath), 'scripts/hello-world.sh must exist.')
check(existsSync(tthwWorkflowPath), '.github/workflows/tthw.yml must exist.')
check(existsSync(e2eSmokeFoundationCheckPath), 'scripts/check-e2e-smoke-foundation.mjs must exist.')
check(
  existsSync(visualBaselineFoundationCheckPath),
  'scripts/check-visual-baseline-foundation.mjs must exist.',
)
check(
  existsSync(browserEvidenceCapturePath),
  'scripts/capture-workbench-browser-evidence.mjs must exist.',
)
check(
  existsSync(browserEvidenceFoundationCheckPath),
  'scripts/check-browser-evidence-foundation.mjs must exist.',
)
check(
  /check-e2e-smoke-foundation\.mjs/.test(testSurfaceFoundationCheck) &&
    /check-visual-baseline-foundation\.mjs/.test(testSurfaceFoundationCheck) &&
    /smoke-e2e-http-shells\.mjs/.test(testSurfaceFoundationCheck) &&
    /test:e2e-http/.test(testSurfaceFoundationCheck) &&
    /test:test-surface/.test(testSurfaceFoundationCheck) &&
    /test:e2e/.test(testSurfaceFoundationCheck) &&
    /test:visual/.test(testSurfaceFoundationCheck),
  'test surface foundation check must guard e2e/visual manifest scripts, local E2E HTTP shell smoke, package wiring, docs, and CI/security wiring.',
)
check(
  /check-tthw-foundation\.mjs/.test(tthwFoundationCheck) &&
    /hello-world\.sh/.test(tthwFoundationCheck) &&
    /test:tthw/.test(tthwFoundationCheck) &&
    /hello:world/.test(tthwFoundationCheck) &&
    /headless browser proof remains external/.test(tthwFoundationCheck),
  'TTHW foundation check must guard the runner, workflow, package wiring, docs, and bounded browser-proof wording.',
)
check(
  /check-msw-node-foundation\.mjs/.test(mswNodeFoundationCheck) &&
    /src\/mocks\/server\.ts/.test(mswNodeFoundationCheck) &&
    /onUnhandledRequest: 'error'/.test(mswNodeFoundationCheck) &&
    /test:msw-node/.test(mswNodeFoundationCheck),
  'MSW node-mode foundation check must guard server setup, strict unhandled-request policy, package wiring, docs, and CI/security wiring.',
)
check(
  /setupServer\(\.\.\.handlers\)/.test(mswNodeServer) &&
    /onUnhandledRequest: 'error'/.test(mswNodeServer) &&
    /server\.resetHandlers\(\)/.test(mswNodeServer) &&
    /server\.close\(\)/.test(mswNodeServer),
  'src/mocks/server.ts must expose node-mode MSW setup, strict unhandled-request policy, reset, and close helpers.',
)
check(
  /MswUnhandledRequestPolicy/.test(mswPolicy) &&
    /isEvalMode/.test(mswPolicy) &&
    /return 'error'/.test(mswPolicy) &&
    /return 'bypass'/.test(mswPolicy),
  'src/mocks/policy.ts must keep eval-mode MSW strictness and local bypass policy explicit.',
)
check(
  /E2E HTTP shell foundation check/.test(e2eHttpFoundationCheck) &&
    /test:e2e-http/.test(e2eHttpFoundationCheck) &&
    /smoke-e2e-http-shells\.mjs/.test(e2eHttpFoundationCheck),
  'E2E HTTP shell foundation check must guard its package and smoke-runner wiring.',
)
check(
  /E2E_HTTP_SHELL_ROUTES/.test(e2eHttpSmoke) &&
    /CONSOLE_SIDEBAR_ROUTES/.test(e2eHttpSmoke) &&
    /VITE_BYPASS_SESSION=true/.test(e2eHttpSmoke) &&
    /VITE_USE_MOCKS=true/.test(e2eHttpSmoke) &&
    /pnpm run dev:mock/.test(e2eHttpSmoke) &&
    /browser Playwright execution remains Phase 2 work/.test(e2eHttpSmoke),
  'smoke-e2e-http-shells.mjs must guard local mock-dev route shell coverage without claiming Playwright execution.',
)
check(
  /ACGI_TTHW_BUDGET_SECONDS/.test(helloWorldCheck) &&
    /pnpm install --frozen-lockfile --ignore-workspace/.test(helloWorldCheck) &&
    /pnpm run dev:mock/.test(helloWorldCheck) &&
    /CHOKIDAR_USEPOLLING/.test(helloWorldCheck) &&
    /VITE_BYPASS_SESSION=true/.test(helloWorldCheck) &&
    /headless browser proof remains external/.test(helloWorldCheck),
  'hello-world.sh must guard budgeted install, mock dev-server launch, watcher fallback, synthetic session, and bounded browser-proof wording.',
)
check(
  /schedule:/.test(tthwWorkflow) &&
    /workflow_dispatch:/.test(tthwWorkflow) &&
    /node-version:\s*['"]24['"]/.test(tthwWorkflow) &&
    /bash acgi-ai\/scripts\/hello-world\.sh/.test(tthwWorkflow),
  'tthw.yml must run the TTHW script on Node 24 by schedule and workflow_dispatch.',
)
check(
  /E2E_SMOKE_ROUTES/.test(e2eSmokeFoundationCheck) &&
    /CONSOLE_SIDEBAR_ROUTES/.test(e2eSmokeFoundationCheck) &&
    /VITE_BYPASS_SESSION=true/.test(e2eSmokeFoundationCheck) &&
    /test:e2e/.test(e2eSmokeFoundationCheck) &&
    /manifest gate only/.test(e2eSmokeFoundationCheck),
  'E2E smoke foundation check must guard route, viewport, sidebar, and package wiring manifests.',
)
check(
  /VISUAL_VIEWPORTS/.test(visualBaselineFoundationCheck) &&
    /VISUAL_BASELINE_TARGETS/.test(visualBaselineFoundationCheck) &&
    /console agents permission-denied/.test(visualBaselineFoundationCheck) &&
    /compile receipt failure/.test(visualBaselineFoundationCheck) &&
    /test:visual/.test(visualBaselineFoundationCheck) &&
    /manifest gate only/.test(visualBaselineFoundationCheck),
  'visual baseline foundation check must guard viewport, target, threshold, and package wiring manifests.',
)
check(
  /local-browser-workbench-evidence/.test(browserEvidenceCapture) &&
    /WORKBENCH_BROWSER_TARGETS/.test(browserEvidenceCapture) &&
    /BROWSER_EVIDENCE_VIEWPORTS/.test(browserEvidenceCapture) &&
    /\/#workbench/.test(browserEvidenceCapture) &&
    /\/console\/workbench/.test(browserEvidenceCapture) &&
    /\/console\/workbench#guided-review-path/.test(browserEvidenceCapture) &&
    /\/console\/workbench#launch-proof-ladder/.test(browserEvidenceCapture) &&
    /--headless=new/.test(browserEvidenceCapture) &&
    /VITE_BYPASS_SESSION/.test(browserEvidenceCapture) &&
    /VITE_USE_MOCKS/.test(browserEvidenceCapture) &&
    /not production deployment proof/.test(browserEvidenceCapture) &&
    /not WCAG conformance proof/.test(browserEvidenceCapture),
  'capture-workbench-browser-evidence.mjs must guard local browser screenshot targets, viewports, mock-session env, and claim boundaries.',
)
check(
  /Browser evidence foundation check/.test(browserEvidenceFoundationCheck) &&
    /evidence:browser-workbench/.test(browserEvidenceFoundationCheck) &&
    /test:browser-evidence/.test(browserEvidenceFoundationCheck) &&
    /dry-run-plan/.test(browserEvidenceFoundationCheck) &&
    /browser-workbench-evidence-local/.test(browserEvidenceFoundationCheck) &&
    /not production deployment proof/.test(browserEvidenceFoundationCheck),
  'check-browser-evidence-foundation.mjs must guard package wiring, dry-run manifest shape, readiness item, docs, and claim boundaries.',
)
check(
  /internal-doc 404 route/.test(vercelRouteCheck) &&
    /https:\/\/console\.acgs\.ai\/console/.test(vercelRouteCheck) &&
    /test:vercel-routes/.test(vercelRouteCheck) &&
    /SPA fallback route must be the final/.test(vercelRouteCheck),
  'Vercel route contract check must guard internal-doc denial, console-origin redirects, package wiring, and fallback ordering.',
)
check(
  /Content-Security-Policy-Report-Only/.test(marketingCspCheck) &&
    /report-uri https:\/\/csp-report\.acgs\.ai\/marketing/.test(marketingCspCheck) &&
    /marketing vercel\.json must not enforce Content-Security-Policy/.test(marketingCspCheck) &&
    /test:marketing-csp/.test(marketingCspCheck),
  'marketing CSP contract check must guard report-only CSP directives and package script wiring.',
)

check(
  /artifactKind"\s*:\s*"production-authority-packet/.test(productionAuthorityPacket) &&
    /pending-external-authority/.test(productionAuthorityPacket) &&
    /pending-external:deploy-owner-approval/.test(productionAuthorityPacket) &&
    /dns-owner-approval/.test(productionAuthorityPacket) &&
    /auth-owner-approval/.test(productionAuthorityPacket) &&
    /claims-owner-approval/.test(productionAuthorityPacket) &&
    /not production deployment proof/.test(productionAuthorityPacket),
  'production-authority.example.json must stay a claim-safe pending authority packet template.',
)
check(
  /Production authority packet check/.test(productionAuthorityPacketCheck) &&
    /test:production-authority-packet/.test(productionAuthorityPacketCheck) &&
    /production-authority\.example\.json/.test(productionAuthorityPacketCheck) &&
    /pending-external:deploy-owner-approval/.test(productionAuthorityPacketCheck) &&
    /not production deployment proof/.test(productionAuthorityPacketCheck),
  'Production authority packet check must guard packet wiring, package script, docs wiring, pending-external approvals, and claim boundary.',
)
check(
  /production-evidence-template/.test(productionEvidenceTemplateCheck) &&
    /production-evidence\.example\.json/.test(productionEvidenceTemplateCheck) &&
    /not live production proof/.test(productionEvidenceTemplateCheck) &&
    /pending-external/.test(productionEvidenceTemplateCheck) &&
    /claimMatrixRef/.test(productionEvidenceTemplateCheck) &&
    /criticalFindingsOpen/.test(productionEvidenceTemplateCheck) &&
    /assistiveTech/.test(productionEvidenceTemplateCheck) &&
    /verify:production-live/.test(productionEvidenceTemplateCheck) &&
    /test:production-live-verifier/.test(productionEvidenceTemplateCheck) &&
    /build:production-blocker-report/.test(productionEvidenceTemplateCheck) &&
    /test:production-blocker-report/.test(productionEvidenceTemplateCheck) &&
    /validate:production-evidence/.test(productionEvidenceTemplateCheck) &&
    /test:production-evidence-validator/.test(productionEvidenceTemplateCheck) &&
    /productionLiveBlockers/.test(productionEvidenceTemplateCheck) &&
    /validatedProductionEvidence/.test(productionEvidenceTemplateCheck) &&
    /test:production-evidence-template/.test(productionEvidenceTemplateCheck) &&
    /hosted-storybook-proof\.example\.json/.test(productionEvidenceTemplateCheck) &&
    /test:hosted-storybook-proof-template/.test(productionEvidenceTemplateCheck),
  'Production evidence template check must guard the example manifest, live-verifier, blocker-report, and validator artifact slots, package wiring, docs wiring, pending-external assurance placeholders, and claim boundary.',
)
check(
  /Production live verifier check/.test(productionLiveVerifierCheck) &&
    /verify:production-live/.test(productionLiveVerifierCheck) &&
    /test:production-live-verifier/.test(productionLiveVerifierCheck) &&
    /build:production-blocker-report/.test(productionLiveVerifierCheck) &&
    /test:production-blocker-report/.test(productionLiveVerifierCheck) &&
    /validate:production-evidence/.test(productionLiveVerifierCheck) &&
    /test:production-evidence-validator/.test(productionLiveVerifierCheck) &&
    /storybook-manifest-live/.test(productionLiveVerifierCheck) &&
    /productionLiveBlockers/.test(productionLiveVerifierCheck) &&
    /not live production proof/.test(productionLiveVerifierCheck) &&
    /production-evidence\.example\.json/.test(productionLiveVerifierCheck) &&
    /hosted-storybook-proof\.example\.json/.test(productionLiveVerifierCheck) &&
    /test:hosted-storybook-proof-template/.test(productionLiveVerifierCheck),
  'Production live verifier checker must guard package wiring, docs, production blocker reporting, and production evidence template output slot.',
)
check(
  /Production blocker report check/.test(productionBlockerReportCheck) &&
    /build:production-blocker-report/.test(productionBlockerReportCheck) &&
    /test:production-blocker-report/.test(productionBlockerReportCheck) &&
    /production-blocker-report/.test(productionBlockerReportCheck) &&
    /copyIntoProductionEvidence/.test(productionBlockerReportCheck) &&
    /productionLiveBlockers/.test(productionBlockerReportCheck) &&
    /not live production proof/.test(productionBlockerReportCheck) &&
    /build:production-cutover-plan/.test(productionBlockerReportCheck) &&
    /test:production-cutover-plan/.test(productionBlockerReportCheck),
  'Production blocker report checker must guard package wiring, docs, cutover-plan anchors, and copy-safe blocker handoff behavior.',
)
check(
  /Production evidence validator check/.test(productionEvidenceValidatorCheck) &&
    /validate:production-evidence/.test(productionEvidenceValidatorCheck) &&
    /test:production-evidence-validator/.test(productionEvidenceValidatorCheck) &&
    /production-evidence-validation/.test(productionEvidenceValidatorCheck) &&
    /--manifest/.test(productionEvidenceValidatorCheck) &&
    /--live-output/.test(productionEvidenceValidatorCheck) &&
    /--require-pass/.test(productionEvidenceValidatorCheck) &&
    /require-pass-assurance-legalClaimMatrix-verified/.test(productionEvidenceValidatorCheck) &&
    /pending external legal claim matrix assurance/.test(productionEvidenceValidatorCheck) &&
    /productionLiveBlockers/.test(productionEvidenceValidatorCheck) &&
    /validatedProductionEvidence/.test(productionEvidenceValidatorCheck) &&
    /not live production proof/.test(productionEvidenceValidatorCheck),
  'Production evidence validator checker must guard completed-manifest validation behavior and package/docs wiring.',
)

check(
  /Production cutover plan check/.test(productionCutoverPlanCheck) &&
    /build:production-cutover-plan/.test(productionCutoverPlanCheck) &&
    /test:production-cutover-plan/.test(productionCutoverPlanCheck) &&
    /production-cutover-plan/.test(productionCutoverPlanCheck) &&
    /dnsCutover/.test(productionCutoverPlanCheck) &&
    /copyIntoProductionEvidence/.test(productionCutoverPlanCheck) &&
    /not live production proof/.test(productionCutoverPlanCheck),
  'Production cutover plan checker must guard package wiring, docs, DNS cutover, and claim boundary.',
)
check(
  /production-cutover-plan/.test(productionCutoverPlan) &&
    /--live-output/.test(productionCutoverPlan) &&
    /--blocker-report/.test(productionCutoverPlan) &&
    /--require-clear/.test(productionCutoverPlan) &&
    /dnsCutover/.test(productionCutoverPlan) &&
    /requiredGitHubSecrets/.test(productionCutoverPlan) &&
    /productionLiveBlockers/.test(productionCutoverPlan) &&
    /copyIntoProductionEvidence/.test(productionCutoverPlan) &&
    /does not deploy/.test(productionCutoverPlan) &&
    /mutate DNS/.test(productionCutoverPlan) &&
    /not live production proof/.test(productionCutoverPlan),
  'Production cutover plan builder must package saved live evidence into a local DNS/deploy handoff without side effects or proof overclaims.',
)
check(
  /production-evidence-draft/.test(productionEvidenceDraft) &&
    /--live-output/.test(productionEvidenceDraft) &&
    /--blocker-report/.test(productionEvidenceDraft) &&
    /--cutover-plan/.test(productionEvidenceDraft) &&
    /deployment-blocked/.test(productionEvidenceDraft) &&
    /pending-external/.test(productionEvidenceDraft) &&
    /productionBlockerReport/.test(productionEvidenceDraft) &&
    /productionCutoverPlan/.test(productionEvidenceDraft) &&
    /does not deploy/.test(productionEvidenceDraft) &&
    /not live production proof/.test(productionEvidenceDraft),
  'build-production-evidence-draft.mjs must package saved blocked live evidence without network I/O or proof overclaims.',
)
check(
  /Production evidence draft check/.test(productionEvidenceDraftCheck) &&
    /build:production-evidence-draft/.test(productionEvidenceDraftCheck) &&
    /test:production-evidence-draft/.test(productionEvidenceDraftCheck) &&
    /production-evidence-draft/.test(productionEvidenceDraftCheck) &&
    /production-evidence\.deployment-blocked\.json/.test(productionEvidenceDraftCheck) &&
    /pending-external/.test(productionEvidenceDraftCheck),
  'check-production-evidence-draft.mjs must guard production evidence draft wiring and validator handoff.',
)
check(
  /hosted-storybook-handoff/.test(hostedStorybookHandoff) &&
    /--buyer-evidence-manifest/.test(hostedStorybookHandoff) &&
    /--live-output/.test(hostedStorybookHandoff) &&
    /--require-live-clear/.test(hostedStorybookHandoff) &&
    /storybook-manifest-live/.test(hostedStorybookHandoff) &&
    /pending-external:storybook-pages-proof/.test(hostedStorybookHandoff) &&
    /copyIntoProductionEvidence/.test(hostedStorybookHandoff) &&
    /does not deploy/.test(hostedStorybookHandoff) &&
    /mutate DNS/.test(hostedStorybookHandoff) &&
    /not live production proof/.test(hostedStorybookHandoff),
  'build-hosted-storybook-handoff.mjs must package saved Storybook publication and live evidence without side effects or proof overclaims.',
)
check(
  /artifactKind"\s*:\s*"storybook-runtime-plan/.test(storybookRuntimePlan) &&
    /pending-dependency-authority/.test(storybookRuntimePlan) &&
    /pending-external:dependency-owner-approval/.test(storybookRuntimePlan) &&
    /@storybook\/react-vite/.test(storybookRuntimePlan) &&
    /npm create storybook@latest/.test(storybookRuntimePlan) &&
    /npx storybook@latest init/.test(storybookRuntimePlan) &&
    /storybook build --output-dir storybook-static/.test(storybookRuntimePlan) &&
    /visual-governance-workbench/.test(storybookRuntimePlan) &&
    /operator-decision-rail/.test(storybookRuntimePlan) &&
    /guided-review-path/.test(storybookRuntimePlan) &&
    /launch-proof-ladder/.test(storybookRuntimePlan) &&
    /not official Storybook runtime proof/.test(storybookRuntimePlan) &&
    /not hosted Storybook proof/.test(storybookRuntimePlan) &&
    /not production deployment proof/.test(storybookRuntimePlan),
  'storybook-runtime.plan.json must keep a claim-safe pending official Storybook runtime dependency plan.',
)
check(
  /Storybook runtime plan check/.test(storybookRuntimePlanCheck) &&
    /test:storybook-runtime-plan/.test(storybookRuntimePlanCheck) &&
    /storybook-runtime\.plan\.json/.test(storybookRuntimePlanCheck) &&
    /pending-external:dependency-owner-approval/.test(storybookRuntimePlanCheck) &&
    /not official Storybook runtime proof/.test(storybookRuntimePlanCheck),
  'check-storybook-runtime-plan.mjs must guard Storybook runtime dependency plan wiring and claim boundary.',
)
check(
  /Hosted Storybook handoff check/.test(hostedStorybookHandoffCheck) &&
    /build:hosted-storybook-handoff/.test(hostedStorybookHandoffCheck) &&
    /test:hosted-storybook-handoff/.test(hostedStorybookHandoffCheck) &&
    /hosted-storybook-handoff\.json/.test(hostedStorybookHandoffCheck) &&
    /pending-external:storybook-pages-proof/.test(hostedStorybookHandoffCheck) &&
    /copyIntoProductionEvidence/.test(hostedStorybookHandoffCheck) &&
    /not live production proof/.test(hostedStorybookHandoffCheck) &&
    /hosted-storybook-proof\.example\.json/.test(hostedStorybookHandoffCheck) &&
    /test:hosted-storybook-proof-template/.test(hostedStorybookHandoffCheck),
  'check-hosted-storybook-handoff.mjs must guard hosted Storybook handoff wiring, docs, hosted-storybook-handoff.json, and claim boundary.',
)
check(
  /artifactKind"\s*:\s*"hosted-storybook-proof-template/.test(hostedStorybookProofTemplate) &&
    /template-only/.test(hostedStorybookProofTemplate) &&
    /REPLACE_WITH_STORYBOOK_WORKFLOW_RUN_URL/.test(hostedStorybookProofTemplate) &&
    /validate:hosted-storybook-proof/.test(hostedStorybookProofTemplate) &&
    /hosted-storybook-proof/.test(hostedStorybookProofTemplate) &&
    /storybook-manifest-live/.test(hostedStorybookProofTemplate) &&
    /live-storybook-manifest/.test(hostedStorybookProofTemplate) &&
    /browserEvidence/.test(hostedStorybookProofTemplate) &&
    /visual-governance-workbench/.test(hostedStorybookProofTemplate) &&
    /operator-decision-rail/.test(hostedStorybookProofTemplate) &&
    /guided-review-path/.test(hostedStorybookProofTemplate) &&
    /launch-proof-ladder/.test(hostedStorybookProofTemplate) &&
    /automatedA11yReportRefs/.test(hostedStorybookProofTemplate) &&
    /visualDiffRefs/.test(hostedStorybookProofTemplate) &&
    /copyIntoProductionEvidence/.test(hostedStorybookProofTemplate) &&
    /copyIntoProductionEvidence.hostedStorybook/.test(hostedStorybookProofTemplate) &&
    /remainingBlockerToRemove/.test(hostedStorybookProofTemplate) &&
    /hosted-storybook-buyer-evidence/.test(hostedStorybookProofTemplate) &&
    /not hosted Storybook proof/.test(hostedStorybookProofTemplate) &&
    /not official Storybook runtime proof/.test(hostedStorybookProofTemplate) &&
    /not production deployment proof/.test(hostedStorybookProofTemplate),
  'hosted-storybook-proof.example.json must keep a claim-safe hosted Storybook proof intake template.',
)
check(
  /Hosted Storybook proof template check/.test(hostedStorybookProofTemplateCheck) &&
    /test:hosted-storybook-proof-template/.test(hostedStorybookProofTemplateCheck) &&
    /validate-hosted-storybook-proof/.test(hostedStorybookProofTemplateCheck) &&
    /hosted-storybook-proof\.example\.json/.test(hostedStorybookProofTemplateCheck) &&
    /storybook-manifest-live/.test(hostedStorybookProofTemplateCheck) &&
    /browserEvidence/.test(hostedStorybookProofTemplateCheck) &&
    /visual-governance-workbench/.test(hostedStorybookProofTemplateCheck) &&
    /operator-decision-rail/.test(hostedStorybookProofTemplateCheck) &&
    /guided-review-path/.test(hostedStorybookProofTemplateCheck) &&
    /launch-proof-ladder/.test(hostedStorybookProofTemplateCheck) &&
    /visualDiffRefs/.test(hostedStorybookProofTemplateCheck) &&
    /pending-external:storybook-pages-proof/.test(hostedStorybookProofTemplateCheck) &&
    /not hosted Storybook proof/.test(hostedStorybookProofTemplateCheck),
  'check-hosted-storybook-proof-template.mjs must guard hosted Storybook proof template wiring and claim boundary.',
)
check(
  /Hosted Storybook proof validation/.test(hostedStorybookProofValidator) &&
    /hosted-storybook-proof-validation/.test(hostedStorybookProofValidator) &&
    /--proof/.test(hostedStorybookProofValidator) &&
    /--live-output/.test(hostedStorybookProofValidator) &&
    /--require-pass/.test(hostedStorybookProofValidator) &&
    /storybook-manifest-live/.test(hostedStorybookProofValidator) &&
    /live-storybook-manifest/.test(hostedStorybookProofValidator) &&
    /browserEvidence/.test(hostedStorybookProofValidator) &&
    /visual-governance-workbench/.test(hostedStorybookProofValidator) &&
    /operator-decision-rail/.test(hostedStorybookProofValidator) &&
    /guided-review-path/.test(hostedStorybookProofValidator) &&
    /launch-proof-ladder/.test(hostedStorybookProofValidator) &&
    /automatedA11yReportRefs/.test(hostedStorybookProofValidator) &&
    /visualDiffRefs/.test(hostedStorybookProofValidator) &&
    /not WCAG conformance proof/.test(hostedStorybookProofValidator) &&
    /copyIntoProductionEvidence.hostedStorybook/.test(hostedStorybookProofValidator) &&
    /not production deployment proof/.test(hostedStorybookProofValidator),
  'validate-hosted-storybook-proof.mjs must verify completed hosted Storybook proof packets without side effects or overclaims.',
)
check(
  /production-evidence-validation/.test(productionEvidenceValidator) &&
    /productionEvidenceValidationCommand/.test(productionEvidenceValidator) &&
    /productionEvidenceValidationOutputRef/.test(productionEvidenceValidator) &&
    /validatedProductionEvidence/.test(productionEvidenceValidator) &&
    /deployment-blocked/.test(productionEvidenceValidator) &&
    /deployment-blocked-live-blockers-match/.test(productionEvidenceValidator) &&
    /live-verified/.test(productionEvidenceValidator) &&
    /productionLiveStatus/.test(productionEvidenceValidator) &&
    /productionLiveBlockers/.test(productionEvidenceValidator) &&
    /--manifest/.test(productionEvidenceValidator) &&
    /--live-output/.test(productionEvidenceValidator) &&
    /--require-pass/.test(productionEvidenceValidator) &&
    /require-pass-assurance-legalClaimMatrix-verified/.test(productionEvidenceValidator) &&
    /criticalFindingsOpen/.test(productionEvidenceValidator) &&
    /assistiveTech/.test(productionEvidenceValidator) &&
    /isBlockedPendingExternalRef/.test(productionEvidenceValidator) &&
    /pending-external/.test(productionEvidenceValidator),
  'validate-production-evidence.mjs must validate completed evidence manifests against live verifier JSON without live network execution.',
)
check(
  /production-blocker-report/.test(productionBlockerReport) &&
    /--live-output/.test(productionBlockerReport) &&
    /--require-clear/.test(productionBlockerReport) &&
    /copyIntoProductionEvidence/.test(productionBlockerReport) &&
    /productionLiveStatus/.test(productionBlockerReport) &&
    /productionLiveBlockers/.test(productionBlockerReport) &&
    /does not deploy/.test(productionBlockerReport) &&
    /not live production proof/.test(productionBlockerReport),
  'build-production-blocker-report.mjs must create local blocker handoff reports without network I/O or proof overclaims.',
)
check(
  /lookup/.test(productionLiveVerifier) &&
    /fetch/.test(productionLiveVerifier) &&
    /https:\/\/console\.acgs\.ai/.test(productionLiveVerifier) &&
    /https:\/\/storybook\.acgs\.ai/.test(productionLiveVerifier) &&
    /manifest\.json/.test(productionLiveVerifier) &&
    /storybook-manifest-live/.test(productionLiveVerifier) &&
    /EXPECTED_SERVED_HASH/.test(productionLiveVerifier) &&
    /EXPECTED_BUILD_ID/.test(productionLiveVerifier) &&
    /claimBoundary/.test(productionLiveVerifier) &&
    /blockedUntil/.test(productionLiveVerifier) &&
    /blockers/.test(productionLiveVerifier) &&
    /--json/.test(productionLiveVerifier) &&
    /--timeout-ms/.test(productionLiveVerifier),
  'verify-production-live.mjs must collect DNS, HTTPS, healthz, security-header, and Storybook evidence with explicit claim boundary.',
)
check(
  /artifactKind"\s*:\s*"production-evidence-template/.test(productionEvidenceTemplate) &&
    /template-only/.test(productionEvidenceTemplate) &&
    /not live production proof/.test(productionEvidenceTemplate) &&
    /pending-external/.test(productionEvidenceTemplate) &&
    /REPLACE_WITH_LEGAL_REVIEWED_CLAIM_MATRIX_ARTIFACT_OR_HASH/.test(productionEvidenceTemplate) &&
    /REPLACE_WITH_ZERO_OPEN_CRITICAL_FINDINGS_COUNT/.test(productionEvidenceTemplate) &&
    /REPLACE_WITH_NVDA_EVIDENCE/.test(productionEvidenceTemplate) &&
    /REPLACE_WITH_BROWSER_SCREENSHOT_OR_VISUAL_DIFF_BUNDLE_ARTIFACT_OR_HASH/.test(
      productionEvidenceTemplate,
    ) &&
    /https:\/\/console\.acgs\.ai\/healthz/.test(productionEvidenceTemplate) &&
    /REPLACE_WITH_POSTDEPLOY_OUTPUT_ARTIFACT_OR_HASH/.test(productionEvidenceTemplate) &&
    /verify:production-live/.test(productionEvidenceTemplate) &&
    /REPLACE_WITH_VERIFY_PRODUCTION_LIVE_JSON_ARTIFACT_OR_HASH/.test(productionEvidenceTemplate) &&
    /REPLACE_WITH_BLOCKER_IDS_FROM_VERIFY_PRODUCTION_LIVE_OR_EMPTY_ARRAY/.test(
      productionEvidenceTemplate,
    ) &&
    /validate:production-evidence/.test(productionEvidenceTemplate) &&
    /productionLiveStatus/.test(productionEvidenceTemplate) &&
    /productionLiveBlockers/.test(productionEvidenceTemplate) &&
    /productionEvidenceValidationCommand/.test(productionEvidenceTemplate) &&
    /productionEvidenceValidationOutputRef/.test(productionEvidenceTemplate) &&
    /validatedProductionEvidence/.test(productionEvidenceTemplate) &&
    /REPLACE_WITH_VALIDATE_PRODUCTION_EVIDENCE_JSON_ARTIFACT_OR_HASH/.test(
      productionEvidenceTemplate,
    ),
  'production-evidence.example.json must stay a claim-safe template for live deploy evidence intake, live-verifier output, and validator output.',
)
check(
  /console\.yml/.test(ciReadinessGateCheck) &&
    /marketing\.yml/.test(ciReadinessGateCheck) &&
    /pnpm test:all/.test(ciReadinessGateCheck) &&
    /test:ci-gates/.test(ciReadinessGateCheck) &&
    /acgi-ai\/A11Y\.md/.test(ciReadinessGateCheck) &&
    /acgi-ai\/contracts\/\*\*/.test(ciReadinessGateCheck) &&
    /test:bus-schema/.test(ciReadinessGateCheck) &&
    /test:production-deploy-contract/.test(ciReadinessGateCheck) &&
    /test:production-launch-handoff/.test(ciReadinessGateCheck) &&
    /test:production-authority-packet/.test(ciReadinessGateCheck) &&
    /production-authority\.example\.json/.test(ciReadinessGateCheck) &&
    /pending-external:deploy-owner-approval/.test(ciReadinessGateCheck) &&
    /test:production-evidence-template/.test(ciReadinessGateCheck) &&
    /test:production-live-verifier/.test(ciReadinessGateCheck) &&
    /test:production-blocker-report/.test(ciReadinessGateCheck) &&
    /test:production-evidence-validator/.test(ciReadinessGateCheck) &&
    /test:production-cutover-plan/.test(ciReadinessGateCheck) &&
    /test:storybook-runtime-plan/.test(ciReadinessGateCheck) &&
    /storybook-runtime\.plan\.json/.test(ciReadinessGateCheck) &&
    /test:hosted-storybook-handoff/.test(ciReadinessGateCheck) &&
    /test:hosted-storybook-proof-template/.test(ciReadinessGateCheck) &&
    /validate:hosted-storybook-proof/.test(ciReadinessGateCheck) &&
    /build:hosted-storybook-handoff/.test(ciReadinessGateCheck) &&
    /hosted-storybook-handoff/.test(ciReadinessGateCheck) &&
    /hosted-storybook-proof\.example\.json/.test(ciReadinessGateCheck) &&
    /copyIntoProductionEvidence.hostedStorybook/.test(ciReadinessGateCheck) &&
    /verify:production-live/.test(ciReadinessGateCheck) &&
    /build:production-blocker-report/.test(ciReadinessGateCheck) &&
    /build:production-cutover-plan/.test(ciReadinessGateCheck) &&
    /validate:production-evidence/.test(ciReadinessGateCheck) &&
    /copyIntoProductionEvidence/.test(ciReadinessGateCheck) &&
    /productionLiveBlockers/.test(ciReadinessGateCheck) &&
    /production-evidence\.example\.json/.test(ciReadinessGateCheck) &&
    /test:performance/.test(ciReadinessGateCheck) &&
    /test:state-coverage/.test(ciReadinessGateCheck) &&
    /test:polling-hygiene/.test(ciReadinessGateCheck) &&
    /test:session-sync/.test(ciReadinessGateCheck) &&
    /test:app-errors/.test(ciReadinessGateCheck) &&
    /test:privilege-banner/.test(ciReadinessGateCheck) &&
    /test:wire-decisions/.test(ciReadinessGateCheck) &&
    /test:test-surface/.test(ciReadinessGateCheck) &&
    /test:tthw/.test(ciReadinessGateCheck) &&
    /test:e2e-http/.test(ciReadinessGateCheck) &&
    /test:browser-evidence/.test(ciReadinessGateCheck) &&
    /evidence:browser-workbench/.test(ciReadinessGateCheck) &&
    /browser-workbench-evidence-local/.test(ciReadinessGateCheck) &&
    /smoke-e2e-http-shells\.mjs/.test(ciReadinessGateCheck) &&
    /test:msw-node/.test(ciReadinessGateCheck) &&
    /check-msw-node-foundation\.mjs/.test(ciReadinessGateCheck) &&
    /src\/mocks\/server\.ts/.test(ciReadinessGateCheck) &&
    /hello-world\.sh/.test(ciReadinessGateCheck) &&
    /tthw\.yml/.test(ciReadinessGateCheck) &&
    /test:e2e/.test(ciReadinessGateCheck) &&
    /test:visual/.test(ciReadinessGateCheck) &&
    /Deploy workflow readiness gate/.test(ciReadinessGateCheck),
  'CI readiness gate check must guard console/marketing workflow gates, package wiring, A11Y/contract path filters, production evidence template, production live verifier, production blocker report, production cutover plan, hosted Storybook proof template, and production evidence validator wiring, performance wiring, state-coverage/polling/session-sync/AppError/privilege-banner/wire-decision/test-surface/E2E HTTP/TTHW/MSW node-mode wiring, and readiness-map evidence.',
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

check(
  /Login interstitial/.test(loginInterstitialCheck) &&
    /test:login-interstitial/.test(loginInterstitialCheck),
  'Login interstitial check must guard its package wiring.',
)
check(
  /Privilege banner contract/.test(privilegeBannerContractCheck) &&
    /test:privilege-banner/.test(privilegeBannerContractCheck),
  'Privilege banner contract check must guard its package wiring.',
)
check(
  /Wire decisions check/.test(wireDecisionsCheck) && /test:wire-decisions/.test(wireDecisionsCheck),
  'Wire decisions check must guard its package wiring.',
)
check(
  /Test surface foundation check/.test(testSurfaceFoundationCheck) &&
    /test:test-surface/.test(testSurfaceFoundationCheck),
  'Test surface foundation check must guard its package wiring.',
)
check(
  /E2E HTTP shell foundation check/.test(e2eHttpFoundationCheck) &&
    /test:e2e-http/.test(e2eHttpFoundationCheck),
  'E2E HTTP shell foundation check must guard its package wiring.',
)
check(
  /Browser evidence foundation check/.test(browserEvidenceFoundationCheck) &&
    /test:browser-evidence/.test(browserEvidenceFoundationCheck),
  'Browser evidence foundation check must guard its package wiring.',
)
check(
  /TTHW foundation check/.test(tthwFoundationCheck) && /test:tthw/.test(tthwFoundationCheck),
  'TTHW foundation check must guard its package wiring.',
)
check(
  /MSW node-mode foundation check/.test(mswNodeFoundationCheck) &&
    /test:msw-node/.test(mswNodeFoundationCheck),
  'MSW node-mode foundation check must guard its package wiring.',
)

if (failures.length > 0) {
  console.error('Security invariant check failed:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log('Security invariant check passed.')
