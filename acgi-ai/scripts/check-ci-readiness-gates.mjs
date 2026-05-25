import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(root, '..')
const failures = []
// Artifact anchor: production-evidence.deployment-blocked.json.

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function readRepo(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), 'utf8')
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

function before(source, earlier, later, label) {
  const earlierIndex = source.indexOf(earlier)
  const laterIndex = source.indexOf(later)
  check(earlierIndex >= 0, `${label} must include ${JSON.stringify(earlier)}.`)
  check(laterIndex >= 0, `${label} must include ${JSON.stringify(later)}.`)
  check(
    earlierIndex >= 0 && laterIndex >= 0 && earlierIndex < laterIndex,
    `${label} must run ${JSON.stringify(earlier)} before ${JSON.stringify(later)}.`,
  )
}

function pathFilterCount(workflow, path) {
  return (workflow.match(new RegExp(path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) ?? []).length
}

const packageJson = JSON.parse(read('package.json'))
const consoleWorkflowPath = '.github/workflows/console.yml'
const marketingWorkflowPath = '.github/workflows/marketing.yml'
const storybookWorkflowPath = '.github/workflows/storybook.yml'
const tthwWorkflowPath = '.github/workflows/tthw.yml'
const productionDeployCheckPath = 'scripts/check-production-deploy-contract.mjs'
const productionLaunchCheckPath = 'scripts/check-production-launch-handoff.mjs'
const productionAuthorityPacketPath = 'production-authority.example.json'
const productionAuthorityPacketCheckPath = 'scripts/check-production-authority-packet.mjs'
const productionEvidenceTemplatePath = 'production-evidence.example.json'
const productionEvidenceTemplateCheckPath = 'scripts/check-production-evidence-template.mjs'
const productionLiveVerifierPath = 'scripts/verify-production-live.mjs'
const productionLiveVerifierCheckPath = 'scripts/check-production-live-verifier.mjs'
const productionBlockerReportPath = 'scripts/build-production-blocker-report.mjs'
const productionBlockerReportCheckPath = 'scripts/check-production-blocker-report.mjs'
const productionEvidenceValidatorPath = 'scripts/validate-production-evidence.mjs'
const productionEvidenceValidatorCheckPath = 'scripts/check-production-evidence-validator.mjs'
const productionCutoverPlanPath = 'scripts/build-production-cutover-plan.mjs'
const productionCutoverPlanCheckPath = 'scripts/check-production-cutover-plan.mjs'
const productionEvidenceDraftPath = 'scripts/build-production-evidence-draft.mjs'
const productionEvidenceDraftCheckPath = 'scripts/check-production-evidence-draft.mjs'
const hostedStorybookHandoffPath = 'scripts/build-hosted-storybook-handoff.mjs'
const hostedStorybookHandoffCheckPath = 'scripts/check-hosted-storybook-handoff.mjs'
const hostedStorybookProofTemplatePath = 'hosted-storybook-proof.example.json'
const hostedStorybookProofTemplateCheckPath = 'scripts/check-hosted-storybook-proof-template.mjs'
const hostedStorybookProofValidatorPath = 'scripts/validate-hosted-storybook-proof.mjs'
const storybookRuntimePlanPath = 'storybook-runtime.plan.json'
const storybookRuntimePlanCheckPath = 'scripts/check-storybook-runtime-plan.mjs'
const mswNodeFoundationCheckPath = 'scripts/check-msw-node-foundation.mjs'
const e2eHttpFoundationCheckPath = 'scripts/check-e2e-http-foundation.mjs'
const e2eHttpSmokePath = 'scripts/smoke-e2e-http-shells.mjs'
const browserEvidenceCapturePath = 'scripts/capture-workbench-browser-evidence.mjs'
const browserEvidenceFoundationCheckPath = 'scripts/check-browser-evidence-foundation.mjs'
const mswNodeServerPath = 'src/mocks/server.ts'
const consoleWorkflow = readRepo(consoleWorkflowPath)
const marketingWorkflow = readRepo(marketingWorkflowPath)
const storybookWorkflow = readRepo(storybookWorkflowPath)
const tthwWorkflow = readRepo(tthwWorkflowPath)
const productionDeployCheck = read(productionDeployCheckPath)
const productionLaunchCheck = read(productionLaunchCheckPath)
const productionAuthorityPacket = read(productionAuthorityPacketPath)
const productionAuthorityPacketCheck = read(productionAuthorityPacketCheckPath)
const productionEvidenceTemplate = read(productionEvidenceTemplatePath)
const productionEvidenceTemplateCheck = read(productionEvidenceTemplateCheckPath)
const productionLiveVerifier = read(productionLiveVerifierPath)
const productionLiveVerifierCheck = read(productionLiveVerifierCheckPath)
const productionBlockerReport = read(productionBlockerReportPath)
const productionBlockerReportCheck = read(productionBlockerReportCheckPath)
const productionEvidenceValidator = read(productionEvidenceValidatorPath)
const productionEvidenceValidatorCheck = read(productionEvidenceValidatorCheckPath)
const productionCutoverPlan = read(productionCutoverPlanPath)
const productionCutoverPlanCheck = read(productionCutoverPlanCheckPath)
const productionEvidenceDraft = read(productionEvidenceDraftPath)
const productionEvidenceDraftCheck = read(productionEvidenceDraftCheckPath)
const hostedStorybookHandoff = read(hostedStorybookHandoffPath)
const hostedStorybookHandoffCheck = read(hostedStorybookHandoffCheckPath)
const hostedStorybookProofTemplate = read(hostedStorybookProofTemplatePath)
const hostedStorybookProofTemplateCheck = read(hostedStorybookProofTemplateCheckPath)
const hostedStorybookProofValidator = read(hostedStorybookProofValidatorPath)
const storybookRuntimePlan = read(storybookRuntimePlanPath)
const storybookRuntimePlanCheck = read(storybookRuntimePlanCheckPath)
const mswNodeFoundationCheck = read(mswNodeFoundationCheckPath)
const e2eHttpFoundationCheck = read(e2eHttpFoundationCheckPath)
const e2eHttpSmoke = read(e2eHttpSmokePath)
const browserEvidenceCapture = read(browserEvidenceCapturePath)
const browserEvidenceFoundationCheck = read(browserEvidenceFoundationCheckPath)
const mswNodeServer = read(mswNodeServerPath)
const deploy = read('DEPLOY.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')

check(
  existsSync(resolve(repoRoot, consoleWorkflowPath)),
  '.github/workflows/console.yml must exist.',
)
check(
  existsSync(resolve(repoRoot, marketingWorkflowPath)),
  '.github/workflows/marketing.yml must exist.',
)
check(
  existsSync(resolve(repoRoot, storybookWorkflowPath)),
  '.github/workflows/storybook.yml must exist.',
)
check(existsSync(resolve(repoRoot, tthwWorkflowPath)), '.github/workflows/tthw.yml must exist.')
check(
  packageJson.scripts?.['test:ci-gates'] === 'node scripts/check-ci-readiness-gates.mjs',
  'package.json must expose test:ci-gates.',
)
check(
  packageJson.scripts?.['test:production-deploy-contract'] ===
    'node scripts/check-production-deploy-contract.mjs',
  'package.json must expose test:production-deploy-contract.',
)
check(
  packageJson.scripts?.['test:production-launch-handoff'] ===
    'node scripts/check-production-launch-handoff.mjs',
  'package.json must expose test:production-launch-handoff.',
)
check(
  packageJson.scripts?.['test:production-authority-packet'] ===
    'node scripts/check-production-authority-packet.mjs',
  'package.json must expose test:production-authority-packet.',
)
check(
  packageJson.scripts?.['test:production-evidence-template'] ===
    'node scripts/check-production-evidence-template.mjs',
  'package.json must expose test:production-evidence-template.',
)
check(
  packageJson.scripts?.['verify:production-live'] === 'node scripts/verify-production-live.mjs',
  'package.json must expose verify:production-live.',
)
check(
  packageJson.scripts?.['test:production-live-verifier'] ===
    'node scripts/check-production-live-verifier.mjs',
  'package.json must expose test:production-live-verifier.',
)
check(
  packageJson.scripts?.['build:production-blocker-report'] ===
    'node scripts/build-production-blocker-report.mjs',
  'package.json must expose build:production-blocker-report.',
)
check(
  packageJson.scripts?.['test:production-blocker-report'] ===
    'node scripts/check-production-blocker-report.mjs',
  'package.json must expose test:production-blocker-report.',
)
check(
  packageJson.scripts?.['validate:production-evidence'] ===
    'node scripts/validate-production-evidence.mjs',
  'package.json must expose validate:production-evidence.',
)
check(
  packageJson.scripts?.['test:production-evidence-validator'] ===
    'node scripts/check-production-evidence-validator.mjs',
  'package.json must expose test:production-evidence-validator.',
)
check(
  packageJson.scripts?.['build:production-cutover-plan'] ===
    'node scripts/build-production-cutover-plan.mjs',
  'package.json must expose build:production-cutover-plan.',
)
check(
  packageJson.scripts?.['test:production-cutover-plan'] ===
    'node scripts/check-production-cutover-plan.mjs',
  'package.json must expose test:production-cutover-plan.',
)
check(
  packageJson.scripts?.['build:production-evidence-draft'] ===
    'node scripts/build-production-evidence-draft.mjs',
  'package.json must expose build:production-evidence-draft.',
)
check(
  packageJson.scripts?.['test:production-evidence-draft'] ===
    'node scripts/check-production-evidence-draft.mjs',
  'package.json must expose test:production-evidence-draft.',
)
check(
  packageJson.scripts?.['validate:hosted-storybook-proof'] ===
    'node scripts/validate-hosted-storybook-proof.mjs',
  'package.json must expose validate:hosted-storybook-proof.',
)
check(
  packageJson.scripts?.['build:hosted-storybook-handoff'] ===
    'node scripts/build-hosted-storybook-handoff.mjs',
  'package.json must expose build:hosted-storybook-handoff.',
)
check(
  packageJson.scripts?.['test:hosted-storybook-handoff'] ===
    'node scripts/check-hosted-storybook-handoff.mjs',
  'package.json must expose test:hosted-storybook-handoff.',
)
check(
  packageJson.scripts?.['test:hosted-storybook-proof-template'] ===
    'node scripts/check-hosted-storybook-proof-template.mjs',
  'package.json must expose test:hosted-storybook-proof-template.',
)
check(
  packageJson.scripts?.['test:storybook-runtime-plan'] ===
    'node scripts/check-storybook-runtime-plan.mjs',
  'package.json must expose test:storybook-runtime-plan.',
)
check(
  packageJson.scripts?.['test:msw-node'] === 'node scripts/check-msw-node-foundation.mjs',
  'package.json must expose test:msw-node.',
)
check(
  packageJson.scripts?.['test:e2e-http'] === 'node scripts/smoke-e2e-http-shells.mjs',
  'package.json must expose test:e2e-http.',
)
check(
  packageJson.scripts?.['evidence:browser-workbench'] ===
    'node scripts/capture-workbench-browser-evidence.mjs',
  'package.json must expose evidence:browser-workbench.',
)
check(
  packageJson.scripts?.['test:browser-evidence'] ===
    'node scripts/check-browser-evidence-foundation.mjs',
  'package.json must expose test:browser-evidence.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:ci-gates') &&
    packageJson.scripts['test:all'].includes('pnpm run test:bus-schema') &&
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
    packageJson.scripts['test:all'].includes('pnpm run test:performance') &&
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
    packageJson.scripts['test:all'].includes('pnpm run test:tthw') &&
    packageJson.scripts['test:all'].includes('pnpm run test:e2e-http') &&
    packageJson.scripts['test:all'].includes('pnpm run test:browser-evidence') &&
    !packageJson.scripts['test:all'].includes('pnpm run evidence:browser-workbench') &&
    packageJson.scripts['test:all'].includes('pnpm run test:msw-node'),
  'package.json test:all must include test:ci-gates, test:bus-schema, test:cloudrun-renderer, test:production-deploy-contract, test:production-launch-handoff, test:production-authority-packet, test:production-evidence-template, test:production-live-verifier, test:production-blocker-report, test:production-evidence-validator, test:production-cutover-plan, test:production-evidence-draft, test:hosted-storybook-handoff, test:hosted-storybook-proof-template, test:performance, test:state-coverage, test:polling-hygiene, test:session-sync, test:login-interstitial, test:privilege-banner, test:wire-decisions, test:test-surface, test:buyer-evidence, test:storybook-runtime-plan, test:storybook-publication, test:hosted-storybook-handoff, test:hosted-storybook-proof-template, test:tthw, test:e2e-http, test:browser-evidence, test:msw-node, and test:app-errors; it must not run live/operator-specific production proof commands.',
)

for (const [label, workflow] of [
  ['console.yml', consoleWorkflow],
  ['marketing.yml', marketingWorkflow],
]) {
  check(/node-version:\s*['"]24['"]/.test(workflow), `${label} must run Node 24.`)
  check(
    /name:\s+Readiness gate[\s\S]*run:\s+pnpm test:all/.test(workflow),
    `${label} must run pnpm test:all in a named Readiness gate step.`,
  )
}

check(
  /name:\s+Verify buyer evidence publication contract[\s\S]*pnpm test:storybook-runtime-plan && pnpm test:storybook-publication && pnpm test:hosted-storybook-handoff && pnpm test:hosted-storybook-proof-template/.test(
    storybookWorkflow,
  ),
  'storybook.yml must run runtime, publication, hosted handoff, and hosted proof-template checks before artifact upload/deploy.',
)

before(consoleWorkflow, 'pnpm test:all', 'Auth to GCP via WIF', 'console.yml')
before(consoleWorkflow, 'pnpm test:all', 'Build buyer evidence gallery artifact', 'console.yml')
before(
  consoleWorkflow,
  'Build buyer evidence gallery artifact',
  'Upload buyer evidence gallery artifact',
  'console.yml',
)
before(
  consoleWorkflow,
  'Upload buyer evidence gallery artifact',
  'Auth to GCP via WIF',
  'console.yml',
)
before(consoleWorkflow, 'pnpm test:all', 'Build & push image', 'console.yml')
before(consoleWorkflow, 'pnpm test:all', 'Deploy to Cloud Run', 'console.yml')
before(marketingWorkflow, 'pnpm test:all', 'Check Vercel secrets present', 'marketing.yml')
before(marketingWorkflow, 'pnpm test:all', 'Pull Vercel environment', 'marketing.yml')
before(marketingWorkflow, 'pnpm test:all', 'Deploy', 'marketing.yml')

check(
  /::error::Vercel production deploy blocked/.test(marketingWorkflow) &&
    /exit 1/.test(marketingWorkflow) &&
    !/::warning::Vercel deploy skipped/.test(marketingWorkflow) &&
    !/available=false/.test(marketingWorkflow),
  'marketing.yml must fail closed instead of warning/skipping when production Vercel secrets are missing.',
)
check(
  /Production deploy contract check/.test(productionDeployCheck) &&
    /test:production-deploy-contract/.test(productionDeployCheck) &&
    /production deploy fail-closed/.test(productionDeployCheck),
  'check-production-deploy-contract.mjs must guard production deploy fail-closed wiring.',
)
check(
  /Production launch handoff check/.test(productionLaunchCheck) &&
    /test:production-launch-handoff/.test(productionLaunchCheck) &&
    /production launch handoff/.test(productionLaunchCheck) &&
    /Local readiness is not production deployment proof/.test(productionLaunchCheck),
  'check-production-launch-handoff.mjs must guard production launch handoff wiring.',
)
check(
  /artifactKind"\s*:\s*"production-authority-packet/.test(productionAuthorityPacket) &&
    /pending-external-authority/.test(productionAuthorityPacket) &&
    /pending-external:deploy-owner-approval/.test(productionAuthorityPacket) &&
    /dns-owner-approval/.test(productionAuthorityPacket) &&
    /auth-owner-approval/.test(productionAuthorityPacket) &&
    /claims-owner-approval/.test(productionAuthorityPacket) &&
    /not production deployment proof/.test(productionAuthorityPacket),
  'production-authority.example.json must keep a claim-safe pending authority packet template.',
)
check(
  /Production authority packet check/.test(productionAuthorityPacketCheck) &&
    /test:production-authority-packet/.test(productionAuthorityPacketCheck) &&
    /production-authority\.example\.json/.test(productionAuthorityPacketCheck) &&
    /pending-external:deploy-owner-approval/.test(productionAuthorityPacketCheck) &&
    /not production deployment proof/.test(productionAuthorityPacketCheck),
  'check-production-authority-packet.mjs must guard production authority packet wiring and claim boundary.',
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
    /validate:production-evidence/.test(productionEvidenceTemplateCheck) &&
    /test:production-evidence-validator/.test(productionEvidenceTemplateCheck) &&
    /productionLiveBlockers/.test(productionEvidenceTemplateCheck) &&
    /validatedProductionEvidence/.test(productionEvidenceTemplateCheck) &&
    /test:production-evidence-template/.test(productionEvidenceTemplateCheck) &&
    /hosted-storybook-proof\.example\.json/.test(productionEvidenceTemplateCheck) &&
    /test:hosted-storybook-proof-template/.test(productionEvidenceTemplateCheck),
  'check-production-evidence-template.mjs must guard production evidence template, live-verifier artifact wiring, and validator artifact wiring.',
)
check(
  /Production live verifier check/.test(productionLiveVerifierCheck) &&
    /verify:production-live/.test(productionLiveVerifierCheck) &&
    /test:production-live-verifier/.test(productionLiveVerifierCheck) &&
    /--json/.test(productionLiveVerifierCheck) &&
    /storybook-manifest-live/.test(productionLiveVerifierCheck) &&
    /productionLiveBlockers/.test(productionLiveVerifierCheck) &&
    /not live production proof/.test(productionLiveVerifierCheck) &&
    /production-evidence\.example\.json/.test(productionLiveVerifierCheck) &&
    /hosted-storybook-proof\.example\.json/.test(productionLiveVerifierCheck) &&
    /test:hosted-storybook-proof-template/.test(productionLiveVerifierCheck),
  'check-production-live-verifier.mjs must guard the live verifier command, package wiring, docs, and evidence template artifact slot.',
)
check(
  /Production blocker report check/.test(productionBlockerReportCheck) &&
    /build:production-blocker-report/.test(productionBlockerReportCheck) &&
    /test:production-blocker-report/.test(productionBlockerReportCheck) &&
    /production-blocker-report/.test(productionBlockerReportCheck) &&
    /copyIntoProductionEvidence/.test(productionBlockerReportCheck) &&
    /not live production proof/.test(productionBlockerReportCheck),
  'check-production-blocker-report.mjs must guard the production blocker report builder, package wiring, docs, and claim boundary.',
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
    /not live production proof/.test(productionEvidenceValidatorCheck),
  'check-production-evidence-validator.mjs must guard the completed production evidence validator wiring and behavior.',
)
check(
  /Production cutover plan check/.test(productionCutoverPlanCheck) &&
    /build:production-cutover-plan/.test(productionCutoverPlanCheck) &&
    /test:production-cutover-plan/.test(productionCutoverPlanCheck) &&
    /production-cutover-plan/.test(productionCutoverPlanCheck) &&
    /dnsCutover/.test(productionCutoverPlanCheck) &&
    /copyIntoProductionEvidence/.test(productionCutoverPlanCheck) &&
    /not live production proof/.test(productionCutoverPlanCheck),
  'check-production-cutover-plan.mjs must guard the production cutover plan builder, package wiring, docs, and claim boundary.',
)
check(
  /Production evidence draft check/.test(productionEvidenceDraftCheck) &&
    /build:production-evidence-draft/.test(productionEvidenceDraftCheck) &&
    /test:production-evidence-draft/.test(productionEvidenceDraftCheck) &&
    /production-evidence-draft/.test(productionEvidenceDraftCheck) &&
    /production-evidence\.deployment-blocked\.json/.test(productionEvidenceDraftCheck) &&
    /pending-external/.test(productionEvidenceDraftCheck) &&
    /not live production proof/.test(productionEvidenceDraftCheck),
  'check-production-evidence-draft.mjs must guard the production evidence draft builder, package wiring, docs, and validator handoff.',
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
  'build-production-evidence-draft.mjs must package saved blocked live evidence into a local manifest draft without network I/O or proof overclaims.',
)
check(
  /Hosted Storybook handoff check/.test(hostedStorybookHandoffCheck) &&
    /build:hosted-storybook-handoff/.test(hostedStorybookHandoffCheck) &&
    /test:hosted-storybook-handoff/.test(hostedStorybookHandoffCheck) &&
    /hosted-storybook-handoff/.test(hostedStorybookHandoffCheck) &&
    /hosted-storybook-handoff\.json/.test(hostedStorybookHandoffCheck) &&
    /pending-external:storybook-pages-proof/.test(hostedStorybookHandoffCheck) &&
    /copyIntoProductionEvidence/.test(hostedStorybookHandoffCheck) &&
    /not live production proof/.test(hostedStorybookHandoffCheck) &&
    /hosted-storybook-proof\.example\.json/.test(hostedStorybookHandoffCheck) &&
    /test:hosted-storybook-proof-template/.test(hostedStorybookHandoffCheck),
  'check-hosted-storybook-handoff.mjs must guard hosted Storybook handoff builder, package wiring, docs, hosted-storybook-handoff.json, and claim boundary.',
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
    /automatedA11yReportRefs/.test(hostedStorybookProofValidator) &&
    /visualDiffRefs/.test(hostedStorybookProofValidator) &&
    /not WCAG conformance proof/.test(hostedStorybookProofValidator) &&
    /not production deployment proof/.test(hostedStorybookProofValidator),
  'validate-hosted-storybook-proof.mjs must verify completed hosted proof packets without side effects or overclaims.',
)
check(
  /artifactKind"\s*:\s*"storybook-runtime-plan/.test(storybookRuntimePlan) &&
    /pending-dependency-authority/.test(storybookRuntimePlan) &&
    /pending-external:dependency-owner-approval/.test(storybookRuntimePlan) &&
    /@storybook\/react-vite/.test(storybookRuntimePlan) &&
    /npx storybook@latest init/.test(storybookRuntimePlan) &&
    /not official Storybook runtime proof/.test(storybookRuntimePlan),
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
  /hosted-storybook-handoff/.test(hostedStorybookHandoff) &&
    /--buyer-evidence-manifest/.test(hostedStorybookHandoff) &&
    /--live-output/.test(hostedStorybookHandoff) &&
    /--require-live-clear/.test(hostedStorybookHandoff) &&
    /storybook-manifest-live/.test(hostedStorybookHandoff) &&
    /pending-external:storybook-pages-proof/.test(hostedStorybookHandoff) &&
    /copyIntoProductionEvidence/.test(hostedStorybookHandoff) &&
    /does not deploy/.test(hostedStorybookHandoff) &&
    /not live production proof/.test(hostedStorybookHandoff),
  'build-hosted-storybook-handoff.mjs must package saved Storybook publication and live evidence into a local handoff without network I/O or proof overclaims.',
)
check(
  /production-evidence-validation/.test(productionEvidenceValidator) &&
    /productionEvidenceValidationCommand/.test(productionEvidenceValidator) &&
    /productionEvidenceValidationOutputRef/.test(productionEvidenceValidator) &&
    /validatedProductionEvidence/.test(productionEvidenceValidator) &&
    /deployment-blocked/.test(productionEvidenceValidator) &&
    /deployment-blocked-live-blockers-match/.test(productionEvidenceValidator) &&
    /live-verified/.test(productionEvidenceValidator) &&
    /productionLiveBlockers/.test(productionEvidenceValidator) &&
    /--manifest/.test(productionEvidenceValidator) &&
    /--live-output/.test(productionEvidenceValidator) &&
    /--require-pass/.test(productionEvidenceValidator) &&
    /require-pass-assurance-legalClaimMatrix-verified/.test(productionEvidenceValidator) &&
    /criticalFindingsOpen/.test(productionEvidenceValidator) &&
    /assistiveTech/.test(productionEvidenceValidator) &&
    /isBlockedPendingExternalRef/.test(productionEvidenceValidator) &&
    /pending-external/.test(productionEvidenceValidator),
  'validate-production-evidence.mjs must validate completed evidence manifests against live verifier JSON without performing network I/O.',
)
check(
  /production-blocker-report/.test(productionBlockerReport) &&
    /--live-output/.test(productionBlockerReport) &&
    /--require-clear/.test(productionBlockerReport) &&
    /copyIntoProductionEvidence/.test(productionBlockerReport) &&
    /productionLiveBlockers/.test(productionBlockerReport) &&
    /does not deploy/.test(productionBlockerReport) &&
    /not live production proof/.test(productionBlockerReport),
  'build-production-blocker-report.mjs must package verify-production-live JSON into a local handoff without network I/O or proof overclaims.',
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
  'build-production-cutover-plan.mjs must package saved live evidence into a local cutover handoff without DNS/deploy side effects or proof overclaims.',
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
    /--timeout-ms/.test(productionLiveVerifier),
  'verify-production-live.mjs must perform DNS/HTTPS/healthz/header/Storybook checks with explicit expected hash/build-id and claim boundary.',
)
check(
  /artifactKind"\s*:\s*"production-evidence-template/.test(productionEvidenceTemplate) &&
    /template-only/.test(productionEvidenceTemplate) &&
    /not live production proof/.test(productionEvidenceTemplate) &&
    /pending-external/.test(productionEvidenceTemplate) &&
    /REPLACE_WITH_LEGAL_REVIEWED_CLAIM_MATRIX_ARTIFACT_OR_HASH/.test(
      productionEvidenceTemplate,
    ) &&
    /REPLACE_WITH_ZERO_OPEN_CRITICAL_FINDINGS_COUNT/.test(productionEvidenceTemplate) &&
    /REPLACE_WITH_NVDA_EVIDENCE/.test(productionEvidenceTemplate) &&
    /REPLACE_WITH_BROWSER_SCREENSHOT_OR_VISUAL_DIFF_BUNDLE_ARTIFACT_OR_HASH/.test(
      productionEvidenceTemplate,
    ) &&
    /https:\/\/console\.acgs\.ai\/healthz/.test(productionEvidenceTemplate) &&
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
  'production-evidence.example.json must keep a claim-safe live evidence intake template plus live-verifier and validator output slots.',
)
check(/node-version:\s*['"]24['"]/.test(tthwWorkflow), 'tthw.yml must run Node 24.')
check(/workflow_dispatch:/.test(tthwWorkflow), 'tthw.yml must expose workflow_dispatch.')
check(/schedule:/.test(tthwWorkflow), 'tthw.yml must run on a schedule.')
check(
  /ACGI_TTHW_BUDGET_SECONDS:\s*300/.test(tthwWorkflow),
  'tthw.yml must use the 300-second TTHW budget.',
)
check(
  /run:\s+bash acgi-ai\/scripts\/hello-world\.sh/.test(tthwWorkflow),
  'tthw.yml must run bash acgi-ai/scripts/hello-world.sh.',
)
check(
  /name:\s+Build buyer evidence gallery artifact[\s\S]*run:\s+pnpm evidence:build/.test(
    consoleWorkflow,
  ) &&
    /name:\s+Upload buyer evidence gallery artifact[\s\S]*uses:\s+actions\/upload-artifact@v4[\s\S]*name:\s+buyer-evidence-gallery[\s\S]*path:\s+acgi-ai\/dist-buyer-evidence[\s\S]*if-no-files-found:\s+error/.test(
      consoleWorkflow,
    ),
  'console.yml must build and upload the buyer evidence gallery artifact before credentialed deploy steps.',
)
check(
  /E2E HTTP shell foundation check/.test(e2eHttpFoundationCheck) &&
    /test:e2e-http/.test(e2eHttpFoundationCheck) &&
    /smoke-e2e-http-shells\.mjs/.test(e2eHttpFoundationCheck),
  'check-e2e-http-foundation.mjs must guard E2E HTTP shell smoke package wiring.',
)
check(
  /E2E_HTTP_SHELL_ROUTES/.test(e2eHttpSmoke) &&
    /CONSOLE_SIDEBAR_ROUTES/.test(e2eHttpSmoke) &&
    /VITE_BYPASS_SESSION=true/.test(e2eHttpSmoke) &&
    /VITE_USE_MOCKS=true/.test(e2eHttpSmoke) &&
    /browser Playwright execution remains Phase 2 work/.test(e2eHttpSmoke),
  'smoke-e2e-http-shells.mjs must guard local route shell smoke without claiming Playwright execution.',
)
check(
  /local-browser-workbench-evidence/.test(browserEvidenceCapture) &&
    /WORKBENCH_BROWSER_TARGETS/.test(browserEvidenceCapture) &&
    /BROWSER_EVIDENCE_VIEWPORTS/.test(browserEvidenceCapture) &&
    /\/console\/workbench#launch-proof-ladder/.test(browserEvidenceCapture) &&
    /--headless=new/.test(browserEvidenceCapture) &&
    /VITE_BYPASS_SESSION/.test(browserEvidenceCapture) &&
    /not production deployment proof/.test(browserEvidenceCapture) &&
    /not WCAG conformance proof/.test(browserEvidenceCapture),
  'capture-workbench-browser-evidence.mjs must guard local browser screenshot targets, viewports, and claim boundaries.',
)
check(
  /Browser evidence foundation check/.test(browserEvidenceFoundationCheck) &&
    /evidence:browser-workbench/.test(browserEvidenceFoundationCheck) &&
    /test:browser-evidence/.test(browserEvidenceFoundationCheck) &&
    /dry-run-plan/.test(browserEvidenceFoundationCheck) &&
    /browser-workbench-evidence-local/.test(browserEvidenceFoundationCheck),
  'check-browser-evidence-foundation.mjs must guard browser-evidence package wiring, dry-run manifest, docs, and readiness wiring.',
)
check(
  /MSW node-mode foundation check/.test(mswNodeFoundationCheck) &&
    /test:msw-node/.test(mswNodeFoundationCheck) &&
    /src\/mocks\/server\.ts/.test(mswNodeFoundationCheck),
  'check-msw-node-foundation.mjs must guard MSW node-mode setup and package wiring.',
)
check(
  /setupServer\(\.\.\.handlers\)/.test(mswNodeServer) &&
    /onUnhandledRequest: 'error'/.test(mswNodeServer),
  'src/mocks/server.ts must provide strict node-mode MSW setup.',
)

for (const path of [
  'acgi-ai/scripts/**',
  'acgi-ai/contracts/**',
  'acgi-ai/DEPLOY.md',
  'acgi-ai/PRODUCTION-LAUNCH.md',
  'acgi-ai/production-authority.example.json',
  'acgi-ai/production-evidence.example.json',
  'acgi-ai/hosted-storybook-proof.example.json',
  'acgi-ai/storybook-runtime.plan.json',
  'acgi-ai/A11Y.md',
  'acgi-ai/ARCHITECTURE.md',
  'acgi-ai/INTEGRATING.md',
  'acgi-ai/GETTING_STARTED.md',
  'docs/integration-readiness-task-map.md',
]) {
  check(
    pathFilterCount(consoleWorkflow, path) >= 2,
    `console.yml pull_request and push path filters must include ${path}.`,
  )
}

for (const path of [
  'acgi-ai/scripts/build-buyer-evidence.mjs',
  'acgi-ai/scripts/check-buyer-evidence-artifact.mjs',
  'acgi-ai/scripts/check-storybook-runtime-plan.mjs',
  'acgi-ai/scripts/check-storybook-publication.mjs',
  'acgi-ai/scripts/build-hosted-storybook-handoff.mjs',
  'acgi-ai/scripts/check-hosted-storybook-handoff.mjs',
  'acgi-ai/scripts/check-hosted-storybook-proof-template.mjs',
  'acgi-ai/storybook-runtime.plan.json',
  'acgi-ai/hosted-storybook-proof.example.json',
  '.github/workflows/storybook.yml',
]) {
  check(
    pathFilterCount(storybookWorkflow, path) >= 2,
    `storybook.yml pull_request and push path filters must include ${path}.`,
  )
}

const marketingIgnoreBlock =
  marketingWorkflow.match(/paths-ignore:[\s\S]*?(?=\n\nconcurrency:)/)?.[0] ?? ''
check(
  !marketingIgnoreBlock.includes('acgi-ai/DEPLOY.md'),
  'marketing.yml must not ignore acgi-ai/DEPLOY.md because deploy-contract edits must run the readiness gate.',
)
check(
  /pnpm test:all/.test(deploy) &&
    /test:ci-gates/.test(deploy) &&
    /test:production-authority-packet/.test(deploy) &&
    /production-authority\.example\.json/.test(deploy) &&
    /test:production-evidence-template/.test(deploy) &&
    /test:production-live-verifier/.test(deploy) &&
    /test:production-blocker-report/.test(deploy) &&
    /test:production-evidence-validator/.test(deploy) &&
    /test:production-cutover-plan/.test(deploy) &&
    /test:production-evidence-draft/.test(deploy) &&
    /test:storybook-runtime-plan/.test(deploy) &&
    /storybook-runtime\.plan\.json/.test(deploy) &&
    /pending-external:dependency-owner-approval/.test(deploy) &&
    /test:hosted-storybook-handoff/.test(deploy) &&
    /test:hosted-storybook-proof-template/.test(deploy) &&
    /verify:production-live/.test(deploy) &&
    /build:production-blocker-report/.test(deploy) &&
    /build:production-cutover-plan/.test(deploy) &&
    /build:production-evidence-draft/.test(deploy) &&
    /build:hosted-storybook-handoff/.test(deploy) &&
    /hosted-storybook-handoff/.test(deploy) &&
    /hosted-storybook-proof\.example\.json/.test(deploy) &&
    /validate:production-evidence/.test(deploy) &&
    /copyIntoProductionEvidence/.test(deploy) &&
    /productionLiveBlockers/.test(deploy) &&
    /production-evidence\.example\.json/.test(deploy) &&
    /hello-world\.sh/.test(deploy) &&
    /tthw\.yml/.test(deploy),
  'DEPLOY.md must document the deploy readiness gate, CI gate verifier, production evidence template, production live verifier, production blocker report, production cutover plan, production evidence draft, Storybook runtime plan, hosted Storybook handoff, production evidence validator, and TTHW foundation workflow.',
)
check(
  /Deploy workflow readiness gate/.test(readiness) &&
    /pnpm -F acgi-ai run test:ci-gates/.test(readiness) &&
    /pnpm -F acgi-ai run test:bus-schema/.test(readiness) &&
    /pnpm -F acgi-ai run test:cloudrun-renderer/.test(readiness) &&
    /pnpm -F acgi-ai run test:production-deploy-contract/.test(readiness) &&
    /production deploy fail-closed/.test(readiness) &&
    /pnpm -F acgi-ai run test:production-launch-handoff/.test(readiness) &&
    /production launch handoff/.test(readiness) &&
    /pnpm -F acgi-ai run test:production-authority-packet/.test(readiness) &&
    /production-authority\.example\.json/.test(readiness) &&
    /pending-external:deploy-owner-approval/.test(readiness) &&
    /pnpm -F acgi-ai run test:production-evidence-template/.test(readiness) &&
    /production evidence template/.test(readiness) &&
    /production-evidence.example.json/.test(readiness) &&
    /pnpm -F acgi-ai run test:production-live-verifier/.test(readiness) &&
    /verify:production-live/.test(readiness) &&
    /pnpm -F acgi-ai run test:production-blocker-report/.test(readiness) &&
    /build:production-blocker-report/.test(readiness) &&
    /copyIntoProductionEvidence/.test(readiness) &&
    /pnpm -F acgi-ai run test:production-evidence-validator/.test(readiness) &&
    /validate:production-evidence/.test(readiness) &&
    /pnpm -F acgi-ai run test:production-cutover-plan/.test(readiness) &&
    /build:production-cutover-plan/.test(readiness) &&
    /production-cutover-plan/.test(readiness) &&
    /pnpm -F acgi-ai run test:production-evidence-draft/.test(readiness) &&
    /build:production-evidence-draft/.test(readiness) &&
    /production-evidence-draft/.test(readiness) &&
    /pnpm -F acgi-ai run test:storybook-runtime-plan/.test(readiness) &&
    /storybook-runtime\.plan\.json/.test(readiness) &&
    /pending-external:dependency-owner-approval/.test(readiness) &&
    /pnpm -F acgi-ai run test:hosted-storybook-handoff/.test(readiness) &&
    /build:hosted-storybook-handoff/.test(readiness) &&
    /hosted-storybook-handoff/.test(readiness) &&
    /hosted-storybook-handoff\.json/.test(readiness) &&
    /pnpm -F acgi-ai run test:hosted-storybook-proof-template/.test(readiness) &&
    /hosted-storybook-proof\.example\.json/.test(readiness) &&
    /productionLiveBlockers/.test(readiness) &&
    /production evidence validator/.test(readiness) &&
    /pnpm -F acgi-ai run test:performance/.test(readiness) &&
    /pnpm -F acgi-ai run test:state-coverage/.test(readiness) &&
    /pnpm -F acgi-ai run test:polling-hygiene/.test(readiness) &&
    /pnpm -F acgi-ai run test:session-sync/.test(readiness) &&
    /pnpm -F acgi-ai run test:app-errors/.test(readiness) &&
    /pnpm -F acgi-ai run test:login-interstitial/.test(readiness) &&
    /pnpm -F acgi-ai run test:privilege-banner/.test(readiness) &&
    /pnpm -F acgi-ai run test:wire-decisions/.test(readiness) &&
    /pnpm -F acgi-ai run test:test-surface/.test(readiness) &&
    /pnpm -F acgi-ai run test:buyer-evidence/.test(readiness) &&
    /pnpm -F acgi-ai run test:storybook-publication/.test(readiness) &&
    /buyer evidence gallery artifact/.test(readiness) &&
    /storybook.acgs.ai/.test(readiness) &&
    /pnpm -F acgi-ai run test:tthw/.test(readiness) &&
    /pnpm -F acgi-ai run test:e2e-http/.test(readiness) &&
    /pnpm -F acgi-ai run test:browser-evidence/.test(readiness) &&
    /pnpm -F acgi-ai run evidence:browser-workbench/.test(readiness) &&
    /browser-workbench-evidence-local/.test(readiness) &&
    /pnpm -F acgi-ai run test:msw-node/.test(readiness) &&
    /pnpm -F acgi-ai run hello:world:local/.test(readiness) &&
    /pnpm -F acgi-ai run test:e2e/.test(readiness) &&
    /pnpm -F acgi-ai run test:visual/.test(readiness),
  'integration readiness map must record the deploy workflow readiness and bus schema, Cloud Run renderer, production deploy fail-closed, production launch handoff, production authority packet, production evidence template, production live verifier, production blocker report, production cutover plan, production evidence draft, Storybook runtime plan, hosted Storybook handoff, hosted Storybook proof template, production evidence validator, performance, console state coverage, polling hygiene, session sync, login interstitial, privilege banner, wire decisions, test surface, buyer-evidence artifact, local browser workbench evidence, Storybook runtime plan, Storybook publication scaffold, hosted Storybook handoff, E2E HTTP shell, TTHW, MSW node-mode, and AppError gates.',
)

if (failures.length > 0) {
  console.error('CI readiness gate check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('CI readiness gate check passed.')
