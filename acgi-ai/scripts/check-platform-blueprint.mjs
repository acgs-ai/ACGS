import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const workspaceRoot = resolve(root, '..')
const failures = []

function read(path) {
  return readFileSync(resolve(root, path), 'utf8')
}

function readWorkspace(path) {
  return readFileSync(resolve(workspaceRoot, path), 'utf8')
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

function mustContain(source, needle, label) {
  check(source.includes(needle), `${label} must include ${JSON.stringify(needle)}.`)
}

const marketing = read('src/routes/Marketing.tsx')
const marketingText = marketing.replace(/\s+/g, ' ')
const consoleShell = read('src/routes/Console.tsx')
const consoleWorkbench = read('src/routes/console/Workbench.tsx')
const consoleWorkbenchText = consoleWorkbench.replace(/\s+/g, ' ')
const workbenchContent = read('src/routes/workbench-content.ts')
const workbenchContentText = workbenchContent.replace(/\s+/g, ' ')
const consoleWireDecisions = read('src/routes/console/wire-decisions.ts')
const design = read('DESIGN.md')
const packageJson = JSON.parse(read('package.json'))
const researchPath = resolve(workspaceRoot, 'docs/platform-ui-ux-research.md')
const research = existsSync(researchPath) ? readWorkspace('docs/platform-ui-ux-research.md') : ''

mustContain(marketing, "from './workbench-content'", 'Marketing shared workbench content import')
mustContain(marketing, 'WORKBENCH_STAGES.map', 'Marketing shared workbench stages')
mustContain(marketing, 'RESEARCH_INPUTS.map', 'Marketing shared research inputs')
mustContain(marketing, 'PLATFORM_REQUIREMENT_LANES.map', 'Marketing shared platform requirements')
mustContain(marketing, 'FRAMEWORK_INTEGRATION_RAIL.map', 'Marketing framework integration rail')
mustContain(marketing, 'AGENT_FRAMEWORK_STARTER_KITS.map', 'Marketing agent framework starter kits')
mustContain(marketing, 'HOSTED_STORYBOOK_RUNWAY.map', 'Marketing hosted Storybook runway')
mustContain(marketing, 'PRODUCTION_CUTOVER_LANES.map', 'Marketing shared cutover lanes')
mustContain(marketing, 'LIVE_VERIFIER_BLOCKER_LANES.map', 'Marketing shared live verifier blockers')
mustContain(marketing, 'PRODUCTION_COMMAND_RAIL.map', 'Marketing production command rail')
mustContain(marketing, 'ASSURANCE_INTAKE_LANES.map', 'Marketing shared assurance intake lanes')
mustContain(marketing, 'RELEASE_BLOCKER_QUEUE.map', 'Marketing shared release blocker queue')
mustContain(marketing, 'OPERATOR_CHECKLIST.map', 'Marketing shared operator quick start')
mustContain(marketing, 'WORKBENCH_GUIDED_PATH.map', 'Marketing shared guided path')
mustContain(marketing, 'WORKBENCH_DECISION_RAIL.map', 'Marketing shared decision rail')
mustContain(marketing, 'LAUNCH_PROOF_LANES.map', 'Marketing shared launch proof ladder')
mustContain(
  consoleWorkbench,
  "from '../workbench-content'",
  'Console shared workbench content import',
)
mustContain(consoleWorkbench, 'WORKBENCH_STAGES.map', 'Console shared workbench stages')
mustContain(
  consoleWorkbench,
  'PLATFORM_REQUIREMENT_LANES.map',
  'Console shared platform requirements',
)
mustContain(
  consoleWorkbench,
  'FRAMEWORK_INTEGRATION_RAIL.map',
  'Console framework integration rail',
)
mustContain(
  consoleWorkbench,
  'AGENT_FRAMEWORK_STARTER_KITS.map',
  'Console agent framework starter kits',
)
mustContain(consoleWorkbench, 'HOSTED_STORYBOOK_RUNWAY.map', 'Console hosted Storybook runway')
mustContain(consoleWorkbench, 'PRODUCTION_CUTOVER_LANES.map', 'Console shared cutover lanes')
mustContain(
  consoleWorkbench,
  'LIVE_VERIFIER_BLOCKER_LANES.map',
  'Console shared live verifier blockers',
)
mustContain(consoleWorkbench, 'PRODUCTION_COMMAND_RAIL.map', 'Console production command rail')
mustContain(consoleWorkbench, 'ASSURANCE_INTAKE_LANES.map', 'Console shared assurance intake lanes')
mustContain(consoleWorkbench, 'RELEASE_BLOCKER_QUEUE.map', 'Console shared release blocker queue')
mustContain(consoleWorkbench, 'OPERATOR_CHECKLIST.map', 'Console shared operator quick start')
mustContain(consoleWorkbench, 'WORKBENCH_GUIDED_PATH.map', 'Console shared guided path')
mustContain(consoleWorkbench, 'WORKBENCH_DECISION_RAIL.map', 'Console shared decision rail')
mustContain(consoleWorkbench, 'LAUNCH_PROOF_LANES.map', 'Console shared launch proof ladder')
mustContain(workbenchContent, 'WORKBENCH_READINESS_SUMMARY', 'Shared readiness summary')
mustContain(
  workbenchContent,
  '35/36 local pass · 1 hosted proof pending',
  'Shared readiness summary',
)
check(
  !workbenchContent.includes('34/35'),
  'Shared workbench content must not show stale 34/35 readiness copy.',
)

mustContain(marketing, 'id="workbench"', 'Marketing workbench section')
mustContain(marketing, 'Visualized <em>work</em>', 'Marketing workbench heading')
mustContain(workbenchContent, 'Work queue', 'Shared workbench stages')
mustContain(workbenchContent, 'Trace graph', 'Shared workbench stages')
mustContain(workbenchContent, 'Evaluation panel', 'Shared workbench stages')
mustContain(workbenchContent, 'Human release gate', 'Shared workbench stages')
mustContain(workbenchContent, 'Evidence room', 'Shared workbench stages')
mustContain(marketing, 'm-workbench-checklist', 'Marketing operator quick start')
mustContain(marketing, 'Operator quick start', 'Marketing operator quick start')
mustContain(workbenchContent, 'Start here', 'Shared operator quick start')
mustContain(workbenchContent, 'Hold release', 'Shared operator quick start')
mustContain(workbenchContent, 'Export proof', 'Shared operator quick start')
mustContain(marketing, 'm-workbench-guided', 'Marketing guided review path')
mustContain(marketing, 'Guided review path', 'Marketing guided review path')
mustContain(workbenchContent, 'WORKBENCH_GUIDED_PATH', 'Shared guided review path')
mustContain(workbenchContent, 'Choose the case', 'Shared guided review path')
mustContain(workbenchContent, 'Follow the path', 'Shared guided review path')
mustContain(workbenchContent, 'Check the hold', 'Shared guided review path')
mustContain(workbenchContent, 'Export bounded proof', 'Shared guided review path')
mustContain(marketing, 'm-workbench-decision', 'Marketing decision rail')
mustContain(marketing, 'Operator decision rail', 'Marketing decision rail')
mustContain(workbenchContent, 'WORKBENCH_DECISION_RAIL', 'Shared decision rail')
mustContain(workbenchContent, 'Pick the case', 'Shared decision rail')
mustContain(workbenchContent, 'Inspect the path', 'Shared decision rail')
mustContain(workbenchContent, 'Decide and export', 'Shared decision rail')
mustContain(marketing, 'm-workbench-proof', 'Marketing launch proof ladder')
mustContain(marketing, 'Launch proof ladder', 'Marketing launch proof ladder')
mustContain(marketing, 'm-workbench-cutover', 'Marketing saved cutover state')
mustContain(marketing, 'Current saved cutover state', 'Marketing saved cutover state')
mustContain(workbenchContent, 'Local readiness', 'Shared launch proof ladder')
mustContain(workbenchContent, 'Live verifier', 'Shared launch proof ladder')
mustContain(workbenchContent, 'Assurance packet', 'Shared launch proof ladder')
mustContain(workbenchContent, 'PRODUCTION_CUTOVER_LANES', 'Shared cutover lanes')
mustContain(workbenchContent, 'Marketing origin', 'Shared cutover lanes')
mustContain(workbenchContent, 'Console origin', 'Shared cutover lanes')
mustContain(workbenchContent, 'Storybook proof', 'Shared cutover lanes')
mustContain(workbenchContent, 'Evidence validation', 'Shared cutover lanes')
mustContain(workbenchContent, 'already-live', 'Shared cutover lanes')
mustContain(workbenchContent, 'dns-or-service-blocked', 'Shared cutover lanes')
mustContain(workbenchContent, 'dns-or-pages-blocked', 'Shared cutover lanes')
mustContain(workbenchContent, 'waiting-for-live-checks', 'Shared cutover lanes')
mustContain(workbenchContent, 'marketing-dns-live', 'Shared cutover lanes')
mustContain(workbenchContent, 'storybook-manifest-live', 'Shared cutover lanes')
mustContain(workbenchContent, 'safeToClaimProduction=false', 'Shared cutover lanes')
mustContain(workbenchContent, 'LIVE_VERIFIER_BLOCKER_LANES', 'Shared live verifier blockers')
mustContain(workbenchContent, 'Console DNS', 'Shared live verifier blockers')
mustContain(workbenchContent, 'Storybook DNS', 'Shared live verifier blockers')
mustContain(workbenchContent, 'Console health', 'Shared live verifier blockers')
mustContain(workbenchContent, 'Security headers', 'Shared live verifier blockers')
mustContain(workbenchContent, 'Storybook HTTPS', 'Shared live verifier blockers')
mustContain(workbenchContent, 'Storybook manifest', 'Shared live verifier blockers')
mustContain(workbenchContent, 'live-console-dns', 'Shared live verifier blockers')
mustContain(workbenchContent, 'live-storybook-dns', 'Shared live verifier blockers')
mustContain(workbenchContent, 'live-console-healthz', 'Shared live verifier blockers')
mustContain(workbenchContent, 'live-console-security-headers', 'Shared live verifier blockers')
mustContain(workbenchContent, 'live-storybook-https', 'Shared live verifier blockers')
mustContain(workbenchContent, 'live-storybook-manifest', 'Shared live verifier blockers')
mustContain(workbenchContent, 'PRODUCTION_COMMAND_RAIL', 'Shared production command rail')
mustContain(workbenchContent, 'Refresh blocked packet', 'Shared production command rail')
mustContain(workbenchContent, 'Rerun live verifier', 'Shared production command rail')
mustContain(workbenchContent, 'Validate production evidence', 'Shared production command rail')
mustContain(workbenchContent, 'Validate hosted Storybook', 'Shared production command rail')
mustContain(workbenchContent, 'make production-blocker-evidence', 'Shared production command rail')
mustContain(workbenchContent, 'validate:production-evidence', 'Shared production command rail')
mustContain(workbenchContent, 'validate:hosted-storybook-proof', 'Shared production command rail')
mustContain(workbenchContent, 'ASSURANCE_INTAKE_LANES', 'Shared assurance intake lanes')
mustContain(workbenchContent, 'Production authority', 'Shared assurance intake lanes')
mustContain(workbenchContent, 'Legal claim review', 'Shared assurance intake lanes')
mustContain(workbenchContent, 'Security assessment', 'Shared assurance intake lanes')
mustContain(workbenchContent, 'Manual accessibility', 'Shared assurance intake lanes')
mustContain(workbenchContent, 'Hosted buyer evidence', 'Shared assurance intake lanes')
mustContain(workbenchContent, 'pending-external-authority', 'Shared assurance intake lanes')
mustContain(workbenchContent, 'pending-external-signoff', 'Shared assurance intake lanes')
mustContain(workbenchContent, 'pending-external-report', 'Shared assurance intake lanes')
mustContain(workbenchContent, 'pending-manual-evidence', 'Shared assurance intake lanes')
mustContain(workbenchContent, 'pending-hosted-proof', 'Shared assurance intake lanes')
mustContain(workbenchContent, 'production-authority.example.json', 'Shared assurance intake lanes')
mustContain(workbenchContent, 'assurance.legalClaimMatrix', 'Shared assurance intake lanes')
mustContain(workbenchContent, 'assurance.pentest', 'Shared assurance intake lanes')
mustContain(
  workbenchContent,
  'assurance.wcagManual + NVDA+VoiceOver',
  'Shared assurance intake lanes',
)
mustContain(
  workbenchContent,
  'hosted-storybook-proof.example.json',
  'Shared assurance intake lanes',
)
mustContain(workbenchContent, 'NIST AI RMF', 'Shared research inputs')
mustContain(workbenchContent, 'ISO/IEC 42001', 'Shared research inputs')
mustContain(workbenchContent, 'EU AI Act', 'Shared research inputs')
mustContain(workbenchContent, 'OWASP GenAI Security Project', 'Shared research inputs')
mustContain(workbenchContent, 'OpenTelemetry GenAI', 'Shared research inputs')
mustContain(workbenchContent, 'OpenAI Agents SDK', 'Shared research inputs')
mustContain(workbenchContent, 'LangSmith + Phoenix', 'Shared research inputs')
mustContain(workbenchContent, 'Humanloop evaluators', 'Shared research inputs')
mustContain(workbenchContent, 'WCAG 2.2', 'Shared research inputs')
mustContain(workbenchContent, 'PLATFORM_REQUIREMENT_LANES', 'Shared platform requirements')
mustContain(workbenchContent, 'FRAMEWORK_INTEGRATION_RAIL', 'Shared framework integration rail')
mustContain(workbenchContent, 'AGENT_FRAMEWORK_STARTER_KITS', 'Shared starter kits')
mustContain(workbenchContent, 'HOSTED_STORYBOOK_RUNWAY', 'Shared hosted Storybook runway')
mustContain(workbenchContent, 'Normalize framework calls', 'Shared framework integration rail')
mustContain(workbenchContent, 'Gate before side effects', 'Shared framework integration rail')
mustContain(workbenchContent, 'Emit governed receipts', 'Shared framework integration rail')
mustContain(workbenchContent, 'Adopt without lock-in', 'Shared framework integration rail')
mustContain(workbenchContent, 'OpenAI Responses', 'Shared framework integration rail')
mustContain(workbenchContent, 'LangChain-style', 'Shared framework integration rail')
mustContain(workbenchContent, 'runtime.malformed_batch', 'Shared framework integration rail')
mustContain(workbenchContent, 'OpenAI Responses starter', 'Shared starter kits')
mustContain(workbenchContent, 'LangChain tool-call starter', 'Shared starter kits')
mustContain(workbenchContent, 'MCP / Claude / Codex hook starter', 'Shared starter kits')
mustContain(workbenchContent, 'Benchmark fixture starter', 'Shared starter kits')
mustContain(workbenchContent, 'uv run --package gove-zone gove-zone gate', 'Shared starter kits')
mustContain(workbenchContent, 'uv run --package gove-zone gove-zone setup', 'Shared starter kits')
mustContain(workbenchContent, 'uv run --package gove-zone gove-zone eval', 'Shared starter kits')
mustContain(workbenchContent, 'Pick payload → run gate → attach receipt', 'Shared starter kits')
mustContain(workbenchContent, 'Build local gallery', 'Shared hosted Storybook runway')
mustContain(workbenchContent, 'Enable Pages deploy', 'Shared hosted Storybook runway')
mustContain(workbenchContent, 'Build proof gap report', 'Shared hosted Storybook runway')
mustContain(workbenchContent, 'Verify live Storybook', 'Shared hosted Storybook runway')
mustContain(workbenchContent, 'Attach hosted proof', 'Shared hosted Storybook runway')
mustContain(
  workbenchContent,
  'pnpm -F acgi-ai run storybook:build',
  'Shared hosted Storybook runway',
)
mustContain(workbenchContent, 'STORYBOOK_PAGES_ENABLED=true', 'Shared hosted Storybook runway')
mustContain(
  workbenchContent,
  'build:hosted-storybook-proof-gap-report',
  'Shared hosted Storybook runway',
)
mustContain(
  workbenchContent,
  'hosted-storybook-proof-gap-report.json',
  'Shared hosted Storybook runway',
)
mustContain(workbenchContent, 'storybook-manifest-live', 'Shared hosted Storybook runway')
mustContain(
  workbenchContent,
  'copyIntoProductionEvidence.hostedStorybook',
  'Shared hosted Storybook runway',
)
mustContain(workbenchContent, 'Operate the governance loop', 'Shared platform requirements')
mustContain(workbenchContent, 'Hold release with context', 'Shared platform requirements')
mustContain(workbenchContent, 'Constrain agent agency', 'Shared platform requirements')
mustContain(workbenchContent, 'Make traces navigable', 'Shared platform requirements')
mustContain(workbenchContent, 'Keep the first minute obvious', 'Shared platform requirements')
mustContain(
  marketingText,
  'product blueprint, not certification or live assurance',
  'Marketing claim boundary',
)
mustContain(consoleShell, "case '/console/workbench'", 'Console workbench route')
mustContain(consoleShell, "label: 'Workbench'", 'Console workbench navigation')
mustContain(consoleWireDecisions, "path: '/console/workbench'", 'Console workbench wire decision')
mustContain(consoleWorkbench, 'workbench-console-map', 'Console workbench visual map')
mustContain(consoleWorkbench, 'id="platform-requirements"', 'Console platform requirements')
mustContain(consoleWorkbench, 'workbench-requirement-grid', 'Console platform requirements')
mustContain(consoleWorkbench, 'Framework → control → proof', 'Console platform requirements')
mustContain(marketing, 'm-workbench-requirements', 'Marketing platform requirements')
mustContain(marketing, 'Platform requirements', 'Marketing platform requirements')
mustContain(
  consoleWorkbench,
  'id="framework-integration-rail"',
  'Console framework integration rail',
)
mustContain(consoleWorkbench, 'workbench-framework-rail', 'Console framework integration rail')
mustContain(consoleWorkbench, 'Framework integration rail', 'Console framework integration rail')
mustContain(marketing, 'm-workbench-framework', 'Marketing framework integration rail')
mustContain(marketing, 'Framework integration rail', 'Marketing framework integration rail')
mustContain(consoleWorkbench, 'id="agent-framework-starter-kits"', 'Console starter kits')
mustContain(consoleWorkbench, 'workbench-starter-summary', 'Console starter kits')
mustContain(consoleWorkbench, 'Agent framework starter kits', 'Console starter kits')
mustContain(marketing, 'm-workbench-starters', 'Marketing starter kits')
mustContain(marketing, 'Agent framework starter kits', 'Marketing starter kits')
mustContain(marketing, 'm-workbench-storybook-runway', 'Marketing hosted Storybook runway')
mustContain(marketing, 'Hosted Storybook runway', 'Marketing hosted Storybook runway')
mustContain(consoleWorkbench, 'workbench-board', 'Console workbench board')
mustContain(workbenchContent, 'Work queue', 'Shared workbench stages')
mustContain(workbenchContent, 'Trace graph', 'Shared workbench stages')
mustContain(workbenchContent, 'Evaluation panel', 'Shared workbench stages')
mustContain(workbenchContent, 'Human release gate', 'Shared workbench stages')
mustContain(workbenchContent, 'Evidence room', 'Shared workbench stages')
mustContain(consoleWorkbench, 'workbench-checklist', 'Console operator quick start')
mustContain(consoleWorkbench, 'Operator quick start', 'Console operator quick start')
mustContain(consoleWorkbench, 'id="guided-review-path"', 'Console guided review path')
mustContain(consoleWorkbench, 'workbench-guided-path', 'Console guided review path')
mustContain(consoleWorkbench, 'Guided review path', 'Console guided review path')
mustContain(consoleWorkbench, 'Choose → Trace → Check → Export', 'Console guided review path')
mustContain(consoleWorkbench, 'workbench-decision-rail', 'Console decision rail')
mustContain(consoleWorkbench, 'Operator decision rail', 'Console decision rail')
mustContain(workbenchContent, 'Open queue', 'Shared operator quick start')
mustContain(workbenchContent, 'Export packet', 'Shared operator quick start')
mustContain(consoleWorkbench, 'workbench-proof-ladder', 'Console launch proof ladder')
mustContain(consoleWorkbench, 'id="launch-proof-ladder"', 'Console launch proof ladder')
mustContain(consoleWorkbench, 'Launch proof ladder', 'Console launch proof ladder')
mustContain(consoleWorkbench, 'Local → Live → Assured', 'Console launch proof ladder')
mustContain(consoleWorkbench, 'workbench-cutover-summary', 'Console saved cutover state')
mustContain(consoleWorkbench, 'Current saved cutover state', 'Console saved cutover state')
mustContain(consoleWorkbench, 'cutoverDelta=blocked-live-cutover', 'Console saved cutover state')
mustContain(marketing, 'm-workbench-live', 'Marketing live verifier blocker map')
mustContain(marketing, 'Live verifier blocker map', 'Marketing live verifier blocker map')
mustContain(consoleWorkbench, 'id="live-verifier-blocker-map"', 'Console live verifier blocker map')
mustContain(consoleWorkbench, 'workbench-live-summary', 'Console live verifier blocker map')
mustContain(consoleWorkbench, 'Live verifier blocker map', 'Console live verifier blocker map')
mustContain(marketing, 'm-workbench-command', 'Marketing production command rail')
mustContain(marketing, 'Production command rail', 'Marketing production command rail')
mustContain(consoleWorkbench, 'id="production-command-rail"', 'Console production command rail')
mustContain(consoleWorkbench, 'workbench-command-summary', 'Console production command rail')
mustContain(consoleWorkbench, 'Production command rail', 'Console production command rail')
mustContain(marketing, 'm-workbench-assurance', 'Marketing assurance proof intake')
mustContain(marketing, 'Assurance proof intake', 'Marketing assurance proof intake')
mustContain(consoleWorkbench, 'id="hosted-storybook-runway"', 'Console hosted Storybook runway')
mustContain(consoleWorkbench, 'workbench-storybook-summary', 'Console hosted Storybook runway')
mustContain(consoleWorkbench, 'Hosted Storybook runway', 'Console hosted Storybook runway')
mustContain(marketing, 'm-workbench-blockers', 'Marketing release blocker queue')
mustContain(marketing, 'Release blocker queue', 'Marketing release blocker queue')
mustContain(consoleWorkbench, 'id="assurance-proof-intake"', 'Console assurance proof intake')
mustContain(consoleWorkbench, 'workbench-assurance-summary', 'Console assurance proof intake')
mustContain(consoleWorkbench, 'Assurance proof intake', 'Console assurance proof intake')
mustContain(consoleWorkbench, 'id="release-blocker-queue"', 'Console release blocker queue')
mustContain(consoleWorkbench, 'workbench-blocker-summary', 'Console release blocker queue')
mustContain(consoleWorkbench, 'Release blocker queue', 'Console release blocker queue')
mustContain(workbenchContent, 'RELEASE_BLOCKER_QUEUE', 'Shared release blocker queue')
mustContain(workbenchContent, 'production-deployment', 'Shared release blocker queue')
mustContain(workbenchContent, 'frontend-production-auth', 'Shared release blocker queue')
mustContain(workbenchContent, 'legal-review-of-claim-matrix', 'Shared release blocker queue')
mustContain(workbenchContent, 'third-party-penetration-test', 'Shared release blocker queue')
mustContain(
  workbenchContent,
  'full-wcag-manual-screen-reader-evidence',
  'Shared release blocker queue',
)
mustContain(workbenchContent, 'hosted-storybook-buyer-evidence', 'Shared release blocker queue')
mustContain(workbenchContent, 'owner · artifact · unblock command', 'Shared release blocker queue')
mustContain(workbenchContent, 'verify:production-live', 'Shared launch proof ladder')
mustContain(workbenchContent, 'legal + pentest + WCAG + Storybook', 'Shared launch proof ladder')
mustContain(
  consoleWorkbenchText,
  'local console blueprint for easier use, not production assurance',
  'Console workbench claim boundary',
)
mustContain(consoleWorkbench, 'Local UX blueprint only', 'Console workbench claim boundary')

mustContain(design, '## Platform UX blueprint', 'Design source of truth')
mustContain(
  design,
  'work queue → trace graph → evaluation panel → human release gate → evidence room',
  'Design source of truth',
)
mustContain(design, 'Start here → Hold release → Export proof', 'Design source of truth')
mustContain(design, 'Framework → control → proof', 'Design source of truth')
mustContain(design, 'Framework integration rail', 'Design source of truth')
mustContain(design, 'Agent framework starter kits', 'Design source of truth')
mustContain(design, 'Hosted Storybook runway', 'Design source of truth')
mustContain(design, 'Choose → Trace → Check → Export', 'Design source of truth')
mustContain(design, 'Local → Live → Assured', 'Design source of truth')
mustContain(design, 'Current saved cutover state', 'Design source of truth')
mustContain(design, 'Live verifier blocker map', 'Design source of truth')
mustContain(design, 'Production command rail', 'Design source of truth')
mustContain(design, 'Assurance proof intake', 'Design source of truth')
mustContain(design, 'Do not add a dashboard color palette', 'Design source of truth')

check(existsSync(researchPath), 'docs/platform-ui-ux-research.md must exist.')
mustContain(research, 'Status: research-backed product blueprint', 'Research memo')
mustContain(research, 'NIST AI Risk Management Framework', 'Research memo')
mustContain(research, 'ISO/IEC 42001', 'Research memo')
mustContain(research, 'EU AI Act', 'Research memo')
mustContain(research, 'OWASP Top 10 for Large Language Model Applications', 'Research memo')
mustContain(research, 'OpenTelemetry', 'Research memo')
mustContain(research, 'OpenAI Agents SDK tracing', 'Research memo')
mustContain(research, 'LangSmith observability', 'Research memo')
mustContain(research, 'Arize Phoenix overview', 'Research memo')
mustContain(research, 'Humanloop evaluators', 'Research memo')
mustContain(research, 'GOV.UK Service Manual', 'Research memo')
mustContain(research, 'WCAG 2.2', 'Research memo')
mustContain(research, 'Operator quick-start path', 'Research memo')
mustContain(research, 'Platform requirements rail', 'Research memo')
mustContain(research, 'Framework integration rail', 'Research memo')
mustContain(research, 'Agent framework starter kits', 'Research memo')
mustContain(research, 'Hosted Storybook runway', 'Research memo')
mustContain(
  research,
  'OpenAI Responses, OpenAI Chat, LangChain-style, MCP-style, and Claude/Codex-style',
  'Research memo',
)
mustContain(
  research,
  'OpenAI Responses starter, LangChain tool-call starter, MCP / Claude / Codex hook starter, and Benchmark fixture starter',
  'Research memo',
)
mustContain(research, 'Govern, Regulate, Secure, Observe, Measure, and Use', 'Research memo')
mustContain(research, 'Start here, Hold release, and Export proof', 'Research memo')
mustContain(research, 'Guided review path', 'Research memo')
mustContain(
  research,
  'Choose the case, Follow the path, Check the hold, and Export bounded proof',
  'Research memo',
)
mustContain(research, 'Operator decision rail', 'Research memo')
mustContain(research, 'Pick the case, Inspect the path, and Decide and export', 'Research memo')
mustContain(research, 'Launch proof ladder', 'Research memo')
mustContain(research, 'Local readiness, Live verifier, and Assurance packet', 'Research memo')
mustContain(research, 'Current saved cutover state', 'Research memo')
mustContain(
  research,
  'Marketing origin, Console origin, Storybook proof, and Evidence validation',
  'Research memo',
)
mustContain(research, 'Live verifier blocker map', 'Research memo')
mustContain(
  research,
  'live-console-dns, live-storybook-dns, live-console-healthz, live-console-security-headers, live-storybook-https, and live-storybook-manifest',
  'Research memo',
)
mustContain(research, 'Production command rail', 'Research memo')
mustContain(research, 'make production-blocker-evidence', 'Research memo')
mustContain(
  research,
  'Build local gallery, Enable Pages deploy, Build proof gap report, Verify live Storybook, and Attach hosted proof',
  'Research memo',
)
mustContain(research, 'Assurance proof intake', 'Research memo')
mustContain(
  research,
  'Production authority, Legal claim review, Security assessment, Manual accessibility, and Hosted buyer evidence',
  'Research memo',
)
mustContain(research, 'text-first and keyboard-reviewable', 'Research memo')

const blueprintSource = [marketing, consoleWorkbench, workbenchContent].join('\n')

check(
  !/\b(certified|guaranteed|production-ready|auditor-ready|fully compliant)\b/i.test(
    blueprintSource,
  ),
  'Marketing workbench blueprint must avoid assurance and production overclaims.',
)
check(
  !/\b(certified|guaranteed|production-ready|auditor-ready|fully compliant)\b/i.test(
    consoleWorkbench,
  ),
  'Console workbench blueprint must avoid assurance and production overclaims.',
)
check(
  !/\b(certified|guaranteed|production-ready|auditor-ready|fully compliant)\b/i.test(
    workbenchContentText,
  ),
  'Shared workbench content must avoid assurance and production overclaims.',
)
check(
  packageJson.scripts?.['test:platform-blueprint'] === 'node scripts/check-platform-blueprint.mjs',
  'package.json must expose test:platform-blueprint.',
)
check(
  packageJson.scripts?.['test:all']?.includes('pnpm run test:platform-blueprint') === true,
  'package.json test:all must include test:platform-blueprint.',
)

if (failures.length > 0) {
  console.error('Platform blueprint check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Platform blueprint check passed.')
