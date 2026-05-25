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
mustContain(marketing, 'OPERATOR_CHECKLIST.map', 'Marketing shared operator quick start')
mustContain(marketing, 'LAUNCH_PROOF_LANES.map', 'Marketing shared launch proof ladder')
mustContain(
  consoleWorkbench,
  "from '../workbench-content'",
  'Console shared workbench content import',
)
mustContain(consoleWorkbench, 'WORKBENCH_STAGES.map', 'Console shared workbench stages')
mustContain(consoleWorkbench, 'OPERATOR_CHECKLIST.map', 'Console shared operator quick start')
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
mustContain(marketing, 'm-workbench-proof', 'Marketing launch proof ladder')
mustContain(marketing, 'Launch proof ladder', 'Marketing launch proof ladder')
mustContain(workbenchContent, 'Local readiness', 'Shared launch proof ladder')
mustContain(workbenchContent, 'Live verifier', 'Shared launch proof ladder')
mustContain(workbenchContent, 'Assurance packet', 'Shared launch proof ladder')
mustContain(workbenchContent, 'NIST AI RMF', 'Shared research inputs')
mustContain(workbenchContent, 'OWASP GenAI Security Project', 'Shared research inputs')
mustContain(workbenchContent, 'OpenAI Agents SDK', 'Shared research inputs')
mustContain(workbenchContent, 'LangSmith + Phoenix', 'Shared research inputs')
mustContain(workbenchContent, 'Humanloop evaluators', 'Shared research inputs')
mustContain(
  marketingText,
  'product blueprint, not certification or live assurance',
  'Marketing claim boundary',
)
mustContain(consoleShell, "case '/console/workbench'", 'Console workbench route')
mustContain(consoleShell, "label: 'Workbench'", 'Console workbench navigation')
mustContain(consoleWireDecisions, "path: '/console/workbench'", 'Console workbench wire decision')
mustContain(consoleWorkbench, 'workbench-console-map', 'Console workbench visual map')
mustContain(consoleWorkbench, 'workbench-board', 'Console workbench board')
mustContain(workbenchContent, 'Work queue', 'Shared workbench stages')
mustContain(workbenchContent, 'Trace graph', 'Shared workbench stages')
mustContain(workbenchContent, 'Evaluation panel', 'Shared workbench stages')
mustContain(workbenchContent, 'Human release gate', 'Shared workbench stages')
mustContain(workbenchContent, 'Evidence room', 'Shared workbench stages')
mustContain(consoleWorkbench, 'workbench-checklist', 'Console operator quick start')
mustContain(consoleWorkbench, 'Operator quick start', 'Console operator quick start')
mustContain(workbenchContent, 'Open queue', 'Shared operator quick start')
mustContain(workbenchContent, 'Export packet', 'Shared operator quick start')
mustContain(consoleWorkbench, 'workbench-proof-ladder', 'Console launch proof ladder')
mustContain(consoleWorkbench, 'id="launch-proof-ladder"', 'Console launch proof ladder')
mustContain(consoleWorkbench, 'Launch proof ladder', 'Console launch proof ladder')
mustContain(consoleWorkbench, 'Local → Live → Assured', 'Console launch proof ladder')
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
mustContain(design, 'Local → Live → Assured', 'Design source of truth')
mustContain(design, 'Do not add a dashboard color palette', 'Design source of truth')

check(existsSync(researchPath), 'docs/platform-ui-ux-research.md must exist.')
mustContain(research, 'Status: research-backed product blueprint', 'Research memo')
mustContain(research, 'NIST AI Risk Management Framework', 'Research memo')
mustContain(research, 'OWASP Top 10 for Large Language Model Applications', 'Research memo')
mustContain(research, 'OpenAI Agents SDK tracing', 'Research memo')
mustContain(research, 'LangSmith observability', 'Research memo')
mustContain(research, 'Arize Phoenix overview', 'Research memo')
mustContain(research, 'Humanloop evaluators', 'Research memo')
mustContain(research, 'GOV.UK Service Manual', 'Research memo')
mustContain(research, 'WCAG 2.2', 'Research memo')
mustContain(research, 'Operator quick-start path', 'Research memo')
mustContain(research, 'Start here, Hold release, and Export proof', 'Research memo')
mustContain(research, 'Launch proof ladder', 'Research memo')
mustContain(research, 'Local readiness, Live verifier, and Assurance packet', 'Research memo')
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
