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
const consoleWireDecisions = read('src/routes/console/wire-decisions.ts')
const design = read('DESIGN.md')
const packageJson = JSON.parse(read('package.json'))
const researchPath = resolve(workspaceRoot, 'docs/platform-ui-ux-research.md')
const research = existsSync(researchPath) ? readWorkspace('docs/platform-ui-ux-research.md') : ''

mustContain(marketing, 'id="workbench"', 'Marketing workbench section')
mustContain(marketing, 'Visualized <em>work</em>', 'Marketing workbench heading')
mustContain(marketing, 'Work queue', 'Marketing workbench stages')
mustContain(marketing, 'Trace graph', 'Marketing workbench stages')
mustContain(marketing, 'Evaluation panel', 'Marketing workbench stages')
mustContain(marketing, 'Human release gate', 'Marketing workbench stages')
mustContain(marketing, 'Evidence room', 'Marketing workbench stages')
mustContain(marketing, 'NIST AI RMF', 'Marketing research inputs')
mustContain(marketing, 'OWASP GenAI Security Project', 'Marketing research inputs')
mustContain(marketing, 'OpenAI Agents SDK', 'Marketing research inputs')
mustContain(marketing, 'LangSmith + Phoenix', 'Marketing research inputs')
mustContain(marketing, 'Humanloop evaluators', 'Marketing research inputs')
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
mustContain(consoleWorkbench, 'Work queue', 'Console workbench stages')
mustContain(consoleWorkbench, 'Trace graph', 'Console workbench stages')
mustContain(consoleWorkbench, 'Evaluation panel', 'Console workbench stages')
mustContain(consoleWorkbench, 'Human release gate', 'Console workbench stages')
mustContain(consoleWorkbench, 'Evidence room', 'Console workbench stages')
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
mustContain(design, 'Do not add a dashboard color palette', 'Design source of truth')

check(existsSync(researchPath), 'docs/platform-ui-ux-research.md must exist.')
mustContain(research, 'Status: research-backed product blueprint', 'Research memo')
mustContain(research, 'NIST AI Risk Management Framework', 'Research memo')
mustContain(research, 'OWASP Top 10 for Large Language Model Applications', 'Research memo')
mustContain(research, 'OpenAI Agents SDK tracing', 'Research memo')
mustContain(research, 'LangSmith observability', 'Research memo')
mustContain(research, 'Arize Phoenix overview', 'Research memo')
mustContain(research, 'Humanloop evaluators', 'Research memo')

const blueprintStart = marketing.indexOf('const workflowStages')
const blueprintEnd = marketing.indexOf('const coverage')
const blueprintSource =
  blueprintStart >= 0 && blueprintEnd > blueprintStart
    ? marketing.slice(blueprintStart, blueprintEnd)
    : marketing

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
