import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const root = resolve(import.meta.dirname, '..')
const failures = []

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

const types = read('src/api/types.ts')
const client = read('src/api/client.ts')
const hooks = read('src/api/hooks.ts')
const consoleRoute = read('src/routes/Console.tsx')
const actionsRoute = read('src/routes/console/Actions.tsx')
const overviewRoute = read('src/routes/console/Overview.tsx')
const actionFixtures = read('src/mocks/data/actions.ts')
const handlers = read('src/mocks/handlers.ts')
const auditRoute = read('src/routes/console/Audit.tsx')
const policiesRoute = read('src/routes/console/Policies.tsx')
const compileRoute = read('src/routes/console/Compile.tsx')

check(
  /export type DecisionOutcome = 'allowed' \| 'denied' \| 'transformed' \| 'escalated'/.test(
    types,
  ),
  'DecisionOutcome must model allowed, denied, transformed, and escalated outcomes.',
)
check(
  /export type GovernedAction = \{[\s\S]*agent:[\s\S]*action:[\s\S]*outcome:[\s\S]*plainReason:[\s\S]*receiptId:[\s\S]*receiptHash:[\s\S]*traceId:[\s\S]*replayCommand:[\s\S]*auditEventId:[\s\S]*checks:/m.test(
    types,
  ),
  'GovernedAction must expose agent, action, outcome, reason, receipt, trace, replay, audit, and checks.',
)
check(
  /actions:\s*\{[\s\S]*list:\s*\(\) => http<GovernedAction\[]>.*\/actions[\s\S]*test:\s*\(body: ActionTestRequest\)/m.test(
    client,
  ),
  'API client must expose governed action list and pre-execution test endpoints.',
)
check(
  /useGovernedActions/.test(hooks) &&
    /useTestAction/.test(hooks) &&
    /import\.meta\.env\.PROD[\s\S]*return false/.test(hooks),
  'Hooks must expose governed action queries and keep fixture fallback disabled in production.',
)
check(
  /\/console\/actions/.test(consoleRoute) &&
    /Action <em>control<\/em>/.test(consoleRoute) &&
    /label: 'Actions'/.test(consoleRoute),
  'Console shell must route and navigate to the governed action control surface.',
)
check(
  /Verify an agent action/.test(overviewRoute) &&
    /Open action control/.test(overviewRoute) &&
    /navigate\('\/console\/actions'\)/.test(overviewRoute),
  'Overview must guide non-technical reviewers to the action control path.',
)
check(
  /What did the agent try to do\?/.test(actionsRoute) &&
    /Why did governance decide that\?/.test(actionsRoute) &&
    /Can it be verified\?/.test(actionsRoute),
  'Actions route must answer the three core governance questions.',
)
check(
  /Before governance/.test(actionsRoute) &&
    /After governance/.test(actionsRoute) &&
    /Receipt/.test(actionsRoute) &&
    /Replay/.test(actionsRoute) &&
    /Audit event/.test(actionsRoute),
  'Actions route must show before/after state, receipt, replay, and audit evidence.',
)
check(
  /Test before execution/.test(actionsRoute) &&
    /Run policy test/.test(actionsRoute) &&
    /testAction\.mutate/.test(actionsRoute),
  'Actions route must include a pre-execution policy test control.',
)
check(
  /outcome: 'denied'/.test(actionFixtures) &&
    /outcome: 'transformed'/.test(actionFixtures) &&
    /outcome: 'escalated'/.test(actionFixtures) &&
    /tool_executed":false/.test(actionFixtures),
  'Action fixtures must demonstrate denied, transformed, escalated, and no-silent-execution cases.',
)
check(
  /http\.get\('\/api\/v1\/actions'/.test(handlers) &&
    /http\.post\('\/api\/v1\/actions\/test'/.test(handlers) &&
    /No production tool was executed/.test(handlers),
  'Mock handlers must provide list and dry-run test endpoints with no production execution copy.',
)
check(
  /append-only/i.test(auditRoute) && /countersigned/i.test(auditRoute),
  'Audit route must communicate append-only, countersigned audit evidence.',
)
check(
  /compiled artifact below is what the\s+bus actually loads/.test(policiesRoute),
  'Policies route must expose safe governance-rule management context.',
)
check(
  /useReplayCompile/.test(compileRoute) && /usePromoteCompile/.test(compileRoute),
  'Compile route must retain replay/promote policy workflow controls.',
)

if (failures.length > 0) {
  console.error('Gove Zone MVP invariant check failed:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log('Gove Zone MVP invariant check passed.')
