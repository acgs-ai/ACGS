import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const root = resolve(import.meta.dirname, '..')
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

const types = read('src/api/types.ts')
const client = read('src/api/client.ts')
const hooks = read('src/api/hooks.ts')
const consoleRoute = read('src/routes/Console.tsx')
const wireDecisions = read('src/routes/console/wire-decisions.ts')
const actionsRoute = read('src/routes/console/Actions.tsx')
const auditProofRoute = maybeRead('src/routes/console/AuditProof.tsx')
const overviewRoute = read('src/routes/console/Overview.tsx')
const actionFixtures = read('src/mocks/data/actions.ts')
const auditFixtures = read('src/mocks/data/audit.ts')
const handlers = read('src/mocks/handlers.ts')
const auditRoute = read('src/routes/console/Audit.tsx')
const consoleApp = read('src/surfaces/console/App.tsx')
const policiesRoute = read('src/routes/console/Policies.tsx')
const compileRoute = read('src/routes/console/Compile.tsx')

check(
  /export type DecisionOutcome = 'allowed' \| 'denied' \| 'transformed' \| 'escalated'/.test(types),
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
    /import\.meta\.env\.PROD[\s\S]*return false/.test(hooks) &&
    /function isNetworkUnavailable\(error: unknown\): boolean/.test(hooks) &&
    /!isNetworkUnavailable\(error\)/.test(hooks),
  'Hooks must expose governed action queries and keep fixture fallback disabled in production and limited to network-unavailable errors in mock mode.',
)
check(
  /\/console\/actions/.test(consoleRoute) &&
    /label: 'Actions'/.test(consoleRoute) &&
    /getConsoleWireDecision/.test(consoleRoute) &&
    /path:\s*'\/console\/actions'[\s\S]*titleLead:\s*'Action'[\s\S]*titleEmphasis:\s*'control'/.test(
      wireDecisions,
    ),
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
  /path:\s*'\/console\/audit\/\$receiptId'/.test(consoleApp) &&
    /ConsoleAuditReceiptRoute/.test(consoleApp),
  'Console router must expose a guarded /console/audit/:receiptId proof journey route.',
)
check(
  /ReceiptProofPacket/.test(types) &&
    /signedEvidencePacket:[\s\S]*hashChainVerified:[\s\S]*policyPath:[\s\S]*toolExecuted/m.test(
      types,
    ) &&
    /phoenixTraceId\?: string[\s\S]*phoenixSpanId\?: string[\s\S]*phoenixParentSpanId\?: string/m.test(
      types,
    ),
  'Receipt proof contract must expose signed packet, hash-chain, policy path, tool execution state, and Phoenix trace ids.',
)
check(
  /export type EvidenceSignatureSummary = \{[\s\S]*status:[\s\S]*algorithm:[\s\S]*keyId\?:/m.test(
    types,
  ) && /evidenceSignature: EvidenceSignatureSummary/.test(types),
  'Receipt proof contract must expose normalized evidence signature status, algorithm, and key id metadata.',
)
check(
  /getProof:\s*\(receiptId: string\)/.test(client) &&
    /\/actions\/\$\{encodeURIComponent\(receiptId\)\}\/proof/.test(client) &&
    /getReceiptProof:\s*\(receiptId: string\)/.test(client) &&
    /\/receipts\/\$\{encodeURIComponent\(receiptId\)\}/.test(client) &&
    /useActionProof/.test(hooks) &&
    /normalizeBusReceiptProof/.test(hooks) &&
    /phoenixTraceId/.test(hooks) &&
    /phoenix_span_id/.test(hooks) &&
    /queryKey:\s*\['action-proof', receiptId\]/.test(hooks),
  'API client and hooks must load a single receipt proof by receipt ID, preferring live bus proof packets with Phoenix trace ids.',
)
check(
  /http\.get\('\/api\/v1\/actions\/:receiptId\/proof'/.test(handlers) &&
    /getGovernedActionProof/.test(handlers),
  'Mock handlers must serve a single governed-action proof packet by receipt ID.',
)
check(
  /getGovernedActionProof/.test(actionFixtures) &&
    /signedEvidencePacket/.test(actionFixtures) &&
    /phoenix_trace_id/.test(actionFixtures) &&
    /phoenixTraceId/.test(actionFixtures) &&
    /hashChainVerified:\s*true/.test(actionFixtures) &&
    /toolExecuted:\s*false/.test(actionFixtures),
  'Action fixtures must include a Phoenix-linked hash-verified signed evidence packet for a no-silent-execution proof journey.',
)
check(
  /export_signature/.test(actionFixtures) &&
    /status:\s*'signed'/.test(actionFixtures) &&
    /key_id:\s*'bus-signer-v1'/.test(actionFixtures),
  'Action fixtures must model deployment-managed export_signature metadata with a signer key id.',
)
check(
  /Open proof journey/.test(actionsRoute) &&
    /\/console\/audit\/\$\{encodeURIComponent\(active\.receiptId\)\}/.test(actionsRoute),
  'Actions route must link each selected receipt to its audit proof journey.',
)
check(
  /Receipt proof/.test(auditProofRoute) &&
    /signed evidence packet/.test(auditProofRoute) &&
    /receiptHash/.test(auditProofRoute) &&
    /traceId/.test(auditProofRoute) &&
    /Phoenix trace/.test(auditProofRoute) &&
    /Phoenix span/.test(auditProofRoute) &&
    /replayCommand/.test(auditProofRoute) &&
    /auditEventId/.test(auditProofRoute) &&
    /downloadSignedEvidencePacket/.test(auditProofRoute) &&
    /Download evidence packet/.test(auditProofRoute) &&
    /Before governance/.test(auditProofRoute) &&
    /After governance/.test(auditProofRoute) &&
    /tool_executed":false/.test(auditProofRoute) &&
    /Signature status/.test(auditProofRoute) &&
    /Key id/.test(auditProofRoute) &&
    /evidenceSignature/.test(auditProofRoute),
  'Audit proof route must show receipt hash, trace, Phoenix ids, replay, audit event, before/after state, signed evidence export copy, signature metadata, and no-execution proof.',
)

check(
  /export type EvaluationEvidenceSource =/m.test(types) &&
    /'agentdojo'/.test(types) &&
    /'injecagent'/.test(types) &&
    /'toolemu'/.test(types) &&
    /export type EvaluationEvidence = \{[\s\S]*source: EvaluationEvidenceSource[\s\S]*dataset:[\s\S]*reportHash:[\s\S]*attackSuccessRate:[\s\S]*utilityRetentionRate:[\s\S]*p95LatencyMs:/m.test(
      types,
    ) &&
    /evaluationEvidence\?: EvaluationEvidence/.test(types),
  'AuditEvent must expose normalized source-aware evaluation evidence with report hash and metrics.',
)
check(
  /export type EvaluationEvidenceApi = \{[\s\S]*source: EvaluationEvidenceSource[\s\S]*report_hash:[\s\S]*policy_version:[\s\S]*event_hash\?:[\s\S]*claim_safe\?:/m.test(
    types,
  ) &&
    /evaluationEvidence:\s*\{[\s\S]*list:\s*\(status\?: EvaluationEvidenceStatus\)[\s\S]*\/evidence\/evaluation-reports\$\{evaluationEvidenceQuery\(status\)\}/m.test(
      client,
    ),
  'Console API client must normalize live eval-MVP evaluation report evidence from the same-origin gateway.',
)
check(
  /useEvaluationEvidence/.test(hooks) &&
    /queryKey:\s*\['evaluation-evidence', status\]/.test(hooks) &&
    /withFixtureFallback\(\s*\(\) => api\.evaluationEvidence\.list\(status\)/.test(hooks),
  'Hooks must expose live eval-MVP evidence queries with dev-only fixture fallback.',
)
check(
  /Evaluation evidence/.test(auditRoute) &&
    /EVALUATION_SOURCE_LABEL/.test(auditRoute) &&
    /Local AgentDojo-style fixture/.test(auditRoute) &&
    /Local InjecAgent-style fixture/.test(auditRoute) &&
    /Local ToolEmu-style fixture/.test(auditRoute) &&
    /claim-safe local evidence/.test(auditRoute) &&
    /reportHash/.test(auditRoute) &&
    /attackSuccessRate/.test(auditRoute) &&
    /utilityRetentionRate/.test(auditRoute) &&
    /useEvaluationEvidence\('passed'\)/.test(auditRoute) &&
    /live eval-MVP query/.test(auditRoute),
  'Audit route must surface live source-aware evaluation report hashes and metrics without overclaiming full-suite execution.',
)
check(
  /source:\s*'agentdojo'/.test(auditFixtures) &&
    /source:\s*'injecagent'/.test(auditFixtures) &&
    /source:\s*'toolemu'/.test(auditFixtures) &&
    /dataset:\s*'agentdojo-mini'/.test(auditFixtures) &&
    /dataset:\s*'injecagent-mini'/.test(auditFixtures) &&
    /dataset:\s*'toolemu-high-stakes-mini'/.test(auditFixtures) &&
    /reportHash:\s*'sha256:/.test(auditFixtures) &&
    /attackSuccessRate:\s*0/.test(auditFixtures) &&
    /utilityRetentionRate:\s*1/.test(auditFixtures),
  'Audit fixtures must include source-aware benchmark evidence rows with claim-safe metrics.',
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
