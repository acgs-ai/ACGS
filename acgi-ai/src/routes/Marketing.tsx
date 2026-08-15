import { ArrowRight, Menu, X } from 'lucide-react'
import { type ReactNode, useEffect, useState } from 'react'
import {
  domainProfile,
  domainSignalBoundary,
  domainWeightDelta,
  REGULATED_DOMAIN_KEYS,
  type RegulatedDomain,
} from '../lib/governance-domains'
import { AGENT_READABLE_RULES, BRIEF_FORMAT } from '../lib/governance-framework'
import { useHashScroll } from '../lib/hashScroll'
import { navigate } from '../lib/navigate'
import {
  AGENT_FRAMEWORK_STARTER_KITS,
  ASSURANCE_INTAKE_LANES,
  FRAMEWORK_INTEGRATION_RAIL,
  HOSTED_STORYBOOK_RUNWAY,
  LAUNCH_PROOF_LANES,
  LIVE_VERIFIER_BLOCKER_LANES,
  OPERATOR_CHECKLIST,
  PLATFORM_REQUIREMENT_LANES,
  PRODUCTION_COMMAND_RAIL,
  PRODUCTION_CUTOVER_LANES,
  RELEASE_BLOCKER_QUEUE,
  RESEARCH_INPUTS,
  WORKBENCH_DECISION_RAIL,
  WORKBENCH_GUIDED_PATH,
  WORKBENCH_STAGES,
} from './workbench-content'

const ASTERISM = '⁂'

type RequestedRole = 'advise' | 'draft' | 'simulate' | 'execute'
type ApprovalState = 'yes' | 'no' | 'unsure'
type Reversibility = 'yes' | 'no' | 'unknown'
type RiskLevel = 'low' | 'medium' | 'high' | 'blocked'
type AgentMode = 'advise-only' | 'draft-only' | 'sandboxed' | 'approval-required' | 'fail-closed'

type SignalKey =
  | 'tools'
  | 'privateData'
  | 'credentials'
  | 'cloud'
  | 'code'
  | 'payments'
  | 'legal'
  | 'userAccounts'
  | 'publishing'
  | 'irreversible'
  | 'production'
  | 'memory'
  | 'multiAgent'
  | 'automationLoop'

interface RiskSignal {
  key: SignalKey
  label: string
  weight: number
  boundary: string
  blockedIfExecute?: boolean
}

interface FailureMode {
  title: string
  what: string
  why: string
  signs: string
  boundary: string
  pattern: string
  rule: string
}

interface GovernancePattern {
  title: string
  use: string
  prevents: string
  behavior: string
  checklist: string[]
}

const hubPillars = [
  {
    title: 'Mistakes became boundaries',
    body: 'Years of broken agent experiments are translated into reusable rules: what must be asked, logged, sandboxed, reviewed, or denied before real-world action.',
  },
  {
    title: 'Before your agent acts',
    body: 'Before your agent acts, define the boundary. The hub asks what the task is, who is affected, which tools and permissions are involved, and what evidence must exist before an agent proceeds.',
  },
  {
    title: 'Agent-readable by design',
    body: 'Every public section is written so a human or an AI agent can inspect the URL, classify risk, and recommend a safer operating mode instead of maximizing autonomy.',
  },
]

const whatTheHubGoverns = [
  'External tools and automations',
  'Memory, context, and prompt state',
  'Cloud, IAM, and production access',
  'Credentials, secrets, and user accounts',
  'Code generation and repository actions',
  'Payments, money movement, and procurement',
  'Legal, compliance, privacy, and regulated data',
  'Public publishing, reputation, and irreversible side effects',
]

const audiences = [
  {
    name: 'Builders and AI bros',
    need: 'A practical way to stop vibe-coded agents from touching tools, repos, money, or credentials before the boundary is defined.',
  },
  {
    name: 'Professional teams',
    need: 'Clearer authorization, auditability, review gates, logging expectations, and fail-closed behavior before agent workflows deploy.',
  },
  {
    name: 'AI agents',
    need: 'A URL they can inspect to identify risk, ask better questions, and recommend the safest useful operating pattern for the user task.',
  },
]

// Hero proof pillars. Each states an operational property the kernel actually
// implements locally; none of them claims external assurance.
const heroProofPillars = [
  {
    title: 'Pre-execution gate',
    body: 'Policy is evaluated before the tool call runs, not after the log is written.',
  },
  {
    title: 'Fail-closed invariant',
    body: 'No valid Decision Receipt, no side effect.',
  },
  {
    title: 'Tamper-evident proof',
    body: 'Hash-chained JSONL audit trail with an opt-in Ed25519 signing mode.',
  },
]

// The five hops a governed action takes between agent reasoning and the real
// side effect. This is the narrative form of the gove-zone execution path.
const governedFlowSteps = [
  {
    step: '1',
    title: 'Task and authority',
    body: 'The agent receives the task with an explicit actor, tenant partition, and scoped permissions.',
  },
  {
    step: '2',
    title: 'Risk classification',
    body: 'The intended call and its arguments are read for blast radius, egress, and reversibility.',
  },
  {
    step: '3',
    title: 'Policy gate',
    body: 'The compiled policy bundle is evaluated against the request. Missing criteria deny rather than default.',
  },
  {
    step: '4',
    title: 'Decision receipt',
    body: 'A receipt is emitted carrying the verdict — allow, escalate to a human hold, or deny.',
    highlight: true,
  },
  {
    step: '5',
    title: 'Bounded side effect',
    body: 'The executor re-checks the receipt and its actor binding before any downstream mutation runs.',
  },
]

// Illustrative specimen only. The values below are hand-written to show the
// SHAPE of a receipt on a public page — they are not an emitted receipt, the
// hashes correspond to nothing, and the signature field is deliberately
// non-functional. Claim-safety: never present a fabricated artifact as real
// evidence. The authoritative field list is docs/DECISION_RECEIPT_SPEC.md.
const SPECIMEN_RECEIPT = `{
  "receipt_id": "rcpt-<uuid>",
  "actor": "treasury-agent@example.internal",
  "action": "execute_wire_transfer",
  "resource": "ledger://disbursements/corporate",
  "decision": "ESCALATE",
  "rationale": "Disbursement exceeds the autonomous threshold. Held for a second human key.",
  "policy_bundle_hash": "<sha256 of the compiled bundle>",
  "prev_audit_hash": "<sha256 of the previous audit line>",
  "signature": "<ed25519 signature — omitted in this specimen>",
  "enforcement": "gove-zone · fail-closed"
}`

// Three concrete failure-signal -> boundary -> safer-mode readings. These are
// the compressed form of the fuller failureModes catalogue below, chosen
// because each one names a boundary the kernel enforces structurally.
const failureBoundaries = [
  {
    id: 'tool-overreach',
    number: '01',
    category: 'Capability overreach',
    title: 'Tool-use overreach and shell escalation',
    failureSignal:
      'An agent reasoning loop escalates from document search into unconstrained shell execution, filesystem mutation, or arbitrary downloads.',
    boundary:
      'Capability-scoped workspace and an explicit tool allowlist. An unpermitted side effect is refused at the gate rather than logged after the fact.',
    saferMode: 'Bounded read-only workspace with advisory and bounded capability tiers.',
    badge: 'Refused at the gate',
  },
  {
    id: 'data-exposure',
    number: '02',
    category: 'Privacy and boundary crossing',
    title: 'Credential and private-data exposure',
    failureSignal:
      'A support or research agent reaches into internal records and tries to carry unredacted personal data or secrets across a tenant seam.',
    boundary:
      'Tenant partition enforcement plus a minimum-necessary disclosure rule applied before the read, not after the response is drafted.',
    saferMode: 'Brokered secrets the model never sees, with redaction on the disclosure path.',
    badge: 'Redaction required',
  },
  {
    id: 'unauthorized-mutation',
    number: '03',
    category: 'Authority and privilege',
    title: 'Production mutation without verified authority',
    failureSignal:
      'An autonomous agent moves money, deploys to a live cluster, or executes a contract with no second human signature anywhere in the path.',
    boundary:
      'A dual-key hold with separated roles: the actor that proposes cannot be the actor that approves or the actor that executes.',
    saferMode: 'Hold state that no downstream executor can clear without the second key.',
    badge: 'Held for co-sign',
  },
]

// The repeatable operating sequence, stated as the question each stage answers
// and the artifact it leaves behind.
const operatingSequence = [
  {
    step: '01',
    name: 'Classify',
    question: 'What authority and risk does this action carry?',
    explanation:
      'Every request is classified before execution: scope, actor identity, asset sensitivity, reversibility, and blast radius.',
    artifact: 'Authority scope and risk class',
  },
  {
    step: '02',
    name: 'Gate',
    question: 'Does the planned call satisfy the compiled policy?',
    explanation:
      'The policy engine tests explicit rules against the request. Missing criteria deny; ambiguity does not resolve to allow.',
    artifact: 'Pre-execution policy verdict',
  },
  {
    step: '03',
    name: 'Observe',
    question: 'Is the agent still inside its bounded window?',
    explanation:
      'Tool invocations, memory writes, and network egress are recorded into a hash-linked stream as they happen.',
    artifact: 'Hash-chained event trail',
  },
  {
    step: '04',
    name: 'Review',
    question: 'Does this need a second human key?',
    explanation:
      'Work above the autonomous threshold enters a hold. A human reviewer inspects the staged receipt before it can clear.',
    artifact: 'Human release hold',
  },
  {
    step: '05',
    name: 'Prove',
    question: 'Can the decision be replayed and checked independently?',
    explanation:
      'Each allowed side effect carries its receipt. Replay re-derives the decision and verifies previous-hash linkage and actor binding.',
    artifact: 'Replayable receipt chain',
  },
]

const riskSignals: RiskSignal[] = [
  {
    key: 'tools',
    label: 'External tools or APIs',
    weight: 2,
    boundary: 'Tool calls require named purpose, scoped permissions, and visible receipts.',
  },
  {
    key: 'privateData',
    label: 'Private or user data',
    weight: 3,
    boundary: 'Minimize data, redact where possible, and log access rationale.',
  },
  {
    key: 'credentials',
    label: 'Credentials or secrets',
    weight: 5,
    boundary: 'Never expose secrets to the model; use isolated brokers and human approval.',
    blockedIfExecute: true,
  },
  {
    key: 'cloud',
    label: 'Cloud or IAM access',
    weight: 4,
    boundary: 'Use least-privilege, dry-run first, and require approval before mutation.',
    blockedIfExecute: true,
  },
  {
    key: 'code',
    label: 'Code repositories',
    weight: 3,
    boundary: 'Require branch isolation, tests, review, and explicit staging paths.',
  },
  {
    key: 'payments',
    label: 'Payments or money movement',
    weight: 5,
    boundary: 'Agents may recommend or draft only until a human approves the transaction.',
    blockedIfExecute: true,
  },
  {
    key: 'legal',
    label: 'Legal or compliance work',
    weight: 5,
    boundary:
      'Treat output as assistance, not advice or certification; escalate to qualified review.',
    blockedIfExecute: true,
  },
  {
    key: 'userAccounts',
    label: 'User accounts or identity',
    weight: 4,
    boundary: 'Account changes require explicit authority, session proof, and rollback planning.',
    blockedIfExecute: true,
  },
  {
    key: 'publishing',
    label: 'Public publishing or reputation',
    weight: 3,
    boundary: 'Draft first, fact-check, and require human release for public claims.',
  },
  {
    key: 'irreversible',
    label: 'Irreversible side effects',
    weight: 5,
    boundary: 'Prefer reversible actions; block irreversible execution without human signoff.',
    blockedIfExecute: true,
  },
  {
    key: 'production',
    label: 'Production systems',
    weight: 5,
    boundary: 'No production mutation without tests, change plan, approval, and rollback path.',
    blockedIfExecute: true,
  },
  {
    key: 'memory',
    label: 'Persistent memory',
    weight: 2,
    boundary: 'Keep memory off by default for sensitive work and separate task-local context.',
  },
  {
    key: 'multiAgent',
    label: 'Multiple agents',
    weight: 2,
    boundary: 'Separate roles, prevent self-approval, and reconcile conflicting outputs.',
  },
  {
    key: 'automationLoop',
    label: 'Autonomous loops',
    weight: 4,
    boundary: 'Define iteration limits, stop conditions, and manual release gates.',
    blockedIfExecute: true,
  },
]

const failureModes: FailureMode[] = [
  {
    title: 'Tool-use overreach',
    what: 'The agent uses tools before the user has defined authority, scope, or the acceptable side effects.',
    why: 'Agents optimize for task completion and often treat available tools as permission to act.',
    signs: 'Broad tool access, vague instruction, no dry-run, no receipt, no approval question.',
    boundary:
      'Tool access is denied until purpose, permission, reversibility, and logging are named.',
    pattern: 'Least-privilege tool access + approval-required mode.',
    rule: 'No named authority, no tool call.',
  },
  {
    title: 'Cloud/IAM permission risk',
    what: 'A workflow grants broad cloud permissions or mutates infrastructure without a change plan.',
    why: 'Cloud APIs make destructive changes look like ordinary function calls.',
    signs: 'Admin roles, production project IDs, service-account keys, no rollback path.',
    boundary: 'Dry-run first; require least privilege, scoped environment, and human release.',
    pattern: 'Sandbox-first execution + two-person review for high-risk tasks.',
    rule: 'No production cloud mutation without approval, tests, and rollback evidence.',
  },
  {
    title: 'Credential exposure',
    what: 'Secrets are pasted into prompts, logs, memory, generated code, or debugging output.',
    why: 'Agents ask for whatever unblocks execution unless credential boundaries are explicit.',
    signs: '.env contents in chat, copied tokens, screenshots with secrets, long-lived keys.',
    boundary: 'Secrets stay in brokers or runtime stores; the model sees references, not values.',
    pattern: 'Credential isolation + memory off for sensitive work.',
    rule: 'Never reveal secrets to the model; rotate if exposure occurs.',
  },
  {
    title: 'Memory contamination',
    what: 'Old assumptions, stale facts, or unrelated user data affect a new task.',
    why: 'Persistent memory can blur scope and authority when it is not task-bound.',
    signs: 'The agent cites prior context the user did not authorize for the current work.',
    boundary: 'Use task-local memory and require refresh for drift-prone facts.',
    pattern: 'Memory off by default for sensitive work.',
    rule: 'Do not use memory unless relevance and permission are clear.',
  },
  {
    title: 'Hallucinated planning',
    what: 'The agent invents dependencies, commands, architecture, or success states.',
    why: 'Planning language can sound complete without repository or runtime evidence.',
    signs: 'No file inspection, no command output, unsupported “should work” claims.',
    boundary: 'Plans must cite observed files, commands, permissions, and open unknowns.',
    pattern: 'No-valid-receipt, no-action.',
    rule: 'No plan is accepted without source evidence and explicit uncertainties.',
  },
  {
    title: 'Fake completion',
    what: 'The agent claims work is done without running the proof command or checking the real surface.',
    why: 'LLMs confuse plausible implementation with verified completion.',
    signs: '“Done” before tests, missing screenshots, no exit code, no diff review.',
    boundary: 'Completion requires fresh verification output and a stated not-verified list.',
    pattern: 'Audit log required + production block until tests pass.',
    rule: 'Evidence before success claims.',
  },
  {
    title: 'Broken code generation',
    what: 'Generated code compiles poorly, misses wiring, or changes behavior outside the intended scope.',
    why: 'Agents write local snippets faster than they understand full execution paths.',
    signs: 'Direct function tests only, no router/dispatcher proof, broad diffs.',
    boundary: 'Require wiring evidence, regression tests, and explicit file-scope limits.',
    pattern: 'Human-in-the-loop approval + tests before merge.',
    rule: 'A handler is not complete until it is registered and tested through its route.',
  },
  {
    title: 'Unsafe automation loops',
    what: 'An agent repeatedly edits, retries, spends, deploys, or calls tools without a stop rule.',
    why: 'Autonomy hides accumulated risk behind small repeated actions.',
    signs: 'Unbounded retry loops, no budget, no human checkpoint, expanding scope.',
    boundary:
      'Set iteration, cost, permission, and failure stop conditions before the loop starts.',
    pattern: 'Fail-closed execution + human release gate.',
    rule: 'The loop stops on uncertainty, failed verification, or boundary expansion.',
  },
  {
    title: 'Misleading benchmarks',
    what: 'A demo score is treated as proof that the agent is safe in the real workflow.',
    why: 'Benchmarks rarely model permissions, authority, messy context, and side effects.',
    signs: 'Leaderboard claims, no task-specific eval, no replayable failure evidence.',
    boundary: 'Translate benchmark claims into local task tests and evidence receipts.',
    pattern: 'Simulation before execution.',
    rule: 'Benchmark success is not deployment authority.',
  },
  {
    title: 'Unclear authority',
    what: 'Nobody can say who allowed the agent to act or what the agent was allowed to change.',
    why: 'Prompts often mix intent, permission, and execution into one vague instruction.',
    signs: 'No owner, no approver, no role, no permission window, no audit anchor.',
    boundary: 'Name the actor, authority source, permitted actions, and prohibited actions.',
    pattern: 'Governance brief before action.',
    rule: 'No authority record, no action.',
  },
  {
    title: 'No audit trail',
    what: 'After the run, the team cannot reconstruct inputs, decisions, tool calls, approvals, or failures.',
    why: 'Chat transcripts are not structured enough for operational accountability.',
    signs: 'No receipt, no command output, no timestamps, no reason for refusal.',
    boundary:
      'Log task, mode, tool calls, evidence, approver, stop events, and final recommendation.',
    pattern: 'Audit log required.',
    rule: 'Every governed action emits a receipt.',
  },
  {
    title: 'No rollback path',
    what: 'The agent changes systems but cannot restore the previous state quickly.',
    why: 'Execution plans emphasize doing the task, not undoing it.',
    signs: 'Production edits, database writes, DNS changes, no backup or revert command.',
    boundary: 'Prefer reversible actions and require rollback proof for high-risk work.',
    pattern: 'Reversible action preference.',
    rule: 'If rollback is unknown, execution is blocked or sandboxed.',
  },
  {
    title: 'Human approval bypass',
    what: 'The agent treats prior enthusiasm, a vague yes, or a default setting as approval.',
    why: 'Approval is often implicit unless the workflow forces an explicit checkpoint.',
    signs: '“User probably wants this,” hidden approvals, auto-clicking release buttons.',
    boundary: 'Approval must be specific to action, scope, risk, and time window.',
    pattern: 'Human-in-the-loop approval.',
    rule: 'Approval is explicit, fresh, and scoped — or it does not exist.',
  },
  {
    title: 'Multi-agent confusion',
    what: 'Multiple agents duplicate work, contradict each other, or approve their own outputs.',
    why: 'Agent teams need role separation and a reconciliation protocol.',
    signs: 'No owner, no reviewer separation, conflicting patches, stale task claims.',
    boundary: 'Split planner, implementer, reviewer, and verifier lanes with one source of truth.',
    pattern: 'Two-person review for high-risk tasks.',
    rule: 'The writer cannot be the final approver.',
  },
  {
    title: 'Context drift',
    what: 'The agent keeps working after the goal, files, assumptions, or runtime have changed.',
    why: 'Long sessions compress, summarize, and forget constraints.',
    signs: 'Stale paths, old branch names, wrong repo root, ignored new instructions.',
    boundary: 'Refresh scope, status, and instructions at each major checkpoint.',
    pattern: 'No-valid-receipt, no-action.',
    rule: 'If context is stale or ambiguous, stop and re-scope.',
  },
  {
    title: 'Prompt injection',
    what: 'Untrusted content tells the agent to ignore rules, exfiltrate data, or use tools unsafely.',
    why: 'Agents can confuse retrieved content with governing instructions.',
    signs: 'Instructions inside web pages, files, emails, tickets, or tool output.',
    boundary:
      'Treat retrieved content as data; only trusted policy and user authority can change rules.',
    pattern: 'Least-privilege access + fail-closed execution.',
    rule: 'Data cannot grant itself authority.',
  },
  {
    title: 'Repository damage',
    what: 'The agent edits generated, sealed, vendored, submodule, or unrelated files.',
    why: 'Broad file tools make every path look equally editable.',
    signs: 'git add -A, lockfile churn, generated file edits, submodule pointer drift.',
    boundary:
      'Detect scope, load local instructions, stage explicit paths, and avoid generated outputs.',
    pattern: 'Sandbox-first execution + explicit staging.',
    rule: 'No boundary detection, no repository write.',
  },
  {
    title: 'Production deployment without verification',
    what: 'The agent deploys or claims production readiness from local build success alone.',
    why: 'Local proof is easier to obtain than live DNS, health, auth, and security evidence.',
    signs: 'No live URL check, no headers, no smoke test, no rollback, no release owner.',
    boundary:
      'Block production claims until local, live, and external assurance evidence are separated.',
    pattern: 'Production block until tests pass.',
    rule: 'Local green is not production proof.',
  },
  {
    title: 'Compliance misunderstanding',
    what: 'The agent turns helpful guidance into claims of certification, legal compliance, or professional advice.',
    why: 'LLMs often overstate authority when asked for confident outputs.',
    signs: '“Compliant,” “externally assured,” “risk-free,” no qualified reviewer.',
    boundary: 'Use claim-safe wording and escalate regulated decisions to qualified humans.',
    pattern: 'Draft-only mode for regulated work.',
    rule: 'Governance guidance is not legal, security, or compliance certification.',
  },
]

const governancePatterns: GovernancePattern[] = [
  {
    title: 'Advise-only mode',
    use: 'Exploration, education, early planning, or any task where authority is not established.',
    prevents: 'Accidental tool calls, unauthorized changes, and false assumptions of permission.',
    behavior:
      'The agent explains options, asks questions, and recommends next steps without drafting final artifacts or acting.',
    checklist: [
      'No external tools without permission',
      'State uncertainty',
      'Ask for authority before mode escalation',
    ],
  },
  {
    title: 'Draft-only mode',
    use: 'Writing, code proposals, policies, emails, legal-sensitive language, and public claims.',
    prevents: 'Premature publishing, compliance overclaims, and action without review.',
    behavior: 'The agent creates reviewable drafts and labels them as unapproved.',
    checklist: ['Mark as draft', 'List assumptions', 'Require human release'],
  },
  {
    title: 'Human-in-the-loop approval',
    use: 'Any workflow that can affect money, accounts, infrastructure, users, reputation, or legal posture.',
    prevents: 'Approval bypass and unsafe execution based on vague intent.',
    behavior: 'The agent pauses at a named checkpoint and waits for explicit scoped approval.',
    checklist: ['Name approver', 'Name exact action', 'Record timestamp and scope'],
  },
  {
    title: 'Sandbox-first execution',
    use: 'Code, cloud, automation, data transformation, and tool-heavy tasks.',
    prevents: 'Production damage from untested plans.',
    behavior: 'The agent tests in a safe environment before proposing real action.',
    checklist: [
      'Use test project or branch',
      'Capture dry-run output',
      'Compare expected vs actual result',
    ],
  },
  {
    title: 'Least-privilege tool access',
    use: 'Any tool-enabled agent workflow.',
    prevents: 'Tool-use overreach and unnecessary blast radius.',
    behavior: 'The agent receives only the tools and scopes needed for the current task.',
    checklist: ['Disable unused tools', 'Scope credentials', 'Expire access after task'],
  },
  {
    title: 'No-valid-receipt, no-action',
    use: 'Tasks where evidence must survive beyond the chat transcript.',
    prevents: 'Fake completion and unreplayable decisions.',
    behavior: 'The agent cannot proceed unless the task has a valid receipt shape.',
    checklist: ['Task summary', 'Risk mode', 'Tool calls', 'Verification evidence'],
  },
  {
    title: 'Fail-closed execution',
    use: 'Credentials, payments, production, legal/compliance, user data, or irreversible actions.',
    prevents: 'Action under uncertainty.',
    behavior: 'The agent refuses or pauses when policy, evidence, approval, or context is missing.',
    checklist: ['Define denial reasons', 'Log refusals', 'Escalate to human owner'],
  },
  {
    title: 'Reversible action preference',
    use: 'Operational workflows where damage must be recoverable.',
    prevents: 'No-rollback failures.',
    behavior:
      'The agent chooses drafts, previews, branches, dry-runs, and staged changes over direct mutation.',
    checklist: ['Identify rollback command', 'Snapshot before action', 'Prefer staged change'],
  },
  {
    title: 'Two-person review for high-risk tasks',
    use: 'Production, security, IAM, legal, payments, or customer-impacting changes.',
    prevents: 'Self-approval and single-agent blind spots.',
    behavior: 'One actor prepares; a separate reviewer validates before release.',
    checklist: ['Separate writer and reviewer', 'Record review verdict', 'Resolve blockers'],
  },
  {
    title: 'Audit log required',
    use: 'Anything with external effects, sensitive data, approvals, or denials.',
    prevents: 'Untraceable action and unrecoverable incident review.',
    behavior:
      'The agent emits structured evidence for decisions, tool calls, approvals, and stop events.',
    checklist: ['Timestamp', 'Actor', 'Action', 'Evidence', 'Decision'],
  },
  {
    title: 'Memory off by default for sensitive work',
    use: 'Credentials, legal, personal data, private repositories, customer matters, and regulated work.',
    prevents: 'Memory contamination and privacy leakage.',
    behavior:
      'The agent uses task-local context unless the user explicitly authorizes persistent memory.',
    checklist: ['Disable memory', 'Minimize context', 'Delete or redact sensitive artifacts'],
  },
  {
    title: 'Credential isolation',
    use: 'Any workflow involving secrets, keys, tokens, sessions, or account access.',
    prevents: 'Secret leakage into prompts, logs, memory, or generated files.',
    behavior: 'The agent requests brokered access and never receives raw secret values.',
    checklist: ['Use secret manager', 'No pasted secrets', 'Rotate on exposure'],
  },
  {
    title: 'Simulation before execution',
    use: 'Automation, deployment, migration, scraping, messaging, or bulk actions.',
    prevents: 'Real-world side effects from untested assumptions.',
    behavior: 'The agent produces a dry-run preview and waits for approval before execution.',
    checklist: ['Show expected changes', 'Estimate blast radius', 'Require release decision'],
  },
  {
    title: 'Production block until tests pass',
    use: 'Code, infrastructure, policy, route, handler, or deployment changes.',
    prevents: 'Shipping unverified work.',
    behavior:
      'The agent cannot claim readiness until the correct local and live checks have current evidence.',
    checklist: ['Run local tests', 'Verify wiring', 'Check live health before production claims'],
  },
]

function riskLabel(level: RiskLevel): string {
  if (level === 'blocked') return 'blocked'
  if (level === 'high') return 'high'
  if (level === 'medium') return 'medium'
  return 'low'
}

function modeFor(level: RiskLevel, requestedRole: RequestedRole): AgentMode {
  if (level === 'blocked') return 'fail-closed'
  if (level === 'high') return 'approval-required'
  if (level === 'medium') return requestedRole === 'execute' ? 'sandboxed' : 'draft-only'
  return requestedRole === 'advise' ? 'advise-only' : 'draft-only'
}

function signalByKey(key: SignalKey): RiskSignal {
  return riskSignals.find((signal) => signal.key === key) ?? riskSignals[0]
}

interface GovernanceBriefInput {
  task: string
  affected: string
  requestedRole: RequestedRole
  approval: ApprovalState
  reversible: Reversibility
  selectedSignals: SignalKey[]
  domain: RegulatedDomain
  spendCap: string
}

interface GovernanceBrief {
  task: string
  affected: string
  requestedRole: RequestedRole
  level: RiskLevel
  mode: AgentMode
  permittedActions: string[]
  boundaries: string[]
  humanChecks: string[]
  logging: string
  doNotAllow: string[]
  stopConditions: string[]
  nextStep: string
  domainLabel: string
  obligations: string[]
  domainDisclaimer: string
  spendLimit: string | null
}

// Pure governance scorer + brief builder. Extracted from GovernanceInterview so
// the persona diff and the regression guard can assert on substantive fields
// without DOM brittleness. The regulated-domain axis is additive: with
// domain='none' and no spend cap, the substantive fields (level, mode,
// permittedActions, boundaries, humanChecks, logging, doNotAllow,
// stopConditions, nextStep) are identical to the pre-axis interview.
export function buildGovernanceBrief(input: GovernanceBriefInput): GovernanceBrief {
  const { requestedRole, approval, reversible, selectedSignals, domain } = input
  const selectedSignalDetails = selectedSignals.map(signalByKey)
  const baseScore = selectedSignalDetails.reduce((total, signal) => total + signal.weight, 0)
  const score = baseScore + domainWeightDelta(domain, selectedSignals)
  const requestedExecution = requestedRole === 'execute'
  const hasBlockedExecutionSignal = selectedSignalDetails.some((signal) => signal.blockedIfExecute)
  const blocked =
    (requestedExecution && hasBlockedExecutionSignal && approval !== 'yes') ||
    (requestedExecution && reversible !== 'yes' && score >= 8)
  const level: RiskLevel = blocked
    ? 'blocked'
    : score >= 10
      ? 'high'
      : score >= 5
        ? 'medium'
        : 'low'
  const mode = modeFor(level, requestedRole)
  const boundaries = selectedSignalDetails.map((signal) =>
    domainSignalBoundary(domain, signal.key, signal.boundary),
  )
  const stopConditions = [
    'Authority or approver is unclear.',
    'The task expands beyond the approved scope.',
    'A tool result conflicts with the plan or evidence.',
    'Required verification fails or cannot be run.',
    'The action becomes irreversible, public, financial, credential-bearing, or production-impacting without fresh approval.',
  ]

  const doNotAllow = [
    'Do not assume available tools equal permission to act.',
    'Do not expose credentials, private data, or regulated records to prompts or memory.',
    'Do not claim legal, security, compliance, or production readiness authority.',
    'Do not execute irreversible, payment, IAM, account, or production actions without explicit scoped human approval.',
  ]

  const permittedActions =
    mode === 'fail-closed'
      ? ['Clarify authority, draft a safer plan, and request human review.']
      : mode === 'approval-required'
        ? [
            'Draft the plan, run safe checks, simulate where possible, and pause before real action.',
          ]
        : mode === 'sandboxed'
          ? ['Run dry-runs, branch-only code changes, local simulations, and reversible checks.']
          : mode === 'draft-only'
            ? ['Draft recommendations, briefs, copy, code proposals, and checklists for review.']
            : ['Explain options, ask clarifying questions, and recommend safer next steps.']

  const humanChecks =
    level === 'low'
      ? ['Human review recommended before publishing or connecting tools.']
      : [
          'A named human owner must approve scope, permissions, and release.',
          'A separate reviewer should inspect high-risk output before execution.',
          'Approval must be fresh, explicit, and tied to the exact action.',
        ]

  const logging =
    level === 'low'
      ? 'Capture task summary, assumptions, and recommendation.'
      : 'Capture task, authority, selected mode, tool calls, evidence, approval, refusal reasons, stop events, and final recommendation as a decision receipt.'

  const nextStep =
    level === 'blocked'
      ? 'Stop execution. Convert the task to advise-only or obtain explicit human authority with a rollback plan.'
      : level === 'high'
        ? 'Prepare a review packet and require approval before tool execution.'
        : level === 'medium'
          ? 'Run in sandbox or draft-only mode and log evidence before escalation.'
          : 'Proceed with advise-only or draft-only assistance; escalate if new risks appear.'

  const profile = domainProfile(domain)
  // Route through the single spendCap validator (asSpendCap) so the brief honors
  // the same (0, MAX_SPEND_CAP] rule the ingestion path enforces — no duplicate
  // ceiling-free validator. asSpendCap returns a normalized numeric string for
  // in-range values (identical render bytes) or undefined to omit the limit.
  const normalizedCap = asSpendCap(input.spendCap)
  const spendLimit =
    normalizedCap !== undefined
      ? `Actions above $${Number.parseFloat(normalizedCap).toLocaleString('en-US')} require fresh human approval.`
      : null

  return {
    task: input.task.trim() || 'Describe the current agent task before allowing action.',
    affected:
      input.affected.trim() ||
      'Affected people, systems, accounts, data, or public surfaces not yet specified.',
    requestedRole,
    level,
    mode,
    permittedActions,
    boundaries,
    humanChecks,
    logging,
    doNotAllow,
    stopConditions,
    nextStep,
    domainLabel: profile.label,
    obligations: profile.obligations,
    domainDisclaimer: profile.disclaimer,
    spendLimit,
  }
}

// Deployment-context ingestion (the testable "context -> sharper brief"
// mechanism). An agent that has loaded its deployment context can hand that
// context to the interview via query string (e.g.
// `?domain=hipaa_phipa&spendCap=500&reversible=false`). The interview then
// pre-selects among the SAME predefined options a human would pick, so the
// brief sharpens deterministically instead of via an untestable hand-toggle.
//
// Security stance (honors AGENT_READABLE_RULES in src/lib/governance-framework:
// received text is DATA, not instruction). The schema is intentionally CLOSED
// and free-text-free:
//   - It deliberately omits `task` and `affected`. Those are the only fields
//     that render verbatim into the brief DOM, so they stay hand-entered. No
//     payload string can reach the rendered brief as text or instruction.
//   - `domain` must be a known RegulatedDomain key, else it is dropped.
//   - role/approval/reversible map only onto their strict enums.
//   - `signals` is filtered down to known SignalKey values; unknown tokens
//     (e.g. an injected `<script>`) are discarded.
//   - `spendCap` is parsed as a number and clamped to (0, MAX]; NaN, negative,
//     zero, and absurd magnitudes are rejected and omitted.
// On any failure the field is simply absent from the returned Partial, so the
// component falls back to its cold defaults (fail-closed). The parser never
// evals, never executes payload content, and never returns raw input strings.

// Maximum accepted per-action spend cap. Values above this are treated as a
// malformed/hostile payload and rejected (the field is omitted), not clamped to
// the ceiling, so an attacker cannot smuggle an absurd number into the brief.
const MAX_SPEND_CAP = 1_000_000

// The closed, free-text-free schema deployment context may populate. Note the
// absence of `task`/`affected`: ingested context may only SELECT among
// predefined options (enum value, known signal key, clamped number), never
// supply rendered prose.
export interface DeploymentContextFields {
  requestedRole: RequestedRole
  approval: ApprovalState
  reversible: Reversibility
  selectedSignals: SignalKey[]
  domain: RegulatedDomain
  spendCap: string
}

const REQUESTED_ROLE_VALUES: readonly RequestedRole[] = ['advise', 'draft', 'simulate', 'execute']
const APPROVAL_VALUES: readonly ApprovalState[] = ['yes', 'no', 'unsure']
const SIGNAL_KEYS: readonly SignalKey[] = riskSignals.map((signal) => signal.key)

function asEnum<T extends string>(value: string | null, allowed: readonly T[]): T | undefined {
  return value !== null && (allowed as readonly string[]).includes(value) ? (value as T) : undefined
}

// Strict boolean parse for `reversible`: only the literal true/false family is
// honored; anything else is left to the cold default.
function asReversible(value: string | null): Reversibility | undefined {
  if (value === null) return undefined
  const normalized = value.trim().toLowerCase()
  if (normalized === 'true' || normalized === 'yes') return 'yes'
  if (normalized === 'false' || normalized === 'no') return 'no'
  if (normalized === 'unknown') return 'unknown'
  return undefined
}

// Clamp/validate a spend-cap string. Returns a normalized numeric string only
// when finite and within (0, MAX_SPEND_CAP]; otherwise undefined so the field
// is omitted and the cold default ('') wins.
function asSpendCap(value: string | null): string | undefined {
  if (value === null) return undefined
  const parsed = Number.parseFloat(value)
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > MAX_SPEND_CAP) return undefined
  return String(parsed)
}

// Parse a `signals` param (comma-separated) down to known SignalKey values.
// Unknown tokens are dropped; an empty result yields no field so the cold
// default selection is preserved.
function asSignals(value: string | null): SignalKey[] | undefined {
  if (value === null) return undefined
  const known = value
    .split(',')
    .map((token) => token.trim())
    .filter((token): token is SignalKey => (SIGNAL_KEYS as readonly string[]).includes(token))
  const deduped = Array.from(new Set(known))
  return deduped.length > 0 ? deduped : undefined
}

// EXPORTED pure parser: query string -> partial, closed deployment context.
// `?ctx=<json>` is accepted as a convenience envelope but is parsed onto the
// SAME closed schema and the SAME validators as the discrete params — it grants
// no extra surface. Discrete params override the envelope. Never throws.
export function parseDeploymentContext(search: string): Partial<DeploymentContextFields> {
  const result: Partial<DeploymentContextFields> = {}
  let params: URLSearchParams
  try {
    params = new URLSearchParams(search)
  } catch {
    return result
  }

  // Optional `ctx` envelope: decode (base64 or raw JSON) into a flat record of
  // string values, then run every value through the discrete-param validators.
  // Any malformed envelope is ignored (fail-closed), never thrown.
  const envelope: Record<string, string> = {}
  const ctx = params.get('ctx')
  if (ctx) {
    let raw = ctx
    try {
      // Tolerate a base64-encoded JSON payload; fall back to treating ctx as
      // raw JSON. Either way the result is only read as data.
      if (typeof atob === 'function' && /^[A-Za-z0-9+/=]+$/.test(ctx)) {
        try {
          raw = atob(ctx)
        } catch {
          raw = ctx
        }
      }
      const decoded = JSON.parse(raw) as unknown
      if (decoded && typeof decoded === 'object' && !Array.isArray(decoded)) {
        for (const [key, value] of Object.entries(decoded as Record<string, unknown>)) {
          // Only primitive scalars are coerced to strings; nested objects/arrays
          // and functions are ignored so no structured payload survives.
          if (
            typeof value === 'string' ||
            typeof value === 'number' ||
            typeof value === 'boolean'
          ) {
            envelope[key] = String(value)
          }
        }
      }
    } catch {
      // Malformed envelope -> ignore entirely.
    }
  }

  const pick = (key: string): string | null => params.get(key) ?? envelope[key] ?? null

  const requestedRole = asEnum(pick('requestedRole') ?? pick('role'), REQUESTED_ROLE_VALUES)
  if (requestedRole) result.requestedRole = requestedRole

  const approval = asEnum(pick('approval'), APPROVAL_VALUES)
  if (approval) result.approval = approval

  const reversible = asReversible(pick('reversible'))
  if (reversible) result.reversible = reversible

  const domain = asEnum<RegulatedDomain>(
    pick('domain'),
    REGULATED_DOMAIN_KEYS as readonly RegulatedDomain[],
  )
  if (domain) result.domain = domain

  const signals = asSignals(pick('signals'))
  if (signals) result.selectedSignals = signals

  const spendCap = asSpendCap(pick('spendCap'))
  if (spendCap !== undefined) result.spendCap = spendCap

  return result
}

export function NavigationLink({
  href,
  children,
  onNavigate,
}: {
  href: string
  children: ReactNode
  onNavigate?: () => void
}) {
  const isRoute = href.startsWith('/') && !href.includes('#')

  return (
    <a
      href={href}
      onClick={(event) => {
        if (!isRoute) return
        event.preventDefault()
        onNavigate?.()
        if (typeof window !== 'undefined' && window.location.pathname === href) {
          window.dispatchEvent(new PopStateEvent('popstate'))
          return
        }
        navigate(href)
      }}
    >
      {children}
    </a>
  )
}

export function MarketingFrame({ children }: { children: ReactNode }) {
  const [navOpen, setNavOpen] = useState(false)

  useHashScroll()

  useEffect(() => {
    if (typeof window === 'undefined') return
    const close = () => setNavOpen(false)
    window.addEventListener('hashchange', close)
    window.addEventListener('popstate', close)
    return () => {
      window.removeEventListener('hashchange', close)
      window.removeEventListener('popstate', close)
    }
  }, [])

  return (
    <div className="marketing">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <div className="shell">
        <nav className={`m-nav${navOpen ? ' is-open' : ''}`} aria-label="Primary">
          <a
            className="m-brand"
            href="/"
            aria-label="ACGS home"
            onClick={(event) => {
              event.preventDefault()
              setNavOpen(false)
              if (typeof window !== 'undefined' && window.location.pathname === '/') {
                window.dispatchEvent(new PopStateEvent('popstate'))
                return
              }
              navigate('/')
            }}
          >
            <span>acgs</span>
            <span className="folio" aria-hidden>
              {ASTERISM}
            </span>
          </a>
          <button
            type="button"
            className="m-nav-toggle"
            aria-expanded={navOpen}
            aria-controls="m-nav-links"
            aria-label={navOpen ? 'Close navigation' : 'Open navigation'}
            onClick={() => setNavOpen((value) => !value)}
          >
            {navOpen ? <X size={18} strokeWidth={1.8} /> : <Menu size={18} strokeWidth={1.8} />}
          </button>
          <div className="m-nav-links" id="m-nav-links">
            <NavigationLink href="/ask" onNavigate={() => setNavOpen(false)}>
              Ask
            </NavigationLink>
            <a href="/#governed-flow">Governed flow</a>
            <a href="/#interview">Interview</a>
            <NavigationLink href="/founder" onNavigate={() => setNavOpen(false)}>
              Founder
            </NavigationLink>
            <NavigationLink href="/failure-modes" onNavigate={() => setNavOpen(false)}>
              Failure modes
            </NavigationLink>
            <NavigationLink href="/governance-patterns" onNavigate={() => setNavOpen(false)}>
              Patterns
            </NavigationLink>
            <NavigationLink href="/agent-readable" onNavigate={() => setNavOpen(false)}>
              Agent-readable
            </NavigationLink>
            <NavigationLink href="/agent-bus" onNavigate={() => setNavOpen(false)}>
              Agent bus
            </NavigationLink>
            <NavigationLink href="/eval-mvp" onNavigate={() => setNavOpen(false)}>
              Eval MVP
            </NavigationLink>
            <NavigationLink href="/products" onNavigate={() => setNavOpen(false)}>
              ACGS
            </NavigationLink>
            <NavigationLink href="/clinicalguard" onNavigate={() => setNavOpen(false)}>
              ClinicalGuard
            </NavigationLink>
            <NavigationLink href="/acgs-lite" onNavigate={() => setNavOpen(false)}>
              acgs-lite
            </NavigationLink>
            <NavigationLink href="/swarm" onNavigate={() => setNavOpen(false)}>
              Swarm
            </NavigationLink>
          </div>
          <a className="m-nav-cta" href="/#interview">
            Start interview <ArrowRight size={14} strokeWidth={1.75} />
          </a>
        </nav>

        <main id="main-content" tabIndex={-1}>
          {children}
        </main>
      </div>

      <footer className="m-foot">
        <div className="m-foot-inner">
          <div>
            <div className="m-foot-mark">
              governance <em>{ASTERISM}</em> hub
            </div>
            <div className="m-foot-addr">
              {`AI Agent Governance Hub
Mistakes became boundaries.

Guidance for users and agents before real-world action.`}
            </div>
          </div>
          <div>
            <h4>Start</h4>
            <ul>
              <li>
                <a href="/#interview">Governance interview</a>
              </li>
              <li>
                <a href="/#brief-generator">Brief generator</a>
              </li>
              <li>
                <NavigationLink href="/agent-readable">Agent-readable page</NavigationLink>
              </li>
              <li>
                <NavigationLink href="/founder">Founder narrative</NavigationLink>
              </li>
            </ul>
          </div>
          <div>
            <h4>Library</h4>
            <ul>
              <li>
                <NavigationLink href="/failure-modes">Failure catalogue</NavigationLink>
              </li>
              <li>
                <NavigationLink href="/agent-bus">Agent bus</NavigationLink>
              </li>
              <li>
                <NavigationLink href="/governance-patterns">Governance patterns</NavigationLink>
              </li>
              <li>
                <NavigationLink href="/products">Deeper ACGS products</NavigationLink>
              </li>
              <li>
                <NavigationLink href="/cft-pack">CFT Governance Pack</NavigationLink>
                <NavigationLink href="/swarm">acgs-swarm showcase</NavigationLink>
              </li>
              <li>
                <a
                  href="/acgs-lite"
                  onClick={(event) => {
                    event.preventDefault()
                    navigate('/acgs-lite')
                  }}
                >
                  acgs-lite package
                </a>
              </li>
              <li>
                <a
                  href="/clinicalguard"
                  onClick={(event) => {
                    event.preventDefault()
                    navigate('/clinicalguard')
                  }}
                >
                  ClinicalGuard
                </a>
              </li>
              <li>
                <a
                  href="/trust"
                  onClick={(event) => {
                    event.preventDefault()
                    navigate('/trust')
                  }}
                >
                  Trust center
                </a>
              </li>
              <li>
                <a
                  href="/security"
                  onClick={(event) => {
                    event.preventDefault()
                    navigate('/security')
                  }}
                >
                  Security
                </a>
              </li>
            </ul>
          </div>
          <div>
            <h4>Boundaries</h4>
            <ul>
              <li>Guidance, not certification</li>
              <li>No legal or compliance guarantee</li>
              <li>Human approval for high-risk work</li>
              <li>Fail closed when authority is unclear</li>
            </ul>
          </div>
        </div>
        <div className="shell">
          <div className="m-foot-bar">
            <span>public governance center · MMXXVI</span>
            <span>
              principle <span className="hash">mistakes-became-boundaries</span>
            </span>
          </div>
        </div>
      </footer>
    </div>
  )
}

// Deliberately icon-free. An icon-in-a-box triptych is the generic SaaS feature
// grid CLAUDE.md rules out, and three lucide glyphs cost real bytes on a
// surface with a tight gzip budget. The plate numeral carries the rhythm.
function HeroProofBar() {
  return (
    <ul className="m-hero-proof-bar" aria-label="Core operating properties">
      {heroProofPillars.map((pillar, index) => (
        <li className="m-proof-item" key={pillar.title}>
          <span className="m-proof-no" aria-hidden>
            {String(index + 1).padStart(2, '0')}
          </span>
          <span className="m-proof-text">
            <span className="m-proof-title">{pillar.title}</span>
            <span className="m-proof-sub">{pillar.body}</span>
          </span>
        </li>
      ))}
    </ul>
  )
}

function GovernedActionFlow() {
  const [copied, setCopied] = useState(false)

  // Clear the "Copied" flag on a timer, and cancel that timer if the component
  // unmounts first so no setState fires after teardown.
  useEffect(() => {
    if (!copied) return
    const timer = window.setTimeout(() => setCopied(false), 2000)
    return () => window.clearTimeout(timer)
  }, [copied])

  const copySpecimen = () => {
    // Clipboard access is unavailable over plain http and in some embedded
    // views; fail quietly rather than throwing into the render path.
    navigator.clipboard
      ?.writeText(SPECIMEN_RECEIPT)
      .then(() => setCopied(true))
      .catch(() => setCopied(false))
  }

  return (
    <section id="governed-flow" aria-labelledby="governed-flow-h">
      <div className="m-sec-head">
        <span className="num">I · How a governed action runs</span>
        <h2 id="governed-flow-h">
          A membrane between reasoning and <em>execution</em>.
        </h2>
      </div>
      <p className="m-product-definition">
        Most agent stacks let the model call the tool and then try to reconstruct what happened from
        logs. The governed path puts the decision first: the call is classified, tested against
        policy, and receipted before the side effect is allowed to run.
      </p>

      <div className="m-flow-diagram">
        <ol className="m-flow-steps" aria-label="Governed action sequence">
          {governedFlowSteps.map((step) => (
            <li className={`m-flow-step${step.highlight ? ' is-highlight' : ''}`} key={step.step}>
              <span className="m-step-badge" aria-hidden>
                {step.step}
              </span>
              <div>
                <h3>{step.title}</h3>
                <p>{step.body}</p>
              </div>
            </li>
          ))}
        </ol>

        <figure className="m-receipt-specimen">
          <figcaption className="m-specimen-bar">
            <span className="m-specimen-meta">
              Specimen receipt · illustrative values, not an emitted receipt
            </span>
            <button
              type="button"
              className="m-specimen-copy"
              onClick={copySpecimen}
              aria-label="Copy the specimen receipt as JSON"
            >
              {copied ? 'Copied' : 'Copy JSON'}
            </button>
          </figcaption>
          <pre className="m-specimen-pre">
            <code>{SPECIMEN_RECEIPT}</code>
          </pre>
          <p className="m-specimen-note">
            The field names are the real receipt shape; the values are placeholders. Hashes and the
            signature here correspond to nothing and will not verify. The rule the shape exists to
            serve: no valid Decision Receipt, no side effect.
          </p>
        </figure>
      </div>
    </section>
  )
}

function FailureBoundaryCards() {
  return (
    <section id="failure-boundaries" aria-labelledby="failure-boundaries-h">
      <div className="m-sec-head">
        <span className="num">III · Signal, boundary, safer mode</span>
        <h2 id="failure-boundaries-h">
          Three failures that became <em>gates</em>.
        </h2>
      </div>
      <div className="m-boundaries-grid">
        {failureBoundaries.map((item) => (
          <article className="m-boundary-card" key={item.id}>
            <div className="m-boundary-top">
              <span className="folio-no">№ {item.number}</span>
              <span className="m-boundary-category">{item.category}</span>
              <span className="m-boundary-badge">{item.badge}</span>
            </div>
            <h3>{item.title}</h3>
            <dl className="m-boundary-flow">
              <div className="m-boundary-block is-failure">
                <dt>Failure signal</dt>
                <dd>{item.failureSignal}</dd>
              </div>
              <div className="m-boundary-block is-boundary">
                <dt>Governance boundary</dt>
                <dd>{item.boundary}</dd>
              </div>
              <div className="m-boundary-block is-safer">
                <dt>Safer operating mode</dt>
                <dd>{item.saferMode}</dd>
              </div>
            </dl>
          </article>
        ))}
      </div>
      <p className="m-section-link">
        <NavigationLink href="/failure-modes">Read all nineteen failure modes</NavigationLink>
      </p>
    </section>
  )
}

function OperatingSequence() {
  return (
    <section id="operating-sequence" aria-labelledby="operating-sequence-h">
      <div className="m-sec-head">
        <span className="num">V · The operating sequence</span>
        <h2 id="operating-sequence-h">
          Classify, gate, observe, review, <em>prove</em>.
        </h2>
      </div>
      <ol className="m-stage-grid" aria-label="Five-stage governance sequence">
        {operatingSequence.map((stage) => (
          <li className="m-stage-card" key={stage.step}>
            <div className="m-stage-head">
              <span className="m-stage-no">{stage.step}</span>
              <h3>{stage.name}</h3>
            </div>
            <p className="m-stage-question">{stage.question}</p>
            <p>{stage.explanation}</p>
            <p className="m-stage-artifact">
              <span>Leaves behind</span>
              <strong>{stage.artifact}</strong>
            </p>
          </li>
        ))}
      </ol>
    </section>
  )
}

function PlatformBlueprint() {
  return (
    <section id="workbench" aria-labelledby="workbench-h">
      <div className="m-sec-head">
        <span className="num">VI · ACGS platform blueprint</span>
        <h2 id="workbench-h">
          Visualized <em>work</em>, not another wall of settings.
        </h2>
      </div>
      <div className="m-workbench">
        <ol className="m-workbench-map" aria-label="Visualized operator workflow">
          {WORKBENCH_STAGES.map((stage) => (
            <li className="m-workbench-stage" key={stage.step}>
              <span className="stage-step">{stage.step}</span>
              <h3>{stage.title}</h3>
              <p className="stage-signal">{stage.signal}</p>
              <p>{stage.body}</p>
            </li>
          ))}
        </ol>

        <aside className="m-workbench-panel" aria-label="Research-backed UI inputs">
          <span className="folio-no">Research inputs</span>
          <h3>What a leading agent-governance platform should make easy.</h3>
          <p>
            The UI should make risky work inspectable in one pass: queue, trace, evaluation,
            release, and export. The claim is a product blueprint, not certification or live
            assurance.
          </p>
          <ul>
            {RESEARCH_INPUTS.map(({ source, cue }) => (
              <li key={source}>
                <strong>{source}</strong>
                <span>{cue}</span>
              </li>
            ))}
          </ul>

          <section className="m-workbench-requirements" aria-labelledby="platform-req-h">
            <span className="folio-no" id="platform-req-h">
              Platform requirements
            </span>
            <ol>
              {PLATFORM_REQUIREMENT_LANES.map(({ pillar, title, proof, source }) => (
                <li key={pillar}>
                  <strong>{pillar}</strong>
                  <span>{title}</span>
                  <code>{proof}</code>
                  <small>{source}</small>
                </li>
              ))}
            </ol>
          </section>

          <section className="m-workbench-framework" aria-labelledby="framework-rail-h">
            <span className="folio-no" id="framework-rail-h">
              Framework integration rail
            </span>
            <ol>
              {FRAMEWORK_INTEGRATION_RAIL.map(({ step, title, source, proof }) => (
                <li key={title}>
                  <strong>{step}</strong>
                  <span>{title}</span>
                  <small>{source}</small>
                  <code>{proof}</code>
                </li>
              ))}
            </ol>
          </section>

          <section className="m-workbench-starters" aria-labelledby="starter-kits-h">
            <span className="folio-no" id="starter-kits-h">
              Agent framework starter kits
            </span>
            <ol>
              {AGENT_FRAMEWORK_STARTER_KITS.map(({ framework, entry, command, proof }) => (
                <li key={framework}>
                  <strong>{framework}</strong>
                  <span>{entry}</span>
                  <code>{proof}</code>
                  <small>{command}</small>
                </li>
              ))}
            </ol>
          </section>

          <section className="m-workbench-guided" aria-labelledby="guided-path-h">
            <span className="folio-no" id="guided-path-h">
              Guided review path
            </span>
            <ol>
              {WORKBENCH_GUIDED_PATH.map(({ step, title, instruction, proof }) => (
                <li key={title}>
                  <strong>{step}</strong>
                  <span>{title}</span>
                  <p>{instruction}</p>
                  <code>{proof}</code>
                </li>
              ))}
            </ol>
          </section>

          <section className="m-workbench-decision" aria-labelledby="decision-rail-h">
            <span className="folio-no" id="decision-rail-h">
              Operator decision rail
            </span>
            <ol>
              {WORKBENCH_DECISION_RAIL.map(({ step, title, prompt, proof }) => (
                <li key={title}>
                  <strong>{step}</strong>
                  <span>{title}</span>
                  <p>{prompt}</p>
                  <code>{proof}</code>
                </li>
              ))}
            </ol>
          </section>

          <section className="m-workbench-checklist" aria-labelledby="operator-start-h">
            <span className="folio-no" id="operator-start-h">
              Operator quick start
            </span>
            <ol>
              {OPERATOR_CHECKLIST.map(({ label, cue }) => (
                <li key={label}>
                  <strong>{label}</strong>
                  <span>{cue}</span>
                </li>
              ))}
            </ol>
          </section>

          <section className="m-workbench-proof" aria-labelledby="proof-ladder-h">
            <span className="folio-no" id="proof-ladder-h">
              Launch proof ladder
            </span>
            <ol>
              {LAUNCH_PROOF_LANES.map(({ title, state, proof, cue }) => (
                <li key={title}>
                  <strong>{title}</strong>
                  <code>{proof}</code>
                  <span>{state}</span>
                  <span>{cue}</span>
                </li>
              ))}
            </ol>
          </section>

          <section className="m-workbench-cutover" aria-labelledby="cutover-state-h">
            <span className="folio-no" id="cutover-state-h">
              Current saved cutover state
            </span>
            <p>safeToClaimProduction=false · saved local state is not production proof.</p>
            <ol>
              {PRODUCTION_CUTOVER_LANES.map(({ title, state, proof }) => (
                <li key={title}>
                  <strong>{title}</strong>
                  <span>{state}</span>
                  <code>{proof}</code>
                </li>
              ))}
            </ol>
          </section>

          <section className="m-workbench-blockers" aria-labelledby="release-blockers-h">
            <span className="folio-no" id="release-blockers-h">
              Release blocker queue
            </span>
            <ol>
              {RELEASE_BLOCKER_QUEUE.map(({ blockerId, owner, artifact, proof }) => (
                <li key={blockerId}>
                  <strong>{owner}</strong>
                  <span>{blockerId}</span>
                  <code>{proof}</code>
                  <small>{artifact}</small>
                </li>
              ))}
            </ol>
          </section>

          <section className="m-workbench-live" aria-labelledby="live-blockers-h">
            <span className="folio-no" id="live-blockers-h">
              Live verifier blocker map
            </span>
            <ol>
              {LIVE_VERIFIER_BLOCKER_LANES.map(({ title, blockerId, proof }) => (
                <li key={blockerId}>
                  <strong>{title}</strong>
                  <span>{blockerId}</span>
                  <code>{proof}</code>
                </li>
              ))}
            </ol>
          </section>

          <section className="m-workbench-command" aria-labelledby="command-rail-h">
            <span className="folio-no" id="command-rail-h">
              Production command rail
            </span>
            <ol>
              {PRODUCTION_COMMAND_RAIL.map(({ title, command, artifact }) => (
                <li key={title}>
                  <strong>{title}</strong>
                  <code>{command}</code>
                  <span>{artifact}</span>
                </li>
              ))}
            </ol>
          </section>

          <section className="m-workbench-storybook-runway" aria-labelledby="storybook-runway-h">
            <span className="folio-no" id="storybook-runway-h">
              Hosted Storybook runway
            </span>
            <ol>
              {HOSTED_STORYBOOK_RUNWAY.map(({ step, title, command, proof }) => (
                <li key={title}>
                  <strong>{step}</strong>
                  <span>{title}</span>
                  <code>{proof}</code>
                  <small>{command}</small>
                </li>
              ))}
            </ol>
          </section>

          <section className="m-workbench-assurance" aria-labelledby="assurance-intake-h">
            <span className="folio-no" id="assurance-intake-h">
              Assurance proof intake
            </span>
            <ol>
              {ASSURANCE_INTAKE_LANES.map(({ title, state, proof }) => (
                <li key={title}>
                  <strong>{title}</strong>
                  <span>{state}</span>
                  <code>{proof}</code>
                </li>
              ))}
            </ol>
          </section>
        </aside>
      </div>
    </section>
  )
}

export function GovernanceInterview() {
  const [task, setTask] = useState('')
  const [affected, setAffected] = useState('')
  const [requestedRole, setRequestedRole] = useState<RequestedRole>('draft')
  const [approval, setApproval] = useState<ApprovalState>('unsure')
  const [reversible, setReversible] = useState<Reversibility>('unknown')
  const [selectedSignals, setSelectedSignals] = useState<SignalKey[]>(['tools', 'code'])
  const [domain, setDomain] = useState<RegulatedDomain>('none')
  const [spendCap, setSpendCap] = useState('')

  // Ingest agent-supplied deployment context from the URL once on mount.
  // Only the closed, validated fields from parseDeploymentContext are applied;
  // task/affected are never populated from the payload, so no payload text can
  // reach the rendered brief. Empty/absent context yields {} -> no setState, so
  // the cold defaults are preserved.
  useEffect(() => {
    if (typeof window === 'undefined') return
    const context = parseDeploymentContext(window.location.search)
    if (context.requestedRole !== undefined) setRequestedRole(context.requestedRole)
    if (context.approval !== undefined) setApproval(context.approval)
    if (context.reversible !== undefined) setReversible(context.reversible)
    if (context.selectedSignals !== undefined) setSelectedSignals(context.selectedSignals)
    if (context.domain !== undefined) setDomain(context.domain)
    if (context.spendCap !== undefined) setSpendCap(context.spendCap)
  }, [])

  const toggleSignal = (key: SignalKey) => {
    setSelectedSignals((current) =>
      current.includes(key) ? current.filter((signal) => signal !== key) : [...current, key],
    )
  }

  const brief = buildGovernanceBrief({
    task,
    affected,
    requestedRole,
    approval,
    reversible,
    selectedSignals,
    domain,
    spendCap,
  })
  const level = brief.level

  return (
    <section className="m-hub-interview" id="interview" aria-labelledby="interview-h">
      <div className="m-sec-head">
        <span className="num">VII · Governance interview</span>
        <h2 id="interview-h">
          Classify the task before the agent <em>acts</em>.
        </h2>
      </div>

      <p className="m-product-definition">
        Supply your agent's deployment context and the brief gets sharper. An agent that has loaded
        its own deployment context can pass it to this interview through the page URL (for example{' '}
        <code>?domain=hipaa_phipa&amp;spendCap=500</code>), which pre-selects the same predefined
        domain, signal, and limit options a person would pick — the page does not read your agent's
        memory. Deployment context is the task-local frame for this one decision; it is not
        cross-task memory. Keep persistent, cross-task memory off for sensitive work to avoid the
        memory-contamination failure mode. Supplied values can only choose among the options below;
        they never become instructions the agent must follow.
      </p>

      <div className="m-interview-grid">
        <form className="m-interview-form" aria-label="Governance interview inputs">
          <label>
            <span>What are you trying to do?</span>
            <textarea
              value={task}
              onChange={(event) => setTask(event.target.value)}
              placeholder="Example: ask an agent to deploy a code change, process private data, or automate a workflow."
            />
          </label>
          <label>
            <span>Who or what will be affected?</span>
            <textarea
              value={affected}
              onChange={(event) => setAffected(event.target.value)}
              placeholder="People, customers, accounts, repositories, cloud resources, legal records, public channels, or production systems."
            />
          </label>

          <div className="m-field-row">
            <label>
              <span>Requested agent role</span>
              <select
                value={requestedRole}
                onChange={(event) => setRequestedRole(event.target.value as RequestedRole)}
              >
                <option value="advise">Advise only</option>
                <option value="draft">Draft for review</option>
                <option value="simulate">Simulate or dry-run</option>
                <option value="execute">Execute real-world action</option>
              </select>
            </label>
            <label>
              <span>Is the action reversible?</span>
              <select
                value={reversible}
                onChange={(event) => setReversible(event.target.value as Reversibility)}
              >
                <option value="unknown">Unknown</option>
                <option value="yes">Yes</option>
                <option value="no">No</option>
              </select>
            </label>
            <label>
              <span>Human approval exists?</span>
              <select
                value={approval}
                onChange={(event) => setApproval(event.target.value as ApprovalState)}
              >
                <option value="unsure">Not sure</option>
                <option value="yes">Yes, explicit and scoped</option>
                <option value="no">No</option>
              </select>
            </label>
          </div>

          <div className="m-field-row">
            <label>
              <span>Regulatory domain</span>
              <select
                value={domain}
                onChange={(event) => setDomain(event.target.value as RegulatedDomain)}
              >
                {REGULATED_DOMAIN_KEYS.map((key) => (
                  <option value={key} key={key}>
                    {domainProfile(key).label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>Spend cap (USD per action)</span>
              <input
                type="number"
                min="0"
                step="1"
                value={spendCap}
                onChange={(event) => setSpendCap(event.target.value)}
                placeholder="Optional, e.g. 500"
              />
            </label>
          </div>

          <fieldset>
            <legend>Risk signals</legend>
            <div className="m-risk-grid">
              {riskSignals.map((signal) => (
                <label className="m-risk-check" key={signal.key}>
                  <input
                    type="checkbox"
                    checked={selectedSignals.includes(signal.key)}
                    onChange={() => toggleSignal(signal.key)}
                  />
                  <span>{signal.label}</span>
                </label>
              ))}
            </div>
          </fieldset>
        </form>

        <aside className="m-brief" id="brief-generator" aria-live="polite">
          <span className={`m-risk-pill is-${riskLabel(level)}`}>Risk: {level}</span>
          <h3>Governance brief</h3>
          <dl>
            <div>
              <dt>Task</dt>
              <dd>{brief.task}</dd>
            </div>
            <div>
              <dt>Affected</dt>
              <dd>{brief.affected}</dd>
            </div>
            <div>
              <dt>Intended agent role</dt>
              <dd>{brief.requestedRole}</dd>
            </div>
            <div>
              <dt>Safer execution mode</dt>
              <dd>{brief.mode}</dd>
            </div>
            <div>
              <dt>Permitted actions</dt>
              <dd>{brief.permittedActions.join(' ')}</dd>
            </div>
            <div>
              <dt>Required boundaries</dt>
              <dd>
                <ul>
                  {brief.boundaries.map((boundary) => (
                    <li key={boundary}>{boundary}</li>
                  ))}
                </ul>
              </dd>
            </div>
            <div>
              <dt>Regulatory domain</dt>
              <dd>{brief.domainLabel}</dd>
            </div>
            {brief.obligations.length > 0 ? (
              <div>
                <dt>Domain obligations</dt>
                <dd>
                  <ul>
                    {brief.obligations.map((obligation) => (
                      <li key={obligation}>{obligation}</li>
                    ))}
                  </ul>
                </dd>
              </div>
            ) : null}
            <div>
              <dt>Domain claim boundary</dt>
              <dd>{brief.domainDisclaimer}</dd>
            </div>
            {brief.spendLimit ? (
              <div>
                <dt>Spend limit</dt>
                <dd>{brief.spendLimit}</dd>
              </div>
            ) : null}
            <div>
              <dt>Human checks</dt>
              <dd>
                <ul>
                  {brief.humanChecks.map((check) => (
                    <li key={check}>{check}</li>
                  ))}
                </ul>
              </dd>
            </div>
            <div>
              <dt>Evidence/logging</dt>
              <dd>{brief.logging}</dd>
            </div>
            <div>
              <dt>Do not allow</dt>
              <dd>
                <ul>
                  {brief.doNotAllow.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </dd>
            </div>
            <div>
              <dt>Stop conditions</dt>
              <dd>
                <ul>
                  {brief.stopConditions.map((condition) => (
                    <li key={condition}>{condition}</li>
                  ))}
                </ul>
              </dd>
            </div>
            <div>
              <dt>Final recommendation</dt>
              <dd>{brief.nextStep}</dd>
            </div>
          </dl>
        </aside>
      </div>
    </section>
  )
}

function FailureModeCatalogue({ compact = false }: { compact?: boolean }) {
  const modes = compact ? failureModes.slice(0, 9) : failureModes

  return (
    <div className="m-failure-grid">
      {modes.map((mode) => (
        <article className="m-failure-card" key={mode.title}>
          <span className="folio-no">Failure mode</span>
          <h3>{mode.title}</h3>
          <dl>
            <div>
              <dt>What goes wrong</dt>
              <dd>{mode.what}</dd>
            </div>
            <div>
              <dt>Why agents make it</dt>
              <dd>{mode.why}</dd>
            </div>
            <div>
              <dt>Warning signs</dt>
              <dd>{mode.signs}</dd>
            </div>
            <div>
              <dt>Boundary</dt>
              <dd>{mode.boundary}</dd>
            </div>
            <div>
              <dt>Safer pattern</dt>
              <dd>{mode.pattern}</dd>
            </div>
            <div>
              <dt>Rule</dt>
              <dd>{mode.rule}</dd>
            </div>
          </dl>
        </article>
      ))}
    </div>
  )
}

function GovernancePatternList({ compact = false }: { compact?: boolean }) {
  const patterns = compact ? governancePatterns.slice(0, 8) : governancePatterns

  return (
    <div className="m-pattern-grid">
      {patterns.map((pattern) => (
        <article className="m-pattern-card" key={pattern.title}>
          <span className="folio-no">Pattern</span>
          <h3>{pattern.title}</h3>
          <p>{pattern.use}</p>
          <dl>
            <div>
              <dt>Prevents</dt>
              <dd>{pattern.prevents}</dd>
            </div>
            <div>
              <dt>Agent behavior</dt>
              <dd>{pattern.behavior}</dd>
            </div>
          </dl>
          <ul>
            {pattern.checklist.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </article>
      ))}
    </div>
  )
}

function AgentReadablePanel() {
  return (
    <section className="m-agent-readable" id="agent-readable" aria-labelledby="agent-readable-h">
      <div className="m-sec-head">
        <span className="num">X · Agent-readable governance</span>
        <h2 id="agent-readable-h">
          A page your agent can <em>inspect</em> before acting.
        </h2>
      </div>
      <div className="m-agent-grid">
        <article>
          <span className="folio-no">Instruction</span>
          <p className="m-agent-instruction">
            When inspecting this hub, do not assume the user wants maximum automation. First
            identify the task, risk, authority, permissions, reversibility, evidence requirements,
            and human approval needs. Recommend the safest useful operating mode.
          </p>
        </article>
        <article>
          <span className="folio-no">Classification rules</span>
          <ol>
            {AGENT_READABLE_RULES.map((rule) => (
              <li key={rule}>{rule}</li>
            ))}
          </ol>
        </article>
        <article>
          <span className="folio-no">Recommendation output</span>
          <ol>
            {BRIEF_FORMAT.map((field) => (
              <li key={field}>{field}</li>
            ))}
          </ol>
        </article>
      </div>
    </section>
  )
}

export function Marketing() {
  return (
    <MarketingFrame>
      <header className="m-hero m-hub-hero">
        <div>
          <span className="m-eyebrow">
            <span className="asterism" aria-hidden>
              {ASTERISM}
            </span>
            Public governance center for users and agents
          </span>
          <h1>
            AI agents need <em>boundaries</em> before autonomy.
          </h1>
          <p className="m-hero-lede">
            Built from years of failed AI-agent experiments, this governance hub helps users and
            agents identify risks, set permissions, and choose safer operating patterns before
            action. Its core rule, enforced by the gove-zone runtime: no valid Decision Receipt, no
            side effect — privileged actions are checked and receipted before they run, not audited
            after.
          </p>
          <div className="m-hero-actions">
            <a className="btn btn-primary" href="#interview">
              Start Governance Interview <ArrowRight size={16} strokeWidth={1.8} />
            </a>
            <NavigationLink href="/agent-readable">Let Your Agent Inspect This Hub</NavigationLink>
          </div>
          <HeroProofBar />
        </div>

        <aside className="m-hero-aside m-hub-cockpit">
          <figure className="m-code">
            <figcaption className="m-code-head">
              <span>governance-brief.agent</span>
              <span>mode: pre-action</span>
            </figcaption>
            <pre>
              <span className="c">{'// Before the agent acts'}</span>
              {'\n'}task: <span className="s">"classify risk"</span>
              {'\n'}authority: <span className="s">"explicit, scoped"</span>
              {'\n'}permissions: <span className="s">"least privilege"</span>
              {'\n'}evidence: <span className="s">"receipt required"</span>
              {'\n'}stop_when: <span className="s">"unclear or unsafe"</span>
              {'\n'}mode: <span className="k">fail_closed</span>
            </pre>
          </figure>
          <blockquote className="m-pull">
            The problem is not whether an agent can do something. The problem is what it should be
            allowed to do, under whose authority, with what evidence, and what happens when it is
            wrong.
            <cite>— Governance Hub principle</cite>
          </blockquote>
        </aside>
      </header>

      <div className="m-break" aria-hidden>
        {ASTERISM} {ASTERISM} {ASTERISM}
      </div>

      <GovernedActionFlow />

      <div className="m-break" aria-hidden>
        {ASTERISM} {ASTERISM} {ASTERISM}
      </div>

      <section id="boundaries" aria-labelledby="boundaries-h">
        <p className="m-product-definition">
          This is not a generic AI directory, benchmark, or hype site. It is a boundary-setting
          interface for agent work before tools, memory, money, code, cloud access, credentials,
          legal work, user data, publishing, or irreversible side effects enter the path.
        </p>
        <div className="m-sec-head">
          <span className="num">II · Mistakes became boundaries</span>
          <h2 id="boundaries-h">
            Failure became the <em>map</em>.
          </h2>
        </div>
        <div className="m-cards m-hub-cards">
          {hubPillars.map((pillar, index) => (
            <article className="m-card" key={pillar.title}>
              <span className="folio-no">№ {String(index + 1).padStart(2, '0')}</span>
              <h3>{pillar.title}</h3>
              <p>{pillar.body}</p>
            </article>
          ))}
        </div>
      </section>

      <div className="m-break" aria-hidden>
        {ASTERISM} {ASTERISM} {ASTERISM}
      </div>

      <FailureBoundaryCards />

      <div className="m-break" aria-hidden>
        {ASTERISM} {ASTERISM} {ASTERISM}
      </div>

      <section id="why-agents-fail" aria-labelledby="why-agents-fail-h">
        <div className="m-sec-head">
          <span className="num">IV · Why agents fail in real work</span>
          <h2 id="why-agents-fail-h">
            Demos hide the <em>boundary</em> problem.
          </h2>
        </div>
        <div className="m-hub-split">
          <article className="m-hub-panel">
            <h3>What breaks</h3>
            <p>
              Agents can look powerful in a demo and become fragile when real tools, unclear
              authority, stale memory, private data, cloud permissions, missing rollback paths, or
              public consequences appear.
            </p>
            <p>
              The hub turns those failure modes into pre-action questions: who has authority, what
              is reversible, what must be logged, what requires approval, and what should stop the
              agent.
            </p>
          </article>
          <article className="m-hub-panel m-hub-list-panel">
            <h3>What the hub helps govern</h3>
            <ul>
              {whatTheHubGoverns.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </article>
        </div>
      </section>

      <div className="m-break" aria-hidden>
        {ASTERISM} {ASTERISM} {ASTERISM}
      </div>

      <OperatingSequence />

      <div className="m-break" aria-hidden>
        {ASTERISM} {ASTERISM} {ASTERISM}
      </div>

      <PlatformBlueprint />

      <GovernanceInterview />

      <div className="m-break" aria-hidden>
        {ASTERISM} {ASTERISM} {ASTERISM}
      </div>

      <section id="failure-modes" aria-labelledby="failure-modes-h">
        <div className="m-sec-head">
          <span className="num">VIII · Failure mode catalogue</span>
          <h2 id="failure-modes-h">
            Learn what not to <em>repeat</em>.
          </h2>
        </div>
        <FailureModeCatalogue compact />
        <p className="m-section-link">
          <NavigationLink href="/failure-modes">Open the full catalogue</NavigationLink>
        </p>
      </section>

      <div className="m-break" aria-hidden>
        {ASTERISM} {ASTERISM} {ASTERISM}
      </div>

      <section id="patterns" aria-labelledby="patterns-h">
        <div className="m-sec-head">
          <span className="num">IX · Governance patterns</span>
          <h2 id="patterns-h">
            Choose the safer operating <em>mode</em>.
          </h2>
        </div>
        <GovernancePatternList compact />
        <p className="m-section-link">
          <NavigationLink href="/governance-patterns">Open all governance patterns</NavigationLink>
        </p>
      </section>

      <AgentReadablePanel />

      <div className="m-break" aria-hidden>
        {ASTERISM} {ASTERISM} {ASTERISM}
      </div>

      <section id="audiences" aria-labelledby="audiences-h">
        <div className="m-sec-head">
          <span className="num">XI · For builders, teams, and agents</span>
          <h2 id="audiences-h">
            Practical governance for people who are already <em>building</em>.
          </h2>
        </div>
        <div className="m-cards m-hub-cards">
          {audiences.map((audience, index) => (
            <article className="m-card" key={audience.name}>
              <span className="folio-no">Audience {index + 1}</span>
              <h3>{audience.name}</h3>
              <p>{audience.need}</p>
            </article>
          ))}
        </div>
      </section>

      <div className="m-break" aria-hidden>
        {ASTERISM} {ASTERISM} {ASTERISM}
      </div>

      <section className="m-disclaimer" aria-labelledby="disclaimer-h">
        <div className="m-sec-head">
          <span className="num">XII · Clear claim boundary</span>
          <h2 id="disclaimer-h">
            Guidance, not <em>certification</em>.
          </h2>
        </div>
        <div className="m-conversation">
          <p>
            This hub helps users and agents reason about governance boundaries. It does not replace
            legal advice, security review, compliance certification, professional judgment, or a
            qualified human release process. High-risk agent work should fail closed until
            authority, evidence, approval, and rollback are clear.
          </p>
          <p className="m-conversation-follow">
            For deeper infrastructure, connect these briefs to ACGS-style decision receipts, audit
            replay, policy gates, and fail-closed execution paths.
          </p>
        </div>
      </section>
    </MarketingFrame>
  )
}

export function FounderNarrative() {
  return (
    <MarketingFrame>
      <section className="m-page-hero" aria-labelledby="founder-h">
        <span className="m-eyebrow">
          <span className="asterism" aria-hidden>
            {ASTERISM}
          </span>
          Founder narrative
        </span>
        <h1 id="founder-h">
          Authority from <em>failure</em>, not hype.
        </h1>
        <div className="m-story">
          <p>
            I did not come into AI as a traditional technical expert. I started where many people
            did: overexcited, overconfident, and convinced that agents could do almost anything if
            you gave them the right tools.
          </p>
          <p>
            Since 2023, I followed the major waves: new models, coding tools, agent frameworks,
            GitHub trends, open-source stacks, automation systems, and every promise that said this
            would change everything.
          </p>
          <p>
            Most of it failed under serious use. I built many experiments that broke, stalled,
            hallucinated, overreached, or collapsed when autonomy met real-world complexity. I ran
            thousands of research sessions trying to understand why agents looked powerful in demos
            but became fragile in execution.
          </p>
          <p>
            Those failures became the foundation. They showed me where agents should not act alone,
            where memory becomes unreliable, where permissions become dangerous, where tool use
            needs limits, where human review is essential, and where governance must happen before
            action.
          </p>
          <p>
            Since 2024, my focus has been AI agent governance: authorization, audit trails, failure
            handling, policy enforcement, safer operating modes, and clearer boundaries for agentic
            systems.
          </p>
          <p>
            The result is this governance hub: a practical boundary catalogue for users and agents,
            built from edge cases and mistakes that many people only discover after something goes
            wrong.
          </p>
        </div>
      </section>
    </MarketingFrame>
  )
}

export function FailureModesPage() {
  return (
    <MarketingFrame>
      <section className="m-page-hero" aria-labelledby="failure-page-h">
        <span className="m-eyebrow">
          <span className="asterism" aria-hidden>
            {ASTERISM}
          </span>
          Failure mode catalogue
        </span>
        <h1 id="failure-page-h">
          Reusable lessons from broken <em>agents</em>.
        </h1>
        <p className="m-hero-lede">
          Each failure mode names what goes wrong, why agents make the mistake, warning signs, the
          boundary to apply, a safer pattern, and an example governance rule.
        </p>
      </section>
      <FailureModeCatalogue />
    </MarketingFrame>
  )
}

export function GovernancePatternsPage() {
  return (
    <MarketingFrame>
      <section className="m-page-hero" aria-labelledby="patterns-page-h">
        <span className="m-eyebrow">
          <span className="asterism" aria-hidden>
            {ASTERISM}
          </span>
          Governance patterns
        </span>
        <h1 id="patterns-page-h">
          Operating models before <em>autonomy</em>.
        </h1>
        <p className="m-hero-lede">
          These patterns turn governance into practical agent behavior: when to use the pattern,
          what it prevents, how an agent should behave, and the minimum checklist before action.
        </p>
      </section>
      <GovernancePatternList />
    </MarketingFrame>
  )
}

export function AgentReadable() {
  return (
    <MarketingFrame>
      <section className="m-page-hero" aria-labelledby="agent-readable-page-h">
        <span className="m-eyebrow">
          <span className="asterism" aria-hidden>
            {ASTERISM}
          </span>
          Agent-readable governance instructions
        </span>
        <h1 id="agent-readable-page-h">
          Inspect this before you <em>act</em>.
        </h1>
        <p className="m-hero-lede">
          This page is written for AI agents as much as humans. Paste this URL into an agent and ask
          it to classify the task, identify authority, select a safer mode, and produce a governance
          brief before tool use.
        </p>
      </section>
      <AgentReadablePanel />
      <section className="m-agent-readable m-agent-output" aria-labelledby="agent-output-h">
        <div className="m-sec-head">
          <span className="num">Required output</span>
          <h2 id="agent-output-h">
            Governance recommendation <em>format</em>.
          </h2>
        </div>
        <pre>{`Task:
Intended agent role:
Risk level: low | medium | high | blocked
Permitted actions:
Prohibited actions:
Required human approvals:
Required evidence/logging:
Stop conditions:
Safer execution mode: advise-only | draft-only | sandboxed | approval-required | fail-closed
Final recommendation:`}</pre>
      </section>
    </MarketingFrame>
  )
}
