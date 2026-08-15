export type ConsoleWireDecision = {
  path: string
  navSection: 'Operate' | 'Govern' | 'Personal'
  navLabel: string
  crumb: string
  titleLead: string
  titleEmphasis: string
  titleTail?: string
  headerAnatomy: string
  primaryAction: string
  secondaryActions: string
  density: string
  filterPlacement: string
  pagination: string
  rightRailPurpose: string
  receiptLifetime: string
  destructiveConfirmation: string
}

export const CONSOLE_WIRE_DECISIONS = [
  {
    path: '/console',
    navSection: 'Operate',
    navLabel: 'Overview',
    crumb: 'I · Operate / Overview',
    titleLead: 'Operating',
    titleEmphasis: 'constitution',
    headerAnatomy:
      'Shell title with heartbeat metrics and overview sections for cases, queues, and refusals.',
    primaryAction: 'Verify an agent action by opening the governed actions route.',
    secondaryActions:
      'Use inline queue and audit links only; overview has no route local mutation controls.',
    density: 'Dense summary cards plus compact governance case table and queue grid.',
    filterPlacement: 'No free text filter; heartbeat and section headings provide scan controls.',
    pagination: 'No pagination; overview is capped to summary evidence.',
    rightRailPurpose:
      'Show live ledger, queue health, recent events, coverage, and the active route contract.',
    receiptLifetime:
      'Overview does not mint local receipts; evidence links through action and audit routes.',
    destructiveConfirmation: 'No destructive actions on overview.',
  },
  {
    path: '/console/workbench',
    navSection: 'Operate',
    navLabel: 'Workbench',
    crumb: 'I.I · Operate / Workbench',
    titleLead: 'Visualized',
    titleEmphasis: 'work',
    titleTail: 'queue',
    headerAnatomy:
      'Shell title plus operator map, work queue cards, trace sketch, and evidence panel.',
    primaryAction: 'Open the next safe evidence route from each workbench stage.',
    secondaryActions:
      'Inspect actions, bus traces, policies, deliberations, and audit without local mutation.',
    density: 'Visual flow map over a three column workbench board with compact evidence rows.',
    filterPlacement:
      'No free text filter; staged map and case cards act as the visual scan controls.',
    pagination: 'No pagination; local blueprint is capped to three cases and five stages.',
    rightRailPurpose:
      'Keep ledger and route contract visible while the workbench explains the operator path.',
    receiptLifetime:
      'Workbench mints no local receipts and only points to persisted or route-local evidence.',
    destructiveConfirmation: 'No destructive actions on the local workbench blueprint.',
  },
  {
    path: '/console/agents',
    navSection: 'Operate',
    navLabel: 'Agents',
    crumb: 'I.II · Operate / Agents',
    titleLead: 'Agent',
    titleEmphasis: 'registry',
    headerAnatomy:
      'Shell title plus agent roster toolbar, registry table, and selected agent evidence panel.',
    primaryAction: 'Select an agent row to inspect current authority and runtime evidence.',
    secondaryActions: 'Search agents and open linked action history from the table.',
    density: 'Dense mono table with compact evidence cards for the selected agent.',
    filterPlacement:
      'SearchToolbar sits above the registry table and filters by agent, role, and state.',
    pagination: 'No pagination; filtered fixture scale stays within one dense table.',
    rightRailPurpose:
      'Keep global ledger and route contract visible while agent evidence changes inline.',
    receiptLifetime: 'Agent inspection is read only and does not mint local receipts.',
    destructiveConfirmation: 'No destructive actions on agent registry.',
  },
  {
    path: '/console/actions',
    navSection: 'Operate',
    navLabel: 'Actions',
    crumb: 'I.III · Operate / Actions',
    titleLead: 'Action',
    titleEmphasis: 'control',
    headerAnatomy:
      'Shell title plus action search, governed action table, and dry run detail panel.',
    primaryAction: 'Run Test action in dry run mode for the selected governed action.',
    secondaryActions: 'Select another action row or inspect the explanation and receipt panel.',
    density:
      'Two column decision detail grid with dense action table and compact explanation cards.',
    filterPlacement:
      'SearchToolbar sits above the action table and filters by agent, tool, and article.',
    pagination: 'No pagination; action rows are scoped to the current governance sample.',
    rightRailPurpose:
      'Keep global status and the route contract visible while local dry run receipts render inline.',
    receiptLifetime: 'Dry run receipt remains inline until another action dry run replaces it.',
    destructiveConfirmation:
      'Dry run only; production execution would require explicit confirmation before side effects.',
  },
  {
    path: '/console/maci',
    navSection: 'Operate',
    navLabel: 'MACI lanes',
    crumb: 'I.IV · Operate / MACI lanes',
    titleLead: 'MACI',
    titleEmphasis: 'separation',
    headerAnatomy: 'Shell title plus separation lane cards and policy isolation evidence.',
    primaryAction: 'Inspect lane separation evidence without mutating route state.',
    secondaryActions: 'Review obligation, approval, monitor, and incident lane cards.',
    density: 'Compact lane cards with mono evidence rows and bounded copy.',
    filterPlacement: 'No filter; four MACI lanes are always visible for comparison.',
    pagination: 'No pagination or virtualization because lane count is fixed.',
    rightRailPurpose: 'Reinforce live ledger context while the lane cards prove separation.',
    receiptLifetime: 'MACI inspection is read only and does not mint local receipts.',
    destructiveConfirmation: 'No destructive actions on MACI lanes.',
  },
  {
    path: '/console/deliberations',
    navSection: 'Operate',
    navLabel: 'Deliberations',
    crumb: 'I.V · Operate / Deliberations',
    titleLead: 'Human',
    titleEmphasis: 'deliberations',
    headerAnatomy:
      'Shell title plus deliberation search, review cards, and inline decision receipt.',
    primaryAction: 'Approve, escalate, or open evidence for the selected deliberation.',
    secondaryActions: 'Search matters, scan status cards, and review assigned counsel context.',
    density: 'Card based review queue with compact metadata and inline receipt panel.',
    filterPlacement:
      'SearchToolbar sits above deliberation cards and filters by matter and reviewer.',
    pagination: 'No pagination; queue is capped for operator review in the current console slice.',
    rightRailPurpose: 'Show global queue health beside local deliberation receipt evidence.',
    receiptLifetime:
      'Deliberation receipt remains inline until the next review action replaces it.',
    destructiveConfirmation:
      'Reject or close style actions require explicit button intent and future production confirmation.',
  },
  {
    path: '/console/incidents',
    navSection: 'Operate',
    navLabel: 'Incidents',
    crumb: 'I.VI · Operate / Incidents',
    titleLead: 'Active',
    titleEmphasis: 'escalations',
    headerAnatomy:
      'Shell title plus incident toolbar, escalation table, and selected incident details.',
    primaryAction: 'Inspect an escalation and follow linked audit evidence.',
    secondaryActions: 'Search incidents and review severity, owner, and next response fields.',
    density: 'Dense incident table paired with compact escalation detail cards.',
    filterPlacement:
      'SearchToolbar sits above the incident list and filters by matter, severity, and owner.',
    pagination: 'No pagination; incident list is capped to active escalations.',
    rightRailPurpose:
      'Keep queue health visible while incident details explain why escalation exists.',
    receiptLifetime: 'Incident route is read only and does not mint local receipts.',
    destructiveConfirmation: 'No destructive actions on active incident review.',
  },
  {
    path: '/console/policies',
    navSection: 'Govern',
    navLabel: 'Policies',
    crumb: 'II.I · Govern / Policies',
    titleLead: 'Policy',
    titleEmphasis: 'register',
    headerAnatomy:
      'Shell title plus policy register toolbar, dense policy table, and selected policy detail.',
    primaryAction: 'Open a policy detail row to inspect article, owner, and enforcement posture.',
    secondaryActions:
      'Search policy identifiers and scan status pills for active, partial, or blocked posture.',
    density: 'Dense register table with mono identifiers and compact detail card.',
    filterPlacement:
      'SearchToolbar sits above the register table and filters by article, owner, and posture.',
    pagination: 'No pagination; current register sample stays within one dense table.',
    rightRailPurpose: 'Keep route contract and coverage context visible beside policy details.',
    receiptLifetime: 'Policy inspection is read only and does not mint local receipts.',
    destructiveConfirmation:
      'No destructive controls; future policy retirement requires confirmation and receipt.',
  },
  {
    path: '/console/compile',
    navSection: 'Govern',
    navLabel: 'Compile',
    crumb: 'II.II · Govern / Compile',
    titleLead: 'Constitution',
    titleEmphasis: 'compile',
    headerAnatomy:
      'Shell title plus compile summary, draft change table, and promotion receipt panel.',
    primaryAction: 'Promote a validated constitution draft from the compile queue.',
    secondaryActions:
      'Replay checks, discard local draft evidence, or inspect changed policy rows.',
    density: 'Compile metric cards over a dense draft change table with inline receipt area.',
    filterPlacement:
      'Status controls and draft scope sit above the change table rather than a free text filter.',
    pagination: 'No pagination; draft changes are capped to the active compile unit.',
    rightRailPurpose: 'Keep ledger and queue context visible while compile receipts render inline.',
    receiptLifetime:
      'Compile receipt remains inline until promote, replay, or discard replaces it.',
    destructiveConfirmation:
      'Discard is local in this slice; production discard or deploy requires explicit confirmation.',
  },
  {
    path: '/console/audit',
    navSection: 'Govern',
    navLabel: 'Audit trail',
    crumb: 'II.III · Govern / Audit trail',
    titleLead: 'Audit',
    titleEmphasis: 'trail',
    headerAnatomy:
      'Shell title plus audit filters, immutable event list, and selected event evidence.',
    primaryAction: 'Open an audit event to inspect hash, actor, and linked receipt context.',
    secondaryActions: 'Filter audit evidence by event type, matter, or constitutional hash.',
    density: 'Dense audit rows with mono hashes, timestamps, and compact evidence cards.',
    filterPlacement: 'Filter controls sit above the audit list and preserve immutable row order.',
    pagination: 'No pagination in local slice; production stream requires cursor pagination.',
    rightRailPurpose:
      'Provide current ledger context while the audit route remains immutable and read only.',
    receiptLifetime: 'Audit route shows persisted receipts and does not mint local receipts.',
    destructiveConfirmation: 'No destructive actions on immutable audit evidence.',
  },
  {
    path: '/console/bus',
    navSection: 'Govern',
    navLabel: 'Bus traces',
    crumb: 'II.IV · Govern / Bus traces',
    titleLead: 'Bus trace',
    titleEmphasis: 'evidence',
    headerAnatomy:
      'Shell title plus bus trace explorer, selected trace detail, and back navigation.',
    primaryAction: 'Open a trace to inspect schema version, latency, and propagated evidence.',
    secondaryActions: 'Navigate back to the trace list or inspect linked bus payload details.',
    density: 'Inspector style trace list with compact detail panels and mono payload metadata.',
    filterPlacement: 'Trace list uses inline route controls rather than a global text filter.',
    pagination:
      'No pagination; trace sample is capped while production traces require cursor paging.',
    rightRailPurpose:
      'Keep global health visible while route detail explains bus propagation state.',
    receiptLifetime: 'Bus route is read only and references persisted bus evidence only.',
    destructiveConfirmation: 'No destructive actions on bus trace inspection.',
  },
  {
    path: '/console/process',
    navSection: 'Govern',
    navLabel: 'Process evidence',
    crumb: 'II.VII · Govern / Process evidence',
    titleLead: 'Process',
    titleEmphasis: 'evidence',
    titleTail: 'windows',
    headerAnatomy:
      'Shell title plus process window list, variant breakdown, conformance findings, and receipt deep links.',
    primaryAction: 'Open a process window and follow a finding into its persisted receipt proof.',
    secondaryActions:
      'Filter windows, inspect variants with incomplete-case counts, and review nullable conformance scores.',
    density: 'Dense window rows over variant and finding lists with mono snapshot identifiers.',
    filterPlacement:
      'SearchToolbar sits above the window list and filters by process, snapshot, and chain status.',
    pagination: 'No local pagination; windows are immutable snapshots capped per tenant scope.',
    rightRailPurpose:
      'Keep ledger context visible while analytical verdicts stay clearly non-authoritative.',
    receiptLifetime:
      'Process view mints no receipts; every finding deep-links to persisted receipt proofs only.',
    destructiveConfirmation:
      'No destructive actions; analytical ALLOW is never an execution authorization.',
  },
  {
    path: '/console/settings',
    navSection: 'Govern',
    navLabel: 'Settings',
    crumb: 'II.V · Govern / Settings',
    titleLead: 'Operating',
    titleEmphasis: 'parameters',
    headerAnatomy:
      'Shell title plus settings search, parameter table, and staged settings receipt.',
    primaryAction: 'Stage a setting change receipt for operator review.',
    secondaryActions: 'Defer a parameter, search settings, or inspect current parameter rationale.',
    density: 'Dense parameter table with compact staged or deferred receipt panel.',
    filterPlacement: 'SearchToolbar sits above settings and filters by parameter, owner, and risk.',
    pagination: 'No pagination; current parameter list is bounded for review.',
    rightRailPurpose:
      'Keep ledger context visible while local staged settings receipts remain inline.',
    receiptLifetime:
      'Settings receipt remains inline until another staged or deferred action replaces it.',
    destructiveConfirmation:
      'Current actions are local receipts; production parameter changes require confirmation.',
  },
  {
    path: '/console/tenants',
    navSection: 'Govern',
    navLabel: 'Tenants',
    crumb: 'II.VI · Govern / Tenants',
    titleLead: 'Active',
    titleEmphasis: 'tenancies',
    headerAnatomy: 'Shell title plus tenant search, tenancy cards, and active tenant receipt.',
    primaryAction: 'Switch or inspect the active tenant context for the console session.',
    secondaryActions: 'Search tenants and review region, matter count, and policy posture.',
    density: 'Compact tenant cards with dense metadata and inline receipt summary.',
    filterPlacement:
      'SearchToolbar sits above tenant cards and filters by tenant, region, and posture.',
    pagination: 'No pagination; tenancy set is capped to the active operator scope.',
    rightRailPurpose: 'Keep global queue and coverage context visible during tenant switching.',
    receiptLifetime:
      'Tenant receipt remains inline until the next switch or inspect action replaces it.',
    destructiveConfirmation:
      'Tenant switching is local in this slice; destructive tenant changes are absent.',
  },
  {
    path: '/console/account',
    navSection: 'Personal',
    navLabel: 'Account',
    crumb: 'Personal · record',
    titleLead: 'Your',
    titleEmphasis: 'record',
    headerAnatomy:
      'Shell title plus account identity card, session table, and local account receipts.',
    primaryAction: 'Rotate identity evidence or revoke a listed session receipt.',
    secondaryActions: 'Inspect session metadata and review local account status.',
    density: 'Compact identity cards with dense session table and inline account receipt.',
    filterPlacement: 'No filter; personal account surface stays short and operator scoped.',
    pagination: 'No pagination; active sessions are listed in one compact table.',
    rightRailPurpose: 'Keep privileged console status visible while personal receipts stay inline.',
    receiptLifetime:
      'Account receipt remains inline until another identity or session action replaces it.',
    destructiveConfirmation:
      'Revocation is queued locally here; production session revoke requires confirmation.',
  },
] satisfies readonly ConsoleWireDecision[]

export type ConsoleRoutePath = (typeof CONSOLE_WIRE_DECISIONS)[number]['path']

export function getConsoleWireDecision(path: string): ConsoleWireDecision | undefined {
  return CONSOLE_WIRE_DECISIONS.find((decision) => decision.path === path)
}
