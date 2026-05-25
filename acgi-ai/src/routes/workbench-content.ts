export const WORKBENCH_READINESS_SUMMARY = '35/36 local pass · 1 hosted proof pending'

export const WORKBENCH_STAGES = [
  {
    step: '01',
    title: 'Work queue',
    signal: 'Who owns the next safe action?',
    body: 'Intake every agent run as a case with owner, risk class, source system, and the next reversible operator action visible before drill-down.',
    posture: 'partial',
    route: '/console/actions',
    cta: 'Open actions',
  },
  {
    step: '02',
    title: 'Trace graph',
    signal: 'What did the agent actually do?',
    body: 'Render model calls, tool calls, handoffs, guardrails, and custom events as a navigable run path instead of a flat log stream.',
    posture: 'confirmed',
    route: '/console/bus',
    cta: 'Inspect traces',
  },
  {
    step: '03',
    title: 'Evaluation panel',
    signal: 'Did quality regress?',
    body: 'Keep dataset tests, code checks, AI judgments, and human labels beside the trace so teams can compare versions before promotion.',
    posture: 'partial',
    route: '/console/policies',
    cta: 'Review policy',
  },
  {
    step: '04',
    title: 'Human release gate',
    signal: 'Can a reviewer reject with context?',
    body: 'Show policy citations, risk deltas, evidence gaps, and release authority in one pane before any privileged action proceeds.',
    posture: 'blocked',
    route: '/console/deliberations',
    cta: 'Open reviews',
  },
  {
    step: '05',
    title: 'Evidence room',
    signal: 'What proof can leave the product?',
    body: 'Export receipts, hashes, snapshots, and replay references as buyer-readable packets with claim boundaries attached.',
    posture: 'confirmed',
    route: '/console/audit',
    cta: 'Open audit',
  },
] as const

export const RESEARCH_INPUTS = [
  {
    source: 'NIST AI RMF',
    cue: 'Govern · Map · Measure · Manage translated into the work queue.',
  },
  {
    source: 'ISO/IEC 42001',
    cue: 'AI management-system ownership, objectives, controls, and improvement loops.',
  },
  {
    source: 'EU AI Act',
    cue: 'Risk, transparency, traceability, human oversight, robustness, and cybersecurity gates.',
  },
  {
    source: 'OWASP GenAI Security Project',
    cue: 'Prompt injection, excessive agency, leakage, and overreliance as visible controls.',
  },
  {
    source: 'OpenTelemetry GenAI',
    cue: 'Common telemetry names for model calls, tool calls, spans, logs, and metrics.',
  },
  {
    source: 'OpenAI Agents SDK',
    cue: 'Tracing and guardrails as first-class workflow objects, not hidden developer logs.',
  },
  {
    source: 'LangSmith + Phoenix',
    cue: 'Trace search, dashboards, evaluations, and annotations for failure investigation.',
  },
  {
    source: 'Humanloop evaluators',
    cue: 'Code, AI, and human judgment lanes for offline regression and live monitoring.',
  },
  {
    source: 'WCAG 2.2',
    cue: 'Text-first, keyboard-reviewable visual work that does not rely on color alone.',
  },
] as const

export const PLATFORM_REQUIREMENT_LANES = [
  {
    pillar: 'Govern',
    source: 'NIST AI RMF + ISO/IEC 42001',
    title: 'Operate the governance loop',
    question: 'Who owns the next safe action?',
    visual:
      'Show owner, risk class, AI objective, control, and reversible next step before tables.',
    proof: 'govern · map · measure · manage',
    route: '/console/actions',
    cta: 'Open queue',
  },
  {
    pillar: 'Regulate',
    source: 'EU AI Act',
    title: 'Hold release with context',
    question: 'Can a reviewer reject for the right reason?',
    visual:
      'Keep risk, transparency, traceability, oversight, robustness, and cybersecurity gaps together.',
    proof: 'risk · oversight · traceability',
    route: '/console/deliberations',
    cta: 'Open reviews',
  },
  {
    pillar: 'Secure',
    source: 'OWASP Agentic AI',
    title: 'Constrain agent agency',
    question: 'Which guardrail stopped or scoped the agent?',
    visual:
      'Surface prompt-injection, tool-scope, leakage, and overreliance controls beside the trace.',
    proof: 'guardrail · least agency',
    route: '/console/bus',
    cta: 'Inspect trace',
  },
  {
    pillar: 'Observe',
    source: 'OpenTelemetry GenAI',
    title: 'Make traces navigable',
    question: 'What did the model and tools actually do?',
    visual:
      'Render spans, model calls, tool calls, logs, metrics, and receipts as a readable path.',
    proof: 'span · tool · receipt',
    route: '/console/bus',
    cta: 'Inspect telemetry',
  },
  {
    pillar: 'Measure',
    source: 'Evaluators + human labels',
    title: 'Compare quality before promotion',
    question: 'Did quality regress or improve?',
    visual:
      'Place offline tests, AI judgments, human labels, and policy citations next to the case.',
    proof: 'eval · label · citation',
    route: '/console/policies',
    cta: 'Review policy',
  },
  {
    pillar: 'Use',
    source: 'WCAG 2.2 + service design',
    title: 'Keep the first minute obvious',
    question: 'Can a new operator act without a manual?',
    visual: 'Use text labels, keyboard-safe targets, claim boundaries, and a plain proof ladder.',
    proof: 'text · focus · boundary',
    route: '/console/workbench#guided-review-path',
    cta: 'Follow guide',
  },
] as const

export const WORKBENCH_GUIDED_PATH = [
  {
    step: '01',
    title: 'Choose the case',
    instruction: 'Start with the highest-risk partial or blocked card before opening dense tables.',
    proof: 'case id · owner · risk',
    route: '/console/actions',
    cta: 'Open queue',
  },
  {
    step: '02',
    title: 'Follow the path',
    instruction: 'Read goal, model call, guardrail, policy decision, and receipt as one trace.',
    proof: 'trace id · guardrail',
    route: '/console/bus',
    cta: 'Inspect trace',
  },
  {
    step: '03',
    title: 'Check the hold',
    instruction: 'Compare evaluation, policy citation, and authority gaps before promotion.',
    proof: 'eval · citation · authority',
    route: '/console/deliberations',
    cta: 'Open review',
  },
  {
    step: '04',
    title: 'Export bounded proof',
    instruction: 'Leave the product with receipts, hashes, and explicit non-production boundaries.',
    proof: 'receipt · hash · boundary',
    route: '/console/audit',
    cta: 'Open proof',
  },
] as const

export const OPERATOR_CHECKLIST = [
  {
    label: 'Start here',
    cue: 'Open the highest-risk case first and make the owner plus next reversible action visible.',
    body: 'Open the highest-risk case and confirm owner, source route, and next reversible action.',
    proof: 'owner + reversible action',
    route: '/console/actions',
    cta: 'Open queue',
  },
  {
    label: 'Hold release',
    cue: 'Block promotion when trace, evaluation, authority, or claim-boundary evidence is missing.',
    body: 'Keep promotion blocked when trace, evaluation, authority, or claim-boundary proof is missing.',
    proof: 'blocked reason + reviewer lane',
    route: '/console/deliberations',
    cta: 'Open reviews',
  },
  {
    label: 'Export proof',
    cue: 'Package receipts, hashes, snapshots, and replay refs only after the boundary is attached.',
    body: 'Package receipts, hashes, snapshots, and replay refs only after the claim boundary is attached.',
    proof: 'receipt hash + export boundary',
    route: '/console/audit',
    cta: 'Export packet',
  },
] as const

export const WORKBENCH_DECISION_RAIL = [
  {
    step: '01',
    title: 'Pick the case',
    prompt: 'Start with the riskiest blocked or partial work item before opening dense tables.',
    proof: 'owner · source · risk',
    route: '/console/actions',
    cta: 'Open queue',
  },
  {
    step: '02',
    title: 'Inspect the path',
    prompt: 'Read trace, guardrail, evaluation, and policy evidence beside the work item.',
    proof: 'trace · eval · policy',
    route: '/console/bus',
    cta: 'Inspect trace',
  },
  {
    step: '03',
    title: 'Decide and export',
    prompt: 'Hold, route review, or export bounded proof with the claim boundary attached.',
    proof: 'hold · review · receipt',
    route: '/console/audit',
    cta: 'Open proof',
  },
] as const

export const LAUNCH_PROOF_LANES = [
  {
    title: 'Local readiness',
    state: WORKBENCH_READINESS_SUMMARY,
    proof: 'make verify + platform-readiness',
    cue: 'Safe for internal blueprint review; not deployment or assurance proof.',
    body: 'Use this only as local readiness evidence for the workbench and release packet.',
    route: '/console/actions',
    cta: 'Review queue',
  },
  {
    title: 'Live verifier',
    state: 'blocked until deploy',
    proof: 'verify:production-live',
    cue: 'DNS, HTTPS, health, headers, assets, and auth must pass after deploy.',
    body: 'Attach DNS, HTTPS, health, headers, asset, and auth evidence after credentialed deploy.',
    route: '/console/settings',
    cta: 'Open settings',
  },
  {
    title: 'Assurance packet',
    state: 'external proof required',
    proof: 'legal + pentest + WCAG + Storybook',
    cue: 'External proof replaces blockers before any production or compliance claim.',
    body: 'Replace pending blockers with legal, security, accessibility, and hosted buyer evidence.',
    route: '/console/audit',
    cta: 'Open audit',
  },
] as const

export const CASE_CARDS = [
  {
    id: 'GOV-214',
    title: 'Claim launch copy',
    detail: 'Needs legal claim matrix',
    posture: 'blocked',
  },
  {
    id: 'BUS-087',
    title: 'Trace regression',
    detail: 'One orphan response under review',
    posture: 'partial',
  },
  {
    id: 'REL-031',
    title: 'Buyer proof packet',
    detail: 'Hosted Storybook proof pending',
    posture: 'partial',
  },
] as const

export const EVIDENCE_ROWS = [
  { label: 'Receipt', value: 'rcpt_608508a9', state: 'hash-chained' },
  { label: 'Policy', value: 'EU AI Act Art. 14', state: 'human oversight' },
  { label: 'Eval', value: 'offline regression set', state: '2 failures held' },
  { label: 'Release', value: 'operator approval', state: 'not production proof' },
] as const
