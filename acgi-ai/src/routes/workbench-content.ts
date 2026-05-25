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
    source: 'OWASP GenAI Security Project',
    cue: 'Prompt injection, excessive agency, leakage, and overreliance as visible controls.',
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
