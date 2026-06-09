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

export const FRAMEWORK_INTEGRATION_RAIL = [
  {
    step: '01',
    title: 'Normalize framework calls',
    source: 'Claude/Codex-style · MCP-style · OpenAI Responses',
    proof: 'tool_call_from_hook_payload',
    body: 'Translate common agent-framework tool-call shapes into one governed request before policy decisions run.',
    route: '/products/acgs',
    cta: 'Open runtime path',
  },
  {
    step: '02',
    title: 'Gate before side effects',
    source: 'RuleSetPolicy · deny · escalate',
    proof: 'gove-zone gate --policy-bundle',
    body: 'Keep allow, deny, and escalate outcomes visible before a host executes a privileged tool call.',
    route: '/console/policies',
    cta: 'Open policy',
  },
  {
    step: '03',
    title: 'Emit governed receipts',
    source: 'OpenAI Chat · LangChain-style · batched calls',
    proof: 'receipt_count + audit hash',
    body: 'Record one receipt per child call so batches, denials, and reviewer handoffs stay inspectable.',
    route: '/console/audit',
    cta: 'Open receipts',
  },
  {
    step: '04',
    title: 'Adopt without lock-in',
    source: 'generic payloads · malformed batch guard',
    proof: 'runtime.malformed_batch',
    body: 'Treat malformed recognized batches as deny receipts instead of hiding unsupported framework behavior.',
    route: '/console/bus',
    cta: 'Inspect traces',
  },
] as const

export const AGENT_FRAMEWORK_STARTER_KITS = [
  {
    framework: 'OpenAI Responses starter',
    entry: 'output function_call payload',
    command:
      'uv run --package gove-zone gove-zone gate --event-file openai-responses-tool-call.json --policy-bundle policy.bundle.json',
    proof: 'responses.output[].type=function_call',
    next: 'Pick payload → run gate → attach receipt before a tool side effect.',
    route: '/products/acgs',
    cta: 'Open runtime path',
  },
  {
    framework: 'LangChain tool-call starter',
    entry: 'message.tool_calls[] payload',
    command:
      'uv run --package gove-zone gove-zone gate --event-file langchain-tool-calls.json --policy-bundle policy.bundle.json',
    proof: 'tool_calls[] → receipt_count',
    next: 'Run the local gate with the policy bundle and inspect the receipt count.',
    route: '/console/bus',
    cta: 'Inspect traces',
  },
  {
    framework: 'MCP / Claude / Codex hook starter',
    entry: 'runtime hook event',
    command: 'uv run --package gove-zone gove-zone setup --format markdown --enforce',
    proof: '.claude/hooks/acgs-emit-receipt.py',
    next: 'Render copy-paste setup, then keep enforce mode explicit before adoption.',
    route: '/console/settings',
    cta: 'Open settings',
  },
  {
    framework: 'Benchmark fixture starter',
    entry: 'AgentDojo / InjecAgent / ToolEmu-style fixture',
    command:
      'uv run --package gove-zone gove-zone eval --bundle policy.bundle.json --scenarios scenarios.json',
    proof: 'attack/utility metrics',
    next: 'Replay local scenarios before treating framework adoption as ready.',
    route: '/console/policies',
    cta: 'Open policy',
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

export const PRODUCTION_CUTOVER_LANES = [
  {
    title: 'Marketing origin',
    state: 'already-live',
    proof: 'marketing-dns-live + marketing-https-live',
    body: 'Saved verifier sees acgs.ai resolving and HTTPS 200. Keep this origin stable while console and Storybook cut over.',
    route: '/console/audit',
    cta: 'Review verifier',
  },
  {
    title: 'Console origin',
    state: 'dns-or-service-blocked',
    proof: 'console-dns-live + healthz + headers',
    body: 'Create or repair console.acgs.ai DNS, deploy the console service, then verify /healthz plus HSTS, CSP, XFO, and referrer headers.',
    route: '/console/settings',
    cta: 'Open settings',
  },
  {
    title: 'Storybook proof',
    state: 'dns-or-pages-blocked',
    proof: 'storybook-dns-live + https + storybook-manifest-live',
    body: 'Publish the buyer-evidence artifact, configure storybook.acgs.ai, then verify HTTPS and a manifest with all eight story ids.',
    route: '/console/workbench#launch-proof-ladder',
    cta: 'Open ladder',
  },
  {
    title: 'Evidence validation',
    state: 'waiting-for-live-checks',
    proof: 'safeToClaimProduction=false + validate:production-evidence',
    body: 'Only after live checks pass, attach verifier JSON and validate completed production evidence. Local state is not production proof.',
    route: '/console/audit',
    cta: 'Open proof',
  },
] as const

export const LIVE_VERIFIER_BLOCKER_LANES = [
  {
    title: 'Console DNS',
    blockerId: 'live-console-dns',
    proof: 'console-dns-live',
    body: 'Create or repair console.acgs.ai DNS for the deployed console service before rerunning the live verifier.',
    route: '/console/settings',
    cta: 'Open settings',
  },
  {
    title: 'Storybook DNS',
    blockerId: 'live-storybook-dns',
    proof: 'storybook-dns-live',
    body: 'Create or repair storybook.acgs.ai DNS for the hosted buyer-evidence origin.',
    route: '/console/workbench#assurance-proof-intake',
    cta: 'Open proof intake',
  },
  {
    title: 'Console health',
    blockerId: 'live-console-healthz',
    proof: 'console-healthz-live',
    body: 'Deploy the console service and verify /healthz reports ok=true with the expected served_hash and build_id.',
    route: '/console/settings',
    cta: 'Open settings',
  },
  {
    title: 'Security headers',
    blockerId: 'live-console-security-headers',
    proof: 'console-security-headers-live',
    body: 'Serve the console origin with HSTS, CSP, X-Frame-Options, and Referrer-Policy headers.',
    route: '/console/settings',
    cta: 'Open settings',
  },
  {
    title: 'Storybook HTTPS',
    blockerId: 'live-storybook-https',
    proof: 'storybook-https-live',
    body: 'Publish the buyer-evidence artifact and verify storybook.acgs.ai returns a 2xx or 3xx HTTPS response.',
    route: '/console/workbench#launch-proof-ladder',
    cta: 'Open ladder',
  },
  {
    title: 'Storybook manifest',
    blockerId: 'live-storybook-manifest',
    proof: 'storybook-manifest-live',
    body: 'Verify the hosted manifest includes expected story ids, publish target, and claim boundary before removing blockers.',
    route: '/console/audit',
    cta: 'Open audit',
  },
] as const

export const PRODUCTION_COMMAND_RAIL = [
  {
    title: 'Refresh blocked packet',
    command: 'make production-blocker-evidence',
    artifact: 'dist-release-evidence/production-launch-preflight.json',
    body: 'Runs the non-deploying evidence wrapper, refreshes the blocked launch packet, and keeps production proof boundaries intact.',
    route: '/console/workbench#live-verifier-blocker-map',
    cta: 'Open blockers',
  },
  {
    title: 'Rerun live verifier',
    command:
      'pnpm -F acgi-ai run verify:production-live -- --json --out ../dist-release-evidence/production-live-verification.json',
    artifact: 'dist-release-evidence/production-live-verification.json',
    body: 'Performs read-only DNS, HTTPS, healthz, header, and Storybook manifest checks after deploy or DNS changes.',
    route: '/console/settings',
    cta: 'Open settings',
  },
  {
    title: 'Validate production evidence',
    command:
      'pnpm -F acgi-ai run validate:production-evidence -- --manifest <production-evidence.json> --live-output <verify-production-live.json> --require-pass',
    artifact: 'dist-release-evidence/production-evidence-validation.json',
    body: 'Checks a completed production evidence manifest against passing live verifier output and attached assurance proof.',
    route: '/console/audit',
    cta: 'Open audit',
  },
  {
    title: 'Validate hosted Storybook',
    command:
      'pnpm -F acgi-ai run validate:hosted-storybook-proof -- --proof <hosted-storybook-proof.json> --live-output <verify-production-live.json> --require-pass',
    artifact: 'dist-release-evidence/hosted-storybook-proof-validation.json',
    body: 'Checks the hosted buyer-evidence proof packet before removing the hosted Storybook blocker.',
    route: '/console/workbench#assurance-proof-intake',
    cta: 'Open proof intake',
  },
] as const

export const HOSTED_STORYBOOK_RUNWAY = [
  {
    step: '01',
    title: 'Build local gallery',
    command: 'pnpm -F acgi-ai run storybook:build',
    proof: 'dist-buyer-evidence/manifest.json + .nojekyll + CNAME',
    body: 'Create the dependency-free buyer-evidence gallery locally and keep the hosted proof boundary attached.',
    route: '/console/workbench#assurance-proof-intake',
    cta: 'Open proof intake',
  },
  {
    step: '02',
    title: 'Enable Pages deploy',
    command: 'STORYBOOK_PAGES_ENABLED=true',
    proof: '.github/workflows/storybook.yml',
    body: 'Only enable the guarded Pages workflow for the intended repository and environment after authority is attached.',
    route: '/console/settings',
    cta: 'Open settings',
  },
  {
    step: '03',
    title: 'Build proof gap report',
    command: 'pnpm -F acgi-ai run build:hosted-storybook-proof-gap-report',
    proof: 'hosted-storybook-proof-gap-report.json',
    body: 'Generate the external-evidence checklist from the hosted proof template, current live verifier output, and Storybook handoff before asking owners for proof.',
    route: '/console/workbench#assurance-proof-intake',
    cta: 'Open proof intake',
  },
  {
    step: '04',
    title: 'Verify live Storybook',
    command:
      'pnpm -F acgi-ai run verify:production-live -- --json --out ../dist-release-evidence/production-live-verification.json',
    proof: 'storybook-dns-live + storybook-https-live + storybook-manifest-live',
    body: 'Rerun the read-only live verifier until DNS, HTTPS, and hosted manifest checks pass for storybook.acgs.ai.',
    route: '/console/workbench#live-verifier-blocker-map',
    cta: 'Open blockers',
  },
  {
    step: '05',
    title: 'Attach hosted proof',
    command:
      'pnpm -F acgi-ai run validate:hosted-storybook-proof -- --proof <hosted-storybook-proof.json> --live-output <verify-production-live.json> --require-pass',
    proof: 'copyIntoProductionEvidence.hostedStorybook',
    body: 'Validate the completed Pages, DNS, manifest, browser, accessibility, and visual-diff proof before removing the hosted blocker.',
    route: '/console/audit',
    cta: 'Open audit',
  },
] as const

export const RELEASE_BLOCKER_QUEUE = [
  {
    blockerId: 'production-deployment',
    title: 'Deploy production surfaces',
    owner: 'Deploy owner',
    artifact: 'production-live-verification.json',
    action:
      'Run the credentialed marketing and console deploys, then attach passing live verifier output.',
    proof: 'owner · artifact · unblock command',
    route: '/console/settings',
    cta: 'Open settings',
  },
  {
    blockerId: 'frontend-production-auth',
    title: 'Prove production auth boundary',
    owner: 'Frontend auth owner',
    artifact: 'production-authority.example.json',
    action:
      'Replace pending auth approval refs and verify the deployed console uses the intended auth upstream.',
    proof: 'auth owner · upstream · live check',
    route: '/console/settings',
    cta: 'Open auth',
  },
  {
    blockerId: 'legal-review-of-claim-matrix',
    title: 'Review launch claims',
    owner: 'Legal reviewer',
    artifact: 'assurance.legalClaimMatrix',
    action:
      'Attach reviewer, reviewedAt, proofRef, and claimMatrixRef before stronger launch copy ships.',
    proof: 'reviewer · matrix · proofRef',
    route: '/console/audit',
    cta: 'Open claims',
  },
  {
    blockerId: 'third-party-penetration-test',
    title: 'Attach security assessment',
    owner: 'Security owner',
    artifact: 'assurance.pentest',
    action:
      'Attach vendor, completedAt, reportRef, and criticalFindingsOpen=0 from a third-party assessment.',
    proof: 'vendor · report · zero criticals',
    route: '/console/audit',
    cta: 'Open security',
  },
  {
    blockerId: 'full-wcag-manual-screen-reader-evidence',
    title: 'Attach manual accessibility proof',
    owner: 'Accessibility reviewer',
    artifact: 'assurance.wcagManual',
    action:
      'Attach manual WCAG report plus NVDA and VoiceOver evidence; local screenshots are not conformance proof.',
    proof: 'WCAG · NVDA · VoiceOver',
    route: '/console/audit',
    cta: 'Open a11y',
  },
  {
    blockerId: 'hosted-storybook-buyer-evidence',
    title: 'Verify hosted buyer evidence',
    owner: 'Evidence publisher',
    artifact: 'hosted-storybook-proof.example.json',
    action:
      'Publish storybook.acgs.ai, attach Pages/DNS/manifest/browser refs, and pass hosted proof validation.',
    proof: 'Pages · DNS · manifest',
    route: '/console/workbench#assurance-proof-intake',
    cta: 'Open proof intake',
  },
] as const

export const ASSURANCE_INTAKE_LANES = [
  {
    title: 'Production authority',
    state: 'pending-external-authority',
    proof: 'production-authority.example.json',
    body: 'Attach deploy, DNS, auth, and claims-owner approvals before production mutation or stronger launch claims.',
    route: '/console/settings',
    cta: 'Open settings',
  },
  {
    title: 'Legal claim review',
    state: 'pending-external-signoff',
    proof: 'assurance.legalClaimMatrix',
    body: 'Replace the pending legal proof reference with reviewer, reviewedAt, proofRef, and claimMatrixRef evidence.',
    route: '/console/audit',
    cta: 'Open audit',
  },
  {
    title: 'Security assessment',
    state: 'pending-external-report',
    proof: 'assurance.pentest',
    body: 'Attach third-party pentest vendor, completedAt, reportRef, and criticalFindingsOpen=0 before release.',
    route: '/console/audit',
    cta: 'Open audit',
  },
  {
    title: 'Manual accessibility',
    state: 'pending-manual-evidence',
    proof: 'assurance.wcagManual + NVDA+VoiceOver',
    body: 'Attach reviewer, reportRef, and NVDA plus VoiceOver evidence; automated checks are not conformance proof.',
    route: '/console/audit',
    cta: 'Open audit',
  },
  {
    title: 'Hosted buyer evidence',
    state: 'pending-hosted-proof',
    proof: 'hosted-storybook-proof.example.json',
    body: 'Attach Pages run, DNS, hosted manifest, browser screenshots, accessibility artifact, and visual-diff refs.',
    route: '/console/workbench#launch-proof-ladder',
    cta: 'Open ladder',
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
