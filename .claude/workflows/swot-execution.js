export const meta = {
  name: 'swot-execution',
  description: 'Execute the 5 SWOT strategic recommendations for gove-zone in priority order: agent-executable parts land as repo artifacts, human-gated parts produce prep kits',
  whenToUse: 'After the (private) SWOT + startup-canvas strategy docs are refreshed and their recommendations should be turned into concrete repo artifacts. Set STRATEGY_DIR below to the local path of the private strategy store before running.',
  phases: [
    { title: 'R1 Auditor sprint prep' },
    { title: 'R2 Design-partner kit' },
    { title: 'R3 MCP gateway gap analysis' },
    { title: 'R4 Overhead benchmarks' },
    { title: 'R5 Receipt spec standards candidate' },
    { title: 'Verify' },
  ],
}

const REPO = '/home/martin/Documents/ACGS'

// SWOT + startup-canvas are commercially sensitive and are NOT stored in this
// public repository. Point this at the private strategy store before running.
const STRATEGY_DIR = process.env.ACGS_STRATEGY_DIR || '/home/martin/Documents/ACGS-private-docs-staging/strategy'

const COMMON = `
Repository root: ${REPO}. Always use absolute paths; your cwd may differ.
Ground rules (non-negotiable):
- Read ${STRATEGY_DIR}/swot-gove-zone.md and ${STRATEGY_DIR}/startup-canvas-gove-zone.md first for context. These live outside the public repo; never copy their commercial content into a file under ${REPO}.
- The working tree is dirty with files owned by other sessions. NEVER modify existing files unless this task explicitly names one. Only CREATE new files at the paths this task specifies.
- Never run git add, git commit, git stash, git checkout, or git restore.
- Claim-safe discipline (see ${REPO}/AGENTS.md and ${REPO}/docs/CLAIMS.md): never claim production-readiness, certification, or compliance approval. Alpha status must stay visible. Every capability claim must map to code/tests you actually inspected or commands you actually ran.
- Where an action needs a human (contacting auditors, outreach, publishing externally), do not fake it — list it under humanActionsRequired.
Your final message is machine-read; return only what the schema asks.`

const STAGE_RESULT = {
  type: 'object',
  required: ['artifacts', 'summary', 'humanActionsRequired'],
  properties: {
    artifacts: { type: 'array', items: { type: 'string' }, description: 'Absolute paths of files created' },
    summary: { type: 'string', description: '3-6 sentences: what was produced and key findings' },
    humanActionsRequired: { type: 'array', items: { type: 'string' } },
    metrics: { type: 'string', description: 'Optional: literal measured numbers, if this stage measured anything' },
  },
}

const VERDICT = {
  type: 'object',
  required: ['pass', 'gateOutput', 'issues'],
  properties: {
    pass: { type: 'boolean' },
    gateOutput: { type: 'string', description: 'Literal tail of gate command outputs' },
    issues: { type: 'array', items: { type: 'string' } },
    scopeViolations: { type: 'array', items: { type: 'string' }, description: 'Pre-existing dirty files that were modified by the workflow, if any' },
  },
}

const RECS = [
  {
    key: 'R1',
    phase: 'R1 Auditor sprint prep',
    prompt: `${COMMON}
Task — SWOT recommendation 1 (auditor validation sprint), agent-executable part.
Goal: everything a real GRC/audit professional needs to assess a gove-zone proof pack must exist in one place, so the human only has to send it.
1. Actually generate a proof pack: read ${REPO}/docs/PROOF_PATH.md and packages/gove-zone docs/CLI to find the real commands (smoke, receipt-gated demo, proof pack, offline verifier). Run them with uv from ${REPO} into a temp dir. Capture literal output. If a command fails, record the failure honestly instead of papering over it.
2. Create ${REPO}/docs/strategy/auditor-validation/BRIEF.md — a self-contained brief for an external auditor: what ACGS claims (and explicitly does not claim), what the proof pack contains, how to verify it offline, what feedback is requested (is a Decision Receipt acceptable control evidence vs post-hoc logs?).
3. Create ${REPO}/docs/strategy/auditor-validation/REVIEW-CHECKLIST.md — a structured checklist the auditor walks: tamper detection, fail-closed denial, receipt binding fields, offline verification, with the exact command per step and expected outcome.
4. Include the literal command transcript (trimmed) in an appendix section of BRIEF.md so the human can sanity-check before sending.`,
  },
  {
    key: 'R2',
    phase: 'R2 Design-partner kit',
    prompt: `${COMMON}
Task — SWOT recommendation 2 (3 design partners fail-closed via security-agent beachhead), agent-executable part.
Goal: a complete recruitment + onboarding kit so the human only has to pick targets and send.
1. Study the governed VulnClaw pentest case study (${REPO}/docs/design/governance-vulnclaw-pentest.md if present, plus packages/gove-zone examples) and the OSINT material. Verify the demo commands actually run before citing them.
2. Create ${REPO}/docs/strategy/design-partner-kit/ONE-PAGER.md — the pitch for a security-engineering team: problem, the fail-closed invariant, what a pilot involves, what the partner gets, honest alpha-status disclosure.
3. Create ${REPO}/docs/strategy/design-partner-kit/DEMO-RUNBOOK.md — a 15-minute live-demo script using the real VulnClaw governed-pentest demo: exact commands, what to show at each step (allow, deny, receipt, tamper), fallback if something breaks.
4. Create ${REPO}/docs/strategy/design-partner-kit/ONBOARDING.md — the time-to-first-governed-call path targeting under 1 hour: prerequisites, install, first governed call, fail-closed proof, instrumentation of the OMTM (fail-closed external pipelines). Every command verified by actually running it.`,
  },
  {
    key: 'R3',
    phase: 'R3 MCP gateway gap analysis',
    prompt: `${COMMON}
Task — SWOT recommendation 3 (governed-MCP gateway as flagship integration): gap analysis against what already exists. This stage is analysis only — do not write or modify any Python code.
1. Read the existing governed MCP implementation: ${REPO}/acgs_governance_eval_mvp/governed_mcp_v0/ (mcp_server.py, server.py, policy.py, verify.py, eval_gate.py, models.py) and any MCP adapter shapes in ${REPO}/packages/gove-zone/ (search for mcp in src and examples) plus ${REPO}/docs/INTEGRATION_MATRIX.md.
2. Define the flagship-gateway bar: a governed MCP gateway a design partner could put in front of an arbitrary MCP server — receipt gate on every tools/call, fail-closed, deny/escalate enforced, receipts + audit chain emitted, offline-verifiable, works with the current MCP spec.
3. Create ${REPO}/docs/strategy/mcp-gateway-gap-analysis.md: current-state map (what governed_mcp_v0 and gove-zone adapters actually do today, with file:line evidence), the bar, the gap list ranked by effort/impact, a concrete implementation plan (ordered work items with target files), and which gaps block a design-partner pilot vs which are polish.`,
  },
  {
    key: 'R4',
    phase: 'R4 Overhead benchmarks',
    prompt: `${COMMON}
Task — SWOT recommendation 4 (publish membrane overhead benchmarks). This one is fully executable: measure, then document.
1. Read existing benchmarks in ${REPO}/packages/gove-zone/benchmarks/ (authz_propagation.py, authz_token_baseline.py, agent_chain.py, test_propagation_overhead.py). Understand what they measure.
2. If they already measure per-governed-call overhead, run them via uv from the repo root (use the package-local invocation the repo expects, e.g. uv run --package gove-zone ...). If a small additional micro-benchmark is needed to get p50/p99 latency per governed call (policy decision + receipt issue + executor validation) versus an ungoverned baseline call, create ONE new file ${REPO}/packages/gove-zone/benchmarks/overhead_receipt_gate.py modelled on the existing benchmark style. Creating this one new benchmark file is the only permitted code write in this workflow.
3. Run the measurements. Capture literal numbers (p50/p95/p99, iterations, machine caveat: local dev box, not a controlled environment).
4. Create ${REPO}/docs/strategy/overhead-benchmarks.md: methodology, exact commands, literal results table, honest caveats (single machine, in-process kernel, unsigned vs signed mode difference if measurable), and what these numbers do NOT claim. Never report a number you did not actually measure in this run.`,
  },
  {
    key: 'R5',
    phase: 'R5 Receipt spec standards candidate',
    prompt: `${COMMON}
Task — SWOT recommendation 5 (open the receipt spec as a standards candidate), agent-executable part.
1. Read ${REPO}/docs/DECISION_RECEIPT_SPEC.md fully, plus receipt.py field usage in packages/gove-zone/src/gove_zone/receipt.py (read-only) to confirm the spec matches the implementation. Note any drift honestly.
2. Create ${REPO}/docs/strategy/receipt-spec-standards-candidate.md: the plan to publish the Decision Receipt format as a vendor-neutral standards candidate — proposed versioning scheme, what belongs in a standalone spec repo vs stays here, spec-vs-implementation conformance statement (with any drift found in step 1), the public-comment process (where, how, what feedback is solicited), and the two success metrics from the SWOT (at least 2 external implementations or formal comments).
3. Include a short comparison of standards venues (standalone GitHub spec repo with versioned releases, IETF Internet-Draft, OASIS) with a recommendation and why.`,
  },
]

const results = []
for (const rec of RECS) {
  phase(rec.phase)
  log(`${rec.key}: starting`)
  const r = await agent(rec.prompt, { label: rec.key, phase: rec.phase, schema: STAGE_RESULT })
  if (r) {
    results.push({ key: rec.key, ...r })
    log(`${rec.key}: ${r.artifacts.length} artifact(s)`)
  } else {
    results.push({ key: rec.key, artifacts: [], summary: 'stage skipped or failed', humanActionsRequired: [] })
    log(`${rec.key}: returned null (skipped/failed)`)
  }
}

phase('Verify')
const allArtifacts = results.flatMap(r => r.artifacts)
const verdict = await agent(`${COMMON}
You are the independent verification lane — you did not author any of these artifacts.
Artifacts created by earlier stages:
${JSON.stringify(allArtifacts, null, 2)}
Stage summaries:
${JSON.stringify(results.map(r => ({ key: r.key, summary: r.summary })), null, 2)}
Verify:
1. Every listed artifact exists and is non-trivial (read each one; flag placeholder or fabricated content, unverified command claims, or claim-safety violations such as certification/production-ready language).
2. Run the docs gates from ${REPO}: "make lint-docs" and "uv run python -m pytest tests/docs --import-mode=importlib -q". Capture literal tail output.
3. Scope check: run "git -C ${REPO} status --short" and confirm the workflow only ADDED new files (plus the one permitted benchmark file). List any modification to a pre-existing tracked file as a scopeViolation (the tree was already dirty before the workflow — compare against the artifact list; only files in the artifact list or untracked new strategy docs are ours).
4. If a benchmark doc reports numbers, spot-check that the benchmark command it cites actually runs.
Do not fix anything — report only.`,
  { label: 'verify', phase: 'Verify', schema: VERDICT })

return {
  recommendations: results,
  humanActionsRequired: results.flatMap(r => (r.humanActionsRequired || []).map(a => `${r.key}: ${a}`)),
  verification: verdict,
}
