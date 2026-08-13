export const meta = {
  name: 'project-showcase-pages',
  description: 'Build a dedicated showcase page per ACGS sub-project (acgs-swarm first, web3-frontier style), each on its own branch for human merge',
  whenToUse: 'When you want polished, design-skill-driven marketing pages for each monorepo package, prioritising acgs-swarm with a web3 aesthetic',
  phases: [
    { title: 'Research' },
    { title: 'Design' },
    { title: 'Build', model: 'opus' },
    { title: 'Verify' },
  ],
}

// ---------------------------------------------------------------------------
// Inputs. `args` may override the project list; otherwise this default runs.
// acgs-swarm is first (priority) and is the only web3-frontier page; the rest
// follow the acgi-ai design contract so the marketing surface stays coherent.
// ---------------------------------------------------------------------------
const DEFAULT_PROJECTS = [
  { slug: 'acgs-swarm',        path: 'packages/Acgs-Swarm',          route: '/swarm',         component: 'Swarm',          style: 'web3-frontier', skill: 'high-end-visual-design', priority: true,  model: 'opus' },
  { slug: 'acgs-lite',         path: 'packages/acgs-lite',           route: '/acgs-lite',     component: 'AcgsLite',       style: 'product',       skill: 'design-taste-frontend',  priority: false, model: 'sonnet' },
  { slug: 'clinicalguard',     path: 'packages/clinicalguard',       route: '/clinicalguard', component: 'ClinicalGuard',  style: 'product',       skill: 'design-taste-frontend',  priority: false, model: 'sonnet' },
  { slug: 'cft-governance',    path: 'acgs-cft-governance-pack',     route: '/cft-pack',      component: 'CftPack',        style: 'product',       skill: 'design-taste-frontend',  priority: false, model: 'sonnet' },
  { slug: 'governance-eval',   path: 'acgs_governance_eval_mvp',     route: '/eval-mvp',      component: 'EvalMvp',        style: 'product',       skill: 'design-taste-frontend',  priority: false, model: 'sonnet' },
  { slug: 'agent-bus',         path: 'packages/agent-bus-analyzer',  route: '/agent-bus',     component: 'AgentBus',       style: 'product',       skill: 'design-taste-frontend',  priority: false, model: 'sonnet' },
]

// Object passes straight through; a JSON string parses; anything else falls back.
const input = typeof args === 'string'
  ? (() => { try { return JSON.parse(args) } catch { return args } })()
  : args
const PROJECTS = Array.isArray(input?.projects) ? input.projects : DEFAULT_PROJECTS

// Fail closed on any value that gets interpolated into sub-agent prompts
// containing shell syntax (branch names, checkout commands). args.projects is
// caller-supplied, so validate every field the prompts embed — same guard the
// sibling workflows implement.
function assertShellSafe(value, label, allowed) {
  const s = String(value)
  if (!allowed.test(s)) {
    throw new Error(
      `project-showcase-pages: refusing to run — \`${label}\` = ${JSON.stringify(s)} ` +
        `contains characters unsafe to embed in a sub-agent command/prompt (allowed: ${allowed}).`
    )
  }
}
for (const p of PROJECTS) {
  assertShellSafe(p.slug, 'project.slug', /^[a-z0-9-]+$/)
  assertShellSafe(p.path, 'project.path', /^[A-Za-z0-9._/-]+$/)
  assertShellSafe(p.route, 'project.route', /^\/[A-Za-z0-9-]*$/)
  assertShellSafe(p.component, 'project.component', /^[A-Za-z0-9]+$/)
}

// ---------------------------------------------------------------------------
// Schemas — small and required-tight so a later JS line can read fields safely.
// ---------------------------------------------------------------------------
const BRIEF = { type: 'object', required: ['name', 'oneLiner', 'features'], properties: {
  name:            { type: 'string' },
  oneLiner:        { type: 'string' },
  audience:        { type: 'string' },
  features:        { type: 'array', items: { type: 'string' } },
  proofPoints:     { type: 'array', items: { type: 'string' } },
  differentiators: { type: 'array', items: { type: 'string' } },
} }

const SPEC = { type: 'object', required: ['archetype', 'sections'], properties: {
  archetype:     { type: 'string' },
  sections:      { type: 'array', items: { type: 'string' } },
  palette:       { type: 'string' },
  typography:    { type: 'string' },
  motion:        { type: 'string' },
  assetPlan:     { type: 'string' },
  contractRisks: { type: 'array', items: { type: 'string' } },
} }

const BUILD = { type: 'object', required: ['branch', 'worktree', 'routeWired', 'navWired'], properties: {
  branch:          { type: 'string' },
  worktree:        { type: 'string', description: 'Absolute path of the isolated worktree the branch was built in (git rev-parse --show-toplevel)' },
  files:           { type: 'array', items: { type: 'string' } },
  routeWired:      { type: 'boolean' },
  navWired:        { type: 'boolean' },
  wiringEvidence:  { type: 'string' },
  gatesRun:        { type: 'array', items: { type: 'string' } },
  notes:           { type: 'string' },
} }

const VERDICT = { type: 'object', required: ['pass', 'cspSafe', 'orphanRoute'], properties: {
  pass:        { type: 'boolean' },
  cspSafe:     { type: 'boolean' },
  orphanRoute: { type: 'boolean' },
  gateResults: { type: 'array', items: { type: 'string' } },
  issues:      { type: 'array', items: { type: 'string' } },
  recommendation: { type: 'string' },
} }

// Repo-specific guardrails every stage must respect.
const GUARDRAILS = `Repo facts (obey them):
- This is the govern-zone monorepo. Pages live in the acgi-ai frontend (React 19, Vite, Tailwind 4, Biome, pnpm). Read acgi-ai/CLAUDE.md, acgi-ai/DESIGN.md, acgi-ai/DEPLOY.md before editing.
- These are PUBLIC MARKETING pages — never touch acgi-ai/src/routes/console/** and never extend public-only patterns (CDN fonts, third-party scripts) into the console origin.
- DESIGN.md is a hard contract: no box-shadow, no hardcoded color/hex/rgba() outside index.css. Derive every tint/glow from CSS tokens via color-mix(var(--token) N%, transparent). It is NOT fully gate-enforced, so do not rely on lint to catch a violation — self-check by grepping your CSS diff for box-shadow / rgba( / hex.
- Routing is custom (lib/navigate, @surface/App) — NOT react-router. Wire new routes through the existing surface router and the marketing nav factory (internalNav). check-trust-surface.mjs greps literal navigate('/...') calls in Marketing.tsx — do not break those literals.
- New routes must be wired in the SAME change as the page (no orphan pages).`

log(`Building ${PROJECTS.length} showcase pages — priority: ${PROJECTS.filter(p => p.priority).map(p => p.slug).join(', ') || '(none)'}`)

// ---------------------------------------------------------------------------
// Pipeline: each project flows research -> design -> build(worktree) -> verify
// independently. No barrier — acgs-swarm builds while others still research.
// ---------------------------------------------------------------------------
const results = await pipeline(
  PROJECTS,

  // Stage 1 — Research the package: what it is, who it's for, real proof points.
  (p) => agent(
    `Research the "${p.slug}" package at ${p.path} in this monorepo. Read its README, CLAUDE.md/AGENTS.md, pyproject/package manifest, and key source to extract an honest marketing brief. Do NOT invent capabilities or compliance claims — only what the code/docs support.\n${GUARDRAILS}`,
    { label: `research:${p.slug}`, phase: 'Research', model: 'sonnet', agentType: 'Explore', schema: BRIEF },
  ),

  // Stage 2 — Design spec via the assigned design skill, inside the design contract.
  (brief, p) => agent(
    `You are designing a dedicated showcase page for "${p.slug}" (route ${p.route}).\n` +
    `STYLE TARGET: ${p.style}${p.style === 'web3-frontier'
      ? ' — a web3 / frontier aesthetic: depth, gradient/glow accents, mono+display type pairing, animated grid or particle motifs, an "onchain governance frontier" mood. It must feel premium and distinct from the other pages.'
      : ' — coherent with the existing acgi-ai marketing surface; premium but on-brand, not a separate visual identity.'}\n` +
    `Invoke the design skill at .agents/skills/${p.skill}/SKILL.md and apply it. Read acgi-ai/DESIGN.md and acgi-ai/src/index.css to learn the available tokens.\n` +
    `Produce a concrete design spec: layout archetype, ordered section list, palette + typography (expressed as token usage, not raw hex), motion notes, and a CSP-safe asset plan (self-hosted only — no external CDN). In contractRisks, list any place the ${p.style} look fights DESIGN.md (e.g. glow wanting box-shadow) and how you reconcile it within tokens, or flag it for a human exception.\n` +
    `Brief: ${JSON.stringify(brief)}\n${GUARDRAILS}`,
    { label: `design:${p.slug}`, phase: 'Design', model: p.model, schema: SPEC },
  ),

  // Stage 3 — Implement + wire on an ISOLATED worktree branch (pages share the
  // router/nav file, so parallel builds would collide without isolation).
  (spec, p) => agent(
    `Implement the "${p.slug}" showcase page in an acgi-ai marketing route, on a NEW branch named showcase/${p.slug} (create it from master in this worktree).\n` +
    `1. Create acgi-ai/src/routes/${p.component}.tsx implementing the design spec below. Put styles in App.css/index.css using ONLY token-derived values (color-mix from var(--token)); no box-shadow, no raw hex/rgba outside index.css.\n` +
    `2. Wire route ${p.route} into the custom surface router AND add a marketing-nav entry through the existing internalNav factory in Marketing.tsx. Keep all existing navigate('/...') literals intact.\n` +
    `3. Self-check: grep your CSS diff for box-shadow / rgba( / '#'; run \`pnpm --dir acgi-ai lint\` (biome) and the relevant acgi-ai/scripts/check-*.mjs gates (at least check-trust-surface.mjs). Run \`pnpm --dir acgi-ai build\` to confirm it compiles.\n` +
    `4. Commit ONLY the files you created/edited (explicit paths, never git add -A) on branch showcase/${p.slug}. Do not push, do not merge.\n` +
    `Return the branch name, the absolute worktree path (git rev-parse --show-toplevel), files changed, whether route+nav are wired, the grep/gate evidence, and which gates you ran.\n` +
    `Design spec: ${JSON.stringify(spec)}\n${GUARDRAILS}`,
    { label: `build:${p.slug}`, phase: 'Build', model: p.model, isolation: 'worktree', agentType: 'designer', schema: BUILD },
  ),

  // Stage 4 — Independent verification INSIDE the build's isolated worktree
  // (read-only). Never `git checkout` in the default checkout: with multiple
  // pipelines advancing concurrently, verifiers would race each other switching
  // branches in one shared tree — and change the user's checked-out branch.
  (build, p) => {
    if (!build?.worktree || !/^[A-Za-z0-9._/-]+$/.test(build.worktree)) {
      return {
        pass: false, cspSafe: false, orphanRoute: true,
        issues: [`build stage returned no usable worktree path (${JSON.stringify(build?.worktree ?? null)}) — cannot verify in isolation`],
        recommendation: 'do not merge; re-run the build stage so verification gets its isolated worktree',
      }
    }
    return agent(
      `Verify the showcase page work on branch ${build.branch || `showcase/${p.slug}`} for "${p.slug}". Work ONLY inside the build's isolated worktree: cd ${build.worktree} first — do NOT git checkout or switch branches in any other checkout (parallel pipelines share the main worktree).\n` +
      `Confirm: (a) route ${p.route} is reachable through the surface router AND linked from marketing nav (trace entry -> router -> ${p.component}; an unreachable page = orphanRoute true); (b) NO box-shadow and NO hardcoded hex/rgba outside index.css in the diff (CSP/DESIGN.md); (c) \`pnpm --dir acgi-ai lint\` and \`pnpm --dir acgi-ai build\` pass (run from inside the worktree); (d) check-trust-surface.mjs and other relevant check-*.mjs gates still pass. A green unit/lint pass does NOT prove wiring — actually trace the route.\n` +
      `Report pass/fail, cspSafe, orphanRoute, the literal gate results, concrete issues, and a merge recommendation.\n` +
      `Build report: ${JSON.stringify(build)}\n${GUARDRAILS}`,
      { label: `verify:${p.slug}`, phase: 'Verify', model: 'sonnet', agentType: 'verifier', schema: VERDICT },
    )
  },
)

// ---------------------------------------------------------------------------
// Collate. Pipeline puts null in any item's slot that threw — filter holes.
// ---------------------------------------------------------------------------
const rows = PROJECTS.map((p, i) => ({ slug: p.slug, route: p.route, branch: `showcase/${p.slug}`, verdict: results[i] }))
const ready    = rows.filter(r => r.verdict && r.verdict.pass && r.verdict.cspSafe && !r.verdict.orphanRoute)
const needWork = rows.filter(r => !ready.includes(r))

log(`Done. ${ready.length}/${PROJECTS.length} pages verified clean. Branches await human merge (agents prep, humans merge).`)

return {
  readyToMerge: ready.map(r => ({ slug: r.slug, route: r.route, branch: r.branch, recommendation: r.verdict?.recommendation })),
  needsWork:    needWork.map(r => ({ slug: r.slug, route: r.route, branch: r.branch, issues: r.verdict?.issues ?? ['stage failed — no verdict returned'] })),
}
