export const meta = {
  name: 'claim-wording-judge-panel',
  description:
    'Strengthen the governance-hub public claim WITHOUT overclaiming: generate candidate hero/subhead/CTA wordings from distinct persuasion angles, screen each against the claim-matrix forbidden-phrase + ops-gated rules, score with a judge panel (persuasiveness × truthfulness × claim-safety), and synthesize the strongest SHIPPABLE-AS-GATED-COPY recommendation.',
  whenToUse:
    "Decide the 'make the claim more powerful' half. Produces ranked candidates + one recommendation, all marked gated (publicDeployAllowed:false) until legal + live evidence. Defaults to the hub-claim worktree; override with args:{packageDir:'…/acgi-ai'}.",
  phases: [{ title: 'Generate' }, { title: 'Screen' }, { title: 'Judge' }, { title: 'Synthesize' }],
}

// ── Configuration ────────────────────────────────────────────────────────────
const PKG_DEFAULT = '/home/martin/Documents/ACGS-hub-claim/acgi-ai'

// Phrases the claim-matrix forbids in shippable copy. Kept here as a fast local
// pre-filter; the package's own scripts/check-claim-matrix.mjs remains authoritative.
const FORBIDDEN = [
  'compliant',
  'certified',
  'guaranteed',
  'production-ready',
  'auditor-ready',
]

// Distinct angles so the candidate space is wide (a one-attempt-iterated claim is
// weak). Each angle is a genuinely different persuasion frame, not a paraphrase.
const ANGLES = [
  {
    key: 'outcome-first',
    frame:
      'Lead with the buyer OUTCOME: what becomes true for a team that puts boundaries on agents before autonomy. Concrete capability, not adjectives.',
  },
  {
    key: 'risk-first',
    frame:
      'Lead with the RISK avoided: the specific failure mode of an unbounded agent in a regulated domain, and how the boundary forecloses it. Sober, not fear-mongering.',
  },
  {
    key: 'developer-first',
    frame:
      'Lead with the DEVELOPER motion: how an engineer wires this in, what the agent-readable surface gives their agent, why it is low-friction. Precise and technical.',
  },
  {
    key: 'plain-clarity',
    frame:
      'Lead with PLAIN CLARITY: the simplest true sentence a non-expert decision-maker understands in one read. No jargon, no hedging, maximal signal.',
  },
]

// ── args normalization ───────────────────────────────────────────────────────
const input =
  typeof args === 'string'
    ? (() => {
        try {
          return JSON.parse(args)
        } catch {
          return { packageDir: args }
        }
      })()
    : args
const PKG = input?.packageDir ?? PKG_DEFAULT

// ── Shell/prompt-safety for args embedded in sub-agent command snippets ───────
// The screen/judge prompts hand sub-agents an example shell command containing
// the package dir (`grep -rn <symbol> ${PKG}/src/`), and the prompts embed PKG
// as a file path the sub-agent will Read/grep. PKG comes from this workflow's
// args. Taken raw it enables two failure modes:
//   1. SHELL injection — a value with a quote / ; / $() / backtick can break out
//      of the example command a sub-agent is told to run.
//   2. PROMPT injection — a value with a newline can inject new instructions into
//      the sub-agent's prompt. Shell-quoting does NOT stop this.
// So: VALIDATE first (fail closed — refuse to run on anything outside a narrow
// allowlist, which also rejects control chars / newlines), shell-quote second
// (defense in depth) wherever a value is embedded in a command.
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`
function assertShellSafe(value, label, allowed) {
  const s = String(value)
  if (!allowed.test(s)) {
    throw new Error(
      `claim-wording-judge-panel: refusing to run — \`${label}\` = ${JSON.stringify(s)} ` +
        `contains characters unsafe to embed in a sub-agent command/prompt (allowed: ${allowed}). ` +
        `This gate fails closed rather than emit a command a sub-agent could be tricked into ` +
        `mis-running, or a prompt it could be tricked into mis-reading.`
    )
  }
}
// PKG is a filesystem path (default '/home/martin/Documents/ACGS-hub-claim/acgi-ai',
// e.g. override 'packages/gove-zone/'); it never legitimately needs a
// quote/space/;/$/backtick/newline. Validate it once — every downstream use
// (the prose paths, the example grep command, the log line) reads this value.
assertShellSafe(PKG, 'packageDir', /^[A-Za-z0-9._/-]+$/)

// ── structured-output contracts ──────────────────────────────────────────────
const CANDIDATE = {
  type: 'object',
  required: ['hero', 'subhead', 'cta', 'rationale'],
  properties: {
    hero: { type: 'string' }, // the billboard headline
    subhead: { type: 'string' }, // one supporting line
    cta: { type: 'string' }, // the call-to-action label/line
    rationale: { type: 'string' }, // why this is both stronger AND still true
    // The candidate's own honesty audit: what it is careful NOT to assert.
    truthGuards: { type: 'array', items: { type: 'string' } },
  },
}

const SCREEN = {
  type: 'object',
  required: ['clean', 'violations'],
  properties: {
    clean: { type: 'boolean' }, // true = no forbidden/ops-gated overclaim
    violations: {
      type: 'array',
      items: {
        type: 'object',
        required: ['field', 'phrase', 'why'],
        properties: {
          field: { type: 'string', enum: ['hero', 'subhead', 'cta'] },
          phrase: { type: 'string' },
          // why it overclaims: a forbidden word, or a present-tense promise that
          // depends on un-shipped ops (live fetch, DNS), or an unverifiable assertion.
          why: { type: 'string' },
        },
      },
    },
  },
}

const SCORE = {
  type: 'object',
  required: ['persuasiveness', 'truthfulness', 'claimSafety', 'why'],
  properties: {
    // 1-10 each. truthfulness and claimSafety gate the winner — a persuasive lie loses.
    persuasiveness: { type: 'integer' },
    truthfulness: { type: 'integer' },
    claimSafety: { type: 'integer' },
    why: { type: 'string' },
  },
}

// ── Stage 1: Generate one candidate per angle ─────────────────────────────────
const genPrompt = (angle) => `You are writing a STRONGER public marketing claim for a regulated-AI governance product (the "governance hub"), without overclaiming.

Read the current live copy + the claim guardrails first (READ-ONLY, no edits):
- ${PKG}/src/routes/Marketing.tsx  — find the hero <h1>, its subhead, and the primary CTA. The current hero is "AI agents need boundaries before autonomy."
- ${PKG}/claim-matrix.json         — the claim ledger. Every claim is currently publicDeployAllowed:false, status pending legal.
- ${PKG}/CLAIM_VALIDATION.md (if present) — the validation rules.

HARD TRUTH CONSTRAINTS (a violation disqualifies the candidate):
- NEVER use these words: ${FORBIDDEN.join(', ')}.
- NEVER state as present-tense fact anything that depends on un-shipped operations — e.g. "point your agent at acgs.ai" / live-URL fetching / a deployed endpoint. Those are ops-gated (DNS + Cloudflare not cut over). You MAY describe the capability that exists in-product; you may NOT promise the live hosted behavior as if it were already on.
- Claim only what the shipped code substantiates: an in-browser governance interview that produces a deployment brief, a domain/obligation axis (GDPR/HIPAA/PCI/etc. framed as "obligations to consider, not legal advice"), and an agent-readable framework surface. Frame regulated items as obligations to consider, never as satisfied/attested.

CHECKOUT PIN (critical — read this carefully):
- The ONLY source of truth for "what the shipped product does" is the code UNDER ${PKG}. Its src/routes/Marketing.tsx is the ~2001-line interview page (it contains buildGovernanceBrief, parseDeploymentContext, and imports the governance-domains.ts domain axis incl. the hipaa_phipa option).
- Do NOT trust any prior audit/report (e.g. hub-verification-report.md) for current behavior — those are STALE snapshots. Verify every capability claim against the live code under ${PKG} right now.
- Do NOT grep the default working directory or the live apex URL: those resolve to an OLDER, DIFFERENT marketing page (an 835-line "publishing house" page with none of these symbols). It is not this product.
- The domain/obligation axis IS shipped and unit-tested — gdpr vs hipaa_phipa yield materially different briefs (PHI handled distinctly from generic PII). Do NOT omit regulated-domain framing on a stale "domain-blind" belief; you MAY truthfully describe it as "obligations to consider".

ANGLE FOR THIS CANDIDATE — ${angle.key}: ${angle.frame}

Produce ONE candidate: a hero headline, a one-line subhead, a CTA, a rationale for why it is BOTH more powerful AND still strictly true, and truthGuards (the specific things you deliberately did NOT assert to stay honest). Make it sharper than the current copy — but every word must survive a hostile fact-check.`

// ── Stage 2: Screen each candidate against the guardrails (mechanical) ─────────
const screenPrompt = (cand) => `You are the claim-safety screen. Given ONE candidate marketing claim, flag every overclaim. Be strict and literal.

Candidate:
${JSON.stringify({ hero: cand.hero, subhead: cand.subhead, cta: cand.cta }, null, 2)}

Flag a violation when any of hero/subhead/cta:
1. Contains a forbidden word (case-insensitive): ${FORBIDDEN.join(', ')}.
2. States as present-tense fact something that depends on un-shipped ops (a live hosted URL the agent points at, live fetching, a deployed endpoint, DNS-dependent behavior).
3. Asserts a regulatory posture as satisfied/attested ("meets X", "X-approved") rather than "obligations to consider".
4. Makes a measurable promise the in-browser product cannot itself back.

For each: {field, phrase (the exact offending span), why}. Set clean=true ONLY if there are zero violations. Do not be charitable — if a phrase could read as an overclaim to a regulator, flag it.

This is a TEXT screen: judge the wording itself. If you need to confirm whether a capability is shipped (Rule 2), the ONLY authority is the code under ${PKG} — never the default working directory or the live apex URL, which are an older, different marketing page.`

// ── Stage 3: Judge each (screened) candidate on three axes ────────────────────
const judgePrompt = (cand, screen) => `Score ONE candidate marketing claim for a regulated-AI governance product on three axes, 1-10.

Candidate:
${JSON.stringify({ hero: cand.hero, subhead: cand.subhead, cta: cand.cta, rationale: cand.rationale }, null, 2)}

Claim-safety screen result (authoritative — a non-clean screen caps claimSafety at 3):
${JSON.stringify(screen, null, 2)}

SOURCE OF TRUTH (critical — get this wrong and your truthfulness score is garbage):
- The ONLY authority for "what the shipped product does" is the code UNDER ${PKG}. To verify a cited symbol or field, read/grep THAT directory, e.g. \`grep -rn buildGovernanceBrief ${shq(PKG)}/src/\`. Its src/routes/Marketing.tsx is the ~2001-line interview page and DOES contain buildGovernanceBrief, parseDeploymentContext, the five brief fields, and the governance-domains.ts domain axis (hipaa_phipa option, unit-tested).
- Do NOT grep the default working directory and do NOT fetch the live apex URL. Those resolve to an OLDER, DIFFERENT marketing page (an 835-line "publishing house" page) that has none of these symbols — judging against it will make you FALSELY flag real, shipped symbols as "fabricated" and wrongly floor truthfulness. A symbol present under ${PKG} IS shipped on this branch, full stop.
- A prior audit/report (e.g. hub-verification-report.md) is a STALE snapshot; do not treat its findings (e.g. "domain-blind / identical PII-PHI briefs") as current — verify against the code under ${PKG}.

Axes:
- persuasiveness: how strongly it moves a regulated-industry buyer to act. Specific capability beats vague adjectives.
- truthfulness: how strictly every word matches what the shipped product does, VERIFIED against the code under ${PKG} (see SOURCE OF TRUTH). Reward candidates whose truthGuards show disciplined restraint; do not floor a candidate for citing a symbol you failed to find in the WRONG directory.
- claimSafety: freedom from overclaim / regulatory exposure. If screen.clean is false, this is <= 3.

Return {persuasiveness, truthfulness, claimSafety, why}. A persuasive claim that is untrue or unsafe must NOT win — say so plainly in the "why" field when relevant.`

// ── Orchestration: pipeline (generate → screen → judge), then synthesize ──────
// Pipeline so each angle advances on its own; synthesis is the natural barrier
// (it awaits the whole pipeline because it must compare every scored candidate).
log(`claim-wording-judge-panel: ${ANGLES.length} angles · package=${PKG}`)

const judged = (
  await pipeline(
    ANGLES,
    // Stage 1 — generate. Inherit the session model (creative + judgment-heavy).
    (angle) =>
      agent(genPrompt(angle), {
        label: `gen:${angle.key}`,
        phase: 'Generate',
        schema: CANDIDATE,
      }).then((cand) => (cand ? { angle: angle.key, cand } : null)),
    // Stage 2 — screen. Inherit the session model (do NOT drop to haiku): a small
    // model unreliably calls the forced StructuredOutput tool and silently returns
    // null, which here would make the candidate vanish from `judged` entirely —
    // i.e. we could silently lose our BEST candidate. Wrong-direction failure, so
    // pay for reliability (only 4 calls).
    (prev) =>
      prev
        ? agent(screenPrompt(prev.cand), {
            label: `screen:${prev.angle}`,
            phase: 'Screen',
            schema: SCREEN,
          }).then((screen) => (screen ? { ...prev, screen } : null))
        : null,
    // Stage 3 — judge. Judgment-heavy → inherit the session model.
    (prev) =>
      prev
        ? agent(judgePrompt(prev.cand, prev.screen), {
            label: `judge:${prev.angle}`,
            phase: 'Judge',
            schema: SCORE,
          }).then((score) => (score ? { ...prev, score } : null))
        : null,
  )
).filter(Boolean)

if (judged.length === 0) {
  log('No candidate survived generation/screen/judge — nothing to synthesize.')
  return {
    recommendation: null,
    reason: 'no candidates produced',
    publicDeployAllowed: false,
    legalSignoffRequired: true,
  }
}

// Rank: claim-safety and truthfulness gate persuasiveness. A clean screen is a
// hard prerequisite to be the recommended winner (fail-closed on overclaim).
const composite = (j) =>
  (j.screen.clean ? 1 : 0) * 1000 +
  j.score.claimSafety * 100 +
  j.score.truthfulness * 10 +
  j.score.persuasiveness
const ranked = [...judged].sort((a, b) => composite(b) - composite(a))
const cleanRanked = ranked.filter((j) => j.screen.clean)

phase('Synthesize')
const synthesisInput = ranked.map((j) => ({
  angle: j.angle,
  hero: j.cand.hero,
  subhead: j.cand.subhead,
  cta: j.cand.cta,
  rationale: j.cand.rationale,
  truthGuards: j.cand.truthGuards ?? [],
  screenClean: j.screen.clean,
  violations: j.screen.violations,
  scores: j.score,
}))

const synthesis =
  cleanRanked.length > 0
    ? await agent(
        `You are choosing and refining the strongest SHIPPABLE governance-hub claim from several scored, screened candidates.

Candidates (ranked; screenClean=false means it overclaims and is INELIGIBLE to win as-is):
${JSON.stringify(synthesisInput, null, 2)}

Produce the definitive recommendation: take the highest-ranked SCREEN-CLEAN candidate as the base, graft the strongest true ideas from the runners-up, and tighten every word. Output a single {hero, subhead, cta, rationale, truthGuards}.

NON-NEGOTIABLE: the result must use none of these words (${FORBIDDEN.join(', ')}), must not promise any un-shipped/ops-gated live behavior as present-tense fact, and must frame regulatory items as "obligations to consider". This is GATED COPY — it cannot ship until legal signs off the claim-matrix and live evidence exists; write it so that gate is honest, not so it reads as already cleared.`,
        { label: 'synthesize', phase: 'Synthesize', schema: CANDIDATE },
      )
    : null

if (!synthesis) {
  log('Every candidate failed the claim-safety screen — no shippable recommendation (fail-closed).')
}

log(
  `judge-panel: ${judged.length} judged · ${cleanRanked.length} screen-clean · ` +
    (synthesis ? `recommendation synthesized (GATED)` : 'NO clean recommendation'),
)

return {
  // The synthesized winner — or null if nothing passed the safety screen.
  recommendation: synthesis,
  // Hard reality: this is never auto-shippable from this workflow.
  publicDeployAllowed: false,
  legalSignoffRequired: true,
  gateNote:
    'Recommendation is GATED COPY. claim-matrix.json keeps publicDeployAllowed:false until legal signoff + live evidence. Do not install in the hero as live copy on this basis alone.',
  ranked: synthesisInput.map((c, i) => ({ rank: i + 1, ...c })),
  cleanCount: cleanRanked.length,
  judgedCount: judged.length,
}
