// Emits the browser-free, agent-readable static governance surface.
//
// An agent (or crawler) that fetches the marketing origin gets a bare SPA shell
// (index.html is just <div id="root">). This generator produces one plain-text
// file — identical bytes for every agent — so a headless reader can obtain the
// governance FRAMEWORK, a self-assessment PROTOCOL, and the per-domain
// obligations index WITHOUT running the in-browser interview. The file is the
// FRAMEWORK + PROTOCOL only; it is NOT a personalized brief. A personalized
// brief requires running the in-browser calculator, which produces a filled
// template (e.g. a "Computed risk level:" line) that this static file
// deliberately never contains.
//
// Scope note: this generator writes ONLY governance-framework.txt. `llms.txt`
// is the repo's canonical claim-safe file — public/llms.txt is pinned
// byte-identical to the repo-root llms.txt by scripts/check-sitemap.mjs, and
// vite copies it into the build output. Generating over it here would silently
// replace the pinned artifact at the served origin, so the two surfaces stay
// separate: llms.txt is authored, governance-framework.txt is derived.
//
// Generated from src/lib/governance-domains.ts and src/lib/governance-framework.ts
// (the single sources of truth) so the framework and the obligations index can
// never drift from the live interview. The pure builder below is exported for
// scripts/check-agent-assets.mjs to compare module-derived content against
// without writing files.
//
// Runtime: invoked via `node --experimental-strip-types`, which strip-types the
// imported .ts. The write side-effect is guarded by a main-module check so that
// importing the builder (in the test) never writes to disk.

import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import { domainProfile, REGULATED_DOMAIN_KEYS } from '../src/lib/governance-domains.ts'
// Framework vocabulary imported from the shared single source of truth so the
// static surface speaks the SAME governance language as the live interview
// (src/routes/Marketing.tsx renders the same constants). No literal rule text is
// duplicated here; editing the rules in one module reaches both consumers.
import { AGENT_READABLE_RULES, BRIEF_FORMAT } from '../src/lib/governance-framework.ts'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const packageRoot = resolve(scriptDir, '..')

// Claim-safe framing the file ends with. Mirrors the disclaimer posture in the
// domain module: obligations to consider, not legal advice.
const CLAIM_SAFE_FRAMING =
  'These are obligations to consider, not legal advice. This framework does not ' +
  'assert that any product satisfies, is attested to, or is approved against any ' +
  'regulation or standard. Route regulated decisions to qualified human review.'

// Self-assessment protocol keywords the check asserts are present, so the file
// always carries a runnable protocol rather than prose that could drift away.
const SELF_ASSESSMENT_STEPS = [
  'Identify your task: what you are being asked to do, the data and systems it touches, and who authorized it.',
  'Map the task to a risk level (low, medium, high, or blocked) using the rules above — higher risk for credentials, private data, irreversible effects, money movement, legal/compliance exposure, production mutation, or unclear authority.',
  'Select your regulatory domain(s) from the per-domain obligations index below and add each listed obligation to consider.',
  'Choose the safest useful operating mode for that risk level: advise-only, draft-only, sandboxed, approval-required, or fail-closed.',
  'Fill in the brief template below for yourself, then stop and escalate to qualified human review wherever authority, permission, evidence, reversibility, or approval is missing.',
]

function bulletList(lines, marker = '-') {
  return lines.map((line) => `${marker} ${line}`).join('\n')
}

function numberedList(lines) {
  return lines.map((line, index) => `${index + 1}. ${line}`).join('\n')
}

// governance-framework.txt — governance framework, self-assessment protocol,
// brief template, and the per-domain obligations index. The domain section is
// built by iterating the domain keys so it is provably module-derived and
// drift-proof.
export function buildFrameworkTxt() {
  const domainBlocks = REGULATED_DOMAIN_KEYS.map((key) => {
    const profile = domainProfile(key)
    const obligations =
      profile.obligations.length > 0
        ? bulletList(profile.obligations)
        : '- No additional regulatory-domain obligations for this selection.'
    return `### ${profile.label} [${key}]

${obligations}

${profile.disclaimer}`
  }).join('\n\n')

  return `# ACGS — Agent Governance Framework (governance-framework.txt)

This is the FRAMEWORK and a self-assessment PROTOCOL for any AI agent reading
this origin without a browser. It is identical for every agent. It is NOT your
personalized brief: a personalized brief requires running the in-browser
governance calculator, which fills the template below for your specific task.
Use this file to govern yourself directly.

## Governance framework

${bulletList(AGENT_READABLE_RULES)}

## Self-assessment protocol

Because you cannot run the in-browser calculator headless, map your own task to a
risk level and produce your own brief with these steps:

${numberedList(SELF_ASSESSMENT_STEPS)}

## Brief template (fill this in for yourself)

A completed brief covers these fields. This is the empty template, not a brief
already computed for you:

${bulletList(BRIEF_FORMAT)}

## Per-domain obligations

${domainBlocks}

## Claim boundary

${CLAIM_SAFE_FRAMING}
`
}

// Resolve the output directory vite just produced. Must match vite's outDir
// resolution (same ACGI_OUT_DIR env var) so the file lands in the FINAL
// published artifact for whichever surface was built.
export function resolveOutDir() {
  return resolve(packageRoot, process.env.ACGI_OUT_DIR || 'dist')
}

export function writeAgentAssets(outDir = resolveOutDir()) {
  mkdirSync(outDir, { recursive: true })
  const frameworkPath = resolve(outDir, 'governance-framework.txt')
  writeFileSync(frameworkPath, buildFrameworkTxt(), 'utf8')
  return { frameworkPath }
}

// Side-effect guard: only write when run as the entry script, never on import.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { frameworkPath } = writeAgentAssets()
  console.log(`Wrote agent governance surface:\n- ${frameworkPath}`)
}
