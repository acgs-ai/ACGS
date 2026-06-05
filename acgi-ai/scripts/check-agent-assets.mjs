// Self-contained equality/existence test for the agent-readable governance
// surface. It does NOT depend on a pre-existing dist file: it runs the
// generator's PURE builders itself and compares them against the W1 module, so
// ordering is intrinsic (no build step required before this test).
//
// Runtime: invoked via `node --experimental-strip-types` so the transitive
// import chain (this file -> gen-agent-assets.mjs -> governance-domains.ts) is
// strip-typed.

import { buildFrameworkTxt, buildLlmsTxt } from './gen-agent-assets.mjs'
import {
  domainProfile,
  REGULATED_DOMAIN_KEYS,
} from '../src/lib/governance-domains.ts'
import { AGENT_READABLE_RULES } from '../src/lib/governance-framework.ts'

const failures = []

function check(condition, message) {
  if (!condition) failures.push(message)
}

const llms = buildLlmsTxt()
const framework = buildFrameworkTxt()

// (a) Both outputs non-empty.
check(typeof llms === 'string' && llms.trim().length > 0, 'llms.txt content must be non-empty.')
check(
  typeof framework === 'string' && framework.trim().length > 0,
  'governance-framework.txt content must be non-empty.',
)

// (b) Every domain label + at least one obligation per domain appears in the
// framework text, proving it is module-derived and drift-proof.
for (const key of REGULATED_DOMAIN_KEYS) {
  const profile = domainProfile(key)
  check(
    framework.includes(profile.label),
    `governance-framework.txt must include the domain label for "${key}": ${profile.label}`,
  )
  if (profile.obligations.length > 0) {
    const first = profile.obligations[0]
    check(
      framework.includes(first),
      `governance-framework.txt must include an obligation for "${key}" (drift check): ${first}`,
    )
  }
  // The disclaimer is the claim-safe framing each domain carries.
  check(
    framework.includes(profile.disclaimer),
    `governance-framework.txt must include the claim-safe disclaimer for "${key}".`,
  )
}

// (c) Self-assessment protocol keywords + the "not legal advice" framing.
const protocolKeywords = [
  'Self-assessment protocol',
  'risk level',
  'fail-closed',
  'qualified human review',
]
for (const keyword of protocolKeywords) {
  check(
    llms.includes(keyword),
    `llms.txt must contain the self-assessment protocol keyword: ${keyword}`,
  )
}
check(llms.includes('not legal advice'), 'llms.txt must carry the "not legal advice" framing.')
check(
  framework.includes('not legal advice'),
  'governance-framework.txt must carry the "not legal advice" framing.',
)

// (c2) Framework-rules drift guard: every AGENT_READABLE_RULES item from the
// shared single source of truth must reach the generated llms.txt framework
// section. A future rules edit that does not propagate into the artifact fails
// here, so the in-browser interview and the static surface can never diverge.
for (const rule of AGENT_READABLE_RULES) {
  check(
    llms.includes(rule),
    `llms.txt framework section must include the shared AGENT_READABLE_RULES item (drift check): ${rule}`,
  )
}

// (d) Negative assertion: framework-only, NOT a personalized brief. A filled
// brief is produced only by the in-browser calculator and would contain a
// computed-verdict sentinel. The static surface must never contain it.
const personalizedBriefMarkers = ['Computed risk level:', 'Your recommended mode:']
for (const marker of personalizedBriefMarkers) {
  check(
    !llms.includes(marker),
    `llms.txt must remain framework-only and not contain a personalized-brief marker: "${marker}"`,
  )
  check(
    !framework.includes(marker),
    `governance-framework.txt must remain framework-only and not contain a personalized-brief marker: "${marker}"`,
  )
}

if (failures.length > 0) {
  console.error('Agent governance asset check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Agent governance asset check passed.')
