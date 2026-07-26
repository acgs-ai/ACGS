// Self-contained equality/existence check for the agent-readable governance
// surface. It does NOT depend on a pre-existing dist file: it runs the
// generator's PURE builder itself and compares the result against the domain and
// framework modules, so ordering is intrinsic (no build step required first).
//
// Scope: only governance-framework.txt is generated. `llms.txt` is authored, not
// derived — scripts/check-sitemap.mjs pins public/llms.txt byte-identical to the
// repo-root llms.txt and owns that assertion. Keep the two gates disjoint.
//
// Runtime: invoked via `node --experimental-strip-types` so the transitive
// import chain (this file -> gen-agent-assets.mjs -> governance-domains.ts) is
// strip-typed.

import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { domainProfile, REGULATED_DOMAIN_KEYS } from '../src/lib/governance-domains.ts'
import { AGENT_READABLE_RULES, BRIEF_FORMAT } from '../src/lib/governance-framework.ts'
import { buildFrameworkTxt } from './gen-agent-assets.mjs'

const failures = []

function check(condition, message) {
  if (!condition) failures.push(message)
}

const framework = buildFrameworkTxt()

// (a) Output non-empty.
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
    framework.includes(keyword),
    `governance-framework.txt must contain the self-assessment protocol keyword: ${keyword}`,
  )
}
check(
  framework.includes('not legal advice'),
  'governance-framework.txt must carry the "not legal advice" framing.',
)

// (c2) Emission guard: every AGENT_READABLE_RULES item must reach the generated
// framework section. Scope of the assertion: the generator and this check import
// the SAME module, so this cannot detect a rules EDIT (both sides move together).
// What it does catch is a generator that stops emitting the rules — e.g. a
// refactor that drops the section, reorders it out of the template, or truncates
// the list. Module-to-consumer coupling is asserted structurally in (c4).
for (const rule of AGENT_READABLE_RULES) {
  check(
    framework.includes(rule),
    `governance-framework.txt must emit the shared AGENT_READABLE_RULES item: ${rule}`,
  )
}

// (c3) Same emission guard for the brief-format field list, which the in-browser
// AgentReadable panel renders from the same module.
for (const field of BRIEF_FORMAT) {
  check(
    framework.includes(field),
    `governance-framework.txt must emit the shared BRIEF_FORMAT field: ${field}`,
  )
}

// (c4) Real drift guard: the in-browser panel must render the SAME module this
// artifact is generated from. Re-inlining the rule literals into Marketing.tsx
// would let the live interview and the static surface diverge silently, and no
// content assertion above could see it — so assert the import edge itself.
const marketingSource = readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), '../src/routes/Marketing.tsx'),
  'utf8',
)
check(
  /import\s*\{[^}]*\bAGENT_READABLE_RULES\b[^}]*\}\s*from\s*'\.\.\/lib\/governance-framework'/s.test(
    marketingSource,
  ),
  'src/routes/Marketing.tsx must import AGENT_READABLE_RULES from ../lib/governance-framework (no re-inlined rule literals).',
)
check(
  /import\s*\{[^}]*\bBRIEF_FORMAT\b[^}]*\}\s*from\s*'\.\.\/lib\/governance-framework'/s.test(
    marketingSource,
  ),
  'src/routes/Marketing.tsx must import BRIEF_FORMAT from ../lib/governance-framework (no re-inlined field literals).',
)

// (d) Negative assertion: framework-only, NOT a personalized brief. A filled
// brief is produced only by the in-browser calculator and would contain a
// computed-verdict sentinel. The static surface must never contain it.
const personalizedBriefMarkers = ['Computed risk level:', 'Your recommended mode:']
for (const marker of personalizedBriefMarkers) {
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
