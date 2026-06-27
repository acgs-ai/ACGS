// Agent/crawler discovery contract for the marketing surface (sitemap + robots + llms.txt).
//
// Guards that public/sitemap.xml is a well-formed sitemaps.org urlset of absolute
// https://acgs.ai canonical URLs, excludes privileged surfaces, that
// public/robots.txt references it, and that public/llms.txt is the canonical
// claim-safe file (pinned byte-identical to the repo-root llms.txt, so /llms.txt
// never silently regresses to the SPA text/html fallback). Deliberately does NOT
// parse the router — route additions are reflected in sitemap.xml by hand (see the
// comment in that file). Wired into test:all so a regression fails CI.

import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []
const check = (condition, message) => {
  if (!condition) failures.push(message)
}

const read = (relativePath) => readFileSync(resolve(root, relativePath), 'utf8')

const SITE_ORIGIN = 'https://acgs.ai'
const PRIVILEGED = ['/console', '/login']

let sitemap = ''
try {
  sitemap = read('public/sitemap.xml')
} catch {
  failures.push('public/sitemap.xml must exist.')
}

if (sitemap) {
  check(
    sitemap.includes('<?xml') && sitemap.includes('http://www.sitemaps.org/schemas/sitemap/0.9'),
    'sitemap.xml must declare the sitemaps.org 0.9 urlset namespace.',
  )

  const locs = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1].trim())
  check(locs.length > 0, 'sitemap.xml must contain at least one <loc>.')

  // Balanced <url>/<loc> — cheap well-formedness signal without a full XML parser.
  const urlOpen = (sitemap.match(/<url>/g) || []).length
  const urlClose = (sitemap.match(/<\/url>/g) || []).length
  check(urlOpen === urlClose, 'sitemap.xml has unbalanced <url> tags.')
  check(urlOpen === locs.length, 'sitemap.xml: every <url> must carry exactly one <loc>.')

  for (const loc of locs) {
    check(
      loc.startsWith(`${SITE_ORIGIN}/`),
      `sitemap loc must be an absolute ${SITE_ORIGIN} URL: ${loc}`,
    )
    const path = loc.slice(SITE_ORIGIN.length)
    check(
      !PRIVILEGED.some((p) => path === p || path.startsWith(`${p}/`)),
      `sitemap must not list privileged/redirect surface: ${loc}`,
    )
  }

  const unique = new Set(locs)
  check(unique.size === locs.length, 'sitemap.xml contains duplicate <loc> entries.')
}

let robots = ''
try {
  robots = read('public/robots.txt')
} catch {
  failures.push('public/robots.txt must exist.')
}

if (robots) {
  check(
    /^Sitemap:\s*https:\/\/acgs\.ai\/sitemap\.xml\s*$/m.test(robots),
    'robots.txt must reference the sitemap (Sitemap: https://acgs.ai/sitemap.xml).',
  )
}

// llms.txt — serve the canonical claim-safe file at the marketing origin, pinned
// byte-identical to the repo-root llms.txt so the public copy can't drift or
// regress to the SPA HTML fallback. Re-copy `llms.txt` -> `acgi-ai/public/llms.txt`
// after editing the root file.
let publicLlms = ''
let rootLlms = ''
try {
  publicLlms = read('public/llms.txt')
} catch {
  failures.push('public/llms.txt must exist.')
}
try {
  rootLlms = readFileSync(resolve(root, '..', 'llms.txt'), 'utf8')
} catch {
  failures.push('repo-root llms.txt must exist.')
}
if (publicLlms && rootLlms) {
  check(
    publicLlms === rootLlms,
    'public/llms.txt must be byte-identical to the repo-root llms.txt (re-copy after editing root).',
  )
}

if (failures.length > 0) {
  console.error('Agent-discovery (sitemap/robots/llms) contract check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Agent-discovery (sitemap/robots/llms) contract check passed.')
