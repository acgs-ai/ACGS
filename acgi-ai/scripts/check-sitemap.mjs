// Sitemap + robots contract for the marketing surface.
//
// Guards that public/sitemap.xml is a well-formed sitemaps.org urlset of absolute
// https://acgs.ai canonical URLs, excludes privileged surfaces, and that
// public/robots.txt references it. Deliberately does NOT parse the router — route
// additions are reflected in sitemap.xml by hand (see the comment in that file).
// Wired into test:all so a malformed sitemap or a dropped Sitemap reference fails CI.

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

if (failures.length > 0) {
  console.error('Sitemap/robots contract check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Sitemap/robots contract check passed.')
