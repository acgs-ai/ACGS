import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, extname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(root, '..')
const failures = []
const allowedUrl =
  /^https?:\/\/(www\.w3\.org\/|react\.dev\/errors\/|localhost(?::\d+)?(?:\/|$)|127\.0\.0\.1(?::\d+)?(?:\/|$))/

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function maybeRead(relativePath) {
  const absolute = resolve(root, relativePath)
  return existsSync(absolute) ? readFileSync(absolute, 'utf8') : ''
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

function walk(dir, predicate = () => true) {
  if (!existsSync(dir)) return []
  const out = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const absolute = join(dir, entry.name)
    if (entry.isDirectory()) {
      out.push(...walk(absolute, predicate))
    } else if (predicate(absolute)) {
      out.push(absolute)
    }
  }
  return out
}

function rel(path) {
  return relative(repoRoot, path)
}

function scanSourceForCspHazards() {
  const sourceFiles = walk(resolve(root, 'src'), (file) => {
    if (file.includes(`${join('src', 'assets')}${join('', '')}`)) return false
    return ['.tsx', '.jsx'].includes(extname(file))
  })

  // Anti-wizard-re-run guard (docs/POSTHOG_CONSOLE_TELEMETRY_DESIGN.md §6):
  // no PostHog (or any analytics vendor) SDK import anywhere under src/ —
  // ALL of src/, .ts included, because Login.tsx and shared modules sit
  // outside src/{surfaces,routes}/console/**. The only sanctioned analytics
  // path is the first-party emitter posting to same-origin /api/telemetry.
  const allSourceFiles = walk(resolve(root, 'src'), (file) =>
    ['.ts', '.tsx', '.js', '.jsx'].includes(extname(file)),
  )
  for (const file of allSourceFiles) {
    const source = readFileSync(file, 'utf8')
    check(
      !/(?:from\s*|import\s*\(\s*|require\s*\(\s*)['"](?:@posthog\/|posthog)/m.test(source),
      `${rel(file)} must not import a PostHog SDK — the console analytics path is the first-party emitter only (docs/POSTHOG_CONSOLE_TELEMETRY_DESIGN.md).`,
    )
  }

  for (const file of sourceFiles) {
    const source = readFileSync(file, 'utf8')
    check(!/style\s*=\s*\{\s*\{/.test(source), `${rel(file)} must not use JSX style={{...}}.`)
    check(
      !/style\s*=\s*['"]/.test(source),
      `${rel(file)} must not render literal style= attributes.`,
    )
    check(
      !/(?:className|class)\s*=\s*["'][^"']*(?:-\[|\[[^\]]+\])/.test(source),
      `${rel(file)} must not use literal arbitrary-value Tailwind classes under strict CSP.`,
    )
  }
}

function scanBuiltConsoleArtifact() {
  const dist = resolve(root, 'dist')
  check(
    existsSync(dist) && statSync(dist).isDirectory(),
    'dist/ must exist before CSP harness scans the production console artifact.',
  )
  if (!existsSync(dist)) return

  for (const file of walk(dist, (candidate) =>
    ['.html', '.js', '.css'].includes(extname(candidate)),
  )) {
    const source = readFileSync(file, 'utf8')
    check(!/<style\b/i.test(source), `${rel(file)} must not contain runtime <style> tags.`)
    check(!/\sstyle=/.test(source), `${rel(file)} must not contain inline style= attributes.`)
    check(!source.includes("'unsafe-inline'"), `${rel(file)} must not contain unsafe-inline CSP.`)

    for (const match of source.matchAll(/https?:\/\/[^\s"'`<>),]+/g)) {
      const url = match[0]
      check(
        allowedUrl.test(url),
        `${rel(file)} contains unexpected third-party URL literal: ${url}`,
      )
    }
  }
}

const packageJson = JSON.parse(read('package.json'))
const caddyfile = read('infra/Caddyfile')
const viteConfig = read('vite.config.ts')
const postdeploy = read('scripts/postdeploy-verify.sh')
const securityCheck = read('scripts/check-security-invariants.mjs')
const readiness = maybeRead('../docs/integration-readiness-task-map.md')
const cspHeaderLine =
  caddyfile.split('\n').find((line) => line.trim().startsWith('Content-Security-Policy ')) ?? ''

check(
  packageJson.scripts?.['test:csp'] ===
    'pnpm run build:console && node scripts/check-console-csp-harness.mjs',
  'package.json must expose test:csp as a production console build plus CSP harness scan.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:csp'),
  'package.json test:all must include test:csp.',
)
check(
  /@tailwindcss\/vite/.test(viteConfig) && /tailwindcss\(\)/.test(viteConfig),
  'vite.config.ts must make the Tailwind-v4 CSP decision explicit while the plugin remains enabled.',
)
check(
  /default-src 'self'/.test(cspHeaderLine) &&
    /script-src 'self'/.test(cspHeaderLine) &&
    /style-src 'self'/.test(cspHeaderLine) &&
    /frame-ancestors 'none'/.test(cspHeaderLine) &&
    /base-uri 'self'/.test(cspHeaderLine) &&
    /form-action 'self'/.test(cspHeaderLine) &&
    !/unsafe-inline/.test(cspHeaderLine),
  'infra/Caddyfile must enforce strict console CSP without unsafe-inline.',
)
check(
  /Content-Security-Policy/.test(postdeploy) &&
    /style=/.test(postdeploy) &&
    /unexpected third-party URLs/.test(postdeploy),
  'postdeploy verifier must preserve CSP header, inline-style, and third-party URL checks.',
)
check(
  securityCheck.includes('check-console-csp-harness.mjs') && securityCheck.includes('test:csp'),
  'security invariant check must cover the console CSP harness wiring.',
)
check(
  readiness.includes('Console CSP/Tailwind harness') &&
    readiness.includes('pnpm -F acgi-ai run test:csp'),
  'integration readiness map must record the console CSP/Tailwind harness gate.',
)

scanSourceForCspHazards()
scanBuiltConsoleArtifact()

if (failures.length) {
  console.error('Console CSP harness check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Console CSP harness check passed.')
