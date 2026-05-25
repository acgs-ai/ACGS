import { createHash } from 'node:crypto'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const manifestRelativePath = 'fonts.sha256'
const manifestPath = resolve(root, manifestRelativePath)
const fontsDirectory = resolve(root, 'public/static/fonts')
const failures = []

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

function sha256(relativePath) {
  const fileBuffer = readFileSync(resolve(root, relativePath))
  return createHash('sha256').update(fileBuffer).digest('hex')
}

function sorted(values) {
  return [...values].sort((a, b) => a.localeCompare(b))
}

function sameItems(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

const fontNames = sorted(
  readdirSync(fontsDirectory).filter((name) => name.endsWith('.woff2')),
)
const expectedFontPaths = fontNames.map((name) => `public/static/fonts/${name}`)
const fontCss = read('src/fonts.css')
const cssFontPaths = sorted(
  [...fontCss.matchAll(/url\(["']?\/static\/fonts\/([^"')]+\.woff2)["']?\)/g)].map(
    (match) => `public/static/fonts/${match[1]}`,
  ),
)
const packageJson = JSON.parse(read('package.json'))

check(fontNames.length > 0, 'public/static/fonts must contain WOFF2 files.')
check(
  sameItems(cssFontPaths, expectedFontPaths),
  'src/fonts.css must reference exactly every WOFF2 file under public/static/fonts/.',
)
check(existsSync(manifestPath), 'fonts.sha256 must exist at the acgi-ai package root.')

let manifestEntries = []
if (existsSync(manifestPath)) {
  const manifestLines = read(manifestRelativePath)
    .split('\n')
    .filter((line) => line.trim().length > 0)

  manifestEntries = manifestLines.map((line) => {
    const match = line.match(/^([a-f0-9]{64}) {2}(public\/static\/fonts\/[A-Za-z0-9._-]+\.woff2)$/)
    if (!match) {
      failures.push(
        `Invalid fonts.sha256 line; expected '<sha256>  public/static/fonts/<file>.woff2': ${line}`,
      )
      return null
    }
    return { hash: match[1], path: match[2], line }
  })

  const validEntries = manifestEntries.filter((entry) => entry !== null)
  const manifestPaths = validEntries.map((entry) => entry.path)
  check(
    sameItems(manifestPaths, expectedFontPaths),
    'fonts.sha256 must contain exactly one sorted entry for every WOFF2 file.',
  )

  for (const entry of validEntries) {
    check(
      entry.hash === sha256(entry.path),
      `fonts.sha256 hash mismatch for ${entry.path}.`,
    )
  }
}

check(
  packageJson.scripts?.['test:font-manifest'] === 'node scripts/check-font-manifest.mjs',
  'package.json must expose test:font-manifest.',
)
check(
  typeof packageJson.scripts?.build === 'string' &&
    packageJson.scripts.build.startsWith('pnpm run test:font-manifest && '),
  'package.json build must verify fonts.sha256 before producing artifacts.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:font-manifest'),
  'package.json test:all must include test:font-manifest.',
)

if (failures.length > 0) {
  console.error('Font manifest check failed:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log(`Font manifest check passed for ${expectedFontPaths.length} WOFF2 files.`)
