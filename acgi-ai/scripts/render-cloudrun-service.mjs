import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')

const placeholders = {
  image: 'REPLACE_AT_DEPLOY_TIME',
  buildId: 'REPLACE_BUILD_ID_AT_DEPLOY_TIME',
  authUpstream: 'REPLACE_AUTH_UPSTREAM_AT_DEPLOY_TIME',
  busUpstream: 'REPLACE_BUS_UPSTREAM_AT_DEPLOY_TIME',
}

const allowedEnvironments = new Set(['preview', 'staging', 'production'])

function usage() {
  return `Usage: node scripts/render-cloudrun-service.mjs --env <preview|staging|production> --image <uri> --build-id <id> --auth-upstream <url> --bus-upstream <url> [--out <path>]\n\nEnvironment fallbacks: DEPLOY_ENV, IMAGE_URI, ACGI_BUILD_ID, AUTH_UPSTREAM, BUS_UPSTREAM.`
}

function fail(message) {
  console.error(`Cloud Run render failed: ${message}`)
  console.error(usage())
  process.exit(1)
}

function parseArgs(argv) {
  const parsed = {}
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (!arg.startsWith('--')) fail(`unexpected argument ${arg}`)
    const key = arg.slice(2)
    const value = argv[index + 1]
    if (!value || value.startsWith('--')) fail(`missing value for --${key}`)
    parsed[key] = value
    index += 1
  }
  return parsed
}

function requireValue(label, value) {
  if (!value?.trim()) fail(`${label} is required`)
  if (/REPLACE_|undefined|null/.test(value)) fail(`${label} must not be a placeholder`)
  return value.trim()
}

function requireUpstream(label, value) {
  const upstream = requireValue(label, value)
  if (!/^https?:\/\//.test(upstream)) fail(`${label} must start with http:// or https://`)
  return upstream
}

function replaceExactlyOnce(source, placeholder, value) {
  const count = source.split(placeholder).length - 1
  if (count !== 1)
    fail(`${placeholder} must appear exactly once in the service template; found ${count}`)
  return source.replace(placeholder, value)
}

const args = parseArgs(process.argv.slice(2))
const environment = requireValue('DEPLOY_ENV', args.env ?? process.env.DEPLOY_ENV ?? 'production')
if (!allowedEnvironments.has(environment)) {
  fail(`unsupported DEPLOY_ENV=${environment}; expected preview, staging, or production`)
}

const image = requireValue('IMAGE_URI', args.image ?? process.env.IMAGE_URI)
const buildId = requireValue('ACGI_BUILD_ID', args['build-id'] ?? process.env.ACGI_BUILD_ID)
const authUpstream = requireUpstream(
  'AUTH_UPSTREAM',
  args['auth-upstream'] ?? process.env.AUTH_UPSTREAM,
)
const busUpstream = requireUpstream(
  'BUS_UPSTREAM',
  args['bus-upstream'] ?? process.env.BUS_UPSTREAM,
)
const outPath = resolve(root, args.out ?? process.env.SERVICE_OUT ?? 'infra/cloudrun/service.yaml')
const templatePath = resolve(root, `infra/cloudrun/service.${environment}.yaml`)

let rendered = readFileSync(templatePath, 'utf8')
rendered = replaceExactlyOnce(rendered, placeholders.image, image)
rendered = replaceExactlyOnce(rendered, placeholders.buildId, buildId)
rendered = replaceExactlyOnce(rendered, placeholders.authUpstream, authUpstream)
rendered = replaceExactlyOnce(rendered, placeholders.busUpstream, busUpstream)

if (/REPLACE_[A-Z_]+/.test(rendered)) {
  fail('rendered service.yaml still contains REPLACE_* placeholders')
}

mkdirSync(dirname(outPath), { recursive: true })
writeFileSync(outPath, rendered, 'utf8')
console.log(`Rendered Cloud Run ${environment} service manifest: ${outPath}`)
