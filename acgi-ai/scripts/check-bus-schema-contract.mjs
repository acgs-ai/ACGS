import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(root, '..')
const failures = []

function check(condition, message) {
  if (!condition) failures.push(message)
}

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function readRepo(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), 'utf8')
}

function readJson(relativePath) {
  return JSON.parse(read(relativePath))
}

function readFixture(name) {
  return JSON.parse(read(`contracts/fixtures/bus/${name}`))
}

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`
}

function getSchema(contract, name) {
  return contract.components?.schemas?.[name]
}

function hasRequired(schema, fields) {
  const required = new Set(schema?.required ?? [])
  return fields.every((field) => required.has(field))
}

function objectHasOnlyKnownProperties(value, schema) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const properties = schema?.properties ?? {}
  return Object.keys(value).every((key) => key in properties)
}

function hasProperties(value, fields) {
  return value && typeof value === 'object' && fields.every((field) => field in value)
}

function eventLooksSchemaConformant(event) {
  return hasProperties(event, [
    'event_id',
    'correlation_id',
    'causal_index',
    'recorded_at',
    'source_agent',
    'payload_ref',
    'kind',
    'constitutional_hash',
    'event_hash',
    'status',
  ])
}

function traceItemLooksSchemaConformant(item) {
  return hasProperties(item, [
    'correlation_id',
    'started_at',
    'event_count',
    'worst_event_status',
    'integrity_status',
    'constitutional_hash',
  ])
}

function codegenMatchesContract() {
  const tempDir = resolve(root, `.tmp-bus-schema-contract-${process.pid}`)
  const tempOut = resolve(tempDir, 'bus.generated.ts')
  try {
    rmSync(tempDir, { force: true, recursive: true })
    mkdirSync(tempDir, { recursive: true })
    execFileSync(
      'pnpm',
      ['exec', 'openapi-typescript', 'contracts/bus.openapi.json', '-o', tempOut],
      {
        cwd: root,
        stdio: 'pipe',
      },
    )
    execFileSync('pnpm', ['exec', 'biome', 'format', '--write', tempOut], {
      cwd: root,
      stdio: 'pipe',
    })
    return readFileSync(tempOut, 'utf8') === read('src/api/bus.generated.ts')
  } catch (error) {
    failures.push(
      `could not regenerate bus.generated.ts from contracts/bus.openapi.json: ${error.message}`,
    )
    return false
  } finally {
    rmSync(tempDir, { force: true, recursive: true })
  }
}

const contractPath = resolve(root, 'contracts/bus.openapi.json')
const legacyOpenApiPath = resolve(root, 'src/api/openapi.json')
const generatedPath = resolve(root, 'src/api/bus.generated.ts')
const fixturesDir = resolve(root, 'contracts/fixtures/bus')
const packageJson = readJson('package.json')
const consoleWorkflow = readRepo('.github/workflows/console.yml')
const securityCheck = read('scripts/check-security-invariants.mjs')
const ciReadinessGateCheck = read('scripts/check-ci-readiness-gates.mjs')
const architecture = read('ARCHITECTURE.md')
const deploy = read('DEPLOY.md')
const integrating = read('INTEGRATING.md')
const readiness = readRepo('docs/integration-readiness-task-map.md')
const apiGuide = read('src/api/AGENTS.md')
const rootMakefile = readRepo('Makefile')

check(
  existsSync(contractPath),
  'contracts/bus.openapi.json must exist as the vendored bus schema source of truth.',
)
check(
  existsSync(legacyOpenApiPath),
  'src/api/openapi.json must remain as a compatibility mirror for local API docs.',
)
check(existsSync(generatedPath), 'src/api/bus.generated.ts must exist as generated bus API types.')
check(
  existsSync(fixturesDir) && statSync(fixturesDir).isDirectory(),
  'contracts/fixtures/bus/ must exist.',
)

if (existsSync(contractPath)) {
  const contract = readJson('contracts/bus.openapi.json')
  const paths = contract.paths ?? {}
  const event = getSchema(contract, 'Event')
  const traceList = getSchema(contract, 'TraceList')
  const traceListItem = getSchema(contract, 'TraceListItem')
  const singleTrace = getSchema(contract, 'SingleTrace')
  const receiptProof = getSchema(contract, 'ReceiptProof')
  const httpValidationError = getSchema(contract, 'HTTPValidationError')

  check(contract.openapi === '3.1.0', 'bus OpenAPI contract must stay on OpenAPI 3.1.0.')
  check(
    contract.info?.title === 'agent-bus-analyzer' && contract.info?.version,
    'bus OpenAPI contract must preserve upstream title and version metadata.',
  )
  for (const path of [
    '/api/bus/healthz',
    '/api/bus/traces',
    '/api/bus/traces/{correlation_id}',
    '/api/bus/receipts/{receipt_id}',
  ]) {
    check(path in paths, `bus OpenAPI contract must include ${path}.`)
  }
  for (const name of [
    'Event',
    'ReceiptProof',
    'TraceList',
    'TraceListItem',
    'SingleTrace',
    'HTTPValidationError',
    'ValidationError',
  ]) {
    check(Boolean(getSchema(contract, name)), `bus OpenAPI contract must include ${name} schema.`)
  }
  check(
    event?.additionalProperties === false &&
      traceList?.additionalProperties === false &&
      traceListItem?.additionalProperties === false &&
      singleTrace?.additionalProperties === false &&
      receiptProof?.additionalProperties === false,
    'bus schemas must reject unknown fields for Event, TraceList, TraceListItem, SingleTrace, and ReceiptProof.',
  )
  check(
    hasRequired(event, [
      'event_id',
      'correlation_id',
      'causal_index',
      'recorded_at',
      'source_agent',
      'payload_ref',
      'kind',
      'constitutional_hash',
      'event_hash',
      'status',
    ]),
    'Event schema must require the audit trace fields used by fixtures and UI.',
  )
  check(
    hasRequired(singleTrace, ['trace', 'integrity_status']),
    'SingleTrace schema must require trace and integrity_status.',
  )
  check(
    hasRequired(receiptProof, [
      'receipt_id',
      'receipt_hash',
      'correlation_id',
      'integrity_status',
      'hash_chain_verified',
      'policy_path',
      'signed_evidence_packet',
    ]),
    'ReceiptProof schema must require receipt identity, integrity, policy path, and signed evidence packet fields.',
  )
  check(
    hasRequired(traceListItem, [
      'correlation_id',
      'started_at',
      'event_count',
      'worst_event_status',
      'integrity_status',
      'constitutional_hash',
    ]),
    'TraceListItem schema must require stable list summary fields.',
  )
  check(
    Boolean(httpValidationError?.properties?.detail),
    'HTTPValidationError schema must expose detail for error-envelope contract tests.',
  )

  if (existsSync(legacyOpenApiPath)) {
    check(
      canonicalJson(contract) === canonicalJson(readJson('src/api/openapi.json')),
      'src/api/openapi.json must byte-for-byte mirror contracts/bus.openapi.json after JSON normalization.',
    )
  }

  if (existsSync(generatedPath)) {
    const generated = read('src/api/bus.generated.ts')
    check(
      generated.includes('This file was auto-generated by openapi-typescript') &&
        generated.includes('/api/bus/traces') &&
        generated.includes('/api/bus/receipts/{receipt_id}') &&
        generated.includes('ReceiptProof') &&
        generated.includes('SingleTrace') &&
        generated.includes('TraceList'),
      'src/api/bus.generated.ts must be generated from the bus OpenAPI schema.',
    )
    check(
      codegenMatchesContract(),
      'src/api/bus.generated.ts must exactly match codegen from contracts/bus.openapi.json.',
    )
  }

  if (existsSync(fixturesDir)) {
    const traceListOk = readFixture('trace-list.ok.json')
    const singleTraceOk = readFixture('single-trace.ok.json')
    const unknownField = readFixture('single-trace.unknown-field.json')
    const missingRequired = readFixture('single-trace.missing-required.json')
    const versionSkew = readFixture('schema-version-skew-error.json')
    const errorEnvelope = readFixture('error-envelope.json')

    check(
      traceListOk.kind === 'trace-list' &&
        Array.isArray(traceListOk.items) &&
        traceListOk.items.length > 0 &&
        traceListOk.items.every(
          (item) =>
            traceItemLooksSchemaConformant(item) &&
            objectHasOnlyKnownProperties(item, traceListItem),
        ),
      'trace-list.ok.json must contain schema-shaped TraceListItem records without extra fields.',
    )
    check(
      singleTraceOk.kind === 'single-trace' &&
        traceItemLooksSchemaConformant(singleTraceOk.trace) &&
        objectHasOnlyKnownProperties(singleTraceOk.trace, traceListItem) &&
        ['intact', 'tampered', 'unknown'].includes(singleTraceOk.integrity_status) &&
        Array.isArray(singleTraceOk.events) &&
        singleTraceOk.events.every(
          (eventFixture) =>
            eventLooksSchemaConformant(eventFixture) &&
            objectHasOnlyKnownProperties(eventFixture, event),
        ),
      'single-trace.ok.json must contain a schema-shaped SingleTrace without extra fields.',
    )
    check(
      Object.keys(unknownField).some((key) => !(key in (singleTrace?.properties ?? {}))),
      'single-trace.unknown-field.json must contain an unknown top-level field to prove strict rejection coverage.',
    )
    check(
      !hasProperties(missingRequired, ['trace', 'integrity_status']),
      'single-trace.missing-required.json must omit a required SingleTrace field.',
    )
    check(
      versionSkew.error?.code === 'schema_version_mismatch' &&
        versionSkew.header === 'X-ACGS-Schema-Version' &&
        typeof versionSkew.expected_schema_version === 'string' &&
        typeof versionSkew.received_schema_version === 'string',
      'schema-version-skew-error.json must document the X-ACGS-Schema-Version mismatch envelope.',
    )
    check(
      typeof errorEnvelope.error?.code === 'string' &&
        typeof errorEnvelope.error?.message === 'string' &&
        typeof errorEnvelope.correlation_id === 'string',
      'error-envelope.json must document the machine-readable bus error envelope.',
    )
  }
}

check(
  packageJson.scripts?.['gen:api'] ===
    'openapi-typescript contracts/bus.openapi.json -o src/api/bus.generated.ts && biome format --write src/api/bus.generated.ts',
  'package.json gen:api must generate bus types from contracts/bus.openapi.json.',
)
const makeOpenapiBlock = rootMakefile.match(/^openapi:\n(?:(?:\t.*\n)+)/m)?.[0] ?? ''
check(
  /export-openapi --output acgi-ai\/contracts\/bus\.openapi\.json/.test(makeOpenapiBlock),
  'root make openapi must regenerate acgi-ai/contracts/bus.openapi.json as the bus schema source of truth.',
)
check(
  /biome format --write contracts\/bus\.openapi\.json/.test(makeOpenapiBlock),
  'root make openapi must format the bus schema source of truth before mirroring it.',
)
check(
  /cp acgi-ai\/contracts\/bus\.openapi\.json acgi-ai\/src\/api\/openapi\.json/.test(
    makeOpenapiBlock,
  ),
  'root make openapi must refresh src/api/openapi.json as a compatibility mirror of the contract.',
)
check(
  /\$\(PNPM\) -F acgi-ai run gen:api/.test(makeOpenapiBlock),
  'root make openapi must regenerate src/api/bus.generated.ts through package.json gen:api.',
)
check(
  packageJson.scripts?.['test:bus-schema'] === 'node scripts/check-bus-schema-contract.mjs',
  'package.json must expose test:bus-schema.',
)
check(
  typeof packageJson.scripts?.['test:contract'] === 'string' &&
    packageJson.scripts['test:contract'].startsWith(
      'pnpm run test:bus-schema && pnpm run test:bus-proxy',
    ),
  'package.json test:contract must start with test:bus-schema before test:bus-proxy.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:bus-schema'),
  'package.json test:all must include test:bus-schema.',
)
check(
  /acgi-ai\/contracts\/\*\*/.test(consoleWorkflow),
  'console.yml path filters must include acgi-ai/contracts/**.',
)
check(
  /contracts\/bus\.openapi\.json/.test(securityCheck) && /test:bus-schema/.test(securityCheck),
  'security invariant check must guard bus schema contract wiring.',
)
check(
  /acgi-ai\/contracts\/\*\*/.test(ciReadinessGateCheck) &&
    /test:bus-schema/.test(ciReadinessGateCheck),
  'CI readiness gate check must guard contract path filters and bus schema gate wiring.',
)
for (const [label, source] of [
  ['ARCHITECTURE.md', architecture],
  ['DEPLOY.md', deploy],
  ['INTEGRATING.md', integrating],
  ['docs/integration-readiness-task-map.md', readiness],
  ['src/api/AGENTS.md', apiGuide],
]) {
  check(
    /contracts\/bus\.openapi\.json/.test(source) && /test:bus-schema/.test(source),
    `${label} must document the bus schema source of truth and test:bus-schema gate.`,
  )
}

if (failures.length > 0) {
  console.error('Bus schema contract check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Bus schema contract check passed.')
