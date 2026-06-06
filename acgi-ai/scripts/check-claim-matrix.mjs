import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const failures = []

function read(relativePath) {
  return readFileSync(resolve(root, relativePath), 'utf8')
}

function check(condition, message) {
  if (!condition) failures.push(message)
}

const matrixPath = resolve(root, 'claim-matrix.json')
const workspaceRoot = resolve(root, '..')
const packageJson = JSON.parse(read('package.json'))

let matrix = null
if (!existsSync(matrixPath)) {
  failures.push('claim-matrix.json must exist at the acgi-ai package root.')
} else {
  try {
    matrix = JSON.parse(read('claim-matrix.json'))
  } catch (error) {
    failures.push(`claim-matrix.json must be valid JSON: ${error.message}`)
  }
}

const publicFiles = [
  'src/routes/Marketing.tsx',
  'src/routes/Privacy.tsx',
  'src/routes/ProductSurfaces.tsx',
  'src/lib/governance-domains.ts',
]
const forbiddenPublicPhrases = [
  {
    phrase: 'production-ready',
    reason: 'local artifacts are verified; production proof is external',
  },
  { phrase: 'auditor-ready', reason: 'auditor/legal review is not complete' },
  { phrase: 'No third party touches', reason: 'subprocessor statement requires live/legal proof' },
  { phrase: 'no third party touches', reason: 'subprocessor statement requires live/legal proof' },
  { phrase: 'WCAG 2.2 AA conformant', reason: 'manual screen-reader evidence is external' },
  { phrase: 'certified', reason: 'certification must not be claimed without external evidence' },
]
for (const file of publicFiles) {
  const source = read(file)
  for (const { phrase, reason } of forbiddenPublicPhrases) {
    check(
      !source.includes(phrase),
      `${file} must not use "${phrase}" before evidence/legal signoff (${reason}).`,
    )
  }
}

if (matrix) {
  const requiredIds = new Set([
    'subprocessor-boundary',
    'console-privilege-boundary',
    'audit-retention',
    'regulatory-positioning',
    'production-auth-boundary',
    'console-csp-and-headers',
    'font-provenance',
    'bus-proxy-boundary',
    'wcag-manual-evidence',
    'soc2-roadmap',
  ])
  check(matrix.version === 1, 'claim-matrix.json must use version 1.')
  check(
    matrix.status === 'engineering_draft_pending_legal',
    'claim-matrix.json status must be engineering_draft_pending_legal until legal signs off.',
  )
  check(
    matrix.legalReview?.signedOff === false &&
      matrix.legalReview?.requiredBeforePublicDeploy === true,
    'claim-matrix.json must explicitly require legal review before public deploy.',
  )
  check(
    Array.isArray(matrix.claims) && matrix.claims.length > 0,
    'claim-matrix.json must list public compliance/security claims.',
  )

  const ids = new Set()
  for (const claim of matrix.claims ?? []) {
    ids.add(claim.id)
    check(typeof claim.id === 'string' && claim.id.length > 0, 'each claim needs an id.')
    check(
      typeof claim.allowedWording === 'string' && claim.allowedWording.length > 20,
      `claim ${claim.id ?? '<missing>'} needs conservative allowedWording.`,
    )
    check(
      !/\b(compliant|certified|guaranteed|production-ready|auditor-ready)\b/i.test(
        claim.allowedWording,
      ),
      `claim ${claim.id ?? '<missing>'} allowedWording must avoid compliance/certification/production-ready overclaims.`,
    )
    check(
      ['live', 'stubbed', 'config', 'manual_required', 'external_required'].includes(
        claim.evidenceState,
      ),
      `claim ${claim.id ?? '<missing>'} must declare evidenceState.`,
    )
    check(
      Array.isArray(claim.evidence) && claim.evidence.length > 0,
      `claim ${claim.id ?? '<missing>'} must cite evidence objects.`,
    )
    for (const item of claim.evidence ?? []) {
      const evidencePath =
        typeof item.file === 'string' ? resolve(workspaceRoot, item.file) : null
      const evidenceFileExists = evidencePath ? existsSync(evidencePath) : false
      check(
        typeof item.file === 'string' && evidenceFileExists,
        `claim ${claim.id ?? '<missing>'} evidence file must exist: ${item.file}`,
      )
      check(
        typeof item.anchor === 'string' && item.anchor.trim().length > 0,
        `claim ${claim.id ?? '<missing>'} evidence item must include a non-empty anchor.`,
      )
      if (evidenceFileExists && typeof item.anchor === 'string' && item.anchor.trim()) {
        const evidenceSource = readFileSync(evidencePath, 'utf8')
        check(
          evidenceSource.includes(item.anchor),
          `claim ${claim.id ?? '<missing>'} evidence anchor must appear in ${item.file}: ${JSON.stringify(
            item.anchor,
          )}`,
        )
      }
    }
    check(
      Array.isArray(claim.sourceFiles) && claim.sourceFiles.length > 0,
      `claim ${claim.id ?? '<missing>'} must list sourceFiles.`,
    )
    for (const sourceFile of claim.sourceFiles ?? []) {
      check(
        typeof sourceFile === 'string' && existsSync(resolve(root, sourceFile)),
        `claim ${claim.id ?? '<missing>'} source file must exist: ${sourceFile}`,
      )
    }
    check(
      typeof claim.owner === 'string' && claim.owner.length > 0,
      `claim ${claim.id ?? '<missing>'} needs owner.`,
    )
    check(
      typeof claim.reviewer === 'string' && claim.reviewer.length > 0,
      `claim ${claim.id ?? '<missing>'} needs reviewer.`,
    )
    check(
      /^\d{4}-\d{2}-\d{2}$/.test(claim.nextReviewDate ?? ''),
      `claim ${claim.id ?? '<missing>'} needs YYYY-MM-DD nextReviewDate.`,
    )
    check(
      claim.publicDeployAllowed === false,
      `claim ${claim.id ?? '<missing>'} must keep publicDeployAllowed=false until legal review is complete.`,
    )
  }
  for (const id of requiredIds) {
    check(ids.has(id), `claim-matrix.json must include required claim id: ${id}.`)
  }

  const validationDocPath = resolve(root, 'CLAIM_VALIDATION.md')
  check(
    existsSync(validationDocPath),
    'CLAIM_VALIDATION.md must document the claim validation contract.',
  )
  if (existsSync(validationDocPath)) {
    const validationDoc = read('CLAIM_VALIDATION.md')
    check(
      validationDoc.includes('pnpm -F acgi-ai run test:claim-matrix'),
      'CLAIM_VALIDATION.md must include the local claim-matrix verification command.',
    )
    check(
      validationDoc.includes('engineering_draft_pending_legal'),
      'CLAIM_VALIDATION.md must document the engineering-draft legal status.',
    )
    for (const id of requiredIds) {
      check(validationDoc.includes(id), `CLAIM_VALIDATION.md must document claim id: ${id}.`)
    }
  }
}

check(
  packageJson.scripts?.['test:claim-matrix'] === 'node scripts/check-claim-matrix.mjs',
  'package.json must expose test:claim-matrix.',
)
check(
  typeof packageJson.scripts?.['test:all'] === 'string' &&
    packageJson.scripts['test:all'].includes('pnpm run test:claim-matrix'),
  'package.json test:all must include test:claim-matrix.',
)

if (failures.length > 0) {
  console.error('Claim matrix check failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exit(1)
}

console.log('Claim matrix check passed.')
