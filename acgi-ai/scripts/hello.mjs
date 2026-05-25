import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

const root = resolve(import.meta.dirname, '..')
const required = [
  'ARCHITECTURE.md',
  'INTEGRATING.md',
  'GETTING_STARTED.md',
  'DEPLOY.md',
  'DESIGN.md',
  'claim-matrix.json',
]

const missing = required.filter((path) => !existsSync(resolve(root, path)))

console.log('ACGI DX hello')
console.log(`node=${process.version}`)
console.log('required-docs=' + (missing.length === 0 ? 'present' : `missing:${missing.join(',')}`))
console.log('next=pnpm -F acgi-ai run test:all && pnpm -F acgi-ai build')

if (missing.length > 0) {
  process.exit(1)
}
