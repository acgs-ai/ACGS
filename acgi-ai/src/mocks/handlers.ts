// MOCK-ONLY MODULE — never import from production code paths.
// This module is only activated when VITE_USE_MOCKS=true (see src/main.tsx).
// The compile/promote and compile/replay handlers return fixture attestations
// that have NO cryptographic validity. Shipping them in production would
// allow unauthenticated constitution promotions via the mock bus.
if (import.meta.env.VITE_USE_MOCKS !== 'true') {
  throw new Error(
    '[acgi-ai] src/mocks/handlers.ts was loaded outside of mock mode. ' +
      'Set VITE_USE_MOCKS=true or remove this import from the production bundle.',
  )
}

import { HttpResponse, http } from 'msw'
import { ACCOUNT_VIEW } from './data/account'
import { AGENTS } from './data/agents'
import { AUDIT_EVENTS } from './data/audit'
import { COMPILE_DRAFT } from './data/compile'
import { CONSOLE_SUMMARY } from './data/console-summary'
import { DELIBERATIONS } from './data/deliberations'
import { INCIDENTS } from './data/incidents'
import { MACI_LANES } from './data/maci'
import { OVERVIEW_SUMMARY } from './data/overview'
import { POLICIES } from './data/policies'
import { SETTING_SECTIONS } from './data/settings'
import { TENANTS } from './data/tenants'

export const handlers = [
  http.get('/api/v1/console-summary', () => HttpResponse.json(CONSOLE_SUMMARY)),
  http.get('/api/v1/agents', () => HttpResponse.json(AGENTS)),
  http.get('/api/v1/overview', () => HttpResponse.json(OVERVIEW_SUMMARY)),
  http.get('/api/v1/maci', () => HttpResponse.json(MACI_LANES)),
  http.get('/api/v1/deliberations', () => HttpResponse.json(DELIBERATIONS)),
  http.get('/api/v1/incidents', () => HttpResponse.json(INCIDENTS)),
  http.get('/api/v1/policies', () => HttpResponse.json(POLICIES)),
  http.get('/api/v1/compile/draft', () => HttpResponse.json(COMPILE_DRAFT)),
  http.post('/api/v1/compile/replay', () =>
    HttpResponse.json({
      title: 'Validator replay attested',
      body: `${COMPILE_DRAFT.changes.length} proposed changes replayed against the conformance set; Validator attestation is fixture-backed.`,
      meta: `${COMPILE_DRAFT.proposedHash} · ${COMPILE_DRAFT.currentHash} · ${new Date().toISOString()}`,
    }),
  ),
  http.post('/api/v1/compile/promote', () =>
    HttpResponse.json({
      title: 'Promotion attested by mock bus',
      body: 'The fixture bus accepted the proposed constitution promotion and returned an auditable receipt.',
      meta: `${COMPILE_DRAFT.proposedHash} · two reviewers + one custodian · ${new Date().toISOString()}`,
    }),
  ),
  http.get('/api/v1/audit', () => HttpResponse.json(AUDIT_EVENTS)),
  http.get('/api/v1/settings', () => HttpResponse.json(SETTING_SECTIONS)),
  http.get('/api/v1/tenants', () => HttpResponse.json(TENANTS)),
  http.get('/api/v1/account', () => HttpResponse.json(ACCOUNT_VIEW)),
]
