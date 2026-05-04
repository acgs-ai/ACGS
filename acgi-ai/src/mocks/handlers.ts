import { HttpResponse, http } from 'msw'
import { ACCOUNT_VIEW } from './data/account'
import { AGENTS } from './data/agents'
import { AUDIT_EVENTS } from './data/audit'
import { COMPILE_DRAFT } from './data/compile'
import { DELIBERATIONS } from './data/deliberations'
import { INCIDENTS } from './data/incidents'
import { MACI_LANES } from './data/maci'
import { OVERVIEW_SUMMARY } from './data/overview'
import { POLICIES } from './data/policies'
import { SETTING_SECTIONS } from './data/settings'
import { TENANTS } from './data/tenants'

export const handlers = [
  http.get('/api/v1/agents', () => HttpResponse.json(AGENTS)),
  http.get('/api/v1/overview', () => HttpResponse.json(OVERVIEW_SUMMARY)),
  http.get('/api/v1/maci', () => HttpResponse.json(MACI_LANES)),
  http.get('/api/v1/deliberations', () => HttpResponse.json(DELIBERATIONS)),
  http.get('/api/v1/incidents', () => HttpResponse.json(INCIDENTS)),
  http.get('/api/v1/policies', () => HttpResponse.json(POLICIES)),
  http.get('/api/v1/compile/draft', () => HttpResponse.json(COMPILE_DRAFT)),
  http.get('/api/v1/audit', () => HttpResponse.json(AUDIT_EVENTS)),
  http.get('/api/v1/settings', () => HttpResponse.json(SETTING_SECTIONS)),
  http.get('/api/v1/tenants', () => HttpResponse.json(TENANTS)),
  http.get('/api/v1/account', () => HttpResponse.json(ACCOUNT_VIEW)),
]
