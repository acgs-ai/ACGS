// Single fetch wrapper for the ACGS console.
//
// Path strategy: every call is relative — `/api/v1/<resource>`. In dev,
// Vite either intercepts via MSW (when VITE_USE_MOCKS=true) or proxies to
// VITE_API_PROXY_TARGET (see vite.config.ts). In prod, Caddy on
// console.acgs.ai reverse-proxies the same prefix to the API gateway.
// The browser never sees an absolute API origin — that keeps the privilege
// boundary visible at the network layer (DEPLOY.md §3, §7).

import type {
  AccountView,
  Agent,
  AuditEvent,
  CompileDraft,
  Deliberation,
  Incident,
  MaciLanes,
  OverviewSummary,
  PolicyRule,
  SettingSection,
  Tenant,
} from './types'

const PREFIX = '/api/v1'

export class ApiError extends Error {
  status: number
  url: string

  constructor(status: number, url: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.url = url
  }
}

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${PREFIX}${path}`
  const res = await fetch(url, {
    ...init,
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...init?.headers,
    },
    credentials: 'same-origin',
  })
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new ApiError(res.status, url, body || res.statusText)
  }
  return res.json() as Promise<T>
}

export const api = {
  agents: {
    list: () => http<Agent[]>('/agents'),
  },
  overview: {
    get: () => http<OverviewSummary>('/overview'),
  },
  maci: {
    get: () => http<MaciLanes>('/maci'),
  },
  deliberations: {
    list: () => http<Deliberation[]>('/deliberations'),
  },
  incidents: {
    list: () => http<Incident[]>('/incidents'),
  },
  policies: {
    list: () => http<PolicyRule[]>('/policies'),
  },
  compile: {
    draft: () => http<CompileDraft>('/compile/draft'),
  },
  audit: {
    list: () => http<AuditEvent[]>('/audit'),
  },
  settings: {
    get: () => http<SettingSection[]>('/settings'),
  },
  tenants: {
    list: () => http<Tenant[]>('/tenants'),
  },
  account: {
    get: () => http<AccountView>('/account'),
  },
}
