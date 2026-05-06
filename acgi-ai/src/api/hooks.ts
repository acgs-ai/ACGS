import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ACCOUNT_VIEW } from '../mocks/data/account'
import { AGENTS } from '../mocks/data/agents'
import { AUDIT_EVENTS } from '../mocks/data/audit'
import { COMPILE_DRAFT } from '../mocks/data/compile'
import { CONSOLE_SUMMARY } from '../mocks/data/console-summary'
import { DELIBERATIONS } from '../mocks/data/deliberations'
import { INCIDENTS } from '../mocks/data/incidents'
import { MACI_LANES } from '../mocks/data/maci'
import { OVERVIEW_SUMMARY } from '../mocks/data/overview'
import { POLICIES } from '../mocks/data/policies'
import { SETTING_SECTIONS } from '../mocks/data/settings'
import { TENANTS } from '../mocks/data/tenants'
import { api } from './client'

const LIVE = { staleTime: 5_000, refetchInterval: 10_000 }
const SLOW = { staleTime: 30_000, refetchInterval: 60_000 }

async function withFixtureFallback<T>(request: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await request()
  } catch (error) {
    console.warn('ACGS API unavailable; rendering fixture-backed console data.', error)
    return fallback
  }
}

export function useAgents() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: () => withFixtureFallback(api.agents.list, AGENTS),
    ...LIVE,
  })
}

export function useConsoleSummary() {
  return useQuery({
    queryKey: ['console-summary'],
    queryFn: () => withFixtureFallback(api.consoleSummary.get, CONSOLE_SUMMARY),
    ...LIVE,
  })
}

export function useOverview() {
  return useQuery({
    queryKey: ['overview'],
    queryFn: () => withFixtureFallback(api.overview.get, OVERVIEW_SUMMARY),
    ...LIVE,
  })
}

export function useMaci() {
  return useQuery({
    queryKey: ['maci'],
    queryFn: () => withFixtureFallback(api.maci.get, MACI_LANES),
    ...LIVE,
  })
}

export function useDeliberations() {
  return useQuery({
    queryKey: ['deliberations'],
    queryFn: () => withFixtureFallback(api.deliberations.list, DELIBERATIONS),
    ...LIVE,
  })
}

export function useIncidents() {
  return useQuery({
    queryKey: ['incidents'],
    queryFn: () => withFixtureFallback(api.incidents.list, INCIDENTS),
    ...LIVE,
  })
}

export function usePolicies() {
  return useQuery({
    queryKey: ['policies'],
    queryFn: () => withFixtureFallback(api.policies.list, POLICIES),
    ...SLOW,
  })
}

export function useCompileDraft() {
  return useQuery({
    queryKey: ['compile-draft'],
    queryFn: () => withFixtureFallback(api.compile.draft, COMPILE_DRAFT),
    ...SLOW,
  })
}

export function useReplayCompile() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.compile.replay,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['compile-draft'] })
      void queryClient.invalidateQueries({ queryKey: ['console-summary'] })
    },
  })
}

export function usePromoteCompile() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.compile.promote,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['compile-draft'] })
      void queryClient.invalidateQueries({ queryKey: ['console-summary'] })
    },
  })
}

export function useAudit() {
  return useQuery({
    queryKey: ['audit'],
    queryFn: () => withFixtureFallback(api.audit.list, AUDIT_EVENTS),
    ...LIVE,
  })
}

export function useSettings() {
  return useQuery({
    queryKey: ['settings'],
    queryFn: () => withFixtureFallback(api.settings.get, SETTING_SECTIONS),
    ...SLOW,
  })
}

export function useTenants() {
  return useQuery({
    queryKey: ['tenants'],
    queryFn: () => withFixtureFallback(api.tenants.list, TENANTS),
    ...SLOW,
  })
}

export function useAccount() {
  return useQuery({
    queryKey: ['account'],
    queryFn: () => withFixtureFallback(api.account.get, ACCOUNT_VIEW),
    ...SLOW,
  })
}
