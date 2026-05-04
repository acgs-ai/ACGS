import { useQuery } from '@tanstack/react-query'
import { api } from './client'

const LIVE = { staleTime: 5_000, refetchInterval: 10_000 }
const SLOW = { staleTime: 30_000, refetchInterval: 60_000 }

export function useAgents() {
  return useQuery({ queryKey: ['agents'], queryFn: api.agents.list, ...LIVE })
}

export function useOverview() {
  return useQuery({ queryKey: ['overview'], queryFn: api.overview.get, ...LIVE })
}

export function useMaci() {
  return useQuery({ queryKey: ['maci'], queryFn: api.maci.get, ...LIVE })
}

export function useDeliberations() {
  return useQuery({ queryKey: ['deliberations'], queryFn: api.deliberations.list, ...LIVE })
}

export function useIncidents() {
  return useQuery({ queryKey: ['incidents'], queryFn: api.incidents.list, ...LIVE })
}

export function usePolicies() {
  return useQuery({ queryKey: ['policies'], queryFn: api.policies.list, ...SLOW })
}

export function useCompileDraft() {
  return useQuery({ queryKey: ['compile-draft'], queryFn: api.compile.draft, ...SLOW })
}

export function useAudit() {
  return useQuery({ queryKey: ['audit'], queryFn: api.audit.list, ...LIVE })
}

export function useSettings() {
  return useQuery({ queryKey: ['settings'], queryFn: api.settings.get, ...SLOW })
}

export function useTenants() {
  return useQuery({ queryKey: ['tenants'], queryFn: api.tenants.list, ...SLOW })
}

export function useAccount() {
  return useQuery({ queryKey: ['account'], queryFn: api.account.get, ...SLOW })
}
