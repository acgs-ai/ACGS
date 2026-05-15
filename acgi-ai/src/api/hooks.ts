import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, api } from './client'

const LIVE = { staleTime: 5_000, refetchInterval: 10_000 }
const SLOW = { staleTime: 30_000, refetchInterval: 60_000 }
// Single-trace inspector: trace is effectively immutable for a reader's
// session (append-only, but the user clicks away to refresh the list view).
// No polling — keep just enough staleness to dedupe re-mounts.
const SNAPSHOT = { staleTime: 5_000 }

function canUseFixtureFallback(): boolean {
  if (import.meta.env.PROD) {
    return false
  }
  return import.meta.env.VITE_USE_MOCKS === 'true'
}

async function withFixtureFallback<T>(
  request: () => Promise<T>,
  fallback: () => Promise<T>,
): Promise<T> {
  try {
    return await request()
  } catch (error) {
    if (error instanceof ApiError || !canUseFixtureFallback()) {
      throw error
    }
    console.warn('ACGS API unavailable; rendering fixture-backed console data.', error)
    return fallback()
  }
}

export function useAgents() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.agents.list, () =>
            import('../mocks/data/agents').then((m) => m.AGENTS),
          )
      : api.agents.list,
    ...LIVE,
  })
}

export function useConsoleSummary() {
  return useQuery({
    queryKey: ['console-summary'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.consoleSummary.get, () =>
            import('../mocks/data/console-summary').then((m) => m.CONSOLE_SUMMARY),
          )
      : api.consoleSummary.get,
    ...LIVE,
  })
}

export function useGovernedActions() {
  return useQuery({
    queryKey: ['governed-actions'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.actions.list, () =>
            import('../mocks/data/actions').then((m) => m.GOVERNED_ACTIONS),
          )
      : api.actions.list,
    ...LIVE,
  })
}

export function useTestAction() {
  return useMutation({
    mutationFn: api.actions.test,
  })
}

export function useOverview() {
  return useQuery({
    queryKey: ['overview'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.overview.get, () =>
            import('../mocks/data/overview').then((m) => m.OVERVIEW_SUMMARY),
          )
      : api.overview.get,
    ...LIVE,
  })
}

export function useMaci() {
  return useQuery({
    queryKey: ['maci'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.maci.get, () =>
            import('../mocks/data/maci').then((m) => m.MACI_LANES),
          )
      : api.maci.get,
    ...LIVE,
  })
}

export function useDeliberations() {
  return useQuery({
    queryKey: ['deliberations'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.deliberations.list, () =>
            import('../mocks/data/deliberations').then((m) => m.DELIBERATIONS),
          )
      : api.deliberations.list,
    ...LIVE,
  })
}

export function useIncidents() {
  return useQuery({
    queryKey: ['incidents'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.incidents.list, () =>
            import('../mocks/data/incidents').then((m) => m.INCIDENTS),
          )
      : api.incidents.list,
    ...LIVE,
  })
}

export function usePolicies() {
  return useQuery({
    queryKey: ['policies'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.policies.list, () =>
            import('../mocks/data/policies').then((m) => m.POLICIES),
          )
      : api.policies.list,
    ...SLOW,
  })
}

export function useCompileDraft() {
  return useQuery({
    queryKey: ['compile-draft'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.compile.draft, () =>
            import('../mocks/data/compile').then((m) => m.COMPILE_DRAFT),
          )
      : api.compile.draft,
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
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.audit.list, () =>
            import('../mocks/data/audit').then((m) => m.AUDIT_EVENTS),
          )
      : api.audit.list,
    ...LIVE,
  })
}

export function useSettings() {
  return useQuery({
    queryKey: ['settings'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.settings.get, () =>
            import('../mocks/data/settings').then((m) => m.SETTING_SECTIONS),
          )
      : api.settings.get,
    ...SLOW,
  })
}

export function useTenants() {
  return useQuery({
    queryKey: ['tenants'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.tenants.list, () =>
            import('../mocks/data/tenants').then((m) => m.TENANTS),
          )
      : api.tenants.list,
    ...SLOW,
  })
}

export function useAccount() {
  return useQuery({
    queryKey: ['account'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(api.account.get, () =>
            import('../mocks/data/account').then((m) => m.ACCOUNT_VIEW),
          )
      : api.account.get,
    ...SLOW,
  })
}

export function useBusTraceList() {
  return useQuery({
    queryKey: ['bus-traces'],
    queryFn: import.meta.env.DEV
      ? () =>
          withFixtureFallback(
            () => api.bus.listTraces(),
            () => import('../mocks/data/bus-analysis').then((m) => m.BUS_TRACE_LIST),
          )
      : () => api.bus.listTraces(),
    ...LIVE,
  })
}

export function useSingleTrace(correlationId: string | null) {
  return useQuery({
    queryKey: ['bus-trace', correlationId],
    enabled: correlationId !== null,
    queryFn: () => {
      const id = correlationId as string
      const live = () => api.bus.getTrace(id)
      const fallback = () =>
        import('../mocks/data/bus-analysis').then((m) => {
          const found = m.getSingleTraceFixture(id)
          if (found) return found
          throw new ApiError(404, `/api/bus/traces/${id}`, 'trace not in fixture set')
        })
      return import.meta.env.DEV ? withFixtureFallback(live, fallback) : live()
    },
    ...SNAPSHOT,
  })
}
