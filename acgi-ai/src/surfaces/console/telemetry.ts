/**
 * Console telemetry emitter — first-party, server-relayed, allowlist-only.
 *
 * Contract: docs/POSTHOG_CONSOLE_TELEMETRY_DESIGN.md (§3 emitter, §4 schema).
 * No third-party SDK; the only sink is the same-origin `/api/telemetry`
 * endpoint (DEPLOY.md §4, amended 2026-08-14). Fire-and-forget and lossy by
 * design: telemetry must never block or degrade the console, and it is NOT
 * audit — nothing here may feed governance evidence.
 *
 * Gated by build-time `VITE_CONSOLE_TELEMETRY`. The guarantee when the flag
 * is off is behavioral — zero telemetry network calls — not bundle absence.
 */

// The typed event map IS the client-side allowlist: `track` only accepts
// these names with exactly these property shapes. There is no arbitrary
// props overload — do not add one (design §4 payload hygiene).
export type TelemetryEventMap = {
  console_section_navigated: { route_template: string }
  console_signed_out: undefined
  login_provider_selected: { provider_id: string }
  magic_link_requested: undefined
  action_policy_test_run: undefined
  constitution_replay_started: undefined
  constitution_promoted: undefined
  constitution_compile_discarded: undefined
  deliberation_action_taken: { action_kind: 'approved' | 'held' | 'refused' }
  policy_rule_selected: { rule_position: number }
}

type QueuedEvent = {
  event: keyof TelemetryEventMap
  properties: Record<string, string | number>
  emitted_at: string
}

/**
 * Console sections whose `$section` param may resolve into `route_template`.
 * A closed set mirroring the sidebar navigation — `$section` is an enum
 * here, not user input. Anything outside this list stays a literal template.
 */
export const CONSOLE_SECTIONS = [
  'workbench',
  'agents',
  'actions',
  'maci',
  'deliberations',
  'incidents',
  'policies',
  'compile',
  'audit',
  'bus',
  'process',
  'settings',
  'tenants',
] as const

/**
 * Route-param resolution table (design §4). Default-deny: a path that does
 * not match an explicitly allowlisted shape reports the literal route
 * template. `$receiptId` NEVER resolves — a receipt id is governance
 * evidence content and must not reach a third party.
 */
export function routeTemplateFor(path: string): string {
  if (path === '/console') return '/console'
  if (path === '/login') return '/login'
  if (path.startsWith('/console/audit/')) return '/console/audit/$receiptId'
  const section = path.match(/^\/console\/([^/]+)$/)?.[1]
  if (section && (CONSOLE_SECTIONS as readonly string[]).includes(section)) {
    return `/console/${section}`
  }
  if (section) return '/console/$section'
  return '$'
}

const ENABLED = import.meta.env.VITE_CONSOLE_TELEMETRY === '1'
const ENDPOINT = '/api/telemetry'
const MAX_BATCH = 20
const FLUSH_BASE_MS = 15_000
const FLUSH_JITTER_MS = 5_000

const queue: QueuedEvent[] = []
let flushTimer: ReturnType<typeof setTimeout> | undefined

function transmit(body: string): void {
  try {
    const beacon = navigator.sendBeacon?.(ENDPOINT, new Blob([body], { type: 'application/json' }))
    if (!beacon) {
      void fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        keepalive: true,
        body,
      }).catch(() => {
        // Lossy by design — a failed flush is dropped, never retried.
      })
    }
  } catch {
    // Same: telemetry failures must never surface into the console.
  }
}

function flush(): void {
  if (flushTimer !== undefined) {
    clearTimeout(flushTimer)
    flushTimer = undefined
  }
  if (queue.length === 0) return
  const events = queue.splice(0, queue.length)
  transmit(JSON.stringify({ schema: 'console-telemetry/1', events }))
}

function scheduleFlush(): void {
  if (flushTimer !== undefined) return
  flushTimer = setTimeout(flush, FLUSH_BASE_MS + Math.random() * FLUSH_JITTER_MS)
}

/**
 * Record one allowlisted event. No-op (zero network) unless the build was
 * made with `VITE_CONSOLE_TELEMETRY=1`. Never throws.
 */
export function track<E extends keyof TelemetryEventMap>(
  event: E,
  ...properties: TelemetryEventMap[E] extends undefined ? [] : [TelemetryEventMap[E]]
): void {
  if (!ENABLED) return
  try {
    queue.push({
      event,
      properties: (properties[0] ?? {}) as Record<string, string | number>,
      emitted_at: new Date().toISOString(),
    })
    if (queue.length >= MAX_BATCH) {
      flush()
      return
    }
    scheduleFlush()
  } catch {
    // Never let telemetry failures reach the console.
  }
}

if (ENABLED && typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') flush()
  })
}

/** Test-only: force a synchronous flush of the pending batch. */
export function __flushForTest(): void {
  flush()
}
