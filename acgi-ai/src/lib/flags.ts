export interface RuntimeFlags {
  useMocks: boolean
  apiProxyTarget: string | null
  evalMode: boolean
  logLevel: 'debug' | 'info' | 'warn' | 'error'
  refreshDisabled: boolean
  fixtureFallbackVisible: boolean
  privilegeBannerAudit: boolean
  isProduction: boolean
  isDevelopment: boolean
}

type RuntimeEnv = ImportMetaEnv & {
  readonly PROD?: boolean
  readonly DEV?: boolean
}

function readBooleanFlag(value: string | undefined): boolean {
  return value === 'true'
}

function readLogLevel(value: string | undefined): RuntimeFlags['logLevel'] {
  if (value === 'debug' || value === 'info' || value === 'warn' || value === 'error') {
    return value
  }
  return 'info'
}

export function getRuntimeFlags(env: RuntimeEnv = import.meta.env): RuntimeFlags {
  return {
    useMocks: readBooleanFlag(env.VITE_USE_MOCKS),
    apiProxyTarget: env.VITE_API_PROXY_TARGET?.trim() || null,
    evalMode: readBooleanFlag(env.VITE_EVAL_MODE),
    logLevel: readLogLevel(env.VITE_LOG_LEVEL),
    refreshDisabled: readBooleanFlag(env.VITE_DISABLE_REFRESH_INTERVAL),
    fixtureFallbackVisible: readBooleanFlag(env.VITE_FIXTURE_FALLBACK_VISIBLE),
    privilegeBannerAudit: readBooleanFlag(env.VITE_PRIVILEGE_BANNER_AUDIT),
    isProduction: import.meta.env.PROD,
    isDevelopment: import.meta.env.DEV,
  }
}

export const runtimeFlags = getRuntimeFlags()

export function isEvalMode(flags: RuntimeFlags = runtimeFlags): boolean {
  return flags.evalMode
}

export function isRefreshDisabled(flags: RuntimeFlags = runtimeFlags): boolean {
  return flags.refreshDisabled || flags.evalMode
}

let deterministicCounter = 0

export function makeDeterministicId(scope: string, flags: RuntimeFlags = runtimeFlags): string {
  const safeScope = scope.replace(/[^a-z0-9-]/gi, '-').toLowerCase()
  if (isEvalMode(flags)) {
    deterministicCounter += 1
    return `${safeScope}-eval-${deterministicCounter.toString().padStart(4, '0')}`
  }
  if (globalThis.crypto?.randomUUID) {
    return `${safeScope}-${globalThis.crypto.randomUUID()}`
  }
  return `${safeScope}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`
}
