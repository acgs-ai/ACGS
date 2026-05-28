import { makeDeterministicId } from './flags'

export type AppErrorKind =
  | 'Auth'
  | 'Network'
  | 'Parse'
  | 'RetryExhausted'
  | 'CSP'
  | 'Permission'
  | 'RateLimit'

export interface AppErrorDetails {
  title: string
  cause: string
  fix: string
  status?: number
}

export const APP_ERROR_DETAILS: Record<AppErrorKind, AppErrorDetails> = {
  Auth: {
    title: 'Authentication required',
    cause: 'The console session is missing, expired, or not accepted by the privileged origin.',
    fix: 'Sign in again through the console origin. In production this must be backed by OIDC or a server-issued HttpOnly cookie.',
    status: 401,
  },
  Network: {
    title: 'Governance bus unavailable',
    cause: 'The same-origin API request could not reach the governed bus boundary.',
    fix: 'Check BUS_UPSTREAM, retry when connectivity is restored, and keep fixture fallback limited to explicit non-production mock mode.',
  },
  Parse: {
    title: 'Unexpected response shape',
    cause: 'The API response could not be parsed into the frontend contract.',
    fix: 'Compare the response with INTEGRATING.md and the generated API types before retrying.',
  },
  RetryExhausted: {
    title: 'Retry budget exhausted',
    cause: 'The request remained unhealthy after the configured retry window.',
    fix: 'Pause mutations, inspect the trace ID, and wait for the bus health indicator to recover.',
  },
  CSP: {
    title: 'Content security policy blocked execution',
    cause:
      'The privileged console attempted to load or execute a resource outside the strict CSP boundary.',
    fix: 'Remove inline or third-party resources and rerun the CSP harness before deploying.',
  },
  Permission: {
    title: 'Permission denied',
    cause: 'The current operator is not authorized to perform this governed action.',
    fix: 'Request the required role grant or choose an action allowed by the active policy snapshot.',
    status: 403,
  },
  RateLimit: {
    title: 'Rate limit reached',
    cause: 'The governed bus is throttling requests for this tenant or operator.',
    fix: 'Wait for the retry window, reduce polling pressure, or escalate if the limit is unexpected.',
    status: 429,
  },
}

export interface AppErrorOptions {
  cause?: string
  fix?: string
  message?: string
  status?: number
  traceId?: string
}

export class AppError extends Error {
  readonly kind: AppErrorKind
  readonly title: string
  readonly cause: string
  readonly fix: string
  readonly status?: number
  readonly traceId: string

  constructor(kind: AppErrorKind, options: AppErrorOptions = {}) {
    const details = APP_ERROR_DETAILS[kind]
    const cause = options.cause ?? details.cause
    super(options.message ?? details.title, { cause })
    this.name = 'AppError'
    this.kind = kind
    this.title = details.title
    this.cause = cause
    this.fix = options.fix ?? details.fix
    this.status = options.status ?? details.status
    this.traceId = options.traceId ?? makeDeterministicId('app-error')
  }

  toJSON() {
    return {
      kind: this.kind,
      title: this.title,
      cause: this.cause,
      fix: this.fix,
      status: this.status,
      traceId: this.traceId,
      message: this.message,
    }
  }
}

export function toAppError(error: unknown, fallbackKind: AppErrorKind = 'Network'): AppError {
  if (error instanceof AppError) return error
  if (error instanceof Error) {
    return new AppError(fallbackKind, {
      cause: error.message,
      message: APP_ERROR_DETAILS[fallbackKind].title,
    })
  }
  return new AppError(fallbackKind, {
    cause: typeof error === 'string' ? error : APP_ERROR_DETAILS[fallbackKind].cause,
    message: APP_ERROR_DETAILS[fallbackKind].title,
  })
}
