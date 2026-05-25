import { isEvalMode } from '../lib/flags'

export type MswUnhandledRequestPolicy = 'bypass' | 'warn' | 'error'

export function getMswUnhandledRequestPolicy(): MswUnhandledRequestPolicy {
  if (isEvalMode()) {
    return 'error'
  }
  return 'bypass'
}
