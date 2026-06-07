/**
 * Same-origin bridge to the ACGS governance boundary.
 *
 * The copilot never performs a side-effectful action directly. Every governed
 * action first asks ACGS to admit it. Only an explicit ALLOW (with a Decision
 * Receipt) authorises execution; anything else — DENY, ESCALATE, a transport
 * error, or a malformed response — is treated as "do not execute".
 *
 * This mirrors the kernel invariant proven in `examples/copilotkit_governed/`:
 *   "No valid Decision Receipt, no side effect."
 *
 * CSP note: the request targets a same-origin path (`/api/governance/admit`),
 * which `connect-src 'self'` permits on both surfaces. The LLM provider and the
 * governance kernel live server-side; the browser only ever talks to its own
 * origin.
 *
 * Wiring status: the `/api/governance/admit` endpoint is delivered in Phase 2
 * (Python governance HTTP bridge). This client is framework-agnostic and is the
 * front-end half of the governed-tool path; it carries forward unchanged.
 */

export type GovernanceDecision = 'allow' | 'deny' | 'escalate'

export interface AdmissionResult {
  decision: GovernanceDecision
  /** Receipt audit hash, present only on ALLOW. */
  receiptAuditHash?: string
  /** Human-readable reason from the policy. */
  reason?: string
}

const ADMIT_ENDPOINT = '/api/governance/admit'

/**
 * Ask ACGS whether `actionName` with `args` may execute.
 *
 * Fail closed: any non-ALLOW decision, network failure, non-2xx status, or
 * unparseable body resolves to a DENY so callers never execute on uncertainty.
 */
export async function admitAction(
  actionName: string,
  args: Record<string, unknown>,
): Promise<AdmissionResult> {
  try {
    const response = await fetch(ADMIT_ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action: actionName, args }),
    })

    if (!response.ok) {
      return { decision: 'deny', reason: `governance bridge returned ${response.status}` }
    }

    const body = (await response.json()) as Partial<AdmissionResult>
    if (body.decision === 'allow' && typeof body.receiptAuditHash === 'string') {
      return { decision: 'allow', receiptAuditHash: body.receiptAuditHash, reason: body.reason }
    }
    if (body.decision === 'escalate') {
      return { decision: 'escalate', reason: body.reason }
    }
    return { decision: 'deny', reason: body.reason ?? 'no valid receipt' }
  } catch (error) {
    return {
      decision: 'deny',
      reason: error instanceof Error ? error.message : 'governance bridge unreachable',
    }
  }
}
