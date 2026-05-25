// Fixture traces for the agent-bus-analyzer console view.
//
// Activated when VITE_USE_MOCKS=true. The shapes match
// packages/agent-bus-analyzer/contracts/trace-query.schema.json. These
// fixtures are not cryptographically valid — the event_hash / prev_hash
// values are illustrative and would not pass the analyzer's chain
// verifier. Production must never serve this module.

import type {
  BusDecisionVerdict,
  BusReceiptProof,
  BusSingleTrace,
  BusTraceEvent,
  BusTraceList,
  BusTraceListItem,
  DecisionOutcome,
  GovernedAction,
} from '../../api/types'
import { GOVERNED_ACTIONS, getGovernedActionProof } from './actions'

const CONST_HASH = '608508a9bd224290'
const HASH_SUFFIX = '0'.repeat(62)
const PHOENIX_TRACE_ID = '4bf92f3577b34da6a3ce929d0e0e4736'
const PHOENIX_SPAN_ID = '53995c3f42cd8ad8'
const PHOENIX_PARENT_SPAN_ID = '00f067aa0ba902b7'

function mkEvent(
  overrides: Partial<BusTraceEvent> &
    Pick<BusTraceEvent, 'event_id' | 'correlation_id' | 'causal_index' | 'kind'>,
): BusTraceEvent {
  return {
    recorded_at: '2026-05-14T13:51:09.000Z',
    source_agent: 'claude:worker-03',
    target_handler_declared: null,
    target_handler_resolved: null,
    payload_ref: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    decision: null,
    flagged_rule: null,
    audit_receipt_hash: null,
    constitutional_hash: CONST_HASH,
    event_hash: '0'.repeat(64),
    prev_hash: null,
    status: 'completed',
    gap_started_at: null,
    gap_ended_at: null,
    phoenix_trace_id: null,
    phoenix_span_id: null,
    phoenix_parent_span_id: null,
    ...overrides,
  }
}

const TRACE_A_ID = '11111111-1111-7111-8111-111111111111'
const TRACE_B_ID = '22222222-2222-7222-8222-222222222222'
const TRACE_C_ID = '33333333-3333-7333-8333-333333333333'

const TRACE_A_EVENTS: BusTraceEvent[] = [
  mkEvent({
    event_id: 'aaaaaaa1-0000-7000-8000-000000000001',
    correlation_id: TRACE_A_ID,
    causal_index: 0,
    kind: 'dispatch',
    source_agent: 'claude:worker-03',
    target_handler_declared: 'analyst.policy_check',
    payload_ref: 'sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    recorded_at: '2026-05-14T13:51:09.011Z',
    event_hash: `a1${HASH_SUFFIX}`,
    status: 'completed',
  }),
  mkEvent({
    event_id: 'aaaaaaa1-0000-7000-8000-000000000002',
    correlation_id: TRACE_A_ID,
    causal_index: 1,
    kind: 'response',
    source_agent: 'gove-zone:kernel',
    target_handler_declared: 'analyst.policy_check',
    target_handler_resolved: 'analyst.policy_check',
    payload_ref: 'sha256:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3',
    recorded_at: '2026-05-14T13:51:09.042Z',
    event_hash: `a2${HASH_SUFFIX}`,
    prev_hash: `a1${HASH_SUFFIX}`,
    status: 'completed',
  }),
  mkEvent({
    event_id: 'aaaaaaa1-0000-7000-8000-000000000003',
    correlation_id: TRACE_A_ID,
    causal_index: 2,
    kind: 'decision',
    source_agent: 'gove-zone:kernel',
    target_handler_resolved: 'analyst.policy_check',
    payload_ref: 'sha256:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4',
    recorded_at: '2026-05-14T13:51:09.064Z',
    event_hash: `a3${HASH_SUFFIX}`,
    prev_hash: `a2${HASH_SUFFIX}`,
    decision: 'allow',
    audit_receipt_hash: 'sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
    status: 'completed',
  }),
]

const TRACE_B_EVENTS: BusTraceEvent[] = [
  mkEvent({
    event_id: 'bbbbbbb2-0000-7000-8000-000000000001',
    correlation_id: TRACE_B_ID,
    causal_index: 0,
    kind: 'dispatch',
    source_agent: 'codex:worker-01',
    target_handler_declared: 'matter.fetch',
    payload_ref: 'sha256:d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5',
    recorded_at: '2026-05-14T14:08:22.011Z',
    event_hash: `b1${HASH_SUFFIX}`,
    status: 'completed',
  }),
  mkEvent({
    event_id: 'bbbbbbb2-0000-7000-8000-000000000002',
    correlation_id: TRACE_B_ID,
    causal_index: 1,
    kind: 'decision',
    source_agent: 'gove-zone:kernel',
    target_handler_resolved: 'matter.fetch',
    payload_ref: 'sha256:e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6',
    recorded_at: '2026-05-14T14:08:22.038Z',
    event_hash: `b2${HASH_SUFFIX}`,
    prev_hash: `b1${HASH_SUFFIX}`,
    decision: 'deny',
    flagged_rule: 'hipaa.164.502.b',
    audit_receipt_hash: 'sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff',
    status: 'policy-violation',
  }),
]

const TRACE_C_EVENTS: BusTraceEvent[] = [
  mkEvent({
    event_id: 'ccccccc3-0000-7000-8000-000000000001',
    correlation_id: TRACE_C_ID,
    causal_index: 0,
    kind: 'dispatch',
    source_agent: 'gemini:worker-02',
    target_handler_declared: 'reasoner.evaluate',
    payload_ref: 'sha256:f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7',
    recorded_at: '2026-05-14T13:32:41.011Z',
    event_hash: `c1${HASH_SUFFIX}`,
    status: 'unwired-handler',
  }),
]

const TRACE_LIST_ITEMS: BusTraceListItem[] = [
  {
    correlation_id: TRACE_A_ID,
    started_at: '2026-05-14T13:51:09.000Z',
    completed_at: '2026-05-14T13:51:09.064Z',
    event_count: TRACE_A_EVENTS.length,
    worst_event_status: 'completed',
    integrity_status: 'intact',
    constitutional_hash: CONST_HASH,
  },
  {
    correlation_id: TRACE_B_ID,
    started_at: '2026-05-14T14:08:22.000Z',
    completed_at: '2026-05-14T14:08:22.038Z',
    event_count: TRACE_B_EVENTS.length,
    worst_event_status: 'policy-violation',
    integrity_status: 'intact',
    constitutional_hash: CONST_HASH,
  },
  {
    correlation_id: TRACE_C_ID,
    started_at: '2026-05-14T13:32:41.000Z',
    completed_at: null,
    event_count: TRACE_C_EVENTS.length,
    worst_event_status: 'unwired-handler',
    integrity_status: 'intact',
    constitutional_hash: CONST_HASH,
  },
]

export const BUS_TRACE_LIST: BusTraceList = {
  kind: 'trace-list',
  items: TRACE_LIST_ITEMS,
  next_cursor: null,
}

const SINGLE_TRACE_BY_ID: Record<string, BusSingleTrace> = {
  [TRACE_A_ID]: {
    kind: 'single-trace',
    trace: TRACE_LIST_ITEMS[0],
    events: TRACE_A_EVENTS,
    integrity_status: 'intact',
    rotation_at_index: null,
  },
  [TRACE_B_ID]: {
    kind: 'single-trace',
    trace: TRACE_LIST_ITEMS[1],
    events: TRACE_B_EVENTS,
    integrity_status: 'intact',
    rotation_at_index: null,
  },
  [TRACE_C_ID]: {
    kind: 'single-trace',
    trace: TRACE_LIST_ITEMS[2],
    events: TRACE_C_EVENTS,
    integrity_status: 'intact',
    rotation_at_index: null,
  },
}

export function getSingleTraceFixture(correlationId: string): BusSingleTrace | null {
  return SINGLE_TRACE_BY_ID[correlationId] ?? null
}

function busDecision(outcome: DecisionOutcome): BusDecisionVerdict {
  switch (outcome) {
    case 'allowed':
      return 'allow'
    case 'denied':
      return 'deny'
    case 'transformed':
      return 'transform'
    case 'escalated':
      return 'escalate'
  }
}

function receiptEventHash(action: GovernedAction, index: number): string {
  const suffix = action.receiptHash
    .replace(/^sha256:/, '')
    .padEnd(64, String(index))
    .slice(0, 64)
  return suffix
}

function receiptEvents(action: GovernedAction): BusTraceEvent[] {
  const dispatchHash = receiptEventHash(action, 0)
  const decisionHash = receiptEventHash(action, 1)
  const decision = busDecision(action.outcome)
  return [
    mkEvent({
      event_id: `${action.id}-dispatch`,
      correlation_id: action.traceId,
      causal_index: 0,
      kind: 'dispatch',
      source_agent: action.agent,
      target_handler_declared: action.action,
      payload_ref: `sha256:${action.before}`,
      recorded_at: '2026-05-14T14:08:22.011Z',
      event_hash: dispatchHash,
      phoenix_trace_id: PHOENIX_TRACE_ID,
      phoenix_span_id: '1111111111111111',
      phoenix_parent_span_id: PHOENIX_PARENT_SPAN_ID,
      status: 'completed',
    }),
    mkEvent({
      event_id: action.receiptId,
      correlation_id: action.traceId,
      causal_index: 1,
      kind: 'decision',
      source_agent: 'gove-zone:kernel',
      target_handler_declared: action.action,
      target_handler_resolved: action.action,
      payload_ref: `sha256:${action.after}`,
      recorded_at: '2026-05-14T14:08:22.038Z',
      event_hash: decisionHash,
      prev_hash: dispatchHash,
      decision,
      flagged_rule: action.checks[0]?.id ?? null,
      audit_receipt_hash: action.receiptHash,
      phoenix_trace_id: PHOENIX_TRACE_ID,
      phoenix_span_id: PHOENIX_SPAN_ID,
      phoenix_parent_span_id: PHOENIX_PARENT_SPAN_ID,
      status: action.outcome === 'denied' ? 'policy-violation' : 'completed',
    }),
  ]
}

function receiptProofFixture(action: GovernedAction): BusReceiptProof {
  const events = receiptEvents(action)
  const proof = getGovernedActionProof(action.receiptId)
  return {
    kind: 'receipt-proof',
    receipt_id: action.receiptId,
    receipt_hash: action.receiptHash,
    correlation_id: action.traceId,
    trace: {
      correlation_id: action.traceId,
      started_at: events[0].recorded_at,
      completed_at: events[events.length - 1]?.recorded_at ?? events[0].recorded_at,
      event_count: events.length,
      worst_event_status: action.outcome === 'denied' ? 'policy-violation' : 'completed',
      integrity_status: 'intact',
      constitutional_hash: CONST_HASH,
      phoenix_trace_id: PHOENIX_TRACE_ID,
      phoenix_span_id: '1111111111111111',
      phoenix_parent_span_id: PHOENIX_PARENT_SPAN_ID,
    },
    events,
    integrity_status: 'intact',
    hash_chain_verified: true,
    policy_path: [action.action, ...action.checks.map((check) => check.id)],
    decision: busDecision(action.outcome),
    flagged_rules: action.checks.map((check) => check.id),
    signed_evidence_packet: proof?.signedEvidencePacket ?? '{}',
    phoenix_trace_id: PHOENIX_TRACE_ID,
    phoenix_span_id: '1111111111111111',
    phoenix_parent_span_id: PHOENIX_PARENT_SPAN_ID,
  }
}

const RECEIPT_PROOF_BY_ID: Record<string, BusReceiptProof> = Object.fromEntries(
  GOVERNED_ACTIONS.map((action) => [action.receiptId, receiptProofFixture(action)]),
)

export function getReceiptProofFixture(receiptId: string): BusReceiptProof | null {
  return RECEIPT_PROOF_BY_ID[receiptId] ?? null
}
