import type { GovernedAction } from '../../api/types'

export const GOVERNED_ACTIONS: readonly GovernedAction[] = [
  {
    id: 'act-9821-deny',
    agent: 'analyst-12',
    action: 'matter.fetch',
    target: 'Matter-9821/private-notes',
    attemptedAt: '2026-05-14 14:08:51 UTC',
    outcome: 'denied',
    plainReason:
      'The agent tried to fetch private matter notes while operating outside the custodial lane. The policy requires a matter-scoped role before private notes can be read.',
    receiptId: 'rcpt-608508a9-8b38',
    receiptHash: 'sha256:8b38f0a1c2',
    traceId: 'trace-matter-9821-t42',
    replayCommand: 'gove-zone replay --trace trace-matter-9821-t42 --receipt rcpt-608508a9-8b38',
    auditEventId: 'audit-8b38',
    before: '{"tool":"matter.fetch","matter_id":"Matter-9821","field":"private-notes"}',
    after: '{"status":"denied","citation":"§164.502(b)","tool_executed":false}',
    checks: [
      {
        id: 'P-1207',
        label: 'Matter disclosure boundary',
        posture: 'blocked',
        reason: 'Payload includes matter_id and agent role is not custodial.',
      },
      {
        id: 'P-1213',
        label: 'Tool scope intersection',
        posture: 'partial',
        reason: 'Agent scope covers public summary only; tool requires private matter scope.',
      },
      {
        id: 'AUD-CHAIN',
        label: 'Append-only audit receipt',
        posture: 'confirmed',
        reason: 'Denial receipt was written before the tool could execute.',
      },
    ],
  },
  {
    id: 'act-514-transform',
    agent: 'redactor-03',
    action: 'message.send',
    target: 'Patient update channel',
    attemptedAt: '2026-05-14 14:07:36 UTC',
    outcome: 'transformed',
    plainReason:
      'The outbound message was allowed only after the redactor removed direct identifiers and attached a safe-harbor attestation.',
    receiptId: 'rcpt-608508a9-8b37',
    receiptHash: 'sha256:8b37a9e4dd',
    traceId: 'trace-redact-514-t19',
    replayCommand: 'gove-zone replay --trace trace-redact-514-t19 --receipt rcpt-608508a9-8b37',
    auditEventId: 'audit-8b37',
    before: '{"message":"Patient Jane Doe, DOB 1972-04-18, is ready for discharge."}',
    after: '{"message":"The patient is ready for discharge.","redaction":"safe-harbor"}',
    checks: [
      {
        id: 'P-1212',
        label: 'PHI redaction',
        posture: 'privileged',
        reason: 'Direct identifiers were removed before delivery.',
      },
      {
        id: 'P-1214',
        label: 'Human route available',
        posture: 'confirmed',
        reason: 'The transformed message keeps escalation metadata attached.',
      },
    ],
  },
  {
    id: 'act-1502-escalate',
    agent: 'executor-01',
    action: 'policy.promote',
    target: 'Policy P-1502',
    attemptedAt: '2026-05-14 13:51:09 UTC',
    outcome: 'escalated',
    plainReason:
      'The policy promotion can be replayed, but it changes production governance. The console routed it to human deliberation instead of applying it silently.',
    receiptId: 'rcpt-608508a9-root',
    receiptHash: 'sha256:root4f6c22',
    traceId: 'trace-policy-1502-t11',
    replayCommand: 'gove-zone replay --trace trace-policy-1502-t11 --receipt rcpt-608508a9-root',
    auditEventId: 'audit-root',
    before: '{"policy":"P-1502","change":"promote","reviewers":1}',
    after: '{"status":"escalated","required_reviewers":2,"tool_executed":false}',
    checks: [
      {
        id: 'P-1210',
        label: 'MACI separation',
        posture: 'confirmed',
        reason: 'The promoting executor cannot validate its own proposal.',
      },
      {
        id: 'P-1214',
        label: 'Human deliberation',
        posture: 'partial',
        reason: 'One more independent reviewer is required before promotion.',
      },
    ],
  },
]
