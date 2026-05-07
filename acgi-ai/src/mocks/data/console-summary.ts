import type { ConsoleSummary } from '../../api/types'

export const CONSOLE_SUMMARY: ConsoleSummary = {
  constitutionHash: '608508a9bd224290',
  agentsOnline: 12,
  agentsTotal: 12,
  checks: 84,
  runtimeLabel: '06h 14m',
  driftBytes: 0,
  auditAnchorSeconds: 18,
  nextRefreshSeconds: 10,
  medianLatencyMs: 38,
  refusals24h: 1402,
  humanReview: 3,
  appeals: 2,
  retryBackoff: 0,
  recentEvents: [
    {
      id: 'EV-140822',
      body: 'Refused tool call matter.fetch for agent analyst-04 and cited §164.502(b).',
      ts: '14:08:22 · UTC',
    },
    {
      id: 'EV-135109',
      body: 'Validator promoted draft P-1207 to canon after two independent reviews and a Dafny replay.',
      ts: '13:51:09 · UTC',
    },
    {
      id: 'EV-133241',
      body: 'Human deliberation opened on Matter-9821; routed to on-call counsel.',
      ts: '13:32:41 · UTC',
    },
  ],
  coverage: [
    { label: 'EU AI Act', posture: 'confirmed', value: 'Active' },
    { label: 'SR 11-7', posture: 'confirmed', value: 'Active' },
    { label: 'HIPAA', posture: 'confirmed', value: 'Active' },
    { label: 'GDPR', posture: 'partial', value: 'Partial' },
  ],
}
