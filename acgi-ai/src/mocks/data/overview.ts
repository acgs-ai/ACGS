import type { OverviewSummary } from '../../api/types'

export const OVERVIEW_SUMMARY: OverviewSummary = {
  stats: [
    { label: 'Decisions today', value: '8,402', sub: '+612 vs. 7d median' },
    { label: 'Refused', value: '1,402', sub: '16.7% of total' },
    { label: 'Promoted', value: '312', sub: 'P-1190 -> P-1502' },
  ],
  activeCases: [
    {
      name: 'Matter-9821',
      stage: 'Human review',
      lane: 'MACI-3',
      age: '18m / T-42',
      evidence: '4 receipts',
      event: 'human review requested',
      posture: 'partial',
    },
    {
      name: 'Policy P-1502',
      stage: 'Promotion',
      lane: 'Registry',
      age: '07m / T-11',
      evidence: 'Dafny replay',
      event: 'policy check completed',
      posture: 'confirmed',
    },
    {
      name: 'Appeal A-118',
      stage: 'Counsel vote',
      lane: 'Deliberation',
      age: '41m / T-07',
      evidence: '2 opinions',
      event: 'appeal queue advanced',
      posture: 'partial',
    },
    {
      name: 'Audit 608508a9',
      stage: 'Seal',
      lane: 'Audit',
      age: '18s / T-03',
      evidence: 'anchor:18s',
      event: 'audit record sealed',
      posture: 'confirmed',
    },
  ],
  queues: [
    { label: 'Human review queue', value: '3', detail: 'oldest 41m', posture: 'partial' },
    { label: 'Appeal queue', value: '1', detail: 'counsel vote open', posture: 'partial' },
    {
      label: 'Enforcement retry/backoff',
      value: '0',
      detail: 'No queued retries',
      posture: 'confirmed',
    },
    { label: 'Audit backlog', value: '4', detail: 'anchor due in 18s', posture: 'confirmed' },
  ],
  refusalsByArticle: [
    { article: 'IV', citation: '§164.502(b)', refusals: 702, trend: '+18%', posture: 'confirmed' },
    {
      article: 'VII',
      citation: 'EU AI Act §15(4)',
      refusals: 441,
      trend: '+4%',
      posture: 'confirmed',
    },
    { article: 'II', citation: 'SR 11-7 §V', refusals: 128, trend: '-9%', posture: 'partial' },
    { article: 'IX', citation: 'GDPR Art. 22', refusals: 88, trend: '+22%', posture: 'partial' },
    { article: 'XI', citation: 'Internal §3.4', refusals: 43, trend: '+11%', posture: 'blocked' },
  ],
}
