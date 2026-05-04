import type { AuditEvent } from '../../api/types'

export const AUDIT_EVENTS: AuditEvent[] = [
  {
    ts: '2026-05-03 14:09:11',
    posture: 'confirmed',
    ev: 'Validator promoted P-1497 to canon',
    src: 'reviewer-02 · validator',
    hash: '608508a9 · 8b3a',
  },
  {
    ts: '2026-05-03 14:09:03',
    posture: 'privileged',
    ev: 'Custodial write to matter notes',
    src: 'executor-01 → matter.notes.append',
    hash: '608508a9 · 8b39',
    matter: 'Matter-9821',
  },
  {
    ts: '2026-05-03 14:08:51',
    posture: 'confirmed',
    ev: 'Refused public matter disclosure',
    src: 'analyst-12 · §164.502(b)',
    hash: '608508a9 · 8b38',
  },
  {
    ts: '2026-05-03 14:08:22',
    posture: 'partial',
    ev: 'Cross-jurisdiction citation flagged',
    src: 'analyst-04 · venue mismatch',
    hash: '608508a9 · 8b37',
  },
  {
    ts: '2026-05-03 14:05:10',
    posture: 'blocked',
    ev: 'Validator hold — constitution byte-drift',
    src: 'reviewer-09 · drift sentry',
    hash: '608508a9 · 8b36',
  },
  {
    ts: '2026-05-03 13:51:09',
    posture: 'confirmed',
    ev: 'Compiled constitution v3.1.0 promoted',
    src: 'maintainer-01 · compiler',
    hash: '608508a9 · root',
  },
  {
    ts: '2026-05-03 13:32:41',
    posture: 'privileged',
    ev: 'Deliberation opened on Matter-9821',
    src: 'custodian-01 · escalation',
    hash: '608508a9 · 8b30',
    matter: 'Matter-9821',
  },
  {
    ts: '2026-05-03 13:14:08',
    posture: 'confirmed',
    ev: 'GDPR Art. 22 disclosure surfaced',
    src: 'analyst-04 · automated decision',
    hash: '608508a9 · 8b27',
  },
  {
    ts: '2026-05-03 12:47:55',
    posture: 'blocked',
    ev: 'Tool call denied — scope intersection empty',
    src: 'executor-03 · cite.lookup.private',
    hash: '608508a9 · 8b1f',
  },
]
