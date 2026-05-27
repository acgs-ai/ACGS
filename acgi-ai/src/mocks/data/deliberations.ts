import type { Deliberation } from '../../api/types'

export const DELIBERATIONS: Deliberation[] = [
  {
    id: 'D-2031',
    matter: 'Matter-9821',
    title: 'Disclose drafting context to opposing counsel?',
    emphasis: 'Disclose',
    citation: '§164.502(b) · privileged',
    body: 'Custodian-01 drafted a memo whose recipient list includes opposing counsel. The bus held the dispatch and opened a deliberation. Recommend on-call partner review with attestation; refuse otherwise.',
    opened: '2026-05-03 13:32:41',
    due: '2026-05-03 17:32:00',
    posture: 'privileged',
  },
  {
    id: 'D-2032',
    matter: 'Matter-3387',
    title: 'Cross-jurisdiction citation in public reply',
    emphasis: 'public',
    citation: 'Internal §3.4',
    body: 'Analyst-04 surfaced a refusal whose draft cites a California statute on a New York matter. The cite is technically defensible but reads as venue-shopping in public; deliberation requested before the reply leaves the bus.',
    opened: '2026-05-03 14:08:22',
    due: '2026-05-03 18:08:00',
    posture: 'partial',
  },
  {
    id: 'D-2033',
    matter: 'Matter-7104',
    title: 'Promote P-1503 to canon?',
    emphasis: 'canon',
    citation: 'Internal §3.1',
    body: 'Six identical refusals of shape "matter disclosure" in the past four hours. Proposer suggests a canon escalation that routes future identical traffic directly to deliberation, bypassing the proposer lane.',
    opened: '2026-05-03 14:06:11',
    due: '2026-05-04 08:00:00',
    posture: 'confirmed',
  },
]
