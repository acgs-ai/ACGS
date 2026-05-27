import type { MaciLanes } from '../../api/types'

export const MACI_LANES: MaciLanes = {
  proposer: [
    {
      id: 'P-1502',
      title: 'Refuse cross-jurisdiction citation',
      body: 'Public Q on a New York matter cited a California statute. Drafting refusal that names the venue mismatch and proposes the correct §.',
      agent: 'analyst-04',
      ts: '14:08:22',
      posture: 'partial',
    },
    {
      id: 'P-1503',
      title: 'Promote draft on §164.502(b) refusal',
      body: 'Six independent refusals of identical shape on matter disclosure. Proposing a canon entry to escalate identical future requests to deliberation.',
      agent: 'analyst-12',
      ts: '14:06:11',
      posture: 'confirmed',
    },
  ],
  validator: [
    {
      id: 'V-0892',
      title: 'Cross-validate P-1497',
      body: 'Independent re-derivation of cite §164.502(b). Replay matches; Dafny proof artifact attached. Recommending promotion.',
      agent: 'reviewer-02',
      ts: '14:07:48',
      posture: 'confirmed',
    },
    {
      id: 'V-0893',
      title: 'Hold P-1499 — drift suspected',
      body: 'Constitution byte-diff present in proposer trace; promoting to deliberations queue with hash mismatch flag. Refusing to validate.',
      agent: 'reviewer-09',
      ts: '14:05:10',
      posture: 'blocked',
    },
  ],
  executor: [
    {
      id: 'E-2210',
      title: 'Tool call · matter.notes.append',
      body: 'Custodian-attested write into Matter-9821; redactor-04 sanitised PHI before commit.',
      agent: 'executor-01',
      ts: '14:09:03',
      posture: 'privileged',
    },
    {
      id: 'E-2211',
      title: 'Tool call · cite.lookup',
      body: 'Public statute index lookup, no privileged context, no PHI; dispatched without escalation.',
      agent: 'executor-03',
      ts: '14:09:00',
      posture: 'confirmed',
    },
  ],
}
