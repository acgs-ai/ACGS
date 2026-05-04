import type { CompileDraft } from '../../api/types'

export const COMPILE_DRAFT: CompileDraft = {
  currentHash: '608508a9bd224290',
  proposedHash: '4c1f7e8a92b3d501',
  changes: [
    {
      id: 'P-1207',
      name: 'matter.disclosure',
      citation: '§164.502(b) · HIPAA',
      change: 'amended',
      note: 'Adds agent.scope.contains("matter") clause; closes the public-counsel bypass found by reviewer-09.',
    },
    {
      id: 'P-1215',
      name: 'vendor.api.attestation',
      citation: 'SR 11-7 §V',
      change: 'added',
      note: 'New rule. Requires every third-party tool call to carry a vendor attestation matching the catalog hash.',
    },
    {
      id: 'P-1216',
      name: 'maci.quorum.minimum',
      citation: 'Internal §3.1',
      change: 'added',
      note: 'New rule. Validator dispatches refused when fewer than two independent reviewers are healthy in-lane.',
    },
    {
      id: 'P-1209',
      name: 'automated.decision.disclosure',
      citation: 'GDPR Art. 22',
      change: 'amended',
      note: 'Formalises the data-subject route to deliberation that was partial coverage in v3.1.0.',
    },
    {
      id: 'P-1213',
      name: 'tool.scope.intersection',
      citation: 'SR 11-7 §V',
      change: 'amended',
      note: 'Extends scope-intersection enforcement to third-party tools by reading the audited vendor catalog.',
    },
    {
      id: 'P-1217',
      name: 'phi.redaction.attestation',
      citation: '§164.514',
      change: 'added',
      note: 'New rule. Splits attestation requirement out of P-1212 so the redactor can be replaced without amending the privilege rule itself.',
    },
    {
      id: 'P-1198',
      name: 'deprecated.tool.scope',
      citation: 'Internal §3.4',
      change: 'removed',
      note: 'Folded into P-1213. The standalone rule duplicated coverage and confused validators.',
    },
  ],
}
