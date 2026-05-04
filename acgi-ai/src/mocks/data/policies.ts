import type { PolicyRule } from '../../api/types'

export const POLICIES: PolicyRule[] = [
  {
    id: 'P-1207',
    name: 'matter.disclosure',
    citation: '§164.502(b) · HIPAA · v2024',
    posture: 'privileged',
    prose:
      'Where an agent operates in the public-counsel role, and a payload contains the token "matter_id" or any cognate identifier, the action MUST be denied with citation §164.502(b). The privilege boundary is structural; it does not depend on user role or session age.',
  },
  {
    id: 'P-1208',
    name: 'model.accuracy.threshold',
    citation: 'EU AI Act §15(4)',
    posture: 'confirmed',
    prose:
      'A model whose rolling 30-day MAE on the SR 11-7 conformance set exceeds the constitutional threshold MUST be removed from production traffic. Promotion back into traffic requires a Validator-attested replay and a fresh signature.',
  },
  {
    id: 'P-1209',
    name: 'automated.decision.disclosure',
    citation: 'GDPR Art. 22',
    posture: 'partial',
    prose:
      'Any automated decision producing legal or similarly significant effects MUST disclose to the data subject that an automated process is involved, identify the controller, and offer a route to human deliberation. Coverage is partial: textual disclosure is enforced; data-subject route to deliberation pending §V audit.',
  },
  {
    id: 'P-1210',
    name: 'maci.separation',
    citation: 'Internal §3.1',
    posture: 'confirmed',
    prose:
      'No agent MAY validate output produced by an agent it shares a parent lane with. The bus rejects validator dispatch on a trace whose proposer pedigree it cannot verify against the lane registry.',
  },
  {
    id: 'P-1211',
    name: 'constitution.drift',
    citation: 'Internal §3.4',
    posture: 'confirmed',
    prose:
      'On every dispatch, the constitutional hash recorded at compile time is compared with the hash present in the bus, the gateway, and the worker. Any mismatch denies the action and pages the maintainer.',
  },
  {
    id: 'P-1212',
    name: 'phi.redaction',
    citation: '§164.514',
    posture: 'privileged',
    prose:
      'Outbound payloads from custodial agents MUST be passed through the redactor lane. The redactor is itself a governed agent and MUST attach an attestation that the safe-harbor identifier set has been removed.',
  },
  {
    id: 'P-1213',
    name: 'tool.scope.intersection',
    citation: 'SR 11-7 §V',
    posture: 'partial',
    prose:
      'A tool call is permitted only if the tool scope and the agent scope intersect non-trivially. Coverage partial: scope intersection enforced for first-party tools; third-party tool scope catalog being audited.',
  },
  {
    id: 'P-1214',
    name: 'humans.in.the.loop',
    citation: 'Art. 14',
    posture: 'confirmed',
    prose:
      'High-risk decisions defined by the operating constitution MUST be routable to human deliberation within a bounded SLA. The bus refuses to ship a high-risk decision without a deliberation receipt.',
  },
]
