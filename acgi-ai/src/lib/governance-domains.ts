// Regulated-domain / obligation axis for the in-browser governance interview.
//
// This module is the single source of truth for the regulatory dimension that
// `src/routes/Marketing.tsx` (the live interview) and W2's static brief
// generator both consume. It is data plus a small pure derivation: which
// obligations a domain adds, how it nudges the existing risk-signal weights,
// and how it overrides a signal boundary (so PHI is treated distinctly from
// generic PII). It never assembles the brief itself.
//
// Claim boundary: every domain's copy frames regulatory items as "obligations
// to consider, not legal advice" and routes regulated decisions to qualified
// human review. This file is scanned by scripts/check-claim-matrix.mjs for
// overclaim phrases, so the copy here must never assert the product satisfies,
// is attested to, or is approved against any regulation or third-party standard.

// Risk-signal keys mirror the SignalKey union in src/routes/Marketing.tsx.
// Kept as a local list so this module stays importable without a circular
// dependency on the route. The override/delta maps reference these keys.
export type DomainSignalKey =
  | 'tools'
  | 'privateData'
  | 'credentials'
  | 'cloud'
  | 'code'
  | 'payments'
  | 'legal'
  | 'userAccounts'
  | 'publishing'
  | 'irreversible'
  | 'production'
  | 'memory'
  | 'multiAgent'
  | 'automationLoop'

// A boundary override replaces the rendered boundary text for one signal when a
// domain is active (e.g. PHI handling under hipaa_phipa is not generic PII).
export interface DomainSignalOverride {
  key: DomainSignalKey
  boundary: string
}

export interface RegulatedDomainProfile {
  // Human-readable label for the selector and the brief.
  label: string
  // Obligations to consider for this regulated context. Framed as items to
  // review with qualified counsel, never as satisfied requirements.
  obligations: string[]
  // Additive weight deltas keyed by an existing risk signal. The interview adds
  // these to the base score so a regulated context raises risk even when the
  // selected base signals are identical.
  weightDeltas: Partial<Record<DomainSignalKey, number>>
  // Boundary-text overrides applied to selected signals. Used so PHI under
  // hipaa_phipa reads distinctly from the generic privateData boundary.
  signalOverrides: DomainSignalOverride[]
  // Claim-safe framing line rendered with the obligations.
  disclaimer: string
}

const SHARED_DISCLAIMER_SUFFIX =
  'These are obligations to consider, not legal advice; escalate regulated decisions to qualified review.'

// Source-of-truth domain table. `none` is intentionally empty: it must produce
// a brief byte-identical to the pre-axis interview (no obligations, no weight
// deltas, no overrides) so the substantive governance model is never regressed.
export const REGULATED_DOMAINS = {
  none: {
    label: 'No specific regulatory domain',
    obligations: [],
    weightDeltas: {},
    signalOverrides: [],
    disclaimer: `No regulatory-domain obligations selected. ${SHARED_DISCLAIMER_SUFFIX}`,
  },
  gdpr: {
    label: 'EU GDPR — personal data',
    obligations: [
      'Map a lawful basis and data-minimization rationale before processing personal data.',
      'Honor data-subject access, rectification, and erasure expectations (GDPR Art. 15-17).',
      'Apply GDPR Art. 22 safeguards: no solely-automated decision with legal effect without human review.',
    ],
    weightDeltas: { privateData: 1 },
    signalOverrides: [
      {
        key: 'privateData',
        boundary:
          'Treat personal data under GDPR: minimize, record lawful basis, and log access rationale for data-subject rights.',
      },
    ],
    disclaimer: `GDPR references describe obligations to map, not satisfied requirements. ${SHARED_DISCLAIMER_SUFFIX}`,
  },
  hipaa_phipa: {
    label: 'HIPAA / PHIPA — protected health information',
    obligations: [
      'Handle protected health information (PHI) under minimum-necessary use, not as generic PII.',
      'Require a covered-entity or business-associate basis before PHI access or disclosure.',
      'Log PHI access and disclosure for accounting-of-disclosures and breach-notification review.',
    ],
    weightDeltas: { privateData: 2 },
    signalOverrides: [
      {
        key: 'privateData',
        boundary:
          'Treat this as protected health information (PHI), distinct from generic PII: minimum-necessary access, covered-entity basis, and disclosure logging.',
      },
    ],
    disclaimer: `HIPAA/PHIPA references describe PHI obligations to consider, not a satisfied posture. ${SHARED_DISCLAIMER_SUFFIX}`,
  },
  soc2: {
    label: 'SOC 2 — Trust Services Criteria mapping',
    obligations: [
      'Map controls to SOC 2 Trust Services Criteria as references, not as an attestation.',
      'Keep change-management and access-review evidence for the control mapping.',
      'Route any attestation wording to qualified review before external claims.',
    ],
    weightDeltas: { production: 1 },
    signalOverrides: [],
    disclaimer: `SOC 2 references are control-mapping language only, not an attestation. ${SHARED_DISCLAIMER_SUFFIX}`,
  },
  pci: {
    label: 'PCI DSS — payment card data',
    obligations: [
      'Keep cardholder data out of prompts, logs, and memory; reference tokens or vault handles only.',
      'Scope payment-data handling to the minimum needed and require human approval before any transaction.',
      'Record payment-data access and approval as part of the decision receipt.',
    ],
    weightDeltas: { payments: 2 },
    signalOverrides: [
      {
        key: 'payments',
        boundary:
          'Raise payment-data handling under PCI DSS: never expose cardholder data to the model, and require fresh human approval before any money movement.',
      },
    ],
    disclaimer: `PCI DSS references describe payment-data obligations to consider, not a satisfied posture. ${SHARED_DISCLAIMER_SUFFIX}`,
  },
  eu_ai_act: {
    label: 'EU AI Act — high-risk AI provisions',
    obligations: [
      'Classify the use case against EU AI Act risk tiers before assuming permitted use.',
      'Keep risk-management, documentation, and transparency evidence for high-risk provisions.',
      'Preserve human oversight of high-risk AI outputs (EU AI Act Art. 14).',
    ],
    weightDeltas: { automationLoop: 1 },
    signalOverrides: [],
    disclaimer: `EU AI Act references describe obligations to map, not a satisfied posture. ${SHARED_DISCLAIMER_SUFFIX}`,
  },
} as const satisfies Record<string, RegulatedDomainProfile>

export type RegulatedDomain = keyof typeof REGULATED_DOMAINS

// Stable ordered list of domain keys for selector rendering and iteration.
export const REGULATED_DOMAIN_KEYS = Object.keys(REGULATED_DOMAINS) as RegulatedDomain[]

export function domainProfile(domain: RegulatedDomain): RegulatedDomainProfile {
  return REGULATED_DOMAINS[domain]
}

// Pure derivation helpers W2's generator and the interview both reuse.

// Total additive weight a domain contributes given the currently selected base
// signals. Only deltas for selected signals count, so an unrelated domain delta
// never inflates the score.
export function domainWeightDelta(
  domain: RegulatedDomain,
  selectedSignals: readonly DomainSignalKey[],
): number {
  const weightDeltas: Partial<Record<DomainSignalKey, number>> =
    REGULATED_DOMAINS[domain].weightDeltas
  return selectedSignals.reduce((total, key) => total + (weightDeltas[key] ?? 0), 0)
}

// Boundary text for one signal under a domain: the domain override when present,
// otherwise the caller's base boundary. Lets the interview render PHI-specific
// language without duplicating the base signal table.
export function domainSignalBoundary(
  domain: RegulatedDomain,
  key: DomainSignalKey,
  baseBoundary: string,
): string {
  const override = REGULATED_DOMAINS[domain].signalOverrides.find((item) => item.key === key)
  return override ? override.boundary : baseBoundary
}
