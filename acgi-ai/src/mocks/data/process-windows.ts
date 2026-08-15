// MOCK-ONLY MODULE — fixture projections for the Process Evidence View.
// Shapes mirror agent-bus-analyzer's process-intelligence API exactly
// (snake_case wire contract, analytical_only pinned true). Receipt ids in
// evidence_references reuse the governed-action fixtures so deep links into
// /console/audit/:receiptId resolve in fixture mode.

import type {
  ProcessComplianceReport,
  ProcessDetail,
  ProcessList,
  ProcessVariantList,
} from '../../api/types'

const TENANT = 'tenant-lex-atlas'

export const PROCESS_LIST: ProcessList = {
  items: [
    {
      tenant_id: TENANT,
      process_id: 'matter-intake',
      process_name: 'Matter intake screening',
      event_count: 42,
      case_count: 9,
      started_at: '2026-08-14T09:12:04+00:00',
      completed_at: '2026-08-14T17:48:51+00:00',
      evidence_coverage: 1.0,
      source_chain_status: 'verified',
      snapshot_id: 'snap-4f1c9b2e77d0a3c1',
      service_version: 'process-service-1.0',
      analytical_only: true,
      executable_authority: false,
    },
    {
      tenant_id: TENANT,
      process_id: 'privileged-doc-release',
      process_name: 'Privileged document release',
      event_count: 27,
      case_count: 6,
      started_at: '2026-08-13T11:02:19+00:00',
      completed_at: '2026-08-14T16:20:33+00:00',
      evidence_coverage: 0.81,
      source_chain_status: 'verified',
      snapshot_id: 'snap-a83e0d5f19c247b6',
      service_version: 'process-service-1.0',
      analytical_only: true,
      executable_authority: false,
    },
  ],
  total: 2,
  offset: 0,
  limit: 50,
}

const PROCESS_DETAILS: ProcessDetail[] = [
  {
    summary: PROCESS_LIST.items[0],
    algorithm_version: 'dfg-1.0',
    activities: [
      { activity: 'intake.received', count: 9 },
      { activity: 'conflict.check', count: 9 },
      { activity: 'policy.gate', count: 9 },
      { activity: 'matter.opened', count: 8 },
    ],
    directly_follows: [
      {
        source: 'intake.received',
        target: 'conflict.check',
        count: 9,
        average_duration_seconds: 312.4,
        p50_duration_seconds: 288.0,
        p95_duration_seconds: 512.7,
        excluded_duration_count: 0,
      },
      {
        source: 'conflict.check',
        target: 'policy.gate',
        count: 9,
        average_duration_seconds: 96.1,
        p50_duration_seconds: 84.0,
        p95_duration_seconds: 149.5,
        excluded_duration_count: 0,
      },
      {
        source: 'policy.gate',
        target: 'matter.opened',
        count: 8,
        average_duration_seconds: 41.8,
        p50_duration_seconds: 39.0,
        p95_duration_seconds: 66.2,
        excluded_duration_count: 0,
      },
    ],
    incomplete_case_count: 1,
    excluded_case_ids: ['case-intake-0007'],
  },
  {
    summary: PROCESS_LIST.items[1],
    algorithm_version: 'dfg-1.0',
    activities: [
      { activity: 'release.requested', count: 6 },
      { activity: 'privilege.review', count: 6 },
      { activity: 'policy.gate', count: 5 },
      { activity: 'document.released', count: 4 },
    ],
    directly_follows: [
      {
        source: 'release.requested',
        target: 'privilege.review',
        count: 6,
        average_duration_seconds: 1804.2,
        p50_duration_seconds: 1521.0,
        p95_duration_seconds: 3390.8,
        excluded_duration_count: 1,
      },
      {
        source: 'privilege.review',
        target: 'policy.gate',
        count: 5,
        average_duration_seconds: 233.9,
        p50_duration_seconds: 205.0,
        p95_duration_seconds: 401.3,
        excluded_duration_count: 0,
      },
      {
        source: 'policy.gate',
        target: 'document.released',
        count: 4,
        average_duration_seconds: 58.6,
        p50_duration_seconds: 52.0,
        p95_duration_seconds: 90.4,
        excluded_duration_count: 0,
      },
    ],
    incomplete_case_count: 2,
    excluded_case_ids: ['case-release-0003', 'case-release-0005'],
  },
]

const PROCESS_VARIANTS: ProcessVariantList[] = [
  {
    tenant_id: TENANT,
    process_id: 'matter-intake',
    snapshot_id: 'snap-4f1c9b2e77d0a3c1',
    algorithm_version: 'variants-1.0',
    items: [
      {
        signature: ['intake.received', 'conflict.check', 'policy.gate', 'matter.opened'],
        case_ids: [
          'case-intake-0001',
          'case-intake-0002',
          'case-intake-0003',
          'case-intake-0004',
          'case-intake-0005',
          'case-intake-0006',
        ],
        count: 6,
        frequency: 0.667,
        average_duration_seconds: 448.5,
        incomplete_case_count: 0,
      },
      {
        signature: [
          'intake.received',
          'conflict.check',
          'conflict.check',
          'policy.gate',
          'matter.opened',
        ],
        case_ids: ['case-intake-0008', 'case-intake-0009'],
        count: 2,
        frequency: 0.222,
        average_duration_seconds: 731.2,
        incomplete_case_count: 0,
      },
      {
        signature: ['intake.received', 'conflict.check'],
        case_ids: ['case-intake-0007'],
        count: 1,
        frequency: 0.111,
        average_duration_seconds: 302.1,
        incomplete_case_count: 1,
      },
    ],
    total: 3,
    offset: 0,
    limit: 50,
  },
  {
    tenant_id: TENANT,
    process_id: 'privileged-doc-release',
    snapshot_id: 'snap-a83e0d5f19c247b6',
    algorithm_version: 'variants-1.0',
    items: [
      {
        signature: ['release.requested', 'privilege.review', 'policy.gate', 'document.released'],
        case_ids: [
          'case-release-0001',
          'case-release-0002',
          'case-release-0004',
          'case-release-0006',
        ],
        count: 4,
        frequency: 0.667,
        average_duration_seconds: 2093.4,
        incomplete_case_count: 0,
      },
      {
        signature: ['release.requested', 'privilege.review'],
        case_ids: ['case-release-0003', 'case-release-0005'],
        count: 2,
        frequency: 0.333,
        average_duration_seconds: 1688.9,
        incomplete_case_count: 2,
      },
    ],
    total: 2,
    offset: 0,
    limit: 50,
  },
]

const PROCESS_COMPLIANCE: ProcessComplianceReport[] = [
  {
    tenant_id: TENANT,
    process_id: 'matter-intake',
    snapshot_id: 'snap-4f1c9b2e77d0a3c1',
    findings: [
      {
        tenant_id: TENANT,
        case_id: 'case-intake-0001',
        event_id: 'evt-intake-0001-03',
        event_normalization_hash:
          '9c1f4a7e0b52d68c3aa1e97f04d2b85c6f13e0a94d7b28c15e6a03f9b84d2c71',
        outcome: 'ALLOW',
        proof_status: 'hash_only',
        reproducibility: 'unknown',
        receipt_verifier_succeeded: false,
        verifier_name: null,
        verifier_signature_required: false,
        verifier_expiry_required: false,
        production_profile_verified: false,
        reasons: [],
        verifier_reason_codes: [],
        evidence_references: [{ reference_type: 'receipt_id', reference_id: 'rcpt-608508a9-8b38' }],
        algorithm_version: 'conformance-1.0',
        analytical_only: true,
        executable_authority: false,
      },
      {
        tenant_id: TENANT,
        case_id: 'case-intake-0004',
        event_id: 'evt-intake-0004-03',
        event_normalization_hash:
          '2e8b0c5f7a41d93e6cc4f18a05e3b96d7f24e1ba5e8c39d26f7b14a0c95e3d82',
        outcome: 'DENY',
        proof_status: 'hash_only',
        reproducibility: 'unknown',
        receipt_verifier_succeeded: false,
        verifier_name: null,
        verifier_signature_required: false,
        verifier_expiry_required: false,
        production_profile_verified: false,
        reasons: ['receipt_missing'],
        verifier_reason_codes: [],
        evidence_references: [
          { reference_type: 'audit_event_hash', reference_id: 'a7b2…missing-receipt' },
        ],
        algorithm_version: 'conformance-1.0',
        analytical_only: true,
        executable_authority: false,
      },
    ],
    relevant_event_count: 42,
    allow_count: 41,
    deny_count: 1,
    investigate_count: 0,
    compliance_score: 0.976,
    verification_posture: 'non_authoritative',
    analytical_only: true,
    executable_authority: false,
  },
  {
    tenant_id: TENANT,
    process_id: 'privileged-doc-release',
    snapshot_id: 'snap-a83e0d5f19c247b6',
    findings: [
      {
        tenant_id: TENANT,
        case_id: 'case-release-0002',
        event_id: 'evt-release-0002-04',
        event_normalization_hash:
          '5d3a9f1c8e60b74d2ff6a35c09e4d17b8a02f5cd6e9b48a37f8c25b1d06e4f93',
        outcome: 'ALLOW',
        proof_status: 'hash_only',
        reproducibility: 'unknown',
        receipt_verifier_succeeded: false,
        verifier_name: null,
        verifier_signature_required: false,
        verifier_expiry_required: false,
        production_profile_verified: false,
        reasons: [],
        verifier_reason_codes: [],
        evidence_references: [{ reference_type: 'receipt_id', reference_id: 'rcpt-608508a9-8b37' }],
        algorithm_version: 'conformance-1.0',
        analytical_only: true,
        executable_authority: false,
      },
      {
        tenant_id: TENANT,
        case_id: 'case-release-0003',
        event_id: 'evt-release-0003-02',
        event_normalization_hash:
          '8f6c2d4b0a97e15f3dd8b46a07f5c29e9b13a6de7f0c59b48a9d36c2e17f5a04',
        outcome: 'INVESTIGATE',
        proof_status: 'incomplete',
        reproducibility: 'unknown',
        receipt_verifier_succeeded: false,
        verifier_name: null,
        verifier_signature_required: false,
        verifier_expiry_required: false,
        production_profile_verified: false,
        reasons: ['audit_missing'],
        verifier_reason_codes: [],
        evidence_references: [],
        algorithm_version: 'conformance-1.0',
        analytical_only: true,
        executable_authority: false,
      },
    ],
    relevant_event_count: 27,
    allow_count: 24,
    deny_count: 1,
    investigate_count: 2,
    compliance_score: null,
    verification_posture: 'non_authoritative',
    analytical_only: true,
    executable_authority: false,
  },
]

export function getProcessDetailFixture(processId: string): ProcessDetail | undefined {
  return PROCESS_DETAILS.find((detail) => detail.summary.process_id === processId)
}

export function getProcessVariantsFixture(processId: string): ProcessVariantList | undefined {
  return PROCESS_VARIANTS.find((variants) => variants.process_id === processId)
}

export function getProcessComplianceFixture(
  processId: string,
): ProcessComplianceReport | undefined {
  return PROCESS_COMPLIANCE.find((report) => report.process_id === processId)
}
