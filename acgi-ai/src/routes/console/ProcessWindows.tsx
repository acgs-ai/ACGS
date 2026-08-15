import { useState } from 'react'
import {
  useProcessCompliance,
  useProcessDetail,
  useProcessList,
  useProcessVariants,
} from '../../api/hooks'
import type {
  Posture,
  ProcessComplianceReport,
  ProcessConformanceFinding,
  ProcessConformanceOutcome,
  ProcessDetail,
  ProcessSourceChainStatus,
  ProcessSummary,
  ProcessVariantList,
} from '../../api/types'
import { navigate } from '../../lib/navigate'
import { ConsoleError, ConsoleLoading, EmptyState, SearchToolbar, useTextFilter } from './shared'

type RowPosture = Extract<Posture, 'confirmed' | 'partial' | 'blocked'>

// Fixed analytical caption (claim-safety): an ALLOW on this page is a
// conformance verdict about recorded evidence, never an execution grant.
const ANALYTICAL_CAPTION = 'Analytical conclusion — not an execution authorization.'

const OUTCOME_POSTURE: Record<ProcessConformanceOutcome, RowPosture> = {
  ALLOW: 'confirmed',
  DENY: 'blocked',
  INVESTIGATE: 'partial',
}

const CHAIN_POSTURE: Record<ProcessSourceChainStatus, RowPosture> = {
  verified: 'confirmed',
  unverified: 'partial',
  not_applicable: 'partial',
}

const CHAIN_LABEL: Record<ProcessSourceChainStatus, string> = {
  verified: 'Chain verified',
  unverified: 'Chain unverified',
  not_applicable: 'Chain n/a',
}

const listFields = (p: ProcessSummary) => [
  p.process_id,
  p.process_name,
  p.snapshot_id,
  p.source_chain_status,
]

function shortTs(iso: string): string {
  return iso.slice(0, 16).replace('T', ' ')
}

function windowLabel(summary: ProcessSummary): string {
  return `${shortTs(summary.started_at)} → ${shortTs(summary.completed_at)} UTC`
}

// Coverage is measured by the backend over side-effect events only; floor
// so a 99.6% window never reads as fully evidenced.
function coverageLabel(coverage: number): string {
  return `${Math.floor(coverage * 100)}% coverage over side-effect events`
}

// A nullable score is rendered as uncertainty, never as zero and never
// dropped — and the stated cause must match the backend's voiding rule:
// no findings at all, any INVESTIGATE, or no determinate findings.
function scoreLabel(report: ProcessComplianceReport): string {
  if (report.compliance_score === null) {
    if (report.findings.length === 0) {
      return 'uncertain — no conformance-relevant events recorded in this window'
    }
    if (report.investigate_count > 0) {
      return `uncertain — ${report.investigate_count} INVESTIGATE finding${
        report.investigate_count === 1 ? '' : 's'
      } void${report.investigate_count === 1 ? 's' : ''} the aggregate score`
    }
    return 'uncertain — no determinate findings in this window'
  }
  return `${(report.compliance_score * 100).toFixed(1)}% of relevant events conform`
}

function receiptReferenceFor(finding: ProcessConformanceFinding): string | null {
  for (const reference of finding.evidence_references) {
    if (typeof reference === 'string') continue
    if (reference.reference_type === 'receipt_id') return reference.reference_id
  }
  return null
}

function ProcessRowList({
  items,
  onSelect,
}: {
  items: readonly ProcessSummary[]
  onSelect: (id: string) => void
}) {
  return (
    <div className="audit-list">
      {items.map((summary) => (
        <button
          key={summary.process_id}
          type="button"
          className="bus-trace-row"
          onClick={() => onSelect(summary.process_id)}
        >
          <span className="ts">{windowLabel(summary)}</span>
          <span className={`pill ${CHAIN_POSTURE[summary.source_chain_status]}`}>
            {CHAIN_LABEL[summary.source_chain_status]}
          </span>
          <span className="ev">
            {summary.process_name ?? summary.process_id}
            <span className="src">
              {summary.case_count} case{summary.case_count === 1 ? '' : 's'} · {summary.event_count}{' '}
              events · {coverageLabel(summary.evidence_coverage)}
            </span>
          </span>
          <span className="hash-col">
            <strong>{summary.snapshot_id}</strong>
            <span> · immutable window</span>
          </span>
        </button>
      ))}
    </div>
  )
}

function VariantSection({
  detail,
  variants,
}: {
  detail: ProcessDetail
  variants: ProcessVariantList
}) {
  return (
    <section className="overview-section" aria-labelledby="process-variants">
      <div className="c-toolbar">
        <h2 className="overview-section-title" id="process-variants">
          Variants
        </h2>
        <span className="c-meta">
          flow over {detail.summary.event_count} events · variants over {detail.summary.case_count}{' '}
          cases · {variants.items.length} of {variants.total} variant
          {variants.total === 1 ? '' : 's'} shown · {detail.incomplete_case_count} incomplete case
          {detail.incomplete_case_count === 1 ? '' : 's'} excluded from durations
        </span>
      </div>
      {variants.items.length === 0 ? (
        <p className="c-meta">
          No variants recorded in this window — absence of evidence, not proof of a single flow.
        </p>
      ) : null}
      <div className="audit-list">
        {variants.items.map((variant) => (
          <div className="audit-row" key={JSON.stringify(variant.signature)}>
            <span className="ts">
              ×{variant.count} · {Math.round(variant.frequency * 100)}%
            </span>
            <span className={`pill ${variant.incomplete_case_count > 0 ? 'partial' : 'confirmed'}`}>
              {variant.incomplete_case_count > 0
                ? `${variant.incomplete_case_count} incomplete`
                : 'complete'}
            </span>
            <span className="ev">
              {variant.signature.join(' → ')}
              <span className="src">
                avg {Math.round(variant.average_duration_seconds)}s · {variant.case_ids.length} case
                {variant.case_ids.length === 1 ? '' : 's'}
              </span>
            </span>
          </div>
        ))}
      </div>
    </section>
  )
}

function FindingRow({ finding }: { finding: ProcessConformanceFinding }) {
  const receiptId = receiptReferenceFor(finding)
  return (
    <div className="audit-row">
      <span className="ts">{finding.case_id}</span>
      <span className={`pill ${OUTCOME_POSTURE[finding.outcome]}`}>{finding.outcome}</span>
      <span className="ev">
        {finding.event_id}
        <span className="src">
          {finding.proof_status}
          {finding.reasons.length > 0 ? ` · ${finding.reasons.join(', ')}` : ''}
        </span>
      </span>
      <span className="hash-col">
        {receiptId ? (
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => navigate(`/console/audit/${encodeURIComponent(receiptId)}`)}
          >
            Open receipt proof
          </button>
        ) : (
          <span className="src">no receipt reference recorded</span>
        )}
      </span>
    </div>
  )
}

function ComplianceSection({ report }: { report: ProcessComplianceReport }) {
  return (
    <section className="overview-section" aria-labelledby="process-conformance">
      <div className="c-toolbar">
        <h2 className="overview-section-title" id="process-conformance">
          Conformance
        </h2>
        <span className="c-meta">
          {report.allow_count} ALLOW · {report.deny_count} DENY · {report.investigate_count}{' '}
          INVESTIGATE · posture {report.verification_posture}
        </span>
      </div>
      <p className="c-meta">
        {scoreLabel(report)} · {ANALYTICAL_CAPTION}
      </p>
      {report.findings.length > 0 ? (
        <div className="audit-list">
          {report.findings.map((finding) => (
            <FindingRow key={`${finding.case_id}-${finding.event_id}`} finding={finding} />
          ))}
        </div>
      ) : (
        <p className="c-meta">
          No conformance-relevant events recorded in this window. Absence of findings is absence of
          evidence, not proof of conformance — page the audit owner before relying on it.
        </p>
      )}
    </section>
  )
}

function ProcessInspector({ processId, onBack }: { processId: string; onBack: () => void }) {
  const detail = useProcessDetail(processId)
  const variants = useProcessVariants(processId)
  const compliance = useProcessCompliance(processId)

  if (detail.isError) {
    return <ConsoleError onRetry={() => detail.refetch()} />
  }
  if (detail.isLoading || !detail.data) {
    return <ConsoleLoading label="Loading process window …" />
  }

  const summary = detail.data.summary
  return (
    <div>
      <button type="button" className="bus-back" onClick={onBack}>
        ← back to process windows
      </button>
      <div className="bus-inspector-header">
        <div>
          <div className="c-meta">Process window</div>
          <div className="bus-inspector-id">{summary.process_name ?? summary.process_id}</div>
        </div>
        <div className="bus-inspector-meta">
          <span className={`pill ${CHAIN_POSTURE[summary.source_chain_status]}`}>
            {CHAIN_LABEL[summary.source_chain_status]}
          </span>
          <span className="hash-col">
            <strong>{summary.snapshot_id}</strong>
            <span> · {detail.data.algorithm_version}</span>
          </span>
        </div>
      </div>

      {variants.isError ? (
        <ConsoleError onRetry={() => variants.refetch()} />
      ) : variants.isLoading || !variants.data ? (
        <ConsoleLoading label="Loading variants …" />
      ) : (
        <VariantSection detail={detail.data} variants={variants.data} />
      )}

      {compliance.isError ? (
        <ConsoleError onRetry={() => compliance.refetch()} />
      ) : compliance.isLoading || !compliance.data ? (
        <ConsoleLoading label="Loading conformance …" />
      ) : (
        <ComplianceSection report={compliance.data} />
      )}

      <p className="u-mt-xl u-mono-cap-wide">
        ⁂ Analytical projection of the receipt-gated audit chain · verdicts link to persisted
        evidence where an evidence reference was recorded · this view never executes, authorizes, or
        mints receipts
      </p>
    </div>
  )
}

export function ProcessWindows() {
  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const list = useProcessList()
  const filtered = useTextFilter(list.data?.items, query, listFields)

  if (selectedId !== null) {
    return <ProcessInspector processId={selectedId} onBack={() => setSelectedId(null)} />
  }

  if (list.isLoading) {
    return <ConsoleLoading label="Loading process windows …" />
  }

  if (list.isError || !list.data) {
    return <ConsoleError onRetry={() => list.refetch()} />
  }

  const total = list.data.total
  return (
    <div>
      <SearchToolbar
        value={query}
        onChange={setQuery}
        placeholder="Filter by process, snapshot, chain status…"
        ariaLabel="Filter process windows"
        meta={`${filtered.length} of ${total} windows visible · immutable windows · read-only`}
      />

      {filtered.length === 0 ? (
        <EmptyState
          emptyMeans="awaiting-bus"
          query={query}
          label="process windows"
          onClear={() => setQuery('')}
        />
      ) : (
        <ProcessRowList items={filtered} onSelect={setSelectedId} />
      )}

      <p className="u-mt-xl u-mono-cap-wide">
        ⁂ Off-path projection · each window is an immutable snapshot of recorded evidence with its
        chain status shown per row · {ANALYTICAL_CAPTION}
      </p>
    </div>
  )
}
