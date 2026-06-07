import { useMemo, useState } from 'react'
import { useAudit, useEvaluationEvidence } from '../../api/hooks'
import type { AuditEvent, EvaluationEvidence, EvaluationEvidenceSource } from '../../api/types'
import { ConsoleError, ConsoleLoading, EmptyState, SearchToolbar, useTextFilter } from './shared'

type EvaluationSourceCopy = { label: string; note: string }

const EVALUATION_SOURCE_LABEL: Record<EvaluationEvidenceSource, EvaluationSourceCopy> = {
  acgs: {
    label: 'ACGS local eval',
    note: 'Policy-bundle replay from the governed runtime evaluation adapter.',
  },
  agentdojo: {
    label: 'AgentDojo-style adapter',
    note: 'Local AgentDojo-style fixture converted into claim-safe local evidence.',
  },
  injecagent: {
    label: 'InjecAgent-style adapter',
    note: 'Local InjecAgent-style fixture converted into claim-safe local evidence.',
  },
  toolemu: {
    label: 'ToolEmu-style adapter',
    note: 'Local ToolEmu-style fixture for high-stakes tools converted into claim-safe local evidence.',
  },
}

const evaluationSourceCopy = (source: EvaluationEvidenceSource) =>
  EVALUATION_SOURCE_LABEL[source] ?? {
    label: source,
    note: 'Source-tagged local benchmark evidence from the eval-MVP audit chain.',
  }

const auditFields = (e: AuditEvent) => [
  e.ts,
  e.ev,
  e.src,
  e.hash,
  e.matter,
  e.posture,
  e.evaluationEvidence?.source,
  e.evaluationEvidence?.dataset,
  e.evaluationEvidence?.reportHash,
  e.evaluationEvidence?.policyVersion,
  e.evaluationEvidence?.status,
]

const evaluationEvidenceFields = (e: EvaluationEvidence) => [
  e.source,
  evaluationSourceCopy(e.source).label,
  e.dataset,
  e.reportHash,
  e.policyVersion,
  e.status,
  e.eventHash,
  e.claimSafe === undefined ? undefined : String(e.claimSafe),
]

const formatRate = (value: number | null) =>
  value === null ? 'n/a' : `${Math.round(value * 100)}%`

const hashParts = (hash: string) => {
  const [primary, secondary] = hash.split(' · ')
  return { primary, secondary }
}

function hasEvaluationEvidence(
  event: AuditEvent,
): event is AuditEvent & { evaluationEvidence: EvaluationEvidence } {
  return Boolean(event.evaluationEvidence)
}

export function Audit() {
  const [query, setQuery] = useState('')
  const { data, isLoading, isError, refetch } = useAudit()
  const evaluationQuery = useEvaluationEvidence('passed')
  const filteredLiveEvidence = useTextFilter(evaluationQuery.data, query, evaluationEvidenceFields)
  const filtered = useTextFilter(data, query, auditFields)
  const auditEvaluationEvidence = useMemo(
    () => filtered.filter(hasEvaluationEvidence).map((event) => event.evaluationEvidence),
    [filtered],
  )
  const evaluationEvidence =
    filteredLiveEvidence.length > 0 ? filteredLiveEvidence : auditEvaluationEvidence

  if (isLoading) {
    return <ConsoleLoading />
  }

  if (isError || !data) {
    return <ConsoleError onRetry={() => refetch()} />
  }

  return (
    <div>
      <SearchToolbar
        value={query}
        onChange={setQuery}
        placeholder="Search by matter, citation, agent, hash…"
        ariaLabel="Search audit"
        meta={`${filtered.length} of ${data.length} visible · ${evaluationEvidence.length} eval reports · UTC · append-only`}
      />

      {evaluationEvidence.length > 0 ? (
        <section className="overview-section" aria-labelledby="evaluation-evidence">
          <div className="c-toolbar">
            <h2 className="overview-section-title" id="evaluation-evidence">
              Evaluation evidence
            </h2>
            <span className="c-meta">
              {evaluationQuery.isError
                ? 'live eval-MVP query unavailable · audit rows only'
                : 'live eval-MVP query · hash-addressed'}
            </span>
          </div>
          <div className="evaluation-evidence-grid">
            {evaluationEvidence.map((evidence) => (
              <EvaluationEvidenceCard
                key={evidence.eventHash ?? evidence.reportHash}
                evidence={evidence}
              />
            ))}
          </div>
        </section>
      ) : null}

      {filtered.length === 0 ? (
        <EmptyState
          emptyMeans="audit-drift"
          query={query}
          label="audit events"
          onClear={() => setQuery('')}
        />
      ) : (
        <div className="audit-list">
          {filtered.map((e) => {
            const { primary, secondary } = hashParts(e.hash)
            return (
              <div className="audit-row" key={`${e.ts}-${e.hash}`}>
                <span className="ts">{e.ts}</span>
                <span className={`pill ${e.posture}`}>
                  {e.posture === 'privileged' ? 'Privileged' : e.posture}
                </span>
                <span className="ev">
                  {e.ev}
                  <span className="src">
                    {e.src}
                    {e.matter ? ` · ${e.matter}` : ''}
                  </span>
                  {e.evaluationEvidence ? (
                    <span className="src">
                      report_hash {e.evaluationEvidence.reportHash.slice(0, 19)}… ·{' '}
                      {e.evaluationEvidence.dataset}
                    </span>
                  ) : null}
                </span>
                <span className="hash-col">
                  <strong>{primary}</strong>
                  {secondary ? <span> · {secondary}</span> : null}
                </span>
              </div>
            )
          })}
        </div>
      )}

      <p className="u-mt-xl u-mono-cap-wide">
        ⁂ Append-only · every entry is countersigned by the constitutional hash 608508a9bd224290 ·
        this view is a window onto the ledger, not the ledger
      </p>
    </div>
  )
}

function EvaluationEvidenceCard({ evidence }: { evidence: EvaluationEvidence }) {
  return (
    <article className="evaluation-evidence-card">
      <div className="evaluation-evidence-head">
        <span className={`pill ${evidence.status === 'passed' ? 'confirmed' : 'blocked'}`}>
          {evidence.status}
        </span>
        <span className="evaluation-evidence-source">
          {evaluationSourceCopy(evidence.source).label}
        </span>
      </div>
      <h3>{evidence.dataset}</h3>
      <p className="evaluation-evidence-source-note">
        {evaluationSourceCopy(evidence.source).note}
      </p>
      <dl className="evaluation-evidence-metrics">
        <div>
          <dt>Scenarios</dt>
          <dd>
            {evidence.passed}/{evidence.scenarioCount} passed
          </dd>
        </div>
        <div>
          <dt>Attack success</dt>
          <dd>{formatRate(evidence.attackSuccessRate)}</dd>
        </div>
        <div>
          <dt>Utility retention</dt>
          <dd>{formatRate(evidence.utilityRetentionRate)}</dd>
        </div>
        <div>
          <dt>p95 latency</dt>
          <dd>{evidence.p95LatencyMs === null ? 'n/a' : `${evidence.p95LatencyMs} ms`}</dd>
        </div>
      </dl>
      <p className="evaluation-evidence-hash">
        <span>report_hash</span>
        <code>{evidence.reportHash}</code>
      </p>
      <p className="evaluation-evidence-policy">{evidence.policyVersion}</p>
      <p className="evaluation-evidence-claim">
        {evidence.claimSafe === false
          ? 'Not claim-safe: failed or denied report evidence.'
          : 'Claim-safe local evidence only; full upstream benchmark execution remains separately verified.'}
      </p>
    </article>
  )
}
