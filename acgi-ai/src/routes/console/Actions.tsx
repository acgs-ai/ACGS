import { useMemo, useState } from 'react'
import { useGovernedActions, useTestAction } from '../../api/hooks'
import type { DecisionOutcome, GovernedAction, Posture } from '../../api/types'
import type { Decision } from '../../components/governance/DecisionBadge'
import { DecisionBadge } from '../../components/governance/DecisionBadge'
import { navigate } from '../../lib/navigate'
import { track } from '../../surfaces/console/telemetry'
import {
  ConsoleError,
  ConsoleLoading,
  EmptyState,
  Receipt,
  SearchToolbar,
  useTextFilter,
} from './shared'

const actionFields = (action: GovernedAction) => [
  action.id,
  action.agent,
  action.action,
  action.target,
  action.outcome,
  action.plainReason,
  action.receiptId,
  action.traceId,
  action.auditEventId,
  ...action.checks.flatMap((check) => [check.id, check.label, check.reason]),
]

const OUTCOME_PILL: Record<DecisionOutcome, { label: string; posture: Posture }> = {
  allowed: { label: 'Allowed', posture: 'confirmed' },
  denied: { label: 'Denied', posture: 'blocked' },
  transformed: { label: 'Transformed', posture: 'privileged' },
  escalated: { label: 'Escalated', posture: 'partial' },
}

const OUTCOME_DECISION: Record<DecisionOutcome, Decision> = {
  allowed: 'ALLOW',
  denied: 'DENY',
  transformed: 'TRANSFORM',
  escalated: 'REVIEW_REQUIRED',
}

const STAT_OUTCOMES: ReadonlyArray<{ outcome: DecisionOutcome; sub: string }> = [
  { outcome: 'denied', sub: 'unsafe tool calls stopped' },
  { outcome: 'transformed', sub: 'payload changed before delivery' },
  { outcome: 'escalated', sub: 'sent to human review' },
]

type ExplainKey = 'intent' | 'reason' | 'verify'
const EXPLAIN_TITLES: Record<ExplainKey, string> = {
  intent: 'What did the agent try to do?',
  reason: 'Why did governance decide that?',
  verify: 'Can it be verified?',
}

export function Actions() {
  const [query, setQuery] = useState('')
  const [activeId, setActiveId] = useState<string | null>(null)
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const { data, isLoading, isError, refetch } = useGovernedActions()
  const testAction = useTestAction()
  const filtered = useTextFilter(data, query, actionFields)
  const active = filtered.find((action) => action.id === activeId) ?? filtered[0]
  const payload = active ? (drafts[active.id] ?? '') : ''

  const outcomeCounts = useMemo(() => {
    const counts: Record<DecisionOutcome, number> = {
      allowed: 0,
      denied: 0,
      transformed: 0,
      escalated: 0,
    }
    for (const action of data ?? []) counts[action.outcome] += 1
    return counts
  }, [data])

  if (isLoading) {
    return <ConsoleLoading label="Loading governed actions …" />
  }

  if (isError || !data) {
    return <ConsoleError onRetry={() => refetch()} />
  }

  const testActiveAction = () => {
    if (!active) return
    // Event only — no action id, agent, outcome, or payload flag crosses the
    // boundary (design §4: outcome property removed in review round 2).
    track('action_policy_test_run')
    testAction.mutate({
      actionId: active.id,
      payload: payload.trim() || active.before,
    })
  }

  return (
    <div>
      <p className="overview-intro">
        This is the action control room. Each row starts with what an agent tried to do, then shows
        the governance decision, human-readable reason, receipt, trace, replay command, and audit
        anchor. The test panel checks a proposed action before any production tool can run.
      </p>

      <div className="overview-stats">
        {STAT_OUTCOMES.map(({ outcome, sub }) => (
          <div className="overview-stat" key={outcome}>
            <div className="overview-stat-label">{OUTCOME_PILL[outcome].label}</div>
            <div className="overview-stat-value">{outcomeCounts[outcome]}</div>
            <div className="overview-stat-sub">{sub}</div>
          </div>
        ))}
      </div>

      <SearchToolbar
        value={query}
        onChange={setQuery}
        placeholder="Search agent, tool, reason, receipt, trace…"
        ariaLabel="Search governed actions"
        meta={`${filtered.length} of ${data.length} actions · no silent execution`}
      />

      {active ? (
        <div className="action-console">
          <div className="action-list">
            {filtered.map((action) => {
              const pill = OUTCOME_PILL[action.outcome]
              return (
                <button
                  key={action.id}
                  type="button"
                  className={`action-card ${action.id === active.id ? 'active' : ''}`}
                  onClick={() => setActiveId(action.id)}
                >
                  <DecisionBadge decision={OUTCOME_DECISION[action.outcome]}>
                    {pill.label}
                  </DecisionBadge>
                  <strong>{action.agent}</strong>
                  <span>
                    {action.action} → {action.target}
                  </span>
                  <code>{action.receiptId}</code>
                </button>
              )
            })}
          </div>

          <section className="action-detail" aria-labelledby="governed-action-detail">
            <div className="action-detail-head">
              <div>
                <div className="c-meta">Attempted action · {active.attemptedAt}</div>
                <h2 id="governed-action-detail">
                  {active.agent} <em>→</em> {active.action}
                </h2>
              </div>
              <DecisionBadge decision={OUTCOME_DECISION[active.outcome]}>
                {OUTCOME_PILL[active.outcome].label}
              </DecisionBadge>
            </div>

            <div className="action-explain-grid">
              {(
                [
                  ['intent', active.target],
                  ['reason', active.plainReason],
                  ['verify', `${active.receiptId} · ${active.traceId}`],
                ] satisfies ReadonlyArray<[ExplainKey, string]>
              ).map(([key, body]) => (
                <div className="action-explain-card" key={key}>
                  <span>{EXPLAIN_TITLES[key]}</span>
                  <p>{body}</p>
                </div>
              ))}
            </div>

            <div className="action-checks">
              {active.checks.map((check) => (
                <div className="action-check" key={check.id}>
                  <span className={`pill ${check.posture}`}>{check.id}</span>
                  <div>
                    <strong>{check.label}</strong>
                    <p>{check.reason}</p>
                  </div>
                </div>
              ))}
            </div>

            <div className="action-before-after">
              {(
                [
                  ['Before governance', active.before],
                  ['After governance', active.after],
                ] as const
              ).map(([label, value]) => (
                <div key={label}>
                  <span className="c-meta">{label}</span>
                  <pre>{value}</pre>
                </div>
              ))}
            </div>

            <div className="action-proof">
              {(
                [
                  ['Receipt', active.receiptHash],
                  ['Replay', active.replayCommand],
                  ['Audit event', active.auditEventId],
                ] as const
              ).map(([label, value]) => (
                <div key={label}>
                  <span className="c-meta">{label}</span>
                  <code>{value}</code>
                </div>
              ))}
            </div>

            <div className="action-proof-actions">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => navigate(`/console/audit/${encodeURIComponent(active.receiptId)}`)}
              >
                Open proof journey
              </button>
            </div>

            <div className="action-test-panel">
              <div>
                <h3>Test before execution</h3>
                <p>
                  Dry-run a payload against the same policy path. The mock console returns a receipt
                  and never executes the production tool.
                </p>
              </div>
              <textarea
                value={payload}
                onChange={(event) => {
                  const next = event.currentTarget.value
                  setDrafts((prev) => ({ ...prev, [active.id]: next }))
                }}
                placeholder={active.before}
                aria-label="Action test payload"
              />
              <button
                type="button"
                className="btn btn-primary"
                onClick={testActiveAction}
                disabled={testAction.isPending}
              >
                {testAction.isPending ? 'Testing …' : 'Run policy test'}
              </button>
              <Receipt receipt={testAction.data ?? null} />
            </div>
          </section>
        </div>
      ) : (
        <EmptyState
          emptyMeans="audit-drift"
          query={query}
          label="actions"
          onClear={() => setQuery('')}
        />
      )}
    </div>
  )
}
