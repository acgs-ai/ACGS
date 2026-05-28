import { useActionProof } from '../../api/hooks'
import { navigate } from '../../lib/navigate'
import { ConsoleError, ConsoleLoading } from './shared'

type AuditProofProps = {
  receiptId: string
}

function executionCopy(toolExecuted: boolean): string {
  return toolExecuted ? '"tool_executed":true' : '"tool_executed":false'
}

function downloadSignedEvidencePacket(receiptId: string, packet: string): void {
  const blob = new Blob([packet], { type: 'application/json' })
  const href = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = href
  link.download = `${receiptId}-signed-evidence-packet.json`
  link.click()
  URL.revokeObjectURL(href)
}

export function AuditProof({ receiptId }: AuditProofProps) {
  const proof = useActionProof(receiptId)

  if (proof.isLoading) {
    return <ConsoleLoading label="Loading receipt proof …" />
  }

  if (proof.isError || !proof.data) {
    return <ConsoleError onRetry={() => proof.refetch()} />
  }

  const { data } = proof
  const action = data.action
  const signature = data.evidenceSignature
  const proofFields = [
    ['Receipt hash', data.receiptHash],
    ['Trace', data.traceId],
    ...(data.phoenixTraceId ? ([['Phoenix trace', data.phoenixTraceId]] as const) : []),
    ...(data.phoenixSpanId ? ([['Phoenix span', data.phoenixSpanId]] as const) : []),
    ...(data.phoenixParentSpanId
      ? ([['Phoenix parent span', data.phoenixParentSpanId]] as const)
      : []),
    ['Replay', data.replayCommand],
    ['Audit event', data.auditEventId],
  ] as const

  return (
    <div>
      <p className="overview-intro">
        Receipt proof loads one governed action, verifies the hash chain, shows the policy path,
        action, before/after state, and exports the signed evidence packet an auditor can replay.
      </p>

      <section className="action-detail receipt-proof" aria-labelledby="receipt-proof-title">
        <div className="action-detail-head">
          <div>
            <div className="c-meta">Receipt proof · {data.receiptId}</div>
            <h2 id="receipt-proof-title">
              {action.agent} <em>→</em> {action.action}
            </h2>
          </div>
          <span className={`pill ${data.hashChainVerified ? 'confirmed' : 'blocked'}`}>
            {data.hashChainVerified ? 'Hash chain verified' : 'Hash chain failed'}
          </span>
        </div>

        <div className="action-explain-grid">
          <div className="action-explain-card">
            <span>Signature status</span>
            <p>
              {signature.label} · {signature.algorithm}
            </p>
          </div>
          <div className="action-explain-card">
            <span>Key id</span>
            <p>{signature.keyId ?? 'No deployment key id published'}</p>
          </div>
          <div className="action-explain-card">
            <span>Policy path</span>
            <p>{data.policyPath}</p>
          </div>
          <div className="action-explain-card">
            <span>Action target</span>
            <p>{action.target}</p>
          </div>
          <div className="action-explain-card">
            <span>No silent execution</span>
            <p>
              {executionCopy(data.toolExecuted)} · side effect status is recorded inside the signed
              evidence packet.
            </p>
          </div>
        </div>

        <div className="action-proof receipt-proof-grid">
          {proofFields.map(([label, value]) => (
            <div key={label}>
              <span className="c-meta">{label}</span>
              <code>{value}</code>
            </div>
          ))}
        </div>

        <div className="action-before-after">
          <div>
            <span className="c-meta">Before governance</span>
            <pre>{action.before}</pre>
          </div>
          <div>
            <span className="c-meta">After governance</span>
            <pre>{action.after}</pre>
          </div>
        </div>

        <div className="receipt-proof-packet">
          <div>
            <span className="c-meta">Export signed evidence packet</span>
            <h3>signed evidence packet</h3>
            <p>
              Copy this packet into an offline replay or reviewer handoff. Signature metadata is
              parsed above; cryptographic validation still happens in the verifier using deployment
              signing material.
            </p>
            {signature.digest ? <p className="c-meta">Digest: {signature.digest}</p> : null}
            {signature.reason ? <p className="c-meta">Note: {signature.reason}</p> : null}
          </div>
          <pre>{data.signedEvidencePacket}</pre>
        </div>

        <div className="action-proof-actions">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => navigate('/console/audit')}
          >
            Back to audit trail
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => downloadSignedEvidencePacket(data.receiptId, data.signedEvidencePacket)}
          >
            Download evidence packet
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => navigate('/console/actions')}
          >
            Inspect action
          </button>
        </div>
      </section>
    </div>
  )
}
