type Change = 'added' | 'amended' | 'removed'

type RuleChange = {
  id: string
  name: string
  citation: string
  change: Change
  note: string
}

const CURRENT_HASH = '608508a9bd224290'
const PROPOSED_HASH = '4c1f7e8a92b3d501'

const CHANGES: RuleChange[] = [
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
]

const COUNTS: Record<Change, number> = { added: 0, amended: 0, removed: 0 }
for (const c of CHANGES) COUNTS[c.change] += 1

export function Compile() {
  return (
    <div>
      <p
        style={{
          fontFamily: 'var(--font-serif)',
          fontSize: 17,
          lineHeight: 1.65,
          color: 'var(--ink-2)',
          maxWidth: '64ch',
        }}
      >
        Seven proposed amendments are staged against the canon. Promotion compiles a new
        constitution, signs it with a fresh hash, and replays the SR 11-7 conformance set before any
        agent on the bus is allowed to dispatch under the new rule.
      </p>

      <div
        style={{
          marginTop: 32,
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: 1,
          background: 'var(--line-softer)',
          border: '1px solid var(--line-softer)',
          borderRadius: 8,
          overflow: 'hidden',
        }}
      >
        <Stat label="Added" value={COUNTS.added} marker="added" />
        <Stat label="Amended" value={COUNTS.amended} marker="amended" />
        <Stat label="Removed" value={COUNTS.removed} marker="removed" />
      </div>

      <div className="compile-hash">
        <div className="col">
          <span className="label">Canon · v3.1.0</span>
          <span className="hash">{CURRENT_HASH}</span>
          <span
            className="label"
            style={{ color: 'var(--ink-3)', textTransform: 'none', letterSpacing: '0.04em' }}
          >
            signed 2026-04-29 · 1,402 refusals carried
          </span>
        </div>
        <span className="arrow" aria-hidden>
          →
        </span>
        <div className="col">
          <span className="label">Proposed · v3.2.0-rc</span>
          <span className="hash">{PROPOSED_HASH}</span>
          <span
            className="label"
            style={{ color: 'var(--ink-3)', textTransform: 'none', letterSpacing: '0.04em' }}
          >
            unsigned · awaits Validator-attested replay
          </span>
        </div>
      </div>

      <div className="compile-changes">
        <div className="c-toolbar">
          <strong style={{ fontFamily: 'var(--font-display)', fontSize: 22, fontWeight: 400 }}>
            Pending <em style={{ fontStyle: 'italic', color: 'var(--accent)' }}>amendments</em>
          </strong>
          <span className="c-meta">7 changes · 5 articles touched</span>
        </div>
        <table className="c-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Rule</th>
              <th>Citation</th>
              <th>Change</th>
              <th>Note</th>
            </tr>
          </thead>
          <tbody>
            {CHANGES.map((c) => (
              <tr key={c.id}>
                <td className="mono">{c.id}</td>
                <td>
                  <strong style={{ fontWeight: 600 }}>{c.name}</strong>
                </td>
                <td className="mono" style={{ color: 'var(--ink-2)' }}>
                  {c.citation}
                </td>
                <td>
                  <span className={`change-marker ${c.change}`}>{c.change}</span>
                </td>
                <td
                  style={{ color: 'var(--ink-3)', fontFamily: 'var(--font-serif)', fontSize: 14 }}
                >
                  {c.note}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="compile-actions">
        <button className="btn btn-rust" type="button">
          Promote to canon
        </button>
        <button className="btn btn-secondary" type="button">
          Replay conformance set
        </button>
        <button className="btn btn-ghost" type="button">
          Discard
        </button>
        <span className="attest">
          {PROPOSED_HASH} · attest required · two reviewers, one custodian
        </span>
      </div>

      <p
        style={{
          marginTop: 28,
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
          color: 'var(--muted)',
          letterSpacing: '0.06em',
        }}
      >
        ⁂ No compile ships without a Validator-attested replay · the bus refuses to load a
        constitution whose hash it cannot verify against the maintainer signature
      </p>
    </div>
  )
}

function Stat({ label, value, marker }: { label: string; value: number; marker: Change }) {
  return (
    <div style={{ background: 'var(--paper-2)', padding: '24px 24px 22px' }}>
      <div className={`change-marker ${marker}`}>{label}</div>
      <div
        style={{
          marginTop: 14,
          fontFamily: 'var(--font-display)',
          fontSize: 44,
          fontWeight: 400,
          letterSpacing: '-0.01em',
          color: 'var(--ink)',
          fontVariantNumeric: 'tabular-nums',
        }}
      >
        {value}
      </div>
      <div
        style={{
          marginTop: 8,
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
          color: 'var(--muted)',
          letterSpacing: '0.04em',
        }}
      >
        rules · v3.2.0-rc
      </div>
    </div>
  )
}
