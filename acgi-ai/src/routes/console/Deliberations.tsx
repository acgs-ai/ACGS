import type { ReactNode } from 'react'
import { useDeliberations } from '../../api/hooks'

function renderTitle(title: string, emphasis: string): ReactNode {
  const idx = title.toLowerCase().indexOf(emphasis.toLowerCase())
  if (idx === -1) return title
  return (
    <>
      {title.slice(0, idx)}
      <em>{title.slice(idx, idx + emphasis.length)}</em>
      {title.slice(idx + emphasis.length)}
    </>
  )
}

export function Deliberations() {
  const { data, isLoading, isError, refetch } = useDeliberations()

  if (isLoading) {
    return (
      <div className="c-toolbar">
        <span className="c-meta">⁂ Polling …</span>
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div className="c-toolbar">
        <span className="c-meta">
          ⁂ Could not reach the bus.{' '}
          <button type="button" className="m-text-link" onClick={() => refetch()}>
            Retry
          </button>
        </span>
      </div>
    )
  }

  return (
    <div>
      <div className="c-toolbar">
        <input
          className="c-search"
          placeholder="Search by matter, citation, posture…"
          aria-label="Search deliberations"
        />
        <span className="c-meta">3 open · oldest 13:32 UTC · SLA 8h</span>
      </div>

      <div className="delib-list">
        {data.map((d) => (
          <article className="delib-card" key={d.id}>
            <div>
              <h4>{renderTitle(d.title, d.emphasis)}</h4>
              <div className="meta">
                <span>{d.id}</span>
                <span>{d.matter}</span>
                <span>{d.citation}</span>
                <span>opened {d.opened.split(' ')[1]}</span>
                <span>due {d.due.split(' ')[1]}</span>
              </div>
              <p className="body">{d.body}</p>
              <div className="u-row-mt-md">
                <span className={`pill ${d.posture}`}>
                  {d.posture === 'privileged' ? 'Privileged' : d.posture}
                </span>
                <span className="u-mono-cap">608508a9 · attest required</span>
              </div>
            </div>
            <div className="delib-card-actions">
              <button className="btn btn-rust" type="button">
                Approve
              </button>
              <button className="btn btn-secondary" type="button">
                Hold
              </button>
              <button className="btn btn-ghost" type="button">
                Refuse
              </button>
            </div>
          </article>
        ))}
      </div>
    </div>
  )
}
