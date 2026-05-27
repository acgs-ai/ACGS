import { navigate } from '../lib/navigate'

type Props = {
  /** Which surface the 404 is rendered into; controls chrome + return CTAs. */
  surface: 'marketing' | 'console'
  /** Path the user tried to reach, shown in mono. */
  path: string
}

export function NotFound({ surface, path }: Props) {
  if (surface === 'console') {
    return <NotFoundContent surface="console" path={path} />
  }

  // Marketing surface — minimal nav strip + content; no full marketing footer
  // because a 404 is not the right place to render the editorial monolith.
  return (
    <div className="marketing">
      <div className="shell">
        <nav className="m-nav">
          <a
            className="m-brand"
            href="/"
            onClick={(e) => {
              e.preventDefault()
              navigate('/')
            }}
          >
            acgs <span className="folio">⁂</span>
          </a>
          <div className="u-nav-row">
            <a
              href="/"
              onClick={(e) => {
                e.preventDefault()
                navigate('/')
              }}
              className="m-nav-cta"
            >
              Back to home
            </a>
          </div>
        </nav>

        <NotFoundContent surface="marketing" path={path} />
      </div>
    </div>
  )
}

function NotFoundContent({ surface, path }: Props) {
  // On the console surface the shell's topbar already shows the crumb
  // ("404 · path not enumerated") and the h1 ("Outside the *canon*"), so the
  // body opens directly with the lede. On marketing there is no topbar to
  // carry that work, so the eyebrow + h1 stay.
  return (
    <section className="notfound">
      {surface === 'marketing' && (
        <>
          <div className="notfound-eyebrow">
            <span className="asterism">⁂</span>
            <span>404 · path not enumerated</span>
          </div>

          <h1 className="notfound-h1">
            Outside the <em>canon</em>
          </h1>
        </>
      )}

      <p className="notfound-lede">
        The constitution does not enumerate this path. Either the link is older than the canon you
        are reading, or someone is fishing.
      </p>

      <div className="notfound-trace">
        <div className="notfound-trace-row">
          <span className="k">requested</span>
          <span className="v">{path || '/'}</span>
        </div>
        <div className="notfound-trace-row">
          <span className="k">surface</span>
          <span className="v">{surface}</span>
        </div>
        <div className="notfound-trace-row">
          <span className="k">hash</span>
          <span className="v">608508a9bd224290</span>
        </div>
      </div>

      <div className="notfound-actions">
        {surface === 'marketing' ? (
          <>
            <button className="btn btn-primary" type="button" onClick={() => navigate('/')}>
              Back to home
            </button>
            <button
              className="btn btn-secondary"
              type="button"
              onClick={() => navigate('/console')}
            >
              Open the console
            </button>
          </>
        ) : (
          <>
            <button className="btn btn-primary" type="button" onClick={() => navigate('/console')}>
              Back to overview
            </button>
            <button
              className="btn btn-secondary"
              type="button"
              onClick={() => navigate('/console/audit')}
            >
              Audit trail
            </button>
          </>
        )}
      </div>
    </section>
  )
}
