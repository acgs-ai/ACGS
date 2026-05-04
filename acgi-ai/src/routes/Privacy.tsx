import { navigate } from '../lib/navigate'

type Subprocessor = {
  name: string
  surface: 'marketing' | 'console' | 'mail'
  purpose: string
  region: string
  dpa: string
}

const SUBPROCESSORS: Subprocessor[] = [
  {
    name: 'Vercel',
    surface: 'marketing',
    purpose: 'Edge hosting for the public marketing landing only',
    region: 'global edge',
    dpa: 'vercel.com/legal/dpa',
  },
  {
    name: 'Google Cloud Platform · Cloud Run',
    surface: 'console',
    purpose: 'Operator-controlled compute for the privileged console',
    region: 'us-central1 · single region',
    dpa: 'cloud.google.com/terms/data-processing-addendum',
  },
  {
    name: "Let's Encrypt",
    surface: 'console',
    purpose: 'TLS certificate issuance via ACME',
    region: '—',
    dpa: 'letsencrypt.org/repository',
  },
  {
    name: 'Resend (or chosen mail provider)',
    surface: 'mail',
    purpose: 'Transactional email — magic-link delivery, deliberation digest',
    region: 'us · eu',
    dpa: 'provider DPA',
  },
]

export function Privacy() {
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
          <div className="m-nav-links" style={{ display: 'flex' }}>
            <a
              href="/"
              onClick={(e) => {
                e.preventDefault()
                navigate('/')
              }}
            >
              Home
            </a>
            <a
              href="/console"
              onClick={(e) => {
                e.preventDefault()
                navigate('/console')
              }}
            >
              Console
            </a>
          </div>
          <a
            href="/console"
            onClick={(e) => {
              e.preventDefault()
              navigate('/console')
            }}
            className="m-nav-cta"
          >
            Open the console
          </a>
        </nav>

        <header style={{ padding: '64px 0 40px' }}>
          <div className="m-eyebrow">
            <span className="asterism">⁂</span>
            <span>Disclosure · effective MMXXVI · v1.0</span>
          </div>
          <h1
            style={{
              fontFamily: 'var(--font-display)',
              fontWeight: 400,
              fontSize: 'clamp(48px, 6vw, 76px)',
              lineHeight: 1.0,
              letterSpacing: '-0.02em',
              marginTop: 28,
              maxWidth: '16ch',
            }}
          >
            Privacy and <em style={{ fontStyle: 'italic', color: 'var(--accent)' }}>provenance</em>
          </h1>
          <p
            style={{
              fontFamily: 'var(--font-serif)',
              fontSize: 20,
              lineHeight: 1.55,
              color: 'var(--ink-3)',
              maxWidth: '60ch',
              marginTop: 28,
            }}
          >
            Constitutional governance is a story about who is allowed to see
            what, and what gets countersigned. This page tells the same story
            about the operator behind the service. No third party touches the
            privileged console.
          </p>
        </header>

        <Section folio="No. 01" title="Subprocessors">
          <p>
            Marketing is hosted on a global edge CDN; the privileged
            console is hosted on operator-controlled compute. The split is
            structural, not stylistic — see DEPLOY.md §2.
          </p>
          <table className="m-coverage" style={{ marginTop: 24 }}>
            <thead>
              <tr>
                <th>Subprocessor</th>
                <th>Surface</th>
                <th>Purpose</th>
                <th>Region</th>
                <th>DPA</th>
              </tr>
            </thead>
            <tbody>
              {SUBPROCESSORS.map((s) => (
                <tr key={s.name}>
                  <td>{s.name}</td>
                  <td className="mono" style={{ color: 'var(--ink-2)' }}>
                    {s.surface}
                  </td>
                  <td style={{ fontFamily: 'var(--font-serif)' }}>{s.purpose}</td>
                  <td className="mono" style={{ color: 'var(--ink-3)' }}>
                    {s.region}
                  </td>
                  <td className="mono" style={{ color: 'var(--muted)' }}>
                    {s.dpa}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>

        <Section folio="No. 02" title="Data residency">
          <p>
            Console operator data sits in a single region you select at
            provisioning time. The default region is <code>us-central1</code>;
            EU-resident customers are provisioned in <code>europe-west1</code>.
            We do not silently replicate to a second region without a written
            change request.
          </p>
        </Section>

        <Section folio="No. 03" title="Retention">
          <p>
            The audit trail is append-only and retained for seven years. This
            satisfies the SR 11-7 floor and matches the HIPAA designated record
            set period. Marketing logs (visits to <em>acgs.ai</em>) roll off
            after ninety days.
          </p>
        </Section>

        <Section folio="No. 04" title="Cookies and trackers">
          <p>
            The console origin sets one cookie: a session cookie scoped to
            <code>console.acgs.ai</code>, <code>SameSite=Strict</code>, the
            <code>HttpOnly</code> and <code>Secure</code> flags both set. No
            third-party analytics, no remarketing pixels, no RUM SDK. Marketing
            sets one privacy-respecting analytics cookie when consent is given.
          </p>
        </Section>

        <Section folio="No. 05" title="Subject access and contact">
          <p>
            Data subject requests, access, deletion, portability — all routed
            to the same address. Reply within ten business days, fulfill within
            thirty.
          </p>
          <p style={{ marginTop: 16 }}>
            <strong>Data Protection Officer:</strong>{' '}
            <a className="m-text-link" href="mailto:dpo@acgs.ai">
              dpo@acgs.ai
            </a>
          </p>
        </Section>

        <p
          style={{
            margin: '64px 0',
            fontFamily: 'var(--font-mono)',
            fontSize: 11,
            color: 'var(--muted)',
            letterSpacing: '0.06em',
            textAlign: 'center',
          }}
        >
          ⁂ This document is itself versioned · v1.0 · 608508a9bd224290 ·
          {' '}MMXXVI
        </p>

        <footer className="m-foot">
          <div className="m-foot-inner">
            <div>
              <div className="m-foot-mark">
                acgs <em>⁂</em>
              </div>
              <p className="m-foot-addr">
                ACGS, Operator of constitutional governance.{'\n'}
                Reading room available by appointment.{'\n'}
                dpo@acgs.ai · sec-ops@acgs.ai
              </p>
            </div>
            <div>
              <h4>Disclosures</h4>
              <ul>
                <li>
                  <a
                    href="/privacy"
                    onClick={(e) => {
                      e.preventDefault()
                      navigate('/privacy')
                    }}
                  >
                    Privacy
                  </a>
                </li>
              </ul>
            </div>
            <div>
              <h4>Platform</h4>
              <ul>
                <li>
                  <a
                    href="/console"
                    onClick={(e) => {
                      e.preventDefault()
                      navigate('/console')
                    }}
                  >
                    Console
                  </a>
                </li>
              </ul>
            </div>
            <div>
              <h4>Authenticate</h4>
              <ul>
                <li>
                  <a
                    href="/login"
                    onClick={(e) => {
                      e.preventDefault()
                      navigate('/login')
                    }}
                  >
                    Sign in
                  </a>
                </li>
              </ul>
            </div>
          </div>
          <div className="m-foot-inner m-foot-bar">
            <span>v3.1.0 · Vol. I · MMXXVI</span>
            <span>
              hash <span className="hash">608508a9bd224290</span>
            </span>
          </div>
        </footer>
      </div>
    </div>
  )
}

function Section({
  folio,
  title,
  children,
}: {
  folio: string
  title: string
  children: React.ReactNode
}) {
  return (
    <section style={{ marginTop: 40 }}>
      <div className="m-sec-head">
        <div className="num">{folio}</div>
        <h2>{title}</h2>
      </div>
      <div
        style={{
          marginTop: 28,
          fontFamily: 'var(--font-serif)',
          fontSize: 16,
          lineHeight: 1.65,
          color: 'var(--ink-2)',
          maxWidth: '64ch',
        }}
      >
        {children}
      </div>
    </section>
  )
}
