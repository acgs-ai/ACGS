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
      <a className="skip-link" href="#main-content">
        Skip to privacy content
      </a>
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
          <div className="m-nav-links">
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

        <main id="main-content" tabIndex={-1}>
          <header className="privacy-header">
            <div className="m-eyebrow">
              <span className="asterism">⁂</span>
              <span>Disclosure · effective MMXXVI · v1.0</span>
            </div>
            <h1 className="privacy-h1">
              Privacy and <em className="u-em-rust">provenance</em>
            </h1>
            <p className="privacy-lede">
              Constitutional governance is a story about who is allowed to see what, and what gets
              countersigned. This page tells the same story about the operator behind the service.
              The deployment contract separates public marketing from the privileged console; live
              subprocessor wording still requires legal review.
            </p>
          </header>

          <Section folio="No. 01" title="Subprocessors">
            <p>
              Marketing is hosted on a global edge CDN; the privileged console is hosted on
              operator-controlled compute. The split is structural, not stylistic — see DEPLOY.md
              §2. Subprocessor disclosure changes are published as an engineering-draft RSS feed at{' '}
              <a className="m-text-link" href="/subprocessors.xml">
                /subprocessors.xml
              </a>
              .
            </p>
            <table className="m-coverage privacy-coverage">
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
                    <td className="mono u-color-ink-2">{s.surface}</td>
                    <td className="privacy-purpose-cell">{s.purpose}</td>
                    <td className="mono u-color-ink-3">{s.region}</td>
                    <td className="mono u-color-muted">{s.dpa}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>

          <Section folio="No. 02" title="Data residency">
            <p>
              Console operator data sits in a single region you select at provisioning time. The
              default region is <code>us-central1</code>; EU-resident customers are provisioned in{' '}
              <code>europe-west1</code>. We do not silently replicate to a second region without a
              written change request.
            </p>
          </Section>

          <Section folio="No. 03" title="Retention">
            <p>
              The audit trail target is append-only retention for seven years, aligned to regulated
              recordkeeping expectations such as SR 11-7 and HIPAA designated-record-set periods.
              Production retention proof requires the live storage policy; marketing logs (visits to{' '}
              <em>acgs.ai</em>) target a ninety-day rolloff.
            </p>
          </Section>

          <Section folio="No. 04" title="Cookies and trackers">
            <p>
              The target console origin uses a server-owned session cookie scoped to
              <code>console.acgs.ai</code>, <code>SameSite=Strict</code>, with the
              <code>HttpOnly</code> and <code>Secure</code> flags both set. The local production
              bundle blocks the demo session path until that provider-backed session layer exists.
              Marketing analytics remain consent-gated.
            </p>
          </Section>

          <Section folio="No. 05" title="Subject access and contact">
            <p>
              Data subject requests, access, deletion, portability — all routed to the same address.
              Reply within ten business days, fulfill within thirty.
            </p>
            <p className="u-mt-lg">
              <strong>Data Protection Officer:</strong>{' '}
              <a className="m-text-link" href="mailto:dpo@acgs.ai">
                dpo@acgs.ai
              </a>
            </p>
          </Section>

          <p className="privacy-version-stamp">
            ⁂ This document is itself versioned · v1.0 · 608508a9bd224290 · MMXXVI
          </p>
        </main>

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
    <section className="privacy-section">
      <div className="m-sec-head">
        <div className="num">{folio}</div>
        <h2>{title}</h2>
      </div>
      <div className="privacy-section-body">{children}</div>
    </section>
  )
}
