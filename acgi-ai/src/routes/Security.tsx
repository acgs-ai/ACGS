import type { ReactNode } from 'react'
import { navigate } from '../lib/navigate'

const SECURITY_ROWS = [
  ['Security contact', 'security@acgs.ai with security.txt metadata at /.well-known/security.txt'],
  [
    'Console CSP',
    'Configured as an enforced same-origin console policy and verified locally before deploy',
  ],
  ['Auth boundary', 'OIDC or server-cookie auth remains a production gate'],
  [
    'Live proof',
    'Header, asset, and served-hash evidence must come from the deployed console origin',
  ],
]

export function Security() {
  return (
    <div className="marketing">
      <a className="skip-link" href="#main-content">
        Skip to security content
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
              href="/trust"
              onClick={(e) => {
                e.preventDefault()
                navigate('/trust')
              }}
            >
              Trust
            </a>
            <a aria-current="page" href="/security">
              Security
            </a>
            <a
              href="/privacy"
              onClick={(e) => {
                e.preventDefault()
                navigate('/privacy')
              }}
            >
              Privacy
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
              <span>Security · Engineering draft pending live deploy evidence</span>
            </div>
            <h1 className="privacy-h1">
              Security posture with <em className="u-em-rust">proof boundaries</em>
            </h1>
            <p className="privacy-lede">
              The security page makes local controls visible without treating them as deployed
              proof. Production claims still require live headers, served-hash verification, real
              auth, CSP telemetry, and independent review.
            </p>
          </header>

          <Section folio="No. 01" title="Security contact">
            <p>
              Report suspected vulnerabilities to{' '}
              <a className="m-text-link" href="mailto:security@acgs.ai">
                security@acgs.ai
              </a>
              . Machine-readable metadata is published at{' '}
              <a className="m-text-link" href="/.well-known/security.txt">
                /.well-known/security.txt
              </a>
              .
            </p>
          </Section>

          <Section folio="No. 02" title="Local control map">
            <table className="m-coverage privacy-coverage">
              <thead>
                <tr>
                  <th>Area</th>
                  <th>Current evidence boundary</th>
                </tr>
              </thead>
              <tbody>
                {SECURITY_ROWS.map(([area, boundary]) => (
                  <tr key={area}>
                    <td>{area}</td>
                    <td>{boundary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>

          <Section folio="No. 03" title="Open gates before stronger claims">
            <ul className="privacy-evidence-list">
              <li>OIDC or server-cookie auth remains a production gate.</li>
              <li>Live Cloud Run or equivalent deploy evidence must prove headers and CSP.</li>
              <li>Third-party penetration testing is still an external vendor gate.</li>
              <li>WCAG conformance requires axe evidence plus manual NVDA and VoiceOver review.</li>
            </ul>
          </Section>
        </main>

        <footer className="m-foot">
          <div className="m-foot-inner">
            <div>
              <div className="m-foot-mark">
                acgs <em>⁂</em>
              </div>
              <p className="m-foot-addr">
                Security disclosure surface.{'\n'}Engineering draft pending live deploy evidence.
                {'\n'}
                security@acgs.ai
              </p>
            </div>
            <div>
              <h4>Disclosures</h4>
              <ul>
                <li>
                  <a href="/trust">Trust</a>
                </li>
                <li>
                  <a href="/privacy">Privacy</a>
                </li>
              </ul>
            </div>
            <div>
              <h4>Static records</h4>
              <ul>
                <li>
                  <a href="/.well-known/security.txt">security.txt</a>
                </li>
                <li>
                  <a href="/subprocessors.xml">Subprocessor RSS</a>
                </li>
              </ul>
            </div>
            <div>
              <h4>Authenticate</h4>
              <ul>
                <li>
                  <a href="/login">Sign in</a>
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
  children: ReactNode
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
