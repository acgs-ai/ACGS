import type { ReactNode } from 'react'
import { navigate } from '../lib/navigate'

const TRUST_CARDS = [
  {
    title: 'DPA draft',
    body: 'The data-processing addendum posture is published as an engineering draft pending legal review. It points buyers to the intended subprocessors, regions, retention posture, and operator contact without treating the draft as a signed agreement.',
    link: '/privacy',
    linkText: 'Read privacy and subprocessors',
  },
  {
    title: 'SOC 2 roadmap',
    body: 'SOC 2 language is roadmap and control-mapping language only. It does not state attestation, certification, or compliance; the claim matrix keeps public wording blocked until independent evidence exists.',
    link: '/security',
    linkText: 'Read security posture',
  },
  {
    title: 'Subprocessor change feed',
    body: 'The RSS feed records intended public disclosure changes so operators can subscribe before production launch. The first entry is an engineering-draft baseline, not legal signoff.',
    link: '/subprocessors.xml',
    linkText: 'Open RSS feed',
  },
]

export function Trust() {
  return (
    <div className="marketing">
      <a className="skip-link" href="#main-content">
        Skip to trust content
      </a>
      <div className="shell">
        <DisclosureNav current="trust" />

        <main id="main-content" tabIndex={-1}>
          <header className="privacy-header">
            <div className="m-eyebrow">
              <span className="asterism">⁂</span>
              <span>Trust center · Engineering draft pending legal review</span>
            </div>
            <h1 className="privacy-h1">
              Trust artifacts, <em className="u-em-rust">without overclaiming</em>
            </h1>
            <p className="privacy-lede">
              This page publishes the local trust-center scaffolding required before a public
              launch: DPA draft pointers, SOC 2 roadmap wording, a subprocessor change feed, and the
              security contact surface. Legal review, live deployment proof, and third-party
              evidence remain explicit gates before public compliance or production-readiness
              claims.
            </p>
          </header>

          <Section folio="No. 01" title="Buyer evidence index">
            <div className="trust-card-grid">
              {TRUST_CARDS.map((card) => (
                <article className="trust-card" key={card.title}>
                  <h3>{card.title}</h3>
                  <p>{card.body}</p>
                  <a className="m-text-link" href={card.link}>
                    {card.linkText}
                  </a>
                </article>
              ))}
            </div>
          </Section>

          <Section folio="No. 02" title="Claim status">
            <table className="m-coverage privacy-coverage">
              <thead>
                <tr>
                  <th>Claim area</th>
                  <th>Current public wording</th>
                  <th>Gate before stronger wording</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>SOC 2 roadmap</td>
                  <td>Roadmap and control mapping only</td>
                  <td>Independent attestation evidence plus legal approval</td>
                </tr>
                <tr>
                  <td>Subprocessor disclosure</td>
                  <td>Engineering draft pending legal review</td>
                  <td>Live environment inventory plus legal signoff</td>
                </tr>
                <tr>
                  <td>Security posture</td>
                  <td>Local config and verifier evidence</td>
                  <td>Live header proof, pentest report, and incident-response owner</td>
                </tr>
              </tbody>
            </table>
          </Section>

          <Section folio="No. 03" title="Published files">
            <p>
              Security contact metadata is available at{' '}
              <a className="m-text-link" href="/.well-known/security.txt">
                /.well-known/security.txt
              </a>
              . Subprocessor changes are published at{' '}
              <a className="m-text-link" href="/subprocessors.xml">
                /subprocessors.xml
              </a>
              . Both are local publication artifacts; stronger public claims still require the claim
              matrix to move out of engineering-draft status.
            </p>
          </Section>
        </main>

        <DisclosureFooter />
      </div>
    </div>
  )
}

function DisclosureNav({ current }: { current: 'trust' | 'security' }) {
  return (
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
          aria-current={current === 'trust' ? 'page' : undefined}
          href="/trust"
          onClick={(e) => {
            e.preventDefault()
            navigate('/trust')
          }}
        >
          Trust
        </a>
        <a
          aria-current={current === 'security' ? 'page' : undefined}
          href="/security"
          onClick={(e) => {
            e.preventDefault()
            navigate('/security')
          }}
        >
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

function DisclosureFooter() {
  return (
    <footer className="m-foot">
      <div className="m-foot-inner">
        <div>
          <div className="m-foot-mark">
            acgs <em>⁂</em>
          </div>
          <p className="m-foot-addr">
            ACGS trust center.{'\n'}Engineering draft pending legal review.{'\n'}security@acgs.ai ·
            dpo@acgs.ai
          </p>
        </div>
        <div>
          <h4>Disclosures</h4>
          <ul>
            <li>
              <a href="/trust">Trust</a>
            </li>
            <li>
              <a href="/security">Security</a>
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
  )
}
