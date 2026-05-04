import { ArrowRight } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { navigate } from '../lib/navigate'

type Provider = {
  id: 'google' | 'entra' | 'okta'
  label: string
  hint: string
}

const PROVIDERS: Provider[] = [
  { id: 'google', label: 'Continue with Google Workspace', hint: 'sso.google.com' },
  { id: 'entra', label: 'Continue with Microsoft Entra', hint: 'login.microsoftonline.com' },
  { id: 'okta', label: 'Continue with Okta', hint: 'sso.okta.com' },
]

export function Login() {
  const [pending, setPending] = useState<Provider['id'] | null>(null)
  const timeoutRef = useRef<number | null>(null)

  // Clear the pending timeout if the user navigates away or unmounts.
  // Otherwise the deferred navigate('/console') would yank a user who
  // clicked the brand or pressed the back button mid-redirect.
  useEffect(() => {
    return () => {
      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current)
      }
    }
  }, [])

  function go(p: Provider) {
    setPending(p.id)
    // No real handler yet — wire to your IdP redirect URL when SSO lands.
    // For now, simulate a brief lag and route into the console.
    timeoutRef.current = window.setTimeout(() => {
      timeoutRef.current = null
      navigate('/console')
    }, 600)
  }

  return (
    <div className="login">
      <div className="login-banner" role="note">
        <span>⁂ Privilege boundary · authentication is the entrance</span>
        <span>608508a9bd224290</span>
      </div>

      <main className="login-shell">
        <a
          className="login-brand"
          href="/"
          onClick={(e) => {
            e.preventDefault()
            navigate('/')
          }}
        >
          acgs <span className="folio">⁂</span>
        </a>

        <div className="login-eyebrow">
          <span className="asterism">⁂</span>
          <span>Authenticate · attest · enter</span>
        </div>

        <h1 className="login-h1">
          Authenticate to <em>enter</em>
        </h1>

        <p className="login-lede">
          Every dispatch on the bus is countersigned by the constitution and by the agent that
          proposed it. The same applies to humans: identify yourself before you are admitted to the
          privileged surface.
        </p>

        <div className="login-providers">
          {PROVIDERS.map((p) => (
            <button
              key={p.id}
              type="button"
              className="login-provider"
              onClick={() => go(p)}
              disabled={pending !== null}
            >
              <span className="login-provider-mark">{p.id.charAt(0).toUpperCase()}</span>
              <span className="login-provider-label">{p.label}</span>
              <span className="login-provider-hint">{p.hint}</span>
              <ArrowRight size={15} strokeWidth={1.8} />
            </button>
          ))}
        </div>

        <div className="login-fallback">
          <span>or</span>
          <button type="button" className="m-text-link" disabled={pending !== null}>
            send a magic link to a verified address
          </button>
        </div>

        {pending && (
          <p className="login-pending">
            Redirecting to <strong>{pending}</strong>…
          </p>
        )}

        <div className="login-foot">
          <span>v3.1.0 · Vol. I · MMXXVI</span>
          <span className="hash">608508a9bd224290</span>
        </div>
      </main>
    </div>
  )
}
