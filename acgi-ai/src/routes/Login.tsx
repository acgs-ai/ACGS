import { ArrowRight } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { navigate } from '../lib/navigate'
import { hasSession } from '../lib/session'
import { CONSTITUTION_HASH } from './console/shared'

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

function nextConsolePath(fallback: string | undefined): string {
  const safeFallback = fallback?.startsWith('/console') ? fallback : '/console'
  if (typeof window === 'undefined') return safeFallback
  const next = new URLSearchParams(window.location.search).get('next')
  return next?.startsWith('/console') ? next : safeFallback
}

export function Login({ nextPath }: { nextPath?: string }) {
  const [pending, setPending] = useState<Provider['id'] | null>(null)
  const [ssoError, setSsoError] = useState<string | null>(null)
  const [email, setEmail] = useState('')
  const [magicQueued, setMagicQueued] = useState(false)
  const timeoutRef = useRef<number | null>(null)

  // Authenticated users do not need to see the entrance ritual again.
  useEffect(() => {
    if (hasSession()) {
      navigate(nextConsolePath(nextPath))
    }
  }, [nextPath])

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
    // SSO redirect URLs are not yet wired. Do NOT grant access here —
    // createSession() must only be called after a real IdP callback confirms
    // identity. Show a clear error instead of fake-granting privilege.
    setSsoError(null)
    setPending(p.id)
    timeoutRef.current = window.setTimeout(() => {
      timeoutRef.current = null
      setPending(null)
      setSsoError(
        `${p.label} is not yet configured. Contact your administrator to provision SSO access.`,
      )
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
          <form
            className="login-magic-form"
            onSubmit={(e) => {
              e.preventDefault()
              setMagicQueued(true)
            }}
          >
            <input
              className="login-magic-input"
              type="email"
              value={email}
              onChange={(e) => {
                setEmail(e.currentTarget.value)
                setMagicQueued(false)
              }}
              placeholder="verified@example.com"
              aria-label="Verified email address"
              disabled={pending !== null}
              required
            />
            <button
              type="submit"
              className="m-text-link"
              disabled={pending !== null || email.trim() === ''}
            >
              send a magic link
            </button>
          </form>
        </div>

        {pending && (
          <p className="login-pending">
            Redirecting to <strong>{pending}</strong>…
          </p>
        )}
        {ssoError && (
          <p className="login-error" role="alert">
            {ssoError}
          </p>
        )}
        {magicQueued && (
          <p className="login-pending" role="status" aria-live="polite">
            Magic link queued locally for <strong>{email}</strong> · {CONSTITUTION_HASH}
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
