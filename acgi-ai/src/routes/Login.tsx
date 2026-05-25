import { ArrowRight } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { navigate } from '../lib/navigate'
import { hasSession } from '../lib/session'
import { CONSTITUTION_HASH } from './console/shared'

type Provider = {
  id: 'google' | 'entra' | 'okta'
  label: string
  hint: string
}

type LoginInterstitial = {
  provider: Provider
  matter: string
  startedAt: number
  ready: boolean
  queuedDismiss: boolean
}

const PROVIDERS: Provider[] = [
  { id: 'google', label: 'Continue with Google Workspace', hint: 'sso.google.com' },
  { id: 'entra', label: 'Continue with Microsoft Entra', hint: 'login.microsoftonline.com' },
  { id: 'okta', label: 'Continue with Okta', hint: 'sso.okta.com' },
]

const LOGIN_INTERSTITIAL_MIN_MS = 800
const LOGIN_OPERATOR = 'custodian-01'

function isConsolePath(path: string): boolean {
  return path === '/console' || path.startsWith('/console/') || path.startsWith('/console?')
}

function nextConsolePath(fallback: string | undefined): string {
  const safeFallback = fallback && isConsolePath(fallback) ? fallback : '/console'
  if (typeof window === 'undefined') return safeFallback
  const next = new URLSearchParams(window.location.search).get('next')
  return next && isConsolePath(next) ? next : safeFallback
}

function describeConsoleMatter(path: string): string {
  const routeOnly = path.split(/[?#]/)[0] ?? '/console'
  const section = routeOnly
    .replace(/^\/console\/?/, '')
    .split('/')
    .filter(Boolean)
    .join(' / ')
  return section ? `console ${section} matter` : 'console overview matter'
}

export function Login({ nextPath }: { nextPath?: string }) {
  const [pending, setPending] = useState<Provider['id'] | null>(null)
  const [ssoError, setSsoError] = useState<string | null>(null)
  const [email, setEmail] = useState('')
  const [magicQueued, setMagicQueued] = useState(false)
  const [loginInterstitial, setLoginInterstitial] = useState<LoginInterstitial | null>(null)
  const loginInterstitialRef = useRef<LoginInterstitial | null>(null)
  const dismissButtonRef = useRef<HTMLButtonElement | null>(null)
  const timeoutRef = useRef<number | null>(null)
  const isBusy = pending !== null || loginInterstitial !== null

  // Authenticated users do not need to see the entrance ritual again.
  useEffect(() => {
    if (hasSession()) {
      navigate(nextConsolePath(nextPath))
    }
  }, [nextPath])

  useEffect(() => {
    loginInterstitialRef.current = loginInterstitial
  }, [loginInterstitial])

  // Clear the pending timeout if the user navigates away or unmounts.
  // Otherwise a deferred auth-status update could yank a user who clicked the
  // brand or pressed the back button mid-redirect.
  useEffect(() => {
    return () => {
      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current)
      }
    }
  }, [])

  useEffect(() => {
    if (!loginInterstitial) return
    dismissButtonRef.current?.focus()
  }, [loginInterstitial])

  const finishSsoAttempt = useCallback((provider: Provider) => {
    setPending(provider.id)
    timeoutRef.current = window.setTimeout(() => {
      timeoutRef.current = null
      setPending(null)
      setSsoError(
        `${provider.label} is not yet configured. Contact your administrator to provision SSO access.`,
      )
    }, 150)
  }, [])

  const completeInterstitial = useCallback(
    function completeInterstitial() {
      const current = loginInterstitialRef.current
      if (!current) return
      if (!current.ready) {
        setLoginInterstitial({ ...current, queuedDismiss: true })
        return
      }
      setLoginInterstitial(null)
      finishSsoAttempt(current.provider)
    },
    [finishSsoAttempt],
  )

  useEffect(() => {
    if (!loginInterstitial) return

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Enter') {
        event.preventDefault()
        completeInterstitial()
      }
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [loginInterstitial, completeInterstitial])

  useEffect(() => {
    if (loginInterstitial?.ready && loginInterstitial.queuedDismiss) {
      completeInterstitial()
    }
  }, [loginInterstitial, completeInterstitial])

  function go(p: Provider) {
    // SSO redirect URLs are not yet wired. Do NOT grant access here; production
    // admission belongs to a real IdP callback or server-issued console cookie.
    if (timeoutRef.current !== null) {
      window.clearTimeout(timeoutRef.current)
      timeoutRef.current = null
    }
    setSsoError(null)
    setMagicQueued(false)
    setPending(null)
    const matter = describeConsoleMatter(nextConsolePath(nextPath))
    setLoginInterstitial({
      provider: p,
      matter,
      startedAt: Date.now(),
      ready: false,
      queuedDismiss: false,
    })
    timeoutRef.current = window.setTimeout(() => {
      timeoutRef.current = null
      setLoginInterstitial((current) => (current ? { ...current, ready: true } : current))
    }, LOGIN_INTERSTITIAL_MIN_MS)
  }

  return (
    <div className="login">
      <a className="skip-link" href="#main-content">
        Skip to sign-in content
      </a>
      <div className="login-banner" role="note">
        <span>⁂ Privilege boundary · authentication is the entrance</span>
        <span>{CONSTITUTION_HASH}</span>
      </div>

      <main id="main-content" className="login-shell" tabIndex={-1}>
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
              disabled={isBusy}
            >
              <span className="login-provider-mark">{p.id.charAt(0).toUpperCase()}</span>
              <span className="login-provider-label">{p.label}</span>
              <span className="login-provider-hint">{p.hint}</span>
              <ArrowRight size={15} strokeWidth={1.8} />
            </button>
          ))}
        </div>

        {loginInterstitial && (
          <section className="login-interstitial" role="status" aria-live="polite">
            <div className="login-interstitial-eyebrow">Parchment handoff</div>
            <h2>Entering the governed console</h2>
            <dl className="login-interstitial-grid">
              <div>
                <dt>Operator</dt>
                <dd>{LOGIN_OPERATOR}</dd>
              </div>
              <div>
                <dt>Matter</dt>
                <dd>{loginInterstitial.matter}</dd>
              </div>
              <div>
                <dt>Constitution</dt>
                <dd>{CONSTITUTION_HASH}</dd>
              </div>
              <div>
                <dt>Provider</dt>
                <dd>{loginInterstitial.provider.label}</dd>
              </div>
            </dl>
            <p>
              This minimum {LOGIN_INTERSTITIAL_MIN_MS}ms pause makes the privilege boundary visible
              before any identity-provider handoff. Production entry still requires the external SSO
              callback.
            </p>
            <time dateTime={new Date(loginInterstitial.startedAt).toISOString()}>
              Handoff recorded locally for this browser route.
            </time>
            <button
              ref={dismissButtonRef}
              type="button"
              className="m-text-link login-interstitial-dismiss"
              onClick={completeInterstitial}
            >
              {loginInterstitial.ready
                ? 'continue to provider status'
                : 'continue after parchment hold'}
            </button>
          </section>
        )}

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
              disabled={isBusy}
              required
            />
            <button type="submit" className="m-text-link" disabled={isBusy || email.trim() === ''}>
              send a magic link
            </button>
          </form>
        </div>

        {pending && (
          <p className="login-pending" role="status" aria-live="polite">
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
          <span className="hash">{CONSTITUTION_HASH}</span>
        </div>
      </main>
    </div>
  )
}
