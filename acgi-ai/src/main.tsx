import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { ErrorBoundary, type FallbackProps } from 'react-error-boundary'
import App from './App.tsx'
import './index.css'
import { navigate } from './lib/navigate'
import { hasSession } from './lib/session'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 5_000,
      refetchOnWindowFocus: false,
    },
  },
})

async function enableMocks(): Promise<void> {
  if (import.meta.env.VITE_USE_MOCKS !== 'true') return
  try {
    const { worker } = await import('./mocks/browser')
    await worker.start({ onUnhandledRequest: 'bypass' })
  } catch (error) {
    console.error('ACGS mock worker failed to start; mounting without mocks.', error)
  }
}

function AppErrorFallback({ resetErrorBoundary }: FallbackProps) {
  const canReturnToConsole = hasSession()
  const go = (path: string) => {
    resetErrorBoundary()
    navigate(path)
  }

  return (
    <main className="app-error" role="alert">
      <div className="app-error-banner">
        <span>⁂ Privilege boundary preserved · interface fault contained</span>
        <span>608508a9bd224290</span>
      </div>
      <section className="app-error-panel">
        <div className="login-eyebrow">
          <span className="asterism">⁂</span>
          <span>Runtime exception · no dispatch emitted</span>
        </div>
        <h1 className="login-h1">
          The interface <em>held</em>
        </h1>
        <p className="login-lede">
          A rendering fault was contained before the console shell could blank the constitutional
          boundary. Return to a stable surface and retry the route after the bus refreshes.
        </p>
        <div className="app-error-actions">
          <button className="btn btn-primary" type="button" onClick={() => go('/')}>
            Return home
          </button>
          {canReturnToConsole && (
            <button className="btn btn-secondary" type="button" onClick={() => go('/console')}>
              Return to console
            </button>
          )}
        </div>
      </section>
    </main>
  )
}

const rootElement = document.getElementById('root')

if (!rootElement) {
  throw new Error('Root element not found')
}

void enableMocks().then(() => {
  createRoot(rootElement).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <ErrorBoundary FallbackComponent={AppErrorFallback}>
          <App />
        </ErrorBoundary>
      </QueryClientProvider>
    </StrictMode>,
  )
})
