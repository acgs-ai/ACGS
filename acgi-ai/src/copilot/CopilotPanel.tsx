import { type FormEvent, useMemo, useState } from 'react'
import { type ChatMessage, createTransport } from './transport'

/**
 * Minimal, CSP-clean governed-copilot panel.
 *
 * No inline styles, no `<style>` injection, no third-party UI: every visual is a
 * design-system class (`.copilot-*` in `src/csp-utilities.css`), so the same
 * component renders under the strict console CSP and the marketing CSP. Chat
 * transport is the thin `@ag-ui/client`; the runtime + live LLM responses are
 * Phase 2 (see docs/COPILOTKIT_FRONTEND_PLAN.md). Until then `send()` surfaces a
 * transport error inline rather than crashing.
 */
export function CopilotPanel() {
  const transport = useMemo(() => createTransport(), [])
  const [open, setOpen] = useState(false)
  const [draft, setDraft] = useState('')
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const content = draft.trim()
    if (!content || busy) return
    setDraft('')
    setError(null)
    setBusy(true)
    // Optimistically show the user's message (collision-safe id).
    const localId = globalThis.crypto?.randomUUID?.() ?? `local-${Date.now()}`
    setMessages((prev) => [...prev, { id: localId, role: 'user', content }])
    try {
      setMessages(await transport.send(content))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Copilot runtime unavailable (Phase 2).')
    } finally {
      setBusy(false)
    }
  }

  if (!open) {
    return (
      <button
        className="btn btn-primary copilot-launcher"
        type="button"
        onClick={() => setOpen(true)}
      >
        Ask the governed copilot
      </button>
    )
  }

  return (
    <section className="copilot-panel" aria-label="Governed copilot">
      <header className="copilot-head">
        <span className="u-mono-cap-accent">⁂ Governed copilot</span>
        <button className="btn btn-ghost btn-sm" type="button" onClick={() => setOpen(false)}>
          Close
        </button>
      </header>
      <ol className="copilot-log">
        {messages.map((message) => (
          <li key={message.id} className="copilot-msg">
            {message.content}
          </li>
        ))}
        {busy && (
          <li className="copilot-msg copilot-msg-pending" aria-live="polite">
            …
          </li>
        )}
        {error && (
          <li className="copilot-msg copilot-msg-error" role="alert">
            {error}
          </li>
        )}
        {messages.length === 0 && !busy && !error && (
          <li className="copilot-msg copilot-msg-pending">
            Ask about governance, policy, or receipts.
          </li>
        )}
      </ol>
      <form className="copilot-form" onSubmit={onSubmit}>
        <input
          className="copilot-input"
          type="text"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder="Message the governed copilot"
          aria-label="Message the governed copilot"
        />
        <button className="btn btn-primary btn-sm" type="submit" disabled={busy}>
          Send
        </button>
      </form>
    </section>
  )
}
