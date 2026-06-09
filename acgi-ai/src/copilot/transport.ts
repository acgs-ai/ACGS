import { HttpAgent } from '@ag-ui/client'

/**
 * Thin AG-UI transport to the same-origin CopilotKit runtime.
 *
 * We deliberately depend on `@ag-ui/client` (the lightweight AG-UI protocol
 * client, ~tens of KB) and NOT on any CopilotKit browser package: those pull
 * katex/markdown/Radix (~3.3 MB) and blow the locked 200 KiB marketing budget +
 * the strict console CSP. See `docs/COPILOTKIT_FRONTEND_PLAN.md` and
 * the memory note `acgs-copilotkit-frontend-incompatible`.
 *
 * `HttpAgent` connects to a same-origin runtime URL (`connect-src 'self'`). The
 * runtime route (`/api/copilotkit`, `@copilotkit/runtime` server-side) and the
 * LLM provider key are Phase 2 — until then `send()` will surface a transport
 * error, which the panel renders without crashing.
 */

export interface ChatMessage {
  id: string
  role: string
  content: string
}

const RUNTIME_URL = import.meta.env.VITE_COPILOT_RUNTIME_URL || '/api/copilotkit'

function newId(): string {
  // Browser-native; no extra dependency.
  return globalThis.crypto?.randomUUID?.() ?? `m-${Date.now()}`
}

export interface GovernedTransport {
  send(content: string): Promise<ChatMessage[]>
}

export function createTransport(): GovernedTransport {
  let agent = new HttpAgent({ url: RUNTIME_URL })

  return {
    async send(content: string): Promise<ChatMessage[]> {
      agent.addMessage({ id: newId(), role: 'user', content })
      try {
        await agent.runAgent()
      } catch (error) {
        agent = new HttpAgent({ url: RUNTIME_URL })
        throw error
      }
      // After the run, `agent.messages` holds the full transcript. Normalise to
      // the minimal shape the panel renders (text messages only).
      const out: ChatMessage[] = []
      for (const m of agent.messages) {
        // Render only user/assistant text turns; skip tool/system/reasoning
        // messages and empty/partial content (which appear during streaming).
        const isChatTurn = m.role === 'user' || m.role === 'assistant'
        if (isChatTurn && typeof m.content === 'string' && m.content.length > 0) {
          out.push({ id: m.id, role: m.role, content: m.content })
        }
      }
      return out
    },
  }
}
