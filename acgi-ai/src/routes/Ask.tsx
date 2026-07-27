import {
  ArrowUp,
  BookOpen,
  FileCheck2,
  Layers,
  Paperclip,
  Plus,
  ScrollText,
  Search,
  Sparkles,
} from 'lucide-react'
import { type ReactNode, useRef, useState } from 'react'
import { navigate } from '../lib/navigate'
import './ask.css'

const ASTERISM = '⁂'

type Source = { title: string; kind: string; href: string }

type Answer = {
  /** Answer body. `[n]` markers are rendered as superscript citations. */
  body: ReactNode
  sources: Source[]
  /** Honest limitation, surfaced as a callout — grounded in docs/CLAIMS.md. */
  limitation: string
  related: string[]
}

type Entry = {
  id: string
  /** Lowercase keywords that route a free-text question to this answer. */
  match: string[]
  answer: Answer
}

function cite(n: number): ReactNode {
  return <sup className="ask-cite">[{n}]</sup>
}

/*
 * Curated governance Q&A. Every claim traces to docs/CLAIMS.md "public wording"
 * so this surface never overclaims (no "production-ready" / "certified").
 * This is a UI demonstration, not a live model — answers are authored, sourced,
 * and conservative by design.
 */
const KNOWLEDGE: Entry[] = [
  {
    id: 'what-is-acgs',
    match: ['what is acgs', 'what is gove-zone', 'govern-zone', 'what does acgs do', 'overview'],
    answer: {
      body: (
        <>
          <p>
            <strong>
              ACGS is a governed agent infrastructure project; its core enforcement kernel,
              gove-zone, is a local receipt-gated governance layer for AI-agent side effects.
            </strong>{' '}
            It sits below agent reasoning and above side-effectful tools: the agent may plan or
            request an action, but the governed executor decides whether it actually runs.{cite(1)}
          </p>
          <p>
            The core invariant is simple —{' '}
            <strong>no valid Decision Receipt, no side effect.</strong> The governed executor fails
            closed without a valid receipt.{cite(2)}
          </p>
        </>
      ),
      sources: [
        {
          title: 'gove-zone kernel & executor',
          kind: 'source · packages/gove-zone',
          href: '/products',
        },
        { title: 'Decision Receipt spec', kind: 'docs · DECISION_RECEIPT_SPEC', href: '/products' },
      ],
      limitation:
        'This is a local kernel, not a managed production service. ACGS is not compliance-certified.',
      related: [
        'How does receipt-gated execution work?',
        'What happens when an action is denied?',
        'Is the audit trail tamper-evident?',
      ],
    },
  },
  {
    id: 'receipt-gating',
    match: [
      'receipt',
      'how does receipt',
      'gated execution',
      'how does gating',
      'decision receipt',
    ],
    answer: {
      body: (
        <>
          <p>
            Policy is evaluated <strong>before</strong> execution. Kernel dispatch evaluates policy
            before the registered tool runs, and emits a Decision Receipt describing the verdict.
            {cite(1)}
          </p>
          <p>
            Receipts <strong>bind the actor, action, and exact arguments</strong> the executor
            checks, so a receipt issued for one call cannot authorise a different one. Gated
            execution rejects a missing receipt, and receipt field tampering is hash-detected.
            {cite(2)}
            {cite(3)}
          </p>
        </>
      ),
      sources: [
        { title: 'executor.py — gate', kind: 'source · test_executor_guard', href: '/products' },
        {
          title: 'receipt.py — binding',
          kind: 'source · test_argument_binding',
          href: '/products',
        },
        { title: 'tamper demo', kind: 'example · examples/tamper_demo', href: '/products' },
      ],
      limitation:
        'Binding only protects paths wired through the governed executor; direct raw-tool calls can bypass if an integrator exposes them. Actor identity comes from the integrator runtime context.',
      related: [
        'Is receipt signing on by default?',
        'Can a receipt be reused?',
        'What is the Decision Receipt format?',
      ],
    },
  },
  {
    id: 'denied',
    match: ['deny', 'denied', 'blocked', 'fail closed', 'fail-closed', 'what happens when'],
    answer: {
      body: (
        <>
          <p>
            A denied action <strong>does not run and leaves evidence.</strong> Denied local actions
            are audited and blocked before any side effect occurs.{cite(1)}
          </p>
          <p>
            <code>DENY</code> and <code>ESCALATE</code> verdicts are never treated as executable —
            the system fails closed rather than defaulting to allow.{cite(2)}
          </p>
        </>
      ),
      sources: [
        { title: 'kernel.py · audit.py', kind: 'source · test_fail_closed', href: '/products' },
        { title: 'smoke demo', kind: 'example · gove-zone smoke', href: '/products' },
      ],
      limitation: 'Evidence is written to local JSONL, which is not WORM storage.',
      related: [
        'Is the audit trail tamper-evident?',
        'How does receipt-gated execution work?',
        'What is ESCALATE?',
      ],
    },
  },
  {
    id: 'audit',
    match: ['audit', 'tamper', 'tamper-evident', 'hash chain', 'hash-chained', 'evidence'],
    answer: {
      body: (
        <>
          <p>
            Local audit events are <strong>hash-chained and tamper-evident</strong>: each event
            commits to the previous one, so truncation or edits to the chain are detectable on
            replay.{cite(1)}
          </p>
          <p>
            The CLI can generate a local <strong>proof pack</strong> bundling receipts, audit,
            verification, and limitations as conformance evidence.{cite(2)}
          </p>
        </>
      ),
      sources: [
        { title: 'audit.py — hash chain', kind: 'source · test_audit_chain', href: '/products' },
        { title: 'proof pack', kind: 'cli · gove-zone proofpack', href: '/products' },
      ],
      limitation:
        'Local JSONL is not WORM storage, and provides local conformance evidence only — not an external attestation.',
      related: [
        'What happens when an action is denied?',
        'Is receipt signing on by default?',
        'What is a proof pack?',
      ],
    },
  },
  {
    id: 'signing',
    match: ['sign', 'signing', 'signature', 'ed25519', 'default', 'unsigned'],
    answer: {
      body: (
        <>
          <p>
            <strong>Signing is opt-in; verification is unsigned by default.</strong> Out of the box
            only the local SHA-256 hash is checked, which is recomputable under host compromise.
            {cite(1)}
          </p>
          <p>
            Opt-in <strong>Ed25519 receipt signing</strong> is implemented for local trusted-key
            verification — set <code>require_signature=True</code> with a trusted verifier for a
            production posture.{cite(2)}
          </p>
        </>
      ),
      sources: [
        { title: 'signing.py — Ed25519', kind: 'source · test_receipt_signing', href: '/products' },
        {
          title: 'contracts.py — require_signature',
          kind: 'source · default False',
          href: '/products',
        },
      ],
      limitation:
        'Signing is opt-in with no PKI, key custody, or revocation. Unsigned dev mode is the default and must not be presented as a production claim.',
      related: ['Can a receipt be reused?', 'Is the audit trail tamper-evident?', 'What is ACGS?'],
    },
  },
  {
    id: 'single-use',
    match: ['reuse', 'reused', 'single use', 'single-use', 'one-time', 'replay', 'consumption'],
    answer: {
      body: (
        <>
          <p>
            <strong>Single-use enforcement is available opt-in</strong> via a hash-chained
            consumption ledger that burns a receipt&apos;s audit anchor before execution.{cite(1)}
          </p>
          <p>
            It is <strong>off by default</strong>: <code>verify</code> itself stays stateless, so
            without a ledger a valid <code>ALLOW</code> receipt is reusable until it expires.
            {cite(2)}
          </p>
        </>
      ),
      sources: [
        {
          title: 'consumption.py — ledger',
          kind: 'source · test_receipt_consumption',
          href: '/products',
        },
        { title: 'SECURITY_MODEL', kind: 'docs · consumption tamper', href: '/products' },
      ],
      limitation:
        'Off by default. Tail truncation still needs an external high-water-mark, and there is no global nonce or revocation registry.',
      related: [
        'Is receipt signing on by default?',
        'How does receipt-gated execution work?',
        'What is ACGS?',
      ],
    },
  },
]

const FALLBACK: Answer = {
  body: (
    <>
      <p>
        This is an ACGS-branded demonstration of a conversational governance interface. It answers
        from a small, sourced knowledge set drawn from the project&apos;s claim ledger rather than a
        live model.
      </p>
      <p>
        Try one of the governance questions below — each answer traces back to code, tests, or
        documented limitations.
      </p>
    </>
  ),
  sources: [{ title: 'Claim ledger', kind: 'docs · CLAIMS.md', href: '/products' }],
  limitation:
    'Answers are authored and conservative by design — this surface is a UI demonstration, not a live assistant.',
  related: [
    'What is ACGS?',
    'How does receipt-gated execution work?',
    'Is the audit trail tamper-evident?',
  ],
}

const SUGGESTIONS = [
  'What is ACGS?',
  'How does receipt-gated execution work?',
  'What happens when an action is denied?',
  'Is the audit trail tamper-evident?',
  'Is receipt signing on by default?',
]

type Mode = { id: string; label: string; icon: typeof Search }

const MODES: Mode[] = [
  { id: 'governance', label: 'Governance', icon: Sparkles },
  { id: 'claims', label: 'Claims', icon: FileCheck2 },
  { id: 'receipts', label: 'Receipts', icon: ScrollText },
]

function resolveAnswer(question: string): Answer {
  const q = question.toLowerCase()
  for (const entry of KNOWLEDGE) {
    if (entry.match.some((m) => q.includes(m))) return entry.answer
  }
  return FALLBACK
}

type Turn = { id: number; question: string; answer: Answer }

export function Ask() {
  const [draft, setDraft] = useState('')
  const [mode, setMode] = useState('governance')
  const [thread, setThread] = useState<Turn[]>([])
  const seq = useRef(0)

  const hasThread = thread.length > 0

  function ask(question: string) {
    const trimmed = question.trim()
    if (!trimmed) return
    seq.current += 1
    setThread((prev) => [
      ...prev,
      { id: seq.current, question: trimmed, answer: resolveAnswer(trimmed) },
    ])
    setDraft('')
  }

  function reset() {
    setThread([])
    setDraft('')
  }

  const composer = (
    <form
      className="ask-form"
      onSubmit={(e) => {
        e.preventDefault()
        ask(draft)
      }}
    >
      <div className="ask-box">
        <textarea
          className="ask-input"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault()
              ask(draft)
            }
          }}
          placeholder="Ask anything about ACGS governance…"
          aria-label="Ask a governance question"
          rows={2}
        />
        <div className="ask-box-row">
          <div className="ask-modes">
            <button type="button" className="ask-mode" aria-label="Attach (demo)" disabled>
              <Paperclip size={14} strokeWidth={1.8} />
            </button>
            {MODES.map((m) => {
              const Icon = m.icon
              return (
                <button
                  key={m.id}
                  type="button"
                  className={`ask-mode${mode === m.id ? ' is-active' : ''}`}
                  onClick={() => setMode(m.id)}
                  aria-pressed={mode === m.id}
                >
                  <Icon size={14} strokeWidth={1.8} />
                  {m.label}
                </button>
              )
            })}
          </div>
          <button type="submit" className="ask-submit" disabled={!draft.trim()} aria-label="Ask">
            <ArrowUp size={18} strokeWidth={2.2} />
          </button>
        </div>
      </div>
    </form>
  )

  return (
    <div className="ask">
      <aside className="ask-rail">
        <button type="button" className="ask-brand" onClick={() => navigate('/')}>
          <span className="ask-brand-mark">{ASTERISM}</span>
          <span className="ask-brand-word">gove-zone</span>
        </button>

        <button type="button" className="ask-new" onClick={reset}>
          <Plus size={16} strokeWidth={2} />
          New thread
        </button>

        <nav className="ask-nav" aria-label="Workspace">
          <button type="button" className="ask-nav-item is-active" aria-current="page">
            <Search size={17} strokeWidth={1.8} />
            Ask
          </button>
          <button type="button" className="ask-nav-item" onClick={() => navigate('/products')}>
            <ScrollText size={17} strokeWidth={1.8} />
            Receipts
          </button>
          <button type="button" className="ask-nav-item" onClick={() => navigate('/trust')}>
            <FileCheck2 size={17} strokeWidth={1.8} />
            Audit
          </button>
          <button type="button" className="ask-nav-item" onClick={() => navigate('/products')}>
            <Layers size={17} strokeWidth={1.8} />
            Library
          </button>
        </nav>

        <div className="ask-rail-foot">
          <p className="ask-rail-note">
            Sourced from the ACGS claim ledger. A UI demonstration, not a live assistant.
          </p>
          <div className="ask-account">
            <span className="ask-avatar">{ASTERISM}</span>
            <span>
              <span className="ask-account-name">Operator</span>
              <br />
              <span className="ask-account-sub">govern-zone · local</span>
            </span>
          </div>
        </div>
      </aside>

      <main className="ask-main">
        {!hasThread ? (
          <div className="ask-home">
            <div className="ask-hero">
              <span className="ask-hero-eyebrow">
                <BookOpen size={13} strokeWidth={1.8} />
                Governance Q&amp;A
              </span>
              <h1 className="ask-hero-h1">
                What do you want to <em>govern</em>?
              </h1>
            </div>
            {composer}
            <div className="ask-suggests">
              {SUGGESTIONS.map((s) => (
                <button key={s} type="button" className="ask-chip" onClick={() => ask(s)}>
                  {s}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <>
            <div className="ask-thread">
              {thread.map((turn) => (
                <article key={turn.id} className="ask-turn">
                  <h2 className="ask-q">{turn.question}</h2>

                  <span className="ask-section-label">
                    <Layers size={12} strokeWidth={1.8} />
                    Sources
                  </span>
                  <div className="ask-sources">
                    {turn.answer.sources.map((src, i) => (
                      <button
                        key={src.title}
                        type="button"
                        className="ask-source"
                        onClick={() => navigate(src.href)}
                      >
                        <span className="ask-source-idx">[{i + 1}]</span>
                        <span className="ask-source-title">{src.title}</span>
                        <span className="ask-source-kind">{src.kind}</span>
                      </button>
                    ))}
                  </div>

                  <span className="ask-section-label">
                    <Sparkles size={12} strokeWidth={1.8} />
                    Answer
                  </span>
                  <div className="ask-answer">
                    {turn.answer.body}
                    <p className="ask-limit">
                      <strong>Limitation: </strong>
                      {turn.answer.limitation}
                    </p>
                  </div>

                  <div className="ask-related">
                    {turn.answer.related.map((r) => (
                      <button
                        key={r}
                        type="button"
                        className="ask-related-item"
                        onClick={() => ask(r)}
                      >
                        {r}
                        <Plus size={16} strokeWidth={1.8} />
                      </button>
                    ))}
                  </div>
                </article>
              ))}
            </div>
            <div className="ask-followbar">{composer}</div>
          </>
        )}
      </main>
    </div>
  )
}

export default Ask
