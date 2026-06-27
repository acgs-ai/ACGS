import { type ReactNode, useEffect, useRef, useState } from 'react'
import { MarketingFrame, NavigationLink } from './Marketing'

const ASTERISM = '⁂'
const GITHUB_URL = 'https://github.com/CA-git-com-co/ACGS'
const PYPI_URL = 'https://pypi.org/project/constitutional-swarm/'
const INSTALL_CMD = 'pip install constitutional-swarm'

/* ---------------------------------------------------------------------------
 * Swarm showcase — acgs-swarm (constitutional-swarm). A "Constitutional Mesh"
 * rendered as the layout: asymmetric inverted hero, mono evidence density, a
 * varying-span bento standing in for the agent peer-mesh, animated CSS-driven
 * SVG mesh + dependency-DAG motifs, and an onchain-feeling settlement receipt
 * motif. Editorial register: token-only colour, hairline depth, single rust
 * accent, one rust-italic word per major title (DESIGN.md §2.2). Copy is
 * claim-safe and source-attributed to match the rest of the marketing site.
 * ------------------------------------------------------------------------- */

interface ProofStat {
  value: string
  unit: string
  label: string
  source: string
}

const PROOF_STATS: ProofStat[] = [
  {
    value: '443',
    unit: 'ns / check',
    label: 'Local co-processor latency',
    source: 'dna.py docstring',
  },
  {
    value: 'O(1)',
    unit: 'per agent',
    label: 'Constitutional check cost',
    source: 'dna.py docstring',
  },
  { value: '800+', unit: 'agents', label: 'Coordinated peer mesh', source: 'AGENTS.md inventory' },
  {
    value: '1603',
    unit: 'tests',
    label: 'Passing · 1 skipped · 2 xfailed',
    source: 'pytest marker run',
  },
  { value: 'v1.0.0', unit: 'release', label: 'Published distribution', source: 'PyPI' },
]

interface MeshCard {
  span: string
  tag: string
  title: string
  blurb: string
  primitive: string
}

// The bento IS the swarm lattice. Varying spans + double-bezel hairline framing
// read as a peer-mesh, not a 3-col icon grid (banned in acgi-ai/CLAUDE.md).
const MESH_CARDS: MeshCard[] = [
  {
    span: 'is-w8',
    tag: 'co-processor',
    title: 'AgentDNA',
    blurb:
      'Every peer carries a local constitutional co-processor. Each governed action is checked in-process against the encoded constitution before it leaves the agent — no round-trip to a central authority.',
    primitive: 'agent_dna.check() · 443ns',
  },
  {
    span: 'is-w4 is-h2',
    tag: 'consensus',
    title: 'ConstitutionalMesh',
    blurb:
      'Peers validate each other. Decisions propagate as signed votes across the mesh; a peer accepts a neighbour’s outcome only when the signature and the constitutional hash agree.',
    primitive: 'mesh.submit_vote(signed)',
  },
  {
    span: 'is-w4',
    tag: 'persistence',
    title: 'SettlementStore',
    blurb: 'Settled decisions land in an append-only JSONL / SQLite store for later replay.',
    primitive: 'JSONL · SQLite',
  },
  {
    span: 'is-w4',
    tag: 'evidence',
    title: 'Governance receipts',
    blurb: 'Each settled action emits a receipt verifiable offline with acgs-verify-receipts.',
    primitive: 'acgs-verify-receipts',
  },
  {
    span: 'is-w4',
    tag: 'monotonic',
    title: 'EvolutionLog',
    blurb: 'A SQLite trigger enforces monotonicity so the constitution log cannot silently rewind.',
    primitive: 'sqlite trigger guard',
  },
  {
    span: 'is-w4',
    tag: 'transport',
    title: 'Remote vote transport',
    blurb: 'Votes cross process and host boundaries over a pluggable signed transport.',
    primitive: '[transport] extra',
  },
  {
    span: 'is-w6',
    tag: 'privacy',
    title: 'Private voting',
    blurb:
      'Commit-reveal ballots with nullifiers let peers vote without disclosing the ballot until reveal, while double-votes are rejected.',
    primitive: 'commit → reveal · nullifier',
  },
  {
    span: 'is-w6',
    tag: 'finality',
    title: 'QuorumCertificate',
    blurb:
      'A quorum certificate aggregates the signed votes that carried a decision and surfaces BFT conflict detection when two certificates disagree.',
    primitive: 'QuorumCertificate',
  },
  {
    span: 'is-w4',
    tag: 'membership',
    title: 'ValidatorSet',
    blurb: 'A committee selector draws the validator set that is eligible to certify each round.',
    primitive: 'CommitteeSelector',
  },
  {
    span: 'is-w4',
    tag: 'epochs',
    title: 'EpochReconfig',
    blurb: 'Membership and parameters rotate at epoch boundaries without halting the mesh.',
    primitive: 'epoch.reconfigure()',
  },
  {
    span: 'is-w4',
    tag: 'federation',
    title: 'FederatedConstitutionBridge',
    blurb: 'Distinct constitutions interoperate across a bridge that pins each side’s hash.',
    primitive: 'constitution bridge',
  },
  {
    span: 'is-w12',
    tag: 'research',
    title: 'SpectralSphereManifold',
    blurb:
      'An experimental manifold embedding for reasoning about swarm state geometry — research-tier, excluded from release gating.',
    primitive: 'spectral_sphere (experimental)',
  },
]

interface SettlementRow {
  field: string
  value: string
}

const SETTLEMENT_ROWS: SettlementRow[] = [
  { field: 'constitutional_hash', value: 'cf1a…9e02' },
  { field: 'schema_version', value: '1.0.0' },
  { field: 'settled_at', value: '2026-06-27T00:00:00Z' },
  { field: 'quorum', value: '5 / 7 signed' },
]

interface CryptoRow {
  primitive: string
  detail: string
}

const CRYPTO_ROWS: CryptoRow[] = [
  {
    primitive: 'Ed25519 mandatory',
    detail:
      'submit_vote has no unsigned fallback path — an unsigned vote is rejected, not downgraded.',
  },
  {
    primitive: 'QuorumCertificate',
    detail: 'BFT conflict detection flags two certificates that certify conflicting outcomes.',
  },
  {
    primitive: 'Signed envelopes',
    detail: 'Each envelope carries a nonce + timestamp checked against a replay window.',
  },
  {
    primitive: 'TLS auto-upgrade',
    detail: 'Tri-state transport upgrades to TLS where available rather than failing open.',
  },
]

interface Integration {
  name: string
  extra: string
  wraps: string
  proof: string
}

const INTEGRATIONS: Integration[] = [
  {
    name: 'LangGraph adapter',
    extra: '[langgraph] · [langgraph-swarm]',
    wraps: 'Wraps LangGraph nodes so each step passes the constitutional check.',
    proof: 'local adapter test — not a live deployment claim',
  },
  {
    name: 'Bittensor subnet',
    extra: '[bittensor]',
    wraps: 'Maps mesh validation onto a Bittensor subnet topology.',
    proof: 'optional extra — integration scaffold',
  },
  {
    name: 'Remote transport',
    extra: '[transport]',
    wraps: 'Carries signed votes across hosts over a pluggable transport.',
    proof: 'signed-envelope unit coverage',
  },
]

interface MaturityItem {
  name: string
  note: string
}

const STABLE_CORE: MaturityItem[] = [
  { name: 'AgentDNA', note: 'local constitutional co-processor' },
  { name: 'ConstitutionalMesh', note: 'signed peer validation' },
  { name: 'QuorumCertificate', note: 'BFT finality + conflict detection' },
  { name: 'SettlementStore', note: 'JSONL / SQLite replay' },
  { name: 'ValidatorSet', note: 'committee selection + epoch reconfig' },
]

const EXPERIMENTAL_RESEARCH: MaturityItem[] = [
  { name: 'latent_dna', note: 'learned constitution embeddings' },
  { name: 'swarm_ode', note: 'continuous-time swarm dynamics' },
  { name: 'MerkleCRDT', note: 'conflict-free replicated audit tree' },
  { name: 'gossip_protocol', note: 'epidemic state dissemination' },
  { name: 'swe_bench', note: 'task benchmark harness' },
]

// Fail-open scroll reveal: content is visible by default. We only arm the
// hidden start-state in JS when IntersectionObserver exists and the user has
// NOT requested reduced motion (the global §2.5 reset disables transitions, so
// an armed-but-unobserved element could otherwise stick at opacity 0). This way
// no-JS, no-observer, and reduced-motion all resolve to visible content.
function useScrollReveal() {
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const host = rootRef.current
    if (!host || typeof window === 'undefined') return
    if (!('IntersectionObserver' in window)) return
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return

    const targets = Array.from(host.querySelectorAll<HTMLElement>('.m-swarm-reveal'))
    if (targets.length === 0) return
    for (const el of targets) el.classList.add('is-armed')

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible')
            observer.unobserve(entry.target)
          }
        }
      },
      { rootMargin: '0px 0px -10% 0px', threshold: 0.08 },
    )
    for (const el of targets) observer.observe(el)
    return () => observer.disconnect()
  }, [])

  return rootRef
}

function CopyInstall() {
  const [copied, setCopied] = useState(false)

  const copy = () => {
    if (typeof navigator === 'undefined' || !navigator.clipboard) return
    navigator.clipboard.writeText(INSTALL_CMD).then(
      () => {
        setCopied(true)
        window.setTimeout(() => setCopied(false), 2000)
      },
      () => setCopied(false),
    )
  }

  return (
    <button
      type="button"
      className="btn btn-primary m-swarm-copy"
      onClick={copy}
      aria-label={copied ? 'Install command copied' : `Copy install command: ${INSTALL_CMD}`}
    >
      <span className="m-swarm-copy-cmd">{INSTALL_CMD}</span>
      <span className="m-swarm-copy-state" aria-hidden>
        {copied ? 'copied' : 'copy'}
      </span>
    </button>
  )
}

// Animated peer mesh — drifting nodes, pulsing edges. All motion is CSS-driven
// (App.css keyframes on the .m-swarm-mesh-* classes), so the global
// prefers-reduced-motion reset disables it. currentColor inherits the band ink.
function SwarmMesh() {
  return (
    <svg
      className="m-swarm-mesh"
      viewBox="0 0 240 200"
      role="img"
      aria-label="Animated constitutional peer mesh: drifting agent nodes connected by signed-vote edges"
      focusable="false"
    >
      <g className="m-swarm-mesh-edges" stroke="currentColor" strokeWidth="0.6" fill="none">
        <line x1="48" y1="40" x2="130" y2="64" />
        <line x1="130" y1="64" x2="196" y2="36" />
        <line x1="48" y1="40" x2="74" y2="128" />
        <line x1="130" y1="64" x2="74" y2="128" />
        <line x1="130" y1="64" x2="170" y2="140" />
        <line x1="74" y1="128" x2="150" y2="172" />
        <line x1="170" y1="140" x2="150" y2="172" />
        <line x1="196" y1="36" x2="170" y2="140" />
      </g>
      <g className="m-swarm-mesh-nodes" fill="currentColor">
        <circle className="m-swarm-node n1" cx="48" cy="40" r="4.5" />
        <circle className="m-swarm-node n2" cx="130" cy="64" r="6" />
        <circle className="m-swarm-node n3" cx="196" cy="36" r="4" />
        <circle className="m-swarm-node n4" cx="74" cy="128" r="5" />
        <circle className="m-swarm-node n5" cx="170" cy="140" r="4.5" />
        <circle className="m-swarm-node n6" cx="150" cy="172" r="3.5" />
      </g>
    </svg>
  )
}

// Dependency DAG — nodes resolve in topological order via staggered opacity
// (animation-delay per layer in App.css). Pure presentation + CSS.
function DependencyDag() {
  return (
    <svg
      className="m-swarm-dag"
      viewBox="0 0 260 180"
      role="img"
      aria-label="Animated dependency DAG: goal compiled into nodes that resolve in topological order"
      focusable="false"
    >
      <g stroke="var(--line-soft)" strokeWidth="1" fill="none">
        <line x1="36" y1="90" x2="110" y2="44" />
        <line x1="36" y1="90" x2="110" y2="136" />
        <line x1="110" y1="44" x2="186" y2="44" />
        <line x1="110" y1="136" x2="186" y2="136" />
        <line x1="186" y1="44" x2="232" y2="90" />
        <line x1="186" y1="136" x2="232" y2="90" />
        <line x1="110" y1="44" x2="186" y2="136" />
      </g>
      <g fill="var(--accent)">
        <circle className="m-swarm-dag-node d0" cx="36" cy="90" r="7" />
        <circle className="m-swarm-dag-node d1" cx="110" cy="44" r="6" />
        <circle className="m-swarm-dag-node d1" cx="110" cy="136" r="6" />
        <circle className="m-swarm-dag-node d2" cx="186" cy="44" r="6" />
        <circle className="m-swarm-dag-node d2" cx="186" cy="136" r="6" />
        <circle className="m-swarm-dag-node d3" cx="232" cy="90" r="7" />
      </g>
    </svg>
  )
}

function SecHead({ num, children }: { num: string; children: ReactNode }) {
  return (
    <div className="m-sec-head">
      <span className="num">{num}</span>
      <h2>{children}</h2>
    </div>
  )
}

export function Swarm() {
  const revealRef = useScrollReveal()

  return (
    <MarketingFrame>
      <div ref={revealRef} className="m-swarm">
        {/* 2 — Hero: token-inverted frontier band, asymmetric */}
        <header className="m-swarm-hero m-swarm-invert">
          <div className="m-swarm-hero-lead">
            <span className="m-swarm-pill">constitutional-swarm · v1.0.0</span>
            <h1 className="m-swarm-h1">
              Constitutional governance, <em>orchestrator-free</em>.
            </h1>
            <p className="m-swarm-lede">
              acgs-swarm gives a swarm of agents a shared constitution that each peer enforces
              locally and the mesh certifies together — signed votes, quorum certificates, and
              hash-pinned settlement, with no central bus in the path.
            </p>
            <div className="m-swarm-cta">
              <CopyInstall />
              <a className="btn btn-secondary m-swarm-cta-alt" href={GITHUB_URL}>
                View source <span aria-hidden>&#8599;</span>
              </a>
            </div>
            <p className="m-swarm-caption">Python 3.11+ · AGPL-3.0-or-later · PyPI 1.0.0</p>
          </div>
          <aside className="m-swarm-hero-aside" aria-hidden>
            <SwarmMesh />
            <span className="m-swarm-aside-cap">peer mesh · signed votes</span>
          </aside>
        </header>

        {/* 3 — Proof bar */}
        <section className="m-swarm-proof" aria-label="Project facts">
          {PROOF_STATS.map((stat) => (
            <div className="m-swarm-stat" key={stat.label}>
              <span className="m-swarm-stat-fig tabular">
                {stat.value}
                <span className="m-swarm-stat-unit">{stat.unit}</span>
              </span>
              <span className="m-swarm-stat-label">{stat.label}</span>
              <span className="m-swarm-stat-src">{stat.source}</span>
            </div>
          ))}
        </section>

        {/* 4 — Runs without an orchestrator */}
        <section className="m-swarm-orch m-swarm-reveal" aria-labelledby="swarm-orch-h">
          <SecHead num="I · No orchestrator">
            <span id="swarm-orch-h">
              Compile the goal, <em>resolve</em> the mesh.
            </span>
          </SecHead>
          <div className="m-swarm-split">
            <div className="m-swarm-prose">
              <p>
                A <strong>DAGCompiler</strong> turns a goal into a dependency graph; the{' '}
                <strong>SwarmExecutor</strong> walks it in topological order while peers coordinate
                stigmergically — leaving and reading shared state rather than messaging a
                coordinator.
              </p>
              <p>
                There is no orchestrator to fail, throttle, or become a trust bottleneck. Every node
                runs the same constitutional check before it acts, and the mesh records what
                carried.
              </p>
              <p className="m-swarm-callout">
                No central bus. No point-to-point messaging. Compile goal &rarr; DAG &rarr; execute.
              </p>
            </div>
            <figure className="m-swarm-figure">
              <DependencyDag />
              <figcaption>DAGCompiler &rarr; SwarmExecutor · topological resolve</figcaption>
            </figure>
          </div>
        </section>

        <div className="m-break" aria-hidden>
          {ASTERISM} {ASTERISM} {ASTERISM}
        </div>

        {/* 5 — Constitutional Mesh bento */}
        <section className="m-swarm-mesh-sec m-swarm-reveal" aria-labelledby="swarm-mesh-h">
          <SecHead num="II · Constitutional mesh">
            <span id="swarm-mesh-h">
              The swarm, rendered as a <em>lattice</em>.
            </span>
          </SecHead>
          <div className="m-swarm-bento">
            {MESH_CARDS.map((card) => (
              <article className={`m-swarm-cell ${card.span}`} key={card.title}>
                <div className="m-swarm-cell-inner">
                  <span className="m-swarm-cell-tag">{card.tag}</span>
                  <h3>{card.title}</h3>
                  <p>{card.blurb}</p>
                  <code className="m-swarm-cell-prim">{card.primitive}</code>
                </div>
              </article>
            ))}
          </div>
        </section>

        <div className="m-break" aria-hidden>
          {ASTERISM} {ASTERISM} {ASTERISM}
        </div>

        {/* 6 — Settlement & evidence (onchain motif) */}
        <section className="m-swarm-settle m-swarm-reveal" aria-labelledby="swarm-settle-h">
          <SecHead num="III · Settlement &amp; evidence">
            <span id="swarm-settle-h">
              Replay any past decision from its <em>receipt</em>.
            </span>
          </SecHead>
          <div className="m-swarm-split">
            <div className="m-swarm-prose">
              <p>
                A settled record carries the constitutional hash and schema version active at
                settlement. You can replay a past decision from the stored receipt without
                re-running the swarm — the evidence, not the runtime, is the source of truth.
              </p>
              <figure className="m-code m-swarm-code">
                <figcaption className="m-code-head">
                  <span>verify</span>
                  <span>offline</span>
                </figcaption>
                <pre>
                  <span className="c">{'# replay from the stored receipt'}</span>
                  {'\n'}acgs-verify-receipts <span className="s">settlement.jsonl</span>
                </pre>
              </figure>
            </div>
            <div className="m-swarm-receipt" role="group" aria-label="Settlement receipt fields">
              <div className="m-swarm-receipt-head">settlement receipt</div>
              {SETTLEMENT_ROWS.map((row) => (
                <div className="m-swarm-receipt-row" key={row.field}>
                  <span className="m-swarm-receipt-key">{row.field}</span>
                  <span className="m-swarm-receipt-val tabular">{row.value}</span>
                  <span className="m-swarm-replay" aria-hidden>
                    &#8617; replay
                  </span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <div className="m-break" aria-hidden>
          {ASTERISM} {ASTERISM} {ASTERISM}
        </div>

        {/* 7 — Cryptographic accountability lane */}
        <section className="m-swarm-crypto m-swarm-reveal" aria-labelledby="swarm-crypto-h">
          <SecHead num="IV · Cryptographic accountability">
            <span id="swarm-crypto-h">
              Signatures are <em>mandatory</em>, not optional.
            </span>
          </SecHead>
          <div className="m-swarm-rows">
            {CRYPTO_ROWS.map((row) => (
              <div className="m-swarm-row" key={row.primitive}>
                <code className="m-swarm-row-key">{row.primitive}</code>
                <span className="m-swarm-row-detail">{row.detail}</span>
              </div>
            ))}
          </div>
        </section>

        <div className="m-break" aria-hidden>
          {ASTERISM} {ASTERISM} {ASTERISM}
        </div>

        {/* 8 — Integrations & extras */}
        <section className="m-swarm-integrations m-swarm-reveal" aria-labelledby="swarm-int-h">
          <SecHead num="V · Integrations">
            <span id="swarm-int-h">
              Wrap your stack, keep your <em>runtime</em>.
            </span>
          </SecHead>
          <div className="m-swarm-int-grid">
            {INTEGRATIONS.map((item) => (
              <article className="m-swarm-int" key={item.name}>
                <h3>{item.name}</h3>
                <code className="m-swarm-int-extra">{item.extra}</code>
                <p>{item.wraps}</p>
                <span className="m-swarm-int-proof">{item.proof}</span>
              </article>
            ))}
          </div>
        </section>

        <div className="m-break" aria-hidden>
          {ASTERISM} {ASTERISM} {ASTERISM}
        </div>

        {/* 9 — Maturity tiers */}
        <section className="m-swarm-maturity m-swarm-reveal" aria-labelledby="swarm-mat-h">
          <SecHead num="VI · Maturity">
            <span id="swarm-mat-h">
              Stable core, honest <em>edges</em>.
            </span>
          </SecHead>
          <div className="m-swarm-tiers">
            <div className="m-swarm-tier">
              <span className="m-swarm-tier-head">
                <span className="m-swarm-dot is-stable" aria-hidden />
                Stable core
              </span>
              <ul>
                {STABLE_CORE.map((item) => (
                  <li key={item.name}>
                    <code>{item.name}</code>
                    <span>{item.note}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="m-swarm-tier">
              <span className="m-swarm-tier-head">
                <span className="m-swarm-dot is-exp" aria-hidden />
                Experimental research
              </span>
              <ul>
                {EXPERIMENTAL_RESEARCH.map((item) => (
                  <li key={item.name}>
                    <code>{item.name}</code>
                    <span>{item.note}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
          <p className="m-swarm-mat-note">
            research modules are not hardened defaults &mdash; excluded from release gating.
          </p>
        </section>

        <div className="m-break" aria-hidden>
          {ASTERISM} {ASTERISM} {ASTERISM}
        </div>

        {/* 10 — Built on acgs-lite */}
        <section className="m-swarm-lite m-swarm-reveal" aria-labelledby="swarm-lite-h">
          <SecHead num="VII · Lineage">
            <span id="swarm-lite-h">
              Built on <em>acgs-lite</em>.
            </span>
          </SecHead>
          <p className="m-swarm-lite-body">
            acgs-swarm extends single-action constitutional governance to a whole swarm — without
            replacing your model or runtime. Embed it into an existing agent stack and keep the
            decision receipts you already trust.
          </p>
          <p className="m-section-link">
            <NavigationLink href="/products">See the ACGS product atlas</NavigationLink>
          </p>
        </section>

        {/* 11 — CTA band: second inverted frontier band */}
        <section
          className="m-swarm-final m-swarm-invert m-swarm-reveal"
          aria-labelledby="swarm-final-h"
        >
          <h2 id="swarm-final-h" className="m-swarm-final-h">
            Govern the <em>swarm</em>.
          </h2>
          <div className="m-swarm-cta">
            <CopyInstall />
            <a className="btn btn-secondary m-swarm-cta-alt" href={GITHUB_URL}>
              GitHub <span aria-hidden>&#8599;</span>
            </a>
            <a className="btn btn-secondary m-swarm-cta-alt" href={PYPI_URL}>
              PyPI <span aria-hidden>&#8599;</span>
            </a>
          </div>
          <p className="m-swarm-caption">
            AGPL-3.0-or-later · No compliance certification or regulator approval.
          </p>
        </section>
      </div>
    </MarketingFrame>
  )
}
