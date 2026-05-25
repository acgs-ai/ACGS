import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const outDir = resolve(root, process.env.ACGI_EVIDENCE_OUT_DIR ?? 'dist-buyer-evidence')
const publishHost = process.env.ACGI_EVIDENCE_CNAME?.trim()
const publishTarget = publishHost
  ? `https://${publishHost}`
  : 'storybook.acgs.ai remains pending external deployment work'
const publicationFiles = ['index.html', 'manifest.json', '.nojekyll']
if (publishHost) publicationFiles.push('CNAME')

const evidenceStories = [
  {
    id: 'receipt-proof-journey',
    title: 'Receipt proof journey',
    route: '/console/audit/rcpt-608508a9-8b38',
    buyerQuestion: 'Can an auditor verify one policy enforcement decision end to end?',
    proof: [
      'Receipt identity and hash-chain status are visible in the console proof packet.',
      'Policy path, decision, and flagged rule context stay attached to the receipt.',
      'Signed evidence packet export copy is surfaced without requiring raw JSON inspection.',
    ],
    localGates: ['pnpm run test:mvp', 'pnpm run test:router', 'pnpm run test:e2e-http'],
    sourceFiles: [
      'src/routes/console/AuditProof.tsx',
      'src/api/hooks.ts',
      'src/mocks/data/actions.ts',
    ],
  },
  {
    id: 'bus-owned-proof-source',
    title: 'Bus-owned proof source',
    route: '/api/bus/receipts/{receipt_id}',
    buyerQuestion: 'Does the proof come from the governed evidence API instead of fixtures?',
    proof: [
      'The console contract includes a bus-owned receipt proof endpoint.',
      'OpenAPI types are generated from the vendored bus schema.',
      'Schema-version and error-envelope cases are statically guarded.',
    ],
    localGates: ['pnpm run test:bus-schema', 'pnpm run test:bus-proxy'],
    sourceFiles: [
      'contracts/bus.openapi.json',
      'src/api/bus.generated.ts',
      'scripts/check-bus-schema-contract.mjs',
    ],
  },
  {
    id: 'claim-safe-trust-surface',
    title: 'Claim-safe trust surface',
    route: '/trust',
    buyerQuestion: 'Are public claims tied to evidence without overstating deployment status?',
    proof: [
      'Engineering-draft claims map to local evidence pointers.',
      'Trust and security pages avoid certification or production-equivalence language.',
      'Legal review and live deployment proof remain explicit external gates.',
    ],
    localGates: ['pnpm run test:claim-matrix', 'pnpm run test:trust-surface'],
    sourceFiles: ['claim-matrix.json', 'src/routes/Trust.tsx', 'src/routes/Security.tsx'],
  },
  {
    id: 'visual-governance-workbench',
    title: 'Visual governance workbench',
    route: '/console/workbench',
    buyerQuestion: 'Can an operator understand the next safe action without reading raw traces?',
    proof: [
      'The console workbench turns queue, trace, evaluation, release, and evidence steps into one visual path.',
      'Each stage links back to an existing console route instead of creating hidden side effects.',
      'The claim boundary keeps the workbench as local UX evidence, not production assurance.',
    ],
    localGates: [
      'pnpm run test:platform-blueprint',
      'pnpm run test:wire-decisions',
      'pnpm run test:e2e-http',
      'pnpm run test:a11y',
    ],
    sourceFiles: [
      'src/routes/console/Workbench.tsx',
      'src/routes/Console.tsx',
      'src/routes/console/wire-decisions.ts',
      'src/App.css',
    ],
  },
  {
    id: 'deploy-readiness-boundary',
    title: 'Deploy readiness boundary',
    route: 'Cloud Run + Vercel deploy contracts',
    buyerQuestion: 'Can the team distinguish local readiness from live production proof?',
    proof: [
      'Cloud Run templates, container pins, CSP, and post-deploy scripts are locally gated.',
      'Live served-hash, build-id, domain, OIDC, and browser evidence remain external.',
      'The root platform-readiness audit keeps blockers visible.',
    ],
    localGates: [
      'pnpm run test:cloudrun-templates',
      'pnpm run test:container-pins',
      'pnpm run test:postdeploy-live-assets',
      'make platform-readiness',
    ],
    sourceFiles: [
      'infra/cloudrun/service.production.yaml',
      'infra/Dockerfile.console',
      'scripts/postdeploy-verify.sh',
    ],
  },
]

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}

function list(items) {
  return `<ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`
}

function storyCard(story) {
  return `<article class="story" id="${escapeHtml(story.id)}">
    <p class="eyebrow">${escapeHtml(story.route)}</p>
    <h2>${escapeHtml(story.title)}</h2>
    <p class="question">${escapeHtml(story.buyerQuestion)}</p>
    <h3>Proof points</h3>
    ${list(story.proof)}
    <h3>Local gates</h3>
    ${list(story.localGates)}
    <h3>Source files</h3>
    ${list(story.sourceFiles)}
  </article>`
}

const manifest = {
  schemaVersion: 1,
  artifactKind: 'local-buyer-evidence-gallery',
  claimBoundary:
    'Local buyer-evidence artifact only; not hosted Storybook, not production deployment proof.',
  publishTarget,
  publication: {
    mode: publishHost ? 'github-pages-custom-domain' : 'local-artifact-only',
    customDomain: publishHost || null,
    requiredFiles: publicationFiles,
    hostedProofRequirements: [
      'successful buyer-evidence-storybook workflow run',
      'GitHub Pages deploy URL for https://storybook.acgs.ai',
      'DNS CNAME/provider evidence for storybook.acgs.ai',
      'passing storybook-dns-live, storybook-https-live, and storybook-manifest-live checks',
    ],
    claimBoundary:
      'Publication files are local build artifacts only; not hosted Storybook proof until the Pages deploy, DNS evidence, hosted manifest, and verify:production-live pass are attached.',
  },
  stories: evidenceStories.map(({ id, title, route, localGates, sourceFiles }) => ({
    id,
    title,
    route,
    localGates,
    sourceFiles,
  })),
}

const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>ACGS buyer evidence gallery</title>
    <style>
      :root {
        color-scheme: light;
        font-family:
          Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #f6f1e8;
        color: #1f2933;
      }
      body {
        margin: 0;
        padding: 32px;
      }
      main {
        max-width: 1040px;
        margin: 0 auto;
      }
      .hero,
      .story {
        border: 1px solid #d9cbb6;
        border-radius: 24px;
        background: #fffdf8;
        box-shadow: 0 20px 70px rgb(68 50 31 / 10%);
      }
      .hero {
        padding: 32px;
        margin-bottom: 24px;
      }
      .story {
        padding: 24px;
        margin: 18px 0;
      }
      h1,
      h2,
      h3,
      p {
        margin-top: 0;
      }
      h1 {
        font-size: clamp(2rem, 4vw, 3.5rem);
        line-height: 1;
      }
      h2 {
        font-size: 1.45rem;
      }
      h3 {
        font-size: 0.9rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #6b5a45;
      }
      .eyebrow {
        color: #8a5a1f;
        font-size: 0.8rem;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
      }
      .question {
        font-size: 1.05rem;
        font-weight: 700;
      }
      .boundary {
        border-left: 4px solid #9a3412;
        padding: 12px 16px;
        background: #fff7ed;
      }
      li {
        margin: 0.35rem 0;
      }
    </style>
  </head>
  <body>
    <main>
      <section class="hero">
        <p class="eyebrow">Local artifact · dependency-free · claim-safe</p>
        <h1>ACGS buyer evidence gallery</h1>
        <p>
          A compact proof gallery for regulated-AI buyers: verify one policy enforcement
          decision, inspect the receipt trail, confirm the signed evidence packet, and see
          which local gates protect the claim.
        </p>
        <p class="boundary">
          Boundary: this is a local buyer-evidence artifact. It is not the hosted
          Storybook site, not live Cloud Run/Vercel proof, not legal signoff, and not a
          regulatory attestation.
        </p>
      </section>
      ${evidenceStories.map(storyCard).join('\n')}
    </main>
  </body>
</html>
`

rmSync(outDir, { force: true, recursive: true })
mkdirSync(outDir, { recursive: true })
writeFileSync(resolve(outDir, 'index.html'), html)
writeFileSync(resolve(outDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`)
writeFileSync(resolve(outDir, '.nojekyll'), '')
if (publishHost) {
  writeFileSync(resolve(outDir, 'CNAME'), `${publishHost}\n`)
}

console.log(`Buyer evidence gallery written to ${outDir}`)
